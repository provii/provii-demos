// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Android Hardware Key Attestation verifier (.7).
 *
 * a 2026-04-16 decision: Android sandbox uses Key Attestation
 * (hardware-backed, TEE or StrongBox), not Play Integrity. The flow
 * the mobile client follows is:
 *
 * 1. Generate a key with
 * KeyGenParameterSpec.Builder(...).setAttestationChallenge(nonce)
 * where `nonce` is the 32 bytes handed back by our
 * `/api/mobile/sandbox/challenge` endpoint.
 * 2. Read the cert chain via
 * KeyStore.getInstance("AndroidKeyStore")
 * .getCertificateChain(alias)
 * which returns leaf + intermediates + a Google Hardware
 * Attestation root. Android batch signer cert chains terminate
 * at one of a handful of public Google Hardware Attestation
 * root CAs.
 * 3. Post the DER chain (as base64 strings in our request body) to
 * `/api/mobile/sandbox/register` where we run the verifier
 * below.
 *
 * Verification:
 * - Walk the chain leaf -> intermediates -> pinned Google root.
 * Every cert must be inside its validity window at `nowMs`.
 * - Extract the Google Attestation extension at OID
 * 1.3.6.1.4.1.11129.2.1.17 from the leaf.
 * - Parse the KeyDescription ASN.1 structure (see below).
 * - Confirm:
 * - `attestationChallenge` bytes == issued nonce.
 * - `attestationSecurityLevel` is TRUSTED_ENVIRONMENT (1) or
 * STRONG_BOX (2). SOFTWARE (0) is rejected.
 * - `keymasterSecurityLevel` is also hardware-backed.
 * - `rootOfTrust.verifiedBootState` is VERIFIED (0), or
 * SELF_SIGNED (1) with `verifiedBootKey` matching an entry
 * in `ALLOWED_SELF_SIGNED_OS_KEYS` (GrapheneOS keys, etc).
 * UNVERIFIED (2) and FAILED (3) are always rejected.
 * - Optionally, if `attestationApplicationId` is present, the
 * decoded `packageName` contains the expected app id.
 *
 * KeyDescription ASN.1 (from the AOSP source at
 * hardware/interfaces/security/keymint/aidl/default):
 *
 * KeyDescription ::= SEQUENCE {
 * attestationVersion INTEGER,
 * attestationSecurityLevel SecurityLevel, -- ENUMERATED
 * keymasterVersion INTEGER,
 * keymasterSecurityLevel SecurityLevel, -- ENUMERATED
 * attestationChallenge OCTET_STRING,
 * uniqueId OCTET_STRING,
 * softwareEnforced AuthorizationList,
 * hardwareEnforced AuthorizationList
 * }
 *
 * AuthorizationList ::= SEQUENCE {
 * ...
 * rootOfTrust [704] EXPLICIT RootOfTrust OPTIONAL,
 * ...
 * }
 *
 * RootOfTrust ::= SEQUENCE {
 * verifiedBootKey OCTET_STRING,
 * deviceLocked BOOLEAN,
 * verifiedBootState ENUMERATED,
 * verifiedBootHash OCTET_STRING
 * }
 *
 * The authorisation-list wraps every optional field in an implicit
 * context-specific tag whose number is the tag id (e.g.
 * attestationApplicationId is [709], rootOfTrust is [704]).
 *
 * Pinned roots. The authoritative set is sourced from
 * https://android.googleapis.com/attestation/root (a JSON array of
 * PEM blocks). On 2026-04-22 that set contained the RSA-4096 2022
 * batch and the new ECDSA P-384 "Key Attestation CA1" that starts
 * signing production traffic on 2026-02-01. Both are pinned. See
 * the constants and ambiguity notes below for rotation mechanics.
 * Hardware Attestation roots are distinct from Play Integrity JWKS.
 */

import {
  bytesEqual,
  children,
  content,
  decodeBoolean,
  decodeEnumerated,
  decodeInteger,
  readTlv,
  TAG_BOOLEAN,
  TAG_OCTET_STRING,
  TAG_SEQUENCE,
  TAG_SET,
  type Tlv,
} from "./asn1";
import {
  parseCertificate,
  verifyChainToRoot,
  type ParsedCertificate,
} from "./x509";

// ---- OID --------------------------------------------------------

/** Google Hardware Attestation extension OID. */
export const OID_KEY_ATTESTATION = "1.3.6.1.4.1.11129.2.1.17";

// ---- Security-level enum ----------------------------------------

export const SECURITY_LEVEL_SOFTWARE = 0;
export const SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
export const SECURITY_LEVEL_STRONG_BOX = 2;

export const VERIFIED_BOOT_STATE_VERIFIED = 0;
export const VERIFIED_BOOT_STATE_SELF_SIGNED = 1;
export const VERIFIED_BOOT_STATE_UNVERIFIED = 2;
export const VERIFIED_BOOT_STATE_FAILED = 3;

// ---- Self-signed OS key allowlist -------------------------------
//
// Android Hardware Key Attestation reports `verifiedBootState =
// SELF_SIGNED (1)` when the device has a re-locked bootloader signed
// with a key the device owner (not Google) installed. The rest of
// the attestation remains hardware-rooted, cryptographically valid
// and bound to the TEE/StrongBox keymint instance, so the only thing
// "self-signed" weakens is the OS provenance signal: we need to
// decide out-of-band which non-Google OS signing keys we trust.
//
// The allowlist below holds SHA-256 digests (lowercase hex) of OS
// signing public keys we explicitly trust for sandbox registration.
// If a SELF_SIGNED chain arrives whose `verifiedBootKey` (the hash
// reported by the TEE) matches an entry here, the verifier accepts
// it the same way it accepts `VERIFIED`. If the key is unknown the
// verifier rejects with a specific error naming whether the key
// matched.
//
// Policy notes:
// - This is policy, not secret. It lives in source (reviewed,
// diffable) rather than in env. Rotating it is a code change.
// - Only permit operating systems that ship security updates and
// have a known-good hardware attestation story. Do NOT add
// developer hobby ROMs.
// - GrapheneOS publishes an authoritative signed JSON of current
// keys at https://grapheneos.org/attestation.json. The values
// below were copied from the HTML compatibility guide and cross
// checked against that JSON on 2026-04-22. When adding new
// devices, re-pull both and verify they match.
// - CalyxOS does not currently publish an official verified-boot
// key fingerprint list we can source, so no CalyxOS entries are
// included. Adding CalyxOS support is a follow-up once we have
// a verifiable public source for their keys.
export const ALLOWED_SELF_SIGNED_OS_KEYS: readonly string[] = [
 // GrapheneOS verified boot keys (SHA-256 of the OS signing public
 // key, lowercase hex), per
 // https://grapheneos.org/articles/attestation-compatibility-guide
 // https://grapheneos.org/attestation.json
 // cross-checked 2026-04-22.
  "d8f879d10419eddc9fcda6280718be763f6bf12299e1f72df3ea8ad8a8eb7f80", // GrapheneOS: Pixel 10a
  "55a2d44103e56d5ec65496399c417987ba77730e6488fc60ba058d09fc3caee3", // GrapheneOS: Pixel 10 Pro Fold
  "141d7fc32af7958a416f2661b37cf6f27bfb376fb5ce616aeaa27a82c7a04f74", // GrapheneOS: Pixel 10 Pro XL
  "4e8ee8f717754052198ca6d2d3aaa232e2461b4293c0d6f297e519cc778de093", // GrapheneOS: Pixel 10 Pro
  "3f7415ea26f5df5b14ea6d153256071a7a1af9ce7b0970b7311cc463c7ea02c7", // GrapheneOS: Pixel 10
  "0508de44ee00bfb49ece32c418af1896391abde0f05b64f41bc9a2dfb589445b", // GrapheneOS: Pixel 9a
  "af4d2c6e62be0fec54f0271b9776ff061dd8392d9f51cf6ab1551d346679e24c", // GrapheneOS: Pixel 9 Pro Fold
  "55d3c2323db91bb91f20d38d015e85112d038f6b6b5738fe352c1a80dba57023", // GrapheneOS: Pixel 9 Pro XL
  "f729cab861da1b83fdfab402fc9480758f2ae78ee0b61c1f2137dd1ab7076e86", // GrapheneOS: Pixel 9 Pro
  "9e6a8f3e0d761a780179f93acd5721ba1ab7c8c537c7761073c0a754b0e932de", // GrapheneOS: Pixel 9
  "096b8bd6d44527a24ac1564b308839f67e78202185cbff9cfdcb10e63250bc5e", // GrapheneOS: Pixel 8a
  "896db2d09d84e1d6bb747002b8a114950b946e5825772a9d48ba7eb01d118c1c", // GrapheneOS: Pixel 8 Pro
  "cd7479653aa88208f9f03034810ef9b7b0af8a9d41e2000e458ac403a2acb233", // GrapheneOS: Pixel 8
  "ee0c9dfef6f55a878538b0dbf7e78e3bc3f1a13c8c44839b095fe26dd5fe2842", // GrapheneOS: Pixel Fold
  "94df136e6c6aa08dc26580af46f36419b5f9baf46039db076f5295b91aaff230", // GrapheneOS: Pixel Tablet
  "508d75dea10c5cbc3e7632260fc0b59f6055a8a49dd84e693b6d8899edbb01e4", // GrapheneOS: Pixel 7a
  "bc1c0dd95664604382bb888412026422742eb333071ea0b2d19036217d49182f", // GrapheneOS: Pixel 7 Pro
  "3efe5392be3ac38afb894d13de639e521675e62571a8a9b3ef9fc8c44fd17fa1", // GrapheneOS: Pixel 7
  "08c860350a9600692d10c8512f7b8e80707757468e8fbfeea2a870c0a83d6031", // GrapheneOS: Pixel 6a
  "439b76524d94c40652ce1bf0d8243773c634d2f99ba3160d8d02aa5e29ff925c", // GrapheneOS: Pixel 6 Pro
  "f0a890375d1405e62ebfd87e8d3f475f948ef031bbf9ddd516d5f600a23677e8", // GrapheneOS: Pixel 6
];

// Module-load sanity check on ALLOWED_SELF_SIGNED_OS_KEYS.
// SHA-256 digests are 32 bytes = 64 lowercase hex characters. A typo
// that slips through review (e.g. 63 chars or an uppercase byte) would
// silently exclude a legitimate Graphene key from the allowlist via
// the length / hex-validity guards inside `isAllowedSelfSignedOsKey`,
// turning the feature off for that SKU without anyone noticing. Fail
// module load instead so a bad allowlist entry is a deploy-time error.
// Also reject duplicates so a mistaken copy-paste can't hide a missing
// device behind a double entry of another one.
(() => {
  const seen = new Set<string>();
  for (const entry of ALLOWED_SELF_SIGNED_OS_KEYS) {
    if (entry.length !== 64) {
      throw new Error(
        `ALLOWED_SELF_SIGNED_OS_KEYS: entry is not 64 hex chars (got ${entry.length}): ${entry}`,
      );
    }
    if (!/^[0-9a-f]+$/.test(entry)) {
      throw new Error(
        `ALLOWED_SELF_SIGNED_OS_KEYS: entry is not lowercase hex: ${entry}`,
      );
    }
    if (seen.has(entry)) {
      throw new Error(
        `ALLOWED_SELF_SIGNED_OS_KEYS: duplicate entry: ${entry}`,
      );
    }
    seen.add(entry);
  }
})();

// ---- AuthorizationList tag numbers ------------------------------
//
// Full list in keymint/aidl/.../Tag.aidl. Only the tags we read in
// this file are named here; anything else is ignored.
const AUTH_TAG_ROOT_OF_TRUST = 704;
const AUTH_TAG_ATTESTATION_APPLICATION_ID = 709;

// ---- Pinned Google roots ----------------------------------------
//
// Google publishes the authoritative set of Hardware Attestation roots
// as a JSON array at https://android.googleapis.com/attestation/root .
// At the moment of fetching (see date below) the array contained two
// active roots; real device chains terminate in one of them depending
// on which batch signer the device manufacturer used.
//
// The gateway accepts a chain whose final cert byte-matches ANY entry
// here. Rotation is a code change: pull the JSON again, diff the set,
// update the constants below, and note the fetch date alongside.
//
// Regenerate with:
//
// curl -sL https://android.googleapis.com/attestation/root \
// | jq -r '.[]' > roots.pem
// awk '/-BEGIN CERT-/{i++}{print > "root_"i".pem"}' roots.pem
// for f in root_*.pem; do
// openssl x509 -in $f -outform DER | base64 | tr -d '\n'; echo
// done
//
// Dual sourcing: the same PEM blocks are also embedded on
// `https://developer.android.com/privacy-and-security/security-key-attestation`
// under the "Root certificates" disclosure. Cross-checked on the fetch
// date below.

/**
 * Root 0: Google Hardware Attestation RSA root.
 * Subject/Issuer: serialNumber=f92009e853b6b045 (self-signed)
 * Serial: 00f1c172a699eaf51d
 * Key: RSA 4096
 * Validity: 2022-03-20T18:07:48Z .. 2042-03-15T18:07:48Z
 * SHA-256 fp: cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc
 *
 * Source: https://android.googleapis.com/attestation/root (entry 0)
 * Fetched 2026-04-22. Upstream commit SHA is not exposed by the JSON
 * endpoint; capture the SHA-256 fingerprint above and cross-check
 * against the PEM embedded on developer.android.com if a rotation is
 * suspected (see ambiguity note at the bottom of this file).
 *
 * Signature-verification caveat: the current `verifyChainToRoot`
 * implementation only supports ECDSA P-256 / P-384 signatures
 * (see x509.ts `verifyCertificateSignature`). A chain that actually
 * terminates in this RSA root will pass the bytewise terminator
 * match below but fail the root-self-signature check. Wiring RSA
 * into the WebCrypto import path is tracked as a follow-up; this
 * file pins the DER so a future RSA-capable verifier can consume
 * it without another source-and-verify step.
 */
export const GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA_DER_BASE64 =
  "MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV"
  + "BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw"
  + "NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B"
  + "AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS"
  + "Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7"
  + "tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj"
  + "nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq"
  + "C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ"
  + "oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O"
  + "JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg"
  + "sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi"
  + "igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M"
  + "RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E"
  + "aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um"
  + "AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud"
  + "IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD"
  + "VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7"
  + "174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC"
  + "W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G"
  + "tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx"
  + "oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG"
  + "1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF"
  + "mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz"
  + "lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw"
  + "n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu"
  + "zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo"
  + "vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn"
  + "w1IdYIg2Wxg7yHcQZemFQg==";

/**
 * Root 1: "Key Attestation CA1", the new ECDSA P-384 root.
 * Subject/Issuer: CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US
 * Serial: 0084a9d0297b0eb58ae7ff0e80de760605
 * Key: ECDSA P-384
 * Validity: 2025-07-17T22:32:18Z .. 2035-07-15T22:32:18Z
 * SHA-256 fp: 6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0
 *
 * Source: https://android.googleapis.com/attestation/root (entry 1)
 * Fetched 2026-04-22. developer.android.com states this root begins
 * signing attestation chains on 2026-02-01, so current production
 * traffic is already migrating to it. This is the root the existing
 * ECDSA-only chain verifier can self-verify today.
 */
export const GOOGLE_HARDWARE_ATTESTATION_ROOT_EC_DER_BASE64 =
  "MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc"
  + "MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET"
  + "MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4"
  + "WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex"
  + "MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG"
  + "EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt"
  + "G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5"
  + "Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB"
  + "/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA"
  + "MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH"
  + "EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY"
  + "uR2zh/80lQyu9vAFCj6E4AXc+osmRg==";

/**
 * Default set of pinned Google Hardware Attestation roots, in DER
 * base64 form. A chain whose final cert byte-matches any entry is
 * accepted (subject to the other verification steps). Ordered with
 * the ECDSA root first to match the 2026-02-01 production rotation.
 */
export const GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64_SET: readonly string[] = [
  GOOGLE_HARDWARE_ATTESTATION_ROOT_EC_DER_BASE64,
  GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA_DER_BASE64,
];

/**
 * Authoritative, used for module-load integrity check against the DER
 * literals above. Lowercase hex SHA-256 of the DER for each entry,
 * positionally aligned with `GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64_SET`.
 *
 * Values sourced from `https://android.googleapis.com/attestation/root`
 * on 2026-04-22 via `openssl x509 -noout -fingerprint -sha256`:
 * - Entry 0 (EC P-384 "Key Attestation CA1"):
 * 6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0
 * - Entry 1 (RSA-4096, serial f92009e853b6b045):
 * cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc
 *
 * Cross-checked against the developer.android.com "Root certificates"
 * disclosure on the same fetch date. If the pinned DER blobs are edited
 * (rotation, typo, trust-anchor swap attempt) the fingerprint will not
 * match and the verifier rejects at first-use inside this isolate.
 */
export const GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_SHA256: readonly string[] = [
  "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0",
  "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc",
];

/**
 * Back-compat single-root export. Callers that still reference this
 * constant pick up the ECDSA (P-384) root, matching the set ordering.
 * New call-sites should read `GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64_SET`
 * directly so both roots are considered.
 */
export const GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64 =
  GOOGLE_HARDWARE_ATTESTATION_ROOT_EC_DER_BASE64;

// ---- Public types -----------------------------------------------

/** Parsed RootOfTrust SEQUENCE. */
export interface RootOfTrust {
  verifiedBootKey: Uint8Array;
  deviceLocked: boolean;
  verifiedBootState: number;
  verifiedBootHash: Uint8Array;
}

/** Top-level KeyDescription structure. */
export interface KeyDescription {
  attestationVersion: number;
  attestationSecurityLevel: number;
  keymasterVersion: number;
  keymasterSecurityLevel: number;
  attestationChallenge: Uint8Array;
  uniqueId: Uint8Array;
  softwareEnforced: AuthorizationList;
  hardwareEnforced: AuthorizationList;
}

export interface AuthorizationList {
  rootOfTrust: RootOfTrust | null;
  attestationApplicationIdRaw: Uint8Array | null;
}

export interface KeyAttestationConfig {
  /** Nonce bytes issued by `/challenge`; must equal attestationChallenge. */
  challenge: Uint8Array;
  /** App package name, e.g. `com.provii.wallet`. Optional cross-check. */
  expectedPackageName?: string;
  /**
 * Pinned Google roots in DER base64. A chain whose final cert
 * byte-matches any entry is accepted as rooted; if the list is
 * empty (or every entry is a zero-length string) the caller gets
 * `no_pinned_root`.
 *
 * When unset, the verifier falls back to the default module-level
 * set exported as
 * `GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64_SET` above. Tests
 * can pass an explicit set (including a synthetic self-signed
 * root) to exercise the chain-walk.
   */
  pinnedRootDerBase64Set?: readonly string[];
  /**
 * Back-compat single-root form. If set, promoted to a one-entry
 * set. Deprecated; prefer `pinnedRootDerBase64Set`.
   */
  pinnedRootDerBase64?: string;
  /** Accept STRONG_BOX in addition to TRUSTED_ENVIRONMENT. Default true. */
  acceptStrongBox?: boolean;
  /** Wall-clock for chain validity. Defaults to Date.now(). */
  nowMs?: number;
}

export interface KeyAttestationVerificationResult {
  leaf: ParsedCertificate;
  keyDescription: KeyDescription;
}

// ---- Module-load integrity check on the pinned root set ---------
//
// Mirrors the synchronous `ALLOWED_SELF_SIGNED_OS_KEYS` IIFE above,
// but the pinned-roots path needs an async SHA-256 digest and that
// call is only available via `crypto.subtle` which returns a Promise.
// Rather than reach for top-level await (the rest of this codebase
// keeps module init synchronous and the vitest-pool-workers
// compatibility window does not flip nodejs_compat_v2 on yet), run
// the integrity check on first use of `verifyKeyAttestation` inside
// an isolate and cache the resolved promise so subsequent calls pay
// nothing. A failure throws the same way the synchronous allowlist
// check would, turning a bad DER literal into a first-request 500
// rather than a silent trust-anchor swap.
let pinnedRootsIntegrityCheck: Promise<void> | null = null;

/**
 * Assert that every entry in `GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64_SET`
 * - decodes as base64,
 * - parses as a DER-encoded X.509 certificate,
 * - has a SHA-256 fingerprint matching the positionally-aligned
 * entry in `GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_SHA256`.
 *
 * Idempotent + memoised per isolate. Re-running is cheap but still
 * allocates a parse + digest; callers should prefer the cached form
 * via `ensurePinnedRootsIntegrity`.
 *
 * Exported so tests can exercise the integrity check in isolation.
 */
export async function verifyPinnedRootsIntegrity(): Promise<void> {
  if (
    GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64_SET.length
      !== GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_SHA256.length
  ) {
    throw new Error(
      `KeyAttestation: pinned root DER set has ${GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64_SET.length} entries but fingerprint set has ${GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_SHA256.length}`,
    );
  }
  for (let i = 0; i < GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64_SET.length; i++) {
    const base64 = GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64_SET[i]!;
    const expectedHex = GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_SHA256[i]!;
 // base64ToBytes throws on malformed base64; parseCertificate
 // throws on malformed DER. Both surface as a specific indexed
 // error so a deploy-time regression points at the bad entry.
    let der: Uint8Array;
    try {
      der = base64ToBytes(base64);
    } catch (cause) {
      throw new Error(
        `KeyAttestation: pinned root entry ${i} is not valid base64: ${(cause as Error).message}`,
      );
    }
    try {
      parseCertificate(der);
    } catch (cause) {
      throw new Error(
        `KeyAttestation: pinned root entry ${i} failed DER parse: ${(cause as Error).message}`,
      );
    }
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", der));
    const actualHex = bytesToHexLower(digest);
    if (actualHex !== expectedHex) {
      throw new Error(
        `KeyAttestation: pinned root entry ${i} SHA-256 fingerprint mismatch (expected ${expectedHex}, got ${actualHex})`,
      );
    }
  }
}

/**
 * Cached form of `verifyPinnedRootsIntegrity`. The first call kicks
 * off the check and stores the resulting promise; subsequent calls
 * resolve against the same promise. If the check rejects, every
 * future call rejects with the same error (isolate-sticky failure).
 */
function ensurePinnedRootsIntegrity(): Promise<void> {
  if (pinnedRootsIntegrityCheck === null) {
    pinnedRootsIntegrityCheck = verifyPinnedRootsIntegrity();
  }
  return pinnedRootsIntegrityCheck;
}

/**
 * Test-only: drop the cached integrity-check promise so a test can
 * exercise a fresh run (e.g. after mutating the DER set inside the
 * test process). Not used at runtime.
 */
export function __resetPinnedRootsIntegrityCacheForTests(): void {
  pinnedRootsIntegrityCheck = null;
}

// ---- Public API --------------------------------------------------

/**
 * Verify a Hardware Key Attestation chain end-to-end. Throws on any
 * failure with a specific error message; callers map onto opaque 4xx
 * responses.
 *
 * `chainDer` is leaf-first: `chainDer[0]` is the leaf cert issued by
 * AndroidKeyStore, subsequent entries are intermediates, and the
 * final entry is expected to match the pinned Google root OR a
 * signed descendant of it. The caller supplies the pinned root DER
 * in `config.pinnedRootDerBase64`.
 */
export async function verifyKeyAttestation(
  chainDer: Uint8Array[],
  config: KeyAttestationConfig,
): Promise<KeyAttestationVerificationResult> {
 // Fail closed if the pinned-root DER literals have drifted from
 // their authoritative SHA-256 fingerprints. The assertion runs
 // once per isolate regardless of which pinned set the caller
 // resolves (explicit override or module default); the module
 // default is the set this integrity check guards, so running
 // even for test-supplied overrides keeps the code path short and
 // catches corruption of the module literals before any
 // verification work starts.
  await ensurePinnedRootsIntegrity();
  if (chainDer.length < 2) {
    throw new Error(
      `KeyAttestation: chain must have >= 2 certs, got ${chainDer.length}`,
    );
  }
 // Resolve the pinned-root set. Explicit `pinnedRootDerBase64Set`
 // beats the single-root back-compat field, which beats the module
 // default set. An empty resolved set is an operator misconfiguration
 // and surfaces as `no pinned Google root configured`.
  const pinnedSetRaw = resolvePinnedRootSet(config);
  const pinnedSet = pinnedSetRaw
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  if (pinnedSet.length === 0) {
    throw new Error("KeyAttestation: no pinned Google root configured");
  }

  const parsedChain = chainDer.map(parseCertificate);
  const leaf = parsedChain[0]!;
  const chainTerminator = parsedChain[parsedChain.length - 1]!;
  const pinnedRoots = pinnedSet.map((entry) => parseCertificate(base64ToBytes(entry)));

 // Chain terminator must match one of the pinned roots bytewise.
 // Google's chains include the root as the final cert so the client
 // does not need to fetch it separately; we re-verify the bytes
 // rather than trust the client's copy.
  const matchingRoot = pinnedRoots.find(
    (root) => bytesEqual(chainTerminator.raw, root.raw),
  );
  if (matchingRoot === undefined) {
    throw new Error("KeyAttestation: chain root does not match any pinned Google root");
  }

  const intermediates = parsedChain.slice(1, -1);
  const nowMs = config.nowMs ?? Date.now();
  await verifyChainToRoot(leaf, intermediates, matchingRoot, nowMs);

 // Pull + parse the Google Attestation extension on the leaf.
  const extnValue = leaf.extensions.get(OID_KEY_ATTESTATION);
  if (extnValue === undefined) {
    throw new Error("KeyAttestation: leaf missing Google Attestation extension");
  }
  const keyDescription = parseKeyDescription(extnValue);

 // Challenge bytewise comparison. Constant-time because the
 // challenge is secret material (binding to our mint request).
  if (keyDescription.attestationChallenge.length !== config.challenge.length
    || !crypto.subtle.timingSafeEqual(
      keyDescription.attestationChallenge,
      config.challenge,
    )
  ) {
    throw new Error("KeyAttestation: attestationChallenge does not match issued nonce");
  }

 // Hardware-backed security levels.
  const acceptStrongBox = config.acceptStrongBox !== false;
  assertHardwareSecurityLevel(
    keyDescription.attestationSecurityLevel,
    acceptStrongBox,
    "attestationSecurityLevel",
  );
  assertHardwareSecurityLevel(
    keyDescription.keymasterSecurityLevel,
    acceptStrongBox,
    "keymasterSecurityLevel",
  );

  const rootOfTrust = keyDescription.hardwareEnforced.rootOfTrust;
  if (rootOfTrust === null) {
    throw new Error("KeyAttestation: hardwareEnforced.rootOfTrust is missing");
  }
  assertVerifiedBootPolicy(rootOfTrust);

 // Optional package name cross-check. We do not fail on missing
 // attestationApplicationId because older Android releases omit it.
 //
 // The blob is a DER-encoded SEQUENCE per
 // AttestationApplicationId ::= SEQUENCE {
 // packageInfos SET OF AttestationPackageInfo,
 // signatureDigests SET OF OCTET STRING
 // }
 // AttestationPackageInfo ::= SEQUENCE {
 // packageName OCTET STRING,
 // version INTEGER
 // }
 // The previous implementation scanned the raw bytes for the expected
 // package name as a UTF-8 substring, which let any attacker-controlled
 // bytes containing the expected name (e.g. embedded inside a
 // signature-digest blob or inside a packageName that merely contains
 // ours as a substring) pass unchallenged. Replace with a strict
 // structural parse and explicit equality against every packageName
 // in the packageInfos SET.
  if (config.expectedPackageName !== undefined) {
    const rawAppId = keyDescription.hardwareEnforced.attestationApplicationIdRaw
      ?? keyDescription.softwareEnforced.attestationApplicationIdRaw;
    if (rawAppId !== null && rawAppId !== undefined) {
      const packageNames = parseAttestationApplicationIdPackageNames(rawAppId);
      const expected = config.expectedPackageName;
      const matched = packageNames.some((name) => name === expected);
      if (!matched) {
        throw new Error(
          `KeyAttestation: attestationApplicationId has no packageName matching "${expected}"`,
        );
      }
    }
  }

  return { leaf, keyDescription };
}

/**
 * Extract every `packageName` string from a DER-encoded
 * AttestationApplicationId blob, returning the UTF-8 decodings in
 * document order. Throws if the outer shape is not a SEQUENCE whose
 * first element is a SET of SEQUENCE(OCTET STRING, INTEGER).
 *
 * Exported for unit tests.
 */
export function parseAttestationApplicationIdPackageNames(
  blob: Uint8Array,
): string[] {
  const outer = readTlv(blob, 0);
  if (outer.tag !== TAG_SEQUENCE) {
    throw new Error(
      "KeyAttestation: AttestationApplicationId outer is not SEQUENCE",
    );
  }
  const outerChildren = children(blob, outer);
  if (outerChildren.length < 1) {
    throw new Error(
      "KeyAttestation: AttestationApplicationId missing packageInfos",
    );
  }
  const packageInfosRef = outerChildren[0]!;
  if (packageInfosRef.tag !== TAG_SET) {
    throw new Error(
      "KeyAttestation: AttestationApplicationId.packageInfos is not SET",
    );
  }
  const names: string[] = [];
  for (const info of children(blob, packageInfosRef)) {
    if (info.tag !== TAG_SEQUENCE) {
      throw new Error(
        "KeyAttestation: AttestationPackageInfo is not SEQUENCE",
      );
    }
    const infoChildren = children(blob, info);
    if (infoChildren.length < 1) {
      throw new Error(
        "KeyAttestation: AttestationPackageInfo missing packageName",
      );
    }
    const nameRef = infoChildren[0]!;
    if (nameRef.tag !== TAG_OCTET_STRING) {
      throw new Error(
        "KeyAttestation: AttestationPackageInfo.packageName is not OCTET STRING",
      );
    }
 // UTF-8 decode with `fatal: true` so a mangled byte sequence surfaces
 // rather than silently becoming U+FFFD that might later coincide
 // with the expected name.
    const decoded = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: false,
    }).decode(content(blob, nameRef));
    names.push(decoded);
  }
  return names;
}

function resolvePinnedRootSet(config: KeyAttestationConfig): readonly string[] {
  if (config.pinnedRootDerBase64Set !== undefined) {
    return config.pinnedRootDerBase64Set;
  }
  if (config.pinnedRootDerBase64 !== undefined) {
    return [config.pinnedRootDerBase64];
  }
  return GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64_SET;
}

function assertHardwareSecurityLevel(
  level: number,
  acceptStrongBox: boolean,
  field: string,
): void {
  if (level === SECURITY_LEVEL_TRUSTED_ENVIRONMENT) return;
  if (level === SECURITY_LEVEL_STRONG_BOX && acceptStrongBox) return;
  throw new Error(
    `KeyAttestation: ${field} ${level} is not hardware-backed`,
  );
}

/**
 * Apply the verified-boot policy to a parsed RootOfTrust. Two accept
 * paths:
 * - VERIFIED (0): Google-signed stock Android.
 * - SELF_SIGNED (1) with `verifiedBootKey` in
 * ALLOWED_SELF_SIGNED_OS_KEYS: re-locked bootloader running a
 * privacy-respecting AOSP derivative (GrapheneOS, etc.) whose
 * OS signing key we explicitly trust.
 * UNVERIFIED (2) and FAILED (3) are always rejected; `deviceLocked`
 * is still required in both accept cases because an unlocked
 * bootloader nullifies the attestation regardless of OS.
 *
 * Exported for unit tests.
 */
export function assertVerifiedBootPolicy(rootOfTrust: RootOfTrust): void {
  const bootState = rootOfTrust.verifiedBootState;
  if (bootState === VERIFIED_BOOT_STATE_VERIFIED) {
 // Accept path: Google-signed stock Android.
  } else if (bootState === VERIFIED_BOOT_STATE_SELF_SIGNED) {
    if (!isAllowedSelfSignedOsKey(rootOfTrust.verifiedBootKey)) {
      const bootKeyHex = bytesToHexLower(rootOfTrust.verifiedBootKey);
      throw new Error(
        `KeyAttestation: verifiedBootState is SELF_SIGNED and verifiedBootKey ${bootKeyHex} is not in ALLOWED_SELF_SIGNED_OS_KEYS`,
      );
    }
  } else {
    throw new Error(
      `KeyAttestation: verifiedBootState ${bootState} is not accepted (VERIFIED or SELF_SIGNED with allowlisted key required)`,
    );
  }
  if (!rootOfTrust.deviceLocked) {
    throw new Error("KeyAttestation: device is not locked");
  }
}

// ---- KeyDescription parsing -------------------------------------

export function parseKeyDescription(extnValue: Uint8Array): KeyDescription {
  const outer = readTlv(extnValue, 0);
  if (outer.tag !== TAG_SEQUENCE) {
    throw new Error("KeyAttestation: KeyDescription is not SEQUENCE");
  }
  const items = children(extnValue, outer);
  if (items.length !== 8) {
    throw new Error(
      `KeyAttestation: KeyDescription has ${items.length} fields, expected 8`,
    );
  }
  const [
    attVer, attSec, kmVer, kmSec, attChallenge, uniqueId, sw, hw,
  ] = items as [Tlv, Tlv, Tlv, Tlv, Tlv, Tlv, Tlv, Tlv];

  if (attChallenge.tag !== TAG_OCTET_STRING) {
    throw new Error("KeyAttestation: attestationChallenge not OCTET STRING");
  }
  if (uniqueId.tag !== TAG_OCTET_STRING) {
    throw new Error("KeyAttestation: uniqueId not OCTET STRING");
  }

  return {
    attestationVersion: decodeInteger(extnValue, attVer),
    attestationSecurityLevel: decodeEnumerated(extnValue, attSec),
    keymasterVersion: decodeInteger(extnValue, kmVer),
    keymasterSecurityLevel: decodeEnumerated(extnValue, kmSec),
    attestationChallenge: new Uint8Array(content(extnValue, attChallenge)),
    uniqueId: new Uint8Array(content(extnValue, uniqueId)),
    softwareEnforced: parseAuthorizationList(extnValue, sw),
    hardwareEnforced: parseAuthorizationList(extnValue, hw),
  };
}

function parseAuthorizationList(
  buf: Uint8Array,
  tlv: Tlv,
): AuthorizationList {
  if (tlv.tag !== TAG_SEQUENCE) {
    throw new Error("KeyAttestation: AuthorizationList not SEQUENCE");
  }
 // The authorisation list is a SEQUENCE of context-specific [n]
 // tagged items. Both rootOfTrust (704) and
 // attestationApplicationId (709) sit above the 31-tag boundary
 // so they encode in the high-tag-number form; the readTlv helper
 // resolves `decodedTagNumber` for us.
 //
 // RFC 5280 style once-and-only-once rule: a well-formed signed TBS
 // does not contain duplicate tag numbers inside an AuthorizationList,
 // and the inner SEQUENCE is part of the signed extnValue so a
 // duplicate implies either a malformed emitter or a crafted blob
 // trying to slip a second RootOfTrust past the parser. The x509
 // parseExtensions helper applies the same rule at the cert-extension
 // level; apply it here for tag 704 and tag 709.
  let rootOfTrust: RootOfTrust | null = null;
  let attestationApplicationIdRaw: Uint8Array | null = null;
  let sawRootOfTrust = false;
  let sawAttestationApplicationId = false;

  for (const item of children(buf, tlv)) {
 // Context-specific class = bits 7-6 = 10, i.e. top two bits 0b10.
    if ((item.tag & 0xc0) !== 0x80) continue;
    if (item.decodedTagNumber === AUTH_TAG_ROOT_OF_TRUST) {
      if (sawRootOfTrust) {
        throw new Error(
          "KeyAttestation: AuthorizationList contains duplicate [704] rootOfTrust",
        );
      }
      sawRootOfTrust = true;
      rootOfTrust = parseRootOfTrust(buf, item);
      continue;
    }
    if (item.decodedTagNumber === AUTH_TAG_ATTESTATION_APPLICATION_ID) {
      if (sawAttestationApplicationId) {
        throw new Error(
          "KeyAttestation: AuthorizationList contains duplicate [709] attestationApplicationId",
        );
      }
      sawAttestationApplicationId = true;
 // [709] IMPLICIT OCTET STRING.
      attestationApplicationIdRaw = new Uint8Array(content(buf, item));
      continue;
    }
  }

  return { rootOfTrust, attestationApplicationIdRaw };
}

function parseRootOfTrust(buf: Uint8Array, tlv: Tlv): RootOfTrust {
 // [704] EXPLICIT wrapping a SEQUENCE.
  const inner = readTlv(buf, tlv.contentOffset);
  if (inner.tag !== TAG_SEQUENCE) {
    throw new Error("KeyAttestation: RootOfTrust inner is not SEQUENCE");
  }
  const fields = children(buf, inner);
  if (fields.length !== 4) {
    throw new Error(
      `KeyAttestation: RootOfTrust has ${fields.length} fields, expected 4`,
    );
  }
  const [vbkTlv, dlTlv, vbsTlv, vbhTlv] = fields as [Tlv, Tlv, Tlv, Tlv];
  if (vbkTlv.tag !== TAG_OCTET_STRING) {
    throw new Error("KeyAttestation: verifiedBootKey not OCTET STRING");
  }
  if (dlTlv.tag !== TAG_BOOLEAN) {
    throw new Error("KeyAttestation: deviceLocked not BOOLEAN");
  }
  if (vbhTlv.tag !== TAG_OCTET_STRING) {
    throw new Error("KeyAttestation: verifiedBootHash not OCTET STRING");
  }
  return {
    verifiedBootKey: new Uint8Array(content(buf, vbkTlv)),
 // DER requires TRUE to be exactly 0xff. The previous inline
 // `content[0] !== 0x00` accepted any non-zero byte, which is a
 // BER-ism, not DER. Every legitimate Android device emits 0xff;
 // accepting anything else is a parser bug rather than a
 // compatibility feature. `decodeBoolean` now rejects anything
 // other than 0x00 or 0xff.
    deviceLocked: decodeBoolean(buf, dlTlv),
    verifiedBootState: decodeEnumerated(buf, vbsTlv),
    verifiedBootHash: new Uint8Array(content(buf, vbhTlv)),
  };
}

// ---- Internal helpers -------------------------------------------

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Lowercase hex of a raw byte string. Local helper to avoid a cross
 * package import from `../crypto.ts`; the attestation module already
 * owns a similar helper in `x509.ts` but it is not exported.
 */
function bytesToHexLower(bytes: Uint8Array): string {
  const parts = new Array<string>(bytes.byteLength);
  for (let i = 0; i < bytes.byteLength; i++) {
    parts[i] = bytes[i]!.toString(16).padStart(2, "0");
  }
  return parts.join("");
}

/**
 * Return true iff `verifiedBootKey` bytes match any entry in
 * `ALLOWED_SELF_SIGNED_OS_KEYS`. Comparison is performed against the
 * raw bytes via `crypto.subtle.timingSafeEqual` per the project security policy. The
 * loop deliberately does NOT early-return on match so the timing
 * profile does not reveal which allowlist slot matched. The allowlist
 * entries are public by design (GrapheneOS publishes them), so this
 * is defence in depth rather than a strict secrecy requirement; using
 * a constant-time primitive is free and keeps the file consistent
 * with the `attestationChallenge` comparison above.
 *
 * Exported for unit tests; not used outside this module at runtime.
 */
export function isAllowedSelfSignedOsKey(verifiedBootKey: Uint8Array): boolean {
  let matched = false;
  for (const allowedHex of ALLOWED_SELF_SIGNED_OS_KEYS) {
    const allowedBytes = hexToBytesOrNull(allowedHex);
    if (allowedBytes === null) continue;
    if (allowedBytes.byteLength !== verifiedBootKey.byteLength) continue;
    if (crypto.subtle.timingSafeEqual(allowedBytes, verifiedBootKey)) {
      matched = true;
    }
  }
  return matched;
}

function hexToBytesOrNull(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const high = parseInt(hex[i]!, 16);
    const low = parseInt(hex[i + 1]!, 16);
    if (Number.isNaN(high) || Number.isNaN(low)) return null;
    out[i / 2] = (high << 4) | low;
  }
  return out;
}

// ---- Rotation + ambiguity note ----------------------------------
//
// Google rotates Hardware Attestation roots on an irregular cadence.
// The authoritative list is the JSON array served by
// https://android.googleapis.com/attestation/root
// which on 2026-04-22 contained exactly two entries: the long-lived
// RSA-4096 root (2022-03-20 to 2042-03-15) and the new ECDSA P-384
// "Key Attestation CA1" (2025-07-17 to 2035-07-15) that the
// developer-site note says starts signing production traffic on
// 2026-02-01. Both are pinned above.
//
// Ambiguity flagged during hardening:
// - The developer-site page also embeds a "Previously Issued Root
// Certificates" disclosure with expired roots from 2016 + 2019.
// These are NOT in the JSON array. We intentionally do not pin
// them here; a chain that terminates in an expired root would
// fail the validity-window check in verifyChainToRoot anyway,
// but pinning them would be noisy churn. If an older device
// shows up in telemetry with a chain ending in a 2016/2019 root
// the operator decision is to reject, not to widen the pin.
// - The JSON endpoint does not expose a commit SHA; the upstream
// AOSP path `platform/hardware/interfaces/.../google_root.0` is
// 404 under the refs/heads/main tree (probed 2026-04-22). The
// roots live in Google's signing infra, not the AOSP source
// tree. Anyone rotating this file should compare the re-fetched
// DER against the SHA-256 fingerprints documented above and
// land a single commit with the new fetch date, rather than
// trying to reference a non-existent AOSP commit.

