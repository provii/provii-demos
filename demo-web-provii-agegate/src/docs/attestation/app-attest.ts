// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Apple App Attest verifier (.6).
 *
 * The App Attest receipt is a CBOR-encoded WebAuthn-style attestation
 * object. The full shape the client hands us is:
 *
 * {
 * "fmt": "apple-appattest",
 * "attStmt": { "x5c": [leaf, intermediate], "receipt": <bytes> },
 * "authData": <bytes>
 * }
 *
 * Verification follows Apple's "Validating Apps That Connect to Your
 * Server" guide plus WWDC 2020 session 10073 (srlabs/appattest-go is a
 * faithful open-source implementation, we mirror its sequencing):
 *
 * 1. Parse the outer CBOR envelope.
 * 2. Parse the x5c chain; walk leaf -> intermediate -> pinned root.
 * 3. Extract the Apple nonce extension (OID 1.2.840.113635.100.8.2)
 * from the leaf. The extension wraps an OCTET STRING of
 * SHA-256(authData || clientDataHash). The spec calls this the
 * expected nonce.
 * 4. Re-derive the expected nonce locally from (authData, clientDataHash)
 * where clientDataHash is the SHA-256 of the 32-byte challenge
 * we issued via /api/mobile/sandbox/challenge. Compare to the
 * extension value using `crypto.subtle.timingSafeEqual` because
 * the nonce is secret material.
 * 5. Parse authData. rpIdHash (first 32 bytes) must equal
 * SHA-256("com.provii.wallet.<team-id>") per Apple's format, the
 * flags byte's AT bit must be set (attested credential data
 * present), and the AAGUID must match the env-expected value.
 * The credentialId region must be present and non-empty.
 * 6. Freshness window: the challenge timestamp attached to the
 * nonce receipt must be within 60 s of now; this bound is
 * enforced by the caller via the KV TTL on the issued nonce
 * record. This function returns the parsed receipt so the
 * gateway can cross-check the timestamp against its own
 * `mobile-sandbox-nonce:{nonce}` record.
 *
 * Real-device smoke test is a post-merge internal step. The tests in
 * `__tests__/app-attest.test.ts` exercise each verification branch with
 * synthetic receipts that re-use the spike's WebCrypto keys; anything
 * that depends on a real App Attest certificate chain is gated by
 * the iOS build handing us a production receipt.
 */

import {
  decodeCbor,
  expectBytes,
  expectBytesArray,
  expectMap,
  expectString,
  type CborValue,
} from "./cbor";
import {
  getPinnedAppleRoot,
  parseCertificate,
  verifyChainToRoot,
  type ParsedCertificate,
} from "./x509";

// ---- OIDs ----------------------------------------------------------
//
// Apple assigned enterprise arc 1.2.840.113635 to itself. The App
// Attest nonce extension is documented at:
// https://developer.apple.com/documentation/devicecheck/
// validating_apps_that_connect_to_your_server
export const OID_APPLE_APP_ATTEST_NONCE = "1.2.840.113635.100.8.2";

// ---- Public types --------------------------------------------------

/**
 * Environment-specific knobs the caller supplies. AAGUIDs differ
 * between Apple's dev build (`appattestdevelop`) and the prod build
 * (`appattest\0\0\0\0\0\0\0`). The expected rpId is the app's
 * bundle identifier; Apple hashes it into the first 32 bytes of
 * authData. `nowMs` is injected for deterministic tests.
 */
export interface AppAttestConfig {
  /** App bundle identifier, e.g. `com.provii.wallet`. */
  appId: string;
  /**
 * Expected AAGUID bytes (16 bytes). Apple's dev AAGUID is
 * "appattestdevelop" ASCII padded; prod AAGUID is "appattest"
 * followed by seven NUL bytes.
   */
  expectedAaguid: Uint8Array;
  /** Wall-clock time for validity checks. Defaults to Date.now(). */
  nowMs?: number;
  /**
 * Challenge bytes the gateway issued on `GET /challenge`. Used
 * directly as clientDataHash input (the bytes the client signed
 * over). Must be exactly 32 bytes to match the nonce issued.
   */
  challenge: Uint8Array;
}

/** The attested credential data extracted from authData. */
export interface AttestedCredential {
  /** 16-byte Apple AAGUID. */
  aaguid: Uint8Array;
  /** The credentialId bytes, length declared in authData. */
  credentialId: Uint8Array;
  /** CBOR-encoded COSE public key starting immediately after credentialId. */
  credentialPublicKeyCose: Uint8Array;
}

export interface AppAttestVerificationResult {
  /** The parsed x5c leaf, for caller-side inspection. */
  leaf: ParsedCertificate;
  /** The attested credential record extracted from authData. */
  attestedCredential: AttestedCredential;
  /**
 * The value of the nonce extension as raw bytes. The caller can
 * compare against its own KV-issued nonce receipt if it wants a
 * second layer of pinning.
   */
  nonceExtensionBytes: Uint8Array;
  /** Signed counter from authData. Apple sets this to 0 on first mint. */
  signCount: number;
}

// ---- Public API ----------------------------------------------------

/**
 * Verify an App Attest token end-to-end. Throws on any failure with
 * a specific error message; callers should map these onto opaque
 * 4xx responses and log the detail through the log sanitiser.
 */
export async function verifyAppAttest(
  tokenCbor: Uint8Array,
  config: AppAttestConfig,
): Promise<AppAttestVerificationResult> {
  if (config.challenge.length !== 32) {
    throw new Error("AppAttest: challenge must be 32 bytes");
  }

 // 1. Outer CBOR envelope.
  const envelope = parseAppAttestEnvelope(tokenCbor);

 // 2. Parse x5c chain and walk to the pinned Apple root.
  if (envelope.x5c.length !== 2) {
    throw new Error(
      `AppAttest: expected 2-cert x5c (leaf + intermediate), got ${envelope.x5c.length}`,
    );
  }
  const leaf = parseCertificate(envelope.x5c[0]!);
  const intermediate = parseCertificate(envelope.x5c[1]!);
  const root = await getPinnedAppleRoot();

  const now = config.nowMs ?? Date.now();
  await verifyChainToRoot(leaf, [intermediate], root, now);

 // 3 + 4. Nonce extension.
  const nonceExtensionBytes = leaf.extensions.get(OID_APPLE_APP_ATTEST_NONCE);
  if (nonceExtensionBytes === undefined) {
    throw new Error("AppAttest: leaf cert missing nonce extension");
  }
  const expectedNonce = await deriveExpectedNonce(
    envelope.authData,
    config.challenge,
  );
  const embeddedNonce = extractNonceFromExtension(nonceExtensionBytes);
  if (embeddedNonce.length !== expectedNonce.length) {
    throw new Error("AppAttest: nonce length mismatch");
  }
  if (!crypto.subtle.timingSafeEqual(embeddedNonce, expectedNonce)) {
    throw new Error("AppAttest: nonce does not match derived value");
  }

 // 5. Parse authData.
  const parsedAuthData = await parseAuthData(envelope.authData, config);

  return {
    leaf,
    attestedCredential: parsedAuthData.credential,
    nonceExtensionBytes,
    signCount: parsedAuthData.signCount,
  };
}

// ---- Envelope + CBOR parsing ---------------------------------------

interface AppAttestEnvelope {
  x5c: Uint8Array[];
  receipt: Uint8Array;
  authData: Uint8Array;
}

function parseAppAttestEnvelope(bytes: Uint8Array): AppAttestEnvelope {
  const outer: CborValue = decodeCbor(bytes);
  const outerMap = expectMap(outer, "<root>");
  const fmt = expectString(outerMap["fmt"], "fmt");
  if (fmt !== "apple-appattest") {
    throw new Error(`AppAttest: unexpected fmt "${fmt}"`);
  }
  const attStmt = expectMap(outerMap["attStmt"], "attStmt");
  const x5c = expectBytesArray(attStmt["x5c"], "attStmt.x5c");
  const receipt = expectBytes(attStmt["receipt"], "attStmt.receipt");
  const authData = expectBytes(outerMap["authData"], "authData");
  return { x5c, receipt, authData };
}

/**
 * Apple stores the nonce in the extension as a SEQUENCE containing
 * a single [1] EXPLICIT OCTET STRING of the 32-byte SHA-256.
 *
 * ExtValue ::= SEQUENCE { [1] EXPLICIT OCTET STRING (SIZE(32)) }
 *
 * Per WWDC 2020 session 10073 and reproduced in srlabs/appattest-go.
 */
function extractNonceFromExtension(extnValue: Uint8Array): Uint8Array {
 // extnValue here is the OCTET STRING content carried in the
 // certificate extension. The content itself is a SEQUENCE.
  if (extnValue.length < 2 || extnValue[0] !== 0x30) {
    throw new Error("AppAttest: nonce extension outer is not SEQUENCE");
  }
  const seqLen = extnValue[1]!;
  const seqBody = extnValue.subarray(2, 2 + seqLen);
 // First child should be [1] constructed: tag 0xa1.
  if (seqBody.length < 2 || seqBody[0] !== 0xa1) {
    throw new Error("AppAttest: nonce extension missing [1] EXPLICIT wrapper");
  }
  const taggedLen = seqBody[1]!;
  const taggedBody = seqBody.subarray(2, 2 + taggedLen);
 // Inside the [1] is an OCTET STRING (tag 0x04).
  if (taggedBody.length < 2 || taggedBody[0] !== 0x04) {
    throw new Error("AppAttest: nonce extension inner is not OCTET STRING");
  }
  const octLen = taggedBody[1]!;
  if (octLen !== 32) {
    throw new Error(`AppAttest: nonce length ${octLen} != 32`);
  }
  return new Uint8Array(taggedBody.subarray(2, 2 + octLen));
}

/**
 * Re-derive the nonce Apple should have embedded in the extension.
 *
 * nonce = SHA-256( authData || SHA-256(challenge) )
 *
 * Per Apple's server validation docs, clientDataHash = SHA-256(challenge).
 */
async function deriveExpectedNonce(
  authData: Uint8Array,
  challenge: Uint8Array,
): Promise<Uint8Array> {
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", challenge),
  );
  const buf = new Uint8Array(authData.length + clientDataHash.length);
  buf.set(authData, 0);
  buf.set(clientDataHash, authData.length);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

// ---- authData parsing ----------------------------------------------

interface ParsedAuthData {
  credential: AttestedCredential;
  signCount: number;
}

/**
 * authData layout (WebAuthn §6.1, adopted by App Attest):
 * rpIdHash (32 bytes, SHA-256 of app bundle id)
 * flags (1 byte; AT bit = 0x40 MUST be set)
 * signCount (4 bytes, big-endian unsigned)
 * AAGUID (16 bytes)
 * credIdLen (2 bytes, big-endian unsigned)
 * credentialId (credIdLen bytes)
 * credentialPublicKey (CBOR COSE_Key, variable)
 *
 * Total fixed-prefix length before credIdLen is 32+1+4+16 = 53 bytes.
 */
async function parseAuthData(
  authData: Uint8Array,
  config: AppAttestConfig,
): Promise<ParsedAuthData> {
  if (authData.length < 53 + 2) {
    throw new Error("AppAttest: authData too short");
  }

 // rpIdHash
  const rpIdHash = authData.subarray(0, 32);
  const expectedRpIdHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(config.appId)),
  );
  if (!crypto.subtle.timingSafeEqual(rpIdHash, expectedRpIdHash)) {
    throw new Error("AppAttest: rpIdHash does not match configured appId");
  }

 // flags
  const flags = authData[32]!;
  if ((flags & 0x40) === 0) {
    throw new Error("AppAttest: AT flag not set in authData.flags");
  }

 // signCount
  const signCount = (authData[33]! << 24)
    | (authData[34]! << 16)
    | (authData[35]! << 8)
    | authData[36]!;

 // AAGUID
  const aaguid = new Uint8Array(authData.subarray(37, 53));
  if (aaguid.length !== config.expectedAaguid.length
    || !crypto.subtle.timingSafeEqual(aaguid, config.expectedAaguid)) {
    throw new Error("AppAttest: AAGUID does not match expected value");
  }

 // credentialId
  const credIdLen = (authData[53]! << 8) | authData[54]!;
  if (credIdLen === 0) {
    throw new Error("AppAttest: credentialIdLength is zero");
  }
  const credIdStart = 55;
  const credIdEnd = credIdStart + credIdLen;
  if (credIdEnd > authData.length) {
    throw new Error("AppAttest: credentialId extends past authData");
  }
  const credentialId = new Uint8Array(authData.subarray(credIdStart, credIdEnd));

 // credentialPublicKey: the remainder. We do not parse the COSE
 // structure here; the caller is free to hand it to WebCrypto later
 // if it needs to verify assertions.
  const credentialPublicKeyCose = new Uint8Array(authData.subarray(credIdEnd));
  if (credentialPublicKeyCose.length === 0) {
    throw new Error("AppAttest: missing credential public key");
  }

  return {
    credential: {
      aaguid,
      credentialId,
      credentialPublicKeyCose,
    },
    signCount,
  };
}

// ---- Standard AAGUIDs ---------------------------------------------

/**
 * Apple's published AAGUIDs for App Attest, from WWDC 2020 session
 * 10073 and cross-checked against `srlabs/appattest-go`. Both are
 * 16 bytes: the prod value is `appattest` (9 bytes) + seven NULs;
 * the dev value is `appattestdevelop` exactly, 16 bytes.
 */
export const APPLE_AAGUID_PROD = new Uint8Array([
  0x61, 0x70, 0x70, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

export const APPLE_AAGUID_DEV = new Uint8Array([
  0x61, 0x70, 0x70, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74,
  0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70,
]);
