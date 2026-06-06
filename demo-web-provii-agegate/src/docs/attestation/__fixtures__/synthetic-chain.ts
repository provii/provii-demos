// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Synthetic Android Key Attestation chain builder for unit tests.
 *
 * Generates a three-cert chain (root, intermediate, leaf) signed with
 * ECDSA P-256 / SHA-256 using WebCrypto (workerd). The leaf embeds a
 * configurable KeyDescription extension at the Google Attestation
 * OID so `verifyKeyAttestation` can be exercised end-to-end against
 * the same parser + chain-walk code that runs against real device
 * attestations.
 *
 * Scope:
 * - ECDSA P-256 / SHA-256 only. The same curve + hash pair both
 * x509.verifyCertificateSignature supports and WebCrypto exposes
 * under workerd. RSA / P-384 are out of scope; real production
 * chains end in a Google-signed root in those algos and the
 * existing chain-walk already covers ECDSA P-384 via App Attest.
 * - Minimal DN encoding (commonName only). Sufficient for the
 * issuer/subject linkage check in verifyChainToRoot.
 * - Does NOT currently emit SubjectKeyIdentifier /
 * AuthorityKeyIdentifier extensions; the chain walker links
 * parents by DN alone.
 *
 * Not intended for use outside tests.
 */

// ---- DER primitives ----------------------------------------------

export function tlv(tag: number, content: Uint8Array): Uint8Array {
  let lengthBytes: number[];
  if (content.length < 0x80) {
    lengthBytes = [content.length];
  } else if (content.length < 0x100) {
    lengthBytes = [0x81, content.length];
  } else if (content.length < 0x10000) {
    lengthBytes = [0x82, (content.length >> 8) & 0xff, content.length & 0xff];
  } else {
    lengthBytes = [
      0x83,
      (content.length >> 16) & 0xff,
      (content.length >> 8) & 0xff,
      content.length & 0xff,
    ];
  }
  const out = new Uint8Array(1 + lengthBytes.length + content.length);
  out[0] = tag;
  out.set(lengthBytes, 1);
  out.set(content, 1 + lengthBytes.length);
  return out;
}

export function concat(...items: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const b of items) total += b.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const b of items) {
    out.set(b, offset);
    offset += b.length;
  }
  return out;
}

export function sequence(...items: Uint8Array[]): Uint8Array {
  return tlv(0x30, concat(...items));
}

export function set(...items: Uint8Array[]): Uint8Array {
  return tlv(0x31, concat(...items));
}

export function octetString(bytes: Uint8Array): Uint8Array {
  return tlv(0x04, bytes);
}

export function bitString(bytes: Uint8Array, unusedBits: number = 0): Uint8Array {
  const prefixed = new Uint8Array(bytes.length + 1);
  prefixed[0] = unusedBits;
  prefixed.set(bytes, 1);
  return tlv(0x03, prefixed);
}

export function boolean(value: boolean): Uint8Array {
  return tlv(0x01, new Uint8Array([value ? 0xff : 0x00]));
}

export function enumerated(value: number): Uint8Array {
  return tlv(0x0a, new Uint8Array([value]));
}

export function integerU8(value: number): Uint8Array {
  if (value < 0 || value > 255) {
    throw new Error("synthetic-chain: integerU8 range 0..255");
  }
  if (value === 0) return tlv(0x02, new Uint8Array([0x00]));
  if (value < 0x80) return tlv(0x02, new Uint8Array([value]));
  return tlv(0x02, new Uint8Array([0x00, value]));
}

/** Encode a positive INTEGER from raw big-endian bytes. */
export function integerBigEndian(bytes: Uint8Array): Uint8Array {
 // If the top bit is set, prepend 0x00 so the value stays positive.
  if (bytes.length > 0 && (bytes[0]! & 0x80) !== 0) {
    const padded = new Uint8Array(bytes.length + 1);
    padded[0] = 0x00;
    padded.set(bytes, 1);
    return tlv(0x02, padded);
  }
  return tlv(0x02, bytes);
}

/** Encode an OID from dotted-decimal form. */
export function oid(dotted: string): Uint8Array {
  const parts = dotted.split(".").map((p) => parseInt(p, 10));
  if (parts.length < 2) throw new Error("synthetic-chain: OID needs >= 2 arcs");
  const out: number[] = [parts[0]! * 40 + parts[1]!];
  for (let i = 2; i < parts.length; i++) {
    const arc = parts[i]!;
    if (arc < 0x80) {
      out.push(arc);
    } else {
      const stack: number[] = [];
      let remaining = arc;
      stack.push(remaining & 0x7f);
      remaining >>>= 7;
      while (remaining > 0) {
        stack.push((remaining & 0x7f) | 0x80);
        remaining >>>= 7;
      }
      for (let j = stack.length - 1; j >= 0; j--) out.push(stack[j]!);
    }
  }
  return tlv(0x06, new Uint8Array(out));
}

/** ASCII UTF8String. Sufficient for the `commonName` DN attribute. */
export function utf8String(text: string): Uint8Array {
  return tlv(0x0c, new TextEncoder().encode(text));
}

/** GeneralizedTime YYYYMMDDHHMMSSZ. */
export function generalizedTime(date: Date): Uint8Array {
  const y = date.getUTCFullYear().toString().padStart(4, "0");
  const mo = (date.getUTCMonth() + 1).toString().padStart(2, "0");
  const d = date.getUTCDate().toString().padStart(2, "0");
  const h = date.getUTCHours().toString().padStart(2, "0");
  const mi = date.getUTCMinutes().toString().padStart(2, "0");
  const s = date.getUTCSeconds().toString().padStart(2, "0");
  return tlv(0x18, new TextEncoder().encode(`${y}${mo}${d}${h}${mi}${s}Z`));
}

/** Context-specific, explicit [n] wrapper (constructed). */
export function explicitTag(tagNumber: number, content: Uint8Array): Uint8Array {
  if (tagNumber > 30) {
    throw new Error("synthetic-chain: only short-form explicit tags supported here");
  }
  return tlv(0xa0 | tagNumber, content);
}

// ---- OIDs we emit ------------------------------------------------

export const OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
export const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
export const OID_P256 = "1.2.840.10045.3.1.7";
export const OID_COMMON_NAME = "2.5.4.3";
export const OID_KEY_ATTESTATION = "1.3.6.1.4.1.11129.2.1.17";
export const OID_SHA256_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.11";
export const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

// ---- DN + time helpers -------------------------------------------

/** Minimal Name = SEQUENCE OF RDN; RDN = SET OF AttributeTypeAndValue. */
export function singleCnName(commonName: string): Uint8Array {
  const atv = sequence(oid(OID_COMMON_NAME), utf8String(commonName));
  const rdn = set(atv);
  return sequence(rdn);
}

// ---- Key handling ------------------------------------------------

export type SigAlgorithm = "ECDSA_P256_SHA256" | "RSA_PKCS1_SHA256";

export interface SyntheticKeyPair {
  algorithm: SigAlgorithm;
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  /** DER-encoded SubjectPublicKeyInfo. */
  spkiDer: Uint8Array;
}

export interface EcP256KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  spkiDer: Uint8Array;
}

export async function generateEcP256KeyPair(): Promise<EcP256KeyPair> {
  const pair = await generateKeyPairOfAlgorithm("ECDSA_P256_SHA256");
  return {
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    spkiDer: pair.spkiDer,
  };
}

/**
 * Generate a WebCrypto signing key pair + export the SPKI DER for the
 * requested algorithm. RSA uses 2048 bits (rather than 4096) because
 * workerd's `crypto.subtle.generateKey` for RSA-4096 is extremely slow
 * (5+ seconds per key in the test pool) and the chain builder spawns
 * three keys; 2048 exercises the same RSASSA-PKCS1-v1_5 + SHA-256
 * WebCrypto import/verify paths without the wall-clock hit. Production
 * chain verification is size-agnostic (the import call accepts any
 * RSA modulus length up to 16384 bits per the Web Crypto spec).
 */
export async function generateKeyPairOfAlgorithm(
  algorithm: SigAlgorithm,
): Promise<SyntheticKeyPair> {
  const generated = algorithm === "ECDSA_P256_SHA256"
    ? await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )
    : await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
  if (!isCryptoKeyPair(generated)) {
    throw new Error("synthetic-chain: expected a CryptoKeyPair");
  }
  const spki = await crypto.subtle.exportKey("spki", generated.publicKey);
  if (!(spki instanceof ArrayBuffer)) {
    throw new Error("synthetic-chain: expected SPKI export as ArrayBuffer");
  }
  return {
    algorithm,
    publicKey: generated.publicKey,
    privateKey: generated.privateKey,
    spkiDer: new Uint8Array(spki),
  };
}

function isCryptoKeyPair(value: CryptoKey | CryptoKeyPair): value is CryptoKeyPair {
  return (value as CryptoKeyPair).privateKey !== undefined
    && (value as CryptoKeyPair).publicKey !== undefined;
}

/**
 * WebCrypto ECDSA.sign returns a raw R || S signature. X.509 requires
 * an ASN.1 SEQUENCE { INTEGER r, INTEGER s } in the signatureValue
 * BIT STRING. Convert here.
 */
export async function signTbsEcdsaP256Sha256(
  tbs: Uint8Array,
  privateKey: CryptoKey,
): Promise<Uint8Array> {
  const raw = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    tbs,
  );
  return rawEcdsaToDer(new Uint8Array(raw));
}

/**
 * WebCrypto RSASSA-PKCS1-v1_5 sign returns the raw PKCS#1 v1.5 padded
 * signature as a byte string. X.509 embeds it directly in the
 * signatureValue BIT STRING; no re-framing required.
 */
export async function signTbsRsaPkcs1Sha256(
  tbs: Uint8Array,
  privateKey: CryptoKey,
): Promise<Uint8Array> {
  const raw = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    privateKey,
    tbs,
  );
  return new Uint8Array(raw);
}

function rawEcdsaToDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const r = raw.subarray(0, half);
  const s = raw.subarray(half);
  return sequence(integerBigEndian(r), integerBigEndian(s));
}

// ---- Certificate builder -----------------------------------------

export interface BuildCertInput {
  serial: number;
  issuerName: Uint8Array;
  subjectName: Uint8Array;
  notBefore: Date;
  notAfter: Date;
  /** SPKI DER of the subject public key (what the cert asserts). */
  subjectSpki: Uint8Array;
  /** Extra extensions to embed (each already the full
 * SEQUENCE Extension DER). */
  extensions?: Uint8Array[];
  /** Private key of the issuer (signs the TBS). */
  issuerPrivateKey: CryptoKey;
  /**
 * Signature algorithm used by the issuer. Determines both the OID
 * written into signatureAlgorithm + tbsCertificate.signature and
 * the WebCrypto `sign` call. Defaults to ECDSA P-256 SHA-256 to
 * keep existing callers unchanged.
   */
  issuerSignatureAlgorithm?: SigAlgorithm;
}

export async function buildCertificate(input: BuildCertInput): Promise<Uint8Array> {
  const algorithm: SigAlgorithm = input.issuerSignatureAlgorithm ?? "ECDSA_P256_SHA256";
  const sigAlgOid = algorithm === "ECDSA_P256_SHA256"
    ? OID_ECDSA_WITH_SHA256
    : OID_SHA256_WITH_RSA_ENCRYPTION;
 // RFC 5280 section 4.1.1.2: for rsaEncryption-family signature
 // algorithms the AlgorithmIdentifier parameters field MUST be
 // present and encoded as NULL. ECDSA variants omit the parameters
 // field entirely. Emit the shape the real Google roots use so the
 // synthetic cert round-trips through the parser identically.
  const sigAlgSequence = algorithm === "ECDSA_P256_SHA256"
    ? sequence(oid(sigAlgOid))
    : sequence(oid(sigAlgOid), tlv(0x05, new Uint8Array(0)));

  const validity = sequence(
    generalizedTime(input.notBefore),
    generalizedTime(input.notAfter),
  );

  const tbsItems: Uint8Array[] = [
 // [0] EXPLICIT version v3 (INTEGER 2)
    explicitTag(0, integerU8(2)),
    integerU8(input.serial),
    sigAlgSequence,
    input.issuerName,
    validity,
    input.subjectName,
    input.subjectSpki,
  ];
  if (input.extensions !== undefined && input.extensions.length > 0) {
 // [3] EXPLICIT extensions SEQUENCE OF Extension
    tbsItems.push(explicitTag(3, sequence(...input.extensions)));
  }
  const tbs = sequence(...tbsItems);

  const signatureBytes = algorithm === "ECDSA_P256_SHA256"
    ? await signTbsEcdsaP256Sha256(tbs, input.issuerPrivateKey)
    : await signTbsRsaPkcs1Sha256(tbs, input.issuerPrivateKey);
  return sequence(tbs, sigAlgSequence, bitString(signatureBytes));
}

/** Build a single Extension = SEQUENCE { OID, extnValue OCTET STRING }. */
export function extension(oidDotted: string, extnValue: Uint8Array): Uint8Array {
  return sequence(oid(oidDotted), octetString(extnValue));
}

// ---- KeyDescription builder (for the leaf extension) -------------

interface RootOfTrustInput {
  verifiedBootKey: Uint8Array;
  deviceLocked: boolean;
  verifiedBootState: number;
  verifiedBootHash: Uint8Array;
}

interface AuthListInput {
  rootOfTrust?: RootOfTrustInput;
  attestationApplicationId?: Uint8Array;
}

export interface KeyDescriptionInput {
  attestationVersion: number;
  attestationSecurityLevel: number;
  keymasterVersion: number;
  keymasterSecurityLevel: number;
  attestationChallenge: Uint8Array;
  uniqueId?: Uint8Array;
  softwareEnforced: AuthListInput;
  hardwareEnforced: AuthListInput;
}

function buildRootOfTrust(input: RootOfTrustInput): Uint8Array {
  return sequence(
    octetString(input.verifiedBootKey),
    boolean(input.deviceLocked),
    enumerated(input.verifiedBootState),
    octetString(input.verifiedBootHash),
  );
}

function longFormConstructed(tagNumber: number, content: Uint8Array): Uint8Array {
  const highBits = encodeBase128(tagNumber);
  const header = new Uint8Array([0xbf, ...highBits]);
  return concatWithLength(header, content);
}

function longFormPrimitive(tagNumber: number, content: Uint8Array): Uint8Array {
  const highBits = encodeBase128(tagNumber);
  const header = new Uint8Array([0x9f, ...highBits]);
  return concatWithLength(header, content);
}

function concatWithLength(header: Uint8Array, content: Uint8Array): Uint8Array {
  let lengthBytes: number[];
  if (content.length < 0x80) {
    lengthBytes = [content.length];
  } else if (content.length < 0x100) {
    lengthBytes = [0x81, content.length];
  } else {
    lengthBytes = [0x82, (content.length >> 8) & 0xff, content.length & 0xff];
  }
  const out = new Uint8Array(header.length + lengthBytes.length + content.length);
  out.set(header, 0);
  out.set(lengthBytes, header.length);
  out.set(content, header.length + lengthBytes.length);
  return out;
}

function encodeBase128(value: number): number[] {
  if (value < 0x80) return [value];
  const out: number[] = [];
  let remaining = value;
  while (remaining > 0) {
    out.unshift((remaining & 0x7f) | 0x80);
    remaining >>= 7;
  }
  out[out.length - 1]! &= 0x7f;
  return out;
}

function buildAuthorizationList(input: AuthListInput): Uint8Array {
  const parts: Uint8Array[] = [];
  if (input.rootOfTrust !== undefined) {
    parts.push(longFormConstructed(704, buildRootOfTrust(input.rootOfTrust)));
  }
  if (input.attestationApplicationId !== undefined) {
    parts.push(longFormPrimitive(709, input.attestationApplicationId));
  }
  return sequence(...parts);
}

export function buildKeyDescription(input: KeyDescriptionInput): Uint8Array {
  return sequence(
    integerU8(input.attestationVersion),
    enumerated(input.attestationSecurityLevel),
    integerU8(input.keymasterVersion),
    enumerated(input.keymasterSecurityLevel),
    octetString(input.attestationChallenge),
    octetString(input.uniqueId ?? new Uint8Array(0)),
    buildAuthorizationList(input.softwareEnforced),
    buildAuthorizationList(input.hardwareEnforced),
  );
}

// ---- Full three-cert chain convenience --------------------------

export interface SyntheticChain {
  rootDer: Uint8Array;
  intermediateDer: Uint8Array;
  leafDer: Uint8Array;
  /** Leaf-first chain (what verifyKeyAttestation expects). */
  chainDer: Uint8Array[];
  /** Root private key, retained for diagnostics. */
  rootPrivateKey: CryptoKey;
}

export interface BuildChainInput {
  /** Attestation challenge issued by the gateway. */
  attestationChallenge: Uint8Array;
  /** KeyDescription payload to embed in the leaf. */
  keyDescription: KeyDescriptionInput;
  /** CN of the root cert. Default "Test Attestation Root". */
  rootCommonName?: string;
  /** notBefore for every cert. Default now minus 1 hour. */
  notBefore?: Date;
  /** notAfter for every cert. Default now plus 24 hours. */
  notAfter?: Date;
  /**
 * Signature algorithm the root uses to self-sign + to sign the
 * intermediate. Default "ECDSA_P256_SHA256" keeps the existing test
 * behaviour; callers pass "RSA_PKCS1_SHA256" to exercise the
 * RSA path through `verifyCertificateSignature` + `verifyChainToRoot`.
   */
  rootSignatureAlgorithm?: SigAlgorithm;
}

export async function buildSyntheticChain(
  input: BuildChainInput,
): Promise<SyntheticChain> {
  const now = Date.now();
  const notBefore = input.notBefore ?? new Date(now - 60 * 60 * 1000);
  const notAfter = input.notAfter ?? new Date(now + 24 * 60 * 60 * 1000);
  const rootCn = input.rootCommonName ?? "Test Attestation Root";
  const rootSigAlgorithm: SigAlgorithm = input.rootSignatureAlgorithm ?? "ECDSA_P256_SHA256";

  const rootKey = await generateKeyPairOfAlgorithm(rootSigAlgorithm);
 // Intermediate + leaf keys stay on ECDSA P-256 regardless of root
 // algorithm. Real Google RSA-rooted chains put EC leaves under an
 // RSA issuer; the interesting exercise for is that the root's
 // self-signature and the intermediate's outer signature both route
 // through the RSA branch of `verifyCertificateSignature`.
  const intKey = await generateEcP256KeyPair();
  const leafKey = await generateEcP256KeyPair();

  const rootName = singleCnName(rootCn);
  const intName = singleCnName("Test Intermediate");
  const leafName = singleCnName("Test Leaf");

  const rootDer = await buildCertificate({
    serial: 1,
    issuerName: rootName,
    subjectName: rootName,
    notBefore,
    notAfter,
    subjectSpki: rootKey.spkiDer,
    issuerPrivateKey: rootKey.privateKey,
    issuerSignatureAlgorithm: rootSigAlgorithm,
  });

  const intDer = await buildCertificate({
    serial: 2,
    issuerName: rootName,
    subjectName: intName,
    notBefore,
    notAfter,
    subjectSpki: intKey.spkiDer,
    issuerPrivateKey: rootKey.privateKey,
    issuerSignatureAlgorithm: rootSigAlgorithm,
  });

  const extnValue = buildKeyDescription(input.keyDescription);
  const leafExt = extension(OID_KEY_ATTESTATION, extnValue);
  const leafDer = await buildCertificate({
    serial: 3,
    issuerName: intName,
    subjectName: leafName,
    notBefore,
    notAfter,
    subjectSpki: leafKey.spkiDer,
    extensions: [leafExt],
    issuerPrivateKey: intKey.privateKey,
 // Leaf is always signed by the intermediate, which is always EC.
    issuerSignatureAlgorithm: "ECDSA_P256_SHA256",
  });

  return {
    rootDer,
    intermediateDer: intDer,
    leafDer,
    chainDer: [leafDer, intDer, rootDer],
    rootPrivateKey: rootKey.privateKey,
  };
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}
