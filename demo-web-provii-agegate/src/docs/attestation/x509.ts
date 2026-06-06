// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Minimal X.509 chain validation for Apple App Attest (.0).
 *
 * Scope of this file: parse enough of a DER-encoded X.509 certificate
 * to extract the `tbsCertificate`, the signature algorithm OID, the
 * signature value, the issuer + subject DNs, and the Subject Public
 * Key Info. That is the minimum needed to verify "this cert was
 * signed by that cert's key" and to walk a chain leaf -> root.
 *
 * What this file does NOT do (deliberately, for the spike):
 * - Extension parsing beyond a validity check. Apple App Attest
 * receipts carry custom extensions (1.2.840.113635.100.8.2 for
 * the nonce, and AAGUID/credential-id in the CBOR attestation
 * object, not the cert). .7 will wire those in.
 * - Revocation (CRL/OCSP). Apple publishes no CRL for this CA.
 * - Name constraints. The root has none.
 * - General-purpose path building. We verify a linear chain.
 *
 * The Apple App Attest Root CA is pinned as a base64-encoded DER
 * constant below. Source:
 * https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
 * SHA-256 fingerprint (captured 2026-04-15):
 * 1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:
 * 4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32
 * notBefore: 2020-03-18T18:32:53Z, notAfter: 2045-03-15T00:00:00Z
 * Signature algorithm: ecdsa-with-SHA384 (OID 1.2.840.10045.4.3.3)
 * Subject public key: secp384r1 (P-384).
 */

// ---- Apple root, pinned --------------------------------------------
//
// Regenerate with:
// curl -s https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem \
// | openssl x509 -outform DER | base64 | tr -d '\n'
export const APPLE_APP_ATTEST_ROOT_CA_DER_BASE64 =
  "MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw"
  + "JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK"
  + "QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa"
  + "Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv"
  + "biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y"
  + "bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh"
  + "NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au"
  + "Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/"
  + "MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw"
  + "CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn"
  + "53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV"
  + "oyFraWVIyd/dganmrduC1bmTBGwD";

/** SHA-256 fingerprint of the pinned root, lowercase hex, no colons. */
export const APPLE_APP_ATTEST_ROOT_CA_FINGERPRINT_SHA256 =
  "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932";

// ---- ASN.1 DER minimal parser --------------------------------------

interface TlvRef {
  /** The raw tag octet. */
  tag: number;
  /** Offset of the content in the input buffer. */
  contentOffset: number;
  /** Length of the content in bytes. */
  contentLength: number;
  /** Offset of the tag octet. Useful for capturing the full TLV region. */
  tlvOffset: number;
  /** Total length of the TLV (tag + length-of-length + length + content). */
  tlvLength: number;
}

function readTlv(buffer: Uint8Array, offset: number): TlvRef {
  if (offset >= buffer.length) {
    throw new Error("ASN.1: read past end of buffer");
  }
  const tag = buffer[offset]!;
  let cursor = offset + 1;
  if (cursor >= buffer.length) {
    throw new Error("ASN.1: truncated length octet");
  }
  const first = buffer[cursor]!;
  cursor += 1;
  let length: number;
  if ((first & 0x80) === 0) {
    length = first;
  } else {
    const lengthOctets = first & 0x7f;
    if (lengthOctets === 0 || lengthOctets > 4) {
      throw new Error("ASN.1: unsupported length encoding");
    }
    length = 0;
    for (let i = 0; i < lengthOctets; i++) {
      if (cursor >= buffer.length) {
        throw new Error("ASN.1: truncated length");
      }
      length = (length << 8) | buffer[cursor]!;
      cursor += 1;
    }
  }
  if (cursor + length > buffer.length) {
    throw new Error("ASN.1: content exceeds buffer");
  }
  return {
    tag,
    contentOffset: cursor,
    contentLength: length,
    tlvOffset: offset,
    tlvLength: cursor + length - offset,
  };
}

/** Iterate direct children of a SEQUENCE/SET at `ref`. */
function children(buffer: Uint8Array, ref: TlvRef): TlvRef[] {
  const out: TlvRef[] = [];
  let cursor = ref.contentOffset;
  const end = ref.contentOffset + ref.contentLength;
  while (cursor < end) {
    const child = readTlv(buffer, cursor);
    out.push(child);
    cursor += child.tlvLength;
  }
  return out;
}

function slice(buffer: Uint8Array, ref: TlvRef): Uint8Array {
  return buffer.subarray(ref.contentOffset, ref.contentOffset + ref.contentLength);
}

function tlvSlice(buffer: Uint8Array, ref: TlvRef): Uint8Array {
  return buffer.subarray(ref.tlvOffset, ref.tlvOffset + ref.tlvLength);
}

function decodeOid(buffer: Uint8Array, ref: TlvRef): string {
  if (ref.tag !== 0x06) throw new Error("ASN.1: expected OID tag");
  const data = slice(buffer, ref);
  if (data.length === 0) throw new Error("ASN.1: empty OID");
  const first = data[0]!;
  const parts: number[] = [Math.floor(first / 40), first % 40];
  let acc = 0;
  for (let i = 1; i < data.length; i++) {
    const byte = data[i]!;
    acc = (acc << 7) | (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(acc);
      acc = 0;
    }
  }
  return parts.join(".");
}

// ---- Certificate parsing -------------------------------------------

export interface ParsedCertificate {
  /** Full DER buffer. */
  raw: Uint8Array;
  /** The TBS (to-be-signed) region, these are the octets the signature covers. */
  tbs: Uint8Array;
  /** DER octets of the issuer Name. */
  issuerDer: Uint8Array;
  /** DER octets of the subject Name. */
  subjectDer: Uint8Array;
  /** DER octets of the SubjectPublicKeyInfo. */
  spkiDer: Uint8Array;
  /** OID of the outer signatureAlgorithm. */
  signatureAlgorithmOid: string;
  /** Raw signatureValue bits (without the BIT STRING unused-bits prefix). */
  signatureBytes: Uint8Array;
  /** Subject public key algorithm OID (`spki.algorithm.algorithm`). */
  publicKeyAlgorithmOid: string;
  /** Named curve OID for ECDSA keys, if present. */
  publicKeyCurveOid: string | null;
  /**
 * Parsed validity.notBefore / notAfter as epoch milliseconds. UTCTime and
 * GeneralizedTime both supported. Used to reject chains that were valid
 * at one point but have since expired. Apple App Attest receipts carry
 * a short-lived leaf with a matching notBefore/notAfter pair that we
 * compare against the nonce freshness window.
   */
  notBeforeMs: number;
  notAfterMs: number;
  /**
 * Map of extension OID to raw extnValue octets (the OCTET STRING content,
 * not the OCTET STRING TLV). Used to pull the Apple App Attest nonce
 * extension (1.2.840.113635.100.8.2) and the Google Hardware Attestation
 * extension (1.3.6.1.4.1.11129.2.1.17) out of the leaf cert.
   */
  extensions: Map<string, Uint8Array>;
}

/**
 * Parse a DER-encoded X.509 certificate into the fields required for
 * chain validation. Throws on structural errors. Does not interpret
 * extensions or validity dates beyond the chain walk.
 */
export function parseCertificate(der: Uint8Array): ParsedCertificate {
  const root = readTlv(der, 0);
  if (root.tag !== 0x30) throw new Error("X.509: expected outer SEQUENCE");

  const [tbsRef, sigAlgRef, sigValueRef, ...rest] = children(der, root);
  if (!tbsRef || !sigAlgRef || !sigValueRef || rest.length !== 0) {
    throw new Error("X.509: malformed certificate top-level");
  }

 // tbsCertificate layout:
 // [0] version (optional, EXPLICIT)
 // serialNumber, signature (AlgorithmIdentifier),
 // issuer (Name), validity (SEQUENCE), subject (Name),
 // subjectPublicKeyInfo, ... (extensions etc.)
  if (tbsRef.tag !== 0x30) throw new Error("X.509: tbsCertificate not SEQUENCE");
  const tbsChildren = children(der, tbsRef);
  let cursor = 0;
 // Optional [0] EXPLICIT version
  if (tbsChildren[cursor]?.tag === 0xa0) cursor += 1;
  const serialRef = tbsChildren[cursor++];
  const innerSigAlgRef = tbsChildren[cursor++];
  const issuerRef = tbsChildren[cursor++];
  const validityRef = tbsChildren[cursor++];
  const subjectRef = tbsChildren[cursor++];
  const spkiRef = tbsChildren[cursor++];
  if (!serialRef || !innerSigAlgRef || !issuerRef || !validityRef
    || !subjectRef || !spkiRef) {
    throw new Error("X.509: tbs missing required fields");
  }
 // Remaining children: optional issuerUniqueId [1], subjectUniqueId [2],
 // and extensions [3]. Only extensions matter for attestation parsing.
  let extensionsRef: TlvRef | null = null;
  for (let i = cursor; i < tbsChildren.length; i++) {
    const tail = tbsChildren[i]!;
    if (tail.tag === 0xa3) {
      extensionsRef = tail;
      break;
    }
  }

 // signatureAlgorithm (outer) is the one WebCrypto uses.
  const sigAlgChildren = children(der, sigAlgRef);
  const sigAlgOidRef = sigAlgChildren[0];
  if (!sigAlgOidRef) throw new Error("X.509: signatureAlgorithm missing OID");
  const signatureAlgorithmOid = decodeOid(der, sigAlgOidRef);

 // signatureValue is a BIT STRING: the first content byte is the
 // unused-bits count, which must be 0 for ECDSA/RSA signatures.
  if (sigValueRef.tag !== 0x03) {
    throw new Error("X.509: signatureValue not BIT STRING");
  }
  const sigContent = slice(der, sigValueRef);
  if (sigContent.length === 0 || sigContent[0] !== 0x00) {
    throw new Error("X.509: unexpected BIT STRING unused-bits value");
  }
  const signatureBytes = sigContent.subarray(1);

 // Subject Public Key Info inner decomposition.
  const spkiChildren = children(der, spkiRef);
  const spkiAlgRef = spkiChildren[0];
  if (!spkiAlgRef) throw new Error("X.509: SPKI missing algorithm");
  const spkiAlgChildren = children(der, spkiAlgRef);
  const spkiOidRef = spkiAlgChildren[0];
  if (!spkiOidRef) throw new Error("X.509: SPKI algorithm missing OID");
  const publicKeyAlgorithmOid = decodeOid(der, spkiOidRef);
  const publicKeyCurveOid = spkiAlgChildren[1]?.tag === 0x06
    ? decodeOid(der, spkiAlgChildren[1])
    : null;

 // Validity = SEQUENCE { notBefore Time, notAfter Time }
  const validityChildren = children(der, validityRef);
  if (validityChildren.length !== 2) {
    throw new Error("X.509: validity must contain exactly 2 entries");
  }
  const notBeforeMs = parseAsn1Time(der, validityChildren[0]!);
  const notAfterMs = parseAsn1Time(der, validityChildren[1]!);

  const extensions = extensionsRef !== null
    ? parseExtensions(der, extensionsRef)
    : new Map<string, Uint8Array>();

  return {
    raw: der,
    tbs: tlvSlice(der, tbsRef),
    issuerDer: tlvSlice(der, issuerRef),
    subjectDer: tlvSlice(der, subjectRef),
    spkiDer: tlvSlice(der, spkiRef),
    signatureAlgorithmOid,
    signatureBytes,
    publicKeyAlgorithmOid,
    publicKeyCurveOid,
    notBeforeMs,
    notAfterMs,
    extensions,
  };
}

/**
 * Parse the `extensions [3] EXPLICIT SEQUENCE OF Extension` block into
 * a map keyed by the extension OID. Duplicates are rejected per RFC 5280
 * because the Apple and Google attestation extensions MUST appear once.
 */
function parseExtensions(der: Uint8Array, tagged: TlvRef): Map<string, Uint8Array> {
 // Inside the [3] tag is a SEQUENCE of Extension.
  const inner = readTlv(der, tagged.contentOffset);
  if (inner.tag !== 0x30) {
    throw new Error("X.509: extensions container is not SEQUENCE");
  }
  const out = new Map<string, Uint8Array>();
  for (const ext of children(der, inner)) {
    if (ext.tag !== 0x30) {
      throw new Error("X.509: extension entry is not SEQUENCE");
    }
    const extChildren = children(der, ext);
    if (extChildren.length < 2 || extChildren.length > 3) {
      throw new Error("X.509: malformed Extension");
    }
    const oidRef = extChildren[0]!;
    const oid = decodeOid(der, oidRef);
 // Extension = SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
 // extnValue OCTET STRING }
    const valueRef = extChildren.length === 3 ? extChildren[2]! : extChildren[1]!;
    if (valueRef.tag !== 0x04) {
      throw new Error(`X.509: extension ${oid} extnValue not OCTET STRING`);
    }
    if (out.has(oid)) {
      throw new Error(`X.509: extension ${oid} appears more than once`);
    }
    out.set(oid, slice(der, valueRef));
  }
  return out;
}

/**
 * Parse an ASN.1 Time (UTCTime, tag 0x17, or GeneralizedTime, tag 0x18)
 * into epoch milliseconds. Both encodings are ASCII with fixed field
 * widths per RFC 5280 section 4.1.2.5.
 */
function parseAsn1Time(der: Uint8Array, tlv: TlvRef): number {
  const content = slice(der, tlv);
  const text = new TextDecoder("ascii").decode(content);
  if (tlv.tag === 0x17) {
 // UTCTime: YYMMDDHHMMSSZ. RFC 5280 requires the Z form.
    if (text.length !== 13 || text[12] !== "Z") {
      throw new Error("X.509: malformed UTCTime");
    }
    const yy = parseInt(text.slice(0, 2), 10);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return Date.UTC(
      year,
      parseInt(text.slice(2, 4), 10) - 1,
      parseInt(text.slice(4, 6), 10),
      parseInt(text.slice(6, 8), 10),
      parseInt(text.slice(8, 10), 10),
      parseInt(text.slice(10, 12), 10),
    );
  }
  if (tlv.tag === 0x18) {
 // GeneralizedTime: YYYYMMDDHHMMSSZ (no fractional seconds in X.509).
    if (text.length !== 15 || text[14] !== "Z") {
      throw new Error("X.509: malformed GeneralizedTime");
    }
    return Date.UTC(
      parseInt(text.slice(0, 4), 10),
      parseInt(text.slice(4, 6), 10) - 1,
      parseInt(text.slice(6, 8), 10),
      parseInt(text.slice(8, 10), 10),
      parseInt(text.slice(10, 12), 10),
      parseInt(text.slice(12, 14), 10),
    );
  }
  throw new Error(`X.509: unsupported time tag 0x${tlv.tag.toString(16)}`);
}

// ---- Signature verification ----------------------------------------

// ecdsa-with-SHA256 / -SHA384 / -SHA512
const OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
const OID_ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3";
const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_P256 = "1.2.840.10045.3.1.7";
const OID_P384 = "1.3.132.0.34";
// sha256WithRSAEncryption per RFC 8017 appendix A.2.4 / Google's
// Hardware Attestation RSA-4096 batch root uses this signature
// algorithm in its TBS. Only the SHA-256 variant is supported; SHA-1
// RSA (1.2.840.113549.1.1.5) is deliberately absent because accepting
// it would be a downgrade.
const OID_SHA256_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.11";
/** rsaEncryption OID used in the SPKI of an RSA key. */
const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

/**
 * Verify that `child.signatureBytes` over `child.tbs` was produced
 * by the key in `signerSpki`. Supports:
 * - ECDSA P-256 / SHA-256 (Apple App Attest intermediates + leaves)
 * - ECDSA P-384 / SHA-384 (Apple App Attest root, Google Hardware
 * Attestation EC P-384 "Key Attestation CA1")
 * - RSASSA-PKCS1-v1_5 / SHA-256 (Google Hardware Attestation RSA
 * 4096 root + older RSA-rooted device chains issued before the
 * 2026-02-01 EC rotation)
 */
export async function verifyCertificateSignature(
  child: ParsedCertificate,
  signerSpki: Uint8Array,
  signerCurveOid: string | null,
): Promise<boolean> {
  switch (child.signatureAlgorithmOid) {
    case OID_ECDSA_WITH_SHA256:
    case OID_ECDSA_WITH_SHA384: {
      const hash = child.signatureAlgorithmOid === OID_ECDSA_WITH_SHA256
        ? "SHA-256"
        : "SHA-384";
      const namedCurve = resolveCurve(signerCurveOid);
      const cryptoKey = await crypto.subtle.importKey(
        "spki",
        signerSpki,
        { name: "ECDSA", namedCurve },
        false,
        ["verify"],
      );
      const rawSig = convertEcdsaDerToRaw(child.signatureBytes, namedCurve);
      return crypto.subtle.verify(
        { name: "ECDSA", hash },
        cryptoKey,
        rawSig,
        child.tbs,
      );
    }
    case OID_SHA256_WITH_RSA_ENCRYPTION: {
      const cryptoKey = await crypto.subtle.importKey(
        "spki",
        signerSpki,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );
 // RSA PKCS#1 v1.5 signatures are emitted as a raw byte string in
 // the BIT STRING, not an ASN.1 SEQUENCE. No DER-to-raw conversion.
      return crypto.subtle.verify(
        { name: "RSASSA-PKCS1-v1_5" },
        cryptoKey,
        child.signatureBytes,
        child.tbs,
      );
    }
    default:
      throw new Error(
        `X.509: unsupported signature algorithm ${child.signatureAlgorithmOid}`,
      );
  }
}

function resolveCurve(oid: string | null): "P-256" | "P-384" {
  if (oid === OID_P256) return "P-256";
  if (oid === OID_P384) return "P-384";
  throw new Error(`X.509: unsupported curve OID ${oid}`);
}

/**
 * WebCrypto ECDSA.verify expects the signature as raw `R || S`
 * left-padded to the curve's field size. X.509 serialises ECDSA
 * signatures as an ASN.1 SEQUENCE { INTEGER r, INTEGER s }. This
 * helper strips the DER framing and re-emits the fixed-width form.
 */
function convertEcdsaDerToRaw(
  derSig: Uint8Array,
  curve: "P-256" | "P-384",
): Uint8Array {
  const fieldSize = curve === "P-256" ? 32 : 48;
  const seq = readTlv(derSig, 0);
  if (seq.tag !== 0x30) throw new Error("X.509: ECDSA sig not SEQUENCE");
  const [rRef, sRef] = children(derSig, seq);
  if (!rRef || !sRef) throw new Error("X.509: ECDSA sig missing r/s");
  return new Uint8Array([
    ...normaliseEcdsaInteger(slice(derSig, rRef), fieldSize),
    ...normaliseEcdsaInteger(slice(derSig, sRef), fieldSize),
  ]);
}

function normaliseEcdsaInteger(value: Uint8Array, size: number): Uint8Array {
  let start = 0;
 // DER INTEGER can have a leading 0x00 to indicate a positive
 // sign on a value with the high bit set; drop it for the raw form.
  while (start < value.length - 1 && value[start] === 0x00) start += 1;
  const trimmed = value.subarray(start);
  if (trimmed.length > size) {
    throw new Error("X.509: ECDSA integer exceeds curve field size");
  }
  const out = new Uint8Array(size);
  out.set(trimmed, size - trimmed.length);
  return out;
}

// ---- Chain walk ----------------------------------------------------

/**
 * Compare two DER-encoded Name octet strings bytewise. Apple's chain
 * uses the same DN encoding for issuer-of-child and subject-of-parent
 * so a byte comparison matches what RFC 5280 calls "binary compare".
 */
function derEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Walk a linear chain from `leaf` through `intermediates` to `root`.
 * Verifies each child's signature against the next certificate's key
 * and checks the subject/issuer DN chain links. The root's signature
 * is verified against itself as a smoke test.
 *
 * `atMs` is the instant to check validity against; every cert on the
 * chain must satisfy `notBefore <= atMs <= notAfter`. Callers pass
 * `now` for real verification and a fixed timestamp for test vectors.
 */
export async function verifyChainToRoot(
  leaf: ParsedCertificate,
  intermediates: ParsedCertificate[],
  root: ParsedCertificate,
  atMs: number = Date.now(),
): Promise<void> {
  const chain = [leaf, ...intermediates, root];
  for (let i = 0; i < chain.length - 1; i++) {
    const child = chain[i]!;
    const parent = chain[i + 1]!;
    if (!derEqual(child.issuerDer, parent.subjectDer)) {
      throw new Error(`X.509: chain break at index ${i}: issuer != parent.subject`);
    }
    if (atMs < child.notBeforeMs || atMs > child.notAfterMs) {
      throw new Error(`X.509: cert at index ${i} is outside its validity window`);
    }
    const ok = await verifyCertificateSignature(
      child,
      parent.spkiDer,
      parent.publicKeyCurveOid,
    );
    if (!ok) {
      throw new Error(`X.509: signature verify failed at chain index ${i}`);
    }
  }
 // Self-signature on the root.
  if (atMs < root.notBeforeMs || atMs > root.notAfterMs) {
    throw new Error("X.509: root outside its validity window");
  }
  const rootOk = await verifyCertificateSignature(
    root,
    root.spkiDer,
    root.publicKeyCurveOid,
  );
  if (!rootOk) throw new Error("X.509: root self-signature failed");

 // The caller is expected to have confirmed that `root` is the
 // pinned trust anchor (Apple App Attest root OR one of the Google
 // Hardware Attestation roots). We don't trust `root` just because
 // it's self-signed. Either EC (P-256/P-384) or RSA is acceptable;
 // the Google Hardware Attestation set contains both an EC P-384
 // "Key Attestation CA1" and an RSA-4096 batch root and real device
 // chains terminate in one of them depending on provisioning vintage.
  if (
    root.publicKeyAlgorithmOid !== OID_EC_PUBLIC_KEY
    && root.publicKeyAlgorithmOid !== OID_RSA_ENCRYPTION
  ) {
    throw new Error(
      `X.509: root public key algorithm ${root.publicKeyAlgorithmOid} is not EC or RSA`,
    );
  }
}

// ---- Pinned root access --------------------------------------------

let cachedPinnedRoot: ParsedCertificate | null = null;

/**
 * Parse the pinned Apple App Attest Root CA once per isolate and
 * return the cached `ParsedCertificate`. Fingerprint is re-checked
 * on first use so any accidental edit to the base64 blob surfaces
 * as a loud failure rather than a silent trust-anchor swap.
 */
export async function getPinnedAppleRoot(): Promise<ParsedCertificate> {
  if (cachedPinnedRoot) return cachedPinnedRoot;
  const der = base64ToBytes(APPLE_APP_ATTEST_ROOT_CA_DER_BASE64);
  const digest = await crypto.subtle.digest("SHA-256", der);
  const hex = bytesToHex(new Uint8Array(digest));
  if (hex !== APPLE_APP_ATTEST_ROOT_CA_FINGERPRINT_SHA256) {
    throw new Error(
      `X.509: pinned Apple root fingerprint mismatch (got ${hex})`,
    );
  }
  cachedPinnedRoot = parseCertificate(der);
  return cachedPinnedRoot;
}

/** Test-only: clear the parsed-root cache so fingerprint failure modes can be exercised. */
export function __resetPinnedRootCacheForTests(): void {
  cachedPinnedRoot = null;
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}
