// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Shared ASN.1 DER primitives for the attestation verifiers.
 *
 * Extracted from the .0 inlined parser in `x509.ts` so
 * `app-attest.ts` and `key-attestation.ts` can both reach into tagged
 * extensions, OCTET STRING wrappers, and SET-OF structures without
 * re-implementing the tag/length/content walker. The certificate-level
 * parser in `x509.ts` continues to own its own specialised walk for
 * the top-level TBS shape; everything below the TBS that extension
 * blobs need is in here.
 *
 * Scope:
 * - Fixed-length (definite) TLVs only. Constructed indefinite-length
 * encodings are illegal in DER so rejecting them is the spec-correct
 * thing to do.
 * - Up to 4-byte length encodings. No extension fits inside a
 * certificate bigger than 2^32 bytes, so 5+ byte length octets
 * mean a malformed input.
 * - Parses the common primitives: INTEGER, BOOLEAN, OCTET STRING,
 * BIT STRING, NULL, OID, UTF8String / PrintableString / IA5String,
 * SEQUENCE, SET, plus context-specific tags [n] IMPLICIT/EXPLICIT.
 */

export interface Tlv {
  /**
 * The raw first tag octet (class + P/C + tag-number-or-marker).
 * Use `decodedTagNumber` for the resolved tag number when a
 * high-tag-number form is present (bits 0-4 of `tag` all set).
   */
  tag: number;
  /**
 * Decoded tag number. Matches `tag & 0x1f` for short-form tags and
 * carries the base-128 decoded number for high-tag-number forms
 * (> 30). Android Key Attestation extensions routinely use tag
 * numbers like 704 and 709 that only fit in the long form.
   */
  decodedTagNumber: number;
  /** Offset of the content octets in the underlying buffer. */
  contentOffset: number;
  /** Length of the content in bytes. */
  contentLength: number;
  /** Offset of the first byte of the TLV (the tag octet). */
  tlvOffset: number;
  /** Full TLV length: tag + length-of-length + length + content. */
  tlvLength: number;
}

/** ASN.1 universal tag numbers we care about. */
export const TAG_BOOLEAN = 0x01;
export const TAG_INTEGER = 0x02;
export const TAG_BIT_STRING = 0x03;
export const TAG_OCTET_STRING = 0x04;
export const TAG_NULL = 0x05;
export const TAG_OID = 0x06;
export const TAG_UTF8_STRING = 0x0c;
export const TAG_SEQUENCE = 0x30;
export const TAG_SET = 0x31;
export const TAG_PRINTABLE_STRING = 0x13;
export const TAG_IA5_STRING = 0x16;
export const TAG_ENUMERATED = 0x0a;

/** Helpers for context-specific tags `[n]`. */
export function contextTag(n: number, constructed: boolean): number {
  return 0x80 | (constructed ? 0x20 : 0x00) | n;
}

/** Read the TLV starting at `offset`. Supports high-tag-number form. */
export function readTlv(bytes: Uint8Array, offset: number): Tlv {
  if (offset >= bytes.length) {
    throw new Error("ASN.1: read past end of buffer");
  }
  const tag = bytes[offset]!;
  let cursor = offset + 1;

 // High-tag-number form: bits 0-4 of the first octet all set.
 // Subsequent octets carry the tag number in base-128 big-endian;
 // continuation bit on all but the final octet.
  let decodedTagNumber = tag & 0x1f;
  if (decodedTagNumber === 0x1f) {
    decodedTagNumber = 0;
    for (;;) {
      if (cursor >= bytes.length) {
        throw new Error("ASN.1: truncated high-tag-number");
      }
      const tagByte = bytes[cursor]!;
      cursor += 1;
      decodedTagNumber = (decodedTagNumber << 7) | (tagByte & 0x7f);
      if ((tagByte & 0x80) === 0) break;
      if (decodedTagNumber > 0x0fff_ffff) {
        throw new Error("ASN.1: high-tag-number out of range");
      }
    }
  }

  if (cursor >= bytes.length) {
    throw new Error("ASN.1: truncated length octet");
  }
  const first = bytes[cursor]!;
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
      if (cursor >= bytes.length) {
        throw new Error("ASN.1: truncated length");
      }
      length = (length << 8) | bytes[cursor]!;
      cursor += 1;
    }
  }
  if (cursor + length > bytes.length) {
    throw new Error("ASN.1: content exceeds buffer");
  }
  return {
    tag,
    decodedTagNumber,
    contentOffset: cursor,
    contentLength: length,
    tlvOffset: offset,
    tlvLength: cursor + length - offset,
  };
}

/** Return the content bytes of `tlv` as a view over `bytes`. */
export function content(bytes: Uint8Array, tlv: Tlv): Uint8Array {
  return bytes.subarray(tlv.contentOffset, tlv.contentOffset + tlv.contentLength);
}

/** Return the full TLV octets (tag + length + content). */
export function fullTlv(bytes: Uint8Array, tlv: Tlv): Uint8Array {
  return bytes.subarray(tlv.tlvOffset, tlv.tlvOffset + tlv.tlvLength);
}

/** Walk direct children of a constructed TLV (SEQUENCE/SET/[n] EXPLICIT). */
export function children(bytes: Uint8Array, tlv: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let cursor = tlv.contentOffset;
  const end = tlv.contentOffset + tlv.contentLength;
  while (cursor < end) {
    const child = readTlv(bytes, cursor);
    out.push(child);
    cursor += child.tlvLength;
  }
  return out;
}

/** Decode an OID from its content bytes into dotted decimal form. */
export function decodeOid(bytes: Uint8Array, tlv: Tlv): string {
  if (tlv.tag !== TAG_OID) throw new Error("ASN.1: expected OID tag");
  const data = content(bytes, tlv);
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

/** Decode an INTEGER into a JS number. Throws if it exceeds safe range. */
export function decodeInteger(bytes: Uint8Array, tlv: Tlv): number {
  if (tlv.tag !== TAG_INTEGER) {
    throw new Error("ASN.1: expected INTEGER");
  }
  const data = content(bytes, tlv);
  if (data.length === 0) throw new Error("ASN.1: empty INTEGER");
 // DER INTEGER is big-endian two's complement. The values we read from
 // Android Key Attestation are all small non-negative enum codes, so
 // anything bigger than 6 bytes is unexpected.
  if (data.length > 6) {
    throw new Error("ASN.1: INTEGER exceeds safe-integer range");
  }
  let acc = 0;
 // Preserve sign bit.
  const negative = (data[0]! & 0x80) !== 0;
  for (let i = 0; i < data.length; i++) {
    acc = acc * 256 + data[i]!;
  }
  if (negative) {
    acc = acc - Math.pow(2, data.length * 8);
  }
  if (!Number.isSafeInteger(acc)) {
    throw new Error("ASN.1: INTEGER out of safe range");
  }
  return acc;
}

/**
 * Decode an ENUMERATED into a JS number. Same wire encoding as INTEGER
 * (big-endian two's complement), so sign-extend the top bit and guard
 * the result against the safe-integer range exactly like
 * `decodeInteger` does. The previous version accepted any content
 * length up to 6 bytes and dropped the sign bit, which silently
 * mis-decoded negative values such as 0xff = 255 instead of -1.
 *
 * If a caller needs unsigned semantics (e.g. the value is known to be
 * a non-negative tag-like code), use `decodeEnumeratedUnsigned` below
 * rather than overloading this function.
 */
export function decodeEnumerated(bytes: Uint8Array, tlv: Tlv): number {
  if (tlv.tag !== TAG_ENUMERATED) {
    throw new Error("ASN.1: expected ENUMERATED");
  }
  const data = content(bytes, tlv);
  if (data.length === 0) throw new Error("ASN.1: empty ENUMERATED");
  if (data.length > 6) {
    throw new Error("ASN.1: ENUMERATED exceeds safe-integer range");
  }
  let acc = 0;
 // Preserve sign bit.
  const negative = (data[0]! & 0x80) !== 0;
  for (let i = 0; i < data.length; i++) {
    acc = acc * 256 + data[i]!;
  }
  if (negative) {
    acc = acc - Math.pow(2, data.length * 8);
  }
  if (!Number.isSafeInteger(acc)) {
    throw new Error("ASN.1: ENUMERATED out of safe range");
  }
  return acc;
}

/**
 * Decode an ENUMERATED that the caller asserts is unsigned. Rejects
 * any encoding whose top bit is set without a leading 0x00 padding
 * octet, matching the DER rule for INTEGER-style unsigned values.
 */
export function decodeEnumeratedUnsigned(bytes: Uint8Array, tlv: Tlv): number {
  const signed = decodeEnumerated(bytes, tlv);
  if (signed < 0) {
    throw new Error("ASN.1: ENUMERATED is negative where unsigned expected");
  }
  return signed;
}

/**
 * Decode a BOOLEAN under DER rules. DER requires TRUE be encoded as
 * exactly 0xff and FALSE as exactly 0x00; any other content octet is
 * a malformed encoding (BER would accept "any non-zero", but this
 * parser is DER-only, and every legitimate Android Key Attestation
 * device emits 0xff). Reject rather than silently coerce.
 */
export function decodeBoolean(bytes: Uint8Array, tlv: Tlv): boolean {
  if (tlv.tag !== TAG_BOOLEAN) {
    throw new Error("ASN.1: expected BOOLEAN");
  }
  const data = content(bytes, tlv);
  if (data.length !== 1) throw new Error("ASN.1: BOOLEAN length != 1");
  const byte = data[0]!;
  if (byte === 0x00) return false;
  if (byte === 0xff) return true;
  throw new Error(
    `ASN.1: DER BOOLEAN content must be 0x00 or 0xff (got 0x${byte.toString(16).padStart(2, "0")})`,
  );
}

/** Decode a NULL. The content must be empty. */
export function decodeNull(bytes: Uint8Array, tlv: Tlv): void {
  if (tlv.tag !== TAG_NULL) {
    throw new Error("ASN.1: expected NULL");
  }
  if (tlv.contentLength !== 0) throw new Error("ASN.1: NULL has content");
}

/** Byte-wise comparison of two sub-buffers. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
