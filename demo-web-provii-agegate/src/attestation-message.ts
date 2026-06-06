// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Canonical attestation-message bytes. Byte-exact mirror of
 * `crypto-commons/src/attestation.rs::compute_message_bytes`
 * (provii-crypto branch `-attestation-binding`, ).
 *
 * This helper lives in its own module so both the demo-subdomain path
 * (`src/index.ts`) and the docs gateway test harness can import it
 * without having to resolve `__STATIC_CONTENT_MANIFEST`. The docs
 * gateway itself has a near-identical copy in `src/docs/attestation.ts`
 * that always emits the v1.1 binding section; this module supports both
 * the legacy (None, None) and v1.1 forms so the existing over/under
 * demo attestations stay verifiable.
 *
 * Canonical layout:
 *
 * Blake2s256(
 * DST || dob_days_i32_le || issuer_len_u8 || issuer ||
 * timestamp_u64_le || nonce[32]
 * [|| session_id_len_u8 || session_id || client_id_len_u8 || client_id]
 * )
 *
 * The binding section (brackets above) is emitted only when at least
 * one of `sessionId` or `clientId` is supplied. When both are omitted,
 * the output is byte-identical to the pre-v1.1 legacy encoding so
 * existing demo attestations continue to verify upstream.
 */

import { blake2s } from "@noble/hashes/blake2.js";

/** Domain-separation tag pinned by crypto-commons. */
export const DOB_ATTESTATION_DST = "provii.attestation.dob.v1";

/**
 * Compute the Blake2s-256 hash of the canonical attestation message.
 *
 * @throws RangeError if any length field would overflow its `u8` prefix,
 * if `nonce` is not exactly 32 bytes, or if `dob_days` falls outside
 * the signed-32-bit range.
 */
export function computeAttestationMessageBytes(
  dobDays: number,
  issuerId: string,
  timestamp: number,
  nonce: Uint8Array,
  sessionId?: string,
  clientId?: string,
): Uint8Array {
  if (
    !Number.isInteger(dobDays) ||
    dobDays < -2_147_483_648 ||
    dobDays > 2_147_483_647
  ) {
    throw new RangeError("dob_days must fit in a signed 32-bit integer");
  }
  if (nonce.byteLength !== 32) {
    throw new RangeError("nonce must be exactly 32 bytes");
  }

  const encoder = new TextEncoder();
  const dstBytes = encoder.encode(DOB_ATTESTATION_DST);
  const issuerBytes = encoder.encode(issuerId);

  if (issuerBytes.length > 255) {
    throw new RangeError("issuer_id exceeds 255 bytes");
  }

 // dob_days as 4-byte signed little-endian (i32::to_le_bytes in Rust).
 // setUint32 would re-encode negative values as 2^32 + x; setInt32
 // preserves the two's-complement wire form so pre-1970 DOBs hash
 // identically upstream.
  const dobBuf = new ArrayBuffer(4);
  new DataView(dobBuf).setInt32(0, dobDays, true);
  const dobBytes = new Uint8Array(dobBuf);

 // timestamp as 8-byte unsigned little-endian.
  const tsBuf = new ArrayBuffer(8);
  new DataView(tsBuf).setBigUint64(0, BigInt(timestamp), true);
  const tsBytes = new Uint8Array(tsBuf);

 // v1.1 binding: emit both sections only when at least one is
 // supplied. A missing field inside a present block serialises as a
 // zero length byte with no payload, matching the Rust reference at
 // `compute_message_bytes` lines 366-380.
  const emitBinding = sessionId !== undefined || clientId !== undefined;
  const sessionBytes = emitBinding
    ? encoder.encode(sessionId ?? "")
    : new Uint8Array();
  const clientBytes = emitBinding
    ? encoder.encode(clientId ?? "")
    : new Uint8Array();
  if (emitBinding) {
    if (sessionBytes.length > 255) {
      throw new RangeError("session_id exceeds 255 bytes");
    }
    if (clientBytes.length > 255) {
      throw new RangeError("client_id exceeds 255 bytes");
    }
  }

  const bindingLen = emitBinding
    ? 1 + sessionBytes.length + 1 + clientBytes.length
    : 0;
  const message = new Uint8Array(
    dstBytes.length + 4 + 1 + issuerBytes.length + 8 + 32 + bindingLen,
  );
  let offset = 0;
  message.set(dstBytes, offset);
  offset += dstBytes.length;
  message.set(dobBytes, offset);
  offset += 4;
  message[offset] = issuerBytes.length;
  offset += 1;
  message.set(issuerBytes, offset);
  offset += issuerBytes.length;
  message.set(tsBytes, offset);
  offset += 8;
  message.set(nonce, offset);
  offset += 32;
  if (emitBinding) {
    message[offset] = sessionBytes.length;
    offset += 1;
    message.set(sessionBytes, offset);
    offset += sessionBytes.length;
    message[offset] = clientBytes.length;
    offset += 1;
    message.set(clientBytes, offset);
  }

  return blake2s(message);
}
