// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Docs gateway crypto helpers.
 *
 * All secret-material comparisons in the docs surface route through
 * `constantTimeEquals`, which delegates to `crypto.subtle.timingSafeEqual`
 * per the repo-wide rule in the project security policy. Hand-rolled loops are prohibited and
 * would be caught by Semgrep. The remaining helpers wrap WebCrypto HMAC and
 * SHA-256 with hex encoding so every `src/docs/*` caller shares one
 * serialisation format (lowercase hex) for tags, hashes, and identifiers.
 */

const textEncoder = new TextEncoder();

/**
 * Constant-time compare of two hex-encoded values. Returns false if lengths
 * differ without consulting `timingSafeEqual` (length is not secret). Throws
 * TypeError on non-string inputs so callers cannot accidentally feed a
 * nullable value through without narrowing.
 */
export function constantTimeEqualsHex(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string") {
    throw new TypeError("constantTimeEqualsHex requires two strings");
  }
  if (a.length !== b.length) return false;

  const aBytes = hexToBytes(a);
  const bBytes = hexToBytes(b);
  if (aBytes === null || bBytes === null) return false;
  if (aBytes.byteLength !== bBytes.byteLength) return false;

  return crypto.subtle.timingSafeEqual(aBytes, bBytes);
}

/**
 * Constant-time compare of two raw byte sequences. Returns false on length
 * mismatch.
 */
export function constantTimeEqualsBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  return crypto.subtle.timingSafeEqual(a, b);
}

/** Convert a hex string to a Uint8Array, or null on malformed input. */
export function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const highChar = hex[i];
    const lowChar = hex[i + 1];
    if (highChar === undefined || lowChar === undefined) return null;
    const high = parseInt(highChar, 16);
    const low = parseInt(lowChar, 16);
    if (Number.isNaN(high) || Number.isNaN(low)) return null;
    out[i / 2] = (high << 4) | low;
  }
  return out;
}

/** Convert a Uint8Array to a lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  const parts = new Array<string>(bytes.byteLength);
  for (let i = 0; i < bytes.byteLength; i++) {
    const byte = bytes[i];
    if (byte === undefined) continue;
    parts[i] = byte.toString(16).padStart(2, "0");
  }
  return parts.join("");
}

/** Generate `length` cryptographically random bytes. */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

/** Generate `length` random bytes as a lowercase hex string. */
export function randomHex(lengthBytes: number): string {
  return bytesToHex(randomBytes(lengthBytes));
}

/**
 * Compute HMAC-SHA-256 over `message` with raw-byte key `key`. Returns the
 * tag as a Uint8Array. Uses `crypto.subtle.importKey` each call; caching is
 * left to specific callers that need it because keys rotate.
 */
export async function hmacSha256(
  key: Uint8Array,
  message: Uint8Array | string,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const data = typeof message === "string" ? textEncoder.encode(message) : message;
  const tag = await crypto.subtle.sign("HMAC", cryptoKey, data);
  return new Uint8Array(tag);
}

/** Compute HMAC-SHA-256 as a lowercase hex string. */
export async function hmacSha256Hex(
  key: Uint8Array,
  message: Uint8Array | string,
): Promise<string> {
  const tag = await hmacSha256(key, message);
  return bytesToHex(tag);
}

/** Compute SHA-256 over `message`, returning hex. */
export async function sha256Hex(message: Uint8Array | string): Promise<string> {
  const data = typeof message === "string" ? textEncoder.encode(message) : message;
  const digest = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(digest));
}

/** Compute SHA-256 over `message`, returning the raw 32-byte digest. */
export async function sha256Bytes(message: Uint8Array | string): Promise<Uint8Array> {
  const data = typeof message === "string" ? textEncoder.encode(message) : message;
  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

/**
 * Encode raw bytes as an RFC 4648 Section 5 base64url string with no padding.
 * Used for the PKCE `code_challenge` field provii-verifier expects on
 * `POST /v1/challenge`; the upstream decoder enforces `len === 43` and the
 * unreserved base64url alphabet (`A-Z` / `a-z` / `0-9` / `-` / `_`).
 */
export function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    const byte = bytes[i];
    if (byte === undefined) continue;
    binary += String.fromCharCode(byte);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
