// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * JWKS fetch + in-memory cache + JWS compact verify.
 *
 * .0 scaffolding. Wired up here so .6 (Google Play
 * Integrity) can import a verified JWS primitive without rebuilding
 * the WebCrypto glue. The shape follows RFC 7517 (JWK / JWKS) and
 * RFC 7515 (JWS Compact Serialisation). Only the algorithms we
 * actually expect from the Play Integrity service are enabled:
 * RS256 and ES256. Any other `alg` header is rejected rather than
 * silently accepted, per the "no silent fallback" rule in the brief.
 *
 * The cache is per-isolate and keyed by the JWKS URL. TTL is 24h,
 * which matches Google's recommended refresh cadence. A 410 or a
 * missing `kid` match forces a re-fetch before failing, so operator
 * key rotations do not require a Worker restart.
 *
 * This file does NOT import Play Integrity specifics. The caller
 * passes in a JWS token and a JWKS URL; we return the verified
 * payload bytes or throw. Keeping the layers separate lets us test
 * JWS verification against RFC 7515 appendix A vectors without any
 * live network dependency.
 */

export interface Jwk {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
 // Extra members are allowed by the spec and ignored here.
  [k: string]: unknown;
}

export interface JwksDocument {
  keys: Jwk[];
}

interface CacheEntry {
  fetchedAtMs: number;
  document: JwksDocument;
}

const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const cache = new Map<string, CacheEntry>();

/** Test-only: clears the per-isolate JWKS cache. */
export function __resetJwksCacheForTests(): void {
  cache.clear();
}

/**
 * Fetch a JWKS document with caching. `forceRefresh` bypasses the
 * TTL check; callers should pass it when a `kid` lookup misses so a
 * rotation can be picked up without waiting for TTL expiry.
 */
export async function fetchJwks(
  url: string,
  opts: { forceRefresh?: boolean; now?: number } = {},
): Promise<JwksDocument> {
  const now = opts.now ?? Date.now();
  const cached = cache.get(url);
  if (!opts.forceRefresh && cached && now - cached.fetchedAtMs < CACHE_TTL_MS) {
    return cached.document;
  }

  const response = await fetch(url, {
    headers: { accept: "application/jwk-set+json, application/json" },
  });
  if (!response.ok) {
    throw new Error(`JWKS fetch failed: ${response.status} ${url}`);
  }
  const parsed: unknown = await response.json();
  if (!isJwksDocument(parsed)) {
    throw new Error(`JWKS fetch returned malformed document: ${url}`);
  }
  cache.set(url, { fetchedAtMs: now, document: parsed });
  return parsed;
}

/**
 * Locate a JWK by `kid`. Returns `null` if no match so the caller
 * can decide whether to re-fetch (rotation) or reject.
 */
export function findKeyByKid(doc: JwksDocument, kid: string): Jwk | null {
  for (const key of doc.keys) {
    if (key.kid === kid) return key;
  }
  return null;
}

function isJwksDocument(value: unknown): value is JwksDocument {
  if (typeof value !== "object" || value === null) return false;
  const maybe = value as { keys?: unknown };
  if (!Array.isArray(maybe.keys)) return false;
  for (const key of maybe.keys) {
    if (typeof key !== "object" || key === null) return false;
    if (typeof (key as { kty?: unknown }).kty !== "string") return false;
  }
  return true;
}

// --- JWS Compact verification ------------------------------------

export interface VerifiedJws {
  header: JwsHeader;
  payload: Uint8Array;
  signature: Uint8Array;
}

export interface JwsHeader {
  alg: "RS256" | "ES256";
  kid?: string;
  typ?: string;
  [k: string]: unknown;
}

const ALLOWED_ALGS = new Set(["RS256", "ES256"]);

/**
 * Verify a JWS compact token against a resolver that returns the
 * matching JWK. We split resolution from verification so tests can
 * inject a fixed key without a network round-trip, and so the
 * eventual Play Integrity wiring can pre-fetch JWKS and hand back a
 * `Jwk` directly.
 */
export async function verifyJwsCompact(
  token: string,
  resolveKey: (header: JwsHeader) => Promise<Jwk>,
): Promise<VerifiedJws> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("JWS: expected three dot-separated segments");
  }
  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

  const header = decodeJsonSegment(headerB64);
  if (!isJwsHeader(header)) {
    throw new Error("JWS: header missing/invalid `alg`");
  }
  if (!ALLOWED_ALGS.has(header.alg)) {
    throw new Error(`JWS: algorithm ${header.alg} not permitted`);
  }

  const jwk = await resolveKey(header);
  const cryptoKey = await importJwkForVerify(jwk, header.alg);

  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signatureBytes = base64urlDecode(signatureB64);
  const verifyParams = header.alg === "RS256"
    ? { name: "RSASSA-PKCS1-v1_5" }
    : { name: "ECDSA", hash: "SHA-256" };

  const ok = await crypto.subtle.verify(
    verifyParams,
    cryptoKey,
    signatureBytes,
    signingInput,
  );
  if (!ok) {
    throw new Error("JWS: signature did not verify");
  }

  return {
    header,
    payload: base64urlDecode(payloadB64),
    signature: signatureBytes,
  };
}

async function importJwkForVerify(
  jwk: Jwk,
  alg: "RS256" | "ES256",
): Promise<CryptoKey> {
  if (alg === "RS256") {
    if (jwk.kty !== "RSA" || typeof jwk.n !== "string" || typeof jwk.e !== "string") {
      throw new Error("JWS: RS256 requires RSA JWK with n + e");
    }
    return crypto.subtle.importKey(
      "jwk",
      jwk as JsonWebKey,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
  }
 // ES256
  if (jwk.kty !== "EC" || jwk.crv !== "P-256") {
    throw new Error("JWS: ES256 requires EC JWK on P-256");
  }
  return crypto.subtle.importKey(
    "jwk",
    jwk as JsonWebKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}

function isJwsHeader(value: unknown): value is JwsHeader {
  if (typeof value !== "object" || value === null) return false;
  const maybe = value as { alg?: unknown };
  return typeof maybe.alg === "string";
}

function decodeJsonSegment(segment: string): unknown {
  const bytes = base64urlDecode(segment);
  return JSON.parse(new TextDecoder().decode(bytes));
}

/**
 * RFC 4648 section 5 base64url decode (no padding required).
 * Tolerates the encoder adding padding because some producers do.
 */
export function base64urlDecode(input: string): Uint8Array {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}
