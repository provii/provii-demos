// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Docs gateway session cookie helpers ().
 *
 * Provides two groups of helpers:
 *
 * 1. Session cookie mint + verify. `__Host-docs_session` cookies carry
 * `<kid>.<bearer_hex>.<hmac_tag_hex>`. The HMAC is over
 * `<kid>.<bearer_hex>` using the current DOCS_SESSION_HMAC_KEY. The
 * kid prefix lets us rotate keys without invalidating every live
 * session in flight.
 *
 * 2. Session KV persistence. `writeSessionRecord` and
 * `readSessionRecord` read/write `docs-session:<session_id>` through
 * the `DocsSessionSchema` validator from schemas.ts so malformed KV
 * values surface as 5xx rather than silently poisoning the handler.
 *
 * Every secret-material comparison (bearer_hash, cookie HMAC tag) flows
 * through the constant-time helpers in crypto.ts. Nothing in this module
 * uses `==` or string equality on secrets.
 */

import {
  DocsSessionIdxSchema,
  DocsSessionSchema,
  KV_PREFIX_DOCS_SESSION,
  KV_PREFIX_DOCS_SESSION_IDX,
  type DocsSession,
} from "./schemas";
import {
  bytesToHex,
  constantTimeEqualsBytes,
  constantTimeEqualsHex,
  hexToBytes,
  hmacSha256,
  hmacSha256Hex,
  randomBytes,
  randomHex,
} from "./crypto";
import type { DocsEnv } from "./handler";

// ============================================================================
// Constants
// ============================================================================

/** Cookie name. `__Host-` prefix requires Secure + Path=/ + no Domain. */
export const DOCS_SESSION_COOKIE_NAME = "__Host-docs_session" as const;

/** Sliding TTL bumped on every authenticated request. 15 minutes. */
export const SESSION_SLIDING_TTL_MS = 15 * 60 * 1000;

/** Absolute lifetime cap regardless of sliding renewals. 4 hours. */
export const SESSION_HARD_TTL_MS = 4 * 60 * 60 * 1000;

/**
 * Active key id used when minting new cookies. Rotating keys becomes a
 * matter of bumping this constant plus the secret binding; old cookies
 * with the previous kid keep verifying until they expire because
 * `verifySessionCookie` accepts any kid it has a key for.
 */
export const ACTIVE_SESSION_KID = "v1" as const;

// ============================================================================
// Cookie mint / verify
// ============================================================================

/**
 * Resolve the raw HMAC key for `kid` as bytes. Foundation phase only knows
 * the active key id; additional kids can be added to this switch during
 * rotations without invalidating in-flight sessions. Returns null when the
 * kid is unknown or the binding is missing.
 */
async function resolveSessionHmacKey(
  env: DocsEnv,
  kid: string,
): Promise<Uint8Array | null> {
  if (kid !== ACTIVE_SESSION_KID) return null;
  const raw = (await env.DOCS_SESSION_HMAC_KEY?.get()) ?? null;
  if (raw === null || raw === "") return null;

 // Secrets Store returns the key as a string. We accept either hex
 // (preferred) or UTF-8 and normalise to bytes. Hex is detected by a
 // length-even all-hex charset.
  const hexCandidate = /^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0;
  if (hexCandidate) {
    const bytes = hexToBytes(raw);
    if (bytes !== null && bytes.byteLength >= 32) return bytes;
  }

  const encoder = new TextEncoder();
  const utf8 = encoder.encode(raw);
  if (utf8.byteLength < 32) return null;
  return utf8;
}

/**
 * Outcome of cookie minting. The bearer hex is returned so the caller can
 * HMAC it and persist the hash on the session record alongside the cookie
 * in the response.
 */
export interface MintedSessionCookie {
  cookieValue: string;
  cookieHeader: string;
  kid: string;
  bearerHex: string;
  bearerHashHex: string;
  sessionId: string;
  issuedAt: number;
  expiresAt: number;
}

/**
 * Mint a fresh session cookie. Generates a 32-byte CSPRNG bearer, computes
 * the HMAC tag with the active key, and assembles the `Set-Cookie` header
 * with `__Host-docs_session=<kid>.<bearer_hex>.<tag_hex>`. Hard expiry is
 * capped at 4 hours; sliding renewal logic lives in `refreshSessionCookie`.
 */
export async function mintSessionCookie(
  env: DocsEnv,
  now: number = Date.now(),
): Promise<MintedSessionCookie | null> {
  const kid = ACTIVE_SESSION_KID;
  const keyBytes = await resolveSessionHmacKey(env, kid);
  if (keyBytes === null) return null;

  const bearerBytes = randomBytes(32);
  const bearerHex = bytesToHex(bearerBytes);
  const bearerHashHex = await hmacSha256Hex(keyBytes, bearerBytes);
  const sessionId = randomHex(16);

  const cookieBody = `${kid}.${bearerHex}`;
  const tagHex = await hmacSha256Hex(keyBytes, cookieBody);
  const cookieValue = `${cookieBody}.${tagHex}`;

  const issuedAt = now;
  const expiresAt = now + SESSION_HARD_TTL_MS;

 // Max-Age is expressed in seconds and reflects the sliding TTL, not the
 // hard cap. `refreshSessionCookie` re-issues this header on each
 // authenticated request up to the hard cap.
  const maxAgeSeconds = Math.floor(SESSION_SLIDING_TTL_MS / 1000);

  const cookieHeader =
    `${DOCS_SESSION_COOKIE_NAME}=${cookieValue}; ` +
    `Max-Age=${maxAgeSeconds}; ` +
    "Path=/; Secure; HttpOnly; SameSite=Strict";

  return {
    cookieValue,
    cookieHeader,
    kid,
    bearerHex,
    bearerHashHex,
    sessionId,
    issuedAt,
    expiresAt,
  };
}

/**
 * Build a revocation `Set-Cookie` header that clears the cookie on the
 * client. Used whenever the server rejects a request for origin mismatch,
 * tampered cookie, etc.
 */
export function revokeSessionCookieHeader(): string {
  return (
    `${DOCS_SESSION_COOKIE_NAME}=; ` +
    "Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict"
  );
}

/**
 * Parsed + verified cookie. Does not carry the raw bearer past the edge;
 * `bearerHashHex` is what callers use to look up the session record.
 */
export interface VerifiedSessionCookie {
  kid: string;
  bearerHashHex: string;
}

/**
 * Parse and HMAC-verify a cookie value. Returns null on any structural
 * mismatch, unknown kid, or tag mismatch. All secret compares are
 * constant-time.
 */
export async function verifySessionCookie(
  env: DocsEnv,
  cookieValue: string,
): Promise<VerifiedSessionCookie | null> {
  const parts = cookieValue.split(".");
  if (parts.length !== 3) return null;
  const [kid, bearerHex, tagHex] = parts;
  if (
    kid === undefined ||
    bearerHex === undefined ||
    tagHex === undefined ||
    kid === "" ||
    bearerHex === "" ||
    tagHex === ""
  ) {
    return null;
  }

  const keyBytes = await resolveSessionHmacKey(env, kid);
  if (keyBytes === null) return null;

  const expectedTag = await hmacSha256(keyBytes, `${kid}.${bearerHex}`);
  const presentedTag = hexToBytes(tagHex);
  if (presentedTag === null) return null;

  if (!constantTimeEqualsBytes(expectedTag, presentedTag)) return null;

  const bearerBytes = hexToBytes(bearerHex);
  if (bearerBytes === null) return null;
  const bearerHashHex = await hmacSha256Hex(keyBytes, bearerBytes);

  return { kid, bearerHashHex };
}

/**
 * Extract the `__Host-docs_session` cookie value from a request's Cookie
 * header, or null if absent / malformed.
 */
export function getSessionCookieFromRequest(request: Request): string | null {
  const header = request.headers.get("Cookie");
  if (header === null || header === "") return null;
  const needle = `${DOCS_SESSION_COOKIE_NAME}=`;
  for (const raw of header.split(";")) {
    const trimmed = raw.trim();
    if (trimmed.startsWith(needle)) {
      return trimmed.slice(needle.length);
    }
  }
  return null;
}

// ============================================================================
// Session record KV IO
// ============================================================================

/**
 * Persist the session record. `DocsSession` shape is enforced by Zod on
 * both write and read paths. Expiry TTL is derived from `expires_at` so KV
 * garbage-collects records naturally without callers having to sweep.
 *
 * Also writes the bearer-hash secondary index used by
 * `authenticateSession`. Both writes share the same TTL so the index
 * cannot outlive the record it points to.
 */
export async function writeSessionRecord(
  env: DocsEnv,
  record: DocsSession,
  now: number = Date.now(),
): Promise<void> {
  const validated = DocsSessionSchema.parse(record);
  const key = `${KV_PREFIX_DOCS_SESSION}${validated.session_id}`;
  const ttlSeconds = Math.max(1, Math.ceil((validated.expires_at - now) / 1000));
  await env.DOCS_SESSIONS.put(key, JSON.stringify(validated), {
    expirationTtl: ttlSeconds,
  });
 // ADV-S2: bearer_hash index entry follows DocsSessionIdxSchema so future
 // fields can attach without another KV rewrite. Validated on both write
 // and read so malformed values surface as auth failures rather than
 // silent wrong-session resolution.
  const indexKey = `${KV_PREFIX_DOCS_SESSION_IDX}${validated.bearer_hash}`;
  const indexValue = DocsSessionIdxSchema.parse({
    session_id: validated.session_id,
  });
  await env.DOCS_SESSIONS.put(indexKey, JSON.stringify(indexValue), {
    expirationTtl: ttlSeconds,
  });
}

/**
 * Read and validate a session record. Returns null on missing, malformed,
 * or schema-violating records so the handler can map those to 401.
 */
export async function readSessionRecord(
  env: DocsEnv,
  sessionId: string,
): Promise<DocsSession | null> {
  const key = `${KV_PREFIX_DOCS_SESSION}${sessionId}`;
  let raw: string | null;
  try {
    raw = await env.DOCS_SESSIONS.get(key);
  } catch {
    return null;
  }
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  const result = DocsSessionSchema.safeParse(parsed);
  if (!result.success) return null;
  return result.data;
}

// ============================================================================
// Session authentication (shared across credentials/challenge/status/etc.)
// ============================================================================

/**
 * Structured outcome of authenticating a request against a session cookie
 * and the corresponding KV record. Handlers map each failure case to the
 * expected 401/403 envelope without having to re-check error classes.
 */
export type AuthenticatedSessionOutcome =
  | { kind: "ok"; session: DocsSession }
  | {
      kind: "error";
      status: number;
      code:
        | "docs_session_cookie_missing"
        | "docs_session_cookie_invalid"
        | "docs_session_not_found"
        | "docs_session_bearer_mismatch"
        | "docs_session_expired";
      message: string;
    };

/**
 * Validate a request's session cookie end-to-end:
 * 1. Cookie present.
 * 2. Cookie HMAC verifies against a known kid.
 * 3. Session record exists in KV.
 * 4. `bearer_hash` on the record constant-time-matches the cookie's
 * bearer hash (already HMAC-hashed by verifySessionCookie).
 * 5. Record `expires_at` is in the future.
 *
 * Returns the validated session on success, or an error outcome otherwise.
 * Any comparison of secret material uses `constantTimeEqualsHex` from
 * crypto.ts.
 */
export async function authenticateSession(
  env: DocsEnv,
  request: Request,
  now: number = Date.now(),
): Promise<AuthenticatedSessionOutcome> {
  const cookieValue = getSessionCookieFromRequest(request);
  if (cookieValue === null) {
    return {
      kind: "error",
      status: 401,
      code: "docs_session_cookie_missing",
      message: "Missing __Host-docs_session cookie.",
    };
  }

  const verified = await verifySessionCookie(env, cookieValue);
  if (verified === null) {
    return {
      kind: "error",
      status: 401,
      code: "docs_session_cookie_invalid",
      message: "Session cookie is malformed or tampered.",
    };
  }

 // The cookie tells us the bearer hash but not the session id. Lookup is
 // keyed by session id in KV. We resolve via the secondary index at
 // `docs-session-idx:<bearer_hash>` written by `writeSessionRecord`; the
 // index value is validated through `DocsSessionIdxSchema` so malformed
 // entries surface as auth failures (ADV-S2).
  const indexKey = `${KV_PREFIX_DOCS_SESSION_IDX}${verified.bearerHashHex}`;
  let rawIndex: string | null;
  try {
    rawIndex = await env.DOCS_SESSIONS.get(indexKey);
  } catch {
    return {
      kind: "error",
      status: 401,
      code: "docs_session_not_found",
      message: "Session not found.",
    };
  }
  if (rawIndex === null) {
    return {
      kind: "error",
      status: 401,
      code: "docs_session_not_found",
      message: "Session not found.",
    };
  }
  let parsedIndex: unknown;
  try {
    parsedIndex = JSON.parse(rawIndex);
  } catch {
    return {
      kind: "error",
      status: 401,
      code: "docs_session_not_found",
      message: "Session not found.",
    };
  }
  const indexResult = DocsSessionIdxSchema.safeParse(parsedIndex);
  if (!indexResult.success) {
    return {
      kind: "error",
      status: 401,
      code: "docs_session_not_found",
      message: "Session not found.",
    };
  }
  const sessionId = indexResult.data.session_id;

  const record = await readSessionRecord(env, sessionId);
  if (record === null) {
    return {
      kind: "error",
      status: 401,
      code: "docs_session_not_found",
      message: "Session not found.",
    };
  }

  if (!constantTimeEqualsHex(record.bearer_hash, verified.bearerHashHex)) {
    return {
      kind: "error",
      status: 401,
      code: "docs_session_bearer_mismatch",
      message: "Session bearer does not match.",
    };
  }

  if (record.expires_at <= now) {
    return {
      kind: "error",
      status: 401,
      code: "docs_session_expired",
      message: "Session has expired.",
    };
  }

  return { kind: "ok", session: record };
}
