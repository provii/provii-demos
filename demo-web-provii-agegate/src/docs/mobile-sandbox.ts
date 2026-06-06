// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Mobile sandbox issuer gateway (.1 to 7A.3 + 7A.8).
 *
 * Wires four endpoints that let provii-mobile (iOS + Android) register
 * an ephemeral sandbox issuer identity and maintain it with HMAC-signed
 * lifecycle calls:
 *
 * GET /api/mobile/sandbox/challenge mint 32-byte nonce
 * POST /api/mobile/sandbox/register verify attestation, mint client_id
 * POST /api/mobile/sandbox/revoke tombstone client_id
 * POST /api/mobile/sandbox/refresh extend client_id TTL
 *
 * The verifiers in `./attestation/app-attest.ts` and
 * `./attestation/key-attestation.ts` do the real cryptographic work;
 * this module is the orchestration glue.
 *
 * Design points worth naming up front so the diff reads cleanly:
 *
 * Nonce lifecycle. Every `/challenge` mints a fresh 32-byte random
 * nonce and persists it under `mobile-sandbox-nonce:{hex}` with a
 * 5-minute TTL. `/register` consumes the nonce atomically (KV
 * `get` then `delete`) before running the attestation verifier;
 * replay of the same attestation blob is therefore bounded by the
 * KV delete.
 *
 * Rate limit. The scope brief asked for a Durable Object counter
 * at 5 hits per hour per IP. The docs gateway already owns a
 * `RATELIMIT` Cloudflare binding (`DOCS_STATUS_POLL_LIMITER`) and
 * a KV-counter limiter (`checkCreationRateLimit`). Pulling in a
 * Durable Object in this PR would require a new migration plus a
 * new wrangler binding; we opt for the KV-counter pattern so the
 * existing cross-isolate fail-closed behaviour carries over. The
 * limit is 5/hour keyed on `mobile-sbx-register:{ip}`. If the mobile owner or
 * the DevOps owner later decides the DO precision matters this swap is one
 * file. Called out in the PR summary.
 *
 * LRU ceiling. `mobile-sandbox-active-count` is an atomic KV
 * counter; every successful register bumps it, every revoke
 * decrements. 100k hard cap returns `sandbox_capacity_reached`
 * to the caller. Counter races are bounded by the per-IP rate
 * limit above, worst case a handful of entries past the ceiling,
 * which is inside the 100k margin.
 *
 * Canonical HMAC envelope. `/revoke` and `/refresh` are
 * HMAC-authenticated with the 32-byte hex secret minted by
 * `/register`. Clients sign
 *
 * mwallet-sbx/v1\n
 * <method>\n
 * <path>\n
 * <timestamp_unix_seconds>\n
 * <nonce_hex>\n
 * <jcs(body)>
 *
 * with HMAC-SHA-256; the tag rides the `X-Mwallet-Sig` header.
 * Body is canonicalised with the existing `jcsBytes` helper so
 * the signature covers the exact bytes the mobile client and the
 * gateway both agree on. A 60-second timestamp skew window plus
 * single-use nonce guards against replay. The full spec lives in
 * `docs/mobile-sandbox-contract.md` for the mobile owner.
 *
 * Origin pin. refined the Origin check to reject only
 * Origins that look browser-issued (match `https://` and a
 * hostname). Mobile clients typically omit `Origin` entirely on
 * native HTTPS, so we allow missing Origin, reject anything that
 * looks like a browser origin outside the docs allowlist.
 *
 * Persisted records all live in the existing `DOCS_SESSIONS` KV
 * namespace under disjoint key prefixes:
 *
 * mobile-sandbox-nonce:{hex} 5-min TTL, {issued_at, platform?}
 * mobile-sandbox-issuer:{cid} 7-day TTL, `SandboxMobileIssuer`
 * mobile-install:{install_uuid} 7-day TTL, reverse index to cid
 * mobile-sandbox-active-count counter, {count}
 * ratelimit:docs:mobile-sbx:{...} 1-min and 1-hour buckets
 */

import { z } from "zod";

import {
  APPLE_AAGUID_DEV,
  APPLE_AAGUID_PROD,
  verifyAppAttest,
} from "./attestation/app-attest";
import { base64ToBytes } from "./attestation/x509";
import {
  verifyKeyAttestation,
  GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64,
} from "./attestation/key-attestation";
import {
  bytesToHex,
  constantTimeEqualsBytes,
  hexToBytes,
  hmacSha256,
  randomBytes,
  randomHex,
} from "./crypto";
import { ALLOWED_DOCS_ORIGINS } from "./cors";
import type { DocsEnv } from "./handler";
import { jcsBytes } from "./jcs";
import { getDocsLogger, markMobileSandboxSecretAsKnown } from "./logger";
import { KV_PREFIX_DOCS_RATELIMIT } from "./schemas";

// ============================================================================
// Constants
// ============================================================================

/** Nonce TTL. Matches provii-mobile's in-flight challenge window. */
const NONCE_TTL_SECONDS = 5 * 60;

/** Issuer credential TTL. Seven days per Meg's provii-mobile design doc. */
const ISSUER_TTL_SECONDS = 7 * 24 * 60 * 60;

/** Maximum skew between the client-supplied timestamp and wall-clock. */
const MAX_TIMESTAMP_SKEW_SECONDS = 60;

/** Per-IP register attempts per hour ceiling. */
const REGISTER_PER_IP_PER_HOUR = 5;

/** Per-IP challenge attempts per minute ceiling (CAT-A-02). */
const CHALLENGE_PER_IP_PER_MINUTE = 10;

/** Global active-issuer ceiling. Matches Meg's LRU-pruning brief. */
const ACTIVE_ISSUER_CEILING = 100_000;

/** Canonical HMAC envelope version string. Bumped if the shape ever changes. */
const HMAC_ENVELOPE_VERSION = "mwallet-sbx/v1";

/** Expected `Origin` allowlist for browser callers. Native callers omit Origin. */
const BROWSER_ORIGIN_PATTERN = /^https?:\/\/[^\s]+$/;

/** KV prefixes owned by this surface. Disjoint from every other prefix. */
const KV_PREFIX_MOBILE_NONCE = "mobile-sandbox-nonce:";
const KV_PREFIX_MOBILE_ISSUER = "mobile-sandbox-issuer:";
const KV_PREFIX_MOBILE_INSTALL = "mobile-install:";
const KV_KEY_ACTIVE_COUNT = "mobile-sandbox-active-count";

/** Standard response headers. No caching, JSON everywhere. */
const JSON_HEADERS: Record<string, string> = {
  "Content-Type": "application/json",
  "Cache-Control": "no-store",
};

// ============================================================================
// Env + binding types
// ============================================================================

/**
 * Configuration bindings the mobile-sandbox gateway expects on top of the
 * regular `DocsEnv`. All optional so the module compiles before wrangler.toml
 * carries the bindings; each handler fails closed with `binding_missing`
 * when the deployment is not yet configured.
 */
export interface MobileSandboxEnv extends DocsEnv {
  /** App bundle id, e.g. `com.provii.wallet`. */
  MOBILE_APP_BUNDLE_ID?: string;
  /** `"prod"` or `"dev"` toggling which Apple AAGUID to require. */
  MOBILE_APPLE_AAGUID_ENV?: string;
  /** Pinned Google Hardware Attestation root DER (base64). Empty falls back to module default. */
  MOBILE_ANDROID_PINNED_ROOT_DER_B64?: string;
  /** Expected Android package name for attestationApplicationId cross-check. */
  MOBILE_ANDROID_PACKAGE_NAME?: string;
}

// ============================================================================
// Zod request schemas
// ============================================================================

/** UUID v4 or v7 (RFC 9562) regex used for install_uuid. Lowercase canonical form. */
const uuidV4OrV7 = z
  .string()
  .regex(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  );

/** Platform tag. No aliases; mobile clients pin to these exact two strings. */
const PlatformSchema = z.enum(["ios", "android"]);

/**
 * Schema for `POST /api/mobile/sandbox/register`. iOS callers supply
 * `app_attest_token` (base64 CBOR), Android callers supply
 * `key_attestation_chain` (array of base64 DER certs). Exactly one of the
 * two must be present; `.superRefine` enforces the pairing with platform.
 */
export const MobileRegisterRequestSchema = z
  .object({
    install_uuid: uuidV4OrV7,
    platform: PlatformSchema,
    app_version: z.string().min(1).max(32),
    attestation_nonce: z.string().regex(/^[0-9a-f]{64}$/),
    app_attest_token: z.string().min(16).optional(),
    key_attestation_chain: z.array(z.string().min(16)).min(2).optional(),
  })
  .strict()
  .superRefine((data, ctx) => {
    if (data.platform === "ios") {
      if (data.app_attest_token === undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "iOS platform requires app_attest_token",
        });
      }
      if (data.key_attestation_chain !== undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "iOS platform must not include key_attestation_chain",
        });
      }
    } else {
      if (data.key_attestation_chain === undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Android platform requires key_attestation_chain",
        });
      }
      if (data.app_attest_token !== undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Android platform must not include app_attest_token",
        });
      }
    }
  });

export type MobileRegisterRequest = z.infer<typeof MobileRegisterRequestSchema>;

/** Body for `POST /revoke` and `POST /refresh`. Carries only the client id. */
export const MobileLifecycleRequestSchema = z.object({
  client_id: z.string().regex(/^mwallet-sbx-[0-9a-f]{32}$/),
}).strict();

export type MobileLifecycleRequest = z.infer<typeof MobileLifecycleRequestSchema>;

// ============================================================================
// Persisted record shapes
// ============================================================================

/** KV record for an in-flight challenge nonce. Written by `/challenge`. */
const MobileNonceRecordSchema = z.object({
  issued_at: z.number().int().positive(),
  platform: PlatformSchema.optional(),
});

type MobileNonceRecord = z.infer<typeof MobileNonceRecordSchema>;

/** Active-count atomic counter. */
const MobileActiveCountSchema = z.object({
  count: z.number().int().min(0),
});

/** KV record for a minted issuer. Written by `/register`. */
const MobileIssuerRecordSchema = z.object({
  client_id: z.string().regex(/^mwallet-sbx-[0-9a-f]{32}$/),
  hmac_secret: z.string().regex(/^[0-9a-f]{64}$/),
  install_uuid: uuidV4OrV7,
  platform: PlatformSchema,
  app_version: z.string().min(1).max(32),
  issued_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
  last_refreshed_at: z.number().int().positive(),
});

type MobileIssuerRecord = z.infer<typeof MobileIssuerRecordSchema>;

// ============================================================================
// Error helpers
// ============================================================================

/**
 * Build the stable error envelope used by every mobile-sandbox endpoint.
 * `code` is machine-readable, `message` is operator-friendly but not
 * user-localised; native clients surface errors by `code` alone.
 */
function mobileError(
  status: number,
  code: string,
  message: string,
  extraHeaders: Record<string, string> = {},
): Response {
  const body = { error: { code, message } };
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders },
  });
}

/**
 * Reject browser-like Origins that are not on the docs allowlist. Mobile
 * callers on iOS/Android set an empty Origin; those are allowed through.
 * : only browsers that look like browsers are filtered; a missing
 * Origin is not treated as a rejection.
 */
function checkMobileOrigin(request: Request): Response | null {
  const origin = request.headers.get("Origin");
  if (origin === null || origin === "") return null;
  if (!BROWSER_ORIGIN_PATTERN.test(origin)) return null;
 // Shape looks like a browser; only docs allowlist passes. Consolidated
 // from cors.ts (MED-12). the original docs-vs-playground isolation
 // decision still applies: mobile endpoints share the docs allowlist, not
 // the playground allowlist. Duplication was between the inline list here
 // and ALLOWED_DOCS_ORIGINS in cors.ts, which is the same surface.
  if (ALLOWED_DOCS_ORIGINS.includes(origin)) return null;
  return mobileError(
    403,
    "mobile_origin_not_allowed",
    "Origin is not permitted for the mobile sandbox gateway.",
  );
}

// ============================================================================
// Rate limiting (per IP, 1-hour window)
// ============================================================================

/** Bucket the current wall-clock into a rolling minute key. */
function currentMinuteKey(now: number): string {
  const date = new Date(now);
  return [
    date.getUTCFullYear(),
    String(date.getUTCMonth() + 1).padStart(2, "0"),
    String(date.getUTCDate()).padStart(2, "0"),
    "T",
    String(date.getUTCHours()).padStart(2, "0"),
    String(date.getUTCMinutes()).padStart(2, "0"),
  ].join("");
}

/** Bucket the current wall-clock into a rolling hour key. */
function currentHourKey(now: number): string {
  const date = new Date(now);
  return [
    date.getUTCFullYear(),
    String(date.getUTCMonth() + 1).padStart(2, "0"),
    String(date.getUTCDate()).padStart(2, "0"),
    "T",
    String(date.getUTCHours()).padStart(2, "0"),
  ].join("");
}

/**
 * Check the per-IP register ceiling. Reads the KV bucket, compares to
 * `REGISTER_PER_IP_PER_HOUR`, increments on success. Fail-closed on any
 * KV error; a worst-case eventual-consistency window is bounded by the
 * 2-hour TTL on the bucket and the per-IP quota headroom.
 */
async function checkRegisterRateLimit(
  env: DocsEnv,
  remoteIp: string | null,
  now: number,
): Promise<{ allowed: true } | { allowed: false; retryAfterSeconds: number }> {
  const key = `${KV_PREFIX_DOCS_RATELIMIT}mobile-sbx-register:${remoteIp ?? "unknown"}:${currentHourKey(now)}`;
  try {
    const raw = await env.DOCS_SESSIONS.get(key);
    const current = raw === null ? 0 : Number(raw);
    const safeCurrent = Number.isFinite(current) && current >= 0 ? current : 0;
    if (safeCurrent >= REGISTER_PER_IP_PER_HOUR) {
      const secondsIntoHour = Math.floor((now % 3_600_000) / 1000);
      return { allowed: false, retryAfterSeconds: Math.max(1, 3600 - secondsIntoHour) };
    }
    await env.DOCS_SESSIONS.put(key, String(safeCurrent + 1), {
      expirationTtl: 2 * 60 * 60,
    });
    return { allowed: true };
  } catch {
    return { allowed: false, retryAfterSeconds: 60 };
  }
}

/**
 * Per-IP rate limit for the challenge endpoint (CAT-A-02). 10 per minute.
 * Same KV-counter pattern as `checkRegisterRateLimit`. Fail-closed on any
 * KV error so an unauthenticated caller cannot flood KV with nonce writes.
 */
async function checkChallengeRateLimit(
  env: DocsEnv,
  remoteIp: string | null,
  now: number,
): Promise<{ allowed: true } | { allowed: false; retryAfterSeconds: number }> {
  const key = `${KV_PREFIX_DOCS_RATELIMIT}mobile-sbx-challenge:${remoteIp ?? "unknown"}:${currentMinuteKey(now)}`;
  try {
    const raw = await env.DOCS_SESSIONS.get(key);
    const current = raw === null ? 0 : Number(raw);
    const safeCurrent = Number.isFinite(current) && current >= 0 ? current : 0;
    if (safeCurrent >= CHALLENGE_PER_IP_PER_MINUTE) {
      const secondsIntoMinute = Math.floor((now % 60_000) / 1000);
      return { allowed: false, retryAfterSeconds: Math.max(1, 60 - secondsIntoMinute) };
    }
    await env.DOCS_SESSIONS.put(key, String(safeCurrent + 1), {
      expirationTtl: 2 * 60,
    });
    return { allowed: true };
  } catch {
    return { allowed: false, retryAfterSeconds: 60 };
  }
}

// ============================================================================
// Active-issuer ceiling (LRU counter)
// ============================================================================

/**
 * Inspect the atomic active-issuer counter. Returns null when unreachable
 * (which the caller treats as fail-closed). Shape mismatch resets to zero
 * so a corrupted value cannot block all registrations forever; the next
 * successful register rewrites the record.
 */
async function readActiveCount(env: DocsEnv): Promise<number | null> {
  try {
    const raw = await env.DOCS_SESSIONS.get(KV_KEY_ACTIVE_COUNT);
    if (raw === null) return 0;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return 0;
    }
    const result = MobileActiveCountSchema.safeParse(parsed);
    if (!result.success) return 0;
    return result.data.count;
  } catch {
    return null;
  }
}

/**
 * Bump the active-issuer counter by `delta` (can be negative). Clamped at
 * zero on the low end; the high end is bounded by the ceiling check the
 * caller runs before `mint`. Returns silently on failure because the
 * ceiling is a best-effort guard against runaway sandbox usage, not a
 * strict quota, and the eventual-consistency bound here is acceptable.
 */
async function bumpActiveCount(env: DocsEnv, delta: number): Promise<void> {
  try {
    const current = (await readActiveCount(env)) ?? 0;
    const next = Math.max(0, current + delta);
    await env.DOCS_SESSIONS.put(
      KV_KEY_ACTIVE_COUNT,
      JSON.stringify({ count: next }),
    );
  } catch {
 // Swallowed intentionally; see doc comment above.
  }
}

// ============================================================================
// HMAC envelope (revoke + refresh auth)
// ============================================================================

/**
 * Canonical message the client signs. The same bytes are re-computed on
 * the gateway and compared to the decoded `X-Mwallet-Sig` header. We
 * canonicalise the body with RFC 8785 JCS so whitespace or key order
 * differences cannot invalidate the tag.
 */
function buildCanonicalHmacMessage(
  method: string,
  path: string,
  timestamp: number,
  nonceHex: string,
  bodyJcs: Uint8Array,
): Uint8Array {
  const header = `${HMAC_ENVELOPE_VERSION}\n${method}\n${path}\n${timestamp}\n${nonceHex}\n`;
  const headerBytes = new TextEncoder().encode(header);
  const out = new Uint8Array(headerBytes.length + bodyJcs.length);
  out.set(headerBytes, 0);
  out.set(bodyJcs, headerBytes.length);
  return out;
}

/**
 * Parse an `X-Mwallet-Auth` header into `(client_id, timestamp, nonce)`.
 * Format is `Mwallet-Sandbox client_id=<id>,ts=<unix>,nonce=<hex>`.
 * Returns null on any malformed input so the caller maps to a single
 * `invalid_auth_header` response.
 */
interface ParsedAuthHeader {
  clientId: string;
  timestamp: number;
  nonceHex: string;
}

function parseAuthHeader(raw: string | null): ParsedAuthHeader | null {
  if (raw === null) return null;
  const prefix = "Mwallet-Sandbox ";
  if (!raw.startsWith(prefix)) return null;
  const fields = raw.slice(prefix.length).split(",");
  const map = new Map<string, string>();
  for (const field of fields) {
    const equalsAt = field.indexOf("=");
    if (equalsAt < 1) return null;
    map.set(field.slice(0, equalsAt).trim(), field.slice(equalsAt + 1).trim());
  }
  const clientId = map.get("client_id");
  const ts = map.get("ts");
  const nonceHex = map.get("nonce");
  if (clientId === undefined || ts === undefined || nonceHex === undefined) {
    return null;
  }
  if (!/^mwallet-sbx-[0-9a-f]{32}$/.test(clientId)) return null;
  if (!/^[0-9a-f]{16,64}$/.test(nonceHex)) return null;
  const timestamp = Number(ts);
  if (!Number.isFinite(timestamp) || !Number.isInteger(timestamp)) return null;
  return { clientId, timestamp, nonceHex };
}

/**
 * Verify the `X-Mwallet-Auth` + `X-Mwallet-Sig` pair against a body. Loads
 * the issuer record for the claimed client_id, recomputes the canonical
 * message, HMAC-signs it, and constant-time compares the tags. Returns the
 * loaded record on success so the caller does not KV-fetch twice.
 */
async function verifyMobileHmac(
  env: DocsEnv,
  request: Request,
  bodyBytes: Uint8Array,
  path: string,
  now: number,
): Promise<
  | { ok: true; record: MobileIssuerRecord }
  | { ok: false; status: number; code: string; message: string }
> {
  const authHeader = parseAuthHeader(request.headers.get("X-Mwallet-Auth"));
  if (authHeader === null) {
    return {
      ok: false,
      status: 401,
      code: "mobile_invalid_auth_header",
      message: "Missing or malformed X-Mwallet-Auth header.",
    };
  }

  const sigHex = request.headers.get("X-Mwallet-Sig");
  if (sigHex === null || !/^[0-9a-f]{64}$/.test(sigHex)) {
    return {
      ok: false,
      status: 401,
      code: "mobile_invalid_signature_header",
      message: "Missing or malformed X-Mwallet-Sig header.",
    };
  }

 // Timestamp skew check first so expired requests drop before any KV round trip.
  const nowSeconds = Math.floor(now / 1000);
  if (Math.abs(nowSeconds - authHeader.timestamp) > MAX_TIMESTAMP_SKEW_SECONDS) {
    return {
      ok: false,
      status: 401,
      code: "mobile_timestamp_skew",
      message: "Request timestamp is outside the accepted window.",
    };
  }

  const record = await loadIssuerRecord(env, authHeader.clientId);
  if (record === null) {
    return {
      ok: false,
      status: 404,
      code: "mobile_client_id_unknown",
      message: "client_id is not registered or has expired.",
    };
  }

  const secretBytes = hexToBytes(record.hmac_secret);
  if (secretBytes === null) {
    return {
      ok: false,
      status: 500,
      code: "mobile_internal_corrupt_record",
      message: "Stored HMAC secret is malformed.",
    };
  }

  const canonical = buildCanonicalHmacMessage(
    request.method,
    path,
    authHeader.timestamp,
    authHeader.nonceHex,
    bodyBytes,
  );
  const expected = await hmacSha256(secretBytes, canonical);
  const received = hexToBytes(sigHex);
  if (received === null || !constantTimeEqualsBytes(expected, received)) {
    return {
      ok: false,
      status: 401,
      code: "mobile_signature_mismatch",
      message: "HMAC tag does not match canonical envelope.",
    };
  }

  return { ok: true, record };
}

// ============================================================================
// Issuer-record I/O
// ============================================================================

async function loadIssuerRecord(
  env: DocsEnv,
  clientId: string,
): Promise<MobileIssuerRecord | null> {
  let raw: string | null;
  try {
    raw = await env.DOCS_SESSIONS.get(`${KV_PREFIX_MOBILE_ISSUER}${clientId}`);
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
  const result = MobileIssuerRecordSchema.safeParse(parsed);
  if (!result.success) return null;
 // INVARIANT-DSGW-2: a cold isolate (one that wakes up after a peer
 // minted the per-install secret, or any isolate handling a refresh /
 // revoke for an existing client_id) sees the secret here for the
 // first time. Without this hook the sanitiser would emit a bare
 // `[REDACTED]` for the secret rather than a correlatable
 // `[REDACTED:<hmac>]` tag on any subsequent log line touching it.
  const readLogger = await getDocsLogger(env);
  await markMobileSandboxSecretAsKnown(
    { clientId: result.data.client_id, hmacSecret: result.data.hmac_secret },
    "kv-read",
    readLogger,
  );
  return result.data;
}

async function writeIssuerRecord(
  env: DocsEnv,
  record: MobileIssuerRecord,
  now: number,
): Promise<void> {
 // INVARIANT-DSGW-2: every KV write surface that persists the
 // per-install HMAC secret in cleartext (the issuer record JSON) must
 // register the plaintext with the redaction tag cache. The mint path
 // already registered the same value, but the refresh path
 // (`handleMobileSandboxRefresh` -> `writeIssuerRecord`) reuses a
 // record loaded from KV, so an isolate that warmed up via refresh
 // (rather than register) only touches the secret here. Idempotent
 // registration is cheap; missing it is the failure mode.
  const writeLogger = await getDocsLogger(env);
  await markMobileSandboxSecretAsKnown(
    { clientId: record.client_id, hmacSecret: record.hmac_secret },
    "kv-write",
    writeLogger,
  );
  const ttl = Math.max(1, Math.ceil((record.expires_at - now) / 1000));
  await env.DOCS_SESSIONS.put(
    `${KV_PREFIX_MOBILE_ISSUER}${record.client_id}`,
    JSON.stringify(record),
    { expirationTtl: ttl },
  );
  await env.DOCS_SESSIONS.put(
    `${KV_PREFIX_MOBILE_INSTALL}${record.install_uuid}`,
    JSON.stringify({ client_id: record.client_id }),
    { expirationTtl: ttl },
  );
}

async function deleteIssuerRecord(
  env: DocsEnv,
  record: MobileIssuerRecord,
): Promise<void> {
  await env.DOCS_SESSIONS.delete(`${KV_PREFIX_MOBILE_ISSUER}${record.client_id}`);
  await env.DOCS_SESSIONS.delete(
    `${KV_PREFIX_MOBILE_INSTALL}${record.install_uuid}`,
  );
}

// ============================================================================
// Nonce I/O
// ============================================================================

async function writeNonceRecord(
  env: DocsEnv,
  nonceHex: string,
  record: MobileNonceRecord,
): Promise<void> {
  await env.DOCS_SESSIONS.put(
    `${KV_PREFIX_MOBILE_NONCE}${nonceHex}`,
    JSON.stringify(record),
    { expirationTtl: NONCE_TTL_SECONDS },
  );
}

async function consumeNonce(
  env: DocsEnv,
  nonceHex: string,
): Promise<MobileNonceRecord | null> {
  const kvKey = `${KV_PREFIX_MOBILE_NONCE}${nonceHex}`;
  let raw: string | null;
  try {
    raw = await env.DOCS_SESSIONS.get(kvKey);
  } catch {
    return null;
  }
  if (raw === null) return null;

 // Delete immediately after reading to minimise the TOCTOU window.
 // KV is eventually consistent, so a narrow race remains where two
 // concurrent callers both read before either deletes. Defence in depth
 // at the provii-issuer layer prevents actual replay exploitation.
  try {
    await env.DOCS_SESSIONS.delete(kvKey);
  } catch {
 // KV delete is best-effort; proceed with validation.
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  const result = MobileNonceRecordSchema.safeParse(parsed);
  if (!result.success) return null;
  return result.data;
}

// ============================================================================
// GET /api/mobile/sandbox/challenge
// ============================================================================

/**
 * Mint a fresh 32-byte nonce for the mobile client to feed into
 * `KeyGenParameterSpec.setAttestationChallenge` (Android) or hash into
 * the App Attest `clientDataHash` (iOS). Returns nonce + expiry + the
 * expected platform tag (echoed if the caller hinted).
 */
export async function handleMobileSandboxChallenge(
  request: Request,
  env: MobileSandboxEnv,
  now: number = Date.now(),
): Promise<Response> {
  const originRejection = checkMobileOrigin(request);
  if (originRejection !== null) return originRejection;

 // CAT-A-02: Per-IP rate limit. Every challenge call writes a nonce to KV.
 // Without rate limiting an unauthenticated caller can flood KV. Fail-closed.
  const remoteIp = request.headers.get("CF-Connecting-IP");
  const rateLimit = await checkChallengeRateLimit(env, remoteIp, now);
  if (!rateLimit.allowed) {
    return mobileError(
      429,
      "mobile_rate_limited",
      "Challenge rate limit reached. Retry shortly.",
      { "Retry-After": String(rateLimit.retryAfterSeconds) },
    );
  }

  const url = new URL(request.url);
  const platformParam = url.searchParams.get("platform");
  let platform: "ios" | "android" | undefined;
  if (platformParam !== null) {
    const parsed = PlatformSchema.safeParse(platformParam);
    if (!parsed.success) {
      return mobileError(
        400,
        "mobile_invalid_platform",
        "Query parameter platform must be 'ios' or 'android'.",
      );
    }
    platform = parsed.data;
  }

  const nonceHex = randomHex(32);
  await writeNonceRecord(env, nonceHex, {
    issued_at: now,
    ...(platform !== undefined ? { platform } : {}),
  });

  const body = {
    nonce: nonceHex,
    expires_at: now + NONCE_TTL_SECONDS * 1000,
    ttl_seconds: NONCE_TTL_SECONDS,
  };
  return new Response(JSON.stringify(body), { status: 200, headers: JSON_HEADERS });
}

// ============================================================================
// POST /api/mobile/sandbox/register
// ============================================================================

/**
 * Body reader bounded to a mobile-register-friendly ceiling. App Attest
 * receipts land around 5 KiB; Android chains can add a few KiB more. 32
 * KiB is comfortably above both with margin for base64 overhead.
 */
const REGISTER_BODY_MAX_BYTES = 32 * 1024;

interface RegisterReadOutcome {
  kind: "ok" | "too_large" | "stream_error" | "invalid_json";
  raw?: unknown;
}

async function readRegisterBody(request: Request): Promise<RegisterReadOutcome> {
  const lengthHeader = request.headers.get("Content-Length");
  if (lengthHeader !== null) {
    const declared = Number(lengthHeader);
    if (Number.isFinite(declared) && declared > REGISTER_BODY_MAX_BYTES) {
      return { kind: "too_large" };
    }
  }
  if (request.body === null) return { kind: "invalid_json" };

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > REGISTER_BODY_MAX_BYTES) {
        try {
          await reader.cancel();
        } catch {
 // non-fatal
        }
        return { kind: "too_large" };
      }
      chunks.push(value);
    }
  } catch {
    return { kind: "stream_error" };
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(merged);
  } catch {
    return { kind: "stream_error" };
  }
  try {
    return { kind: "ok", raw: JSON.parse(text) };
  } catch {
    return { kind: "invalid_json" };
  }
}

/**
 * Handle `POST /api/mobile/sandbox/register`. Flow:
 *
 * 1. Origin pin + body cap.
 * 2. Schema parse.
 * 3. Per-IP hourly rate limit.
 * 4. Atomic nonce consume.
 * 5. Active-count ceiling.
 * 6. Real attestation verify (iOS or Android).
 * 7. Mint client_id + hmac_secret, persist under two KV keys.
 * 8. Bump the active-count counter.
 */
export async function handleMobileSandboxRegister(
  request: Request,
  env: MobileSandboxEnv,
  now: number = Date.now(),
): Promise<Response> {
  const originRejection = checkMobileOrigin(request);
  if (originRejection !== null) return originRejection;

  const body = await readRegisterBody(request);
  if (body.kind === "too_large") {
    return mobileError(
      413,
      "mobile_payload_too_large",
      `Body exceeds ${REGISTER_BODY_MAX_BYTES} bytes.`,
    );
  }
  if (body.kind === "stream_error") {
    return mobileError(400, "mobile_malformed_body", "Body could not be read.");
  }
  if (body.kind === "invalid_json") {
    return mobileError(400, "mobile_malformed_body", "Body must be JSON.");
  }

  const parsed = MobileRegisterRequestSchema.safeParse(body.raw);
  if (!parsed.success) {
    return mobileError(
      400,
      "mobile_schema_mismatch",
      "Body failed mobile register schema validation.",
    );
  }
  const data = parsed.data;

  const remoteIp = request.headers.get("CF-Connecting-IP");
  const rateLimit = await checkRegisterRateLimit(env, remoteIp, now);
  if (!rateLimit.allowed) {
    return mobileError(
      429,
      "mobile_rate_limited",
      "Register ceiling reached. Retry after the hour boundary.",
      { "Retry-After": String(rateLimit.retryAfterSeconds) },
    );
  }

  const nonce = await consumeNonce(env, data.attestation_nonce);
  if (nonce === null) {
    return mobileError(
      409,
      "mobile_nonce_unknown_or_consumed",
      "attestation_nonce is unknown, expired, or already consumed.",
    );
  }

 // Active-count ceiling. Read-then-write race bounded by per-IP limit.
  const activeCount = await readActiveCount(env);
  if (activeCount === null) {
    return mobileError(
      503,
      "mobile_state_unavailable",
      "Active-issuer counter is temporarily unavailable.",
    );
  }
  if (activeCount >= ACTIVE_ISSUER_CEILING) {
    return mobileError(
      503,
      "mobile_sandbox_capacity_reached",
      "Sandbox issuer ceiling reached. Retry after pruning runs.",
    );
  }

 // Real attestation verification.
  const challengeBytes = hexToBytes(data.attestation_nonce);
  if (challengeBytes === null) {
    return mobileError(
      400,
      "mobile_internal_hex_error",
      "attestation_nonce could not be decoded.",
    );
  }

  const attestationLogger = await getDocsLogger(env);

  try {
    if (data.platform === "ios") {
      await verifyIosAttestation(env, data, challengeBytes, now);
    } else {
      await verifyAndroidAttestation(env, data, challengeBytes, now);
    }
  } catch (err) {
    const detail = err instanceof Error ? err.message : "Unknown error";
    attestationLogger.error("[mobile-attestation]", detail);
    return mobileError(
      400,
      "mobile_attestation_rejected",
      "Attestation verification failed.",
    );
  }

 // Mint + persist.
  const clientIdSuffix = bytesToHex(randomBytes(16));
  const clientId = `mwallet-sbx-${clientIdSuffix}`;
  const hmacSecret = randomHex(32);
 // INVARIANT-DSGW-2: this isolate just minted the per-install HMAC
 // secret. Register the plaintext with the redaction tag cache before
 // the value flows into the KV record literal below or the response
 // body further down. Without this hook a stray log of the freshly
 // minted secret would emit a bare `[REDACTED]` rather than the
 // correlatable `[REDACTED:<hmac>]` form.
  const mintLogger = await getDocsLogger(env);
  await markMobileSandboxSecretAsKnown(
    { clientId, hmacSecret },
    "self-mint",
    mintLogger,
  );
  const expiresAt = now + ISSUER_TTL_SECONDS * 1000;
  const record = MobileIssuerRecordSchema.parse({
    client_id: clientId,
    hmac_secret: hmacSecret,
    install_uuid: data.install_uuid,
    platform: data.platform,
    app_version: data.app_version,
    issued_at: now,
    expires_at: expiresAt,
    last_refreshed_at: now,
  });
  await writeIssuerRecord(env, record, now);
  await bumpActiveCount(env, +1);

  const responseBody = {
    client_id: clientId,
    hmac_secret: hmacSecret,
 // Wire format for expires_at is ISO8601 (mobile parsers use Instant.parse
 // / ISO8601DateFormatter). KV storage keeps unix millis for TTL math.
    expires_at: new Date(expiresAt).toISOString(),
    refresh_ttl_remaining: ISSUER_TTL_SECONDS,
    envelope_version: HMAC_ENVELOPE_VERSION,
  };
  return new Response(JSON.stringify(responseBody), {
    status: 200,
    headers: JSON_HEADERS,
  });
}

/**
 * iOS-side attestation verification. Decodes the base64 CBOR token and
 * runs `verifyAppAttest` against the pinned Apple root with the env-chosen
 * AAGUID. `MOBILE_APP_BUNDLE_ID` is required; without it the verifier
 * cannot bind to a known app identity and we reject.
 */
async function verifyIosAttestation(
  env: MobileSandboxEnv,
  data: MobileRegisterRequest,
  challengeBytes: Uint8Array,
  now: number,
): Promise<void> {
  if (env.MOBILE_APP_BUNDLE_ID === undefined || env.MOBILE_APP_BUNDLE_ID === "") {
    throw new Error("iOS app bundle id is not configured.");
  }
  if (data.app_attest_token === undefined) {
    throw new Error("iOS registration requires app_attest_token.");
  }
  const tokenBytes = base64ToBytes(data.app_attest_token);
  const aaguidEnv = (env.MOBILE_APPLE_AAGUID_ENV ?? "prod").toLowerCase();
  const expectedAaguid = aaguidEnv === "dev" ? APPLE_AAGUID_DEV : APPLE_AAGUID_PROD;
  await verifyAppAttest(tokenBytes, {
    appId: env.MOBILE_APP_BUNDLE_ID,
    expectedAaguid,
    challenge: challengeBytes,
    nowMs: now,
  });
}

/**
 * Android-side attestation verification. Decodes every base64 DER cert in
 * the chain, then runs `verifyKeyAttestation` against the pinned Google
 * Hardware Attestation root. Env override takes precedence over the
 * module default (`GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64`) so Tim
 * can rotate the root without a redeploy.
 */
async function verifyAndroidAttestation(
  env: MobileSandboxEnv,
  data: MobileRegisterRequest,
  challengeBytes: Uint8Array,
  now: number,
): Promise<void> {
  if (data.key_attestation_chain === undefined) {
    throw new Error("Android registration requires key_attestation_chain.");
  }
  const chain = data.key_attestation_chain.map((b64) => base64ToBytes(b64));
  const pinned =
    env.MOBILE_ANDROID_PINNED_ROOT_DER_B64 !== undefined
    && env.MOBILE_ANDROID_PINNED_ROOT_DER_B64 !== ""
      ? env.MOBILE_ANDROID_PINNED_ROOT_DER_B64
      : GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64;
  await verifyKeyAttestation(chain, {
    challenge: challengeBytes,
    pinnedRootDerBase64: pinned,
    ...(env.MOBILE_ANDROID_PACKAGE_NAME !== undefined
      ? { expectedPackageName: env.MOBILE_ANDROID_PACKAGE_NAME }
      : {}),
    nowMs: now,
  });
}

// ============================================================================
// POST /api/mobile/sandbox/revoke
// ============================================================================

/**
 * Revoke a mobile sandbox issuer. HMAC-authenticated with the plaintext
 * secret minted by `/register`. The request body carries only `client_id`
 * (must match the one in the auth header). On success the issuer record
 * and the install reverse index are deleted, and the active-count counter
 * decrements.
 */
export async function handleMobileSandboxRevoke(
  request: Request,
  env: MobileSandboxEnv,
  now: number = Date.now(),
): Promise<Response> {
  const originRejection = checkMobileOrigin(request);
  if (originRejection !== null) return originRejection;

  const body = await readRegisterBody(request);
  if (body.kind === "too_large") {
    return mobileError(
      413,
      "mobile_payload_too_large",
      `Body exceeds ${REGISTER_BODY_MAX_BYTES} bytes.`,
    );
  }
  if (body.kind === "stream_error" || body.kind === "invalid_json") {
    return mobileError(400, "mobile_malformed_body", "Body must be JSON.");
  }

  const parsed = MobileLifecycleRequestSchema.safeParse(body.raw);
  if (!parsed.success) {
    return mobileError(
      400,
      "mobile_schema_mismatch",
      "Body failed mobile lifecycle schema validation.",
    );
  }

  const bodyBytes = jcsBytes(parsed.data);
  const hmac = await verifyMobileHmac(
    env,
    request,
    bodyBytes,
    "/api/mobile/sandbox/revoke",
    now,
  );
  if (!hmac.ok) {
    return mobileError(hmac.status, hmac.code, hmac.message);
  }
  if (hmac.record.client_id !== parsed.data.client_id) {
    return mobileError(
      400,
      "mobile_client_id_mismatch",
      "Body client_id does not match authenticated client.",
    );
  }

  await deleteIssuerRecord(env, hmac.record);
  await bumpActiveCount(env, -1);

  return new Response(
    JSON.stringify({ revoked: true, client_id: hmac.record.client_id }),
    { status: 200, headers: JSON_HEADERS },
  );
}

// ============================================================================
// POST /api/mobile/sandbox/refresh
// ============================================================================

/**
 * Extend a mobile sandbox issuer's TTL. HMAC-authenticated identically to
 * `/revoke`. The new expiry is `now + ISSUER_TTL_SECONDS`; we do not stack
 * refreshes, so a client that calls refresh ten times gets a single
 * 7-day window starting from the last call. `last_refreshed_at` is
 * bumped; the install reverse index TTL is refreshed alongside.
 */
export async function handleMobileSandboxRefresh(
  request: Request,
  env: MobileSandboxEnv,
  now: number = Date.now(),
): Promise<Response> {
  const originRejection = checkMobileOrigin(request);
  if (originRejection !== null) return originRejection;

  const body = await readRegisterBody(request);
  if (body.kind === "too_large") {
    return mobileError(
      413,
      "mobile_payload_too_large",
      `Body exceeds ${REGISTER_BODY_MAX_BYTES} bytes.`,
    );
  }
  if (body.kind === "stream_error" || body.kind === "invalid_json") {
    return mobileError(400, "mobile_malformed_body", "Body must be JSON.");
  }

  const parsed = MobileLifecycleRequestSchema.safeParse(body.raw);
  if (!parsed.success) {
    return mobileError(
      400,
      "mobile_schema_mismatch",
      "Body failed mobile lifecycle schema validation.",
    );
  }

  const bodyBytes = jcsBytes(parsed.data);
  const hmac = await verifyMobileHmac(
    env,
    request,
    bodyBytes,
    "/api/mobile/sandbox/refresh",
    now,
  );
  if (!hmac.ok) {
    return mobileError(hmac.status, hmac.code, hmac.message);
  }
  if (hmac.record.client_id !== parsed.data.client_id) {
    return mobileError(
      400,
      "mobile_client_id_mismatch",
      "Body client_id does not match authenticated client.",
    );
  }

  const newExpires = now + ISSUER_TTL_SECONDS * 1000;
  const refreshed: MobileIssuerRecord = {
    ...hmac.record,
    expires_at: newExpires,
    last_refreshed_at: now,
  };
  await writeIssuerRecord(env, refreshed, now);

  return new Response(
    JSON.stringify({
      client_id: refreshed.client_id,
      expires_at: new Date(refreshed.expires_at).toISOString(),
      refresh_ttl_remaining: ISSUER_TTL_SECONDS,
    }),
    { status: 200, headers: JSON_HEADERS },
  );
}

// ============================================================================
// Test helpers (internal; exercised by __tests__/mobile-sandbox.test.ts)
// ============================================================================

/** @internal Test-only: sign a canonical envelope. Handy for building valid fixtures. */
export async function __signMobileEnvelopeForTests(
  secretHex: string,
  method: string,
  path: string,
  timestamp: number,
  nonceHex: string,
  bodyJcs: Uint8Array,
): Promise<string> {
  const keyBytes = hexToBytes(secretHex);
  if (keyBytes === null) throw new Error("invalid secret hex");
  const canonical = buildCanonicalHmacMessage(method, path, timestamp, nonceHex, bodyJcs);
  const tag = await hmacSha256(keyBytes, canonical);
  return bytesToHex(tag);
}

export const __mobileTestExports = {
  buildCanonicalHmacMessage,
  parseAuthHeader,
  checkRegisterRateLimit,
  readActiveCount,
  bumpActiveCount,
  loadIssuerRecord,
  MOBILE_ACTIVE_COUNT_KEY: KV_KEY_ACTIVE_COUNT,
  MOBILE_ISSUER_PREFIX: KV_PREFIX_MOBILE_ISSUER,
  MOBILE_NONCE_PREFIX: KV_PREFIX_MOBILE_NONCE,
  MOBILE_INSTALL_PREFIX: KV_PREFIX_MOBILE_INSTALL,
  HMAC_ENVELOPE_VERSION,
  ISSUER_TTL_SECONDS,
  NONCE_TTL_SECONDS,
  REGISTER_PER_IP_PER_HOUR,
  ACTIVE_ISSUER_CEILING,
  MAX_TIMESTAMP_SKEW_SECONDS,
};
