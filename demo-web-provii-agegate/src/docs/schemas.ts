// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Docs gateway Zod schemas and KV key prefixes.
 *
 * Every record persisted to the DOCS_SESSIONS KV namespace gets validated
 * through one of the schemas below before write and after read. Validation at
 * both boundaries means a malformed value cached by an older code path cannot
 * silently corrupt later handler logic; reads either return a clean typed
 * value or throw a ZodError that the handler maps to a 5xx.
 *
 * Surface scope (post per-session credential mint retirement):
 * - Bearer session cookie state.
 * - Challenge state for the TestInWallet widget on /guides/mobile-verification.
 * - Rate-limit counter prefix.
 *
 * Real upstream credential material is no longer minted per-session; the
 * gateway signs `/v1/challenge` against a sandbox credential it self-mints
 * via `POST /v1/register-test-origin` and caches in this same KV namespace
 * under `docs-bootstrap-cred:v1`. Authentication of the mint call uses the
 * shared `SANDBOX_API_KEY` Secrets Store binding.
 */

import { z } from "zod";

// ============================================================================
// KV key prefixes
// All under the DOCS_SESSIONS namespace bound in wrangler.toml. Trailing colon
// preserved so callers concatenate `${PREFIX}${id}` and never accidentally
// share a key space across record kinds.
// ============================================================================

/** Prefix for `__Host-docs_session` cookie payloads. */
export const KV_PREFIX_DOCS_SESSION = "docs-session:" as const;

/**
 * Secondary index mapping `bearer_hash` to `session_id` (ADV-S2). Written
 * alongside the primary session record at the same TTL so
 * `authenticateSession` can resolve a cookie to a session_id in a single
 * KV get. Separate prefix keeps listings under `docs-session:` free of
 * index entries.
 */
export const KV_PREFIX_DOCS_SESSION_IDX = "docs-session-idx:" as const;

/** Prefix for in-flight challenge records driving `/api/status/:id` polling. */
export const KV_PREFIX_DOCS_CHALLENGE = "docs-chal:" as const;

/** Prefix for KV-counter rate limits scoped to docs gateway endpoints. */
export const KV_PREFIX_DOCS_RATELIMIT = "ratelimit:docs:" as const;

// ============================================================================
// Shared primitive validators
// ============================================================================

/** Hex string of exactly `length` characters (case-insensitive). */
function hexString(length: number) {
  return z.string().regex(new RegExp(`^[0-9a-fA-F]{${length}}$`));
}

/** Unix epoch milliseconds. Positive integer. */
const epochMillis = z.number().int().positive();

/** Sandbox-only literal pinned across every docs record. */
const sandboxEnvironment = z.literal("sandbox");

// ============================================================================
// Session cookie payload
// ============================================================================

/**
 * Decoded `__Host-docs_session` cookie body. The cookie itself carries
 * `kid` plus the HMAC tag; the bearer hash is persisted server-side under
 * `docs-session:<session_id>`.
 */
export const DocsSessionSchema = z.object({
  /** Key id prefix that selects the active DOCS_SESSION_HMAC_KEY for verification. */
  kid: z.string().min(1).max(32),
  /** HMAC-SHA-256 of the raw bearer token bytes, hex-encoded. */
  bearer_hash: hexString(64),
  /** Random session identifier, hex-encoded. 128 bits of entropy. */
  session_id: hexString(32),
  /** Issuance timestamp (epoch ms). */
  issued_at: epochMillis,
  /** Hard expiry timestamp (epoch ms). 4-hour cap from issued_at. */
  expires_at: epochMillis,
  /**
 * Per-session CSRF secret derived on first call to
 * `/api/csrf/bootstrap` ( + ). Stored as 64-hex (32 raw bytes).
 * Optional because legacy session records minted before the primer endpoint
 * landed will not carry it; the CSRF verify helper maps "absent" to a 401
 * asking the caller to bootstrap first.
   */
  csrf_secret: hexString(64).optional(),
});

export type DocsSession = z.infer<typeof DocsSessionSchema>;

/**
 * Value persisted at `docs-session-idx:<bearer_hash>` (ADV-S2). Index entry
 * pointing back at the owning `session_id` so `authenticateSession` can
 * resolve a cookie's bearer hash to a session record in O(1). Kept as its
 * own object shape (not a bare string) so future fields can attach without
 * another KV rewrite.
 */
export const DocsSessionIdxSchema = z.object({
  session_id: hexString(32),
});

export type DocsSessionIdx = z.infer<typeof DocsSessionIdxSchema>;

// ============================================================================
// Challenge record
// ============================================================================

/**
 * In-flight challenge persisted at `docs-chal:<challenge_id>`. Tracks the
 * hard-cap poll counter and the absolute expiry used by
 * `/api/status/:id` to serve a 410 once exhausted. The `code_verifier`
 * field carries the PKCE verifier string generated at challenge mint time
 * so `/redeem` can present it to provii-verifier when the proof submission
 * arrives back through this surface. `challenge_id` is a UUIDv4 as issued
 * by provii-verifier.
 */
export const ChallengeRecordSchema = z.object({
  /**
 * Challenge identifier. UUIDv4 as emitted by provii-verifier's
 * `ChallengeResponse`. Hyphenated lower-case canonical form.
   */
  challenge_id: z
    .string()
    .regex(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    ),
  /** Session id that minted the challenge. Used for cross-bind enforcement. */
  session_id: hexString(32),
  /** Pinned to "sandbox"; production never touches this namespace. */
  environment: sandboxEnvironment,
  /** Number of times `/api/status/:id` has fetched upstream for this challenge. */
  poll_count: z.number().int().min(0),
  /** Hard expiry (epoch ms). Challenge TTL is 5 minutes per upstream provii-verifier. */
  expires_at: epochMillis,
  /**
 * PKCE code verifier string generated at challenge mint (ADV-B1). RFC 7636
 * unreserved charset, 43..128 chars. Retained here so `/redeem` can
 * resubmit it to provii-verifier when the wallet completes the proof.
   */
  code_verifier: z
    .string()
    .min(43)
    .max(128)
    .regex(/^[A-Za-z0-9\-._~]+$/),
});

export type ChallengeRecord = z.infer<typeof ChallengeRecordSchema>;
