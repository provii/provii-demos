// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Docs gateway rate limiting ( remediation).
 *
 * Two tiers plus two hard ceilings. Every limiter in here is scoped to the
 * docs surface via the `ratelimit:docs:*` key prefix or a dedicated binding,
 * so a compromise of the playground rate-limit state cannot blunt these
 * controls and vice versa.
 *
 * Tiers:
 * Tier A Creation endpoints (`/session/init`, `/csrf/bootstrap`,
 * `/challenge`). KV-counter keyed on the bearer HMAC, 1-minute
 * window. Kept in `DOCS_SESSIONS` under
 * `ratelimit:docs:create:<bearer_hmac>:<minute>` with a 2-minute
 * TTL so the counter survives the active minute plus the next
 * one during minute-boundary churn.
 * Tier B Polling endpoint (`/status/:id`). Uses the Cloudflare Rate
 * Limiting API binding `DOCS_STATUS_POLL_LIMITER` (declared in
 * wrangler.toml as `[[unsafe.bindings]] type = "ratelimit"`) with
 * a 10-second period. Binding is the right fit here because
 * poll traffic is the hot path and we want the edge-side
 * sliding-window enforcement rather than KV round-trips.
 *
 * Hard ceilings:
 * - Per-challenge `poll_count` lifetime cap: 30. Tracked on the challenge
 * record (see `ChallengeRecordSchema` in schemas.ts); incremented here
 * and surfaced via `checkPollRateLimit` / `incrementPollCount`.
 * - Per-bearer daily cap: 500 polls. Stored under
 * `ratelimit:docs:poll-daily:<bearer_hmac>:<date>` with a 25-hour TTL.
 *
 * Failure policy: every limiter fails closed. A KV read error, a Rate
 * Limiting binding throw, or a schema parse failure turns into a rejection
 * rather than a pass. The docs surface is low-traffic sandbox tooling; a
 * minute of unavailability during an outage is an acceptable cost to
 * guarantee the ceilings hold. Callers get a structured `RateLimitDecision`
 * that carries the machine-readable reason so 429 responses stay consistent.
 */

import { z } from "zod";

import type { DocsEnv } from "./handler";
import {
  ChallengeRecordSchema,
  KV_PREFIX_DOCS_CHALLENGE,
  KV_PREFIX_DOCS_RATELIMIT,
  type ChallengeRecord,
} from "./schemas";

// ============================================================================
// Tier A: creation endpoints, KV-counter
// ============================================================================

/** Maximum creation-endpoint requests per bearer per minute. */
const CREATION_TIER_LIMIT_PER_MINUTE = 20;

/**
 * TTL applied to the minute counter. Two minutes so a counter written at
 * second 59 of minute N still exists at second 0 of minute N+1 when the
 * next bucket is opened; eventual expiry removes stale keys.
 */
const CREATION_TIER_TTL_SECONDS = 120;

// ============================================================================
// Tier B: polling endpoint, binding + hard ceilings
// ============================================================================

/** Per-challenge lifetime poll ceiling from AR-C3. */
export const POLL_LIFETIME_CEILING_PER_CHALLENGE = 30;

/** Per-bearer daily poll ceiling from AR-C3. */
const POLL_DAILY_CEILING_PER_BEARER = 500;

/**
 * TTL for the daily counter. 25 hours covers the active UTC day plus a one
 * hour buffer so a poll recorded at 23:59 and queried at 00:00 sees the
 * correct preceding day's total until it naturally expires.
 */
const POLL_DAILY_TTL_SECONDS = 25 * 60 * 60;

// ============================================================================
// Public types
// ============================================================================

/**
 * Structured outcome from every rate-limit check. Callers consume
 * `allowed` for the 429 branch and echo `reason` and optional
 * `retry_after_seconds` into their response body so clients can back off
 * intelligently. Never throws: every error path collapses to
 * `{ allowed: false, reason: "..." }` so callers cannot fail open by
 * forgetting to wrap in try/catch.
 */
export interface RateLimitDecision {
  allowed: boolean;
  reason:
    | "ok"
    | "tier_a_exceeded"
    | "tier_b_exceeded"
    | "poll_ceiling_exceeded"
    | "poll_daily_exceeded"
    | "challenge_not_found"
    | "internal_error";
  retry_after_seconds?: number;
}

/**
 * Shape of the polling binding declared in wrangler.toml. Narrowed to the
 * single method we call so the interface is not dependent on the shifting
 * experimental `unsafe.bindings` surface. `env.DOCS_STATUS_POLL_LIMITER`
 * is optional because the foundation commit may run without the binding
 * provisioned; the helper fails closed when the binding is absent.
 */
export interface DocsStatusPollLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/**
 * DocsEnv augmented with the rate-limit binding. Kept here rather than on
 * `DocsEnv` itself so tasks that do not touch rate limiting can import the
 * narrower type. The binding name matches wrangler.toml.
 */
export type RateLimitEnv = DocsEnv & {
  DOCS_STATUS_POLL_LIMITER?: DocsStatusPollLimiter;
};

// ============================================================================
// Internal helpers
// ============================================================================

/** Current UTC minute as a string key, e.g. `2026-04-13T17:42`. */
function currentMinuteKey(now: number): string {
  const date = new Date(now);
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");
  const hour = String(date.getUTCHours()).padStart(2, "0");
  const minute = String(date.getUTCMinutes()).padStart(2, "0");
  return `${year}-${month}-${day}T${hour}:${minute}`;
}

/** Current UTC date as `YYYY-MM-DD`. */
function currentDateKey(now: number): string {
  const date = new Date(now);
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

/** Schema for the creation-tier counter stored as a JSON string. */
const CreationCounterSchema = z.object({
  count: z.number().int().min(0),
});

/** Schema for the daily-poll counter stored as a JSON string. */
const DailyPollCounterSchema = z.object({
  count: z.number().int().min(0),
});

/**
 * Safely parse a KV JSON value. Returns null on missing, malformed, or
 * schema-violating payloads so the caller can treat any of those cases as
 * "no counter yet". Never throws.
 */
function parseCounter<T extends z.ZodTypeAny>(
  schema: T,
  raw: string | null,
): z.infer<T> | null {
  if (raw === null) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    const result = schema.safeParse(parsed);
    if (!result.success) return null;
    return result.data;
  } catch {
    return null;
  }
}

// ============================================================================
// Tier A: creation endpoints
// ============================================================================

/**
 * Increment the creation-tier counter for `bearerHmac` and decide whether
 * the request is allowed. Fails closed on any KV error, schema mismatch, or
 * missing binding. Uses a read-modify-write rather than a true atomic
 * counter because KV does not expose an atomic increment; the race here is
 * bounded at one extra request per isolate per minute, which is well inside
 * the ceiling's headroom.
 */
export async function checkCreationRateLimit(
  env: DocsEnv,
  bearerHmac: string,
  now: number = Date.now(),
): Promise<RateLimitDecision> {
  if (!bearerHmac) {
    return { allowed: false, reason: "internal_error" };
  }

  const minute = currentMinuteKey(now);
  const key = `${KV_PREFIX_DOCS_RATELIMIT}create:${bearerHmac}:${minute}`;

  try {
    const existingRaw = await env.DOCS_SESSIONS.get(key);
    const existing = parseCounter(CreationCounterSchema, existingRaw);
    const nextCount = (existing?.count ?? 0) + 1;

    if (nextCount > CREATION_TIER_LIMIT_PER_MINUTE) {
 // Seconds remaining in the current UTC minute, bounded to >=1.
      const secondsIntoMinute = Math.floor((now % 60_000) / 1000);
      const retryAfter = Math.max(1, 60 - secondsIntoMinute);
      return {
        allowed: false,
        reason: "tier_a_exceeded",
        retry_after_seconds: retryAfter,
      };
    }

    await env.DOCS_SESSIONS.put(
      key,
      JSON.stringify({ count: nextCount }),
      { expirationTtl: CREATION_TIER_TTL_SECONDS },
    );

    return { allowed: true, reason: "ok" };
  } catch {
    return { allowed: false, reason: "internal_error" };
  }
}

// ============================================================================
// Tier B: polling endpoint
// ============================================================================

/**
 * Decide whether a poll for `challengeId` on behalf of `bearerHmac` is
 * allowed. Runs four checks in order and returns on the first failure:
 * 1. Rate Limiting binding (Tier B, 10-second period).
 * 2. Per-bearer daily ceiling (500 polls/day).
 * 3. Challenge record exists and has not exhausted the lifetime cap.
 * Does NOT mutate counters; the caller must invoke `incrementPollCount`
 * after a successful upstream fetch so a failed upstream call does not
 * consume a poll slot. Fails closed on any error.
 */
export async function checkPollRateLimit(
  env: RateLimitEnv,
  bearerHmac: string,
  challengeId: string,
  now: number = Date.now(),
): Promise<RateLimitDecision> {
  if (!bearerHmac || !challengeId) {
    return { allowed: false, reason: "internal_error" };
  }

 // 1. Tier B: Rate Limiting binding.
  try {
    const limiter = env.DOCS_STATUS_POLL_LIMITER;
    if (!limiter) {
      return { allowed: false, reason: "internal_error" };
    }
    const outcome = await limiter.limit({
      key: `docs:status-poll:${bearerHmac}:${challengeId}`,
    });
    if (!outcome.success) {
      return {
        allowed: false,
        reason: "tier_b_exceeded",
        retry_after_seconds: 10,
      };
    }
  } catch {
    return { allowed: false, reason: "internal_error" };
  }

 // 2. Daily ceiling.
  const dailyKey = `${KV_PREFIX_DOCS_RATELIMIT}poll-daily:${bearerHmac}:${currentDateKey(now)}`;
  try {
    const existingRaw = await env.DOCS_SESSIONS.get(dailyKey);
    const existing = parseCounter(DailyPollCounterSchema, existingRaw);
    const currentCount = existing?.count ?? 0;
    if (currentCount >= POLL_DAILY_CEILING_PER_BEARER) {
      return {
        allowed: false,
        reason: "poll_daily_exceeded",
      };
    }
  } catch {
    return { allowed: false, reason: "internal_error" };
  }

 // 3. Challenge record and lifetime cap.
  try {
    const challengeKey = `${KV_PREFIX_DOCS_CHALLENGE}${challengeId}`;
    const raw = await env.DOCS_SESSIONS.get(challengeKey);
    if (raw === null) {
      return { allowed: false, reason: "challenge_not_found" };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { allowed: false, reason: "internal_error" };
    }
    const result = ChallengeRecordSchema.safeParse(parsed);
    if (!result.success) {
      return { allowed: false, reason: "internal_error" };
    }
    if (result.data.poll_count >= POLL_LIFETIME_CEILING_PER_CHALLENGE) {
      return { allowed: false, reason: "poll_ceiling_exceeded" };
    }
  } catch {
    return { allowed: false, reason: "internal_error" };
  }

  return { allowed: true, reason: "ok" };
}

/**
 * Record one upstream poll against `challengeId` and the owning bearer's
 * daily counter. Called only after `checkPollRateLimit` passes AND the
 * upstream request completes, so rate-limited polls do not consume budget.
 * Fails closed: on error, callers should treat the poll as though the
 * ceiling had been hit. Returns the new poll_count on success.
 *
 * ACCEPTED RACE (challenge-scoped poll_count is read-modify-write):
 * Two concurrent polls for the same challenge can both read poll_count = N
 * and both write N+1, losing one increment. KV does not expose CAS at the
 * Workers binding level, so this is unavoidable without moving the counter
 * to a Durable Object. The race is bounded by the tier-A Cloudflare Rate
 * Limiting binding above (10 polls/10s per bearer/challenge) and by the
 * lifetime ceiling check in `checkPollRateLimit`. In the worst case, a
 * caller polling at the maximum allowed rate can leak ~1-2 polls past
 * `POLL_LIFETIME_CEILING_PER_CHALLENGE` per concurrent client, which is
 * within the safety margin baked into that ceiling. We do not promote this
 * to a DO because (a) the wallet client polls at most once per ~2s, (b)
 * the ceiling is upper-bound enforcement not exact accounting, and (c) the
 * upstream provii-verifier also rate-limits per challenge. Cross-reference
 * tracker: .
 *
 * The bearer-daily counter (second KV write below) has the same race
 * shape and the same acceptance argument; the daily ceiling is set with
 * the same margin in mind.
 */
export async function incrementPollCount(
  env: DocsEnv,
  bearerHmac: string,
  challengeId: string,
  now: number = Date.now(),
): Promise<{ ok: true; poll_count: number } | { ok: false }> {
  if (!bearerHmac || !challengeId) {
    return { ok: false };
  }

 // Challenge-scoped counter.
  let newPollCount: number;
  try {
    const challengeKey = `${KV_PREFIX_DOCS_CHALLENGE}${challengeId}`;
    const raw = await env.DOCS_SESSIONS.get(challengeKey);
    if (raw === null) return { ok: false };
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { ok: false };
    }
    const result = ChallengeRecordSchema.safeParse(parsed);
    if (!result.success) return { ok: false };

    const nextRecord: ChallengeRecord = {
      ...result.data,
      poll_count: result.data.poll_count + 1,
    };
    newPollCount = nextRecord.poll_count;

 // Preserve the original hard-expiry so the challenge expires at the
 // upstream-dictated time, not at the write moment.
    const expirationTtl = Math.max(
      1,
      Math.ceil((result.data.expires_at - now) / 1000),
    );
    await env.DOCS_SESSIONS.put(challengeKey, JSON.stringify(nextRecord), {
      expirationTtl,
    });
  } catch {
    return { ok: false };
  }

 // Bearer-daily counter. Best effort: if this write fails after the
 // challenge write succeeded, the next poll will still be bounded by the
 // challenge-level ceiling, so we still return `ok` with the new count.
  try {
    const dailyKey = `${KV_PREFIX_DOCS_RATELIMIT}poll-daily:${bearerHmac}:${currentDateKey(now)}`;
    const existingRaw = await env.DOCS_SESSIONS.get(dailyKey);
    const existing = parseCounter(DailyPollCounterSchema, existingRaw);
    const nextCount = (existing?.count ?? 0) + 1;
    await env.DOCS_SESSIONS.put(
      dailyKey,
      JSON.stringify({ count: nextCount }),
      { expirationTtl: POLL_DAILY_TTL_SECONDS },
    );
  } catch {
 // Deliberately swallowed; see note above.
  }

  return { ok: true, poll_count: newPollCount };
}
