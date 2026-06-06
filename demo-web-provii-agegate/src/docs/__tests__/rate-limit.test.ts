// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Rate-limit module tests ( / ).
 *
 * Covers the three public functions exported by `rate-limit.ts`:
 * - `checkCreationRateLimit` (Tier A, KV-counter per minute)
 * - `checkPollRateLimit` (Tier B, binding + daily + lifetime caps)
 * - `incrementPollCount` (challenge + daily counter writes)
 *
 * Each function is exercised against an in-memory KV stub and (for Tier B)
 * a configurable poll limiter stub, so the tests run without Miniflare
 * bindings and verify pure logic rather than KV transport. The KV stub
 * honours `get`, `put`, and `delete` with TTL tracking; it does not
 * simulate eventual consistency because the module's accepted race
 * documentation already accounts for that gap.
 */

import { describe, expect, it, beforeEach } from "vitest";

import {
  checkCreationRateLimit,
  checkPollRateLimit,
  incrementPollCount,
  POLL_LIFETIME_CEILING_PER_CHALLENGE,
  type RateLimitDecision,
  type RateLimitEnv,
  type DocsStatusPollLimiter,
} from "../rate-limit";
import type { DocsEnv } from "../handler";
import {
  KV_PREFIX_DOCS_CHALLENGE,
  KV_PREFIX_DOCS_RATELIMIT,
} from "../schemas";

// ============================================================================
// Stubs
// ============================================================================

/**
 * Minimal in-memory KV namespace stub. Stores values as strings keyed by
 * their KV key. Ignores TTL enforcement (callers are responsible for
 * checking expiry semantics where needed). Tracks put calls so tests can
 * assert write side-effects.
 */
function buildKvStub(): KVNamespace & { _store: Map<string, string>; _puts: Array<{ key: string; value: string }> } {
  const store = new Map<string, string>();
  const puts: Array<{ key: string; value: string }> = [];
  return {
    _store: store,
    _puts: puts,
    get(key: string) {
      return Promise.resolve(store.get(key) ?? null);
    },
    put(key: string, value: string, _opts?: unknown) {
      store.set(key, value);
      puts.push({ key, value });
      return Promise.resolve();
    },
    delete(key: string) {
      store.delete(key);
      return Promise.resolve();
    },
    list: () => Promise.resolve({ keys: [], list_complete: true, cacheStatus: null }),
    getWithMetadata: () => Promise.resolve({ value: null, metadata: null, cacheStatus: null }),
  } as unknown as KVNamespace & { _store: Map<string, string>; _puts: Array<{ key: string; value: string }> };
}

/** Build a DocsEnv backed by the given KV stub. */
function buildDocsEnv(kv: KVNamespace): DocsEnv {
  return { DOCS_SESSIONS: kv } as DocsEnv;
}

/** Build a RateLimitEnv with a configurable poll limiter. */
function buildRateLimitEnv(
  kv: KVNamespace,
  limiter?: DocsStatusPollLimiter | undefined,
): RateLimitEnv {
  return {
    DOCS_SESSIONS: kv,
    DOCS_STATUS_POLL_LIMITER: limiter,
  } as RateLimitEnv;
}

/** Limiter stub that always allows. */
function buildAllowLimiter(): DocsStatusPollLimiter {
  return {
    limit: () => Promise.resolve({ success: true }),
  };
}

/** Limiter stub that always rejects. */
function buildRejectLimiter(): DocsStatusPollLimiter {
  return {
    limit: () => Promise.resolve({ success: false }),
  };
}

/** Limiter stub that throws (simulates binding failure). */
function buildBrokenLimiter(): DocsStatusPollLimiter {
  return {
    limit: () => Promise.reject(new Error("limiter binding unreachable")),
  };
}

// A fixed timestamp: 2026-05-19T12:30:15.000Z
const FIXED_NOW = Date.UTC(2026, 4, 19, 12, 30, 15);

const BEARER_HMAC = "a".repeat(64);
const CHALLENGE_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
const SESSION_ID = "b".repeat(32);

/** A valid challenge record for seeding KV. */
function validChallengeRecord(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    challenge_id: CHALLENGE_ID,
    session_id: SESSION_ID,
    environment: "sandbox",
    poll_count: 0,
    expires_at: FIXED_NOW + 300_000, // 5 minutes ahead
    code_verifier: "A".repeat(43),
    ...overrides,
  });
}

// ============================================================================
// Tier A: checkCreationRateLimit
// ============================================================================

describe("checkCreationRateLimit (Tier A)", () => {
  let kv: ReturnType<typeof buildKvStub>;
  let docsEnv: DocsEnv;

  beforeEach(() => {
    kv = buildKvStub();
    docsEnv = buildDocsEnv(kv);
  });

  it("allows the first request for a bearer in a fresh minute", async () => {
    const decision = await checkCreationRateLimit(docsEnv, BEARER_HMAC, FIXED_NOW);
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe("ok");
  });

  it("allows up to 20 requests in the same minute window", async () => {
    for (let i = 0; i < 20; i++) {
      const decision = await checkCreationRateLimit(docsEnv, BEARER_HMAC, FIXED_NOW);
      expect(decision.allowed).toBe(true);
      expect(decision.reason).toBe("ok");
    }
  });

  it("rejects the 21st request in the same minute window", async () => {
    for (let i = 0; i < 20; i++) {
      await checkCreationRateLimit(docsEnv, BEARER_HMAC, FIXED_NOW);
    }
    const decision = await checkCreationRateLimit(docsEnv, BEARER_HMAC, FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("tier_a_exceeded");
    expect(decision.retry_after_seconds).toBeGreaterThan(0);
  });

  it("provides a sensible retry_after_seconds value", async () => {
 // At 15 seconds into the minute (FIXED_NOW = ...12:30:15), 45 seconds remain.
    for (let i = 0; i < 20; i++) {
      await checkCreationRateLimit(docsEnv, BEARER_HMAC, FIXED_NOW);
    }
    const decision = await checkCreationRateLimit(docsEnv, BEARER_HMAC, FIXED_NOW);
    expect(decision.retry_after_seconds).toBe(45);
  });

  it("resets the counter when a new minute begins", async () => {
 // Exhaust the limit in the current minute.
    for (let i = 0; i < 20; i++) {
      await checkCreationRateLimit(docsEnv, BEARER_HMAC, FIXED_NOW);
    }
    const rejected = await checkCreationRateLimit(docsEnv, BEARER_HMAC, FIXED_NOW);
    expect(rejected.allowed).toBe(false);

 // Advance to the next minute.
    const nextMinute = FIXED_NOW + 60_000;
    const allowed = await checkCreationRateLimit(docsEnv, BEARER_HMAC, nextMinute);
    expect(allowed.allowed).toBe(true);
    expect(allowed.reason).toBe("ok");
  });

  it("tracks separate counters per bearer", async () => {
    const otherBearer = "f".repeat(64);

 // Exhaust bearer A.
    for (let i = 0; i < 20; i++) {
      await checkCreationRateLimit(docsEnv, BEARER_HMAC, FIXED_NOW);
    }
    const rejectedA = await checkCreationRateLimit(docsEnv, BEARER_HMAC, FIXED_NOW);
    expect(rejectedA.allowed).toBe(false);

 // Bearer B should still be allowed.
    const allowedB = await checkCreationRateLimit(docsEnv, otherBearer, FIXED_NOW);
    expect(allowedB.allowed).toBe(true);
  });

  it("rejects with internal_error when bearerHmac is empty", async () => {
    const decision = await checkCreationRateLimit(docsEnv, "", FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("internal_error");
  });

  it("fails closed when KV throws on get", async () => {
    const brokenKv = {
      get: () => Promise.reject(new Error("kv down")),
      put: () => Promise.resolve(),
      delete: () => Promise.resolve(),
      list: () => Promise.resolve({ keys: [], list_complete: true, cacheStatus: null }),
      getWithMetadata: () => Promise.resolve({ value: null, metadata: null, cacheStatus: null }),
    } as unknown as KVNamespace;
    const brokenEnv = buildDocsEnv(brokenKv);

    const decision = await checkCreationRateLimit(brokenEnv, BEARER_HMAC, FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("internal_error");
  });

  it("fails closed when KV throws on put", async () => {
    const brokenKv = {
      get: () => Promise.resolve(null),
      put: () => Promise.reject(new Error("kv write failed")),
      delete: () => Promise.resolve(),
      list: () => Promise.resolve({ keys: [], list_complete: true, cacheStatus: null }),
      getWithMetadata: () => Promise.resolve({ value: null, metadata: null, cacheStatus: null }),
    } as unknown as KVNamespace;
    const brokenEnv = buildDocsEnv(brokenKv);

    const decision = await checkCreationRateLimit(brokenEnv, BEARER_HMAC, FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("internal_error");
  });

  it("treats a corrupted counter value as zero (fresh start)", async () => {
 // Seed a malformed counter value.
    const minuteKey = "2026-05-19T12:30";
    const kvKey = `${KV_PREFIX_DOCS_RATELIMIT}create:${BEARER_HMAC}:${minuteKey}`;
    kv._store.set(kvKey, "not-valid-json");

    const decision = await checkCreationRateLimit(docsEnv, BEARER_HMAC, FIXED_NOW);
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe("ok");
  });

  it("persists the incremented counter to KV after a successful check", async () => {
    await checkCreationRateLimit(docsEnv, BEARER_HMAC, FIXED_NOW);

 // Verify the counter was written.
    const minuteKey = "2026-05-19T12:30";
    const kvKey = `${KV_PREFIX_DOCS_RATELIMIT}create:${BEARER_HMAC}:${minuteKey}`;
    const raw = kv._store.get(kvKey);
    expect(raw).toBeDefined();
    const parsed = JSON.parse(raw!);
    expect(parsed.count).toBe(1);
  });
});

// ============================================================================
// Tier B: checkPollRateLimit
// ============================================================================

describe("checkPollRateLimit (Tier B)", () => {
  let kv: ReturnType<typeof buildKvStub>;

  beforeEach(() => {
    kv = buildKvStub();
  });

  it("allows a poll when all checks pass", async () => {
 // Seed a valid challenge record.
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, validChallengeRecord());

    const rateLimitEnv = buildRateLimitEnv(kv, buildAllowLimiter());
    const decision = await checkPollRateLimit(rateLimitEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe("ok");
  });

  it("rejects when the Tier B binding rate-limits", async () => {
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, validChallengeRecord());

    const rateLimitEnv = buildRateLimitEnv(kv, buildRejectLimiter());
    const decision = await checkPollRateLimit(rateLimitEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("tier_b_exceeded");
    expect(decision.retry_after_seconds).toBe(10);
  });

  it("fails closed when the limiter binding is absent", async () => {
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, validChallengeRecord());

    const rateLimitEnv = buildRateLimitEnv(kv, undefined);
    const decision = await checkPollRateLimit(rateLimitEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("internal_error");
  });

  it("fails closed when the limiter binding throws", async () => {
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, validChallengeRecord());

    const rateLimitEnv = buildRateLimitEnv(kv, buildBrokenLimiter());
    const decision = await checkPollRateLimit(rateLimitEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("internal_error");
  });

  it("rejects when the daily poll ceiling is reached", async () => {
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, validChallengeRecord());

 // Seed the daily counter at the ceiling (500).
    const dateKey = "2026-05-19";
    const dailyKvKey = `${KV_PREFIX_DOCS_RATELIMIT}poll-daily:${BEARER_HMAC}:${dateKey}`;
    kv._store.set(dailyKvKey, JSON.stringify({ count: 500 }));

    const rateLimitEnv = buildRateLimitEnv(kv, buildAllowLimiter());
    const decision = await checkPollRateLimit(rateLimitEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("poll_daily_exceeded");
  });

  it("allows when the daily counter is one below the ceiling", async () => {
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, validChallengeRecord());

    const dateKey = "2026-05-19";
    const dailyKvKey = `${KV_PREFIX_DOCS_RATELIMIT}poll-daily:${BEARER_HMAC}:${dateKey}`;
    kv._store.set(dailyKvKey, JSON.stringify({ count: 499 }));

    const rateLimitEnv = buildRateLimitEnv(kv, buildAllowLimiter());
    const decision = await checkPollRateLimit(rateLimitEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe("ok");
  });

  it("rejects when the per-challenge lifetime ceiling is reached", async () => {
    kv._store.set(
      `${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`,
      validChallengeRecord({ poll_count: POLL_LIFETIME_CEILING_PER_CHALLENGE }),
    );

    const rateLimitEnv = buildRateLimitEnv(kv, buildAllowLimiter());
    const decision = await checkPollRateLimit(rateLimitEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("poll_ceiling_exceeded");
  });

  it("allows when the per-challenge counter is one below the lifetime ceiling", async () => {
    kv._store.set(
      `${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`,
      validChallengeRecord({ poll_count: POLL_LIFETIME_CEILING_PER_CHALLENGE - 1 }),
    );

    const rateLimitEnv = buildRateLimitEnv(kv, buildAllowLimiter());
    const decision = await checkPollRateLimit(rateLimitEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe("ok");
  });

  it("rejects with challenge_not_found when no challenge record exists", async () => {
    const rateLimitEnv = buildRateLimitEnv(kv, buildAllowLimiter());
    const decision = await checkPollRateLimit(rateLimitEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("challenge_not_found");
  });

  it("fails closed when the challenge record is malformed JSON", async () => {
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, "{{broken");

    const rateLimitEnv = buildRateLimitEnv(kv, buildAllowLimiter());
    const decision = await checkPollRateLimit(rateLimitEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("internal_error");
  });

  it("fails closed when the challenge record fails schema validation", async () => {
 // Valid JSON but missing required fields.
    kv._store.set(
      `${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`,
      JSON.stringify({ challenge_id: CHALLENGE_ID }),
    );

    const rateLimitEnv = buildRateLimitEnv(kv, buildAllowLimiter());
    const decision = await checkPollRateLimit(rateLimitEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("internal_error");
  });

  it("rejects with internal_error when bearerHmac is empty", async () => {
    const rateLimitEnv = buildRateLimitEnv(kv, buildAllowLimiter());
    const decision = await checkPollRateLimit(rateLimitEnv, "", CHALLENGE_ID, FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("internal_error");
  });

  it("rejects with internal_error when challengeId is empty", async () => {
    const rateLimitEnv = buildRateLimitEnv(kv, buildAllowLimiter());
    const decision = await checkPollRateLimit(rateLimitEnv, BEARER_HMAC, "", FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("internal_error");
  });

  it("fails closed when daily counter KV read throws", async () => {
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, validChallengeRecord());

 // Override the get method to fail only on the daily-counter key.
    const originalGet = kv.get.bind(kv);
    kv.get = ((key: string) => {
      if (key.includes("poll-daily:")) {
        return Promise.reject(new Error("kv read failed"));
      }
      return originalGet(key);
    }) as KVNamespace["get"];

    const rateLimitEnv = buildRateLimitEnv(kv, buildAllowLimiter());
    const decision = await checkPollRateLimit(rateLimitEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("internal_error");
  });
});

// ============================================================================
// incrementPollCount
// ============================================================================

describe("incrementPollCount", () => {
  let kv: ReturnType<typeof buildKvStub>;
  let docsEnv: DocsEnv;

  beforeEach(() => {
    kv = buildKvStub();
    docsEnv = buildDocsEnv(kv);
  });

  it("increments the challenge poll_count from 0 to 1", async () => {
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, validChallengeRecord());

    const result = await incrementPollCount(docsEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.poll_count).toBe(1);
    }
  });

  it("increments from an existing poll_count", async () => {
    kv._store.set(
      `${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`,
      validChallengeRecord({ poll_count: 14 }),
    );

    const result = await incrementPollCount(docsEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.poll_count).toBe(15);
    }
  });

  it("persists the updated challenge record back to KV", async () => {
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, validChallengeRecord());

    await incrementPollCount(docsEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);

    const raw = kv._store.get(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`);
    expect(raw).toBeDefined();
    const record = JSON.parse(raw!);
    expect(record.poll_count).toBe(1);
  });

  it("increments the bearer daily poll counter", async () => {
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, validChallengeRecord());

    await incrementPollCount(docsEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);

    const dateKey = "2026-05-19";
    const dailyKvKey = `${KV_PREFIX_DOCS_RATELIMIT}poll-daily:${BEARER_HMAC}:${dateKey}`;
    const raw = kv._store.get(dailyKvKey);
    expect(raw).toBeDefined();
    const counter = JSON.parse(raw!);
    expect(counter.count).toBe(1);
  });

  it("accumulates the daily counter across multiple increments", async () => {
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, validChallengeRecord());

 // Seed an existing daily counter at 42.
    const dateKey = "2026-05-19";
    const dailyKvKey = `${KV_PREFIX_DOCS_RATELIMIT}poll-daily:${BEARER_HMAC}:${dateKey}`;
    kv._store.set(dailyKvKey, JSON.stringify({ count: 42 }));

    await incrementPollCount(docsEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);

    const raw = kv._store.get(dailyKvKey);
    expect(raw).toBeDefined();
    const counter = JSON.parse(raw!);
    expect(counter.count).toBe(43);
  });

  it("returns ok: false when the challenge record does not exist", async () => {
    const result = await incrementPollCount(docsEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(result.ok).toBe(false);
  });

  it("returns ok: false when the challenge record is malformed", async () => {
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, "not json");

    const result = await incrementPollCount(docsEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(result.ok).toBe(false);
  });

  it("returns ok: false when the challenge record fails schema validation", async () => {
    kv._store.set(
      `${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`,
      JSON.stringify({ challenge_id: CHALLENGE_ID, environment: "production" }),
    );

    const result = await incrementPollCount(docsEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(result.ok).toBe(false);
  });

  it("returns ok: false when bearerHmac is empty", async () => {
    const result = await incrementPollCount(docsEnv, "", CHALLENGE_ID, FIXED_NOW);
    expect(result.ok).toBe(false);
  });

  it("returns ok: false when challengeId is empty", async () => {
    const result = await incrementPollCount(docsEnv, BEARER_HMAC, "", FIXED_NOW);
    expect(result.ok).toBe(false);
  });

  it("still returns ok: true when the daily counter KV write fails", async () => {
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, validChallengeRecord());

 // Let challenge writes succeed but daily-counter writes fail.
    const originalPut = kv.put.bind(kv);
    let putCallCount = 0;
    kv.put = ((key: string, value: string, opts?: unknown) => {
      putCallCount++;
 // The first put is the challenge record; the second is the daily counter.
      if (putCallCount === 2) {
        return Promise.reject(new Error("daily counter write failed"));
      }
      return originalPut(key, value, opts);
    }) as KVNamespace["put"];

    const result = await incrementPollCount(docsEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
 // The module deliberately swallows the daily-counter write failure.
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.poll_count).toBe(1);
    }
  });

  it("returns ok: false when the challenge record KV write throws", async () => {
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, validChallengeRecord());

 // Fail the very first put (the challenge record write).
    kv.put = (() => Promise.reject(new Error("challenge write failed"))) as KVNamespace["put"];

    const result = await incrementPollCount(docsEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(result.ok).toBe(false);
  });
});

// ============================================================================
// RateLimitDecision type contract
// ============================================================================

describe("RateLimitDecision structure", () => {
  it("allowed decisions carry reason 'ok' and no retry_after", async () => {
    const kv = buildKvStub();
    const docsEnv = buildDocsEnv(kv);

    const decision = await checkCreationRateLimit(docsEnv, BEARER_HMAC, FIXED_NOW);
    expect(decision).toEqual({ allowed: true, reason: "ok" });
    expect(decision.retry_after_seconds).toBeUndefined();
  });

  it("rejected decisions always carry a non-ok reason", async () => {
    const kv = buildKvStub();
    kv._store.set(`${KV_PREFIX_DOCS_CHALLENGE}${CHALLENGE_ID}`, validChallengeRecord());

    const rateLimitEnv = buildRateLimitEnv(kv, buildRejectLimiter());
    const decision = await checkPollRateLimit(rateLimitEnv, BEARER_HMAC, CHALLENGE_ID, FIXED_NOW);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).not.toBe("ok");
  });
});
