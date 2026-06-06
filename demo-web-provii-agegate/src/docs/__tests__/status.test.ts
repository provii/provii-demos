// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Status polling module tests ( / ).
 *
 * Exercises `handleChallengeStatus` from `status.ts`, the hot path that
 * the provii-agegate widget polls while a user completes verification on
 * their phone. The module implements three layer defence: gateway
 * cache coalescing, Tier B rate limiting, and per-challenge lifetime
 * poll cap.
 *
 * Each test uses a unique challenge ID and bearer hash to avoid cache
 * bleed and counter accumulation across tests, because `singleWorker`
 * mode shares `caches.default` and KV state across the entire suite.
 *
 * Test groups:
 * 1. Successful upstream fetch with pending and terminal states
 * 2. Rate limiting (Tier B, daily ceiling, lifetime cap)
 * 3. Challenge record validation (missing, session mismatch)
 * 4. Upstream error handling (unreachable, non-JSON, HTTP errors)
 * 5. Poll counter increment behaviour and write failures
 */

import { describe, expect, it } from "vitest";
import { env } from "cloudflare:test";

import { handleChallengeStatus } from "../status";
import {
  KV_PREFIX_DOCS_CHALLENGE,
  KV_PREFIX_DOCS_RATELIMIT,
  type ChallengeRecord,
} from "../schemas";
import {
  POLL_LIFETIME_CEILING_PER_CHALLENGE,
  type RateLimitEnv,
  type DocsStatusPollLimiter,
} from "../rate-limit";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const TEST_SESSION_ID = "abcdef01234567890abcdef012345678";
const WRONG_SESSION_ID = "ffffffffffffffffffffffffffffffff";
const NOW = 1_800_000_000_000;
const FIVE_MINUTES_MS = 5 * 60 * 1000;

/**
 * PKCE code verifier that satisfies the ChallengeRecordSchema regex.
 * 43 chars from the unreserved charset.
 */
const TEST_CODE_VERIFIER = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs";

// Monotonic counter to generate unique IDs per test. Avoids cache and
// counter bleed across tests in the shared Miniflare isolate.
let testCounter = 0;

/**
 * Generate a unique UUIDv4-shaped challenge ID and a matching unique
 * bearer hash for each test invocation. The challenge ID satisfies the
 * ChallengeRecordSchema regex (hyphenated lower-case UUIDv4 with the
 * correct version and variant nibbles).
 */
function uniqueIds(): { challengeId: string; bearerHash: string } {
  testCounter++;
  const hexSuffix = testCounter.toString(16).padStart(12, "0");
  const challengeId = `00000000-0000-4000-8000-${hexSuffix}`;
  const bearerHash = testCounter.toString(16).padStart(64, "0");
  return { challengeId, bearerHash };
}

// Execution context stub. Status handler uses ctx.waitUntil for cache writes.
const ctxStub: ExecutionContext = {
  waitUntil: () => undefined,
  passThroughOnException: () => undefined,
  props: {},
};

// ---------------------------------------------------------------------------
// Env builder helpers
// ---------------------------------------------------------------------------

/** Rate limiter that always allows. */
function alwaysAllowLimiter(): DocsStatusPollLimiter {
  return {
    limit: async () => ({ success: true }),
  };
}

/** Rate limiter that always rejects. */
function alwaysRejectLimiter(): DocsStatusPollLimiter {
  return {
    limit: async () => ({ success: false }),
  };
}

/**
 * Build a RateLimitEnv backed by the real test KV namespace, with a
 * controllable rate limiter and an optional VERIFIER_API_SANDBOX stub.
 */
function buildTestEnv(options: {
  limiter?: DocsStatusPollLimiter;
  verifierFetch?: (request: Request) => Promise<Response>;
}): RateLimitEnv {
  const limiter = options.limiter ?? alwaysAllowLimiter();
  const verifierBinding = options.verifierFetch
    ? ({ fetch: options.verifierFetch } as unknown as Fetcher)
    : undefined;

  return {
    DOCS_SESSIONS: env.DOCS_SESSIONS,
    DOCS_STATUS_POLL_LIMITER: limiter,
    VERIFIER_API_SANDBOX: verifierBinding,
  } as RateLimitEnv;
}

/** Seed a well-formed challenge record into KV. */
async function seedChallengeRecord(
  challengeId: string,
  overrides: Partial<ChallengeRecord> = {},
): Promise<void> {
  const record: ChallengeRecord = {
    challenge_id: challengeId,
    session_id: TEST_SESSION_ID,
    environment: "sandbox",
    poll_count: 0,
    expires_at: NOW + FIVE_MINUTES_MS,
    code_verifier: TEST_CODE_VERIFIER,
    ...overrides,
  };
  await env.DOCS_SESSIONS.put(
    `${KV_PREFIX_DOCS_CHALLENGE}${challengeId}`,
    JSON.stringify(record),
    { expirationTtl: 600 },
  );
}

/**
 * Build a provii-verifier stub that returns the given state JSON. Simulates
 * the upstream `GET /v1/challenge/:id` response.
 */
function verifierReturning(
  state: string,
  challengeId: string,
  httpStatus = 200,
): (req: Request) => Promise<Response> {
  return async () =>
    new Response(
      JSON.stringify({ state, challenge_id: challengeId }),
      {
        status: httpStatus,
        headers: { "Content-Type": "application/json" },
      },
    );
}

/** Parse the JSON body of a Response. */
async function parseJsonBody(response: Response): Promise<unknown> {
  const text = await response.text();
  return JSON.parse(text);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("handleChallengeStatus: successful upstream fetch", () => {
  it("returns 200 with pending state from upstream", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("pending", challengeId),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(200);
    const body = await parseJsonBody(response) as { state: string };
    expect(body.state).toBe("pending");
    expect(response.headers.get("X-Docs-Cache")).toBe("miss");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("returns 200 with verified (terminal) state from upstream", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("verified", challengeId),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(200);
    const body = await parseJsonBody(response) as { state: string };
    expect(body.state).toBe("verified");
  });

  it("returns 200 with failed (terminal) state from upstream", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("failed", challengeId),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(200);
    const body = await parseJsonBody(response) as { state: string };
    expect(body.state).toBe("failed");
  });

  it("returns 200 with expired (terminal) state from upstream", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("expired", challengeId),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(200);
    const body = await parseJsonBody(response) as { state: string };
    expect(body.state).toBe("expired");
  });

  it("returns 200 with revoked (terminal) state from upstream", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("revoked", challengeId),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(200);
    const body = await parseJsonBody(response) as { state: string };
    expect(body.state).toBe("revoked");
  });

  it("increments poll_count on the challenge record after a successful fetch", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("pending", challengeId),
    });

    await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

 // Read the challenge record back and verify the poll count bumped.
    const raw = await env.DOCS_SESSIONS.get(
      `${KV_PREFIX_DOCS_CHALLENGE}${challengeId}`,
    );
    expect(raw).not.toBeNull();
    const record = JSON.parse(raw!) as ChallengeRecord;
    expect(record.poll_count).toBe(1);
  });
});

describe("handleChallengeStatus: rate limiting", () => {
  it("returns 429 when Tier B rate limiter rejects", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      limiter: alwaysRejectLimiter(),
      verifierFetch: verifierReturning("pending", challengeId),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(429);
    const body = await parseJsonBody(response) as { error: { code: string } };
    expect(body.error.code).toBe("docs_tier_b_exceeded");
  });

  it("returns 429 when per-challenge lifetime poll ceiling is reached", async () => {
    const { challengeId, bearerHash } = uniqueIds();
 // Seed a challenge that has already hit the ceiling.
    await seedChallengeRecord(challengeId, {
      poll_count: POLL_LIFETIME_CEILING_PER_CHALLENGE,
    });

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("pending", challengeId),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(429);
    const body = await parseJsonBody(response) as { error: { code: string } };
    expect(body.error.code).toBe("docs_poll_ceiling_exceeded");
  });

  it("returns 429 when per-bearer daily poll ceiling is reached", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

 // Seed the daily counter at the ceiling (500 polls).
    const date = new Date(NOW);
    const year = date.getUTCFullYear();
    const month = String(date.getUTCMonth() + 1).padStart(2, "0");
    const day = String(date.getUTCDate()).padStart(2, "0");
    const dailyKey = `${KV_PREFIX_DOCS_RATELIMIT}poll-daily:${bearerHash}:${year}-${month}-${day}`;
    await env.DOCS_SESSIONS.put(dailyKey, JSON.stringify({ count: 500 }));

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("pending", challengeId),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(429);
    const body = await parseJsonBody(response) as { error: { code: string } };
    expect(body.error.code).toBe("docs_poll_daily_exceeded");
  });

  it("returns 404 when the challenge id does not exist in KV (rate-limit check)", async () => {
    const { challengeId, bearerHash } = uniqueIds();
 // Do NOT seed a challenge record; KV has no entry for this id.

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("pending", challengeId),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(404);
    const body = await parseJsonBody(response) as { error: { code: string } };
    expect(body.error.code).toBe("docs_challenge_not_found");
  });
});

describe("handleChallengeStatus: challenge record validation", () => {
  it("returns 404 when challenge record is absent from KV", async () => {
    const { challengeId, bearerHash } = uniqueIds();
 // No seed: KV has no record for this challenge id.

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("pending", challengeId),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

 // The rate-limit check reads the challenge from KV, finds nothing,
 // and returns challenge_not_found which the handler maps to 404.
    expect(response.status).toBe(404);
  });

  it("returns 403 when session id does not match the challenge record", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("pending", challengeId),
    });

 // Pass a different session id than the one stored on the record.
    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      WRONG_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(403);
    const body = await parseJsonBody(response) as { error: { code: string } };
    expect(body.error.code).toBe("docs_challenge_session_mismatch");
  });

  it("returns 429 when challenge record is malformed JSON in KV (fails closed)", async () => {
    const { challengeId, bearerHash } = uniqueIds();
 // Write invalid JSON directly under the challenge key.
    await env.DOCS_SESSIONS.put(
      `${KV_PREFIX_DOCS_CHALLENGE}${challengeId}`,
      "not valid json {{{",
      { expirationTtl: 600 },
    );

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("pending", challengeId),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

 // Rate-limit check parses the record; malformed JSON fails closed as
 // internal_error. The handler maps non-challenge_not_found reasons to 429.
    expect(response.status).toBe(429);
  });
});

describe("handleChallengeStatus: upstream error handling", () => {
  it("returns 502 when VERIFIER_API_SANDBOX binding is absent", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

 // No verifierFetch provided; binding is undefined.
    const testEnv = buildTestEnv({});

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(502);
    const body = await parseJsonBody(response) as { error: { code: string } };
    expect(body.error.code).toBe("docs_status_upstream_unreachable");
  });

  it("returns 502 when upstream fetch throws (network failure)", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: async () => {
        throw new Error("simulated network failure");
      },
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(502);
    const body = await parseJsonBody(response) as { error: { code: string } };
    expect(body.error.code).toBe("docs_status_upstream_unreachable");
  });

  it("returns 502 when upstream returns non-JSON body", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: async () =>
        new Response("<html>Server Error</html>", {
          status: 200,
          headers: { "Content-Type": "text/html" },
        }),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(502);
    const body = await parseJsonBody(response) as { error: { code: string } };
    expect(body.error.code).toBe("docs_status_upstream_invalid_json");
  });

  it("returns 502 when upstream JSON does not satisfy VerifierStatusResponseSchema", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: async () =>
        new Response(JSON.stringify({ unrelated: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

 // F-3: schema validation failure on an OK upstream body returns 502.
    expect(response.status).toBe(502);
  });

  it("forwards upstream HTTP error status when upstream returns non-OK JSON", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: async () =>
        new Response(
          JSON.stringify({ error: "not found" }),
          { status: 404, headers: { "Content-Type": "application/json" } },
        ),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

 // Upstream 404 is forwarded through as-is.
    expect(response.status).toBe(404);
  });

  it("does not increment poll_count when upstream returns a 5xx error", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: async () =>
        new Response(
          JSON.stringify({ error: "internal" }),
          { status: 503, headers: { "Content-Type": "application/json" } },
        ),
    });

    await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

 // The poll count should remain at 0 because 5xx responses do not
 // consume poll budget per the module contract.
    const raw = await env.DOCS_SESSIONS.get(
      `${KV_PREFIX_DOCS_CHALLENGE}${challengeId}`,
    );
    expect(raw).not.toBeNull();
    const record = JSON.parse(raw!) as ChallengeRecord;
    expect(record.poll_count).toBe(0);
  });

  it("does increment poll_count when upstream returns a 4xx error", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: async () =>
        new Response(
          JSON.stringify({ error: "bad request" }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        ),
    });

    await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

 // 4xx is < 500, so the counter should increment.
    const raw = await env.DOCS_SESSIONS.get(
      `${KV_PREFIX_DOCS_CHALLENGE}${challengeId}`,
    );
    expect(raw).not.toBeNull();
    const record = JSON.parse(raw!) as ChallengeRecord;
    expect(record.poll_count).toBe(1);
  });
});

describe("handleChallengeStatus: poll counter write failures", () => {
  it("returns 503 when incrementPollCount fails due to deleted challenge record", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    let fetchCount = 0;
    const testEnv = buildTestEnv({
      verifierFetch: async () => {
        fetchCount++;
 // On the first upstream call, delete the challenge record from KV
 // to simulate the race between the rate-limit check and the
 // counter increment.
        if (fetchCount === 1) {
          await env.DOCS_SESSIONS.delete(
            `${KV_PREFIX_DOCS_CHALLENGE}${challengeId}`,
          );
        }
        return new Response(
          JSON.stringify({ state: "pending", challenge_id: challengeId }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      },
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

 // The module should return 503 when the counter write fails so the
 // cap remains enforceable.
    expect(response.status).toBe(503);
    const body = await parseJsonBody(response) as { error: { code: string } };
    expect(body.error.code).toBe("docs_status_counter_write_failed");
  });
});

describe("handleChallengeStatus: edge cases", () => {
  it("handles a challenge at poll_count = ceiling - 1 (last allowed poll)", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId, {
      poll_count: POLL_LIFETIME_CEILING_PER_CHALLENGE - 1,
    });

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("pending", challengeId),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

 // The last poll below the ceiling should succeed.
    expect(response.status).toBe(200);

 // Verify the counter is now at the ceiling.
    const raw = await env.DOCS_SESSIONS.get(
      `${KV_PREFIX_DOCS_CHALLENGE}${challengeId}`,
    );
    expect(raw).not.toBeNull();
    const record = JSON.parse(raw!) as ChallengeRecord;
    expect(record.poll_count).toBe(POLL_LIFETIME_CEILING_PER_CHALLENGE);
  });

  it("returns correct headers on every response path", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("pending", challengeId),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.headers.get("Content-Type")).toBe("application/json");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("rejects empty bearerHashHex with a rate-limit error (fails closed)", async () => {
    const { challengeId } = uniqueIds();
    await seedChallengeRecord(challengeId);

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("pending", challengeId),
    });

 // Empty bearer hash triggers the rate limiter's guard clause.
    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      "",
      TEST_SESSION_ID,
      NOW,
    );

 // checkPollRateLimit returns internal_error for empty bearerHmac,
 // which the status handler maps to 429.
    expect(response.status).toBe(429);
  });

  it("rejects empty challengeId with a rate-limit error (fails closed)", async () => {
    const { bearerHash } = uniqueIds();

    const testEnv = buildTestEnv({
      verifierFetch: verifierReturning("pending", ""),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      "",
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(429);
  });

  it("re-serialises upstream JSON to prevent injection (F-3 defence)", async () => {
    const { challengeId, bearerHash } = uniqueIds();
    await seedChallengeRecord(challengeId);

 // Upstream returns JSON containing an HTML script tag. The module
 // parses and re-serialises via JSON.stringify, which escapes the
 // angle brackets in string values.
    const testEnv = buildTestEnv({
      verifierFetch: async () =>
        new Response(
          `{"state":"pending","challenge_id":"${challengeId}","extra_field":"<script>alert(1)</script>"}`,
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    });

    const response = await handleChallengeStatus(
      testEnv,
      ctxStub,
      challengeId,
      bearerHash,
      TEST_SESSION_ID,
      NOW,
    );

    expect(response.status).toBe(200);
    const bodyText = await response.text();
 // The body should be valid JSON (re-serialised by JSON.stringify).
    const parsed = JSON.parse(bodyText);
    expect(parsed.state).toBe("pending");
  });
});
