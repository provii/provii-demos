// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii
//
// Docs gateway status polling ().
//
// GET /api/status/:id is the hot path: the provii-agegate demo widget polls
// while a user completes verification on their phone. 50 concurrent
// pollers on the same challenge should not translate to 50 upstream
// provii-verifier calls per tick. This module implements the three
// layer defence:
//
// 1. Gateway-side coalescing via `caches.default`. Keyed on the
// challenge id, not the request URL, so cookies / tokens do not
// fragment the cache. TTL 2s for pending states, 30s for terminal
// ones (verified/failed/expired). With a 2s pending TTL every
// concurrent poll for the same id shares one upstream call per two
// second window.
// 2. Tier B rate limiting binding (DOCS_STATUS_POLL_LIMITER), evaluated
// in rate-limit.ts before the cache read so a caller cannot bypass
// the limit by varying the URL.
// 3. Per-challenge lifetime `poll_count` counter (cap 30) incremented
// only after a successful upstream fetch so a failed upstream call
// does not consume budget.
//
// A challenge that has exhausted its lifetime cap returns 429. A challenge
// that has never been registered on this surface returns 404 so pollers
// of arbitrary ids cannot use the endpoint as an oracle.

import { z } from "zod";

import { checkPollRateLimit, incrementPollCount, type RateLimitEnv } from "./rate-limit";
import {
  ChallengeRecordSchema,
  KV_PREFIX_DOCS_CHALLENGE,
  type ChallengeRecord,
} from "./schemas";
import type { DocsEnv } from "./handler";

/**
 * Pending-state cache TTL in seconds. Keep this low enough that a user
 * tapping "approve" on their phone sees the state flip within two seconds;
 * high enough that 50 concurrent pollers share a single upstream call.
 */
const PENDING_CACHE_TTL_SECONDS = 2;

/** Terminal-state cache TTL. Verified/failed/expired never reverts. */
const TERMINAL_CACHE_TTL_SECONDS = 30;

/** Set of upstream states that we treat as terminal. */
const TERMINAL_STATES = new Set([
  "verified",
  "failed",
  "expired",
  "revoked",
]);

/** Timeout applied to upstream service binding fetches (F-5). */
const UPSTREAM_FETCH_TIMEOUT_MS = 10_000;

/** Path on provii-verifier that owns the authoritative challenge state. */
const VERIFIER_STATUS_PATH_PREFIX = "/v1/challenge/";

/**
 * Shape accepted from provii-verifier. `state` is intentionally loose; the
 * gateway does not need to enumerate every upstream state because the
 * only decision the cache makes is "terminal vs pending".
 */
const VerifierStatusResponseSchema = z.object({
  state: z.string().min(1),
  challenge_id: z.string().min(1).optional(),
});

/**
 * Extra context for the handler to assemble its outer Response. Separated
 * from the inner fetch so `statusInner` can be unit-tested without the
 * coalescing shell.
 */
export interface StatusUpstreamResult {
  status: number;
  bodyText: string;
  isTerminal: boolean;
}

/**
 * Result of the entire status-polling flow. Maps 1:1 onto the Response
 * returned by the handler.
 */
export type StatusOutcome =
  | { kind: "response"; response: Response }
  | { kind: "needs_upstream" };

/**
 * Return the `caches.default` cache key for `challengeId`. Uses a synthetic
 * URL because `caches.default` requires a Request keyed on URL. Cookies
 * are stripped by the synthetic request so per-caller state does not
 * fragment the cache.
 */
function cacheKeyForChallenge(challengeId: string): Request {
  return new Request(`https://docs-gateway.internal/status-cache/${challengeId}`, {
    method: "GET",
  });
}

/**
 * Issue a Response tagged with a Cache-Control directive that matches the
 * TTL we want for this state. The TTL drives `caches.default.put` not
 * client caches; client-side we always set `Cache-Control: no-store` on
 * the outer response.
 */
function makeCacheEntry(status: number, bodyText: string, isTerminal: boolean): Response {
  const ttl = isTerminal ? TERMINAL_CACHE_TTL_SECONDS : PENDING_CACHE_TTL_SECONDS;
  return new Response(bodyText, {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": `public, s-maxage=${ttl}`,
    },
  });
}

/**
 * Try to serve the status from `caches.default`. Returns the cached body
 * + status if present, otherwise null so the caller knows to run the
 * upstream path.
 */
async function readFromCache(challengeId: string): Promise<{
  status: number;
  bodyText: string;
} | null> {
  const cache = caches.default;
  const cached = await cache.match(cacheKeyForChallenge(challengeId));
  if (cached === undefined) return null;
  const bodyText = await cached.text();
  return { status: cached.status, bodyText };
}

/**
 * Persist a freshly-fetched status into `caches.default`. Invoked after
 * every successful upstream round trip.
 */
async function writeToCache(
  challengeId: string,
  status: number,
  bodyText: string,
  isTerminal: boolean,
  ctx: ExecutionContext,
): Promise<void> {
  const cache = caches.default;
  const entry = makeCacheEntry(status, bodyText, isTerminal);
  ctx.waitUntil(cache.put(cacheKeyForChallenge(challengeId), entry));
}

/**
 * Load the challenge record from KV. Returns null on missing, malformed,
 * or schema-violating records so the handler can map those to 404.
 */
async function loadChallenge(
  env: DocsEnv,
  challengeId: string,
): Promise<ChallengeRecord | null> {
  let raw: string | null;
  try {
    raw = await env.DOCS_SESSIONS.get(
      `${KV_PREFIX_DOCS_CHALLENGE}${challengeId}`,
    );
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
  const result = ChallengeRecordSchema.safeParse(parsed);
  if (!result.success) return null;
  return result.data;
}

/**
 * Call provii-verifier for the authoritative challenge state. Classifies the
 * response as terminal or pending so the coalescing cache can use the
 * right TTL.
 */
async function fetchUpstreamStatus(
  env: DocsEnv,
  challengeId: string,
): Promise<StatusUpstreamResult | null> {
  if (env.VERIFIER_API_SANDBOX === undefined) return null;
  let response: Response;
  try {
    response = await env.VERIFIER_API_SANDBOX.fetch(
      new Request(
        `https://provii-verifier${VERIFIER_STATUS_PATH_PREFIX}${challengeId}`,
        { method: "GET", signal: AbortSignal.timeout(UPSTREAM_FETCH_TIMEOUT_MS) },
      ),
    );
  } catch {
    return null;
  }
  const rawText = await response.text();
 // F-3: Parse and re-serialise upstream JSON to prevent HTML injection and
 // open-redirect vectors. Non-JSON upstream bodies become a generic 502.
  let parsedBody: unknown;
  try {
    parsedBody = JSON.parse(rawText);
  } catch {
    return { status: 502, bodyText: JSON.stringify({ error: { code: "docs_status_upstream_invalid_json", message: "Upstream response was not valid JSON." } }), isTerminal: false };
  }
  const reSerialisedBody = JSON.stringify(parsedBody);
  if (!response.ok) {
    return { status: response.status, bodyText: reSerialisedBody, isTerminal: false };
  }
  const parsed = VerifierStatusResponseSchema.safeParse(parsedBody);
  if (!parsed.success) {
    return { status: 502, bodyText: reSerialisedBody, isTerminal: false };
  }
  const isTerminal = TERMINAL_STATES.has(parsed.data.state.toLowerCase());
  return { status: 200, bodyText: reSerialisedBody, isTerminal };
}

/**
 * Handle one `/api/status/:id` poll end-to-end. The caller has already
 * session-authenticated and established the session record.
 */
export async function handleChallengeStatus(
  env: RateLimitEnv,
  ctx: ExecutionContext,
  challengeId: string,
  bearerHashHex: string,
  sessionId: string,
  now: number = Date.now(),
): Promise<Response> {
 // Tier B + daily-cap + lifetime-cap check. Consumes neither the cache
 // nor the upstream budget if it fails.
  const decision = await checkPollRateLimit(env, bearerHashHex, challengeId, now);
  if (!decision.allowed) {
    const status = decision.reason === "challenge_not_found" ? 404 : 429;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    };
    if (decision.retry_after_seconds !== undefined) {
      headers["Retry-After"] = String(decision.retry_after_seconds);
    }
    return new Response(
      JSON.stringify({
        error: { code: `docs_${decision.reason}`, message: decision.reason },
      }),
      { status, headers },
    );
  }

 // Challenge record must exist AND be bound to this session. Prevents a
 // caller with a valid cookie from polling challenges they did not mint.
  const challenge = await loadChallenge(env, challengeId);
  if (challenge === null) {
    return new Response(
      JSON.stringify({
        error: { code: "docs_challenge_not_found", message: "No such challenge." },
      }),
      {
        status: 404,
        headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
      },
    );
  }
  if (challenge.session_id !== sessionId) {
    return new Response(
      JSON.stringify({
        error: {
          code: "docs_challenge_session_mismatch",
          message: "Challenge does not belong to this session.",
        },
      }),
      {
        status: 403,
        headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
      },
    );
  }

 // Edge cache lookup. If a warm entry exists (populated by a prior poll
 // in the same 2s/30s window), serve it without touching upstream or the
 // poll counter.
  const cached = await readFromCache(challengeId);
  if (cached !== null) {
    return new Response(cached.bodyText, {
      status: cached.status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "X-Docs-Cache": "hit",
      },
    });
  }

 // Cache miss: fetch upstream, increment counter, cache.
  const upstream = await fetchUpstreamStatus(env, challengeId);
  if (upstream === null) {
    return new Response(
      JSON.stringify({
        error: {
          code: "docs_status_upstream_unreachable",
          message: "provii-verifier is unreachable.",
        },
      }),
      {
        status: 502,
        headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
      },
    );
  }

 // Only count successful upstream fetches against the lifetime cap. A
 // 502 or 503 from provii-verifier should not burn poll budget that the
 // caller did not get value from.
  if (upstream.status < 500) {
    const bumped = await incrementPollCount(env, bearerHashHex, challengeId, now);
    if (!bumped.ok) {
 // Counter write failed. Treat as a hard failure to keep the cap
 // enforceable rather than risk blowing past 30 polls silently.
      return new Response(
        JSON.stringify({
          error: {
            code: "docs_status_counter_write_failed",
            message: "Failed to record poll. Retry shortly.",
          },
        }),
        {
          status: 503,
          headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
        },
      );
    }
  }

  await writeToCache(
    challengeId,
    upstream.status,
    upstream.bodyText,
    upstream.isTerminal,
    ctx,
  );

  return new Response(upstream.bodyText, {
    status: upstream.status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-Docs-Cache": "miss",
    },
  });
}
