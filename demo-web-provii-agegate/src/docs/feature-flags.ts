// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Per-widget feature flags with global kill switch ().
 *
 * The docs gateway is a single Worker but many endpoints are exercised by
 * different widgets in the docs UI. The flags here let an operator disable
 * a single widget without redeploying, and disable the entire surface in
 * one stroke if the bound-attestation logic regresses or the provii-issuer
 * goes hostile.
 *
 * Storage layout in the DOCS_SESSIONS KV namespace:
 * docs-features:<endpoint>:enabled -> "true" | "false"
 * docs-features:gateway:disabled -> "true" | "false"
 *
 * Reads are cached per isolate for `FEATURE_FLAG_CACHE_TTL_MS` (60s) so
 * each request does not pay a KV round-trip. The cache window is short
 * enough that a kill flip propagates within roughly a minute even without
 * a deploy. Feature flag reads MUST NOT throw; any KV error falls back to
 * the default specified by the caller.
 */

import type { DocsEnv } from "./handler";

/** Per-isolate cache TTL. 60 seconds matches the operator's expected lag. */
const FEATURE_FLAG_CACHE_TTL_MS = 60_000;

/**
 * Endpoints that are gated by per-widget flags. Add new entries explicitly.
 *
 * The per-session credential mint surface (`credentials_verifier`,
 * `credentials_issuer`, `attestation`, `simulate_proof`, `fixtures`) was
 * retired alongside the CredentialGenerator widget; only the surfaces still
 * served by the docs gateway are listed here.
 */
export type DocsFeatureEndpoint =
  | "session_init"
  | "challenge"
  | "status";

/** Global kill key. When true, every endpoint short-circuits to 503. */
const GLOBAL_KILL_KEY = "docs-features:gateway:disabled";

/** Per-endpoint enable key prefix. */
const ENDPOINT_ENABLED_PREFIX = "docs-features:";

interface CacheEntry {
  value: boolean;
  cachedAt: number;
}

/**
 * Per-isolate cache. `let` not `const` so we can clear it during tests via
 * `__resetFeatureFlagCacheForTests`; never exported via the surface API.
 */
let cache: Map<string, CacheEntry> = new Map();

/**
 * Fail mode for feature flag reads. Write endpoints use `"closed"` so a KV
 * outage disables the endpoint rather than leaving it open. Read-only
 * endpoints use `"open"` so a transient KV error does not take widgets down.
 */
export type FeatureFlagFailMode = "open" | "closed";

/** Internal helper: read+cache a single flag with a default fallback. */
async function readFlagCached(
  env: DocsEnv,
  key: string,
  fallback: boolean,
  now: number,
): Promise<boolean> {
  const hit = cache.get(key);
  if (hit !== undefined && now - hit.cachedAt < FEATURE_FLAG_CACHE_TTL_MS) {
    return hit.value;
  }
  let raw: string | null;
  try {
    raw = await env.DOCS_SESSIONS.get(key);
  } catch {
    return fallback;
  }
  let value: boolean;
  if (raw === null) {
    value = fallback;
  } else if (raw === "true") {
    value = true;
  } else if (raw === "false") {
    value = false;
  } else {
 // Anything else is treated as the fallback so a stray value cannot
 // accidentally enable or kill a widget.
    value = fallback;
  }
  cache.set(key, { value, cachedAt: now });
  return value;
}

/**
 * Per-endpoint flag reader that distinguishes "key missing" from "KV error".
 * A missing key always defaults to enabled (no operator has disabled the
 * endpoint). A KV read error uses the fail mode: open returns true, closed
 * returns false.
 */
async function readEndpointFlag(
  env: DocsEnv,
  key: string,
  failMode: FeatureFlagFailMode,
  now: number,
): Promise<boolean> {
  const hit = cache.get(key);
  if (hit !== undefined && now - hit.cachedAt < FEATURE_FLAG_CACHE_TTL_MS) {
    return hit.value;
  }
  let raw: string | null;
  try {
    raw = await env.DOCS_SESSIONS.get(key);
  } catch {
 // KV error: use fail mode.
    return failMode === "open";
  }
  let value: boolean;
  if (raw === null) {
 // Key missing: always default to enabled.
    value = true;
  } else if (raw === "true") {
    value = true;
  } else if (raw === "false") {
    value = false;
  } else {
 // Stray value: default to enabled so a corrupted value does not
 // accidentally disable an endpoint.
    value = true;
  }
  cache.set(key, { value, cachedAt: now });
  return value;
}

/**
 * Outcome of `readPublicFeatureFlag`. Mirrors the JSON shape the docs UI
 * expects from `/api/feature-flags/:key`:
 * `{ enabled: boolean, reason?: string }`
 *
 * `reason` is always populated so operators tailing logs can tell default-on
 * from explicit-on and gateway_killed from endpoint_disabled.
 */
export type PublicFeatureFlagValue = {
  enabled: boolean;
  reason: "default_on" | "flag_true" | "flag_false" | "gateway_killed";
};

/**
 * Public read of a single `docs-features:<widget>:enabled` flag for the
 * `/api/feature-flags/:key` endpoint (). Read posture:
 *
 * 1. Global kill wins. If `docs-features:gateway:disabled` is `"true"`
 * every widget reports `{enabled: false, reason: "gateway_killed"}`.
 * 2. Explicit flag value overrides the default. `"true"` yields
 * `{enabled: true, reason: "flag_true"}`, `"false"` yields
 * `{enabled: false, reason: "flag_false"}`.
 * 3. Missing key defaults to `{enabled: true, reason: "default_on"}`.
 *
 * Caller is responsible for validating the `key` shape before reaching
 * this helper; see the Zod schema guarding the handler in handler.ts.
 */
export async function readPublicFeatureFlag(
  env: DocsEnv,
  key: string,
  now: number = Date.now(),
): Promise<PublicFeatureFlagValue> {
  const killed = await readFlagCached(env, GLOBAL_KILL_KEY, false, now);
  if (killed) {
    return { enabled: false, reason: "gateway_killed" };
  }

 // Read with a sentinel default so we can distinguish "flag missing"
 // from "flag set to true" without a second KV round-trip.
  const hitCache = cache.get(key);
  if (hitCache !== undefined && now - hitCache.cachedAt < FEATURE_FLAG_CACHE_TTL_MS) {
    return {
      enabled: hitCache.value,
      reason: hitCache.value ? "flag_true" : "flag_false",
    };
  }
  let raw: string | null;
  try {
    raw = await env.DOCS_SESSIONS.get(key);
  } catch {
 // Transient KV error falls back to default_on. Same posture as
 // `readFlagCached` uses for its internal callers: a KV outage must
 // not take a widget down by accident.
    return { enabled: true, reason: "default_on" };
  }
  if (raw === null) {
    return { enabled: true, reason: "default_on" };
  }
  if (raw === "true") {
    cache.set(key, { value: true, cachedAt: now });
    return { enabled: true, reason: "flag_true" };
  }
  if (raw === "false") {
    cache.set(key, { value: false, cachedAt: now });
    return { enabled: false, reason: "flag_false" };
  }
 // Stray value: treat as default-on but do not cache so an operator
 // fix-up flows through on the next read.
  return { enabled: true, reason: "default_on" };
}

/** Outcome of `checkEndpointEnabled`. The handler maps each variant 1:1. */
export type FeatureFlagDecision =
  | { kind: "enabled" }
  | { kind: "endpoint_disabled" }
  | { kind: "gateway_disabled" };

/**
 * Decide whether `endpoint` should serve. Order is:
 * 1. Global kill (`docs-features:gateway:disabled = "true"`) wins.
 * 2. Per-endpoint enable flag (`docs-features:<endpoint>:enabled = "false"`).
 * 3. Default enabled.
 *
 * `failMode` controls behaviour when a KV read throws:
 * - `"open"` (default): fall back to enabled. Suitable for read-only
 * endpoints (status, feature-flags, openapi).
 * - `"closed"`: fall back to disabled. Required for write endpoints
 * (challenge, mobile register/revoke/refresh, csrf/bootstrap).
 */
export async function checkEndpointEnabled(
  env: DocsEnv,
  endpoint: DocsFeatureEndpoint,
  failMode: FeatureFlagFailMode = "open",
  now: number = Date.now(),
): Promise<FeatureFlagDecision> {
 // Global kill always fails closed: a KV error should not accidentally
 // suppress a legitimate kill flip, so the global kill fallback stays
 // `false` regardless of failMode.
  const killed = await readFlagCached(env, GLOBAL_KILL_KEY, false, now);
  if (killed) return { kind: "gateway_disabled" };

 // Per-endpoint flag. The KV error fallback differs by fail mode:
 // - "open": KV read error falls back to true (enabled).
 // - "closed": KV read error falls back to false (disabled).
 // A missing key (null) always defaults to true (enabled) regardless of
 // fail mode, because absence of a flag means no operator has disabled
 // the endpoint. Only a KV read *error* (thrown exception) triggers the
 // fail-closed path.
  const endpointKey = `${ENDPOINT_ENABLED_PREFIX}${endpoint}:enabled`;
  const enabled = await readEndpointFlag(env, endpointKey, failMode, now);
  if (!enabled) return { kind: "endpoint_disabled" };

  return { kind: "enabled" };
}

/**
 * Build the JSON body returned when a feature flag short-circuits the
 * handler. The error code makes the dashboard distinguish a global kill
 * (incident response) from a single-widget disable (planned maintenance).
 */
export function buildFeatureFlagErrorBody(
  decision: Exclude<FeatureFlagDecision, { kind: "enabled" }>,
): { code: string; message: string } {
  if (decision.kind === "gateway_disabled") {
    return {
      code: "docs_gateway_disabled",
      message: "Docs gateway is temporarily disabled.",
    };
  }
  return {
    code: "docs_endpoint_disabled",
    message: "This docs endpoint is temporarily disabled.",
  };
}

/** Test-only escape hatch. Not exported via the module's barrel. */
export function __resetFeatureFlagCacheForTests(): void {
  cache = new Map();
}
