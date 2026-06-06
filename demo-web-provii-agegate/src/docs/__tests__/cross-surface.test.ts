// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Cross-surface docs gateway tests ().
 *
 * Four groups, each pinning behaviour that is hard to verify by inspection:
 *
 * 1. KV unreachable. When DOCS_SESSIONS throws, the dispatcher and
 * session helpers must fail closed (4xx/5xx, never silently return
 * stale state).
 * 2. Path fuzz. 50 adversarial pathnames must dispatch to either a
 * well-defined route or a 404, never to an unintended handler.
 * 3. Per-isolate cache isolation. The feature flag cache should not
 * bleed values across two distinct keys. Resetting the cache must
 * clear every entry.
 *
 * These tests exercise the modules in isolation. The `handleDocs`
 * end-to-end is covered indirectly via the dispatcher path-fuzz group; we
 * stub the env where a real Worker binding is not yet provisioned in the
 * test harness.
 */

import { describe, expect, it, beforeEach } from "vitest";
import { env } from "cloudflare:test";

import { handleDocs, type DocsEnv } from "../handler";
import {
  __resetFeatureFlagCacheForTests,
  checkEndpointEnabled,
} from "../feature-flags";

// Execution context stub that satisfies handleDocs's signature without
// needing a real Cloudflare Workers waitUntil scheduler.
const ctxStub: ExecutionContext = {
  waitUntil: () => undefined,
  passThroughOnException: () => undefined,
  props: {},
};

/**
 * Build a DocsEnv where DOCS_SESSIONS rejects every operation. Used to
 * verify the dispatcher does not hang or leak state when KV is offline.
 */
function buildBrokenKvEnv(): DocsEnv {
  const brokenKv = {
    get: () => Promise.reject(new Error("kv unreachable")),
    put: () => Promise.reject(new Error("kv unreachable")),
    delete: () => Promise.reject(new Error("kv unreachable")),
    list: () => Promise.reject(new Error("kv unreachable")),
    getWithMetadata: () => Promise.reject(new Error("kv unreachable")),
  } as unknown as KVNamespace;
  return { DOCS_SESSIONS: brokenKv } as DocsEnv;
}

describe("docs gateway: KV unreachable", () => {
  beforeEach(() => {
    __resetFeatureFlagCacheForTests();
  });

  it("checkEndpointEnabled defaults to enabled when KV throws (fail-open)", async () => {
    const broken = buildBrokenKvEnv();
 // Explicitly pass fail-open mode. Failure-closed for the global kill
 // (defaults to false), failure-open for the per-endpoint enable
 // (defaults to true). Net result: enabled.
    const decision = await checkEndpointEnabled(broken, "session_init", "open");
    expect(decision.kind).toBe("enabled");
  });

  it("checkEndpointEnabled defaults to disabled when KV throws (fail-closed)", async () => {
    const broken = buildBrokenKvEnv();
    const decision = await checkEndpointEnabled(broken, "session_init", "closed");
    expect(decision.kind).toBe("endpoint_disabled");
  });

  it("dispatcher returns 404 for unmapped paths even when KV is offline", async () => {
    const broken = buildBrokenKvEnv();
    const req = new Request("https://docs.provii.app/api/does-not-exist", {
      method: "GET",
    });
    const res = await handleDocs(req, broken, ctxStub);
    expect(res.status).toBe(404);
  });

  it("dispatcher returns 503 on wrong method when KV is offline for fail-closed endpoint", async () => {
 // HIGH-1: session_init is fail-closed. When KV is unreachable the
 // feature flag check returns disabled (503) before the method check
 // can run. This is the correct fail-closed posture.
    const broken = buildBrokenKvEnv();
    const req = new Request("https://docs.provii.app/api/session/init", {
      method: "GET",
    });
    const res = await handleDocs(req, broken, ctxStub);
    expect(res.status).toBe(503);
  });
});

describe("docs gateway: path fuzz", () => {
 // 50 adversarial path variants. Each must either dispatch to a
 // well-defined handler (returning a deterministic status) or 404. None
 // may 500 from a missing route table entry.
  const fuzzPaths: readonly string[] = [
    "/api",
    "/api/",
    "/api//",
    "/api/.",
    "/api/..",
    "/api/../",
    "/api/session",
    "/api/session/",
    "/api/session/init/extra",
    "/api/SESSION/INIT",
    "/api/session/init?x=1",
    "/api/credentials",
    "/api/credentials/",
    "/api/credentials/verifier/extra",
    "/api/credentials/issuer/extra",
    "/api/credentials/admin",
    "/api/challenge/",
    "/api/challenge/extra",
    "/api/status",
    "/api/status/",
    "/api/status/123",
    "/api/status/abcd-1234",
    "/api/status/" + "x".repeat(64),
    "/api/status/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    "/api/status/00000000-0000-4000-8000-000000000000",
    "/api/attestation/extra",
    "/api/simulate-proof/",
    "/api/fixtures/",
    "/api/fixtures/list",
    "/api/healthz",
    "/api/admin",
    "/api/admin/secret",
    "/api//session/init",
    "/api/%2e%2e/session",
    "/api/session/init%00",
    "/api/session/init%0a",
    "/api/session/init%20",
    "/api/session/init/../credentials/verifier",
    "/api/x".repeat(20),
    "/",
    "/index.html",
    "/api?",
    "/api/?",
    "/api?path=session/init",
    "/api/session/init#fragment",
    "/api/session\\init",
    "/api/session/init/",
    "/api/Session/Init",
    "/API/session/init",
    "/api/session/init\u200B",
  ];

  it.each(fuzzPaths)(
    "%s dispatches to 404, 405, or 503 (feature-disabled) without 5xx surprises",
    async (path) => {
      const broken = buildBrokenKvEnv();
      const url = path.startsWith("/")
        ? `https://docs.provii.app${path}`
        : `https://docs.provii.app/${path}`;
      const req = new Request(url, { method: "GET" });
      let status: number;
      let body: unknown = null;
      try {
        const res = await handleDocs(req, broken, ctxStub);
        status = res.status;
 // Read the body so the 503 check below can inspect `code`.
 // Empty bodies (e.g. some 405 responses) resolve to null.
        const text = await res.text();
        if (text !== "") {
          try {
            body = JSON.parse(text);
          } catch {
            body = text;
          }
        }
      } catch (err) {
 // Any uncaught exception is a fuzz failure. Surface the path so
 // the failure message is actionable.
        throw new Error(`uncaught from ${path}: ${String(err)}`);
      }
 // 404 is the default for unmapped routes. 405 is the standard
 // method-not-allowed. 503 is the feature-flag-disabled response.
 // 403 is the origin-allowlist rejection that fires before any
 // handler touches KV. Mapped routes (notably `/api/status/:id`)
 // reach 403 because the dispatcher routes them to their handler
 // which origin-rejects an Origin-less fuzz request before any
 // downstream work. The status range is intentionally tight so a
 // future route addition that bypasses validation surfaces here
 // as a 5xx.
      expect([403, 404, 405, 503]).toContain(status);

 // : a 503 is only acceptable when it comes from the feature
 // flag kill path. The two feature-flag decision codes are
 // `docs_gateway_disabled` (global kill) and `docs_endpoint_disabled`
 // (per-endpoint). Any other 503 (e.g.
 // `docs_verifier_service_binding_missing`,
 // `docs_issuer_service_binding_missing`,
 // `docs_sandbox_api_key_unavailable`) would mean fuzz traffic
 // reached a binding call, which is a regression the fuzz test must
 // catch.
      if (status === 503) {
        const code =
          typeof body === "object" &&
          body !== null &&
          "error" in body &&
          typeof (body as { error?: unknown }).error === "object" &&
          (body as { error: unknown }).error !== null &&
          "code" in (body as { error: Record<string, unknown> }).error
            ? ((body as { error: { code?: unknown } }).error.code ?? null)
            : null;
        expect(
          code === "docs_gateway_disabled" ||
            code === "docs_endpoint_disabled",
        ).toBe(true);
      }
    },
  );
});

describe("docs gateway: per-isolate cache isolation", () => {
  beforeEach(() => {
    __resetFeatureFlagCacheForTests();
  });

  it("flag cache caches each key independently", async () => {
 // Set both keys directly to known values, then read them.
    await env.DOCS_SESSIONS.put("docs-features:gateway:disabled", "false");
    await env.DOCS_SESSIONS.put("docs-features:session_init:enabled", "false");

    const sessionInit = await checkEndpointEnabled(
      env as DocsEnv,
      "session_init",
    );
    const challenge = await checkEndpointEnabled(env as DocsEnv, "challenge");

    expect(sessionInit.kind).toBe("endpoint_disabled");
 // challenge has no flag set; defaults to enabled.
    expect(challenge.kind).toBe("enabled");
  });

  it("__resetFeatureFlagCacheForTests forces re-read", async () => {
 // Prime the cache.
    await env.DOCS_SESSIONS.put("docs-features:fixtures:enabled", "false");
    let decision = await checkEndpointEnabled(env as DocsEnv, "fixtures");
    expect(decision.kind).toBe("endpoint_disabled");

 // Flip the underlying value WITHOUT resetting the cache; we should
 // still see the cached "false".
    await env.DOCS_SESSIONS.put("docs-features:fixtures:enabled", "true");
    decision = await checkEndpointEnabled(env as DocsEnv, "fixtures");
    expect(decision.kind).toBe("endpoint_disabled");

 // Reset the cache; now we should see the new value.
    __resetFeatureFlagCacheForTests();
    decision = await checkEndpointEnabled(env as DocsEnv, "fixtures");
    expect(decision.kind).toBe("enabled");
  });
});
