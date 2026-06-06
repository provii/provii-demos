// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Tests for `POST /playground/api/create-issuer-environment` in `src/index.ts`.
 *
 * The handler mints an Issuing Party credential bundle by calling
 * `register-test-issuer` on provii-issuer with an `X-Docs-Hmac` tag computed
 * under `SANDBOX_API_KEY`. The Issuer signs every attestation server-side
 * when /v1/attestation/create is later called; the Issuing Party never
 * holds an Ed25519 signing key. The handler returns the upstream payload
 * verbatim. Upstream is mocked through `globalThis.fetch`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import worker, {
  __resetPlaygroundSecretsCacheForTests,
} from "../../index";

// Use a Worker-side stand-in KV that satisfies the get/put/delete surface
// the handler exercises through `getRateLimitState` / `recordRateLimitHit`.
// Running against the real Miniflare KV would force every test to either
// share state or pre-pin a wipe in `beforeEach`, and we want the handler
// to be testable in isolation regardless of the pool's KV bindings.
function buildStubKv(): KVNamespace {
  const store = new Map<string, string>();
  return {
    async get(key: string): Promise<string | null> {
      return store.get(key) ?? null;
    },
    async put(key: string, value: string): Promise<void> {
      store.set(key, value);
    },
    async delete(key: string): Promise<void> {
      store.delete(key);
    },
    async list(): Promise<KVNamespaceListResult<unknown, string>> {
      return {
        keys: Array.from(store.keys()).map((name) => ({ name })),
        list_complete: true,
        cacheStatus: null,
      } as unknown as KVNamespaceListResult<unknown, string>;
    },
    async getWithMetadata(): Promise<never> {
      throw new Error("getWithMetadata not used by this handler");
    },
  } as unknown as KVNamespace;
}

interface MockSecretsBinding {
  get(): Promise<string | null>;
}

function buildSandboxApiKeyBinding(value: string | null): MockSecretsBinding {
  return {
    get: () => Promise.resolve(value),
  };
}

const FIXTURE_API_KEY = "sandbox_api_key_for_tests";
const FIXTURE_ISSUER_BASE = "https://issuer-stub.test";

/**
 * Build the Env shape the worker dispatcher expects. Only the bindings
 * the issuer-environment handler actually reads need to be populated.
 * Everything else is left as a runtime-shaped stub; the dispatcher
 * doesn't reach into the unused bindings on this code path.
 */
function buildEnv(
  overrides: Partial<{
    sandboxApiKey: string | null;
    issuerBaseUrl: string | undefined;
    cfConnectingIp: string;
  }> = {},
): unknown {
 // Use `in` rather than `??` so callers can distinguish "field omitted"
 // (use the fixture key) from "field explicitly null" (mock the unbound
 // Secrets Store binding). Nullish-coalescing collapses both into the
 // omitted branch, which broke the SANDBOX_API_KEY-unbound test.
  const sandboxApiKey =
    "sandboxApiKey" in overrides
      ? (overrides.sandboxApiKey ?? null)
      : FIXTURE_API_KEY;
  return {
    PLAYGROUND_SESSIONS: buildStubKv(),
    SANDBOX_API_KEY: buildSandboxApiKeyBinding(sandboxApiKey),
    ISSUER_API_URL_SANDBOX: overrides.issuerBaseUrl ?? FIXTURE_ISSUER_BASE,
 // Stubs for bindings the handler never touches on this code path.
    __STATIC_CONTENT: undefined,
    DOCS_SESSIONS: buildStubKv(),
  };
}

const ctxStub: ExecutionContext = {
  waitUntil: () => undefined,
  passThroughOnException: () => undefined,
  props: {},
};

function buildUpstreamSuccessBody(): string {
  return JSON.stringify({
    client_id: "cl_iss_sandbox_aabbccddeeff",
    hmac_secret: "minted_issuer_hmac_secret_v1",
    kid: "iss_sbx_12345678",
    expires_at: Math.floor(Date.now() / 1000) + 72 * 60 * 60,
    base_url: "https://sandbox-issuer.provii.app",
    minted_at: Math.floor(Date.now() / 1000),
  });
}

/**
 * Issue a POST against the create-issuer-environment endpoint. Uses an
 * `over.provii.app` host so the dispatcher's subdomain-routing
 * branch falls through to the playground-API match. Production traffic
 * lands on `playground.provii.app`, which is *not* a registered
 * subdomain in `extractSubdomain`, so it also falls through.
 */
function buildPostRequest(body: unknown = undefined, ip = "203.0.113.7"): Request {
  const init: RequestInit = {
    method: "POST",
    headers: { "CF-Connecting-IP": ip },
  };
  if (typeof body !== "undefined") {
    init.body = typeof body === "string" ? body : JSON.stringify(body);
    (init.headers as Record<string, string>)["Content-Type"] =
      "application/json";
  }
  return new Request(
    "https://playground.provii.app/playground/api/create-issuer-environment",
    init,
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
 // The Secrets Store cache lives at module scope and survives across
 // tests inside a single vitest isolate. Any test that swaps the
 // SANDBOX_API_KEY binding (notably the 503 unbound test) must wipe the
 // cache first, or the handler returns the previously cached key.
  __resetPlaygroundSecretsCacheForTests();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("POST /playground/api/create-issuer-environment", () => {
  it("mints a fresh bundle with empty body and returns every expected field", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(
        new Response(buildUpstreamSuccessBody(), { status: 200 }),
      );

    const res = await worker.fetch(
      buildPostRequest(),
      buildEnv() as never,
      ctxStub,
    );

    expect(res.status).toBe(200);
    const payload = (await res.json()) as Record<string, unknown>;

    expect(typeof payload["client_id"]).toBe("string");
    expect(payload["client_id"]).toBe("cl_iss_sandbox_aabbccddeeff");
    expect(typeof payload["hmac_secret"]).toBe("string");
    expect(typeof payload["kid"]).toBe("string");
    expect(typeof payload["expires_at"]).toBe("number");
    expect(typeof payload["base_url"]).toBe("string");

 // No PEM, no public key. The Issuer signs server-side; the Issuing
 // Party authenticates with HMAC only.
    expect(payload["ed25519_public_key"]).toBeUndefined();
    expect(payload["ed25519_private_key_pem"]).toBeUndefined();

    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("calls register-test-issuer with the correct URL, body shape and X-Docs-Hmac header", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(
        new Response(buildUpstreamSuccessBody(), { status: 200 }),
      );

    const res = await worker.fetch(
      buildPostRequest({ issuer_label: "Test Issuer Label" }),
      buildEnv() as never,
      ctxStub,
    );
    expect(res.status).toBe(200);

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const callArgs = fetchSpy.mock.calls[0];
    expect(callArgs).toBeDefined();
    if (!callArgs) return;

    const calledUrl = callArgs[0];
    const init = callArgs[1] as RequestInit | undefined;
    expect(calledUrl).toBe(`${FIXTURE_ISSUER_BASE}/v1/register-test-issuer`);
    expect(init?.method).toBe("POST");

    const headers = (init?.headers ?? {}) as Record<string, string>;
    expect(headers["X-Docs-Hmac"]).toBeDefined();
    expect(headers["X-Docs-Hmac"]).toMatch(/^[0-9a-f]{64}$/);
    expect(headers["Content-Type"]).toBe("application/json");

    const sentBodyText = init?.body as string;
    expect(typeof sentBodyText).toBe("string");
    const sentBody = JSON.parse(sentBodyText) as Record<string, unknown>;
    expect(sentBody["api_key"]).toBe(FIXTURE_API_KEY);
    expect(sentBody["issuer_label"]).toBe("Test Issuer Label");
    expect(sentBody["ed25519_public_key"]).toBeUndefined();
  });

  it("defaults issuer_label to 'Sandbox issuer <hex>' when the body omits it", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(
        new Response(buildUpstreamSuccessBody(), { status: 200 }),
      );

    await worker.fetch(buildPostRequest(), buildEnv() as never, ctxStub);

    const callArgs = fetchSpy.mock.calls[0];
    if (!callArgs) throw new Error("upstream not called");
    const init = callArgs[1] as RequestInit;
    const sentBody = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(typeof sentBody["issuer_label"]).toBe("string");
    expect(sentBody["issuer_label"] as string).toMatch(
      /^Sandbox issuer [0-9a-f]{8}$/,
    );
  });

  it("returns 503 when SANDBOX_API_KEY is unbound", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const res = await worker.fetch(
      buildPostRequest(),
      buildEnv({ sandboxApiKey: null }) as never,
      ctxStub,
    );
    expect(res.status).toBe(503);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("returns 502 with the upstream body surfaced as upstream_error on non-200", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "RATE_LIMITED" }), { status: 429 }),
    );

    const res = await worker.fetch(
      buildPostRequest(),
      buildEnv() as never,
      ctxStub,
    );
    expect(res.status).toBe(502);
    const payload = (await res.json()) as { upstream_error: { code: string } };
    expect(payload.upstream_error.code).toBe("RATE_LIMITED");
  });

  it("rejects an invalid issuer_label with a 400", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const res = await worker.fetch(
      buildPostRequest({ issuer_label: "" }),
      buildEnv() as never,
      ctxStub,
    );
    expect(res.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects malformed JSON with a 400", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const req = new Request(
      "https://playground.provii.app/playground/api/create-issuer-environment",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "203.0.113.9",
        },
        body: "{not-json",
      },
    );
    const res = await worker.fetch(req, buildEnv() as never, ctxStub);
    expect(res.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rate-limits at 6 calls from the same IP", async () => {
 // Six consecutive calls from one IP. The first five should pass, the
 // sixth should hit the per-hour bucket limit and 429.
 //
 // We must hand each invocation a fresh `Response` because Response
 // bodies are single-use streams. `mockResolvedValue` returning the
 // same instance would cause every call after the first to fail at
 // `.json()` with a "body already used" error and surface as 502.
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () =>
        new Response(buildUpstreamSuccessBody(), { status: 200 }),
      );

    const env = buildEnv() as never;
    for (let i = 0; i < 5; i += 1) {
      const res = await worker.fetch(buildPostRequest(), env, ctxStub);
      expect(res.status).toBe(200);
    }
    const sixth = await worker.fetch(buildPostRequest(), env, ctxStub);
    expect(sixth.status).toBe(429);
    expect(fetchSpy).toHaveBeenCalledTimes(5);
  });
});
