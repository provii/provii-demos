// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Tests for `getOrBootstrapDocsSandboxCredential`. The helper replaced the
 * pinned static-credential pattern; the contract this suite locks down is:
 *
 * 1. A fresh KV record is reused across calls.
 * 2. A near-expiry record triggers a fresh mint via
 * `register-test-origin`.
 * 3. A second isolate that finds a held lock waits for the peer write.
 * 4. Missing `SANDBOX_API_KEY` returns empty strings (handler maps to 503).
 * 5. Upstream failure returns empty strings.
 *
 * The upstream `register-test-origin` is mocked through `globalThis.fetch`.
 * The KV namespace is the real Miniflare one bound by vitest-pool-workers,
 * so the helper exercises actual KV gets/puts and the lock TTL semantics.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { env } from "cloudflare:test";

import {
  __resetDocsBootstrapCacheForTest,
  getOrBootstrapDocsSandboxCredential,
  type DocsEnv,
} from "../handler";
import { __resetDocsLoggerForTest } from "../logger";
import { __testing as logSanitizerTesting } from "../log-sanitizer";

const KV_KEY_BOOTSTRAP_CRED = "docs-bootstrap-cred:v1";
const KV_KEY_BOOTSTRAP_LOCK = "docs-bootstrap-cred:v1:lock";

interface MockSecretsBinding {
  get(): Promise<string | null>;
}

function buildSandboxApiKeyBinding(value: string | null): MockSecretsBinding {
  return {
    get: () => Promise.resolve(value),
  };
}

function buildEnv(sandboxApiKey: string | null = "sandbox_api_key_value"): DocsEnv {
 // Reuse the Miniflare-bound DOCS_SESSIONS so KV behaviour matches
 // production. Layer on the SANDBOX_API_KEY mock so each test can pick
 // its own binding state.
  return {
    DOCS_SESSIONS: env.DOCS_SESSIONS,
    SANDBOX_API_KEY: buildSandboxApiKeyBinding(sandboxApiKey),
  };
}

/**
 * INVARIANT-DSGW-1 test variant: layer a `LOG_SANITIZER_KEY` binding on
 * top of the standard env so the sanitiser produces real `[REDACTED:<hmac>]`
 * tags rather than the fail-closed bare marker. The cold-isolate test
 * asserts that the loaded credential's plaintext is registered with the
 * tag cache, which only emits a useful tag when the key is present.
 */
const SANITISER_KEY_MATERIAL = "test-log-sanitiser-key-material-32bytes!";

function buildEnvWithSanitizerKey(
  sandboxApiKey: string | null = "sandbox_api_key_value",
): DocsEnv {
  return {
    DOCS_SESSIONS: env.DOCS_SESSIONS,
    SANDBOX_API_KEY: buildSandboxApiKeyBinding(sandboxApiKey),
    LOG_SANITIZER_KEY: {
      get: () => Promise.resolve(SANITISER_KEY_MATERIAL),
    },
  };
}

/**
 * Build a `register-test-origin` response payload. The helper accepts
 * overrides so individual tests can drive an upstream that omits
 * `expires_at`, returns malformed data, etc.
 */
function buildUpstreamResponseBody(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    success: true,
    client_id: "rp_sandbox_aabbccddeeff",
    hmac_secret: "minted_hmac_secret_v1",
    expires_at: Math.floor(Date.now() / 1000) + 72 * 60 * 60,
    ...overrides,
  });
}

beforeEach(async () => {
  __resetDocsBootstrapCacheForTest();
 // INVARIANT-DSGW-1: the cold-isolate-after-peer-mint scenario requires
 // a fully-fresh sanitiser tag cache. Reset both the logger install
 // promise (so the next `getDocsLogger` re-reads the env bindings) and
 // the underlying tag cache (so a value primed by a previous test does
 // not leak in and pre-satisfy the assertion).
  __resetDocsLoggerForTest();
  logSanitizerTesting.resetCache();
 // Wipe the two KV keys the helper touches so each test starts clean.
  await env.DOCS_SESSIONS.delete(KV_KEY_BOOTSTRAP_CRED);
  await env.DOCS_SESSIONS.delete(KV_KEY_BOOTSTRAP_LOCK);
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("getOrBootstrapDocsSandboxCredential", () => {
  it("mints via register-test-origin when no KV record exists", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(
        new Response(buildUpstreamResponseBody(), { status: 200 }),
      );

    const credential = await getOrBootstrapDocsSandboxCredential(buildEnv());

    expect(credential.clientId).toBe("rp_sandbox_aabbccddeeff");
    expect(credential.hmacSecret).toBe("minted_hmac_secret_v1");
    expect(fetchSpy).toHaveBeenCalledTimes(1);

 // Inspect the upstream call shape.
    const callArgs = fetchSpy.mock.calls[0];
    expect(callArgs).toBeDefined();
    if (!callArgs) return;
    const url = callArgs[0];
    const init = callArgs[1] as RequestInit | undefined;
    expect(url).toBe("https://sandbox-verify.provii.app/v1/register-test-origin");
    expect(init?.method).toBe("POST");
    const headers = (init?.headers ?? {}) as Record<string, string>;
    expect(headers["X-Docs-Hmac"]).toBeDefined();
    expect(headers["Content-Type"]).toBe("application/json");

 // The KV record is now persisted for the next call.
    const persisted = await env.DOCS_SESSIONS.get(KV_KEY_BOOTSTRAP_CRED);
    expect(persisted).not.toBeNull();
    if (persisted !== null) {
      const record = JSON.parse(persisted) as Record<string, unknown>;
      expect(record["client_id"]).toBe("rp_sandbox_aabbccddeeff");
      expect(record["hmac_secret"]).toBe("minted_hmac_secret_v1");
    }
  });

  it("reuses a fresh KV record without minting", async () => {
    const futureExpiry = Date.now() + 24 * 60 * 60 * 1000;
    await env.DOCS_SESSIONS.put(
      KV_KEY_BOOTSTRAP_CRED,
      JSON.stringify({
        client_id: "rp_sandbox_cached",
        hmac_secret: "cached_hmac_secret",
        expires_at: futureExpiry,
        minted_at: Date.now() - 60 * 1000,
      }),
    );

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const credential = await getOrBootstrapDocsSandboxCredential(buildEnv());

    expect(credential.clientId).toBe("rp_sandbox_cached");
    expect(credential.hmacSecret).toBe("cached_hmac_secret");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("re-mints when the cached record is within the refresh headroom", async () => {
 // Within 1 hour of expiry => stale. The helper must call upstream.
    const nearExpiry = Date.now() + 30 * 60 * 1000;
    await env.DOCS_SESSIONS.put(
      KV_KEY_BOOTSTRAP_CRED,
      JSON.stringify({
        client_id: "rp_sandbox_stale",
        hmac_secret: "stale_hmac_secret",
        expires_at: nearExpiry,
        minted_at: Date.now() - 71 * 60 * 60 * 1000,
      }),
    );

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(
        new Response(
          buildUpstreamResponseBody({
            client_id: "rp_sandbox_refreshed",
            hmac_secret: "refreshed_hmac_secret",
          }),
          { status: 200 },
        ),
      );

    const credential = await getOrBootstrapDocsSandboxCredential(buildEnv());

    expect(credential.clientId).toBe("rp_sandbox_refreshed");
    expect(credential.hmacSecret).toBe("refreshed_hmac_secret");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("returns empty strings when SANDBOX_API_KEY is unbound", async () => {
 // Empty Secrets Store value means handler will 503; the helper itself
 // must not throw so the request lifecycle stays linear.
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const credential = await getOrBootstrapDocsSandboxCredential(buildEnv(null));

    expect(credential.clientId).toBe("");
    expect(credential.hmacSecret).toBe("");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("returns empty strings when the upstream call fails", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(
        new Response("upstream blew up", { status: 503 }),
      );

    const credential = await getOrBootstrapDocsSandboxCredential(buildEnv());

    expect(credential.clientId).toBe("");
    expect(credential.hmacSecret).toBe("");
    expect(fetchSpy).toHaveBeenCalledTimes(1);

 // No record persisted on failure.
    const persisted = await env.DOCS_SESSIONS.get(KV_KEY_BOOTSTRAP_CRED);
    expect(persisted).toBeNull();
  });

  it("returns empty strings when upstream emits malformed JSON", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(
        new Response("{ not valid json", { status: 200 }),
      );

    const credential = await getOrBootstrapDocsSandboxCredential(buildEnv());

    expect(credential.clientId).toBe("");
    expect(credential.hmacSecret).toBe("");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("registers the plaintext credential with the sanitiser when a cold isolate loads a peer-minted KV record (INVARIANT-DSGW-1)", async () => {
 // Scenario: another isolate already minted the credential and wrote
 // `docs-bootstrap-cred:v1` to KV. THIS isolate is cold (no per-isolate
 // cache, no logger install yet, empty tag cache). Without the
 // KV-read branch calling `markDocsBootstrapCredentialAsKnown`, the
 // freshly-loaded plaintext would never reach the sanitiser, and the
 // first `console.log(plaintext)` after the call would emit a tagless
 // `[REDACTED]` instead of the correlatable `[REDACTED:<hmac>]` form.
 //
 // The assertion stack:
 // 1. After the call, `tagCache` contains the loaded hmac_secret.
 // 2. After the call, `tagCache` contains the loaded client_id
 // (defence-in-depth registration).
 // 3. A sync sanitise of `console.log(plaintext)` emits
 // `[REDACTED:<8 hex>]`, not bare `[REDACTED]`.
 // 4. The canary in `log-sanitizer.ts` did NOT fire, because the
 // plaintext was registered before any redaction.

 // Use a 43-char base64url plaintext so the b64url256 sanitiser
 // pattern is the one that catches the value. 43 chars matches the
 // unpadded 256-bit shape of a real `register-test-origin` HMAC
 // secret.
    const peerMintedHmacSecret = "PeerMintedHmacSecret_43_chars_aBcDeFgHiJk-A";
    expect(peerMintedHmacSecret.length).toBe(43);
    const peerMintedClientId = "rp_sandbox_peer_mint_42";

    const futureExpiry = Date.now() + 24 * 60 * 60 * 1000;
    await env.DOCS_SESSIONS.put(
      KV_KEY_BOOTSTRAP_CRED,
      JSON.stringify({
        client_id: peerMintedClientId,
        hmac_secret: peerMintedHmacSecret,
        expires_at: futureExpiry,
        minted_at: Date.now() - 60 * 1000,
      }),
    );

 // Sanity: this is a cold isolate, the tag cache must be empty.
    expect(logSanitizerTesting.isRegistered(peerMintedHmacSecret)).toBe(false);
    expect(logSanitizerTesting.isRegistered(peerMintedClientId)).toBe(false);

 // Upstream must NOT be called: the helper should reuse the KV record.
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const credential = await getOrBootstrapDocsSandboxCredential(
      buildEnvWithSanitizerKey(),
    );

 // Helper returned the peer-minted credential.
    expect(credential.clientId).toBe(peerMintedClientId);
    expect(credential.hmacSecret).toBe(peerMintedHmacSecret);
    expect(fetchSpy).not.toHaveBeenCalled();

 // 1 + 2: tag cache contains both halves.
    expect(logSanitizerTesting.isRegistered(peerMintedHmacSecret)).toBe(true);
    expect(logSanitizerTesting.isRegistered(peerMintedClientId)).toBe(true);

 // 3: sync sanitise emits the tagged form, not the bare marker.
    const sanitised = logSanitizerTesting.sanitiseStringSync(
      `outbound: ${peerMintedHmacSecret} (do not log)`,
    );
    expect(sanitised).not.toContain(peerMintedHmacSecret);
    expect(sanitised).toMatch(/\[REDACTED:[0-9a-f]{8}\]/);
    expect(sanitised).not.toMatch(/\[REDACTED\](?!:)/);

 // 4: canary did not fire. The hook ran before any redaction needed
 // to reach for the plaintext, so the b64url256-shape miss path was
 // never taken.
    expect(logSanitizerTesting.canaryEmittedCount()).toBe(0);
  });

  it("waits for a peer when the bootstrap lock is already held", async () => {
 // Simulate an in-flight peer: write a fresh lock, then have the peer
 // win by writing the credential record after a short delay. The
 // helper under test should observe the record and skip the upstream
 // call entirely.
    await env.DOCS_SESSIONS.put(KV_KEY_BOOTSTRAP_LOCK, String(Date.now()), {
      expirationTtl: 60,
    });

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const peerCredential = {
      client_id: "rp_sandbox_from_peer",
      hmac_secret: "peer_hmac_secret",
      expires_at: Date.now() + 24 * 60 * 60 * 1000,
      minted_at: Date.now(),
    };

 // Land the peer's write after a short delay so the helper enters the
 // wait loop at least once.
    setTimeout(() => {
      void env.DOCS_SESSIONS.put(
        KV_KEY_BOOTSTRAP_CRED,
        JSON.stringify(peerCredential),
      );
    }, 300);

    const credential = await getOrBootstrapDocsSandboxCredential(buildEnv());

    expect(credential.clientId).toBe("rp_sandbox_from_peer");
    expect(credential.hmacSecret).toBe("peer_hmac_secret");
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
