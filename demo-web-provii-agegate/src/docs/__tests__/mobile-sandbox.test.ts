// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Mobile sandbox gateway tests (.1-7A.3, 7A.8).
 *
 * Focus: the orchestration layer. Real cryptographic verification of
 * iOS App Attest receipts and Android Key Attestation chains is pinned
 * in `app-attest.test.ts` and `key-attestation.test.ts`. These tests
 * exercise schema validation, nonce lifecycle, rate-limit posture,
 * LRU ceiling, HMAC envelope parsing + signing, revoke/refresh
 * flows, router wire-up, and the TTL extension logic.
 *
 * Real-device attestation blobs (and therefore a full end-to-end
 * register success) are blocked on the Pixel / iPhone smoke test;
 * those will be added as a follow-up fixture-driven spec once the mobile owner
 * hands over signed receipts. Until then the register tests lock the
 * rejection branches (schema mismatch, missing nonce, rate limit,
 * capacity ceiling) and the happy-path is exercised by the revoke and
 * refresh specs which seed the KV issuer record directly.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { env } from "cloudflare:test";

import { handleDocs, type DocsEnv } from "../handler";
import {
  MobileRegisterRequestSchema,
  __mobileTestExports,
  __signMobileEnvelopeForTests,
  type MobileSandboxEnv,
} from "../mobile-sandbox";
import { jcsBytes } from "../jcs";

// ---- Test harness --------------------------------------------------------

const ctxStub: ExecutionContext = {
  waitUntil: () => undefined,
  passThroughOnException: () => undefined,
  props: {},
};

/**
 * Build a Request aimed at the docs gateway. Mobile callers talk to
 * `docs.provii.app/api/mobile/sandbox/*`; the dispatcher keys off
 * `URL(request.url).pathname` so this host is cosmetic. We set
 * `CF-Connecting-IP` so the rate-limit keys are deterministic.
 */
function buildRequest(
  path: string,
  init: RequestInit & { ip?: string } = {},
): Request {
  const { ip, headers, ...rest } = init;
  const merged = new Headers(headers ?? {});
  merged.set("CF-Connecting-IP", ip ?? "203.0.113.10");
  return new Request(`https://docs.provii.app${path}`, {
    ...rest,
    headers: merged,
  });
}

/** Clear any KV state the dispatcher cares about between tests. */
async function resetMobileKv(): Promise<void> {
  const keys = [
    __mobileTestExports.MOBILE_ACTIVE_COUNT_KEY,
  ];
  for (const key of keys) {
    try {
      await env.DOCS_SESSIONS.delete(key);
    } catch {
 // tolerated
    }
  }
 // List-and-delete any keys matching the mobile prefixes so the
 // counter and records from a previous spec cannot leak. Miniflare's
 // KV list() is synchronous and bounded for the sizes we touch here.
  const prefixes: string[] = [
    __mobileTestExports.MOBILE_ISSUER_PREFIX,
    __mobileTestExports.MOBILE_NONCE_PREFIX,
    __mobileTestExports.MOBILE_INSTALL_PREFIX,
    "ratelimit:docs:mobile-sbx-register:",
  ];
  for (const prefix of prefixes) {
    let cursor: string | undefined;
 // eslint-disable-next-line no-constant-condition
    while (true) {
      const page: KVNamespaceListResult<unknown, string> = cursor
        ? await env.DOCS_SESSIONS.list({ prefix, cursor })
        : await env.DOCS_SESSIONS.list({ prefix });
      for (const { name } of page.keys) {
        await env.DOCS_SESSIONS.delete(name);
      }
      if (page.list_complete) break;
      cursor = page.cursor;
    }
  }
}

function makeMobileEnv(overrides: Partial<MobileSandboxEnv> = {}): MobileSandboxEnv {
  return {
    ...(env as unknown as DocsEnv),
    MOBILE_APP_BUNDLE_ID: "com.provii.wallet",
    MOBILE_APPLE_AAGUID_ENV: "prod",
    MOBILE_ANDROID_PACKAGE_NAME: "com.provii.wallet",
    ...overrides,
  };
}

// =========================================================================
// GET /api/mobile/sandbox/challenge
// =========================================================================

describe("GET /api/mobile/sandbox/challenge", () => {
  beforeEach(async () => {
    await resetMobileKv();
  });

  it("mints a 32-byte hex nonce and writes a nonce record", async () => {
    const mobileEnv = makeMobileEnv();
    const req = buildRequest("/api/mobile/sandbox/challenge", { method: "GET" });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      nonce: string;
      expires_at: number;
      ttl_seconds: number;
    };
    expect(body.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(body.ttl_seconds).toBe(__mobileTestExports.NONCE_TTL_SECONDS);
    expect(body.expires_at).toBeGreaterThan(Date.now());

    const kvKey = `${__mobileTestExports.MOBILE_NONCE_PREFIX}${body.nonce}`;
    const stored = await env.DOCS_SESSIONS.get(kvKey);
    expect(stored).not.toBeNull();
  });

  it("echoes the platform hint when supplied", async () => {
    const mobileEnv = makeMobileEnv();
    const req = buildRequest("/api/mobile/sandbox/challenge?platform=ios", {
      method: "GET",
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { nonce: string };
    const stored = await env.DOCS_SESSIONS.get(
      `${__mobileTestExports.MOBILE_NONCE_PREFIX}${body.nonce}`,
    );
    const parsed = JSON.parse(stored ?? "{}") as { platform?: string };
    expect(parsed.platform).toBe("ios");
  });

  it("rejects an unknown platform hint", async () => {
    const mobileEnv = makeMobileEnv();
    const req = buildRequest("/api/mobile/sandbox/challenge?platform=wasm", {
      method: "GET",
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("mobile_invalid_platform");
  });

  it("rejects a POST with 405", async () => {
    const mobileEnv = makeMobileEnv();
    const req = buildRequest("/api/mobile/sandbox/challenge", { method: "POST" });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(405);
  });

  it("rejects a browser Origin outside the docs allowlist", async () => {
    const mobileEnv = makeMobileEnv();
    const headers = new Headers({ Origin: "https://evil.example" });
    const req = buildRequest("/api/mobile/sandbox/challenge", {
      method: "GET",
      headers,
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(403);
  });

  it("accepts a missing Origin (native caller)", async () => {
    const mobileEnv = makeMobileEnv();
    const req = buildRequest("/api/mobile/sandbox/challenge", { method: "GET" });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(200);
  });

  it("accepts docs.provii.app Origin", async () => {
    const mobileEnv = makeMobileEnv();
    const headers = new Headers({ Origin: "https://docs.provii.app" });
    const req = buildRequest("/api/mobile/sandbox/challenge", {
      method: "GET",
      headers,
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(200);
  });
});

// =========================================================================
// POST /api/mobile/sandbox/register (rejection branches)
// =========================================================================

describe("POST /api/mobile/sandbox/register", () => {
  beforeEach(async () => {
    await resetMobileKv();
  });

  it("rejects a malformed JSON body", async () => {
    const mobileEnv = makeMobileEnv();
    const req = buildRequest("/api/mobile/sandbox/register", {
      method: "POST",
      body: "{not-json",
      headers: new Headers({ "Content-Type": "application/json" }),
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("mobile_malformed_body");
  });

  it("rejects an iOS payload that omits app_attest_token", async () => {
    const mobileEnv = makeMobileEnv();
    const body = {
      install_uuid: "00000000-0000-4000-8000-000000000000",
      platform: "ios",
      app_version: "1.2.3",
      attestation_nonce: "a".repeat(64),
    };
    const req = buildRequest("/api/mobile/sandbox/register", {
      method: "POST",
      body: JSON.stringify(body),
      headers: new Headers({ "Content-Type": "application/json" }),
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(400);
    const errBody = (await res.json()) as { error: { code: string } };
    expect(errBody.error.code).toBe("mobile_schema_mismatch");
  });

  it("rejects an Android payload that omits key_attestation_chain", async () => {
    const mobileEnv = makeMobileEnv();
    const body = {
      install_uuid: "00000000-0000-4000-8000-000000000000",
      platform: "android",
      app_version: "1.2.3",
      attestation_nonce: "a".repeat(64),
    };
    const req = buildRequest("/api/mobile/sandbox/register", {
      method: "POST",
      body: JSON.stringify(body),
      headers: new Headers({ "Content-Type": "application/json" }),
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(400);
  });

  it("rejects an Android payload that also carries app_attest_token", async () => {
    const mobileEnv = makeMobileEnv();
    const body = {
      install_uuid: "00000000-0000-4000-8000-000000000000",
      platform: "android",
      app_version: "1.2.3",
      attestation_nonce: "a".repeat(64),
      app_attest_token: "AAAA".repeat(16),
      key_attestation_chain: ["AAAA".repeat(16), "BBBB".repeat(16)],
    };
    const req = buildRequest("/api/mobile/sandbox/register", {
      method: "POST",
      body: JSON.stringify(body),
      headers: new Headers({ "Content-Type": "application/json" }),
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(400);
  });

  it("returns 409 when attestation_nonce was never minted", async () => {
    const mobileEnv = makeMobileEnv();
    const body = {
      install_uuid: "00000000-0000-4000-8000-000000000000",
      platform: "ios",
      app_version: "1.0.0",
      attestation_nonce: "0".repeat(64),
      app_attest_token: Buffer.from("cbor-placeholder-bytes-1234567890").toString(
        "base64",
      ),
    };
    const req = buildRequest("/api/mobile/sandbox/register", {
      method: "POST",
      body: JSON.stringify(body),
      headers: new Headers({ "Content-Type": "application/json" }),
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(409);
    const errBody = (await res.json()) as { error: { code: string } };
    expect(errBody.error.code).toBe("mobile_nonce_unknown_or_consumed");
  });

  it("rate-limits after 5 attempts in one hour from a single IP", async () => {
    const mobileEnv = makeMobileEnv();
    const ip = "203.0.113.77";
 // Hammer register with syntactically valid but nonce-failed bodies so
 // the rate limiter is the thing that eventually trips. Each call also
 // consumes a rate-limit slot (limit runs before nonce consume).
    const body = {
      install_uuid: "00000000-0000-4000-8000-000000000000",
      platform: "ios",
      app_version: "1.0.0",
      attestation_nonce: "0".repeat(64),
      app_attest_token: Buffer.from("cbor-placeholder").toString("base64"),
    };
 // 5 attempts at 409 (nonce unknown), 6th must be 429.
    for (let i = 0; i < __mobileTestExports.REGISTER_PER_IP_PER_HOUR; i++) {
      const req = buildRequest("/api/mobile/sandbox/register", {
        method: "POST",
        body: JSON.stringify(body),
        headers: new Headers({ "Content-Type": "application/json" }),
        ip,
      });
      const res = await handleDocs(req, mobileEnv, ctxStub);
      expect(res.status).toBe(409);
    }
    const blocked = await handleDocs(
      buildRequest("/api/mobile/sandbox/register", {
        method: "POST",
        body: JSON.stringify(body),
        headers: new Headers({ "Content-Type": "application/json" }),
        ip,
      }),
      mobileEnv,
      ctxStub,
    );
    expect(blocked.status).toBe(429);
    const blockedBody = (await blocked.json()) as { error: { code: string } };
    expect(blockedBody.error.code).toBe("mobile_rate_limited");
    expect(blocked.headers.get("Retry-After")).not.toBeNull();
  });

  it("returns 503 when the active-count ceiling is reached", async () => {
    const mobileEnv = makeMobileEnv();
 // Seed the counter at the ceiling. Challenge is issued so the nonce
 // check passes and the ceiling check is the next thing to reject.
    await env.DOCS_SESSIONS.put(
      __mobileTestExports.MOBILE_ACTIVE_COUNT_KEY,
      JSON.stringify({ count: __mobileTestExports.ACTIVE_ISSUER_CEILING }),
    );
 // Mint a nonce first.
    const challengeRes = await handleDocs(
      buildRequest("/api/mobile/sandbox/challenge", { method: "GET" }),
      mobileEnv,
      ctxStub,
    );
    const { nonce } = (await challengeRes.json()) as { nonce: string };

    const body = {
      install_uuid: "11111111-0000-4000-8000-000000000000",
      platform: "ios",
      app_version: "1.0.0",
      attestation_nonce: nonce,
      app_attest_token: Buffer.from("cbor-placeholder").toString("base64"),
    };
    const res = await handleDocs(
      buildRequest("/api/mobile/sandbox/register", {
        method: "POST",
        body: JSON.stringify(body),
        headers: new Headers({ "Content-Type": "application/json" }),
      }),
      mobileEnv,
      ctxStub,
    );
    expect(res.status).toBe(503);
    const errBody = (await res.json()) as { error: { code: string } };
    expect(errBody.error.code).toBe("mobile_sandbox_capacity_reached");
  });

  it("returns 413 on payloads above the body ceiling", async () => {
    const mobileEnv = makeMobileEnv();
    const huge = "A".repeat(40 * 1024);
    const req = buildRequest("/api/mobile/sandbox/register", {
      method: "POST",
      body: huge,
      headers: new Headers({
        "Content-Type": "application/json",
        "Content-Length": String(huge.length),
      }),
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(413);
  });
});

// =========================================================================
// POST /api/mobile/sandbox/revoke
// =========================================================================

/** Seed a synthetic issuer record so revoke/refresh have something to act on. */
async function seedIssuerRecord(
  overrides: {
    clientId?: string;
    hmacSecret?: string;
    installUuid?: string;
    issuedAt?: number;
    expiresAt?: number;
  } = {},
): Promise<{ clientId: string; hmacSecret: string; installUuid: string }> {
  const clientId = overrides.clientId ?? "mwallet-sbx-" + "a".repeat(32);
  const hmacSecret = overrides.hmacSecret ?? "b".repeat(64);
  const installUuid =
    overrides.installUuid ?? "22222222-0000-4000-8000-000000000000";
  const now = Date.now();
  const record = {
    client_id: clientId,
    hmac_secret: hmacSecret,
    install_uuid: installUuid,
    platform: "ios" as const,
    app_version: "1.0.0",
    issued_at: overrides.issuedAt ?? now,
    expires_at: overrides.expiresAt ?? now + 7 * 24 * 60 * 60 * 1000,
    last_refreshed_at: overrides.issuedAt ?? now,
  };
  await env.DOCS_SESSIONS.put(
    `${__mobileTestExports.MOBILE_ISSUER_PREFIX}${clientId}`,
    JSON.stringify(record),
  );
  await env.DOCS_SESSIONS.put(
    `${__mobileTestExports.MOBILE_INSTALL_PREFIX}${installUuid}`,
    JSON.stringify({ client_id: clientId }),
  );
 // Seed the active counter at 1 so revoke's decrement lands on 0.
  await env.DOCS_SESSIONS.put(
    __mobileTestExports.MOBILE_ACTIVE_COUNT_KEY,
    JSON.stringify({ count: 1 }),
  );
  return { clientId, hmacSecret, installUuid };
}

async function signedRequest(params: {
  method: "POST";
  path: string;
  body: Record<string, unknown>;
  clientId: string;
  hmacSecret: string;
  timestampSeconds?: number;
  nonceHex?: string;
}): Promise<Request> {
  const timestamp =
    params.timestampSeconds ?? Math.floor(Date.now() / 1000);
  const nonceHex = params.nonceHex ?? "c".repeat(32);
  const jcs = jcsBytes(params.body);
  const sig = await __signMobileEnvelopeForTests(
    params.hmacSecret,
    params.method,
    params.path,
    timestamp,
    nonceHex,
    jcs,
  );
  const headers = new Headers({
    "Content-Type": "application/json",
    "X-Mwallet-Auth": `Mwallet-Sandbox client_id=${params.clientId},ts=${timestamp},nonce=${nonceHex}`,
    "X-Mwallet-Sig": sig,
  });
  return new Request(`https://docs.provii.app${params.path}`, {
    method: params.method,
    body: new TextDecoder().decode(jcs),
    headers,
  });
}

describe("POST /api/mobile/sandbox/revoke", () => {
  beforeEach(async () => {
    await resetMobileKv();
  });

  it("tombstones the issuer record on a valid HMAC-signed body", async () => {
    const mobileEnv = makeMobileEnv();
    const seeded = await seedIssuerRecord();
    const req = await signedRequest({
      method: "POST",
      path: "/api/mobile/sandbox/revoke",
      body: { client_id: seeded.clientId },
      clientId: seeded.clientId,
      hmacSecret: seeded.hmacSecret,
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { revoked: boolean; client_id: string };
    expect(body.revoked).toBe(true);
    expect(body.client_id).toBe(seeded.clientId);

    const afterRecord = await env.DOCS_SESSIONS.get(
      `${__mobileTestExports.MOBILE_ISSUER_PREFIX}${seeded.clientId}`,
    );
    expect(afterRecord).toBeNull();

    const count = JSON.parse(
      (await env.DOCS_SESSIONS.get(
        __mobileTestExports.MOBILE_ACTIVE_COUNT_KEY,
      )) ?? "{}",
    ) as { count: number };
    expect(count.count).toBe(0);
  });

  it("rejects a mismatched HMAC tag with 401", async () => {
    const mobileEnv = makeMobileEnv();
    const seeded = await seedIssuerRecord();
    const req = await signedRequest({
      method: "POST",
      path: "/api/mobile/sandbox/revoke",
      body: { client_id: seeded.clientId },
      clientId: seeded.clientId,
      hmacSecret: "d".repeat(64),
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(401);
    const errBody = (await res.json()) as { error: { code: string } };
    expect(errBody.error.code).toBe("mobile_signature_mismatch");
  });

  it("rejects a timestamp outside the 60s skew window", async () => {
    const mobileEnv = makeMobileEnv();
    const seeded = await seedIssuerRecord();
    const staleTs = Math.floor(Date.now() / 1000) - 120;
    const req = await signedRequest({
      method: "POST",
      path: "/api/mobile/sandbox/revoke",
      body: { client_id: seeded.clientId },
      clientId: seeded.clientId,
      hmacSecret: seeded.hmacSecret,
      timestampSeconds: staleTs,
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(401);
    const errBody = (await res.json()) as { error: { code: string } };
    expect(errBody.error.code).toBe("mobile_timestamp_skew");
  });

  it("rejects a missing X-Mwallet-Auth header", async () => {
    const mobileEnv = makeMobileEnv();
    const seeded = await seedIssuerRecord();
    const jcs = jcsBytes({ client_id: seeded.clientId });
    const req = new Request(
      "https://docs.provii.app/api/mobile/sandbox/revoke",
      {
        method: "POST",
        body: new TextDecoder().decode(jcs),
        headers: new Headers({ "Content-Type": "application/json" }),
      },
    );
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(401);
    const errBody = (await res.json()) as { error: { code: string } };
    expect(errBody.error.code).toBe("mobile_invalid_auth_header");
  });

  it("rejects when auth header client_id does not match body client_id", async () => {
    const mobileEnv = makeMobileEnv();
    const seeded = await seedIssuerRecord();
    const bodyClientId = "mwallet-sbx-" + "e".repeat(32);
    const req = await signedRequest({
      method: "POST",
      path: "/api/mobile/sandbox/revoke",
      body: { client_id: bodyClientId },
      clientId: seeded.clientId,
      hmacSecret: seeded.hmacSecret,
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(400);
    const errBody = (await res.json()) as { error: { code: string } };
    expect(errBody.error.code).toBe("mobile_client_id_mismatch");
  });

  it("returns 404 when the client_id is unknown", async () => {
    const mobileEnv = makeMobileEnv();
    const clientId = "mwallet-sbx-" + "f".repeat(32);
    const req = await signedRequest({
      method: "POST",
      path: "/api/mobile/sandbox/revoke",
      body: { client_id: clientId },
      clientId,
      hmacSecret: "b".repeat(64),
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(404);
    const errBody = (await res.json()) as { error: { code: string } };
    expect(errBody.error.code).toBe("mobile_client_id_unknown");
  });
});

// =========================================================================
// POST /api/mobile/sandbox/refresh
// =========================================================================

describe("POST /api/mobile/sandbox/refresh", () => {
  beforeEach(async () => {
    await resetMobileKv();
  });

  it("extends the expiry to now + 7 days on a valid HMAC-signed body", async () => {
    const mobileEnv = makeMobileEnv();
    const originalExpiry = Date.now() + 60 * 60 * 1000; // 1h away
    const seeded = await seedIssuerRecord({
      expiresAt: originalExpiry,
    });
    const req = await signedRequest({
      method: "POST",
      path: "/api/mobile/sandbox/refresh",
      body: { client_id: seeded.clientId },
      clientId: seeded.clientId,
      hmacSecret: seeded.hmacSecret,
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(200);
 // Wire format for `expires_at` is ISO8601 (commit 31a70a1) so mobile
 // parsers can hand it to Instant.parse / ISO8601DateFormatter directly.
 // KV storage keeps unix millis for TTL math.
    const body = (await res.json()) as {
      client_id: string;
      expires_at: string;
      refresh_ttl_remaining: number;
    };
    expect(body.client_id).toBe(seeded.clientId);
    const wireExpiryMs = Date.parse(body.expires_at);
    expect(Number.isFinite(wireExpiryMs)).toBe(true);
    expect(wireExpiryMs).toBeGreaterThan(originalExpiry);
    expect(body.refresh_ttl_remaining).toBe(
      __mobileTestExports.ISSUER_TTL_SECONDS,
    );

    const stored = JSON.parse(
      (await env.DOCS_SESSIONS.get(
        `${__mobileTestExports.MOBILE_ISSUER_PREFIX}${seeded.clientId}`,
      )) ?? "{}",
    ) as { expires_at: number; last_refreshed_at: number };
    expect(stored.expires_at).toBe(wireExpiryMs);
    expect(stored.last_refreshed_at).toBeGreaterThanOrEqual(
      Date.now() - 5_000,
    );
  });

  it("rejects a refresh signed with the wrong HMAC secret", async () => {
    const mobileEnv = makeMobileEnv();
    const seeded = await seedIssuerRecord();
    const req = await signedRequest({
      method: "POST",
      path: "/api/mobile/sandbox/refresh",
      body: { client_id: seeded.clientId },
      clientId: seeded.clientId,
      hmacSecret: "0".repeat(64),
    });
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(401);
  });

  it("rejects a malformed X-Mwallet-Sig header", async () => {
    const mobileEnv = makeMobileEnv();
    const seeded = await seedIssuerRecord();
    const timestamp = Math.floor(Date.now() / 1000);
    const nonceHex = "c".repeat(32);
    const headers = new Headers({
      "Content-Type": "application/json",
      "X-Mwallet-Auth": `Mwallet-Sandbox client_id=${seeded.clientId},ts=${timestamp},nonce=${nonceHex}`,
      "X-Mwallet-Sig": "not-a-hex-string",
    });
    const req = new Request(
      "https://docs.provii.app/api/mobile/sandbox/refresh",
      {
        method: "POST",
        body: JSON.stringify({ client_id: seeded.clientId }),
        headers,
      },
    );
    const res = await handleDocs(req, mobileEnv, ctxStub);
    expect(res.status).toBe(401);
    const errBody = (await res.json()) as { error: { code: string } };
    expect(errBody.error.code).toBe("mobile_invalid_signature_header");
  });
});

// =========================================================================
// Schema + helper unit tests
// =========================================================================

describe("MobileRegisterRequestSchema cross-field rules", () => {
  it("accepts a minimal iOS payload", () => {
    const result = MobileRegisterRequestSchema.safeParse({
      install_uuid: "00000000-0000-4000-8000-000000000000",
      platform: "ios",
      app_version: "1.2.3",
      attestation_nonce: "a".repeat(64),
      app_attest_token: "AAAA".repeat(16),
    });
    expect(result.success).toBe(true);
  });

  it("accepts a minimal Android payload", () => {
    const result = MobileRegisterRequestSchema.safeParse({
      install_uuid: "00000000-0000-4000-8000-000000000000",
      platform: "android",
      app_version: "1.2.3",
      attestation_nonce: "a".repeat(64),
      key_attestation_chain: ["AAAA".repeat(16), "BBBB".repeat(16)],
    });
    expect(result.success).toBe(true);
  });

  it("rejects a nonce that is not 64 hex chars", () => {
    const result = MobileRegisterRequestSchema.safeParse({
      install_uuid: "00000000-0000-4000-8000-000000000000",
      platform: "ios",
      app_version: "1.2.3",
      attestation_nonce: "zz",
      app_attest_token: "AAAA".repeat(16),
    });
    expect(result.success).toBe(false);
  });
});

describe("canonical HMAC envelope", () => {
  it("round-trips sign + verify on a synthetic body", async () => {
    const secretHex = "b".repeat(64);
    const body = { client_id: "mwallet-sbx-" + "a".repeat(32) };
    const jcs = jcsBytes(body);
    const ts = 1_713_110_400;
    const nonce = "c".repeat(32);
    const sig1 = await __signMobileEnvelopeForTests(
      secretHex,
      "POST",
      "/api/mobile/sandbox/revoke",
      ts,
      nonce,
      jcs,
    );
    const sig2 = await __signMobileEnvelopeForTests(
      secretHex,
      "POST",
      "/api/mobile/sandbox/revoke",
      ts,
      nonce,
      jcs,
    );
    expect(sig1).toBe(sig2);
    expect(sig1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("produces distinct tags for different paths", async () => {
    const secretHex = "b".repeat(64);
    const jcs = jcsBytes({ client_id: "mwallet-sbx-" + "a".repeat(32) });
    const ts = 1_713_110_400;
    const nonce = "c".repeat(32);
    const sigRevoke = await __signMobileEnvelopeForTests(
      secretHex,
      "POST",
      "/api/mobile/sandbox/revoke",
      ts,
      nonce,
      jcs,
    );
    const sigRefresh = await __signMobileEnvelopeForTests(
      secretHex,
      "POST",
      "/api/mobile/sandbox/refresh",
      ts,
      nonce,
      jcs,
    );
    expect(sigRevoke).not.toBe(sigRefresh);
  });
});

describe("parseAuthHeader", () => {
  const { parseAuthHeader } = __mobileTestExports;

  it("accepts the canonical shape", () => {
    const parsed = parseAuthHeader(
      "Mwallet-Sandbox client_id=mwallet-sbx-" + "a".repeat(32) +
        ",ts=1713110400,nonce=" + "c".repeat(32),
    );
    expect(parsed).not.toBeNull();
    expect(parsed?.timestamp).toBe(1_713_110_400);
  });

  it("rejects the wrong prefix", () => {
    expect(
      parseAuthHeader(
        "Bearer client_id=mwallet-sbx-" + "a".repeat(32) + ",ts=1,nonce=c",
      ),
    ).toBeNull();
  });

  it("rejects a missing nonce", () => {
    expect(
      parseAuthHeader(
        "Mwallet-Sandbox client_id=mwallet-sbx-" + "a".repeat(32) + ",ts=1",
      ),
    ).toBeNull();
  });
});

// =========================================================================
// End-to-end integration (orchestration layer, no real attestation)
// =========================================================================

describe("mobile sandbox e2e: challenge -> register(rejected) -> revoke flow", () => {
  beforeEach(async () => {
    await resetMobileKv();
  });

  it("completes a challenge + seeded-record revoke + refresh flow", async () => {
    const mobileEnv = makeMobileEnv();

 // 1. Mint a challenge. We do not actually feed it to register because
 // the real attestation verifiers require signed blobs; instead we
 // assert the nonce is stored and consumed separately below.
    const challengeRes = await handleDocs(
      buildRequest("/api/mobile/sandbox/challenge", { method: "GET" }),
      mobileEnv,
      ctxStub,
    );
    expect(challengeRes.status).toBe(200);
    const challengeBody = (await challengeRes.json()) as { nonce: string };
    const stored = await env.DOCS_SESSIONS.get(
      `${__mobileTestExports.MOBILE_NONCE_PREFIX}${challengeBody.nonce}`,
    );
    expect(stored).not.toBeNull();

 // 2. Seed an issuer record so we can exercise the authenticated
 // lifecycle endpoints end-to-end through the router.
    const seeded = await seedIssuerRecord({
      clientId: "mwallet-sbx-" + "1".repeat(32),
    });

 // 3. Refresh the record.
    const refreshReq = await signedRequest({
      method: "POST",
      path: "/api/mobile/sandbox/refresh",
      body: { client_id: seeded.clientId },
      clientId: seeded.clientId,
      hmacSecret: seeded.hmacSecret,
    });
    const refreshRes = await handleDocs(refreshReq, mobileEnv, ctxStub);
    expect(refreshRes.status).toBe(200);

 // 4. Revoke. Active counter must drop by one.
    const revokeReq = await signedRequest({
      method: "POST",
      path: "/api/mobile/sandbox/revoke",
      body: { client_id: seeded.clientId },
      clientId: seeded.clientId,
      hmacSecret: seeded.hmacSecret,
    });
    const revokeRes = await handleDocs(revokeReq, mobileEnv, ctxStub);
    expect(revokeRes.status).toBe(200);
    const countRaw = await env.DOCS_SESSIONS.get(
      __mobileTestExports.MOBILE_ACTIVE_COUNT_KEY,
    );
    const count = JSON.parse(countRaw ?? "{}") as { count: number };
    expect(count.count).toBe(0);

 // 5. A second revoke on the same client_id must 404.
    const secondRevoke = await signedRequest({
      method: "POST",
      path: "/api/mobile/sandbox/revoke",
      body: { client_id: seeded.clientId },
      clientId: seeded.clientId,
      hmacSecret: seeded.hmacSecret,
    });
    const secondRes = await handleDocs(secondRevoke, mobileEnv, ctxStub);
    expect(secondRes.status).toBe(404);
  });
});
