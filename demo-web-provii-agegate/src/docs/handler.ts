// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Docs Gateway Handler.
 *
 * Owns every `docs.provii.app/api/*` request. Runs in the same Worker as
 * the playground handler but on a narrowed `DocsEnv` that deliberately excludes
 * playground-only bindings (`DEMO_TOKEN_SECRET`, `PLAYGROUND_SESSIONS`). This
 * keeps cross-surface reachability impossible at the type level: the docs
 * handler cannot accidentally read playground secrets even if a future change
 * tries to share helpers between the two surfaces.
 *
 * Surface scope (post per-session credential mint retirement):
 *
 * - POST /api/session/init bearer cookie + session record
 * - POST /api/csrf/bootstrap CSRF secret derivation primer
 * - POST /api/docs/demo/challenge (alias /api/challenge), TestInWallet
 * - GET /api/docs/demo/challenge/{id} (alias /api/status/{id}), status poll
 * - GET /api/feature-flags/{key} widget-level flag read
 * - GET /api/openapi/{service} same-origin Scalar spec proxy
 * - {GET,POST} /api/mobile/sandbox/* provii-mobile per-install attestation
 *
 * The challenge route signs upstream provii-verifier calls with a sandbox
 * verifier credential the gateway provisions itself by calling
 * `POST /v1/register-test-origin` against `sandbox-verify.provii.app`
 * with the shared `SANDBOX_API_KEY`. The resulting `(client_id, hmac_secret)`
 * triple is cached in `DOCS_SESSIONS` KV under `docs-bootstrap-cred:v1` for
 * 72 hours and refreshed proactively when within an hour of expiry. No
 * pinned per-credential Secrets Store entries are required; an operator only
 * has to provision `SANDBOX_API_KEY`. The previous per-session credential
 * mint surface (`/api/credentials/*`, `/api/attestation`,
 * `/api/simulate-proof`, `/api/fixtures`) was retired; real credentials only
 * come from playground.provii.app.
 */

import { getAllowedDocsOrigin } from "./cors";
import { checkCreationRateLimit } from "./rate-limit";
import {
  authenticateSession,
  mintSessionCookie,
  revokeSessionCookieHeader,
  writeSessionRecord,
} from "./session";
import { DocsSessionSchema } from "./schemas";
import { createChallenge } from "./challenge";
import { handleChallengeStatus } from "./status";
import type { RateLimitEnv } from "./rate-limit";
import {
  buildFeatureFlagErrorBody,
  checkEndpointEnabled,
  readPublicFeatureFlag,
  type DocsFeatureEndpoint,
  type FeatureFlagFailMode,
} from "./feature-flags";
import { z } from "zod";
import {
  CSRF_RESPONSE_HEADER,
  deriveCsrfSecret,
  verifyCsrfHeader,
} from "./csrf";
import { getDocsLogger, markDocsBootstrapCredentialAsKnown } from "./logger";
import { hmacSha256Hex } from "./crypto";
import {
  handleMobileSandboxChallenge,
  handleMobileSandboxRefresh,
  handleMobileSandboxRegister,
  handleMobileSandboxRevoke,
  type MobileSandboxEnv,
} from "./mobile-sandbox";

/**
 * Narrowed Worker env for the docs gateway. Intentionally excludes
 * `DEMO_TOKEN_SECRET` and `PLAYGROUND_SESSIONS`. The docs handler maintains
 * its own caches in this module and resolves its own copies of every secret
 * from the bindings declared below.
 *
 * The docs gateway shares the playground's `SANDBOX_API_KEY` Secrets Store
 * binding because both surfaces use the same upstream endpoint
 * (`POST /v1/register-test-origin`) to mint sandbox credentials. The two
 * call sites are independent and credentials they mint are scoped to
 * disjoint origins (`docs-gateway-bootstrap.sandbox.provii.app` for
 * the docs gateway, ephemeral hex-suffix origins for playground sessions),
 * so a compromise of one surface cannot reuse the other's credentials.
 */
export interface DocsEnv {
  /**
 * KV namespace for docs sessions, challenges, rate-limit counters, and
 * the bootstrapped sandbox verifier credential cache. Bound separately
 * from `PLAYGROUND_SESSIONS` so a sandbox compromise of one surface
 * cannot enumerate the other.
   */
  DOCS_SESSIONS: KVNamespace;

  /**
 * Sandbox provii-verifier API key shared with the playground handler.
 * Used to authenticate the docs gateway's self-bootstrap call to
 * `POST /v1/register-test-origin` (X-Docs-Hmac signed with this key).
 * The minted `(client_id, hmac_secret)` triple is cached in
 * `DOCS_SESSIONS` under `docs-bootstrap-cred:v1`; this binding is
 * never used to sign provii-verifier `/v1/challenge` calls directly.
   */
  SANDBOX_API_KEY?: { get(): Promise<string | null> };

  /** HMAC key used to sign `__Host-docs_session` cookies. */
  DOCS_SESSION_HMAC_KEY?: { get(): Promise<string | null> };

  /** Service Binding to provii-verifier sandbox. Used by /api/challenge and /api/status. */
  VERIFIER_API_SANDBOX?: Fetcher;

  /**
 * Cloudflare Rate Limiting binding for `GET /api/status/:id`. Declared
 * in wrangler.toml as an `unsafe.bindings` entry of type `ratelimit`.
 * 10-second sliding window (Tier B). Optional here because the gateway
 * may run without the binding provisioned; the rate-limit helper fails
 * closed when absent.
   */
  DOCS_STATUS_POLL_LIMITER?: { limit(options: { key: string }): Promise<{ success: boolean }> };

  /**
 * HMAC-SHA-256 key used by `src/docs/log-sanitizer.ts` to derive per-secret
 * redaction tags (). Optional so the gateway still boots when the
 * binding is absent; the sanitiser falls back to the bare `[REDACTED]`
 * marker without a hash suffix. Consumed via `getDocsLogger(env)` from
 * `./logger`.
   */
  LOG_SANITIZER_KEY?: { get(): Promise<string | null> };

 // --- Mobile sandbox bindings (.1-7A.3, 7A.8) -----------------
 //
 // All optional so the handler keeps compiling on branches that have
 // not yet landed wrangler.toml additions. Every mobile-sandbox handler
 // fails closed with a descriptive error code when the binding it needs
 // is absent. the mobile client reads from the real production
 // bindings once wrangler.toml is updated.

  /** Upstream origin for OpenAPI spec proxy. Falls back to provenance.provii.app. */
  OPENAPI_UPSTREAM_ORIGIN?: string;

  /** Mobile app bundle id used as Apple App Attest rpId / Android cross-check. */
  MOBILE_APP_BUNDLE_ID?: string;
  /** `"prod"` or `"dev"` toggling which Apple AAGUID to require. Defaults to `"prod"`. */
  MOBILE_APPLE_AAGUID_ENV?: string;
  /** Pinned Google Hardware Attestation root DER (base64). Empty falls back to module default. */
  MOBILE_ANDROID_PINNED_ROOT_DER_B64?: string;
  /** Expected Android package name for attestationApplicationId cross-check. */
  MOBILE_ANDROID_PACKAGE_NAME?: string;
}

// ============================================================================
// Self-bootstrapped sandbox verifier credential
//
// The docs gateway calls `POST /v1/register-test-origin` against
// sandbox-verify.provii.app once per credential lifetime (72 hours)
// authenticated by the shared `SANDBOX_API_KEY`. The resulting
// `(client_id, hmac_secret)` triple is cached in `DOCS_SESSIONS` KV under
// `docs-bootstrap-cred:v1` so every isolate in the deployment sees the
// same credential. A second isolate that finds an in-flight bootstrap
// (signalled by `docs-bootstrap-cred:v1:lock`) waits and re-reads from KV
// rather than minting a duplicate.
//
// Origin choice: a stable host (`docs-gateway-bootstrap.sandbox.provii.app`)
// rather than a random suffix means the upstream policy record stays put
// across refreshes. A churn pattern would create a new policy entry every
// 72 hours and leave dead entries in the provii-verifier KV that only TTL out
// after their own 72-hour expiry.
// ============================================================================

/**
 * Stable origin registered upstream for the docs gateway's self-bootstrap
 * credential. Chosen so the upstream policy record is reused across every
 * refresh; if the value here ever changes, the previous origin's policy
 * stays in upstream KV until its 72-hour TTL elapses.
 */
const BOOTSTRAP_ORIGIN = "https://docs-gateway-bootstrap.sandbox.provii.app";

/** KV key for the cached `(client_id, hmac_secret)` triple. */
const KV_KEY_BOOTSTRAP_CRED = "docs-bootstrap-cred:v1";

/** KV key for the in-flight-bootstrap lock flag. */
const KV_KEY_BOOTSTRAP_LOCK = "docs-bootstrap-cred:v1:lock";

/** Hard cache TTL applied to the KV record. Matches the upstream origin policy TTL. */
const BOOTSTRAP_CACHE_TTL_SECONDS = 72 * 60 * 60;

/**
 * Refresh the credential when within this many milliseconds of the cached
 * `expires_at`. One hour gives an isolate that wakes up just before the
 * TTL window enough headroom to re-mint without a tail of expired-credential
 * 401s leaking to live traffic.
 */
const BOOTSTRAP_REFRESH_HEADROOM_MS = 60 * 60 * 1000;

/**
 * TTL on the in-flight lock flag. Bounds how long a stuck mint blocks others.
 * Cloudflare KV enforces a 60-second minimum on `expirationTtl`, so 60 is
 * the floor; the helper's 10-second wait window means a stuck peer never
 * blocks live traffic for the full TTL.
 */
const BOOTSTRAP_LOCK_TTL_SECONDS = 60;

/** How long a waiter polls KV before giving up and minting itself anyway. */
const BOOTSTRAP_LOCK_WAIT_MAX_MS = 10_000;

/** Polling interval while waiting on an in-flight bootstrap. */
const BOOTSTRAP_LOCK_POLL_INTERVAL_MS = 250;

/** Timeout applied to the upstream `register-test-origin` fetch. */
const BOOTSTRAP_REGISTER_TIMEOUT_MS = 10_000;

/**
 * Schema for the persisted credential record. `expires_at` is epoch
 * milliseconds; the client_id and hmac_secret are echoed as strings.
 */
const BootstrappedCredentialRecordSchema = z.object({
  client_id: z.string().min(1),
  hmac_secret: z.string().min(1),
  expires_at: z.number().int().positive(),
  minted_at: z.number().int().positive(),
});

type BootstrappedCredentialRecord = z.infer<
  typeof BootstrappedCredentialRecordSchema
>;

/** Subset of the `register-test-origin` response we actually need. */
const RegisterTestOriginResponseSchema = z.object({
  client_id: z.string().min(1),
  hmac_secret: z.string().min(1),
 // Upstream returns seconds (epoch); optional because schema flux upstream
 // would otherwise hard-fail the bootstrap. We fall back to a 72-hour
 // synthetic expiry computed from the local clock.
  expires_at: z.number().int().positive().optional(),
});

/** Public-facing credential shape consumed by `createChallenge`. */
export interface DocsSandboxCredential {
  clientId: string;
  hmacSecret: string;
}

/**
 * Per-isolate cache. The KV record is the source of truth; this cache
 * exists only to skip a KV `get` on every challenge call within the same
 * isolate. Cleared whenever the cached record is within the refresh
 * headroom so a refresh never serves a stale value.
 */
let cachedBootstrappedCredential: BootstrappedCredentialRecord | null = null;

/**
 * Sleep promise used while polling for an in-flight bootstrap to land. The
 * Workers runtime caps `setTimeout` at the request lifetime, so a stuck
 * mint cannot keep an isolate alive past its natural billing window.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Read the cached record from KV, return null on missing or malformed data. */
async function readBootstrappedCredentialRecord(
  env: DocsEnv,
): Promise<BootstrappedCredentialRecord | null> {
  let raw: string | null;
  try {
    raw = await env.DOCS_SESSIONS.get(KV_KEY_BOOTSTRAP_CRED);
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
  const result = BootstrappedCredentialRecordSchema.safeParse(parsed);
  if (!result.success) return null;
  return result.data;
}

/**
 * True if `record` is fresh enough to use without re-minting. A record
 * within `BOOTSTRAP_REFRESH_HEADROOM_MS` of expiry is treated as stale so
 * the next request triggers a refresh.
 */
function isCredentialFresh(
  record: BootstrappedCredentialRecord,
  now: number,
): boolean {
  return record.expires_at - now > BOOTSTRAP_REFRESH_HEADROOM_MS;
}

/**
 * Attempt to acquire the in-flight bootstrap lock. Returns true if this
 * isolate took the lock, false if another isolate already holds it. KV
 * has no atomic SETNX, so a concurrent put can produce two winners; we
 * accept one extra mint per ~5-minute window as cheaper than a Durable
 * Object for a credential that refreshes every 72 hours.
 */
async function tryAcquireBootstrapLock(
  env: DocsEnv,
  now: number,
): Promise<boolean> {
  let existing: string | null;
  try {
    existing = await env.DOCS_SESSIONS.get(KV_KEY_BOOTSTRAP_LOCK);
  } catch {
    return false;
  }
  if (existing !== null) {
 // A lock with no parseable timestamp is treated as fresh (defensive);
 // an older isolate that crashed mid-mint will see its lock TTL out on
 // its own.
    const lockAt = Number(existing);
    if (Number.isFinite(lockAt) && now - lockAt < BOOTSTRAP_LOCK_TTL_SECONDS * 1000) {
      return false;
    }
  }
  try {
    await env.DOCS_SESSIONS.put(KV_KEY_BOOTSTRAP_LOCK, String(now), {
      expirationTtl: BOOTSTRAP_LOCK_TTL_SECONDS,
    });
  } catch {
    return false;
  }
  return true;
}

/** Best-effort lock release. Failures are non-fatal (TTL handles the worst case). */
async function releaseBootstrapLock(env: DocsEnv): Promise<void> {
  try {
    await env.DOCS_SESSIONS.delete(KV_KEY_BOOTSTRAP_LOCK);
  } catch {
 // Ignored; the lock TTL bounds the worst case.
  }
}

/**
 * Wait for an in-flight bootstrap by another isolate to land in KV. Polls
 * `KV_KEY_BOOTSTRAP_CRED` until a fresh record appears or the wait window
 * closes. Returns the record on success or null on timeout.
 */
async function waitForBootstrappedCredential(
  env: DocsEnv,
  startedAt: number,
): Promise<BootstrappedCredentialRecord | null> {
  while (Date.now() - startedAt < BOOTSTRAP_LOCK_WAIT_MAX_MS) {
    await sleep(BOOTSTRAP_LOCK_POLL_INTERVAL_MS);
    const record = await readBootstrappedCredentialRecord(env);
    if (record !== null && isCredentialFresh(record, Date.now())) {
      return record;
    }
  }
  return null;
}

/**
 * Call `POST /v1/register-test-origin` against the sandbox provii-verifier
 * with the shared `SANDBOX_API_KEY`. Returns the parsed response or null
 * on any upstream failure. The HMAC scheme matches the playground's
 * `register-test-origin` call: the body bytes are HMAC-SHA-256'd with the
 * UTF-8 bytes of the API key and the digest is sent as `X-Docs-Hmac`.
 */
async function callRegisterTestOrigin(
  sandboxApiKey: string,
  now: number,
): Promise<BootstrappedCredentialRecord | null> {
 // Body matches the playground's register-test-origin contract. We pin
 // `proof_direction = "over_age"` and `min_age_years = 18` because the
 // docs gateway's only consumer (`createChallenge`) signs `/v1/challenge`
 // upstream which does not consult the policy's age bounds; the values
 // are accepted by the upstream validator and never surface to widget
 // users.
 // SECURITY: api_key in the body is the designed register-policy API
 // contract. Sandbox keys are publicly documented; production keys travel
 // over TLS only.
  const registerBody = JSON.stringify({
    origin: BOOTSTRAP_ORIGIN,
    min_age_years: 18,
    api_key: sandboxApiKey,
    proof_direction: "over_age",
  });
  const registerSignature = await hmacSha256Hex(
    new TextEncoder().encode(sandboxApiKey),
    registerBody,
  );

  let response: Response;
  try {
    response = await fetch(
      "https://sandbox-verify.provii.app/v1/register-test-origin",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Sec-Fetch-Site": "same-origin",
          "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Dest": "empty",
          "X-Docs-Hmac": registerSignature,
        },
        body: registerBody,
        signal: AbortSignal.timeout(BOOTSTRAP_REGISTER_TIMEOUT_MS),
      },
    );
  } catch {
    return null;
  }

  if (!response.ok) return null;

  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch {
    return null;
  }
  const result = RegisterTestOriginResponseSchema.safeParse(parsed);
  if (!result.success) return null;

 // Upstream `expires_at` is seconds; convert to milliseconds for the
 // record. Fall back to a synthetic 72-hour window when absent.
  const upstreamExpiresAtMs =
    result.data.expires_at !== undefined
      ? result.data.expires_at * 1000
      : now + BOOTSTRAP_CACHE_TTL_SECONDS * 1000;

  return {
    client_id: result.data.client_id,
    hmac_secret: result.data.hmac_secret,
    expires_at: upstreamExpiresAtMs,
    minted_at: now,
  };
}

/**
 * Persist a freshly-minted credential to KV. TTL matches the cache
 * lifetime so an isolate that loses its in-memory cache reads the same
 * record from KV. Failures are non-fatal: the request that minted the
 * credential still uses it, but the next isolate to need a credential
 * will re-mint. Logged for visibility.
 */
async function persistBootstrappedCredentialRecord(
  env: DocsEnv,
  record: BootstrappedCredentialRecord,
): Promise<void> {
  try {
    await env.DOCS_SESSIONS.put(
      KV_KEY_BOOTSTRAP_CRED,
      JSON.stringify(record),
      { expirationTtl: BOOTSTRAP_CACHE_TTL_SECONDS },
    );
  } catch (error) {
    const logger = await getDocsLogger(env);
    const reason = error instanceof Error ? error.message : String(error);
    logger.warn(`[docs-bootstrap] persist failed (will re-mint): ${reason}`);
  }
}

/**
 * Resolve a usable docs sandbox verifier credential. Order of operations:
 * 1. Per-isolate cache hit, when fresh.
 * 2. KV read, when fresh.
 * 3. If a peer isolate is mid-bootstrap, wait for its KV write.
 * 4. Otherwise mint via `register-test-origin` and persist to KV.
 *
 * Every branch where this isolate first sees the plaintext credential
 * (KV read, peer wait, self-mint) calls
 * `markDocsBootstrapCredentialAsKnown(...)` so the redaction tag cache
 * carries the value before any subsequent log line could leak it as a
 * bare `[REDACTED]`. See INVARIANT-DSGW-1 in `logger.ts`.
 *
 * Returns an empty-string credential on failure; the caller (handler) maps
 * the empty case to a 503 so the failure is visible in Logpush.
 */
export async function getOrBootstrapDocsSandboxCredential(
  env: DocsEnv,
): Promise<DocsSandboxCredential> {
  const now = Date.now();

 // 1. Per-isolate cache.
  if (
    cachedBootstrappedCredential !== null &&
    isCredentialFresh(cachedBootstrappedCredential, now)
  ) {
    return {
      clientId: cachedBootstrappedCredential.client_id,
      hmacSecret: cachedBootstrappedCredential.hmac_secret,
    };
  }

 // 2. KV read.
  const fromKv = await readBootstrappedCredentialRecord(env);
  if (fromKv !== null && isCredentialFresh(fromKv, now)) {
    cachedBootstrappedCredential = fromKv;
 // INVARIANT-DSGW-1: a cold isolate that wakes up after a peer minted
 // sees the credential here for the first time. Without this hook the
 // sanitiser would emit a bare `[REDACTED]` for the secret rather than
 // a correlatable `[REDACTED:<hmac>]` tag.
    const kvLogger = await getDocsLogger(env);
    await markDocsBootstrapCredentialAsKnown(
      { clientId: fromKv.client_id, hmacSecret: fromKv.hmac_secret },
      "kv-read",
      kvLogger,
    );
    return {
      clientId: fromKv.client_id,
      hmacSecret: fromKv.hmac_secret,
    };
  }

 // 3 + 4. Mint, with concurrent-fetch protection.
  const sandboxApiKey = (await env.SANDBOX_API_KEY?.get()) ?? null;
  if (sandboxApiKey === null || sandboxApiKey === "") {
    return { clientId: "", hmacSecret: "" };
  }

  const acquiredLock = await tryAcquireBootstrapLock(env, now);
  if (!acquiredLock) {
 // Another isolate is already minting. Wait for its KV write and reuse
 // the result. If the wait times out we fall through to a self-mint as
 // a safety net so a stuck peer cannot starve live traffic.
    const peerRecord = await waitForBootstrappedCredential(env, now);
    if (peerRecord !== null) {
      cachedBootstrappedCredential = peerRecord;
 // INVARIANT-DSGW-1: peer mint completed during our wait. Tag-cache
 // registration is required here for the same reason as the KV-read
 // branch above; this isolate is seeing the plaintext for the first time.
      const peerLogger = await getDocsLogger(env);
      await markDocsBootstrapCredentialAsKnown(
        { clientId: peerRecord.client_id, hmacSecret: peerRecord.hmac_secret },
        "peer-wait",
        peerLogger,
      );
      return {
        clientId: peerRecord.client_id,
        hmacSecret: peerRecord.hmac_secret,
      };
    }
 // Fall through to self-mint without holding the lock; one extra mint
 // is preferable to serving 503 to the caller waiting on a stuck peer.
  }

  try {
    const minted = await callRegisterTestOrigin(sandboxApiKey, Date.now());
    if (minted === null) {
      return { clientId: "", hmacSecret: "" };
    }
    cachedBootstrappedCredential = minted;
    await persistBootstrappedCredentialRecord(env, minted);
 // INVARIANT-DSGW-1: this isolate minted the credential, register the
 // plaintext with the redaction tag cache before the secret can flow
 // into any subsequent `register-test-origin`-style log line.
    const mintLogger = await getDocsLogger(env);
    await markDocsBootstrapCredentialAsKnown(
      { clientId: minted.client_id, hmacSecret: minted.hmac_secret },
      "self-mint",
      mintLogger,
    );
    return {
      clientId: minted.client_id,
      hmacSecret: minted.hmac_secret,
    };
  } finally {
    if (acquiredLock) {
      await releaseBootstrapLock(env);
    }
  }
}

/**
 * Reset the per-isolate bootstrap cache. Test-only: production callers
 * reset by waiting out the refresh headroom or by invalidating the KV
 * record directly.
 */
export function __resetDocsBootstrapCacheForTest(): void {
  cachedBootstrappedCredential = null;
}

/**
 * Stable error envelope returned by every docs gateway endpoint. `code` is the
 * machine-readable identifier; `message` is human-friendly but not localised
 * (docs surface is English-only).
 */
interface DocsErrorBody {
  error: {
    code: string;
    message: string;
  };
}

const ERROR_RESPONSE_HEADERS: Record<string, string> = {
  "Content-Type": "application/json",
  "Cache-Control": "no-store",
};

/** Common JSON response headers. */
const JSON_RESPONSE_HEADERS: Record<string, string> = {
  "Content-Type": "application/json",
  "Cache-Control": "no-store",
};

function notFound(_pathname: string): Response {
 // INVAL-F-1: Omit pathname from the body to prevent reflected content injection.
  const body: DocsErrorBody = {
    error: {
      code: "docs_route_not_found",
      message: "No docs gateway route matches the requested path.",
    },
  };
  return new Response(JSON.stringify(body), {
    status: 404,
    headers: ERROR_RESPONSE_HEADERS,
  });
}

/**
 * HIGH-2: Enforce Content-Type: application/json on POST requests. Returns
 * a 415 Response if the header is missing or wrong, or null to proceed.
 */
function requireJsonContentType(request: Request): Response | null {
 // Empty-body POSTs (session init, CSRF bootstrap) are exempt: no body
 // means no content to type. This keeps the cross-origin form-submission
 // defence (POSTs with urlencoded bodies are still rejected) without
 // forcing every empty-body fetch call site to set the header.
  const contentLengthHeader = request.headers.get("Content-Length");
  const contentLength = contentLengthHeader === null ? null : Number(contentLengthHeader);
  if (contentLength === 0) return null;
  const contentType = request.headers.get("Content-Type");
  if (contentType === null && contentLength === null) {
 // No Content-Length declared and no body read yet. Treat as empty-body
 // until the handler opts to consume the body.
    return null;
  }
  if (contentType === null || !contentType.startsWith("application/json")) {
    const body: DocsErrorBody = {
      error: {
        code: "docs_unsupported_content_type",
        message: "POST requests with a body must carry Content-Type: application/json.",
      },
    };
    return new Response(JSON.stringify(body), {
      status: 415,
      headers: ERROR_RESPONSE_HEADERS,
    });
  }
  return null;
}

function rejectUnexpectedBody(request: Request): Response | null {
  const lengthHeader = request.headers.get("Content-Length");
  if (lengthHeader !== null) {
    const declared = Number(lengthHeader);
    if (Number.isFinite(declared) && declared > 0) {
      const body: DocsErrorBody = {
        error: {
          code: "docs_unexpected_body",
          message: "This endpoint does not accept a request body.",
        },
      };
      return new Response(JSON.stringify(body), {
        status: 413,
        headers: ERROR_RESPONSE_HEADERS,
      });
    }
  }
  return null;
}

function methodNotAllowed(allowed: readonly string[]): Response {
  const body: DocsErrorBody = {
    error: {
      code: "docs_method_not_allowed",
      message: `Allowed methods: ${allowed.join(", ")}.`,
    },
  };
  return new Response(JSON.stringify(body), {
    status: 405,
    headers: { ...ERROR_RESPONSE_HEADERS, Allow: allowed.join(", ") },
  });
}

/**
 * Match `/api/status/:id` and return the captured id, or `null`. Kept as a
 * narrow path matcher rather than a full router so the dispatcher does not
 * pull in unnecessary routing infrastructure.
 */
function matchStatusId(pathname: string): string | null {
  const match = pathname.match(/^\/api\/status\/([A-Za-z0-9_-]+)$/);
  return match && match[1] ? match[1] : null;
}

/**
 * Allowlist of services exposed through `/api/openapi/:service`. The docs
 * gateway fetches `https://provenance.provii.app/{service}/latest.json`
 * server-side so the Scalar API Explorer can pull the spec same-origin
 * under CSP `connect-src 'self'`. Any value outside this set returns 404.
 *
 * Match is case-insensitive on the URL segment; the canonical lower-case
 * form is used when building the upstream URL.
 */
const OPENAPI_SERVICE_ALLOWLIST = new Set<string>([
  "provii-verifier",
  "provii-issuer",
]);

/**
 * Match `/api/openapi/:service` case-insensitively. Returns the canonical
 * (lower-case, allowed) service id, or `null`. Rejecting unknown
 * services at the matcher level keeps the dispatcher linear.
 */
function matchOpenapiService(pathname: string): string | null {
  const match = pathname.match(/^\/api\/openapi\/([A-Za-z0-9_-]+)$/);
  if (!match || !match[1]) return null;
  const canonical = match[1].toLowerCase();
  return OPENAPI_SERVICE_ALLOWLIST.has(canonical) ? canonical : null;
}

/** Default upstream for OpenAPI spec proxy. Overridable via env var for rebrand. */
const OPENAPI_UPSTREAM_ORIGIN_DEFAULT = "https://provenance.provii.app";

/**
 * Proxy the upstream OpenAPI spec same-origin. The specs on
 * `provenance.provii.app` are public, so no auth is added. Cache
 * at the edge for 5 minutes with a 1-hour stale-while-revalidate window;
 * the Scalar bundle fetches specs on demand and we do not want to hit
 * the upstream on every page view.
 *
 * Fail-closed on upstream failure: surface the upstream status and a
 * JSON error body. Upstream body is not forwarded on failure because
 * upstream errors may be HTML.
 */
function flattenOpenApiDefs(spec: unknown): unknown {
  if (spec === null || typeof spec !== "object") return spec;
  const root = spec as Record<string, unknown>;

 // schemars emits $defs at multiple levels: one root-level block PLUS an
 // inline $defs on every per-operation schema. Walk the whole tree,
 // collect every $defs map into a single components.schemas, and strip
 // the $defs keys along the way. Then rewrite all $ref values from
 // #/$defs/X to #/components/schemas/X.
  const components = (root["components"] as Record<string, unknown>) ?? {};
  const schemas = (components["schemas"] as Record<string, unknown>) ?? {};

  const collectAndStrip = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(collectAndStrip);
    if (node !== null && typeof node === "object") {
      const src = node as Record<string, unknown>;
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(src)) {
        if (k === "$defs" && v !== null && typeof v === "object" && !Array.isArray(v)) {
          for (const [name, value] of Object.entries(v as Record<string, unknown>)) {
            if (schemas[name] === undefined) schemas[name] = collectAndStrip(value);
          }
          continue;
        }
        out[k] = collectAndStrip(v);
      }
      return out;
    }
    return node;
  };

  const stripped = collectAndStrip(root) as Record<string, unknown>;

  const rewriteRefs = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(rewriteRefs);
    if (node !== null && typeof node === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        if (k === "$ref" && typeof v === "string" && v.startsWith("#/$defs/")) {
          out[k] = `#/components/schemas/${v.slice("#/$defs/".length)}`;
        } else {
          out[k] = rewriteRefs(v);
        }
      }
      return out;
    }
    return node;
  };

  components["schemas"] = schemas;
  stripped["components"] = components;
  return rewriteRefs(stripped);
}

async function handleDocsOpenapiProxy(service: string, env: DocsEnv, request: Request): Promise<Response> {
 // CAT-A-01: Per-IP rate limit (100/min) on OpenAPI proxy. Fail-closed.
  const remoteIp = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const openapiRateLimit = await checkCreationRateLimit(env, `openapi:${remoteIp}`);
  if (!openapiRateLimit.allowed) {
    const body: DocsErrorBody = {
      error: {
        code: "docs_openapi_rate_limited",
        message: "Too many OpenAPI proxy requests. Retry shortly.",
      },
    };
    const headers: Record<string, string> = { ...ERROR_RESPONSE_HEADERS };
    if (openapiRateLimit.retry_after_seconds !== undefined) {
      headers["Retry-After"] = String(openapiRateLimit.retry_after_seconds);
    }
    return new Response(JSON.stringify(body), { status: 429, headers });
  }

  const openapiOrigin = env.OPENAPI_UPSTREAM_ORIGIN ?? OPENAPI_UPSTREAM_ORIGIN_DEFAULT;
  const upstreamUrl = `${openapiOrigin}/${service}/latest.json`;
  let upstream: Response;
  try {
    upstream = await fetch(upstreamUrl, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    });
  } catch (error) {
 // INVAL-F-2: Log the real error; return a generic public message.
    const logger = await getDocsLogger(env);
    const reason = error instanceof Error ? error.message : String(error);
    logger.error(`[docs-openapi] upstream fetch failed: ${reason}`);
    const body: DocsErrorBody = {
      error: {
        code: "docs_openapi_upstream_unreachable",
        message: "Upstream OpenAPI fetch failed.",
      },
    };
    return new Response(JSON.stringify(body), {
      status: 502,
      headers: ERROR_RESPONSE_HEADERS,
    });
  }

  if (!upstream.ok) {
    const body: DocsErrorBody = {
      error: {
        code: "docs_openapi_upstream_error",
        message: `Upstream OpenAPI returned ${upstream.status} for ${service}.`,
      },
    };
    return new Response(JSON.stringify(body), {
      status: upstream.status === 404 ? 404 : 502,
      headers: ERROR_RESPONSE_HEADERS,
    });
  }

  const rawSpec = await upstream.text();
 // F-11: Parse and re-serialise to validate JSON before caching at the edge.
  let parsedSpec: unknown;
  try {
    parsedSpec = JSON.parse(rawSpec);
  } catch {
    const errBody: DocsErrorBody = {
      error: {
        code: "docs_openapi_upstream_invalid_json",
        message: "Upstream OpenAPI response was not valid JSON.",
      },
    };
    return new Response(JSON.stringify(errBody), {
      status: 502,
      headers: ERROR_RESPONSE_HEADERS,
    });
  }
 // schemars-emitted OpenAPI specs use JSON Schema 2020-12 `$defs` at the
 // root + `#/$defs/X` refs. Scalar 1.52.2 expects OpenAPI 3.0
 // `#/components/schemas/X`. Hoist $defs into components.schemas and
 // rewrite $ref values to match. Runs once per edge-cache window.
  parsedSpec = flattenOpenApiDefs(parsedSpec);
  return new Response(JSON.stringify(parsedSpec), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=300, stale-while-revalidate=3600",
    },
  });
}

/**
 * Match `/api/docs/demo/challenge/:id` (provii-docs widget path alias,
 * AR-001b) and return the captured challenge id. The widget calls this
 * surface via the alias form; the dispatcher routes it to the same handler
 * as `/api/status/:id` so the behaviour is identical regardless of which
 * URL the browser uses.
 */
function matchAliasChallengeId(pathname: string): string | null {
  const match = pathname.match(/^\/api\/docs\/demo\/challenge\/([A-Za-z0-9_-]+)$/);
  return match && match[1] ? match[1] : null;
}

/**
 * Match `/api/feature-flags/:key` (). Captured key is returned as a
 * raw string; the caller Zod-validates shape before reading KV so a
 * malformed key never reaches the namespace at all.
 */
function matchFeatureFlagKey(pathname: string): string | null {
  const match = pathname.match(/^\/api\/feature-flags\/(.+)$/);
  if (!match || !match[1]) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return null;
  }
}

/**
 * Zod schema for the `/api/feature-flags/:key` key parameter. Shape is
 * `docs-features:<widget>:enabled` where the widget token is 1-64
 * lowercase alphanumerics plus dashes. The inner character class is
 * deliberately tight so an operator cannot accidentally route a lookup
 * at a `docs-session:` or `docs-chal:` key via this public surface.
 */
const FeatureFlagKeySchema = z
  .string()
  .regex(/^docs-features:[a-z0-9][a-z0-9-]{0,63}:enabled$/, {
    message: "key must match docs-features:<widget>:enabled",
  });

// ============================================================================
// Body-size guard ()
// ============================================================================

/**
 * Hard cap on `/api/session/init` request bodies (AR-). The body is
 * now optional (session init requires no fields), but the 16 KiB ceiling
 * remains as defence-in-depth against oversized payloads.
 */
const SESSION_INIT_BODY_MAX_BYTES = 16 * 1024;

/**
 * Outcome from `readBoundedBody`. `text` is the request body decoded as
 * UTF-8 when the byte length is within the cap. `too_large` triggers a
 * 413 in the caller; `stream_error` collapses to a 400.
 */
type BoundedBodyOutcome =
  | { kind: "text"; text: string }
  | { kind: "too_large" }
  | { kind: "stream_error" };

/**
 * Read `request.body` into memory while enforcing a byte ceiling. Reads
 * one chunk at a time; if the cumulative byte count would exceed
 * `maxBytes` after the next chunk, abort with `too_large` without
 * appending the offending chunk. Calls cancel on the reader so the
 * runtime stops streaming the rest of the body.
 *
 * The Workers runtime sets `Content-Length` for almost every inbound
 * fetch, so the upstream caller checks the header first and only falls
 * through to this routine when the header was absent or untrustworthy.
 * Caller still pays one max-sized read in the worst case but never more.
 */
async function readBoundedBody(
  request: Request,
  maxBytes: number,
): Promise<BoundedBodyOutcome> {
  if (request.body === null) {
    return { kind: "text", text: "" };
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch {
 // Cancellation failures are non-fatal; the runtime will
 // tear the stream down once we exit this scope.
        }
        return { kind: "too_large" };
      }
      chunks.push(value);
    }
  } catch {
    return { kind: "stream_error" };
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return { kind: "text", text: new TextDecoder("utf-8").decode(merged) };
  } catch {
    return { kind: "stream_error" };
  }
}

// ============================================================================
// /api/session/init
// ============================================================================

/**
 * Minimum wall-clock time every `/session/init` response takes. Floor that
 * hides the difference between success, rate-limited, and rejected responses.
 */
const SESSION_INIT_MIN_ELAPSED_MS = 250;

/**
 * Pad the handler's elapsed time up to `SESSION_INIT_MIN_ELAPSED_MS`.
 * Measurement uses `performance.now()` because it is monotonic and
 * immune to wall-clock jumps; `setTimeout` is fine for padding because
 * the padding is coarse (tens of ms) relative to handler RTT jitter.
 *
 * BILLING NOTE. Cloudflare Workers bills CPU time, not wall-clock
 * time. The pending `setTimeout` window does not consume CPU and is not
 * billed under either the Bundled or Standard usage model. The request is
 * still attributable to the worker (it counts toward the requests metric)
 * but the padded interval is effectively free. We intentionally use
 * `setTimeout` rather than `scheduler.wait` or a busy loop because the
 * latter would attribute the wait time to CPU and break the floor's
 * cost model.
 */
async function padToTimingFloor(startedAtMs: number): Promise<void> {
  const elapsed = performance.now() - startedAtMs;
  const remaining = SESSION_INIT_MIN_ELAPSED_MS - elapsed;
  if (remaining <= 0) return;
  await new Promise<void>((resolve) => setTimeout(resolve, remaining));
}

/**
 * Outcome from `readSessionInitBody`. The body is now optional (session
 * init needs no required fields). The 16 KiB cap remains as
 * defence-in-depth.
 *
 * - `too_large` => 413 `docs_session_init_payload_too_large`
 * - `stream_error` => 400 `docs_session_init_malformed_body`
 * - `ok` => body read successfully (contents ignored)
 */
type SessionInitBodyOutcome =
  | { kind: "ok" }
  | { kind: "too_large" }
  | { kind: "stream_error" };

async function readSessionInitBody(request: Request): Promise<SessionInitBodyOutcome> {
  const lengthHeader = request.headers.get("Content-Length");
  if (lengthHeader !== null) {
    const declaredLength = Number(lengthHeader);
    if (
      Number.isFinite(declaredLength) &&
      declaredLength > SESSION_INIT_BODY_MAX_BYTES
    ) {
      return { kind: "too_large" };
    }
  }

  const bounded = await readBoundedBody(request, SESSION_INIT_BODY_MAX_BYTES);
  if (bounded.kind === "too_large") return { kind: "too_large" };
  if (bounded.kind === "stream_error") return { kind: "stream_error" };

  return { kind: "ok" };
}

/** JSON error response used by the session-init handler. */
function sessionInitError(
  status: number,
  code: string,
  message: string,
  extraHeaders: Record<string, string> = {},
): Response {
  const body: DocsErrorBody = { error: { code, message } };
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_RESPONSE_HEADERS, ...extraHeaders },
  });
}

/**
 * Implement `POST /api/session/init`. Flow:
 * 1. Enforce Origin header (revoke any stale cookie on mismatch).
 * 2. Read body (optional, contents ignored; 16 KiB cap stays as
 * defence-in-depth).
 * 3. Rate-limit by IP (`CF-Connecting-IP`).
 * 4. Mint bearer + cookie, write session record, return 200.
 *
 * Bot protection is handled at the Cloudflare dashboard level (Bot Fight
 * Mode + WAF rules), not in-Worker.
 */
async function sessionInitInner(request: Request, env: DocsEnv): Promise<Response> {
  const now = Date.now();

  const allowedOrigin = getAllowedDocsOrigin(request);
  if (allowedOrigin === null) {
    return sessionInitError(
      403,
      "docs_origin_not_allowed",
      "Origin header is missing or not in the docs allowlist.",
      { "Set-Cookie": revokeSessionCookieHeader() },
    );
  }

  const baseHeaders: Record<string, string> = {
    "Access-Control-Allow-Origin": allowedOrigin,
    Vary: "Origin",
  };

  const bodyOutcome = await readSessionInitBody(request);
  if (bodyOutcome.kind === "too_large") {
    return sessionInitError(
      413,
      "docs_session_init_payload_too_large",
      `Body exceeds ${SESSION_INIT_BODY_MAX_BYTES} bytes.`,
      baseHeaders,
    );
  }
  if (bodyOutcome.kind === "stream_error") {
    return sessionInitError(
      400,
      "docs_session_init_malformed_body",
      "Request body could not be read.",
      baseHeaders,
    );
  }

  const rateLimitKey = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const preSessionLimit = await checkCreationRateLimit(env, `pre:${rateLimitKey}`, now);
  if (!preSessionLimit.allowed) {
    const extra: Record<string, string> = { ...baseHeaders };
    if (preSessionLimit.retry_after_seconds !== undefined) {
      extra["Retry-After"] = String(preSessionLimit.retry_after_seconds);
    }
    return sessionInitError(
      429,
      "docs_rate_limited",
      "Too many session-init attempts. Retry shortly.",
      extra,
    );
  }

  const minted = await mintSessionCookie(env, now);
  if (minted === null) {
    return sessionInitError(
      503,
      "docs_session_key_unavailable",
      "Session key binding is not configured.",
      baseHeaders,
    );
  }

  const record = DocsSessionSchema.parse({
    kid: minted.kid,
    bearer_hash: minted.bearerHashHex,
    session_id: minted.sessionId,
    issued_at: minted.issuedAt,
    expires_at: minted.expiresAt,
  });
  await writeSessionRecord(env, record, now);

  const bodyObject = {
    session_id: minted.sessionId,
    expires_at: minted.expiresAt,
  };
  return new Response(JSON.stringify(bodyObject), {
    status: 200,
    headers: {
      ...JSON_RESPONSE_HEADERS,
      ...baseHeaders,
      "Set-Cookie": minted.cookieHeader,
    },
  });
}

/**
 * Timing-hardened wrapper around `sessionInitInner`. Every response path is
 * padded to at least `SESSION_INIT_MIN_ELAPSED_MS` so the elapsed time does
 * not distinguish rate-limited vs. rejected vs. accepted. Exceptions
 * collapse to a 500 with the same pad applied.
 */
async function handleDocsSessionInit(
  request: Request,
  env: DocsEnv,
): Promise<Response> {
  const startedAt = performance.now();
  let response: Response;
  try {
    response = await sessionInitInner(request, env);
  } catch {
    response = sessionInitError(
      500,
      "docs_session_init_internal_error",
      "Session initialisation failed due to an internal error.",
    );
  }
  await padToTimingFloor(startedAt);
  return response;
}

// ============================================================================
// /api/docs/demo/challenge (alias /api/challenge)
// ============================================================================

/**
 * Apply CORS headers for authenticated JSON responses. Origin must be on
 * the docs allowlist; the caller already enforces that, but we still
 * Vary on Origin so intermediate caches do not echo a wrong value.
 */
function authedJsonHeaders(origin: string): Record<string, string> {
  return {
    ...JSON_RESPONSE_HEADERS,
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    Vary: "Origin",
  };
}

/**
 * Handle `POST /api/docs/demo/challenge`. Session-authenticated, rate-limited
 * on the creation tier, delegates to `createChallenge` which signs and calls
 * provii-verifier via the sandbox service binding using the static sandbox
 * verifier credential pinned in Secrets Store. Persists the challenge record
 * at `docs-chal:<challenge_id>` with `poll_count=0`.
 */
async function handleDocsChallenge(
  request: Request,
  env: DocsEnv,
): Promise<Response> {
 // CAT-D-02: Reject body on endpoints that do not consume one.
  const bodyReject = rejectUnexpectedBody(request);
  if (bodyReject !== null) return bodyReject;

  const allowedOrigin = getAllowedDocsOrigin(request);
  if (allowedOrigin === null) {
    return new Response(
      JSON.stringify({
        error: {
          code: "docs_origin_not_allowed",
          message: "Origin is not on the docs allowlist.",
        },
      }),
      {
        status: 403,
        headers: { ...JSON_RESPONSE_HEADERS, "Set-Cookie": revokeSessionCookieHeader() },
      },
    );
  }

  const auth = await authenticateSession(env, request);
  if (auth.kind !== "ok") {
    return new Response(
      JSON.stringify({ error: { code: auth.code, message: auth.message } }),
      { status: auth.status, headers: authedJsonHeaders(allowedOrigin) },
    );
  }

 // : CSRF header verify. Runs before the rate-limit increment so a
 // failed CSRF probe does not consume the caller's creation budget.
  const csrf = verifyCsrfHeader(request, auth.session);
  if (csrf.kind !== "ok") {
    return new Response(
      JSON.stringify({ error: { code: csrf.code, message: csrf.message } }),
      { status: csrf.status, headers: authedJsonHeaders(allowedOrigin) },
    );
  }

  const rateLimit = await checkCreationRateLimit(env, auth.session.bearer_hash);
  if (!rateLimit.allowed) {
    const headers: Record<string, string> = authedJsonHeaders(allowedOrigin);
    if (rateLimit.retry_after_seconds !== undefined) {
      headers["Retry-After"] = String(rateLimit.retry_after_seconds);
    }
    return new Response(
      JSON.stringify({
        error: {
          code: "docs_rate_limited",
          message: "Creation-tier rate limit exceeded.",
          reason: rateLimit.reason,
        },
      }),
      { status: 429, headers },
    );
  }

 // Resolve a sandbox verifier credential. The gateway self-mints via
 // `POST /v1/register-test-origin` on first use and caches in KV for
 // 72 hours. Empty strings here mean either the SANDBOX_API_KEY binding
 // is unset or the upstream call itself failed; either case fails closed
 // with 503 so the cause shows up in Logpush rather than leaking through
 // as a malformed signature 401 from provii-verifier.
  const credential = await getOrBootstrapDocsSandboxCredential(env);
  if (credential.clientId === "" || credential.hmacSecret === "") {
    return new Response(
      JSON.stringify({
        error: {
          code: "docs_sandbox_verifier_credential_unavailable",
          message:
            "Sandbox verifier credential is unavailable. Bootstrap via SANDBOX_API_KEY failed.",
        },
      }),
      { status: 503, headers: authedJsonHeaders(allowedOrigin) },
    );
  }

  const outcome = await createChallenge(env, auth.session, credential);
  if (outcome.kind !== "ok") {
    return new Response(
      JSON.stringify({
        error: { code: outcome.code, message: outcome.message },
      }),
      { status: outcome.status, headers: authedJsonHeaders(allowedOrigin) },
    );
  }

 // ADV-B1: response body carries `environment: "sandbox"` plus the upstream
 // fields. Upstream payload is echoed under `upstream` so the widget can
 // read `rp_challenge`, `submit_secret`, `verify_url` etc. without the
 // docs surface having to re-enumerate every field provii-verifier emits.
  return new Response(JSON.stringify(outcome.body), {
    status: 200,
    headers: authedJsonHeaders(allowedOrigin),
  });
}

// ============================================================================
// /api/status/:id (alias /api/docs/demo/challenge/:id)
// ============================================================================

/**
 * Handle `GET /api/status/:challengeId`. Session-authenticated, Tier B
 * rate-limited, gateway-side coalesced through `caches.default`. Delegates
 * to `handleChallengeStatus` for the actual flow.
 */
async function handleDocsStatus(
  request: Request,
  env: DocsEnv,
  ctx: ExecutionContext,
  challengeId: string,
): Promise<Response> {
  const allowedOrigin = getAllowedDocsOrigin(request);
  if (allowedOrigin === null) {
    return new Response(
      JSON.stringify({
        error: {
          code: "docs_origin_not_allowed",
          message: "Origin is not on the docs allowlist.",
        },
      }),
      {
        status: 403,
        headers: { ...JSON_RESPONSE_HEADERS, "Set-Cookie": revokeSessionCookieHeader() },
      },
    );
  }

  const auth = await authenticateSession(env, request);
  if (auth.kind !== "ok") {
    return new Response(
      JSON.stringify({ error: { code: auth.code, message: auth.message } }),
      { status: auth.status, headers: authedJsonHeaders(allowedOrigin) },
    );
  }

  const response = await handleChallengeStatus(
    env as RateLimitEnv,
    ctx,
    challengeId,
    auth.session.bearer_hash,
    auth.session.session_id,
  );

 // Attach CORS + no-store on the client-facing response. The internal
 // cached Response carried `s-maxage` for the edge cache only; the
 // browser should always re-ask the gateway.
  const responseHeaders = new Headers(response.headers);
  responseHeaders.set("Access-Control-Allow-Origin", allowedOrigin);
  responseHeaders.set("Access-Control-Allow-Credentials", "true");
  responseHeaders.set("Vary", "Origin");
  responseHeaders.set("Cache-Control", "no-store");
  return new Response(response.body, {
    status: response.status,
    headers: responseHeaders,
  });
}

// ============================================================================
// /api/csrf/bootstrap ()
// ============================================================================

/**
 * Handle `POST /api/csrf/bootstrap`. The browser calls this once per
 * docs session, receives the derived CSRF secret in both the
 * `X-Docs-CSRF-Secret` response header and a `__Host-docs_csrf`
 * secondary cookie, and then echoes the value on every subsequent
 * mint call via an `X-Docs-CSRF` request header.
 *
 * Flow:
 * 1. Origin allowlist check (same posture as every authenticated endpoint).
 * 2. Session authentication. Unauthenticated callers receive 401.
 * 3. Creation-tier rate limit so the primer cannot be used as a
 * free session-alive probe.
 * 4. Derive the secret via `deriveCsrfSecret(env, session_id)` and
 * persist it on the session record. Re-derivation is idempotent
 * (the HMAC is deterministic), so a client that loses its copy
 * can POST again and get the same value without rotating the
 * secret server-side. If Tim wants rotation later, rotate
 * `DOCS_SESSION_HMAC_KEY` and every secret invalidates in
 * lock-step.
 * 5. Return 200 plus the header + cookie the client needs to carry
 * on subsequent calls.
 */
async function handleDocsCsrfBootstrap(
  request: Request,
  env: DocsEnv,
): Promise<Response> {
 // CAT-D-02: Reject body on endpoints that do not consume one.
  const bodyReject = rejectUnexpectedBody(request);
  if (bodyReject !== null) return bodyReject;

  const allowedOrigin = getAllowedDocsOrigin(request);
  if (allowedOrigin === null) {
    return new Response(
      JSON.stringify({
        error: {
          code: "docs_origin_not_allowed",
          message: "Origin is not on the docs allowlist.",
        },
      }),
      {
        status: 403,
        headers: { ...JSON_RESPONSE_HEADERS, "Set-Cookie": revokeSessionCookieHeader() },
      },
    );
  }

  const auth = await authenticateSession(env, request);
  if (auth.kind !== "ok") {
    return new Response(
      JSON.stringify({ error: { code: auth.code, message: auth.message } }),
      { status: auth.status, headers: authedJsonHeaders(allowedOrigin) },
    );
  }

  const rateLimit = await checkCreationRateLimit(env, auth.session.bearer_hash);
  if (!rateLimit.allowed) {
    const headers: Record<string, string> = authedJsonHeaders(allowedOrigin);
    if (rateLimit.retry_after_seconds !== undefined) {
      headers["Retry-After"] = String(rateLimit.retry_after_seconds);
    }
    return new Response(
      JSON.stringify({
        error: {
          code: "docs_rate_limited",
          message: "Creation-tier rate limit exceeded.",
          reason: rateLimit.reason,
        },
      }),
      { status: 429, headers },
    );
  }

  const derived = await deriveCsrfSecret(env, auth.session.session_id);
  if (derived === null) {
    return new Response(
      JSON.stringify({
        error: {
          code: "docs_csrf_key_unavailable",
          message: "CSRF derivation key is not configured.",
        },
      }),
      { status: 503, headers: authedJsonHeaders(allowedOrigin) },
    );
  }

  const updatedSession = { ...auth.session, csrf_secret: derived.secretHex };
  await writeSessionRecord(env, updatedSession);

  const headers: Record<string, string> = {
    ...authedJsonHeaders(allowedOrigin),
    [CSRF_RESPONSE_HEADER]: derived.secretHex,
    "Set-Cookie": derived.setCookie,
  };

  return new Response(
    JSON.stringify({ bootstrapped: true, session_id: auth.session.session_id }),
    { status: 200, headers },
  );
}

// ============================================================================
// /api/feature-flags/:key ()
// ============================================================================

/**
 * Handle `GET /api/feature-flags/:key`. Public, unauthenticated read of a
 * single feature flag so the docs widgets can decide client-side whether to
 * render at all before trying an authenticated mint. Global kill applies to
 * every widget: `{enabled: false, reason: "gateway_killed"}` wins over the
 * per-widget flag value. Missing key defaults to
 * `{enabled: true, reason: "default_on"}` so new widgets deploy without an
 * operator flag-flip.
 *
 * Zod-validates the key against `docs-features:<widget>:enabled` to prevent
 * this surface reaching outside the feature-flag namespace.
 */
async function handleDocsFeatureFlag(
  request: Request,
  env: DocsEnv,
  rawKey: string,
): Promise<Response> {
  const allowedOrigin = getAllowedDocsOrigin(request);
 // Public endpoint: origin need not be on the allowlist, but we still
 // echo ACAO when it is so a docs page fetch reads cleanly with
 // `credentials: "omit"`. No cookie is revoked from here.
  const headers: Record<string, string> = { ...JSON_RESPONSE_HEADERS };
  if (allowedOrigin !== null) {
    headers["Access-Control-Allow-Origin"] = allowedOrigin;
    headers["Vary"] = "Origin";
  }

  const parsed = FeatureFlagKeySchema.safeParse(rawKey);
  if (!parsed.success) {
    const body: DocsErrorBody = {
      error: {
        code: "docs_feature_flag_key_invalid",
        message: "Key must match docs-features:<widget>:enabled.",
      },
    };
    return new Response(JSON.stringify(body), { status: 400, headers });
  }

  const value = await readPublicFeatureFlag(env, parsed.data);
  return new Response(JSON.stringify(value), { status: 200, headers });
}

/**
 * Map dispatcher routes to their feature flag endpoint key and fail mode.
 * Centralised so we only ever consult the flag once per request. Write
 * endpoints fail closed (KV error disables endpoint); read-only endpoints
 * fail open (KV error keeps endpoint available).
 */
function featureKeyFor(pathname: string): { key: DocsFeatureEndpoint; failMode: FeatureFlagFailMode } | null {
  if (pathname === "/api/session/init") return { key: "session_init", failMode: "closed" };
  if (pathname === "/api/challenge" || pathname === "/api/docs/demo/challenge") {
    return { key: "challenge", failMode: "closed" };
  }
  if (matchStatusId(pathname) !== null || matchAliasChallengeId(pathname) !== null) {
    return { key: "status", failMode: "open" };
  }
  return null;
}

/**
 * Build the JSON 503 body returned when a feature flag short-circuits a
 * dispatch. Keeps the dispatcher responsible for the response so each
 * endpoint handler does not have to repeat the same boilerplate.
 */
function featureFlagShortCircuit(
  decision: { kind: "endpoint_disabled" | "gateway_disabled" },
): Response {
  const body = buildFeatureFlagErrorBody(decision);
  return new Response(JSON.stringify({ error: body }), {
    status: 503,
    headers: ERROR_RESPONSE_HEADERS,
  });
}

/**
 * Dispatch a `docs.provii.app/api/*` request to the appropriate handler.
 *
 * Two cross-cutting checks run before the per-endpoint handler:
 * 1. Method validation through `methodNotAllowed`.
 * 2. Feature flags via `checkEndpointEnabled` so an operator can disable
 * a single widget or the entire gateway from KV without redeploying.
 */
export async function handleDocs(
  request: Request,
  env: DocsEnv,
  ctx: ExecutionContext,
): Promise<Response> {
 // `ctx` is consumed by the /api/status/:id handler via `caches.default.put`
 // + `ctx.waitUntil`. Other endpoints do not need it, but passing it through
 // keeps the dispatcher uniform.

 // (W5 remediation). Warm the sanitised logger facade once per
 // request so downstream handlers that log an error reach into a cached
 // sanitiser install rather than re-importing the HMAC key every time.
 // `getDocsLogger` memoises the install at module scope, so the cost on
 // subsequent requests in the same isolate collapses to a single promise
 // reuse.
  await getDocsLogger(env);

  const url = new URL(request.url);
  const pathname = url.pathname;
  const method = request.method;

 // Feature-flag introspection endpoint (). Dispatched BEFORE the
 // gateway kill-switch check so an operator can still read the current
 // flag state when the gateway itself is disabled; the handler's own
 // response carries `{enabled: false, reason: "gateway_killed"}` in
 // that case, which is the signal the docs page needs to render its
 // "widgets temporarily offline" state.
  const featureFlagKey = matchFeatureFlagKey(pathname);
  if (featureFlagKey !== null) {
    if (method !== "GET") return methodNotAllowed(["GET"]);
    return handleDocsFeatureFlag(request, env, featureFlagKey);
  }

 // Feature-flag short circuit applies to every flag-mapped route. Routes
 // outside the table (404 below) do not consult flags so an unmapped
 // pathname cannot accidentally toggle a wrong endpoint.
  const featureEntry = featureKeyFor(pathname);
  if (featureEntry !== null) {
    const decision = await checkEndpointEnabled(env, featureEntry.key, featureEntry.failMode);
    if (decision.kind !== "enabled") {
      return featureFlagShortCircuit(decision);
    }
  }

  if (pathname === "/api/session/init") {
    if (method !== "POST") return methodNotAllowed(["POST"]);
    const ctReject = requireJsonContentType(request);
    if (ctReject !== null) return ctReject;
    return handleDocsSessionInit(request, env);
  }

  if (pathname === "/api/csrf/bootstrap") {
    if (method !== "POST") return methodNotAllowed(["POST"]);
    const ctReject = requireJsonContentType(request);
    if (ctReject !== null) return ctReject;
    return handleDocsCsrfBootstrap(request, env);
  }

  if (pathname === "/api/challenge" || pathname === "/api/docs/demo/challenge") {
 // Alias added AR-001b: provii-docs widgets call the `/api/docs/demo/*`
 // variant; route both to the same handler so a widget edit does not
 // need a docs gateway redeploy.
    if (method !== "POST") return methodNotAllowed(["POST"]);
    const ctReject = requireJsonContentType(request);
    if (ctReject !== null) return ctReject;
    return handleDocsChallenge(request, env);
  }

  const statusId = matchStatusId(pathname) ?? matchAliasChallengeId(pathname);
  if (statusId !== null) {
    if (method !== "GET") return methodNotAllowed(["GET"]);
    return handleDocsStatus(request, env, ctx, statusId);
  }

 // `/api/openapi/:service` is the same-origin OpenAPI spec proxy consumed
 // by the Scalar API Explorer on docs.provii.app. No auth, no
 // feature flag: specs are public on provenance.provii.app and the
 // widget needs them reachable for the CSP to stay tight. Allowlist lives
 // in `matchOpenapiService`; unknown services fall through to 404.
  const openapiService = matchOpenapiService(pathname);
  if (openapiService !== null) {
    if (method !== "GET") return methodNotAllowed(["GET"]);
    return handleDocsOpenapiProxy(openapiService, env, request);
  }

 // --- Mobile sandbox routes (.1-7A.3) -------------------------
 //
 // These are NOT feature-flag-gated because the mobile client shipping
 // behind the provii-mobile staging build needs them reachable from
 // day one of the sandbox rollout. If an operator wants to kill a
 // mobile endpoint the right move is to rotate the attestation pin;
 // full kill-switch control is tracked as a follow-up in the doc.

  if (pathname === "/api/mobile/sandbox/challenge") {
    if (method !== "GET") return methodNotAllowed(["GET"]);
    return handleMobileSandboxChallenge(request, env as MobileSandboxEnv);
  }

  if (pathname === "/api/mobile/sandbox/register") {
    if (method !== "POST") return methodNotAllowed(["POST"]);
    const ctReject = requireJsonContentType(request);
    if (ctReject !== null) return ctReject;
    return handleMobileSandboxRegister(request, env as MobileSandboxEnv);
  }

  if (pathname === "/api/mobile/sandbox/revoke") {
    if (method !== "POST") return methodNotAllowed(["POST"]);
    const ctReject = requireJsonContentType(request);
    if (ctReject !== null) return ctReject;
    return handleMobileSandboxRevoke(request, env as MobileSandboxEnv);
  }

  if (pathname === "/api/mobile/sandbox/refresh") {
    if (method !== "POST") return methodNotAllowed(["POST"]);
    const ctReject = requireJsonContentType(request);
    if (ctReject !== null) return ctReject;
    return handleMobileSandboxRefresh(request, env as MobileSandboxEnv);
  }

  return notFound(pathname);
}
