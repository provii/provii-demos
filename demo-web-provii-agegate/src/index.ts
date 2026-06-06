// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Provii Demo Worker
 *
 * Serves static files and provides sandbox attestation generation.
 * Age verification logic is handled by provii-verifier via provii-agegate.
 *
 * Sandbox Attestation Flow:
 * 1. POST /v1/attestation/sandbox with { dob_days: 7000 }
 * 2. Worker authenticates to provii-issuer /v1/attestation/create with HMAC;
 * Issuer signs the Ed25519 attestation server-side
 * 3. Returns deep link: https://provii.app/attest?d=<attestation_data>
 * 4. User opens link in wallet, wallet calls /v1/issuance/blind
 */

import { getAssetFromKV } from "@cloudflare/kv-asset-handler";
import { handleDocs, type DocsEnv } from "./docs/handler";
import { SDK_SRI_HASH, SDK_URL } from "./generated/sdk-sri";
// @ts-ignore
import manifestJSON from "__STATIC_CONTENT_MANIFEST";
let assetManifest: Record<string, string>;
try {
  assetManifest = JSON.parse(manifestJSON);
} catch {
  throw new Error("Failed to parse static content manifest");
}

/**
 * : top-level Env declares every binding the worker may dispatch into,
 * including the docs gateway bindings consumed by `handleDocs`. Previously
 * `handleDocs(request, env as unknown as DocsEnv, ctx)` papered over the
 * mismatch; the cast was load-bearing on every binding rename. Declaring
 * the union here means TypeScript catches a missing binding at compile time
 * for both the demo handler and the docs handler.
 *
 * `DocsEnv` is intersected so future additions to that interface flow into
 * `Env` without manual sync. Anything bound only on `env.sandbox` is still
 * marked optional in `DocsEnv`, so the intersection stays accurate.
 */
interface Env extends DocsEnv {
  __STATIC_CONTENT: KVNamespace;
  DEMO_TOKEN_SECRET?: { get(): Promise<string | null> };
  PLAYGROUND_SESSIONS: KVNamespace;
  /**
 * Sandbox provii-verifier API key used by `register-test-origin` calls. Both
 * surfaces share this binding: the playground handler in `src/index.ts`
 * calls the upstream once per visitor session, the docs gateway calls it
 * once per 72-hour bootstrap window via
 * `getOrBootstrapDocsSandboxCredential`. The two call sites mint
 * credentials against disjoint origins (`docs-gateway-bootstrap.sandbox.provii.app`
 * for the gateway, ephemeral hex-suffix origins for the playground), so
 * the upstream policies the two surfaces own do not collide.
   */
  SANDBOX_API_KEY?: { get(): Promise<string | null> };
  /**
 * Optional override for the sandbox provii-issuer base URL used by the
 * `/playground/api/create-issuer-environment` handler. Defaults to
 * `https://sandbox-issuer.provii.app` when unset, which is the
 * production sandbox provii-issuer endpoint. The override exists so test
 * pools and local dev can point at a stand-in upstream without
 * rebuilding the Worker.
   */
  ISSUER_API_URL_SANDBOX?: string;
}

// ============================================================================
// Playground Secrets Store caching (, , )
// Secrets Store bindings require an async .get() call per access. Cache at
// module level so each isolate only pays for one fetch per TTL window.
//
// Names are explicitly scoped to the playground handler. The docs gateway
// handler keeps its own independent caches in src/docs/handler.ts so a
// playground compromise cannot leak through a shared cache and vice versa
// (per James's Finding 1).
// ============================================================================
let cachedPlaygroundSandboxApiKey: string | null = null;
let playgroundSandboxApiKeyCachedAt = 0;
const PLAYGROUND_SANDBOX_KEY_CACHE_TTL_MS = 300_000; // 5 minutes

async function getCachedPlaygroundSandboxApiKey(env: Env): Promise<string> {
  const now = Date.now();
  if (
    cachedPlaygroundSandboxApiKey === null ||
    now - playgroundSandboxApiKeyCachedAt > PLAYGROUND_SANDBOX_KEY_CACHE_TTL_MS
  ) {
    cachedPlaygroundSandboxApiKey = (await env.SANDBOX_API_KEY?.get()) ?? null;
    playgroundSandboxApiKeyCachedAt = now;
  }
  return cachedPlaygroundSandboxApiKey ?? "";
}

let cachedPlaygroundDemoTokenSecret: string | null = null;
let playgroundDemoTokenSecretCachedAt = 0;
const PLAYGROUND_DEMO_SECRET_CACHE_TTL_MS = 300_000; // 5 minutes

async function getCachedPlaygroundDemoTokenSecret(env: Env): Promise<string> {
  const now = Date.now();
  if (
    cachedPlaygroundDemoTokenSecret === null ||
    now - playgroundDemoTokenSecretCachedAt > PLAYGROUND_DEMO_SECRET_CACHE_TTL_MS
  ) {
    cachedPlaygroundDemoTokenSecret = (await env.DEMO_TOKEN_SECRET?.get()) ?? null;
    playgroundDemoTokenSecretCachedAt = now;
  }
  return cachedPlaygroundDemoTokenSecret ?? "";
}

/**
 * Test-only reset for the playground Secrets Store caches above. The
 * vitest isolate is single-worker so module state survives across tests;
 * any test that wants to swap the SANDBOX_API_KEY binding (e.g. to unbind
 * it) must clear the cache first or it will keep returning the previously
 * cached value. Production code never calls this; the underscore prefix
 * + the `__resetXForTest` naming convention matches the rest of the
 * codebase (`__resetDocsBootstrapCacheForTest`,
 * `__resetFeatureFlagCacheForTests`).
 */
export function __resetPlaygroundSecretsCacheForTests(): void {
  cachedPlaygroundSandboxApiKey = null;
  playgroundSandboxApiKeyCachedAt = 0;
  cachedPlaygroundDemoTokenSecret = null;
  playgroundDemoTokenSecretCachedAt = 0;
}

// ============================================================================
// Allowed CORS origins (CH-163)
// ============================================================================
const ALLOWED_DEMO_ORIGINS = [
  "https://playground.provii.app",
  "https://over.provii.app",
  "https://under.provii.app",
];

// ============================================================================
// Subdomain demo configurations (W1: demo subdomains)
// ============================================================================

interface SubdomainConfig {
  policyLabel: string;
  ageDisplay: string;
  direction: "over_age" | "under_age";
  /** Age threshold: minimum for over_age, maximum for under_age. */
  age: number;
}

/**
 * Demo subdomains. The hosted-flow public key is NOT hardcoded any more — a
 * cron ({@link refreshAllSubdomainKeys}) mints one registered key per direction
 * via register-test-origin and caches it in KV; page loads only READ it
 * ({@link getSubdomainPublicKey}), so visitors never provision on load.
 */
const SUBDOMAIN_CONFIGS: Record<string, SubdomainConfig> = {
  over: {
    policyLabel: "Over 18 Verification",
    ageDisplay: "18 or older",
    direction: "over_age",
    age: 18,
  },
  under: {
    policyLabel: "Under 16 Verification",
    ageDisplay: "under 16",
    direction: "under_age",
    age: 16,
  },
};

// Shared hosted key per demo subdomain, refreshed by the cron and cached in
// PLAYGROUND_SESSIONS KV. TTL matches the hosted-key lifetime so that if the
// cron ever stops, the entry eventually expires and the load fallback re-mints.
const SUBDOMAIN_PK_TTL_SECONDS = 72 * 60 * 60;

function subdomainPkCacheKey(subdomain: string): string {
  return `bootstrap-pk:${subdomain}`;
}

/**
 * Mint a fresh REGISTERED hosted-flow public key for a demo subdomain via
 * register-test-origin and cache it in KV. Called by the cron on a schedule
 * (and once by a page load only if the cache is empty). Returns null on failure.
 */
async function mintAndCacheSubdomainKey(
  env: Env,
  subdomain: string,
  config: SubdomainConfig,
): Promise<string | null> {
  const sandboxApiKey = await getCachedPlaygroundSandboxApiKey(env);
  if (!sandboxApiKey) {
    console.error(`[bootstrap-pk:${subdomain}] SANDBOX_API_KEY missing; cannot mint`);
    return null;
  }
  const isOver = config.direction === "over_age";
  const registerBody: Record<string, unknown> = {
    origin: `https://${subdomain}.provii.app`,
    min_age_years: isOver ? config.age : 1,
    api_key: sandboxApiKey,
    proof_direction: config.direction,
  };
  if (!isOver) registerBody.max_age_years = config.age;

  const registerBodyJson = JSON.stringify(registerBody);
  const signature = await hmacBodyHex(sandboxApiKey, registerBodyJson);
  const resp = await fetch(
    "https://sandbox-verify.provii.app/v1/register-test-origin",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "X-Docs-Hmac": signature,
      },
      body: registerBodyJson,
    },
  );
  if (!resp.ok) {
    console.error(`[bootstrap-pk:${subdomain}] register-test-origin ${resp.status}`);
    return null;
  }
  let result: Record<string, unknown>;
  try {
    result = (await resp.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
  const publicKey =
    typeof result.public_key === "string" ? result.public_key : null;
  if (!publicKey) {
    console.error(`[bootstrap-pk:${subdomain}] no public_key in response`);
    return null;
  }
  await env.PLAYGROUND_SESSIONS.put(subdomainPkCacheKey(subdomain), publicKey, {
    expirationTtl: SUBDOMAIN_PK_TTL_SECONDS,
  });
  return publicKey;
}

/**
 * Read the cron-cached shared hosted key for a subdomain. Falls back to a
 * SINGLE mint only if the cache is empty (e.g. right after deploy, before the
 * first cron run); steady-state page loads are pure KV reads.
 */
async function getSubdomainPublicKey(
  env: Env,
  subdomain: string,
  config: SubdomainConfig,
): Promise<string | null> {
  const cached = await env.PLAYGROUND_SESSIONS.get(
    subdomainPkCacheKey(subdomain),
  );
  if (cached) return cached;
  return mintAndCacheSubdomainKey(env, subdomain, config);
}

/** Cron entrypoint: refresh every demo subdomain's shared hosted key. */
async function refreshAllSubdomainKeys(env: Env): Promise<void> {
  for (const subdomain of Object.keys(SUBDOMAIN_CONFIGS)) {
    const config = SUBDOMAIN_CONFIGS[subdomain];
    if (config) await mintAndCacheSubdomainKey(env, subdomain, config);
  }
}

/**
 * Extract the subdomain from a request to *.provii.app.
 * Returns null for non-matching hosts or retired subdomains.
 * Matches: over.provii.app, under.provii.app, playground.provii.app
 */
function extractSubdomain(request: Request): string | null {
  const host = request.headers.get("Host");
  if (!host) return null;
  const parts = host.split(":");
  const hostname = parts[0] ?? "";
  if (!hostname) return null;
  const match = hostname.match(/^([a-z0-9-]+)\.provii\.app$/);
  if (!match || !match[1]) return null;
 // Safety: don't intercept retired subdomains (Worker no longer routes them, but guard remains)
  const sub = match[1];
  if (sub === "demo" || sub === "sandbox-demo") return null;
  return sub;
}

/**
 * Escape HTML special characters to prevent XSS in template interpolation.
 */
function escapeHtml(unsafeString: string): string {
  return unsafeString
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

/**
 * Return the origin if it is in the allowlist, otherwise null.
 */
function getAllowedOrigin(request: Request): string | null {
  const origin = request.headers.get("Origin");
  if (origin && ALLOWED_DEMO_ORIGINS.includes(origin)) {
    return origin;
  }
  return null;
}

// ============================================================================
// Security headers helpers (CH-160, CH-161, CH-162, CH-164)
// ============================================================================

/** Base security headers applied to every response */
const BASE_SECURITY_HEADERS: Record<string, string> = {
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy":
    "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "credentialless",
  "Cross-Origin-Resource-Policy": "same-origin",
};

/** CSP for API/JSON responses (no inline scripts needed) */
const API_CSP =
  "default-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests";

/** Generate a CSPRNG nonce (128 bits, base64-encoded) */
function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

/** Inject nonce into inline <script> tags (skip external scripts with src=) */
function addNoncesToScripts(html: string, nonce: string): string {
  return html.replace(/<script\b([^>]*)>/gi, (match, attrs: string) => {
    if (/\bsrc\s*=/i.test(attrs)) return match;
    if (/\bnonce\s*=/i.test(attrs)) return match;
    return `<script nonce="${nonce}"${attrs}>`;
  });
}

/**
 * Build a JSON API Response with full security headers (CH-160, CH-161, CH-162).
 */
function jsonResponse(
  body: unknown,
  status: number,
  request: Request,
  extraHeaders?: Record<string, string>,
): Response {
  const origin = getAllowedOrigin(request);
  const headers: Record<string, string> = {
    ...BASE_SECURITY_HEADERS,
    "Content-Type": "application/json",
    "Content-Security-Policy": API_CSP,
  };
  if (origin) {
    headers["Access-Control-Allow-Origin"] = origin;
  }
  if (extraHeaders) {
    Object.assign(headers, extraHeaders);
  }
  return new Response(JSON.stringify(body), { status, headers });
}

/**
 * Apply security headers to an existing Response (for static assets).
 * For HTML responses, generates a nonce and injects it into inline scripts.
 */
async function addSecurityHeaders(
  response: Response,
  isHtml: boolean,
): Promise<Response> {
  const newHeaders = new Headers(response.headers);
  for (const [key, value] of Object.entries(BASE_SECURITY_HEADERS)) {
    newHeaders.set(key, value);
  }

  if (!isHtml) {
    newHeaders.set("Content-Security-Policy", API_CSP);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  }

 // HTML: generate nonce, inject into inline scripts, build dynamic CSP
  const nonce = generateNonce();
  let html = await response.text();
  html = addNoncesToScripts(html, nonce);

 // CDN origin for provii-agegate SDK, 'unsafe-inline' for element style attrs (CH-167 ACCEPTED)
  const htmlCsp = `default-src 'none'; script-src 'nonce-${nonce}' https://cdn.provii.app; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self' https://*.provii.app wss://*.provii.app; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests`;
  newHeaders.set("Content-Security-Policy", htmlCsp);

  return new Response(html, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
}

// ============================================================================
// Sandbox configuration
// ============================================================================

// `/v1/attestation/sandbox` mints a per-deployment Issuing Party cred via
// `register-test-issuer` and authenticates to `/v1/attestation/create` with
// HMAC; the Issuer signs every attestation server-side. See
// `getOrMintPlaygroundServerIssuerCred` below.

// ============================================================================
// W4: Playground types and rate limiting
// ============================================================================

interface PlaygroundSession {
  origin: string;
  hmacSecret: string;
  clientId: string;
  publicKey?: string;
  age: number;
  direction: "over" | "under";
  createdAt: number;
  submitSecret?: string;
  codeVerifier?: string;
  challengeId?: string;
}

/**
 * KV-based rate limiter for playground endpoints.
 * Uses a rolling-window counter stored in PLAYGROUND_SESSIONS KV with 1hr TTL.
 * Key format: ratelimit:<hashedIp>:<endpoint>
 */
const RATE_LIMITS: Record<string, number> = {
  "create-env": 5,
 // Issuer-side mirror of `create-env`. Same per-hour ceiling: a fresh
 // sandbox issuer mint is at least as expensive as the verifier mint
 // because provii-issuer also runs an Ed25519 public-key binding step, and
 // we don't want a single IP to flood provii-issuer's rate-limit bucket.
  "create-issuer-env": 5,
  "create-challenge": 30,
  "status": 1200,
  "simulate-proof": 30,
};
const RATE_LIMIT_TTL_SECONDS = 3600; // 1 hour

async function hashIpForRateLimit(clientIp: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(clientIp),
  );
  return Array.from(new Uint8Array(digest).slice(0, 16))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

interface RateLimitEntry {
  count: number;
  firstHit: number; // epoch seconds
}

async function getRateLimitState(
  kv: KVNamespace,
  clientIp: string,
  endpoint: string,
): Promise<{ limited: boolean; resetsAt: number | null }> {
  const hashedIp = await hashIpForRateLimit(clientIp);
  const rateLimitKey = `ratelimit:${hashedIp}:${endpoint}`;
  const limit = RATE_LIMITS[endpoint] ?? 30;

  const existing = await kv.get(rateLimitKey);
  if (!existing) return { limited: false, resetsAt: null };

  try {
    const entry: RateLimitEntry = JSON.parse(existing);
    const resetsAt = entry.firstHit + RATE_LIMIT_TTL_SECONDS;
    return { limited: entry.count >= limit, resetsAt };
  } catch {
    return { limited: false, resetsAt: null };
  }
}

async function recordRateLimitHit(
  kv: KVNamespace,
  clientIp: string,
  endpoint: string,
): Promise<void> {
  const hashedIp = await hashIpForRateLimit(clientIp);
  const rateLimitKey = `ratelimit:${hashedIp}:${endpoint}`;
  const now = Math.floor(Date.now() / 1000);

  const existing = await kv.get(rateLimitKey);
  let entry: RateLimitEntry;

  if (existing) {
    try {
      entry = JSON.parse(existing);
      entry.count += 1;
    } catch {
      entry = { count: 1, firstHit: now };
    }
  } else {
    entry = { count: 1, firstHit: now };
  }

 // TTL from first hit, not from this hit
  const elapsed = now - entry.firstHit;
  const remainingTtl = Math.max(RATE_LIMIT_TTL_SECONDS - elapsed, 60);

  await kv.put(rateLimitKey, JSON.stringify(entry), {
    expirationTtl: remainingTtl,
  });
}

/** Generate a random hex string of the specified byte length. */
function randomHex(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * HMAC-SHA256 the given body under the UTF-8 bytes of `key` and return
 * the tag as lowercase hex. Matches provii-verifier's `X-Docs-Hmac` contract
 * (src/security/docs_hmac.rs). Used when the playground worker calls
 * sandbox-only upstream endpoints like `/v1/register-test-origin`.
 */
async function hmacBodyHex(key: string, body: string): Promise<string> {
  const keyBytes = new TextEncoder().encode(key);
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    hmacKey,
    new TextEncoder().encode(body),
  );
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function computeHmacSignature(
  hmacSecretBase64url: string,
  method: string,
  path: string,
  bodyJson: string,
  timestamp: number,
  nonce: string,
): Promise<string> {
  const canonicalMessage = `${timestamp}:${method}:${path}:${bodyJson}:${nonce}`;
 // HMAC harmonisation (provii-verifier / ). The 43-char wire
 // string is transport encoding only; base64url-decode it to 32 raw bytes
 // FIRST, then use those bytes as the HMAC key. The server stores the same
 // 32 raw bytes (encrypted under the MEK) and verifies against them, so
 // signing with the ASCII bytes of the wire string produces a tag mismatch
 // and 401 INVALID_HMAC.
  const secretBytes = base64urlDecode(hmacSecretBase64url);
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const hmacSig = await crypto.subtle.sign(
    "HMAC",
    hmacKey,
    new TextEncoder().encode(canonicalMessage),
  );
  return Array.from(new Uint8Array(hmacSig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Code snippet bundle returned to the playground UI.
 *
 * The first three fields (`agegateJs`, `curl`, `nodejs`) predate the mode
 * picker and are kept for backwards compatibility per a brief. The
 * remaining fields cover the Expert mode (Python, Go) and the Mobile mode
 * app-side clients (iOS, Android, Flutter). The Mobile tab no longer ships
 * a backend snippet of its own; the Expert tab is the canonical home for
 * cURL, Node.js, Python and Go signing recipes.
 */
export interface PlaygroundCodeSnippets {
  agegateJs: string;
  curl: string;
  nodejs: string;
  python: string;
  go: string;
  iosSwift: string;
  androidKotlin: string;
  flutterDart: string;
}

/**
 * Build code snippets for a playground environment so developers can copy
 * and paste them into their own integration.
 *
 * Exported for unit testing. Pure function: given the same credentials it
 * always returns the same string blocks.
 */
export function buildCodeSnippets(
  clientId: string,
  hmacSecret: string,
  apiKey: string,
  publicKey: string,
): PlaygroundCodeSnippets {
 // Age threshold is bound server-side to the public key's policy.
 // No data-minimum-age or data-maximum-age attribute is needed here.
 // SDK_URL and SDK_SRI_HASH come from src/generated/sdk-sri.ts, which is
 // regenerated from the live CDN bundle at build time and verified in CI.
 // Hard-coding either value here would silently break every developer who
 // pastes this snippet onto a real site as soon as the SDK is rotated.
  const agegateJs = `<script src="${SDK_URL}"
  integrity="${SDK_SRI_HASH}"
  crossorigin="anonymous"
  data-public-key="${publicKey}"
  data-environment="sandbox"
  async></script>`;

  const curl = `# Create a challenge using your sandbox credentials.
# Sandbox \`rp_sandbox_*\` credentials accept ANY Origin value (origin allowlist
# is bypassed in sandbox). Production credentials require Origin to match one
# of the registered \`allowed_origins\`.

# PKCE recipe. Generate a verifier, derive the SHA-256 challenge, keep the
# verifier somewhere safe; YOUR backend hands it back at the redeem call.
# The \`tr -d '=\\n'\` strips both base64 padding AND the embedded line
# breaks that openssl emits every 64 chars, so the verifier is a clean
# RFC 7636 unreserved-chars-only string with no whitespace surprises.
CODE_VERIFIER=$(openssl rand -base64 96 | tr -d '=\\n' | tr '/+' '_-' | head -c 128)
CODE_CHALLENGE=$(printf '%s' "\${CODE_VERIFIER}" | openssl dgst -sha256 -binary | openssl base64 -A | tr -d '=\\n' | tr '/+' '_-')
echo "code_verifier (save for redeem): \${CODE_VERIFIER}"

TIMESTAMP=$(date +%s)
NONCE=$(openssl rand -hex 32)
BODY="{\\"code_challenge\\":\\"\${CODE_CHALLENGE}\\",\\"method\\":\\"S256\\",\\"verifying_key_id\\":null,\\"expires_in\\":300}"
# Braces around \${TIMESTAMP} are mandatory: zsh (macOS default since 2019)
# parses unbraced \`$TIMESTAMP:POST\` as \`\${TIMESTAMP:P}OST\`. The \`:P\`
# absolute-pathname modifier silently rewrites the canonical message
# to a filesystem path, producing 401 INVALID_HMAC on the server.
MESSAGE="\${TIMESTAMP}:POST:/v1/challenge:\${BODY}:\${NONCE}"

# HMAC-key prep. The 43-char hmac_secret is base64url transport encoding;
# decode to 32 raw bytes FIRST and key the HMAC with those bytes (the same
# bytes the server stores in KV). Signing under the ASCII bytes of the
# 43-char string produces a tag mismatch and 401 INVALID_HMAC. We pad the
# string to a multiple of 4, swap the URL-safe alphabet for standard, and
# hex-encode the decoded bytes for openssl's -macopt hexkey path.
HMAC_SECRET='${hmacSecret}'
PAD=$(printf '%0.s=' $(seq 1 $(( (4 - \${#HMAC_SECRET} % 4) % 4 ))))
SECRET_HEX=$(printf '%s%s' "\${HMAC_SECRET}" "\${PAD}" | tr '_-' '/+' | base64 -d | xxd -p -c 256)
HMAC=$(printf '%s' "\${MESSAGE}" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"\${SECRET_HEX}" | sed 's/^.* //')

curl -X POST https://sandbox-verify.provii.app/v1/challenge \\
  -H "Content-Type: application/json" \\
  -H "Origin: https://your-shop.example.com" \\
  -H "X-API-Key: ${apiKey}" \\
  -d "{
    \\"code_challenge\\": \\"\${CODE_CHALLENGE}\\",
    \\"method\\": \\"S256\\",
    \\"verifying_key_id\\": null,
    \\"expires_in\\": 300,
    \\"authorizer\\": {
      \\"keyId\\": \\"${clientId}\\",
      \\"timestamp\\": \${TIMESTAMP},
      \\"nonce\\": \\"\${NONCE}\\",
      \\"hmac\\": \\"\${HMAC}\\"
    }
  }"

# --- After challenge creation -------------------------------------------------
# The create response carries \`challenge_id\`, \`status_url\`, and
# \`verify_url\`. Capture \`challenge_id\` into SESSION_ID, poll until the
# wallet has submitted its proof, then redeem the code_verifier.
#
# IMPORTANT: poll + redeem use the SAME long X-API-Key value as the create
# call above (the \`${apiKey}\` value, NOT a \`pk_test_*\` value). The server
# returns 401 POLL_AUTH_FAILED if the \`pk_*\` value is sent on these routes.
#
# SESSION_ID=<challenge_id from the create response>
#
# # 1) Poll status. Repeat on a short interval until state is
# # \`proof_ok_waiting_for_redeem\` (wallet has submitted a valid proof
# # and is waiting for your backend to redeem the verifier):
# curl https://sandbox-verify.provii.app/v1/challenge/\${SESSION_ID} \\
# -H "Origin: https://your-shop.example.com" \\
# -H "X-API-Key: ${apiKey}"
#
# # 2) Redeem. Exchange the original code_verifier for the final result:
# curl -X POST https://sandbox-verify.provii.app/v1/challenge/\${SESSION_ID}/redeem \\
# -H "Content-Type: application/json" \\
# -H "Origin: https://your-shop.example.com" \\
# -H "X-API-Key: ${apiKey}" \\
# -d "{\\"code_verifier\\": \\"\${CODE_VERIFIER}\\"}"`;

  const nodejs = `// save as .mjs or use "type": "module" in package.json
// Sandbox \`rp_sandbox_*\` credentials accept ANY Origin value (origin allowlist
// is bypassed in sandbox). Production credentials require Origin to match one
// of the registered \`allowed_origins\`.
// Node 22+ ships fetch + crypto natively, no extra packages needed.
import crypto from 'node:crypto';

const CLIENT_ID = '${clientId}';
const HMAC_SECRET = '${hmacSecret}';
const API_KEY = '${apiKey}';

async function createChallenge() {
 // PKCE recipe. Persist codeVerifier server-side keyed by challenge_id; YOUR
 // backend hands it back at the redeem call (the wallet never sees it).
  const codeVerifier = crypto.randomBytes(96).toString('base64url').slice(0, 128);
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(32).toString('hex');

 // Field order is significant. The HMAC is computed over the JSON.stringify
 // output of this exact object literal, so reordering keys silently breaks
 // the signature on the server side.
  const body = {
    code_challenge: codeChallenge,
    method: 'S256',
    verifying_key_id: null,
    expires_in: 300,
  };
  const bodyJson = JSON.stringify(body);
  const message = \`\${timestamp}:POST:/v1/challenge:\${bodyJson}:\${nonce}\`;

 // HMAC-key prep. The 43-char HMAC_SECRET is base64url transport encoding;
 // decode to 32 raw bytes FIRST and key the HMAC with those bytes (the same
 // bytes the server stores in KV). Signing under the ASCII bytes of the
 // 43-char string produces a tag mismatch and 401 INVALID_HMAC.
  const secretBytes = Buffer.from(HMAC_SECRET, 'base64url');
  const hmac = crypto.createHmac('sha256', secretBytes)
    .update(message).digest('hex');

  const fullBody = {
    ...body,
    authorizer: { keyId: CLIENT_ID, timestamp, nonce, hmac },
  };

  const res = await fetch(
    'https://sandbox-verify.provii.app/v1/challenge',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Origin': 'https://your-shop.example.com',
        'X-API-Key': API_KEY,
      },
      body: JSON.stringify(fullBody),
    }
  );

 // Surface the structured error envelope ({error, code, field, detail,
 // request_id}) when the server returns 4xx. Returning res.json() blindly
 // would let an error body parse silently as if it were a challenge.
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error(
      \`Provii \${res.status} \${errBody.code ?? 'UNKNOWN'}: \${errBody.detail ?? ''} \` +
      \`(field=\${errBody.field ?? ''}, request_id=\${errBody.request_id ?? ''})\`,
    );
  }

 // Pair the codeVerifier with the challenge response so the caller can
 // persist both. The verifier is required to redeem the challenge later.
  const challenge = await res.json();
  return { challenge, codeVerifier };
}`;

 // Python snippet uses requests + hmac/hashlib. Same canonical-message shape
 // as the Node.js snippet so the two are interchangeable on the wire.
  const python = `# Sandbox \`rp_sandbox_*\` credentials accept ANY Origin value (origin allowlist
# is bypassed in sandbox). Production credentials require Origin to match one
# of the registered \`allowed_origins\`.
# pip install requests
import base64
import hashlib
import hmac
import json
import secrets
import time

import requests

CLIENT_ID = '${clientId}'
HMAC_SECRET = '${hmacSecret}'
API_KEY = '${apiKey}'


def create_challenge():
 # PKCE recipe. The code_verifier is a per-challenge secret that a real
 # integration must keep server-side and hand back at the redeem call; this
 # snippet only demonstrates minting it (no storage layer is shown). The
 # wallet never sees it.
 # 96 random bytes base64url-encodes to 128 chars, the RFC 7636 maximum.
    code_verifier = secrets.token_urlsafe(96)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode()

    timestamp = int(time.time())
    nonce = secrets.token_hex(32)

 # Field order is significant. json.dumps preserves dict insertion order in
 # Python 3.7+, but rebuilding this dict with sort_keys=True or rearranging
 # the kwargs silently breaks the HMAC signature on the server side.
    body = {
        'code_challenge': code_challenge,
        'method': 'S256',
        'verifying_key_id': None,
        'expires_in': 300,
    }
    body_json = json.dumps(body, separators=(',', ':'))
    message = f'{timestamp}:POST:/v1/challenge:{body_json}:{nonce}'

 # HMAC-key prep. The 43-char HMAC_SECRET is base64url transport encoding;
 # decode to 32 raw bytes FIRST and key the HMAC with those bytes (the same
 # bytes the server stores in KV). Signing under the ASCII bytes of the
 # 43-char string produces a tag mismatch and 401 INVALID_HMAC. The
 # urlsafe_b64decode call needs trailing '=' padding to multiples of 4.
    secret_bytes = base64.urlsafe_b64decode(
        HMAC_SECRET + '=' * (-len(HMAC_SECRET) % 4)
    )
    signature = hmac.new(
        secret_bytes,
        message.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()

    full_body = {
        **body,
        'authorizer': {
            'keyId': CLIENT_ID,
            'timestamp': timestamp,
            'nonce': nonce,
            'hmac': signature,
        },
    }

    response = requests.post(
        'https://sandbox-verify.provii.app/v1/challenge',
        headers={
            'Content-Type': 'application/json',
            'Origin': 'https://your-shop.example.com',
            'X-API-Key': API_KEY,
        },
        json=full_body,
        timeout=10,
    )

 # Surface the structured error envelope ({error, code, field, detail,
 # request_id}) when the server returns 4xx. response.raise_for_status()
 # would discard the body and leave the dev with no diagnostic.
    if not response.ok:
        try:
            err = response.json()
            raise RuntimeError(
                f"Provii {response.status_code} {err.get('code', 'UNKNOWN')}: "
                f"{err.get('detail', '')} "
                f"(field={err.get('field', '')}, request_id={err.get('request_id', '')})"
            )
        except ValueError:
            response.raise_for_status()

 # Pair the code_verifier with the challenge response so the caller can
 # persist both. The verifier is required to redeem the challenge later.
    return {'challenge': response.json(), 'code_verifier': code_verifier}`;

 // Go snippet uses net/http + crypto/hmac. Mirrors the canonical message
 // exactly so the HMAC tag matches what the provii-verifier expects.
  const go = `// Sandbox \`rp_sandbox_*\` credentials accept ANY Origin value (origin allowlist
// is bypassed in sandbox). Production credentials require Origin to match one
// of the registered \`allowed_origins\`.
package main

import (
\t"bytes"
\t"crypto/hmac"
\t"crypto/rand"
\t"crypto/sha256"
\t"encoding/base64"
\t"encoding/hex"
\t"encoding/json"
\t"fmt"
\t"net/http"
\t"time"
)

const (
\tclientID   = "${clientId}"
\thmacSecret = "${hmacSecret}"
\tapiKey     = "${apiKey}"
)

// Field order is significant. encoding/json marshals maps in alphabetical key
// order, which silently breaks the HMAC signature; structs marshal in field
// declaration order, so always sign + send via a typed struct.
type challengeBody struct {
\tCodeChallenge  string \`json:"code_challenge"\`
\tMethod         string \`json:"method"\`
\tVerifyingKeyID *int   \`json:"verifying_key_id"\`
\tExpiresIn      int    \`json:"expires_in"\`
}

type authorizer struct {
\tKeyID     string \`json:"keyId"\`
\tTimestamp int64  \`json:"timestamp"\`
\tNonce     string \`json:"nonce"\`
\tHMAC      string \`json:"hmac"\`
}

type fullBody struct {
\tchallengeBody
\tAuthorizer authorizer \`json:"authorizer"\`
}

// challengeResult pairs the server response with the codeVerifier so the
// caller can persist both. The verifier is required at redeem time and YOUR
// backend hands it back to the provii-verifier then; the wallet never sees it.
type challengeResult struct {
\tChallenge    map[string]any
\tCodeVerifier string
}

func createChallenge() (*challengeResult, error) {
\t// PKCE recipe. Persist codeVerifier server-side keyed by challenge_id; YOUR
\t// backend hands it back at the redeem call (the wallet never sees it).
\tverifierBytes := make([]byte, 64)
\tif _, err := rand.Read(verifierBytes); err != nil {
\t\treturn nil, err
\t}
\tcodeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
\tsum := sha256.Sum256([]byte(codeVerifier))
\tcodeChallenge := base64.RawURLEncoding.EncodeToString(sum[:])

\ttimestamp := time.Now().Unix()
\tnonceBytes := make([]byte, 32)
\tif _, err := rand.Read(nonceBytes); err != nil {
\t\treturn nil, err
\t}
\tnonce := hex.EncodeToString(nonceBytes)

\tbody := challengeBody{
\t\tCodeChallenge:  codeChallenge,
\t\tMethod:         "S256",
\t\tVerifyingKeyID: nil,
\t\tExpiresIn:      300,
\t}
\tbodyJSON, err := json.Marshal(body)
\tif err != nil {
\t\treturn nil, err
\t}
\tmessage := fmt.Sprintf("%d:POST:/v1/challenge:%s:%s", timestamp, bodyJSON, nonce)

\t// HMAC-key prep. The 43-char hmacSecret is base64url transport encoding;
\t// decode to 32 raw bytes FIRST and key the HMAC with those bytes (the
\t// same bytes the server stores in KV). Signing under the ASCII bytes of
\t// the 43-char string produces a tag mismatch and 401 INVALID_HMAC.
\tsecretBytes, err := base64.RawURLEncoding.DecodeString(hmacSecret)
\tif err != nil {
\t\treturn nil, fmt.Errorf("hmac_secret base64url decode: %w", err)
\t}
\tmac := hmac.New(sha256.New, secretBytes)
\tmac.Write([]byte(message))
\tsignature := hex.EncodeToString(mac.Sum(nil))

\tpayload, err := json.Marshal(fullBody{
\t\tchallengeBody: body,
\t\tAuthorizer: authorizer{
\t\t\tKeyID:     clientID,
\t\t\tTimestamp: timestamp,
\t\t\tNonce:     nonce,
\t\t\tHMAC:      signature,
\t\t},
\t})
\tif err != nil {
\t\treturn nil, err
\t}

\treq, err := http.NewRequest(
\t\t"POST",
\t\t"https://sandbox-verify.provii.app/v1/challenge",
\t\tbytes.NewReader(payload),
\t)
\tif err != nil {
\t\treturn nil, err
\t}
\treq.Header.Set("Content-Type", "application/json")
\treq.Header.Set("Origin", "https://your-shop.example.com")
\treq.Header.Set("X-API-Key", apiKey)

\tresp, err := http.DefaultClient.Do(req)
\tif err != nil {
\t\treturn nil, err
\t}
\tdefer resp.Body.Close()

\tvar out map[string]any
\tif err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
\t\treturn nil, err
\t}

\t// Surface the structured error envelope ({error, code, field, detail,
\t// request_id}) when the server returns 4xx. Returning the body blindly
\t// would let an error envelope parse silently as if it were a challenge.
\tif resp.StatusCode >= 400 {
\t\treturn nil, fmt.Errorf(
\t\t\t"provii %d %v: %v (field=%v, request_id=%v)",
\t\t\tresp.StatusCode, out["code"], out["detail"], out["field"], out["request_id"],
\t\t)
\t}

\treturn &challengeResult{Challenge: out, CodeVerifier: codeVerifier}, nil
}

func main() {
\tresult, err := createChallenge()
\tif err != nil {
\t\tfmt.Println("error:", err)
\t\treturn
\t}
\tpretty, _ := json.MarshalIndent(result.Challenge, "", "  ")
\tfmt.Println(string(pretty))
\tfmt.Println("code_verifier (save for redeem):", result.CodeVerifier)
}`;

 // iOS Swift snippet, modelled on apps/ios/ProviiVerifierDemo/APIClient.swift.
 // Calls YOUR backend, receives a deep link, and opens it via UIApplication.
 // The HMAC secret + API key never touch the device.
  const iosSwift = `// SECURITY: HMAC secret + API key live on YOUR backend, never the device.
// The mobile app receives a pre-signed deep link from your server and opens it.
// See the Expert tab on this page for the backend signing recipe; cURL,
// Node.js, Python and Go live there as the canonical server-side samples.
// In production your backend must set Origin: https://your-registered-domain.com
// when calling sandbox-verify.provii.app; sandbox credentials skip that check.
import Foundation
import UIKit

struct CreateChallengeResponse: Decodable {
    let sessionId: String
    let deepLink: String
    let expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case deepLink = "deep_link"
        case expiresAt = "expires_at"
    }
}

final class ProviiVerifier {
    private let backendURL = URL(string: "https://your-backend.example.com")!

    func startVerification(age: Int) async throws {
        var request = URLRequest(url: backendURL.appendingPathComponent("/api/create-challenge"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode([
            "minimum_age": age,
            "expires_in": 300,
        ])

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw URLError(.badServerResponse)
        }

        let decoded = try JSONDecoder().decode(CreateChallengeResponse.self, from: data)
        guard let url = URL(string: decoded.deepLink),
              decoded.deepLink.hasPrefix("https://provii.app/verify?") else {
            throw URLError(.badURL)
        }

        await MainActor.run {
            UIApplication.shared.open(url)
        }
    }
}`;

 // Android Kotlin snippet, modelled on apps/android/verifier/.../ProviiVerifier.kt.
 // Same shape: mobile app calls YOUR backend, opens returned deep link via Intent.
  const androidKotlin = `// SECURITY: HMAC secret + API key live on YOUR backend, never the device.
// The mobile app receives a pre-signed deep link from your server and opens it.
// See the Expert tab on this page for the backend signing recipe; cURL,
// Node.js, Python and Go live there as the canonical server-side samples.
// In production your backend must set Origin: https://your-registered-domain.com
// when calling sandbox-verify.provii.app; sandbox credentials skip that check.
import android.content.Context
import android.content.Intent
import android.net.Uri
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

@Serializable
data class CreateChallengeResponse(
    @SerialName("session_id") val sessionId: String,
    @SerialName("deep_link") val deepLink: String,
    @SerialName("expires_at") val expiresAt: Long,
)

class ProviiVerifier(private val context: Context) {
    private val backendUrl = "https://your-backend.example.com"
    private val http = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }

    suspend fun startVerification(age: Int) {
        val payload = """{"minimum_age":$age,"expires_in":300}"""
        val request = Request.Builder()
            .url("$backendUrl/api/create-challenge")
            .post(payload.toRequestBody("application/json".toMediaType()))
            .build()

        val response = http.newCall(request).execute()
        check(response.isSuccessful) { "Backend error: \${response.code}" }
        val body = response.body?.string() ?: error("Empty response body")
        val decoded = json.decodeFromString<CreateChallengeResponse>(body)
        require(decoded.deepLink.startsWith("https://provii.app/verify?"))

        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(decoded.deepLink)).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
    }
}`;

 // Flutter Dart snippet, modelled on apps/flutter/provii_verifier_demo/.../provii_verifier.dart.
 // Same shape again: app calls backend, opens returned deep link via url_launcher.
  const flutterDart = `// SECURITY: HMAC secret + API key live on YOUR backend, never the device.
// The mobile app receives a pre-signed deep link from your server and opens it.
// See the Expert tab on this page for the backend signing recipe; cURL,
// Node.js, Python and Go live there as the canonical server-side samples.
// In production your backend must set Origin: https://your-registered-domain.com
// when calling sandbox-verify.provii.app; sandbox credentials skip that check.
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';

class CreateChallengeResponse {
  final String sessionId;
  final String deepLink;
  final int expiresAt;

  CreateChallengeResponse({
    required this.sessionId,
    required this.deepLink,
    required this.expiresAt,
  });

  factory CreateChallengeResponse.fromJson(Map<String, dynamic> json) {
    return CreateChallengeResponse(
      sessionId: json['session_id'] as String,
      deepLink: json['deep_link'] as String,
      expiresAt: (json['expires_at'] as num).toInt(),
    );
  }
}

class ProviiVerifier {
  static const String backendUrl = 'https://your-backend.example.com';

  Future<void> startVerification({required int age}) async {
    final response = await http.post(
      Uri.parse('\$backendUrl/api/create-challenge'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'minimum_age': age, 'expires_in': 300}),
    );

    if (response.statusCode != 200) {
      throw Exception('Backend error: \${response.statusCode}');
    }

    final decoded = CreateChallengeResponse.fromJson(
      jsonDecode(response.body) as Map<String, dynamic>,
    );

    if (!decoded.deepLink.startsWith('https://provii.app/verify?')) {
      throw Exception('Invalid deep link from backend');
    }

    final uri = Uri.parse(decoded.deepLink);
    final launched = await launchUrl(uri, mode: LaunchMode.externalApplication);
    if (!launched) {
      throw Exception('Could not open Provii Wallet');
    }
  }
}`;

  return {
    agegateJs,
    curl,
    nodejs,
    python,
    go,
    iosSwift,
    androidKotlin,
    flutterDart,
  };
}

/**
 * Decode base64url string to Uint8Array
 */
function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encode Uint8Array to base64url string
 */
function base64urlEncode(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Generate a daily rotating demo token using HMAC-SHA256
 * Token format: demo_token_v1_<YYYYMMDD>_<16-char-hmac>
 */
async function generateDemoToken(
  secret: string,
): Promise<{ token: string; expiresAt: number }> {
  const now = new Date();
  const dateStr = now.toISOString().slice(0, 10).replace(/-/g, "");

 // Compute HMAC-SHA256
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(`provii-demos-v1:${dateStr}`),
  );

 // Convert to hex and truncate to 16 chars
  const sigHex = Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 16);

  const token = `demo_token_v1_${dateStr}_${sigHex}`;

 // Expires at end of tomorrow (48-hour window for timezone handling)
  const tomorrow = new Date(now);
  tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
  tomorrow.setUTCHours(23, 59, 59, 999);
  const expiresAt = Math.floor(tomorrow.getTime() / 1000);

  return { token, expiresAt };
}

// ============================================================================
// Server-side Issuing Party cred for the public marketing demo
// ============================================================================
//
// `/v1/attestation/sandbox` backs the public marketing demo at
// provii.app/demo/wallet. The Worker acts as an Issuing Party: it
// authenticates to provii-issuer `/v1/attestation/create` with HMAC-SHA256,
// and the Issuer signs the Ed25519 attestation server-side with its own
// keys. The Worker never holds an Ed25519 signing key, matching the role
// model used everywhere else.
//
// On first use the Worker calls `register-test-issuer` to mint a
// per-deployment sandbox bundle (client_id + hmac_secret + kid +
// base_url) and caches it in KV under `playground-server-issuer-cred:v1`
// for 70 hours (provii-issuer itself binds the cred for 72 hours; the
// 2-hour gap is so we refresh before the upstream record expires).
//
// If two isolates race the first mint we accept the duplicate; both
// writes target the same KV key and the second one wins. Provii-issuer
// dedupes on `kid`, not on `client_id`, so the orphaned mint times out.
//
// Schema is stable. If the cached blob fails to parse (forward incompat)
// we re-mint. No migration code.
// ============================================================================

const KV_KEY_PLAYGROUND_SERVER_ISSUER_CRED = "playground-server-issuer-cred:v1";
const SERVER_ISSUER_CRED_TTL_SECONDS = 252_000; // 70 hours
const SERVER_ISSUER_CRED_REFRESH_MARGIN_SECONDS = 600; // refresh in last 10 mins

interface ServerIssuerCred {
  /** provii-issuer kid (iss_sbx_<8 hex>). */
  kid: string;
  /** Sandbox client_id minted by register-test-issuer. */
  clientId: string;
  /** Base64url-encoded HMAC secret. Used to authenticate to /v1/attestation/create. */
  hmacSecretB64u: string;
  /** Provii-issuer base URL returned by register-test-issuer. */
  baseUrl: string;
  /** Epoch seconds. We refresh whenever now() is past this minus the margin. */
  expiresAt: number;
}

async function mintPlaygroundServerIssuerCred(
  env: Env,
): Promise<ServerIssuerCred> {
  const sandboxApiKey = await getCachedPlaygroundSandboxApiKey(env);
  if (!sandboxApiKey) {
    throw new Error(
      "SANDBOX_API_KEY binding missing; cannot mint server-side issuer cred",
    );
  }

  const upstreamBody = {
    api_key: sandboxApiKey,
    issuer_label: "Playground server demo",
  };
  const upstreamBodyJson = JSON.stringify(upstreamBody);
  const upstreamSignature = await hmacBodyHex(sandboxApiKey, upstreamBodyJson);

  const issuerApiBaseUrl =
    env.ISSUER_API_URL_SANDBOX ?? "https://sandbox-issuer.provii.app";
  const upstreamUrl = `${issuerApiBaseUrl}/v1/register-test-issuer`;

  const upstreamResp = await fetch(upstreamUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Sec-Fetch-Site": "same-origin",
      "Sec-Fetch-Mode": "cors",
      "Sec-Fetch-Dest": "empty",
      "X-Docs-Hmac": upstreamSignature,
    },
    body: upstreamBodyJson,
  });

  if (!upstreamResp.ok) {
    const errText = await upstreamResp.text();
    throw new Error(
      `register-test-issuer failed: ${upstreamResp.status} ${errText}`,
    );
  }

  const decoded: unknown = await upstreamResp.json();
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("register-test-issuer returned non-object JSON");
  }
  const upstreamResult = decoded as Record<string, unknown>;
  const kid = upstreamResult["kid"];
  const clientId = upstreamResult["client_id"];
  const hmacSecret = upstreamResult["hmac_secret"];
  const baseUrl = upstreamResult["base_url"];
  const expiresAt = upstreamResult["expires_at"];
  if (
    typeof kid !== "string" ||
    typeof clientId !== "string" ||
    typeof hmacSecret !== "string" ||
    typeof baseUrl !== "string" ||
    typeof expiresAt !== "number"
  ) {
    throw new Error(
      "register-test-issuer response missing required fields",
    );
  }

  const cred: ServerIssuerCred = {
    kid,
    clientId,
    hmacSecretB64u: hmacSecret,
    baseUrl,
    expiresAt,
  };

  await env.PLAYGROUND_SESSIONS.put(
    KV_KEY_PLAYGROUND_SERVER_ISSUER_CRED,
    JSON.stringify(cred),
    { expirationTtl: SERVER_ISSUER_CRED_TTL_SECONDS },
  );

  return cred;
}

async function getOrMintPlaygroundServerIssuerCred(
  env: Env,
): Promise<ServerIssuerCred> {
  const raw = await env.PLAYGROUND_SESSIONS.get(
    KV_KEY_PLAYGROUND_SERVER_ISSUER_CRED,
  );
  if (raw) {
    try {
      const parsed = JSON.parse(raw) as Partial<ServerIssuerCred>;
      const now = Math.floor(Date.now() / 1000);
      if (
        typeof parsed.kid === "string" &&
        typeof parsed.clientId === "string" &&
        typeof parsed.hmacSecretB64u === "string" &&
        typeof parsed.baseUrl === "string" &&
        typeof parsed.expiresAt === "number" &&
        parsed.expiresAt - now > SERVER_ISSUER_CRED_REFRESH_MARGIN_SECONDS
      ) {
        return parsed as ServerIssuerCred;
      }
    } catch {
 // Fall through to mint a fresh cred.
    }
  }
  return mintPlaygroundServerIssuerCred(env);
}

/**
 * Request a signed attestation from provii-issuer. The marketing-demo Worker
 * acts as an Issuing Party: it authenticates to /v1/attestation/create with
 * HMAC-SHA256, the Issuer signs the Ed25519 attestation server-side with
 * its own keys, and returns the base64url envelope. The wallet later
 * verifies the signature against the Issuer's standard JWKS published at
 * /.well-known/jwks.json.
 */
async function createSignedAttestation(
  env: Env,
  dobDays: number,
): Promise<{ attestation: string; expiresAt: number }> {
  const cred = await getOrMintPlaygroundServerIssuerCred(env);

  const timestamp = Math.floor(Date.now() / 1000);
 // 64-char hex nonce per Authorizer.nonce contract (provii-issuer types.rs).
  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  const nonce = Array.from(nonceBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

 // Canonical JSON ordering is fixed by provii-issuer session.rs:923. The
 // canonical authorizer subset is {format, key_id, timestamp} only. The
 // wire body's hmac and nonce are excluded from the signed payload.
 // Field name is `key_id` (snake_case) in canonical, `keyId` in wire.
  const canonicalJson = `{"dob_days":${dobDays},"authorizer":{"format":"client","key_id":${JSON.stringify(cred.clientId)},"timestamp":${timestamp}}}`;
  const hmac = await computeHmacSignature(
    cred.hmacSecretB64u,
    "POST",
    "/v1/attestation/create",
    canonicalJson,
    timestamp,
    nonce,
  );

  const requestBody = {
    dob_days: dobDays,
    authorizer: {
      format: "client",
      keyId: cred.clientId,
      timestamp,
      hmac,
      nonce,
    },
  };

  const upstreamUrl = `${cred.baseUrl}/v1/attestation/create`;
  const resp = await fetch(upstreamUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestBody),
  });
  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(
      `attestation/create failed: ${resp.status} ${errText}`,
    );
  }
  const json: unknown = await resp.json();
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    throw new Error("attestation/create returned non-object JSON");
  }
  const result = json as Record<string, unknown>;
  const attestation = result["attestation"];
  const expiresAt = result["expires_at"];
  if (typeof attestation !== "string" || typeof expiresAt !== "number") {
    throw new Error("attestation/create response missing required fields");
  }
  return { attestation, expiresAt };
}

/**
 * Render the HTML page for a demo subdomain. Server-side template rendering
 * with WCAG 2.2 compliance: landmarks, skip link, heading hierarchy, focus
 * indicators, touch targets, and text-based differentiation (not colour alone).
 */
function renderSubdomainPage(config: SubdomainConfig, nonce: string, publicKey: string): string {
  const escapedPolicyLabel = escapeHtml(config.policyLabel);
  const escapedAgeDisplay = escapeHtml(config.ageDisplay);
  const escapedPublicKey = escapeHtml(publicKey);

  const isOverAge = config.direction === "over_age";
  const directionLabel = isOverAge ? "Over-age" : "Under-age";
  const otherDemoUrl = isOverAge
    ? "https://under.provii.app"
    : "https://over.provii.app";
  const otherDemoLabel = isOverAge ? "Under 16" : "Over 18";
  const otherDirection = isOverAge ? "under-age" : "over-age";
  const heroSubtitle = isOverAge
    ? "This demo enforces a minimum age of 18. The site verifies you are 18 or older without ever learning your date of birth."
    : "This demo enforces a maximum age of 16. The site verifies you are under 16 without ever learning your date of birth.";

  return `<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0, user-scalable=yes, viewport-fit=cover">
    <meta name="theme-color" content="#DB2777" media="(prefers-color-scheme: light)">
    <meta name="theme-color" content="#0a0a0f" media="(prefers-color-scheme: dark)">
    <title>${escapedPolicyLabel} - Provii Demo</title>
    <meta name="description" content="Try Provii's ${escapedPolicyLabel.toLowerCase()} demo. Privacy preserving age verification using zero knowledge proofs.">
    <link rel="preload" href="/fonts/Manrope-Variable.woff2" as="font" type="font/woff2" crossorigin>
    <link rel="stylesheet" href="/demo.css">
</head>
<body class="demo-bg demo-page-enter">
    <a href="#main-content" class="demo-skip-link">Skip to main content</a>

    <header class="demo-header" role="banner">
      <nav class="demo-header__inner" aria-label="Site navigation">
        <a href="https://provii.app" class="demo-logo" aria-label="Provii Wallet home">
          <span class="demo-logo__text demo-gradient-text">Provii Wallet</span>
        </a>
        <div class="demo-header__links">
          <a href="${otherDemoUrl}" class="demo-header__link">${otherDemoLabel}</a>
          <a href="https://playground.provii.app" class="demo-header__link">Playground</a>
        </div>
      </nav>
    </header>

    <main id="main-content">
      <section class="demo-hero" aria-labelledby="hero-heading">
        <div class="demo-hero__badge">
          <span class="demo-badge">${directionLabel} Verification</span>
        </div>
        <h1 id="hero-heading" class="demo-hero__title">
          Prove you are <span class="demo-gradient-text">${escapedAgeDisplay}</span>
        </h1>
        <p class="demo-hero__subtitle">
          ${heroSubtitle}
        </p>
      </section>

      <section class="demo-widget-section" aria-labelledby="widget-heading">
        <h2 id="widget-heading" class="sr-only">Verification widget</h2>
        <div class="demo-widget-card demo-card">
          <div id="age-gate" role="region" aria-label="Age verification widget"></div>
        </div>
      </section>

      <section class="demo-steps" aria-labelledby="steps-heading">
        <h2 id="steps-heading" class="demo-section-title">
          How it <span class="demo-gradient-text">works</span>
        </h2>
        <div class="demo-steps__grid">
          <div class="demo-step-card demo-card demo-reveal">
            <div class="demo-step-card__number">01</div>
            <div class="demo-step-card__icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
            </div>
            <h3>Scan or tap</h3>
            <p>On mobile, tap the button to open Provii Wallet. On desktop, scan the QR code with your phone.</p>
          </div>
          <div class="demo-step-card demo-card demo-reveal">
            <div class="demo-step-card__number">02</div>
            <div class="demo-step-card__icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            <h3>Generate a proof</h3>
            <p>Your wallet creates a zero knowledge proof confirming you are ${escapedAgeDisplay}.</p>
          </div>
          <div class="demo-step-card demo-card demo-reveal">
            <div class="demo-step-card__number">03</div>
            <div class="demo-step-card__icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            </div>
            <h3>Access granted</h3>
            <p>The site learns only that you meet the age requirement. No personal data is ever shared.</p>
          </div>
          <div class="demo-step-card demo-card demo-reveal">
            <div class="demo-step-card__number">04</div>
            <div class="demo-step-card__icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            </div>
            <h3>Nothing stored</h3>
            <p>Proofs are one-time use and expire in minutes. No accounts, no cookies, no tracking.</p>
          </div>
        </div>
      </section>

      <section class="demo-crosslinks demo-reveal" aria-labelledby="crosslinks-heading">
        <h2 id="crosslinks-heading" class="sr-only">Try other demos</h2>
        <div class="demo-crosslinks__grid">
          <a href="${otherDemoUrl}" class="demo-crosslink-card demo-card demo-card--interactive">
            <div>
              <span class="demo-crosslink-card__label">${otherDemoLabel} Demo</span>
              <span class="demo-crosslink-card__desc">Try ${otherDirection} verification</span>
            </div>
            <svg class="demo-crosslink-card__arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="9 18 15 12 9 6"/></svg>
          </a>
          <a href="https://playground.provii.app" class="demo-crosslink-card demo-card demo-card--interactive">
            <div>
              <span class="demo-crosslink-card__label">Playground</span>
              <span class="demo-crosslink-card__desc">Create custom test environments</span>
            </div>
            <svg class="demo-crosslink-card__arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="9 18 15 12 9 6"/></svg>
          </a>
        </div>
      </section>
    </main>

    <footer class="demo-footer" role="contentinfo">
      <div class="demo-footer__brand">
        <span class="demo-gradient-text">Provii Wallet</span>
      </div>
      <p>Sandbox demonstration. No personal information is collected.</p>
      <div class="demo-footer__links">
        <a href="https://provii.app">provii.app</a>
        <a href="https://docs.provii.app">Documentation</a>
      </div>
    </footer>

    <script nonce="${nonce}">
    (function() {
      var els = document.querySelectorAll('.demo-reveal');
      if (!('IntersectionObserver' in window)) {
        for (var i = 0; i < els.length; i++) els[i].classList.add('demo-revealed');
        return;
      }
      var obs = new IntersectionObserver(function(entries) {
        for (var j = 0; j < entries.length; j++) {
          if (entries[j].isIntersecting) {
            entries[j].target.classList.add('demo-revealed');
            obs.unobserve(entries[j].target);
          }
        }
      }, { threshold: 0.15, rootMargin: '0px 0px -40px 0px' });
      for (var k = 0; k < els.length; k++) obs.observe(els[k]);
    })();
    </script>

    <script src="${SDK_URL}"
            integrity="${SDK_SRI_HASH}"
            crossorigin="anonymous"
            data-public-key="${escapedPublicKey}"
            data-environment="sandbox"
            async></script>
</body>
</html>`;
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);

 // Handle CORS preflight with security headers (CH-163, CH-164)
    if (request.method === "OPTIONS") {
      const origin = getAllowedOrigin(request);
      const headers: Record<string, string> = {
        ...BASE_SECURITY_HEADERS,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Max-Age": "86400",
        "Content-Security-Policy": API_CSP,
      };
      if (origin) {
        headers["Access-Control-Allow-Origin"] = origin;
      }
      return new Response(null, { headers });
    }

 // ========================================================================
 // W1: Subdomain routing, checked early, before API endpoints
 // ========================================================================
    const subdomain = extractSubdomain(request);
    if (subdomain !== null) {
 // ----------------------------------------------------------------------
 // docs gateway dispatcher ()
 //
 // The gateway only claims `docs.provii.app/api/*`. Everything else
 // on the docs host is served by the provii-docs Worker; everything that
 // is not the docs host has no business hitting `/api/*` here. Both
 // mismatches return 403 to make cross-surface reachability impossible
 // before any handler-specific code runs.
 // ----------------------------------------------------------------------
      if (subdomain === "docs") {
        if (!url.pathname.startsWith("/api/")) {
          return new Response("Forbidden", {
            status: 403,
            headers: {
              ...BASE_SECURITY_HEADERS,
              "Content-Type": "text/plain; charset=utf-8",
              "Content-Security-Policy": API_CSP,
            },
          });
        }
        return handleDocs(request, env, ctx);
      }

      if (url.pathname.startsWith("/api/")) {
        return new Response("Forbidden", {
          status: 403,
          headers: {
            ...BASE_SECURITY_HEADERS,
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Security-Policy": API_CSP,
          },
        });
      }

 // "playground" subdomain: rewrite root path to /playground so the
 // playground page serves at playground.provii.app/ directly.
 // API routes (playground/api/*) work as-is since they match by pathname.
      if (subdomain === "playground") {
        if (url.pathname === "/" || url.pathname === "/index.html") {
          url.pathname = "/playground";
        }
 // Fall through to the main handler with rewritten url
      } else {
        const subdomainConfig = SUBDOMAIN_CONFIGS[subdomain];

 // SECURITY: Unknown subdomains get a plain 404 with security headers.
 // No CORS headers are applied to prevent subdomain takeover abuse.
        if (!subdomainConfig) {
          return new Response("Not found", {
            status: 404,
            headers: {
              ...BASE_SECURITY_HEADERS,
              "Content-Type": "text/plain; charset=utf-8",
              "Content-Security-Policy": API_CSP,
            },
          });
        }

 // Only allow GET and HEAD for subdomain pages
      if (request.method !== "GET" && request.method !== "HEAD") {
        return new Response("Method not allowed", {
          status: 405,
          headers: {
            ...BASE_SECURITY_HEADERS,
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Security-Policy": API_CSP,
            Allow: "GET, HEAD",
          },
        });
      }

 // Non-root paths: attempt static asset serving from KV (CSS, JS, images)
      if (url.pathname !== "/" && url.pathname !== "/index.html") {
        try {
          const eventRequest =
            request.method === "HEAD"
              ? new Request(request.url, { method: "GET" })
              : request;

          const assetResponse = await getAssetFromKV(
            {
              request: eventRequest,
              waitUntil: ctx.waitUntil.bind(ctx),
            },
            {
              ASSET_NAMESPACE: env.__STATIC_CONTENT,
              ASSET_MANIFEST: assetManifest,
            },
          );

          const isHtml = url.pathname.endsWith(".html");
          const secured = await addSecurityHeaders(assetResponse, isHtml);

          if (request.method === "HEAD") {
            return new Response(null, {
              status: secured.status,
              statusText: secured.statusText,
              headers: secured.headers,
            });
          }

          return secured;
        } catch {
          return new Response("Not found", {
            status: 404,
            headers: {
              ...BASE_SECURITY_HEADERS,
              "Content-Type": "text/plain; charset=utf-8",
              "Content-Security-Policy": API_CSP,
            },
          });
        }
      }

 // Root path: render the subdomain-specific verification page. The hosted
 // public key is the cron-refreshed shared key from KV (read-only here).
      const nonce = generateNonce();
      const publicKey = await getSubdomainPublicKey(env, subdomain, subdomainConfig);
      const html = renderSubdomainPage(subdomainConfig, nonce, publicKey ?? "");

      const subdomainCsp = `default-src 'none'; script-src 'nonce-${nonce}' https://cdn.provii.app; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self' https://*.provii.app wss://*.provii.app; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests`;

      const htmlHeaders: Record<string, string> = {
        ...BASE_SECURITY_HEADERS,
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": subdomainCsp,
        "Cache-Control": "no-cache, no-store, must-revalidate",
        Pragma: "no-cache",
        Expires: "0",
      };

      if (request.method === "HEAD") {
        return new Response(null, { status: 200, headers: htmlHeaders });
      }

      return new Response(html, { status: 200, headers: htmlHeaders });
      } // end else (non-playground subdomain)
    }

 // Wave D removed the two static-cred GET endpoints under /v1/config that
 // handed out a single shared sandbox cred bundle to anyone on the
 // internet. Integrators now mint their own via
 // `/playground/api/create-environment` (verifier) and
 // `/playground/api/create-issuer-environment` (issuer). The Worker no
 // longer exposes any static-cred surface.

 // Demo token endpoint for demo app authentication
 // GET /v1/config/demo-token
 // Returns a daily rotating token that demo apps use to authenticate with demo backends
    if (url.pathname === "/v1/config/demo-token" && request.method === "GET") {
      const secret = await getCachedPlaygroundDemoTokenSecret(env);
      if (!secret) {
        return jsonResponse(
          { error: "Demo service not configured" },
          503,
          request,
        );
      }
      const { token, expiresAt } = await generateDemoToken(secret);

      return jsonResponse(
        {
          token,
          expires_at: expiresAt,
          cache_seconds: 86400,
        },
        200,
        request,
        { "Cache-Control": "public, max-age=3600" },
      );
    }

 // Sandbox attestation endpoint for provii-mobile testers
 // POST /v1/attestation/sandbox with { dob_days: number }
 // Returns { deep_link: "https://provii.app/attest?d=...", attestation: "...", expires_at: number }
    if (
      url.pathname === "/v1/attestation/sandbox" &&
      request.method === "POST"
    ) {
      try {
        let body: { dob_days?: number };
        try {
          body = (await request.json()) as { dob_days?: number };
        } catch {
          return jsonResponse(
            { error: "Invalid JSON in request body" },
            400,
            request,
          );
        }
        const dobDays = body.dob_days;

        if (!dobDays || dobDays < 1 || dobDays > 36500) {
          return jsonResponse(
            { error: "Invalid dob_days: must be between 1 and 36500" },
            400,
            request,
          );
        }

        const { attestation, expiresAt } =
          await createSignedAttestation(env, dobDays);

 // Generate deep link (attestation is already base64url encoded)
        const deepLink = `https://provii.app/attest?d=${attestation}`;

        return jsonResponse(
          {
            deep_link: deepLink,
            attestation: attestation,
            expires_at: expiresAt,
          },
          200,
          request,
          { "Cache-Control": "no-store" },
        );
      } catch (error) {
        const detail =
          error instanceof Error ? error.message : "Unknown error";
        console.error("[attestation-sandbox-post]", detail);
        return jsonResponse({ error: "Internal error" }, 500, request);
      }
    }

 // GET endpoint for convenience (e.g., QR code generation)
    if (
      url.pathname === "/v1/attestation/sandbox" &&
      request.method === "GET"
    ) {
      try {
        const dobDaysParam = url.searchParams.get("dob_days");
        const dobDays = dobDaysParam ? parseInt(dobDaysParam, 10) : undefined;

        if (!dobDays || dobDays < 1 || dobDays > 36500) {
          return jsonResponse(
            {
              error:
                "Invalid dob_days query parameter: must be between 1 and 36500",
            },
            400,
            request,
          );
        }

        const { attestation, expiresAt } =
          await createSignedAttestation(env, dobDays);

 // Generate deep link (attestation is already base64url encoded)
        const deepLink = `https://provii.app/attest?d=${attestation}`;

        return jsonResponse(
          {
            deep_link: deepLink,
            attestation: attestation,
            expires_at: expiresAt,
          },
          200,
          request,
          { "Cache-Control": "no-store" },
        );
      } catch (error) {
        const detail =
          error instanceof Error ? error.message : "Unknown error";
        console.error("[attestation-sandbox-get]", detail);
        return jsonResponse({ error: "Internal error" }, 500, request);
      }
    }

 // ========================================================================
 // W4: Playground API endpoints
 // ========================================================================

 // POST /playground/api/create-environment
    if (
      url.pathname === "/playground/api/create-environment" &&
      request.method === "POST"
    ) {
      try {
 // Validate SANDBOX_API_KEY is configured (Secrets Store binding, cached)
        const sandboxApiKey = await getCachedPlaygroundSandboxApiKey(env);
        if (!sandboxApiKey) {
          return jsonResponse(
            { error: "Playground is not configured. SANDBOX_API_KEY is missing." },
            503,
            request,
          );
        }

 // Rate limit by IP (KV-based, survives Worker restarts)
        const clientIp =
          request.headers.get("CF-Connecting-IP") ?? "unknown";
        const rateLimitState = await getRateLimitState(env.PLAYGROUND_SESSIONS, clientIp, "create-env");
        if (rateLimitState.limited) {
          return jsonResponse(
            {
              error: "Rate limit exceeded. You can create up to 5 environments per hour.",
              resetsAt: rateLimitState.resetsAt,
            },
            429,
            request,
          );
        }

 // Parse and validate body
        let body: { age?: unknown; direction?: unknown };
        try {
          body = (await request.json()) as {
            age?: unknown;
            direction?: unknown;
          };
        } catch {
          return jsonResponse(
            { error: "Invalid JSON in request body" },
            400,
            request,
          );
        }

        const age =
          typeof body.age === "number"
            ? body.age
            : typeof body.age === "string"
              ? parseInt(body.age, 10)
              : NaN;
        if (!Number.isInteger(age) || age < 5 || age > 25) {
          return jsonResponse(
            { error: "age must be an integer between 5 and 25" },
            400,
            request,
          );
        }

        const direction = body.direction;
        if (direction !== "over" && direction !== "under") {
          return jsonResponse(
            { error: 'direction must be "over" or "under"' },
            400,
            request,
          );
        }

 // Opaque placeholder origin. Sandbox pk_test_* keys skip Origin
 // validation on the provii-verifier, so this value is never surfaced
 // to the integrator and never determines where the snippet runs.
 // It stays here only because register-test-origin still wants a
 // unique value to attach the ephemeral policy record to.
        const originSuffix = randomHex(8);
        const fullOrigin = `https://${originSuffix}.sandbox.provii.app`;

        const registerBody: Record<string, unknown> = {
          origin: fullOrigin,
          min_age_years: direction === "over" ? age : 1,
          api_key: sandboxApiKey,
          proof_direction: direction === "over" ? "over_age" : "under_age",
        };
        if (direction === "under") {
          registerBody.max_age_years = age;
        }

        const registerBodyJson = JSON.stringify(registerBody);
        const registerSignature = await hmacBodyHex(
          sandboxApiKey,
          registerBodyJson,
        );

 // Call sandbox provii-verifier to register the ephemeral origin.
 // register-test-origin expects Sec-Fetch headers plus the
 // X-Docs-Hmac tag (provii-verifier/src/security/docs_hmac.rs) which
 // proves the caller holds the shared SANDBOX_API_KEY.
        const registerResp = await fetch(
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
            body: registerBodyJson,
          },
        );

        if (!registerResp.ok) {
          const errText = await registerResp.text();
          return jsonResponse(
            {
              error: `Failed to create test environment: ${registerResp.status}`,
              detail: errText,
            },
            502,
            request,
          );
        }

        let registerResult: Record<string, unknown>;
        try {
          registerResult = (await registerResp.json()) as Record<
            string,
            unknown
          >;
        } catch {
          return jsonResponse(
            { error: "Invalid JSON from register-test-origin" },
            502,
            request,
          );
        }

 // Extract credentials from response
        const hmacSecret = registerResult.hmac_secret;
        const clientId = registerResult.client_id;
        const expiresAt = registerResult.expires_at;
 // public_key is returned when hosted key provisioning succeeds
        const publicKey: string | undefined =
          typeof registerResult.public_key === "string"
            ? registerResult.public_key
            : undefined;

        if (
          typeof hmacSecret !== "string" ||
          typeof clientId !== "string"
        ) {
          return jsonResponse(
            { error: "Unexpected response from register-test-origin" },
            502,
            request,
          );
        }

 // Generate environment ID
        const environmentId = randomHex(16);

 // Store in KV with 72h TTL (matches the origin policy TTL)
        const session: PlaygroundSession = {
          origin: fullOrigin,
          hmacSecret,
          clientId,
          publicKey,
          age,
          direction,
          createdAt: Math.floor(Date.now() / 1000),
        };

        await env.PLAYGROUND_SESSIONS.put(
          `playground:${environmentId}`,
          JSON.stringify(session),
          { expirationTtl: 259200 },
        );

 // Record rate limit hit only on success
        await recordRateLimitHit(env.PLAYGROUND_SESSIONS, clientIp, "create-env");

        if (!publicKey) {
          return jsonResponse(
            { error: "Sandbox public key missing from register-test-origin response" },
            502,
            request,
          );
        }

        const codeSnippets = buildCodeSnippets(
          clientId,
          hmacSecret,
          sandboxApiKey,
          publicKey,
        );

        return jsonResponse(
          {
            environmentId,
            age,
            direction,
            clientId,
            hmacSecret,
            apiKey: sandboxApiKey,
            publicKey,
            expiresAt,
            codeSnippets,
          },
          200,
          request,
          { "Cache-Control": "no-store" },
        );
      } catch (e) {
        const detail = e instanceof Error ? e.message : "Unknown error";
        console.error("[playground-create-environment]", detail);
        return jsonResponse({ error: "Internal error" }, 500, request);
      }
    }

 // ========================================================================
 // POST /playground/api/create-issuer-environment
 //
 // Mints a per-developer Issuing Party credential bundle (client_id +
 // hmac_secret + base_url) by calling provii-issuer's `register-test-issuer`.
 // The Issuing Party authenticates to /v1/attestation/create with the
 // HMAC secret; provii-issuer signs the Ed25519 attestation server-side using
 // its own keys. The Issuing Party never holds a signing key.
 //
 // Inbound auth: none. Public endpoint, IP rate-limited via the same KV
 // bucket pattern as `create-env` (separate `create-issuer-env` bucket so
 // the two limits don't share a counter).
 // ========================================================================
    if (
      url.pathname === "/playground/api/create-issuer-environment" &&
      request.method === "POST"
    ) {
      try {
 // SANDBOX_API_KEY doubles as the provii-issuer X-Docs-Hmac key (same
 // Secrets Store binding name on both sides). Fail fast if the
 // playground was deployed without it bound.
        const sandboxApiKey = await getCachedPlaygroundSandboxApiKey(env);
        if (!sandboxApiKey) {
          return jsonResponse(
            {
              error:
                "Playground is not configured. SANDBOX_API_KEY is missing.",
            },
            503,
            request,
          );
        }

        const clientIp =
          request.headers.get("CF-Connecting-IP") ?? "unknown";
        const rateLimitState = await getRateLimitState(
          env.PLAYGROUND_SESSIONS,
          clientIp,
          "create-issuer-env",
        );
        if (rateLimitState.limited) {
          return jsonResponse(
            {
              error:
                "Rate limit exceeded. You can create up to 5 issuer environments per hour.",
              resetsAt: rateLimitState.resetsAt,
            },
            429,
            request,
          );
        }

 // Body shape: { issuer_label?: string }. Empty body is fine; the
 // playground UI for Wave C may post no body at all when the dev
 // accepts the default label.
        let parsedBody: { issuer_label?: unknown } = {};
        const rawBodyText = await request.text();
        if (rawBodyText.length > 0) {
          try {
            const decoded: unknown = JSON.parse(rawBodyText);
            if (
              typeof decoded === "object" &&
              decoded !== null &&
              !Array.isArray(decoded)
            ) {
              parsedBody = decoded as { issuer_label?: unknown };
            } else {
              return jsonResponse(
                { error: "Request body must be a JSON object" },
                400,
                request,
              );
            }
          } catch {
            return jsonResponse(
              { error: "Invalid JSON in request body" },
              400,
              request,
            );
          }
        }

 // Validate issuer_label. Spec: 1-64 ASCII printable chars. Default
 // to a randomised "Sandbox issuer <hex>" value when the caller
 // omits the field.
        const ASCII_PRINTABLE = /^[\x20-\x7E]+$/;
        let issuerLabel: string;
        if (typeof parsedBody.issuer_label === "undefined") {
          issuerLabel = `Sandbox issuer ${randomHex(4)}`;
        } else if (typeof parsedBody.issuer_label === "string") {
          const trimmed = parsedBody.issuer_label.trim();
          if (
            trimmed.length < 1 ||
            trimmed.length > 64 ||
            !ASCII_PRINTABLE.test(trimmed)
          ) {
            return jsonResponse(
              {
                error:
                  "issuer_label must be 1-64 printable ASCII characters",
              },
              400,
              request,
            );
          }
          issuerLabel = trimmed;
        } else {
          return jsonResponse(
            { error: "issuer_label must be a string" },
            400,
            request,
          );
        }

 // Compose the upstream body. provii-issuer's `register-test-issuer`
 // mints client_id + hmac_secret. No Ed25519 key is involved on the
 // Issuing Party side: provii-issuer signs every attestation with its
 // own server-side key when /v1/attestation/create is called.
        const upstreamBody = {
          api_key: sandboxApiKey,
          issuer_label: issuerLabel,
        };
        const upstreamBodyJson = JSON.stringify(upstreamBody);
        const upstreamSignature = await hmacBodyHex(
          sandboxApiKey,
          upstreamBodyJson,
        );

        const issuerApiBaseUrl =
          env.ISSUER_API_URL_SANDBOX ??
          "https://sandbox-issuer.provii.app";
        const upstreamUrl = `${issuerApiBaseUrl}/v1/register-test-issuer`;

        const upstreamResp = await fetch(upstreamUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "X-Docs-Hmac": upstreamSignature,
          },
          body: upstreamBodyJson,
        });

        if (!upstreamResp.ok) {
 // Surface the upstream body so devs see provii-issuer's actual
 // 4xx detail (rate-limit, malformed payload, etc.) instead of
 // a generic 502.
          const upstreamErrorBodyText = await upstreamResp.text();
          let upstreamErrorBody: unknown = upstreamErrorBodyText;
          try {
            upstreamErrorBody = JSON.parse(upstreamErrorBodyText);
          } catch {
 // Fall through with the raw text.
          }
          return jsonResponse(
            {
              error: `Failed to create issuer environment: ${upstreamResp.status}`,
              upstream_error: upstreamErrorBody,
            },
            502,
            request,
          );
        }

        let upstreamResult: Record<string, unknown>;
        try {
          const decoded: unknown = await upstreamResp.json();
          if (
            typeof decoded !== "object" ||
            decoded === null ||
            Array.isArray(decoded)
          ) {
            return jsonResponse(
              { error: "Invalid JSON object from register-test-issuer" },
              502,
              request,
            );
          }
          upstreamResult = decoded as Record<string, unknown>;
        } catch {
          return jsonResponse(
            { error: "Invalid JSON from register-test-issuer" },
            502,
            request,
          );
        }

 // Field-level guard: refuse to surface an under-spec'd response.
 // Devs need every field below to actually sign attestations, so a
 // missing field is a 502 not a partial-success. The upstream
 // contract is locked in §4 Wave A.
        const clientId = upstreamResult["client_id"];
        const hmacSecret = upstreamResult["hmac_secret"];
        const kid = upstreamResult["kid"];
        const expiresAt = upstreamResult["expires_at"];
        if (
          typeof clientId !== "string" ||
          typeof hmacSecret !== "string" ||
          typeof kid !== "string" ||
          typeof expiresAt !== "number"
        ) {
          return jsonResponse(
            {
              error: "Unexpected response from register-test-issuer",
            },
            502,
            request,
          );
        }

        await recordRateLimitHit(
          env.PLAYGROUND_SESSIONS,
          clientIp,
          "create-issuer-env",
        );

 // Pass through the entire upstream payload (client_id, hmac_secret,
 // kid, base_url, expires_at, minted_at). The Wave C UI parks
 // `client_id` + `hmac_secret` + `kid` in localStorage.
        return jsonResponse(
          { ...upstreamResult },
          200,
          request,
          { "Cache-Control": "no-store" },
        );
      } catch (e) {
        const detail = e instanceof Error ? e.message : "Unknown error";
        console.error("[playground-create-issuer-environment]", detail);
        return jsonResponse({ error: "Internal error" }, 500, request);
      }
    }

 // Serve playground.html at /playground with playground-specific CSP
    if (
      (url.pathname === "/playground" ||
        url.pathname === "/playground/") &&
      (request.method === "GET" || request.method === "HEAD")
    ) {
      try {
 // Fetch playground.html from static assets
        const playgroundUrl = new URL(request.url);
        playgroundUrl.pathname = "/playground.html";
        const assetRequest = new Request(playgroundUrl.toString(), {
          method: "GET",
        });

        const assetResponse = await getAssetFromKV(
          {
            request: assetRequest,
            waitUntil: ctx.waitUntil.bind(ctx),
          },
          {
            ASSET_NAMESPACE: env.__STATIC_CONTENT,
            ASSET_MANIFEST: assetManifest,
          },
        );

 // Generate nonce and inject into inline scripts
        const nonce = generateNonce();
        let html = await assetResponse.text();
        html = addNoncesToScripts(html, nonce);

 // Playground-specific CSP: allows 'self' for playground.js and
 // qrcode.min.js loaded from the same origin
        const playgroundCsp = `default-src 'none'; script-src 'self' 'nonce-${nonce}' https://cdn.provii.app; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self' https://*.provii.app wss://*.provii.app; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests`;

        const headers: Record<string, string> = {
          ...BASE_SECURITY_HEADERS,
          "Content-Type": "text/html; charset=utf-8",
          "Content-Security-Policy": playgroundCsp,
          "Cache-Control": "no-cache, no-store, must-revalidate",
          Pragma: "no-cache",
          Expires: "0",
        };

        if (request.method === "HEAD") {
          return new Response(null, { status: 200, headers });
        }

        return new Response(html, { status: 200, headers });
      } catch {
        return new Response("Not found", {
          status: 404,
          headers: {
            ...BASE_SECURITY_HEADERS,
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Security-Policy": API_CSP,
          },
        });
      }
    }

    try {
 // Handle HEAD requests by converting to GET for asset fetching
      const eventRequest =
        request.method === "HEAD"
          ? new Request(request.url, { method: "GET" })
          : request;

      const response = await getAssetFromKV(
        {
          request: eventRequest,
          waitUntil: ctx.waitUntil.bind(ctx),
        },
        {
          ASSET_NAMESPACE: env.__STATIC_CONTENT,
          ASSET_MANIFEST: assetManifest,
        },
      );

      const isHtml = url.pathname === "/" || url.pathname.endsWith(".html");

 // For HEAD requests, return empty body with security headers
      if (request.method === "HEAD") {
        const secured = await addSecurityHeaders(response, isHtml);
        return new Response(null, {
          status: secured.status,
          statusText: secured.statusText,
          headers: secured.headers,
        });
      }

 // Add security headers to all static assets (CH-160, CH-161)
      const secured = await addSecurityHeaders(response, isHtml);

 // Disable caching for HTML files to ensure updates are seen immediately
      if (isHtml) {
        const newHeaders = new Headers(secured.headers);
        newHeaders.set("Cache-Control", "no-cache, no-store, must-revalidate");
        newHeaders.set("Pragma", "no-cache");
        newHeaders.set("Expires", "0");
        return new Response(secured.body, {
          status: secured.status,
          statusText: secured.statusText,
          headers: newHeaders,
        });
      }

      return secured;
    } catch (e) {
 // If asset not found, return 404
      return new Response("Not found", {
        status: 404,
        headers: {
          ...BASE_SECURITY_HEADERS,
          "Content-Type": "text/plain; charset=utf-8",
          "Content-Security-Policy": API_CSP,
        },
      });
    }
  },

  // Cron: refresh the shared hosted key for each demo subdomain so page loads
  // only ever READ it from KV and never provision per visitor.
  async scheduled(
    _event: ScheduledController,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<void> {
    ctx.waitUntil(refreshAllSubdomainKeys(env));
  },
};
