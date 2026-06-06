// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Provii Verifier Backend Demo for Cloudflare Workers.
 *
 * Reference implementation showing how third-party verifiers (social media apps,
 * age-gated websites, content platforms, dating services) integrate with
 * Provii's provii-verifier using direct HMAC authentication.
 *
 * Integration steps:
 *
 * 1. Copy the core functions marked with "=== COPY THIS ===" below
 * 2. Set secrets via wrangler: CLIENT_ID, API_KEY, HMAC_SECRET
 * 3. Create a KV namespace for session storage
 * 4. Create your /api/create-challenge endpoint
 * 5. Return the deep_link to your mobile app
 * 6. Store the code_verifier securely in KV (associated with challenge_id)
 * 7. When user completes verification, call /api/redeem with code_verifier
 *
 * See INTEGRATION.md for complete examples and framework-specific code.
 *
 * Verification flow:
 *
 * 1. Mobile app requests age verification from YOUR backend
 * 2. Your backend generates PKCE (code_verifier + code_challenge)
 * 3. Your backend authenticates to provii-verifier with HMAC
 * 4. Your backend stores code_verifier securely (in KV)
 * 5. Your backend returns deep_link to mobile app
 * 6. Mobile app opens Provii Wallet with deep link
 * 7. User verifies in wallet (ZK proof submitted to provii-verifier)
 * 8. Mobile app polls YOUR backend for status
 * 9. When verified, YOUR backend redeems with code_verifier
 *
 * SECURITY: Your backend never exposes HMAC_SECRET or code_verifier to clients.
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { bodyLimit } from 'hono/body-limit';

/** Cloudflare Workers environment bindings. */
interface Env {
  /** Secrets provisioned via `wrangler secret put`. */
  CLIENT_ID?: string;
  API_KEY?: string;
  HMAC_SECRET?: string;
  DEMO_TOKEN_SECRET?: { get(): Promise<string | null> };

  /** Environment variables declared in wrangler.toml. */
  ENVIRONMENT?: string;
  VERIFIER_API_URL?: string;
  ALLOWED_ORIGINS?: string;
  /** Origin sent on outbound requests to provii-verifier. */
  WORKER_ORIGIN?: string;

  /** KV namespace for session storage. */
  SESSIONS: KVNamespace;
}

/** Resolved configuration cached per request. */
interface Config {
  verifierApiUrl: string;
  clientId: string;
  apiKey: string;
  hmacSecret: string;
  allowedOrigins: string[];
  /** Origin sent on outbound requests to provii-verifier. */
  workerOrigin: string;
  isProduction: boolean;
}

/** Session data persisted in KV alongside the secret code_verifier. */
interface SessionData {
  codeVerifier: string;
  challengeId: string;
  expiresAt: number;
  createdAt: number;
  proofDirection: string;
}

/**
 * Parse the comma-separated ALLOWED_ORIGINS env var into an array.
 * Falls back to localhost origins for local development.
 */
function parseAllowedOrigins(env: Env): string[] {
  const envOrigins = env.ALLOWED_ORIGINS;
  if (envOrigins) {
    return envOrigins.split(',').map(o => o.trim()).filter(o => o.length > 0);
  }
  return ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:8787'];
}

// ============================================================================
// Secrets Store caching ()
// ============================================================================
let cachedDemoTokenSecret: string | null = null;
let demoTokenSecretCachedAt = 0;
const DEMO_SECRET_CACHE_TTL_MS = 300_000; // 5 minutes

async function getCachedDemoTokenSecret(env: Env): Promise<string> {
  const now = Date.now();
  if (cachedDemoTokenSecret === null || now - demoTokenSecretCachedAt > DEMO_SECRET_CACHE_TTL_MS) {
    cachedDemoTokenSecret = (await env.DEMO_TOKEN_SECRET?.get()) ?? null;
    demoTokenSecretCachedAt = now;
  }
  return cachedDemoTokenSecret ?? "";
}

function buildConfig(env: Env): Config {
  const clientId = env.CLIENT_ID || '';
  const apiKey = env.API_KEY || '';
  const hmacSecret = env.HMAC_SECRET || '';
  const verifierApiUrl = env.VERIFIER_API_URL || '';

  if (!clientId || !apiKey || !hmacSecret || !verifierApiUrl) {
    throw new Error(
      'missing required env bindings: set CLIENT_ID, API_KEY, HMAC_SECRET, and VERIFIER_API_URL via wrangler secrets. Mint sandbox credentials at https://admin.provii.app. See backends/verifier/cloudflare-workers/README.md.'
    );
  }

  const workerOrigin = env.WORKER_ORIGIN || 'https://playground.provii.app';

  return {
    verifierApiUrl,
    clientId,
    apiKey,
    hmacSecret,
    allowedOrigins: parseAllowedOrigins(env),
    workerOrigin,
    isProduction: env.ENVIRONMENT === 'production',
  };
}

// ============================================================================
// === COPY THIS: Core Cryptographic & API Functions ===
// ============================================================================

/** Decode a base64url string to a Uint8Array. */
function base64urlDecode(str: string): Uint8Array {
  try {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    throw new Error(`Invalid base64url string: contains invalid characters or malformed encoding`);
  }
}

/** Encode a Uint8Array to a base64url string without padding. */
function base64urlEncode(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Generate cryptographically secure random bytes via the Web Crypto API. */
function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Generate an RFC 7636 PKCE code_verifier.
 * 32 random bytes yield 43 base64url characters.
 */
function generateCodeVerifier(): string {
  return base64urlEncode(randomBytes(32));
}

/** Generate the S256 PKCE code_challenge by SHA-256 hashing the code_verifier. */
async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64urlEncode(new Uint8Array(hash));
}

/**
 * SECURITY: Create an HMAC-SHA256 signature (hex-encoded, lowercase).
 *
 * Canonical message format for provii-verifier:
 * `{timestamp}:POST:/v1/challenge:{json_payload_without_hmac}:{nonce}`
 */
async function createHmacSignature(message: string, secretBase64url: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = base64urlDecode(secretBase64url);

 // Web Crypto requires an owned ArrayBuffer, not a view into a shared one
  const keyBuffer = new ArrayBuffer(keyData.length);
  new Uint8Array(keyBuffer).set(keyData);

  const key = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  const bytes = new Uint8Array(signature);

  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Build a Provii Wallet deep link URL from the challenge response fields. */
function buildDeepLink(challenge: ChallengeResponse): string {
  const payload = {
    challenge_id: challenge.challenge_id,
    rp_challenge: challenge.rp_challenge,
    submit_secret: challenge.submit_secret,
    cutoff_days: challenge.cutoff_days,
    verifying_key_id: challenge.verifying_key_id,
    verify_url: challenge.verify_url,
    expires_at: challenge.expires_at,
    proof_direction: challenge.proof_direction,
  };

  const jsonStr = JSON.stringify(payload);
  const bytes = new TextEncoder().encode(jsonStr);
  return `https://provii.app/verify?d=${base64urlEncode(bytes)}`;
}

/** Validate that a string matches the UUID format. */
function isValidUUID(str: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(str);
}

// ============================================================================
// === END OF CORE FUNCTIONS ===
// ============================================================================

/** Challenge response received from provii-verifier. */
interface ChallengeResponse {
  challenge_id: string;
  rp_challenge: string;
  cutoff_days: number;
  verifying_key_id: number;
  submit_secret: string;
  expires_at: number;
  status_url: string;
  verify_url: string;
  proof_direction: string;
  /** Optional 6-digit numeric short code for manual entry. */
  short_code?: string;
  /** Optional formatted short code (e.g. "123-456"). */
  short_code_formatted?: string;
}

/** Status response received from provii-verifier. */
interface StatusResponse {
  state: string;
  status: string;
  verified: boolean;
  proof_verified: boolean;
}

/** Redemption response received from provii-verifier. */
interface RedeemResponse {
  result: string;
  verified: boolean;
}

/**
 * SECURITY: Create a verification challenge via provii-verifier with HMAC authentication.
 * The HMAC covers a canonical message to prevent request tampering.
 */
async function createChallengeWithApi(
  config: Config,
  codeChallenge: string,
  minimumAge: number,
  expiresIn: number = 300
): Promise<ChallengeResponse> {
  if (!config.hmacSecret) {
    throw new Error('HMAC_SECRET not configured');
  }
  if (!config.apiKey) {
    throw new Error('API_KEY not configured');
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  const nonce = [...nonceBytes].map(b => b.toString(16).padStart(2, '0')).join('');

 // SECURITY: Canonical payload for HMAC must match server's create_canonical_message_for_challenge.
 // The server uses serde_json::json!() with preserve_order enabled (via feature unification),
 // so keys follow INSERTION ORDER from the json!() macro in challenge.rs:265-270:
 // code_challenge, method, verifying_key_id, expires_in.
 // The nonce from the authorizer block is appended as the 5th field in the canonical message.
 // proof_direction is determined server-side from origin policy, not sent by client.
  const payloadForHmac = {
    code_challenge: codeChallenge,
    method: 'S256',
    verifying_key_id: null,
    expires_in: expiresIn,
  };

  const canonicalMessage = `${timestamp}:POST:/v1/challenge:${JSON.stringify(payloadForHmac)}:${nonce}`;
  const hmac = await createHmacSignature(canonicalMessage, config.hmacSecret);

 // Full payload includes the authorizer block with nonce for replay protection
  const fullPayload = {
    code_challenge: codeChallenge,
    method: 'S256',
    expires_in: expiresIn,
    authorizer: {
      keyId: config.clientId,
      timestamp: timestamp,
      nonce: nonce,
      hmac: hmac,
    },
  };

 // Origin header must match the registered origin policy in provii-verifier
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(`${config.verifierApiUrl}/v1/challenge`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': config.apiKey,
        'Origin': config.workerOrigin,
      },
      body: JSON.stringify(fullPayload),
      signal: controller.signal,
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Challenge creation failed: ${response.status} - ${error}`);
    }

    try {
      return await response.json() as ChallengeResponse;
    } catch {
      throw new Error('Invalid JSON response from provii-verifier during challenge creation');
    }
  } finally {
    clearTimeout(timeoutId);
  }
}

/** Poll challenge status from provii-verifier by challenge ID. */
async function pollChallengeStatus(config: Config, challengeId: string): Promise<StatusResponse> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(`${config.verifierApiUrl}/v1/challenge/${challengeId}`, {
      method: 'GET',
      headers: {
        'X-API-Key': config.apiKey,
        'Origin': config.workerOrigin,
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Status check failed: ${response.status} - ${error}`);
    }

    try {
      return await response.json() as StatusResponse;
    } catch {
      throw new Error('Invalid JSON response from provii-verifier during status check');
    }
  } finally {
    clearTimeout(timeoutId);
  }
}

/** Redeem a verified challenge by presenting the PKCE code_verifier to provii-verifier. */
async function redeemChallenge(config: Config, challengeId: string, codeVerifier: string): Promise<RedeemResponse> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(`${config.verifierApiUrl}/v1/challenge/${challengeId}/redeem`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': config.apiKey,
        'Origin': config.workerOrigin,
      },
      body: JSON.stringify({ code_verifier: codeVerifier }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Redeem failed: ${response.status} - ${error}`);
    }

    try {
      return await response.json() as RedeemResponse;
    } catch {
      throw new Error('Invalid JSON response from provii-verifier during redemption');
    }
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================================
// Demo Token Validation
// ============================================================================

/**
 * SECURITY: Validate X-Demo-Token header to prevent unauthorised access to demo backends.
 * Token format: `demo_token_v1_<YYYYMMDD>_<16-char-hmac>`.
 * Uses crypto.subtle.timingSafeEqual for constant-time comparison of the HMAC tag.
 */
async function validateDemoToken(token: string, secret: string): Promise<{ valid: boolean; error?: string }> {
  if (!secret) {
    return { valid: false, error: 'DEMO_TOKEN_SECRET is not configured' };
  }

  if (!token || !token.startsWith('demo_token_v1_')) {
    return { valid: false };
  }

  const parts = token.split('_');
  if (parts.length !== 5) {
    return { valid: false };
  }

  const dateStr = parts[3];
  const providedSig = parts[4];

 // Accept today or yesterday to handle timezone boundaries (48-hour window)
  const now = new Date();
  const today = now.toISOString().slice(0, 10).replace(/-/g, '');
  const yesterday = new Date(now.getTime() - 86400000).toISOString().slice(0, 10).replace(/-/g, '');

  if (dateStr !== today && dateStr !== yesterday) {
    return { valid: false };
  }

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(`provii-demos-v1:${dateStr}`));
  const sigHex = Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 16);

 // SECURITY: Constant-time comparison using crypto.subtle.timingSafeEqual (Workers platform)
  const encoder2 = new TextEncoder();
  const a = encoder2.encode(providedSig);
  const b = encoder2.encode(sigHex);
  if (a.byteLength !== b.byteLength) {
    return { valid: false };
  }
  const isValid = crypto.subtle.timingSafeEqual(a, b);
  return { valid: isValid };
}

// ============================================================================
// Hono App Setup
// ============================================================================

const app = new Hono<{ Bindings: Env }>();

// Security headers middleware applied to all responses
app.use('*', async (c, next) => {
  await next();

  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');

 // Demo HTML pages need a permissive CSP to load provii-agegate.
 // API endpoints use a strict CSP.
  const path = c.req.path;
  if (path === '/' || path.endsWith('.html')) {
    c.header('Content-Security-Policy',
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline' https://cdn.provii.app; " +
      "style-src 'self' 'unsafe-inline' https://cdn.provii.app; " +
      "connect-src 'self' https://*.provii.app wss://*.provii.app; " +
      "img-src 'self' data:; " +
      "frame-ancestors 'none'"
    );
  } else {
    c.header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests");
  }

  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.header('Permissions-Policy', 'accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), cross-origin-isolated=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), navigation-override=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()');
  c.header('Cross-Origin-Opener-Policy', 'same-origin');
  c.header('Cross-Origin-Embedder-Policy', 'require-corp');
  c.header('Cross-Origin-Resource-Policy', 'same-origin');
});

// CORS middleware with configurable origin allowlist
app.use('*', async (c, next) => {
  const config = buildConfig(c.env);

  return cors({
    origin: (origin) => {
      if (!origin) return null;
      if (config.allowedOrigins.includes(origin)) {
        return origin;
      }
      return null;
    },
    credentials: true,
    allowHeaders: ['Content-Type', 'Accept', 'X-Demo-Token'],
  })(c, next);
});

// M-47: Reject oversized request bodies before any further processing (64 KB)
app.use('/api/*', bodyLimit({ maxSize: 1024 * 64 }));

// Demo token validation middleware for Hardcore endpoints only.
// Expert proxy endpoints (/api/challenge, /api/poll, /api/redeem) are called
// by provii-agegate from the browser and authenticate via HMAC to provii-verifier.
const EXPERT_PATHS = ['/api/challenge', '/api/poll', '/api/redeem', '/api/session'];
app.use('/api/*', async (c, next) => {
  if (EXPERT_PATHS.includes(c.req.path)) {
    await next();
    return;
  }

  const secret = await getCachedDemoTokenSecret(c.env);
  const token = c.req.header('X-Demo-Token') || '';

  const result = await validateDemoToken(token, secret);
  if (!result.valid) {
    if (result.error) {
      return c.json({ error: 'Server configuration error' }, 500);
    }
    return c.json({
      error: 'Invalid or missing demo token',
      hint: 'Fetch token from https://playground.provii.app/v1/config/demo-token',
    }, 401);
  }

  await next();
});

// ============================================================================
// API Endpoints
// ============================================================================

/** Health check returning credential configuration status. */
app.get('/health', async (c) => {
  const config = buildConfig(c.env);
  return c.json({
    status: 'ok',
    configured: !!(config.hmacSecret && config.apiKey && config.clientId),
    runtime: 'cloudflare-workers',
  });
});

/** Configuration visibility endpoint for debugging. */
app.get('/api/config', async (c) => {
  const config = buildConfig(c.env);
  return c.json({
    verifier_api_url: config.verifierApiUrl,
    has_client_id: !!config.clientId,
    api_key_configured: !!config.apiKey,
    hmac_secret_configured: !!config.hmacSecret,
    runtime: 'cloudflare-workers',
  });
});

/**
 * Create a new age verification challenge.
 *
 * Accepts `minimum_age` (over_age) or `maximum_age` (under_age), but not both.
 * Generates a PKCE pair, authenticates to provii-verifier with HMAC, stores the
 * code_verifier in KV, and returns a deep link for the mobile app.
 */
app.post('/api/create-challenge', async (c) => {
  try {
    const config = buildConfig(c.env);

    let body: { minimum_age?: number; maximum_age?: number; expires_in?: number };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: 'Invalid JSON in request body' }, 400);
    }

    if (body.minimum_age != null && body.maximum_age != null) {
      return c.json({ error: 'Cannot specify both minimum_age and maximum_age' }, 400);
    }

    const isUnderAge = body.maximum_age != null;
    const age = isUnderAge ? (body.maximum_age ?? 18) : (body.minimum_age ?? 18);
    const expiresIn = body.expires_in ?? 300;

    if (typeof age !== 'number' || !Number.isFinite(age) || age < 13 || age > 120) {
      return c.json({ error: `Invalid ${isUnderAge ? 'maximum_age' : 'minimum_age'}: must be 13-120` }, 400);
    }

    if (typeof expiresIn !== 'number' || !Number.isFinite(expiresIn) || expiresIn < 60 || expiresIn > 300) {
      return c.json({ error: 'Invalid expires_in: must be 60-300 seconds' }, 400);
    }

    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);

 // proof_direction is determined server-side from origin policy
    const challenge = await createChallengeWithApi(config, codeChallenge, age, expiresIn);

 // SECURITY: code_verifier is secret and must never leave the backend
    const sessionData: SessionData = {
      codeVerifier,
      challengeId: challenge.challenge_id,
      expiresAt: challenge.expires_at,
      createdAt: Date.now(),
      proofDirection: challenge.proof_direction,
    };

    const ttlSeconds = Math.max(expiresIn + 60, 60);
    await c.env.SESSIONS.put(
      `session:${challenge.challenge_id}`,
      JSON.stringify(sessionData),
      { expirationTtl: ttlSeconds }
    );

    const deepLink = buildDeepLink(challenge);

    return c.json({
      session_id: challenge.challenge_id,
      deep_link: deepLink,
      expires_at: challenge.expires_at,
      status_url: `/api/status/${challenge.challenge_id}`,
      proof_direction: challenge.proof_direction,
    });
  } catch (error) {
    const errorId = crypto.randomUUID().slice(0, 8);
    console.error(`[${errorId}] Error creating challenge:`, error instanceof Error ? error.stack : error);
    return c.json({
      error: 'Failed to create challenge',
      code: 'CHALLENGE_FAILED',
      reference: errorId,
    }, 500);
  }
});

/**
 * Poll the current verification status for a session.
 *
 * Returns the state (pending, verified, expired) by forwarding the query
 * to provii-verifier.
 */
app.get('/api/status/:sessionId', async (c) => {
  try {
    const config = buildConfig(c.env);
    const sessionId = c.req.param('sessionId');

    if (!sessionId) {
      return c.json({ error: 'Missing session_id' }, 400);
    }

    if (!isValidUUID(sessionId)) {
      return c.json({ error: 'Invalid session_id format' }, 400);
    }

    const sessionJson = await c.env.SESSIONS.get(`session:${sessionId}`);
    if (!sessionJson) {
      return c.json({ error: 'Session not found' }, 404);
    }

    const status = await pollChallengeStatus(config, sessionId);

    return c.json({
      state: status.state,
      verified: status.verified,
      proof_verified: status.proof_verified,
    });
  } catch (error) {
    const errorId = crypto.randomUUID().slice(0, 8);
    console.error(`[${errorId}] Error checking status:`, error instanceof Error ? error.message : error);
    return c.json({
      error: 'Failed to check verification status',
      code: 'STATUS_CHECK_FAILED',
      reference: errorId,
    }, 500);
  }
});

/**
 * Redeem a verified challenge to complete the verification flow.
 *
 * SECURITY: Uses delete-before-use pattern to prevent TOCTOU race conditions.
 * The session is deleted BEFORE using the code_verifier so that only one
 * request can succeed even if multiple concurrent requests arrive. The
 * provii-verifier also enforces single redemption as defence-in-depth.
 */
app.post('/api/redeem/:sessionId', async (c) => {
  try {
    const config = buildConfig(c.env);
    const sessionId = c.req.param('sessionId');

    if (!sessionId) {
      return c.json({ error: 'Missing session_id' }, 400);
    }

    if (!isValidUUID(sessionId)) {
      return c.json({ error: 'Invalid session_id format' }, 400);
    }

    const sessionKey = `session:${sessionId}`;

 // SECURITY: Delete-before-use pattern prevents double-redemption.
 // Two concurrent requests could both read the session before either deletes it.
 // By deleting first, we "claim" the session atomically (KV best-effort).
 // Provii-verifier enforces single-use as defence-in-depth.
    const sessionJson = await c.env.SESSIONS.get(sessionKey);
    if (!sessionJson) {
      return c.json({ error: 'Session not found or already redeemed' }, 404);
    }

    await c.env.SESSIONS.delete(sessionKey);

    let session: SessionData;
    try {
      session = JSON.parse(sessionJson);
    } catch {
      return c.json({ error: 'Corrupted session data' }, 500);
    }

 // Session already deleted, so replay is impossible even if redemption fails
    const result = await redeemChallenge(config, sessionId, session.codeVerifier);

    return c.json({
      result: result.result,
      verified: result.verified,
    });
  } catch (error) {
    const errorId = crypto.randomUUID().slice(0, 8);
    console.error(`[${errorId}] Error redeeming challenge:`, error instanceof Error ? error.message : error);
    return c.json({
      error: 'Failed to redeem verification',
      code: 'REDEEM_FAILED',
      reference: errorId,
    }, 500);
  }
});

// ============================================================================
// Expert Mode Proxy Endpoints (provii-agegate rp-proxy mode)
//
// These endpoints accept requests from provii-agegate and proxy them to
// provii-verifier with HMAC authentication. provii-agegate manages PKCE and
// the frontend UX. The developer only needs to run this backend.
// ============================================================================

/**
 * Expert mode: Create challenge (proxy for provii-agegate).
 *
 * provii-agegate sends { code_challenge, method, verifying_key_id, expires_in }
 * and this endpoint adds HMAC auth and forwards to provii-verifier.
 */
app.post('/api/challenge', async (c) => {
  try {
    const config = buildConfig(c.env);

    let body: {
      code_challenge?: string;
      method?: string;
      verifying_key_id?: number | null;
      expires_in?: number;
    };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: 'Invalid JSON in request body' }, 400);
    }

    const codeChallenge = body.code_challenge;
    if (!codeChallenge || typeof codeChallenge !== 'string') {
      return c.json({ error: 'code_challenge is required' }, 400);
    }

    const expiresIn = body.expires_in ?? 300;

 // Use the client-provided code_challenge (provii-agegate generated it)
    const challenge = await createChallengeWithApi(config, codeChallenge, 18, expiresIn);

 // Return the full challenge response (provii-agegate expects these fields)
    return c.json(challenge);
  } catch (error) {
    const errorId = crypto.randomUUID().slice(0, 8);
    console.error(`[${errorId}] Error creating challenge (expert):`, error);
    return c.json({
      error: 'Failed to create challenge',
      code: 'CHALLENGE_FAILED',
      reference: errorId,
    }, 500);
  }
});

/**
 * Expert mode: Poll status (proxy for provii-agegate).
 *
 * provii-agegate sends { challengeId } via POST in rp-proxy mode.
 */
app.post('/api/poll', async (c) => {
  try {
    const config = buildConfig(c.env);

    let body: { challengeId?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: 'Invalid JSON in request body' }, 400);
    }

    const challengeId = body.challengeId;
    if (!challengeId || typeof challengeId !== 'string') {
      return c.json({ error: 'challengeId is required' }, 400);
    }

    const status = await pollChallengeStatus(config, challengeId);
    return c.json(status);
  } catch (error) {
    const errorId = crypto.randomUUID().slice(0, 8);
    console.error(`[${errorId}] Error polling status (expert):`, error);
    return c.json({
      error: 'Failed to check status',
      code: 'STATUS_CHECK_FAILED',
      reference: errorId,
    }, 500);
  }
});

/**
 * Expert mode: Redeem challenge (proxy for provii-agegate).
 *
 * provii-agegate sends { challenge_id, code_verifier } in rp-proxy mode.
 * The code_verifier comes from provii-agegate (it generated the PKCE pair).
 */
app.post('/api/redeem', async (c) => {
  try {
    const config = buildConfig(c.env);

    let body: { challenge_id?: string; code_verifier?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: 'Invalid JSON in request body' }, 400);
    }

    const challengeId = body.challenge_id;
    const codeVerifier = body.code_verifier;

    if (!challengeId || typeof challengeId !== 'string') {
      return c.json({ error: 'challenge_id is required' }, 400);
    }
    if (!codeVerifier || typeof codeVerifier !== 'string') {
      return c.json({ error: 'code_verifier is required' }, 400);
    }

    const result = await redeemChallenge(config, challengeId, codeVerifier);

 // Set a session cookie so the frontend knows the user is verified on reload.
 // In production, use a signed/encrypted token with expiry.
    const sessionBytes = new Uint8Array(32);
    crypto.getRandomValues(sessionBytes);
    const sessionToken = Array.from(sessionBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    c.header('Set-Cookie',
      `verified_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`
    );
    return c.json(result);
  } catch (error) {
    const errorId = crypto.randomUUID().slice(0, 8);
    console.error(`[${errorId}] Error redeeming (expert):`, error);
    return c.json({
      error: 'Failed to redeem verification',
      code: 'REDEEM_FAILED',
      reference: errorId,
    }, 500);
  }
});

/**
 * Expert mode: Session check.
 *
 * Returns whether the user has a valid session cookie.
 * In Expert mode, the developer manages sessions, not provii-verifier.
 */
app.get('/api/session', (c) => {
  const cookie = c.req.header('Cookie') || '';
  const hasSession = cookie.includes('verified_session=');
  return c.json({ verified: hasSession });
});

// ============================================================================
// Static File Serving (inlined for Workers, which have no filesystem access)
// ============================================================================

/** Inlined Expert mode demo HTML page. */
const EXPERT_HTML = `<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Expert Mode Demo: provii-agegate + Your Backend</title>
    <style>
 * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; }
        .page { max-width: 640px; margin: 0 auto; padding: 40px 20px; }
        h1 { font-size: 24px; margin-bottom: 8px; }
        .subtitle { color: #64748b; margin-bottom: 32px; }
        .mode-badge { display: inline-block; background: #7c3aed; color: white; font-size: 12px; font-weight: 600; padding: 2px 8px; border-radius: 4px; margin-bottom: 16px; }
        .info { background: white; border: 1px solid #e2e8f0; border-radius: 12px; padding: 24px; margin-bottom: 24px; }
        .info h2 { font-size: 16px; margin-bottom: 8px; }
        .info p { color: #475569; font-size: 14px; line-height: 1.6; }
 #age-gate { min-height: 300px; }
 #main-content { display: none; background: white; border: 1px solid #e2e8f0; border-radius: 12px; padding: 40px; text-align: center; }
 #main-content h2 { color: #16a34a; margin-bottom: 12px; }
        .retry-btn { margin-top: 20px; padding: 10px 24px; background: #7c3aed; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; }
    </style>
</head>
<body>
    <div class="page">
        <div class="mode-badge">Expert Mode</div>
        <h1>Age Verification Demo</h1>
        <p class="subtitle">provii-agegate frontend + your own backend with HMAC auth</p>

        <div class="info">
            <h2>How this works</h2>
            <p>
                This page uses provii-agegate in <code>rp-proxy</code> mode. The SDK handles
                QR codes, deep links, short codes, and polling. Your backend (running on
                this server) handles HMAC authentication to provii-verifier. You wrote the
                backend; Provii provides the frontend SDK.
            </p>
        </div>

        <div id="age-gate"></div>

        <div id="main-content">
            <h2>Verified</h2>
            <p>Age verification complete. No personal data was shared.</p>
            <p style="color: #64748b; margin-top: 8px; font-size: 14px;">
                Your backend authenticated via HMAC-SHA256 and managed the PKCE flow
                through provii-agegate proxy endpoints.
            </p>
            <button class="retry-btn" onclick="location.reload()">Try Again</button>
        </div>
    </div>

    <script src="https://cdn.provii.app/sdk/provii-agegate/v0.1.3/agegate.browser.js"
            integrity="sha384-2YgklkdwmF3u5HNQBha6kV/fXphpO0quuQ2dR1jN+1SAolpkdGEFrql40VBv3Phq"
            crossorigin="anonymous"
            async
            id="agegate-script"></script>

    <script>
 // Check for existing session before initialising provii-agegate.
 // In Expert mode, YOUR backend manages sessions (not provii-verifier).
        async function checkSessionAndInit() {
            try {
                const res = await fetch('/api/session', { credentials: 'include' });
                const data = await res.json();
                if (data.verified) {
 // User already verified. Show content, skip age gate.
                    document.getElementById('age-gate').style.display = 'none';
                    document.getElementById('main-content').style.display = 'block';
                    return;
                }
            } catch (e) {
                console.debug('[Expert Demo] Session check failed, showing age gate:', e);
            }

 // No session. Wait for provii-agegate to load, then initialise.
            if (typeof AgeGate !== 'undefined') {
                initAgeGate();
            } else {
                const script = document.getElementById('agegate-script');
                if (script) {
                    script.addEventListener('load', initAgeGate);
                    script.addEventListener('error', () => {
                        document.getElementById('age-gate').textContent = 'Error: provii-agegate failed to load';
                    });
                }
            }
        }

        function initAgeGate() {
            if (typeof AgeGate === 'undefined') {
                document.getElementById('age-gate').textContent = 'Error: provii-agegate failed to load';
                return;
            }

            const gate = new AgeGate({
                mountElementId: 'age-gate',
 // After verification, provii-agegate redirects here. The page reloads,
 // session check finds the cookie, and shows verified content.
                contentUrl: window.location.href,
                environment: 'sandbox',

 // Expert mode: point provii-agegate at YOUR backend
                challengeUrl: '/api/challenge',
                pollUrl: '/api/poll',
                redeemUrl: '/api/redeem',
                redeemMode: 'rp-proxy',

 // Public key format is validated by provii-agegate but not used for auth in Expert mode.
 // Your backend authenticates via HMAC instead. Use your sandbox pk_ key here.
                publicKey: 'pk_test_07c3e7c6659c9c980a8db6c48a1367b929ec797bfcb79282626c9751c38eb3d9',
            });

            gate.subscribe((state, context) => {
                console.log('[Expert Demo] State:', state, context);
            });

            gate.init().catch((error) => {
                console.error('[Expert Demo] Init failed:', error);
                document.getElementById('age-gate').textContent = 'Error: ' + error.message;
            });
        }

        checkSessionAndInit();
    </script>
</body>
</html>`;

app.get('/', (c) => c.redirect('/expert.html'));
app.get('/expert.html', (c) => {
  return c.html(EXPERT_HTML);
});

export default app;
