// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Provii Issuer Backend Demo (Cloudflare Workers)
 *
 * Reference implementation showing how to integrate Provii credential issuance
 * into a Cloudflare Workers backend. The core HMAC functions between the
 * "COPY THIS" markers can be extracted into your own project.
 *
 * Required secrets (set via `wrangler secret put`):
 * CLIENT_ID, HMAC_SECRET, ISSUER_API_URL
 *
 * Issuance flow (HMAC-SHA256 authenticated):
 * 1. Mobile app sends customer's DOB as days since Unix epoch
 * 2. This backend authenticates with HMAC-SHA256, sends dob_days to Provii provii-issuer
 * 3. Provii provii-issuer creates and signs the attestation (Ed25519)
 * 4. This backend returns a deep link containing the signed attestation
 * 5. Mobile app opens Provii Wallet via the deep link
 * 6. Wallet sends the attestation to provii-issuer for credential issuance
 *
 * See INTEGRATION.md for framework-specific code samples.
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { bodyLimit } from 'hono/body-limit';

/** Cloudflare Workers environment bindings. */
interface Env {
  /** Issuer client identifier, set via `wrangler secret put`. */
  CLIENT_ID?: string;
  /** Base64url-encoded HMAC secret for provii-issuer authentication. */
  HMAC_SECRET?: string;
  /** Base URL of the Provii provii-issuer instance. */
  ISSUER_API_URL?: string;
  /** Secrets Store binding for the demo token validation secret. */
  DEMO_TOKEN_SECRET?: { get(): Promise<string | null> };

  /** Deployment environment name, set in wrangler.toml. */
  ENVIRONMENT?: string;
  /** Comma-separated list of allowed CORS origins, set in wrangler.toml. */
  ALLOWED_ORIGINS?: string;
}

/** Per-request configuration resolved from environment bindings. */
interface Config {
  clientId: string;
  hmacSecret: string;
  issuerApiUrl: string;
  allowedOrigins: string[];
  isProduction: boolean;
}

/**
 * Parse the ALLOWED_ORIGINS environment variable into an array.
 * Falls back to localhost origins when the variable is unset,
 * which is only appropriate for local development.
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
  const hmacSecret = env.HMAC_SECRET || '';
  const issuerApiUrl = env.ISSUER_API_URL || '';

  if (!clientId || !hmacSecret || !issuerApiUrl) {
    throw new Error(
      'missing required env bindings: set CLIENT_ID, HMAC_SECRET, and ISSUER_API_URL via wrangler secrets. Mint sandbox credentials at https://admin.provii.app. See backends/issuer/cloudflare-workers/README.md.'
    );
  }

  return {
    clientId,
    hmacSecret,
    issuerApiUrl,
    allowedOrigins: parseAllowedOrigins(env),
    isProduction: env.ENVIRONMENT === 'production',
  };
}

// ============================================================================
// === COPY THIS: Core HMAC Authentication Functions ===
// ============================================================================

/**
 * Decode a base64url-encoded string into a Uint8Array.
 * Handles the URL-safe alphabet and missing padding characters.
 */
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

/**
 * Compute an HMAC-SHA256 signature and return it as a lowercase hex string.
 * Uses the Web Crypto API (available in Cloudflare Workers).
 */
async function hmacSha256Hex(secret: Uint8Array, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(message)
  );
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Build the canonical message string for HMAC signing against /v1/attestation/create.
 *
 * Format: `{timestamp}:POST:/v1/attestation/create:{canonical_json}:{nonce}`
 *
 * The canonical JSON body uses snake_case field names (`key_id`), which differs
 * from the camelCase (`keyId`) used in the actual HTTP request body. The nonce
 * is appended after the JSON payload and MUST match the `authorizer.nonce`
 * field sent in the request body. See `create_canonical_message_for_attestation`
 * in `provii-issuer/src/session.rs` for the server-side reference.
 */
function buildCanonicalMessage(dobDays: number, clientId: string, timestamp: number, nonce: string): string {
  const canonicalJson = `{"dob_days":${dobDays},"authorizer":{"format":"client","key_id":"${clientId}","timestamp":${timestamp}}}`;
  return `${timestamp}:POST:/v1/attestation/create:${canonicalJson}:${nonce}`;
}

/**
 * Create a signed attestation via Provii's provii-issuer.
 *
 * SECURITY: Authenticates the request with HMAC-SHA256 over a canonical message.
 * Provii provii-issuer signs the attestation internally using Ed25519.
 *
 * @returns The base64url-encoded attestation, its expiry timestamp, and issuer identifier.
 */
async function createAttestation(config: Config, dobDays: number): Promise<{
  attestation: string;
  expiresAt: number;
  issuerId: string;
}> {
  if (!config.hmacSecret) {
    throw new Error('HMAC_SECRET not configured. Get this from the Provii admin portal.');
  }
  if (!config.issuerApiUrl) {
    throw new Error('ISSUER_API_URL not configured.');
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
 // SECURITY: 256-bit random nonce prevents replay attacks. The same nonce
 // value MUST appear in both the canonical HMAC message and the request body
 // Server verification fails otherwise (provii-issuer session.rs).
  const nonce = [...nonceBytes].map(b => b.toString(16).padStart(2, '0')).join('');

 // SECURITY: HMAC is computed over a canonical message to prevent tampering
  const canonicalMessage = buildCanonicalMessage(dobDays, config.clientId, timestamp, nonce);
  const secretBytes = base64urlDecode(config.hmacSecret);
  const hmac = await hmacSha256Hex(secretBytes, canonicalMessage);

  const url = `${config.issuerApiUrl}/v1/attestation/create`;
  const body = JSON.stringify({
    dob_days: dobDays,
    authorizer: {
      format: 'client',
      keyId: config.clientId,
      timestamp: timestamp,
      hmac: hmac,
      nonce: nonce,
    },
  });

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body,
    signal: controller.signal,
  });
  clearTimeout(timeoutId);

  if (!response.ok) {
    const errorText = await response.text().catch(() => 'unknown');
    throw new Error(`Issuer API returned ${response.status}: ${errorText}`);
  }

  let result: { attestation: string; expires_at: number; issuer_id: string };
  try {
    result = await response.json() as typeof result;
  } catch {
    throw new Error('Invalid JSON response from provii-issuer');
  }

  if (typeof result.attestation !== 'string' || !result.attestation) {
    throw new Error('Issuer API response missing attestation field');
  }

  return {
    attestation: result.attestation,
    expiresAt: result.expires_at,
    issuerId: result.issuer_id,
  };
}

// ============================================================================
// === END OF CORE FUNCTIONS ===
// ============================================================================

const app = new Hono<{ Bindings: Env }>();

/** Security headers middleware. Applied to every response. */
app.use('*', async (c, next) => {
  await next();

  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests");
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.header('Permissions-Policy', 'accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), cross-origin-isolated=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), navigation-override=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()');
  c.header('Cross-Origin-Opener-Policy', 'same-origin');
  c.header('Cross-Origin-Embedder-Policy', 'require-corp');
  c.header('Cross-Origin-Resource-Policy', 'same-origin');
});

/** CORS middleware with a configurable origin allowlist. */
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
    allowHeaders: ['Content-Type', 'X-Demo-Token'],
  })(c, next);
});

// ============================================================================
// Demo Token Validation
// Validates the X-Demo-Token header to prevent unauthorised access to demo
// backends. Token format: demo_token_v1_<YYYYMMDD>_<16-char-hmac>
// ============================================================================

/**
 * Validate a demo access token against the expected HMAC signature.
 *
 * SECURITY: Uses crypto.subtle.timingSafeEqual for constant-time comparison
 * of the provided signature against the expected value.
 *
 * Accepts tokens dated today or yesterday to account for timezone differences.
 */
async function validateDemoToken(token: string, secret: string): Promise<boolean> {
  if (!secret) {
    console.warn('DEMO_TOKEN_SECRET is not configured, rejecting all demo token requests');
    return false;
  }

  if (!token || !token.startsWith('demo_token_v1_')) {
    return false;
  }

 // Split: ['demo', 'token', 'v1', date, sig]
  const parts = token.split('_');
  if (parts.length !== 5) {
    return false;
  }

  const dateStr = parts[3];
  const providedSig = parts[4];

 // 48-hour acceptance window covers UTC day boundary edge cases
  const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10).replace(/-/g, '');

  if (dateStr !== today && dateStr !== yesterday) {
    return false;
  }

 // SECURITY: Compute expected HMAC-SHA256 signature
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(`provii-demos-v1:${dateStr}`)
  );

  const expectedSig = Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 16);

 // SECURITY: Constant-time comparison to prevent timing side-channel attacks
  const encoder2 = new TextEncoder();
  const a = encoder2.encode(providedSig);
  const b = encoder2.encode(expectedSig);
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  return crypto.subtle.timingSafeEqual(a, b);
}

/** Enforce demo token validation on all /api/* routes. */
app.use('/api/*', async (c, next) => {
  const token = c.req.header('X-Demo-Token') || '';
  const secret = await getCachedDemoTokenSecret(c.env);
  if (!secret) {
    return c.json({ error: 'Server configuration error' }, 500);
  }
  if (!await validateDemoToken(token, secret)) {
    return c.json({
      error: 'Invalid or missing demo token',
      hint: 'Fetch token from https://playground.provii.app/v1/config/demo-token'
    }, 401);
  }
  await next();
});

// M-47: Reject request bodies larger than 64 KB on API routes.
app.use('/api/*', bodyLimit({ maxSize: 1024 * 64 }));

/** Health check endpoint. Returns service status and runtime identifier. */
app.get('/health', (c) => c.json({ status: 'ok', mode: 'hmac-authenticated', runtime: 'cloudflare-workers' }));

/** Returns current configuration state for debugging. Does not expose secrets. */
app.get('/api/config', async (c) => {
  const config = buildConfig(c.env);

  return c.json({
    has_client_id: !!config.clientId,
    hmac_configured: !!config.hmacSecret,
    issuer_api_url: config.issuerApiUrl,
    mode: 'hmac-authenticated',
    runtime: 'cloudflare-workers',
  });
});

/**
 * Create a signed attestation from a DOB expressed as days since Unix epoch.
 *
 * Expects `{ "dob_days": 7000 }` in the request body.
 * Returns `{ "deep_link": "https://provii.app/attest?d=...", "expires_at": ... }`.
 */
app.post('/api/create-attestation', async (c) => {
  try {
    const config = buildConfig(c.env);

    let body: { dob_days?: number };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: 'Invalid JSON in request body' }, 400);
    }
    const dobDays = body.dob_days;

    if (typeof dobDays !== 'number' || !Number.isInteger(dobDays) || dobDays < -25000 || dobDays > 36500) {
      return c.json({ error: 'Invalid dob_days: must be an integer between -25000 and 36500' }, 400);
    }

    const result = await createAttestation(config, dobDays);

    const deepLink = `https://provii.app/attest?d=${result.attestation}`;

    return c.json({
      deep_link: deepLink,
      expires_at: result.expiresAt,
    });
  } catch (error) {
    const errorId = crypto.randomUUID().slice(0, 8);
    console.error(`[${errorId}] Error creating attestation:`, error instanceof Error ? error.stack : error);
    return c.json({
      error: 'Failed to create attestation',
      code: 'ATTESTATION_FAILED',
      reference: errorId
    }, 500);
  }
});

/**
 * Create a signed attestation from a date string in YYYY-MM-DD format.
 *
 * Expects `{ "dob": "1990-05-15" }` in the request body. Converts the date
 * to days since Unix epoch before forwarding to the provii-issuer.
 */
app.post('/api/create-attestation-from-dob', async (c) => {
  try {
    const config = buildConfig(c.env);

    let body: { dob?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: 'Invalid JSON in request body' }, 400);
    }
    const dob = body.dob;

    if (!dob || !/^\d{4}-\d{2}-\d{2}$/.test(dob)) {
      return c.json({ error: 'Invalid dob: must be in YYYY-MM-DD format' }, 400);
    }

    const dobParts = dob.split('-');
    const yearStr = dobParts[0];
    const monthStr = dobParts[1];
    const dayStr = dobParts[2];
    if (yearStr === undefined || monthStr === undefined || dayStr === undefined) {
      return c.json({ error: 'Invalid dob: must be in YYYY-MM-DD format' }, 400);
    }
    const inputYear = parseInt(yearStr, 10);
    const inputMonth = parseInt(monthStr, 10);
    const inputDay = parseInt(dayStr, 10);

    const dobDate = new Date(dob + 'T00:00:00Z');

 // Detect impossible dates (e.g. Feb 30) that JavaScript silently rolls over
    if (isNaN(dobDate.getTime()) ||
        dobDate.getUTCFullYear() !== inputYear ||
        dobDate.getUTCMonth() + 1 !== inputMonth ||
        dobDate.getUTCDate() !== inputDay) {
      return c.json({ error: 'Invalid date: the specified date does not exist' }, 400);
    }

    const dobDays = Math.floor(dobDate.getTime() / (24 * 60 * 60 * 1000));

    if (!Number.isInteger(dobDays) || dobDays < -25000 || dobDays > 36500) {
      return c.json({ error: 'Invalid date: must be between 1970 and 2070' }, 400);
    }

    const result = await createAttestation(config, dobDays);

    const deepLink = `https://provii.app/attest?d=${result.attestation}`;

    return c.json({
      deep_link: deepLink,
      dob_days: dobDays,
      expires_at: result.expiresAt,
    });
  } catch (error) {
    const errorId = crypto.randomUUID().slice(0, 8);
    console.error(`[${errorId}] Error creating attestation:`, error instanceof Error ? error.stack : error);
    return c.json({
      error: 'Failed to create attestation',
      code: 'ATTESTATION_FAILED',
      reference: errorId
    }, 500);
  }
});

export default app;
