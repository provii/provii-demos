// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Provii Issuer Backend Demo (Node.js)
 *
 * Reference implementation showing how to integrate Provii credential issuance
 * into a Node.js backend. The core HMAC functions between the "COPY THIS"
 * markers can be extracted into your own project.
 *
 * Required environment variables:
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
import { serve } from '@hono/node-server';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/** Application configuration, populated from environment variables or the demo API. */
interface Config {
  clientId: string;
  hmacSecret: string;
  issuerApiUrl: string;
  port: number;
  allowedOrigins: string[];
  isProduction: boolean;
}

/**
 * Parse the ALLOWED_ORIGINS environment variable into an array.
 * Falls back to localhost origins when the variable is unset.
 * Production deployments should set ALLOWED_ORIGINS to HTTPS origins.
 */
function parseAllowedOrigins(): string[] {
  const envOrigins = process.env.ALLOWED_ORIGINS;
  if (envOrigins) {
    return envOrigins.split(',').map(o => o.trim()).filter(o => o.length > 0);
  }
  return ['http://localhost:3000', 'http://localhost:5173'];
}

function loadConfig(): Config {
  const clientId = process.env.CLIENT_ID;
  const hmacSecret = process.env.HMAC_SECRET;
  const issuerApiUrl = process.env.ISSUER_API_URL;

  if (!clientId || !hmacSecret || !issuerApiUrl) {
    console.error('FATAL: missing required environment variables.');
    console.error('Set CLIENT_ID, HMAC_SECRET, and ISSUER_API_URL before starting.');
    console.error('Mint sandbox credentials at https://admin.provii.app');
    console.error('See backends/issuer/nodejs/README.md for the setup walkthrough.');
    process.exit(1);
  }

  return {
    clientId,
    hmacSecret,
    issuerApiUrl,
    port: parseInt(process.env.PORT || '3000', 10),
    allowedOrigins: parseAllowedOrigins(),
    isProduction: process.env.NODE_ENV === 'production',
  };
}

const config: Config = loadConfig();

const app = new Hono();

/** Security headers middleware. HSTS is only applied in production. */
app.use('*', async (c, next) => {
  await next();
  if (config.isProduction) {
    c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
});

/**
 * CORS middleware with a configurable origin allowlist.
 * This is a demo application. Production deployments should add rate limiting
 * (e.g. hono-rate-limiter or an API gateway) to prevent abuse.
 */
app.use('*', cors({
  origin: (origin) => {
    if (!origin) return null;
    if (config.allowedOrigins.includes(origin)) {
      return origin;
    }
    return null;
  },
  credentials: true,
  allowHeaders: ['Content-Type', 'X-Demo-Token'],
}));

// ============================================================================
// Demo Token Validation
//
// The X-Demo-Token header guards the publicly-deployed CF Worker
// (issuer-demo.provii.app) against unauthorised use of shared sandbox
// credentials. The signing secret lives in Cloudflare's Secrets Store and is
// only available to the deployed Worker.
//
// For a local Node backend on localhost, the dev controls both sides of the
// request, so there is no security boundary to enforce. When DEMO_TOKEN_SECRET
// is unset (the default for `npm run dev`), token validation is skipped.
// Setting DEMO_TOKEN_SECRET re-enables validation, which is what the production
// CF Worker code path does via its Secrets Store binding.
// Token format: demo_token_v1_<YYYYMMDD>_<16-char-hmac>
// ============================================================================
const DEMO_TOKEN_SECRET = process.env.DEMO_TOKEN_SECRET || '';
const DEMO_TOKEN_VALIDATION_ENABLED = DEMO_TOKEN_SECRET.length > 0;

/**
 * Validate a demo access token against the expected HMAC signature.
 *
 * SECURITY: Uses Node.js crypto.timingSafeEqual for constant-time comparison
 * of the provided signature against the expected value.
 *
 * Caller MUST gate this on DEMO_TOKEN_VALIDATION_ENABLED. The function assumes
 * DEMO_TOKEN_SECRET is set.
 */
async function validateDemoToken(token: string): Promise<{ valid: boolean }> {
  if (!token || !token.startsWith('demo_token_v1_')) {
    return { valid: false };
  }

 // Split: ['demo', 'token', 'v1', date, sig]
  const parts = token.split('_');
  if (parts.length !== 5) {
    return { valid: false };
  }

  const dateStr = parts[3] ?? '';
  const providedSig = parts[4] ?? '';
  if (!dateStr || !providedSig) {
    return { valid: false };
  }

 // 48-hour acceptance window covers UTC day boundary edge cases
  const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10).replace(/-/g, '');

  if (dateStr !== today && dateStr !== yesterday) {
    return { valid: false };
  }

 // SECURITY: Compute expected HMAC-SHA256 signature.
 // Caller already verified DEMO_TOKEN_VALIDATION_ENABLED before invoking this function.
  const expectedSig = createHmac('sha256', DEMO_TOKEN_SECRET)
    .update(`provii-demos-v1:${dateStr}`)
    .digest('hex')
    .slice(0, 16);

 // SECURITY: Constant-time comparison to prevent timing side-channel attacks
  if (providedSig.length !== expectedSig.length) {
    return { valid: false };
  }
  const providedBuf = Buffer.from(providedSig, 'utf-8');
  const expectedBuf = Buffer.from(expectedSig, 'utf-8');
  const isValid = timingSafeEqual(providedBuf, expectedBuf);
  return { valid: isValid };
}

// M-47: Reject oversized request bodies before any further processing (64 KB)
app.use('/api/*', bodyLimit({ maxSize: 1024 * 64 }));

/**
 * Enforce demo token validation on all /api/* routes.
 *
 * When DEMO_TOKEN_SECRET is unset (local dev), this middleware is a pass-through.
 * Production CF Worker deployments have the secret bound via the Secrets Store.
 */
app.use('/api/*', async (c, next) => {
  if (!DEMO_TOKEN_VALIDATION_ENABLED) {
    await next();
    return;
  }
  const token = c.req.header('X-Demo-Token') || '';
  const result = await validateDemoToken(token);
  if (!result.valid) {
    return c.json({
      error: 'Invalid or missing demo token',
      hint: 'Fetch token from https://playground.provii.app/v1/config/demo-token'
    }, 401);
  }
  await next();
});

// ============================================================================
// === COPY THIS: Core HMAC Authentication Functions ===
// ============================================================================

/**
 * Decode a base64url-encoded string into a Buffer.
 * Handles the URL-safe alphabet and missing padding characters.
 */
function base64urlDecode(str: string): Buffer {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  return Buffer.from(padded, 'base64');
}

/**
 * Compute an HMAC-SHA256 signature and return it as a lowercase hex string.
 * Uses the Node.js crypto module.
 */
function hmacSha256Hex(secret: Buffer, message: string): string {
  return createHmac('sha256', secret).update(message).digest('hex');
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
async function createAttestation(dobDays: number): Promise<{
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
 // SECURITY: 256-bit random nonce prevents replay attacks. The same nonce
 // value MUST appear in both the canonical HMAC message and the request body
 // Server verification fails otherwise (provii-issuer session.rs).
  const nonce = randomBytes(32).toString('hex');

 // SECURITY: HMAC is computed over a canonical message to prevent tampering
  const canonicalMessage = buildCanonicalMessage(dobDays, config.clientId, timestamp, nonce);
  const secretBytes = base64urlDecode(config.hmacSecret);
  const hmac = hmacSha256Hex(secretBytes, canonicalMessage);

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

/** Health check endpoint. Returns service status. */
app.get('/health', (c) => c.json({ status: 'ok', mode: 'hmac-authenticated' }));

/** Returns current configuration state for debugging. Does not expose secrets. */
app.get('/api/config', (c) => {
  return c.json({
    has_client_id: !!config.clientId,
    hmac_configured: !!config.hmacSecret,
    issuer_api_url: config.issuerApiUrl,
    mode: 'hmac-authenticated',
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

    const result = await createAttestation(dobDays);

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

    const result = await createAttestation(dobDays);

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

/** Start the HTTP server. */
async function main() {
  console.log('');
  console.log('=== Provii Issuer Demo Backend ===');
  console.log(`Mode: HMAC-SHA256 Authenticated (Provii Signs Attestation)`);
  console.log(`Port: ${config.port}`);
  console.log(`Client ID: ${config.clientId}`);
  console.log(`HMAC Secret Configured: ${!!config.hmacSecret}`);
  console.log(`Issuer API URL: ${config.issuerApiUrl}`);
  if (DEMO_TOKEN_VALIDATION_ENABLED) {
    console.log('Demo token validation: ENABLED (DEMO_TOKEN_SECRET is set)');
  } else {
    console.log('Demo token validation: DISABLED (local dev mode, DEMO_TOKEN_SECRET unset).');
    console.log('  Bind DEMO_TOKEN_SECRET via wrangler secrets / env injection for production.');
  }
  console.log('');
  console.log('Test with:');
  console.log(`  curl -X POST http://localhost:${config.port}/api/create-attestation \\`);
  console.log(`    -H "Content-Type: application/json" \\`);
  console.log(`    -d '{"dob_days": 7000}'`);
  console.log('');
  console.log('Or with a date:');
  console.log(`  curl -X POST http://localhost:${config.port}/api/create-attestation-from-dob \\`);
  console.log(`    -H "Content-Type: application/json" \\`);
  console.log(`    -d '{"dob": "1990-05-15"}'`);
  console.log('');

  if (!config.hmacSecret) {
    console.log('WARNING: HMAC_SECRET not set!');
    console.log('Set it via environment variable or the request will fail.');
    console.log('Get credentials from the Provii admin portal.');
    console.log('');
  }

  serve({ fetch: app.fetch, port: config.port });
}

main().catch(console.error);
