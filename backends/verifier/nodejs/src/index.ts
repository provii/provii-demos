// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Provii Verifier Backend Demo for Node.js.
 *
 * Reference implementation showing how third-party verifiers (social media apps,
 * age-gated websites, content platforms, dating services) integrate with
 * Provii's provii-verifier using direct HMAC authentication.
 *
 * Integration steps:
 *
 * 1. Copy the core functions marked with "=== COPY THIS ===" below
 * 2. Set environment variables: CLIENT_ID, HMAC_SECRET, API_KEY
 * 3. Create your /api/create-challenge endpoint
 * 4. Return the deep_link to your mobile app
 * 5. Store the code_verifier securely (associated with session_id)
 * 6. When user completes verification, call /api/redeem with code_verifier
 *
 * See INTEGRATION.md for complete examples and framework-specific code.
 *
 * Verification flow:
 *
 * 1. Mobile app requests age verification from YOUR backend
 * 2. Your backend generates PKCE (code_verifier + code_challenge)
 * 3. Your backend authenticates to provii-verifier with HMAC
 * 4. Your backend stores code_verifier securely (in session/DB)
 * 5. Your backend returns deep_link to mobile app
 * 6. Mobile app opens Provii Wallet with deep link
 * 7. User verifies in wallet (ZK proof submitted to provii-verifier)
 * 8. Mobile app polls YOUR backend for status
 * 9. When verified, YOUR backend redeems with code_verifier
 *
 * SECURITY: Your backend never exposes HMAC_SECRET or code_verifier to clients.
 */

import 'dotenv/config'; // loads .env at startup if present

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { bodyLimit } from 'hono/body-limit';
import { serve } from '@hono/node-server';
import { randomBytes as nodeRandomBytes, timingSafeEqual } from 'node:crypto';
import nodePath from 'node:path';

// ============================================================================
// Configuration
// ============================================================================

/** Resolved server configuration built from environment variables. */
interface Config {
  verifierApiUrl: string;
  clientId: string;
  apiKey: string;
  hmacSecret: string;
  registeredOrigin: string;
  port: number;
  allowedOrigins: string[];
  isProduction: boolean;
}

/**
 * Parse the comma-separated ALLOWED_ORIGINS env var into an array.
 * Falls back to localhost origins for local development.
 */
function parseAllowedOrigins(): string[] {
  const envOrigins = process.env.ALLOWED_ORIGINS;
  if (envOrigins) {
    return envOrigins.split(',').map(o => o.trim()).filter(o => o.length > 0);
  }
  return ['http://localhost:3000', 'http://localhost:5173'];
}

let config: Config = {
  verifierApiUrl: process.env.VERIFIER_API_URL || 'https://sandbox-verify.provii.app',
  clientId: process.env.CLIENT_ID || '',
  apiKey: process.env.API_KEY || '',
  hmacSecret: process.env.HMAC_SECRET || '',
  registeredOrigin: process.env.REGISTERED_ORIGIN || 'https://playground.provii.app',
  port: parseInt(process.env.PORT || '3001', 10),
  allowedOrigins: parseAllowedOrigins(),
  isProduction: process.env.NODE_ENV === 'production',
};

// In-memory session store. Replace with Redis or a database in production.
const sessions = new Map<string, SessionData>();

/** Session data stored alongside the secret code_verifier. */
interface SessionData {
  codeVerifier: string;
  challengeId: string;
  expiresAt: number;
  createdAt: number;
  proofDirection: string;
}

// ============================================================================
// Hono App Setup
// ============================================================================

const app = new Hono();

// Security headers middleware
app.use('*', async (c, next) => {
  await next();
  if (config.isProduction) {
    c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');

 // Demo HTML pages need a permissive CSP to load provii-agegate from CDN.
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
    c.header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
  }
});

// CORS middleware with configurable origin allowlist
app.use('*', cors({
  origin: (origin) => {
    if (!origin) return null;
    if (config.allowedOrigins.includes(origin)) return origin;
    return null;
  },
  credentials: true,
  allowHeaders: ['Content-Type', 'X-Demo-Token'],
}));

// ============================================================================
// Demo Token Validation
//
// The X-Demo-Token header guards the publicly-deployed CF Worker
// (verifier-demo.provii.app) against unauthorised use of shared sandbox
// credentials. The signing secret lives in Cloudflare's Secrets Store and is
// only available to the deployed Worker.
//
// For a local Node backend on localhost, the dev controls both sides of the
// request, so there is no security boundary to enforce. When DEMO_TOKEN_SECRET
// is unset (the default for `npm run dev`), token validation is skipped.
// Setting DEMO_TOKEN_SECRET re-enables validation, which is what the production
// CF Worker code path does via its Secrets Store binding.
// ============================================================================

const DEMO_TOKEN_SECRET = process.env.DEMO_TOKEN_SECRET || '';
const DEMO_TOKEN_VALIDATION_ENABLED = DEMO_TOKEN_SECRET.length > 0;

/**
 * SECURITY: Validate X-Demo-Token header to prevent unauthorised access to demo backends.
 * Token format: `demo_token_v1_<YYYYMMDD>_<16-char-hmac>`.
 * Uses Node.js crypto.timingSafeEqual for constant-time comparison of the HMAC tag.
 *
 * Caller MUST gate this on DEMO_TOKEN_VALIDATION_ENABLED. The function assumes
 * DEMO_TOKEN_SECRET is set.
 */
async function validateDemoToken(token: string): Promise<{ valid: boolean }> {
  if (!token || !token.startsWith('demo_token_v1_')) {
    return { valid: false };
  }

  const parts = token.split('_');
  if (parts.length !== 5) {
    return { valid: false };
  }

  const dateStr = parts[3] ?? '';
  const providedSig = parts[4] ?? '';
  if (!dateStr || !providedSig) {
    return { valid: false };
  }

 // Accept today or yesterday to handle timezone boundaries (48-hour window)
  const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10).replace(/-/g, '');

  if (dateStr !== today && dateStr !== yesterday) {
    return { valid: false };
  }

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(DEMO_TOKEN_SECRET),
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

 // SECURITY: Constant-time comparison using Node.js crypto.timingSafeEqual
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

// Demo token validation middleware for Hardcore endpoints only.
// Expert proxy endpoints (/api/challenge, /api/poll, /api/redeem) are called
// by provii-agegate from the browser and authenticate via HMAC to provii-verifier.
//
// When DEMO_TOKEN_SECRET is unset (local dev), validation is skipped entirely.
// Production CF Worker deployments bind the secret via the Secrets Store.
const EXPERT_PATHS = ['/api/challenge', '/api/poll', '/api/redeem', '/api/session'];
app.use('/api/*', async (c, next) => {
  if (EXPERT_PATHS.includes(c.req.path)) {
    await next();
    return;
  }
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
// === COPY THIS: Core Cryptographic & API Functions ===
// ============================================================================

/** Decode a base64url string to a Uint8Array. */
function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
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
  codeChallenge: string,
  minimumAge: number,
  expiresIn: number = 300,
): Promise<ChallengeResponse> {
  if (!config.hmacSecret) {
    throw new Error('HMAC_SECRET not configured');
  }
  if (!config.apiKey) {
    throw new Error('API_KEY not configured');
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = nodeRandomBytes(32).toString('hex');

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
  const response = await fetch(`${config.verifierApiUrl}/v1/challenge`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': config.apiKey,
      'Origin': config.registeredOrigin,
    },
    body: JSON.stringify(fullPayload),
    signal: AbortSignal.timeout(15_000),
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
}

/** Poll challenge status from provii-verifier by challenge ID. */
async function pollChallengeStatus(challengeId: string): Promise<StatusResponse> {
  const response = await fetch(`${config.verifierApiUrl}/v1/challenge/${challengeId}`, {
    method: 'GET',
    headers: {
      'X-API-Key': config.apiKey,
      'Origin': config.registeredOrigin,
    },
    signal: AbortSignal.timeout(15_000),
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
}

/** Redeem a verified challenge by presenting the PKCE code_verifier to provii-verifier. */
async function redeemChallenge(challengeId: string, codeVerifier: string): Promise<RedeemResponse> {
  const response = await fetch(`${config.verifierApiUrl}/v1/challenge/${challengeId}/redeem`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': config.apiKey,
      'Origin': config.registeredOrigin,
    },
    body: JSON.stringify({ code_verifier: codeVerifier }),
    signal: AbortSignal.timeout(15_000),
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
}

// ============================================================================
// API Endpoints
// ============================================================================

/** Health check returning credential configuration status. */
app.get('/health', (c) => c.json({
  status: 'ok',
  configured: !!(config.hmacSecret && config.apiKey && config.clientId),
}));

/** Configuration visibility endpoint for debugging. */
app.get('/api/config', (c) => {
  return c.json({
    verifier_api_url: config.verifierApiUrl,
    has_client_id: !!config.clientId,
    api_key_configured: !!config.apiKey,
    hmac_secret_configured: !!config.hmacSecret,
  });
});

/**
 * Create a new age verification challenge.
 *
 * Accepts `minimum_age` (over_age) or `maximum_age` (under_age), but not both.
 * Generates a PKCE pair, authenticates to provii-verifier with HMAC, stores the
 * code_verifier in memory, and returns a deep link for the mobile app.
 */
app.post('/api/create-challenge', async (c) => {
  try {
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
    const challenge = await createChallengeWithApi(codeChallenge, age, expiresIn);

 // SECURITY: code_verifier is secret and must never leave the backend
    sessions.set(challenge.challenge_id, {
      codeVerifier,
      challengeId: challenge.challenge_id,
      expiresAt: challenge.expires_at,
      createdAt: Date.now(),
      proofDirection: challenge.proof_direction,
    });

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
    console.error(`[${errorId}] Error creating challenge:`, error);
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
    const sessionId = c.req.param('sessionId');

    if (!sessionId) {
      return c.json({ error: 'Missing session_id' }, 400);
    }

 // UUID format validation before session lookup
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sessionId)) {
      return c.json({ error: 'Invalid session_id format' }, 400);
    }

    const session = sessions.get(sessionId);
    if (!session) {
      return c.json({ error: 'Session not found' }, 404);
    }

    const status = await pollChallengeStatus(sessionId);

    return c.json({
      state: status.state,
      verified: status.verified,
      proof_verified: status.proof_verified,
    });
  } catch (error) {
    const errorId = crypto.randomUUID().slice(0, 8);
    console.error(`[${errorId}] Error checking status:`, error instanceof Error ? error.stack : error);
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
    const sessionId = c.req.param('sessionId');

    if (!sessionId) {
      return c.json({ error: 'Missing session_id' }, 400);
    }

 // UUID format validation before session lookup
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sessionId)) {
      return c.json({ error: 'Invalid session_id format' }, 400);
    }

 // SECURITY: Delete-before-use pattern prevents double-redemption.
 // Even if redemption fails, the session cannot be replayed.
    const session = sessions.get(sessionId);
    if (!session) {
      return c.json({ error: 'Session not found or already redeemed' }, 404);
    }

    sessions.delete(sessionId);

 // Session already deleted, so replay is impossible even if redemption fails.
 // Provii-verifier enforces single-use as defence-in-depth.
    const result = await redeemChallenge(sessionId, session.codeVerifier);

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
    const challenge = await createChallengeWithApi(codeChallenge, 18, expiresIn);

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

    const status = await pollChallengeStatus(challengeId);
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
    const result = await redeemChallenge(challengeId, codeVerifier);

 // Set a session cookie so the frontend knows the user is verified on reload.
 // In production, use a signed/encrypted token with expiry.
    const sessionToken = nodeRandomBytes(32).toString('hex');
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
// Static File Serving (demo pages)
// ============================================================================

const PUBLIC_DIR = nodePath.resolve(process.cwd(), 'public');

app.get('/', (c) => c.redirect('/expert.html'));
app.get('/:filename{.+\\.html$}', async (c) => {
  const filename = c.req.param('filename');
 // Prevent path traversal by resolving and checking the result stays within PUBLIC_DIR
  const resolved = nodePath.resolve(PUBLIC_DIR, filename);
  if (!resolved.startsWith(PUBLIC_DIR + nodePath.sep)) {
    return c.text('Forbidden', 403);
  }
  try {
    const { readFile } = await import('node:fs/promises');
    const content = await readFile(resolved, 'utf-8');
    return c.html(content);
  } catch {
    return c.text('Not found', 404);
  }
});
app.get('/:filename{.+\\.(js|css)$}', async (c) => {
  const filename = c.req.param('filename');
 // Prevent path traversal by resolving and checking the result stays within PUBLIC_DIR
  const resolved = nodePath.resolve(PUBLIC_DIR, filename);
  if (!resolved.startsWith(PUBLIC_DIR + nodePath.sep)) {
    return c.text('Forbidden', 403);
  }
  try {
    const { readFile } = await import('node:fs/promises');
    const content = await readFile(resolved, 'utf-8');
    const ct = filename.endsWith('.js') ? 'application/javascript' : 'text/css';
    return c.body(content, { headers: { 'Content-Type': ct } });
  } catch {
    return c.text('Not found', 404);
  }
});

// ============================================================================
// Server Startup
// ============================================================================

function requireCredentials(): void {
  if (!config.clientId || !config.apiKey || !config.hmacSecret || !config.verifierApiUrl) {
    console.error('FATAL: missing required environment variables.');
    console.error('Set CLIENT_ID, API_KEY, HMAC_SECRET, and VERIFIER_API_URL before starting.');
    console.error('Mint sandbox credentials at https://admin.provii.app');
    console.error('See backends/verifier/nodejs/README.md for the setup walkthrough.');
    process.exit(1);
  }
}

/** Start the HTTP server. */
async function main() {
  requireCredentials();

  console.log('');
  console.log('=== Provii Verifier Demo Backend ===');
  console.log(`Mode: Direct provii-verifier integration with HMAC auth`);
  console.log(`Port: ${config.port}`);
  console.log(`Verifier API: ${config.verifierApiUrl}`);
  console.log(`Client ID: ${config.clientId}`);
  console.log(`API Key Configured: ${!!config.apiKey}`);
  console.log(`HMAC Secret Configured: ${!!config.hmacSecret}`);
  if (DEMO_TOKEN_VALIDATION_ENABLED) {
    console.log('Demo token validation: ENABLED (DEMO_TOKEN_SECRET is set)');
  } else {
    console.log('Demo token validation: DISABLED (local dev mode, DEMO_TOKEN_SECRET unset).');
    console.log('  Bind DEMO_TOKEN_SECRET via wrangler secrets / env injection for production.');
  }
  console.log('');
  console.log('Test with:');
  console.log(`  curl -X POST http://localhost:${config.port}/api/create-challenge \\`);
  console.log(`    -H "Content-Type: application/json" \\`);
  console.log(`    -d '{"minimum_age": 21}'`);
  console.log('');
  console.log('Then check status:');
  console.log(`  curl http://localhost:${config.port}/api/status/<session_id>`);
  console.log('');
  console.log('Then redeem (after user verifies in wallet):');
  console.log(`  curl -X POST http://localhost:${config.port}/api/redeem/<session_id>`);
  console.log('');

  const server = serve({ fetch: app.fetch, port: config.port });

  server.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`\nPort ${config.port} is already in use.`);
      console.error(`A previous dev process is still bound. Kill it with:`);
      console.error(`  lsof -ti:${config.port} | xargs kill -9\n`);
      process.exit(1);
    }
    console.error('Server error:', err);
    process.exit(1);
  });

  const shutdown = (signal: string) => {
    console.log(`\nReceived ${signal}, closing server.`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
