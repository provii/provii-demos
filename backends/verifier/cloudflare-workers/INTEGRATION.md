# Cloudflare Workers Verifier Backend Integration Guide

This guide shows how to add Provii age verification to your Cloudflare Workers backend.

## Overview

This demo backend shows how to implement the **Expert Verifier Setup**: your backend authenticates to provii-verifier with HMAC-SHA256, manages PKCE, and stores sessions.

**Your backend's role:**
1. Generate PKCE pair (code_verifier stays with you, code_challenge goes to API)
2. Authenticate to provii-verifier with HMAC-SHA256 signature
3. Store code_verifier securely (in KV)
4. Return deep link to your mobile app
5. Poll status and redeem with code_verifier when verified

## Architecture

```
Your Mobile App Your Backend provii-verifier Provii Wallet
 │ │ │ │
 │ POST /create-challenge │ │
 │ { minimum_age: 21 } │ │ │
 │ ─────────────────────► │ │
 │ │ │ │
 │ │ 1. Generate PKCE │ │
 │ │ - code_verifier │ │
 │ │ - code_challenge │ │
 │ │ │ │
 │ │ 2. Create HMAC signature│ │
 │ │ + mandatory nonce │ │
 │ │ │ │
 │ │ POST /v1/challenge ────►│ │
 │ │ {code_challenge, hmac} │ │
 │ │ │ │
 │ │◄────────────────────────│ │
 │ │ {challenge_id, etc} │ │
 │ │ │ │
 │ │ 3. Store code_verifier │ │
 │ │ in KV (secret!) │ │
 │ │ │ │
 │◄────────────────────── │ │
 │ {session_id, deep_link} │ │
 │ │ │ │
 │ Open deep link ──────┼─────────────────────────┼─────────────────────►│
 │ │ │ │
 │ │ │ 4. User creates ZK │
 │ │ │ proof in wallet │
 │ │ │ │
 │ │ │◄─────────────────────│
 │ │ │ POST /v1/verify │
 │ │ │ {proof} │
 │ │ │ │
 │ Poll status │ │ │
 │ ─────────────────────► │ │
 │ │ GET /v1/challenge/:id ──► │
 │◄────────────────────── │ │
 │ { verified: true } │ │ │
 │ │ │ │
 │ Redeem │ │ │
 │ ─────────────────────► │ │
 │ │ POST /redeem ──────────►│ │
 │ │ + code_verifier │ │
 │◄──────────────────────◄────────────────────────│ │
 │ { result: "verified" } │ │
```

**Key insight:** Your backend never exposes `HMAC_SECRET` or `code_verifier` to clients. PKCE ensures only your backend can redeem verified challenges.

## Code to Copy

### Core Cryptographic Functions (COPY THIS)

```typescript
/**
 * Decode base64url string to Uint8Array
 */
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

/**
 * Encode Uint8Array to base64url string (no padding)
 */
function base64urlEncode(bytes: Uint8Array): string {
 const binary = String.fromCharCode(...bytes);
 const base64 = btoa(binary);
 return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Generate PKCE code_verifier (RFC 7636 compliant)
 */
function generateCodeVerifier: string {
 const bytes = new Uint8Array(32);
 crypto.getRandomValues(bytes);
 return base64urlEncode(bytes);
}

/**
 * Generate PKCE code_challenge from code_verifier using S256 method
 */
async function generateCodeChallenge(codeVerifier: string): Promise<string> {
 const encoder = new TextEncoder;
 const data = encoder.encode(codeVerifier);
 const hash = await crypto.subtle.digest('SHA-256', data);
 return base64urlEncode(new Uint8Array(hash));
}

/**
 * Create HMAC-SHA256 signature (hex-encoded, lowercase)
 */
async function createHmacSignature(message: string, secretBase64url: string): Promise<string> {
 const encoder = new TextEncoder;
 const keyData = base64urlDecode(secretBase64url);

 const key = await crypto.subtle.importKey(
 'raw',
 keyData,
 { name: 'HMAC', hash: 'SHA-256' },
 false,
 ['sign']
 );

 const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
 const bytes = new Uint8Array(signature);

 // Hex encode (64 chars, lowercase)
 return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert minimum age to cutoff_days for ZK proof
 */
function ageToCutoffDays(minimumAge: number): number {
 return Math.floor(minimumAge * 365.2425);
}

/**
 * Build deep link from challenge response
 */
function buildDeepLink(challenge: ChallengeResponse): string {
 const payload = {
 challenge_id: challenge.challenge_id,
 rp_challenge: challenge.rp_challenge,
 submit_secret: challenge.submit_secret,
 cutoff_days: challenge.cutoff_days,
 verifying_key_id: challenge.verifying_key_id,
 verify_url: challenge.verify_url,
 expires_at: challenge.expires_at,
 };
 const jsonStr = JSON.stringify(payload);
 const bytes = new TextEncoder.encode(jsonStr);
 return `https://provii.app/verify?d=${base64urlEncode(bytes)}`;
}

interface ChallengeResponse {
 challenge_id: string;
 rp_challenge: string;
 cutoff_days: number;
 verifying_key_id: number;
 submit_secret: string;
 expires_at: number;
 status_url: string;
 verify_url: string;
}
```

### Creating a Challenge with HMAC Auth (COPY THIS)

```typescript
async function createChallengeWithApi(
 codeChallenge: string,
 minimumAge: number,
 expiresIn: number = 300,
 proofDirection: string = 'over_age'
): Promise<ChallengeResponse> {
 const timestamp = Math.floor(Date.now / 1000);
 const cutoffDays = ageToCutoffDays(minimumAge);
 const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
 const nonce = [...nonceBytes].map(b => b.toString(16).padStart(2, '0')).join('');

 // CRITICAL: Canonical payload for HMAC (specific field order, NO authorizer)
 // proof_direction is NOT included. It is determined server-side from origin policy
 const payloadForHmac = {
 code_challenge: codeChallenge,
 method: 'S256',
 verifying_key_id: null, // Must be present even if null
 expires_in: expiresIn,
 };

 // Canonical message format: 5 colon-separated fields including nonce
 const canonicalMessage = `${timestamp}:POST:/v1/challenge:${JSON.stringify(payloadForHmac)}:${nonce}`;
 const hmac = await createHmacSignature(canonicalMessage, HMAC_SECRET);

 // Full payload WITH authorizer (sent to API)
 const fullPayload = {
 code_challenge: codeChallenge,
 method: 'S256',
 expires_in: expiresIn,
 authorizer: {
 keyId: CLIENT_ID,
 timestamp: timestamp,
 nonce: nonce, // MANDATORY: replay prevention
 hmac: hmac,
 },
 };

 const response = await fetch(`${VERIFIER_API_URL}/v1/challenge`, {
 method: 'POST',
 headers: {
 'Content-Type': 'application/json',
 'X-API-Key': API_KEY,
 'Origin': 'https://yourapp.com', // Must match registered origin
 },
 body: JSON.stringify(fullPayload),
 });

 if (!response.ok) {
 const error = await response.text;
 throw new Error(`Challenge creation failed: ${response.status} - ${error}`);
 }

 return response.json;
}
```

### Session Storage Pattern

```typescript
// Store session in Cloudflare KV
interface SessionData {
 codeVerifier: string;
 challengeId: string;
 expiresAt: number;
 createdAt: number;
}

// After creating challenge:
const session: SessionData = {
 codeVerifier,
 challengeId: challenge.challenge_id,
 expiresAt: challenge.expires_at,
 createdAt: Date.now,
};

await env.SESSIONS.put(
 `session:${challenge.challenge_id}`,
 JSON.stringify(session),
 { expirationTtl: expiresIn + 60 }
);
```

## Key Flows

### 1. Create Verification Challenge

**Endpoint:** `POST /api/create-challenge`

**Request:**
```json
{
 "minimum_age": 21,
 "expires_in": 300
}
```

**Response:**
```json
{
 "session_id": "550e8400-e29b-41d4-a716-446655440000",
 "deep_link": "https://provii.app/verify?d=eyJjaGFsbGVuZ2VfaWQiOi...",
 "expires_at": 1735600300,
 "status_url": "/api/status/550e8400-e29b-41d4-a716-446655440000"
}
```

**Your mobile app should:**
1. Call this endpoint when age verification is needed
2. Open the `deep_link` to launch Provii Wallet
3. Poll `status_url` while waiting for user
4. Call redeem when status shows verified

### 2. Poll Verification Status

**Endpoint:** `GET /api/status/:sessionId`

**Response:**
```json
{
 "state": "verified",
 "verified": true,
 "proof_verified": true
}
```

**States:**
- `pending` - Waiting for user to verify in wallet
- `verified` - User completed verification, ready to redeem
- `expired` - Challenge expired
- `failed` - Verification was rejected or encountered an error

### 3. Redeem Verification

**Endpoint:** `POST /api/redeem/:sessionId`

**Response:**
```json
{
 "result": "verified",
 "verified": true
}
```

This is the final confirmation. Only call this after status shows verified.

### 4. Deep Link Format

```
https://provii.app/verify?d=<base64url-encoded-json>
```

The `d` parameter contains:
```json
{
 "challenge_id": "uuid",
 "rp_challenge": "base64url(32 bytes)",
 "submit_secret": "base64url(32 bytes)",
 "cutoff_days": 7670,
 "verifying_key_id": 1,
 "verify_url": "https://sandbox-verify.provii.app/v1/verify",
 "expires_at": 1735600300
}
```

## Environment Variables

Set via `wrangler secret put`:

```bash
# Required credentials from Provii admin portal
wrangler secret put CLIENT_ID
# Enter: rp_your_client_id

wrangler secret put API_KEY
# Enter: your_api_key

wrangler secret put HMAC_SECRET
# Enter: base64url-encoded-secret
```

Set in `wrangler.toml`:

```toml
[vars]
ENVIRONMENT = "production"
VERIFIER_API_URL = "https://verify.provii.app"
ALLOWED_ORIGINS = "https://yourapp.com"

[[kv_namespaces]]
binding = "SESSIONS"
id = "your-kv-namespace-id"
```

Create KV namespace:

```bash
wrangler kv namespace create SESSIONS
# Copy the id to wrangler.toml
```

## Security Considerations

### Production Requirements

| What | Demo Behaviour | Production Requirement |
|------|---------------|------------------------|
| Session storage | Cloudflare KV (good) | KV with encryption-at-rest (default) |
| HMAC secret | Environment variable | Cloudflare Workers Secrets |
| CORS origins | Localhost allowed | Restrict to your domains only |
| Rate limiting | None | Implement via Cloudflare WAF |
| Session TTL | Challenge expiry + 60s | Match challenge expiry |

### Critical Security Rules

| Rule | Detail |
|------|--------|
| NEVER expose HMAC_SECRET | It must stay on your backend |
| NEVER expose code_verifier | It must stay on your backend (in KV) |
| Always include nonce | Mandatory for replay prevention (5-minute TTL) |
| Validate session ownership | Before redeeming, verify the session belongs to the requesting user |
| Clean up sessions | Delete from KV after successful redemption |

### HMAC Canonical Message Format

The canonical message **must** match provii-verifier's expectations exactly. It contains 5 colon-separated fields:

```
{timestamp}:POST:/v1/challenge:{json_payload_without_authorizer}:{nonce}
```

The JSON payload must have fields in this exact order:
1. `code_challenge`
2. `method`
3. `verifying_key_id` (even if null)
4. `expires_in`

The nonce (32 cryptographically random bytes, hex-encoded to 64 characters) is appended as the 5th field after the JSON payload. It provides replay prevention with a 5-minute TTL on the server side.

Note: `proof_direction` is determined server-side from origin policy and is not included in the canonical payload or request body. It is returned in the API response.

### Why PKCE + HMAC?

| Mechanism | Purpose |
|-----------|---------|
| HMAC-SHA256 | Proves your backend is authorised to create challenges |
| Nonce | Prevents replay attacks (each request is unique) |
| PKCE | Ensures only your backend can redeem (code_verifier never sent to API until redeem) |
| Combined effect | Even if someone intercepts the deep link, they cannot complete verification |

## Testing

### 1. Local Development

```bash
cd backends/verifier/cloudflare-workers
npm install
npm run dev
```

### 2. Create a Challenge

```bash
# Fetch demo token first
DEMO_TOKEN=$(curl -s https://playground.provii.app/v1/config/demo-token | jq -r .token)

# Create challenge
curl -X POST http://localhost:8787/api/create-challenge \
 -H "Content-Type: application/json" \
 -H "X-Demo-Token: $DEMO_TOKEN" \
 -d '{"minimum_age": 21}'
```

### 3. Enable Sandbox Mode in Provii Wallet

Settings > tap version 5 times > toggle "Sandbox Mode"

### 4. Complete Flow

1. Open the `deep_link` from step 2 in Provii Wallet
2. Complete verification in the wallet
3. Poll status:
 ```bash
 curl http://localhost:8787/api/status/SESSION_ID \
 -H "X-Demo-Token: $DEMO_TOKEN"
 ```
4. Redeem when verified:
 ```bash
 curl -X POST http://localhost:8787/api/redeem/SESSION_ID \
 -H "X-Demo-Token: $DEMO_TOKEN"
 ```

### 5. Deploy to Cloudflare

```bash
wrangler kv namespace create SESSIONS
# Update wrangler.toml with the namespace ID

wrangler deploy
```

## Common Issues

### "HMAC_SECRET not configured"

The worker requires `CLIENT_ID`, `API_KEY`, `HMAC_SECRET`, and `VERIFIER_API_URL` to be set. Mint sandbox credentials from the playground UI: visit https://playground.provii.app, switch to the "Set up a Verifier" tab, fill in the policy form, click mint. Copy `client_id`, `api_key`, `hmac_secret`, and `base_url` into `.dev.vars` for local runs:

```ini
# .dev.vars (do not commit)
CLIENT_ID=rp_sandbox_<your minted id>
API_KEY=<your minted api key>
HMAC_SECRET=<your minted hmac secret>
VERIFIER_API_URL=https://sandbox-verify.provii.app
```

The credential expires in 72 hours. Mint a new one when it expires; the playground remembers it in localStorage so reloading does not lose it.

For production:
1. Get credentials from the Provii admin portal at https://admin.provii.app.
2. Set via `wrangler secret put HMAC_SECRET` (and the other three).

### Challenge creation fails with 401

Check:
- `CLIENT_ID` and `HMAC_SECRET` are correct
- Timestamp is current (within 5 minutes)
- Canonical message format matches exactly (field order matters!)
- Nonce is unique for each request

### Session not found (404)

- Sessions expire after challenge TTL + 60 seconds
- KV namespace must be properly bound in wrangler.toml
- Verify KV namespace ID is correct
- For local dev, confirm `.dev.vars` has the right `VERIFIER_API_URL`

### CORS errors

- Add your app's origin to `ALLOWED_ORIGINS`
- The demo only allows localhost origins by default

## API Reference

| Endpoint | Method | Body | Response |
|----------|--------|------|----------|
| `/health` | GET | - | `{ "status": "ok", "configured": true }` |
| `/api/config` | GET | - | Configuration info (no secrets) |
| `/api/create-challenge` | POST | `{ "minimum_age": 21 }` | Session + deep link |
| `/api/status/:sessionId` | GET | - | Verification status |
| `/api/redeem/:sessionId` | POST | - | Final verification result |

## Comparison: Simple vs Expert Setup

| Aspect | Simple (pk_ public key) | Expert (this demo) |
|--------|-------------------------|-------------------|
| Use case | Websites with provii-agegate | Mobile apps, custom UX |
| Backend required | No | Yes |
| Authentication | pk_ public key | HMAC-SHA256 + nonce |
| Session management | Provii handles it | You handle it (KV) |
| PKCE | Provii handles it | You handle it |
| Flexibility | Limited | Full control |

Mobile apps must use the Expert setup. The Simple setup uses browser cookie-based sessions which do not survive the app-switch into the wallet.
