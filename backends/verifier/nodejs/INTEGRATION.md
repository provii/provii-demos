# Node.js Verifier Backend Integration Guide

This guide shows how to add Provii age verification to your Node.js backend.

## Quick Start (5 minutes)

### Option 1: Copy the Core Module

Copy the verification logic from `src/index.ts`:

```typescript
import crypto from 'crypto';

// Your credentials from Provii admin portal
const VERIFIER_API_URL = process.env.VERIFIER_API_URL!;
const CLIENT_ID = process.env.CLIENT_ID!;
const API_KEY = process.env.API_KEY!;
const HMAC_SECRET = process.env.HMAC_SECRET!;

// In-memory sessions (use Redis/DB in production)
const sessions = new Map<string, { codeVerifier: string }>;

async function createVerificationChallenge(minimumAge: number) {
 // Generate PKCE pair
 const codeVerifier = generateCodeVerifier;
 const codeChallenge = await generateCodeChallenge(codeVerifier);

 // Create challenge with provii-verifier
 const challenge = await createChallengeWithApi(codeChallenge, minimumAge, 300, 'over_age');

 // Store code_verifier securely
 sessions.set(challenge.challenge_id, { codeVerifier });

 return {
 session_id: challenge.challenge_id,
 deep_link: buildDeepLink(challenge),
 expires_at: challenge.expires_at,
 };
}
```

### Option 2: Use as Reference

Run this demo backend and study the flow:

```bash
cd backends/verifier/nodejs
npm install
npm start
```

## Dependencies

```json
{
 "dependencies": {
 "hono": "^4.0.0",
 "@hono/node-server": "^1.0.0"
 }
}
```

No external crypto libraries needed - uses native Node.js crypto.

## API Endpoints

Your backend needs to expose:

| Endpoint | Method | Body | Response |
|----------|--------|------|----------|
| `/api/create-challenge` | POST | `{ "minimum_age": 21 }` | `{ "session_id": "...", "deep_link": "https://provii.app/..." }` |
| `/api/status/:sessionId` | GET | - | `{ "state": "verified", "verified": true }` |
| `/api/redeem/:sessionId` | POST | - | `{ "result": "verified", "verified": true }` |

## Environment Variables

```bash
# Required - mint via the playground for sandbox, or via the admin portal for production
VERIFIER_API_URL=https://sandbox-verify.provii.app
CLIENT_ID=rp_your_client_id
API_KEY=your_api_key
HMAC_SECRET=base64url-encoded-secret

# Optional
PORT=3001
ALLOWED_ORIGINS=https://yourapp.com
NODE_ENV=production
```

## Flow Diagram

```
Mobile App Your Backend provii-verifier
 │ │ │
 │ POST /create-challenge │ │
 │ { minimum_age: 21 } │ │
 │ ─────────────────────────► │
 │ │ │
 │ │ 1. Generate PKCE │
 │ │ - code_verifier (keep) │
 │ │ - code_challenge (send) │
 │ │ │
 │ │ 2. Create challenge │
 │ │ + HMAC signature │
 │ │ ──────────────────────────►│
 │ │ │
 │ │◄──────────────────────────│
 │ │ 3. Store code_verifier │
 │ │ │
 │◄─────────────────────────│ │
 │ { session_id, deep_link }│ │
 │ │ │
 │ Open wallet with deep_link │
 │ ──────────────────────────────────────────────────────►
 │ │ 4. User creates │
 │ │ ZK proof │
 │ │ │
 │ Poll status │ │
 │ ─────────────────────────► │
 │ │ GET /challenge/:id ────────►
 │ │ │
 │ Call redeem when verified│ │
 │ ─────────────────────────► │
 │ │ POST /redeem │
 │ │ + code_verifier ──────────►│
 │ │ │
 │◄─────────────────────────│◄───────────────────────────│
 │ { verified: true } │ │
```

## Core Functions

### PKCE Generation

```typescript
// Generate cryptographically secure code_verifier
function generateCodeVerifier: string {
 const bytes = new Uint8Array(32);
 crypto.getRandomValues(bytes);
 return base64urlEncode(bytes);
}

// Generate code_challenge (SHA-256 hash of code_verifier)
async function generateCodeChallenge(codeVerifier: string): Promise<string> {
 const encoder = new TextEncoder;
 const data = encoder.encode(codeVerifier);
 const hash = await crypto.subtle.digest('SHA-256', data);
 return base64urlEncode(new Uint8Array(hash));
}
```

### HMAC Authentication

```typescript
// Create HMAC-SHA256 signature (hex-encoded)
async function createHmacSignature(message: string, secretBase64url: string): Promise<string> {
 const keyData = base64urlDecode(secretBase64url);
 const key = await crypto.subtle.importKey(
 'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
 );
 const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder.encode(message));
 return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// IMPORTANT: Canonical payload does NOT include authorizer
// Field order: code_challenge, method, verifying_key_id, expires_in
// proof_direction is determined server-side from origin policy
const payloadForHmac = {
 code_challenge: codeChallenge,
 method: 'S256',
 verifying_key_id: null, // Must be present even if null
 expires_in: expiresIn,
};

// Nonce must be generated BEFORE the canonical message (it is the 5th field)
const nonce = crypto.randomBytes(32).toString('hex');

// Canonical message format: 5 colon-separated fields
const canonicalMessage = `${timestamp}:POST:/v1/challenge:${JSON.stringify(payloadForHmac)}:${nonce}`;
const hmac = await createHmacSignature(canonicalMessage, HMAC_SECRET);

// Full payload includes authorizer with nonce for replay protection
const fullPayload = {
 code_challenge: codeChallenge,
 method: 'S256',
 expires_in: expiresIn,
 authorizer: {
 keyId: CLIENT_ID,
 timestamp: timestamp,
 nonce: nonce,
 hmac: hmac,
 },
};
```

### Age to Cutoff Days

```typescript
// Convert minimum age to cutoff_days for the ZK proof
function ageToCutoffDays(minimumAge: number): number {
 return Math.floor(minimumAge * 365.2425);
}
```

### Deep Link Construction

```typescript
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
```

## Express.js Example

```typescript
import express from 'express';

const app = express;
app.use(express.json);

const sessions = new Map;

app.post('/api/create-challenge', async (req, res) => {
 const { minimum_age = 18 } = req.body;

 if (minimum_age < 13 || minimum_age > 120) {
 return res.status(400).json({ error: 'Invalid minimum_age' });
 }

 try {
 const codeVerifier = generateCodeVerifier;
 const codeChallenge = await generateCodeChallenge(codeVerifier);
 const challenge = await createChallengeWithApi(codeChallenge, minimum_age, 300, 'over_age');

 sessions.set(challenge.challenge_id, { codeVerifier });

 res.json({
 session_id: challenge.challenge_id,
 deep_link: buildDeepLink(challenge),
 expires_at: challenge.expires_at,
 });
 } catch (error) {
 console.error('Challenge failed:', error);
 res.status(500).json({ error: 'Failed to create challenge' });
 }
});

app.get('/api/status/:sessionId', async (req, res) => {
 const session = sessions.get(req.params.sessionId);
 if (!session) return res.status(404).json({ error: 'Session not found' });

 const status = await pollChallengeStatus(req.params.sessionId);
 res.json(status);
});

app.post('/api/redeem/:sessionId', async (req, res) => {
 const session = sessions.get(req.params.sessionId);
 if (!session) return res.status(404).json({ error: 'Session not found' });

 const result = await redeemChallenge(req.params.sessionId, session.codeVerifier);
 if (result.verified) sessions.delete(req.params.sessionId);

 res.json(result);
});
```

## Hono Example (This Demo)

See `src/index.ts` for a complete Hono implementation with:
- CORS configuration
- Security headers
- Input validation
- Error handling

Mint sandbox credentials from the playground UI. Visit https://playground.provii.app, switch to the "Set up a Verifier" tab, fill in the policy form, click mint. Copy `client_id`, `api_key`, `hmac_secret`, and `base_url` into your `.env`:

```bash
# .env (do not commit)
CLIENT_ID=rp_sandbox_<your minted id>
API_KEY=<your minted api key>
HMAC_SECRET=<your minted hmac secret>
VERIFIER_API_URL=https://sandbox-verify.provii.app
```

The credential expires in 72 hours. Mint a new one when it expires; the playground remembers it in localStorage so reloading does not lose it.

## Security Considerations

| Rule | Detail |
|------|--------|
| Never expose HMAC_SECRET | Keep in secure environment variables |
| Never expose code_verifier | It must stay on your backend |
| Use HTTPS in production | The demo uses HTTP for local development only |
| Implement rate limiting | Protect against abuse |
| Use Redis/DB for sessions | In-memory storage is for demo only |
| Validate CORS origins | Set `ALLOWED_ORIGINS` to your app domains only |

## Testing

1. Start the backend:
 ```bash
 npm start
 ```

2. Create a challenge:
 ```bash
 curl -X POST http://localhost:3001/api/create-challenge \
 -H "Content-Type: application/json" \
 -d '{"minimum_age": 21}'
 ```

3. The response contains a `deep_link` that opens Provii Wallet

4. Enable Sandbox Mode in Provii Wallet: Settings → tap 5 times → toggle Sandbox

5. Poll status until verified, then redeem

## Common Issues

### "HMAC_SECRET not configured"
Mint sandbox credentials from the playground (https://playground.provii.app, "Set up a Verifier" tab) and copy them into `.env`. For production, fetch credentials from the Provii admin portal.

### Challenge creation fails with 401
Ensure:
- `CLIENT_ID` and `HMAC_SECRET` are correct
- Timestamp in HMAC is current (within 5 minutes)
- Canonical message format matches exactly
- Nonce is unique for each request (no reuse)

### Session not found
Sessions are stored in-memory and lost on restart. Use Redis/DB in production.
