# Cloudflare Workers Issuer Backend Integration Guide

This guide shows how to add Provii credential issuance to your Cloudflare Workers backend.

## Overview

Your backend authenticates with Provii's provii-issuer using HMAC-SHA256. Provii creates and signs the attestation internally with Ed25519. You never handle cryptographic keys for signing.

**Your backend's role:**
1. Retrieve customer DOB from your KYC database
2. Authenticate with HMAC-SHA256 and call Provii's provii-issuer
3. Return the deep link (containing Provii's signed attestation) to your mobile app
4. Wallet handles the rest (r_bits generation, blind issuance)

## Architecture

```
Your Mobile App Your Backend Provii provii-issuer
 │ │ │
 │ POST /create-attest │ │
 │ { dob: "1990-05-15" }│ │
 │ ─────────────────────► │
 │ │ │
 │ │ 1. Convert DOB to │
 │ │ days since epoch │
 │ │ │
 │ │ 2. Build HMAC-SHA256 │
 │ │ canonical message │
 │ │ │
 │ │ POST /v1/attestation/create
 │ │ ─────────────────────►│
 │ │ │
 │ │ provii-issuer signs │
 │ │ attestation (Ed25519)│
 │ │ │
 │ │◄──────────────────────│
 │ │ {attestation, expires_at, issuer_id}
 │ │ │
 │◄────────────────────── │
 │ { deep_link } │ │
 │ │ │
 │ Open deep link ──────┼──────────────────────► Provii Wallet
 │ │ │ │
 │ │ │ │ Generates r_bits
 │ │ │ │ (128 random bits)
 │ │ │ │
 │ │ │◄───┤ POST /v1/issuance/blind
 │ │ │ │ {attestation, r_bits}
 │ │ │ │
 │ │ provii-issuer verifies │ │
 │ │ attestation, computes│ │
 │ │ Pedersen commitment, │ │
 │ │ signs credential │ │
 │ │ │────► Credential stored
```

**Key insight:** Your backend never handles signing keys or sees `r_bits`. Provii signs attestations server-side, and the wallet generates randomness locally.

## Code to Copy

### Core HMAC Authentication Functions (COPY THIS)

```typescript
/**
 * Decode base64url string to Uint8Array
 */
function base64urlDecode(str: string): Uint8Array {
 const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
 const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
 const binary = atob(padded);
 const bytes = new Uint8Array(binary.length);
 for (let i = 0; i < binary.length; i++) {
 bytes[i] = binary.charCodeAt(i);
 }
 return bytes;
}

/**
 * Compute HMAC-SHA256 and return as hex string.
 * Uses Web Crypto API (available in Cloudflare Workers).
 */
async function hmacSha256Hex(secret: Uint8Array, message: string): Promise<string> {
 const key = await crypto.subtle.importKey(
 'raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
 );
 const sig = await crypto.subtle.sign(
 'HMAC', key, new TextEncoder.encode(message)
 );
 return Array.from(new Uint8Array(sig))
 .map((b) => b.toString(16).padStart(2, '0'))
 .join('');
}

/**
 * Build the canonical message for HMAC signing.
 *
 * Format: {timestamp}:POST:/v1/attestation/create:{canonical_json}:{nonce}
 * IMPORTANT:
 * - canonical JSON uses "key_id" (snake_case), NOT "keyId" (camelCase).
 * - the same nonce value MUST appear in both the canonical message and the
 * request body's authorizer.nonce field.
 */
function buildCanonicalMessage(dobDays: number, clientId: string, timestamp: number, nonce: string): string {
 const canonicalJson =
 `{"dob_days":${dobDays},"authorizer":{"format":"client","key_id":"${clientId}","timestamp":${timestamp}}}`;
 return `${timestamp}:POST:/v1/attestation/create:${canonicalJson}:${nonce}`;
}

/**
 * Create an attestation via Provii's provii-issuer.
 *
 * Authenticates with HMAC-SHA256. Provii signs the attestation internally.
 * Returns { attestation, expires_at, issuer_id }.
 */
async function createAttestation(
 dobDays: number,
 clientId: string,
 hmacSecretB64url: string,
 issuerApiUrl: string
): Promise<{ attestation: string; expires_at: number; issuer_id: string }> {
 const timestamp = Math.floor(Date.now / 1000);

 // 256-bit random nonce. The SAME value goes into both the canonical message and the request body.
 const nonceBytes = new Uint8Array(32);
 crypto.getRandomValues(nonceBytes);
 const nonce = [...nonceBytes].map((b) => b.toString(16).padStart(2, '0')).join('');

 // Build canonical message and compute HMAC
 const canonicalMessage = buildCanonicalMessage(dobDays, clientId, timestamp, nonce);
 const secretBytes = base64urlDecode(hmacSecretB64url);
 const hmacHex = await hmacSha256Hex(secretBytes, canonicalMessage);

 // Call Provii provii-issuer
 const response = await fetch(`${issuerApiUrl}/v1/attestation/create`, {
 method: 'POST',
 headers: { 'Content-Type': 'application/json' },
 body: JSON.stringify({
 dob_days: dobDays,
 authorizer: {
 format: 'client',
 keyId: clientId, // camelCase in the request body
 timestamp,
 hmac: hmacHex,
 nonce,
 },
 }),
 });

 if (!response.ok) {
 const text = await response.text;
 throw new Error(`Issuer API returned ${response.status}: ${text}`);
 }

 return response.json;
}
```

### Converting Date of Birth to Days

```typescript
function dobToDays(dob: string): number {
 if (!/^\d{4}-\d{2}-\d{2}$/.test(dob)) {
 throw new Error('Invalid dob format: must be YYYY-MM-DD');
 }

 const dobDate = new Date(dob + 'T00:00:00Z');

 const [yearStr, monthStr, dayStr] = dob.split('-');
 if (dobDate.getUTCFullYear !== parseInt(yearStr) ||
 dobDate.getUTCMonth + 1 !== parseInt(monthStr) ||
 dobDate.getUTCDate !== parseInt(dayStr)) {
 throw new Error('Invalid date: the specified date does not exist');
 }

 return Math.floor(dobDate.getTime / (24 * 60 * 60 * 1000));
}
```

## Key Flows

### 1. Create Attestation from DOB

**Endpoint:** `POST /api/create-attestation-from-dob`

**Request:**
```json
{ "dob": "1990-05-15" }
```

**Response:**
```json
{
 "deep_link": "https://provii.app/attest?d=eyJkb2JfZGF5cyI6NzQzOS...",
 "expires_at": 1735603600
}
```

**Your mobile app should:**
1. Call this endpoint with the user's DOB
2. Open the `deep_link` to launch Provii Wallet
3. The wallet will dismiss itself when issuance completes
4. Detect foreground resume in your app and update the UI accordingly

### 2. Deep Link Format

```
https://provii.app/attest?d=<base64url-encoded-attestation>
```

The `d` parameter contains the base64url-encoded attestation returned by Provii's provii-issuer. Your backend does not need to understand its contents.

## Environment Variables

Mint sandbox values via the playground (see Sandbox Mode below), or pull production values from the admin portal. Set via `wrangler secret put`:

```bash
wrangler secret put CLIENT_ID
# Enter: your client ID

wrangler secret put HMAC_SECRET
# Enter: base64url-encoded HMAC secret

wrangler secret put ISSUER_API_URL
# Enter: https://issuer.provii.app (or sandbox URL)
```

Set in `wrangler.toml`:

```toml
[vars]
ENVIRONMENT = "production"
ALLOWED_ORIGINS = "https://yourapp.com,https://admin.yourapp.com"
```

## API Endpoints

| Endpoint | Method | Body | Response |
|----------|--------|------|----------|
| `/health` | GET | - | `{ "status": "ok" }` |
| `/api/config` | GET | - | Configuration info (no secrets) |
| `/api/create-attestation` | POST | `{ "dob_days": 7439 }` | Deep link + expiry |
| `/api/create-attestation-from-dob` | POST | `{ "dob": "1990-05-15" }` | Deep link + expiry |

## Security Considerations

### Production Requirements

| What | Demo Behaviour | Production Requirement |
|------|---------------|------------------------|
| HMAC secret storage | Environment variable | Cloudflare Workers Secrets |
| CORS origins | Localhost allowed | Restrict to your domains only |
| Rate limiting | None | Implement via Cloudflare WAF or middleware |
| DOB validation | Format only | Verify against your KYC database |
| Logging | Full errors | Never log DOB values |

### Critical Security Rules

1. **NEVER expose your HMAC secret** in client-side code or logs
2. **NEVER log DOB values** on your backend
3. **Always use HTTPS** for calls to Provii's provii-issuer
4. **Validate customer identity** before creating attestations
5. **Restrict CORS origins** to your application domains only

## Testing

### 1. Local Development

```bash
cd backends/issuer/cloudflare-workers
npm install
npm run dev
```

### 2. Create an Attestation

```bash
# Fetch demo token first
DEMO_TOKEN=$(curl -s https://playground.provii.app/v1/config/demo-token | jq -r .token)

# Create attestation
curl -X POST http://localhost:8787/api/create-attestation-from-dob \
 -H "Content-Type: application/json" \
 -H "X-Demo-Token: $DEMO_TOKEN" \
 -d '{"dob": "1990-05-15"}'
```

### 3. Enable Sandbox Mode in Provii Wallet

Settings > tap version 5 times > toggle "Sandbox Mode"

### 4. Deploy to Cloudflare

```bash
wrangler deploy
```

## Sandbox Mode

For testing without production credentials:

1. Mint sandbox credentials from the playground UI. Visit https://playground.provii.app, switch to the "Set up an Issuing Party" tab, fill in the issuer label, click mint. Copy `client_id`, `hmac_secret`, `kid`, and `base_url` into `.dev.vars`. The Issuer signs every attestation server-side; your worker authenticates with HMAC and never holds an Ed25519 signing key.

 ```ini
 # .dev.vars (do not commit)
 CLIENT_ID=cl_iss_sandbox_<your minted id>
 HMAC_SECRET=<your minted hmac secret>
 ISSUER_API_URL=https://sandbox-issuer.provii.app
 ```

 The credential expires in 72 hours. Mint a new one when it expires; the playground remembers it in localStorage. For a deployed worker, set the same values via `wrangler secret put`.
2. Enable Sandbox Mode in Provii Wallet: Settings > tap 5 times > toggle Sandbox.

## Common Issues

### "HMAC_SECRET not configured"

The worker requires `CLIENT_ID`, `HMAC_SECRET`, and `ISSUER_API_URL` to be set. For sandbox testing, mint values from the playground (see Sandbox Mode above) and write them to `.dev.vars` for local runs. For production:
1. Get your client ID and HMAC secret from the Provii admin portal at https://admin.provii.app.
2. Set them via `wrangler secret put CLIENT_ID` and `wrangler secret put HMAC_SECRET`.

### Attestation creation fails (4xx/5xx from provii-issuer)

Ensure:
- The canonical message format matches exactly (see `buildCanonicalMessage`)
- The canonical message ends with `:{nonce}` matching the body's `authorizer.nonce`. If you get 401 UNAUTHORIZED, this is the most common cause.
- `key_id` uses snake_case in the canonical message, `keyId` uses camelCase in the request body
- The HMAC secret is base64url-decoded before use as the HMAC key
- The timestamp is current (within ±30 seconds)

### Date parsing issues

The endpoint validates dates like "1990-02-30" by checking the parsed date matches input components. Use YYYY-MM-DD format.
