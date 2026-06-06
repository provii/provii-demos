# Node.js Issuer Backend Integration Guide

This guide shows how to add Provii credential issuance to your Node.js backend.

## Quick Start (5 minutes)

### Option 1: Copy the Core Functions

Copy the HMAC authentication logic from `src/index.ts`:

```typescript
import { createHmac, randomBytes } from 'node:crypto';

// Your credentials from Provii admin portal
const CLIENT_ID = process.env.CLIENT_ID!;
const HMAC_SECRET = process.env.HMAC_SECRET!; // base64url-encoded
const ISSUER_API_URL = process.env.ISSUER_API_URL!;

function base64urlDecode(str: string): Buffer {
 const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
 const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
 return Buffer.from(padded, 'base64');
}

function hmacSha256Hex(secret: Buffer, message: string): string {
 return createHmac('sha256', secret).update(message, 'utf-8').digest('hex');
}

function buildCanonicalMessage(dobDays: number, clientId: string, timestamp: number, nonce: string): string {
 const canonicalJson =
 `{"dob_days":${dobDays},"authorizer":{"format":"client","key_id":"${clientId}","timestamp":${timestamp}}}`;
 return `${timestamp}:POST:/v1/attestation/create:${canonicalJson}:${nonce}`;
}

async function createAttestation(dobDays: number) {
 const timestamp = Math.floor(Date.now / 1000);
 // 256-bit random nonce. The SAME value goes into both the canonical message and the request body.
 const nonce = randomBytes(32).toString('hex');
 const canonicalMessage = buildCanonicalMessage(dobDays, CLIENT_ID, timestamp, nonce);
 const secretBytes = base64urlDecode(HMAC_SECRET);
 const hmacHex = hmacSha256Hex(secretBytes, canonicalMessage);

 const response = await fetch(`${ISSUER_API_URL}/v1/attestation/create`, {
 method: 'POST',
 headers: { 'Content-Type': 'application/json' },
 body: JSON.stringify({
 dob_days: dobDays,
 authorizer: {
 format: 'client',
 keyId: CLIENT_ID,
 timestamp,
 hmac: hmacHex,
 nonce,
 },
 }),
 });

 if (!response.ok) {
 throw new Error(`Issuer API returned ${response.status}: ${await response.text}`);
 }

 return response.json;
}
```

### Option 2: Use as Reference

Run this demo backend and study the flow:

```bash
cd backends/issuer/nodejs
npm install
npm start
```

## Dependencies

No cryptographic dependencies are needed. HMAC-SHA256 is built into Node.js:

```json
{
 "dependencies": {
 "hono": "^4.0.0"
 }
}
```

## API Endpoints

Your backend needs to expose:

| Endpoint | Method | Body | Response |
|----------|--------|------|----------|
| `/api/create-attestation-from-dob` | POST | `{ "dob": "1990-05-15" }` | `{ "deep_link": "https://provii.app/..." }` |
| `/api/create-attestation` | POST | `{ "dob_days": 7000 }` | `{ "deep_link": "https://provii.app/..." }` |

## Environment Variables

```bash
# Required - mint via the playground for sandbox, or via the admin portal for production
CLIENT_ID=your_client_id
HMAC_SECRET=base64url-encoded-hmac-secret
ISSUER_API_URL=https://issuer.provii.app

# Optional
PORT=3000
ALLOWED_ORIGINS=https://yourapp.com,https://admin.yourapp.com
NODE_ENV=production
```

## Flow Diagram

```
Mobile App Your Backend Provii provii-issuer
 │ │ │
 │ POST /create-attestation │ │
 │ { dob: "1990-05-15" } │ │
 │ ────────────────────────►│ │
 │ │ │
 │ │ 1. Convert DOB to days │
 │ │ 2. Build HMAC-SHA256 │
 │ │ canonical message │
 │ │ 3. POST to provii-issuer │
 │ │ ────────────────────────►│
 │ │ │
 │ │ Provii signs attestation│
 │ │ internally (Ed25519) │
 │ │ │
 │ │◄─────────────────────────│
 │ │ {attestation, expires_at}│
 │ │ │
 │◄─────────────────────────│ │
 │ { deep_link: "https://provii.app/attest?d=..." } │
 │ │ │
 │ Opens deep link │ │
 │ ─────────────────────────────────────────────────► │
 │ │ │
 │ │ Wallet generates │
 │ │ r_bits and calls │
 │ │ /v1/issuance/blind │
```

## HMAC Authentication Details

The canonical message format for `/v1/attestation/create`:

```
{timestamp}:POST:/v1/attestation/create:{"dob_days":{dob_days},"authorizer":{"format":"client","key_id":"{client_id}","timestamp":{timestamp}}}:{nonce}
```

**Important:**
- The canonical message uses `key_id` (snake_case). The actual HTTP request body uses `keyId` (camelCase).
- The trailing `{nonce}` is the SAME value sent as `authorizer.nonce` in the request body. Server-side verification recomputes the HMAC using the body's nonce, so the two MUST match. Omitting the nonce (or using a different one) returns 401 UNAUTHORIZED. See `create_canonical_message_for_attestation` in `provii-issuer/src/session.rs`.

## Express.js Example

```typescript
import express from 'express';

const app = express;
app.use(express.json);

app.post('/api/create-attestation-from-dob', async (req, res) => {
 const { dob } = req.body;

 if (!dob || !/^\d{4}-\d{2}-\d{2}$/.test(dob)) {
 return res.status(400).json({ error: 'Invalid dob format' });
 }

 const dobDate = new Date(dob + 'T00:00:00Z');
 const dobDays = Math.floor(dobDate.getTime / (24 * 60 * 60 * 1000));

 try {
 const result = await createAttestation(dobDays);
 const deepLink = `https://provii.app/attest?d=${result.attestation}`;
 res.json({ deep_link: deepLink, expires_at: result.expires_at });
 } catch (error) {
 console.error('Attestation failed:', error);
 res.status(500).json({ error: 'Failed to create attestation' });
 }
});
```

## Hono Example (This Demo)

See `src/index.ts` for a complete Hono implementation with:
- CORS configuration
- Security headers
- Input validation
- Error handling

## Security Considerations

1. **Never expose your HMAC secret** in client-side code or logs
2. **Use HTTPS in production** for all calls to Provii's provii-issuer
3. **Implement rate limiting** to protect against abuse
4. **Validate CORS origins** by setting `ALLOWED_ORIGINS` to your app domains only
5. **Don't log DOB values** on your backend

## Testing

1. Start the backend:
 ```bash
 npm start
 ```

2. Create an attestation:
 ```bash
 curl -X POST http://localhost:3000/api/create-attestation-from-dob \
 -H "Content-Type: application/json" \
 -d '{"dob": "1990-05-15"}'
 ```

3. The response contains a `deep_link` that opens Provii Wallet

## Sandbox Mode

For testing without production credentials:

1. Mint sandbox credentials from the playground UI. Visit https://playground.provii.app, switch to the "Set up an Issuing Party" tab, fill in the issuer label, click mint. Copy `client_id`, `hmac_secret`, `kid`, and `base_url` into your `.env`. The Issuer signs every attestation server-side; your backend authenticates with HMAC and never holds an Ed25519 signing key.

 ```bash
 # .env (do not commit)
 CLIENT_ID=cl_iss_sandbox_<your minted id>
 HMAC_SECRET=<your minted hmac secret>
 ISSUER_API_URL=https://sandbox-issuer.provii.app
 ```

 The credential expires in 72 hours. Mint a new one when it expires; the playground remembers it in localStorage.
2. Enable Sandbox Mode in Provii Wallet: Settings > tap 5 times > toggle Sandbox.

## Common Issues

### "HMAC_SECRET not configured"
Mint sandbox credentials from the playground (https://playground.provii.app, "Set up an Issuing Party" tab) and copy them into `.env`. For production, fetch credentials from the Provii admin portal.

### Attestation creation fails (4xx/5xx from provii-issuer)
Ensure:
- The canonical message format matches exactly (see `buildCanonicalMessage`)
- The canonical message ends with `:{nonce}` matching the body's `authorizer.nonce`. If you get 401 UNAUTHORIZED, this is the most common cause.
- `key_id` uses snake_case in canonical form, `keyId` uses camelCase in the request
- The HMAC secret is base64url-decoded before use as the HMAC key
- The timestamp is current (within ±30 seconds)
