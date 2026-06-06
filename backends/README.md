# Provii Backend Demo Implementations

Reference implementations showing how third-party companies integrate with Provii's age verification system.

## Directory Structure

```
backends/
├── issuer/ # For banks, identity providers
│ ├── nodejs/
│ ├── go/
│ └── python/
└── verifier/ # For social media, age-gated sites
 ├── nodejs/
 ├── go/
 └── python/
```

## Two Integration Patterns

### 1. Issuer Backend (Banks, Identity Providers)

For organisations that want to issue age credentials to their customers using the **blind attestation flow**.

```
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Mobile App │ │ Your Backend │ │ provii-issuer │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
 │ │ │
 1. Send customer DOB ───────────▶│ │
 │ │ │
 │ 2. Create attestation │
 │ (dob, issuer_id, │
 │ timestamp, nonce) │
 │ │ │
 │ 3. Sign with Ed25519 │
 │ private key │
 │ │ │
 4. Receive deep link ◀───────────│ │
 (https://provii.app/attest?d=...) │ │
 │ │ │
 5. Open Provii Wallet ───────────┼──────────────────────────▶│
 │ │ 6. Wallet sends │
 │ │ attestation for │
 │ │ verification │
 │ │ │
 │ │ 7. provii-issuer verifies│
 │ │ Ed25519 signature │
 │ │ and issues cred │
```

**Key endpoint:** `POST /api/create-attestation`

### 2. Verifier Backend (Social Media, Age-Gated Sites)

For organisations that want to verify a user is above a certain age using **PKCE + HMAC authentication**.

```
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Mobile App │ │ Your Backend │ │ provii-verifier │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
 │ │ │
 1. Request verification ────────▶│ │
 │ │ │
 │ 2. Generate PKCE: │
 │ - code_verifier (secret) │
 │ - code_challenge (hash) │
 │ │ │
 │ 3. Create challenge with │
 │ HMAC auth + code_challenge ─────▶│
 │ │ │
 │ 4. Store code_verifier │
 │ (linked to session_id) │
 │ │ │
 5. Receive deep link ◀───────────│ │
 (https://provii.app/verify?d=...) │ │
 │ │ │
 6. Open Provii Wallet │ │
 (User creates ZK proof) ──────┼──────────────────────────▶│
 │ │ 7. Wallet submits │
 │ │ ZK proof │
 │ │ │
 8. Poll for status ─────────────▶│ │
 │ 9. Check status ──────────────────▶ │
 │ │ │
 10. When verified, call redeem ──▶│ │
 │ 11. Redeem with code_verifier ──────▶│
 │ │ │
 12. Receive confirmation ◀────────│◀──────────────────────────│
```

**Key endpoints:** `POST /api/create-challenge`, `GET /api/status/:sessionId`, `POST /api/redeem/:sessionId`

**Key points:**
- Your backend generates PKCE `code_verifier` and keeps it secret.
- Only the `code_challenge` (SHA-256 hash) is sent to provii-verifier.
- HMAC authentication proves your backend's identity.
- The wallet submits a ZK proof directly to provii-verifier.
- Your backend redeems with `code_verifier` to complete the flow.

## Getting Sandbox Credentials

Both flows now mint per-developer sandbox credentials through the playground UI at https://playground.provii.app. The old `/v1/config/{verifier,issuer}-credentials` endpoints have been removed.

### Verifier credentials

Mint sandbox credentials from the playground UI. Visit https://playground.provii.app, switch to the "Set up a Verifier" tab, fill in the policy form, click mint. Copy `client_id`, `api_key`, `hmac_secret`, and `base_url` into your `.env`:

```bash
# .env (do not commit)
CLIENT_ID=rp_sandbox_<your minted id>
API_KEY=<your minted api key>
HMAC_SECRET=<your minted hmac secret>
VERIFIER_API_URL=https://sandbox-verify.provii.app
```

The credential expires in 72 hours. Mint a new one when it expires; the playground remembers it in localStorage so reloading does not lose it.

### Issuer credentials

Mint sandbox credentials from the playground UI. Visit https://playground.provii.app, switch to the "Set up an Issuing Party" tab, fill in the issuer label, click mint. Copy `client_id`, `hmac_secret`, `kid`, and `base_url` into your `.env`. The Issuer signs every attestation server-side; your backend authenticates with HMAC and never holds an Ed25519 signing key.

```bash
# .env (do not commit)
CLIENT_ID=cl_iss_sandbox_<your minted id>
HMAC_SECRET=<your minted hmac secret>
ISSUER_KID=iss_sbx_<your minted kid>
ISSUER_API_URL=https://sandbox-issuer.provii.app
```

The credential expires in 72 hours. Mint a new one when it expires; the playground remembers it in localStorage.

### Production credentials

For production, sign in to the Provii admin portal at https://admin.provii.app, create a long-lived client, and store the secrets in your secrets manager. The same variable names apply.

## Quick Start

### Issuer Backend (Node.js)

```bash
cd issuer/nodejs
npm install
# populate .env using the issuer flow above
npm run dev
```

Test:
```bash
# Using dob_days (days since Unix epoch)
curl -X POST http://localhost:3000/api/create-attestation \
 -H "Content-Type: application/json" \
 -d '{"dob_days": 7000}'

# Using date string
curl -X POST http://localhost:3000/api/create-attestation-from-dob \
 -H "Content-Type: application/json" \
 -d '{"dob": "1990-05-15"}'
```

Response:
```json
{
 "deep_link": "https://provii.app/attest?d=...",
 "attestation": {
 "dob_days": 7000,
 "issuer_id": "did:provii:demo-sandbox",
 "timestamp": 1735776000,
 "nonce": "abc123...",
 "signature": "def456..."
 },
 "expires_at": 1735779600
}
```

### Verifier Backend (Node.js)

```bash
cd verifier/nodejs
npm install
# populate .env using the verifier flow above
npm run dev
```

Test:
```bash
# Create a verification challenge
curl -X POST http://localhost:3001/api/create-challenge \
 -H "Content-Type: application/json" \
 -d '{"minimum_age": 21}'
```

Response:
```json
{
 "session_id": "550e8400-e29b-41d4-a716-446655440000",
 "deep_link": "https://provii.app/verify?d=...",
 "expires_at": 1735779600,
 "status_url": "/api/status/550e8400-e29b-41d4-a716-446655440000"
}
```

Check status:
```bash
curl http://localhost:3001/api/status/<session_id>
```

Redeem after verification:
```bash
curl -X POST http://localhost:3001/api/redeem/<session_id>
```

## HMAC Authentication (Verifier)

The provii-verifier requires HMAC-SHA256 authentication. The canonical message format is 5 colon-separated fields:

```
{timestamp}:POST:/v1/challenge:{json_payload_without_authorizer}:{nonce}
```

Example:
```typescript
const timestamp = Math.floor(Date.now / 1000);
const nonce = crypto.randomBytes(32).toString('hex');

// IMPORTANT: Canonical payload does NOT include authorizer
const payloadForHmac = {
 code_challenge: codeChallenge,
 method: 'S256',
 verifying_key_id: null,
 expires_in: 300,
};
const canonicalMessage = `${timestamp}:POST:/v1/challenge:${JSON.stringify(payloadForHmac)}:${nonce}`;
const hmac = createHmacSignature(canonicalMessage, hmacSecret);

// Full payload includes authorizer with nonce
const fullPayload = {
 ...payloadForHmac,
 authorizer: { keyId: clientId, timestamp, nonce, hmac },
};
```

## PKCE Flow (Verifier)

PKCE (Proof Key for Code Exchange) ensures only your backend can redeem a verified challenge:

1. Generate `code_verifier` (43-128 random base64url characters).
2. Compute `code_challenge = base64url(SHA256(code_verifier))`.
3. Send `code_challenge` to provii-verifier (keep `code_verifier` secret).
4. After user verifies, redeem with `code_verifier`.

```typescript
function generateCodeVerifier: string {
 const bytes = new Uint8Array(32);
 crypto.getRandomValues(bytes);
 return base64urlEncode(bytes);
}

async function generateCodeChallenge(codeVerifier: string): Promise<string> {
 const hash = await crypto.subtle.digest('SHA-256',
 new TextEncoder.encode(codeVerifier));
 return base64urlEncode(new Uint8Array(hash));
}
```

## Security Notes

| Concern | Guidance |
|---------|---------|
| Credential storage | Never commit credentials to version control. Use environment variables or a secrets manager. |
| Ed25519 private keys | Only shown once at creation. Store them in your secrets manager immediately. |
| HMAC secrets | Only shown once at creation. Store them alongside your private keys. |
| PKCE code_verifier | Must stay on your backend. Never send it to the client or log it. |
| Transport security | Use HTTPS/TLS for all production traffic. The demo backends run plain HTTP for local development only. |

## Production Deployment

1. Set up secure credential storage (e.g. secrets manager).
2. Configure HTTPS/TLS.
3. Replace in-memory session storage with Redis or a database.
4. Set up logging and monitoring.
5. Configure rate limiting.
6. Deploy behind a reverse proxy.

## Attestation Format (Issuer)

The signed attestation matches the `DobAttestation` format:

```json
{
 "dob_days": 7000,
 "issuer_id": "did:provii:example",
 "timestamp": 1735776000,
 "nonce": "64-hex-chars-random",
 "signature": "128-hex-chars-ed25519-signature"
}
```

The signature is computed over:
```
Blake2s256(
 "provii.attestation.dob.v1" ||
 dob_days (4 bytes LE) ||
 issuer_id_len (1 byte) ||
 issuer_id (UTF-8) ||
 timestamp (8 bytes LE) ||
 nonce (32 bytes)
)
```

The wallet sends this to `provii-issuer` which verifies the signature using the registered public key.
