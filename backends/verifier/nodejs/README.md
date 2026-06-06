# Provii Relying Party backend demo (Node.js)

Reference implementation of the **expert verifier** integration scenario. Your backend authenticates to Provii's `provii-verifier` with HMAC-SHA256 plus a mandatory nonce, manages PKCE, stores session state, and redeems verified challenges. Works for both mobile apps and websites that need full control over the verification flow.

This is the Expert setup, not the Simple setup. The Simple setup uses provii-agegate with a `pk_` public key against `provii-verifier`. If you are just age-gating a website and want minimal integration effort, you do not need this backend at all.

These are the canonical setup steps for a fresh checkout. They have not been end-to-end tested by the content team.

## Requirements

Node.js 18 or newer. The backend uses the native `crypto.getRandomValues` and `fetch` APIs.

## Required environment variables

| Variable | Description |
|----------|-------------|
| `CLIENT_ID` | Relying party client ID from the admin portal |
| `API_KEY` | Relying party API key (sent as `X-API-Key` to provii-verifier) |
| `HMAC_SECRET` | Base64url-encoded HMAC secret |
| `VERIFIER_API_URL` | `https://sandbox-verify.provii.app` for sandbox, `https://verify.provii.app` for production |

Optional variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | Server port |
| `ALLOWED_ORIGINS` | `http://localhost:3000,http://localhost:5173` | Comma-separated CORS allowlist |
| `NODE_ENV` | `development` | Set to `production` to emit `Strict-Transport-Security` |
| `DEMO_TOKEN_SECRET` | unset | Production-only HMAC signing secret for the `X-Demo-Token` gate. Leave unset for local dev (validation skips). The deployed CF Worker pulls this from the Cloudflare Secrets Store |

The sandbox-credential auto-fetch fallback was removed in . A missing required variable now fails startup instead of silently pulling demo credentials.

## Obtain sandbox credentials

1. Sign in at [https://admin.provii.app](https://admin.provii.app) and create a sandbox relying party client.
2. Copy the `client_id`, `api_key`, and `hmac_secret`. The admin portal shows the HMAC secret exactly once; save it to a password manager.
3. Put them into `.env`:
4. Verify credentials are working by starting the server and hitting `GET /health`.

 ```bash
 CLIENT_ID=rp_sandbox_xxxxxxxx
 API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 HMAC_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 VERIFIER_API_URL=https://sandbox-verify.provii.app
 ```

Sandbox credentials are publicly shared across demo apps and have no origin restrictions in the sandbox tenant. Do not reuse them in production.

The `X-Demo-Token` gate is a production-only protection for the deployed CF Worker (`verifier-demo.provii.app`). When `DEMO_TOKEN_SECRET` is unset, this local backend skips token validation entirely. There is no need to fetch a demo token to run locally.

## Run it

```bash
npm install
npm run dev
```

The server binds to `http://localhost:3001`. For a production build:

```bash
npm install
npm run build
npm start
```

## Happy-path request

```bash
curl -X POST http://localhost:3001/api/create-challenge \
 -H "Content-Type: application/json" \
 -d '{"minimum_age": 21}'
```

The local backend accepts requests without an `X-Demo-Token` header. If you set `DEMO_TOKEN_SECRET` to mirror the production CF Worker, you must send a valid token with each request to the Hardcore endpoints (`/api/create-challenge`, `/api/status/:sessionId`, `/api/redeem/:sessionId`). The Expert proxy endpoints (`/api/challenge`, `/api/poll`, `/api/redeem`, `/api/session`) never require the demo token because they authenticate via HMAC to provii-verifier.

Expected response:

```json
{
 "session_id": "550e8400-e29b-41d4-a716-446655440000",
 "deep_link": "https://provii.app/verify?d=eyJjaGFsbGVuZ2VfaWQiOi...",
 "expires_at": 1735603600,
 "status_url": "/api/status/550e8400-e29b-41d4-a716-446655440000"
}
```

Open the `deep_link` on a phone that has Provii Wallet in sandbox mode. Poll `/api/status/:sessionId` every 2 to 3 seconds. When it returns `{"state": "verified"}`, call `POST /api/redeem/:sessionId` to complete the PKCE flow.

## Endpoints

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/health` | GET | Returns `{ "status": "ok", "configured": true }` |
| `/api/config` | GET | Returns `verifier_api_url`, `client_id`, and boolean flags. No secrets exposed |
| `/api/create-challenge` | POST | Body: `{ "minimum_age": 13-120, "expires_in": 60-300 }` |
| `/api/status/:sessionId` | GET | Returns `state` (`pending`, `verified`, `expired`, `failed`) |
| `/api/redeem/:sessionId` | POST | Completes PKCE, returns `{ "result": "verified" }` |

## Troubleshooting

**401 from provii-verifier on challenge creation.** HMAC verification failed. Check that `HMAC_SECRET` is base64url-decoded before use, the canonical payload fields appear in the exact order `code_challenge`, `method`, `verifying_key_id`, `expires_in` (the `verifying_key_id` field must be present even if `null`), and the `nonce` inside the `authorizer` object is unique for each request. The system clock must be within ±300 seconds of UTC.

**403 from provii-verifier.** The `Origin` header does not match a registered origin on the relying party credential, or the `API_KEY` header is missing or wrong. Origin validation is production-only for relying party credentials; sandbox skips the check.

**404 on status or redeem.** The session expired. Sessions live for `expires_in + 60 seconds`. Create a fresh challenge.

**401 with hint about a demo token.** `DEMO_TOKEN_SECRET` is set, so token validation runs and your request is missing or has an invalid `X-Demo-Token` header. For local dev, leave `DEMO_TOKEN_SECRET` unset. The deployed CF Worker pulls the secret from the Cloudflare Secrets Store; clients must send the matching HMAC token.

**`TOO_MANY_REDEMPTION_ATTEMPTS`.** After 3 failed redemptions the session is unrecoverable. Mint a fresh challenge rather than retrying.

## Related docs

- [Relying Party Sandbox and Testing](https://docs.provii.app/getting-started/sandbox-verifier) for the end-to-end walkthrough.
- [Relying Party Authentication](https://docs.provii.app/getting-started/auth-verifier) for HMAC and PKCE details.
- [HMAC Canonical Message](https://docs.provii.app/reference/hmac-canonical-message) for the byte-for-byte layout.
- [Rate Limits and Quotas](https://docs.provii.app/reference/rate-limits).
