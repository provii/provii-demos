# Provii Relying Party backend demo (Cloudflare Workers)

Reference implementation of the **expert verifier** integration scenario, running as a Cloudflare Worker with session state in Workers KV. Your backend authenticates to Provii's `provii-verifier` with HMAC-SHA256 plus a mandatory nonce, manages PKCE, and redeems verified challenges.

This is the Expert setup. If you only need to age-gate a website, use provii-agegate with a `pk_` public key against `provii-verifier` instead. Mobile apps must use the Expert setup because the Simple setup uses browser cookies that do not survive the app-switch into the wallet.

These are the canonical setup steps for a fresh checkout. They have not been end-to-end tested by the content team.

For line-by-line copy and paste of the HMAC and PKCE helpers, see [INTEGRATION.md](./INTEGRATION.md).

## Requirements

Node.js 18 or newer (for the Wrangler CLI) and a Cloudflare account. The Worker runtime provides Web Crypto.

## Required secrets

Set these with `wrangler secret put`:

| Secret | Description |
|--------|-------------|
| `CLIENT_ID` | Relying party client ID from the admin portal |
| `API_KEY` | Relying party API key (sent as `X-API-Key` to provii-verifier) |
| `HMAC_SECRET` | Base64url-encoded HMAC secret |
| `VERIFIER_API_URL` | `https://sandbox-verify.provii.app` for sandbox, `https://verify.provii.app` for production |
| `DEMO_TOKEN_SECRET` | Demo-backend internal token from `https://playground.provii.app/v1/config/demo-token` |

Non-secret vars go in `wrangler.toml`:

```toml
[vars]
ENVIRONMENT = "sandbox"
ALLOWED_ORIGINS = "https://yourapp.com"

[[kv_namespaces]]
binding = "SESSIONS"
id = "your-kv-namespace-id"
```

Create the KV namespace once per environment:

```bash
wrangler kv namespace create SESSIONS
```

Copy the returned id into the `[[kv_namespaces]]` block above.

The sandbox-credential auto-fetch fallback was removed in . A missing secret now fails the Worker fetch handler instead of silently pulling demo credentials.

## Obtain sandbox credentials

1. Sign in at [https://admin.provii.app](https://admin.provii.app) and mint a sandbox relying party client. Copy the `client_id`, `api_key`, and `hmac_secret`.
2. Fetch a demo token from `https://playground.provii.app/v1/config/demo-token`.
3. Push each value with `wrangler secret put`:
4. Verify credentials are working by running `wrangler dev` and hitting the `/health` endpoint.

 ```bash
 wrangler secret put CLIENT_ID
 wrangler secret put API_KEY
 wrangler secret put HMAC_SECRET
 wrangler secret put VERIFIER_API_URL
 wrangler secret put DEMO_TOKEN_SECRET
 ```

For local dev, put them into `.dev.vars` next to `wrangler.toml`:

```bash
CLIENT_ID=rp_sandbox_xxxxxxxx
API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
HMAC_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
VERIFIER_API_URL=https://sandbox-verify.provii.app
DEMO_TOKEN_SECRET=<value from the demo-token endpoint>
```

Sandbox credentials are publicly shared across demo apps.

## Run it

```bash
npm install
wrangler dev
```

Local dev runs on `http://localhost:8787`. Deploy with:

```bash
wrangler deploy
```

Use `wrangler deploy --env sandbox` if your `wrangler.toml` declares a `[env.sandbox]` block with its own KV namespace id.

## Happy-path request

```bash
curl -X POST http://localhost:8787/api/create-challenge \
 -H "Content-Type: application/json" \
 -H "X-Demo-Token: $DEMO_TOKEN_SECRET" \
 -d '{"minimum_age": 21}'
```

Expected response:

```json
{
 "session_id": "550e8400-e29b-41d4-a716-446655440000",
 "deep_link": "https://provii.app/verify?d=eyJjaGFsbGVuZ2VfaWQiOi...",
 "expires_at": 1735600300,
 "status_url": "/api/status/550e8400-e29b-41d4-a716-446655440000"
}
```

Open the `deep_link` on a phone with Provii Wallet in sandbox mode. Poll `/api/status/:sessionId` every 2 to 3 seconds, then `POST /api/redeem/:sessionId` when status is `verified`.

## Endpoints

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/health` | GET | Returns `{ "status": "ok", "configured": true }` |
| `/api/config` | GET | Returns `verifier_api_url`, `client_id`. No secrets exposed |
| `/api/create-challenge` | POST | Body: `{ "minimum_age": 13-120, "expires_in": 60-300 }` |
| `/api/status/:sessionId` | GET | States: `pending`, `verified`, `expired`, `failed` |
| `/api/redeem/:sessionId` | POST | Completes PKCE with the stored `code_verifier` |

## Troubleshooting

**"HMAC_SECRET not configured" in the Worker log.** One of the required secrets is missing. Re-run `wrangler secret put` or update `.dev.vars`.

**401 from provii-verifier.** HMAC verification failed. Canonical payload field order must be `code_challenge`, `method`, `verifying_key_id`, `expires_in`. The `verifying_key_id` key must appear even when `null`. Nonce must be unique per request. Clock tolerance is ±300 seconds.

**403 from provii-verifier.** `Origin` header not registered, or `API_KEY` missing. Sandbox skips origin checks; production enforces them.

**404 on status or redeem.** Session not found in KV. Sessions expire `expires_in + 60 seconds` after creation, and the `SESSIONS` KV binding may be misconfigured. Confirm the binding id in `wrangler.toml` matches what `wrangler kv namespace list` reports.

**500 on every request.** `DEMO_TOKEN_SECRET` is not set.

**CORS errors.** Add your frontend origin to `ALLOWED_ORIGINS` in `wrangler.toml`.

**`TOO_MANY_REDEMPTION_ATTEMPTS`.** After 3 failed redemptions the session is unrecoverable. Create a fresh challenge.

## Related docs

- [Relying Party Sandbox and Testing](https://docs.provii.app/getting-started/sandbox-verifier).
- [Relying Party Authentication](https://docs.provii.app/getting-started/auth-verifier).
- [HMAC Canonical Message](https://docs.provii.app/reference/hmac-canonical-message).
- [Rate Limits and Quotas](https://docs.provii.app/reference/rate-limits).
- [INTEGRATION.md](./INTEGRATION.md) in this directory for copy-and-paste HMAC and PKCE helpers.
