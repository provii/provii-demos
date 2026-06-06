# Provii Issuing Party backend demo (Cloudflare Workers)

Reference implementation of the **mobile app issuance** integration scenario, running as a Cloudflare Worker. A third-party issuing party authenticates to Provii's `provii-issuer` with HMAC-SHA256 and requests an Ed25519-signed attestation. Your backend never handles signing keys.

These are the canonical setup steps for a fresh checkout. They have not been end-to-end tested by the content team.

For line-by-line copy and paste of the HMAC helpers, see [INTEGRATION.md](./INTEGRATION.md).

## Requirements

Node.js 18 or newer (for the Wrangler CLI) and a Cloudflare account. The Worker runtime provides the Web Crypto API; no additional cryptographic dependencies are needed.

## Required secrets

Set these with `wrangler secret put` for each environment you deploy to:

| Secret | Description |
|--------|-------------|
| `CLIENT_ID` | Issuing party client ID from the admin portal |
| `HMAC_SECRET` | Base64url-encoded HMAC secret |
| `ISSUER_API_URL` | `https://sandbox-issuer.provii.app` for sandbox, `https://issuer.provii.app` for production |
| `DEMO_TOKEN_SECRET` | Demo-backend internal token from `https://playground.provii.app/v1/config/demo-token` |

Non-secret vars can go in `wrangler.toml` under `[vars]`:

```toml
[vars]
ENVIRONMENT = "sandbox"
ALLOWED_ORIGINS = "https://yourapp.com,https://admin.yourapp.com"
```

The sandbox-credential auto-fetch fallback was removed in . A missing secret now fails the Worker fetch handler with HTTP 500 instead of silently pulling demo credentials.

## Obtain sandbox credentials

1. Sign in to the Provii admin portal at [https://admin.provii.app](https://admin.provii.app) and mint a sandbox issuing party client. Copy the `client_id` and the base64url `hmac_secret`.
2. Fetch a demo token from `https://playground.provii.app/v1/config/demo-token`.
3. Push each value with `wrangler secret put`:
4. Verify credentials are working by running `wrangler dev` and hitting the `/health` endpoint.

 ```bash
 wrangler secret put CLIENT_ID
 wrangler secret put HMAC_SECRET
 wrangler secret put ISSUER_API_URL
 wrangler secret put DEMO_TOKEN_SECRET
 ```

For local development, put them into `.dev.vars` next to `wrangler.toml` (gitignored):

```bash
CLIENT_ID=client_sandbox_xxxxxxxx
HMAC_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ISSUER_API_URL=https://sandbox-issuer.provii.app
DEMO_TOKEN_SECRET=<value from the demo-token endpoint>
```

Sandbox credentials are publicly shared across demo apps. Do not reuse them in production.

## Run it

```bash
npm install
wrangler dev
```

Local dev runs on `http://localhost:8787`. To deploy:

```bash
wrangler deploy
```

Use `wrangler deploy --env sandbox` if your `wrangler.toml` declares a `[env.sandbox]` block.

## Happy-path request

```bash
curl -X POST http://localhost:8787/api/create-attestation-from-dob \
 -H "Content-Type: application/json" \
 -H "X-Demo-Token: $DEMO_TOKEN_SECRET" \
 -d '{"dob": "1990-05-15"}'
```

Expected response:

```json
{
 "deep_link": "https://provii.app/attest?d=eyJkb2JfZGF5cyI6...",
 "expires_at": 1735603600
}
```

Open the `deep_link` on a phone that has Provii Wallet installed in sandbox mode.

## Endpoints

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/health` | GET | Returns `{ "status": "ok" }` |
| `/api/config` | GET | Returns `client_id` and `issuer_api_url`. No secrets exposed |
| `/api/create-attestation` | POST | Body: `{ "dob_days": <int> }` |
| `/api/create-attestation-from-dob` | POST | Body: `{ "dob": "YYYY-MM-DD" }` |

## Troubleshooting

**"HMAC_SECRET not configured" in the Worker log.** One of the required secrets is missing. Re-run `wrangler secret put` for each, or populate `.dev.vars` for local dev.

**401 from the issuer.** HMAC verification failed. Confirm the secret is base64url-decoded before use, the canonical message uses `key_id` in snake_case with the request body using `keyId` in camelCase, and the Worker's `Date.now` is within ±30 seconds of UTC. Clock drift is rare on Workers but worth checking if you use a wall-clock mock.

**403 from the issuer.** Client is locked or expired. Check the admin portal.

**500 on every request.** `DEMO_TOKEN_SECRET` is not set.

**Connection errors to the issuer.** `ISSUER_API_URL` is wrong or unset. Sandbox credentials cannot be used against production URLs and vice versa.

## Related docs

- [Issuing Party Sandbox and Testing](https://docs.provii.app/getting-started/sandbox-issuer).
- [Issuing Party Authentication](https://docs.provii.app/getting-started/auth-issuer).
- [Mobile Credential Issuance](https://docs.provii.app/guides/mobile-issuance).
- [INTEGRATION.md](./INTEGRATION.md) in this directory for copy-and-paste HMAC helpers.
