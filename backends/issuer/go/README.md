# Provii Issuing Party backend demo (Go)

Reference implementation of the **mobile app issuance** integration scenario. A third-party issuing party authenticates to Provii's `provii-issuer` with HMAC-SHA256 and requests an Ed25519-signed attestation. Your backend never handles signing keys.

These are the canonical setup steps for a fresh checkout. They have not been end-to-end tested by the content team.

## Requirements

Go 1.21 or newer. Chi handles routing. HMAC-SHA256 is in the standard library.

## Required environment variables

| Variable | Description |
|----------|-------------|
| `CLIENT_ID` | Your issuing party client ID from the admin portal |
| `HMAC_SECRET` | Base64url-encoded HMAC secret |
| `ISSUER_API_URL` | `https://sandbox-issuer.provii.app` for sandbox, `https://issuer.provii.app` for production |

Optional variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `ALLOWED_ORIGINS` | `http://localhost:3000,http://localhost:5173` | Comma-separated CORS allowlist |
| `GO_ENV` | `development` | Set to `production` to emit `Strict-Transport-Security` |
| `DEMO_TOKEN_SECRET` | unset | Production-only HMAC signing secret for the `X-Demo-Token` gate. Leave unset for local dev (validation skips). The deployed CF Worker pulls this from the Cloudflare Secrets Store |

The sandbox-credential auto-fetch fallback was removed in . Missing required variables fail startup.

## Obtain sandbox credentials

1. Sign in at [https://admin.provii.app](https://admin.provii.app) and create a sandbox issuing party client.
2. Copy the `client_id` and the base64url `hmac_secret`.
3. Export them, or put them into `.env`:
4. Verify credentials are working by starting the server and hitting `GET /health`.

 ```bash
 export CLIENT_ID=client_sandbox_xxxxxxxx
 export HMAC_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 export ISSUER_API_URL=https://sandbox-issuer.provii.app
 ```

Sandbox credentials are publicly shared across demo apps. Do not reuse them in production.

The `X-Demo-Token` gate is a production-only protection for the deployed CF Worker (`issuer-demo.provii.app`). When `DEMO_TOKEN_SECRET` is unset, this local backend skips token validation entirely. There is no need to fetch a demo token to run locally.

## Run it

```bash
go mod tidy
go run main.go
```

For a production build:

```bash
go build -o server main.go
./server
```

## Happy-path request

```bash
curl -X POST http://localhost:3000/api/create-attestation-from-dob \
 -H "Content-Type: application/json" \
 -d '{"dob": "1990-05-15"}'
```

The local backend accepts requests without an `X-Demo-Token` header. If you set `DEMO_TOKEN_SECRET` to mirror the production CF Worker, you must send a valid token with each request.

Expected response:

```json
{
 "deep_link": "https://provii.app/attest?d=eyJkb2JfZGF5cyI6...",
 "dob_days": 7439,
 "expires_at": 1735603600
}
```

Open the `deep_link` on a phone that has Provii Wallet installed in sandbox mode. The wallet generates blinding factors locally, calls `provii-issuer` for blind issuance, and stores the credential.

## Endpoints

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/health` | GET | Returns `{ "status": "ok" }` |
| `/api/config` | GET | Returns `client_id` and `issuer_api_url`. No secrets exposed |
| `/api/create-attestation` | POST | Body: `{ "dob_days": <integer, -25000 to 36500> }` |
| `/api/create-attestation-from-dob` | POST | Body: `{ "dob": "YYYY-MM-DD" }` |

## Troubleshooting

**401 from the issuer.** HMAC signature mismatch. Confirm the secret is base64url-decoded before use, the canonical JSON uses `key_id` in snake_case with the request body using `keyId` in camelCase, and the system clock is within ±30 seconds of UTC.

**403 from the issuer.** Client is locked or expired. Yubikey-backed Issuer flows lock after 5 consecutive failed challenge responses and auto-clear after 15 minutes. Otherwise check the admin portal.

**401 with hint about a demo token.** `DEMO_TOKEN_SECRET` is set, so token validation runs and your request is missing or has an invalid `X-Demo-Token` header. For local dev, leave `DEMO_TOKEN_SECRET` unset.

**Connection errors to the issuer.** `ISSUER_API_URL` is wrong or unset. Sandbox credentials will not authenticate against production URLs and vice versa.

## Related docs

- [Issuing Party Sandbox and Testing](https://docs.provii.app/getting-started/sandbox-issuer).
- [Issuing Party Authentication](https://docs.provii.app/getting-started/auth-issuer).
- [Mobile Credential Issuance](https://docs.provii.app/guides/mobile-issuance).
- [Admin Portal](https://admin.provii.app) for managing credentials and monitoring usage.
