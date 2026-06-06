# Provii Issuing Party backend demo (Node.js)

Reference implementation of the **mobile app issuance** integration scenario. A third-party issuing party (bank, telco, identity provider) authenticates to Provii's `provii-issuer` with HMAC-SHA256 and requests an Ed25519-signed attestation. Your backend never handles signing keys.

These are the canonical setup steps for a fresh checkout. They have not been end-to-end tested by the content team.

## Requirements

Node.js 18 or newer. The backend uses the native `crypto` and `fetch` APIs.

## Required environment variables

| Variable | Description |
|----------|-------------|
| `CLIENT_ID` | Your issuing party client ID, minted in the admin portal |
| `HMAC_SECRET` | Base64url-encoded HMAC secret, minted alongside the client ID |
| `ISSUER_API_URL` | Issuer base URL, `https://sandbox-issuer.provii.app` for sandbox or `https://issuer.provii.app` for production |

Optional variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `ALLOWED_ORIGINS` | `http://localhost:3000,http://localhost:5173` | Comma-separated CORS allowlist |
| `NODE_ENV` | `development` | Set to `production` to emit `Strict-Transport-Security` on every response |
| `DEMO_TOKEN_SECRET` | unset | Production-only HMAC signing secret for the `X-Demo-Token` gate. Leave unset for local dev (validation skips). The deployed CF Worker pulls this from the Cloudflare Secrets Store |

The sandbox-credential auto-fetch fallback was removed in . A missing `CLIENT_ID`, `HMAC_SECRET`, or `ISSUER_API_URL` now fails startup instead of silently pulling demo credentials at runtime.

## Obtain sandbox credentials

1. Sign in to the Provii admin portal at [https://admin.provii.app](https://admin.provii.app).
2. Create a sandbox issuing party client. The portal issues a `client_id` and a base64url `hmac_secret`. Copy both.
3. Put them into a `.env` file next to `package.json`:
4. Verify credentials are working by starting the server and hitting `GET /health`.

 ```bash
 CLIENT_ID=client_sandbox_xxxxxxxx
 HMAC_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 ISSUER_API_URL=https://sandbox-issuer.provii.app
 ```

Sandbox credentials are publicly shared across demo apps, so treat any testing you do as visible to others. For production, generate unique credentials and store the HMAC secret in a secrets manager.

The `X-Demo-Token` gate is a production-only protection for the deployed CF Worker (`issuer-demo.provii.app`). When `DEMO_TOKEN_SECRET` is unset, this local backend skips token validation entirely. There is no need to fetch a demo token to run locally.

## Run it

```bash
npm install
npm run dev
```

The server binds to `http://localhost:3000`. In production mode:

```bash
npm install
npm run build
npm start
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

Open the `deep_link` in a phone that has Provii Wallet installed in sandbox mode. The wallet generates `r_bits` locally, calls `provii-issuer` for blind issuance, and stores the resulting credential.

## Endpoints

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/health` | GET | Returns `{ "status": "ok" }` |
| `/api/config` | GET | Returns `client_id` and `issuer_api_url`. No secrets exposed |
| `/api/create-attestation` | POST | Body: `{ "dob_days": <integer, -25000 to 36500> }` |
| `/api/create-attestation-from-dob` | POST | Body: `{ "dob": "YYYY-MM-DD" }` |

## Troubleshooting

Most failures fall into a small handful of categories.

**401 from the issuer.** The HMAC signature does not verify. Check that `HMAC_SECRET` is base64url-decoded before use, the canonical message uses `key_id` in snake_case while the request body uses `keyId` in camelCase, and your system clock is within ±30 seconds of wall time (the Issuer tolerance is tighter than the Verifier's).

**403 from the issuer.** The client ID is valid but the account is locked or the credential is expired. Check the admin portal. Yubikey-backed Issuer flows lock after 5 consecutive failed challenge responses and auto-clear after 15 minutes.

**401 with hint about a demo token.** `DEMO_TOKEN_SECRET` is set, so token validation runs and your request is missing or has an invalid `X-Demo-Token` header. For local dev, leave `DEMO_TOKEN_SECRET` unset. For production, the deployed CF Worker pulls the secret from the Cloudflare Secrets Store; clients must send the matching HMAC token.

**Network error calling the issuer.** `ISSUER_API_URL` is wrong or unset. Sandbox is `https://sandbox-issuer.provii.app`. Do not point production credentials at a sandbox URL or vice versa.

## Related docs

- [Issuing Party Sandbox and Testing](https://docs.provii.app/getting-started/sandbox-issuer) for the end-to-end walkthrough, demo customer fixtures, and wallet sandbox mode.
- [Issuing Party Authentication](https://docs.provii.app/getting-started/auth-issuer) for HMAC canonical message details.
- [Mobile Credential Issuance](https://docs.provii.app/guides/mobile-issuance) for the full attestation plus deep-link flow.
- [Admin Portal](https://admin.provii.app) for managing credentials and monitoring usage.
