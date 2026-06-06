# Provii Issuing Party backend demo (Python, FastAPI)

Reference implementation of the **mobile app issuance** integration scenario. A third-party issuing party authenticates to Provii's `provii-issuer` with HMAC-SHA256 and requests an Ed25519-signed attestation. Your backend never handles signing keys.

These are the canonical setup steps for a fresh checkout. They have not been end-to-end tested by the content team.

## Requirements

Python 3.10 or newer. FastAPI, Uvicorn, Pydantic, and httpx are pinned in `requirements.txt`. HMAC-SHA256 is in the standard library.

## Required environment variables

| Variable | Description |
|----------|-------------|
| `CLIENT_ID` | Issuing party client ID from the admin portal |
| `HMAC_SECRET` | Base64url-encoded HMAC secret |
| `ISSUER_API_URL` | `https://sandbox-issuer.provii.app` for sandbox, `https://issuer.provii.app` for production |

Optional variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `ALLOWED_ORIGINS` | `http://localhost:3000,http://localhost:5173` | Comma-separated CORS allowlist |
| `PYTHON_ENV` | `development` | When `production`, expect a reverse proxy to add HSTS |
| `DEMO_TOKEN_SECRET` | unset | Production-only HMAC signing secret for the `X-Demo-Token` gate. Leave unset for local dev (validation skips). The deployed CF Worker pulls this from the Cloudflare Secrets Store |

The sandbox-credential auto-fetch fallback was removed in . Missing required variables fail startup.

## Obtain sandbox credentials

1. Create a sandbox issuing party client in the admin portal at [https://admin.provii.app](https://admin.provii.app).
2. Copy the `client_id` and the base64url `hmac_secret`.
3. Populate a `.env` file or export the variables in your shell:
4. Verify credentials are working by starting the server and hitting `GET /health`.

 ```bash
 export CLIENT_ID=client_sandbox_xxxxxxxx
 export HMAC_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 export ISSUER_API_URL=https://sandbox-issuer.provii.app
 ```

Sandbox credentials are publicly shared across every demo app. Do not reuse them in production.

The `X-Demo-Token` gate is a production-only protection for the deployed CF Worker (`issuer-demo.provii.app`). When `DEMO_TOKEN_SECRET` is unset, this local backend skips token validation entirely. There is no need to fetch a demo token to run locally.

## Run it

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

Or run uvicorn directly:

```bash
python -m uvicorn main:app --host 0.0.0.0 --port 3000
```

For production, use a Gunicorn worker pool behind HTTPS:

```bash
gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app
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

Open the `deep_link` on a phone that has Provii Wallet installed in sandbox mode. Interactive OpenAPI docs live at `http://localhost:3000/docs`.

## Endpoints

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/health` | GET | Returns `{ "status": "ok" }` |
| `/api/config` | GET | Returns `client_id` and `issuer_api_url`. No secrets exposed |
| `/api/create-attestation` | POST | Body: `{ "dob_days": <integer, -25000 to 36500> }` |
| `/api/create-attestation-from-dob` | POST | Body: `{ "dob": "YYYY-MM-DD" }` |
| `/docs` | GET | Swagger UI |

## Troubleshooting

**401 from the issuer.** HMAC verification failed. Confirm `HMAC_SECRET` is base64url-decoded before the HMAC call, the canonical payload uses `key_id` (snake_case) while the request body uses `keyId` (camelCase), and the system clock is within ±30 seconds of UTC.

**403 from the issuer.** Client is locked or expired. Yubikey-backed Issuer flows lock after 5 consecutive failed challenges and auto-clear after 15 minutes. Otherwise check the admin portal.

**401 with hint about a demo token.** `DEMO_TOKEN_SECRET` is set, so token validation runs and your request is missing or has an invalid `X-Demo-Token` header. For local dev, leave `DEMO_TOKEN_SECRET` unset.

**Connection errors to the issuer.** `ISSUER_API_URL` is wrong or unset. Sandbox credentials cannot be used against production URLs and vice versa.

## Related docs

- [Issuing Party Sandbox and Testing](https://docs.provii.app/getting-started/sandbox-issuer).
- [Issuing Party Authentication](https://docs.provii.app/getting-started/auth-issuer).
- [Mobile Credential Issuance](https://docs.provii.app/guides/mobile-issuance).
- [Admin Portal](https://admin.provii.app) for managing credentials and monitoring usage.
