# Provii Relying Party backend demo (Python, FastAPI)

Reference implementation of the **expert verifier** integration scenario. Your backend authenticates to Provii's `provii-verifier` with HMAC-SHA256 plus a mandatory nonce, manages PKCE, stores session state, and redeems verified challenges.

This is the Expert setup. If you only need to age-gate a website, use provii-agegate with a `pk_` public key against `provii-verifier` instead.

These are the canonical setup steps for a fresh checkout. They have not been end-to-end tested by the content team.

## Requirements

Python 3.10 or newer. FastAPI, Uvicorn, Pydantic, and httpx are pinned in `requirements.txt`.

## Required environment variables

| Variable | Description |
|----------|-------------|
| `CLIENT_ID` | Relying party client ID from the admin portal |
| `API_KEY` | Relying party API key (`X-API-Key` header) |
| `HMAC_SECRET` | Base64url-encoded HMAC secret |
| `VERIFIER_API_URL` | `https://sandbox-verify.provii.app` for sandbox, `https://verify.provii.app` for production |

Optional variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | Server port |
| `ALLOWED_ORIGINS` | `http://localhost:3000,http://localhost:5173` | Comma-separated CORS allowlist |
| `PYTHON_ENV` | `development` | When `production`, expect a reverse proxy to add HSTS |
| `DEMO_TOKEN_SECRET` | unset | Production-only HMAC signing secret for the `X-Demo-Token` gate. Leave unset for local dev (validation skips). The deployed CF Worker pulls this from the Cloudflare Secrets Store |

The sandbox-credential auto-fetch fallback was removed in . Missing required variables fail startup.

## Obtain sandbox credentials

1. Create a sandbox relying party client at [https://admin.provii.app](https://admin.provii.app). Copy the `client_id`, `api_key`, and `hmac_secret`.
2. Populate `.env` or your shell:

 ```bash
 export CLIENT_ID=rp_sandbox_xxxxxxxx
 export API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 export HMAC_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 export VERIFIER_API_URL=https://sandbox-verify.provii.app
 ```

Sandbox credentials are publicly shared across demo apps.

The `X-Demo-Token` gate is a production-only protection for the deployed CF Worker (`verifier-demo.provii.app`). When `DEMO_TOKEN_SECRET` is unset, this local backend skips token validation entirely. There is no need to fetch a demo token to run locally.

## Run it

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

Or directly via uvicorn:

```bash
python -m uvicorn main:app --host 0.0.0.0 --port 3001
```

Production with Gunicorn:

```bash
gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app
```

## Happy-path request

```bash
curl -X POST http://localhost:3001/api/create-challenge \
 -H "Content-Type: application/json" \
 -d '{"minimum_age": 21}'
```

The local backend accepts requests without an `X-Demo-Token` header. If you set `DEMO_TOKEN_SECRET` to mirror the production CF Worker, you must send a valid token with each request to the Hardcore endpoints. The Expert proxy endpoints (`/api/challenge`, `/api/poll`, `/api/redeem`, `/api/session`) never require the demo token because they authenticate via HMAC to provii-verifier.

Expected response:

```json
{
 "session_id": "550e8400-e29b-41d4-a716-446655440000",
 "deep_link": "https://provii.app/verify?d=eyJjaGFsbGVuZ2VfaWQiOi...",
 "expires_at": 1735603600,
 "status_url": "/api/status/550e8400-e29b-41d4-a716-446655440000"
}
```

Open the `deep_link` on a phone with Provii Wallet in sandbox mode. Poll `/api/status/{session_id}` every 2 to 3 seconds, then call `POST /api/redeem/{session_id}` when status is `verified`. Interactive OpenAPI docs live at `http://localhost:3001/docs`.

## Endpoints

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/health` | GET | Returns `{ "status": "ok", "configured": true }` |
| `/api/config` | GET | Returns `verifier_api_url`, `client_id`. No secrets exposed |
| `/api/create-challenge` | POST | Body: `{ "minimum_age": 13-120, "expires_in": 60-300 }` |
| `/api/status/{session_id}` | GET | States: `pending`, `verified`, `expired`, `failed` |
| `/api/redeem/{session_id}` | POST | Completes PKCE |
| `/docs` | GET | Swagger UI |

## Troubleshooting

**401 from provii-verifier.** HMAC verification failed. Canonical payload field order must be `code_challenge`, `method`, `verifying_key_id`, `expires_in`. The `verifying_key_id` key must appear even when `None`. Python's default `json.dumps` inserts spaces; use `separators=(",", ":")` so the canonical JSON matches what the server expects. Nonce must be unique per request. Clock tolerance is ±300 seconds.

**403 from provii-verifier.** `Origin` header not registered, or `API_KEY` missing. Sandbox skips origin checks; production enforces them.

**404 on status or redeem.** Session expired. Sessions live for `expires_in + 60 seconds`.

**401 with hint about a demo token.** `DEMO_TOKEN_SECRET` is set, so token validation runs and your request is missing or has an invalid `X-Demo-Token` header. For local dev, leave `DEMO_TOKEN_SECRET` unset.

**`TOO_MANY_REDEMPTION_ATTEMPTS`.** After 3 failed redemptions the session is unrecoverable.

## Related docs

- [Relying Party Sandbox and Testing](https://docs.provii.app/getting-started/sandbox-verifier).
- [Relying Party Authentication](https://docs.provii.app/getting-started/auth-verifier).
- [HMAC Canonical Message](https://docs.provii.app/reference/hmac-canonical-message).
- [Rate Limits and Quotas](https://docs.provii.app/reference/rate-limits).
