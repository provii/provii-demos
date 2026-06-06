# Python Issuer Backend Integration Guide

This guide shows how to add Provii credential issuance to your Python backend.

## Quick Start (5 minutes)

### Option 1: Copy the Core Functions

Copy the HMAC authentication logic from `main.py`:

```python
import base64
import hashlib
import hmac
import secrets
import time

import httpx

# Your credentials from Provii admin portal
CLIENT_ID = os.getenv("CLIENT_ID")
HMAC_SECRET = os.getenv("HMAC_SECRET") # base64url-encoded
ISSUER_API_URL = os.getenv("ISSUER_API_URL")


def base64url_decode(s: str) -> bytes:
 """Decode base64url string to bytes."""
 padding = 4 - len(s) % 4
 if padding != 4:
 s += "=" * padding
 return base64.urlsafe_b64decode(s)


def hmac_sha256_hex(secret: bytes, message: str) -> str:
 """Compute HMAC-SHA256 and return as hex string."""
 return hmac.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest


def build_canonical_message(dob_days: int, client_id: str, timestamp: int, nonce: str) -> str:
 """
 Build the canonical message for /v1/attestation/create HMAC signing.

 Format: {timestamp}:POST:/v1/attestation/create:{canonical_json}:{nonce}
 Canonical JSON uses "key_id" (snake_case), NOT "keyId" (camelCase).
 The nonce MUST match the authorizer.nonce sent in the request body.
 """
 canonical_json = (
 f'{{"dob_days":{dob_days},'
 f'"authorizer":{{"format":"client",'
 f'"key_id":"{client_id}",'
 f'"timestamp":{timestamp}}}}}'
 )
 return f"{timestamp}:POST:/v1/attestation/create:{canonical_json}:{nonce}"


def create_attestation(dob_days: int) -> dict:
 """
 Create an attestation via Provii's provii-issuer.

 Authenticates with HMAC-SHA256. Provii signs the attestation internally.
 Returns { attestation, expires_at, issuer_id }.
 """
 timestamp = int(time.time)
 # 256-bit random nonce. The SAME value goes into both the canonical message and the request body.
 nonce = secrets.token_hex(32)

 canonical_message = build_canonical_message(dob_days, CLIENT_ID, timestamp, nonce)
 secret_bytes = base64url_decode(HMAC_SECRET)
 hmac_hex = hmac_sha256_hex(secret_bytes, canonical_message)

 url = f"{ISSUER_API_URL}/v1/attestation/create"
 body = {
 "dob_days": dob_days,
 "authorizer": {
 "format": "client",
 "keyId": CLIENT_ID, # camelCase in request body
 "timestamp": timestamp,
 "hmac": hmac_hex,
 "nonce": nonce,
 },
 }

 with httpx.Client(timeout=15.0) as client:
 response = client.post(url, json=body)

 if response.status_code != 200:
 raise RuntimeError(f"Issuer API returned {response.status_code}: {response.text}")

 result = response.json
 if "attestation" not in result:
 raise RuntimeError("Issuer API response missing attestation field")

 return result
```

### Option 2: Use as Reference

Run this demo backend and study the flow:

```bash
cd backends/issuer/python
pip install -r requirements.txt
python main.py
```

## Dependencies

No cryptographic dependencies are needed. HMAC-SHA256 is built into Python:

```txt
# requirements.txt
fastapi>=0.100.0
uvicorn>=0.23.0
httpx>=0.24.0
pydantic>=2.0.0
```

Install:
```bash
pip install fastapi uvicorn httpx
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

## FastAPI Example (This Demo)

See `main.py` for a complete FastAPI implementation with:
- CORS middleware
- Pydantic validation
- Error handling
- OpenAPI documentation

## Flask Example

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/create-attestation-from-dob", methods=["POST"])
def create_attestation_from_dob:
 data = request.get_json
 dob = data.get("dob")

 if not dob or len(dob) != 10:
 return jsonify({"error": "Invalid dob format"}), 400

 from datetime import datetime, timezone
 try:
 dob_date = datetime.strptime(dob, "%Y-%m-%d").replace(tzinfo=timezone.utc)
 except ValueError:
 return jsonify({"error": "Invalid dob: must be in YYYY-MM-DD format"}), 400
 dob_days = int(dob_date.timestamp // (24 * 60 * 60))
 if dob_days < -25000 or dob_days > 36500:
 return jsonify({"error": "Invalid date: out of valid range"}), 400

 result = create_attestation(dob_days)
 deep_link = f"https://provii.app/attest?d={result['attestation']}"

 return jsonify({
 "deep_link": deep_link,
 "expires_at": result["expires_at"],
 })

if __name__ == "__main__":
 app.run(port=3000)
```

## Django Example

```python
# views.py
import json
from datetime import datetime
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

@csrf_exempt
@require_POST
def create_attestation_from_dob(request):
 try:
 data = json.loads(request.body)
 dob = data.get("dob")
 except json.JSONDecodeError:
 return JsonResponse({"error": "Invalid JSON"}, status=400)

 if not dob:
 return JsonResponse({"error": "Missing dob"}, status=400)

 try:
 dob_date = datetime.strptime(dob, "%Y-%m-%d").replace(tzinfo=timezone.utc)
 except ValueError:
 return JsonResponse({"error": "Invalid dob: must be in YYYY-MM-DD format"}, status=400)
 dob_days = int(dob_date.timestamp // (24 * 60 * 60))
 if dob_days < -25000 or dob_days > 36500:
 return JsonResponse({"error": "Invalid date: out of valid range"}, status=400)

 result = create_attestation(dob_days)
 deep_link = f"https://provii.app/attest?d={result['attestation']}"

 return JsonResponse({
 "deep_link": deep_link,
 "expires_at": result["expires_at"],
 })
```

## Security Considerations

1. **Never expose your HMAC secret** in client-side code or logs
2. **Use HTTPS in production** for all calls to Provii's provii-issuer. The demo binds to 0.0.0.0 for containers; use a reverse proxy with TLS.
3. **Implement rate limiting** using slowapi or similar middleware
4. **Validate CORS origins** by setting `ALLOWED_ORIGINS` to your app domains only
5. **Don't log DOB values** on your backend

## Testing

1. Start the backend:
 ```bash
 python main.py
 ```

2. Create an attestation:
 ```bash
 curl -X POST http://localhost:3000/api/create-attestation-from-dob \
 -H "Content-Type: application/json" \
 -d '{"dob": "1990-05-15"}'
 ```

3. The response contains a `deep_link` that opens Provii Wallet

4. View API docs at `http://localhost:3000/docs` (FastAPI auto-generated)

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
- The canonical message format matches exactly (see `build_canonical_message`)
- The canonical message ends with `:{nonce}` matching the body's `authorizer.nonce`. If you get 401 UNAUTHORIZED, this is the most common cause.
- `key_id` uses snake_case in canonical form, `keyId` uses camelCase in the request
- The HMAC secret is base64url-decoded before use as the HMAC key
- The timestamp is current (within ±30 seconds)

### Date timezone issues
Use UTC when parsing dates:
```python
from datetime import datetime, timezone
dob_date = datetime.strptime(dob, "%Y-%m-%d").replace(tzinfo=timezone.utc)
```
