# Python Verifier Backend Integration Guide

This guide shows how to add Provii age verification to your Python backend.

## Quick Start (5 minutes)

### Option 1: Copy the Core Module

Copy the verification logic from `main.py`:

```python
import base64
import hashlib
import hmac
import json
import math
import secrets
import time

import httpx

# Your credentials from Provii admin portal
VERIFIER_API_URL = os.getenv("VERIFIER_API_URL")
CLIENT_ID = os.getenv("CLIENT_ID")
API_KEY = os.getenv("API_KEY")
HMAC_SECRET = os.getenv("HMAC_SECRET")

# In-memory sessions (use Redis/DB in production)
sessions: dict[str, dict] = {}

async def create_verification_challenge(minimum_age: int) -> dict:
 # Generate PKCE pair
 code_verifier = generate_code_verifier
 code_challenge = generate_code_challenge(code_verifier)

 # Create challenge with provii-verifier
 challenge = await create_challenge_with_api(code_challenge, minimum_age, 300, "over_age")

 # Store code_verifier securely
 sessions[challenge["challenge_id"]] = {"code_verifier": code_verifier}

 return {
 "session_id": challenge["challenge_id"],
 "deep_link": build_deep_link(challenge),
 "expires_at": challenge["expires_at"],
 }
```

### Option 2: Use as Reference

Run this demo backend and study the flow:

```bash
cd backends/verifier/python
pip install -r requirements.txt
python main.py
```

## Dependencies

```
# requirements.txt
fastapi>=0.100.0
uvicorn>=0.23.0
httpx>=0.24.0
pydantic>=2.0.0
```

No external crypto libraries needed - uses Python standard library.

## API Endpoints

Your backend needs to expose:

| Endpoint | Method | Body | Response |
|----------|--------|------|----------|
| `/api/create-challenge` | POST | `{ "minimum_age": 21 }` | `{ "session_id": "...", "deep_link": "https://provii.app/..." }` |
| `/api/status/{session_id}` | GET | - | `{ "state": "verified", "verified": true }` |
| `/api/redeem/{session_id}` | POST | - | `{ "result": "verified", "verified": true }` |

## Environment Variables

```bash
# Required - mint via the playground for sandbox, or via the admin portal for production
VERIFIER_API_URL=https://sandbox-verify.provii.app
CLIENT_ID=rp_your_client_id
API_KEY=your_api_key
HMAC_SECRET=base64url-encoded-secret

# Optional
PORT=3001
ALLOWED_ORIGINS=https://yourapp.com
PYTHON_ENV=production
```

## Flow Diagram

```
Mobile App Your Backend provii-verifier
 │ │ │
 │ POST /create-challenge │ │
 │ { minimum_age: 21 } │ │
 │ ─────────────────────────► │
 │ │ │
 │ │ 1. Generate PKCE │
 │ │ - code_verifier (keep) │
 │ │ - code_challenge (send) │
 │ │ │
 │ │ 2. Create challenge │
 │ │ + HMAC signature │
 │ │ ──────────────────────────►│
 │ │ │
 │ │◄──────────────────────────│
 │ │ 3. Store code_verifier │
 │ │ │
 │◄─────────────────────────│ │
 │ { session_id, deep_link }│ │
 │ │ │
 │ Open wallet with deep_link │
 │ ──────────────────────────────────────────────────────►
 │ │ 4. User creates │
 │ │ ZK proof │
 │ │ │
 │ Poll status │ │
 │ ─────────────────────────► │
 │ │ GET /challenge/:id ────────►
 │ │ │
 │ Call redeem when verified│ │
 │ ─────────────────────────► │
 │ │ POST /redeem │
 │ │ + code_verifier ──────────►│
 │ │ │
 │◄─────────────────────────│◄───────────────────────────│
 │ { verified: true } │ │
```

## Core Functions

### PKCE Generation

```python
import base64
import hashlib
import secrets

def base64url_encode(data: bytes) -> str:
 """Encode bytes to base64url without padding."""
 return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
 """Decode base64url string to bytes (handles missing padding)."""
 padding = 4 - len(s) % 4
 if padding != 4:
 s += "=" * padding
 return base64.urlsafe_b64decode(s)


def generate_code_verifier -> str:
 """
 Generate PKCE code_verifier (43-128 chars, base64url).
 RFC 7636 compliant.
 """
 # 32 bytes = 43 base64url characters
 return base64url_encode(secrets.token_bytes(32))


def generate_code_challenge(code_verifier: str) -> str:
 """Generate PKCE code_challenge from code_verifier using S256 method."""
 digest = hashlib.sha256(code_verifier.encode("ascii")).digest
 return base64url_encode(digest)
```

### HMAC Authentication

```python
import hmac
import hashlib
import json
import secrets

def create_hmac_signature(message: str, secret_base64url: str) -> str:
 """
 Create HMAC-SHA256 signature (hex-encoded, lowercase).

 Canonical message format for provii-verifier (5 colon-separated fields):
 {timestamp}:POST:/v1/challenge:{json_payload_without_authorizer}:{nonce}
 """
 secret_bytes = base64url_decode(secret_base64url)
 signature = hmac.new(
 secret_bytes, message.encode("utf-8"), hashlib.sha256
 ).hexdigest
 return signature


# IMPORTANT: Canonical payload does NOT include authorizer
# Field order: code_challenge, method, verifying_key_id, expires_in
# proof_direction is determined server-side from origin policy
timestamp = int(time.time)
nonce = secrets.token_hex(32)

payload_for_hmac = {
 "code_challenge": code_challenge,
 "method": "S256",
 "verifying_key_id": None, # Must be present even if null
 "expires_in": expires_in,
}

payload_json = json.dumps(payload_for_hmac, separators=(",", ":"))
canonical_message = f"{timestamp}:POST:/v1/challenge:{payload_json}:{nonce}"
hmac_sig = create_hmac_signature(canonical_message, HMAC_SECRET)

# Full payload includes authorizer with nonce for replay protection
full_payload = {
 "code_challenge": code_challenge,
 "method": "S256",
 "expires_in": expires_in,
 "authorizer": {
 "keyId": CLIENT_ID,
 "timestamp": timestamp,
 "nonce": nonce,
 "hmac": hmac_sig,
 },
}
```

### Age to Cutoff Days

```python
import math

def age_to_cutoff_days(minimum_age: int) -> int:
 """
 Calculate cutoff_days from minimum age.
 cutoff_days = floor(age * 365.2425)
 """
 return math.floor(minimum_age * 365.2425)
```

### Deep Link Construction

```python
import json

def build_deep_link(challenge: dict) -> str:
 """Build deep link from challenge response."""
 payload = {
 "challenge_id": challenge["challenge_id"],
 "rp_challenge": challenge["rp_challenge"],
 "submit_secret": challenge["submit_secret"],
 "cutoff_days": challenge["cutoff_days"],
 "verifying_key_id": challenge["verifying_key_id"],
 "verify_url": challenge["verify_url"],
 "expires_at": challenge["expires_at"],
 }
 json_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
 return f"https://provii.app/verify?d={base64url_encode(json_bytes)}"
```

## Flask Example

```python
from flask import Flask, request, jsonify

app = Flask(__name__)
sessions = {}

@app.route("/api/create-challenge", methods=["POST"])
def create_challenge:
 data = request.get_json
 minimum_age = data.get("minimum_age", 18)

 if minimum_age < 13 or minimum_age > 120:
 return jsonify({"error": "Invalid minimum_age"}), 400

 code_verifier = generate_code_verifier
 code_challenge = generate_code_challenge(code_verifier)

 # This would be async in production
 import asyncio
 challenge = asyncio.run(create_challenge_with_api(code_challenge, minimum_age, 300, "over_age"))

 sessions[challenge["challenge_id"]] = {"code_verifier": code_verifier}

 return jsonify({
 "session_id": challenge["challenge_id"],
 "deep_link": build_deep_link(challenge),
 "expires_at": challenge["expires_at"],
 })


@app.route("/api/status/<session_id>")
def get_status(session_id):
 session = sessions.get(session_id)
 if not session:
 return jsonify({"error": "Session not found"}), 404

 import asyncio
 status = asyncio.run(poll_challenge_status(session_id))
 return jsonify(status)


@app.route("/api/redeem/<session_id>", methods=["POST"])
def redeem(session_id):
 session = sessions.get(session_id)
 if not session:
 return jsonify({"error": "Session not found"}), 404

 import asyncio
 result = asyncio.run(redeem_challenge(session_id, session["code_verifier"]))

 if result.get("verified"):
 del sessions[session_id]

 return jsonify(result)


if __name__ == "__main__":
 app.run(port=3001)
```

## Django Example

```python
# views.py
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

sessions = {}

@csrf_exempt
@require_http_methods(["POST"])
def create_challenge(request):
 data = json.loads(request.body)
 minimum_age = data.get("minimum_age", 18)

 if minimum_age < 13 or minimum_age > 120:
 return JsonResponse({"error": "Invalid minimum_age"}, status=400)

 code_verifier = generate_code_verifier
 code_challenge = generate_code_challenge(code_verifier)

 import asyncio
 challenge = asyncio.run(create_challenge_with_api(code_challenge, minimum_age, 300, "over_age"))

 sessions[challenge["challenge_id"]] = {"code_verifier": code_verifier}

 return JsonResponse({
 "session_id": challenge["challenge_id"],
 "deep_link": build_deep_link(challenge),
 "expires_at": challenge["expires_at"],
 })


@require_http_methods(["GET"])
def get_status(request, session_id):
 session = sessions.get(session_id)
 if not session:
 return JsonResponse({"error": "Session not found"}, status=404)

 import asyncio
 status = asyncio.run(poll_challenge_status(session_id))
 return JsonResponse(status)


@csrf_exempt
@require_http_methods(["POST"])
def redeem(request, session_id):
 session = sessions.get(session_id)
 if not session:
 return JsonResponse({"error": "Session not found"}, status=404)

 import asyncio
 result = asyncio.run(redeem_challenge(session_id, session["code_verifier"]))

 if result.get("verified"):
 del sessions[session_id]

 return JsonResponse(result)


# urls.py
from django.urls import path
from . import views

urlpatterns = [
 path("api/create-challenge", views.create_challenge),
 path("api/status/<str:session_id>", views.get_status),
 path("api/redeem/<str:session_id>", views.redeem),
]
```

## FastAPI Example (This Demo)

See `main.py` for a complete FastAPI implementation with:
- CORS configuration
- Pydantic validation
- Async HTTP client
- Error handling

Mint sandbox credentials from the playground UI. Visit https://playground.provii.app, switch to the "Set up a Verifier" tab, fill in the policy form, click mint. Copy `client_id`, `api_key`, `hmac_secret`, and `base_url` into your `.env`:

```bash
# .env (do not commit)
CLIENT_ID=rp_sandbox_<your minted id>
API_KEY=<your minted api key>
HMAC_SECRET=<your minted hmac secret>
VERIFIER_API_URL=https://sandbox-verify.provii.app
```

The credential expires in 72 hours. Mint a new one when it expires; the playground remembers it in localStorage so reloading does not lose it.

## API Client Functions

```python
import httpx
import secrets

async def create_challenge_with_api(
 code_challenge: str, minimum_age: int, expires_in: int = 300
) -> dict:
 """Create verification challenge via provii-verifier with HMAC auth."""
 timestamp = int(time.time)
 nonce = secrets.token_hex(32)

 # IMPORTANT: Canonical payload does NOT include authorizer
 # Field order: code_challenge, method, verifying_key_id, expires_in
 # proof_direction is determined server-side from origin policy
 payload_for_hmac = {
 "code_challenge": code_challenge,
 "method": "S256",
 "verifying_key_id": None, # Must be present even if null
 "expires_in": expires_in,
 }

 # Canonical message: 5 colon-separated fields including nonce
 payload_json = json.dumps(payload_for_hmac, separators=(",", ":"))
 canonical_message = f"{timestamp}:POST:/v1/challenge:{payload_json}:{nonce}"
 hmac_sig = create_hmac_signature(canonical_message, HMAC_SECRET)

 # Full payload WITH authorizer (including nonce for replay protection)
 full_payload = {
 "code_challenge": code_challenge,
 "method": "S256",
 "expires_in": expires_in,
 "authorizer": {
 "keyId": CLIENT_ID,
 "timestamp": timestamp,
 "nonce": nonce,
 "hmac": hmac_sig,
 },
 }

 # Origin header must match registered domain for sandbox credentials
 async with httpx.AsyncClient as client:
 response = await client.post(
 f"{VERIFIER_API_URL}/v1/challenge",
 json=full_payload,
 headers={
 "Content-Type": "application/json",
 "X-API-Key": API_KEY,
 "Origin": "https://verifier-demo.provii.app",
 },
 timeout=30.0,
 )

 response.raise_for_status
 return response.json


async def poll_challenge_status(challenge_id: str) -> dict:
 """Poll challenge status from provii-verifier."""
 async with httpx.AsyncClient as client:
 response = await client.get(
 f"{VERIFIER_API_URL}/v1/challenge/{challenge_id}",
 timeout=30.0,
 )
 response.raise_for_status
 return response.json


async def redeem_challenge(challenge_id: str, code_verifier: str) -> dict:
 """Redeem verified challenge with PKCE code_verifier."""
 async with httpx.AsyncClient as client:
 response = await client.post(
 f"{VERIFIER_API_URL}/v1/challenge/{challenge_id}/redeem",
 json={"code_verifier": code_verifier},
 headers={"Content-Type": "application/json"},
 timeout=30.0,
 )
 response.raise_for_status
 return response.json
```

## Security Considerations

| Rule | Detail |
|------|--------|
| Never expose HMAC_SECRET | Keep in secure environment variables |
| Never expose code_verifier | It must stay on your backend |
| Use HTTPS in production | The demo uses HTTP for local development only |
| Implement rate limiting | Use slowapi or similar for FastAPI |
| Use Redis/DB for sessions | In-memory storage is for demo only |
| Validate CORS origins | Set `ALLOWED_ORIGINS` to your app domains only |
| JSON serialisation order | Use `separators=(",", ":")` for consistent HMAC |

## Testing

1. Start the backend:
 ```bash
 python main.py
 ```

2. Create a challenge:
 ```bash
 curl -X POST http://localhost:3001/api/create-challenge \
 -H "Content-Type: application/json" \
 -d '{"minimum_age": 21}'
 ```

3. The response contains a `deep_link` that opens Provii Wallet

4. Enable Sandbox Mode in Provii Wallet: Settings → tap 5 times → toggle Sandbox

5. Poll status until verified, then redeem

## Common Issues

### "HMAC_SECRET not configured"
Mint sandbox credentials from the playground (https://playground.provii.app, "Set up a Verifier" tab) and copy them into `.env`. For production, fetch credentials from the Provii admin portal.

### Challenge creation fails with 401
Ensure:
- `CLIENT_ID` and `HMAC_SECRET` are correct
- Timestamp in HMAC is current (within 5 minutes)
- Canonical message format matches exactly
- Use `separators=(",", ":")` in `json.dumps` for consistent output

### Session not found
Sessions are stored in-memory and lost on restart. Use Redis/DB in production.

### JSON serialisation issues
Python's `json.dumps` may produce different output than expected. Always use:
```python
json.dumps(payload, separators=(",", ":"))
```
This ensures no spaces after separators, matching the expected canonical format.
