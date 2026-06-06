# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Provii

"""
Provii Verifier Backend Demo for Python (FastAPI).

Reference implementation showing how third-party verifiers (social media apps,
age-gated websites, content platforms, dating services) integrate with
Provii's provii-verifier using direct HMAC authentication.

Integration steps:

1. Copy the core functions marked with "=== COPY THIS ===" below
2. Set environment variables: CLIENT_ID, HMAC_SECRET, API_KEY
3. Create your /api/create-challenge endpoint
4. Return the deep_link to your mobile app
5. Store the code_verifier securely (associated with session_id)
6. When user completes verification, call /api/redeem with code_verifier

See INTEGRATION.md for complete examples and framework-specific code.

Verification flow:

1. Mobile app requests age verification from YOUR backend
2. Your backend generates PKCE (code_verifier + code_challenge)
3. Your backend authenticates to provii-verifier with HMAC
4. Your backend stores code_verifier securely (in session/DB)
5. Your backend returns deep_link to mobile app
6. Mobile app opens Provii Wallet with deep link
7. User verifies in wallet (ZK proof submitted to provii-verifier)
8. Mobile app polls YOUR backend for status
9. When verified, YOUR backend redeems with code_verifier

SECURITY: Your backend never exposes HMAC_SECRET or code_verifier to clients.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import httpx
from dotenv import load_dotenv

# Load .env BEFORE FastAPI/Pydantic import. Pydantic models read env at
# import time, so the dotenv call must run first. The four imports
# below are intentionally past the call and silence ruff's E402.
load_dotenv()  # loads .env at startup if present

from contextlib import asynccontextmanager  # noqa: E402

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

# ============================================================================
# Configuration
# ============================================================================


@dataclass
class Config:
    """Resolved server configuration built from environment variables."""

    verifier_api_url: str
    client_id: str
    api_key: str
    hmac_secret: str
    registered_origin: str
    port: int
    allowed_origins: list[str]
    is_production: bool


config = Config(
    verifier_api_url=os.getenv("VERIFIER_API_URL", "https://sandbox-verify.provii.app"),
    client_id=os.getenv("CLIENT_ID", ""),
    api_key=os.getenv("API_KEY", ""),
    hmac_secret=os.getenv("HMAC_SECRET", ""),
    registered_origin=os.getenv("REGISTERED_ORIGIN", "https://playground.provii.app"),
    port=int(os.getenv("PORT", "3001")),
    allowed_origins=os.getenv(
        "ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173"
    ).split(","),
    is_production=os.getenv("PYTHON_ENV", "") == "production",
)


# ============================================================================
# Demo Token Validation
#
# The X-Demo-Token header guards the publicly-deployed CF Worker
# (verifier-demo.provii.app) against unauthorised use of shared sandbox
# credentials. The signing secret lives in Cloudflare's Secrets Store and is
# only available to the deployed Worker.
#
# For a local Python backend on localhost, the dev controls both sides of the
# request, so there is no security boundary to enforce. When DEMO_TOKEN_SECRET
# is unset (the default for `python main.py`), token validation is skipped.
# Setting DEMO_TOKEN_SECRET re-enables validation, which is what the production
# CF Worker code path does via its Secrets Store binding.
# ============================================================================

DEMO_TOKEN_SECRET = os.getenv("DEMO_TOKEN_SECRET", "")
DEMO_TOKEN_VALIDATION_ENABLED = bool(DEMO_TOKEN_SECRET)


def validate_demo_token(token: str) -> bool:
    """
    Validate the X-Demo-Token header to prevent unauthorised access.

    Token format: demo_token_v1_<YYYYMMDD>_<16-char-hmac>.

    Caller MUST gate this on DEMO_TOKEN_VALIDATION_ENABLED. The function assumes
    DEMO_TOKEN_SECRET is set.

    SECURITY: Uses hmac.compare_digest for constant-time comparison of the HMAC tag.
    """
    if not token or not token.startswith("demo_token_v1_"):
        return False

    parts = token.split("_")
    if len(parts) != 5:
        return False

    date_str = parts[3]
    provided_sig = parts[4]

    # Accept today or yesterday to handle timezone boundaries (48-hour window)
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y%m%d")

    if date_str not in [today, yesterday]:
        return False

    message = f"provii-demos-v1:{date_str}".encode()
    expected_sig = hmac.new(
        DEMO_TOKEN_SECRET.encode(),
        message,
        hashlib.sha256,
    ).hexdigest()[:16]

    # SECURITY: Constant-time comparison using hmac.compare_digest
    return hmac.compare_digest(provided_sig, expected_sig)


async def verify_demo_token(x_demo_token: Optional[str] = Header(None)) -> None:
    """FastAPI dependency that enforces demo token validation on Hardcore API routes.

    Pass-through when DEMO_TOKEN_SECRET is unset (local dev mode).
    """
    if not DEMO_TOKEN_VALIDATION_ENABLED:
        return
    if not validate_demo_token(x_demo_token or ""):
        raise HTTPException(
            status_code=401,
            detail={
                "error": "Invalid or missing demo token",
                "hint": "Fetch token from https://playground.provii.app/v1/config/demo-token",
            },
        )


# Directory containing static demo files (expert.html, provii-agegate assets)
PUBLIC_DIR = Path(__file__).parent / "public"


# UUID format validation regex (matches any UUID version, consistent with Go/CF Workers)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def _is_valid_uuid(s: str) -> bool:
    """Return True if *s* matches the standard UUID format (any version)."""
    return bool(_UUID_RE.match(s))


# In-memory session store. Replace with Redis or a database in production.
@dataclass
class SessionData:
    """Session state stored alongside the secret code_verifier."""

    code_verifier: str
    challenge_id: str
    expires_at: int
    created_at: int
    proof_direction: str = "over_age"


sessions: dict[str, SessionData] = {}


# ============================================================================
# === COPY THIS: Core Cryptographic & API Functions ===
# ============================================================================


def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    """Decode a base64url string to bytes, handling missing padding."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def generate_code_verifier() -> str:
    """
    Generate an RFC 7636 PKCE code_verifier.

    32 random bytes yield 43 base64url characters.
    """
    return base64url_encode(secrets.token_bytes(32))


def generate_code_challenge(code_verifier: str) -> str:
    """Generate the S256 PKCE code_challenge by SHA-256 hashing the code_verifier."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64url_encode(digest)


def create_hmac_signature(message: str, secret_base64url: str) -> str:
    """
    Create an HMAC-SHA256 signature (hex-encoded, lowercase).

    SECURITY: Canonical message format for provii-verifier:
    {timestamp}:POST:/v1/challenge:{json_payload_without_hmac}:{nonce}
    """
    secret_bytes = base64url_decode(secret_base64url)
    signature = hmac.new(
        secret_bytes, message.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return signature


def build_deep_link(challenge: dict) -> str:
    """Build a Provii Wallet deep link URL from the challenge response fields."""
    payload = {
        "challenge_id": challenge["challenge_id"],
        "rp_challenge": challenge["rp_challenge"],
        "submit_secret": challenge["submit_secret"],
        "cutoff_days": challenge["cutoff_days"],
        "verifying_key_id": challenge["verifying_key_id"],
        "verify_url": challenge["verify_url"],
        "expires_at": challenge["expires_at"],
        "proof_direction": challenge["proof_direction"],
    }
    json_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return f"https://provii.app/verify?d={base64url_encode(json_bytes)}"


# ============================================================================
# === END OF CORE FUNCTIONS ===
# ============================================================================


async def create_challenge_with_api(
    code_challenge: str,
    minimum_age: int,
    expires_in: int = 300,
) -> dict:
    """
    Create a verification challenge via provii-verifier with HMAC authentication.

    SECURITY: The HMAC covers a canonical message to prevent request tampering.
    """
    if not config.hmac_secret:
        raise ValueError("HMAC_SECRET not configured")
    if not config.api_key:
        raise ValueError("API_KEY not configured")

    timestamp = int(time.time())
    nonce = secrets.token_hex(32)

    # SECURITY: Canonical payload for HMAC must match server's create_canonical_message_for_challenge.
    # The server uses serde_json::json!() with preserve_order enabled (via feature unification),
    # so keys follow INSERTION ORDER from the json!() macro in challenge.rs:265-270:
    # code_challenge, method, verifying_key_id, expires_in.
    # The nonce from the authorizer block is appended as the 5th field in the canonical message.
    # proof_direction is determined server-side from origin policy, not sent by client.
    payload_for_hmac = {
        "code_challenge": code_challenge,
        "method": "S256",
        "verifying_key_id": None,
        "expires_in": expires_in,
    }

    payload_json = json.dumps(payload_for_hmac, separators=(",", ":"))
    canonical_message = f"{timestamp}:POST:/v1/challenge:{payload_json}:{nonce}"
    hmac_sig = create_hmac_signature(canonical_message, config.hmac_secret)

    # Full payload includes the authoriser block with nonce for replay protection
    full_payload = {
        "code_challenge": code_challenge,
        "method": "S256",
        "expires_in": expires_in,
        "authorizer": {
            "keyId": config.client_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "hmac": hmac_sig,
        },
    }

    # Origin header must match the registered origin policy in provii-verifier
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{config.verifier_api_url}/v1/challenge",
            json=full_payload,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": config.api_key,
                "Origin": config.registered_origin,
            },
            timeout=30.0,
        )

    if response.status_code not in (200, 201):
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Challenge creation failed: {response.text}",
        )

    return response.json()


async def poll_challenge_status(challenge_id: str) -> dict:
    """Poll challenge status from provii-verifier by challenge ID."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{config.verifier_api_url}/v1/challenge/{challenge_id}",
            headers={
                "X-API-Key": config.api_key,
                "Origin": config.registered_origin,
            },
            timeout=30.0,
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Status check failed: {response.text}",
        )

    return response.json()


async def redeem_challenge(challenge_id: str, code_verifier: str) -> dict:
    """Redeem a verified challenge by presenting the PKCE code_verifier to provii-verifier."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{config.verifier_api_url}/v1/challenge/{challenge_id}/redeem",
            json={"code_verifier": code_verifier},
            headers={
                "Content-Type": "application/json",
                "X-API-Key": config.api_key,
                "Origin": config.registered_origin,
            },
            timeout=30.0,
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Redeem failed: {response.text}",
        )

    return response.json()


def require_credentials() -> None:
    """Fail-fast if any required credential is missing from the environment."""
    if not (
        config.client_id
        and config.api_key
        and config.hmac_secret
        and config.verifier_api_url
    ):
        print("FATAL: missing required environment variables.")
        print(
            "Set CLIENT_ID, API_KEY, HMAC_SECRET, and VERIFIER_API_URL before starting."
        )
        print("Mint sandbox credentials at https://admin.provii.app")
        print("See backends/verifier/python/README.md for the setup walkthrough.")
        raise SystemExit(1)


# ============================================================================
# FastAPI App
# ============================================================================


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Validate credentials and print configuration on server startup."""
    require_credentials()

    print("")
    print("=== Provii Verifier Demo Backend (Python) ===")
    print("Mode: Direct provii-verifier integration with HMAC auth")
    print(f"Port: {config.port}")
    print(f"Verifier API: {config.verifier_api_url}")
    print(f"Client ID: {config.client_id}")
    print(f"API Key Configured: {bool(config.api_key)}")
    print(f"HMAC Secret Configured: {bool(config.hmac_secret)}")
    if DEMO_TOKEN_VALIDATION_ENABLED:
        print("Demo token validation: ENABLED (DEMO_TOKEN_SECRET is set)")
    else:
        print(
            "Demo token validation: DISABLED (local dev mode, DEMO_TOKEN_SECRET unset)."
        )
        print("  Bind DEMO_TOKEN_SECRET via env injection for production.")
    print("")
    print("Test with:")
    print(f"  curl -X POST http://localhost:{config.port}/api/create-challenge \\")
    print('    -H "Content-Type: application/json" \\')
    print("    -d '{\"minimum_age\": 21}'")
    print("")
    print("Then check status:")
    print(f"  curl http://localhost:{config.port}/api/status/<session_id>")
    print("")
    print("Then redeem (after user verifies in wallet):")
    print(f"  curl -X POST http://localhost:{config.port}/api/redeem/<session_id>")
    print("")

    yield


app = FastAPI(
    title="Provii Verifier Backend Demo",
    description="Reference implementation for third-party age verification with direct provii-verifier integration",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "X-Demo-Token"],
)

MAX_BODY_SIZE = 64 * 1024  # 64 KB


@app.middleware("http")
async def body_size_limit(request: Request, call_next):
    """Reject request bodies larger than 64 KB to match other backends."""
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_BODY_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={"error": "Request body too large"},
                )
        except ValueError:
            pass
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add security headers to all responses.

    Demo HTML pages get a permissive CSP to load provii-agegate from CDN.
    API endpoints get a strict CSP.
    """
    response = await call_next(request)

    if config.is_production:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"

    path = request.url.path
    if path == "/" or path.endswith(".html"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.provii.app; "
            "style-src 'self' 'unsafe-inline' https://cdn.provii.app; "
            "connect-src 'self' https://*.provii.app wss://*.provii.app; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'"
        )
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )

    return response


# ============================================================================
# Request/Response Models
# ============================================================================


class CreateChallengeRequest(BaseModel):
    """Request body for POST /api/create-challenge."""

    minimum_age: Optional[int] = Field(
        default=None, ge=13, le=120, description="Minimum age to verify (over_age)"
    )
    maximum_age: Optional[int] = Field(
        default=None, ge=13, le=120, description="Maximum age to verify (under_age)"
    )
    expires_in: int = Field(
        default=300,
        ge=60,
        le=300,
        description="Challenge expiration in seconds (server MAX_CHALLENGE_TTL is 300)",
    )


class CreateChallengeResponse(BaseModel):
    """Response body for POST /api/create-challenge."""

    session_id: str
    deep_link: str
    expires_at: int
    status_url: str
    proof_direction: str


class StatusResponse(BaseModel):
    """Response body for GET /api/status/{session_id}."""

    state: str
    verified: bool
    proof_verified: bool


class RedeemResponse(BaseModel):
    """Response body for POST /api/redeem/{session_id}."""

    result: str
    verified: bool


# ============================================================================
# API Endpoints
# ============================================================================


@app.get("/health")
async def health_check():
    """Return health status and credential configuration state."""
    configured = bool(config.hmac_secret and config.api_key and config.client_id)
    return {"status": "ok", "configured": configured}


@app.get("/api/config", dependencies=[Depends(verify_demo_token)])
async def get_config():
    """Return configuration visibility info for debugging."""
    return {
        "verifier_api_url": config.verifier_api_url,
        "has_client_id": bool(config.client_id),
        "api_key_configured": bool(config.api_key),
        "hmac_secret_configured": bool(config.hmac_secret),
    }


@app.post(
    "/api/create-challenge",
    response_model=CreateChallengeResponse,
    dependencies=[Depends(verify_demo_token)],
)
async def create_challenge(request: CreateChallengeRequest):
    """
    Create a new age verification challenge.

    Accepts minimum_age (over_age) or maximum_age (under_age), but not both.
    Generates a PKCE pair, authenticates to provii-verifier with HMAC, stores the
    code_verifier in memory, and returns a deep link for the mobile app.
    """
    if request.minimum_age is not None and request.maximum_age is not None:
        raise HTTPException(
            status_code=400,
            detail="Cannot specify both minimum_age and maximum_age",
        )

    if request.maximum_age is not None:
        age = request.maximum_age
    else:
        age = request.minimum_age or 18

    try:
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)

        # proof_direction is determined server-side from origin policy
        challenge = await create_challenge_with_api(
            code_challenge, age, request.expires_in
        )

        # SECURITY: code_verifier is secret and must never leave the backend
        sessions[challenge["challenge_id"]] = SessionData(
            code_verifier=code_verifier,
            challenge_id=challenge["challenge_id"],
            expires_at=challenge["expires_at"],
            created_at=int(time.time()),
            proof_direction=challenge["proof_direction"],
        )

        deep_link = build_deep_link(challenge)

        return CreateChallengeResponse(
            session_id=challenge["challenge_id"],
            deep_link=deep_link,
            expires_at=challenge["expires_at"],
            status_url=f"/api/status/{challenge['challenge_id']}",
            proof_direction=challenge["proof_direction"],
        )
    except Exception as e:
        error_id = secrets.token_hex(4)
        print(f"[{error_id}] Error creating challenge: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Failed to create challenge",
                "code": "CHALLENGE_FAILED",
                "reference": error_id,
            },
        )


@app.get(
    "/api/status/{session_id}",
    response_model=StatusResponse,
    dependencies=[Depends(verify_demo_token)],
)
async def get_status(session_id: str):
    """
    Poll the current verification status for a session.

    Returns the state (pending, verified, expired) by forwarding the query
    to provii-verifier.
    """
    if not _is_valid_uuid(session_id):
        raise HTTPException(status_code=400, detail="Invalid session_id format")

    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    status = await poll_challenge_status(session_id)

    return StatusResponse(
        state=status.get("state", "unknown"),
        verified=status.get("verified", False),
        proof_verified=status.get("proof_verified", False),
    )


@app.post(
    "/api/redeem/{session_id}",
    response_model=RedeemResponse,
    dependencies=[Depends(verify_demo_token)],
)
async def redeem(session_id: str):
    """
    Redeem a verified challenge to complete the verification flow.

    SECURITY: Uses pop-before-use pattern to prevent TOCTOU race conditions.
    The session is removed from the dict BEFORE calling redeem_challenge so that
    only one request can succeed even if multiple concurrent requests arrive. The
    provii-verifier also enforces single redemption as defence-in-depth.
    """
    if not _is_valid_uuid(session_id):
        raise HTTPException(status_code=400, detail="Invalid session_id format")

    session = sessions.pop(session_id, None)
    if not session:
        raise HTTPException(
            status_code=404, detail="Session not found or already redeemed"
        )

    # Session already removed, so replay is impossible even if redemption fails.
    # Provii-verifier enforces single-use as defence-in-depth.
    result = await redeem_challenge(session_id, session.code_verifier)

    return RedeemResponse(
        result=result.get("result", "unknown"),
        verified=result.get("verified", False),
    )


# ============================================================================
# Expert Mode Proxy Endpoints (provii-agegate rp-proxy mode)
#
# These endpoints accept requests from provii-agegate and proxy them to
# provii-verifier with HMAC authentication. provii-agegate manages PKCE and
# the frontend UX. The developer only needs to run this backend.
# Expert endpoints skip demo token validation because the real security
# is HMAC authentication to provii-verifier.
# ============================================================================


class ExpertChallengeRequest(BaseModel):
    """Request body for POST /api/challenge (Expert proxy)."""

    code_challenge: str
    method: str = "S256"
    verifying_key_id: Optional[int] = None
    expires_in: int = 300


class ExpertPollRequest(BaseModel):
    """Request body for POST /api/poll (Expert proxy)."""

    challengeId: str


class ExpertRedeemRequest(BaseModel):
    """Request body for POST /api/redeem (Expert proxy)."""

    challenge_id: str
    code_verifier: str


@app.post("/api/challenge")
async def expert_create_challenge(request: ExpertChallengeRequest):
    """
    Expert mode: Create challenge (proxy for provii-agegate).

    provii-agegate sends { code_challenge, method, verifying_key_id, expires_in }
    and this endpoint adds HMAC auth and forwards to provii-verifier.
    """
    try:
        # Use the client-provided code_challenge (provii-agegate generated it)
        challenge = await create_challenge_with_api(
            request.code_challenge, 18, request.expires_in
        )
        # Return the full challenge response (provii-agegate expects these fields)
        return challenge
    except Exception as e:
        error_id = secrets.token_hex(4)
        print(f"[{error_id}] Error creating challenge (expert): {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Failed to create challenge",
                "code": "CHALLENGE_FAILED",
                "reference": error_id,
            },
        )


@app.post("/api/poll")
async def expert_poll(request: ExpertPollRequest):
    """
    Expert mode: Poll status (proxy for provii-agegate).

    provii-agegate sends { challengeId } via POST in rp-proxy mode.
    """
    try:
        status = await poll_challenge_status(request.challengeId)
        return status
    except Exception as e:
        error_id = secrets.token_hex(4)
        print(f"[{error_id}] Error polling status (expert): {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Failed to check status",
                "code": "STATUS_CHECK_FAILED",
                "reference": error_id,
            },
        )


@app.post("/api/redeem")
async def expert_redeem(request: ExpertRedeemRequest):
    """
    Expert mode: Redeem challenge (proxy for provii-agegate).

    provii-agegate sends { challenge_id, code_verifier } in rp-proxy mode.
    The code_verifier comes from provii-agegate (it generated the PKCE pair).
    """
    try:
        result = await redeem_challenge(request.challenge_id, request.code_verifier)

        # Set a session cookie so the frontend knows the user is verified on reload.
        # In production, use a signed/encrypted token with expiry.
        session_token = secrets.token_hex(32)
        response = JSONResponse(content=result)
        response.set_cookie(
            key="verified_session",
            value=session_token,
            path="/",
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=86400,
        )
        return response
    except Exception as e:
        error_id = secrets.token_hex(4)
        print(f"[{error_id}] Error redeeming (expert): {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Failed to redeem verification",
                "code": "REDEEM_FAILED",
                "reference": error_id,
            },
        )


@app.get("/api/session")
async def expert_session(verified_session: Optional[str] = Cookie(None)):
    """
    Expert mode: Session check.

    Returns whether the user has a valid session cookie.
    In Expert mode, the developer manages sessions, not provii-verifier.
    """
    return {"verified": verified_session is not None}


# ============================================================================
# Static File Serving (demo pages)
# ============================================================================


@app.get("/")
async def root_redirect():
    """Redirect root to the Expert mode demo page."""
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url="/expert.html")


@app.get("/{filename:path}")
async def serve_static(filename: str):
    """Serve static files from the public/ directory (HTML, JS, CSS)."""
    if not filename.endswith((".html", ".js", ".css")):
        raise HTTPException(status_code=404, detail="Not found")

    filepath = PUBLIC_DIR / filename
    if not filepath.exists() or not filepath.is_file():
        raise HTTPException(status_code=404, detail="Not found")

    # Prevent directory traversal
    try:
        filepath.resolve().relative_to(PUBLIC_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found")

    content_types = {
        ".html": "text/html",
        ".js": "application/javascript",
        ".css": "text/css",
    }
    suffix = filepath.suffix
    media_type = content_types.get(suffix, "application/octet-stream")
    return FileResponse(filepath, media_type=media_type)


# ============================================================================
# Startup
# ============================================================================


if __name__ == "__main__":
    import uvicorn

    # M-47: Body size limits are configured via uvicorn's --limit-concurrency
    # and reverse proxy settings. For production, set
    # `--limit-max-body-size 65536` (64 KB) in the uvicorn CLI or use
    # nginx/Caddy `client_max_body_size` to reject oversized payloads.
    host = "0.0.0.0" if config.is_production else "127.0.0.1"
    uvicorn.run(app, host=host, port=config.port)
