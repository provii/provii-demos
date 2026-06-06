# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Provii

"""
Provii Issuer Backend Demo (Python/FastAPI).

Reference implementation showing how to integrate Provii credential issuance
into a Python backend. The core HMAC functions between the "COPY THIS" markers
can be extracted into your own project.

Required environment variables:
    CLIENT_ID, HMAC_SECRET, ISSUER_API_URL

Issuance flow (HMAC-SHA256 authenticated):
    1. Mobile app sends customer's DOB as days since Unix epoch
    2. This backend authenticates with HMAC-SHA256, sends dob_days to Provii provii-issuer
    3. Provii provii-issuer creates and signs the attestation (Ed25519)
    4. This backend returns a deep link containing the signed attestation
    5. Mobile app opens Provii Wallet via the deep link
    6. Wallet sends the attestation to provii-issuer for credential issuance

See INTEGRATION.md for framework-specific code samples.
"""

import base64
import hashlib
import hmac
import logging
import os
import secrets
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("provii-issuer")

# ============================================================================
# === COPY THIS: Core HMAC Authentication Functions ===
# ============================================================================

# Module-level configuration, populated from environment variables or the demo API at startup.
config: dict[str, Any] = {
    "client_id": os.getenv("CLIENT_ID", ""),
    "hmac_secret": os.getenv("HMAC_SECRET", ""),
    "issuer_api_url": os.getenv("ISSUER_API_URL", ""),
    "port": int(os.getenv("PORT", "3000")),
    "allowed_origins": [
        origin.strip()
        for origin in os.getenv(
            "ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173"
        ).split(",")
        if origin.strip()
    ],
}


def require_credentials() -> None:
    """Fail-fast if any of CLIENT_ID, HMAC_SECRET, ISSUER_API_URL is missing."""
    missing = [
        key for key in ("client_id", "hmac_secret", "issuer_api_url") if not config[key]
    ]
    if missing:
        logger.error("FATAL: missing required environment variables.")
        logger.error("Set CLIENT_ID, HMAC_SECRET, and ISSUER_API_URL before starting.")
        logger.error("Mint sandbox credentials at https://admin.provii.app")
        logger.error("See backends/issuer/python/README.md for the setup walkthrough.")
        sys.exit(1)


def base64url_decode(s: str) -> bytes:
    """Decode a base64url-encoded string to bytes, adding padding if needed."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def hmac_sha256_hex(secret: bytes, message: str) -> str:
    """Compute an HMAC-SHA256 signature and return it as a lowercase hex string."""
    return hmac.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()


def build_canonical_message(
    dob_days: int, client_id: str, timestamp: int, nonce: str
) -> str:
    """Build the canonical message string for HMAC signing against /v1/attestation/create.

    Format: {timestamp}:POST:/v1/attestation/create:{canonical_json}:{nonce}

    The canonical JSON body uses snake_case field names (key_id), which differs
    from the camelCase (keyId) used in the actual HTTP request body. The nonce
    is appended after the JSON payload and MUST match the authorizer.nonce
    field sent in the request body. See create_canonical_message_for_attestation
    in provii-issuer/src/session.rs for the server-side reference.
    """
    canonical_json = (
        f'{{"dob_days":{dob_days},'
        f'"authorizer":{{"format":"client",'
        f'"key_id":"{client_id}",'
        f'"timestamp":{timestamp}}}}}'
    )
    return f"{timestamp}:POST:/v1/attestation/create:{canonical_json}:{nonce}"


async def create_attestation(dob_days: int) -> dict:
    """Create a signed attestation via Provii's provii-issuer.

    SECURITY: Authenticates the request with HMAC-SHA256 over a canonical message.
    Provii provii-issuer signs the attestation internally using Ed25519.

    Returns the API response dict containing attestation, expires_at, and issuer_id.
    """
    if not config["hmac_secret"]:
        raise ValueError(
            "HMAC_SECRET not configured. Get this from the Provii admin portal."
        )
    if not config["issuer_api_url"]:
        raise ValueError("ISSUER_API_URL not configured.")

    timestamp = int(time.time())
    # SECURITY: 256-bit random nonce prevents replay attacks. The same nonce
    # value MUST appear in both the canonical HMAC message and the request body
    # - server verification fails otherwise (provii-issuer session.rs).
    nonce = secrets.token_hex(32)

    # SECURITY: HMAC is computed over a canonical message to prevent tampering
    canonical_message = build_canonical_message(
        dob_days, config["client_id"], timestamp, nonce
    )
    secret_bytes = base64url_decode(config["hmac_secret"])
    hmac_hex = hmac_sha256_hex(secret_bytes, canonical_message)

    url = f"{config['issuer_api_url']}/v1/attestation/create"
    body = {
        "dob_days": dob_days,
        "authorizer": {
            "format": "client",
            "keyId": config["client_id"],
            "timestamp": timestamp,
            "hmac": hmac_hex,
            "nonce": nonce,
        },
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(url, json=body)

    if response.status_code != 200:
        raise RuntimeError(
            f"Issuer API returned {response.status_code}: {response.text}"
        )

    result = response.json()
    if "attestation" not in result:
        raise RuntimeError("Issuer API response missing attestation field")

    return result


# ============================================================================
# === END OF CORE FUNCTIONS ===
# ============================================================================

app = FastAPI(
    title="Provii Issuer Backend Demo",
    description="Reference implementation for third-party credential issuance (HMAC-SHA256 Authenticated)",
    version="1.0.0",
)

# CORS middleware with a configurable origin allowlist.
# Set ALLOWED_ORIGINS env var for production (comma-separated list).
app.add_middleware(
    CORSMiddleware,
    allow_origins=config["allowed_origins"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "X-Demo-Token"],
)

MAX_BODY_SIZE = 64 * 1024  # 64 KB

IS_PRODUCTION = os.getenv("PYTHON_ENV", "") == "production"


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
    """Add security headers to all responses matching the Node.js issuer."""
    response = await call_next(request)

    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'"
    )

    return response


# ============================================================================
# Demo Token Validation
#
# The X-Demo-Token header guards the publicly-deployed CF Worker
# (issuer-demo.provii.app) against unauthorised use of shared sandbox
# credentials. The signing secret lives in Cloudflare's Secrets Store and is
# only available to the deployed Worker.
#
# For a local Python backend on localhost, the dev controls both sides of the
# request, so there is no security boundary to enforce. When DEMO_TOKEN_SECRET
# is unset (the default for `python main.py`), token validation is skipped.
# Setting DEMO_TOKEN_SECRET re-enables validation, which is what the production
# CF Worker code path does via its Secrets Store binding.
# Token format: demo_token_v1_<YYYYMMDD>_<16-char-hmac>
# ============================================================================

DEMO_TOKEN_SECRET = os.getenv("DEMO_TOKEN_SECRET", "")
DEMO_TOKEN_VALIDATION_ENABLED = bool(DEMO_TOKEN_SECRET)


def validate_demo_token(token: str) -> bool:
    """Validate a demo access token against the expected HMAC signature.

    SECURITY: Uses hmac.compare_digest for constant-time comparison of the
    provided signature against the expected value.

    Caller MUST gate this on DEMO_TOKEN_VALIDATION_ENABLED. The function assumes
    DEMO_TOKEN_SECRET is set.

    Accepts tokens dated today or yesterday to account for timezone differences.
    """
    if not token or not token.startswith("demo_token_v1_"):
        return False

    # Split: ['demo', 'token', 'v1', date, sig]
    parts = token.split("_")
    if len(parts) != 5:
        return False

    date_str = parts[3]
    provided_sig = parts[4]

    # 48-hour acceptance window covers UTC day boundary edge cases
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y%m%d")

    if date_str not in [today, yesterday]:
        return False

    # SECURITY: Compute expected HMAC-SHA256 signature
    message = f"provii-demos-v1:{date_str}".encode()
    expected_sig = hmac.new(
        DEMO_TOKEN_SECRET.encode(),
        message,
        hashlib.sha256,
    ).hexdigest()[:16]

    # SECURITY: Constant-time comparison to prevent timing side-channel attacks
    return hmac.compare_digest(provided_sig, expected_sig)


async def verify_demo_token(x_demo_token: Optional[str] = Header(None)) -> None:
    """FastAPI dependency that enforces demo token validation on API routes.

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


class CreateAttestationRequest(BaseModel):
    """Request body for creating an attestation from DOB days."""

    dob_days: int = Field(
        ..., ge=-25000, le=36500, description="Date of birth as days since Unix epoch"
    )


class CreateAttestationFromDobRequest(BaseModel):
    """Request body for creating an attestation from a DOB date string."""

    dob: str = Field(
        ...,
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="Date of birth in YYYY-MM-DD format",
    )


class AttestationResponse(BaseModel):
    """Response containing the Provii Wallet deep link and attestation expiry."""

    deep_link: str
    dob_days: Optional[int] = None
    expires_at: int


class ErrorResponse(BaseModel):
    """Error response with a machine-readable code and support reference."""

    error: str
    code: str
    reference: str


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Log full error details server-side but return only a generic error to clients."""
    error_id = str(uuid.uuid4())[:8]

    logger.error(
        "Unhandled exception [error_id=%s] path=%s method=%s: %s",
        error_id,
        request.url.path,
        request.method,
        exc,
        exc_info=True,
    )

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "code": "INTERNAL_ERROR",
            "reference": error_id,
        },
    )


@app.get("/health")
async def health_check():
    """Return service health status."""
    return {"status": "ok", "mode": "hmac-authenticated"}


@app.get("/api/config", dependencies=[Depends(verify_demo_token)])
async def get_config():
    """Return current configuration state for debugging. Does not expose secrets."""
    return {
        "has_client_id": bool(config["client_id"]),
        "hmac_configured": bool(config["hmac_secret"]),
        "issuer_api_url": config["issuer_api_url"],
        "mode": "hmac-authenticated",
    }


@app.post(
    "/api/create-attestation",
    response_model=AttestationResponse,
    dependencies=[Depends(verify_demo_token)],
)
async def api_create_attestation(request: CreateAttestationRequest):
    """Create a signed attestation from DOB days and return a Provii Wallet deep link.

    SECURITY: Authenticates with Provii's provii-issuer using HMAC-SHA256.
    Provii signs the attestation internally with Ed25519.
    """
    error_id = str(uuid.uuid4())[:8]

    try:
        result = await create_attestation(request.dob_days)
    except (ValueError, RuntimeError) as e:
        logger.error(
            "Attestation creation failed [error_id=%s]: %s",
            error_id,
            e,
        )
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Attestation creation failed",
                "code": "ATTESTATION_FAILED",
                "reference": error_id,
            },
        ) from e

    logger.info("Attestation created successfully [client=%s]", config["client_id"])

    deep_link = f"https://provii.app/attest?d={result['attestation']}"

    return AttestationResponse(
        deep_link=deep_link,
        expires_at=result["expires_at"],
    )


@app.post(
    "/api/create-attestation-from-dob",
    response_model=AttestationResponse,
    dependencies=[Depends(verify_demo_token)],
)
async def api_create_attestation_from_dob(request: CreateAttestationFromDobRequest):
    """Create a signed attestation from a YYYY-MM-DD date string.

    Converts the date to days since Unix epoch before forwarding to the provii-issuer.

    SECURITY: Authenticates with Provii's provii-issuer using HMAC-SHA256.
    Provii signs the attestation internally with Ed25519.
    """
    error_id = str(uuid.uuid4())[:8]

    try:
        dob_date = datetime.strptime(request.dob, "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        # Not chaining the exception because the HTTPException carries its own
        # user-facing message and should not expose internal parse details
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid date format",
                "code": "INVALID_DATE_FORMAT",
                "reference": error_id,
            },
        )

    dob_days = int(dob_date.timestamp() // (24 * 60 * 60))

    if dob_days < -25000 or dob_days > 36500:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Date out of valid range",
                "code": "DATE_OUT_OF_RANGE",
                "reference": error_id,
            },
        )

    try:
        result = await create_attestation(dob_days)
    except (ValueError, RuntimeError) as e:
        logger.error(
            "Attestation creation failed [error_id=%s]: %s",
            error_id,
            e,
        )
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Attestation creation failed",
                "code": "ATTESTATION_FAILED",
                "reference": error_id,
            },
        ) from e

    logger.info("Attestation created successfully [client=%s]", config["client_id"])

    deep_link = f"https://provii.app/attest?d={result['attestation']}"

    return AttestationResponse(
        deep_link=deep_link,
        dob_days=dob_days,
        expires_at=result["expires_at"],
    )


if __name__ == "__main__":
    import uvicorn

    require_credentials()

    logger.info("=== Provii Issuer Demo Backend (Python) ===")
    logger.info("Mode: HMAC-SHA256 Authenticated (Provii Signs Attestation)")
    logger.info("Port: %d", config["port"])
    logger.info("Client ID: %s", config["client_id"])
    logger.info("HMAC Secret Configured: %s", bool(config["hmac_secret"]))
    logger.info("Issuer API URL: %s", config["issuer_api_url"])
    logger.info("Allowed origins: %s", config["allowed_origins"])
    if DEMO_TOKEN_VALIDATION_ENABLED:
        logger.info("Demo token validation: ENABLED (DEMO_TOKEN_SECRET is set)")
    else:
        logger.info(
            "Demo token validation: DISABLED (local dev mode, DEMO_TOKEN_SECRET unset). "
            "Bind DEMO_TOKEN_SECRET via env injection for production."
        )
    logger.info(
        "Test endpoint: POST http://localhost:%d/api/create-attestation",
        config["port"],
    )

    if not config["hmac_secret"]:
        logger.warning("HMAC_SECRET not set - requests will fail")
        logger.warning(
            "Set it via environment variable or get from Provii admin portal"
        )

    # M-47: Body size limits are configured via uvicorn's --limit-concurrency
    # and reverse proxy settings. For production, set
    # `--limit-max-body-size 65536` (64 KB) in the uvicorn CLI or use
    # nginx/Caddy `client_max_body_size` to reject oversized payloads.
    host = "0.0.0.0" if IS_PRODUCTION else "127.0.0.1"
    uvicorn.run(app, host=host, port=config["port"])
