# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Provii

"""Tests for the Provii Verifier Backend Demo (Python/FastAPI)."""

import hashlib
import hmac as hmac_mod
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import main
from main import (
    SessionData,
    _is_valid_uuid,
    app,
    base64url_decode,
    base64url_encode,
    build_deep_link,
    create_hmac_signature,
    generate_code_challenge,
    generate_code_verifier,
    sessions,
    validate_demo_token,
)


@pytest.fixture(autouse=True)
def _reset_state():
    """Clear session store and reset demo token state between tests."""
    sessions.clear()
    original_secret = main.DEMO_TOKEN_SECRET
    original_enabled = main.DEMO_TOKEN_VALIDATION_ENABLED
    yield
    sessions.clear()
    main.DEMO_TOKEN_SECRET = original_secret
    main.DEMO_TOKEN_VALIDATION_ENABLED = original_enabled


@pytest.fixture()
def _disable_demo_token():
    """Disable demo token validation for tests that do not need it."""
    main.DEMO_TOKEN_VALIDATION_ENABLED = False
    yield
    main.DEMO_TOKEN_VALIDATION_ENABLED = False


@pytest.fixture()
def client(_disable_demo_token):
    """Return a FastAPI test client with demo token validation disabled."""
    return TestClient(app)


# ---------------------------------------------------------------------------
# Utility function tests
# ---------------------------------------------------------------------------


class TestBase64url:
    def test_encode_decode_roundtrip(self):
        original = b"pkce-verifier-bytes-for-testing"
        encoded = base64url_encode(original)
        assert isinstance(encoded, str)
        decoded = base64url_decode(encoded)
        assert decoded == original

    def test_decode_with_padding(self):
        encoded = base64url_encode(b"a")
        decoded = base64url_decode(encoded)
        assert decoded == b"a"


class TestGenerateCodeVerifier:
    def test_length_is_43(self):
        verifier = generate_code_verifier()
        assert len(verifier) == 43

    def test_uniqueness(self):
        v1 = generate_code_verifier()
        v2 = generate_code_verifier()
        assert v1 != v2


class TestGenerateCodeChallenge:
    def test_deterministic(self):
        verifier = "test-verifier-value"
        c1 = generate_code_challenge(verifier)
        c2 = generate_code_challenge(verifier)
        assert c1 == c2

    def test_differs_from_verifier(self):
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier)
        assert challenge != verifier


class TestCreateHmacSignature:
    def test_produces_hex(self):
        secret = base64url_encode(b"my-test-secret-key")
        sig = create_hmac_signature("test-message", secret)
        assert len(sig) == 64  # SHA-256 hex = 64 chars
        int(sig, 16)  # Must be valid hex

    def test_matches_manual(self):
        raw_secret = b"my-test-secret-key"
        secret = base64url_encode(raw_secret)
        sig = create_hmac_signature("test-message", secret)
        expected = hmac_mod.new(raw_secret, b"test-message", hashlib.sha256).hexdigest()
        assert sig == expected


class TestBuildDeepLink:
    def test_produces_deep_link(self):
        challenge = {
            "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
            "rp_challenge": "rp-chal",
            "submit_secret": "secret",
            "cutoff_days": 6574,
            "verifying_key_id": 1,
            "verify_url": "https://example.com/verify",
            "expires_at": 1700000300,
            "proof_direction": "over_age",
        }
        link = build_deep_link(challenge)
        assert link.startswith("https://provii.app/verify?d=")


class TestIsValidUuid:
    def test_valid(self):
        assert _is_valid_uuid("550e8400-e29b-41d4-a716-446655440000") is True

    def test_uppercase(self):
        assert _is_valid_uuid("550E8400-E29B-41D4-A716-446655440000") is True

    def test_invalid(self):
        assert _is_valid_uuid("not-a-uuid") is False
        assert _is_valid_uuid("") is False


# ---------------------------------------------------------------------------
# Demo token validation
# ---------------------------------------------------------------------------


class TestValidateDemoToken:
    def test_valid_token(self):
        main.DEMO_TOKEN_SECRET = "test-secret"
        main.DEMO_TOKEN_VALIDATION_ENABLED = True
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        sig = hmac_mod.new(
            b"test-secret", f"provii-demos-v1:{today}".encode(), hashlib.sha256
        ).hexdigest()[:16]
        token = f"demo_token_v1_{today}_{sig}"
        assert validate_demo_token(token) is True

    def test_wrong_prefix(self):
        main.DEMO_TOKEN_SECRET = "test-secret"
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        assert validate_demo_token(f"bad_prefix_v1_{today}_abcdef1234567890") is False

    def test_wrong_sig(self):
        main.DEMO_TOKEN_SECRET = "test-secret"
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        assert validate_demo_token(f"demo_token_v1_{today}_0000000000000000") is False

    def test_old_date(self):
        main.DEMO_TOKEN_SECRET = "test-secret"
        assert validate_demo_token("demo_token_v1_19700101_abcdef1234567890") is False

    def test_malformed(self):
        main.DEMO_TOKEN_SECRET = "test-secret"
        assert validate_demo_token("garbage") is False

    def test_empty(self):
        main.DEMO_TOKEN_SECRET = "test-secret"
        assert validate_demo_token("") is False

    def test_yesterday_accepted(self):
        main.DEMO_TOKEN_SECRET = "test-secret"
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y%m%d")
        sig = hmac_mod.new(
            b"test-secret", f"provii-demos-v1:{yesterday}".encode(), hashlib.sha256
        ).hexdigest()[:16]
        token = f"demo_token_v1_{yesterday}_{sig}"
        assert validate_demo_token(token) is True


# ---------------------------------------------------------------------------
# Health and config endpoints
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"


class TestConfigEndpoint:
    def test_returns_config(self, client):
        resp = client.get("/api/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "has_client_id" in data
        assert "hmac_secret_configured" in data


# ---------------------------------------------------------------------------
# Create challenge endpoint
# ---------------------------------------------------------------------------


class TestCreateChallenge:
    def test_invalid_json(self, client):
        resp = client.post(
            "/api/create-challenge",
            content="not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422 or resp.status_code == 400

    def test_both_ages_rejected(self, client):
        resp = client.post(
            "/api/create-challenge",
            json={"minimum_age": 18, "maximum_age": 25},
        )
        assert resp.status_code == 400

    def test_age_too_low(self, client):
        resp = client.post(
            "/api/create-challenge",
            json={"minimum_age": 5},
        )
        assert resp.status_code == 422  # Pydantic validation

    def test_age_too_high(self, client):
        resp = client.post(
            "/api/create-challenge",
            json={"maximum_age": 130},
        )
        assert resp.status_code == 422

    def test_expires_in_too_low(self, client):
        resp = client.post(
            "/api/create-challenge",
            json={"expires_in": 10},
        )
        assert resp.status_code == 422

    def test_expires_in_too_high(self, client):
        resp = client.post(
            "/api/create-challenge",
            json={"expires_in": 500},
        )
        assert resp.status_code == 422

    @patch("main.create_challenge_with_api", new_callable=AsyncMock)
    def test_success(self, mock_api, client):
        mock_api.return_value = {
            "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
            "rp_challenge": "rp-chal",
            "cutoff_days": 6574,
            "verifying_key_id": 1,
            "submit_secret": "secret",
            "expires_at": int(time.time()) + 300,
            "status_url": "/v1/challenge/550e8400-e29b-41d4-a716-446655440000",
            "verify_url": "/v1/challenge/550e8400-e29b-41d4-a716-446655440000/verify",
            "proof_direction": "over_age",
        }
        resp = client.post("/api/create-challenge", json={"minimum_age": 21})
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert data["deep_link"].startswith("https://provii.app/verify?d=")

    @patch("main.create_challenge_with_api", new_callable=AsyncMock)
    def test_api_failure(self, mock_api, client):
        mock_api.side_effect = Exception("upstream failure")
        resp = client.post("/api/create-challenge", json={"minimum_age": 18})
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# Status endpoint
# ---------------------------------------------------------------------------


class TestGetStatus:
    def test_invalid_uuid(self, client):
        resp = client.get("/api/status/not-a-uuid")
        assert resp.status_code == 400

    def test_session_not_found(self, client):
        resp = client.get("/api/status/550e8400-e29b-41d4-a716-446655440000")
        assert resp.status_code == 404

    @patch("main.poll_challenge_status", new_callable=AsyncMock)
    def test_success(self, mock_poll, client):
        sessions["550e8400-e29b-41d4-a716-446655440000"] = SessionData(
            code_verifier="v",
            challenge_id="550e8400-e29b-41d4-a716-446655440000",
            expires_at=int(time.time()) + 300,
            created_at=int(time.time()),
            proof_direction="over_age",
        )
        mock_poll.return_value = {
            "state": "verified",
            "verified": True,
            "proof_verified": True,
        }
        resp = client.get("/api/status/550e8400-e29b-41d4-a716-446655440000")
        assert resp.status_code == 200
        assert resp.json()["verified"] is True


# ---------------------------------------------------------------------------
# Redeem endpoint
# ---------------------------------------------------------------------------


class TestRedeem:
    def test_invalid_uuid(self, client):
        resp = client.post("/api/redeem/not-a-uuid")
        assert resp.status_code == 400

    def test_session_not_found(self, client):
        resp = client.post("/api/redeem/550e8400-e29b-41d4-a716-446655440000")
        assert resp.status_code == 404

    @patch("main.redeem_challenge", new_callable=AsyncMock)
    def test_success(self, mock_redeem, client):
        sessions["550e8400-e29b-41d4-a716-446655440000"] = SessionData(
            code_verifier="v",
            challenge_id="550e8400-e29b-41d4-a716-446655440000",
            expires_at=int(time.time()) + 300,
            created_at=int(time.time()),
        )
        mock_redeem.return_value = {"result": "success", "verified": True}
        resp = client.post("/api/redeem/550e8400-e29b-41d4-a716-446655440000")
        assert resp.status_code == 200
        assert resp.json()["verified"] is True

    @patch("main.redeem_challenge", new_callable=AsyncMock)
    def test_delete_before_use(self, mock_redeem, client):
        """Verify that session is deleted before redemption attempt."""
        sessions["550e8400-e29b-41d4-a716-446655440000"] = SessionData(
            code_verifier="v",
            challenge_id="550e8400-e29b-41d4-a716-446655440000",
            expires_at=int(time.time()) + 300,
            created_at=int(time.time()),
        )
        mock_redeem.return_value = {"result": "success", "verified": True}

        resp = client.post("/api/redeem/550e8400-e29b-41d4-a716-446655440000")
        assert resp.status_code == 200

        # Second attempt should fail
        resp2 = client.post("/api/redeem/550e8400-e29b-41d4-a716-446655440000")
        assert resp2.status_code == 404


# ---------------------------------------------------------------------------
# Expert mode endpoints
# ---------------------------------------------------------------------------


class TestExpertChallenge:
    def test_missing_code_challenge(self, client):
        resp = client.post("/api/challenge", json={"method": "S256"})
        assert resp.status_code == 422

    @patch("main.create_challenge_with_api", new_callable=AsyncMock)
    def test_success(self, mock_api, client):
        mock_api.return_value = {
            "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
            "rp_challenge": "rp-chal",
        }
        resp = client.post(
            "/api/challenge",
            json={
                "code_challenge": "test-challenge",
                "method": "S256",
                "expires_in": 300,
            },
        )
        assert resp.status_code == 200

    @patch("main.create_challenge_with_api", new_callable=AsyncMock)
    def test_api_failure(self, mock_api, client):
        mock_api.side_effect = Exception("upstream failure")
        resp = client.post(
            "/api/challenge",
            json={"code_challenge": "test-challenge", "method": "S256"},
        )
        assert resp.status_code == 500


class TestExpertPoll:
    def test_missing_challenge_id(self, client):
        resp = client.post("/api/poll", json={})
        assert resp.status_code == 422

    @patch("main.poll_challenge_status", new_callable=AsyncMock)
    def test_success(self, mock_poll, client):
        mock_poll.return_value = {"state": "verified", "verified": True}
        resp = client.post(
            "/api/poll", json={"challengeId": "550e8400-e29b-41d4-a716-446655440000"}
        )
        assert resp.status_code == 200

    @patch("main.poll_challenge_status", new_callable=AsyncMock)
    def test_api_failure(self, mock_poll, client):
        mock_poll.side_effect = Exception("upstream failure")
        resp = client.post(
            "/api/poll", json={"challengeId": "550e8400-e29b-41d4-a716-446655440000"}
        )
        assert resp.status_code == 500


class TestExpertRedeem:
    def test_missing_fields(self, client):
        resp = client.post("/api/redeem", json={"challenge_id": "c"})
        assert resp.status_code == 422

    @patch("main.redeem_challenge", new_callable=AsyncMock)
    def test_success(self, mock_redeem, client):
        mock_redeem.return_value = {"result": "success", "verified": True}
        resp = client.post(
            "/api/redeem",
            json={
                "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
                "code_verifier": "test-verifier",
            },
        )
        assert resp.status_code == 200
        assert "verified_session" in resp.headers.get("set-cookie", "")

    @patch("main.redeem_challenge", new_callable=AsyncMock)
    def test_api_failure(self, mock_redeem, client):
        mock_redeem.side_effect = Exception("upstream failure")
        resp = client.post(
            "/api/redeem",
            json={
                "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
                "code_verifier": "test-verifier",
            },
        )
        assert resp.status_code == 500


class TestExpertSession:
    def test_no_cookie(self, client):
        resp = client.get("/api/session")
        assert resp.status_code == 200
        assert resp.json()["verified"] is False

    def test_with_cookie(self, client):
        client.cookies.set("verified_session", "abc123")
        resp = client.get("/api/session")
        assert resp.status_code == 200
        assert resp.json()["verified"] is True


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------


class TestSecurityHeaders:
    def test_nosniff_present(self, client):
        resp = client.get("/health")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_frame_deny(self, client):
        resp = client.get("/health")
        assert resp.headers.get("X-Frame-Options") == "DENY"


# ---------------------------------------------------------------------------
# Body size limit middleware
# ---------------------------------------------------------------------------


class TestBodySizeLimit:
    def test_oversized_body_rejected(self, client):
        resp = client.post(
            "/api/create-challenge",
            content="x" * (65 * 1024),
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(65 * 1024),
            },
        )
        assert resp.status_code == 413


# ---------------------------------------------------------------------------
# Static file serving
# ---------------------------------------------------------------------------


class TestStaticServing:
    def test_root_redirect(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 307 or resp.status_code == 302

    def test_disallowed_extension(self, client):
        resp = client.get("/secret.json")
        assert resp.status_code == 404

    def test_nonexistent_html(self, client):
        resp = client.get("/nonexistent.html")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# require_credentials
# ---------------------------------------------------------------------------


class TestRequireCredentials:
    def test_exits_when_missing(self):
        import main as m

        saved = (m.config.client_id, m.config.api_key, m.config.hmac_secret)
        m.config.client_id = ""
        m.config.api_key = ""
        m.config.hmac_secret = ""
        try:
            with pytest.raises(SystemExit):
                m.require_credentials()
        finally:
            m.config.client_id, m.config.api_key, m.config.hmac_secret = saved


# ---------------------------------------------------------------------------
# create_challenge_with_api: unconfigured credential errors
# ---------------------------------------------------------------------------


class TestCreateChallengeWithApiErrors:
    def test_missing_hmac_returns_500(self, client):
        """When HMAC_SECRET is empty, challenge creation returns 500."""
        saved = main.config.hmac_secret
        main.config.hmac_secret = ""
        try:
            resp = client.post("/api/create-challenge", json={"minimum_age": 18})
            assert resp.status_code == 500
        finally:
            main.config.hmac_secret = saved

    def test_missing_api_key_returns_500(self, client):
        """When API_KEY is empty, challenge creation returns 500."""
        saved_key = main.config.api_key
        saved_hmac = main.config.hmac_secret
        main.config.api_key = ""
        main.config.hmac_secret = "dGVzdA"
        try:
            resp = client.post("/api/create-challenge", json={"minimum_age": 18})
            assert resp.status_code == 500
        finally:
            main.config.api_key = saved_key
            main.config.hmac_secret = saved_hmac


# ---------------------------------------------------------------------------
# poll_challenge_status: upstream error propagation
# ---------------------------------------------------------------------------


class TestPollChallengeStatusErrors:
    @patch("main.poll_challenge_status", new_callable=AsyncMock)
    def test_upstream_error_in_status(self, mock_poll, client):
        sessions["550e8400-e29b-41d4-a716-446655440000"] = SessionData(
            code_verifier="v",
            challenge_id="550e8400-e29b-41d4-a716-446655440000",
            expires_at=int(time.time()) + 300,
            created_at=int(time.time()),
            proof_direction="over_age",
        )
        mock_poll.side_effect = HTTPException(status_code=500, detail="upstream down")
        resp = client.get("/api/status/550e8400-e29b-41d4-a716-446655440000")
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# redeem: upstream failure propagation
# ---------------------------------------------------------------------------


class TestRedeemErrors:
    @patch("main.redeem_challenge", new_callable=AsyncMock)
    def test_upstream_failure(self, mock_redeem, client):
        sessions["550e8400-e29b-41d4-a716-446655440000"] = SessionData(
            code_verifier="v",
            challenge_id="550e8400-e29b-41d4-a716-446655440000",
            expires_at=int(time.time()) + 300,
            created_at=int(time.time()),
        )
        mock_redeem.side_effect = HTTPException(status_code=400, detail="bad request")
        resp = client.post("/api/redeem/550e8400-e29b-41d4-a716-446655440000")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Expert mode: default expires_in
# ---------------------------------------------------------------------------


class TestExpertChallengeDefaults:
    @patch("main.create_challenge_with_api", new_callable=AsyncMock)
    def test_default_expires_in(self, mock_api, client):
        mock_api.return_value = {
            "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
            "rp_challenge": "rp-chal",
        }
        resp = client.post(
            "/api/challenge",
            json={"code_challenge": "test-challenge", "method": "S256"},
        )
        assert resp.status_code == 200
        # Verify the default expires_in was used (300)
        call_args = mock_api.call_args
        assert call_args[0][2] == 300  # expires_in argument


# ---------------------------------------------------------------------------
# Expert poll: API failure propagation with error structure
# ---------------------------------------------------------------------------


class TestExpertPollErrorStructure:
    @patch("main.poll_challenge_status", new_callable=AsyncMock)
    def test_error_structure(self, mock_poll, client):
        mock_poll.side_effect = Exception("connection timeout")
        resp = client.post(
            "/api/poll", json={"challengeId": "550e8400-e29b-41d4-a716-446655440000"}
        )
        assert resp.status_code == 500
        data = resp.json()
        assert data["detail"]["code"] == "STATUS_CHECK_FAILED"
        assert "reference" in data["detail"]


# ---------------------------------------------------------------------------
# Expert redeem: error response structure
# ---------------------------------------------------------------------------


class TestExpertRedeemErrorStructure:
    @patch("main.redeem_challenge", new_callable=AsyncMock)
    def test_error_structure(self, mock_redeem, client):
        mock_redeem.side_effect = Exception("upstream failure")
        resp = client.post(
            "/api/redeem",
            json={
                "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
                "code_verifier": "test-verifier",
            },
        )
        assert resp.status_code == 500
        data = resp.json()
        assert data["detail"]["code"] == "REDEEM_FAILED"


# ---------------------------------------------------------------------------
# Verify demo token dependency blocks requests when enabled
# ---------------------------------------------------------------------------


class TestDemoTokenDependency:
    def test_config_blocked_with_invalid_token(self):
        main.DEMO_TOKEN_VALIDATION_ENABLED = True
        main.DEMO_TOKEN_SECRET = "test-dep-secret"
        c = TestClient(app)
        resp = c.get("/api/config", headers={"X-Demo-Token": "invalid"})
        assert resp.status_code == 401

    def test_config_passes_with_valid_token(self):
        main.DEMO_TOKEN_VALIDATION_ENABLED = True
        main.DEMO_TOKEN_SECRET = "test-dep-secret"
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        sig = hmac_mod.new(
            b"test-dep-secret", f"provii-demos-v1:{today}".encode(), hashlib.sha256
        ).hexdigest()[:16]
        token = f"demo_token_v1_{today}_{sig}"
        c = TestClient(app)
        resp = c.get("/api/config", headers={"X-Demo-Token": token})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Create challenge: maximum_age success
# ---------------------------------------------------------------------------


class TestCreateChallengeMaxAge:
    @patch("main.create_challenge_with_api", new_callable=AsyncMock)
    def test_maximum_age_success(self, mock_api, client):
        mock_api.return_value = {
            "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
            "rp_challenge": "rp-chal",
            "cutoff_days": 6574,
            "verifying_key_id": 1,
            "submit_secret": "secret",
            "expires_at": int(time.time()) + 300,
            "status_url": "/v1/challenge/550e8400-e29b-41d4-a716-446655440000",
            "verify_url": "/v1/challenge/550e8400-e29b-41d4-a716-446655440000/verify",
            "proof_direction": "under_age",
        }
        resp = client.post("/api/create-challenge", json={"maximum_age": 25})
        assert resp.status_code == 200
        data = resp.json()
        assert data["proof_direction"] == "under_age"

    @patch("main.create_challenge_with_api", new_callable=AsyncMock)
    def test_default_age(self, mock_api, client):
        mock_api.return_value = {
            "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
            "rp_challenge": "rp-chal",
            "cutoff_days": 6574,
            "verifying_key_id": 1,
            "submit_secret": "secret",
            "expires_at": int(time.time()) + 300,
            "status_url": "/v1/challenge/550e8400-e29b-41d4-a716-446655440000",
            "verify_url": "/v1/challenge/550e8400-e29b-41d4-a716-446655440000/verify",
            "proof_direction": "over_age",
        }
        resp = client.post("/api/create-challenge", json={})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# CSP headers on HTML vs API paths
# ---------------------------------------------------------------------------


class TestCSPHeaders:
    def test_api_path_strict_csp(self, client):
        resp = client.get("/api/config")
        csp = resp.headers.get("Content-Security-Policy", "")
        assert "default-src 'none'" in csp

    def test_health_strict_csp(self, client):
        resp = client.get("/health")
        csp = resp.headers.get("Content-Security-Policy", "")
        assert "default-src 'none'" in csp


# ---------------------------------------------------------------------------
# create_challenge_with_api integration (via mocked httpx)
# ---------------------------------------------------------------------------


class TestCreateChallengeWithApiIntegration:
    def test_full_flow_via_httpx_mock(self, client):
        """Exercise the actual create_challenge_with_api HMAC signing path."""
        import httpx

        mock_response = httpx.Response(
            200,
            json={
                "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
                "rp_challenge": "rp-chal",
                "cutoff_days": 6574,
                "verifying_key_id": 1,
                "submit_secret": "secret",
                "expires_at": int(time.time()) + 300,
                "status_url": "/v1/challenge/550e8400-e29b-41d4-a716-446655440000",
                "verify_url": "/v1/challenge/550e8400-e29b-41d4-a716-446655440000/verify",
                "proof_direction": "over_age",
            },
        )

        saved_hmac = main.config.hmac_secret
        saved_key = main.config.api_key
        saved_id = main.config.client_id
        saved_url = main.config.verifier_api_url

        import base64

        secret = (
            base64.urlsafe_b64encode(b"test-hmac-secret-32-bytes!!")
            .rstrip(b"=")
            .decode()
        )
        main.config.hmac_secret = secret
        main.config.api_key = "test-api-key"
        main.config.client_id = "test-client-id"
        main.config.verifier_api_url = "https://mock-verify.provii.app"

        try:
            with patch(
                "httpx.AsyncClient.post",
                new_callable=AsyncMock,
                return_value=mock_response,
            ):
                with patch(
                    "httpx.AsyncClient.get",
                    new_callable=AsyncMock,
                    return_value=httpx.Response(
                        200,
                        json={
                            "state": "verified",
                            "verified": True,
                            "proof_verified": True,
                        },
                    ),
                ):
                    # Create challenge
                    resp = client.post(
                        "/api/create-challenge", json={"minimum_age": 21}
                    )
                    assert resp.status_code == 200
                    data = resp.json()
                    assert data["deep_link"].startswith("https://provii.app/verify?d=")
                    session_id = data["session_id"]

                    # Poll status
                    resp2 = client.get(f"/api/status/{session_id}")
                    assert resp2.status_code == 200
                    assert resp2.json()["verified"] is True
        finally:
            main.config.hmac_secret = saved_hmac
            main.config.api_key = saved_key
            main.config.client_id = saved_id
            main.config.verifier_api_url = saved_url

    def test_upstream_error(self, client):
        """Exercise upstream error path in create_challenge_with_api."""
        import httpx

        mock_response = httpx.Response(400, text="bad request")

        saved_hmac = main.config.hmac_secret
        saved_key = main.config.api_key
        saved_id = main.config.client_id
        saved_url = main.config.verifier_api_url

        import base64

        secret = (
            base64.urlsafe_b64encode(b"test-hmac-secret-32-bytes!!")
            .rstrip(b"=")
            .decode()
        )
        main.config.hmac_secret = secret
        main.config.api_key = "test-api-key"
        main.config.client_id = "test-client-id"
        main.config.verifier_api_url = "https://mock-verify.provii.app"

        try:
            with patch(
                "httpx.AsyncClient.post",
                new_callable=AsyncMock,
                return_value=mock_response,
            ):
                resp = client.post("/api/create-challenge", json={"minimum_age": 21})
                assert resp.status_code == 500
        finally:
            main.config.hmac_secret = saved_hmac
            main.config.api_key = saved_key
            main.config.client_id = saved_id
            main.config.verifier_api_url = saved_url

    def test_poll_upstream_error(self, client):
        """Exercise poll_challenge_status error path via httpx mock."""
        import httpx

        challenge_response = httpx.Response(
            200,
            json={
                "challenge_id": "770e8400-e29b-41d4-a716-446655440000",
                "rp_challenge": "rp-chal",
                "cutoff_days": 6574,
                "verifying_key_id": 1,
                "submit_secret": "secret",
                "expires_at": int(time.time()) + 300,
                "status_url": "/v1/challenge/770e8400-e29b-41d4-a716-446655440000",
                "verify_url": "/v1/challenge/770e8400-e29b-41d4-a716-446655440000/verify",
                "proof_direction": "over_age",
            },
        )
        poll_error = httpx.Response(404, text="not found")

        saved_hmac = main.config.hmac_secret
        saved_key = main.config.api_key
        saved_id = main.config.client_id
        saved_url = main.config.verifier_api_url

        import base64

        secret = (
            base64.urlsafe_b64encode(b"test-hmac-secret-32-bytes!!")
            .rstrip(b"=")
            .decode()
        )
        main.config.hmac_secret = secret
        main.config.api_key = "test-api-key"
        main.config.client_id = "test-client-id"
        main.config.verifier_api_url = "https://mock-verify.provii.app"

        try:
            with patch(
                "httpx.AsyncClient.post",
                new_callable=AsyncMock,
                return_value=challenge_response,
            ):
                resp = client.post("/api/create-challenge", json={"minimum_age": 18})
                assert resp.status_code == 200
                session_id = resp.json()["session_id"]

            with patch(
                "httpx.AsyncClient.get", new_callable=AsyncMock, return_value=poll_error
            ):
                resp2 = client.get(f"/api/status/{session_id}")
                assert resp2.status_code == 404
        finally:
            main.config.hmac_secret = saved_hmac
            main.config.api_key = saved_key
            main.config.client_id = saved_id
            main.config.verifier_api_url = saved_url

    def test_redeem_upstream_error(self, client):
        """Exercise redeem_challenge error path via httpx mock."""
        import httpx

        challenge_response = httpx.Response(
            200,
            json={
                "challenge_id": "880e8400-e29b-41d4-a716-446655440000",
                "rp_challenge": "rp-chal",
                "cutoff_days": 6574,
                "verifying_key_id": 1,
                "submit_secret": "secret",
                "expires_at": int(time.time()) + 300,
                "status_url": "/v1/challenge/880e8400-e29b-41d4-a716-446655440000",
                "verify_url": "/v1/challenge/880e8400-e29b-41d4-a716-446655440000/verify",
                "proof_direction": "over_age",
            },
        )
        redeem_error = httpx.Response(400, text="invalid verifier")

        saved_hmac = main.config.hmac_secret
        saved_key = main.config.api_key
        saved_id = main.config.client_id
        saved_url = main.config.verifier_api_url

        import base64

        secret = (
            base64.urlsafe_b64encode(b"test-hmac-secret-32-bytes!!")
            .rstrip(b"=")
            .decode()
        )
        main.config.hmac_secret = secret
        main.config.api_key = "test-api-key"
        main.config.client_id = "test-client-id"
        main.config.verifier_api_url = "https://mock-verify.provii.app"

        try:
            with patch(
                "httpx.AsyncClient.post",
                new_callable=AsyncMock,
                side_effect=[challenge_response, redeem_error],
            ):
                resp = client.post("/api/create-challenge", json={"minimum_age": 18})
                assert resp.status_code == 200
                session_id = resp.json()["session_id"]

                resp2 = client.post(f"/api/redeem/{session_id}")
                assert resp2.status_code == 400
        finally:
            main.config.hmac_secret = saved_hmac
            main.config.api_key = saved_key
            main.config.client_id = saved_id
            main.config.verifier_api_url = saved_url

    def test_redeem_with_httpx_mock(self, client):
        """Exercise the full redeem path with mocked httpx."""
        import httpx

        challenge_response = httpx.Response(
            200,
            json={
                "challenge_id": "660e8400-e29b-41d4-a716-446655440000",
                "rp_challenge": "rp-chal",
                "cutoff_days": 6574,
                "verifying_key_id": 1,
                "submit_secret": "secret",
                "expires_at": int(time.time()) + 300,
                "status_url": "/v1/challenge/660e8400-e29b-41d4-a716-446655440000",
                "verify_url": "/v1/challenge/660e8400-e29b-41d4-a716-446655440000/verify",
                "proof_direction": "over_age",
            },
        )
        redeem_response = httpx.Response(
            200,
            json={"result": "success", "verified": True},
        )

        saved_hmac = main.config.hmac_secret
        saved_key = main.config.api_key
        saved_id = main.config.client_id
        saved_url = main.config.verifier_api_url

        import base64

        secret = (
            base64.urlsafe_b64encode(b"test-hmac-secret-32-bytes!!")
            .rstrip(b"=")
            .decode()
        )
        main.config.hmac_secret = secret
        main.config.api_key = "test-api-key"
        main.config.client_id = "test-client-id"
        main.config.verifier_api_url = "https://mock-verify.provii.app"

        try:
            with patch(
                "httpx.AsyncClient.post",
                new_callable=AsyncMock,
                side_effect=[challenge_response, redeem_response],
            ):
                # Create challenge
                resp = client.post("/api/create-challenge", json={"minimum_age": 18})
                assert resp.status_code == 200
                session_id = resp.json()["session_id"]

                # Redeem
                resp2 = client.post(f"/api/redeem/{session_id}")
                assert resp2.status_code == 200
                assert resp2.json()["verified"] is True
        finally:
            main.config.hmac_secret = saved_hmac
            main.config.api_key = saved_key
            main.config.client_id = saved_id
            main.config.verifier_api_url = saved_url
