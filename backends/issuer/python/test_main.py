# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Provii

"""Tests for the Provii Issuer Backend Demo (Python/FastAPI)."""

import hashlib
import hmac as hmac_mod
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

import main
from main import (
    app,
    base64url_decode,
    build_canonical_message,
    hmac_sha256_hex,
    validate_demo_token,
)

# HTTPException is used in some test assertions
from fastapi import HTTPException  # noqa: F401


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset demo token state between tests."""
    original_secret = main.DEMO_TOKEN_SECRET
    original_enabled = main.DEMO_TOKEN_VALIDATION_ENABLED
    yield
    main.DEMO_TOKEN_SECRET = original_secret
    main.DEMO_TOKEN_VALIDATION_ENABLED = original_enabled


@pytest.fixture()
def _disable_demo_token():
    """Disable demo token validation."""
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


class TestBase64urlDecode:
    def test_roundtrip(self):
        import base64

        original = b"test-key-bytes"
        encoded = base64.urlsafe_b64encode(original).rstrip(b"=").decode()
        decoded = base64url_decode(encoded)
        assert decoded == original

    def test_with_padding_needed(self):
        decoded = base64url_decode("YQ")  # 'a'
        assert decoded == b"a"


class TestHmacSha256Hex:
    def test_produces_correct_hex(self):
        secret = b"my-secret"
        message = "hello world"
        got = hmac_sha256_hex(secret, message)
        expected = hmac_mod.new(secret, message.encode(), hashlib.sha256).hexdigest()
        assert got == expected


class TestBuildCanonicalMessage:
    def test_format(self):
        got = build_canonical_message(7000, "client-123", 1700000000, "abc123")
        expected = (
            "1700000000:POST:/v1/attestation/create:"
            '{"dob_days":7000,"authorizer":{"format":"client",'
            '"key_id":"client-123","timestamp":1700000000}}:abc123'
        )
        assert got == expected

    def test_negative_dob(self):
        got = build_canonical_message(-5000, "client-456", 1700000000, "nonce")
        assert '"dob_days":-5000' in got


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
        assert validate_demo_token(f"demo_token_v1_{today}_{sig}") is True

    def test_wrong_prefix(self):
        main.DEMO_TOKEN_SECRET = "test-secret"
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        assert validate_demo_token(f"bad_token_v1_{today}_0000000000000000") is False

    def test_wrong_sig(self):
        main.DEMO_TOKEN_SECRET = "test-secret"
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        assert validate_demo_token(f"demo_token_v1_{today}_0000000000000000") is False

    def test_old_date(self):
        main.DEMO_TOKEN_SECRET = "test-secret"
        assert validate_demo_token("demo_token_v1_19700101_0000000000000000") is False

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
        assert validate_demo_token(f"demo_token_v1_{yesterday}_{sig}") is True


# ---------------------------------------------------------------------------
# Health and config endpoints
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["mode"] == "hmac-authenticated"


class TestConfigEndpoint:
    def test_returns_config(self, client):
        resp = client.get("/api/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "has_client_id" in data
        assert "hmac_configured" in data
        assert data["mode"] == "hmac-authenticated"


# ---------------------------------------------------------------------------
# Create attestation endpoint
# ---------------------------------------------------------------------------


class TestCreateAttestation:
    def test_invalid_json(self, client):
        resp = client.post(
            "/api/create-attestation",
            content="not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_dob_days_too_high(self, client):
        resp = client.post("/api/create-attestation", json={"dob_days": 999999})
        assert resp.status_code == 422

    def test_dob_days_too_low(self, client):
        resp = client.post("/api/create-attestation", json={"dob_days": -30000})
        assert resp.status_code == 422

    @patch("main.create_attestation", new_callable=AsyncMock)
    def test_success(self, mock_api, client):
        mock_api.return_value = {
            "attestation": "dGVzdC1hdHRlc3RhdGlvbg",
            "expires_at": 1700000600,
            "issuer_id": "issuer-test",
        }
        resp = client.post("/api/create-attestation", json={"dob_days": 7000})
        assert resp.status_code == 200
        data = resp.json()
        assert data["deep_link"].startswith("https://provii.app/attest?d=")

    @patch("main.create_attestation", new_callable=AsyncMock)
    def test_api_failure(self, mock_api, client):
        mock_api.side_effect = ValueError("HMAC_SECRET not configured")
        resp = client.post("/api/create-attestation", json={"dob_days": 7000})
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# Create attestation from DOB endpoint
# ---------------------------------------------------------------------------


class TestCreateAttestationFromDob:
    def test_invalid_json(self, client):
        resp = client.post(
            "/api/create-attestation-from-dob",
            content="not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_invalid_date_format(self, client):
        resp = client.post(
            "/api/create-attestation-from-dob", json={"dob": "not-a-date"}
        )
        assert resp.status_code == 422

    def test_empty_dob(self, client):
        resp = client.post("/api/create-attestation-from-dob", json={"dob": ""})
        assert resp.status_code == 422

    def test_future_date(self, client):
        resp = client.post(
            "/api/create-attestation-from-dob", json={"dob": "2099-01-01"}
        )
        assert resp.status_code == 400

    @patch("main.create_attestation", new_callable=AsyncMock)
    def test_success(self, mock_api, client):
        mock_api.return_value = {
            "attestation": "dGVzdC1hdHRlc3RhdGlvbg",
            "expires_at": 1700000600,
            "issuer_id": "issuer-test",
        }
        resp = client.post(
            "/api/create-attestation-from-dob", json={"dob": "1990-05-15"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["deep_link"].startswith("https://provii.app/attest?d=")
        assert data["dob_days"] is not None

    @patch("main.create_attestation", new_callable=AsyncMock)
    def test_api_failure(self, mock_api, client):
        mock_api.side_effect = ValueError("HMAC_SECRET not configured")
        resp = client.post(
            "/api/create-attestation-from-dob", json={"dob": "1990-05-15"}
        )
        assert resp.status_code == 500

    def test_unparseable_date(self, client):
        resp = client.post(
            "/api/create-attestation-from-dob", json={"dob": "1990-13-01"}
        )
        assert resp.status_code == 400 or resp.status_code == 422


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------


class TestSecurityHeaders:
    def test_nosniff_present(self, client):
        resp = client.get("/health")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_frame_deny(self, client):
        resp = client.get("/health")
        assert resp.headers.get("X-Frame-Options") == "DENY"


# ---------------------------------------------------------------------------
# Body size limit
# ---------------------------------------------------------------------------


class TestBodySizeLimit:
    def test_oversized_body_rejected(self, client):
        resp = client.post(
            "/api/create-attestation",
            content="x" * (65 * 1024),
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(65 * 1024),
            },
        )
        assert resp.status_code == 413


# ---------------------------------------------------------------------------
# require_credentials
# ---------------------------------------------------------------------------


class TestRequireCredentials:
    def test_exits_when_missing(self):
        saved = dict(main.config)
        main.config["client_id"] = ""
        main.config["hmac_secret"] = ""
        main.config["issuer_api_url"] = ""
        try:
            with pytest.raises(SystemExit):
                main.require_credentials()
        finally:
            main.config.update(saved)

    def test_passes_when_configured(self):
        saved = dict(main.config)
        main.config["client_id"] = "c"
        main.config["hmac_secret"] = "s"
        main.config["issuer_api_url"] = "https://sandbox-issue.provii.app"
        try:
            # Should not raise
            main.require_credentials()
        finally:
            main.config.update(saved)


# ---------------------------------------------------------------------------
# create_attestation: error paths
# ---------------------------------------------------------------------------


class TestCreateAttestationErrors:
    def test_missing_hmac_returns_500(self, client):
        """When hmac_secret is empty, attestation creation returns 500."""
        saved = dict(main.config)
        main.config["hmac_secret"] = ""
        try:
            resp = client.post("/api/create-attestation", json={"dob_days": 7000})
            assert resp.status_code == 500
        finally:
            main.config.update(saved)

    def test_missing_issuer_url_returns_500(self, client):
        """When issuer_api_url is empty, attestation creation returns 500."""
        saved = dict(main.config)
        main.config["hmac_secret"] = "dGVzdA"
        main.config["issuer_api_url"] = ""
        try:
            resp = client.post("/api/create-attestation", json={"dob_days": 7000})
            assert resp.status_code == 500
        finally:
            main.config.update(saved)


# ---------------------------------------------------------------------------
# Attestation handler: error response structure
# ---------------------------------------------------------------------------


class TestAttestationErrorStructure:
    @patch("main.create_attestation", new_callable=AsyncMock)
    def test_value_error_returns_500(self, mock_api, client):
        mock_api.side_effect = ValueError("HMAC_SECRET not configured")
        resp = client.post("/api/create-attestation", json={"dob_days": 7000})
        assert resp.status_code == 500
        data = resp.json()
        assert data["detail"]["code"] == "ATTESTATION_FAILED"
        assert "reference" in data["detail"]

    @patch("main.create_attestation", new_callable=AsyncMock)
    def test_runtime_error_returns_500(self, mock_api, client):
        mock_api.side_effect = RuntimeError("Issuer API returned 500")
        resp = client.post("/api/create-attestation", json={"dob_days": 7000})
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# Attestation from DOB: error paths
# ---------------------------------------------------------------------------


class TestAttestationFromDobErrorPaths:
    def test_unparseable_date_2(self, client):
        resp = client.post(
            "/api/create-attestation-from-dob", json={"dob": "2000-02-30"}
        )
        assert resp.status_code == 400

    @patch("main.create_attestation", new_callable=AsyncMock)
    def test_api_runtime_error(self, mock_api, client):
        mock_api.side_effect = RuntimeError("Issuer API returned 500")
        resp = client.post(
            "/api/create-attestation-from-dob", json={"dob": "1990-05-15"}
        )
        assert resp.status_code == 500
        data = resp.json()
        assert data["detail"]["code"] == "ATTESTATION_FAILED"

    @patch("main.create_attestation", new_callable=AsyncMock)
    def test_pre_epoch_date(self, mock_api, client):
        mock_api.return_value = {
            "attestation": "dGVzdA",
            "expires_at": 1700000600,
            "issuer_id": "id",
        }
        resp = client.post(
            "/api/create-attestation-from-dob", json={"dob": "1960-06-15"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["dob_days"] < 0


# ---------------------------------------------------------------------------
# Demo token: middleware with valid token
# ---------------------------------------------------------------------------


class TestDemoTokenMiddleware:
    def test_valid_token_passes(self):
        main.DEMO_TOKEN_VALIDATION_ENABLED = True
        main.DEMO_TOKEN_SECRET = "test-issuer-dep-secret"
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        sig = hmac_mod.new(
            b"test-issuer-dep-secret",
            f"provii-demos-v1:{today}".encode(),
            hashlib.sha256,
        ).hexdigest()[:16]
        token = f"demo_token_v1_{today}_{sig}"
        c = TestClient(app)
        resp = c.get("/api/config", headers={"X-Demo-Token": token})
        assert resp.status_code == 200

    def test_invalid_token_blocked(self):
        main.DEMO_TOKEN_VALIDATION_ENABLED = True
        main.DEMO_TOKEN_SECRET = "test-issuer-dep-secret"
        c = TestClient(app)
        resp = c.get("/api/config", headers={"X-Demo-Token": "invalid"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------


class TestGlobalExceptionHandler:
    @patch("main.create_attestation", new_callable=AsyncMock)
    def test_unhandled_exception_returns_500(self, mock_api):
        """Trigger the global exception handler by raising an unexpected error type."""
        mock_api.side_effect = TypeError("unexpected error type")
        main.DEMO_TOKEN_VALIDATION_ENABLED = False
        c = TestClient(app, raise_server_exceptions=False)
        resp = c.post(
            "/api/create-attestation",
            json={"dob_days": 7000},
        )
        # TypeError falls through the (ValueError, RuntimeError) catch and
        # hits the global exception handler.
        assert resp.status_code == 500
        data = resp.json()
        assert data["code"] == "INTERNAL_ERROR"
        assert "reference" in data


# ---------------------------------------------------------------------------
# Config handler: field values
# ---------------------------------------------------------------------------


class TestConfigHandlerValues:
    def test_mode_field(self, client):
        resp = client.get("/api/config")
        data = resp.json()
        assert data["mode"] == "hmac-authenticated"

    def test_unconfigured_fields(self, client):
        saved = dict(main.config)
        main.config["client_id"] = ""
        main.config["hmac_secret"] = ""
        try:
            resp = client.get("/api/config")
            data = resp.json()
            assert data["has_client_id"] is False
            assert data["hmac_configured"] is False
        finally:
            main.config.update(saved)


# ---------------------------------------------------------------------------
# CSP headers on API paths
# ---------------------------------------------------------------------------


class TestCSPHeaders:
    def test_api_path_strict_csp(self, client):
        resp = client.get("/api/config")
        csp = resp.headers.get("Content-Security-Policy", "")
        assert "default-src 'none'" in csp


# ---------------------------------------------------------------------------
# create_attestation: integration test with httpx mock
# ---------------------------------------------------------------------------


class TestCreateAttestationIntegration:
    def test_success_via_handler(self, client):
        """Test the full attestation flow with a mocked httpx response."""
        import httpx

        mock_response = httpx.Response(
            200,
            json={
                "attestation": "dGVzdC1hdHRlc3RhdGlvbg",
                "expires_at": 1700000600,
                "issuer_id": "issuer-test",
            },
        )

        saved = dict(main.config)
        import base64

        secret = (
            base64.urlsafe_b64encode(b"test-hmac-secret-32-bytes!!")
            .rstrip(b"=")
            .decode()
        )
        main.config["client_id"] = "test-client"
        main.config["hmac_secret"] = secret
        main.config["issuer_api_url"] = "https://mock-issuer.provii.app"

        try:
            with patch(
                "httpx.AsyncClient.post",
                new_callable=AsyncMock,
                return_value=mock_response,
            ):
                resp = client.post("/api/create-attestation", json={"dob_days": 7000})
                assert resp.status_code == 200
                data = resp.json()
                assert data["deep_link"].startswith("https://provii.app/attest?d=")
                assert data["expires_at"] == 1700000600
        finally:
            main.config.update(saved)

    def test_from_dob_success_via_handler(self, client):
        """Test attestation from DOB with mocked httpx response."""
        import httpx

        mock_response = httpx.Response(
            200,
            json={
                "attestation": "dGVzdC1hdHRlc3RhdGlvbg",
                "expires_at": 1700000600,
                "issuer_id": "issuer-test",
            },
        )

        saved = dict(main.config)
        import base64

        secret = (
            base64.urlsafe_b64encode(b"test-hmac-secret-32-bytes!!")
            .rstrip(b"=")
            .decode()
        )
        main.config["client_id"] = "test-client"
        main.config["hmac_secret"] = secret
        main.config["issuer_api_url"] = "https://mock-issuer.provii.app"

        try:
            with patch(
                "httpx.AsyncClient.post",
                new_callable=AsyncMock,
                return_value=mock_response,
            ):
                resp = client.post(
                    "/api/create-attestation-from-dob", json={"dob": "1990-05-15"}
                )
                assert resp.status_code == 200
                data = resp.json()
                assert data["dob_days"] is not None
        finally:
            main.config.update(saved)

    def test_upstream_500_via_handler(self, client):
        """Test upstream failure propagation."""
        import httpx

        mock_response = httpx.Response(500, text="internal error")

        saved = dict(main.config)
        import base64

        secret = (
            base64.urlsafe_b64encode(b"test-hmac-secret-32-bytes!!")
            .rstrip(b"=")
            .decode()
        )
        main.config["client_id"] = "test-client"
        main.config["hmac_secret"] = secret
        main.config["issuer_api_url"] = "https://mock-issuer.provii.app"

        try:
            with patch(
                "httpx.AsyncClient.post",
                new_callable=AsyncMock,
                return_value=mock_response,
            ):
                resp = client.post("/api/create-attestation", json={"dob_days": 7000})
                assert resp.status_code == 500
        finally:
            main.config.update(saved)

    def test_missing_attestation_field(self, client):
        """Test response missing the attestation field."""
        import httpx

        mock_response = httpx.Response(
            200,
            json={"expires_at": 1700000600, "issuer_id": "id"},
        )

        saved = dict(main.config)
        import base64

        secret = (
            base64.urlsafe_b64encode(b"test-hmac-secret-32-bytes!!")
            .rstrip(b"=")
            .decode()
        )
        main.config["client_id"] = "test-client"
        main.config["hmac_secret"] = secret
        main.config["issuer_api_url"] = "https://mock-issuer.provii.app"

        try:
            with patch(
                "httpx.AsyncClient.post",
                new_callable=AsyncMock,
                return_value=mock_response,
            ):
                resp = client.post("/api/create-attestation", json={"dob_days": 7000})
                assert resp.status_code == 500
        finally:
            main.config.update(saved)
