// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// setupMockIssuerAPI creates a mock provii-issuer server and configures the
// global config to use it. Returns a cleanup function that restores the
// original config.
func setupMockIssuerAPI(t *testing.T) (*httptest.Server, func()) {
	t.Helper()

	savedConfig := config
	savedSecret := demoTokenSecret
	savedEnabled := demoTokenValidationEnabled

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/v1/attestation/create" && r.Method == "POST" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"attestation": "dGVzdC1hdHRlc3RhdGlvbi1kYXRh",
				"expires_at":  time.Now().Unix() + 300,
				"issuer_id":   "issuer-test-id",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		ClientId:       "test-client-id",
		HmacSecret:     secret,
		IssuerApiUrl:   mockServer.URL,
		Port:           "3000",
		AllowedOrigins: map[string]bool{"http://localhost:3000": true},
		IsProduction:   false,
	}
	demoTokenSecret = ""
	demoTokenValidationEnabled = false

	cleanup := func() {
		mockServer.Close()
		config = savedConfig
		demoTokenSecret = savedSecret
		demoTokenValidationEnabled = savedEnabled
	}

	return mockServer, cleanup
}

// ---------------------------------------------------------------------------
// Utility function tests
// ---------------------------------------------------------------------------

func TestGetEnv(t *testing.T) {
	t.Run("returns value when set", func(t *testing.T) {
		t.Setenv("TEST_GET_ENV_KEY", "hello")
		if got := getEnv("TEST_GET_ENV_KEY", "fallback"); got != "hello" {
			t.Errorf("getEnv() = %q, want %q", got, "hello")
		}
	})
	t.Run("returns fallback when unset", func(t *testing.T) {
		os.Unsetenv("TEST_GET_ENV_MISSING")
		if got := getEnv("TEST_GET_ENV_MISSING", "default"); got != "default" {
			t.Errorf("getEnv() = %q, want %q", got, "default")
		}
	})
}

func TestBase64urlDecode(t *testing.T) {
	original := []byte("test-secret-key-bytes")
	encoded := base64.RawURLEncoding.EncodeToString(original)
	decoded, err := base64urlDecode(encoded)
	if err != nil {
		t.Fatalf("base64urlDecode() error: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("round-trip failed: got %q, want %q", decoded, original)
	}
}

func TestBase64urlDecodeInvalid(t *testing.T) {
	_, err := base64urlDecode("!!!not-valid!!!")
	if err == nil {
		t.Error("expected error for invalid base64url input")
	}
}

func TestHmacSha256Hex(t *testing.T) {
	secret := []byte("my-secret")
	message := "hello world"
	got := hmacSha256Hex(secret, message)

	h := hmac.New(sha256.New, secret)
	h.Write([]byte(message))
	want := hex.EncodeToString(h.Sum(nil))

	if got != want {
		t.Errorf("hmacSha256Hex() = %q, want %q", got, want)
	}
}

func TestBuildCanonicalMessage(t *testing.T) {
	got := buildCanonicalMessage(7000, "client-123", 1700000000, "abc123")
	want := `1700000000:POST:/v1/attestation/create:{"dob_days":7000,"authorizer":{"format":"client","key_id":"client-123","timestamp":1700000000}}:abc123`
	if got != want {
		t.Errorf("buildCanonicalMessage() =\n  %q\nwant\n  %q", got, want)
	}
}

func TestBuildCanonicalMessageNegativeDob(t *testing.T) {
	got := buildCanonicalMessage(-5000, "client-456", 1700000000, "nonce")
	if !strings.Contains(got, `"dob_days":-5000`) {
		t.Errorf("expected negative dob_days in canonical message, got: %s", got)
	}
}

func TestParseAllowedOrigins(t *testing.T) {
	origins := parseAllowedOrigins("http://localhost:3000, https://example.com , http://other.test")
	if len(origins) != 3 {
		t.Fatalf("expected 3 origins, got %d", len(origins))
	}
	for _, want := range []string{"http://localhost:3000", "https://example.com", "http://other.test"} {
		if !origins[want] {
			t.Errorf("expected origin %q in map", want)
		}
	}
}

func TestParseAllowedOriginsEmpty(t *testing.T) {
	origins := parseAllowedOrigins("")
	if len(origins) != 0 {
		t.Errorf("expected 0 origins for empty string, got %d", len(origins))
	}
}

func TestParseAllowedOriginsTrailingComma(t *testing.T) {
	origins := parseAllowedOrigins("http://a.com,")
	if len(origins) != 1 {
		t.Errorf("expected 1 origin, got %d: %v", len(origins), origins)
	}
}

func TestGenerateErrorID(t *testing.T) {
	id := generateErrorID()
	if len(id) != 8 {
		t.Errorf("generateErrorID() length = %d, want 8", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Errorf("generateErrorID() produced invalid hex: %v", err)
	}
	// Uniqueness
	id2 := generateErrorID()
	if id == id2 {
		t.Error("two calls to generateErrorID() returned the same value")
	}
}

// ---------------------------------------------------------------------------
// Demo Token validation
// ---------------------------------------------------------------------------

func TestValidateDemoToken(t *testing.T) {
	originalSecret := demoTokenSecret
	originalEnabled := demoTokenValidationEnabled
	defer func() {
		demoTokenSecret = originalSecret
		demoTokenValidationEnabled = originalEnabled
	}()

	demoTokenSecret = "test-demo-secret"
	demoTokenValidationEnabled = true

	today := time.Now().UTC().Format("20060102")

	h := hmac.New(sha256.New, []byte("test-demo-secret"))
	h.Write([]byte("provii-demos-v1:" + today))
	expectedSig := hex.EncodeToString(h.Sum(nil))[:16]
	validToken := "demo_token_v1_" + today + "_" + expectedSig

	t.Run("valid token accepted", func(t *testing.T) {
		if !validateDemoToken(validToken) {
			t.Error("validateDemoToken() returned false for a valid token")
		}
	})

	t.Run("wrong prefix rejected", func(t *testing.T) {
		if validateDemoToken("bad_token_v1_" + today + "_" + expectedSig) {
			t.Error("accepted token with wrong prefix")
		}
	})

	t.Run("wrong signature rejected", func(t *testing.T) {
		if validateDemoToken("demo_token_v1_" + today + "_0000000000000000") {
			t.Error("accepted token with wrong signature")
		}
	})

	t.Run("old date rejected", func(t *testing.T) {
		if validateDemoToken("demo_token_v1_20200101_" + expectedSig) {
			t.Error("accepted token with old date")
		}
	})

	t.Run("malformed token rejected", func(t *testing.T) {
		if validateDemoToken("not-a-token") {
			t.Error("accepted malformed token")
		}
	})

	t.Run("empty token rejected", func(t *testing.T) {
		if validateDemoToken("") {
			t.Error("accepted empty token")
		}
	})

	t.Run("too many parts rejected", func(t *testing.T) {
		if validateDemoToken("demo_token_v1_" + today + "_sig_extra") {
			t.Error("accepted token with extra parts")
		}
	})

	t.Run("yesterday accepted", func(t *testing.T) {
		yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("20060102")
		yh := hmac.New(sha256.New, []byte("test-demo-secret"))
		yh.Write([]byte("provii-demos-v1:" + yesterday))
		ySig := hex.EncodeToString(yh.Sum(nil))[:16]
		yToken := "demo_token_v1_" + yesterday + "_" + ySig
		if !validateDemoToken(yToken) {
			t.Error("rejected token dated yesterday")
		}
	})
}

// ---------------------------------------------------------------------------
// Health / Config handlers
// ---------------------------------------------------------------------------

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	healthHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status field = %v, want %q", body["status"], "ok")
	}
	if body["mode"] != "hmac-authenticated" {
		t.Errorf("mode field = %v, want %q", body["mode"], "hmac-authenticated")
	}
}

func TestConfigHandler(t *testing.T) {
	config = Config{
		ClientId:       "test-client",
		HmacSecret:     "test-secret",
		IssuerApiUrl:   "https://sandbox-issue.provii.app",
		Port:           "3000",
		AllowedOrigins: map[string]bool{"http://localhost:3000": true},
	}

	req := httptest.NewRequest("GET", "/api/config", nil)
	rec := httptest.NewRecorder()
	configHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if body["has_client_id"] != true {
		t.Error("has_client_id should be true")
	}
	if body["hmac_configured"] != true {
		t.Error("hmac_configured should be true")
	}
	if body["issuer_api_url"] != "https://sandbox-issue.provii.app" {
		t.Errorf("issuer_api_url = %v", body["issuer_api_url"])
	}
}

func TestConfigHandlerUnconfigured(t *testing.T) {
	savedConfig := config
	defer func() { config = savedConfig }()

	config = Config{
		ClientId:       "",
		HmacSecret:     "",
		IssuerApiUrl:   "",
		Port:           "3000",
		AllowedOrigins: map[string]bool{},
	}

	req := httptest.NewRequest("GET", "/api/config", nil)
	rec := httptest.NewRecorder()
	configHandler(rec, req)

	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	if body["has_client_id"] != false {
		t.Error("has_client_id should be false")
	}
	if body["hmac_configured"] != false {
		t.Error("hmac_configured should be false")
	}
}

// ---------------------------------------------------------------------------
// createAttestation
// ---------------------------------------------------------------------------

func TestCreateAttestationMissingConfig(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	config.HmacSecret = ""
	_, err := createAttestation(7000)
	if err == nil {
		t.Error("expected error when HmacSecret is empty")
	}

	config.HmacSecret = "something"
	config.IssuerApiUrl = ""
	_, err = createAttestation(7000)
	if err == nil {
		t.Error("expected error when IssuerApiUrl is empty")
	}
}

func TestCreateAttestationSuccess(t *testing.T) {
	_, cleanup := setupMockIssuerAPI(t)
	defer cleanup()

	resp, err := createAttestation(7000)
	if err != nil {
		t.Fatalf("createAttestation() error: %v", err)
	}
	if resp.Attestation == "" {
		t.Error("attestation should not be empty")
	}
	if resp.IssuerId == "" {
		t.Error("issuer_id should not be empty")
	}
}

func TestCreateAttestationServerError(t *testing.T) {
	savedConfig := config
	defer func() { config = savedConfig }()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		ClientId:     "test-client",
		HmacSecret:   secret,
		IssuerApiUrl: mockServer.URL,
		Port:         "3000",
	}

	_, err := createAttestation(7000)
	if err == nil {
		t.Error("expected error for server 500")
	}
}

func TestCreateAttestationMissingField(t *testing.T) {
	savedConfig := config
	defer func() { config = savedConfig }()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"expires_at": time.Now().Unix() + 300,
			"issuer_id":  "id",
		})
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		ClientId:     "test-client",
		HmacSecret:   secret,
		IssuerApiUrl: mockServer.URL,
		Port:         "3000",
	}

	_, err := createAttestation(7000)
	if err == nil {
		t.Error("expected error when attestation field is missing")
	}
}

func TestCreateAttestationInvalidJSON(t *testing.T) {
	savedConfig := config
	defer func() { config = savedConfig }()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		ClientId:     "test-client",
		HmacSecret:   secret,
		IssuerApiUrl: mockServer.URL,
		Port:         "3000",
	}

	_, err := createAttestation(7000)
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

// ---------------------------------------------------------------------------
// createAttestationHandler
// ---------------------------------------------------------------------------

func TestCreateAttestationHandlerInvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/create-attestation", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	createAttestationHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateAttestationHandlerInvalidDobDays(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/create-attestation", strings.NewReader(`{"dob_days": 999999}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createAttestationHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateAttestationHandlerDobDaysTooLow(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/create-attestation", strings.NewReader(`{"dob_days": -30000}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createAttestationHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCreateAttestationHandlerMissingConfig(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	config.HmacSecret = ""
	config.IssuerApiUrl = ""
	config.ClientId = "test"

	req := httptest.NewRequest("POST", "/api/create-attestation", strings.NewReader(`{"dob_days": 7000}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createAttestationHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestCreateAttestationHandlerSuccess(t *testing.T) {
	_, cleanup := setupMockIssuerAPI(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/create-attestation", strings.NewReader(`{"dob_days": 7000}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createAttestationHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var resp CreateAttestationResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.DeepLink == "" {
		t.Error("deep_link should not be empty")
	}
	if !strings.HasPrefix(resp.DeepLink, "https://provii.app/attest?d=") {
		t.Errorf("unexpected deep link: %s", resp.DeepLink)
	}
}

// ---------------------------------------------------------------------------
// createAttestationFromDobHandler
// ---------------------------------------------------------------------------

func TestCreateAttestationFromDobHandlerInvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/create-attestation-from-dob", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	createAttestationFromDobHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateAttestationFromDobHandlerInvalidDate(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/create-attestation-from-dob", strings.NewReader(`{"dob": "not-a-date"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createAttestationFromDobHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateAttestationFromDobHandlerEmptyDob(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/create-attestation-from-dob", strings.NewReader(`{"dob": ""}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createAttestationFromDobHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateAttestationFromDobHandlerFutureDate(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/create-attestation-from-dob", strings.NewReader(`{"dob": "2099-01-01"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createAttestationFromDobHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for out-of-range date", rec.Code)
	}
}

func TestCreateAttestationFromDobHandlerValidDate(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	config.HmacSecret = ""
	config.IssuerApiUrl = ""
	config.ClientId = "test"

	// Valid date that will pass parsing but fail on createAttestation (missing config).
	req := httptest.NewRequest("POST", "/api/create-attestation-from-dob", strings.NewReader(`{"dob": "1990-05-15"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createAttestationFromDobHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestCreateAttestationFromDobHandlerSuccess(t *testing.T) {
	_, cleanup := setupMockIssuerAPI(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/create-attestation-from-dob", strings.NewReader(`{"dob": "1990-05-15"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createAttestationFromDobHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var resp CreateAttestationResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.DeepLink == "" {
		t.Error("deep_link should not be empty")
	}
	if resp.DobDays == 0 {
		t.Error("dob_days should be non-zero for a 1990 date")
	}
}

func TestCreateAttestationFromDobHandlerPreEpoch(t *testing.T) {
	_, cleanup := setupMockIssuerAPI(t)
	defer cleanup()

	// Pre-epoch date (negative dob_days)
	req := httptest.NewRequest("POST", "/api/create-attestation-from-dob", strings.NewReader(`{"dob": "1960-01-15"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createAttestationFromDobHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var resp CreateAttestationResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.DobDays >= 0 {
		t.Errorf("expected negative dob_days for pre-epoch date, got %d", resp.DobDays)
	}
}

func TestCreateAttestationFromDobHandlerShortDob(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/create-attestation-from-dob", strings.NewReader(`{"dob": "1990"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createAttestationFromDobHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for short dob", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// CORS Middleware
// ---------------------------------------------------------------------------

func TestCorsMiddleware(t *testing.T) {
	saved := config
	defer func() { config = saved }()
	config.AllowedOrigins = map[string]bool{"http://localhost:3000": true}

	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("allowed origin sets CORS headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
			t.Error("missing CORS header for allowed origin")
		}
		if rec.Header().Get("Vary") != "Origin" {
			t.Error("missing Vary: Origin header")
		}
	})

	t.Run("disallowed origin gets no CORS headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		req.Header.Set("Origin", "http://evil.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("CORS header should not be set for disallowed origin")
		}
	})

	t.Run("OPTIONS returns 200", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("OPTIONS status = %d, want 200", rec.Code)
		}
	})

	t.Run("no origin header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("should not set CORS with no Origin")
		}
	})
}

// ---------------------------------------------------------------------------
// Security Headers Middleware
// ---------------------------------------------------------------------------

func TestSecurityHeadersMiddleware(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	handler := securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("non-production omits HSTS", func(t *testing.T) {
		config.IsProduction = false
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Header().Get("Strict-Transport-Security") != "" {
			t.Error("HSTS should not be set in non-production")
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Error("missing X-Content-Type-Options")
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Error("missing X-Frame-Options")
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Error("missing CSP")
		}
	})

	t.Run("production sets HSTS", func(t *testing.T) {
		config.IsProduction = true
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Header().Get("Strict-Transport-Security") == "" {
			t.Error("HSTS should be set in production")
		}
	})
}

// ---------------------------------------------------------------------------
// Demo Token Middleware
// ---------------------------------------------------------------------------

func TestDemoTokenMiddleware(t *testing.T) {
	originalSecret := demoTokenSecret
	originalEnabled := demoTokenValidationEnabled
	defer func() {
		demoTokenSecret = originalSecret
		demoTokenValidationEnabled = originalEnabled
	}()

	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	t.Run("non-api path passes through", func(t *testing.T) {
		demoTokenValidationEnabled = true
		demoTokenSecret = "test-secret"
		innerCalled = false
		handler := demoTokenMiddleware(inner)
		req := httptest.NewRequest("GET", "/health", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if !innerCalled {
			t.Error("inner handler should have been called for non-api path")
		}
	})

	t.Run("disabled validation passes through", func(t *testing.T) {
		demoTokenValidationEnabled = false
		innerCalled = false
		handler := demoTokenMiddleware(inner)
		req := httptest.NewRequest("GET", "/api/config", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if !innerCalled {
			t.Error("inner handler should have been called when validation disabled")
		}
	})

	t.Run("missing token returns 401", func(t *testing.T) {
		demoTokenValidationEnabled = true
		demoTokenSecret = "test-secret"
		handler := demoTokenMiddleware(inner)
		req := httptest.NewRequest("GET", "/api/config", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("valid token passes through", func(t *testing.T) {
		demoTokenValidationEnabled = true
		demoTokenSecret = "test-secret"
		innerCalled = false

		today := time.Now().UTC().Format("20060102")
		h := hmac.New(sha256.New, []byte("test-secret"))
		h.Write([]byte("provii-demos-v1:" + today))
		sig := hex.EncodeToString(h.Sum(nil))[:16]
		token := "demo_token_v1_" + today + "_" + sig

		handler := demoTokenMiddleware(inner)
		req := httptest.NewRequest("GET", "/api/config", nil)
		req.Header.Set("X-Demo-Token", token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if !innerCalled {
			t.Error("inner handler should have been called with valid token")
		}
	})
}

// ---------------------------------------------------------------------------
// createAttestation: invalid JSON response from upstream
// ---------------------------------------------------------------------------

func TestCreateAttestationInvalidHMACSecret(t *testing.T) {
	savedConfig := config
	defer func() { config = savedConfig }()

	config = Config{
		ClientId:     "test-client",
		HmacSecret:   "!!!invalid-base64!!!",
		IssuerApiUrl: "http://localhost:1",
		Port:         "3000",
	}

	_, err := createAttestation(7000)
	if err == nil {
		t.Error("expected error for invalid base64 HMAC secret")
	}
}

func TestCreateAttestationConnectionRefused(t *testing.T) {
	savedConfig := config
	defer func() { config = savedConfig }()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		ClientId:     "test-client",
		HmacSecret:   secret,
		IssuerApiUrl: "http://127.0.0.1:1",
		Port:         "3000",
	}

	_, err := createAttestation(7000)
	if err == nil {
		t.Error("expected error for connection refused")
	}
}

// ---------------------------------------------------------------------------
// Handler response structure validation
// ---------------------------------------------------------------------------

func TestHealthHandlerContentType(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	healthHandler(rec, req)

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestConfigHandlerContentType(t *testing.T) {
	savedConfig := config
	defer func() { config = savedConfig }()
	config = Config{
		ClientId:     "c",
		HmacSecret:   "s",
		IssuerApiUrl: "https://sandbox-issue.provii.app",
		Port:         "3000",
	}

	req := httptest.NewRequest("GET", "/api/config", nil)
	rec := httptest.NewRecorder()
	configHandler(rec, req)

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// ---------------------------------------------------------------------------
// createAttestationHandler: error response structure
// ---------------------------------------------------------------------------

func TestCreateAttestationHandlerErrorResponseStructure(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	config.HmacSecret = ""
	config.IssuerApiUrl = ""
	config.ClientId = "test"

	req := httptest.NewRequest("POST", "/api/create-attestation", strings.NewReader(`{"dob_days": 7000}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createAttestationHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["code"] != "ATTESTATION_FAILED" {
		t.Errorf("code = %v, want ATTESTATION_FAILED", resp["code"])
	}
	if resp["reference"] == nil || resp["reference"] == "" {
		t.Error("expected reference in error response")
	}
}

// ---------------------------------------------------------------------------
// createAttestationFromDobHandler: error response structure
// ---------------------------------------------------------------------------

func TestCreateAttestationFromDobHandlerErrorStructure(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	config.HmacSecret = ""
	config.IssuerApiUrl = ""
	config.ClientId = "test"

	req := httptest.NewRequest("POST", "/api/create-attestation-from-dob", strings.NewReader(`{"dob": "1990-05-15"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createAttestationFromDobHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["code"] != "ATTESTATION_FAILED" {
		t.Errorf("code = %v, want ATTESTATION_FAILED", resp["code"])
	}
}

// ---------------------------------------------------------------------------
// Canonical message HMAC verification
// ---------------------------------------------------------------------------

func TestBuildCanonicalMessageContainsAllFields(t *testing.T) {
	got := buildCanonicalMessage(7000, "client-123", 1700000000, "nonce-abc")

	// Verify the full canonical message structure
	if !strings.HasPrefix(got, "1700000000:POST:/v1/attestation/create:") {
		t.Errorf("unexpected prefix: %s", got)
	}
	if !strings.HasSuffix(got, ":nonce-abc") {
		t.Errorf("nonce should be at the end: %s", got)
	}
	if !strings.Contains(got, `"dob_days":7000`) {
		t.Errorf("missing dob_days: %s", got)
	}
	if !strings.Contains(got, `"key_id":"client-123"`) {
		t.Errorf("canonical message should use snake_case key_id: %s", got)
	}
	if !strings.Contains(got, `"format":"client"`) {
		t.Errorf("missing format:client: %s", got)
	}
}

// ---------------------------------------------------------------------------
// createAttestation: verify request body structure
// ---------------------------------------------------------------------------

func TestCreateAttestationRequestBody(t *testing.T) {
	savedConfig := config
	defer func() { config = savedConfig }()

	var capturedBody map[string]interface{}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&capturedBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"attestation": "dGVzdA",
			"expires_at":  time.Now().Unix() + 300,
			"issuer_id":   "issuer-test",
		})
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		ClientId:     "my-client-id",
		HmacSecret:   secret,
		IssuerApiUrl: mockServer.URL,
		Port:         "3000",
	}

	_, err := createAttestation(7000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedBody["dob_days"] != float64(7000) {
		t.Errorf("dob_days = %v, want 7000", capturedBody["dob_days"])
	}

	auth, ok := capturedBody["authorizer"].(map[string]interface{})
	if !ok {
		t.Fatal("missing authorizer block in request body")
	}
	if auth["format"] != "client" {
		t.Errorf("authorizer.format = %v, want client", auth["format"])
	}
	// Note: HTTP body uses camelCase keyId, not snake_case key_id
	if auth["keyId"] != "my-client-id" {
		t.Errorf("authorizer.keyId = %v, want my-client-id", auth["keyId"])
	}
	if auth["hmac"] == nil || auth["hmac"] == "" {
		t.Error("authorizer.hmac should not be empty")
	}
	if auth["nonce"] == nil || auth["nonce"] == "" {
		t.Error("authorizer.nonce should not be empty")
	}
}

// ---------------------------------------------------------------------------
// DOB days floor division for pre-epoch dates
// ---------------------------------------------------------------------------

func TestCreateAttestationFromDobHandlerFloorDivision(t *testing.T) {
	_, cleanup := setupMockIssuerAPI(t)
	defer cleanup()

	// 1969-12-30 is 2 days before epoch, should produce dob_days = -2
	req := httptest.NewRequest("POST", "/api/create-attestation-from-dob", strings.NewReader(`{"dob": "1969-12-30"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createAttestationFromDobHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var resp CreateAttestationResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.DobDays >= 0 {
		t.Errorf("expected negative dob_days for pre-epoch date, got %d", resp.DobDays)
	}
}

// ---------------------------------------------------------------------------
// parseAllowedOrigins: whitespace-only entries filtered
// ---------------------------------------------------------------------------

func TestParseAllowedOriginsWhitespace(t *testing.T) {
	origins := parseAllowedOrigins("http://a.com,  ,  http://b.com  , ")
	if len(origins) != 2 {
		t.Errorf("expected 2 origins (whitespace-only filtered), got %d: %v", len(origins), origins)
	}
}

// ---------------------------------------------------------------------------
// CORS: verify middleware sets Vary header
// ---------------------------------------------------------------------------

func TestCorsMiddlewareVaryHeader(t *testing.T) {
	saved := config
	defer func() { config = saved }()
	config.AllowedOrigins = map[string]bool{"http://localhost:3000": true}

	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Vary") != "Origin" {
		t.Error("missing Vary: Origin header")
	}
}

// ---------------------------------------------------------------------------
// Security headers: verify CSP on all responses
// ---------------------------------------------------------------------------

func TestSecurityHeadersCSP(t *testing.T) {
	saved := config
	defer func() { config = saved }()
	config.IsProduction = false

	handler := securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP should be strict for API paths, got: %s", csp)
	}
}

// ---------------------------------------------------------------------------
// newRouter: verify route registration
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// loadConfig and requireCredentials
// ---------------------------------------------------------------------------

func TestLoadConfigDefaults(t *testing.T) {
	// Unset all env vars to test defaults
	for _, key := range []string{"CLIENT_ID", "HMAC_SECRET", "ISSUER_API_URL", "PORT", "ALLOWED_ORIGINS", "GO_ENV"} {
		t.Setenv(key, "")
	}
	os.Unsetenv("CLIENT_ID")
	os.Unsetenv("HMAC_SECRET")
	os.Unsetenv("ISSUER_API_URL")

	c := loadConfig()
	if c.Port != "3000" {
		t.Errorf("default port = %q, want 3000", c.Port)
	}
	if c.IsProduction {
		t.Error("IsProduction should be false by default")
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv("CLIENT_ID", "test-client")
	t.Setenv("HMAC_SECRET", "test-secret")
	t.Setenv("ISSUER_API_URL", "https://test.provii.app")
	t.Setenv("PORT", "4000")
	t.Setenv("GO_ENV", "production")

	c := loadConfig()
	if c.ClientId != "test-client" {
		t.Errorf("ClientId = %q, want test-client", c.ClientId)
	}
	if c.Port != "4000" {
		t.Errorf("Port = %q, want 4000", c.Port)
	}
	if !c.IsProduction {
		t.Error("IsProduction should be true")
	}
}

func TestRequireCredentialsMissing(t *testing.T) {
	c := Config{ClientId: "", HmacSecret: "s", IssuerApiUrl: "u"}
	if err := requireCredentials(c); err == nil {
		t.Error("expected error for missing ClientId")
	}

	c = Config{ClientId: "c", HmacSecret: "", IssuerApiUrl: "u"}
	if err := requireCredentials(c); err == nil {
		t.Error("expected error for missing HmacSecret")
	}

	c = Config{ClientId: "c", HmacSecret: "s", IssuerApiUrl: ""}
	if err := requireCredentials(c); err == nil {
		t.Error("expected error for missing IssuerApiUrl")
	}
}

func TestRequireCredentialsComplete(t *testing.T) {
	c := Config{ClientId: "c", HmacSecret: "s", IssuerApiUrl: "u"}
	if err := requireCredentials(c); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// printBanner and parsePort
// ---------------------------------------------------------------------------

func TestPrintBanner(t *testing.T) {
	originalEnabled := demoTokenValidationEnabled
	defer func() { demoTokenValidationEnabled = originalEnabled }()

	c := Config{
		ClientId:     "test-client",
		HmacSecret:   "secret",
		IssuerApiUrl: "https://sandbox-issue.provii.app",
		Port:         "3000",
	}

	t.Run("with demo token enabled", func(t *testing.T) {
		demoTokenValidationEnabled = true
		// Should not panic
		printBanner(c)
	})

	t.Run("with demo token disabled", func(t *testing.T) {
		demoTokenValidationEnabled = false
		printBanner(c)
	})

	t.Run("with empty hmac secret", func(t *testing.T) {
		c2 := c
		c2.HmacSecret = ""
		printBanner(c2)
	})
}

func TestParsePort(t *testing.T) {
	port := parsePort("3000")
	if port != 3000 {
		t.Errorf("parsePort(\"3000\") = %d, want 3000", port)
	}

	port2 := parsePort("8080")
	if port2 != 8080 {
		t.Errorf("parsePort(\"8080\") = %d, want 8080", port2)
	}
}

func TestNewRouterRegistersRoutes(t *testing.T) {
	savedConfig := config
	savedSecret := demoTokenSecret
	savedEnabled := demoTokenValidationEnabled
	defer func() {
		config = savedConfig
		demoTokenSecret = savedSecret
		demoTokenValidationEnabled = savedEnabled
	}()

	config = Config{
		ClientId:       "test",
		HmacSecret:     "secret",
		IssuerApiUrl:   "https://test.provii.app",
		Port:           "3000",
		AllowedOrigins: map[string]bool{"http://localhost:3000": true},
		IsProduction:   false,
	}
	demoTokenSecret = ""
	demoTokenValidationEnabled = false

	r := newRouter()

	// Verify health endpoint works through the full router stack
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("health via newRouter() returned %d, want 200", rec.Code)
	}

	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("health status = %v, want ok", body["status"])
	}
}
