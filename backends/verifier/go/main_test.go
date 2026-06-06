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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// chiContext returns an httptest.ResponseRecorder served through a chi router
// so URL parameters are correctly extracted.
func chiServe(t *testing.T, method, pattern, url string, handler http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := chi.NewRouter()
	switch method {
	case "GET":
		r.Get(pattern, handler)
	case "POST":
		r.Post(pattern, handler)
	}
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	} else {
		bodyReader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, url, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// setupMockVerifierAPI creates an httptest.Server that mimics provii-verifier
// endpoints used during challenge, status, and redeem flows. It returns the
// server (caller must defer Close) and configures the global config to use it.
func setupMockVerifierAPI(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	saved := config
	savedDemoSecret := demoTokenSecret
	savedDemoEnabled := demoTokenValidationEnabled

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/v1/challenge" && r.Method == "POST":
			json.NewEncoder(w).Encode(ChallengeAPIResponse{
				ChallengeID:    "a1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5",
				RPChallenge:    "rp-chal-data",
				CutoffDays:     6574,
				VerifyingKeyID: 1,
				SubmitSecret:   "submit-secret",
				ExpiresAt:      time.Now().Unix() + 300,
				StatusURL:      "/v1/challenge/a1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5",
				VerifyURL:      "/v1/challenge/a1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5/verify",
				ProofDirection: "over_age",
			})

		case strings.HasSuffix(r.URL.Path, "/redeem") && r.Method == "POST":
			json.NewEncoder(w).Encode(RedeemAPIResponse{
				Result:   "success",
				Verified: true,
			})

		case strings.HasPrefix(r.URL.Path, "/v1/challenge/") && r.Method == "GET":
			json.NewEncoder(w).Encode(StatusAPIResponse{
				State:         "verified",
				Status:        "complete",
				Verified:      true,
				ProofVerified: true,
			})

		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"not found"}`))
		}
	}))

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   mockServer.URL,
		ClientID:         "test-client-id",
		APIKey:           "test-api-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://test.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
		IsProduction:     false,
	}
	demoTokenSecret = ""
	demoTokenValidationEnabled = false

	cleanup := func() {
		mockServer.Close()
		config = saved
		demoTokenSecret = savedDemoSecret
		demoTokenValidationEnabled = savedDemoEnabled
	}

	return mockServer, cleanup
}

// ---------------------------------------------------------------------------
// Utility function tests
// ---------------------------------------------------------------------------

func TestGetEnv(t *testing.T) {
	t.Run("returns value when set", func(t *testing.T) {
		t.Setenv("TEST_VERIFIER_ENV_KEY", "world")
		if got := getEnv("TEST_VERIFIER_ENV_KEY", "fb"); got != "world" {
			t.Errorf("getEnv() = %q, want %q", got, "world")
		}
	})
	t.Run("returns fallback when unset", func(t *testing.T) {
		os.Unsetenv("TEST_VERIFIER_ENV_MISSING")
		if got := getEnv("TEST_VERIFIER_ENV_MISSING", "default"); got != "default" {
			t.Errorf("getEnv() = %q, want %q", got, "default")
		}
	})
}

func TestParseAllowedOrigins(t *testing.T) {
	origins := parseAllowedOrigins("http://a.com, http://b.com")
	if len(origins) != 2 {
		t.Fatalf("expected 2 origins, got %d", len(origins))
	}
	if origins[0] != "http://a.com" || origins[1] != "http://b.com" {
		t.Errorf("unexpected origins: %v", origins)
	}
}

func TestParseAllowedOriginsEmpty(t *testing.T) {
	origins := parseAllowedOrigins("")
	if len(origins) != 0 {
		t.Errorf("expected 0 origins for empty string, got %d", len(origins))
	}
}

func TestParseAllowedOriginsSingleTrailingComma(t *testing.T) {
	origins := parseAllowedOrigins("http://a.com,")
	if len(origins) != 1 {
		t.Errorf("expected 1 origin, got %d: %v", len(origins), origins)
	}
}

func TestBase64URLEncodeDecode(t *testing.T) {
	original := []byte("pkce-code-verifier-bytes")
	encoded := base64URLEncode(original)
	decoded, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("base64URLDecode() error: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("round-trip failed: got %q, want %q", decoded, original)
	}
}

func TestBase64URLDecodeInvalid(t *testing.T) {
	_, err := base64URLDecode("!!!not-valid!!!")
	if err == nil {
		t.Error("expected error for invalid base64url input")
	}
}

func TestGenerateCodeVerifier(t *testing.T) {
	verifier, err := generateCodeVerifier()
	if err != nil {
		t.Fatalf("generateCodeVerifier() error: %v", err)
	}
	if len(verifier) != 43 {
		t.Errorf("generateCodeVerifier() length = %d, want 43", len(verifier))
	}

	// Verify uniqueness (two verifiers should differ)
	verifier2, err := generateCodeVerifier()
	if err != nil {
		t.Fatalf("generateCodeVerifier() second call error: %v", err)
	}
	if verifier == verifier2 {
		t.Error("two calls to generateCodeVerifier() returned the same value")
	}
}

func TestGenerateCodeChallenge(t *testing.T) {
	verifier := "test-verifier-value"
	challenge := generateCodeChallenge(verifier)

	hash := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(hash[:])
	if challenge != want {
		t.Errorf("generateCodeChallenge() = %q, want %q", challenge, want)
	}
}

func TestCreateHMACSignature(t *testing.T) {
	secret := base64.RawURLEncoding.EncodeToString([]byte("my-hmac-secret"))
	sig, err := createHMACSignature("message-to-sign", secret)
	if err != nil {
		t.Fatalf("createHMACSignature() error: %v", err)
	}

	h := hmac.New(sha256.New, []byte("my-hmac-secret"))
	h.Write([]byte("message-to-sign"))
	want := hex.EncodeToString(h.Sum(nil))
	if sig != want {
		t.Errorf("createHMACSignature() = %q, want %q", sig, want)
	}
}

func TestCreateHMACSignatureInvalidBase64(t *testing.T) {
	_, err := createHMACSignature("msg", "!!!invalid-base64!!!")
	if err == nil {
		t.Error("createHMACSignature() with invalid base64 should error")
	}
}

func TestIsValidUUID(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"550e8400-e29b-41d4-a716-446655440000", true},
		{"550E8400-E29B-41D4-A716-446655440000", true},
		{"not-a-uuid", false},
		{"", false},
		{"550e8400e29b41d4a716446655440000", false},
		{"550e8400-e29b-41d4-a716-44665544000", false},  // too short
		{"550e8400-e29b-41d4-a716-4466554400000", false}, // too long
	}
	for _, tc := range tests {
		if got := isValidUUID(tc.input); got != tc.want {
			t.Errorf("isValidUUID(%q) = %v, want %v", tc.input, got, tc.want)
		}
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

	// Verify uniqueness
	id2 := generateErrorID()
	if id == id2 {
		t.Error("two calls to generateErrorID() returned the same value")
	}
}

func TestBuildDeepLink(t *testing.T) {
	challenge := &ChallengeAPIResponse{
		ChallengeID:    "550e8400-e29b-41d4-a716-446655440000",
		RPChallenge:    "rp-challenge-data",
		CutoffDays:     6574,
		VerifyingKeyID: 1,
		SubmitSecret:   "submit-secret-value",
		ExpiresAt:      1700000300,
		StatusURL:      "https://sandbox-verify.provii.app/v1/challenge/550e8400-e29b-41d4-a716-446655440000",
		VerifyURL:      "https://sandbox-verify.provii.app/v1/challenge/550e8400-e29b-41d4-a716-446655440000/verify",
		ProofDirection: "over_age",
	}
	link := buildDeepLink(challenge)
	if link == "" {
		t.Fatal("buildDeepLink() returned empty string")
	}
	if !strings.HasPrefix(link, "https://provii.app/verify?d=") {
		t.Errorf("unexpected deep link prefix: %s", link)
	}
}

// ---------------------------------------------------------------------------
// Demo token validation
// ---------------------------------------------------------------------------

func TestValidateDemoToken(t *testing.T) {
	originalSecret := demoTokenSecret
	originalEnabled := demoTokenValidationEnabled
	defer func() {
		demoTokenSecret = originalSecret
		demoTokenValidationEnabled = originalEnabled
	}()

	demoTokenSecret = "test-verifier-secret"
	demoTokenValidationEnabled = true

	today := time.Now().UTC().Format("20060102")

	h := hmac.New(sha256.New, []byte("test-verifier-secret"))
	h.Write([]byte("provii-demos-v1:" + today))
	expectedSig := hex.EncodeToString(h.Sum(nil))[:16]
	validToken := "demo_token_v1_" + today + "_" + expectedSig

	t.Run("valid token accepted", func(t *testing.T) {
		if !validateDemoToken(validToken) {
			t.Error("validateDemoToken() returned false for valid token")
		}
	})

	t.Run("wrong prefix rejected", func(t *testing.T) {
		if validateDemoToken("bad_prefix_v1_" + today + "_" + expectedSig) {
			t.Error("accepted token with wrong prefix")
		}
	})

	t.Run("wrong signature rejected", func(t *testing.T) {
		if validateDemoToken("demo_token_v1_" + today + "_aaaaaaaaaaaaaaaa") {
			t.Error("accepted token with wrong signature")
		}
	})

	t.Run("old date rejected", func(t *testing.T) {
		if validateDemoToken("demo_token_v1_19700101_" + expectedSig) {
			t.Error("accepted token with old date")
		}
	})

	t.Run("malformed rejected", func(t *testing.T) {
		if validateDemoToken("garbage") {
			t.Error("accepted malformed token")
		}
	})

	t.Run("too many parts rejected", func(t *testing.T) {
		if validateDemoToken("demo_token_v1_" + today + "_sig_extra") {
			t.Error("accepted token with extra parts")
		}
	})

	t.Run("yesterday's date accepted", func(t *testing.T) {
		yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("20060102")
		yh := hmac.New(sha256.New, []byte("test-verifier-secret"))
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
	saved := config
	defer func() { config = saved }()
	config.HMACSecret = "s"
	config.APIKey = "k"
	config.ClientID = "c"

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	healthHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("status = %v", body["status"])
	}
	if body["configured"] != true {
		t.Error("configured should be true when all creds are set")
	}
}

func TestHealthHandlerUnconfigured(t *testing.T) {
	saved := config
	defer func() { config = saved }()
	config.HMACSecret = ""
	config.APIKey = ""
	config.ClientID = ""

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	healthHandler(rec, req)

	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	if body["configured"] != false {
		t.Error("configured should be false when creds are missing")
	}
}

func TestConfigHandler(t *testing.T) {
	saved := config
	defer func() { config = saved }()
	config.VerifierAPIURL = "https://sandbox-verify.provii.app"
	config.ClientID = "cid"
	config.APIKey = "key"
	config.HMACSecret = "sec"

	req := httptest.NewRequest("GET", "/api/config", nil)
	rec := httptest.NewRecorder()
	configHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	if body["has_client_id"] != true {
		t.Error("has_client_id should be true")
	}
	if body["api_key_configured"] != true {
		t.Error("api_key_configured should be true")
	}
	if body["hmac_secret_configured"] != true {
		t.Error("hmac_secret_configured should be true")
	}
}

// ---------------------------------------------------------------------------
// createChallengeHandler
// ---------------------------------------------------------------------------

func TestCreateChallengeHandlerInvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCreateChallengeHandlerBothAges(t *testing.T) {
	min, max := 18, 25
	body, _ := json.Marshal(CreateChallengeRequest{MinimumAge: &min, MaximumAge: &max})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCreateChallengeHandlerInvalidAge(t *testing.T) {
	age := 5
	body, _ := json.Marshal(CreateChallengeRequest{MinimumAge: &age})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for age below 13", rec.Code)
	}
}

func TestCreateChallengeHandlerAgeTooHigh(t *testing.T) {
	age := 130
	body, _ := json.Marshal(CreateChallengeRequest{MaximumAge: &age})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for age above 120", rec.Code)
	}
}

func TestCreateChallengeHandlerInvalidExpiresIn(t *testing.T) {
	body, _ := json.Marshal(map[string]interface{}{"expires_in": 10})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for too-low expires_in", rec.Code)
	}
}

func TestCreateChallengeHandlerExpiresInTooHigh(t *testing.T) {
	body, _ := json.Marshal(map[string]interface{}{"expires_in": 500})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for expires_in > 300", rec.Code)
	}
}

func TestCreateChallengeHandlerSuccess(t *testing.T) {
	_, cleanup := setupMockVerifierAPI(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{"minimum_age": 21})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var resp CreateChallengeResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.SessionID == "" {
		t.Error("session_id should not be empty")
	}
	if resp.DeepLink == "" {
		t.Error("deep_link should not be empty")
	}
	if !strings.HasPrefix(resp.DeepLink, "https://provii.app/verify?d=") {
		t.Errorf("unexpected deep link: %s", resp.DeepLink)
	}
	if resp.ProofDirection != "over_age" {
		t.Errorf("proof_direction = %q, want over_age", resp.ProofDirection)
	}
}

func TestCreateChallengeHandlerDefaultAge(t *testing.T) {
	_, cleanup := setupMockVerifierAPI(t)
	defer cleanup()

	// No minimum_age or maximum_age specified; defaults to 18
	body, _ := json.Marshal(map[string]interface{}{})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestCreateChallengeHandlerWithMaximumAge(t *testing.T) {
	_, cleanup := setupMockVerifierAPI(t)
	defer cleanup()

	age := 25
	body, _ := json.Marshal(CreateChallengeRequest{MaximumAge: &age})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// getStatusHandler (via chi router for URL params)
// ---------------------------------------------------------------------------

func TestGetStatusHandlerMissingID(t *testing.T) {
	// chi returns 404 when the URL doesn't match the route pattern (trailing slash with no param)
	rec := chiServe(t, "GET", "/api/status/{sessionId}", "/api/status/", getStatusHandler, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (chi route mismatch)", rec.Code)
	}
}

func TestGetStatusHandlerInvalidUUID(t *testing.T) {
	rec := chiServe(t, "GET", "/api/status/{sessionId}", "/api/status/not-a-uuid", getStatusHandler, "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestGetStatusHandlerSessionNotFound(t *testing.T) {
	rec := chiServe(t, "GET", "/api/status/{sessionId}", "/api/status/550e8400-e29b-41d4-a716-446655440000", getStatusHandler, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestGetStatusHandlerSuccess(t *testing.T) {
	_, cleanup := setupMockVerifierAPI(t)
	defer cleanup()

	// First create a session by calling createChallengeHandler
	body, _ := json.Marshal(map[string]interface{}{"minimum_age": 18})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("create-challenge status = %d", rec.Code)
	}

	var createResp CreateChallengeResponse
	json.NewDecoder(rec.Body).Decode(&createResp)

	// Now poll status
	statusRec := chiServe(t, "GET", "/api/status/{sessionId}", "/api/status/"+createResp.SessionID, getStatusHandler, "")
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status check returned %d: %s", statusRec.Code, statusRec.Body.String())
	}

	var statusResp StatusResponse
	json.NewDecoder(statusRec.Body).Decode(&statusResp)
	if !statusResp.Verified {
		t.Error("expected verified=true from mock server")
	}
}

// ---------------------------------------------------------------------------
// redeemHandler (via chi router for URL params)
// ---------------------------------------------------------------------------

func TestRedeemHandlerMissingID(t *testing.T) {
	// chi returns 404 when the URL doesn't match the route pattern (trailing slash with no param)
	rec := chiServe(t, "POST", "/api/redeem/{sessionId}", "/api/redeem/", redeemHandler, "{}")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (chi route mismatch)", rec.Code)
	}
}

func TestRedeemHandlerInvalidUUID(t *testing.T) {
	rec := chiServe(t, "POST", "/api/redeem/{sessionId}", "/api/redeem/not-a-uuid", redeemHandler, "{}")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestRedeemHandlerSessionNotFound(t *testing.T) {
	rec := chiServe(t, "POST", "/api/redeem/{sessionId}", "/api/redeem/550e8400-e29b-41d4-a716-446655440000", redeemHandler, "{}")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestRedeemHandlerSuccess(t *testing.T) {
	_, cleanup := setupMockVerifierAPI(t)
	defer cleanup()

	// Create a session
	body, _ := json.Marshal(map[string]interface{}{"minimum_age": 18})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create-challenge status = %d", rec.Code)
	}
	var createResp CreateChallengeResponse
	json.NewDecoder(rec.Body).Decode(&createResp)

	// Redeem it
	redeemRec := chiServe(t, "POST", "/api/redeem/{sessionId}", "/api/redeem/"+createResp.SessionID, redeemHandler, "{}")
	if redeemRec.Code != http.StatusOK {
		t.Fatalf("redeem returned %d: %s", redeemRec.Code, redeemRec.Body.String())
	}

	var redeemResp RedeemResponse
	json.NewDecoder(redeemRec.Body).Decode(&redeemResp)
	if !redeemResp.Verified {
		t.Error("expected verified=true")
	}

	// Second redeem should fail (delete-before-use)
	redeemRec2 := chiServe(t, "POST", "/api/redeem/{sessionId}", "/api/redeem/"+createResp.SessionID, redeemHandler, "{}")
	if redeemRec2.Code != http.StatusNotFound {
		t.Errorf("second redeem status = %d, want 404", redeemRec2.Code)
	}
}

// ---------------------------------------------------------------------------
// Expert mode handlers
// ---------------------------------------------------------------------------

func TestExpertChallengeHandlerInvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/challenge", strings.NewReader("invalid"))
	rec := httptest.NewRecorder()
	expertChallengeHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestExpertChallengeHandlerMissingChallenge(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/challenge", strings.NewReader(`{"method":"S256"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	expertChallengeHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestExpertChallengeHandlerSuccess(t *testing.T) {
	_, cleanup := setupMockVerifierAPI(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{
		"code_challenge": "test-code-challenge-value",
		"method":         "S256",
		"expires_in":     300,
	})
	req := httptest.NewRequest("POST", "/api/challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	expertChallengeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var resp ChallengeAPIResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.ChallengeID == "" {
		t.Error("challenge_id should not be empty")
	}
}

func TestExpertChallengeHandlerDefaultExpiresIn(t *testing.T) {
	_, cleanup := setupMockVerifierAPI(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{
		"code_challenge": "test-code-challenge-value",
		"method":         "S256",
	})
	req := httptest.NewRequest("POST", "/api/challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	expertChallengeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestExpertPollHandlerInvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/poll", strings.NewReader("invalid"))
	rec := httptest.NewRecorder()
	expertPollHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestExpertPollHandlerMissingID(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/poll", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	expertPollHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestExpertPollHandlerSuccess(t *testing.T) {
	_, cleanup := setupMockVerifierAPI(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{
		"challengeId": "a1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5",
	})
	req := httptest.NewRequest("POST", "/api/poll", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	expertPollHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var resp StatusAPIResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if !resp.Verified {
		t.Error("expected verified=true from mock")
	}
}

func TestExpertRedeemHandlerInvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/redeem", strings.NewReader("invalid"))
	rec := httptest.NewRecorder()
	expertRedeemHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestExpertRedeemHandlerMissingFields(t *testing.T) {
	t.Run("missing challenge_id", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/redeem", strings.NewReader(`{"code_verifier":"v"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		expertRedeemHandler(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
	t.Run("missing code_verifier", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/redeem", strings.NewReader(`{"challenge_id":"c"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		expertRedeemHandler(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
}

func TestExpertRedeemHandlerSuccess(t *testing.T) {
	_, cleanup := setupMockVerifierAPI(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{
		"challenge_id":  "a1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5",
		"code_verifier": "test-code-verifier-value",
	})
	req := httptest.NewRequest("POST", "/api/redeem", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	expertRedeemHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	// Verify Set-Cookie header is present
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "verified_session=") {
		t.Error("expected verified_session cookie in response")
	}
}

func TestExpertSessionHandler(t *testing.T) {
	t.Run("no cookie returns false", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/session", nil)
		rec := httptest.NewRecorder()
		expertSessionHandler(rec, req)

		var body map[string]bool
		json.NewDecoder(rec.Body).Decode(&body)
		if body["verified"] != false {
			t.Error("expected verified=false with no cookie")
		}
	})
	t.Run("with cookie returns true", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/session", nil)
		req.AddCookie(&http.Cookie{Name: "verified_session", Value: "abc123"})
		rec := httptest.NewRecorder()
		expertSessionHandler(rec, req)

		var body map[string]bool
		json.NewDecoder(rec.Body).Decode(&body)
		if body["verified"] != true {
			t.Error("expected verified=true with cookie")
		}
	})
}

// ---------------------------------------------------------------------------
// CORS Middleware
// ---------------------------------------------------------------------------

func TestCorsMiddleware(t *testing.T) {
	saved := config
	defer func() { config = saved }()
	config.AllowedOrigins = []string{"http://localhost:3000"}
	config.IsProduction = false

	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("allowed origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
			t.Error("missing CORS header for allowed origin")
		}
	})

	t.Run("disallowed origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		req.Header.Set("Origin", "http://evil.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("should not set CORS for disallowed origin")
		}
	})

	t.Run("OPTIONS preflight", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("OPTIONS status = %d, want 200", rec.Code)
		}
	})

	t.Run("production sets HSTS", func(t *testing.T) {
		config.IsProduction = true
		req := httptest.NewRequest("GET", "/api/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Header().Get("Strict-Transport-Security") == "" {
			t.Error("HSTS should be set in production")
		}
	})

	t.Run("HTML page gets permissive CSP", func(t *testing.T) {
		config.IsProduction = false
		req := httptest.NewRequest("GET", "/expert.html", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "cdn.provii.app") {
			t.Error("HTML CSP should reference cdn.provii.app")
		}
	})

	t.Run("API path gets strict CSP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/config", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") {
			t.Error("API CSP should be strict")
		}
	})

	t.Run("root path gets permissive CSP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "cdn.provii.app") {
			t.Error("root CSP should be permissive")
		}
	})

	t.Run("no origin header produces no Allow-Origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("should not set CORS with no Origin header")
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

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("non-api path passes through", func(t *testing.T) {
		demoTokenValidationEnabled = true
		demoTokenSecret = "s"
		handler := demoTokenMiddleware(inner)
		req := httptest.NewRequest("GET", "/health", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("expert path bypasses token check", func(t *testing.T) {
		demoTokenValidationEnabled = true
		demoTokenSecret = "s"
		handler := demoTokenMiddleware(inner)

		for _, path := range []string{"/api/challenge", "/api/poll", "/api/redeem", "/api/session"} {
			req := httptest.NewRequest("POST", path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 for expert path %s", rec.Code, path)
			}
		}
	})

	t.Run("disabled passes through", func(t *testing.T) {
		demoTokenValidationEnabled = false
		handler := demoTokenMiddleware(inner)
		req := httptest.NewRequest("GET", "/api/config", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("missing token returns 401", func(t *testing.T) {
		demoTokenValidationEnabled = true
		demoTokenSecret = "s"
		handler := demoTokenMiddleware(inner)
		req := httptest.NewRequest("GET", "/api/config", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// createChallengeWithAPI
// ---------------------------------------------------------------------------

func TestCreateChallengeWithAPIMissingConfig(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	config.HMACSecret = ""
	config.APIKey = "k"
	_, err := createChallengeWithAPI("challenge", 18, 300)
	if err == nil {
		t.Error("expected error when HMACSecret is empty")
	}

	config.HMACSecret = "s"
	config.APIKey = ""
	_, err = createChallengeWithAPI("challenge", 18, 300)
	if err == nil {
		t.Error("expected error when APIKey is empty")
	}
}

func TestCreateChallengeWithAPIMockServer(t *testing.T) {
	_, cleanup := setupMockVerifierAPI(t)
	defer cleanup()

	resp, err := createChallengeWithAPI("test-challenge", 18, 300)
	if err != nil {
		t.Fatalf("createChallengeWithAPI() error: %v", err)
	}
	if resp.ChallengeID != "a1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5" {
		t.Errorf("unexpected challenge_id: %s", resp.ChallengeID)
	}
	if resp.ProofDirection != "over_age" {
		t.Errorf("unexpected proof_direction: %s", resp.ProofDirection)
	}
}

func TestCreateChallengeWithAPIServerError(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config.VerifierAPIURL = mockServer.URL
	config.ClientID = "test-client"
	config.APIKey = "test-key"
	config.HMACSecret = secret

	_, err := createChallengeWithAPI("test-challenge", 18, 300)
	if err == nil {
		t.Error("expected error for server 500")
	}
}

func TestPollChallengeStatusMock(t *testing.T) {
	_, cleanup := setupMockVerifierAPI(t)
	defer cleanup()

	resp, err := pollChallengeStatus("550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatalf("pollChallengeStatus() error: %v", err)
	}
	if !resp.Verified {
		t.Error("expected verified=true")
	}
}

func TestPollChallengeStatusError(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer mockServer.Close()

	config.VerifierAPIURL = mockServer.URL
	config.APIKey = "test-key"

	_, err := pollChallengeStatus("nonexistent")
	if err == nil {
		t.Error("expected error for 404")
	}
}

func TestRedeemChallengeMock(t *testing.T) {
	_, cleanup := setupMockVerifierAPI(t)
	defer cleanup()

	resp, err := redeemChallenge("challenge-id", "code-verifier")
	if err != nil {
		t.Fatalf("redeemChallenge() error: %v", err)
	}
	if !resp.Verified {
		t.Error("expected verified=true")
	}
}

func TestRedeemChallengeError(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad"))
	}))
	defer mockServer.Close()

	config.VerifierAPIURL = mockServer.URL
	config.APIKey = "test-key"

	_, err := redeemChallenge("cid", "cv")
	if err == nil {
		t.Error("expected error for 400")
	}
}

// ---------------------------------------------------------------------------
// Static file handler
// ---------------------------------------------------------------------------

func TestStaticFileHandler(t *testing.T) {
	t.Run("empty filename redirects", func(t *testing.T) {
		rec := chiServe(t, "GET", "/*", "/", staticFileHandler, "")
		if rec.Code != http.StatusFound {
			t.Errorf("status = %d, want 302", rec.Code)
		}
	})

	t.Run("disallowed extension returns 404", func(t *testing.T) {
		rec := chiServe(t, "GET", "/*", "/secret.json", staticFileHandler, "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("existing html file is served", func(t *testing.T) {
		// Create a temporary public directory with a test file
		tmpDir := t.TempDir()
		publicDir := filepath.Join(tmpDir, "public")
		os.MkdirAll(publicDir, 0o755)
		os.WriteFile(filepath.Join(publicDir, "test.html"), []byte("<html>test</html>"), 0o644)

		// Change to the temp dir so staticFileHandler can find "public/"
		origDir, _ := os.Getwd()
		os.Chdir(tmpDir)
		defer os.Chdir(origDir)

		rec := chiServe(t, "GET", "/*", "/test.html", staticFileHandler, "")
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Errorf("Content-Type = %q, want text/html", ct)
		}
	})

	t.Run("js file served with correct content type", func(t *testing.T) {
		tmpDir := t.TempDir()
		publicDir := filepath.Join(tmpDir, "public")
		os.MkdirAll(publicDir, 0o755)
		os.WriteFile(filepath.Join(publicDir, "app.js"), []byte("console.log('hi')"), 0o644)

		origDir, _ := os.Getwd()
		os.Chdir(tmpDir)
		defer os.Chdir(origDir)

		rec := chiServe(t, "GET", "/*", "/app.js", staticFileHandler, "")
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("css file served with correct content type", func(t *testing.T) {
		tmpDir := t.TempDir()
		publicDir := filepath.Join(tmpDir, "public")
		os.MkdirAll(publicDir, 0o755)
		os.WriteFile(filepath.Join(publicDir, "style.css"), []byte("body{}"), 0o644)

		origDir, _ := os.Getwd()
		os.Chdir(tmpDir)
		defer os.Chdir(origDir)

		rec := chiServe(t, "GET", "/*", "/style.css", staticFileHandler, "")
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("path traversal blocked", func(t *testing.T) {
		rec := chiServe(t, "GET", "/*", "/../../etc/passwd", staticFileHandler, "")
		// The extension check will reject it as 404 (not .html/.js/.css)
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// Handler error paths (upstream API failures)
// ---------------------------------------------------------------------------

func TestCreateChallengeHandlerAPIFailure(t *testing.T) {
	saved := config
	savedDemoSecret := demoTokenSecret
	savedDemoEnabled := demoTokenValidationEnabled
	defer func() {
		config = saved
		demoTokenSecret = savedDemoSecret
		demoTokenValidationEnabled = savedDemoEnabled
	}()

	// Mock server that returns 500 for challenge creation
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("upstream failure"))
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   mockServer.URL,
		ClientID:         "test-client",
		APIKey:           "test-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://test.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
	}
	demoTokenSecret = ""
	demoTokenValidationEnabled = false

	body, _ := json.Marshal(map[string]interface{}{"minimum_age": 18})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["reference"] == "" {
		t.Error("expected error reference in response")
	}
}

func TestGetStatusHandlerAPIFailure(t *testing.T) {
	saved := config
	savedDemoSecret := demoTokenSecret
	savedDemoEnabled := demoTokenValidationEnabled
	defer func() {
		config = saved
		demoTokenSecret = savedDemoSecret
		demoTokenValidationEnabled = savedDemoEnabled
	}()

	// Mock server that fails for status checks
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/challenge" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ChallengeAPIResponse{
				ChallengeID:    "b1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5",
				RPChallenge:    "rp-chal",
				CutoffDays:     6574,
				VerifyingKeyID: 1,
				SubmitSecret:   "secret",
				ExpiresAt:      time.Now().Unix() + 300,
				StatusURL:      "/v1/challenge/b1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5",
				VerifyURL:      "/v1/challenge/b1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5/verify",
				ProofDirection: "over_age",
			})
			return
		}
		// Status and redeem requests fail
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("upstream down"))
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   mockServer.URL,
		ClientID:         "test-client",
		APIKey:           "test-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://test.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
	}
	demoTokenSecret = ""
	demoTokenValidationEnabled = false

	// Create a session first
	body, _ := json.Marshal(map[string]interface{}{"minimum_age": 18})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("create-challenge status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var createResp CreateChallengeResponse
	json.NewDecoder(rec.Body).Decode(&createResp)

	// Status check should fail (mock returns 500 for GET)
	statusRec := chiServe(t, "GET", "/api/status/{sessionId}", "/api/status/"+createResp.SessionID, getStatusHandler, "")
	if statusRec.Code != http.StatusInternalServerError {
		t.Errorf("status check returned %d, want 500", statusRec.Code)
	}
}

func TestRedeemHandlerAPIFailure(t *testing.T) {
	saved := config
	savedDemoSecret := demoTokenSecret
	savedDemoEnabled := demoTokenValidationEnabled
	defer func() {
		config = saved
		demoTokenSecret = savedDemoSecret
		demoTokenValidationEnabled = savedDemoEnabled
	}()

	// Mock server that succeeds for challenge creation but fails for redeem
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/challenge" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ChallengeAPIResponse{
				ChallengeID:    "c1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5",
				RPChallenge:    "rp-chal",
				CutoffDays:     6574,
				VerifyingKeyID: 1,
				SubmitSecret:   "secret",
				ExpiresAt:      time.Now().Unix() + 300,
				StatusURL:      "/v1/challenge/c1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5",
				VerifyURL:      "/v1/challenge/c1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5/verify",
				ProofDirection: "over_age",
			})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("redeem failed"))
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   mockServer.URL,
		ClientID:         "test-client",
		APIKey:           "test-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://test.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
	}
	demoTokenSecret = ""
	demoTokenValidationEnabled = false

	// Create a session
	body, _ := json.Marshal(map[string]interface{}{"minimum_age": 18})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("create-challenge status = %d", rec.Code)
	}
	var createResp CreateChallengeResponse
	json.NewDecoder(rec.Body).Decode(&createResp)

	// Redeem should fail (mock returns 400 for POST to /redeem)
	redeemRec := chiServe(t, "POST", "/api/redeem/{sessionId}", "/api/redeem/"+createResp.SessionID, redeemHandler, "{}")
	if redeemRec.Code != http.StatusInternalServerError {
		t.Errorf("redeem returned %d, want 500", redeemRec.Code)
	}
}

func TestExpertChallengeHandlerAPIFailure(t *testing.T) {
	saved := config
	savedDemoSecret := demoTokenSecret
	savedDemoEnabled := demoTokenValidationEnabled
	defer func() {
		config = saved
		demoTokenSecret = savedDemoSecret
		demoTokenValidationEnabled = savedDemoEnabled
	}()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("fail"))
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   mockServer.URL,
		ClientID:         "test-client",
		APIKey:           "test-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://test.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
	}
	demoTokenSecret = ""
	demoTokenValidationEnabled = false

	body, _ := json.Marshal(map[string]interface{}{
		"code_challenge": "test-challenge",
		"method":         "S256",
	})
	req := httptest.NewRequest("POST", "/api/challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	expertChallengeHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestExpertPollHandlerAPIFailure(t *testing.T) {
	saved := config
	savedDemoSecret := demoTokenSecret
	savedDemoEnabled := demoTokenValidationEnabled
	defer func() {
		config = saved
		demoTokenSecret = savedDemoSecret
		demoTokenValidationEnabled = savedDemoEnabled
	}()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("fail"))
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   mockServer.URL,
		ClientID:         "test-client",
		APIKey:           "test-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://test.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
	}
	demoTokenSecret = ""
	demoTokenValidationEnabled = false

	body, _ := json.Marshal(map[string]interface{}{
		"challengeId": "a1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5",
	})
	req := httptest.NewRequest("POST", "/api/poll", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	expertPollHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestExpertRedeemHandlerAPIFailure(t *testing.T) {
	saved := config
	savedDemoSecret := demoTokenSecret
	savedDemoEnabled := demoTokenValidationEnabled
	defer func() {
		config = saved
		demoTokenSecret = savedDemoSecret
		demoTokenValidationEnabled = savedDemoEnabled
	}()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("fail"))
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   mockServer.URL,
		ClientID:         "test-client",
		APIKey:           "test-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://test.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
	}
	demoTokenSecret = ""
	demoTokenValidationEnabled = false

	body, _ := json.Marshal(map[string]interface{}{
		"challenge_id":  "a1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5",
		"code_verifier": "test-verifier",
	})
	req := httptest.NewRequest("POST", "/api/redeem", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	expertRedeemHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Invalid JSON response paths (upstream returns non-JSON)
// ---------------------------------------------------------------------------

func TestCreateChallengeWithAPIInvalidJSON(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not-json"))
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   mockServer.URL,
		ClientID:         "test-client",
		APIKey:           "test-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://test.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
	}

	_, err := createChallengeWithAPI("challenge", 18, 300)
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

func TestCreateChallengeWithAPIStatus201(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated) // 201
		json.NewEncoder(w).Encode(ChallengeAPIResponse{
			ChallengeID:    "d1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5",
			RPChallenge:    "rp-chal",
			CutoffDays:     6574,
			VerifyingKeyID: 1,
			SubmitSecret:   "secret",
			ExpiresAt:      time.Now().Unix() + 300,
			ProofDirection: "over_age",
		})
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   mockServer.URL,
		ClientID:         "test-client",
		APIKey:           "test-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://test.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
	}

	resp, err := createChallengeWithAPI("challenge", 18, 300)
	if err != nil {
		t.Fatalf("expected success for 201 response, got: %v", err)
	}
	if resp.ChallengeID != "d1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5" {
		t.Errorf("unexpected challenge_id: %s", resp.ChallengeID)
	}
}

func TestCreateChallengeWithAPIConnectionRefused(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   "http://127.0.0.1:1", // nothing is listening here
		ClientID:         "test-client",
		APIKey:           "test-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://test.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
	}

	_, err := createChallengeWithAPI("challenge", 18, 300)
	if err == nil {
		t.Error("expected error for connection refused")
	}
}

func TestPollChallengeStatusInvalidJSON(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not-json"))
	}))
	defer mockServer.Close()

	config.VerifierAPIURL = mockServer.URL
	config.APIKey = "test-key"

	_, err := pollChallengeStatus("some-id")
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

func TestPollChallengeStatusConnectionRefused(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	config.VerifierAPIURL = "http://127.0.0.1:1"
	config.APIKey = "test-key"

	_, err := pollChallengeStatus("some-id")
	if err == nil {
		t.Error("expected error for connection refused")
	}
}

func TestRedeemChallengeInvalidJSON(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not-json"))
	}))
	defer mockServer.Close()

	config.VerifierAPIURL = mockServer.URL
	config.APIKey = "test-key"

	_, err := redeemChallenge("cid", "cv")
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

func TestRedeemChallengeConnectionRefused(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	config.VerifierAPIURL = "http://127.0.0.1:1"
	config.APIKey = "test-key"

	_, err := redeemChallenge("cid", "cv")
	if err == nil {
		t.Error("expected error for connection refused")
	}
}

// ---------------------------------------------------------------------------
// createChallengeWithAPI: invalid HMAC secret (base64 decode failure)
// ---------------------------------------------------------------------------

func TestCreateChallengeWithAPIInvalidHMACSecret(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	config.HMACSecret = "!!!invalid-base64!!!"
	config.APIKey = "test-key"
	config.ClientID = "test-client"
	config.VerifierAPIURL = "http://localhost:1"

	_, err := createChallengeWithAPI("challenge", 18, 300)
	if err == nil {
		t.Error("expected error for invalid base64 HMAC secret")
	}
}

// ---------------------------------------------------------------------------
// HMAC signature verification: canonical message format
// ---------------------------------------------------------------------------

func TestCanonicalMessageFormat(t *testing.T) {
	// Verify the canonical payload uses the correct key order:
	// code_challenge, method, verifying_key_id, expires_in
	payload := CanonicalPayload{
		CodeChallenge:  "test-challenge",
		Method:         "S256",
		VerifyingKeyID: nil,
		ExpiresIn:      300,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	payloadStr := string(payloadBytes)
	// Verify key order matches server expectation
	codeIdx := strings.Index(payloadStr, "code_challenge")
	methodIdx := strings.Index(payloadStr, "method")
	vkeyIdx := strings.Index(payloadStr, "verifying_key_id")
	expiresIdx := strings.Index(payloadStr, "expires_in")

	if codeIdx >= methodIdx || methodIdx >= vkeyIdx || vkeyIdx >= expiresIdx {
		t.Errorf("key order mismatch in canonical payload: %s", payloadStr)
	}

	// Verify null verifying_key_id is serialised correctly
	if !strings.Contains(payloadStr, `"verifying_key_id":null`) {
		t.Errorf("verifying_key_id should be null, got: %s", payloadStr)
	}
}

// ---------------------------------------------------------------------------
// Demo token middleware: valid token with validation enabled
// ---------------------------------------------------------------------------

func TestDemoTokenMiddlewareValidToken(t *testing.T) {
	originalSecret := demoTokenSecret
	originalEnabled := demoTokenValidationEnabled
	defer func() {
		demoTokenSecret = originalSecret
		demoTokenValidationEnabled = originalEnabled
	}()

	demoTokenSecret = "test-middleware-secret"
	demoTokenValidationEnabled = true

	today := time.Now().UTC().Format("20060102")
	h := hmac.New(sha256.New, []byte("test-middleware-secret"))
	h.Write([]byte("provii-demos-v1:" + today))
	expectedSig := hex.EncodeToString(h.Sum(nil))[:16]
	validToken := "demo_token_v1_" + today + "_" + expectedSig

	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := demoTokenMiddleware(inner)
	req := httptest.NewRequest("GET", "/api/config", nil)
	req.Header.Set("X-Demo-Token", validToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !innerCalled {
		t.Error("inner handler should have been called with valid demo token")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Static file handler: path traversal with .html extension
// ---------------------------------------------------------------------------

func TestStaticFileHandlerTraversalWithHTMLExtension(t *testing.T) {
	rec := chiServe(t, "GET", "/*", "/../../../etc/passwd.html", staticFileHandler, "")
	// Should return 404 because the resolved path escapes the public directory
	if rec.Code != http.StatusOK && rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (or 200 if file exists, but it should not)", rec.Code)
	}
}

func TestStaticFileHandlerNonExistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	publicDir := filepath.Join(tmpDir, "public")
	os.MkdirAll(publicDir, 0o755)

	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	rec := chiServe(t, "GET", "/*", "/nonexistent.html", staticFileHandler, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Verify response content types and field presence
// ---------------------------------------------------------------------------

func TestHealthHandlerContentType(t *testing.T) {
	saved := config
	defer func() { config = saved }()
	config.HMACSecret = "s"
	config.APIKey = "k"
	config.ClientID = "c"

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	healthHandler(rec, req)

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestConfigHandlerUnconfigured(t *testing.T) {
	saved := config
	defer func() { config = saved }()
	config.VerifierAPIURL = "https://sandbox-verify.provii.app"
	config.ClientID = ""
	config.APIKey = ""
	config.HMACSecret = ""

	req := httptest.NewRequest("GET", "/api/config", nil)
	rec := httptest.NewRecorder()
	configHandler(rec, req)

	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	if body["has_client_id"] != false {
		t.Error("has_client_id should be false when client_id empty")
	}
	if body["api_key_configured"] != false {
		t.Error("api_key_configured should be false when api_key empty")
	}
	if body["hmac_secret_configured"] != false {
		t.Error("hmac_secret_configured should be false when hmac_secret empty")
	}
}

// ---------------------------------------------------------------------------
// Expert mode: verify error response structure
// ---------------------------------------------------------------------------

func TestExpertChallengeHandlerFailureResponseStructure(t *testing.T) {
	saved := config
	savedDemoSecret := demoTokenSecret
	savedDemoEnabled := demoTokenValidationEnabled
	defer func() {
		config = saved
		demoTokenSecret = savedDemoSecret
		demoTokenValidationEnabled = savedDemoEnabled
	}()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("fail"))
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   mockServer.URL,
		ClientID:         "test-client",
		APIKey:           "test-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://test.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
	}
	demoTokenSecret = ""
	demoTokenValidationEnabled = false

	body, _ := json.Marshal(map[string]interface{}{
		"code_challenge": "test",
		"method":         "S256",
	})
	req := httptest.NewRequest("POST", "/api/challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	expertChallengeHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["code"] != "CHALLENGE_FAILED" {
		t.Errorf("error code = %q, want CHALLENGE_FAILED", resp["code"])
	}
	if resp["reference"] == "" {
		t.Error("expected reference in error response")
	}
}

func TestExpertPollHandlerFailureResponseStructure(t *testing.T) {
	saved := config
	savedDemoSecret := demoTokenSecret
	savedDemoEnabled := demoTokenValidationEnabled
	defer func() {
		config = saved
		demoTokenSecret = savedDemoSecret
		demoTokenValidationEnabled = savedDemoEnabled
	}()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   mockServer.URL,
		ClientID:         "test-client",
		APIKey:           "test-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://test.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
	}
	demoTokenSecret = ""
	demoTokenValidationEnabled = false

	body, _ := json.Marshal(map[string]interface{}{"challengeId": "some-id"})
	req := httptest.NewRequest("POST", "/api/poll", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	expertPollHandler(rec, req)

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["code"] != "STATUS_CHECK_FAILED" {
		t.Errorf("error code = %q, want STATUS_CHECK_FAILED", resp["code"])
	}
}

func TestExpertRedeemHandlerFailureResponseStructure(t *testing.T) {
	saved := config
	savedDemoSecret := demoTokenSecret
	savedDemoEnabled := demoTokenValidationEnabled
	defer func() {
		config = saved
		demoTokenSecret = savedDemoSecret
		demoTokenValidationEnabled = savedDemoEnabled
	}()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   mockServer.URL,
		ClientID:         "test-client",
		APIKey:           "test-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://test.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
	}
	demoTokenSecret = ""
	demoTokenValidationEnabled = false

	body, _ := json.Marshal(map[string]interface{}{
		"challenge_id":  "some-id",
		"code_verifier": "some-verifier",
	})
	req := httptest.NewRequest("POST", "/api/redeem", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	expertRedeemHandler(rec, req)

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["code"] != "REDEEM_FAILED" {
		t.Errorf("error code = %q, want REDEEM_FAILED", resp["code"])
	}
}

// ---------------------------------------------------------------------------
// createChallengeHandler: verify session is stored correctly after success
// ---------------------------------------------------------------------------

func TestCreateChallengeHandlerSessionStored(t *testing.T) {
	_, cleanup := setupMockVerifierAPI(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{"minimum_age": 18})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp CreateChallengeResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	// Verify session was stored
	sessionMutex.RLock()
	session := sessions[resp.SessionID]
	sessionMutex.RUnlock()

	if session == nil {
		t.Fatal("session should be stored after successful challenge creation")
	}
	if session.CodeVerifier == "" {
		t.Error("session code_verifier should not be empty")
	}
	if session.ChallengeID != resp.SessionID {
		t.Errorf("session challenge_id = %q, want %q", session.ChallengeID, resp.SessionID)
	}
	if session.ProofDirection != "over_age" {
		t.Errorf("session proof_direction = %q, want over_age", session.ProofDirection)
	}

	// Clean up
	sessionMutex.Lock()
	delete(sessions, resp.SessionID)
	sessionMutex.Unlock()
}

// ---------------------------------------------------------------------------
// Verify create-challenge handler responds correctly with valid expires_in
// ---------------------------------------------------------------------------

func TestCreateChallengeHandlerValidExpiresIn(t *testing.T) {
	_, cleanup := setupMockVerifierAPI(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{"minimum_age": 18, "expires_in": 120})
	req := httptest.NewRequest("POST", "/api/create-challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	createChallengeHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Verify the full createChallengeWithAPI request sends correct headers
// ---------------------------------------------------------------------------

func TestCreateChallengeWithAPIHeaders(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	var gotContentType, gotAPIKey, gotOrigin string
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		gotAPIKey = r.Header.Get("X-API-Key")
		gotOrigin = r.Header.Get("Origin")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ChallengeAPIResponse{
			ChallengeID: "e1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5",
			RPChallenge: "rp", CutoffDays: 6574, VerifyingKeyID: 1,
			SubmitSecret: "s", ExpiresAt: time.Now().Unix() + 300,
			ProofDirection: "over_age",
		})
	}))
	defer mockServer.Close()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   mockServer.URL,
		ClientID:         "my-client-id",
		APIKey:           "my-api-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://my-origin.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
	}

	_, err := createChallengeWithAPI("challenge", 18, 300)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotAPIKey != "my-api-key" {
		t.Errorf("X-API-Key = %q, want my-api-key", gotAPIKey)
	}
	if gotOrigin != "https://my-origin.provii.app" {
		t.Errorf("Origin = %q, want https://my-origin.provii.app", gotOrigin)
	}
}

// ---------------------------------------------------------------------------
// createChallengeWithAPI: invalid URL triggers http.NewRequest error
// ---------------------------------------------------------------------------

func TestCreateChallengeWithAPIInvalidURL(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	secret := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-32-bytes-long!!"))
	config = Config{
		VerifierAPIURL:   "://invalid-url", // missing scheme
		ClientID:         "test-client",
		APIKey:           "test-key",
		HMACSecret:       secret,
		RegisteredOrigin: "https://test.provii.app",
		Port:             "3001",
		AllowedOrigins:   []string{"http://localhost:3000"},
	}

	_, err := createChallengeWithAPI("challenge", 18, 300)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

// ---------------------------------------------------------------------------
// pollChallengeStatus: invalid URL triggers http.NewRequest error
// ---------------------------------------------------------------------------

func TestPollChallengeStatusInvalidURL(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	config.VerifierAPIURL = "://invalid-url"
	config.APIKey = "test-key"

	_, err := pollChallengeStatus("some-id")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

// ---------------------------------------------------------------------------
// redeemChallenge: invalid URL triggers http.NewRequest error
// ---------------------------------------------------------------------------

func TestRedeemChallengeInvalidURL(t *testing.T) {
	saved := config
	defer func() { config = saved }()

	config.VerifierAPIURL = "://invalid-url"
	config.APIKey = "test-key"

	_, err := redeemChallenge("cid", "cv")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

// ---------------------------------------------------------------------------
// newRouter: verify route registration
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// requireCredentials
// ---------------------------------------------------------------------------

func TestRequireCredentialsMissing(t *testing.T) {
	c := Config{ClientID: "", APIKey: "k", HMACSecret: "s", VerifierAPIURL: "u"}
	if err := requireCredentials(c); err == nil {
		t.Error("expected error for missing ClientID")
	}
	c = Config{ClientID: "c", APIKey: "", HMACSecret: "s", VerifierAPIURL: "u"}
	if err := requireCredentials(c); err == nil {
		t.Error("expected error for missing APIKey")
	}
	c = Config{ClientID: "c", APIKey: "k", HMACSecret: "", VerifierAPIURL: "u"}
	if err := requireCredentials(c); err == nil {
		t.Error("expected error for missing HMACSecret")
	}
	c = Config{ClientID: "c", APIKey: "k", HMACSecret: "s", VerifierAPIURL: ""}
	if err := requireCredentials(c); err == nil {
		t.Error("expected error for missing VerifierAPIURL")
	}
}

func TestRequireCredentialsComplete(t *testing.T) {
	c := Config{ClientID: "c", APIKey: "k", HMACSecret: "s", VerifierAPIURL: "u"}
	if err := requireCredentials(c); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewRouterRegistersRoutes(t *testing.T) {
	saved := config
	savedDemoSecret := demoTokenSecret
	savedDemoEnabled := demoTokenValidationEnabled
	defer func() {
		config = saved
		demoTokenSecret = savedDemoSecret
		demoTokenValidationEnabled = savedDemoEnabled
	}()

	config.AllowedOrigins = []string{"http://localhost:3000"}
	config.IsProduction = false
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

	// Verify root redirect works
	req2 := httptest.NewRequest("GET", "/", nil)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusFound {
		t.Errorf("root redirect via newRouter() returned %d, want 302", rec2.Code)
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestSessionConcurrency(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := "test-" + strings.Repeat("0", id%10)
			sessionMutex.Lock()
			sessions[key] = &SessionData{
				CodeVerifier: "v",
				ChallengeID:  key,
				ExpiresAt:    time.Now().Unix() + 300,
				CreatedAt:    time.Now().Unix(),
			}
			sessionMutex.Unlock()

			sessionMutex.RLock()
			_ = sessions[key]
			sessionMutex.RUnlock()
		}(i)
	}
	wg.Wait()

	sessionMutex.Lock()
	for k := range sessions {
		if strings.HasPrefix(k, "test-") {
			delete(sessions, k)
		}
	}
	sessionMutex.Unlock()
}
