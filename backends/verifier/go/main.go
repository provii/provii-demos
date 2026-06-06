// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// Provii Verifier Backend Demo for Go.
//
// Reference implementation showing how third-party verifiers (social media apps,
// age-gated websites, content platforms, dating services) integrate with
// Provii's provii-verifier using direct HMAC authentication.
//
// Integration steps:
//
//  1. Copy the core functions marked with "=== COPY THIS ===" below
//  2. Set environment variables: CLIENT_ID, HMAC_SECRET, API_KEY
//  3. Create your /api/create-challenge endpoint
//  4. Return the deep_link to your mobile app
//  5. Store the code_verifier securely (associated with session_id)
//  6. When user completes verification, call /api/redeem with code_verifier
//
// See INTEGRATION.md for complete examples and framework-specific code.
//
// Verification flow:
//
//  1. Mobile app requests age verification from YOUR backend
//  2. Your backend generates PKCE (code_verifier + code_challenge)
//  3. Your backend authenticates to provii-verifier with HMAC
//  4. Your backend stores code_verifier securely (in session/DB)
//  5. Your backend returns deep_link to mobile app
//  6. Mobile app opens Provii Wallet with deep link
//  7. User verifies in wallet (ZK proof submitted to provii-verifier)
//  8. Mobile app polls YOUR backend for status
//  9. When verified, YOUR backend redeems with code_verifier
//
// SECURITY: Your backend never exposes HMAC_SECRET or code_verifier to clients.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	_ "github.com/joho/godotenv/autoload" // loads .env at startup if present
	"github.com/go-chi/chi/v5/middleware"
)

// ============================================================================
// Configuration
// ============================================================================

// Config holds the resolved server configuration built from environment variables.
type Config struct {
	VerifierAPIURL   string
	ClientID         string
	APIKey           string
	HMACSecret       string
	RegisteredOrigin string
	Port             string
	AllowedOrigins   []string
	IsProduction     bool
}

var config = Config{
	VerifierAPIURL:   getEnv("VERIFIER_API_URL", "https://sandbox-verify.provii.app"),
	ClientID:         getEnv("CLIENT_ID", ""),
	APIKey:           getEnv("API_KEY", ""),
	HMACSecret:       getEnv("HMAC_SECRET", ""),
	RegisteredOrigin: getEnv("REGISTERED_ORIGIN", "https://playground.provii.app"),
	Port:             getEnv("PORT", "3001"),
	AllowedOrigins:   parseAllowedOrigins(getEnv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173")),
	IsProduction:     getEnv("GO_ENV", "") == "production",
}

// getEnv returns the environment variable value or the provided fallback.
func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// parseAllowedOrigins splits a comma-separated string of origins into a slice.
func parseAllowedOrigins(originsStr string) []string {
	var origins []string
	for _, origin := range strings.Split(originsStr, ",") {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			origins = append(origins, origin)
		}
	}
	return origins
}

// SessionData holds session state alongside the secret code_verifier.
// Replace this in-memory map with Redis or a database in production.
type SessionData struct {
	CodeVerifier   string
	ChallengeID    string
	ExpiresAt      int64
	CreatedAt      int64
	ProofDirection string
}

var (
	sessions     = make(map[string]*SessionData)
	sessionMutex sync.RWMutex
	httpClient   = &http.Client{Timeout: 15 * time.Second}
)

// ============================================================================
// === COPY THIS: Core Cryptographic & API Functions ===
// ============================================================================

// base64URLEncode encodes bytes to base64url without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode decodes a base64url string to bytes.
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// generateCodeVerifier creates a cryptographically secure PKCE code_verifier.
// RFC 7636 compliant: 32 random bytes yield 43 base64url characters.
func generateCodeVerifier() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64URLEncode(bytes), nil
}

// generateCodeChallenge creates the S256 PKCE code_challenge by SHA-256 hashing
// the code_verifier.
func generateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64URLEncode(hash[:])
}

// createHMACSignature creates an HMAC-SHA256 signature (hex-encoded, lowercase).
//
// SECURITY: Canonical message format for provii-verifier:
// {timestamp}:POST:/v1/challenge:{json_payload_without_hmac}:{nonce}
func createHMACSignature(message, secretBase64URL string) (string, error) {
	secretBytes, err := base64URLDecode(secretBase64URL)
	if err != nil {
		return "", fmt.Errorf("failed to decode HMAC secret: %w", err)
	}

	h := hmac.New(sha256.New, secretBytes)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// isValidUUID validates that a string matches the UUID format.
var uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func isValidUUID(s string) bool {
	return uuidRegex.MatchString(strings.ToLower(s))
}

// generateErrorID creates an 8-character hex error reference for log correlation.
func generateErrorID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ============================================================================
// === END OF CORE FUNCTIONS ===
// ============================================================================

// ChallengeAPIResponse is the challenge response received from provii-verifier.
type ChallengeAPIResponse struct {
	ChallengeID        string `json:"challenge_id"`
	RPChallenge        string `json:"rp_challenge"`
	CutoffDays         int    `json:"cutoff_days"`
	VerifyingKeyID     int64  `json:"verifying_key_id"`
	SubmitSecret       string `json:"submit_secret"`
	ExpiresAt          int64  `json:"expires_at"`
	StatusURL          string `json:"status_url"`
	VerifyURL          string `json:"verify_url"`
	ProofDirection     string `json:"proof_direction"`
	ShortCode          string `json:"short_code,omitempty"`
	ShortCodeFormatted string `json:"short_code_formatted,omitempty"`
}

// StatusAPIResponse is the status response received from provii-verifier.
type StatusAPIResponse struct {
	State         string `json:"state"`
	Status        string `json:"status"`
	Verified      bool   `json:"verified"`
	ProofVerified bool   `json:"proof_verified"`
}

// RedeemAPIResponse is the redemption response received from provii-verifier.
type RedeemAPIResponse struct {
	Result   string `json:"result"`
	Verified bool   `json:"verified"`
}

// Authorizer carries the HMAC authentication fields for provii-verifier requests.
type Authorizer struct {
	KeyID     string `json:"keyId"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// CanonicalPayload is the subset of fields used for HMAC computation.
// Field order MUST match server's create_canonical_message_for_challenge.
// The server uses serde_json::json!() with preserve_order enabled (via feature unification),
// so keys follow INSERTION ORDER from the json!() macro in challenge.rs:265-270:
// code_challenge, method, verifying_key_id, expires_in.
// The nonce from the authorizer block is appended as the 5th field in the canonical message.
type CanonicalPayload struct {
	CodeChallenge  string `json:"code_challenge"`
	Method         string `json:"method"`
	VerifyingKeyID *int   `json:"verifying_key_id"`
	ExpiresIn      int    `json:"expires_in"`
}

// ChallengePayload is the full request body sent to provii-verifier, including
// the authorizer block with nonce for replay protection.
type ChallengePayload struct {
	CodeChallenge string     `json:"code_challenge"`
	Method        string     `json:"method"`
	ExpiresIn     int        `json:"expires_in"`
	Authorizer    Authorizer `json:"authorizer"`
}

// buildDeepLink constructs a Provii Wallet deep link URL from the challenge
// response fields.
func buildDeepLink(challenge *ChallengeAPIResponse) string {
	payload := map[string]interface{}{
		"challenge_id":     challenge.ChallengeID,
		"rp_challenge":     challenge.RPChallenge,
		"submit_secret":    challenge.SubmitSecret,
		"cutoff_days":      challenge.CutoffDays,
		"verifying_key_id": challenge.VerifyingKeyID,
		"verify_url":       challenge.VerifyURL,
		"expires_at":       challenge.ExpiresAt,
		"proof_direction":  challenge.ProofDirection,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		// This should never fail with known-good types, but propagate rather than silently corrupt.
		return ""
	}
	return "https://provii.app/verify?d=" + base64URLEncode(jsonBytes)
}

// createChallengeWithAPI creates a verification challenge via provii-verifier
// with HMAC authentication. The HMAC covers a canonical message to prevent
// request tampering.
func createChallengeWithAPI(codeChallenge string, minimumAge, expiresIn int) (*ChallengeAPIResponse, error) {
	if config.HMACSecret == "" {
		return nil, fmt.Errorf("HMAC_SECRET not configured")
	}
	if config.APIKey == "" {
		return nil, fmt.Errorf("API_KEY not configured")
	}

	timestamp := time.Now().Unix()
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	// SECURITY: Canonical payload for HMAC must match server's create_canonical_message_for_challenge.
	// The server uses serde_json::json!() with preserve_order enabled (via feature unification),
	// so keys follow INSERTION ORDER from the json!() macro in challenge.rs:265-270:
	// code_challenge, method, verifying_key_id, expires_in.
	// The nonce from the authorizer block is appended as the 5th field in the canonical message.
	// proof_direction is determined server-side from origin policy, not sent by client.
	// Go json.Marshal follows struct field definition order, which matches the required order.
	canonicalPayload := CanonicalPayload{
		CodeChallenge:  codeChallenge,
		Method:         "S256",
		VerifyingKeyID: nil,
		ExpiresIn:      expiresIn,
	}

	payloadBytes, err := json.Marshal(canonicalPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal canonical payload: %w", err)
	}

	canonicalMessage := fmt.Sprintf("%d:POST:/v1/challenge:%s:%s", timestamp, string(payloadBytes), nonce)
	hmacSig, err := createHMACSignature(canonicalMessage, config.HMACSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create HMAC: %w", err)
	}

	fullPayload := ChallengePayload{
		CodeChallenge: codeChallenge,
		Method:        "S256",
		ExpiresIn:     expiresIn,
		Authorizer: Authorizer{
			KeyID:     config.ClientID,
			Timestamp: timestamp,
			Nonce:     nonce,
			HMAC:      hmacSig,
		},
	}

	body, err := json.Marshal(fullPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal challenge payload: %w", err)
	}

	// Origin header must match the registered origin policy in provii-verifier
	req, err := http.NewRequest("POST", config.VerifierAPIURL+"/v1/challenge", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create challenge request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", config.APIKey)
	req.Header.Set("Origin", config.RegisteredOrigin)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("challenge creation failed: %d - %s", resp.StatusCode, string(bodyBytes))
	}

	var result ChallengeAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// pollChallengeStatus checks challenge status from provii-verifier by challenge ID.
func pollChallengeStatus(challengeID string) (*StatusAPIResponse, error) {
	req, err := http.NewRequest("GET", config.VerifierAPIURL+"/v1/challenge/"+challengeID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create status request: %w", err)
	}
	req.Header.Set("X-API-Key", config.APIKey)
	req.Header.Set("Origin", config.RegisteredOrigin)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status check failed: %d - %s", resp.StatusCode, string(bodyBytes))
	}

	var result StatusAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// redeemChallenge redeems a verified challenge by presenting the PKCE
// code_verifier to provii-verifier.
func redeemChallenge(challengeID, codeVerifier string) (*RedeemAPIResponse, error) {
	body, err := json.Marshal(map[string]string{"code_verifier": codeVerifier})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal redeem payload: %w", err)
	}

	req, err := http.NewRequest("POST", config.VerifierAPIURL+"/v1/challenge/"+challengeID+"/redeem", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create redeem request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", config.APIKey)
	req.Header.Set("Origin", config.RegisteredOrigin)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("redeem failed: %d - %s", resp.StatusCode, string(bodyBytes))
	}

	var result RedeemAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ============================================================================
// HTTP Handlers
// ============================================================================

// CreateChallengeRequest is the request body for POST /api/create-challenge.
type CreateChallengeRequest struct {
	MinimumAge *int `json:"minimum_age,omitempty"`
	MaximumAge *int `json:"maximum_age,omitempty"`
	ExpiresIn  int  `json:"expires_in,omitempty"`
}

// CreateChallengeResponse is the response body for POST /api/create-challenge.
type CreateChallengeResponse struct {
	SessionID      string `json:"session_id"`
	DeepLink       string `json:"deep_link"`
	ExpiresAt      int64  `json:"expires_at"`
	StatusURL      string `json:"status_url"`
	ProofDirection string `json:"proof_direction"`
}

// StatusResponse is the response body for GET /api/status/{sessionId}.
type StatusResponse struct {
	State         string `json:"state"`
	Verified      bool   `json:"verified"`
	ProofVerified bool   `json:"proof_verified"`
}

// RedeemResponse is the response body for POST /api/redeem/{sessionId}.
type RedeemResponse struct {
	Result   string `json:"result"`
	Verified bool   `json:"verified"`
}

// healthHandler returns credential configuration status.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	configured := config.HMACSecret != "" && config.APIKey != "" && config.ClientID != ""
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"configured": configured,
	})
}

// configHandler returns configuration visibility info for debugging.
func configHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"verifier_api_url":       config.VerifierAPIURL,
		"has_client_id":          config.ClientID != "",
		"api_key_configured":     config.APIKey != "",
		"hmac_secret_configured": config.HMACSecret != "",
	})
}

// createChallengeHandler creates a new age verification challenge.
// Accepts minimum_age (over_age) or maximum_age (under_age), but not both.
func createChallengeHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB

	var req CreateChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.MinimumAge != nil && req.MaximumAge != nil {
		http.Error(w, `{"error":"Cannot specify both minimum_age and maximum_age"}`, http.StatusBadRequest)
		return
	}

	isUnderAge := req.MaximumAge != nil
	var age int
	if isUnderAge {
		age = *req.MaximumAge
	} else if req.MinimumAge != nil {
		age = *req.MinimumAge
	} else {
		age = 18
	}

	if req.ExpiresIn == 0 {
		req.ExpiresIn = 300
	}

	if req.ExpiresIn < 60 || req.ExpiresIn > 300 {
		http.Error(w, `{"error":"Invalid expires_in: must be between 60 and 300"}`, http.StatusBadRequest)
		return
	}

	if age < 13 || age > 120 {
		field := "minimum_age"
		if isUnderAge {
			field = "maximum_age"
		}
		http.Error(w, fmt.Sprintf(`{"error":"Invalid %s: must be 13-120"}`, field), http.StatusBadRequest)
		return
	}

	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		errorID := generateErrorID()
		log.Printf("[%s] Error generating code verifier: %v", errorID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Internal server error", "reference": errorID})
		return
	}
	codeChallenge := generateCodeChallenge(codeVerifier)

	challenge, err := createChallengeWithAPI(codeChallenge, age, req.ExpiresIn)
	if err != nil {
		errorID := generateErrorID()
		log.Printf("[%s] Error creating challenge: %v", errorID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Challenge creation failed", "reference": errorID})
		return
	}

	// SECURITY: code_verifier is secret and must never leave the backend
	sessionMutex.Lock()
	sessions[challenge.ChallengeID] = &SessionData{
		CodeVerifier:   codeVerifier,
		ChallengeID:    challenge.ChallengeID,
		ExpiresAt:      challenge.ExpiresAt,
		CreatedAt:      time.Now().Unix(),
		ProofDirection: challenge.ProofDirection,
	}
	sessionMutex.Unlock()

	deepLink := buildDeepLink(challenge)
	if deepLink == "" {
		errorID := generateErrorID()
		log.Printf("[%s] Error building deep link for challenge %s", errorID, challenge.ChallengeID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to build deep link", "reference": errorID})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(CreateChallengeResponse{
		SessionID:      challenge.ChallengeID,
		DeepLink:       deepLink,
		ExpiresAt:      challenge.ExpiresAt,
		StatusURL:      fmt.Sprintf("/api/status/%s", challenge.ChallengeID),
		ProofDirection: challenge.ProofDirection,
	})
}

// getStatusHandler polls the current verification status for a session by
// forwarding the query to provii-verifier.
func getStatusHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionId")
	if sessionID == "" {
		http.Error(w, `{"error":"Missing session_id"}`, http.StatusBadRequest)
		return
	}

	if !isValidUUID(sessionID) {
		http.Error(w, `{"error":"Invalid session_id format"}`, http.StatusBadRequest)
		return
	}

	sessionMutex.RLock()
	session := sessions[sessionID]
	sessionMutex.RUnlock()

	if session == nil {
		http.Error(w, `{"error":"Session not found"}`, http.StatusNotFound)
		return
	}

	status, err := pollChallengeStatus(sessionID)
	if err != nil {
		errorID := generateErrorID()
		log.Printf("[%s] Error checking status: %v", errorID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to check status", "reference": errorID})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(StatusResponse{
		State:         status.State,
		Verified:      status.Verified,
		ProofVerified: status.ProofVerified,
	})
}

// redeemHandler redeems a verified challenge to complete the verification flow.
//
// SECURITY: Uses delete-before-use pattern to prevent TOCTOU race conditions.
// The session is deleted BEFORE using the code_verifier so that only one
// request can succeed even if multiple concurrent requests arrive. The
// provii-verifier also enforces single redemption as defence-in-depth.
func redeemHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB

	sessionID := chi.URLParam(r, "sessionId")
	if sessionID == "" {
		http.Error(w, `{"error":"Missing session_id"}`, http.StatusBadRequest)
		return
	}

	if !isValidUUID(sessionID) {
		http.Error(w, `{"error":"Invalid session_id format"}`, http.StatusBadRequest)
		return
	}

	// SECURITY: Delete-before-use pattern prevents double-redemption.
	// Acquire write lock, read session, delete it, release lock, THEN redeem.
	sessionMutex.Lock()
	session := sessions[sessionID]
	if session != nil {
		delete(sessions, sessionID)
	}
	sessionMutex.Unlock()

	if session == nil {
		http.Error(w, `{"error":"Session not found or already redeemed"}`, http.StatusNotFound)
		return
	}

	// Session already deleted, so replay is impossible even if redemption fails.
	// Provii-verifier enforces single-use as defence-in-depth.
	result, err := redeemChallenge(sessionID, session.CodeVerifier)
	if err != nil {
		errorID := generateErrorID()
		log.Printf("[%s] Error redeeming challenge: %v", errorID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to redeem challenge", "reference": errorID})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RedeemResponse{
		Result:   result.Result,
		Verified: result.Verified,
	})
}

// corsMiddleware handles CORS preflight and sets appropriate headers based on
// the configured origin allowlist.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := false
		for _, o := range config.AllowedOrigins {
			if o == origin {
				allowed = true
				break
			}
		}
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Demo-Token")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if config.IsProduction {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")

		// Demo HTML pages need a permissive CSP to load provii-agegate from CDN.
		// API endpoints use a strict CSP.
		path := r.URL.Path
		if path == "/" || strings.HasSuffix(path, ".html") {
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self' 'unsafe-inline' https://cdn.provii.app; "+
					"style-src 'self' 'unsafe-inline' https://cdn.provii.app; "+
					"connect-src 'self' https://*.provii.app wss://*.provii.app; "+
					"img-src 'self' data:; "+
					"frame-ancestors 'none'")
		} else {
			w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		}

		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// Demo Token Validation
//
// The X-Demo-Token header guards the publicly-deployed CF Worker
// (verifier-demo.provii.app) against unauthorised use of shared sandbox
// credentials. The signing secret lives in Cloudflare's Secrets Store and is
// only available to the deployed Worker.
//
// For a local Go backend on localhost, the dev controls both sides of the
// request, so there is no security boundary to enforce. When DEMO_TOKEN_SECRET
// is unset (the default for `go run main.go`), token validation is skipped.
// Setting DEMO_TOKEN_SECRET re-enables validation, which is what the production
// CF Worker code path does via its Secrets Store binding.
// ============================================================================

var demoTokenSecret = os.Getenv("DEMO_TOKEN_SECRET")
var demoTokenValidationEnabled = demoTokenSecret != ""

// validateDemoToken validates the X-Demo-Token header to prevent unauthorised
// access to demo backends.
//
// Token format: demo_token_v1_<YYYYMMDD>_<16-char-hmac>.
//
// Caller MUST gate this on demoTokenValidationEnabled. The function assumes
// demoTokenSecret is set.
//
// SECURITY: Uses hmac.Equal for constant-time comparison of the HMAC tag.
func validateDemoToken(token string) bool {
	if !strings.HasPrefix(token, "demo_token_v1_") {
		return false
	}

	parts := strings.Split(token, "_")
	if len(parts) != 5 {
		return false
	}

	dateStr := parts[3]
	providedSig := parts[4]

	// Accept today or yesterday to handle timezone boundaries (48-hour window)
	today := time.Now().UTC().Format("20060102")
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("20060102")

	if dateStr != today && dateStr != yesterday {
		return false
	}

	h := hmac.New(sha256.New, []byte(demoTokenSecret))
	h.Write([]byte("provii-demos-v1:" + dateStr))
	expectedSig := hex.EncodeToString(h.Sum(nil))[:16]

	// SECURITY: Constant-time comparison using hmac.Equal
	return hmac.Equal([]byte(providedSig), []byte(expectedSig))
}

// expertPaths lists the URL paths used by Expert mode proxy endpoints.
// These skip demo token validation because they authenticate via HMAC to provii-verifier.
var expertPaths = map[string]bool{
	"/api/challenge": true,
	"/api/poll":      true,
	"/api/redeem":    true,
	"/api/session":   true,
}

// demoTokenMiddleware validates the X-Demo-Token header on /api/* routes.
// Expert proxy endpoints are excluded because HMAC auth to provii-verifier is the real security.
// Pass-through when demoTokenSecret is unset (local dev mode).
func demoTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		// Expert mode endpoints bypass demo token validation
		if expertPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		if !demoTokenValidationEnabled {
			next.ServeHTTP(w, r)
			return
		}

		token := r.Header.Get("X-Demo-Token")
		if !validateDemoToken(token) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid or missing demo token",
				"hint":  "Fetch token from https://playground.provii.app/v1/config/demo-token",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// Expert Mode Proxy Endpoints (provii-agegate rp-proxy mode)
//
// These endpoints accept requests from provii-agegate and proxy them to
// provii-verifier with HMAC authentication. provii-agegate manages PKCE and
// the frontend UX. The developer only needs to run this backend.
// ============================================================================

// ExpertChallengeRequest is the request body for POST /api/challenge (Expert proxy).
type ExpertChallengeRequest struct {
	CodeChallenge  string `json:"code_challenge"`
	Method         string `json:"method"`
	VerifyingKeyID *int   `json:"verifying_key_id"`
	ExpiresIn      int    `json:"expires_in"`
}

// ExpertPollRequest is the request body for POST /api/poll (Expert proxy).
type ExpertPollRequest struct {
	ChallengeID string `json:"challengeId"`
}

// ExpertRedeemRequest is the request body for POST /api/redeem (Expert proxy).
type ExpertRedeemRequest struct {
	ChallengeID  string `json:"challenge_id"`
	CodeVerifier string `json:"code_verifier"`
}

// expertChallengeHandler creates a challenge on behalf of provii-agegate.
// provii-agegate sends { code_challenge, method, verifying_key_id, expires_in }
// and this endpoint adds HMAC auth and forwards to provii-verifier.
func expertChallengeHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB

	var req ExpertChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.CodeChallenge == "" {
		http.Error(w, `{"error":"code_challenge is required"}`, http.StatusBadRequest)
		return
	}

	expiresIn := req.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 300
	}

	// Use the client-provided code_challenge (provii-agegate generated it)
	challenge, err := createChallengeWithAPI(req.CodeChallenge, 18, expiresIn)
	if err != nil {
		errorID := generateErrorID()
		log.Printf("[%s] Error creating challenge (expert): %v", errorID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":     "Failed to create challenge",
			"code":      "CHALLENGE_FAILED",
			"reference": errorID,
		})
		return
	}

	// Return the full challenge response (provii-agegate expects these fields)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(challenge)
}

// expertPollHandler polls challenge status on behalf of provii-agegate.
// provii-agegate sends { challengeId } via POST in rp-proxy mode.
func expertPollHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB

	var req ExpertPollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.ChallengeID == "" {
		http.Error(w, `{"error":"challengeId is required"}`, http.StatusBadRequest)
		return
	}

	status, err := pollChallengeStatus(req.ChallengeID)
	if err != nil {
		errorID := generateErrorID()
		log.Printf("[%s] Error polling status (expert): %v", errorID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":     "Failed to check status",
			"code":      "STATUS_CHECK_FAILED",
			"reference": errorID,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// expertRedeemHandler redeems a challenge on behalf of provii-agegate.
// provii-agegate sends { challenge_id, code_verifier } in rp-proxy mode.
// The code_verifier comes from provii-agegate (it generated the PKCE pair).
func expertRedeemHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB

	var req ExpertRedeemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.ChallengeID == "" {
		http.Error(w, `{"error":"challenge_id is required"}`, http.StatusBadRequest)
		return
	}
	if req.CodeVerifier == "" {
		http.Error(w, `{"error":"code_verifier is required"}`, http.StatusBadRequest)
		return
	}

	result, err := redeemChallenge(req.ChallengeID, req.CodeVerifier)
	if err != nil {
		errorID := generateErrorID()
		log.Printf("[%s] Error redeeming (expert): %v", errorID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":     "Failed to redeem verification",
			"code":      "REDEEM_FAILED",
			"reference": errorID,
		})
		return
	}

	// Set a session cookie so the frontend knows the user is verified on reload.
	// In production, use a signed/encrypted token with expiry.
	sessionToken := make([]byte, 32)
	rand.Read(sessionToken)
	http.SetCookie(w, &http.Cookie{
		Name:     "verified_session",
		Value:    hex.EncodeToString(sessionToken),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// expertSessionHandler checks whether the user has a valid session cookie.
// In Expert mode, the developer manages sessions, not provii-verifier.
func expertSessionHandler(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("verified_session")
	hasSession := err == nil

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"verified": hasSession,
	})
}

// ============================================================================
// Static File Serving (demo pages)
// ============================================================================

// staticFileHandler serves files from the public/ directory relative to the
// binary's working directory. Only serves .html, .js, and .css files.
func staticFileHandler(w http.ResponseWriter, r *http.Request) {
	filename := chi.URLParam(r, "*")
	if filename == "" {
		http.Redirect(w, r, "/expert.html", http.StatusFound)
		return
	}

	// Only serve expected file types
	ext := filepath.Ext(filename)
	contentTypes := map[string]string{
		".html": "text/html; charset=utf-8",
		".js":   "application/javascript",
		".css":  "text/css",
	}
	ct, allowed := contentTypes[ext]
	if !allowed {
		http.NotFound(w, r)
		return
	}

	path := filepath.Join("public", filepath.Clean(filename))

	// Prevent directory traversal
	absPath, err := filepath.Abs(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	absPublic, _ := filepath.Abs("public")
	if !strings.HasPrefix(absPath, absPublic) {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", ct)
	http.ServeFile(w, r, path)
}

// requireCredentials returns an error if any required credential is missing.
func requireCredentials(c Config) error {
	if c.ClientID == "" || c.APIKey == "" || c.HMACSecret == "" || c.VerifierAPIURL == "" {
		return fmt.Errorf("missing required environment variables: CLIENT_ID, API_KEY, HMAC_SECRET, VERIFIER_API_URL")
	}
	return nil
}

// newRouter creates and configures the chi router with all routes and middleware.
// Extracted from main() for testability.
func newRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(corsMiddleware)
	r.Use(demoTokenMiddleware)

	r.Get("/health", healthHandler)
	r.Get("/api/config", configHandler)
	r.Post("/api/create-challenge", createChallengeHandler)
	r.Get("/api/status/{sessionId}", getStatusHandler)
	r.Post("/api/redeem/{sessionId}", redeemHandler)

	// Expert mode proxy endpoints (provii-agegate rp-proxy mode)
	r.Post("/api/challenge", expertChallengeHandler)
	r.Post("/api/poll", expertPollHandler)
	r.Post("/api/redeem", expertRedeemHandler)
	r.Get("/api/session", expertSessionHandler)

	// Static file serving for demo pages
	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/expert.html", http.StatusFound)
	})
	r.Get("/*", staticFileHandler)

	return r
}

func main() {
	if err := requireCredentials(config); err != nil {
		log.Println("FATAL: missing required environment variables.")
		log.Println("Set CLIENT_ID, API_KEY, HMAC_SECRET, and VERIFIER_API_URL before starting.")
		log.Println("Mint sandbox credentials at https://admin.provii.app")
		log.Println("See backends/verifier/go/README.md for the setup walkthrough.")
		os.Exit(1)
	}

	r := newRouter()

	fmt.Println("")
	fmt.Println("=== Provii Verifier Demo Backend (Go) ===")
	fmt.Println("Mode: Direct provii-verifier integration with HMAC auth")
	fmt.Printf("Port: %s\n", config.Port)
	fmt.Printf("Verifier API: %s\n", config.VerifierAPIURL)
	fmt.Printf("Client ID: %s\n", config.ClientID)
	fmt.Printf("API Key Configured: %t\n", config.APIKey != "")
	fmt.Printf("HMAC Secret Configured: %t\n", config.HMACSecret != "")
	if demoTokenValidationEnabled {
		fmt.Println("Demo token validation: ENABLED (DEMO_TOKEN_SECRET is set)")
	} else {
		fmt.Println("Demo token validation: DISABLED (local dev mode, DEMO_TOKEN_SECRET unset).")
		fmt.Println("  Bind DEMO_TOKEN_SECRET via env injection for production.")
	}
	fmt.Println("")
	fmt.Println("Test with:")
	fmt.Printf("  curl -X POST http://localhost:%s/api/create-challenge \\\n", config.Port)
	fmt.Println("    -H \"Content-Type: application/json\" \\")
	fmt.Println("    -d '{\"minimum_age\": 21}'")
	fmt.Println("")
	fmt.Println("Then check status:")
	fmt.Printf("  curl http://localhost:%s/api/status/<session_id>\n", config.Port)
	fmt.Println("")
	fmt.Println("Then redeem (after user verifies in wallet):")
	fmt.Printf("  curl -X POST http://localhost:%s/api/redeem/<session_id>\n", config.Port)
	fmt.Println("")

	server := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
