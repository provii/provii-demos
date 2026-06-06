// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// Provii Issuer Backend Demo (Go)
//
// Reference implementation showing how to integrate Provii credential issuance
// into a Go backend. The core HMAC functions between the "COPY THIS" markers
// can be extracted into your own project.
//
// Required environment variables:
//
//	CLIENT_ID, HMAC_SECRET, ISSUER_API_URL
//
// Issuance flow (HMAC-SHA256 authenticated):
//  1. Mobile app sends customer's DOB as days since Unix epoch
//  2. This backend authenticates with HMAC-SHA256, sends dob_days to Provii provii-issuer
//  3. Provii provii-issuer creates and signs the attestation (Ed25519)
//  4. This backend returns a deep link containing the signed attestation
//  5. Mobile app opens Provii Wallet via the deep link
//  6. Wallet sends the attestation to provii-issuer for credential issuance
//
// See INTEGRATION.md for framework-specific code samples.

package main

import (
	"bytes"
	"context"
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
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// ============================================================================
// === COPY THIS: Core HMAC Authentication Functions ===
// ============================================================================

// Config holds the issuer API credentials and server settings.
type Config struct {
	ClientId       string
	HmacSecret     string
	IssuerApiUrl   string
	Port           string
	AllowedOrigins map[string]bool
	IsProduction   bool
}

var config Config
var httpClient = &http.Client{Timeout: 15 * time.Second}

// CreateAttestationRequest is the JSON request body for attestation creation.
type CreateAttestationRequest struct {
	DobDays int `json:"dob_days"`
}

// IssuerApiResponse is the JSON response returned by Provii's provii-issuer.
type IssuerApiResponse struct {
	Attestation string `json:"attestation"`
	ExpiresAt   int64  `json:"expires_at"`
	IssuerId    string `json:"issuer_id"`
}

// CreateAttestationResponse is the JSON response returned to the caller.
type CreateAttestationResponse struct {
	DeepLink  string `json:"deep_link"`
	DobDays   int    `json:"dob_days,omitempty"`
	ExpiresAt int64  `json:"expires_at"`
}

// getEnv returns the value of an environment variable, or a fallback if unset.
func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// base64urlDecode decodes a base64url-encoded string to bytes.
func base64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// hmacSha256Hex computes an HMAC-SHA256 signature and returns it as a lowercase hex string.
func hmacSha256Hex(secret []byte, message string) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// buildCanonicalMessage builds the canonical message string for HMAC signing
// against /v1/attestation/create.
//
// Format: {timestamp}:POST:/v1/attestation/create:{canonical_json}:{nonce}
//
// The canonical JSON body uses snake_case field names (key_id), which differs
// from the camelCase (keyId) used in the actual HTTP request body. The nonce
// is appended after the JSON payload and MUST match the authorizer.nonce
// field sent in the request body. See create_canonical_message_for_attestation
// in provii-issuer/src/session.rs for the server-side reference.
func buildCanonicalMessage(dobDays int, clientId string, timestamp int64, nonce string) string {
	canonicalJson := fmt.Sprintf(
		`{"dob_days":%d,"authorizer":{"format":"client","key_id":"%s","timestamp":%d}}`,
		dobDays, clientId, timestamp,
	)
	return fmt.Sprintf("%d:POST:/v1/attestation/create:%s:%s", timestamp, canonicalJson, nonce)
}

// createAttestation creates a signed attestation via Provii's provii-issuer.
//
// SECURITY: Authenticates the request with HMAC-SHA256 over a canonical message.
// Provii provii-issuer signs the attestation internally using Ed25519.
func createAttestation(dobDays int) (*IssuerApiResponse, error) {
	if config.HmacSecret == "" {
		return nil, fmt.Errorf("HMAC_SECRET not configured. Get this from the Provii admin portal")
	}
	if config.IssuerApiUrl == "" {
		return nil, fmt.Errorf("ISSUER_API_URL not configured")
	}

	timestamp := time.Now().Unix()

	// SECURITY: 256-bit random nonce prevents replay attacks. The same nonce
	// value MUST appear in both the canonical HMAC message and the request body
	// Server verification fails otherwise (provii-issuer session.rs).
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	// SECURITY: HMAC is computed over a canonical message to prevent tampering
	canonicalMessage := buildCanonicalMessage(dobDays, config.ClientId, timestamp, nonce)
	secretBytes, err := base64urlDecode(config.HmacSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode HMAC secret: %w", err)
	}
	hmacHex := hmacSha256Hex(secretBytes, canonicalMessage)

	// The HTTP request body uses camelCase keyId, while the canonical message uses snake_case key_id
	requestBody := map[string]interface{}{
		"dob_days": dobDays,
		"authorizer": map[string]interface{}{
			"format":    "client",
			"keyId":     config.ClientId,
			"timestamp": timestamp,
			"hmac":      hmacHex,
			"nonce":     nonce,
		},
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := config.IssuerApiUrl + "/v1/attestation/create"

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("issuer API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		errorBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("issuer API returned %d: %s", resp.StatusCode, string(errorBody))
	}

	var result IssuerApiResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode issuer API response: %w", err)
	}

	if result.Attestation == "" {
		return nil, fmt.Errorf("issuer API response missing attestation field")
	}

	return &result, nil
}

// ============================================================================
// === END OF CORE FUNCTIONS ===
// ============================================================================

// generateErrorID creates an 8-character hex error reference for log correlation.
// Matches the crypto.randomUUID().slice(0, 8) pattern used by Node.js and CF Workers.
func generateErrorID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// healthHandler returns the service health status.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"mode":   "hmac-authenticated",
	}); err != nil {
		log.Printf("Failed to encode health response: %v", err)
	}
}

// configHandler returns current configuration state for debugging. Does not expose secrets.
func configHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"has_client_id":   config.ClientId != "",
		"hmac_configured": config.HmacSecret != "",
		"issuer_api_url":  config.IssuerApiUrl,
		"mode":            "hmac-authenticated",
	}); err != nil {
		log.Printf("Failed to encode config response: %v", err)
	}
}

// createAttestationHandler creates a signed attestation from DOB days.
func createAttestationHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB

	var req CreateAttestationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON in request body"}`, http.StatusBadRequest)
		return
	}

	dobDays := req.DobDays

	if dobDays < -25000 || dobDays > 36500 {
		http.Error(w, `{"error":"Invalid dob_days: must be between -25000 and 36500"}`, http.StatusBadRequest)
		return
	}

	result, err := createAttestation(dobDays)
	if err != nil {
		errorID := generateErrorID()
		log.Printf("[%s] Attestation creation failed: %v", errorID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"error":     "Failed to create attestation",
			"code":      "ATTESTATION_FAILED",
			"reference": errorID,
		}); err != nil {
			log.Printf("Failed to encode error response: %v", err)
		}
		return
	}

	deepLink := "https://provii.app/attest?d=" + result.Attestation

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(CreateAttestationResponse{
		DeepLink:  deepLink,
		ExpiresAt: result.ExpiresAt,
	}); err != nil {
		log.Printf("Failed to encode attestation response: %v", err)
	}
}

// createAttestationFromDobHandler creates a signed attestation from a YYYY-MM-DD date string.
func createAttestationFromDobHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB

	var req struct {
		Dob string `json:"dob"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON in request body"}`, http.StatusBadRequest)
		return
	}

	if req.Dob == "" || len(req.Dob) != 10 {
		http.Error(w, `{"error":"Invalid dob: must be in YYYY-MM-DD format"}`, http.StatusBadRequest)
		return
	}

	dobDate, err := time.Parse("2006-01-02", req.Dob)
	if err != nil {
		http.Error(w, `{"error":"Invalid dob: must be in YYYY-MM-DD format"}`, http.StatusBadRequest)
		return
	}

	// Floor division for negative Unix timestamps: Go integer division truncates
	// toward zero, but we need to round down to match JavaScript's Math.floor.
	unixSecs := dobDate.Unix()
	dobDays := int(unixSecs / 86400)
	if unixSecs < 0 && unixSecs%86400 != 0 {
		dobDays--
	}

	if dobDays < -25000 || dobDays > 36500 {
		http.Error(w, `{"error":"Invalid date: must be between 1970 and 2070"}`, http.StatusBadRequest)
		return
	}

	result, err := createAttestation(dobDays)
	if err != nil {
		errorID := generateErrorID()
		log.Printf("[%s] Attestation creation failed: %v", errorID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"error":     "Failed to create attestation",
			"code":      "ATTESTATION_FAILED",
			"reference": errorID,
		}); err != nil {
			log.Printf("Failed to encode error response: %v", err)
		}
		return
	}

	deepLink := "https://provii.app/attest?d=" + result.Attestation

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(CreateAttestationResponse{
		DeepLink:  deepLink,
		DobDays:   dobDays,
		ExpiresAt: result.ExpiresAt,
	}); err != nil {
		log.Printf("Failed to encode attestation response: %v", err)
	}
}

// parseAllowedOrigins splits a comma-separated string of origins into a lookup map.
func parseAllowedOrigins(originsStr string) map[string]bool {
	origins := make(map[string]bool)
	for _, origin := range strings.Split(originsStr, ",") {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			origins[origin] = true
		}
	}
	return origins
}

// corsMiddleware sets CORS headers based on the configured origin allowlist.
// Origins not in the allowlist receive no CORS headers, causing the browser to block the request.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if origin != "" && config.AllowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Demo-Token")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds standard security headers to all responses.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.IsProduction {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// Demo Token Validation
//
// The X-Demo-Token header guards the publicly-deployed CF Worker
// (issuer-demo.provii.app) against unauthorised use of shared sandbox
// credentials. The signing secret lives in Cloudflare's Secrets Store and is
// only available to the deployed Worker.
//
// For a local Go backend on localhost, the dev controls both sides of the
// request, so there is no security boundary to enforce. When DEMO_TOKEN_SECRET
// is unset (the default for `go run main.go`), token validation is skipped.
// Setting DEMO_TOKEN_SECRET re-enables validation, which is what the production
// CF Worker code path does via its Secrets Store binding.
// Token format: demo_token_v1_<YYYYMMDD>_<16-char-hmac>
// ============================================================================

var demoTokenSecret = os.Getenv("DEMO_TOKEN_SECRET")
var demoTokenValidationEnabled = demoTokenSecret != ""

// validateDemoToken validates a demo access token against the expected HMAC signature.
//
// SECURITY: Uses hmac.Equal for constant-time comparison of the provided
// signature against the expected value.
//
// Caller MUST gate this on demoTokenValidationEnabled. The function assumes
// demoTokenSecret is set.
//
// Accepts tokens dated today or yesterday to account for timezone differences.
func validateDemoToken(token string) bool {
	if !strings.HasPrefix(token, "demo_token_v1_") {
		return false
	}

	// Split: ["demo", "token", "v1", date, sig]
	parts := strings.Split(token, "_")
	if len(parts) != 5 {
		return false
	}

	dateStr := parts[3]
	providedSig := parts[4]

	// 48-hour acceptance window covers UTC day boundary edge cases
	today := time.Now().UTC().Format("20060102")
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("20060102")

	if dateStr != today && dateStr != yesterday {
		return false
	}

	// SECURITY: Compute expected HMAC-SHA256 signature
	h := hmac.New(sha256.New, []byte(demoTokenSecret))
	h.Write([]byte("provii-demos-v1:" + dateStr))
	expectedSig := hex.EncodeToString(h.Sum(nil))[:16]

	// SECURITY: Constant-time comparison to prevent timing side-channel attacks
	return hmac.Equal([]byte(providedSig), []byte(expectedSig))
}

// demoTokenMiddleware enforces demo token validation on all /api/* routes.
// Pass-through when demoTokenSecret is unset (local dev mode).
func demoTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
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

// loadConfig builds the Config from environment variables.
func loadConfig() Config {
	allowedOriginsStr := getEnv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173")
	return Config{
		ClientId:       getEnv("CLIENT_ID", ""),
		HmacSecret:     getEnv("HMAC_SECRET", ""),
		IssuerApiUrl:   getEnv("ISSUER_API_URL", ""),
		Port:           getEnv("PORT", "3000"),
		AllowedOrigins: parseAllowedOrigins(allowedOriginsStr),
		IsProduction:   getEnv("GO_ENV", "") == "production",
	}
}

// requireCredentials returns an error if any required credential is missing.
func requireCredentials(c Config) error {
	if c.ClientId == "" || c.HmacSecret == "" || c.IssuerApiUrl == "" {
		return fmt.Errorf("missing required environment variables: CLIENT_ID, HMAC_SECRET, ISSUER_API_URL")
	}
	return nil
}

// newRouter creates and configures the chi router with all routes and middleware.
// Extracted from main() for testability.
func newRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(corsMiddleware)
	r.Use(securityHeadersMiddleware)
	r.Use(demoTokenMiddleware)

	r.Get("/health", healthHandler)
	r.Get("/api/config", configHandler)
	r.Post("/api/create-attestation", createAttestationHandler)
	r.Post("/api/create-attestation-from-dob", createAttestationFromDobHandler)

	return r
}

// printBanner prints the startup banner with configuration details.
func printBanner(c Config) {
	fmt.Println("")
	fmt.Println("=== Provii Issuer Demo Backend (Go) ===")
	fmt.Println("Mode: HMAC-SHA256 Authenticated (Provii Signs Attestation)")
	fmt.Printf("Port: %s\n", c.Port)
	fmt.Printf("Client ID: %s\n", c.ClientId)
	fmt.Printf("HMAC Secret Configured: %t\n", c.HmacSecret != "")
	fmt.Printf("Issuer API URL: %s\n", c.IssuerApiUrl)
	if demoTokenValidationEnabled {
		fmt.Println("Demo token validation: ENABLED (DEMO_TOKEN_SECRET is set)")
	} else {
		fmt.Println("Demo token validation: DISABLED (local dev mode, DEMO_TOKEN_SECRET unset).")
		fmt.Println("  Bind DEMO_TOKEN_SECRET via env injection for production.")
	}
	fmt.Println("")
	fmt.Println("Test with:")
	fmt.Printf("  curl -X POST http://localhost:%s/api/create-attestation \\\n", c.Port)
	fmt.Println("    -H \"Content-Type: application/json\" \\")
	fmt.Println("    -d '{\"dob_days\": 7000}'")
	fmt.Println("")
	fmt.Println("Or with a date:")
	fmt.Printf("  curl -X POST http://localhost:%s/api/create-attestation-from-dob \\\n", c.Port)
	fmt.Println("    -H \"Content-Type: application/json\" \\")
	fmt.Println("    -d '{\"dob\": \"1990-05-15\"}'")
	fmt.Println("")

	if c.HmacSecret == "" {
		fmt.Println("WARNING: HMAC_SECRET not set!")
		fmt.Println("Set it via environment variable or the request will fail.")
		fmt.Println("Get credentials from the Provii admin portal.")
		fmt.Println("")
	}
}

// parsePort converts the port string to an integer, exiting on failure.
func parsePort(portStr string) int {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("Invalid port number '%s': %v", portStr, err)
	}
	return port
}

func main() {
	config = loadConfig()

	if err := requireCredentials(config); err != nil {
		log.Println("FATAL: missing required environment variables.")
		log.Println("Set CLIENT_ID, HMAC_SECRET, and ISSUER_API_URL before starting.")
		log.Println("Mint sandbox credentials at https://admin.provii.app")
		log.Println("See backends/issuer/go/README.md for the setup walkthrough.")
		os.Exit(1)
	}

	r := newRouter()
	printBanner(config)
	port := parsePort(config.Port)

	// Server timeouts prevent resource exhaustion from slow or idle connections
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
