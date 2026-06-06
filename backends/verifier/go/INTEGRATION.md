# Go Verifier Backend Integration Guide

This guide shows how to add Provii age verification to your Go backend.

## Quick Start (5 minutes)

### Option 1: Copy the Core Module

Copy the verification logic from `main.go`:

```go
import (
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "math"
)

// Your credentials from Provii admin portal
var (
 VerifierAPIURL = os.Getenv("VERIFIER_API_URL")
 ClientID = os.Getenv("CLIENT_ID")
 APIKey = os.Getenv("API_KEY")
 HMACSecret = os.Getenv("HMAC_SECRET")
)

// In-memory sessions (use Redis/DB in production)
var sessions = make(map[string]*SessionData)

func createVerificationChallenge(minimumAge int) (*ChallengeResponse, error) {
 // Generate PKCE pair
 codeVerifier, err := generateCodeVerifier
 if err != nil {
 return nil, fmt.Errorf("failed to generate code verifier: %w", err)
 }
 codeChallenge := generateCodeChallenge(codeVerifier)

 // Create challenge with provii-verifier
 challenge, err := createChallengeWithAPI(codeChallenge, minimumAge, 300, "over_age")
 if err != nil {
 return nil, err
 }

 // Store code_verifier securely
 sessions[challenge.ChallengeID] = &SessionData{CodeVerifier: codeVerifier}

 return &ChallengeResponse{
 SessionID: challenge.ChallengeID,
 DeepLink: buildDeepLink(challenge),
 ExpiresAt: challenge.ExpiresAt,
 }, nil
}
```

### Option 2: Use as Reference

Run this demo backend and study the flow:

```bash
cd backends/verifier/go
go mod tidy
go run main.go
```

## Dependencies

```go
// go.mod
module verifier-demo

go 1.21

require github.com/go-chi/chi/v5 v5.0.0
```

No external crypto libraries needed - uses Go standard library.

## API Endpoints

Your backend needs to expose:

| Endpoint | Method | Body | Response |
|----------|--------|------|----------|
| `/api/create-challenge` | POST | `{ "minimum_age": 21 }` | `{ "session_id": "...", "deep_link": "https://provii.app/..." }` |
| `/api/status/:sessionId` | GET | - | `{ "state": "verified", "verified": true }` |
| `/api/redeem/:sessionId` | POST | - | `{ "result": "verified", "verified": true }` |

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
GO_ENV=production
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

```go
// Generate cryptographically secure code_verifier
func generateCodeVerifier (string, error) {
 bytes := make([]byte, 32)
 if _, err := rand.Read(bytes); err != nil {
 return "", err
 }
 return base64URLEncode(bytes), nil
}

// Generate code_challenge (SHA-256 hash of code_verifier)
func generateCodeChallenge(codeVerifier string) string {
 hash := sha256.Sum256([]byte(codeVerifier))
 return base64URLEncode(hash[:])
}

// Base64URL encoding without padding
func base64URLEncode(data []byte) string {
 return base64.RawURLEncoding.EncodeToString(data)
}

func base64URLDecode(s string) ([]byte, error) {
 return base64.RawURLEncoding.DecodeString(s)
}
```

### HMAC Authentication

```go
import (
 "crypto/rand"
 "encoding/hex"
)

// Create HMAC-SHA256 signature (hex-encoded)
func createHMACSignature(message, secretBase64URL string) (string, error) {
 secretBytes, err := base64URLDecode(secretBase64URL)
 if err != nil {
 return "", fmt.Errorf("failed to decode HMAC secret: %w", err)
 }

 h := hmac.New(sha256.New, secretBytes)
 h.Write([]byte(message))
 return hex.EncodeToString(h.Sum(nil)), nil
}

// IMPORTANT: Canonical payload does NOT include authorizer
// Field order: code_challenge, method, verifying_key_id, expires_in
// proof_direction is determined server-side from origin policy
type CanonicalPayload struct {
 CodeChallenge string `json:"code_challenge"`
 Method string `json:"method"`
 VerifyingKeyID *int `json:"verifying_key_id"` // nullable
 ExpiresIn int `json:"expires_in"`
}

// Canonical message format: 5 colon-separated fields including nonce
timestamp := time.Now.Unix
nonceBytes := make([]byte, 32)
if _, err := rand.Read(nonceBytes); err != nil {
 return fmt.Errorf("failed to generate nonce: %w", err)
}
nonce := hex.EncodeToString(nonceBytes)

canonicalPayload := CanonicalPayload{
 CodeChallenge: codeChallenge,
 Method: "S256",
 VerifyingKeyID: nil, // Must be present even if null
 ExpiresIn: expiresIn,
}

payloadBytes, _ := json.Marshal(canonicalPayload)
canonicalMessage := fmt.Sprintf("%d:POST:/v1/challenge:%s:%s", timestamp, string(payloadBytes), nonce)
hmacSig, _ := createHMACSignature(canonicalMessage, HMACSecret)

// Full payload includes authorizer with nonce for replay protection
fullPayload := ChallengePayload{
 CodeChallenge: codeChallenge,
 Method: "S256",
 RequestedCutoffDays: cutoffDays,
 ExpiresIn: expiresIn,
 Authorizer: Authorizer{
 KeyID: ClientID,
 Timestamp: timestamp,
 Nonce: nonce,
 HMAC: hmacSig,
 },
}
```

### Age to Cutoff Days

```go
// Convert minimum age to cutoff_days for the ZK proof
func ageToCutoffDays(minimumAge int) int {
 return int(math.Floor(float64(minimumAge) * 365.2425))
}
```

### Deep Link Construction

```go
func buildDeepLink(challenge *ChallengeAPIResponse) string {
 payload := map[string]interface{}{
 "challenge_id": challenge.ChallengeID,
 "rp_challenge": challenge.RPChallenge,
 "submit_secret": challenge.SubmitSecret,
 "cutoff_days": challenge.CutoffDays,
 "verifying_key_id": challenge.VerifyingKeyID,
 "verify_url": challenge.VerifyURL,
 "expires_at": challenge.ExpiresAt,
 }
 jsonBytes, _ := json.Marshal(payload)
 return "https://provii.app/verify?d=" + base64URLEncode(jsonBytes)
}
```

## Gin Framework Example

```go
package main

import (
 "github.com/gin-gonic/gin"
)

var sessions = make(map[string]*SessionData)

func main {
 r := gin.Default

 r.POST("/api/create-challenge", func(c *gin.Context) {
 var req struct {
 MinimumAge int `json:"minimum_age"`
 }
 if err := c.ShouldBindJSON(&req); err != nil {
 c.JSON(400, gin.H{"error": "Invalid request"})
 return
 }
 if req.MinimumAge == 0 {
 req.MinimumAge = 18
 }

 codeVerifier, err := generateCodeVerifier
 if err != nil {
 c.JSON(500, gin.H{"error": "Failed to generate code verifier"})
 return
 }
 codeChallenge := generateCodeChallenge(codeVerifier)
 challenge, err := createChallengeWithAPI(codeChallenge, req.MinimumAge, 300, "over_age")
 if err != nil {
 c.JSON(500, gin.H{"error": "Challenge creation failed"})
 return
 }

 sessions[challenge.ChallengeID] = &SessionData{CodeVerifier: codeVerifier}

 c.JSON(200, gin.H{
 "session_id": challenge.ChallengeID,
 "deep_link": buildDeepLink(challenge),
 "expires_at": challenge.ExpiresAt,
 })
 })

 r.GET("/api/status/:sessionId", func(c *gin.Context) {
 sessionID := c.Param("sessionId")
 session := sessions[sessionID]
 if session == nil {
 c.JSON(404, gin.H{"error": "Session not found"})
 return
 }

 status, err := pollChallengeStatus(sessionID)
 if err != nil {
 c.JSON(500, gin.H{"error": "Failed to check status"})
 return
 }
 c.JSON(200, status)
 })

 r.POST("/api/redeem/:sessionId", func(c *gin.Context) {
 sessionID := c.Param("sessionId")
 session := sessions[sessionID]
 if session == nil {
 c.JSON(404, gin.H{"error": "Session not found"})
 return
 }

 result, err := redeemChallenge(sessionID, session.CodeVerifier)
 if err != nil {
 c.JSON(500, gin.H{"error": "Failed to redeem challenge"})
 return
 }
 if result.Verified {
 delete(sessions, sessionID)
 }
 c.JSON(200, result)
 })

 r.Run(":3001")
}
```

## Chi Router Example (This Demo)

See `main.go` for a complete chi implementation with:
- CORS configuration
- Security headers
- Input validation
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

## Standard Library Example

```go
package main

import (
 "encoding/json"
 "net/http"
)

var sessions = make(map[string]*SessionData)

func main {
 http.HandleFunc("/api/create-challenge", createChallengeHandler)
 http.HandleFunc("/api/status/", getStatusHandler)
 http.HandleFunc("/api/redeem/", redeemHandler)
 http.ListenAndServe(":3001", nil)
}

func createChallengeHandler(w http.ResponseWriter, r *http.Request) {
 if r.Method != "POST" {
 http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
 return
 }

 var req struct {
 MinimumAge int `json:"minimum_age"`
 }
 json.NewDecoder(r.Body).Decode(&req)
 if req.MinimumAge == 0 {
 req.MinimumAge = 18
 }

 codeVerifier, err := generateCodeVerifier
 if err != nil {
 http.Error(w, `{"error":"Failed to generate code verifier"}`, http.StatusInternalServerError)
 return
 }
 codeChallenge := generateCodeChallenge(codeVerifier)
 challenge, err := createChallengeWithAPI(codeChallenge, req.MinimumAge, 300, "over_age")
 if err != nil {
 http.Error(w, `{"error":"Challenge creation failed"}`, http.StatusInternalServerError)
 return
 }

 sessions[challenge.ChallengeID] = &SessionData{CodeVerifier: codeVerifier}

 w.Header.Set("Content-Type", "application/json")
 json.NewEncoder(w).Encode(map[string]interface{}{
 "session_id": challenge.ChallengeID,
 "deep_link": buildDeepLink(challenge),
 "expires_at": challenge.ExpiresAt,
 })
}

func getStatusHandler(w http.ResponseWriter, r *http.Request) {
 sessionID := r.URL.Path[len("/api/status/"):]
 session := sessions[sessionID]
 if session == nil {
 http.Error(w, `{"error":"Session not found"}`, http.StatusNotFound)
 return
 }

 status, err := pollChallengeStatus(sessionID)
 if err != nil {
 http.Error(w, `{"error":"Failed to check status"}`, http.StatusInternalServerError)
 return
 }
 w.Header.Set("Content-Type", "application/json")
 json.NewEncoder(w).Encode(status)
}

func redeemHandler(w http.ResponseWriter, r *http.Request) {
 if r.Method != "POST" {
 http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
 return
 }

 sessionID := r.URL.Path[len("/api/redeem/"):]
 session := sessions[sessionID]
 if session == nil {
 http.Error(w, `{"error":"Session not found"}`, http.StatusNotFound)
 return
 }

 result, err := redeemChallenge(sessionID, session.CodeVerifier)
 if err != nil {
 http.Error(w, `{"error":"Failed to redeem challenge"}`, http.StatusInternalServerError)
 return
 }
 if result.Verified {
 delete(sessions, sessionID)
 }

 w.Header.Set("Content-Type", "application/json")
 json.NewEncoder(w).Encode(result)
}
```

## Security Considerations

| Rule | Detail |
|------|--------|
| Never expose HMAC_SECRET | Keep in secure environment variables |
| Never expose code_verifier | It must stay on your backend |
| Use HTTPS in production | The demo uses HTTP for local development only |
| Implement rate limiting | Protect against abuse |
| Use Redis/DB for sessions | In-memory storage is for demo only |
| Validate CORS origins | Set `AllowedOrigins` to your app domains only |
| Use sync.RWMutex | Protect session map in concurrent environments |

## Testing

1. Start the backend:
 ```bash
 go run main.go
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
- JSON marshaling produces consistent output (use same struct order)

### Session not found
Sessions are stored in-memory and lost on restart. Use Redis/DB in production.

### Race conditions
Use `sync.RWMutex` to protect the sessions map in concurrent environments.
