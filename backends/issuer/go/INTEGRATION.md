# Go Issuer Backend Integration Guide

This guide shows how to add Provii credential issuance to your Go backend.

## Quick Start (5 minutes)

### Option 1: Copy the Core Functions

Copy the HMAC authentication logic from `main.go`:

```go
import (
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "net/http"
 "strings"
 "time"
)

// Configuration - set from environment or Provii admin portal
var (
 clientID = os.Getenv("CLIENT_ID")
 hmacSecret = os.Getenv("HMAC_SECRET") // base64url-encoded
 issuerAPIURL = os.Getenv("ISSUER_API_URL")
)

func base64urlDecode(s string) ([]byte, error) {
 return base64.RawURLEncoding.DecodeString(s)
}

func hmacSha256Hex(secret []byte, message string) string {
 mac := hmac.New(sha256.New, secret)
 mac.Write([]byte(message))
 return hex.EncodeToString(mac.Sum(nil))
}

// buildCanonicalMessage builds the canonical message for HMAC signing.
//
// Format: {timestamp}:POST:/v1/attestation/create:{canonical_json}:{nonce}
//
// The canonical JSON uses snake_case key_id (request body uses camelCase keyId).
// The nonce MUST match the authorizer.nonce sent in the request body.
func buildCanonicalMessage(dobDays int, clientID string, timestamp int64, nonce string) string {
 canonicalJSON := fmt.Sprintf(
 `{"dob_days":%d,"authorizer":{"format":"client","key_id":"%s","timestamp":%d}}`,
 dobDays, clientID, timestamp,
 )
 return fmt.Sprintf("%d:POST:/v1/attestation/create:%s:%s", timestamp, canonicalJSON, nonce)
}

type CreateAttestationResponse struct {
 Attestation string `json:"attestation"`
 ExpiresAt int64 `json:"expires_at"`
 IssuerID string `json:"issuer_id"`
}

func createAttestation(dobDays int) (*CreateAttestationResponse, error) {
 timestamp := time.Now.Unix

 // 256-bit random nonce. The SAME value goes into both the canonical message and the request body.
 nonceBytes := make([]byte, 32)
 if _, err := rand.Read(nonceBytes); err != nil {
 return nil, fmt.Errorf("failed to generate nonce: %w", err)
 }
 nonce := hex.EncodeToString(nonceBytes)

 canonicalMsg := buildCanonicalMessage(dobDays, clientID, timestamp, nonce)
 secretBytes, err := base64urlDecode(hmacSecret)
 if err != nil {
 return nil, fmt.Errorf("failed to decode HMAC secret: %w", err)
 }
 hmacHex := hmacSha256Hex(secretBytes, canonicalMsg)

 // Build request body (note: keyId is camelCase in the request)
 body := map[string]interface{}{
 "dob_days": dobDays,
 "authorizer": map[string]interface{}{
 "format": "client",
 "keyId": clientID,
 "timestamp": timestamp,
 "hmac": hmacHex,
 "nonce": nonce,
 },
 }

 bodyJSON, _ := json.Marshal(body)
 url := fmt.Sprintf("%s/v1/attestation/create", issuerAPIURL)

 resp, err := http.Post(url, "application/json", strings.NewReader(string(bodyJSON)))
 if err != nil {
 return nil, fmt.Errorf("failed to call issuer API: %w", err)
 }
 defer resp.Body.Close

 if resp.StatusCode != 200 {
 return nil, fmt.Errorf("issuer API returned status %d", resp.StatusCode)
 }

 var result CreateAttestationResponse
 if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
 return nil, fmt.Errorf("failed to decode response: %w", err)
 }

 return &result, nil
}
```

### Option 2: Use as Reference

Run this demo backend and study the flow:

```bash
cd backends/issuer/go
go run main.go
```

## Dependencies

No cryptographic dependencies are needed. HMAC-SHA256 is built into Go's standard library:

```go
import (
 "crypto/hmac"
 "crypto/sha256"
)
```

## API Endpoints

Your backend needs to expose:

| Endpoint | Method | Body | Response |
|----------|--------|------|----------|
| `/api/create-attestation-from-dob` | POST | `{ "dob": "1990-05-15" }` | `{ "deep_link": "https://provii.app/..." }` |
| `/api/create-attestation` | POST | `{ "dob_days": 7000 }` | `{ "deep_link": "https://provii.app/..." }` |

## Environment Variables

```bash
# Required - mint via the playground for sandbox, or via the admin portal for production
CLIENT_ID=your_client_id
HMAC_SECRET=base64url-encoded-hmac-secret
ISSUER_API_URL=https://issuer.provii.app

# Optional
PORT=3000
ALLOWED_ORIGINS=https://yourapp.com,https://admin.yourapp.com
```

## Flow Diagram

```
Mobile App Your Backend Provii provii-issuer
 │ │ │
 │ POST /create-attestation │ │
 │ { dob: "1990-05-15" } │ │
 │ ────────────────────────►│ │
 │ │ │
 │ │ 1. Convert DOB to days │
 │ │ 2. Build HMAC-SHA256 │
 │ │ canonical message │
 │ │ 3. POST to provii-issuer │
 │ │ ────────────────────────►│
 │ │ │
 │ │ Provii signs attestation│
 │ │ internally (Ed25519) │
 │ │ │
 │ │◄─────────────────────────│
 │ │ {attestation, expires_at}│
 │ │ │
 │◄─────────────────────────│ │
 │ { deep_link: "https://provii.app/attest?d=..." } │
 │ │ │
 │ Opens deep link │ │
 │ ─────────────────────────────────────────────────► │
 │ │ │
 │ │ Wallet generates │
 │ │ r_bits and calls │
 │ │ /v1/issuance/blind │
```

## HMAC Authentication Details

The canonical message format for `/v1/attestation/create`:

```
{timestamp}:POST:/v1/attestation/create:{"dob_days":{dob_days},"authorizer":{"format":"client","key_id":"{client_id}","timestamp":{timestamp}}}:{nonce}
```

**Important:**
- The canonical message uses `key_id` (snake_case). The actual HTTP request body uses `keyId` (camelCase).
- The trailing `{nonce}` is the SAME value sent as `authorizer.nonce` in the request body. Server-side verification recomputes the HMAC using the body's nonce, so the two MUST match. Omitting the nonce (or using a different one) returns 401 UNAUTHORIZED. See `create_canonical_message_for_attestation` in `provii-issuer/src/session.rs`.

## Chi Router Example (This Demo)

See `main.go` for a complete Chi implementation with:
- CORS middleware
- Request logging
- Input validation
- Server timeouts

## net/http Example

```go
package main

import (
 "encoding/json"
 "net/http"
 "time"
)

func main {
 http.HandleFunc("/api/create-attestation-from-dob", func(w http.ResponseWriter, r *http.Request) {
 if r.Method != http.MethodPost {
 http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
 return
 }

 var req struct {
 Dob string `json:"dob"`
 }
 if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
 http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
 return
 }

 dobDate, err := time.Parse("2006-01-02", req.Dob)
 if err != nil {
 http.Error(w, `{"error":"Invalid dob: must be in YYYY-MM-DD format"}`, http.StatusBadRequest)
 return
 }
 dobDays := int(dobDate.Unix / (24 * 60 * 60))
 if dobDays < -25000 || dobDays > 36500 {
 http.Error(w, `{"error":"Invalid date: out of valid range"}`, http.StatusBadRequest)
 return
 }

 result, err := createAttestation(dobDays)
 if err != nil {
 http.Error(w, `{"error":"Attestation failed"}`, http.StatusInternalServerError)
 return
 }

 w.Header.Set("Content-Type", "application/json")
 json.NewEncoder(w).Encode(map[string]interface{}{
 "deep_link": "https://provii.app/attest?d=" + result.Attestation,
 "expires_at": result.ExpiresAt,
 })
 })

 server := &http.Server{
 Addr: ":3000",
 ReadTimeout: 15 * time.Second,
 WriteTimeout: 15 * time.Second,
 }
 server.ListenAndServe
}
```

## Gin Example

```go
import "github.com/gin-gonic/gin"

func main {
 r := gin.Default

 r.POST("/api/create-attestation-from-dob", func(c *gin.Context) {
 var req struct {
 Dob string `json:"dob" binding:"required"`
 }
 if err := c.ShouldBindJSON(&req); err != nil {
 c.JSON(400, gin.H{"error": "Invalid request"})
 return
 }

 dobDate, err := time.Parse("2006-01-02", req.Dob)
 if err != nil {
 c.JSON(400, gin.H{"error": "Invalid dob: must be in YYYY-MM-DD format"})
 return
 }
 dobDays := int(dobDate.Unix / (24 * 60 * 60))
 if dobDays < -25000 || dobDays > 36500 {
 c.JSON(400, gin.H{"error": "Invalid date: out of valid range"})
 return
 }

 result, err := createAttestation(dobDays)
 if err != nil {
 c.JSON(500, gin.H{"error": "Attestation failed"})
 return
 }

 c.JSON(200, gin.H{
 "deep_link": "https://provii.app/attest?d=" + result.Attestation,
 "expires_at": result.ExpiresAt,
 })
 })

 r.Run(":3000")
}
```

## Security Considerations

1. **Never expose your HMAC secret** in client-side code or logs
2. **Use HTTPS in production** for all calls to Provii's provii-issuer
3. **Set server timeouts** to prevent resource exhaustion (see demo for example)
4. **Validate CORS origins** by setting `ALLOWED_ORIGINS` to your app domains only
5. **Don't log DOB values** on your backend

## Testing

1. Start the backend:
 ```bash
 go run main.go
 ```

2. Create an attestation:
 ```bash
 curl -X POST http://localhost:3000/api/create-attestation-from-dob \
 -H "Content-Type: application/json" \
 -d '{"dob": "1990-05-15"}'
 ```

3. The response contains a `deep_link` that opens Provii Wallet

## Sandbox Mode

For testing without production credentials:

1. Mint sandbox credentials from the playground UI. Visit https://playground.provii.app, switch to the "Set up an Issuing Party" tab, fill in the issuer label, click mint. Copy `client_id`, `hmac_secret`, `kid`, and `base_url` into your `.env`. The Issuer signs every attestation server-side; your backend authenticates with HMAC and never holds an Ed25519 signing key.

 ```bash
 # .env (do not commit)
 CLIENT_ID=cl_iss_sandbox_<your minted id>
 HMAC_SECRET=<your minted hmac secret>
 ISSUER_API_URL=https://sandbox-issuer.provii.app
 ```

 The credential expires in 72 hours. Mint a new one when it expires; the playground remembers it in localStorage.
2. Enable Sandbox Mode in Provii Wallet: Settings > tap 5 times > toggle Sandbox.

## Common Issues

### "HMAC_SECRET not configured"
Mint sandbox credentials from the playground (https://playground.provii.app, "Set up an Issuing Party" tab) and copy them into `.env`. For production, fetch credentials from the Provii admin portal.

### Attestation creation fails (4xx/5xx from provii-issuer)
Ensure:
- The canonical message format matches exactly (see `buildCanonicalMessage`)
- The canonical message ends with `:{nonce}` matching the body's `authorizer.nonce`. If you get 401 UNAUTHORIZED, this is the most common cause.
- `key_id` uses snake_case in canonical form, `keyId` uses camelCase in the request
- The HMAC secret is base64url-decoded before use as the HMAC key
- The timestamp is current (within ±30 seconds)

### Date parsing issues
Go's date format template is `"2006-01-02"` not `"YYYY-MM-DD"`.
