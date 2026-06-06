// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

//go:build ignore
// +build ignore

// OpenAPI 3.0.3 specification generator for the Provii Verifier Backend Demo.
//
// Run with: go run openapi_gen.go > openapi.json
//
// Outputs the specification as JSON to stdout. Pipe to a file to persist it.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	spec := map[string]interface{}{
		"openapi": "3.0.3",
		"info": map[string]interface{}{
			"title":   "Provii Verifier Backend API",
			"version": "1.0.0",
			"description": `Third-party verifier backend API for age verification using Provii Wallet.

This is the API contract that verifiers implement to integrate with Provii.
The backend handles PKCE generation, HMAC authentication with provii-verifier,
and secure code_verifier storage.

## Flow
1. Your mobile app calls POST /api/create-challenge
2. Your backend generates PKCE pair and authenticates to provii-verifier with HMAC
3. Your backend stores code_verifier securely and returns deep_link
4. Mobile app opens Provii Wallet with deep link
5. User verifies age in wallet (ZK proof submitted to provii-verifier)
6. Mobile app polls GET /api/status/:sessionId
7. When verified, mobile app calls POST /api/redeem/:sessionId
8. Your backend redeems with stored code_verifier

## Security
- Your backend never exposes HMAC_SECRET or code_verifier to clients
- All sensitive operations happen server-side
`,
			"contact": map[string]string{
				"name": "Provii Support",
				"url":  "https://provii.app",
			},
		},
		"servers": []map[string]string{
			{"url": "http://localhost:3001", "description": "Local development"},
			{"url": "https://your-verifier-backend.com", "description": "Production (replace with your URL)"},
		},
		"tags": []map[string]string{
			{"name": "Verification", "description": "Age verification challenge flow"},
			{"name": "System", "description": "Health and configuration endpoints"},
		},
		"paths": map[string]interface{}{
			"/api/create-challenge": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Create verification challenge",
					"description": "Creates a new age verification challenge. Returns a session ID and deep link URL for the user to complete verification in Provii Wallet.",
					"operationId": "createChallenge",
					"tags":        []string{"Verification"},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema":  map[string]string{"$ref": "#/components/schemas/CreateChallengeRequest"},
								"example": map[string]int{"minimum_age": 21},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Challenge created successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]string{"$ref": "#/components/schemas/CreateChallengeResponse"},
								},
							},
						},
						"400": map[string]interface{}{
							"description": "Invalid request",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]string{"$ref": "#/components/schemas/ErrorResponse"},
								},
							},
						},
						"500": map[string]interface{}{
							"description": "Server error",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]string{"$ref": "#/components/schemas/ErrorResponse"},
								},
							},
						},
					},
				},
			},
			"/api/status/{sessionId}": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Check verification status",
					"description": "Poll the status of a verification challenge. Returns the current state (pending, verified, expired).",
					"operationId": "getStatus",
					"tags":        []string{"Verification"},
					"parameters": []map[string]interface{}{
						{
							"name":        "sessionId",
							"in":          "path",
							"required":    true,
							"schema":      map[string]string{"type": "string"},
							"description": "Session ID from challenge creation",
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Current status",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]string{"$ref": "#/components/schemas/StatusResponse"},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "Session not found",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]string{"$ref": "#/components/schemas/ErrorResponse"},
								},
							},
						},
					},
				},
			},
			"/api/redeem/{sessionId}": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Redeem verified challenge",
					"description": "Complete the verification flow by redeeming with the stored code_verifier. Only callable after status shows 'verified'.",
					"operationId": "redeemChallenge",
					"tags":        []string{"Verification"},
					"parameters": []map[string]interface{}{
						{
							"name":        "sessionId",
							"in":          "path",
							"required":    true,
							"schema":      map[string]string{"type": "string"},
							"description": "Session ID from challenge creation",
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Redemption result",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]string{"$ref": "#/components/schemas/RedeemResponse"},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "Session not found",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]string{"$ref": "#/components/schemas/ErrorResponse"},
								},
							},
						},
						"500": map[string]interface{}{
							"description": "Redemption failed",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]string{"$ref": "#/components/schemas/ErrorResponse"},
								},
							},
						},
					},
				},
			},
			"/health": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Health check",
					"description": "Returns health status and configuration state.",
					"operationId": "healthCheck",
					"tags":        []string{"System"},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Service is healthy",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]string{"$ref": "#/components/schemas/HealthResponse"},
								},
							},
						},
					},
				},
			},
			"/api/config": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Get configuration",
					"description": "Returns current configuration (for debugging only, remove in production).",
					"operationId": "getConfig",
					"tags":        []string{"System"},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Configuration info",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]string{"$ref": "#/components/schemas/ConfigResponse"},
								},
							},
						},
					},
				},
			},
		},
		"components": map[string]interface{}{
			"schemas": map[string]interface{}{
				"CreateChallengeRequest": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"minimum_age": map[string]interface{}{
							"type":        "integer",
							"minimum":     13,
							"maximum":     120,
							"default":     18,
							"description": "Minimum age to verify (e.g., 18, 21)",
						},
						"expires_in": map[string]interface{}{
							"type":        "integer",
							"minimum":     60,
							"maximum":     300,
							"default":     300,
							"description": "Challenge expiration in seconds (server MAX_CHALLENGE_TTL is 300)",
						},
					},
					"description": "Request to create a verification challenge",
				},
				"CreateChallengeResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"session_id": map[string]interface{}{"type": "string", "description": "Unique session identifier for polling and redemption"},
						"deep_link":  map[string]interface{}{"type": "string", "description": "Deep link URL to open Provii Wallet (https://provii.app/verify?d=...)"},
						"expires_at": map[string]interface{}{"type": "integer", "description": "Unix timestamp when the challenge expires"},
						"status_url": map[string]interface{}{"type": "string", "description": "Relative URL to poll for status"},
					},
					"required":    []string{"session_id", "deep_link", "expires_at", "status_url"},
					"description": "Response containing session info and deep link",
				},
				"StatusResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"state":          map[string]interface{}{"type": "string", "enum": []string{"pending", "verified", "expired", "failed"}, "description": "Current state of the verification"},
						"verified":       map[string]interface{}{"type": "boolean", "description": "Whether age verification succeeded"},
						"proof_verified": map[string]interface{}{"type": "boolean", "description": "Whether the ZK proof was verified"},
					},
					"required":    []string{"state", "verified"},
					"description": "Current verification status",
				},
				"RedeemResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"result":   map[string]interface{}{"type": "string", "description": "Result of the redemption"},
						"verified": map[string]interface{}{"type": "boolean", "description": "Whether age was verified"},
					},
					"required":    []string{"result", "verified"},
					"description": "Redemption result",
				},
				"HealthResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"status":     map[string]interface{}{"type": "string", "enum": []string{"ok"}},
						"configured": map[string]interface{}{"type": "boolean", "description": "Whether credentials are configured"},
					},
					"required":    []string{"status", "configured"},
					"description": "Health check response",
				},
				"ConfigResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"verifier_api_url":       map[string]interface{}{"type": "string", "description": "Verifier API URL being used"},
						"client_id":              map[string]interface{}{"type": "string", "description": "Client ID (if configured)"},
						"api_key_configured":     map[string]interface{}{"type": "boolean", "description": "Whether API key is set"},
						"hmac_secret_configured": map[string]interface{}{"type": "boolean", "description": "Whether HMAC secret is set"},
					},
					"required":    []string{"verifier_api_url", "api_key_configured", "hmac_secret_configured"},
					"description": "Configuration info",
				},
				"ErrorResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"error":     map[string]interface{}{"type": "string", "description": "Error message"},
						"code":      map[string]interface{}{"type": "string", "description": "Error code"},
						"reference": map[string]interface{}{"type": "string", "description": "Error reference ID for debugging"},
					},
					"required":    []string{"error"},
					"description": "Error response",
				},
			},
		},
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(spec); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encode OpenAPI spec: %v\n", err)
		os.Exit(1)
	}
}
