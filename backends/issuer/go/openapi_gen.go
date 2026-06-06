// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

//go:build ignore
// +build ignore

// OpenAPI specification generator for the Go issuer backend.
//
// Outputs a JSON OpenAPI 3.0.3 document to stdout. The spec matches the
// request/response types defined in main.go.
//
// Usage: go run openapi_gen.go > openapi.json

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
			"title":   "Provii Issuer Backend API",
			"version": "1.0.0",
			"description": `Third-party issuer backend API for creating signed attestations via Provii's provii-issuer.

This is the API contract that issuers implement to integrate with Provii Wallet.

## Issuance Flow
1. Your app calls POST /api/create-attestation-from-dob with the user's DOB
2. This backend authenticates with HMAC-SHA256 and calls Provii's provii-issuer
4. Provii signs the attestation internally and returns it
5. Returns a deep link (https://provii.app/attest?d=...)
6. Your app opens the deep link to launch Provii Wallet

## Authentication
This demo backend has no client-facing authentication. In production, protect
these endpoints with your own auth (API keys, OAuth, session tokens, etc.)
to ensure only your app can create attestations.
`,
			"contact": map[string]string{
				"name": "Provii Support",
				"url":  "https://provii.app",
			},
		},
		"servers": []map[string]string{
			{"url": "http://localhost:3000", "description": "Local development"},
			{"url": "https://your-issuer-backend.com", "description": "Production (replace with your URL)"},
		},
		"tags": []map[string]string{
			{"name": "Attestation", "description": "Create attestations for credential issuance"},
			{"name": "System", "description": "Health and configuration endpoints"},
		},
		"paths": map[string]interface{}{
			"/api/create-attestation": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Create attestation from DOB days",
					"description": "Create an attestation using days since Unix epoch. Authenticates with Provii's provii-issuer using HMAC-SHA256.",
					"operationId": "createAttestation",
					"tags":        []string{"Attestation"},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema":  map[string]string{"$ref": "#/components/schemas/CreateAttestationRequest"},
								"example": map[string]int{"dob_days": 7305},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Attestation created successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]string{"$ref": "#/components/schemas/AttestationResponse"},
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
			"/api/create-attestation-from-dob": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Create attestation from DOB string",
					"description": "Create an attestation using a date string (YYYY-MM-DD format). Authenticates with Provii's provii-issuer using HMAC-SHA256.",
					"operationId": "createAttestationFromDob",
					"tags":        []string{"Attestation"},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema":  map[string]string{"$ref": "#/components/schemas/CreateAttestationFromDobRequest"},
								"example": map[string]string{"dob": "1990-05-15"},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Attestation created successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]string{"$ref": "#/components/schemas/AttestationResponse"},
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
			"/health": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Health check",
					"description": "Returns health status of the service.",
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
					"description": "Returns current configuration state for debugging. Secrets are never exposed.",
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
				"CreateAttestationRequest": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"dob_days": map[string]interface{}{
							"type":        "integer",
							"minimum":     -25000,
							"maximum":     36500,
							"description": "Date of birth as days since Unix epoch (1970-01-01)",
						},
					},
					"required":    []string{"dob_days"},
					"description": "Request to create attestation from DOB days",
				},
				"CreateAttestationFromDobRequest": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"dob": map[string]interface{}{
							"type":        "string",
							"pattern":     `^\d{4}-\d{2}-\d{2}$`,
							"description": "Date of birth in YYYY-MM-DD format",
						},
					},
					"required":    []string{"dob"},
					"description": "Request to create attestation from DOB string",
				},
				"AttestationResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"deep_link":  map[string]interface{}{"type": "string", "description": "Deep link URL to open Provii Wallet (https://provii.app/attest?d=...)"},
						"dob_days":   map[string]interface{}{"type": "integer", "description": "DOB in days (included when using /create-attestation-from-dob)"},
						"expires_at": map[string]interface{}{"type": "integer", "description": "Unix timestamp when attestation expires"},
					},
					"required":    []string{"deep_link", "expires_at"},
					"description": "Response containing the deep link and expiry",
				},
				"ErrorResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"error": map[string]interface{}{"type": "string", "description": "Human-readable error message"},
						"code":  map[string]interface{}{"type": "string", "description": "Machine-readable error code"},
					},
					"required":    []string{"error"},
					"description": "Error response",
				},
				"HealthResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"status": map[string]interface{}{"type": "string", "enum": []string{"ok"}},
						"mode":   map[string]interface{}{"type": "string", "enum": []string{"hmac-authenticated"}},
					},
					"required":    []string{"status", "mode"},
					"description": "Health check response",
				},
				"ConfigResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"has_client_id":   map[string]interface{}{"type": "boolean", "description": "Whether the issuer client identifier is configured"},
						"hmac_configured": map[string]interface{}{"type": "boolean", "description": "Whether the HMAC secret is configured"},
						"issuer_api_url":  map[string]interface{}{"type": "string", "description": "Provii provii-issuer base URL"},
						"mode":            map[string]interface{}{"type": "string", "enum": []string{"hmac-authenticated"}},
					},
					"required":    []string{"has_client_id", "hmac_configured", "issuer_api_url", "mode"},
					"description": "Current configuration state (secrets are not exposed)",
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
