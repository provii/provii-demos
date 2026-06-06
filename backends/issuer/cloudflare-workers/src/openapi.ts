// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * OpenAPI specification generator for the Cloudflare Workers issuer backend.
 *
 * Outputs a JSON OpenAPI 3.0.3 document to stdout. JSON schemas are defined
 * inline and match the actual request/response types used by the API.
 *
 * Usage: `npx tsx src/openapi.ts > openapi.json`
 */

const CreateAttestationRequest = {
  type: 'object',
  properties: {
    dob_days: {
      type: 'integer',
      minimum: -25000,
      maximum: 36500,
      description: 'Date of birth as days since Unix epoch (1970-01-01)',
    },
  },
  required: ['dob_days'],
  description: 'Request to create attestation from DOB days',
};

const CreateAttestationFromDobRequest = {
  type: 'object',
  properties: {
    dob: {
      type: 'string',
      pattern: '^\\d{4}-\\d{2}-\\d{2}$',
      description: 'Date of birth in YYYY-MM-DD format',
    },
  },
  required: ['dob'],
  description: 'Request to create attestation from DOB string',
};

const AttestationResponse = {
  type: 'object',
  properties: {
    deep_link: { type: 'string', description: 'Deep link URL to open Provii Wallet (https://provii.app/attest?d=...)' },
    dob_days: { type: 'integer', description: 'DOB in days (included when using /create-attestation-from-dob)' },
    expires_at: { type: 'integer', description: 'Unix timestamp when attestation expires' },
  },
  required: ['deep_link', 'expires_at'],
  description: 'Response containing the deep link and expiry',
};

const ErrorResponse = {
  type: 'object',
  properties: {
    error: { type: 'string', description: 'Human-readable error message' },
    code: { type: 'string', description: 'Machine-readable error code' },
    reference: { type: 'string', description: 'Error reference identifier for support enquiries' },
  },
  required: ['error'],
  description: 'Error response',
};

const HealthResponse = {
  type: 'object',
  properties: {
    status: { type: 'string', enum: ['ok'] },
    mode: { type: 'string', enum: ['hmac-authenticated'] },
    runtime: { type: 'string', enum: ['cloudflare-workers'] },
  },
  required: ['status', 'mode', 'runtime'],
  description: 'Health check response',
};

const ConfigResponse = {
  type: 'object',
  properties: {
    has_client_id: { type: 'boolean', description: 'Whether the issuer client identifier is configured' },
    hmac_configured: { type: 'boolean', description: 'Whether the HMAC secret is configured' },
    issuer_api_url: { type: 'string', description: 'Provii provii-issuer base URL' },
    mode: { type: 'string', enum: ['hmac-authenticated'] },
    runtime: { type: 'string', enum: ['cloudflare-workers'] },
  },
  required: ['has_client_id', 'hmac_configured', 'issuer_api_url', 'mode', 'runtime'],
  description: 'Current configuration state (secrets are not exposed)',
};

const openApiSpec = {
  openapi: '3.0.3',
  info: {
    title: 'Provii Issuer Backend API (Cloudflare Workers)',
    version: '1.0.0',
    description: `Third-party issuer backend API for creating signed attestations via Provii's provii-issuer.

This is the API contract that issuers implement to integrate with Provii Wallet.
This variant runs on Cloudflare Workers at issuer-demo.provii.app.

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
    contact: {
      name: 'Provii Support',
      url: 'https://provii.app',
    },
  },
  servers: [
    { url: 'https://issuer-demo.provii.app', description: 'Production' },
    { url: 'https://sandbox-issuer-demo.provii.app', description: 'Sandbox' },
    { url: 'http://localhost:8787', description: 'Local development' },
  ],
  tags: [
    { name: 'Attestation', description: 'Create attestations for credential issuance' },
    { name: 'System', description: 'Health and configuration endpoints' },
  ],
  paths: {
    '/api/create-attestation': {
      post: {
        summary: 'Create attestation from DOB days',
        description: 'Create an attestation using days since Unix epoch. Authenticates with Provii\'s provii-issuer using HMAC-SHA256.',
        operationId: 'createAttestation',
        tags: ['Attestation'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CreateAttestationRequest' },
              example: { dob_days: 7305 },
            },
          },
        },
        responses: {
          '200': {
            description: 'Attestation created successfully',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AttestationResponse' },
              },
            },
          },
          '400': {
            description: 'Invalid request',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ErrorResponse' },
              },
            },
          },
          '500': {
            description: 'Server error',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ErrorResponse' },
              },
            },
          },
        },
      },
    },
    '/api/create-attestation-from-dob': {
      post: {
        summary: 'Create attestation from DOB string',
        description: 'Create an attestation using a date string (YYYY-MM-DD format). Authenticates with Provii\'s provii-issuer using HMAC-SHA256.',
        operationId: 'createAttestationFromDob',
        tags: ['Attestation'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CreateAttestationFromDobRequest' },
              example: { dob: '1990-05-15' },
            },
          },
        },
        responses: {
          '200': {
            description: 'Attestation created successfully',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AttestationResponse' },
              },
            },
          },
          '400': {
            description: 'Invalid request',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ErrorResponse' },
              },
            },
          },
          '500': {
            description: 'Server error',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ErrorResponse' },
              },
            },
          },
        },
      },
    },
    '/health': {
      get: {
        summary: 'Health check',
        description: 'Returns health status of the service.',
        operationId: 'healthCheck',
        tags: ['System'],
        responses: {
          '200': {
            description: 'Service is healthy',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/HealthResponse' },
              },
            },
          },
        },
      },
    },
    '/api/config': {
      get: {
        summary: 'Get configuration',
        description: 'Returns current configuration state for debugging. Secrets are never exposed.',
        operationId: 'getConfig',
        tags: ['System'],
        responses: {
          '200': {
            description: 'Configuration info',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ConfigResponse' },
              },
            },
          },
        },
      },
    },
  },
  components: {
    schemas: {
      CreateAttestationRequest,
      CreateAttestationFromDobRequest,
      AttestationResponse,
      ErrorResponse,
      HealthResponse,
      ConfigResponse,
    },
  },
};

console.log(JSON.stringify(openApiSpec, null, 2));
