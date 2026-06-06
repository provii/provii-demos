# Provii Integration Tests

Cross-service integration tests for end-to-end verification flows across all Provii services.

## Overview

This test suite validates the complete verification flow including:

- Customer onboarding
- Challenge creation
- Status polling
- PKCE redemption
- Authentication consistency
- Cryptographic implementations
- Session management
- Credit management

## Test Structure

```
integration-tests/
├── integration/
│   ├── e2e_verification_flow.test.ts        # End-to-end verification tests
│   ├── authentication_consistency.test.ts   # HMAC and auth validation
│   ├── crypto_consistency.test.ts           # PKCE, nonce, encryption tests
│   ├── session_management.test.ts           # Session lifecycle tests
│   └── credit_management.test.ts            # Credit deduction tests
│
├── utils/
│   ├── test-client.ts                       # HTTP client with auth helpers
│   ├── mock-data.ts                         # Test fixtures and data
│   └── assertions.ts                        # Custom assertions
│
├── package.json                              # Test dependencies
└── README.md                                 # This file
```

## Installation

```bash
cd integration-tests
npm install
```

## Running Tests

These tests require live service endpoints. They will not pass against a cold environment.

Run all tests:
```bash
npm test
```

Run in watch mode (useful during development):
```bash
npm run test:watch
```

Run specific test suites:
```bash
npm run test:e2e         # E2E verification flow
npm run test:auth        # Authentication consistency
npm run test:crypto      # Crypto consistency
npm run test:session     # Session management
npm run test:credit      # Credit management
```

Run with coverage:
```bash
npm run test:coverage
```

### Running Against Sandbox

To run tests against the sandbox environment:

```bash
npm run test:sandbox
```

Or set environment variables manually:

```bash
export VERIFIER_PORTAL_URL=https://sandbox-verify.provii.app
export HOSTED_BACKEND_URL=https://sandbox-verify.provii.app
export ISSUER_API_URL=https://sandbox-issuer.provii.app
export CREDIT_MANAGEMENT_URL=https://sandbox-credit.provii.app
export VERIFIER_API_URL=https://sandbox-verify.provii.app

npm test
```

## Test Coverage

### E2E Verification Flow (4 test groups, ~20 tests)

Customer onboarding: create account in verifier portal, generate provii-verifier key pair, verify key registration, verify credits provisioned.

Challenge creation: create challenge via provii-verifier, verify challenge created in provii-issuer, verify credit deduction, verify session stored with binding.

Status polling: poll status endpoint, verify provii-verifier integration, validate session binding.

PKCE redemption: redeem with code_verifier, verify redemption succeeds, verify session marked as verified, test replay protection.

### Authentication Consistency (~30 tests)

HMAC generation across services, canonical message formatting, constant-time comparison, public key authentication, session binding validation, error handling.

### Crypto Consistency (~35 tests)

PKCE challenge generation (RFC 7636), nonce generation, session token generation, AES-256-GCM encryption/decryption, base64 URL encoding, cross-implementation compatibility, timing attack prevention.

### Session Management (~25 tests)

Session creation with binding, session validation (IP/UA matching), idle timeout enforcement, absolute expiry enforcement, session extension logic, session encryption at rest, concurrent session handling, session security (cookies, flags).

### Credit Management (~25 tests)

Credit deduction on challenge creation, insufficient credit handling (402 errors), balance synchronisation, credit provisioning, reservation and release, usage analytics, low balance alerts.

## Test Data

Mock data is provided in `utils/mock-data.ts`:

- **Mock customers**: Alice (1000 credits), Bob (500 credits), Charlie (0 credits)
- **PKCE test vectors**: RFC 7636 compliant
- **HMAC test vectors**: For validation
- **Session fixtures**: Pre-configured sessions
- **Challenge fixtures**: Sample challenges

## Custom Assertions

Domain-specific assertions in `utils/assertions.ts`:

- `assertPkceMatch(verifier, challenge)` validates the PKCE relationship
- `assertValidHmacSignature(message, signature, key)` validates HMAC
- `assertConstantTimeEqual(a, b)` does timing-safe comparison
- `assertSessionBinding(session)` validates session binding
- `assertCreditsDeducted(before, after, expected)` validates credit deduction
- `assertAes256GcmEncryption(encrypted)` validates encryption format

## Test Client

The `TestClient` class provides:

- Automatic authentication (HMAC, public key, session)
- Request signing
- Cookie management
- Helper methods for common operations:
  - `loginVerifierPortal(customer_id, token)`
  - `createHostedChallenge(params)`
  - `checkHostedStatus(session_id)`
  - `redeemHostedSession(session_id, code_verifier)`
  - `getCreditBalance(customer_id)`

## Environment Variables

Configure test endpoints via environment variables:

```bash
VERIFIER_PORTAL_URL=http://localhost:8787
HOSTED_BACKEND_URL=http://localhost:8788
ISSUER_API_URL=http://localhost:8789
CREDIT_MANAGEMENT_URL=http://localhost:8790
VERIFIER_API_URL=http://localhost:8791
```

## Troubleshooting

### Tests failing due to missing services

If services are not fully implemented, tests are designed to gracefully handle 404 errors, partial implementations, and missing features. Tests will log warnings but continue execution.

### Authentication failures

Ensure test credentials match sandbox/local environment: customer IDs are correct, secret keys are valid, public keys are registered.

### Timeout issues

Increase timeout for slow endpoints:
```typescript
await client.waitFor(
  async () => await client.checkHostedStatus(sessionId),
  (result) => result.status === 'verified',
  { timeout: 60000 } // 60 seconds
);
```

## Licence

MIT
