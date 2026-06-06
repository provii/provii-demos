# Integration Tests, Getting Started

## Setup

```bash
cd integration-tests
npm install
```

## Run All Tests

```bash
npm test
```

Tests will run against default local endpoints.

## Running Specific Test Suites

### E2E Verification Flow
```bash
npm run test:e2e
```
Tests the complete verification flow from onboarding through redemption.

### Authentication Consistency
```bash
npm run test:auth
```
Validates HMAC generation, canonical message formatting, and constant-time comparison.

### Crypto Consistency
```bash
npm run test:crypto
```
Tests PKCE, nonce generation, AES-256-GCM encryption, and cross-implementation compatibility.

### Session Management
```bash
npm run test:session
```
Validates session lifecycle, binding, timeouts, and security.

### Credit Management
```bash
npm run test:credit
```
Tests credit deduction, balance synchronisation, and provisioning.

## Testing Against Sandbox

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

## Watch Mode (Development)

Run tests in watch mode for rapid development:

```bash
npm run test:watch
```

Tests will re-run automatically when you save changes.

## Coverage Report

```bash
npm run test:coverage
```

Coverage report will be available in console output (text), `coverage/index.html` (HTML report), and `coverage/coverage-final.json` (JSON report).

## Interpreting Results

### Successful Test Run
```
integration/e2e_verification_flow.test.ts (20)
integration/authentication_consistency.test.ts (30)
integration/crypto_consistency.test.ts (35)
integration/session_management.test.ts (25)
integration/credit_management.test.ts (25)

Test Files  5 passed (5)
     Tests  135 passed (135)
  Start at  10:00:00
  Duration  45.23s
```

### Partial Implementation
Some tests may show warnings if services are partially implemented. `404` responses indicate endpoint not yet implemented. Tests gracefully handle missing features. Check console output for details.

### Test Failures
If tests fail, check the error message for specific failure, verify service endpoints are accessible, ensure credentials are correct, and check test environment configuration.

## Common Commands

| Command | Description |
|---------|-------------|
| `npm test` | Run all tests once |
| `npm run test:watch` | Run tests in watch mode |
| `npm run test:e2e` | Run E2E tests only |
| `npm run test:auth` | Run auth tests only |
| `npm run test:crypto` | Run crypto tests only |
| `npm run test:session` | Run session tests only |
| `npm run test:credit` | Run credit tests only |
| `npm run test:coverage` | Run with coverage |
| `npm run test:sandbox` | Run against sandbox |
| `npm run typecheck` | Type check without running |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VERIFIER_PORTAL_URL` | `http://localhost:8787` | Verifier portal endpoint |
| `HOSTED_BACKEND_URL` | `http://localhost:8788` | Hosted backend endpoint |
| `ISSUER_API_URL` | `http://localhost:8789` | Issuer service endpoint |
| `CREDIT_MANAGEMENT_URL` | `http://localhost:8790` | Credit management endpoint |
| `VERIFIER_API_URL` | `http://localhost:8791` | Verifier API endpoint |

## Troubleshooting

### Tests timing out
Increase timeout in `vitest.config.ts`:
```typescript
testTimeout: 60000, // 60 seconds
```

### Services not responding
Check services are running, verify endpoint URLs, check network connectivity, review service logs.

### Authentication failures
Verify customer credentials in `mock-data.ts`, check secret keys match environment, ensure public keys are registered.

### All tests showing 404
Services may not be fully implemented yet. Tests are designed to handle this gracefully.
