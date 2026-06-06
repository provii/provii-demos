/**
 * Custom Assertions for Integration Tests
 *
 * Provides domain-specific assertions for cryptographic validation,
 * session management, and API response validation.
 */

import { expect } from 'vitest';
import { createHash, timingSafeEqual, createHmac } from 'crypto';

/**
 * Assert that a PKCE code_verifier matches a code_challenge
 */
export function assertPkceMatch(verifier: string, challenge: string): void {
  const hash = createHash('sha256').update(verifier).digest();
  const computed = hash.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  expect(computed).toBe(challenge);
}

/**
 * Assert that a PKCE code_verifier has the correct format
 */
export function assertValidPkceVerifier(verifier: string): void {
  // RFC 7636: 43-128 characters, [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
  expect(verifier.length).toBeGreaterThanOrEqual(43);
  expect(verifier.length).toBeLessThanOrEqual(128);
  expect(verifier).toMatch(/^[A-Za-z0-9\-._~]+$/);
}

/**
 * Assert that a PKCE code_challenge has the correct format
 */
export function assertValidPkceChallenge(challenge: string): void {
  // SHA-256 hash base64url-encoded (43 characters, no padding)
  expect(challenge.length).toBe(43);
  expect(challenge).toMatch(/^[A-Za-z0-9\-_]+$/);
  expect(challenge).not.toContain('='); // No padding
}

/**
 * Assert that two values are equal using constant-time comparison
 */
export function assertConstantTimeEqual(a: string, b: string): void {
  const bufferA = Buffer.from(a, 'utf8');
  const bufferB = Buffer.from(b, 'utf8');

  if (bufferA.length !== bufferB.length) {
    throw new Error('Values have different lengths');
  }

  const isEqual = timingSafeEqual(bufferA, bufferB);
  expect(isEqual).toBe(true);
}

/**
 * Assert that an HMAC signature is valid
 */
export function assertValidHmacSignature(
  message: string,
  signature: string,
  secretKey: string
): void {
  const hmac = createHmac('sha256', secretKey);
  hmac.update(message);
  const expected = hmac.digest('hex');

  assertConstantTimeEqual(signature, expected);
}

/**
 * Assert that a nonce has the correct format (base64url, 32 bytes)
 */
export function assertValidNonce(nonce: string): void {
  expect(nonce).toMatch(/^[A-Za-z0-9\-_]+$/);
  expect(nonce).not.toContain('='); // No padding

  // Decode and check length
  const decoded = Buffer.from(
    nonce.replace(/-/g, '+').replace(/_/g, '/'),
    'base64'
  );
  expect(decoded.length).toBe(32);
}

/**
 * Assert that a session token has the correct format
 */
export function assertValidSessionToken(token: string): void {
  expect(token).toMatch(/^[A-Za-z0-9\-_]+$/);
  expect(token.length).toBeGreaterThan(32);
}

/**
 * Assert that a session has required binding properties
 */
export function assertSessionBinding(session: {
  binding?: { ip?: string; userAgent?: string };
}): void {
  expect(session.binding).toBeDefined();
  expect(session.binding?.ip).toBeDefined();
  expect(session.binding?.userAgent).toBeDefined();
  expect(session.binding?.ip).toMatch(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
  expect(session.binding?.userAgent?.length).toBeGreaterThan(0);
}

/**
 * Assert that a timestamp is within a reasonable range
 */
export function assertRecentTimestamp(
  timestamp: number,
  maxAgeSeconds: number = 60
): void {
  const now = Math.floor(Date.now() / 1000);
  const diff = Math.abs(now - timestamp);
  expect(diff).toBeLessThan(maxAgeSeconds);
}

/**
 * Assert that a timestamp is in the future
 */
export function assertFutureTimestamp(
  timestamp: number,
  minFutureSeconds: number = 0
): void {
  const now = Math.floor(Date.now() / 1000);
  expect(timestamp).toBeGreaterThan(now + minFutureSeconds);
}

/**
 * Assert that a session is expired
 */
export function assertSessionExpired(expiresAt: number): void {
  const now = Math.floor(Date.now() / 1000);
  expect(expiresAt).toBeLessThan(now);
}

/**
 * Assert that a session is not expired
 */
export function assertSessionNotExpired(expiresAt: number): void {
  const now = Math.floor(Date.now() / 1000);
  expect(expiresAt).toBeGreaterThan(now);
}

/**
 * Assert that an API response has the expected status code
 */
export function assertResponseStatus(
  response: Response,
  expectedStatus: number,
  context?: string
): void {
  if (response.status !== expectedStatus) {
    const message = context
      ? `Expected ${expectedStatus} but got ${response.status} (${context})`
      : `Expected ${expectedStatus} but got ${response.status}`;
    throw new Error(message);
  }
}

/**
 * Assert that an API response is successful (2xx)
 */
export function assertResponseOk(response: Response, context?: string): void {
  if (!response.ok) {
    const message = context
      ? `Expected successful response but got ${response.status} (${context})`
      : `Expected successful response but got ${response.status}`;
    throw new Error(message);
  }
}

/**
 * Assert that an API response is an error (4xx or 5xx)
 */
export function assertResponseError(response: Response, context?: string): void {
  if (response.ok) {
    const message = context
      ? `Expected error response but got ${response.status} (${context})`
      : `Expected error response but got ${response.status}`;
    throw new Error(message);
  }
}

/**
 * Assert that a credit balance is valid
 */
export function assertValidCreditBalance(balance: {
  balance_credits: number;
  reserved_credits: number;
  total_verifications?: number;
}): void {
  expect(balance.balance_credits).toBeGreaterThanOrEqual(0);
  expect(balance.reserved_credits).toBeGreaterThanOrEqual(0);
  if (balance.total_verifications !== undefined) {
    expect(balance.total_verifications).toBeGreaterThanOrEqual(0);
  }
}

/**
 * Assert that credits were deducted correctly
 */
export function assertCreditsDeducted(
  beforeBalance: number,
  afterBalance: number,
  expectedDeduction: number
): void {
  const actualDeduction = beforeBalance - afterBalance;
  expect(actualDeduction).toBe(expectedDeduction);
}

/**
 * Assert that a UUID is valid (v4)
 */
export function assertValidUuid(uuid: string): void {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  expect(uuid).toMatch(uuidRegex);
}

/**
 * Assert that a session ID has the expected format
 */
export function assertValidSessionId(sessionId: string): void {
  // Can be UUID or custom format (e.g., sess_abc123)
  if (sessionId.startsWith('sess_')) {
    expect(sessionId).toMatch(/^sess_[a-f0-9]{32}$/);
  } else {
    assertValidUuid(sessionId);
  }
}

/**
 * Assert that a challenge ID has the expected format
 */
export function assertValidChallengeId(challengeId: string): void {
  expect(challengeId).toMatch(/^chal_[a-f0-9]{32}$/);
}

/**
 * Assert that a QR code URL is valid
 */
export function assertValidQrCodeUrl(url: string): void {
  expect(url).toMatch(/^https?:\/\/.+/);
  expect(url).toContain('challenge');
}

/**
 * Assert that a challenge code has the expected format (e.g., "ABC-123-XYZ")
 */
export function assertValidChallengeCode(code: string): void {
  expect(code).toMatch(/^[A-Z0-9]{3}-[A-Z0-9]{3}-[A-Z0-9]{3}$/);
}

/**
 * Assert that encryption is using AES-256-GCM
 */
export function assertAes256GcmEncryption(encrypted: {
  ciphertext: string;
  iv: string;
  tag: string;
}): void {
  expect(encrypted.ciphertext).toBeDefined();
  expect(encrypted.iv).toBeDefined();
  expect(encrypted.tag).toBeDefined();

  // IV should be 12 bytes (96 bits) for GCM
  const ivBuffer = Buffer.from(encrypted.iv, 'base64');
  expect(ivBuffer.length).toBe(12);

  // Auth tag should be 16 bytes (128 bits)
  const tagBuffer = Buffer.from(encrypted.tag, 'base64');
  expect(tagBuffer.length).toBe(16);
}

/**
 * Assert that security headers are present
 */
export function assertSecurityHeaders(headers: Headers): void {
  expect(headers.get('Strict-Transport-Security')).toBeDefined();
  expect(headers.get('X-Content-Type-Options')).toBe('nosniff');
  expect(headers.get('X-Frame-Options')).toBe('DENY');
  expect(headers.get('Content-Security-Policy')).toBeDefined();
  expect(headers.get('X-XSS-Protection')).toBeDefined();
}

/**
 * Assert that CORS headers are present and valid
 */
export function assertCorsHeaders(headers: Headers, expectedOrigin: string): void {
  expect(headers.get('Access-Control-Allow-Origin')).toBe(expectedOrigin);
  expect(headers.get('Access-Control-Allow-Credentials')).toBe('true');
  expect(headers.get('Vary')).toContain('Origin');
}

/**
 * Measure and assert constant-time comparison (timing attack prevention)
 */
export async function assertConstantTimeComparison(
  fn: (input: string) => Promise<boolean>,
  validInput: string,
  invalidInput: string,
  maxTimingDifferenceMs: number = 5
): Promise<void> {
  const iterations = 100;
  const validTimings: number[] = [];
  const invalidTimings: number[] = [];

  for (let i = 0; i < iterations; i++) {
    const startValid = performance.now();
    await fn(validInput);
    validTimings.push(performance.now() - startValid);

    const startInvalid = performance.now();
    await fn(invalidInput);
    invalidTimings.push(performance.now() - startInvalid);
  }

  const avgValid = validTimings.reduce((a, b) => a + b, 0) / iterations;
  const avgInvalid = invalidTimings.reduce((a, b) => a + b, 0) / iterations;
  const difference = Math.abs(avgValid - avgInvalid);

  expect(difference).toBeLessThan(maxTimingDifferenceMs);
}

/**
 * Assert that entropy is sufficient for cryptographic values
 */
export function assertSufficientEntropy(value: string, minBits: number = 128): void {
  const buffer = Buffer.from(value, 'base64');
  const entropyBits = buffer.length * 8;
  expect(entropyBits).toBeGreaterThanOrEqual(minBits);
}

/**
 * Assert that a value is unique in a set
 */
export function assertUnique(values: string[]): void {
  const uniqueValues = new Set(values);
  expect(uniqueValues.size).toBe(values.length);
}
