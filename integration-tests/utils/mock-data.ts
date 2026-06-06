/**
 * Mock Data and Test Fixtures
 *
 * Provides reusable test data for integration tests including
 * keys, sessions, challenges, and crypto values.
 */

import { randomBytes, createHmac } from 'crypto';
import { createHash } from 'crypto';

/**
 * Generate a PKCE code_verifier (43-128 characters, base64url)
 */
export function generateCodeVerifier(): string {
  const bytes = randomBytes(32);
  return base64UrlEncode(bytes);
}

/**
 * Generate a PKCE code_challenge from a code_verifier
 */
export function generateCodeChallenge(verifier: string): string {
  const hash = createHash('sha256').update(verifier).digest();
  return base64UrlEncode(hash);
}

/**
 * Generate a cryptographically secure nonce
 */
export function generateNonce(): string {
  const bytes = randomBytes(32);
  return base64UrlEncode(bytes);
}

/**
 * Generate a session token
 */
export function generateSessionToken(): string {
  const bytes = randomBytes(32);
  return base64UrlEncode(bytes);
}

/**
 * Generate HMAC signature for authentication
 */
export function generateHmacSignature(
  secretKey: string,
  message: string
): string {
  const hmac = createHmac('sha256', secretKey);
  hmac.update(message);
  return hmac.digest('hex');
}

/**
 * Generate HMAC authentication token (customer_id:signature format)
 */
export function generateAuthToken(
  customer_id: string,
  secretKey: string
): string {
  const message = customer_id;
  const signature = generateHmacSignature(secretKey, message);
  return signature;
}

/**
 * Base64 URL encoding without padding
 */
function base64UrlEncode(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Mock customer data
 */
export const mockCustomers = {
  alice: {
    customer_id: 'cust_alice_123',
    secretKey: 'sk_alice_secret_key_for_testing_12345678',
    publicKey: 'pk_alice_public_key_for_testing',
    user_id: 'user_alice_456',
    email: 'alice@example.com',
    organization: 'Alice Corp',
    allowed_origins: ['https://alice.example.com', 'https://app.alice.com'],
    credits: 1000,
  },
  bob: {
    customer_id: 'cust_bob_789',
    secretKey: 'sk_bob_secret_key_for_testing_87654321',
    publicKey: 'pk_bob_public_key_for_testing',
    user_id: 'user_bob_101',
    email: 'bob@example.com',
    organization: 'Bob Industries',
    allowed_origins: ['https://bob.example.com'],
    credits: 500,
  },
  charlie: {
    customer_id: 'cust_charlie_999',
    secretKey: 'sk_charlie_secret_key_for_testing_99999',
    publicKey: 'pk_charlie_public_key_for_testing',
    user_id: 'user_charlie_202',
    email: 'charlie@example.com',
    organization: 'Charlie Enterprises',
    allowed_origins: ['https://charlie.example.com', 'http://localhost:3000'],
    credits: 0, // No credits for testing insufficient credit scenarios
  },
};

/**
 * Mock session data
 */
export interface MockSession {
  session_id: string;
  customer_id: string;
  public_key: string;
  origin: string;
  code_challenge: string;
  code_verifier: string;
  challenge_id: string;
  minimum_age: number;
  status: 'pending' | 'verified' | 'expired' | 'failed';
  created_at: number;
  expires_at: number;
  verified_at?: number;
  binding?: {
    ip: string;
    userAgent: string;
  };
}

/**
 * Create a mock session
 */
export function createMockSession(overrides?: Partial<MockSession>): MockSession {
  const code_verifier = generateCodeVerifier();
  const code_challenge = generateCodeChallenge(code_verifier);
  const now = Math.floor(Date.now() / 1000);

  return {
    session_id: `sess_${randomBytes(16).toString('hex')}`,
    customer_id: mockCustomers.alice.customer_id,
    public_key: mockCustomers.alice.publicKey,
    origin: 'https://alice.example.com',
    code_challenge,
    code_verifier,
    challenge_id: `chal_${randomBytes(16).toString('hex')}`,
    minimum_age: 18,
    status: 'pending',
    created_at: now,
    expires_at: now + 3600,
    ...overrides,
  };
}

/**
 * Mock challenge data
 */
export interface MockChallenge {
  challenge_id: string;
  qr_code_url: string;
  challenge_code: string;
  minimum_age: number;
  created_at: number;
  expires_at: number;
  status: 'pending' | 'completed' | 'expired';
}

/**
 * Create a mock challenge
 */
export function createMockChallenge(overrides?: Partial<MockChallenge>): MockChallenge {
  const now = Math.floor(Date.now() / 1000);
  const challenge_id = `chal_${randomBytes(16).toString('hex')}`;

  return {
    challenge_id,
    qr_code_url: `https://issuer.provii.app/challenge/${challenge_id}`,
    challenge_code: generateChallengeCode(),
    minimum_age: 18,
    created_at: now,
    expires_at: now + 3600,
    status: 'pending',
    ...overrides,
  };
}

/**
 * Generate a human-readable challenge code (e.g., "ABC-123-XYZ")
 */
function generateChallengeCode(): string {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  for (let i = 0; i < 9; i++) {
    if (i > 0 && i % 3 === 0) {
      code += '-';
    }
    const randomIndex = Math.floor(Math.random() * charset.length);
    code += charset[randomIndex];
  }
  return code;
}

/**
 * Mock public key configuration
 */
export interface MockPublicKeyConfig {
  public_key: string;
  secret_key: string;
  customer_id: string;
  allowed_origins: string[];
  active: boolean;
  rate_limit: {
    max_requests: number;
    window_seconds: number;
  };
  credits: number;
  enforce_credits: boolean;
  created_at: number;
}

/**
 * Create a mock public key configuration
 */
export function createMockPublicKeyConfig(
  overrides?: Partial<MockPublicKeyConfig>
): MockPublicKeyConfig {
  const now = Math.floor(Date.now() / 1000);

  return {
    public_key: `pk_test_${randomBytes(8).toString('hex')}`,
    secret_key: `sk_test_${randomBytes(16).toString('hex')}`,
    customer_id: `cust_${randomBytes(8).toString('hex')}`,
    allowed_origins: ['https://example.com'],
    active: true,
    rate_limit: {
      max_requests: 100,
      window_seconds: 60,
    },
    credits: 1000,
    enforce_credits: false,
    created_at: now,
    ...overrides,
  };
}

/**
 * Mock credit balance
 */
export interface MockCreditBalance {
  customer_id: string;
  balance_credits: number;
  reserved_credits: number;
  total_verifications: number;
  last_updated: number;
}

/**
 * Create a mock credit balance
 */
export function createMockCreditBalance(
  overrides?: Partial<MockCreditBalance>
): MockCreditBalance {
  const now = Math.floor(Date.now() / 1000);

  return {
    customer_id: mockCustomers.alice.customer_id,
    balance_credits: 1000,
    reserved_credits: 0,
    total_verifications: 0,
    last_updated: now,
    ...overrides,
  };
}

/**
 * Mock verification proof data
 */
export interface MockProof {
  proof_id: string;
  challenge_id: string;
  age: number;
  verified_at: number;
  issuer: string;
  signature: string;
}

/**
 * Create a mock verification proof
 */
export function createMockProof(overrides?: Partial<MockProof>): MockProof {
  const now = Math.floor(Date.now() / 1000);

  return {
    proof_id: `proof_${randomBytes(16).toString('hex')}`,
    challenge_id: `chal_${randomBytes(16).toString('hex')}`,
    age: 21,
    verified_at: now,
    issuer: 'issuer.provii.app',
    signature: randomBytes(64).toString('hex'),
    ...overrides,
  };
}

/**
 * Test vectors for crypto validation
 */
export const cryptoTestVectors = {
  // RFC 7636 PKCE test vector
  pkce: {
    verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  },
  // HMAC test vectors
  hmac: {
    key: 'test-secret-key-for-hmac-validation',
    message: 'test-message-to-sign',
    signature: createHmac('sha256', 'test-secret-key-for-hmac-validation')
      .update('test-message-to-sign')
      .digest('hex'),
  },
};

/**
 * Time helpers for tests
 */
export const timeHelpers = {
  now: () => Math.floor(Date.now() / 1000),
  nowMs: () => Date.now(),
  futureSeconds: (seconds: number) => Math.floor(Date.now() / 1000) + seconds,
  pastSeconds: (seconds: number) => Math.floor(Date.now() / 1000) - seconds,
  sleep: (ms: number) => new Promise(resolve => setTimeout(resolve, ms)),
};

/**
 * User agent strings for testing
 */
export const userAgents = {
  chrome: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  firefox: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
  safari: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
  mobile: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
};

/**
 * IP addresses for testing
 */
export const testIPs = {
  localhost: '127.0.0.1',
  privateNetwork: '192.168.1.100',
  publicIP1: '203.0.113.42',
  publicIP2: '198.51.100.100',
  cloudflare: '1.1.1.1',
};
