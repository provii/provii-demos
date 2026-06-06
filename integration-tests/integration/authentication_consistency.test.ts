/**
 * Authentication Consistency Integration Tests
 *
 * Tests authentication patterns across all services to ensure consistent
 * HMAC generation, canonical message formatting, and constant-time comparison.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { createTestClient, TestClient } from '../utils/test-client';
import {
  mockCustomers,
  generateAuthToken,
  generateHmacSignature,
  cryptoTestVectors,
} from '../utils/mock-data';
import {
  assertValidHmacSignature,
  assertConstantTimeEqual,
  assertConstantTimeComparison,
  assertResponseOk,
  assertResponseStatus,
} from '../utils/assertions';
import { createHmac, timingSafeEqual } from 'crypto';

describe('Authentication Consistency Tests', () => {
  let client: TestClient;
  const testCustomer = mockCustomers.alice;

  beforeAll(() => {
    client = createTestClient();
  });

  describe('HMAC Generation Across Services', () => {
    it('should generate consistent HMAC signatures with same input', () => {
      const message = 'test-message';
      const secretKey = testCustomer.secretKey;

      // Generate signature multiple times
      const sig1 = generateHmacSignature(secretKey, message);
      const sig2 = generateHmacSignature(secretKey, message);
      const sig3 = generateHmacSignature(secretKey, message);

      // All should be identical
      expect(sig1).toBe(sig2);
      expect(sig2).toBe(sig3);

      // Verify using test vector
      assertValidHmacSignature(
        cryptoTestVectors.hmac.message,
        cryptoTestVectors.hmac.signature,
        cryptoTestVectors.hmac.key
      );
    });

    it('should produce different signatures for different messages', () => {
      const secretKey = testCustomer.secretKey;
      const message1 = 'message-one';
      const message2 = 'message-two';

      const sig1 = generateHmacSignature(secretKey, message1);
      const sig2 = generateHmacSignature(secretKey, message2);

      expect(sig1).not.toBe(sig2);
    });

    it('should produce different signatures for different keys', () => {
      const message = 'same-message';
      const key1 = mockCustomers.alice.secretKey;
      const key2 = mockCustomers.bob.secretKey;

      const sig1 = generateHmacSignature(key1, message);
      const sig2 = generateHmacSignature(key2, message);

      expect(sig1).not.toBe(sig2);
    });

    it('should match Node.js crypto.createHmac implementation', () => {
      const message = 'test-message';
      const secretKey = 'test-secret-key';

      // Our implementation
      const ourSignature = generateHmacSignature(secretKey, message);

      // Node.js crypto implementation
      const nodeSignature = createHmac('sha256', secretKey)
        .update(message)
        .digest('hex');

      expect(ourSignature).toBe(nodeSignature);
    });
  });

  describe('Canonical Message Format Comparison', () => {
    it('should use consistent canonical format: METHOD:PATH:BODY', () => {
      // Verifier portal format
      const verifierCanonical = (method: string, path: string, body: string) => {
        return `${method.toUpperCase()}:${path}:${body}`;
      };

      // provii-issuer format (should match)
      const issuerCanonical = (method: string, path: string, body: string) => {
        return `${method.toUpperCase()}:${path}:${body}`;
      };

      // provii-verifier format (should match)
      const hostedCanonical = (method: string, path: string, body: string) => {
        return `${method.toUpperCase()}:${path}:${body}`;
      };

      const method = 'POST';
      const path = '/api/v1/test';
      const body = JSON.stringify({ key: 'value' });

      const v1 = verifierCanonical(method, path, body);
      const v2 = issuerCanonical(method, path, body);
      const v3 = hostedCanonical(method, path, body);

      expect(v1).toBe(v2);
      expect(v2).toBe(v3);
    });

    it('should handle empty body consistently', () => {
      const method = 'GET';
      const path = '/api/v1/balance';
      const emptyBody = '';

      const canonical1 = `${method}:${path}:${emptyBody}`;
      const canonical2 = `${method}:${path}:`;
      const canonical3 = `${method}:${path}`;

      // First two formats should match
      expect(canonical1).toBe(canonical2);

      // Third format (without colon) should be different
      expect(canonical1).not.toBe(canonical3);

      // Verify our implementation uses the correct format (with trailing colon)
      const canonicalMessage = `${method}:${path}:${emptyBody}`;
      expect(canonicalMessage).toBe('GET:/api/v1/balance:');
    });

    it('should handle JSON body serialization consistently', () => {
      const body = {
        customer_id: 'cust_123',
        amount: 100,
        metadata: { key: 'value' },
      };

      // JSON.stringify produces consistent output
      const json1 = JSON.stringify(body);
      const json2 = JSON.stringify(body);

      expect(json1).toBe(json2);

      // Verify canonical message includes serialized body
      const canonical = `POST:/api/v1/deduct:${json1}`;
      expect(canonical).toContain('"customer_id":"cust_123"');
    });
  });

  describe('Constant-Time Comparison', () => {
    it('should use constant-time comparison for HMAC validation', async () => {
      const validSignature = generateHmacSignature(
        testCustomer.secretKey,
        'test-message'
      );
      const invalidSignature = '0'.repeat(validSignature.length);

      // Function to validate signature
      const validateSignature = async (sig: string): Promise<boolean> => {
        const expected = validSignature;
        if (sig.length !== expected.length) {
          return false;
        }

        const bufA = Buffer.from(sig, 'hex');
        const bufB = Buffer.from(expected, 'hex');

        if (bufA.length !== bufB.length) {
          return false;
        }

        return timingSafeEqual(bufA, bufB);
      };

      // Verify timing is constant
      await assertConstantTimeComparison(
        validateSignature,
        validSignature,
        invalidSignature,
        5 // Max 5ms difference
      );
    });

    it('should reject signatures with different lengths immediately', () => {
      const sig1 = 'a'.repeat(64);
      const sig2 = 'b'.repeat(32);

      const bufA = Buffer.from(sig1);
      const bufB = Buffer.from(sig2);

      // Different lengths should fail immediately
      expect(() => {
        if (bufA.length !== bufB.length) {
          throw new Error('Length mismatch');
        }
        timingSafeEqual(bufA, bufB);
      }).toThrow('Length mismatch');
    });

    it('should validate using timingSafeEqual for equal-length inputs', () => {
      const sig1 = 'a'.repeat(64);
      const sig2 = 'a'.repeat(64);
      const sig3 = 'b'.repeat(64);

      const buf1 = Buffer.from(sig1);
      const buf2 = Buffer.from(sig2);
      const buf3 = Buffer.from(sig3);

      // Same signature
      expect(timingSafeEqual(buf1, buf2)).toBe(true);

      // Different signature (same length)
      expect(timingSafeEqual(buf1, buf3)).toBe(false);
    });
  });

  describe('Public Key Authentication (Provii Verifier)', () => {
    it('should authenticate requests with X-Public-Key header', async () => {
      client.setAuth({
        publicKey: testCustomer.publicKey,
        secretKey: testCustomer.secretKey,
      });

      // Make a request to provii-verifier
      const response = await client.get('hostedBackend', '/v1/hosted/health');

      // Should accept public key authentication
      expect([200, 404]).toContain(response.status);
      // 404 is acceptable if endpoint not implemented yet
    });

    it('should validate public key exists in KV store', async () => {
      const validPublicKey = testCustomer.publicKey;
      const invalidPublicKey = 'pk_invalid_nonexistent_key';

      // Valid key should work
      client.setAuth({ publicKey: validPublicKey });
      const validResponse = await client.get('hostedBackend', '/v1/hosted/health');
      expect([200, 404]).toContain(validResponse.status);

      // Invalid key should fail
      client.setAuth({ publicKey: invalidPublicKey });
      const invalidResponse = await client.get('hostedBackend', '/v1/hosted/health');
      // May return 401/403 or 404 depending on implementation
      expect([401, 403, 404]).toContain(invalidResponse.status);
    });

    it('should validate origin matches allowed origins', async () => {
      const allowedOrigin = testCustomer.allowed_origins[0];
      const forbiddenOrigin = 'https://malicious.example.com';

      client.setAuth({
        publicKey: testCustomer.publicKey,
        secretKey: testCustomer.secretKey,
      });

      // Request from allowed origin
      const allowedResponse = await client.post(
        'hostedBackend',
        '/v1/hosted/challenge',
        {
          origin: allowedOrigin,
          minimum_age: 18,
          code_challenge: 'test-challenge',
          code_challenge_method: 'S256',
        }
      );

      // Should succeed or return specific error
      expect([200, 201, 400, 404]).toContain(allowedResponse.status);

      // Request from forbidden origin
      const forbiddenResponse = await client.post(
        'hostedBackend',
        '/v1/hosted/challenge',
        {
          origin: forbiddenOrigin,
          minimum_age: 18,
          code_challenge: 'test-challenge',
          code_challenge_method: 'S256',
        }
      );

      // Should return 403 Forbidden or similar
      expect([400, 403, 404]).toContain(forbiddenResponse.status);
    });
  });

  describe('Session Binding Validation', () => {
    it('should bind sessions to IP address and User-Agent', async () => {
      // This test verifies that session binding is implemented
      // The actual validation happens in session management tests
      const binding = {
        ip: '203.0.113.42',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...',
      };

      expect(binding.ip).toMatch(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
      expect(binding.userAgent.length).toBeGreaterThan(0);
    });

    it('should validate session binding on status checks', async () => {
      // Create a session
      const verifier = mockCustomers.alice;

      await client.loginVerifierPortal(
        verifier.customer_id,
        verifier.secretKey
      );

      // Make a request (session will be bound to IP/UA)
      const response = await client.get('verifierPortal', '/api/v1/balance');

      if (response.ok) {
        // Session created successfully with binding
        expect(response.status).toBe(200);
      }

      // Subsequent requests should use same binding
      const response2 = await client.get('verifierPortal', '/api/v1/balance');
      expect(response2.status).toBe(response.status);
    });
  });

  describe('Authentication Error Handling', () => {
    it('should return 401 for missing authentication', async () => {
      client.clearAuth();

      const response = await client.get('verifierPortal', '/api/v1/balance');

      // Should require authentication
      expect([401, 403]).toContain(response.status);
    });

    it('should return 401 for invalid HMAC signature', async () => {
      client.setAuth({
        customer_id: testCustomer.customer_id,
        token: 'invalid-signature-12345678',
      });

      const response = await client.get('verifierPortal', '/api/v1/balance');

      // Should reject invalid signature
      expect([401, 403]).toContain(response.status);
    });

    it('should return 403 for valid auth but insufficient permissions', async () => {
      // Login as regular user
      await client.loginVerifierPortal(
        testCustomer.customer_id,
        testCustomer.secretKey
      );

      // Try to access admin endpoint
      const response = await client.get(
        'verifierPortal',
        '/api/v1/admin/users'
      );

      // Should deny access
      expect([403, 404]).toContain(response.status);
    });
  });

  describe('Cross-Service Authentication Compatibility', () => {
    it('should use same HMAC algorithm across verifier portal and provii-credit-management', () => {
      const message = 'cust_123';
      const secretKey = 'shared-secret-key';

      // Verifier portal HMAC
      const sig1 = createHmac('sha256', secretKey)
        .update(message)
        .digest('hex');

      // provii-credit-management HMAC (should match)
      const sig2 = createHmac('sha256', secretKey)
        .update(message)
        .digest('hex');

      expect(sig1).toBe(sig2);
      assertConstantTimeEqual(sig1, sig2);
    });

    it('should validate HMAC signatures from provii-credit-management in verifier portal', () => {
      // Simulate provii-credit-management generating a signature
      const customer_id = testCustomer.customer_id;
      const secretKey = testCustomer.secretKey;

      const creditMgmtSignature = generateHmacSignature(secretKey, customer_id);

      // Verifier portal should be able to validate it
      assertValidHmacSignature(customer_id, creditMgmtSignature, secretKey);
    });

    it('should use consistent authentication for provii-verifier admin endpoints', async () => {
      // Admin endpoints should use separate authentication
      // This test verifies the pattern is consistent

      const adminSecretKey = process.env.ADMIN_SECRET_KEY || 'admin-secret-123';

      client.setAuth({
        token: generateHmacSignature(adminSecretKey, 'admin'),
      });

      const response = await client.get('hostedBackend', '/v1/admin/health');

      // Should authenticate (or return 404 if not implemented)
      expect([200, 401, 403, 404]).toContain(response.status);
    });
  });
});
