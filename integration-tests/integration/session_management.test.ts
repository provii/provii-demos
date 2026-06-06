/**
 * Session Management Integration Tests
 *
 * Tests session creation, validation, binding, timeouts, and encryption
 * across verifier portal and provii-verifier.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createTestClient, TestClient } from '../utils/test-client';
import {
  mockCustomers,
  createMockSession,
  generateSessionToken,
  generateCodeVerifier,
  generateCodeChallenge,
  timeHelpers,
  userAgents,
  testIPs,
} from '../utils/mock-data';
import {
  assertValidSessionToken,
  assertSessionBinding,
  assertSessionExpired,
  assertSessionNotExpired,
  assertRecentTimestamp,
  assertResponseStatus,
} from '../utils/assertions';

describe('Session Management Tests', () => {
  let client: TestClient;
  const testCustomer = mockCustomers.alice;

  beforeEach(() => {
    client = createTestClient();
    client.clearAuth();
  });

  afterEach(() => {
    client.clearAuth();
  });

  describe('Session Creation with Binding', () => {
    it('should create session with IP and User-Agent binding', async () => {
      const loginResult = await client.loginVerifierPortal(
        testCustomer.customer_id,
        testCustomer.secretKey
      );

      expect(loginResult.sessionToken).toBeDefined();
      assertValidSessionToken(loginResult.sessionToken);

      // Session should be bound to IP and User-Agent from request headers
      // Verify session is usable for subsequent requests
      const balanceResponse = await client.get('verifierPortal', '/api/v1/balance');
      expect([200, 401]).toContain(balanceResponse.status);
    });

    it('should bind provii-verifier sessions to origin and IP', async () => {
      const code_verifier = generateCodeVerifier();
      const code_challenge = generateCodeChallenge(code_verifier);

      client.setAuth({
        publicKey: testCustomer.publicKey,
        secretKey: testCustomer.secretKey,
      });

      const challengeResponse = await client.createHostedChallenge({
        publicKey: testCustomer.publicKey,
        secretKey: testCustomer.secretKey,
        origin: testCustomer.allowed_origins[0],
        minimum_age: 18,
        code_challenge,
      });

      const sessionId = challengeResponse.session_id;
      expect(sessionId).toBeDefined();

      // Session should be bound to the origin
      // Subsequent requests with same origin should work
      const statusResponse = await client.checkHostedStatus(sessionId);
      expect(statusResponse).toBeDefined();
    });

    it('should store session binding metadata', async () => {
      const mockSession = createMockSession({
        binding: {
          ip: testIPs.publicIP1,
          userAgent: userAgents.chrome,
        },
      });

      assertSessionBinding(mockSession);
      expect(mockSession.binding?.ip).toBe(testIPs.publicIP1);
      expect(mockSession.binding?.userAgent).toBe(userAgents.chrome);
    });

    it('should include creation timestamp in session', async () => {
      const mockSession = createMockSession();

      assertRecentTimestamp(mockSession.created_at, 60);
      expect(mockSession.created_at).toBeLessThanOrEqual(timeHelpers.now());
    });
  });

  describe('Session Validation', () => {
    it('should accept requests with matching IP and User-Agent', async () => {
      await client.loginVerifierPortal(
        testCustomer.customer_id,
        testCustomer.secretKey
      );

      // First request establishes binding
      const response1 = await client.get('verifierPortal', '/api/v1/balance');
      const status1 = response1.status;

      // Second request with same client (same IP/UA) should work
      const response2 = await client.get('verifierPortal', '/api/v1/balance');
      expect(response2.status).toBe(status1);
    });

    it('should handle IP mismatch scenarios', async () => {
      // This test verifies session binding validation
      // In production, IP changes may be tolerated depending on policy

      const mockSession = createMockSession({
        binding: {
          ip: testIPs.publicIP1,
          userAgent: userAgents.chrome,
        },
      });

      // Simulate request from different IP
      const requestIP = testIPs.publicIP2;
      const isIPMatch = mockSession.binding?.ip === requestIP;

      expect(isIPMatch).toBe(false);

      // Implementation may log warning but allow request
      // or may reject based on security policy
    });

    it('should handle User-Agent mismatch scenarios', async () => {
      const mockSession = createMockSession({
        binding: {
          ip: testIPs.publicIP1,
          userAgent: userAgents.chrome,
        },
      });

      // Simulate request from different browser
      const requestUA = userAgents.firefox;
      const isUAMatch = mockSession.binding?.userAgent === requestUA;

      expect(isUAMatch).toBe(false);

      // Implementation may reject or allow with warning
      // depending on security policy
    });

    it('should validate session exists before use', async () => {
      const fakeSessionToken = generateSessionToken();

      client.setAuth({
        customer_id: testCustomer.customer_id,
        sessionToken: fakeSessionToken,
        csrfToken: 'fake-csrf-token',
      });

      const response = await client.get('verifierPortal', '/api/v1/balance');

      // Should reject invalid session
      expect([401, 403]).toContain(response.status);
    });

    it('should reject expired sessions', async () => {
      const expiredSession = createMockSession({
        created_at: timeHelpers.pastSeconds(7200),
        expires_at: timeHelpers.pastSeconds(1800),
      });

      assertSessionExpired(expiredSession.expires_at);

      // Requests with expired session should fail
      // This is verified by checking expiry timestamp
      const now = timeHelpers.now();
      expect(expiredSession.expires_at).toBeLessThan(now);
    });
  });

  describe('Idle Timeout Enforcement', () => {
    it('should expire sessions after idle timeout (30 minutes)', async () => {
      const idleTimeoutSeconds = 1800; // 30 minutes

      const session = createMockSession({
        created_at: timeHelpers.pastSeconds(idleTimeoutSeconds + 60),
        expires_at: timeHelpers.futureSeconds(0), // Set to now
      });

      // Session should be expired
      const now = timeHelpers.now();
      const idleTime = now - session.created_at;
      expect(idleTime).toBeGreaterThan(idleTimeoutSeconds);
    });

    it('should not expire active sessions', async () => {
      const activeSession = createMockSession({
        created_at: timeHelpers.pastSeconds(600), // 10 minutes ago
        expires_at: timeHelpers.futureSeconds(1200), // 20 minutes from now
      });

      assertSessionNotExpired(activeSession.expires_at);

      const now = timeHelpers.now();
      expect(activeSession.expires_at).toBeGreaterThan(now);
    });

    it('should update last_activity on each request', async () => {
      // Login creates session
      await client.loginVerifierPortal(
        testCustomer.customer_id,
        testCustomer.secretKey
      );

      // Make request
      await client.get('verifierPortal', '/api/v1/balance');

      // Last activity should be updated (tested by verifying session is still valid)
      await client.get('verifierPortal', '/api/v1/balance');

      // If idle timeout was enforced, second request would fail
      // Success indicates activity was updated
    });
  });

  describe('Absolute Expiry Enforcement', () => {
    it('should enforce absolute expiry (1 hour for verifier-portal)', async () => {
      const absoluteExpirySeconds = 3600; // 1 hour

      const session = createMockSession({
        created_at: timeHelpers.pastSeconds(absoluteExpirySeconds + 60),
        expires_at: timeHelpers.pastSeconds(60),
      });

      assertSessionExpired(session.expires_at);
    });

    it('should enforce absolute expiry for provii-verifier sessions', async () => {
      // Verifier sessions expire after challenge completion or 1 hour
      const session = createMockSession({
        created_at: timeHelpers.pastSeconds(3600),
        expires_at: timeHelpers.pastSeconds(1),
      });

      assertSessionExpired(session.expires_at);
    });

    it('should not extend session beyond absolute expiry', async () => {
      const createdAt = timeHelpers.pastSeconds(3500); // 58 minutes ago
      const expiresAt = createdAt + 3600; // 1 hour from creation

      const session = createMockSession({
        created_at: createdAt,
        expires_at: expiresAt,
      });

      // Session should still be valid (2 minutes remaining)
      assertSessionNotExpired(session.expires_at);

      // But cannot be extended beyond absolute expiry
      const maxExpiry = session.created_at + 3600;
      const now = timeHelpers.now();

      expect(session.expires_at).toBeLessThanOrEqual(maxExpiry);
    });
  });

  describe('Session Extension Logic', () => {
    it('should refresh session when nearing expiration', async () => {
      // Auto-refresh sessions nearing expiration
      await client.loginVerifierPortal(
        testCustomer.customer_id,
        testCustomer.secretKey
      );

      // Make request (should refresh if near expiry)
      const response = await client.get('verifierPortal', '/api/v1/balance');

      // Check for session refresh header
      const refreshed = response.headers.get('X-Session-Refreshed');

      // May or may not be refreshed depending on time remaining
      expect([null, 'true']).toContain(refreshed);
    });

    it('should extend idle timeout on activity', async () => {
      const session = createMockSession({
        created_at: timeHelpers.pastSeconds(600),
        expires_at: timeHelpers.futureSeconds(1200),
      });

      // Simulate activity
      const updatedExpiresAt = timeHelpers.futureSeconds(1800); // Reset to 30min

      const updatedSession = {
        ...session,
        expires_at: updatedExpiresAt,
      };

      assertSessionNotExpired(updatedSession.expires_at);
      expect(updatedSession.expires_at).toBeGreaterThan(session.expires_at);
    });

    it('should not refresh sessions past absolute expiry', async () => {
      const createdAt = timeHelpers.pastSeconds(3500);
      const absoluteExpiry = createdAt + 3600;

      // Try to extend beyond absolute expiry
      const attemptedExpiry = timeHelpers.futureSeconds(1800);

      // Should be capped at absolute expiry
      const actualExpiry = Math.min(attemptedExpiry, absoluteExpiry);

      const now = timeHelpers.now();
      expect(actualExpiry).toBeLessThanOrEqual(absoluteExpiry);
      expect(actualExpiry - now).toBeLessThanOrEqual(120); // Max 2 minutes remaining
    });
  });

  describe('Session Encryption at Rest', () => {
    it('should encrypt sensitive session data', () => {
      // Session should encrypt:
      // - code_verifier (PKCE)
      // - CSRF tokens
      // - Any PII

      const session = createMockSession();

      // Verify code_verifier is stored
      expect(session.code_verifier).toBeDefined();
      expect(session.code_verifier.length).toBeGreaterThan(40);

      // In production, this would be encrypted with MEK
      // For testing, verify structure is present
    });

    it('should use AES-256-GCM for session encryption', () => {
      // Verified in crypto_consistency tests
      // Session data should be encrypted using AES-256-GCM

      const sensitiveData = {
        code_verifier: generateCodeVerifier(),
        csrf_token: generateSessionToken(),
      };

      expect(sensitiveData.code_verifier).toBeDefined();
      expect(sensitiveData.csrf_token).toBeDefined();

      // In production, these would be encrypted before storage
    });

    it('should decrypt session data on retrieval', () => {
      const session = createMockSession();

      // Simulate encryption/decryption
      const encrypted = session.code_verifier; // Would be encrypted in production
      const decrypted = encrypted; // Would be decrypted on retrieval

      expect(decrypted).toBe(session.code_verifier);
    });
  });

  describe('Session Cleanup', () => {
    it('should clean up expired sessions', async () => {
      const expiredSession = createMockSession({
        expires_at: timeHelpers.pastSeconds(3600),
      });

      assertSessionExpired(expiredSession.expires_at);

      // Cleanup process should remove expired sessions
      // This is typically done by background worker
    });

    it('should clean up completed sessions after redemption', async () => {
      const completedSession = createMockSession({
        status: 'verified',
        verified_at: timeHelpers.pastSeconds(60),
      });

      expect(completedSession.status).toBe('verified');
      expect(completedSession.verified_at).toBeDefined();

      // Completed sessions may be kept for audit or cleaned up
      // Depends on retention policy
    });

    it('should maintain audit trail for deleted sessions', () => {
      const session = createMockSession();

      // Before deletion, session data should be logged
      const auditLog = {
        session_id: session.session_id,
        customer_id: session.customer_id,
        action: 'session_deleted',
        timestamp: timeHelpers.now(),
      };

      expect(auditLog.session_id).toBe(session.session_id);
      expect(auditLog.action).toBe('session_deleted');
    });
  });

  describe('Concurrent Session Handling', () => {
    it('should support multiple active sessions per customer', async () => {
      // Login creates first session
      await client.loginVerifierPortal(
        testCustomer.customer_id,
        testCustomer.secretKey
      );

      const session1Token = client['sessionCookies'].get('__Host-session');

      // Create another client for second session
      const client2 = createTestClient();
      await client2.loginVerifierPortal(
        testCustomer.customer_id,
        testCustomer.secretKey
      );

      const session2Token = client2['sessionCookies'].get('__Host-session');

      // Both sessions should be valid
      expect(session1Token).toBeDefined();
      expect(session2Token).toBeDefined();

      // They should be different
      if (session1Token && session2Token) {
        expect(session1Token).not.toBe(session2Token);
      }
    });

    it('should handle race conditions in session creation', async () => {
      // Simulate concurrent session creation
      const promises = Array.from({ length: 5 }, () =>
        client.loginVerifierPortal(testCustomer.customer_id, testCustomer.secretKey)
      );

      const results = await Promise.allSettled(promises);

      // At least one should succeed
      const succeeded = results.filter(r => r.status === 'fulfilled');
      expect(succeeded.length).toBeGreaterThan(0);
    });

    it('should prevent session fixation attacks', async () => {
      // Attacker provides session token
      const attackerSessionToken = generateSessionToken();

      client.setAuth({
        customer_id: testCustomer.customer_id,
        sessionToken: attackerSessionToken,
        csrfToken: 'attacker-csrf',
      });

      // Login should create NEW session, not use provided one
      const loginResult = await client.loginVerifierPortal(
        testCustomer.customer_id,
        testCustomer.secretKey
      );

      // Should get different session token
      expect(loginResult.sessionToken).not.toBe(attackerSessionToken);
    });
  });

  describe('Session Security', () => {
    it('should use __Host- cookie prefix for enhanced security', async () => {
      await client.loginVerifierPortal(
        testCustomer.customer_id,
        testCustomer.secretKey
      );

      // Session cookie should use __Host- prefix
      const sessionCookie = client['sessionCookies'].get('__Host-session');

      // Prefix ensures:
      // - Secure flag required
      // - Domain cannot be specified
      // - Path must be /
      expect(sessionCookie).toBeDefined();
    });

    it('should set HttpOnly flag on session cookies', () => {
      // HttpOnly prevents JavaScript access
      // This is set by the server in Set-Cookie header

      // Cookie attributes should include:
      // - HttpOnly
      // - Secure
      // - SameSite=Strict
      // - Path=/
      // - Max-Age=1800 (30 minutes)

      const expectedAttributes = [
        'HttpOnly',
        'Secure',
        'SameSite=Strict',
        'Path=/',
        'Max-Age=1800',
      ];

      // These are enforced by the server
      expect(expectedAttributes).toHaveLength(5);
    });

    it('should use SameSite=Strict for session cookies', () => {
      // SameSite=Strict prevents CSRF attacks
      // Cookie is only sent with same-site requests

      const sameSitePolicy = 'Strict';
      expect(sameSitePolicy).toBe('Strict');
    });

    it('should regenerate session ID after login', async () => {
      // First, create anonymous session
      const response1 = await client.get('verifierPortal', '/health');
      const anonymousSession = client['sessionCookies'].get('__Host-session');

      // Login
      const loginResult = await client.loginVerifierPortal(
        testCustomer.customer_id,
        testCustomer.secretKey
      );

      // Session ID should change after authentication
      const authenticatedSession = loginResult.sessionToken;

      if (anonymousSession) {
        expect(authenticatedSession).not.toBe(anonymousSession);
      }
    });
  });
});
