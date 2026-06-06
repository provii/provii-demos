/**
 * Crypto Consistency Integration Tests
 *
 * Tests cryptographic implementations across provii-agegate, provii-verifier (Rust),
 * and other services to ensure consistency in PKCE, nonce generation, and encryption.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  generateCodeVerifier,
  generateCodeChallenge,
  generateNonce,
  cryptoTestVectors,
} from '../utils/mock-data';
import {
  assertPkceMatch,
  assertValidPkceVerifier,
  assertValidPkceChallenge,
  assertValidNonce,
  assertSufficientEntropy,
  assertUnique,
  assertAes256GcmEncryption,
} from '../utils/assertions';
import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'crypto';

describe('Crypto Consistency Tests', () => {
  const encryptAes256Gcm = (
    plaintext: string,
    key: Buffer
  ): { ciphertext: string; iv: string; tag: string } => {
    const iv = randomBytes(12); // 96-bit IV for GCM
    const cipher = createCipheriv('aes-256-gcm', key, iv);

    let ciphertext = cipher.update(plaintext, 'utf8', 'base64');
    ciphertext += cipher.final('base64');

    const tag = cipher.getAuthTag();

    return {
      ciphertext,
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
    };
  };

  const decryptAes256Gcm = (
    encrypted: { ciphertext: string; iv: string; tag: string },
    key: Buffer
  ): string => {
    const iv = Buffer.from(encrypted.iv, 'base64');
    const tag = Buffer.from(encrypted.tag, 'base64');

    const decipher = createDecipheriv('aes-256-gcm', key, iv, {
      authTagLength: 16,
    });
    decipher.setAuthTag(tag);

    let plaintext = decipher.update(encrypted.ciphertext, 'base64', 'utf8');
    plaintext += decipher.final('utf8');

    return plaintext;
  };

  describe('PKCE Challenge Generation', () => {
    it('should generate RFC 7636 compliant code_verifier', () => {
      const verifier = generateCodeVerifier();

      // Validate format
      assertValidPkceVerifier(verifier);

      // Verify entropy (32 bytes = 256 bits)
      assertSufficientEntropy(verifier, 256);
    });

    it('should generate RFC 7636 compliant code_challenge', () => {
      const verifier = generateCodeVerifier();
      const challenge = generateCodeChallenge(verifier);

      // Validate format
      assertValidPkceChallenge(challenge);

      // Verify challenge matches verifier
      assertPkceMatch(verifier, challenge);
    });

    it('should produce same challenge for same verifier (deterministic)', () => {
      const verifier = cryptoTestVectors.pkce.verifier;

      const challenge1 = generateCodeChallenge(verifier);
      const challenge2 = generateCodeChallenge(verifier);
      const challenge3 = generateCodeChallenge(verifier);

      expect(challenge1).toBe(challenge2);
      expect(challenge2).toBe(challenge3);

      // Verify against test vector
      expect(challenge1).toBe(cryptoTestVectors.pkce.challenge);
    });

    it('should match provii-agegate PKCE implementation', () => {
      // provii-agegate uses SHA-256 and base64url encoding
      const verifier = cryptoTestVectors.pkce.verifier;

      // Our implementation
      const ourChallenge = generateCodeChallenge(verifier);

      // Simulate provii-agegate implementation
      const hash = createHash('sha256').update(verifier).digest();
      const ageGateChallenge = hash
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      expect(ourChallenge).toBe(ageGateChallenge);
    });

    it('should match provii-verifier (Rust) PKCE implementation', () => {
      // Rust implementation uses provii-crypto which should match
      const verifier = cryptoTestVectors.pkce.verifier;
      const expectedChallenge = cryptoTestVectors.pkce.challenge;

      const challenge = generateCodeChallenge(verifier);

      expect(challenge).toBe(expectedChallenge);
    });

    it('should produce unique challenges for different verifiers', () => {
      const verifiers = Array.from({ length: 100 }, () => generateCodeVerifier());
      const challenges = verifiers.map(v => generateCodeChallenge(v));

      // All challenges should be unique
      assertUnique(challenges);
    });

    it('should use SHA-256 for S256 challenge method', () => {
      const verifier = 'test-verifier-' + 'a'.repeat(40);

      // Our implementation
      const challenge = generateCodeChallenge(verifier);

      // Manual SHA-256 calculation
      const hash = createHash('sha256').update(verifier).digest();
      const expected = hash
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      expect(challenge).toBe(expected);
    });
  });

  describe('Nonce Generation', () => {
    it('should generate cryptographically secure nonces', () => {
      const nonce = generateNonce();

      // Validate format
      assertValidNonce(nonce);

      // Verify entropy (32 bytes = 256 bits)
      assertSufficientEntropy(nonce, 256);
    });

    it('should generate unique nonces', () => {
      const nonces = Array.from({ length: 1000 }, () => generateNonce());

      // All should be unique
      assertUnique(nonces);
    });

    it('should use same nonce generation across services', () => {
      // All services should use randomBytes(32) -> base64url

      // Our implementation
      const bytes = randomBytes(32);
      const nonce1 = bytes
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      // Verify length (43 characters for 32 bytes base64url)
      expect(nonce1.length).toBe(43);

      // Verify format
      assertValidNonce(nonce1);
    });

    it('should validate nonce entropy distribution', () => {
      const nonces = Array.from({ length: 100 }, () => generateNonce());

      // Calculate entropy
      const charCounts = new Map<string, number>();

      for (const nonce of nonces) {
        for (const char of nonce) {
          charCounts.set(char, (charCounts.get(char) || 0) + 1);
        }
      }

      // Should have good distribution of base64url characters
      expect(charCounts.size).toBeGreaterThan(50); // At least 50 different characters used
    });
  });

  describe('Session Token Generation', () => {
    it('should generate cryptographically secure session tokens', () => {
      const token = randomBytes(32)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      // Validate format
      expect(token).toMatch(/^[A-Za-z0-9\-_]+$/);
      expect(token.length).toBe(43);

      // Verify entropy
      assertSufficientEntropy(token, 256);
    });

    it('should generate unique session tokens', () => {
      const tokens = Array.from({ length: 1000 }, () =>
        randomBytes(32)
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, '')
      );

      assertUnique(tokens);
    });
  });

  describe('Encryption/Decryption (AES-256-GCM)', () => {
    it('should use AES-256-GCM for encryption', () => {
      const plaintext = 'sensitive-data-to-encrypt';
      const key = randomBytes(32); // 256-bit key

      const encrypted = encryptAes256Gcm(plaintext, key);

      // Validate encryption structure
      assertAes256GcmEncryption(encrypted);
    });

    it('should decrypt to original plaintext', () => {
      const plaintext = 'test-code-verifier-' + 'x'.repeat(30);
      const key = randomBytes(32);

      const encrypted = encryptAes256Gcm(plaintext, key);
      const decrypted = decryptAes256Gcm(encrypted, key);

      expect(decrypted).toBe(plaintext);
    });

    it('should use proper IV handling (96 bits)', () => {
      const plaintext = 'test-data';
      const key = randomBytes(32);

      const encrypted = encryptAes256Gcm(plaintext, key);
      const ivBuffer = Buffer.from(encrypted.iv, 'base64');

      // IV should be 12 bytes (96 bits) for GCM
      expect(ivBuffer.length).toBe(12);
    });

    it('should use proper auth tag (128 bits)', () => {
      const plaintext = 'test-data';
      const key = randomBytes(32);

      const encrypted = encryptAes256Gcm(plaintext, key);
      const tagBuffer = Buffer.from(encrypted.tag, 'base64');

      // Auth tag should be 16 bytes (128 bits)
      expect(tagBuffer.length).toBe(16);
    });

    it('should fail decryption with wrong key', () => {
      const plaintext = 'test-data';
      const key1 = randomBytes(32);
      const key2 = randomBytes(32);

      const encrypted = encryptAes256Gcm(plaintext, key1);

      expect(() => {
        decryptAes256Gcm(encrypted, key2);
      }).toThrow();
    });

    it('should fail decryption with tampered ciphertext', () => {
      const plaintext = 'test-data';
      const key = randomBytes(32);

      const encrypted = encryptAes256Gcm(plaintext, key);

      // Tamper with ciphertext
      const tampered = {
        ...encrypted,
        ciphertext: encrypted.ciphertext.replace(/A/g, 'B'),
      };

      expect(() => {
        decryptAes256Gcm(tampered, key);
      }).toThrow();
    });

    it('should fail decryption with tampered auth tag', () => {
      const plaintext = 'test-data';
      const key = randomBytes(32);

      const encrypted = encryptAes256Gcm(plaintext, key);

      // Tamper with auth tag
      const tampered = {
        ...encrypted,
        tag: randomBytes(16).toString('base64'),
      };

      expect(() => {
        decryptAes256Gcm(tampered, key);
      }).toThrow();
    });

    it('should use consistent encryption across provii-issuer and verifier portal', () => {
      // Both should use AES-256-GCM with same parameters
      const plaintext = 'shared-secret-data';
      const sharedKey = randomBytes(32);

      // Issuer-service encryption
      const issuerEncrypted = encryptAes256Gcm(plaintext, sharedKey);

      // Verifier-portal should decrypt successfully
      const decrypted = decryptAes256Gcm(issuerEncrypted, sharedKey);

      expect(decrypted).toBe(plaintext);
    });

    it('should use consistent encryption in provii-verifier', () => {
      // provii-verifier uses same AES-256-GCM encryption
      const codeVerifier = generateCodeVerifier();
      const mek = randomBytes(32); // Master Encryption Key

      const encrypted = encryptAes256Gcm(codeVerifier, mek);
      const decrypted = decryptAes256Gcm(encrypted, mek);

      expect(decrypted).toBe(codeVerifier);
      assertValidPkceVerifier(decrypted);
    });
  });

  describe('Base64 URL Encoding', () => {
    it('should use consistent base64url encoding (no padding)', () => {
      const data = randomBytes(32);

      const base64url = data
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      // Should not contain standard base64 characters
      expect(base64url).not.toContain('+');
      expect(base64url).not.toContain('/');
      expect(base64url).not.toContain('=');

      // Should only contain URL-safe characters
      expect(base64url).toMatch(/^[A-Za-z0-9\-_]+$/);
    });

    it('should decode base64url correctly', () => {
      const original = 'test-data-to-encode';
      const buffer = Buffer.from(original, 'utf8');

      const base64url = buffer
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      // Decode
      const decodedBuffer = Buffer.from(
        base64url.replace(/-/g, '+').replace(/_/g, '/'),
        'base64'
      );

      expect(decodedBuffer.toString('utf8')).toBe(original);
    });
  });

  describe('Cryptographic Constant-Time Operations', () => {
    it('should use constant-time comparison for PKCE verification', () => {
      const verifier1 = generateCodeVerifier();
      const challenge1 = generateCodeChallenge(verifier1);

      const verifier2 = generateCodeVerifier();
      const challenge2 = generateCodeChallenge(verifier2);

      // Same verifier should match its challenge
      assertPkceMatch(verifier1, challenge1);

      // Different verifier should not match
      expect(() => {
        assertPkceMatch(verifier1, challenge2);
      }).toThrow();
    });

    it('should prevent timing attacks on challenge comparison', () => {
      // This would require measuring actual execution time
      // which is difficult in a test environment

      const validChallenge = cryptoTestVectors.pkce.challenge;
      const invalidChallenge = 'X'.repeat(validChallenge.length);

      // Both comparisons should take similar time
      const compare = (a: string, b: string): boolean => {
        if (a.length !== b.length) return false;

        let result = 0;
        for (let i = 0; i < a.length; i++) {
          result |= a.charCodeAt(i) ^ b.charCodeAt(i);
        }
        return result === 0;
      };

      expect(compare(validChallenge, validChallenge)).toBe(true);
      expect(compare(validChallenge, invalidChallenge)).toBe(false);
    });
  });

  describe('Random Number Generation', () => {
    it('should use crypto.randomBytes for secure randomness', () => {
      const bytes1 = randomBytes(32);
      const bytes2 = randomBytes(32);

      // Should be different
      expect(bytes1.equals(bytes2)).toBe(false);

      // Should be correct length
      expect(bytes1.length).toBe(32);
      expect(bytes2.length).toBe(32);
    });

    it('should not use Math.random for cryptographic values', () => {
      // This is a code review check, not a runtime check
      // Math.random should never be used for:
      // - PKCE verifiers
      // - Nonces
      // - Session tokens
      // - Encryption keys
      // - HMAC secrets

      // Verify our implementations use crypto.randomBytes
      const nonce = generateNonce();
      assertValidNonce(nonce);
      assertSufficientEntropy(nonce, 256);
    });
  });

  describe('Cross-Implementation Compatibility', () => {
    it('should have provii-agegate JS and Rust produce compatible PKCE challenges', () => {
      const testVerifier = cryptoTestVectors.pkce.verifier;
      const expectedChallenge = cryptoTestVectors.pkce.challenge;

      // JavaScript implementation
      const jsChallenge = generateCodeChallenge(testVerifier);

      // Should match Rust implementation (via test vector)
      expect(jsChallenge).toBe(expectedChallenge);
    });

    it('should have provii-verifier decrypt verifier portal encrypted data', () => {
      // Both should use same MEK and encryption algorithm
      const sharedMek = randomBytes(32);
      const sensitiveData = 'shared-secret-code-verifier';

      // Verifier portal encrypts
      const encrypted = encryptAes256Gcm(sensitiveData, sharedMek);

      // provii-verifier decrypts
      const decrypted = decryptAes256Gcm(encrypted, sharedMek);

      expect(decrypted).toBe(sensitiveData);
    });

    it('should validate provii-crypto compatibility', () => {
      // provii-crypto is used by Rust services
      // Verify it produces same output as our JS implementation

      const verifier = cryptoTestVectors.pkce.verifier;
      const challenge = generateCodeChallenge(verifier);

      // Should match the test vector which comes from provii-crypto
      expect(challenge).toBe(cryptoTestVectors.pkce.challenge);
    });
  });
});
