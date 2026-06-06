// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Tests for the Provii Verifier Backend Demo (Node.js).
 *
 * The source file (index.ts) starts a server at module load time, so these
 * tests re-implement and verify the core integration functions (HMAC, PKCE,
 * base64url, deep link construction, demo token validation) directly.
 * Handler tests are covered by the Go and Python backends which share
 * identical logic.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { describe, expect, it } from 'vitest';

// ---------------------------------------------------------------------------
// Re-implemented core functions from index.ts for testing
// (these are the "COPY THIS" functions that integrators extract)
// ---------------------------------------------------------------------------

function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64urlEncode(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function generateCodeVerifier(): string {
  return base64urlEncode(randomBytes(32));
}

async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64urlEncode(new Uint8Array(hash));
}

async function createHmacSignature(message: string, secretBase64url: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = base64urlDecode(secretBase64url);
  const keyBuffer = new ArrayBuffer(keyData.length);
  new Uint8Array(keyBuffer).set(keyData);

  const key = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

interface ChallengeResponse {
  challenge_id: string;
  rp_challenge: string;
  cutoff_days: number;
  verifying_key_id: number;
  submit_secret: string;
  expires_at: number;
  status_url: string;
  verify_url: string;
  proof_direction: string;
}

function buildDeepLink(challenge: ChallengeResponse): string {
  const payload = {
    challenge_id: challenge.challenge_id,
    rp_challenge: challenge.rp_challenge,
    submit_secret: challenge.submit_secret,
    cutoff_days: challenge.cutoff_days,
    verifying_key_id: challenge.verifying_key_id,
    verify_url: challenge.verify_url,
    expires_at: challenge.expires_at,
    proof_direction: challenge.proof_direction,
  };

  const jsonStr = JSON.stringify(payload);
  const bytes = new TextEncoder().encode(jsonStr);
  return `https://provii.app/verify?d=${base64urlEncode(bytes)}`;
}

function parseAllowedOrigins(envOrigins?: string): string[] {
  if (envOrigins) {
    return envOrigins
      .split(',')
      .map((o) => o.trim())
      .filter((o) => o.length > 0);
  }
  return ['http://localhost:3000', 'http://localhost:5173'];
}

async function validateDemoToken(
  token: string,
  secret: string,
): Promise<{ valid: boolean }> {
  if (!token || !token.startsWith('demo_token_v1_')) {
    return { valid: false };
  }

  const parts = token.split('_');
  if (parts.length !== 5) {
    return { valid: false };
  }

  const dateStr = parts[3] ?? '';
  const providedSig = parts[4] ?? '';
  if (!dateStr || !providedSig) {
    return { valid: false };
  }

  const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const yesterday = new Date(Date.now() - 86400000)
    .toISOString()
    .slice(0, 10)
    .replace(/-/g, '');

  if (dateStr !== today && dateStr !== yesterday) {
    return { valid: false };
  }

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(`provii-demos-v1:${dateStr}`),
  );

  const expectedSig = Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 16);

  if (providedSig.length !== expectedSig.length) {
    return { valid: false };
  }
  const providedBuf = Buffer.from(providedSig, 'utf-8');
  const expectedBuf = Buffer.from(expectedSig, 'utf-8');
  const isValid = timingSafeEqual(providedBuf, expectedBuf);
  return { valid: isValid };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('base64url', () => {
  it('round-trips encode/decode', () => {
    const original = new TextEncoder().encode('pkce-code-verifier-bytes');
    const encoded = base64urlEncode(original);
    const decoded = base64urlDecode(encoded);
    expect(Array.from(decoded)).toEqual(Array.from(original));
  });

  it('produces URL-safe characters', () => {
    const encoded = base64urlEncode(randomBytes(32));
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');
  });
});

describe('generateCodeVerifier', () => {
  it('produces 43-character string', () => {
    const verifier = generateCodeVerifier();
    expect(verifier.length).toBe(43);
  });

  it('produces unique values', () => {
    const v1 = generateCodeVerifier();
    const v2 = generateCodeVerifier();
    expect(v1).not.toBe(v2);
  });
});

describe('generateCodeChallenge', () => {
  it('produces deterministic output', async () => {
    const verifier = 'test-verifier-value';
    const c1 = await generateCodeChallenge(verifier);
    const c2 = await generateCodeChallenge(verifier);
    expect(c1).toBe(c2);
  });

  it('differs from verifier', async () => {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    expect(challenge).not.toBe(verifier);
  });
});

describe('createHmacSignature', () => {
  it('produces 64-char hex string', async () => {
    const secret = base64urlEncode(new TextEncoder().encode('my-test-secret'));
    const sig = await createHmacSignature('test-message', secret);
    expect(sig.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(sig)).toBe(true);
  });

  it('matches Node.js crypto HMAC', async () => {
    const rawSecret = 'my-test-secret';
    const secret = base64urlEncode(new TextEncoder().encode(rawSecret));
    const sig = await createHmacSignature('test-message', secret);
    const expected = createHmac('sha256', rawSecret)
      .update('test-message')
      .digest('hex');
    expect(sig).toBe(expected);
  });
});

describe('buildDeepLink', () => {
  it('produces valid deep link', () => {
    const challenge: ChallengeResponse = {
      challenge_id: '550e8400-e29b-41d4-a716-446655440000',
      rp_challenge: 'rp-chal',
      cutoff_days: 6574,
      verifying_key_id: 1,
      submit_secret: 'secret',
      expires_at: 1700000300,
      status_url: '/status',
      verify_url: '/verify',
      proof_direction: 'over_age',
    };
    const link = buildDeepLink(challenge);
    expect(link).toMatch(/^https:\/\/provii\.app\/verify\?d=/);
  });

  it('deep link payload decodes to valid JSON', () => {
    const challenge: ChallengeResponse = {
      challenge_id: '550e8400-e29b-41d4-a716-446655440000',
      rp_challenge: 'rp-chal',
      cutoff_days: 6574,
      verifying_key_id: 1,
      submit_secret: 'secret',
      expires_at: 1700000300,
      status_url: '/status',
      verify_url: '/verify',
      proof_direction: 'over_age',
    };
    const link = buildDeepLink(challenge);
    const encoded = link.split('d=')[1]!;
    const decoded = new TextDecoder().decode(base64urlDecode(encoded));
    const parsed = JSON.parse(decoded);
    expect(parsed.challenge_id).toBe('550e8400-e29b-41d4-a716-446655440000');
    expect(parsed.proof_direction).toBe('over_age');
  });
});

describe('parseAllowedOrigins', () => {
  it('parses comma-separated origins', () => {
    const origins = parseAllowedOrigins('http://a.com, http://b.com');
    expect(origins).toEqual(['http://a.com', 'http://b.com']);
  });

  it('returns defaults when undefined', () => {
    const origins = parseAllowedOrigins(undefined);
    expect(origins).toContain('http://localhost:3000');
  });

  it('handles empty string as falsy (returns defaults)', () => {
    const origins = parseAllowedOrigins('');
    // Empty string is falsy in JS, so returns the defaults
    expect(origins).toContain('http://localhost:3000');
  });

  it('handles trailing comma', () => {
    const origins = parseAllowedOrigins('http://a.com,');
    expect(origins).toEqual(['http://a.com']);
  });
});

describe('validateDemoToken', () => {
  const testSecret = 'test-verifier-secret';

  async function makeValidToken(dateStr: string): Promise<string> {
    const sig = createHmac('sha256', testSecret)
      .update(`provii-demos-v1:${dateStr}`)
      .digest('hex')
      .slice(0, 16);
    return `demo_token_v1_${dateStr}_${sig}`;
  }

  it('accepts valid token', async () => {
    const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const token = await makeValidToken(today);
    const result = await validateDemoToken(token, testSecret);
    expect(result.valid).toBe(true);
  });

  it('rejects wrong prefix', async () => {
    const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const result = await validateDemoToken(
      `bad_prefix_v1_${today}_0000000000000000`,
      testSecret,
    );
    expect(result.valid).toBe(false);
  });

  it('rejects wrong signature', async () => {
    const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const result = await validateDemoToken(
      `demo_token_v1_${today}_aaaaaaaaaaaaaaaa`,
      testSecret,
    );
    expect(result.valid).toBe(false);
  });

  it('rejects old date', async () => {
    const result = await validateDemoToken(
      'demo_token_v1_19700101_0000000000000000',
      testSecret,
    );
    expect(result.valid).toBe(false);
  });

  it('rejects malformed token', async () => {
    const result = await validateDemoToken('garbage', testSecret);
    expect(result.valid).toBe(false);
  });

  it('rejects empty token', async () => {
    const result = await validateDemoToken('', testSecret);
    expect(result.valid).toBe(false);
  });

  it('accepts yesterday token', async () => {
    const yesterday = new Date(Date.now() - 86400000)
      .toISOString()
      .slice(0, 10)
      .replace(/-/g, '');
    const token = await makeValidToken(yesterday);
    const result = await validateDemoToken(token, testSecret);
    expect(result.valid).toBe(true);
  });
});
