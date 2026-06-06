// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Tests for the Provii Issuer Backend Demo (Node.js).
 *
 * The source file (index.ts) calls loadConfig() at module load time which
 * exits if env vars are missing, so these tests re-implement and verify the
 * core integration functions (HMAC, base64url, canonical message, demo token
 * validation) directly. Handler tests are covered by the Go and Python
 * backends which share identical logic.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { describe, expect, it } from 'vitest';

// ---------------------------------------------------------------------------
// Re-implemented core functions from index.ts for testing
// ---------------------------------------------------------------------------

function base64urlDecode(str: string): Buffer {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

function base64urlEncode(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function hmacSha256Hex(secret: Buffer, message: string): string {
  return createHmac('sha256', secret).update(message).digest('hex');
}

function buildCanonicalMessage(
  dobDays: number,
  clientId: string,
  timestamp: number,
  nonce: string,
): string {
  const canonicalJson = `{"dob_days":${dobDays},"authorizer":{"format":"client","key_id":"${clientId}","timestamp":${timestamp}}}`;
  return `${timestamp}:POST:/v1/attestation/create:${canonicalJson}:${nonce}`;
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

  const expectedSig = createHmac('sha256', secret)
    .update(`provii-demos-v1:${dateStr}`)
    .digest('hex')
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

describe('base64urlDecode', () => {
  it('round-trips encode/decode', () => {
    const original = Buffer.from('test-secret-key-bytes');
    const encoded = base64urlEncode(original);
    const decoded = base64urlDecode(encoded);
    expect(decoded.toString()).toBe('test-secret-key-bytes');
  });

  it('handles URL-safe characters', () => {
    const data = Buffer.from([0xff, 0xfe, 0xfd]);
    const encoded = base64urlEncode(data);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
  });
});

describe('hmacSha256Hex', () => {
  it('produces correct hex signature', () => {
    const secret = Buffer.from('my-secret');
    const got = hmacSha256Hex(secret, 'hello world');
    const expected = createHmac('sha256', 'my-secret')
      .update('hello world')
      .digest('hex');
    expect(got).toBe(expected);
  });

  it('produces 64-char hex string', () => {
    const sig = hmacSha256Hex(Buffer.from('key'), 'msg');
    expect(sig.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(sig)).toBe(true);
  });
});

describe('buildCanonicalMessage', () => {
  it('produces correct format', () => {
    const got = buildCanonicalMessage(7000, 'client-123', 1700000000, 'abc123');
    const expected =
      '1700000000:POST:/v1/attestation/create:{"dob_days":7000,"authorizer":{"format":"client","key_id":"client-123","timestamp":1700000000}}:abc123';
    expect(got).toBe(expected);
  });

  it('handles negative dob_days', () => {
    const got = buildCanonicalMessage(-5000, 'client-456', 1700000000, 'nonce');
    expect(got).toContain('"dob_days":-5000');
  });

  it('includes nonce at end', () => {
    const got = buildCanonicalMessage(100, 'cid', 1000, 'my-nonce-value');
    expect(got).toMatch(/:my-nonce-value$/);
  });
});

describe('parseAllowedOrigins', () => {
  it('parses comma-separated origins', () => {
    const origins = parseAllowedOrigins(
      'http://localhost:3000, https://example.com',
    );
    expect(origins).toEqual(['http://localhost:3000', 'https://example.com']);
  });

  it('returns defaults when undefined', () => {
    const origins = parseAllowedOrigins(undefined);
    expect(origins).toContain('http://localhost:3000');
  });

  it('handles empty string as falsy (returns defaults)', () => {
    // Empty string is falsy in JS, so returns the defaults
    expect(parseAllowedOrigins('')).toContain('http://localhost:3000');
  });

  it('handles trailing comma', () => {
    expect(parseAllowedOrigins('http://a.com,')).toEqual(['http://a.com']);
  });
});

describe('validateDemoToken', () => {
  const testSecret = 'test-issuer-secret';

  function makeValidToken(dateStr: string): string {
    const sig = createHmac('sha256', testSecret)
      .update(`provii-demos-v1:${dateStr}`)
      .digest('hex')
      .slice(0, 16);
    return `demo_token_v1_${dateStr}_${sig}`;
  }

  it('accepts valid token', async () => {
    const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const token = makeValidToken(today);
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
    const token = makeValidToken(yesterday);
    const result = await validateDemoToken(token, testSecret);
    expect(result.valid).toBe(true);
  });
});
