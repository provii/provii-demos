// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust
//
// Regression tests for the log-sanitiser fixes.
//
// : the pre-fix `b64url256` pattern used `\b` as the boundary. `\b`
// anchors on `[A-Za-z0-9_]` transitions, so a 43-char base64url token that
// begins with `-` and is preceded by whitespace (or ends with `-` followed
// by whitespace) did NOT match. A bearer cookie or Ed25519 seed whose first
// byte happens to encode as `-` would therefore leak through every
// `console.*` wrapper in the docs gateway. The fix switches the anchors to
// an explicit `(?<![A-Za-z0-9_-])...(?![A-Za-z0-9_-])` lookaround over the
// full base64url alphabet; these tests lock the new behaviour in.
//
// : the generic `hex32` pattern previously redacted any 64-char hex
// string on word boundaries, which ate the published canonical-message
// fixture SHA. That SHA is a drift-check invariant, not secret material.
// The fix adds a `PUBLIC_HEX_INVARIANTS` allowlist with that specific digest
// in it. These tests assert the digest survives redaction while unrelated
// 64-char hex strings still redact.
//
// The suite runs under the same `@cloudflare/vitest-pool-workers` config as
// the other files in `src/docs/__tests__/` so the `crypto.subtle.importKey`
// / `crypto.subtle.sign` calls used by `installLogSanitizer` hit the real
// Workers runtime rather than a Node polyfill.

import { beforeEach, describe, expect, it, vi } from "vitest";

import { __testing, installLogSanitizer } from "../log-sanitizer";

// Canonical-message fixture SHA-256. Kept in lockstep with
// `test/docs/canonical_message_vectors.json` (and its mirrors in
// provii-verifier + provii-issuer repos) and with the allowlist entry in
// `log-sanitizer.ts`. If the fixture SHA rotates the test breaks
// deliberately; bump all three together.
const CANONICAL_FIXTURE_SHA256 =
  "16661f12e890423524ccebb437347de5f0678e4fe38d8df8f452a87673792dcd";

// A valid 43-char base64url token (256 bit) whose FIRST byte is `-`.
// Preceded by whitespace, the old `\b`-anchored pattern failed to match
// because `\b` sees no word transition between ` ` and `-`. The fix must
// redact it to `[REDACTED:<hmac>]` or `[REDACTED]`.
const LEADING_DASH_B64URL = "-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcdE";

// A 43-char base64url token whose LAST byte is `-`. Same failure mode on
// the trailing side of the old `\b` anchor.
const TRAILING_DASH_B64URL = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcdE-";

// A 43-char token that is purely alphanumeric. The old pattern matched
// this fine; the fix must continue to match it (guard against regression
// in the other direction).
const ALPHANUMERIC_B64URL = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG";

// (): A valid 44-char UNPADDED base64url token. A raw
// 32-byte secret emitted without the `=` pad runs 44 chars (not 43).
// Under the prior `{43}` quantifier plus right-hand lookahead, the 44th
// character was still in the alphabet so the match at position 43 was
// rejected and the token survived sanitisation verbatim. The widened
// `{43,44}` quantifier consumes the full token and the lookahead then
// sits past the boundary, so the match succeeds. This is the canonical
// case a caller hits when they log a 32-byte value that happens to
// emit without padding.
const UNPADDED_44_CHAR_B64URL =
  "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFGH";

// A 64-char hex string that is NOT the canonical-message fixture SHA.
// Represents a real HMAC tag or SHA-256 digest of secret material. Must
// still redact under the hex32 rule.
const UNRELATED_HEX32 =
  "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef";

// The HMAC key material used by the sanitiser. Any 32+-byte string works
// for these tests; the tag computation is deterministic so once `install`
// has run we can observe stable `[REDACTED:<hmac>]` markers.
const TEST_KEY_MATERIAL = "test-log-sanitiser-key-material-32bytes!";

describe("log-sanitizer W6-NT4 base64url boundary fix", () => {
  beforeEach(() => {
    __testing.resetCache();
  });

  it("redacts a 43-char base64url token that starts with '-' preceded by whitespace", async () => {
    await installLogSanitizer(TEST_KEY_MATERIAL, [LEADING_DASH_B64URL]);
    const sanitised = __testing.sanitiseStringSync(
      `bearer token ${LEADING_DASH_B64URL} was leaked`,
    );
    expect(sanitised).not.toContain(LEADING_DASH_B64URL);
    expect(sanitised).toMatch(/\[REDACTED(:[0-9a-f]{8})?\]/);
 // The non-secret surrounding text must survive.
    expect(sanitised.startsWith("bearer token ")).toBe(true);
    expect(sanitised.endsWith(" was leaked")).toBe(true);
  });

  it("redacts a 43-char base64url token that ends with '-' followed by whitespace", async () => {
    await installLogSanitizer(TEST_KEY_MATERIAL, [TRAILING_DASH_B64URL]);
    const sanitised = __testing.sanitiseStringSync(
      `token=${TRAILING_DASH_B64URL} expires in 5m`,
    );
    expect(sanitised).not.toContain(TRAILING_DASH_B64URL);
    expect(sanitised).toMatch(/\[REDACTED(:[0-9a-f]{8})?\]/);
    expect(sanitised.includes("expires in 5m")).toBe(true);
  });

  it("redacts a 43-char alphanumeric base64url token (no regression on the happy path)", async () => {
    await installLogSanitizer(TEST_KEY_MATERIAL, [ALPHANUMERIC_B64URL]);
    const sanitised = __testing.sanitiseStringSync(
      `cookie docs-session=${ALPHANUMERIC_B64URL};`,
    );
    expect(sanitised).not.toContain(ALPHANUMERIC_B64URL);
  });

  it("does not greedily consume longer runs of base64url chars", async () => {
 // 50 base64url chars in a row; the pattern must NOT match the first 43
 // because the character to its right is still in the alphabet and the
 // new lookaheads block that. The full 50-char run is therefore left
 // alone (none of the registered patterns cover 50-char tokens).
    const longRun = "a".repeat(50);
    await installLogSanitizer(TEST_KEY_MATERIAL, []);
    const sanitised = __testing.sanitiseStringSync(`run=${longRun} end`);
 // Entire 50-char run should be preserved because no 43-char window has
 // both boundaries satisfied inside a longer alphabet run.
    expect(sanitised).toContain(longRun);
  });

  it("async sanitiser agrees with sync sanitiser on leading-dash token", async () => {
    await installLogSanitizer(TEST_KEY_MATERIAL, [LEADING_DASH_B64URL]);
    const syncOut = __testing.sanitiseStringSync(
      `cookie: ${LEADING_DASH_B64URL}`,
    );
    const asyncOut = await __testing.sanitiseStringAsync(
      `cookie: ${LEADING_DASH_B64URL}`,
    );
    expect(syncOut).toBe(asyncOut);
    expect(syncOut).not.toContain(LEADING_DASH_B64URL);
  });
});

describe("log-sanitizer W7-S3 44-char unpadded base64url match", () => {
  beforeEach(() => {
    __testing.resetCache();
  });

  it("redacts a 44-char unpadded base64url token", async () => {
 // Length sanity check so a future typo in the constant does not
 // silently defeat the test.
    expect(UNPADDED_44_CHAR_B64URL.length).toBe(44);
    await installLogSanitizer(TEST_KEY_MATERIAL, [UNPADDED_44_CHAR_B64URL]);
    const sanitised = __testing.sanitiseStringSync(
      `secret ${UNPADDED_44_CHAR_B64URL} leaked`,
    );
    expect(sanitised).not.toContain(UNPADDED_44_CHAR_B64URL);
    expect(sanitised).toMatch(/\[REDACTED(:[0-9a-f]{8})?\]/);
    expect(sanitised.startsWith("secret ")).toBe(true);
    expect(sanitised.endsWith(" leaked")).toBe(true);
  });

  it("redacts a 44-char unpadded token in a docs-session cookie header", async () => {
    await installLogSanitizer(TEST_KEY_MATERIAL, [UNPADDED_44_CHAR_B64URL]);
    const logLine = `Cookie: docs-session=${UNPADDED_44_CHAR_B64URL}; Path=/`;
    const sanitised = __testing.sanitiseStringSync(logLine);
    expect(sanitised).not.toContain(UNPADDED_44_CHAR_B64URL);
  });

  it("async sanitiser agrees with sync sanitiser on 44-char unpadded token", async () => {
    await installLogSanitizer(TEST_KEY_MATERIAL, [UNPADDED_44_CHAR_B64URL]);
    const syncOut = __testing.sanitiseStringSync(
      `value=${UNPADDED_44_CHAR_B64URL}`,
    );
    const asyncOut = await __testing.sanitiseStringAsync(
      `value=${UNPADDED_44_CHAR_B64URL}`,
    );
    expect(syncOut).toBe(asyncOut);
    expect(syncOut).not.toContain(UNPADDED_44_CHAR_B64URL);
  });
});

describe("log-sanitizer W6-NT16 hex32 public-invariant allowlist", () => {
  beforeEach(() => {
    __testing.resetCache();
  });

  it("preserves the canonical-message fixture SHA verbatim when it appears in a log line", async () => {
    await installLogSanitizer(TEST_KEY_MATERIAL, []);
    const logLine = `canonical fixture digest ${CANONICAL_FIXTURE_SHA256} matches`;
    const sanitised = __testing.sanitiseStringSync(logLine);
    expect(sanitised).toBe(logLine);
 // Belt-and-braces: redaction marker must NOT appear anywhere.
    expect(sanitised).not.toContain("[REDACTED");
  });

  it("preserves the fixture SHA in async path as well", async () => {
    await installLogSanitizer(TEST_KEY_MATERIAL, []);
    const logLine = `fixture=${CANONICAL_FIXTURE_SHA256}`;
    const sanitised = await __testing.sanitiseStringAsync(logLine);
    expect(sanitised).toBe(logLine);
  });

  it("is case-insensitive on the allowlist match", async () => {
    await installLogSanitizer(TEST_KEY_MATERIAL, []);
    const upper = CANONICAL_FIXTURE_SHA256.toUpperCase();
    const logLine = `fixture=${upper}`;
    const sanitised = __testing.sanitiseStringSync(logLine);
    expect(sanitised).toBe(logLine);
  });

  it("still redacts unrelated 64-char hex strings (non-regression)", async () => {
    await installLogSanitizer(TEST_KEY_MATERIAL, [UNRELATED_HEX32]);
    const sanitised = __testing.sanitiseStringSync(
      `hmac tag ${UNRELATED_HEX32} leaked`,
    );
    expect(sanitised).not.toContain(UNRELATED_HEX32);
    expect(sanitised).toMatch(/\[REDACTED(:[0-9a-f]{8})?\]/);
  });

  it("redacts the surrounding secret material even when the fixture SHA shares a log line", async () => {
    await installLogSanitizer(TEST_KEY_MATERIAL, [UNRELATED_HEX32]);
    const logLine = `fixture=${CANONICAL_FIXTURE_SHA256} hmac=${UNRELATED_HEX32}`;
    const sanitised = __testing.sanitiseStringSync(logLine);
    expect(sanitised).toContain(CANONICAL_FIXTURE_SHA256);
    expect(sanitised).not.toContain(UNRELATED_HEX32);
  });
});

describe("log-sanitizer INVARIANT-DSGW-1 canary", () => {
  beforeEach(() => {
    __testing.resetCache();
  });

  it("emits exactly one warning per unique unregistered b64url256 value seen by the sync redactor", async () => {
 // Install with NO known secrets; this simulates the regression
 // shape: a bootstrap-cred-shaped value reaches the redactor before
 // `markDocsBootstrapCredentialAsKnown` ran.
    await installLogSanitizer(TEST_KEY_MATERIAL, []);

 // 43-char base64url, never registered with the tag cache. Same shape
 // as a real `register-test-origin` HMAC secret.
    const unregisteredCredential = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG";
    expect(unregisteredCredential.length).toBe(43);

    const warnSpy = vi
      .spyOn(console, "warn")
      .mockImplementation(() => {
        /* swallow during test */
      });

 // First sync redaction: canary fires.
    const out1 = __testing.sanitiseStringSync(
      `secret=${unregisteredCredential} leaked`,
    );
    expect(out1).not.toContain(unregisteredCredential);
    expect(__testing.canaryEmittedCount()).toBe(1);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0]?.[0]).toContain("INVARIANT-DSGW-1");

 // Second sync redaction with the SAME value: canary deduped.
    const out2 = __testing.sanitiseStringSync(
      `secret=${unregisteredCredential} leaked again`,
    );
    expect(out2).not.toContain(unregisteredCredential);
    expect(__testing.canaryEmittedCount()).toBe(1);
    expect(warnSpy).toHaveBeenCalledTimes(1);

    warnSpy.mockRestore();
  });

  it("does not fire the canary when the b64url256 value is registered before redaction", async () => {
    const registeredCredential = "ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210ZyXwVuT";
    expect(registeredCredential.length).toBe(43);

 // Pre-register: the install primer puts the value in the tag cache,
 // mirroring what `markDocsBootstrapCredentialAsKnown` does at runtime.
    await installLogSanitizer(TEST_KEY_MATERIAL, [registeredCredential]);

    const warnSpy = vi
      .spyOn(console, "warn")
      .mockImplementation(() => {
        /* swallow during test */
      });

    const sanitised = __testing.sanitiseStringSync(
      `secret=${registeredCredential} did not leak`,
    );
    expect(sanitised).toMatch(/\[REDACTED:[0-9a-f]{8}\]/);
    expect(__testing.canaryEmittedCount()).toBe(0);
    expect(warnSpy).not.toHaveBeenCalled();

    warnSpy.mockRestore();
  });

  it("fires the INVARIANT-DSGW-2 canary on an unregistered lowercase hex32 value (mobile sandbox mint shape)", async () => {
 // 64-char lowercase hex matches the canonical `randomHex(32)` output
 // shape used by `handleMobileSandboxRegister` to mint per-install
 // HMAC secrets. An unregistered value of this shape reaching the
 // sync redactor means a future refactor likely dropped one of the
 // `markMobileSandboxSecretAsKnown` hooks in `mobile-sandbox.ts`,
 // so the canary fires and names the specific invariant.
    await installLogSanitizer(TEST_KEY_MATERIAL, []);
    const warnSpy = vi
      .spyOn(console, "warn")
      .mockImplementation(() => {
        /* swallow */
      });
    const hexValue = "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef";
    const sanitised = __testing.sanitiseStringSync(`tag=${hexValue}`);
    expect(sanitised).not.toContain(hexValue);
    expect(__testing.canaryEmittedCount()).toBe(1);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0]?.[0]).toContain("INVARIANT-DSGW-2");
    expect(warnSpy.mock.calls[0]?.[0]).toContain("mobile-sandbox-secret-shaped");
    warnSpy.mockRestore();
  });

  it("does not fire the canary on a value that matches neither shape (uppercase hex32)", async () => {
 // Uppercase hex matches the generic `hex32` redaction pattern but
 // NOT the lowercase-only `MOBILE_SBX_SECRET_SHAPE` discriminator;
 // it also fails the b64url256 shape (`=` pad, length, alphabet).
 // The canary therefore stays silent. A genuine mint can never
 // produce uppercase output (`randomHex` lowercases) so this branch
 // protects against a callsite logging an unrelated SHA-256 hex
 // digest emitted upper-case (e.g., a Java `Hex.encode(...)` print)
 // and tripping the canary on noise.
    await installLogSanitizer(TEST_KEY_MATERIAL, []);
    const warnSpy = vi
      .spyOn(console, "warn")
      .mockImplementation(() => {
        /* swallow */
      });
    const upperHex = "DEADBEEFCAFEBABE0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    const sanitised = __testing.sanitiseStringSync(`tag=${upperHex}`);
    expect(sanitised).not.toContain(upperHex);
    expect(__testing.canaryEmittedCount()).toBe(0);
    expect(warnSpy).not.toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  it("fires the INVARIANT-DSGW-2 canary exactly once per unique unregistered hex32 value (dedup)", async () => {
 // Same dedup contract as the b64url256 path: the canary must alert
 // on a regression but must not spam the warning stream when the
 // same offending value shows up many times in one isolate.
    await installLogSanitizer(TEST_KEY_MATERIAL, []);
    const warnSpy = vi
      .spyOn(console, "warn")
      .mockImplementation(() => {
        /* swallow */
      });
    const hexValue = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    __testing.sanitiseStringSync(`first=${hexValue}`);
    __testing.sanitiseStringSync(`second=${hexValue}`);
    __testing.sanitiseStringSync(`third=${hexValue}`);
    expect(__testing.canaryEmittedCount()).toBe(1);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    warnSpy.mockRestore();
  });
});
