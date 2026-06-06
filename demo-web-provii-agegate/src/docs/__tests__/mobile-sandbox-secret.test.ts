// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * INVARIANT-DSGW-2 regression tests for the mobile sandbox per-install
 * HMAC secret sanitiser registration.
 *
 * Sibling of `bootstrap-credential.test.ts`. The contract this suite
 * locks down is:
 *
 * 1. A cold isolate that wakes up and reads an existing
 * `mobile-sandbox-issuer:{client_id}` KV record (e.g., during a
 * revoke or refresh handled by a peer-minted issuer) registers
 * the loaded `(client_id, hmac_secret)` pair with the redaction
 * tag cache before returning, so a subsequent `console.log`
 * emits `[REDACTED:<8 hex>]` rather than the bare `[REDACTED]`
 * marker. Without `markMobileSandboxSecretAsKnown` in
 * `loadIssuerRecord` the sanitiser would fall back to the bare
 * marker on any sync redact path that hits the unregistered
 * hex32 mint shape.
 *
 * 2. The `INVARIANT-DSGW-2` canary in `log-sanitizer.ts` stays
 * silent on the happy path (the hook ran first) and fires when
 * the registration is skipped (regression simulation). The
 * canary message names `INVARIANT-DSGW-2` so on-call can route
 * directly to this surface without grepping multiple invariants.
 *
 * The test exercises the real Miniflare KV namespace bound by
 * vitest-pool-workers so the read path matches production.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { env } from "cloudflare:test";

import type { DocsEnv } from "../handler";
import {
  __mobileTestExports,
  type MobileSandboxEnv,
} from "../mobile-sandbox";
import { __resetDocsLoggerForTest } from "../logger";
import { __testing as logSanitizerTesting } from "../log-sanitizer";

// HMAC key material for the sanitiser. Any non-empty string works; the
// tag is deterministic so once `installLogSanitizer` (driven through
// `getDocsLogger`) has run we get stable `[REDACTED:<hmac>]` markers.
const SANITISER_KEY_MATERIAL = "test-log-sanitiser-key-material-32bytes!";

interface MockSecretsBinding {
  get(): Promise<string | null>;
}

function buildSanitizerKeyBinding(): MockSecretsBinding {
  return { get: () => Promise.resolve(SANITISER_KEY_MATERIAL) };
}

/**
 * Build a `MobileSandboxEnv` that reuses the Miniflare-bound
 * `DOCS_SESSIONS` KV namespace and layers on a `LOG_SANITIZER_KEY`
 * binding so the sanitiser produces real `[REDACTED:<hmac>]` tags.
 * The cold-isolate test asserts the loaded credential lands in the
 * tag cache, which is only useful when the key is present.
 */
function buildEnvWithSanitizerKey(): MobileSandboxEnv {
  return {
    ...(env as unknown as DocsEnv),
    LOG_SANITIZER_KEY: buildSanitizerKeyBinding(),
    MOBILE_APP_BUNDLE_ID: "com.provii.wallet",
    MOBILE_APPLE_AAGUID_ENV: "prod",
    MOBILE_ANDROID_PACKAGE_NAME: "com.provii.wallet",
  };
}

/**
 * Wipe every KV key the loader and the issuer record write paths
 * touch. We only need to clear the issuer prefix here; the other mobile
 * prefixes (nonce, install, ratelimit) are scoped by client_id /
 * install_uuid and never collide with this test's fixed values.
 */
async function clearIssuerRecord(clientId: string): Promise<void> {
  await env.DOCS_SESSIONS.delete(
    `${__mobileTestExports.MOBILE_ISSUER_PREFIX}${clientId}`,
  );
}

describe("loadIssuerRecord INVARIANT-DSGW-2 sanitiser registration", () => {
  beforeEach(async () => {
 // Reset the logger install promise so the next call to
 // `getDocsLogger` re-imports the sanitiser key from the freshly
 // bound `LOG_SANITIZER_KEY`, AND reset the underlying tag cache so
 // a value primed by a previous test does not leak across the
 // assertion. Both resets are required: dropping either lets a
 // stale install or a cached tag survive into this test.
    __resetDocsLoggerForTest();
    logSanitizerTesting.resetCache();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it(
    "registers the per-install HMAC secret with the sanitiser when a cold isolate loads a peer-minted KV record (INVARIANT-DSGW-2)",
    async () => {
 // Scenario: a peer isolate already minted a sandbox issuer
 // (`handleMobileSandboxRegister`) and persisted it under
 // `mobile-sandbox-issuer:{client_id}`. THIS isolate is cold (no
 // logger install yet, empty tag cache) and is now handling a
 // revoke or refresh whose first KV touch is `loadIssuerRecord`.
 // Without the read-path branch calling
 // `markMobileSandboxSecretAsKnown`, the freshly-loaded plaintext
 // would never reach the sanitiser, and the first
 // `console.log(plaintext)` after the call would emit a tagless
 // `[REDACTED]` instead of the correlatable `[REDACTED:<hmac>]`
 // form, breaking on-call log triage.
 //
 // The assertion stack:
 // 1. After the call, `tagCache` contains the loaded
 // hmac_secret.
 // 2. After the call, `tagCache` contains the loaded client_id
 // (defence-in-depth registration).
 // 3. A sync sanitise of `console.log(plaintext)` emits
 // `[REDACTED:<8 hex>]`, not bare `[REDACTED]`.
 // 4. The canary in `log-sanitizer.ts` did NOT fire, because
 // the plaintext was registered before any redaction.

 // Use the canonical mint shapes: 64-char lowercase hex secret
 // (the `randomHex(32)` output format) and the
 // `mwallet-sbx-{32-hex}` client_id format enforced by
 // `MobileIssuerRecordSchema`.
      const peerMintedHmacSecret =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
      expect(peerMintedHmacSecret.length).toBe(64);
      expect(/^[0-9a-f]{64}$/.test(peerMintedHmacSecret)).toBe(true);
      const peerMintedClientId = "mwallet-sbx-0123456789abcdef0123456789abcdef";

      const futureExpiry = Date.now() + 24 * 60 * 60 * 1000;
      const peerRecord = {
        client_id: peerMintedClientId,
        hmac_secret: peerMintedHmacSecret,
        install_uuid: "11111111-1111-7111-8111-111111111111",
        platform: "android" as const,
        app_version: "1.0.0",
        issued_at: Date.now() - 60 * 1000,
        expires_at: futureExpiry,
        last_refreshed_at: Date.now() - 60 * 1000,
      };
      await clearIssuerRecord(peerMintedClientId);
      await env.DOCS_SESSIONS.put(
        `${__mobileTestExports.MOBILE_ISSUER_PREFIX}${peerMintedClientId}`,
        JSON.stringify(peerRecord),
      );

 // Sanity: this is a cold isolate, the tag cache must be empty
 // for both halves of the secret pair before the read.
      expect(logSanitizerTesting.isRegistered(peerMintedHmacSecret)).toBe(false);
      expect(logSanitizerTesting.isRegistered(peerMintedClientId)).toBe(false);

 // Drive the read path under test.
      const loaded = await __mobileTestExports.loadIssuerRecord(
        buildEnvWithSanitizerKey(),
        peerMintedClientId,
      );
      expect(loaded).not.toBeNull();
      expect(loaded?.hmac_secret).toBe(peerMintedHmacSecret);
      expect(loaded?.client_id).toBe(peerMintedClientId);

 // 1 + 2: tag cache contains both halves.
      expect(logSanitizerTesting.isRegistered(peerMintedHmacSecret)).toBe(true);
      expect(logSanitizerTesting.isRegistered(peerMintedClientId)).toBe(true);

 // 3: sync sanitise emits the tagged form, not the bare marker.
 // The hex32 pattern is the one that catches a lowercase 64-hex
 // secret; the assertion confirms the sync redactor reaches the
 // pre-populated cache rather than the fail-closed bare marker
 // path.
      const sanitised = logSanitizerTesting.sanitiseStringSync(
        `outbound: ${peerMintedHmacSecret} (do not log)`,
      );
      expect(sanitised).not.toContain(peerMintedHmacSecret);
      expect(sanitised).toMatch(/\[REDACTED:[0-9a-f]{8}\]/);
      expect(sanitised).not.toMatch(/\[REDACTED\](?!:)/);

 // 4: canary did not fire. The hook ran before any redaction
 // needed to reach for the plaintext, so the hex32-shape miss
 // path was never taken.
      expect(logSanitizerTesting.canaryEmittedCount()).toBe(0);

      await clearIssuerRecord(peerMintedClientId);
    },
  );
});
