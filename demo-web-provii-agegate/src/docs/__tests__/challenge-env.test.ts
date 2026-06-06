// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * + : gateway ChallengePayload env-field contract tests.
 *
 * The docs gateway's `POST /api/challenge` response body is consumed by two
 * downstream surfaces: the docs widget (TestInWallet.astro) that forwards the
 * payload into the base64url-encoded deeplink JSON, and the provii-mobile
 * `ChallengePayload` parser (the mobile owner, provii-mobile main at 77d5c5df, 
 * handshake on provii-mobile-w14 WIP). Both sides treat `environment` as a
 * REQUIRED field; absence is a protocol violation.
 *
 * These tests lock the runtime schema contract so a regression that drops the
 * field or writes a wrong value fails here loudly instead of shipping a body
 * the wallet will reject on the far side of the deeplink.
 */

import { describe, expect, it } from "vitest";

import { ChallengeOkBodySchema } from "../challenge";

// A well-formed UUIDv4 that satisfies the challenge_id regex.
const VALID_CHALLENGE_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
const VALID_SHORT_CODE = "ABCDEF123456";

describe("W14-4.18: ChallengeOkBodySchema env field", () => {
  it("accepts a body where environment is the literal 'sandbox'", () => {
    const result = ChallengeOkBodySchema.safeParse({
      environment: "sandbox",
      challenge_id: VALID_CHALLENGE_ID,
      short_code: VALID_SHORT_CODE,
      expires_at: 1_800_000_000_000,
      upstream: { rp_challenge: "deadbeef", submit_secret: "ss_abc" },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.environment).toBe("sandbox");
    }
  });

  it("rejects a body that omits the environment field", () => {
    const result = ChallengeOkBodySchema.safeParse({
      challenge_id: VALID_CHALLENGE_ID,
      short_code: VALID_SHORT_CODE,
      expires_at: 1_800_000_000_000,
      upstream: {},
    });
    expect(result.success).toBe(false);
    if (!result.success) {
 // Zod surfaces the missing field on the `environment` path. The wallet
 // parses this exact shape and refuses the payload; the gateway must
 // refuse first so we never ship a body the wallet will reject.
      const paths = result.error.issues.map((i) => i.path.join("."));
      expect(paths).toContain("environment");
    }
  });

  it("rejects a body where environment is 'production'", () => {
 // The docs gateway is sandbox-only by construction (). A
 // production emit would be a severe bug: the widget would forward it to
 // the wallet, which would open a production verification flow against a
 // sandbox-provisioned issuer. Lock the literal here.
    const result = ChallengeOkBodySchema.safeParse({
      environment: "production",
      challenge_id: VALID_CHALLENGE_ID,
      short_code: VALID_SHORT_CODE,
      expires_at: 1_800_000_000_000,
      upstream: {},
    });
    expect(result.success).toBe(false);
  });

  it("rejects a body where environment is any other string", () => {
    const result = ChallengeOkBodySchema.safeParse({
      environment: "staging",
      challenge_id: VALID_CHALLENGE_ID,
      short_code: VALID_SHORT_CODE,
      expires_at: 1_800_000_000_000,
      upstream: {},
    });
    expect(result.success).toBe(false);
  });

  it("rejects a body where environment is a non-string type", () => {
    const result = ChallengeOkBodySchema.safeParse({
      environment: 1,
      challenge_id: VALID_CHALLENGE_ID,
      short_code: VALID_SHORT_CODE,
      expires_at: 1_800_000_000_000,
      upstream: {},
    });
    expect(result.success).toBe(false);
  });
});
