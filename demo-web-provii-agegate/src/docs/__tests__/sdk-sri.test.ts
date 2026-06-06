// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

/**
 * Unit tests for the build-time SRI generated constants.
 *
 * The bug these tests guard against: the playground snippet emitted at
 * /playground/api/create-environment embedded a hard-coded SRI string. When
 * the SDK at the pinned version was rotated on the CDN, the SRI went stale
 * and every developer who pasted the snippet onto a real site got their
 * script blocked by the browser.
 *
 * Two layers of defence are exercised here:
 * 1. Format invariants on the generated constants (catches obvious
 * corruption from a regen script bug, partial writes, missing regen).
 * 2. URL/version coherence (catches drift between the version pin and
 * the URL the SRI was computed from).
 *
 * The build-time `verify:sdk-sri` script catches drift between the
 * generated file and the live CDN. This test catches drift inside the
 * generated file itself. Cross-file consistency between the generated
 * constants and every emit site is enforced by the regen script's
 * --check mode (run as `npm run verify:sdk-sri`, gated in `prebuild`).
 */

import { describe, expect, it } from "vitest";

import { SDK_SRI_HASH, SDK_URL, SDK_VERSION } from "../../generated/sdk-sri";

describe("provii-agegate SRI build-time generation", () => {
  it("SDK_SRI_HASH is a well-formed sha384 SRI", () => {
 // sha384 is 48 bytes, which encodes to 64 base64 chars (no padding).
 // Reject anything that doesn't match exactly so a partial or truncated
 // value cannot ship.
    expect(SDK_SRI_HASH).toMatch(/^sha384-[A-Za-z0-9+/]{64}$/);
  });

  it("SDK_VERSION is a vX.Y.Z pin", () => {
    expect(SDK_VERSION).toMatch(/^v\d+\.\d+\.\d+$/);
  });

  it("SDK_URL points at the CDN at the pinned version", () => {
    expect(SDK_URL).toBe(
      `https://cdn.provii.app/sdk/provii-agegate/${SDK_VERSION}/agegate.browser.js`,
    );
  });
});
