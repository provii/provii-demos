// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Android Hardware Key Attestation verifier tests (.7).
 *
 * Synthetic test vectors. Real-device validation (Pixel 8 dev build)
 * is a post-merge internal smoke test tracked in the report.
 *
 * Every ASN.1 byte layout below is derived from the authoritative
 * AOSP source:
 *
 * - Top-level KeyDescription SEQUENCE:
 * android.googlesource.com/platform/hardware/interfaces/+/
 * refs/heads/main/security/keymint/aidl/android/hardware/
 * security/keymint/KeyDescription.aidl (canonical location
 * in the KeyMint tree, schema unchanged since KeyMint v1).
 * - RootOfTrust SEQUENCE fields + tag numbers:
 * developer.android.com/training/articles/security-key-attestation
 * - AuthorizationList tag numbers (704, 709):
 * android.googlesource.com/platform/hardware/interfaces/+/
 * refs/heads/main/security/keymint/aidl/android/hardware/
 * security/keymint/Tag.aidl
 *
 * We exercise the KeyDescription ASN.1 parser end-to-end against
 * synthetic extnValue blobs; the chain-walk branch is covered by
 * the app-attest tests (same x509 module) and the real pinned root
 * path is gated on the device sample.
 */

import { describe, expect, it } from "vitest";

import {
  ALLOWED_SELF_SIGNED_OS_KEYS,
  assertVerifiedBootPolicy,
  GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64_SET,
  GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_SHA256,
  isAllowedSelfSignedOsKey,
  parseKeyDescription,
  SECURITY_LEVEL_SOFTWARE,
  SECURITY_LEVEL_STRONG_BOX,
  SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
  VERIFIED_BOOT_STATE_FAILED,
  VERIFIED_BOOT_STATE_SELF_SIGNED,
  VERIFIED_BOOT_STATE_UNVERIFIED,
  VERIFIED_BOOT_STATE_VERIFIED,
  verifyKeyAttestation,
  verifyPinnedRootsIntegrity,
  OID_KEY_ATTESTATION,
  type RootOfTrust,
} from "../attestation/key-attestation";

// ---- Minimal DER builder ------------------------------------------

/**
 * Write the tag + length prefix followed by a content buffer. Length
 * encoding follows DER rules (short form under 128 bytes, long form
 * with a leading byte count above). Only lengths < 65536 supported
 * because none of our test vectors come close.
 */
function tlv(tag: number, content: Uint8Array): Uint8Array {
  let lengthBytes: number[];
  if (content.length < 0x80) {
    lengthBytes = [content.length];
  } else if (content.length < 0x100) {
    lengthBytes = [0x81, content.length];
  } else {
    lengthBytes = [0x82, (content.length >> 8) & 0xff, content.length & 0xff];
  }
  const out = new Uint8Array(1 + lengthBytes.length + content.length);
  out[0] = tag;
  out.set(lengthBytes, 1);
  out.set(content, 1 + lengthBytes.length);
  return out;
}

function integer(value: number): Uint8Array {
  if (value < 0 || value > 255) {
    throw new Error("test-der: only 0..255 integers supported");
  }
 // Two's-complement: if the top bit is set we need a leading 0x00.
  if (value === 0) return tlv(0x02, new Uint8Array([0x00]));
  if (value < 0x80) return tlv(0x02, new Uint8Array([value]));
  return tlv(0x02, new Uint8Array([0x00, value]));
}

function enumerated(value: number): Uint8Array {
  return tlv(0x0a, new Uint8Array([value]));
}

function octetString(bytes: Uint8Array): Uint8Array {
  return tlv(0x04, bytes);
}

function boolean(value: boolean): Uint8Array {
  return tlv(0x01, new Uint8Array([value ? 0xff : 0x00]));
}

function sequence(...items: Uint8Array[]): Uint8Array {
  return tlv(0x30, concat(...items));
}

function concat(...items: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const b of items) total += b.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const b of items) {
    out.set(b, offset);
    offset += b.length;
  }
  return out;
}

// ---- RootOfTrust + AuthorizationList builders ---------------------

interface RootOfTrustInput {
  verifiedBootKey: Uint8Array;
  deviceLocked: boolean;
  verifiedBootState: number;
  verifiedBootHash: Uint8Array;
}

function buildRootOfTrust(input: RootOfTrustInput): Uint8Array {
  return sequence(
    octetString(input.verifiedBootKey),
    boolean(input.deviceLocked),
    enumerated(input.verifiedBootState),
    octetString(input.verifiedBootHash),
  );
}

interface AuthListInput {
  rootOfTrust?: RootOfTrustInput;
  attestationApplicationId?: Uint8Array;
}

// Builds the authorisation list using the high-tag-number long form
// for tag 704 (constructed) and tag 709 (primitive) so the ASN.1
// parser exercises the same path real Android keymint extensions use.
function buildAuthorizationListWithTag704Long(input: AuthListInput): Uint8Array {
  const parts: Uint8Array[] = [];
  if (input.rootOfTrust !== undefined) {
    parts.push(longFormConstructed(704, buildRootOfTrust(input.rootOfTrust)));
  }
  if (input.attestationApplicationId !== undefined) {
    parts.push(longFormPrimitive(709, input.attestationApplicationId));
  }
  return sequence(...parts);
}

function longFormConstructed(tagNumber: number, content: Uint8Array): Uint8Array {
 // constructed + context-specific + high-tag
  const highBits = encodeBase128(tagNumber);
  const header = new Uint8Array([0xbf, ...highBits]);
  return concatWithLength(header, content);
}

function longFormPrimitive(tagNumber: number, content: Uint8Array): Uint8Array {
 // primitive + context-specific + high-tag
  const highBits = encodeBase128(tagNumber);
  const header = new Uint8Array([0x9f, ...highBits]);
  return concatWithLength(header, content);
}

function concatWithLength(header: Uint8Array, content: Uint8Array): Uint8Array {
  let lengthBytes: number[];
  if (content.length < 0x80) {
    lengthBytes = [content.length];
  } else if (content.length < 0x100) {
    lengthBytes = [0x81, content.length];
  } else {
    lengthBytes = [0x82, (content.length >> 8) & 0xff, content.length & 0xff];
  }
  const out = new Uint8Array(header.length + lengthBytes.length + content.length);
  out.set(header, 0);
  out.set(lengthBytes, header.length);
  out.set(content, header.length + lengthBytes.length);
  return out;
}

function encodeBase128(value: number): number[] {
  if (value < 0x80) return [value];
  const out: number[] = [];
  let remaining = value;
  while (remaining > 0) {
    out.unshift((remaining & 0x7f) | 0x80);
    remaining >>= 7;
  }
 // Last byte (low order) must not have the continuation bit set.
  out[out.length - 1]! &= 0x7f;
  return out;
}

// ---- KeyDescription builder ---------------------------------------

interface KeyDescInput {
  attestationVersion: number;
  attestationSecurityLevel: number;
  keymasterVersion: number;
  keymasterSecurityLevel: number;
  attestationChallenge: Uint8Array;
  uniqueId?: Uint8Array;
  softwareEnforced: AuthListInput;
  hardwareEnforced: AuthListInput;
}

function buildKeyDescription(input: KeyDescInput): Uint8Array {
  return sequence(
    integer(input.attestationVersion),
    enumerated(input.attestationSecurityLevel),
    integer(input.keymasterVersion),
    enumerated(input.keymasterSecurityLevel),
    octetString(input.attestationChallenge),
    octetString(input.uniqueId ?? new Uint8Array(0)),
    buildAuthorizationListWithTag704Long(input.softwareEnforced),
    buildAuthorizationListWithTag704Long(input.hardwareEnforced),
  );
}

// ---- Tests: KeyDescription parser ---------------------------------

describe("KeyDescription parser", () => {
  it("round-trips the fields we care about", () => {
    const challenge = new Uint8Array([1, 2, 3, 4, 5]);
    const blob = buildKeyDescription({
      attestationVersion: 4,
      attestationSecurityLevel: SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
      keymasterVersion: 41,
      keymasterSecurityLevel: SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
      attestationChallenge: challenge,
      softwareEnforced: {},
      hardwareEnforced: {
        rootOfTrust: {
          verifiedBootKey: new Uint8Array(32).fill(0xab),
          deviceLocked: true,
          verifiedBootState: VERIFIED_BOOT_STATE_VERIFIED,
          verifiedBootHash: new Uint8Array(32).fill(0xcd),
        },
      },
    });
    const parsed = parseKeyDescription(blob);
    expect(parsed.attestationVersion).toBe(4);
    expect(parsed.attestationSecurityLevel).toBe(SECURITY_LEVEL_TRUSTED_ENVIRONMENT);
    expect(parsed.keymasterVersion).toBe(41);
    expect(parsed.keymasterSecurityLevel).toBe(SECURITY_LEVEL_TRUSTED_ENVIRONMENT);
    expect(Array.from(parsed.attestationChallenge)).toEqual(Array.from(challenge));
    expect(parsed.hardwareEnforced.rootOfTrust).not.toBeNull();
    expect(parsed.hardwareEnforced.rootOfTrust!.deviceLocked).toBe(true);
    expect(parsed.hardwareEnforced.rootOfTrust!.verifiedBootState).toBe(
      VERIFIED_BOOT_STATE_VERIFIED,
    );
  });

  it("handles an authorisation list with no rootOfTrust", () => {
    const blob = buildKeyDescription({
      attestationVersion: 4,
      attestationSecurityLevel: SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
      keymasterVersion: 41,
      keymasterSecurityLevel: SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
      attestationChallenge: new Uint8Array([0x42]),
      softwareEnforced: {},
      hardwareEnforced: {},
    });
    const parsed = parseKeyDescription(blob);
    expect(parsed.hardwareEnforced.rootOfTrust).toBeNull();
  });

  it("surfaces the attestationApplicationId raw bytes", () => {
    const appIdBytes = new TextEncoder().encode("com.provii.wallet");
    const blob = buildKeyDescription({
      attestationVersion: 4,
      attestationSecurityLevel: SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
      keymasterVersion: 41,
      keymasterSecurityLevel: SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
      attestationChallenge: new Uint8Array([0x42]),
      softwareEnforced: { attestationApplicationId: appIdBytes },
      hardwareEnforced: {},
    });
    const parsed = parseKeyDescription(blob);
    expect(parsed.softwareEnforced.attestationApplicationIdRaw).not.toBeNull();
    expect(
      new TextDecoder().decode(
        parsed.softwareEnforced.attestationApplicationIdRaw!,
      ),
    ).toBe("com.provii.wallet");
  });

  it("rejects a malformed KeyDescription", () => {
    const bogus = new Uint8Array([0x30, 0x01, 0x02]); // SEQUENCE { INTEGER }
    expect(() => parseKeyDescription(bogus)).toThrow();
  });
});

// ---- Tests: verifyKeyAttestation config posture -------------------

describe("verifyKeyAttestation config posture", () => {
  it("returns an error when pinnedRootDerBase64 is empty", async () => {
    await expect(
      verifyKeyAttestation([new Uint8Array(10), new Uint8Array(10)], {
        challenge: new Uint8Array(32),
        pinnedRootDerBase64: "",
      }),
    ).rejects.toThrow(/no pinned Google root configured/);
  });

  it("rejects chains with fewer than 2 certs", async () => {
    await expect(
      verifyKeyAttestation([new Uint8Array(10)], {
        challenge: new Uint8Array(32),
        pinnedRootDerBase64: "ZHVtbXk=", // base64("dummy")
      }),
    ).rejects.toThrow(/chain must have/);
  });
});

describe("OID + security-level constants", () => {
  it("Google Attestation extension OID matches AOSP docs", () => {
    expect(OID_KEY_ATTESTATION).toBe("1.3.6.1.4.1.11129.2.1.17");
  });

  it("SOFTWARE is distinct from TRUSTED_ENVIRONMENT and STRONG_BOX", () => {
    expect(SECURITY_LEVEL_SOFTWARE).toBe(0);
    expect(SECURITY_LEVEL_TRUSTED_ENVIRONMENT).toBe(1);
    expect(SECURITY_LEVEL_STRONG_BOX).toBe(2);
  });

  it("boot-state enum constants match AOSP", () => {
    expect(VERIFIED_BOOT_STATE_VERIFIED).toBe(0);
    expect(VERIFIED_BOOT_STATE_SELF_SIGNED).toBe(1);
    expect(VERIFIED_BOOT_STATE_UNVERIFIED).toBe(2);
    expect(VERIFIED_BOOT_STATE_FAILED).toBe(3);
  });
});

// ---- Tests: self-signed OS allowlist ------------------------------
//
// `isAllowedSelfSignedOsKey` accepts raw bytes; the allowlist entries
// are lowercase hex. We exercise one representative GrapheneOS key
// (Pixel 8, a dev device) and a incident vector.

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}

const GRAPHENEOS_PIXEL_8_KEY_HEX =
  "cd7479653aa88208f9f03034810ef9b7b0af8a9d41e2000e458ac403a2acb233";

describe("ALLOWED_SELF_SIGNED_OS_KEYS", () => {
  it("contains the current GrapheneOS Pixel 8 verified boot key", () => {
 // Regression guard. If this digest moves, pull the latest from
 // https://grapheneos.org/attestation.json
 // and update in lockstep.
    expect(ALLOWED_SELF_SIGNED_OS_KEYS).toContain(GRAPHENEOS_PIXEL_8_KEY_HEX);
  });

  it("contains only lowercase 32-byte (64-hex-char) digests", () => {
    for (const entry of ALLOWED_SELF_SIGNED_OS_KEYS) {
      expect(entry.length).toBe(64);
      expect(entry).toBe(entry.toLowerCase());
      expect(/^[0-9a-f]+$/.test(entry)).toBe(true);
    }
  });

  it("has no duplicate entries", () => {
    const seen = new Set(ALLOWED_SELF_SIGNED_OS_KEYS);
    expect(seen.size).toBe(ALLOWED_SELF_SIGNED_OS_KEYS.length);
  });
});

describe("isAllowedSelfSignedOsKey", () => {
  it("accepts the GrapheneOS Pixel 8 key", () => {
    const key = hexToBytes(GRAPHENEOS_PIXEL_8_KEY_HEX);
    expect(isAllowedSelfSignedOsKey(key)).toBe(true);
  });

  it("rejects a 32-byte key that is not on the list", () => {
    const key = new Uint8Array(32).fill(0xaa);
    expect(isAllowedSelfSignedOsKey(key)).toBe(false);
  });

  it("rejects a key that differs by a single byte from a known entry", () => {
    const key = hexToBytes(GRAPHENEOS_PIXEL_8_KEY_HEX);
    key[0] = (key[0]! ^ 0x01) & 0xff;
    expect(isAllowedSelfSignedOsKey(key)).toBe(false);
  });

  it("rejects a key of the wrong length", () => {
    const short = hexToBytes(GRAPHENEOS_PIXEL_8_KEY_HEX).slice(0, 16);
    expect(isAllowedSelfSignedOsKey(short)).toBe(false);
  });

  it("rejects an empty key", () => {
    expect(isAllowedSelfSignedOsKey(new Uint8Array(0))).toBe(false);
  });
});

// ---- Tests: assertVerifiedBootPolicy ------------------------------

function makeRootOfTrust(overrides: Partial<RootOfTrust> = {}): RootOfTrust {
  return {
    verifiedBootKey: new Uint8Array(32).fill(0x00),
    deviceLocked: true,
    verifiedBootState: VERIFIED_BOOT_STATE_VERIFIED,
    verifiedBootHash: new Uint8Array(32).fill(0xcd),
    ...overrides,
  };
}

describe("assertVerifiedBootPolicy", () => {
  it("accepts VERIFIED + deviceLocked (Google-signed stock Android)", () => {
    expect(() => assertVerifiedBootPolicy(makeRootOfTrust())).not.toThrow();
  });

  it("accepts SELF_SIGNED + allowlisted GrapheneOS key + deviceLocked", () => {
    const rot = makeRootOfTrust({
      verifiedBootState: VERIFIED_BOOT_STATE_SELF_SIGNED,
      verifiedBootKey: hexToBytes(GRAPHENEOS_PIXEL_8_KEY_HEX),
    });
    expect(() => assertVerifiedBootPolicy(rot)).not.toThrow();
  });

  it("rejects SELF_SIGNED with an unknown key and surfaces the hex + allowlist in the error", () => {
    const rot = makeRootOfTrust({
      verifiedBootState: VERIFIED_BOOT_STATE_SELF_SIGNED,
      verifiedBootKey: new Uint8Array(32).fill(0x11),
    });
    try {
      assertVerifiedBootPolicy(rot);
      throw new Error("expected assertVerifiedBootPolicy to throw");
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).toMatch(/SELF_SIGNED/);
      expect(msg).toMatch(/ALLOWED_SELF_SIGNED_OS_KEYS/);
      expect(msg).toMatch(/1111111111111111111111111111111111111111111111111111111111111111/);
    }
  });

  it("rejects UNVERIFIED boot state regardless of verifiedBootKey", () => {
    const rot = makeRootOfTrust({
      verifiedBootState: VERIFIED_BOOT_STATE_UNVERIFIED,
 // Even if the key happens to be on the allowlist, UNVERIFIED
 // must never be accepted; the allowlist only promotes SELF_SIGNED.
      verifiedBootKey: hexToBytes(GRAPHENEOS_PIXEL_8_KEY_HEX),
    });
    expect(() => assertVerifiedBootPolicy(rot)).toThrow(
      /verifiedBootState 2 is not accepted/,
    );
  });

  it("rejects FAILED boot state regardless of verifiedBootKey", () => {
    const rot = makeRootOfTrust({
      verifiedBootState: VERIFIED_BOOT_STATE_FAILED,
      verifiedBootKey: hexToBytes(GRAPHENEOS_PIXEL_8_KEY_HEX),
    });
    expect(() => assertVerifiedBootPolicy(rot)).toThrow(
      /verifiedBootState 3 is not accepted/,
    );
  });

  it("rejects VERIFIED if the device bootloader is unlocked", () => {
    const rot = makeRootOfTrust({ deviceLocked: false });
    expect(() => assertVerifiedBootPolicy(rot)).toThrow(/device is not locked/);
  });

  it("rejects SELF_SIGNED + allowlisted key if the device bootloader is unlocked", () => {
    const rot = makeRootOfTrust({
      verifiedBootState: VERIFIED_BOOT_STATE_SELF_SIGNED,
      verifiedBootKey: hexToBytes(GRAPHENEOS_PIXEL_8_KEY_HEX),
      deviceLocked: false,
    });
    expect(() => assertVerifiedBootPolicy(rot)).toThrow(/device is not locked/);
  });

  it("rejects an unrecognised boot-state integer (future KeyMint values)", () => {
 // KeyMint currently defines 0..3. If AOSP adds a new state in the
 // future (4, 5, ...) the verifier must reject-by-default, never
 // silent-accept. Even with an allowlisted key the outer else branch
 // should catch and throw.
    const rot = makeRootOfTrust({
      verifiedBootState: 4,
      verifiedBootKey: hexToBytes(GRAPHENEOS_PIXEL_8_KEY_HEX),
    });
    expect(() => assertVerifiedBootPolicy(rot)).toThrow(
      /verifiedBootState 4 is not accepted/,
    );
  });
});

// ---- Tests: pinned-root DER integrity () ---------------------
//
// The module-default pinned root set carries an authoritative SHA-256
// fingerprint alongside each DER literal. `verifyPinnedRootsIntegrity`
// must:
// - confirm the two constants are in lockstep,
// - base64-decode every entry without error,
// - parse each as DER X.509 without error,
// - fingerprint the DER and byte-match the expected hex.
// The assertion runs once per isolate as the first step inside
// `verifyKeyAttestation`; dedicated tests exercise it in isolation so
// a DER drift surfaces as a specific failure rather than an
// opaque "chain root does not match" from the downstream walker.

describe("pinned Google Hardware Attestation roots (AR-K2)", () => {
  it("has the DER set and SHA-256 set the same length", () => {
    expect(GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64_SET.length).toBe(
      GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_SHA256.length,
    );
 // The current set is 2 entries (EC P-384 CA1 + RSA-4096 2022).
 // A count drift means the pin rotated and one of the two consts
 // was updated without the other.
    expect(GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64_SET.length).toBe(2);
  });

  it("every entry has a 64-char lowercase hex fingerprint", () => {
    for (const entry of GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_SHA256) {
      expect(entry.length).toBe(64);
      expect(entry).toBe(entry.toLowerCase());
      expect(/^[0-9a-f]+$/.test(entry)).toBe(true);
    }
  });

  it("carries the authoritative fingerprints Tim captured on 2026-04-22", () => {
 // If Google rotates the root set, this test fails loudly and the
 // operator updates both the DER and the fingerprint in lockstep.
 // See the rotation note at the bottom of key-attestation.ts.
    expect(GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_SHA256[0]).toBe(
      "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0",
    );
    expect(GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_SHA256[1]).toBe(
      "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc",
    );
  });

  it("verifyPinnedRootsIntegrity resolves for the shipped set", async () => {
 // End-to-end sanity: decode, parse, digest, compare. If any link
 // breaks the promise rejects with a specific error identifying
 // the bad entry.
    await expect(verifyPinnedRootsIntegrity()).resolves.toBeUndefined();
  });
});

// ---- Tests: parser still routes SELF_SIGNED through correctly -----

describe("KeyDescription parser (SELF_SIGNED regression)", () => {
  it("decodes SELF_SIGNED + GrapheneOS key inside a full KeyDescription", () => {
    const challenge = new Uint8Array([9, 9, 9]);
    const grapheneKey = hexToBytes(GRAPHENEOS_PIXEL_8_KEY_HEX);
    const blob = buildKeyDescription({
      attestationVersion: 4,
      attestationSecurityLevel: SECURITY_LEVEL_STRONG_BOX,
      keymasterVersion: 41,
      keymasterSecurityLevel: SECURITY_LEVEL_STRONG_BOX,
      attestationChallenge: challenge,
      softwareEnforced: {},
      hardwareEnforced: {
        rootOfTrust: {
          verifiedBootKey: grapheneKey,
          deviceLocked: true,
          verifiedBootState: VERIFIED_BOOT_STATE_SELF_SIGNED,
          verifiedBootHash: new Uint8Array(32).fill(0x00),
        },
      },
    });
    const parsed = parseKeyDescription(blob);
    const rot = parsed.hardwareEnforced.rootOfTrust;
    expect(rot).not.toBeNull();
    expect(rot!.verifiedBootState).toBe(VERIFIED_BOOT_STATE_SELF_SIGNED);
    expect(Array.from(rot!.verifiedBootKey)).toEqual(Array.from(grapheneKey));
 // And the policy function should accept it end-to-end.
    expect(() => assertVerifiedBootPolicy(rot!)).not.toThrow();
  });
});
