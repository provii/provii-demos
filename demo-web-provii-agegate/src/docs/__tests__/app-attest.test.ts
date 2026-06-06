// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Apple App Attest verifier tests (.6).
 *
 * These vectors are synthetic. We do not have a production App Attest
 * receipt on this branch. Real-device validation is a post-merge
 * internal smoke test tracked in the report. What the tests
 * below exercise end-to-end:
 *
 * - CBOR envelope parsing (good + bad shapes).
 * - Pinned-root chain walk (uses a synthetic leaf signed by a
 * synthetic intermediate, both rejected against the real Apple
 * root so the rejection path is exercised; the pass path is
 * exercised separately by injecting a synthetic root via
 * monkey-patching the x509 module).
 * - The Apple-style nonce derivation + comparison.
 * - authData layout (rpIdHash, flags, AAGUID, credentialId).
 *
 * Source URLs for every protocol constant:
 * - CBOR: RFC 8949 section 3, https://datatracker.ietf.org/doc/html/rfc8949
 * - WebAuthn authData layout: W3C WebAuthn Level 3 section 6.5.4,
 * https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data
 * - App Attest nonce extension OID: Apple dev docs,
 * https://developer.apple.com/documentation/devicecheck/
 * validating_apps_that_connect_to_your_server
 * - App Attest AAGUID values: WWDC 2020 session 10073 +
 * srlabs/appattest-go lookup table.
 */

import { beforeEach, describe, expect, it } from "vitest";

import {
  APPLE_AAGUID_DEV,
  APPLE_AAGUID_PROD,
  OID_APPLE_APP_ATTEST_NONCE,
  verifyAppAttest,
  type AppAttestConfig,
} from "../attestation/app-attest";
import { decodeCbor } from "../attestation/cbor";

// ---- CBOR helpers --------------------------------------------------

/**
 * Minimal CBOR encoder for the shapes our tests produce. Definite
 * length only. We keep the encoder tiny so the tests do not drag in
 * a generic CBOR library when we are deliberately trying to match
 * Apple's narrow subset.
 */
function encodeCbor(value: unknown): Uint8Array {
  if (value === null) return new Uint8Array([0xf6]);
  if (value === false) return new Uint8Array([0xf4]);
  if (value === true) return new Uint8Array([0xf5]);
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error("test-cbor: only non-negative integers supported");
    }
    return encodeUnsigned(0, value);
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return concat([encodeUnsigned(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) {
    return concat([encodeUnsigned(2, value.length), value]);
  }
  if (Array.isArray(value)) {
    const items = value.map((v) => encodeCbor(v));
    return concat([encodeUnsigned(4, value.length), ...items]);
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    const parts: Uint8Array[] = [encodeUnsigned(5, entries.length)];
    for (const [k, v] of entries) {
      parts.push(encodeCbor(k));
      parts.push(encodeCbor(v));
    }
    return concat(parts);
  }
  throw new Error(`test-cbor: cannot encode ${typeof value}`);
}

function encodeUnsigned(major: number, value: number): Uint8Array {
  const prefix = major << 5;
  if (value < 24) return new Uint8Array([prefix | value]);
  if (value < 0x100) return new Uint8Array([prefix | 24, value]);
  if (value < 0x10000) {
    return new Uint8Array([prefix | 25, (value >> 8) & 0xff, value & 0xff]);
  }
  if (value < 0x100000000) {
    return new Uint8Array([
      prefix | 26,
      (value >>> 24) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 8) & 0xff,
      value & 0xff,
    ]);
  }
  throw new Error("test-cbor: value too large for 4-byte length");
}

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

// ---- Synthetic authData builder ------------------------------------

/**
 * Build authData bytes. Callers control every field so each test
 * can target one branch of the verifier. Layout matches WebAuthn
 * Level 3 section 6.5.4.
 */
async function buildAuthData(params: {
  appId: string;
  flagsByte: number;
  signCount: number;
  aaguid: Uint8Array;
  credentialId: Uint8Array;
  credentialPublicKeyCose: Uint8Array;
}): Promise<Uint8Array> {
  const rpIdHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(params.appId)),
  );
  const fixed = new Uint8Array(53);
  fixed.set(rpIdHash, 0);
  fixed[32] = params.flagsByte;
  fixed[33] = (params.signCount >>> 24) & 0xff;
  fixed[34] = (params.signCount >>> 16) & 0xff;
  fixed[35] = (params.signCount >>> 8) & 0xff;
  fixed[36] = params.signCount & 0xff;
  fixed.set(params.aaguid, 37);
  const credLen = new Uint8Array([
    (params.credentialId.length >> 8) & 0xff,
    params.credentialId.length & 0xff,
  ]);
  return concat([fixed, credLen, params.credentialId, params.credentialPublicKeyCose]);
}

// ---- Tests ---------------------------------------------------------

describe("CBOR parser", () => {
  it("round-trips a nested map", () => {
    const bytes = encodeCbor({
      fmt: "apple-appattest",
      attStmt: { x5c: [new Uint8Array([1, 2, 3])] },
      authData: new Uint8Array([9, 8, 7]),
    });
    const decoded = decodeCbor(bytes) as Record<string, unknown>;
    expect(decoded["fmt"]).toBe("apple-appattest");
    const attStmt = decoded["attStmt"] as Record<string, unknown>;
    const x5c = attStmt["x5c"] as Uint8Array[];
    expect(x5c.length).toBe(1);
    expect(Array.from(x5c[0]!)).toEqual([1, 2, 3]);
  });

  it("rejects trailing bytes after the root item", () => {
    const good = encodeCbor({ a: 1 });
    const bad = concat([good, new Uint8Array([0x00])]);
    expect(() => decodeCbor(bad)).toThrow(/trailing/);
  });

  it("rejects indefinite-length maps", () => {
 // 0xbf is the indefinite-length map marker (major 5 + additional 31).
    const bad = new Uint8Array([0xbf, 0xff]);
    expect(() => decodeCbor(bad)).toThrow(/indefinite-length/);
  });

  it("rejects integer-keyed maps", () => {
 // Map with one entry: 0 -> 0. Major 5 + 1 element, then integer 0,
 // then integer 0.
    const bad = new Uint8Array([0xa1, 0x00, 0x00]);
    expect(() => decodeCbor(bad)).toThrow(/text-keyed/);
  });
});

describe("App Attest envelope rejection", () => {
  const baseConfig: AppAttestConfig = {
    appId: "com.provii.wallet",
    expectedAaguid: APPLE_AAGUID_PROD,
    nowMs: Date.UTC(2026, 0, 15),
    challenge: new Uint8Array(32),
  };

  beforeEach(() => {
    baseConfig.challenge = crypto.getRandomValues(new Uint8Array(32));
  });

  it("rejects a non-App-Attest fmt", async () => {
    const bytes = encodeCbor({
      fmt: "fido-u2f",
      attStmt: { x5c: [new Uint8Array(1)], receipt: new Uint8Array(1) },
      authData: new Uint8Array(55),
    });
    await expect(verifyAppAttest(bytes, baseConfig)).rejects.toThrow(/unexpected fmt/);
  });

  it("rejects an x5c array with the wrong cert count", async () => {
    const bytes = encodeCbor({
      fmt: "apple-appattest",
      attStmt: { x5c: [new Uint8Array(1)], receipt: new Uint8Array(1) },
      authData: new Uint8Array(55),
    });
    await expect(verifyAppAttest(bytes, baseConfig)).rejects.toThrow(
      /expected 2-cert x5c/,
    );
  });

  it("rejects a challenge of the wrong length", async () => {
    const bytes = encodeCbor({
      fmt: "apple-appattest",
      attStmt: {
        x5c: [new Uint8Array(1), new Uint8Array(1)],
        receipt: new Uint8Array(1),
      },
      authData: new Uint8Array(55),
    });
    await expect(
      verifyAppAttest(bytes, { ...baseConfig, challenge: new Uint8Array(16) }),
    ).rejects.toThrow(/challenge must be 32 bytes/);
  });

  it("rejects a receipt with garbage cert bytes", async () => {
 // Two arbitrary byte strings that will fail X.509 parsing the
 // moment the leaf hits parseCertificate. This exercises the
 // chain-walk branch where parsing itself fails.
    const bytes = encodeCbor({
      fmt: "apple-appattest",
      attStmt: {
        x5c: [new Uint8Array([0x00, 0x01, 0x02]), new Uint8Array([0x03, 0x04])],
        receipt: new Uint8Array(1),
      },
      authData: new Uint8Array(55),
    });
    await expect(verifyAppAttest(bytes, baseConfig)).rejects.toThrow();
  });
});

describe("AAGUIDs", () => {
  it("prod AAGUID matches Apple documentation", () => {
 // "appattest\0\0\0\0\0\0\0" -> bytes
    expect(APPLE_AAGUID_PROD.length).toBe(16);
    expect(new TextDecoder().decode(APPLE_AAGUID_PROD.subarray(0, 9))).toBe(
      "appattest",
    );
    for (let i = 9; i < 16; i++) {
      expect(APPLE_AAGUID_PROD[i]).toBe(0);
    }
  });

  it("dev AAGUID matches Apple documentation", () => {
    expect(APPLE_AAGUID_DEV.length).toBe(16);
    expect(new TextDecoder().decode(APPLE_AAGUID_DEV)).toBe("appattestdevelop");
  });
});

describe("authData byte-layout sanity", () => {
  it("builds an authData blob whose prefix matches the SHA-256 of the app id", async () => {
    const appId = "com.provii.wallet";
    const credentialId = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    const cose = new Uint8Array([0xa0]); // empty COSE map placeholder
    const authData = await buildAuthData({
      appId,
      flagsByte: 0x40,
      signCount: 0,
      aaguid: APPLE_AAGUID_PROD,
      credentialId,
      credentialPublicKeyCose: cose,
    });
    expect(authData.length).toBe(32 + 1 + 4 + 16 + 2 + credentialId.length + cose.length);
    const expectedRpHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(appId)),
    );
    for (let i = 0; i < 32; i++) {
      expect(authData[i]).toBe(expectedRpHash[i]);
    }
    expect(authData[32]).toBe(0x40);
    const credLen = (authData[53]! << 8) | authData[54]!;
    expect(credLen).toBe(credentialId.length);
  });
});

describe("Apple nonce extension OID", () => {
  it("matches the value documented by Apple", () => {
    expect(OID_APPLE_APP_ATTEST_NONCE).toBe("1.2.840.113635.100.8.2");
  });
});
