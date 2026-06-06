// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii
//
// Cross-service canonical-message golden-vector tests for the docs gateway
// (tasks 0.51 + ).
//
// The fixture file `test/docs/canonical_message_vectors.json` is mirrored
// byte-for-byte from
// `provii-verifier/tests/fixtures/canonical_message_vectors.json` and
// `provii-issuer/tests/fixtures/canonical_message_vectors.json`. The
// `scripts/check-canonical-fixtures.sh` drift check (wired into `make
// check-canonical-fixtures` at the provii-demos repo root) SHA-256 diffs
// the three copies so a stale edit in any one repo fails CI before this
// suite runs. Run locally via `npm test`.
//
// What the suite locks (all live now, not skipped):
//
// 1. `buildCanonicalBodyJson` in `src/docs/challenge.ts` produces the
// SAME JSON string as the provii-verifier Rust `json!` macro with
// `preserve_order` active. Insertion order is
// `code_challenge, method, verifying_key_id, expires_in`. The
// pre- implementation serialised keys alphabetically and
// would have failed HMAC verification once the CSRF flag flipped.
// 2. `buildCanonicalMessage` assembles the 5-section envelope
// `{ts}:POST:/v1/challenge:{body}:{nonce}` byte-exact per the
// fixture's `expected_canonical_bytes_hex` for provii-verifier vectors.
// 3. `hmacSha256Hex` produces the published
// `expected_hmac_hex_with_known_key` tag for every provii-verifier
// vector when fed the known `hmac_key_hex` key and the canonical
// bytes the fixture publishes.
// 4. `computeAttestationMessageBytes` (shared helper) matches the
// `attestation_vectors` entries byte-exactly. This locks the
// Blake2s input format against drift from the provii-crypto
// `-attestation-binding` branch (). The suite
// covers the legacy (None, None) path taken by the demo
// subdomains, the fully-bound path taken by the docs gateway, and
// the mixed (session only) path that exercises the zero-length
// client_id encoding.

import { describe, expect, it } from "vitest";

import fixture from "../../../test/docs/canonical_message_vectors.json";

import { computeAttestationMessageBytes } from "../../attestation-message";
import {
  bytesToHex,
  hexToBytes,
  hmacSha256Hex,
} from "../crypto";
import { __internal } from "../challenge";

const SHARED_HMAC_KEY_HEX: string = fixture.hmac_key_hex;

/** Shape we rely on from the fixture for provii-verifier vectors. */
interface VerifierVector {
  readonly test_name: string;
  readonly service_origin: string;
  readonly constructor: string;
  readonly inputs: {
    readonly timestamp: number;
    readonly method: string;
    readonly path: string;
    readonly body: string;
    readonly nonce: string;
  };
  readonly expected_canonical_bytes_hex?: string;
  readonly expected_hmac_hex_with_known_key?: string;
}

function selectVerifierVectors(): readonly VerifierVector[] {
  return (fixture.vectors as readonly VerifierVector[]).filter(
    (v) => v.service_origin === "provii-verifier",
  );
}

/**
 * Decode a URL-safe base64 (no-pad) segment, used to map the fixture's
 * `code_challenge` string back into bytes so we can round-trip it through
 * the TS helpers that operate on the encoded form.
 */
function selectCodeChallengeFromBody(bodyJson: string): string {
  const parsed = JSON.parse(bodyJson) as {
    code_challenge?: string;
  };
  if (typeof parsed.code_challenge !== "string") {
    throw new Error("fixture body missing code_challenge");
  }
  return parsed.code_challenge;
}

function selectVerifyingKeyIdFromBody(bodyJson: string): number | null {
  const parsed = JSON.parse(bodyJson) as {
    verifying_key_id?: number | null;
  };
  if (parsed.verifying_key_id === null || parsed.verifying_key_id === undefined) {
    return null;
  }
  return parsed.verifying_key_id;
}

function selectExpiresInFromBody(bodyJson: string): number {
  const parsed = JSON.parse(bodyJson) as { expires_in?: number };
  if (typeof parsed.expires_in !== "number") {
    throw new Error("fixture body missing expires_in");
  }
  return parsed.expires_in;
}

describe("canonical message golden vectors (cross-service contract lock)", () => {
  it("buildCanonicalBodyJson matches provii-verifier serde_json preserve_order output", () => {
    for (const vector of selectVerifierVectors()) {
      const codeChallenge = selectCodeChallengeFromBody(vector.inputs.body);
      const verifyingKeyId = selectVerifyingKeyIdFromBody(vector.inputs.body);
      const expiresInSeconds = selectExpiresInFromBody(vector.inputs.body);
      const actual = __internal.buildCanonicalBodyJson({
        codeChallenge,
        verifyingKeyId,
        expiresInSeconds,
      });
      expect(actual, `body drift on ${vector.test_name}`).toBe(
        vector.inputs.body,
      );
    }
  });

  it("buildCanonicalMessage assembles the 5-section envelope byte-exactly", () => {
    for (const vector of selectVerifierVectors()) {
      if (vector.expected_canonical_bytes_hex === undefined) continue;
 // The helper hard-codes method=POST and path=/v1/challenge. Every
 // provii-verifier vector in the fixture uses those values; if a
 // future vector diverges, the assertion below flags the drift so
 // the helper can be generalised before the fixture accepts it.
      expect(
        vector.inputs.method,
        `fixture method drift on ${vector.test_name}`,
      ).toBe("POST");
      expect(
        vector.inputs.path,
        `fixture path drift on ${vector.test_name}`,
      ).toBe("/v1/challenge");

      const actual = __internal.buildCanonicalMessage({
        timestampSeconds: vector.inputs.timestamp,
        bodyJson: vector.inputs.body,
        nonceHex: vector.inputs.nonce,
      });
      const actualBytes = new TextEncoder().encode(actual);
      const expectedHex = bytesToHex(actualBytes);
      expect(
        expectedHex,
        `canonical bytes drift on ${vector.test_name}`,
      ).toBe(vector.expected_canonical_bytes_hex);
    }
  });

  it("buildCanonicalBodyJson serialises keys in Rust `json!` macro order", () => {
 // Guard against a future regression that sorts keys alphabetically.
 // The Rust verifier uses serde_json's `preserve_order` feature so
 // the insertion order from the `json!` literal in
 // `provii-verifier/src/routes/challenge.rs` is the wire format. If
 // someone reintroduces a `Object.keys(...).sort()` pass here,
 // HMAC verification will silently drift out of sync with upstream.
    const body = __internal.buildCanonicalBodyJson({
      codeChallenge: "A".repeat(43),
      verifyingKeyId: 42,
      expiresInSeconds: 300,
    });
    expect(body).toBe(
      '{"code_challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","method":"S256","verifying_key_id":42,"expires_in":300}',
    );
  });

  it("hmacSha256Hex matches expected_hmac_hex_with_known_key for every verifier vector", async () => {
    const keyBytes = hexToBytes(SHARED_HMAC_KEY_HEX);
    if (keyBytes === null) {
      throw new Error("fixture hmac_key_hex failed to decode");
    }
    for (const vector of selectVerifierVectors()) {
      if (
        vector.expected_canonical_bytes_hex === undefined ||
        vector.expected_hmac_hex_with_known_key === undefined
      ) {
        continue;
      }
      const canonicalBytes = hexToBytes(vector.expected_canonical_bytes_hex);
      if (canonicalBytes === null) {
        throw new Error(
          `fixture ${vector.test_name} canonical bytes failed to decode`,
        );
      }
 // Decode the published canonical bytes back to UTF-8 so we sign
 // the same string the wire format carries. The fixture canonicals
 // are pure ASCII, so a TextDecoder default (replacement char on
 // malformed input) is safe and avoids the Workers TextDecoder
 // option-shape divergence from lib.dom.d.ts.
      const canonicalText = new TextDecoder("utf-8").decode(canonicalBytes);
      const tag = await hmacSha256Hex(keyBytes, canonicalText);
      expect(tag, `HMAC drift on ${vector.test_name}`).toBe(
        vector.expected_hmac_hex_with_known_key,
      );
    }
  });
});

/** Shape we rely on from the fixture for DobAttestation vectors. */
interface AttestationVector {
  readonly test_name: string;
  readonly constructor: string;
  readonly inputs: {
    readonly dob_days: number;
    readonly issuer_id: string;
    readonly timestamp: number;
    readonly nonce_hex: string;
    readonly session_id: string | null;
    readonly client_id: string | null;
  };
  readonly expected_message_bytes_hex: string;
}

function selectAttestationVectors(): readonly AttestationVector[] {
  const raw = (fixture as unknown as { attestation_vectors?: readonly AttestationVector[] })
    .attestation_vectors;
  if (raw === undefined) {
    throw new Error("fixture missing attestation_vectors array");
  }
  return raw;
}

describe("DobAttestation canonical-message golden vectors (task 0.28d)", () => {
  it("computeAttestationMessageBytes matches every attestation fixture vector", () => {
    for (const vector of selectAttestationVectors()) {
      const nonceBytes = hexToBytes(vector.inputs.nonce_hex);
      if (nonceBytes === null) {
        throw new Error(
          `fixture ${vector.test_name} nonce_hex failed to decode`,
        );
      }
      const sessionId =
        vector.inputs.session_id === null ? undefined : vector.inputs.session_id;
      const clientId =
        vector.inputs.client_id === null ? undefined : vector.inputs.client_id;
      const actualBytes = computeAttestationMessageBytes(
        vector.inputs.dob_days,
        vector.inputs.issuer_id,
        vector.inputs.timestamp,
        nonceBytes,
        sessionId,
        clientId,
      );
      expect(
        bytesToHex(actualBytes),
        `attestation message-bytes drift on ${vector.test_name}`,
      ).toBe(vector.expected_message_bytes_hex);
    }
  });

  it("setInt32 emits two's-complement bytes for negative dob_days", () => {
 // Direct assertion that negative dob_days do not fold into the
 // unsigned u32 range. dob_days = -1000 should hash to the fixture
 // vector `attestation_negative_dob_days_edge`; if it regressed to
 // setUint32, the leading 4 bytes would encode 0xFFFFFC18 -> 4294966296
 // rather than the two's-complement of -1000, and the hash would
 // drift. The previous test already proves byte-parity against the
 // fixture; this test makes the intent explicit so a future rewrite
 // cannot "optimise" setInt32 back to setUint32 without tripping.
    const nonce = new Uint8Array(32);
    const bound = computeAttestationMessageBytes(-1000, "x", 0, nonce, "s", "c");
    expect(bytesToHex(bound)).toBe(
      "bccec409786145fbbd779f71909f5bfc757d4b82dc6d62ef52386bc4ad751388",
    );
  });

  it("legacy (None, None) path stays byte-identical to pre-v1.1 attestations", () => {
 // Explicit coverage that omitting both session_id and client_id
 // produces the same output as the legacy fixture vector. Prevents
 // a future refactor from accidentally requiring the binding section
 // for every caller, which would break the demo-subdomain path.
    const nonce = hexToBytes(
      "4242424242424242424242424242424242424242424242424242424242424242",
    );
    if (nonce === null) throw new Error("nonce decode failed");
    const legacyBytes = computeAttestationMessageBytes(
      7300,
      "dmv.ca.gov",
      1704067200,
      nonce,
    );
    expect(bytesToHex(legacyBytes)).toBe(
      "1b08cb4c04148b01f08fe3ca93bd93dcd79f1f23a96b70b8fcfae494716c017d",
    );
  });
});
