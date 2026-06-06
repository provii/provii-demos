// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * JWS verification against RFC 7515 appendix A test vectors.
 * https://datatracker.ietf.org/doc/html/rfc7515#appendix-A
 *
 * Appendix A.2 covers RS256, A.3 covers ES256. The vectors include
 * JWK public keys, the pre-encoded signing input, and the signature.
 * These are published by the IETF and safe to commit.
 *
 * Note: ES256 signature verification in WebCrypto requires the raw
 * R || S concatenation, which matches the JWS compact encoding (the
 * RFC 7515 signature segment is already R || S base64url). RS256
 * requires the raw RSA signature bytes; same story.
 */

import { describe, expect, it } from "vitest";

import {
  __resetJwksCacheForTests,
  base64urlDecode,
  findKeyByKid,
  type Jwk,
  verifyJwsCompact,
} from "../attestation/jwks";

// RFC 7515 Appendix A.2, RS256 public key. The modulus `n` below is
// the concatenation of the six chunks printed on page 41 of RFC 7515
// (with display-only line breaks removed).
const RFC7515_A2_PUBLIC_JWK: Jwk = {
  kty: "RSA",
  n:
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
    + "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
    + "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
    + "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
    + "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
    + "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
  e: "AQAB",
};

// Appendix A.2: the signing input (BASE64URL(header) + "." + BASE64URL(payload))
// and the signature, both base64url without padding.
const RFC7515_A2_SIGNING_INPUT =
  "eyJhbGciOiJSUzI1NiJ9"
  + "."
  + "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxl"
  + "LmNvbS9pc19yb290Ijp0cnVlfQ";
const RFC7515_A2_SIGNATURE =
  "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
  + "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
  + "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
  + "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
  + "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
  + "p0igcN_IoypGlUPQGe77Rw";
const RFC7515_A2_TOKEN = `${RFC7515_A2_SIGNING_INPUT}.${RFC7515_A2_SIGNATURE}`;

// RFC 7515 Appendix A.3: ES256 public key (P-256 JWK).
const RFC7515_A3_PUBLIC_JWK: Jwk = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
};

// Appendix A.3: signing input + signature.
const RFC7515_A3_SIGNING_INPUT =
  "eyJhbGciOiJFUzI1NiJ9"
  + "."
  + "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxl"
  + "LmNvbS9pc19yb290Ijp0cnVlfQ";
const RFC7515_A3_SIGNATURE =
  "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
  + "pmWQxfKTUJqPP3-Kg6NU1Q";
const RFC7515_A3_TOKEN = `${RFC7515_A3_SIGNING_INPUT}.${RFC7515_A3_SIGNATURE}`;

describe("verifyJwsCompact, RFC 7515 appendix A", () => {
  it("verifies the A.2 RS256 vector", async () => {
    const verified = await verifyJwsCompact(
      RFC7515_A2_TOKEN,
      async () => RFC7515_A2_PUBLIC_JWK,
    );
    expect(verified.header.alg).toBe("RS256");
    const payloadJson = JSON.parse(new TextDecoder().decode(verified.payload));
    expect(payloadJson.iss).toBe("joe");
    expect(payloadJson["http://example.com/is_root"]).toBe(true);
  });

  it("verifies the A.3 ES256 vector", async () => {
    const verified = await verifyJwsCompact(
      RFC7515_A3_TOKEN,
      async () => RFC7515_A3_PUBLIC_JWK,
    );
    expect(verified.header.alg).toBe("ES256");
    const payloadJson = JSON.parse(new TextDecoder().decode(verified.payload));
    expect(payloadJson.iss).toBe("joe");
  });

  it("rejects an A.2 token with one flipped byte in the signature", async () => {
    const tampered = flipLastSignatureByte(RFC7515_A2_TOKEN);
    await expect(
      verifyJwsCompact(tampered, async () => RFC7515_A2_PUBLIC_JWK),
    ).rejects.toThrow(/did not verify|signature/i);
  });

  it("rejects an unsupported `alg` header", async () => {
 // `alg=HS256` with the RFC's A.1 header byte pattern, but with a
 // body we do not care about. The parser should bail before any
 // key material is resolved.
    const header = btoa(JSON.stringify({ alg: "HS256" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const payload = btoa(JSON.stringify({}))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const bogus = `${header}.${payload}.AAAA`;
    await expect(
      verifyJwsCompact(bogus, async () => RFC7515_A2_PUBLIC_JWK),
    ).rejects.toThrow(/not permitted/);
  });

  it("rejects a token with too few segments", async () => {
    await expect(
      verifyJwsCompact("only.twoparts", async () => RFC7515_A2_PUBLIC_JWK),
    ).rejects.toThrow(/three dot-separated/);
  });
});

describe("findKeyByKid + cache helpers", () => {
  it("finds a key by kid or returns null", () => {
    const doc = {
      keys: [
        { kty: "RSA", kid: "alpha", n: "n", e: "AQAB" },
        { kty: "RSA", kid: "beta", n: "n", e: "AQAB" },
      ],
    };
    expect(findKeyByKid(doc, "alpha")?.kid).toBe("alpha");
    expect(findKeyByKid(doc, "missing")).toBeNull();
  });

  it("exposes a cache reset for tests", () => {
    expect(() => __resetJwksCacheForTests()).not.toThrow();
  });
});

describe("base64urlDecode", () => {
  it("round-trips the RFC 7515 header segments", () => {
 // The header "eyJhbGciOiJSUzI1NiJ9" decodes to {"alg":"RS256"}.
    const bytes = base64urlDecode("eyJhbGciOiJSUzI1NiJ9");
    expect(new TextDecoder().decode(bytes)).toBe('{"alg":"RS256"}');
  });

  it("tolerates padding if producers add it", () => {
    expect(new TextDecoder().decode(base64urlDecode("YQ=="))).toBe("a");
    expect(new TextDecoder().decode(base64urlDecode("YQ"))).toBe("a");
  });
});

function flipLastSignatureByte(token: string): string {
  const parts = token.split(".");
  const sigBytes = base64urlDecode(parts[2] ?? "");
  sigBytes[sigBytes.length - 1] = sigBytes[sigBytes.length - 1]! ^ 0x01;
  let binary = "";
  for (let i = 0; i < sigBytes.length; i++) binary += String.fromCharCode(sigBytes[i]!);
  const newSig = btoa(binary)
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${parts[0]}.${parts[1]}.${newSig}`;
}
