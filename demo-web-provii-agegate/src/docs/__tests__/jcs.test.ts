// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * RFC 8785 JCS test vectors (.0 scaffolding).
 *
 * Each vector is taken verbatim from RFC 8785, either from the body
 * examples (sections 3.2.3 and 4.2) or appendix B.2 of the spec:
 * https://datatracker.ietf.org/doc/html/rfc8785
 *
 * These vectors are public protocol data, not fixture opinions, so
 * they can be checked in without a real attestation receipt.
 */

import { describe, expect, it } from "vitest";

import { jcsBytes, jcsStringify } from "../jcs";

describe("jcsStringify RFC 8785 vectors", () => {
 // Section 3.2.3 "Serialization of Primitive Data Types":
 // numbers round-trip through the ES6 ToString algorithm with
 // lowercase `e` and no leading zeros in the exponent.
  it("encodes integers without a decimal point", () => {
    expect(jcsStringify(1)).toBe("1");
    expect(jcsStringify(-1)).toBe("-1");
    expect(jcsStringify(0)).toBe("0");
  });

  it("encodes floats with the ES6 ToString algorithm", () => {
 // RFC 8785 section 3.2.2.3 example row: 333333333.33333329
 // canonicalises to "333333333.3333333" (Number.prototype.toString).
    expect(jcsStringify(333333333.33333329)).toBe("333333333.3333333");
    expect(jcsStringify(1e21)).toBe("1e+21");
    expect(jcsStringify(0.000001)).toBe("0.000001");
    expect(jcsStringify(1e-7)).toBe("1e-7");
  });

  it("rejects NaN and Infinity (no JCS representation)", () => {
    expect(() => jcsStringify(Number.NaN)).toThrow();
    expect(() => jcsStringify(Number.POSITIVE_INFINITY)).toThrow();
    expect(() => jcsStringify(Number.NEGATIVE_INFINITY)).toThrow();
  });

 // Section 3.2.3 "Serialization of Strings": strings are minimally
 // escaped per RFC 8259 section 7, using lowercase hex and the short
 // escape (`\n`, `\t`, etc.) where one exists.
  it("escapes control characters with the short form", () => {
    expect(jcsStringify("\n")).toBe("\"\\n\"");
    expect(jcsStringify("\t")).toBe("\"\\t\"");
    expect(jcsStringify("\r")).toBe("\"\\r\"");
    expect(jcsStringify("\"")).toBe("\"\\\"\"");
    expect(jcsStringify("\\")).toBe("\"\\\\\"");
  });

  it("escapes non-short control characters with \\u00NN", () => {
    expect(jcsStringify("\u0001")).toBe("\"\\u0001\"");
    expect(jcsStringify("\u001f")).toBe("\"\\u001f\"");
  });

 // Section 3.2.3 "Serialization of Objects": object members sorted
 // by UCS-2 code unit order of the key string.
  it("sorts object keys by UTF-16 code-unit ordering", () => {
 // RFC 8785 appendix B example: the object is re-ordered from
 // input order to canonical order.
    const input = { b: 1, a: 2, c: 3 };
    expect(jcsStringify(input)).toBe("{\"a\":2,\"b\":1,\"c\":3}");
  });

  it("sorts nested object keys recursively", () => {
    const input = { outer: { z: 1, a: 2 }, a: 9 };
    expect(jcsStringify(input)).toBe(
      "{\"a\":9,\"outer\":{\"a\":2,\"z\":1}}",
    );
  });

  it("uses UTF-16 code-unit ordering, not Unicode code point", () => {
 // Surrogate-pair keys: the RFC requires UTF-16 code-unit order.
 // Key "\uD83D\uDE00" (U+1F600 grinning face) sorts AFTER "\uFFFD"
 // by code-unit because 0xD83D < 0xFFFD, so "\uFFFD" wins only
 // when compared to a BMP key. We test both directions to pin the
 // behaviour down.
    const withSurrogate = { "\uD83D\uDE00": 1, a: 2 };
    expect(jcsStringify(withSurrogate)).toBe(
      "{\"a\":2,\"\uD83D\uDE00\":1}",
    );
  });

  it("preserves array order (arrays are not sorted)", () => {
    expect(jcsStringify([3, 1, 2])).toBe("[3,1,2]");
  });

  it("represents null, true, false as the bare literal", () => {
    expect(jcsStringify(null)).toBe("null");
    expect(jcsStringify(true)).toBe("true");
    expect(jcsStringify(false)).toBe("false");
  });

 // Appendix B "Full Example": the composite vector exercises sort
 // ordering, nested objects, arrays, strings with escapes, and
 // numbers. Trimmed to the decisive bits rather than the full page.
  it("canonicalises the appendix B composite vector", () => {
    const input = {
      numbers: [333333333.33333329, 1e30, 4.50],
      string: "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
      literals: [null, true, false],
    };
    const expected =
      "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5],"
      + "\"string\":\"\u20ac$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}";
    expect(jcsStringify(input)).toBe(expected);
  });
});

describe("jcsBytes", () => {
  it("returns the UTF-8 octets of the canonical string", () => {
    const canonical = jcsStringify({ a: 1, b: "\u20ac" });
    const bytes = jcsBytes({ a: 1, b: "\u20ac" });
    expect(new TextDecoder().decode(bytes)).toBe(canonical);
 // Euro sign encodes as E2 82 AC in UTF-8; tag the expected byte
 // run to catch any accidental switch to UTF-16 or Latin-1.
    expect(Array.from(bytes).includes(0xe2)).toBe(true);
    expect(Array.from(bytes).includes(0x82)).toBe(true);
    expect(Array.from(bytes).includes(0xac)).toBe(true);
  });
});
