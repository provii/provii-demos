// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * JSON Canonicalization Scheme (RFC 8785) wrapper.
 *
 * .0 spike scaffolding. Wraps Samuel Erdtman's `canonicalize`
 * package (Apache-2.0, zero runtime deps, SHA-pinned via package-lock
 * integrity field). The package is ~720 bytes minified, so we can
 * embed it in the docs gateway Worker bundle without touching the
 * size budget.
 *
 * Why wrap it at all:
 * - Centralise the import so future swaps (pure-JS re-implementation,
 * native WebCrypto helper if it ever lands) stay single-file.
 * - Add the `Uint8Array` variant up front. .1 HMAC will need
 * bytes, not a string, because the gateway signs the exact body
 * octets that the provii-verifier will re-canonicalise and re-sign.
 * - Narrow the input type. `canonicalize` takes `unknown` and throws
 * on `NaN`/`Infinity`/circular. We keep the throw semantics but
 * document them so callers do not treat the helper as infallible.
 *
 * Reference: RFC 8785 JSON Canonicalization Scheme
 * https://datatracker.ietf.org/doc/html/rfc8785
 *
 * Test vectors (`src/docs/__tests__/jcs.test.ts`) come from the RFC
 * appendix B examples, which Erdtman's repo mirrors at:
 * https://github.com/erdtman/canonicalize/tree/master/test
 */

import canonicalize from "canonicalize";

const textEncoder = new TextEncoder();

/**
 * Canonicalise `value` per RFC 8785 and return the resulting JSON
 * string. Throws on `NaN`, `+/-Infinity`, and circular references
 * because the underlying spec has no representation for them.
 */
export function jcsStringify(value: unknown): string {
  const canonical = canonicalize(value);
  if (typeof canonical !== "string") {
 // canonicalize returns `undefined` for `undefined` input. JCS has
 // no representation for `undefined` at the top level, so surface
 // that as an error rather than silently producing an empty body.
    throw new TypeError("jcsStringify: input is not serialisable under RFC 8785");
  }
  return canonical;
}

/**
 * Canonicalise `value` and return the UTF-8 byte encoding. HMAC and
 * signature paths should use this variant so the tag covers the exact
 * octets that travel over the wire.
 */
export function jcsBytes(value: unknown): Uint8Array {
  return textEncoder.encode(jcsStringify(value));
}
