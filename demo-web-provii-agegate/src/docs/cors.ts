// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Docs gateway CORS allowlist ().
 *
 * Per the integration-isolation review, the docs allowlist and helper are
 * fully duplicated from the playground equivalents. No shared helper. A
 * change to one allowlist (rotation, new preview host, kill) cannot
 * accidentally widen the other. The duplicated code is intentional; do not
 * factor it out without revisiting that review decision.
 */

/**
 * Origins permitted to call `docs.provii.app/api/*`. Production docs,
 * UAT docs, and the sandboxed styler-preview origin used by the provii-agegate
 * styler (separate origin so its iframe runs without `allow-same-origin`).
 */
export const ALLOWED_DOCS_ORIGINS: readonly string[] = [
  "https://docs.provii.app",
  "https://uat-docs.provii.app",
  "https://preview.docs-sandbox.provii.app",
];

/**
 * Return the `Origin` header if it is in the docs allowlist, otherwise null.
 * Callers use this to decide whether to set `Access-Control-Allow-Origin`. A
 * null result means CORS headers are omitted, not that the request is
 * rejected; same-origin requests have no `Origin` header on every browser.
 */
export function getAllowedDocsOrigin(request: Request): string | null {
  const origin = request.headers.get("Origin");
  if (origin && ALLOWED_DOCS_ORIGINS.includes(origin)) {
    return origin;
  }
  return null;
}
