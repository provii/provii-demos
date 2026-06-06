// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Docs gateway CSRF primer + verify helpers (, + ).
 *
 * The docs gateway already pins Origin on every mint endpoint, but Origin
 * alone does not stop a same-origin XSS payload minting sandbox credentials
 * on behalf of a docs user. adds a CSRF layer on top: the browser
 * bootstraps a per-session secret once via `POST /api/csrf/bootstrap`,
 * receives it in an `X-Docs-CSRF-Secret` response header and a
 * `__Host-docs_csrf` secondary cookie, and then echoes it in an
 * `X-Docs-CSRF` header on every subsequent mint call. The server side
 * constant-time-compares the echoed value against the secret stored on
 * the session record.
 *
 * The secret is derived deterministically from the session id and a
 * dedicated HMAC label so it is stable across isolate restarts without
 * needing a fresh KV write on every primer call; the session record still
 * persists a copy so a key rotation eventually invalidates old secrets
 * alongside old bearer hashes.
 *
 * Every secret comparison routes through `constantTimeEqualsHex` from
 * `crypto.ts`, which delegates to `crypto.subtle.timingSafeEqual`. No
 * hand-rolled equality on this path.
 */

import {
  bytesToHex,
  constantTimeEqualsHex,
  hmacSha256,
} from "./crypto";
import type { DocsEnv } from "./handler";
import type { DocsSession } from "./schemas";

/** Header the browser must echo on every CSRF-protected mint call. */
export const CSRF_REQUEST_HEADER = "X-Docs-CSRF" as const;

/** Header the primer uses to deliver the newly-minted secret to the client. */
export const CSRF_RESPONSE_HEADER = "X-Docs-CSRF-Secret" as const;

/** `__Host-` prefixed secondary cookie name carrying the secret as a backup. */
export const CSRF_COOKIE_NAME = "__Host-docs_csrf" as const;

/** Max-Age on the secondary cookie. Matches the session hard cap (4h). */
const CSRF_COOKIE_MAX_AGE_SECONDS = 4 * 60 * 60;

/** HMAC domain separator so the CSRF derivation never collides with the bearer HMAC. */
const CSRF_DERIVATION_LABEL = "csrf-v1" as const;

/**
 * Structured outcome of the primer derivation. `secretHex` is the 32-byte
 * CSRF secret as lowercase hex. `setCookie` is the pre-built `Set-Cookie`
 * header value the handler writes straight into the response.
 */
export interface DerivedCsrfSecret {
  secretHex: string;
  setCookie: string;
}

/**
 * Derive the CSRF secret for a session id using the docs session HMAC key.
 * Truncates the HMAC tag to 32 bytes. Returns `null` when the HMAC key
 * binding is absent so the handler can fail closed with a 503.
 *
 * The derivation is deterministic: calling this twice for the same session
 * yields the same secret. That is the desired behaviour; each browser
 * session receives one CSRF secret that lives for the session TTL.
 */
export async function deriveCsrfSecret(
  env: DocsEnv,
  sessionId: string,
): Promise<DerivedCsrfSecret | null> {
  const raw = (await env.DOCS_SESSION_HMAC_KEY?.get()) ?? null;
  if (raw === null || raw === "") return null;

 // Accept either hex or UTF-8 key material, mirroring
 // `resolveSessionHmacKey` in session.ts. The derivation must use the
 // same key posture as the bearer cookie HMAC so a future rotation
 // invalidates both at once.
  const hexCandidate = /^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0;
  let keyBytes: Uint8Array;
  if (hexCandidate) {
    const decoded = new Uint8Array(raw.length / 2);
    for (let i = 0; i < decoded.length; i++) {
      decoded[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
    }
    if (decoded.byteLength < 32) return null;
    keyBytes = decoded;
  } else {
    const encoded = new TextEncoder().encode(raw);
    if (encoded.byteLength < 32) return null;
    keyBytes = encoded;
  }

 // Message: `<session_id> || <label>`. Label keeps the CSRF tag in a
 // different domain to the bearer-cookie HMAC so the same key material
 // cannot be reused across the two surfaces.
  const message = `${sessionId}||${CSRF_DERIVATION_LABEL}`;
  const tag = await hmacSha256(keyBytes, message);
 // HMAC-SHA-256 is 32 bytes; truncation is a no-op but explicit for docs.
  const secretBytes = tag.slice(0, 32);
  const secretHex = bytesToHex(secretBytes);

  const setCookie =
    `${CSRF_COOKIE_NAME}=${secretHex}; ` +
    `Max-Age=${CSRF_COOKIE_MAX_AGE_SECONDS}; ` +
    "Path=/; Secure; SameSite=Strict";

  return { secretHex, setCookie };
}

/** Outcome of `verifyCsrfHeader`. Handlers map each failure 1:1 to a response. */
export type CsrfVerifyOutcome =
  | { kind: "ok" }
  | {
      kind: "error";
      status: number;
      code:
        | "docs_csrf_not_bootstrapped"
        | "docs_csrf_header_missing"
        | "docs_csrf_header_mismatch";
      message: string;
    };

/**
 * Verify the `X-Docs-CSRF` header against the CSRF secret stored on the
 * session record. Returns a structured outcome so the handler can map
 * each failure to a specific 4xx code.
 *
 * Cases:
 * - session record has no `csrf_secret` => 428 `docs_csrf_not_bootstrapped`
 * (client must POST /api/csrf/bootstrap first)
 * - header missing or empty => 403 `docs_csrf_header_missing`
 * - header set but does not constant-time match => 403 `docs_csrf_header_mismatch`
 */
export function verifyCsrfHeader(
  request: Request,
  session: DocsSession,
): CsrfVerifyOutcome {
  const stored = session.csrf_secret;
  if (stored === undefined) {
    return {
      kind: "error",
      status: 428,
      code: "docs_csrf_not_bootstrapped",
      message:
        "CSRF secret not bootstrapped. POST /api/csrf/bootstrap before calling this endpoint.",
    };
  }

  const presented = request.headers.get(CSRF_REQUEST_HEADER);
  if (presented === null || presented === "") {
    return {
      kind: "error",
      status: 403,
      code: "docs_csrf_header_missing",
      message: `Missing ${CSRF_REQUEST_HEADER} header.`,
    };
  }

 // Constant-time-compare lengths and contents. `constantTimeEqualsHex`
 // also rejects non-hex input, which is stricter than we need here but
 // keeps the surface aligned with the bearer-hash comparison.
  if (!constantTimeEqualsHex(stored, presented)) {
    return {
      kind: "error",
      status: 403,
      code: "docs_csrf_header_mismatch",
      message: "CSRF header does not match the session secret.",
    };
  }

  return { kind: "ok" };
}
