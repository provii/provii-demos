// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Docs gateway challenge creation.
 *
 * POST /api/docs/demo/challenge flow (used by the TestInWallet widget on
 * docs.provii.app/guides/mobile-verification):
 * 1. Resolve the gateway-bootstrapped sandbox verifier credential via
 * `getOrBootstrapDocsSandboxCredential`. The gateway self-mints
 * `(client_id, hmac_secret)` against provii-verifier's
 * `/v1/register-test-origin` once per 72-hour window using the shared
 * `SANDBOX_API_KEY`; the result is cached in KV under
 * `docs-bootstrap-cred:v1` so every isolate sees the same credential.
 * Per-session credential minting was retired; one bootstrapped
 * credential covers every TestInWallet session because the docs widgets
 * never escape the sandbox upstream.
 * 2. Generate a PKCE S256 pair. 32 bytes of CSPRNG, base64url-no-pad the
 * verifier, SHA-256 the ASCII bytes of the verifier string, base64url-
 * no-pad the digest for the `code_challenge` field. Provii-verifier's
 * `PkceCodeVerifier` accepts 43..128 chars of RFC 7636 unreserved
 * charset; 43 chars is what base64url-no-pad of 32 bytes produces.
 * 3. Build the canonical HMAC message that provii-verifier's
 * `create_canonical_message_for_challenge` function expects
 * (`provii-verifier/src/routes/challenge.rs`):
 *
 * {timestamp}:{method}:{path}:{body_json}:{nonce}
 *
 * where body_json is the serde_json `json!` macro output over
 * `{code_challenge, method, verifying_key_id, expires_in}`. Upstream
 * uses serde_json with `preserve_order` active (transitively enabled
 * via schemars 1.0), so keys serialise in the literal source order
 * of the Rust `json!` macro. Clients MUST emit the same key order
 * byte-exactly or the HMAC will not verify. The nonce is 64 hex chars
 * (256 bits) per `Authorizer::validate` in
 * `provii-verifier/src/types/auth.rs`; the HMAC is 64 hex chars
 * (SHA-256 lowercase hex).
 * 4. POST to provii-verifier `/v1/challenge` with the body + `authorizer`
 * envelope. The `authorizer.keyId` field uses camelCase on the wire
 * per `#[serde(rename = "keyId")]` on `types::auth::Authorizer`.
 * 5. Persist `docs-chal:<challenge_id>` with `poll_count=0` and the PKCE
 * code verifier. `/redeem` later sends this verifier upstream for
 * code verifier validation.
 * 6. Return the upstream fields plus `environment: "sandbox"` to the docs
 * widget. The environment pin is for the wallet's contract per
 * (sandbox issuer credentialing); nothing in this module
 * ever touches production.
 */

import { z } from "zod";

import {
  base64urlEncode,
  hmacSha256Hex,
  randomBytes,
  randomHex,
  sha256Bytes,
} from "./crypto";
import type { DocsEnv } from "./handler";
import {
  ChallengeRecordSchema,
  KV_PREFIX_DOCS_CHALLENGE,
  type DocsSession,
} from "./schemas";

// ============================================================================
// Upstream contract constants
// ============================================================================

/** Timeout applied to upstream service binding fetches (F-5). */
const UPSTREAM_FETCH_TIMEOUT_MS = 10_000;

/** Path hit on provii-verifier. Bytes matter; used inside the canonical message. */
const VERIFIER_CHALLENGE_PATH = "/v1/challenge";

/** HTTP method. Also used inside the canonical message. */
const VERIFIER_CHALLENGE_METHOD = "POST";

/**
 * Challenge TTL requested on the upstream. Provii-verifier's `ExpiresIn` wrapper
 * clamps to `[30, 300]` seconds, so 300 is the maximum we can ask for and the
 * upstream will never grant longer. Matches the challenge TTL policy pinned
 * across the platform (5 minutes / 300s).
 */
const CHALLENGE_EXPIRES_IN_SECONDS = 300;

/** Millisecond version for composing the fallback `expires_at`. */
const CHALLENGE_EXPIRES_IN_MS = CHALLENGE_EXPIRES_IN_SECONDS * 1000;

// ============================================================================
// Upstream response schema
// ============================================================================

/**
 * Subset of the `ChallengeResponse` struct (provii-verifier/src/routes/
 * challenge.rs). We only validate the fields the docs widget echoes; the
 * upstream may send additional fields (rp_challenge, submit_secret, etc.)
 * that we intentionally pass through via raw body echo on success.
 *
 * `challenge_id` is a UUIDv4 per `UuidV4`'s serialisation in
 * provii-verifier/src/types/strict.rs.
 */
const VerifierChallengeResponseSchema = z.object({
  challenge_id: z
    .string()
    .regex(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    ),
  short_code: z.string().min(12).max(16),
  expires_at: z.number().int().positive().optional(),
});

type VerifierChallengeResponse = z.infer<typeof VerifierChallengeResponseSchema>;

// ============================================================================
// Outcome surfaced to the handler
// ============================================================================

/**
 * : Zod schema for the body the docs widget receives on a successful
 * challenge mint. The `environment` field is a REQUIRED literal "sandbox";
 * the docs gateway is sandbox-only by construction and never mints production
 * challenges. The wallet (per ) treats absence of `environment` as a
 * protocol violation and refuses to open the payload.
 */
export const ChallengeOkBodySchema = z.object({
  /**
 * : Hard-coded literal "sandbox". Docs-sandbox gateway is
 * sandbox-only; docs widgets never hit production. Widget forwards this
 * byte-for-byte into the base64url-encoded deeplink JSON so the wallet's
 * `ChallengePayload` parser sees the same value as the signing origin.
   */
  environment: z.literal("sandbox"),
  challenge_id: z
    .string()
    .regex(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    ),
  short_code: z.string().min(12).max(16),
  expires_at: z.number().int().positive(),
  /** Raw upstream JSON object. Widget may read rp_challenge, submit_secret etc. */
  upstream: z.record(z.string(), z.unknown()),
});

/** Body the docs widget receives on a successful challenge mint. */
export type ChallengeOkBody = z.infer<typeof ChallengeOkBodySchema>;

/** Outcome the handler maps to a 200 body or a 4xx/5xx error envelope. */
export type CreateChallengeOutcome =
  | { kind: "ok"; body: ChallengeOkBody }
  | {
      kind: "error";
      status: number;
      code: string;
      message: string;
    };

// ============================================================================
// PKCE
// ============================================================================

/** Output of `generatePkcePair`. Both fields are ASCII. */
interface PkcePair {
  /** RFC 7636 code verifier string; 43 chars, unreserved charset. */
  codeVerifier: string;
  /** base64url-no-pad of SHA-256 over the verifier string bytes; 43 chars. */
  codeChallenge: string;
}

/**
 * Generate a PKCE S256 challenge + verifier. 32 bytes of CSPRNG entropy
 * base64url-no-pad encode to exactly 43 chars of unreserved charset, which
 * sits inside provii-verifier's `PkceCodeVerifier` 43..128 bound. The challenge
 * follows RFC 7636: base64url(SHA-256(ASCII(code_verifier))).
 */
async function generatePkcePair(): Promise<PkcePair> {
  const verifierBytes = randomBytes(32);
  const codeVerifier = base64urlEncode(verifierBytes);
  const digest = await sha256Bytes(codeVerifier);
  const codeChallenge = base64urlEncode(digest);
  return { codeVerifier, codeChallenge };
}

// ============================================================================
// Canonical message + body JSON
// ============================================================================

/**
 * Build the body JSON used inside the canonical signing message. This MUST
 * match `provii-verifier/src/routes/challenge.rs::
 * create_canonical_message_for_challenge` byte-exactly. Upstream uses
 * `serde_json::json!` with the `preserve_order` feature active
 * (transitively enabled via schemars 1.0), so keys emit in the literal
 * source order of the Rust `json!` macro:
 *
 * code_challenge, method, verifying_key_id, expires_in
 *
 * : a prior version of this function serialised keys in
 * ASCII-alphabetical order on the (incorrect) assumption that serde_json
 * was using its default `BTreeMap` backend. That drifted from the Rust
 * wire format and would silently break HMAC verification once the CSRF
 * protection flag flipped. The canonical-message golden-vector fixture
 * `test/docs/canonical_message_vectors.json` now locks the insertion
 * order byte-exact against the provii-verifier and provii-issuer copies; the
 * parity suite at `src/docs/__tests__/canonical_message_vectors.test.ts`
 * enforces the contract on every `npm test` run.
 *
 * `verifying_key_id` is emitted as `null` when absent on the Rust side
 * (`body.verifying_key_id.map(|v| v.get())`). `JSON.stringify` omits keys
 * whose value is `undefined`, so we explicitly use `null` to line up.
 *
 * Note: this JSON is the SIGNED form only. The actual request body sent
 * over the wire is a separate `JSON.stringify` call that may differ in
 * whitespace. Neither party cares, upstream rebuilds its own canonical
 * from the parsed struct, not from the request bytes.
 */
function buildCanonicalBodyJson(params: {
  codeChallenge: string;
  verifyingKeyId: number | null;
  /**
 * Accepted as a parameter so the canonical-message parity suite can
 * drive the helper with every provii-verifier fixture vector, including
 * the `expires_in=120` vector that exercises a non-default TTL. The
 * production call path always passes `CHALLENGE_EXPIRES_IN_SECONDS`.
   */
  expiresInSeconds?: number;
}): string {
 // Insertion order mirrors the Rust `json!` macro literal.
 // JSON.stringify of a plain object preserves insertion order for
 // string keys (ECMAScript 2015+), so the literal below drives the
 // wire format. No Unicode escapes are used by serde_json by default
 // for ASCII; all fields are ASCII-only.
  const payload = {
    code_challenge: params.codeChallenge,
    method: "S256",
    verifying_key_id: params.verifyingKeyId,
    expires_in: params.expiresInSeconds ?? CHALLENGE_EXPIRES_IN_SECONDS,
  };
  return JSON.stringify(payload);
}

/**
 * Assemble the five-section canonical HMAC signing message:
 *
 * {timestamp}:{method}:{path}:{body_json}:{nonce}
 *
 * Provii-verifier added the nonce as the fifth field in EA-018 so an attacker
 * cannot substitute a fresh nonce against a captured HMAC inside the same-
 * second window. See `provii-verifier/src/routes/challenge.rs` lines 247-278.
 */
function buildCanonicalMessage(params: {
  timestampSeconds: number;
  bodyJson: string;
  nonceHex: string;
}): string {
  return `${params.timestampSeconds}:${VERIFIER_CHALLENGE_METHOD}:${VERIFIER_CHALLENGE_PATH}:${params.bodyJson}:${params.nonceHex}`;
}

// ============================================================================
// Challenge mint
// ============================================================================

/**
 * Mint a challenge on behalf of `session`. Reads the bootstrapped sandbox
 * credential from `credential`, signs the upstream call, persists the
 * challenge state, and returns the response body the handler ships to the
 * docs widget.
 *
 * `credential` is resolved by the handler via
 * `getOrBootstrapDocsSandboxCredential`. The handler maps a missing or empty
 * credential to a 503 before this function is called, so the inputs are
 * guaranteed non-empty here.
 */
export async function createChallenge(
  env: DocsEnv,
  session: DocsSession,
  credential: { clientId: string; hmacSecret: string },
  now: number = Date.now(),
): Promise<CreateChallengeOutcome> {
  if (env.VERIFIER_API_SANDBOX === undefined) {
    return {
      kind: "error",
      status: 503,
      code: "docs_verifier_service_binding_missing",
      message: "provii-verifier service binding is not configured.",
    };
  }

 // PKCE pair first. The verifier is persisted on the challenge record
 // below so /redeem can submit it upstream later.
  const pkce = await generatePkcePair();

 // Bootstrapped credential is owned by the gateway, not the session, so we
 // send `null` for verifying_key_id. provii-verifier accepts JSON `null` and
 // falls back to the registered origin's default verifying key, which is
 // what the bootstrap credential is configured to expose.
  const verifyingKeyId: number | null = null;
  const canonicalBodyJson = buildCanonicalBodyJson({
    codeChallenge: pkce.codeChallenge,
    verifyingKeyId,
  });

  const timestampSeconds = Math.floor(now / 1000);
  const nonceHex = randomHex(32); // 32 bytes => 64 hex chars (256 bits)
  const canonicalMessage = buildCanonicalMessage({
    timestampSeconds,
    bodyJson: canonicalBodyJson,
    nonceHex,
  });

 // HMAC the canonical message with the bootstrapped HMAC secret.
 // provii-verifier interprets the HMAC key as the raw UTF-8 bytes of the
 // secret string; see `provii-verifier/src/security/auth.rs::authenticate`.
  const keyBytes = new TextEncoder().encode(credential.hmacSecret);
  const hmacHex = await hmacSha256Hex(keyBytes, canonicalMessage);

 // The outer request body includes the authorizer envelope. provii-verifier's
 // Authorizer serialises `key_id` as `keyId` (camelCase) via
 // `#[serde(rename = "keyId")]`. Everything else stays snake_case.
  const requestBodyObject = {
    code_challenge: pkce.codeChallenge,
    method: "S256" as const,
    verifying_key_id: verifyingKeyId,
    expires_in: CHALLENGE_EXPIRES_IN_SECONDS,
    authorizer: {
      keyId: credential.clientId,
      timestamp: timestampSeconds,
      hmac: hmacHex,
      nonce: nonceHex,
    },
  };
  const requestBody = JSON.stringify(requestBodyObject);

  let response: Response;
  try {
    response = await env.VERIFIER_API_SANDBOX.fetch(
      new Request(`https://provii-verifier${VERIFIER_CHALLENGE_PATH}`, {
        method: VERIFIER_CHALLENGE_METHOD,
        headers: {
          "Content-Type": "application/json",
          "X-Docs-Session": session.session_id,
        },
        body: requestBody,
        signal: AbortSignal.timeout(UPSTREAM_FETCH_TIMEOUT_MS),
      }),
    );
  } catch (err) {
    if (err instanceof DOMException && err.name === "TimeoutError") {
      return {
        kind: "error",
        status: 504,
        code: "docs_verifier_upstream_timeout",
        message: "provii-verifier did not respond in time.",
      };
    }
    return {
      kind: "error",
      status: 502,
      code: "docs_verifier_upstream_unreachable",
      message: "provii-verifier is unreachable.",
    };
  }

  if (!response.ok) {
    return {
      kind: "error",
      status: 502,
      code: "docs_verifier_upstream_rejected",
      message: `provii-verifier responded ${response.status}.`,
    };
  }

  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch {
    return {
      kind: "error",
      status: 502,
      code: "docs_verifier_upstream_malformed",
      message: "provii-verifier response was not JSON.",
    };
  }

  const upstream = VerifierChallengeResponseSchema.safeParse(parsed);
  if (!upstream.success) {
    return {
      kind: "error",
      status: 502,
      code: "docs_verifier_upstream_schema_mismatch",
      message: "provii-verifier response failed validation.",
    };
  }
  const challenge: VerifierChallengeResponse = upstream.data;

 // Upstream `expires_at` is seconds (epoch). The docs record uses millis.
  const upstreamExpiresAtMs =
    typeof challenge.expires_at === "number"
      ? challenge.expires_at * 1000
      : undefined;
  const expiresAt = upstreamExpiresAtMs ?? now + CHALLENGE_EXPIRES_IN_MS;

  const record = ChallengeRecordSchema.parse({
    challenge_id: challenge.challenge_id,
    session_id: session.session_id,
    environment: "sandbox",
    poll_count: 0,
    expires_at: expiresAt,
    code_verifier: pkce.codeVerifier,
  });
  const ttlSeconds = Math.max(1, Math.ceil((expiresAt - now) / 1000));
  await env.DOCS_SESSIONS.put(
    `${KV_PREFIX_DOCS_CHALLENGE}${challenge.challenge_id}`,
    JSON.stringify(record),
    { expirationTtl: ttlSeconds },
  );

 // Guard against the parsed object being a non-plain JSON Object. Zod above
 // already checked the fields we care about; `parsed` is unknown, so we
 // narrow to `Record<string, unknown>` for the passthrough echo.
  const upstreamEcho =
    typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};

 // : parse through `ChallengeOkBodySchema` so the `environment`
 // literal is enforced at runtime. A regression that drops the field or
 // writes the wrong value fails here loudly instead of shipping a body the
 // wallet will reject on the far side of the deeplink.
  const body = ChallengeOkBodySchema.parse({
    environment: "sandbox",
    challenge_id: challenge.challenge_id,
    short_code: challenge.short_code,
    expires_at: expiresAt,
    upstream: upstreamEcho,
  });

  return {
    kind: "ok",
    body,
  };
}

// ============================================================================
// Re-exports for tests
// ============================================================================

export const __internal = {
  buildCanonicalBodyJson,
  buildCanonicalMessage,
  generatePkcePair,
};
