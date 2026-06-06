// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

/**
 * Logger facade for the docs gateway (, W5 remediation).
 *
 * Wraps `installLogSanitizer` so every call site inside `src/docs/**` emits
 * through a sanitised console without having to re-thread the install
 * promise on every request. The sanitiser facade is lazily built on first
 * use, memoised at module scope, and reused across every subsequent call
 * within the same isolate. This matters because `installLogSanitizer`
 * awaits an HMAC key import and a tag-cache primer, both of which we want
 * to amortise across the isolate's lifetime.
 *
 * Correlation helpers.
 *
 * `correlationIdFor(value)` returns a short, opaque Blake2s-256 prefix
 * that on-call can use to thread a log line back to a specific session
 * or challenge WITHOUT ever emitting the raw identifier. The named-secret
 * regex in `log-sanitizer.ts` only catches Secrets-Store binding names
 * and shaped tokens; it does NOT know that `session_id` / `client_id`
 * URL-safe base64 values are sensitive. Call sites that want correlation
 * therefore compute an 8-hex Blake2s prefix and log that instead of the
 * raw value. Fail-closed: an empty input returns `unknown`.
 */

import { blake2s } from "@noble/hashes/blake2.js";
import { installLogSanitizer, registerKnownSecret } from "./log-sanitizer";

export interface DocsLoggerEnv {
  LOG_SANITIZER_KEY?: { get(): Promise<string | null> };
  DEMO_TOKEN_SECRET?: { get(): Promise<string | null> };
  SANDBOX_API_KEY?: { get(): Promise<string | null> };
  DOCS_SESSION_HMAC_KEY?: { get(): Promise<string | null> };
}

/**
 * Minimal Console-like surface exposed to docs gateway callers. Mirrors
 * `console.log` / `info` / `warn` / `error` / `debug`; other methods are
 * intentionally omitted so call sites cannot reach for unsanitised paths.
 */
export interface DocsLogger {
  log(...args: unknown[]): void;
  info(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
  debug(...args: unknown[]): void;
}

type SanitiserInstall = Awaited<ReturnType<typeof installLogSanitizer>>;

// Module-scoped sanitiser cache. Workers isolates reuse the module for
// the lifetime of the isolate, so the first request pays the install
// cost and every subsequent request in the same isolate reuses the
// cached promise. We hold a strong reference to the last env object so
// an isolate swap (new env instance) forces a re-install. WeakRef is
// not available in the vitest-pool-workers runtime and is unnecessary
// here: the env object outlives the module in every normal deploy.
let installPromise: Promise<SanitiserInstall> | null = null;
let lastEnv: DocsLoggerEnv | null = null;

/**
 * Resolve a Secrets Store binding to a plain string, falling back to an
 * empty string when the binding is absent. Never throws; we'd rather lose
 * one secret from the tag cache than trip the request path.
 */
async function readSecret(
  binding: { get(): Promise<string | null> } | undefined,
): Promise<string> {
  if (!binding) return "";
  try {
    const value = await binding.get();
    return value ?? "";
  } catch {
    return "";
  }
}

/**
 * Collect every Secrets-Store-bound value we can reach so the tag cache
 * emits the full `[REDACTED:<hmac>]` marker when one of them ever turns
 * up in a log line. We only read bindings that are actually declared in
 * `DocsLoggerEnv`; unknown entries stay out.
 *
 * The docs gateway's provii-verifier HMAC secret used to be provisioned as
 * a pinned Secrets Store binding and was registered here at install time.
 * The credential is now self-minted via `register-test-origin`, so the
 * freshly-loaded plaintext is registered by
 * `markDocsBootstrapCredentialAsKnown` (INVARIANT-DSGW-1) at every point
 * where the gateway gains awareness of the credential rather than at
 * logger install time.
 */
async function collectKnownSecrets(env: DocsLoggerEnv): Promise<string[]> {
  const values = await Promise.all([
    readSecret(env.DEMO_TOKEN_SECRET),
    readSecret(env.SANDBOX_API_KEY),
    readSecret(env.DOCS_SESSION_HMAC_KEY),
    readSecret(env.LOG_SANITIZER_KEY),
  ]);
  return values.filter((v): v is string => v.length > 0);
}

/**
 * Lazy, isolate-scoped installer. First caller does the async work;
 * every subsequent caller awaits the same promise. If the env object
 * reference changes (worker runtime spins a new isolate with a fresh
 * env), the cache is invalidated so the new bindings populate the tag
 * cache.
 */
async function resolveSanitiser(env: DocsLoggerEnv): Promise<SanitiserInstall> {
  if (installPromise !== null && lastEnv === env) {
    return installPromise;
  }
  lastEnv = env;
  installPromise = (async (): Promise<SanitiserInstall> => {
    const keyMaterial = await readSecret(env.LOG_SANITIZER_KEY);
    const knownSecrets = await collectKnownSecrets(env);
    return installLogSanitizer(keyMaterial === "" ? null : keyMaterial, knownSecrets);
  })();
  return installPromise;
}

/**
 * Public entry point called from `handleDocs`. Returns the sanitised
 * logger facade. The first call pays the HMAC import + secret read
 * cost; subsequent calls within the same isolate are a promise reuse.
 */
export async function getDocsLogger(env: DocsLoggerEnv): Promise<DocsLogger> {
  const install = await resolveSanitiser(env);
  return install.console;
}

/**
 * Reset the module-level cache. Exported solely for tests; production
 * callers should never invoke this directly.
 */
export function __resetDocsLoggerForTest(): void {
  installPromise = null;
  lastEnv = null;
}

/**
 * INVARIANT-DSGW-1: docs gateway bootstrap credential awareness.
 *
 * MUST be called every time the gateway gains awareness of the docs
 * sandbox bootstrap credential plaintext. The points in
 * `getOrBootstrapDocsSandboxCredential` that count as gaining awareness
 * are the local KV read returning a fresh record (cold isolate path
 * after a peer minted), a waited-for peer KV write landing during
 * in-flight bootstrap, and this isolate minting via
 * `register-test-origin`. Per-isolate cache hits do NOT count because
 * the credential was already registered on the call that populated the
 * cache.
 *
 * Each call site MUST call this helper rather than `registerKnownSecret`
 * directly so the invariant stays auditable from one place. Without one
 * of these hooks a cold isolate that wakes up after another isolate has
 * already minted would log the secret as a bare `[REDACTED]` rather than
 * the `[REDACTED:<hmac>]` correlation tag, breaking log triage.
 *
 * The sync `[REDACTED]`-shape canary in `log-sanitizer.ts`
 * (`bootstrap-cred-shaped value redacted without registration`) fires
 * once per isolate if a future refactor drops one of these hooks; the
 * canary is the runtime check that backs this compile-time invariant.
 *
 * Args:
 * - `credential`: the freshly-loaded `(clientId, hmacSecret)` triple.
 * hmacSecret is the only truly secret half; clientId is registered
 * as defence-in-depth so a stray log of the pair stays correlatable
 * through the redaction tag.
 * - `source`: where the credential came from. Logged for visibility
 * (each cold isolate's first registration emits one `[INVARIANT-DSGW-1]`
 * line so on-call can confirm the hook fired).
 * - `log`: optional logger facade. Defaults to none; the bootstrap
 * helper threads its `getDocsLogger(env)` result through here so the
 * structured event respects whatever sanitisation policy the request
 * lifecycle installed.
 *
 * The sanitiser must already be installed (`getDocsLogger` called once
 * for the request lifecycle); the dispatcher in `handleDocs` warms it
 * before any per-route handler runs, so the bootstrap helper that calls
 * this function always sees an installed sanitiser.
 */
export type DocsBootstrapCredentialSource = "kv-read" | "peer-wait" | "self-mint";

export async function markDocsBootstrapCredentialAsKnown(
  credential: { clientId: string; hmacSecret: string },
  source: DocsBootstrapCredentialSource,
  log?: Pick<DocsLogger, "info">,
): Promise<void> {
  await Promise.all([
    registerKnownSecret(credential.clientId),
    registerKnownSecret(credential.hmacSecret),
  ]);
 // Structured event so a future log scrape can confirm every isolate that
 // touched the bootstrap credential called the helper. The hmacSecret has
 // already been registered above, so even if a future regression made the
 // sanitiser leak it, this log line would come out tagged. We log a
 // correlation prefix rather than the value itself for defence in depth.
  if (log !== undefined) {
    const correlation = correlationIdFor("docs-bootstrap-cred", credential.hmacSecret);
    log.info(
      `[INVARIANT-DSGW-1] docs bootstrap credential registered (source=${source} cred_corr=${correlation})`,
    );
  }
}

/**
 * INVARIANT-DSGW-2: mobile sandbox per-install HMAC secret awareness.
 *
 * MUST be called every time the gateway gains awareness of a mobile
 * sandbox per-install HMAC secret plaintext. The points in
 * `mobile-sandbox.ts` that count as gaining awareness are the mint
 * site in `handleMobileSandboxRegister` (where `randomHex(32)` returns
 * a fresh 64-char hex string), the KV write surface in
 * `writeIssuerRecord` (which persists the secret under the issuer +
 * install KV keys for both the initial register and any later
 * refresh), and the KV read surface in `loadIssuerRecord` (cold
 * isolate path where another isolate or a previous request minted the
 * secret).
 *
 * Each call site MUST call this helper rather than `registerKnownSecret`
 * directly so the invariant stays auditable from one place. Without one
 * of these hooks a stray log of the per-install secret would emit a
 * bare `[REDACTED]` rather than the `[REDACTED:<hmac>]` correlation
 * tag, breaking on-call log triage of mobile sandbox issuer activity.
 *
 * The mobile sandbox secret is a 64-char lowercase hex string minted
 * by `randomHex(32)`. The sanitiser's `hex32` pattern catches it on
 * any log line, but without prior tag-cache registration the sync
 * redactor cannot compute the HMAC tag and falls back to the bare
 * marker. The sync `[REDACTED]`-shape canary in `log-sanitizer.ts`
 * (`mobile-sandbox-secret-shaped value redacted without registration`)
 * fires once per unique unregistered hex32 value if a future refactor
 * drops one of these hooks.
 *
 * Args:
 * - `secret`: the freshly-loaded `(clientId, hmacSecret)` triple.
 * hmacSecret is the only truly secret half; clientId is registered
 * as defence-in-depth so a stray log of the pair stays correlatable
 * through the redaction tag.
 * - `source`: where the secret came from. Logged for visibility (each
 * call to the helper emits one `[INVARIANT-DSGW-2]` info line so
 * on-call can confirm the hook fired).
 * - `log`: optional logger facade. Defaults to none; mobile sandbox
 * call sites that already hold a logger thread it through here so
 * the structured event respects whatever sanitisation policy the
 * request lifecycle installed.
 */
export type MobileSandboxSecretSource = "self-mint" | "kv-write" | "kv-read";

export async function markMobileSandboxSecretAsKnown(
  secret: { clientId: string; hmacSecret: string },
  source: MobileSandboxSecretSource,
  log?: Pick<DocsLogger, "info">,
): Promise<void> {
  await Promise.all([
    registerKnownSecret(secret.clientId),
    registerKnownSecret(secret.hmacSecret),
  ]);
  if (log !== undefined) {
    const correlation = correlationIdFor("mobile-sandbox-secret", secret.hmacSecret);
    log.info(
      `[INVARIANT-DSGW-2] mobile sandbox secret registered (source=${source} cred_corr=${correlation})`,
    );
  }
}

/**
 * Derive an opaque 8-hex correlation identifier from a potentially
 * sensitive value (session_id, client_id, challenge_id). Uses a domain
 * tag so cross-field collisions do not correlate. Returns `unknown`
 * when the input is empty so call sites do not log a marker that
 * could round-trip to an empty-string lookup.
 *
 * NOTE: Blake2s without a key is still a reasonable fingerprint for
 * the log-correlation use case because we are not trying to hide
 * the link between equal inputs across log lines, only hide the raw
 * value from anyone who eyeballs Logpush. Blake2s-256 truncated to 8
 * hex chars gives 32 bits of collision resistance for per-session
 * correlation, which is enough for an on-call engineer to filter.
 */
export function correlationIdFor(domain: string, value: string): string {
  if (value === "") return "unknown";
  const enc = new TextEncoder();
  const tagged = enc.encode(`${domain}\u0000${value}`);
  const digest = blake2s(tagged);
  let hex = "";
  for (let i = 0; i < 4; i++) {
    const b = digest[i] ?? 0;
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
}
