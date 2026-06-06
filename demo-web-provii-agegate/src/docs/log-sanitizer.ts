// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

/**
 * Log sanitisation for the docs gateway worker ().
 *
 * Adversarial review flagged that any future `console.error` / `console.log`
 * call inside the gateway could leak secret material (Secrets Store values,
 * docs-session bearer cookies, HMAC tags, registered env var contents) to
 * Cloudflare's Logpush sink.
 * The Rust provii-verifier uses a hand-written sanitiser
 * (`src/security/log_sanitizer.rs`) that hashes IP addresses with
 * HMAC-SHA-256 and truncates session and challenge IDs. This file is the
 * TypeScript counterpart for the Workers runtime: same pattern, same
 * HMAC primitive, scoped to the strings that show up in console arguments
 * and Analytics Engine payloads.
 *
 * Design notes.
 *
 * Every console method (`log`, `info`, `warn`, `error`, `debug`, `trace`)
 * call is funnelled through `sanitise()` before any data leaves the worker.
 * `sanitise()` walks the
 * argument tree and rewrites any leaf string matching one of the
 * registered patterns to `[REDACTED:<hmac-hash-prefix>]` so logs remain
 * correlatable without exposing the underlying value. Patterns cover
 * registered env var names (Secrets Store keys, the dashboard exposes
 * them by name), 32-byte hex strings (hash digests and HMAC tags written
 * out by `crypto.subtle`), and base64url strings the length of the
 * docs-session bearer cookie (256 bit entropy, 43 chars unpadded).
 *
 * The redaction key comes from the Secrets Store binding
 * `LOG_SANITIZER_KEY`. Install is async (`installLogSanitizer`) and
 * imports the key once. After that point both the async sanitiser path
 * and the sync console wrappers produce identical `[REDACTED:<tag>]`
 * output because tags are computed on-demand and cached in a synchronous
 * `Map<string, string>`. If the binding is missing the sanitiser fails
 * closed: every match is replaced with a static `[REDACTED]` string with
 * no hash suffix, so callers cannot inadvertently downgrade the policy
 * by forgetting to provision the key.
 *
 * Constant-time equality comparisons against secret material use
 * `crypto.subtle.timingSafeEqual` per the repo-wide rule in the project security policy.
 * `constantTimeEqualsString` is exported so upstream callers that want
 * to check whether a logged candidate string matches a known secret can
 * do so without leaking timing information.
 *
 * Invariants.
 *
 * Pure data transformation. Never throws on malformed input; unknown
 * types stringify with `String(value)` and are sanitised. The wrapper
 * installation (`installLogSanitizer`) is idempotent: a second call
 * replaces the first, which matters for the worker module-evaluation
 * reuse pattern across requests in the same isolate.
 */

const REDACTION_PREFIX_LEN = 8; // hex chars; 4 bytes of HMAC-SHA-256 prefix
const ASSIGNMENT_MARKER = "=";

/**
 * Public hex invariants that must NEVER be redacted.
 *
 * (): the generic `hex32` pattern matches any 64-char
 * hex string on word boundaries, which eats published invariants like
 * the cross-service canonical-message fixture SHA-256 digest. Those
 * values are not secret; they are drift-check references shipped in the
 * fixture and referenced by name from ISMS docs and the tracker. Keep
 * the allowlist narrow: one entry per well-known public digest, added
 * only after the value is considered a permanent invariant.
 */
const PUBLIC_HEX_INVARIANTS: ReadonlySet<string> = new Set<string>([
 // Canonical-message fixture SHA-256. Identical across provii-verifier,
 // provii-issuer, and provii-demos copies. Referenced by
 // `provii-demos/scripts/check-canonical-fixtures.sh` and by
 // `the tracker`. Match is case-insensitive via
 // `toLowerCase()` in `isPublicHexInvariant` below so logs that
 // upper-case the digest still survive the allowlist check.
  "16661f12e890423524ccebb437347de5f0678e4fe38d8df8f452a87673792dcd",
]);

function isPublicHexInvariant(candidate: string): boolean {
  return PUBLIC_HEX_INVARIANTS.has(candidate.toLowerCase());
}

/**
 * Patterns whose matches in any logged string should be redacted.
 *
 * Order matters: more specific patterns first so a docs-session cookie
 * does not fall through to the generic 43-char base64url rule that
 * prints a less-helpful redaction tag.
 */
const SECRET_PATTERNS: ReadonlyArray<{
  name: string;
  regex: RegExp;
  allowlist?: (candidate: string) => boolean;
}> = [
 // Registered env var and Secrets Store binding names. Listing these by
 // name catches the common `log("DEMO_TOKEN_SECRET=" + value)` mistake
 // even when the value itself does not match a structural pattern.
 // The regex captures the binding name so it stays readable in the log.
  {
    name: "secrets-store-assignment",
    regex:
      /\b(DEMO_TOKEN_SECRET|SANDBOX_API_KEY|LOG_SANITIZER_KEY|DOCS_HMAC_SECRET|VERIFIER_IP_HASH_SALT|INTERNAL_SERVICE_TOKEN|PROVII_WALLET_PAT|GH_TOKEN|GITLEAKS_LICENSE|CLOUDFLARE_API_TOKEN|PII_HASH_SALT|PII_HASH_KEY)\s*[:=]\s*([^\s,;}\]]+)/g,
  },
 // 32 byte hex digests (HMAC-SHA-256 tags, SHA-256 hashes). Anchored on
 // word boundaries so we do not slice longer hex strings in half.
 //
 // : the `PUBLIC_HEX_INVARIANTS` allowlist exempts published
 // drift-check digests (currently only the canonical-message fixture
 // SHA) from redaction. Anything not on the list redacts as before.
  {
    name: "hex32",
    regex: /\b[0-9a-fA-F]{64}\b/g,
    allowlist: isPublicHexInvariant,
  },
 // 256 bit base64url tokens (Ed25519 seeds, 32 byte symmetric keys, the
 // docs-session bearer cookie). 43 chars plus a `=` pad, or 44 chars
 // unpadded; both encode exactly 256 bits and both appear in practice.
 //
 // : `\b` treats `-` and `_` as non-word characters, so a base64url
 // token starting with `-` preceded by whitespace (or ending with `-`
 // followed by whitespace) misses the match. The explicit character-class
 // lookaround enforces the boundary on the full base64url alphabet
 // `[A-Za-z0-9_-]` so leading and trailing dashes are caught.
 //
 // (): the prior `{43}` quantifier plus trailing
 // lookahead under-matched the 44-char unpadded form. The 44th
 // character is still in the alphabet, so a lookahead pinned at
 // position 43 rejected a token that was actually one byte longer.
 // Widening the length to `{43,44}` makes the greedy match consume the
 // full token; the optional `=` suffix still catches the padded form.
 // The two lengths are mutually exclusive on real outputs so the regex
 // cannot over-match legitimate payloads.
  {
    name: "b64url256",
    regex: /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43,44}={0,1}(?![A-Za-z0-9_-])/g,
  },
 // Bearer cookie literal (defence in depth). The b64url256 rule above
 // already covers the value half of the cookie, this catches the
 // `docs-session=` prefix in case someone logs the whole Cookie header.
  {
    name: "docs-session-cookie",
    regex: /docs-session=[A-Za-z0-9_+/=-]+/g,
  },
];

/**
 * Module-level cache. `cachedKey` is the imported HMAC key; `tagCache`
 * memoises the HMAC prefix per unique secret value so the synchronous
 * console wrapper path can re-use it without awaiting.
 *
 * Cache size is bounded by `MAX_TAG_CACHE` to stop a hostile caller
 * flooding the isolate with unique candidate strings.
 */
let cachedKey: CryptoKey | null = null;
let cachedKeyMaterial: string | null = null;
const tagCache = new Map<string, string>();
const MAX_TAG_CACHE = 1024;

/**
 * INVARIANT-DSGW-{1,2} canary: fires once per process if the sanitiser
 * is about to redact a value that matches a docs gateway bootstrap or
 * mobile sandbox secret shape AND the value is not in `tagCache`. Two
 * shapes are watched:
 *
 * 1. INVARIANT-DSGW-1: b64url256 (43-44 base64url chars, optional
 * `=` pad). Same shape as the upstream `register-test-origin`
 * response's `hmac_secret`. Expected to be primed by
 * `markDocsBootstrapCredentialAsKnown` at every awareness point in
 * `getOrBootstrapDocsSandboxCredential`.
 *
 * 2. INVARIANT-DSGW-2: hex32 (exactly 64 lowercase hex chars). Same
 * shape as the per-install HMAC secret minted by `randomHex(32)`
 * in `handleMobileSandboxRegister`. Expected to be primed by
 * `markMobileSandboxSecretAsKnown` at every awareness point in
 * `mobile-sandbox.ts` (mint, KV write, KV read).
 *
 * A bare `[REDACTED]` on either candidate shape means a future refactor
 * likely dropped one of the awareness hooks. The canary emits one
 * warning per unique unregistered candidate, with the message naming
 * the specific invariant that may be broken.
 *
 * Dedup is module-scoped so a noisy log stream cannot spam every
 * request with the same warning. We track the candidate value itself
 * in a `Set` rather than an opaque flag because the sanitiser may see
 * the SAME unregistered value many times in one isolate (one stray log
 * call inside a per-request loop) and we only want one warning per
 * unique candidate; if a NEW unregistered value of the same shape
 * shows up later that is genuinely a separate signal worth logging.
 *
 * The canonical-message fixture SHA never reaches this canary because
 * the `hex32` pattern's `isPublicHexInvariant` allowlist short-circuits
 * the redaction altogether, so the value never enters
 * `redactionTagSyncCached` and never reaches `maybeEmitInvariantCanary`.
 * No extra carve-out is needed here.
 */
const canaryEmittedFor = new Set<string>();
const CANARY_DEDUP_MAX = 32;
/**
 * b64url256 shape detector: 43 or 44 base64url chars, optional `=` pad.
 * Same character class as the `b64url256` SECRET_PATTERNS entry below
 * but pinned to the FULL string rather than a substring; the canary
 * fires per-match in the sync redaction path so the input here is
 * already the matched substring and we just need to confirm it really
 * is the bootstrap-cred shape rather than a longer hex blob that
 * happened to slip past the lookarounds.
 */
const BOOTSTRAP_CRED_SHAPE = /^[A-Za-z0-9_-]{43,44}={0,1}$/;
/**
 * Mobile sandbox per-install HMAC secret shape: exactly 64 lowercase
 * hex chars, the canonical output shape of `randomHex(32)` in
 * `mobile-sandbox.ts`. Anchored on the full string so the canary only
 * fires for values that match the mint format precisely; arbitrary
 * 64-char mixed-case hex blobs (HMAC tags, SHA-256 digests of public
 * data, fixture digests) take the bare-redaction path without firing
 * the canary because they never match the lowercase-only mint format.
 * Discriminator strength: not perfect (any other lowercase 64-hex
 * value will fire too), but good enough that the noise floor in normal
 * traffic stays close to zero, and any genuine miss of a per-install
 * mint registration produces an audible signal.
 */
const MOBILE_SBX_SECRET_SHAPE = /^[0-9a-f]{64}$/;

function maybeEmitInvariantCanary(matchedValue: string): void {
  let invariantTag: string | null = null;
  if (BOOTSTRAP_CRED_SHAPE.test(matchedValue)) {
    invariantTag = "INVARIANT-DSGW-1";
  } else if (MOBILE_SBX_SECRET_SHAPE.test(matchedValue)) {
    invariantTag = "INVARIANT-DSGW-2";
  }
  if (invariantTag === null) return;
  if (tagCache.has(matchedValue)) return;
  if (canaryEmittedFor.has(matchedValue)) return;
  if (canaryEmittedFor.size >= CANARY_DEDUP_MAX) {
 // Already fired enough to alert on; further entries would just be
 // noise. The sanitiser keeps redacting the value either way.
    return;
  }
  canaryEmittedFor.add(matchedValue);
 // We MUST go through the original (non-wrapped) `console.warn` here
 // because the sanitised facade installed by `installLogSanitizer`
 // would call back into `sanitiseStringSync`, which would call back
 // into `maybeEmitInvariantCanary`, etc. The warning string is a
 // fixed literal with no secret material in it, so emitting on the
 // raw console is safe.
  const shapeLabel =
    invariantTag === "INVARIANT-DSGW-1"
      ? "bootstrap-cred-shaped"
      : "mobile-sandbox-secret-shaped";
  console.warn(
    `[log-sanitizer] ${shapeLabel} value redacted without registration. ${invariantTag} may be broken.`,
  );
}

/**
 * Import the HMAC key. Called from `installLogSanitizer` at module boot.
 * Subsequent calls with an unchanged key material are a no-op.
 */
async function ensureKey(keyMaterial: string | null): Promise<CryptoKey | null> {
  if (!keyMaterial) {
    cachedKey = null;
    cachedKeyMaterial = null;
    tagCache.clear();
    return null;
  }
  if (cachedKey && cachedKeyMaterial === keyMaterial) {
    return cachedKey;
  }
  const enc = new TextEncoder();
  cachedKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(keyMaterial),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  cachedKeyMaterial = keyMaterial;
  tagCache.clear();
  return cachedKey;
}

function redactionMarker(): string {
  return "[REDACTED]";
}

/**
 * Compute the 8-hex redaction tag for a single secret value.
 *
 * Returns `[REDACTED]` if the HMAC key is not provisioned. Returns
 * `[REDACTED:<8-hex>]` once the key is available. Result is memoised in
 * `tagCache` so the sync console wrapper path can hit the cache on
 * subsequent calls for the same secret value.
 */
async function redactionTag(value: string): Promise<string> {
  if (!cachedKey) return redactionMarker();
  const cached = tagCache.get(value);
  if (cached !== undefined) return cached;
  const enc = new TextEncoder();
  const sig = await crypto.subtle.sign("HMAC", cachedKey, enc.encode(value));
  const bytes = new Uint8Array(sig);
  let hex = "";
  for (let i = 0; i < REDACTION_PREFIX_LEN / 2; i++) {
    const b = bytes[i] ?? 0;
    hex += b.toString(16).padStart(2, "0");
  }
  const tag = `[REDACTED:${hex}]`;
  if (tagCache.size >= MAX_TAG_CACHE) {
 // Drop the oldest entry. Map iteration order is insertion order.
    const first = tagCache.keys().next();
    if (!first.done && first.value !== undefined) tagCache.delete(first.value);
  }
  tagCache.set(value, tag);
  return tag;
}

/** Sync lookup against the memoised cache; returns `[REDACTED]` on miss. */
function redactionTagSyncCached(value: string): string {
  if (!cachedKey) return redactionMarker();
  const cached = tagCache.get(value);
  if (cached !== undefined) return cached;
 // INVARIANT-DSGW-{1,2} canary: a sync miss on a bootstrap-cred-shaped
 // (b64url256) or mobile-sandbox-secret-shaped (lowercase hex32) value
 // means the redactor is about to emit a tagless `[REDACTED]` for what
 // looks like a docs gateway sandbox secret. Either a future refactor
 // dropped a hook in `getOrBootstrapDocsSandboxCredential` or in
 // `mobile-sandbox.ts`, or a non-bootstrap caller logged a value of
 // those shapes that the gateway never registered. Either way, emit
 // one structured warning per unique value so CI can pick it up
 // without spamming live traffic.
  maybeEmitInvariantCanary(value);
  return redactionMarker();
}

/**
 * Pre-populate the tag cache for a list of known secret values so the
 * sync console wrapper path can always emit the full HMAC-tagged marker.
 * Called from `installLogSanitizer` with any concrete secret material
 * the caller already holds (binding values, the current bearer cookie).
 */
async function primeTagCache(values: ReadonlyArray<string>): Promise<void> {
  for (const v of values) {
    if (typeof v === "string" && v.length > 0) {
      await redactionTag(v);
    }
  }
}

/**
 * Async string sanitiser. Computes a stable HMAC tag for every match.
 * Used by `sanitiseStringWithTag` so callers that can await get a
 * stable HMAC tag rather than the bare marker.
 */
async function sanitiseStringAsync(s: string): Promise<string> {
  let out = s;
  for (const { regex, allowlist } of SECRET_PATTERNS) {
    const matches: Array<{ index: number; length: number; replacement: string }> = [];
    for (const m of out.matchAll(regex)) {
      const idx = m.index ?? 0;
      const fullMatch = m[0];
 // : per-pattern allowlist bypass. Published public invariants
 // (e.g., canonical-message fixture digest) must survive redaction so
 // logs stay useful for drift investigations.
      if (allowlist && allowlist(fullMatch)) continue;
      const captured = m[1] as string | undefined;
      let replacement: string;
      if (captured) {
        const tag = await redactionTag(fullMatch);
        replacement = `${captured}${ASSIGNMENT_MARKER}${tag}`;
      } else {
        replacement = await redactionTag(fullMatch);
      }
      matches.push({ index: idx, length: fullMatch.length, replacement });
    }
 // Apply right-to-left so earlier indices stay valid.
    for (let i = matches.length - 1; i >= 0; i--) {
      const entry = matches[i];
      if (!entry) continue;
      out = out.slice(0, entry.index) + entry.replacement + out.slice(entry.index + entry.length);
    }
  }
  return out;
}

/**
 * Sync string sanitiser. Uses the pre-populated tag cache so console
 * wrappers emit `[REDACTED:<hmac>]` for known values and fall back to
 * the bare marker only for unknown-on-the-fly matches. That fallback
 * is the fail-closed case flagged in the module docstring.
 */
function sanitiseStringSync(s: string): string {
  let out = s;
  for (const { regex, allowlist } of SECRET_PATTERNS) {
 // String.prototype.replace passes the offset as the second-last
 // argument followed by the source string. With patterns that carry
 // NO capture group, the second positional argument is the numeric
 // offset, NOT a captured string. Type the rest as `unknown[]` and
 // narrow the first slot to a string before treating it as a capture.
 // The previous `(match, p1?: string)` typing accepted a number at
 // runtime and emitted `<offset>=[REDACTED]` for capture-less patterns
 // ( + regressions).
    out = out.replace(regex, (...args: unknown[]) => {
      const match = args[0] as string;
 // : per-pattern allowlist bypass for public invariants.
      if (allowlist && allowlist(match)) return match;
      const maybeCaptured = args[1];
      if (typeof maybeCaptured === "string" && maybeCaptured.length > 0) {
        return `${maybeCaptured}${ASSIGNMENT_MARKER}${redactionTagSyncCached(match)}`;
      }
      return redactionTagSyncCached(match);
    });
  }
  return out;
}

/**
 * Walk an arbitrary value tree and sanitise every leaf string.
 *
 * Cycle protection: a `WeakSet` records every object we descend into.
 * Unknown types stringify; null and undefined pass through.
 */
function walkSync(value: unknown, seen: WeakSet<object>): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return sanitiseStringSync(value);
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return value;
  }
  if (typeof value === "symbol" || typeof value === "function") {
    return sanitiseStringSync(String(value));
  }
  if (typeof value === "object") {
    if (seen.has(value as object)) return "[Circular]";
    seen.add(value as object);
    if (Array.isArray(value)) {
      return value.map((v) => walkSync(v, seen));
    }
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = walkSync(v, seen);
    }
    return out;
  }
  return value;
}

/**
 * Sanitise a list of console-style arguments (varargs). Used by the
 * `console.*` wrappers.
 */
export function sanitiseArgs(args: ReadonlyArray<unknown>): unknown[] {
  const seen = new WeakSet<object>();
  return args.map((a) => walkSync(a, seen));
}

/**
 * Constant-time equality check against secret material.
 *
 * Wraps `crypto.subtle.timingSafeEqual` per the project security policy: hand-rolled
 * comparisons are prohibited. Returns false immediately on length
 * mismatch because length is not itself secret, which also protects
 * the underlying primitive from being called with mismatched buffers.
 */
export function constantTimeEqualsString(candidate: string, known: string): boolean {
  if (typeof candidate !== "string" || typeof known !== "string") return false;
  if (candidate.length !== known.length) return false;
  const enc = new TextEncoder();
  const a = enc.encode(candidate);
  const b = enc.encode(known);
  if (a.byteLength !== b.byteLength) return false;
  return crypto.subtle.timingSafeEqual(a, b);
}

/**
 * Initialise the redaction key and return a sanitised console facade.
 *
 * The facade replaces `log`, `info`, `warn`, `error`, `debug`, and
 * `trace` so every argument walks through `sanitiseArgs` before being
 * forwarded to the real console method. A sanitised facade is preferred
 * over monkey-patching the global `console` because monkey-patching
 * would also affect Workers runtime internals (stack trace printing,
 * source map resolution), which is undesirable.
 *
 * @param keyMaterial HMAC key sourced from the `LOG_SANITIZER_KEY`
 * Secrets Store binding. Null or empty input
 * puts the sanitiser in fail-closed mode.
 * @param knownSecrets Optional list of concrete secret values the
 * caller already holds (bearer cookies, bound
 * secret values). Pre-populates the tag cache
 * so sync console wrappers emit the full
 * `[REDACTED:<hmac>]` marker.
 * @param target Console to wrap. Defaults to the global.
 */
export async function installLogSanitizer(
  keyMaterial: string | null,
  knownSecrets: ReadonlyArray<string> = [],
  target: Console = console,
): Promise<{
  console: Console;
  sanitiseString(s: string): Promise<string>;
  constantTimeEqualsString(candidate: string, known: string): boolean;
}> {
  await ensureKey(keyMaterial);
  await primeTagCache(knownSecrets);

  const wrapMethod =
    (method: (...args: unknown[]) => void) =>
    (...args: unknown[]) => {
      method(...sanitiseArgs(args));
    };

 // Create a sanitised facade rather than monkey-patching the global.
  const originals = {
    log: target.log.bind(target),
    info: target.info.bind(target),
    warn: target.warn.bind(target),
    error: target.error.bind(target),
    debug: target.debug.bind(target),
    trace: target.trace.bind(target),
  };
  const safeConsole: Console = Object.create(target) as Console;
  safeConsole.log = wrapMethod(originals.log);
  safeConsole.info = wrapMethod(originals.info);
  safeConsole.warn = wrapMethod(originals.warn);
  safeConsole.error = wrapMethod(originals.error);
  safeConsole.debug = wrapMethod(originals.debug);
  safeConsole.trace = wrapMethod(originals.trace);

  return {
    console: safeConsole,
    sanitiseString: sanitiseStringAsync,
    constantTimeEqualsString,
  };
}

/**
 * One-shot async sanitiser for callers that DO want the HMAC tag and
 * can afford the await. `await installLogSanitizer(...)` then
 * `await sanitiseStringWithTag("...secret...")` for one-off fields that
 * never hit `console`.
 */
export async function sanitiseStringWithTag(s: string): Promise<string> {
  return sanitiseStringAsync(s);
}

/**
 * Register a freshly-minted secret with the redaction tag cache so that
 * any subsequent log line containing the value is replaced with the
 * full `[REDACTED:<hmac>]` marker rather than leaking through.
 *
 * Used by the docs gateway bootstrap path (`getOrBootstrapDocsSandboxCredential`)
 * after `register-test-origin` returns a new HMAC secret. The static-secret
 * pattern primed the cache once at sanitiser install; the self-bootstrap
 * pattern mints a fresh secret on a 72-hour cadence, so each refresh
 * has to top up the cache.
 *
 * No-op when the input is empty or when the HMAC key has not been
 * provisioned (the sanitiser is in fail-closed mode and emits the bare
 * `[REDACTED]` marker either way).
 */
export async function registerKnownSecret(value: string): Promise<void> {
  if (typeof value !== "string" || value.length === 0) return;
  await redactionTag(value);
}

/**
 * Test-only entry points. Not exported by `index.ts`. Exposed here so
 * unit tests can exercise the deterministic-tag behaviour without
 * having to thread the cached key through the public API.
 */
export const __testing = {
  sanitiseStringSync,
  sanitiseStringAsync,
  redactionMarker,
  redactionTag,
  patterns: SECRET_PATTERNS,
  primeTagCache,
  /**
 * INVARIANT-DSGW-1 test helper: returns true when `value` is in the
 * redaction tag cache (either pre-primed at install time or registered
 * via `registerKnownSecret`). Used by the bootstrap regression test to
 * confirm `markDocsBootstrapCredentialAsKnown` ran during the
 * cold-isolate-after-peer-mint path. Test-only because exposing the
 * cache to production callers would let them probe for known secret
 * values; the test export is gated behind `__testing` and never reached
 * from `index.ts`.
   */
  isRegistered(value: string): boolean {
    return tagCache.has(value);
  },
  /** Test-only: how many entries the canary has fired for so far. */
  canaryEmittedCount(): number {
    return canaryEmittedFor.size;
  },
  resetCache(): void {
    cachedKey = null;
    cachedKeyMaterial = null;
    tagCache.clear();
    canaryEmittedFor.clear();
  },
};
