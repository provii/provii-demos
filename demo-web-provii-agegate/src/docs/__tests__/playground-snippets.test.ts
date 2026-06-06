// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Mode-picker tests for the playground snippet generator.
 *
 * The playground UI exposes a Simple / Expert / Mobile mode picker with
 * per-mode language sub-tabs. The Worker's `buildCodeSnippets` function
 * produces every language for every mode in one bundle so the front end
 * can switch without a round-trip. These tests lock the bundle shape +
 * the per-mode credential-rendering rules used by the front-end.
 *
 * The Mobile tab carries app-side snippets only (iOS, Android, Flutter).
 * Backend signing recipes live in the Expert tab; the Mobile tab no longer
 * ships its own Node.js backend snippet.
 *
 * Why pure-function tests:
 * - `buildCodeSnippets` has no side effects.
 * - The credential visibility rule lives both in the front end (
 * `playground.js#CREDENTIAL_FIELDS_BY_MODE`) and conceptually here:
 * the test re-states the rule and asserts each snippet only embeds
 * the credentials its mode is allowed to show.
 * - Avoids having to spin up a DOM in the Workers test pool. Browser
 * wiring (clicks, focus, ARIA toggles) is exercised manually by
 * `npm run test-local` per the TS testing guardrails.
 */

import { describe, expect, it } from "vitest";

import { buildCodeSnippets } from "../../index";

const fixtureClientId = "rp_sandbox_clientid_abc123";
const fixtureHmacSecret = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const fixtureApiKey = "sandbox_api_key_xyz789";
const fixturePublicKey = "pk_sandbox_publickey_def456";

function buildFixture() {
  return buildCodeSnippets(
    fixtureClientId,
    fixtureHmacSecret,
    fixtureApiKey,
    fixturePublicKey,
  );
}

describe("buildCodeSnippets bundle shape", () => {
  it("returns the full eight-snippet bundle", () => {
    const bundle = buildFixture();
    expect(Object.keys(bundle).sort()).toEqual(
      [
        "agegateJs",
        "androidKotlin",
        "curl",
        "flutterDart",
        "go",
        "iosSwift",
        "nodejs",
        "python",
      ].sort(),
    );
  });

  it("does not ship a Mobile-tab backend snippet (Expert tab is canonical)", () => {
    const bundle = buildFixture();
 // The Mobile tab is for app-side code only. cURL, Node.js, Python and Go
 // signing recipes live in the Expert tab. Reintroducing a Mobile-tab
 // backend snippet duplicates the Expert content and confuses fresh devs.
    expect(bundle).not.toHaveProperty("mobileBackendNodejs");
  });

  it("preserves the original field names", () => {
    const bundle = buildFixture();
    expect(typeof bundle.agegateJs).toBe("string");
    expect(typeof bundle.curl).toBe("string");
    expect(typeof bundle.nodejs).toBe("string");
 // The pre-mode-picker snippets had this exact public-key + sandbox env
 // wiring; if either disappears we've broken existing copy-paste flows.
    expect(bundle.agegateJs).toContain(`data-public-key="${fixturePublicKey}"`);
    expect(bundle.agegateJs).toContain(`data-environment="sandbox"`);
  });
});

describe("Simple mode (provii-agegate script tag)", () => {
  it("embeds only the public key, never secrets", () => {
    const bundle = buildFixture();
    const simple = bundle.agegateJs;
    expect(simple).toContain(fixturePublicKey);
    expect(simple).not.toContain(fixtureHmacSecret);
    expect(simple).not.toContain(fixtureApiKey);
    expect(simple).not.toContain(fixtureClientId);
  });
});

describe("Expert mode credential plumbing", () => {
  const expertLanguages: Array<keyof ReturnType<typeof buildCodeSnippets>> = [
    "curl",
    "nodejs",
    "python",
    "go",
  ];

  for (const lang of expertLanguages) {
    it(`${lang} embeds clientId, hmacSecret and apiKey`, () => {
      const bundle = buildFixture();
      const snippet = bundle[lang];
      expect(snippet).toContain(fixtureClientId);
      expect(snippet).toContain(fixtureHmacSecret);
      expect(snippet).toContain(fixtureApiKey);
    });

    it(`${lang} states the corrected sandbox vs production Origin behaviour`, () => {
      const bundle = buildFixture();
      const snippet = bundle[lang];
 // Every expert snippet must reflect the server reality: sandbox accepts
 // any Origin value (allowlist bypassed), production enforces the
 // registered allowed_origins. No "no Origin needed" wording allowed.
      expect(snippet).toMatch(/accept ANY Origin/);
      expect(snippet).toMatch(/bypassed in sandbox/);
      expect(snippet).toMatch(/allowed_origins/);
      expect(snippet).not.toMatch(/no Origin header is needed/i);
    });

    it(`${lang} sends an Origin header on the live request`, () => {
      const bundle = buildFixture();
      const snippet = bundle[lang];
 // Server returns 400 BAD_REQUEST when Origin is omitted. The snippet
 // must include an Origin header so a fresh dev sees what to substitute.
      expect(snippet).toContain("https://your-shop.example.com");
      expect(snippet).toMatch(/Origin/);
    });

    it(`${lang} embeds a PKCE recipe rather than a placeholder`, () => {
      const bundle = buildFixture();
      const snippet = bundle[lang];
 // A bare YOUR_PKCE_CHALLENGE placeholder leaves cURL devs with no path
 // to a working request. Each snippet now derives the challenge inline.
      expect(snippet).not.toContain("YOUR_PKCE_CHALLENGE");
      expect(snippet.toLowerCase()).toMatch(/pkce/);
      expect(snippet.toLowerCase()).toMatch(/code[_ ]?verifier|codeverifier/);
      expect(snippet.toLowerCase()).toMatch(/code[_ ]?challenge|codechallenge/);
    });
  }

  it("Python uses requests + hmac per Tim's brief", () => {
    const bundle = buildFixture();
    expect(bundle.python).toContain("import hmac");
    expect(bundle.python).toContain("import requests");
    expect(bundle.python).toContain("hashlib.sha256");
  });

  it("Python carries the field-order-matters comment", () => {
    const bundle = buildFixture();
 // Reordering keys silently breaks the HMAC signature. Node and Go
 // already warn inline; Python now does the same.
    expect(bundle.python).toMatch(/[Ff]ield order is significant/);
    expect(bundle.python).toMatch(/sort_keys/);
  });

  it("Go uses net/http + crypto/hmac per Tim's brief", () => {
    const bundle = buildFixture();
    expect(bundle.go).toContain('"net/http"');
    expect(bundle.go).toContain('"crypto/hmac"');
    expect(bundle.go).toContain("sha256.New");
  });

  it("Go uses a typed struct rather than map[string]any for the body", () => {
    const bundle = buildFixture();
 // encoding/json marshals maps in alphabetical key order. The HMAC must
 // be computed over insertion-ordered JSON, so structs are the only safe
 // pattern. The shipped snippet must not regress to map[string]any.
    expect(bundle.go).toContain("type challengeBody struct");
    expect(bundle.go).toContain("type fullBody struct");
    expect(bundle.go).not.toMatch(/body\s*:?=\s*map\[string\]any/);
  });

  it("Go snippet has a runnable main()", () => {
    const bundle = buildFixture();
 // Without main() the snippet does not compile as a standalone file.
    expect(bundle.go).toMatch(/func main\(\)/);
    expect(bundle.go).toMatch(/createChallenge\(\)/);
  });

  it("Node snippet uses ESM import for crypto, not CommonJS require", () => {
    const bundle = buildFixture();
 // .mjs + require() trips Node 22+ ERR_AMBIGUOUS_MODULE_SYNTAX. Convert
 // to ESM and tell devs to save as .mjs or set "type": "module".
    expect(bundle.nodejs).toContain("import crypto from 'node:crypto'");
    expect(bundle.nodejs).not.toMatch(/require\(['"]crypto['"]\)/);
    expect(bundle.nodejs).toMatch(/save as \.mjs|type.*module/);
  });

  it("cURL echoes the code_verifier so devs can save it for redeem (R3 NEW-M/cURL)", () => {
    const bundle = buildFixture();
 // Without an echo, the dev sees the challenge response but the verifier
 // they need at redeem time is silently lost in the shell session. R4
 // braces every variable expansion to dodge the zsh `:P` modifier trap,
 // so the regex must accept either `$CODE_VERIFIER` or `${CODE_VERIFIER}`.
    expect(bundle.curl).toMatch(/echo\s+"code_verifier \(save for redeem\):\s+\$\{?CODE_VERIFIER\}?"/);
  });

  it("Node returns codeVerifier paired with the challenge response (R3 NEW-M/Node)", () => {
    const bundle = buildFixture();
 // Returning res.json() alone discards the verifier the caller needs at
 // redeem time. Pair both into a single return so the caller can persist.
    expect(bundle.nodejs).toMatch(/return\s*\{\s*challenge,\s*codeVerifier\s*\}/);
  });

  it("Node surfaces the structured error envelope on non-2xx (R3 NEW-L)", () => {
    const bundle = buildFixture();
 // Returning res.json() blindly lets a 4xx error envelope parse silently
 // as if it were a successful challenge. Check res.ok and surface
 // {code, field, detail, request_id} per the contract.
    expect(bundle.nodejs).toMatch(/if\s*\(\s*!res\.ok\s*\)/);
    expect(bundle.nodejs).toMatch(/errBody\.code/);
    expect(bundle.nodejs).toMatch(/errBody\.detail/);
    expect(bundle.nodejs).toMatch(/errBody\.field/);
    expect(bundle.nodejs).toMatch(/errBody\.request_id/);
  });

  it("Python surfaces the structured error envelope rather than raise_for_status (R3 NEW-K)", () => {
    const bundle = buildFixture();
 // raise_for_status() throws an HTTPError with no body content, hiding
 // the diagnostic the emits. Check response.ok and surface
 // {code, field, detail, request_id} from the JSON body instead.
    expect(bundle.python).toMatch(/if not response\.ok/);
    expect(bundle.python).toMatch(/err\.get\('code'/);
    expect(bundle.python).toMatch(/err\.get\('detail'/);
    expect(bundle.python).toMatch(/err\.get\('field'/);
    expect(bundle.python).toMatch(/err\.get\('request_id'/);
 // raise_for_status() may still appear in the JSON-decode fallback, but
 // it must not be the only error path.
    expect(bundle.python).not.toMatch(/^\s*response\.raise_for_status\(\)\s*\n\s*return response\.json\(\)/m);
  });

  it("Python returns code_verifier paired with the challenge response (R3 NEW-M/Python)", () => {
    const bundle = buildFixture();
    expect(bundle.python).toMatch(/return\s*\{\s*'challenge'\s*:\s*response\.json\(\)\s*,\s*'code_verifier'\s*:\s*code_verifier\s*\}/);
  });

  it("Go does not discard codeVerifier with `_ =` and pairs it with the response (R3 NEW-M/Go)", () => {
    const bundle = buildFixture();
 // The original snippet's `_ = codeVerifier` threw away the value the
 // caller needs at redeem. Result struct must carry both fields.
    expect(bundle.go).not.toMatch(/_\s*=\s*codeVerifier/);
    expect(bundle.go).toContain("type challengeResult struct");
    expect(bundle.go).toMatch(/CodeVerifier\s+string/);
    expect(bundle.go).toMatch(/Challenge\s+map\[string\]any/);
    expect(bundle.go).toMatch(/code_verifier \(save for redeem\)/);
  });

  it("Go surfaces the structured error envelope on non-2xx (R3 NEW-L/Go)", () => {
    const bundle = buildFixture();
    expect(bundle.go).toMatch(/resp\.StatusCode\s*>=\s*400/);
    expect(bundle.go).toMatch(/out\["code"\]/);
    expect(bundle.go).toMatch(/out\["detail"\]/);
    expect(bundle.go).toMatch(/out\["field"\]/);
    expect(bundle.go).toMatch(/out\["request_id"\]/);
  });

  it("every Expert snippet base64url-decodes the HMAC secret before signing", () => {
 // provii-verifier / inverted the on-the-wire contract.
 // The 43-char hmac_secret is base64url transport encoding; the server
 // stores 32 raw bytes and verifies against them. Snippets that sign
 // under the ASCII bytes of the 43-char string produce 401 INVALID_HMAC.
    const bundle = buildFixture();

 // cURL: openssl needs the decoded bytes as hex via -macopt hexkey, so
 // the snippet must build SECRET_HEX from the base64url string before
 // the openssl dgst call. The old `-hmac '${hmacSecret}'` path is
 // forbidden because openssl uses its argument as raw key material.
    expect(bundle.curl).toContain("base64 -d");
    expect(bundle.curl).toContain("xxd -p");
    expect(bundle.curl).toMatch(/-macopt\s+hexkey:/);
    expect(bundle.curl).not.toMatch(/-hmac\s+'?\$\{?HMAC_SECRET\}?'?/);
    expect(bundle.curl).not.toMatch(/-hmac\s+'\$\{hmacSecret\}'/);

 // Node.js: Buffer.from(HMAC_SECRET, 'base64url') is the canonical
 // decode and must precede crypto.createHmac.
    expect(bundle.nodejs).toMatch(/Buffer\.from\(\s*HMAC_SECRET\s*,\s*['"]base64url['"]\s*\)/);
    expect(bundle.nodejs).not.toMatch(/createHmac\(\s*['"]sha256['"]\s*,\s*HMAC_SECRET\s*\)/);

 // Python: urlsafe_b64decode with re-padding to a multiple of 4.
    expect(bundle.python).toMatch(/base64\.urlsafe_b64decode\(/);
    expect(bundle.python).toMatch(/HMAC_SECRET \+ ['"]=['"] \* \(-len\(HMAC_SECRET\) % 4\)/);
    expect(bundle.python).not.toMatch(/HMAC_SECRET\.encode\(['"]utf-8['"]\)/);

 // Go: base64.RawURLEncoding.DecodeString feeds hmac.New.
    expect(bundle.go).toMatch(/base64\.RawURLEncoding\.DecodeString\(\s*hmacSecret\s*\)/);
    expect(bundle.go).not.toMatch(/hmac\.New\(\s*sha256\.New\s*,\s*\[\]byte\(hmacSecret\)\s*\)/);
  });

  it("PKCE comments correctly state the backend (not wallet) returns the verifier (R3 NEW-N)", () => {
    const bundle = buildFixture();
 // Round 2 surfaced that "the wallet returns it back" is inaccurate. The
 // dev's backend hands code_verifier back to provii-verifier at redeem; the
 // wallet never sees it.
    for (const lang of ["nodejs", "python", "go"] as const) {
      expect(bundle[lang]).not.toMatch(/wallet returns it back/);
    }
  });

  it("cURL snippet substitutes CODE_CHALLENGE consistently in BODY and curl -d", () => {
    const bundle = buildFixture();
    const curl = bundle.curl;
 // The trap: YOUR_PKCE_CHALLENGE appearing twice means devs editing the
 // curl body alone get a silent HMAC mismatch. Both occurrences must
 // resolve to the same shell variable. R4 braces every variable
 // expansion (`${CODE_CHALLENGE}`) to dodge the zsh `:P` modifier trap,
 // so the regex tolerates both forms.
    expect(curl).not.toContain("YOUR_PKCE_CHALLENGE");
    const challengeUses = curl.match(/\$\{?CODE_CHALLENGE\}?/g) ?? [];
    expect(challengeUses.length).toBeGreaterThanOrEqual(2);
    expect(curl).toMatch(/CODE_VERIFIER=/);
    expect(curl).toMatch(/CODE_CHALLENGE=/);
  });

  it("cURL braces every variable expansion to dodge the zsh `:P` modifier (R4 NEW-R4-C)", () => {
    const bundle = buildFixture();
    const curl = bundle.curl;
 // zsh on macOS parses `$TIMESTAMP:POST` as `${TIMESTAMP:P}OST`, the
 // `:P` absolute-pathname modifier, turning the canonical message into
 // a filesystem path and producing 401 INVALID_HMAC. The fix is braces
 // around every variable expansion.
    expect(curl).toContain('MESSAGE="${TIMESTAMP}:POST:/v1/challenge:${BODY}:${NONCE}"');
 // Comment text may still cite `$TIMESTAMP:POST` to explain the trap, so
 // we only filter out the executable shell lines (those that don't begin
 // with a `#`) before scanning for the unbraced colon-letter form.
    const executableLines = curl
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("#"))
      .join("\n");
    expect(executableLines).not.toMatch(/\$TIMESTAMP:POST/);
    expect(executableLines).not.toMatch(/\$BODY:\$NONCE/);
  });

  it("cURL strips the trailing newline from openssl base64 output (R4 NEW-R4-B)", () => {
    const bundle = buildFixture();
    const curl = bundle.curl;
 // `openssl rand -base64 96` emits a trailing LF + line breaks every 64
 // chars. The first `tr` must strip both `=` and `\n` so the verifier is
 // RFC 7636-conformant rather than passing by luck through `head -c 128`.
    expect(curl).toContain("openssl rand -base64 96 | tr -d '=\\n'");
  });

  it("cURL extends the snippet to status poll and redeem (R4 NEW-R4-D)", () => {
    const bundle = buildFixture();
    const curl = bundle.curl;
 // After challenge creation, fresh devs need an inline path to poll +
 // redeem. The trailing comment block shows both calls and warns that
 // the long API_KEY (not pk_test_*) is the right X-API-Key value.
    expect(curl).toMatch(/SESSION_ID=/);
    expect(curl).toMatch(/proof_ok_waiting_for_redeem/);
    expect(curl).toContain("/v1/challenge/${SESSION_ID}");
    expect(curl).toContain("/v1/challenge/${SESSION_ID}/redeem");
    expect(curl).toMatch(/code_verifier/);
 // Every X-API-Key line in the snippet (create + poll + redeem) reuses
 // the same long apiKey value. The pk_* keys never end up on those
 // lines, only as a warning in the comment block.
    const apiKeyLines = curl
      .split("\n")
      .filter((line) => /X-API-Key:/.test(line));
    expect(apiKeyLines.length).toBeGreaterThanOrEqual(3);
    for (const line of apiKeyLines) {
      expect(line).toContain(fixtureApiKey);
      expect(line).not.toMatch(/pk_test_|pk_live_|pk_sandbox_/);
    }
  });
});

describe("Mobile mode credential plumbing", () => {
  it("native snippets never embed HMAC secret or API key on-device", () => {
    const bundle = buildFixture();
    const nativeClients = [bundle.iosSwift, bundle.androidKotlin, bundle.flutterDart];
    for (const snippet of nativeClients) {
      expect(snippet).not.toContain(fixtureHmacSecret);
      expect(snippet).not.toContain(fixtureApiKey);
      expect(snippet).not.toContain(fixtureClientId);
      expect(snippet).not.toContain(fixturePublicKey);
 // Each native client validates the deep link points to provii.app
      expect(snippet).toContain("https://provii.app/verify?");
    }
  });

  it("native snippet header comments cross-reference the Expert tab for backend code", () => {
    const bundle = buildFixture();
 // The Mobile tab no longer ships a backend snippet. Each native header
 // must point readers at the Expert tab so they know where the cURL /
 // Node.js / Python / Go signing recipes live.
    const nativeClients = [bundle.iosSwift, bundle.androidKotlin, bundle.flutterDart];
    for (const snippet of nativeClients) {
      expect(snippet).toMatch(/Expert tab/);
 // Should not imply a sibling Mobile-tab backend example exists.
      expect(snippet).not.toMatch(/Express route above|Node\.js Express handler/);
    }
  });

  it("iOS snippet uses URLSession + UIApplication.open", () => {
    const bundle = buildFixture();
    expect(bundle.iosSwift).toContain("URLSession.shared");
    expect(bundle.iosSwift).toContain("UIApplication.shared.open");
  });

  it("Android snippet uses Intent + Uri.parse", () => {
    const bundle = buildFixture();
    expect(bundle.androidKotlin).toContain("Intent(Intent.ACTION_VIEW");
    expect(bundle.androidKotlin).toContain("Uri.parse");
  });

  it("Flutter snippet uses url_launcher", () => {
    const bundle = buildFixture();
    expect(bundle.flutterDart).toContain("package:url_launcher/url_launcher.dart");
    expect(bundle.flutterDart).toContain("launchUrl");
  });
});

describe("Per-mode credential rendering rules (mirror of playground.js)", () => {
 // The credential rows in the DOM are filtered by these allowlists. The
 // server-side bundle is mode-agnostic, so this test acts as a contract:
 // the front-end visibility rule and the bundle must agree on what each
 // mode legitimately needs.
  const visibilityRule: Record<"simple" | "expert" | "mobile", readonly string[]> = {
    simple: ["publicKey", "expiresAt"],
    expert: ["publicKey", "clientId", "hmacSecret", "apiKey", "expiresAt"],
    mobile: ["publicKey", "clientId", "hmacSecret", "apiKey", "expiresAt"],
  };

  it("simple mode advertises only publicKey + expiresAt", () => {
    expect(visibilityRule.simple).toEqual(["publicKey", "expiresAt"]);
    expect(visibilityRule.simple).not.toContain("hmacSecret");
    expect(visibilityRule.simple).not.toContain("apiKey");
  });

  it("expert and mobile advertise the same five fields", () => {
    expect(visibilityRule.expert).toEqual(visibilityRule.mobile);
    expect(visibilityRule.expert).toHaveLength(5);
  });
});
