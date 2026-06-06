# Test Coverage Scope

## What is covered

Backend integration logic across all four runtime ecosystems:

| Backend | Tool | Gate | Actual | Scope |
|---------|------|------|--------|-------|
| Go verifier | `go test -cover` | 85% | ~86% | HMAC auth, PKCE, handlers, middleware, session management, router setup |
| Go issuer | `go test -cover` | 85% | ~90% | HMAC auth, canonical message, handlers, middleware, config loading, router setup |
| Python verifier | `pytest --cov` | 85% | ~85% | HMAC auth, PKCE, handlers, middleware, demo token validation, httpx integration |
| Python issuer | `pytest --cov` | 85% | ~87% | HMAC auth, canonical message, handlers, middleware, httpx integration |
| Node.js verifier | `vitest --coverage` | pass | pass | HMAC auth, PKCE, base64url, deep link, demo token validation |
| Node.js issuer | `vitest --coverage` | pass | pass | HMAC auth, canonical message, base64url, demo token validation |

All Go and Python backends enforce an 85% coverage gate in CI. Node.js tests
verify re-implemented core functions (the source files start a server at module
load time, preventing direct import in tests). The Go and Python backends test
handlers end-to-end via mock HTTP servers (Go) and mocked httpx responses
(Python), covering the full HMAC-SHA256 + nonce + PKCE verification flow and
HMAC-SHA256 + nonce attestation flow respectively.

## What is excluded

**Demo app UI (Flutter, React Native, SwiftUI, Compose):** these are illustrative
screens that render QR codes, deep links, and status badges. They contain no
security-critical logic (HMAC signing, PKCE, attestation handling). Testing UI
layout and navigation in four mobile frameworks provides no meaningful coverage
of integration correctness.

**Cloudflare Workers backends:** these share identical logic with the Node.js
backends (same TypeScript, same Hono framework). Testing them requires miniflare
or the Cloudflare Workers runtime, which adds CI complexity without additional
coverage of integration logic.

**Server startup code:** `main()` functions in Go, `if __name__ == "__main__"`
blocks in Python, and `main().catch()` calls in Node.js bind ports and print
configuration. These are untestable without starting actual servers. In Go, the
router setup, config loading, credential validation, and banner printing have
been extracted into testable functions (`newRouter()`, `loadConfig()`,
`requireCredentials()`, `printBanner()`) to minimise the untestable surface in
`main()`. The remaining `main()` body contains only `os.Exit`, `log.Fatal`, and
`ListenAndServe` calls.

**HTTP client calls to external APIs:** the functions that make real HTTP
requests to provii-verifier and provii-issuer (`createChallengeWithAPI`,
`pollChallengeStatus`, `redeemChallenge`, `createAttestation`) are tested
via mock servers in Go. In Python, these functions are tested via mocked
httpx responses at the transport layer, exercising the full HMAC signing,
canonical message construction, and response handling code paths. The actual
network I/O is the only thing excluded.

**Unreachable defensive error paths:** a small number of error handlers guard
against conditions that cannot occur in practice (e.g. `json.Marshal` failing
on a known-good map literal, `crypto/rand.Read` returning an error). These
account for the gap between actual coverage (~86-90%) and 100%.

## Rationale

The backends exist to demonstrate correct HMAC-SHA256 + nonce + PKCE
integration with provii-verifier, and correct HMAC-SHA256 + nonce
integration with provii-issuer (where Ed25519 attestation signing happens
server-side). Coverage targets the request validation, authentication
construction, session management, and response formatting that integrators
will adapt. Startup glue and UI chrome are outside this scope.
