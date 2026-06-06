# Demo: Cloudflare Worker provii-agegate Edge Injection

Reference implementation of an edge Worker that injects Provii's provii-agegate into HTML responses using Cloudflare's HTMLRewriter API.

This Worker demonstrates the injection pattern described in the [Edge Injection Specification](https://docs.provii.app/partners/edge-injection).

## What It Does

The Worker intercepts all responses from an origin server. For HTML responses, it injects two elements.

A FOUC prevention `<style>` in `<head>` that hides the page body until provii-agegate renders its overlay. A CSS animation makes the body visible after 5 seconds as a safety net if the script fails to load.

The provii-agegate `<script>` tag before `</body>` with the configured public key, environment, and optional language and SRI hash.

Non-HTML responses (images, JSON, CSS, etc.) pass through unchanged.

If the origin sends a `Content-Security-Policy` header, the Worker adds `cdn.provii.app` to `script-src` and `verify.provii.app` (or `sandbox-verify.provii.app` in sandbox) to `connect-src`.

## Local Testing

Install dependencies and start the dev server:

```bash
npm install
npm run dev
```

Wrangler starts a local dev server (default `http://localhost:8787`). You need an origin server for the Worker to proxy. The simplest approach is to use `wrangler dev --remote` with a route pointing at a real site, or set up a local origin.

To test with a local HTML file, create a simple origin server. For example, using Python:

```bash
# In a separate terminal, serve a test HTML page on port 8080
echo '<!DOCTYPE html>
<html lang="en">
<head><title>Test Page</title></head>
<body><h1>Hello, this page should be age-gated</h1></body>
</html>' > /tmp/test.html

cd /tmp && python3 -m http.server 8080
```

Then update `wrangler.toml` to proxy to that origin, or use `wrangler dev` with `--upstream` if available.

## Configuration

All configuration is via environment variables in `wrangler.toml` or the Cloudflare dashboard.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PROVII_PUBLIC_KEY` | Yes | (none) | Your `pk_live_` or `pk_test_` public key from the Partner API |
| `PROVII_ENVIRONMENT` | Yes | (none) | `"production"` or `"sandbox"` |
| `PROVII_LANG` | No | (auto-detect) | BCP 47 language code for the age gate UI |
| `PROVII_SRI_HASH` | No | (none) | SRI hash from the version manifest |
| `PROVII_SDK_VERSION` | No | `v1` (major) | Exact version to pin, e.g. `"1.2.3"` |

## Deployment

```bash
npm run deploy
```

In production, configure routes in `wrangler.toml` to match your customer's domain:

```toml
routes = [
 { pattern = "example.com/*", zone_name = "example.com" }
]
```

## Type Checking

```bash
npm run typecheck
```
