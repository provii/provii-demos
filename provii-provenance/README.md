# provii-provenance

Cloudflare Worker that serves the R2 provenance archive at `provenance.provii.app`. Replaces the static `index.html` previously stored in the bucket with dynamic directory listings and file serving.

## What it does

When a request path ends with `/` or has no file extension, the Worker lists the contents of that R2 prefix as an HTML page with breadcrumb navigation, human-readable file sizes, and last-modified dates. The root page includes explanatory content about the archive (artefact table, signature verification commands, SLSA provenance examples).

When a request path matches an R2 object key, the Worker streams the object with correct `Content-Type`, `Content-Disposition`, `Cache-Control`, and security headers. Release and SHA paths are served as immutable with a 24-hour cache. `latest.json` files get a 5-minute cache so downstream consumers pick up new specs quickly.

## Local development

```bash
npm install
npx wrangler dev --local
```

Local R2 is empty, so you will see directory listings with no entries. To test against real data:

```bash
npx wrangler dev --remote
```

This requires R2 bucket access on the Cloudflare account.

## Type checking

```bash
npx tsc --noEmit
```

## Smoke tests

```bash
bash scripts/smoke.sh
```

Starts a local dev server, runs curl assertions (root page content, security headers, 404 for missing objects, 405 for POST), then tears down.

## Deploy

Tim deploys when ready:

```bash
cd provii-provenance
wrangler deploy --env production
```

After deployment, delete the static `index.html` and any root-key objects from the `provii-api-specs` R2 bucket, since the Worker now generates listings dynamically.
