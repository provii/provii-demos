export interface Env {
  BUCKET: R2Bucket;
}

const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'same-origin',
  'Permissions-Policy': 'interest-cohort=()',
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
};

const EXT_TYPES: Record<string, string> = {
  '.json': 'application/json', '.jsonl': 'application/jsonlines',
  '.sig': 'application/octet-stream', '.pem': 'application/x-pem-file',
  '.html': 'text/html; charset=utf-8', '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml', '.css': 'text/css; charset=utf-8', '.js': 'application/javascript',
};

function resolveContentType(key: string, r2ContentType: string | undefined): string {
  if (r2ContentType) return r2ContentType;
  const dotIndex = key.lastIndexOf('.');
  if (dotIndex === -1) return 'application/octet-stream';
  return EXT_TYPES[key.slice(dotIndex)] ?? 'application/octet-stream';
}

function isTextType(contentType: string): boolean {
  return contentType.startsWith('text/') || contentType.startsWith('application/json')
    || contentType === 'application/jsonlines' || contentType === 'application/x-pem-file';
}

function cacheControlForKey(key: string): string {
  if (key.includes('releases/') || key.includes('sha/')) return 'public, max-age=86400, immutable';
  if (key.endsWith('latest.json')) return 'public, max-age=300';
  return 'public, max-age=3600';
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, exponent);
  return `${value < 10 && exponent > 0 ? value.toFixed(1) : Math.round(value)} ${units[exponent]}`;
}

function formatDate(date: Date): string {
  return date.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

/** Escape characters that are dangerous in an HTML text context. */
function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Encode a full path (preserving slashes) for use in href attributes. */
function encodeHrefPath(path: string): string {
  return path.split('/').map(encodeURIComponent).join('/');
}

function buildBreadcrumbs(prefix: string): string {
  const segments = prefix.split('/').filter(Boolean);
  let html = '<nav class="breadcrumbs"><a href="/">root</a>';
  let accumulated = '';
  for (const segment of segments) {
    accumulated += segment + '/';
    html += ` / <a href="/${encodeHrefPath(accumulated)}">${escapeHtml(segment)}</a>`;
  }
  html += '</nav>';
  return html;
}

function buildDirectoryHtml(
  prefix: string,
  prefixes: string[],
  objects: { key: string; size: number; uploaded: Date; httpMetadata?: { contentType?: string } }[],
  includeIntro: boolean,
): string {
  const title = prefix === '' ? 'Provii Provenance Archive' : `Index of /${escapeHtml(prefix)}`;
  const breadcrumbs = buildBreadcrumbs(prefix);

  const rows: string[] = [];
  if (prefix !== '') {
    const parentSegments = prefix.split('/').filter(Boolean);
    parentSegments.pop();
    const parentPath = parentSegments.length > 0 ? '/' + parentSegments.join('/') + '/' : '/';
    rows.push(`<tr><td><a href="${encodeHrefPath(parentPath)}">..</a></td><td></td><td></td><td></td></tr>`);
  }
  for (const dirPrefix of prefixes) {
    const displayName = dirPrefix.slice(prefix.length);
    rows.push(`<tr><td><a href="/${encodeHrefPath(dirPrefix)}">${escapeHtml(displayName)}</a></td><td></td><td></td><td>directory</td></tr>`);
  }
  for (const object of objects) {
    const displayName = object.key.slice(prefix.length);
    if (displayName.includes('/')) continue;
    const ct = object.httpMetadata?.contentType ?? resolveContentType(object.key, undefined);
    rows.push(`<tr><td><a href="/${encodeHrefPath(object.key)}">${escapeHtml(displayName)}</a></td><td>${formatBytes(object.size)}</td><td>${formatDate(object.uploaded)}</td><td><code>${escapeHtml(ct)}</code></td></tr>`);
  }
  const listingHtml = `<div class="listing"><h2>Contents</h2><table><thead><tr><th>Name</th><th>Size</th><th>Modified</th><th>Type</th></tr></thead><tbody>${rows.join('')}</tbody></table></div>`;

  const introSection = includeIntro ? ROOT_INTRO_HTML : '';

  return `<!DOCTYPE html>
<html lang="en-AU">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  ${PAGE_STYLES}
</head>
<body>
  <h1>Provii Provenance Archive</h1>
  ${breadcrumbs}
  ${introSection}
  ${listingHtml}
  <footer><p>Report security vulnerabilities to <code>security@provii.app</code>. Source code is at <a href="https://github.com/provii-mobile">github.com/provii-mobile</a>.</p></footer>
</body>
</html>`;
}

function addSecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function isDirectoryRequest(pathname: string): boolean {
 // Only treat paths ending with / (or root /) as directories.
 // Extensionless files (e.g. SHA256SUMS) exist in R2 and must not be
 // misrouted to directory listing.
  return pathname === '/' || pathname.endsWith('/');
}

async function handleDirectoryListing(prefix: string, env: Env): Promise<Response> {
  const listResult = await env.BUCKET.list({ prefix: prefix === '' ? undefined : prefix, delimiter: '/' });
  const dirs = listResult.delimitedPrefixes ?? [];
  const objects = listResult.objects.map((obj) => ({
    key: obj.key, size: obj.size, uploaded: obj.uploaded,
    httpMetadata: obj.httpMetadata as { contentType?: string } | undefined,
  }));
  const html = buildDirectoryHtml(prefix, dirs, objects, prefix === '');
  return new Response(html, {
    status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=60' },
  });
}

async function handleFileRequest(key: string, env: Env): Promise<Response> {
  const object = await env.BUCKET.get(key);
  if (object === null) return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain' } });
  const contentType = resolveContentType(key, object.httpMetadata?.contentType);
  const headers: Record<string, string> = {
    'Content-Type': contentType,
    'Content-Disposition': isTextType(contentType) ? 'inline' : 'attachment',
    'Cache-Control': cacheControlForKey(key),
  };
  if (object.httpEtag) headers['ETag'] = object.httpEtag;
  return new Response(object.body, { status: 200, headers });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return addSecurityHeaders(
        new Response('Method not allowed', { status: 405, headers: { 'Content-Type': 'text/plain' } }),
      );
    }

    let pathname: string;
    try {
      pathname = decodeURIComponent(url.pathname);
    } catch {
      return addSecurityHeaders(
        new Response('Bad request: malformed percent-encoded path', { status: 400, headers: { 'Content-Type': 'text/plain' } }),
      );
    }
 // Strip leading slash to get R2 key/prefix
    const key = pathname.slice(1);

    let response: Response;
    if (isDirectoryRequest(pathname)) {
 // Normalise: ensure prefix ends with / unless it is empty
      const prefix = key === '' ? '' : key.endsWith('/') ? key : key + '/';
      response = await handleDirectoryListing(prefix, env);
    } else {
      response = await handleFileRequest(key, env);
    }

    return addSecurityHeaders(response);
  },
} satisfies ExportedHandler<Env>;

// ── HTML template fragments ─────────────────────────────────────────

const PAGE_STYLES = `<style>
  :root { --bg: #fafafa; --fg: #1a1a1a; --accent: #2563eb; --border: #e5e7eb; --code-bg: #f3f4f6; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #111; --fg: #e5e5e5; --accent: #60a5fa; --border: #333; --code-bg: #1e1e1e; }
  }
 * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--fg); line-height: 1.6; padding: 2rem 1rem; max-width: 56rem; margin: 0 auto; }
  h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
  h2 { font-size: 1.3rem; margin-top: 2rem; margin-bottom: 0.5rem; border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; }
  p, li { margin-bottom: 0.5rem; }
  ul { padding-left: 1.5rem; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  code { background: var(--code-bg); padding: 0.15rem 0.35rem; border-radius: 3px; font-size: 0.9em; }
  pre { background: var(--code-bg); padding: 1rem; border-radius: 6px; overflow-x: auto; margin: 0.75rem 0; }
  pre code { background: none; padding: 0; }
  table { width: 100%; border-collapse: collapse; margin: 0.75rem 0; }
  th, td { text-align: left; padding: 0.5rem 0.75rem; border: 1px solid var(--border); }
  th { background: var(--code-bg); font-weight: 600; }
  td a { display: block; }
  .breadcrumbs { margin-bottom: 1.5rem; font-size: 0.95rem; }
  .breadcrumbs a { margin: 0 0.15rem; }
  .note { background: var(--code-bg); border-left: 3px solid var(--accent); padding: 0.75rem 1rem; margin: 1rem 0; border-radius: 0 4px 4px 0; }
  .listing { margin-top: 2rem; }
  footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); font-size: 0.9rem; }
</style>`;

const ROOT_INTRO_HTML = `
<p>Public record of build provenance, Sigstore signatures, SBOMs, and SLSA attestations for every Provii release. Hosted independently of GitHub to satisfy ISO 27001 evidence retention requirements.</p>

<h2>What is stored here</h2>
<p>Each release directory contains a subset of the following artefacts, depending on what the repository produces:</p>

<table>
  <thead>
    <tr><th>Artefact</th><th>Format</th><th>Purpose</th></tr>
  </thead>
  <tbody>
    <tr><td>Cosign signature bundle</td><td><code>.cosign-bundle</code> / <code>.sig</code></td><td>Sigstore keyless signature proving the artefact was built by GitHub Actions</td></tr>
    <tr><td>SLSA provenance</td><td><code>.intoto.jsonl</code></td><td>SLSA Level 3 in-toto attestation linking the artefact to its source commit</td></tr>
    <tr><td>SBOM</td><td><code>.spdx.json</code> / <code>.cyclonedx.json</code></td><td>Software Bill of Materials listing every dependency</td></tr>
    <tr><td>SRI hash</td><td><code>.sri</code></td><td>Subresource Integrity hash for browser bundles</td></tr>
    <tr><td>Checksums</td><td><code>SHA256SUMS.txt</code></td><td>SHA-256 digests of all release files</td></tr>
  </tbody>
</table>

<h2>Repository layout</h2>
<p>Artefacts are organised by repository name and release tag. OpenAPI specs additionally store per-commit copies keyed by Git SHA.</p>

<table>
  <thead>
    <tr><th>Repository</th><th>Type</th><th>Path pattern</th></tr>
  </thead>
  <tbody>
    <tr><td>provii-verifier</td><td>Rust backend</td><td><code>provii-verifier/releases/&lt;tag&gt;/</code>, <code>provii-verifier/sha/&lt;sha&gt;/</code></td></tr>
    <tr><td>provii-issuer</td><td>Rust backend</td><td><code>provii-issuer/releases/&lt;tag&gt;/</code>, <code>provii-issuer/sha/&lt;sha&gt;/</code></td></tr>
    <tr><td>provii-mobile-sdk</td><td>Rust library</td><td><code>provii-mobile-sdk/releases/&lt;tag&gt;/</code></td></tr>
    <tr><td>provii-mobile</td><td>iOS + Android</td><td><code>provii/releases/&lt;tag&gt;/</code></td></tr>
    <tr><td>provii-agegate</td><td>TypeScript SDK</td><td><code>provii-agegate/releases/&lt;tag&gt;/</code></td></tr>
  </tbody>
</table>

<h2>Verifying signatures</h2>
<p>Install <a href="https://docs.sigstore.dev/cosign/system_config/installation/">cosign</a>, then verify any artefact against GitHub Actions OIDC identity:</p>

<pre><code># Verify a cosign bundle (provii-mobile-sdk example)
cosign verify-blob \\
  --bundle provii-mobile-sdk/releases/v0.4.2/provii-mobile-sdk-bundle.cosign-bundle \\
  --certificate-identity-regexp="https://github.com/provii/provii-mobile-sdk/.*" \\
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \\
  provii-mobile-sdk-bundle.tar.gz

# Verify a detached signature (provii-mobile example)
cosign verify-blob \\
  --signature provii/releases/v1.0.0/provii-mobile-1.0.0.apk.sig \\
  --certificate provii/releases/v1.0.0/provii-mobile-1.0.0.apk.pem \\
  --certificate-identity-regexp="https://github.com/provii/provii/.*" \\
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \\
  provii-mobile-1.0.0.apk</code></pre>

<h2>Verifying SLSA provenance</h2>
<p>Use the <a href="https://github.com/slsa-framework/slsa-verifier">slsa-verifier</a> CLI:</p>

<pre><code>slsa-verifier verify-artifact provii-mobile-sdk-bundle.tar.gz \\
  --provenance-path provii-mobile-sdk/releases/v0.4.2/provii-mobile-sdk.intoto.jsonl \\
  --source-uri github.com/provii/provii-mobile-sdk</code></pre>

<div class="note">
  <p>All signatures use Sigstore's keyless signing flow. The signing identity is the GitHub Actions workflow run itself, verified via OIDC federation with Fulcio. No long-lived signing keys exist.</p>
</div>

<h2>OpenAPI specs</h2>
<p>The latest signed OpenAPI spec for each backend service is available at:</p>
<ul>
  <li><code>provenance.provii.app/provii-verifier/latest.json</code></li>
  <li><code>provenance.provii.app/provii-issuer/latest.json</code></li>
</ul>
<p>Each <code>latest.json</code> is a manifest pointing to the most recent per-commit spec with its signature and provenance sidecars.</p>`;
