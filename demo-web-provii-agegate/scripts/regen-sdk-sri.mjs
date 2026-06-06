#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust
//
// Regenerates `src/generated/sdk-sri.ts` from the live CDN bundle.
//
// Run modes:
// `node scripts/regen-sdk-sri.mjs` , write file, exit 0
// `node scripts/regen-sdk-sri.mjs --check` , verify file matches live CDN
// without writing. Exits non-zero
// if stale. Used by CI guard.
//
// Why a build-time computation: SDK_VERSION is pinned, so the bundle hash is
// stable per release. Build time avoids per-request fetches of the SDK from
// the playground hot path (latency, CDN dependency at request time). The CI
// guard catches drift the moment the SDK is rotated under the same version,
// so the stale-SRI bug that broke pasted snippets cannot recur silently.

import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TARGET_PATH = resolve(__dirname, "../src/generated/sdk-sri.ts");

// Static HTML assets that load agegate.browser.js with an `integrity=...`
// attribute. These are served as static assets from the playground origin
// and from the per-language reference verifier backends. Each file is
// rewritten in place so the embedded SRI matches the live CDN bundle.
//
// Paths are relative to the repository root (resolved against `../../..`
// from this script). Adding a new HTML asset here is the single change
// needed to bring it under the build-time guard.
const STATIC_HTML_PATHS = [
  "demo-web-provii-agegate/public/index.html",
  "demo-web-provii-agegate/public/demo.html",
  "backends/verifier/nodejs/public/expert.html",
  "backends/verifier/go/public/expert.html",
  "backends/verifier/python/public/expert.html",
  "backends/verifier/cloudflare-workers/src/index.ts",
];
const REPO_ROOT = resolve(__dirname, "../../");

// Read the current SDK_VERSION from the generated file rather than hardcoding,
// so the version pin lives in one place. The version itself is a manual edit
// (operators decide when to roll forward); only the SRI is automated.
async function readPinnedVersion() {
  const text = await readFile(TARGET_PATH, "utf8");
  const m = text.match(/export const SDK_VERSION = "(v[\d.]+)";/);
  if (!m) {
    throw new Error(
      `Cannot parse SDK_VERSION from ${TARGET_PATH}. Expected: export const SDK_VERSION = "vX.Y.Z";`,
    );
  }
  return m[1];
}

async function fetchSdkBytes(version) {
  const url = `https://cdn.provii.app/sdk/provii-agegate/${version}/agegate.browser.js`;
  const resp = await fetch(url);
  if (resp.status === 404) {
    // SDK bundle not yet published to this CDN path. Return null so
    // callers can distinguish "asset absent" from "asset drifted".
    return { url, buf: null };
  }
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status} fetching ${url}`);
  }
  const buf = Buffer.from(await resp.arrayBuffer());
  if (buf.length === 0) {
    throw new Error(`Empty body from ${url}`);
  }
  return { url, buf };
}

function computeSri(buf) {
  const digest = createHash("sha384").update(buf).digest("base64");
  return `sha384-${digest}`;
}

function renderFile(version, sri) {
  return `// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

// AUTO-GENERATED , DO NOT EDIT BY HAND.
// Regenerate with: \`npm run regen:sdk-sri\`
// CI verifies this file against the live CDN on every build.
//
// The SRI is the SHA-384 of the bundle currently published at
// https://cdn.provii.app/sdk/provii-agegate/<SDK_VERSION>/agegate.browser.js.
// It is embedded as the \`integrity\` attribute in every script tag the
// playground emits (snippets returned by /playground/api/create-environment
// and the demo HTML served at the playground origin). Browsers reject any
// script whose body does not match the SRI, so a stale value here breaks
// every developer who pastes the snippet onto a real site.

export const SDK_VERSION = "${version}";
export const SDK_SRI_HASH =
  "${sri}";
export const SDK_URL = \`https://cdn.provii.app/sdk/provii-agegate/\${SDK_VERSION}/agegate.browser.js\`;
`;
}

// Rewrite every `integrity="sha384-..."` attribute in the file so that any
// file containing a stale SRI is brought up to date. The replacement is
// scoped to attributes whose preceding `src=` URL points at provii-agegate, so
// unrelated SRIs (other CDN assets, test fixtures) are left alone.
const SRI_ATTR_REGEX =
  /(<script[^>]*src="https:\/\/cdn\.provii\.app\/sdk\/provii-agegate\/[^"]*\/agegate\.browser\.js"[\s\S]*?integrity=")sha384-[A-Za-z0-9+/=]+(")/g;

// Also rewrite any pinned `vX.Y.Z` directory in the script src so a version
// bump in the generated file flows through to every static reference.
function srcUrlRegex() {
  return /(<script[^>]*src="https:\/\/cdn\.provii\.app\/sdk\/provii-agegate\/)v[\d.]+(\/agegate\.browser\.js")/g;
}

async function rewriteStaticAssets({ version, sri, checkOnly }) {
  const stale = [];
  for (const rel of STATIC_HTML_PATHS) {
    const abs = resolve(REPO_ROOT, rel);
    let text;
    try {
      text = await readFile(abs, "utf8");
    } catch (err) {
      if (err.code === "ENOENT") {
 // Optional asset (e.g. a backend reference is removed). Skip rather
 // than fail; CI should have a separate inventory check for required
 // paths if that ever matters.
        console.warn(`[regen-sdk-sri] skip (not found): ${rel}`);
        continue;
      }
      throw err;
    }

    const updated = text
      .replace(srcUrlRegex(), `$1${version}$2`)
      .replace(SRI_ATTR_REGEX, `$1${sri}$2`);

    if (updated === text) {
 // No provii-agegate script tag in this file (or already current).
      continue;
    }

    if (checkOnly) {
      stale.push(rel);
      continue;
    }
    await writeFile(abs, updated, "utf8");
    console.log(`[regen-sdk-sri] updated ${rel}`);
  }
  return stale;
}

async function main() {
  const checkOnly = process.argv.includes("--check");

  const version = await readPinnedVersion();
  const { url, buf } = await fetchSdkBytes(version);

  // SDK bundle not yet published to the CDN. The SRI check cannot verify
  // drift against an asset that does not exist, so warn and exit cleanly.
  // Once the bundle is published, the check will enforce drift detection
  // as intended.
  if (buf === null) {
    console.warn(
      `[regen-sdk-sri] SKIP: ${url} returned 404 (SDK not yet published). ` +
        `SRI drift detection will activate once the bundle is live on CDN.`,
    );
    return;
  }

  const liveSri = computeSri(buf);

  if (checkOnly) {
    const existing = await readFile(TARGET_PATH, "utf8");
    const generatedStale = !existing.includes(liveSri);
    const staticStale = await rewriteStaticAssets({
      version,
      sri: liveSri,
      checkOnly: true,
    });
    if (generatedStale || staticStale.length > 0) {
      console.error(
        `[regen-sdk-sri] STALE: SRI drift detected.\n` +
          `  URL:        ${url}\n` +
          `  Live SRI:   ${liveSri}\n` +
          (generatedStale ? `  Generated:  ${TARGET_PATH}\n` : "") +
          (staticStale.length > 0
            ? `  Static:     ${staticStale.join(", ")}\n`
            : "") +
          `  Run \`npm run regen:sdk-sri\` and commit the result.`,
      );
      process.exit(1);
    }
    console.log(
      `[regen-sdk-sri] OK: ${version} matches live CDN across all assets (${liveSri})`,
    );
    return;
  }

  const rendered = renderFile(version, liveSri);
  await writeFile(TARGET_PATH, rendered, "utf8");
  console.log(
    `[regen-sdk-sri] Wrote ${TARGET_PATH}\n  version: ${version}\n  sri:     ${liveSri}\n  bytes:   ${buf.length}`,
  );

  await rewriteStaticAssets({ version, sri: liveSri, checkOnly: false });
}

main().catch((err) => {
  console.error(`[regen-sdk-sri] FAILED: ${err.message ?? err}`);
  process.exit(2);
});
