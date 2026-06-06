// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Vitest configuration for the docs gateway test suite.
 *
 * Runs every test file inside `src/docs/__tests__/**` against
 * `@cloudflare/vitest-pool-workers`, which boots a Miniflare-backed
 * isolate identical to the production runtime. We keep the suite scoped
 * to the docs surface so a green run is a meaningful guarantee for the
 * gateway without dragging in playground or static-asset code paths.
 *
 * Flags worth knowing:
 * - `singleWorker: true` keeps every test in one isolate so the KV
 * namespace and per-isolate caches behave exactly as they will in
 * production. Tests that need a fresh isolate use the
 * `__resetFeatureFlagCacheForTests` helper or write distinct keys.
 * - `wrangler.configPath` points at the repo's wrangler.toml so the
 * pool inherits real binding shapes (DOCS_SESSIONS, the rate-limit
 * namespace, secrets-store stubs).
 * - `workers[]` declares the stand-in provii-verifier Worker bound into
 * the main runner as the `VERIFIER_API_SANDBOX` service binding.
 * The stand-in returns a stable 501 for every request so a future
 * test that forgets to mock the binding fails loudly rather than
 * silently masking a missing upstream.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const thisDir = path.dirname(fileURLToPath(import.meta.url));
const standInVerifierScript = path.join(
  thisDir,
  "test",
  "fixtures",
  "stand-in-provii-verifier.mjs",
);

export default defineConfig({
  plugins: [
    cloudflareTest({
      singleWorker: true,
      miniflare: {
 // : the pool requires one of `nodejs_compat` or
 // `nodejs_compat_v2` on the runner worker. We only want the flag
 // under test, not in the deployed wrangler.toml, so the override
 // lives here. The test-only compat flag has no effect on the
 // deployed Worker.
        compatibilityFlags: ["nodejs_compat"],
 // Bind a KV namespace under the same name the Worker expects.
 // The pool creates the Miniflare KV on demand so specs that
 // touch DOCS_SESSIONS (cross-surface.test.ts) can run without a
 // remote namespace lookup.
        kvNamespaces: ["DOCS_SESSIONS"],
 // Route the gateway's `VERIFIER_API_SANDBOX` service binding to
 // a stand-in aux Worker. wrangler.toml declares the binding at
 // the sandbox env level so the test pool needs a target workerd
 // isolate or boot fails. No existing test fires a verifier
 // call; the stand-in returns 501 for every request to keep a
 // silent mock from masking a regression.
        serviceBindings: {
          VERIFIER_API_SANDBOX: { name: "stand-in-provii-verifier" },
        },
        workers: [
          {
            name: "stand-in-provii-verifier",
            modules: [
              {
                type: "ESModule",
                path: standInVerifierScript,
              },
            ],
            compatibilityDate: "2025-11-17",
            compatibilityFlags: ["nodejs_compat"],
          },
        ],
      },
      wrangler: {
        configPath: "./wrangler.toml",
      },
    }),
  ],
  test: {
    include: ["src/docs/__tests__/**/*.test.ts"],
  },
});
