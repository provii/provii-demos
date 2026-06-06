// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Augment ProvidedEnv from `cloudflare:test` with the bindings the docs
 * gateway test suite expects. Required because vitest-pool-workers has no
 * way to infer binding shapes from wrangler.toml at type-check time.
 */

declare module "cloudflare:test" {
  interface ProvidedEnv {
    DOCS_SESSIONS: KVNamespace;
  }
}

export {};
