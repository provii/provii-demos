// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Minimal stand-in provii-verifier Worker for the test harness.
 *
 * Fix 6 () added `VERIFIER_API_SANDBOX` as a top-level service
 * binding in `wrangler.toml` so production docs.provii.app can
 * dial the sandbox verifier. The vitest pool reads that binding on
 * boot and fails closed if no service named `sandbox-verify` exists,
 * which broke every `src/docs/__tests__/**` run. This stand-in is
 * wired into `vitest.config.ts` as the target of the binding so the
 * pool boots cleanly without pulling in the real provii-verifier WASM.
 *
 * No existing test calls `env.VERIFIER_API_SANDBOX.fetch(...)` today;
 * the stand-in therefore returns a stable 501 for every request so a
 * future test that forgets to mock the binding fails loudly rather
 * than silently masking a missing upstream.
 */

export default {
  async fetch() {
    return new Response(
      JSON.stringify({
        error: {
          code: "stand_in_verifier_not_implemented",
          message:
            "Stand-in provii-verifier is reach-only; add a proper mock to the test fixture if you need a real response.",
        },
      }),
      {
        status: 501,
        headers: { "Content-Type": "application/json" },
      },
    );
  },
};
