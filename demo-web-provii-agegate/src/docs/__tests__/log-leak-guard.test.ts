// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Static log-leak guard (task ).
 *
 * landed correlation-ID plumbing in `challenge.ts` so the only log
 * line that references `session_id` or `client_id` now goes through
 * `correlationIdFor(...)` before hitting the sanitised logger facade.
 * Manual inspection across the docs gateway source (excluding tests)
 * found no remaining raw-identifier log call sites.
 *
 * This test freezes that invariant. It reads every `.ts` file under
 * `src/docs/` (tests excluded), strips line and block comments, and
 * then asserts that no `console.*(...)` argument list mentions
 * `session_id` or `client_id`. If a future edit introduces a
 * `console.error("session_id=" + id)` style call the assertion catches
 * it before review.
 *
 * The test walks source as plain strings via Vite's `?raw` import query
 * rather than `node:fs` because vitest-pool-workers runs inside workerd
 * and the Cloudflare Workers nodejs_compat shim does not expose a
 * filesystem.
 */

import { describe, expect, it } from "vitest";

// Vite resolves every `.ts` file under `src/docs/` into an eager string
// import keyed by absolute project path. `__tests__` is excluded via the
// glob pattern so the guard does not self-reference.
const sourceModules = import.meta.glob("../*.ts", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

/**
 * Remove line and block comments from `input`. Does not attempt to
 * preserve line numbers; the test only cares about the surviving
 * non-comment text.
 *
 * Minimal but sufficient for this code base: we are scanning for
 * `console.` tokens that never appear inside a string literal, so a
 * richer parser would buy no additional coverage for the specific
 * regression this test guards against.
 */
function stripComments(input: string): string {
  const BLOCK = new RegExp("/\\*[\\s\\S]*?\\*/", "g");
  const LINE = /(^|[^:])\/\/[^\n]*/g;
  return input.replace(BLOCK, "").replace(LINE, "$1");
}

describe("docs gateway: log-leak guard (W6-NT8)", () => {
  it("no console.* call references session_id or client_id", () => {
    const offenders: Array<{ file: string; snippet: string }> = [];

    for (const [file, source] of Object.entries(sourceModules)) {
      const stripped = stripComments(source);
 // Match any console.<method>(...) argument list. The regex is
 // non-greedy on the closing paren so a multi-line call is
 // captured up to its first `)`; enough coverage for the leak
 // shapes we care about (literal-key, template literal,
 // object-shorthand).
      const consoleCalls = stripped.match(
        /console\.[A-Za-z]+\s*\([\s\S]*?\)/g,
      );
      if (consoleCalls === null) continue;
      for (const call of consoleCalls) {
        if (/\bsession_id\b|\bclient_id\b/.test(call)) {
          offenders.push({ file, snippet: call });
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  it("scans at least one file (sanity: glob resolved non-empty)", () => {
 // Guard against a silent glob regression that would cause the
 // primary assertion above to pass vacuously.
    expect(Object.keys(sourceModules).length).toBeGreaterThan(0);
  });
});
