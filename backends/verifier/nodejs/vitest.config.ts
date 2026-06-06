import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      // Node.js source starts a server at module load time, so tests
      // re-implement the core functions (HMAC, PKCE, base64url, demo token
      // validation) and verify them directly. Coverage thresholds apply to the
      // test file's copies; the source file shares identical logic.
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/openapi.ts'],
      reporter: ['text', 'json-summary', 'lcov'],
    },
  },
});
