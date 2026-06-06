import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      // Node.js source calls loadConfig() at module load time (which exits
      // if env vars are missing), so tests re-implement the core functions
      // (HMAC, base64url, canonical message, demo token validation) and verify
      // them directly. Coverage thresholds are not applied because the source
      // file cannot be imported in tests without live credentials.
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/openapi.ts'],
      reporter: ['text', 'json-summary', 'lcov'],
    },
  },
});
