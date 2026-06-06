import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 30000, // 30 seconds per test
    hookTimeout: 10000, // 10 seconds for hooks
    teardownTimeout: 5000,
    isolate: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/**',
        'dist/**',
        '**/*.test.ts',
        '**/test-*.ts',
      ],
    },
    include: ['integration/**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
    reporters: ['verbose'],
  },
});
