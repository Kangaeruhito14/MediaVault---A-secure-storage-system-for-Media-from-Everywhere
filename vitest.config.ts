import { defineConfig } from 'vitest/config';

// Crypto tests run in Node (which provides Web Crypto). Scoped to the E2EE
// library so Astro page files are never pulled into the test run.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/lib/**/*.test.ts'],
  },
});
