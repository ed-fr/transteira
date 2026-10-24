import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vitest/config';

// Unit tests run in Node (no jsdom): the router, i18n, API client and upload engine take their
// browser dependencies (history, fetch, storage, transport, timers) by injection.
export default defineConfig({
  plugins: [svelte()],
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text-summary', 'text'],
      reportsDirectory: 'coverage',
      // CLAUDE.md section 24.3: the shared core and the logic of the public and admin applications are
      // held to 90 %. Every .ts file of these directories is measured, tested or not (generated
      // types, tests and the browser entry point excepted; .svelte components are not measured).
      include: [
        'src/shared/{api,router,i18n,upload,safe,theme}/**/*.ts',
        'src/public/**/*.ts',
        'src/admin/**/*.ts',
      ],
      exclude: [
        'src/shared/api/schema.ts',
        'src/public/main.ts',
        'src/admin/main.ts',
        '**/*.d.ts',
        '**/*.test.ts',
        '**/*.test-helper.ts',
      ],
      thresholds: {
        lines: 90,
        branches: 90,
        functions: 90,
        statements: 90,
      },
    },
  },
});
