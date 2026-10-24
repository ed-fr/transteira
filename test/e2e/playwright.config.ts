// Playwright configuration of the TransTeira end-to-end suite (test/README.md).
// One run covers one database engine (E2E_DB=sqlite|postgres); `make e2e` runs both.
import { defineConfig, devices } from '@playwright/test';
import os from 'node:os';

// One report and one results folder per engine, so that `make e2e` keeps both.
const db = process.env.E2E_DB ?? 'sqlite';

const retries = Number(process.env.E2E_RETRIES ?? '0');
const workers = Number(process.env.E2E_WORKERS ?? Math.max(1, Math.min(4, Math.floor(os.cpus().length / 2))));

// Specs that change state shared by every test of the run (maintenance mode refuses deposits on
// every entity): they run in the "system-serial" project, one test at a time, after the main
// project has finished. Run one alone with `--project=system-serial --no-deps`.
const SERIAL_SPECS = /admin-system\.spec\.ts$/;

// Documentation screenshots (specs/screenshots.spec.ts): only with SCREENSHOTS=1 (`make
// screenshots`), alone, on one worker and in order, so that the data shown is deterministic.
const SCREENSHOT_SPECS = /screenshots\.spec\.ts$/;
const screenshots = process.env.SCREENSHOTS === '1';

export default defineConfig({
  testDir: './specs',
  globalSetup: './global-setup.ts',
  globalTeardown: './global-teardown.ts',
  outputDir: `./test-results/${db}`,
  fullyParallel: true,
  forbidOnly: true,
  retries,
  workers: screenshots ? 1 : workers,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [['list'], ['html', { outputFolder: `playwright-report/${db}`, open: 'never' }]],
  use: {
    ...devices['Desktop Chrome'],
    // Caddy serves certificates from its internal CA, unknown to the browser.
    ignoreHTTPSErrors: true,
    locale: 'en-US',
    timezoneId: 'Europe/Paris',
    viewport: { width: 1280, height: 800 },
    acceptDownloads: true,
    // Traces are kept only for failed tests (on the first retry when retries are enabled).
    trace: retries > 0 ? 'on-first-retry' : 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: screenshots
    ? [
        {
          name: 'screenshots',
          use: { browserName: 'chromium', contextOptions: { reducedMotion: 'reduce' } },
          testMatch: SCREENSHOT_SPECS,
          fullyParallel: false,
        },
      ]
    : [
        { name: 'chromium', use: { browserName: 'chromium' }, testIgnore: [SERIAL_SPECS, SCREENSHOT_SPECS] },
        {
          name: 'system-serial',
          use: { browserName: 'chromium' },
          testMatch: SERIAL_SPECS,
          fullyParallel: false,
          dependencies: ['chromium'],
        },
      ],
});
