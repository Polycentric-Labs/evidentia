/**
 * Playwright configuration for Evidentia UI end-to-end DAST probing.
 *
 * v0.9.5 P1.2 scaffold. NOT wired into the default test run; invoked
 * explicitly at pre-release-review Step 4 (capability-matrix DAST
 * sub-step).
 *
 * Pre-flight:
 *   uv sync --all-packages
 *   uv run playwright install
 *
 * Invocation:
 *   uv run playwright test --config tests/dast/playwright.config.ts
 *
 * Expects `evidentia serve` running on http://127.0.0.1:8000.
 */

import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: /test_.*\.e2e\.ts$/,
  timeout: 30_000,
  expect: { timeout: 5_000 },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? 'github' : 'list',

  use: {
    baseURL: process.env.EVIDENTIA_DAST_BASE_URL ?? 'http://127.0.0.1:8000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],

  // No webServer block — operators are expected to launch
  // `evidentia serve` themselves so the DAST suite probes the
  // exact configuration they ship (auth tokens, TLS, etc.).
});
