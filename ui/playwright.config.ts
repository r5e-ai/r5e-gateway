// F004 T005 — Playwright e2e config per contracts/frontend_architecture.md §"Tests".
//
// Runs against a Gateway booted via `mix run --no-halt` on localhost:4000.
// Tests live under src/tests/e2e/ and cover US1–US6 acceptance scenarios.

import { defineConfig, devices } from "@playwright/test";

const isCI = !!process.env.CI;

export default defineConfig({
  testDir: "./src/tests/e2e",
  fullyParallel: true,
  forbidOnly: isCI,
  retries: isCI ? 2 : 0,
  workers: isCI ? 2 : undefined,
  reporter: isCI ? [["github"], ["html", { open: "never" }]] : "list",
  timeout: 30_000,
  expect: {
    timeout: 5_000,
  },
  use: {
    baseURL:
      process.env.PLAYWRIGHT_BASE_URL ||
      (process.env.VITE_DEV_MOCKS ? "http://localhost:5179" : "http://localhost:4000"),
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: isCI ? "retain-on-failure" : "off",
  },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        ...(process.env.PLAYWRIGHT_CHROME_CHANNEL
          ? { channel: process.env.PLAYWRIGHT_CHROME_CHANNEL }
          : {}),
      },
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
    },
  ],
  webServer: process.env.PLAYWRIGHT_NO_WEBSERVER
    ? undefined
    : process.env.VITE_DEV_MOCKS
      ? {
          command: "VITE_DEV_MOCKS=1 pnpm dev --port 5179 --strictPort",
          url: "http://localhost:5179/admin/",
          reuseExistingServer: !isCI,
          timeout: 30_000,
        }
      : {
          command:
            "cd .. && mix run --no-halt --no-compile -e 'Application.ensure_all_started(:recurse_gateway)'",
          url: "http://localhost:4000/admin/login",
          reuseExistingServer: !isCI,
          timeout: 60_000,
        },
});
