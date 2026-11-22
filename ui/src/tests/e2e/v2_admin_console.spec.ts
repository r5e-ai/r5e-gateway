// Playwright E2E spec for the Provenance v2 Admin Console against `VITE_DEV_MOCKS=1`.
//
// Run locally:
//   VITE_DEV_MOCKS=1 PLAYWRIGHT_CHROME_CHANNEL=chrome pnpm test:e2e --project=chromium

import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_VERIFY_BIN = resolve(
  __dirname,
  "../../../../../r5e-verify-rs/target/release/recurse_verify",
);
const HAS_VERIFIER = existsSync(process.env.R5E_VERIFY_RS_BIN || DEFAULT_VERIFY_BIN);

test.describe("v2 Admin Console (Provenance v2 + CedarToolUseGate)", () => {
  test("Dashboard -> RecordDetail (Content + Verify) -> Policy Simulator (Simulate, Replay, Draft & Blast Radius)", async ({
    page,
  }) => {
    const consoleErrors: string[] = [];
    page.on("console", (m) => {
      if (m.type() === "error") consoleErrors.push(m.text());
    });
    page.on("pageerror", (e) => consoleErrors.push(e.message));

    // 1. Dashboard loads real signed Provenance v2 snapshot records
    await page.goto("/admin/dashboard", { waitUntil: "networkidle" });
    await expect(page.getByTestId("evidence-table")).toBeVisible();
    await expect(page.getByTestId("deployment-chain-badge")).toContainText("b1c6b5aa");

    // 2. Open a ToolCall record -> fetch content blob -> run verifier
    const toolCallRow = page.getByTestId("evidence-row-ToolCall").first();
    await expect(toolCallRow).toBeVisible();
    await toolCallRow.click();
    await expect(page.getByTestId("record-detail-drawer")).toBeVisible();

    await page.getByTestId("detail-tab-content").click();
    await page.getByTestId("fetch-content-btn").click();
    await expect(page.getByTestId("content-blob-json")).toBeVisible();

    await page.getByTestId("detail-tab-verify").click();
    await page.getByTestId("run-verify-btn").click();
    await expect(page.getByTestId("verify-report")).toBeVisible();
    await expect(page.getByTestId("verify-failed-count")).toContainText("failed: 0");
    if (HAS_VERIFIER) {
      await expect(page.getByTestId("verify-ok-count")).toHaveText(/^ok:\s*[1-9]\d*$/i);
    }

    // 3. Navigate to Policy Simulator -> Mode 1 Simulate (Cedar 4.9.1 WASM)
    await page.getByTestId("close-drawer-btn").click();
    await page.getByTestId("sidebar-link-policy-simulator").click();
    await expect(page.getByTestId("active-policy-banner")).toBeVisible();
    await page.getByTestId("run-simulate-btn").click();
    await expect(page.getByTestId("simulate-verdict-pill")).toHaveText("deny");

    // 4. Mode 3 Draft & Blast Radius
    await page.getByTestId("mode-tab-draft").click();
    await page.getByTestId("run-blast-radius-btn").click();
    await expect(page.getByTestId("blast-cell-noChange")).toBeVisible();

    expect(consoleErrors).toEqual([]);
  });
});
