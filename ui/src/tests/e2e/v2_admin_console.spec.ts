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
  test("Dashboard (Histogram brush + Column resize/reorder/picker) -> RecordDetail (Content + Verify) -> Policy Simulator", async ({
    page,
  }) => {
    const consoleErrors: string[] = [];
    page.on("console", (m) => {
      if (m.type() === "error") consoleErrors.push(m.text());
    });
    page.on("pageerror", (e) => consoleErrors.push(e.message));

    // 1. Dashboard loads real signed Provenance v2 snapshot + server facets & histogram
    await page.goto("/admin/dashboard", { waitUntil: "networkidle" });
    await expect(page.getByTestId("evidence-table")).toBeVisible();
    await expect(page.getByTestId("evidence-histogram")).toBeVisible();
    await expect(page.getByTestId("histogram-source-badge")).toContainText(
      "server histogram",
    );
    await expect(page.getByTestId("topbar-signout")).toBeInViewport();

    // 2. Column Picker: show hidden Session column, hide Ref, reorder Actor left
    await page.getByTestId("column-picker-button").click();
    await expect(page.getByTestId("column-picker-popover")).toBeVisible();
    await page.getByTestId("column-toggle-session").check();
    await expect(page.getByTestId("col-header-session")).toBeVisible();
    await page.getByTestId("column-toggle-ref").uncheck();
    await expect(page.getByTestId("col-header-ref")).toHaveCount(0);
    await page.getByTestId("column-move-left-actor").click();
    await page.getByTestId("column-picker-reset").click();
    await expect(page.getByTestId("col-header-ref")).toBeVisible();
    await page.keyboard.press("Escape");

    // 3. Column Resize: drag right border of Target header
    const targetHeader = page.getByTestId("col-header-target");
    const beforeBox = await targetHeader.boundingBox();
    const resizer = page.getByTestId("col-resize-target");
    const resizerBox = await resizer.boundingBox();
    expect(beforeBox).not.toBeNull();
    expect(resizerBox).not.toBeNull();
    await page.mouse.move(resizerBox!.x + 2, resizerBox!.y + resizerBox!.height / 2);
    await page.mouse.down();
    await page.mouse.move(resizerBox!.x + 62, resizerBox!.y + resizerBox!.height / 2);
    await page.mouse.up();
    const afterBox = await targetHeader.boundingBox();
    expect(afterBox!.width).toBeGreaterThan(beforeBox!.width + 20);

    // 4. Histogram time-brush selection sets since & until, matches facets total, then Clear resets
    const sumHistogramCounts = async () =>
      page.evaluate(() => {
        const bars = Array.from(document.querySelectorAll<HTMLElement>("[data-bucket-count]"));
        return bars.reduce((sum, el) => sum + Number(el.dataset.bucketCount || 0), 0);
      });
    const statTotal = async () => {
      const text = await page.getByTestId("stat-total").textContent();
      return Number((text ?? "").replace(/[^0-9]/g, ""));
    };
    expect(await sumHistogramCounts()).toBe(await statTotal());

    const brushArea = page.getByTestId("histogram-brush-area");
    const brushBox = await brushArea.boundingBox();
    expect(brushBox).not.toBeNull();
    await page.mouse.move(brushBox!.x + brushBox!.width * 0.6, brushBox!.y + 20);
    await page.mouse.down();
    await page.mouse.move(brushBox!.x + brushBox!.width * 0.99, brushBox!.y + 20);
    await page.mouse.up();
    await expect(page.getByTestId("clear-time-range-btn")).toBeVisible();
    expect(page.url()).toContain("since=");
    expect(page.url()).toContain("until=");
    await expect
      .poll(async () => (await sumHistogramCounts()) === (await statTotal()))
      .toBe(true);
    await page.getByTestId("clear-time-range-btn").click();
    await expect(page.getByTestId("clear-time-range-btn")).toHaveCount(0);

    // 5. Open a ToolCall record -> fetch content blob -> run verifier
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

    // 6. Navigate to Policy Simulator -> Mode 1 Simulate (Cedar 4.9.1 WASM)
    await page.getByTestId("close-drawer-btn").click();
    await page.getByTestId("sidebar-link-policy-simulator").click();
    await expect(page.getByTestId("active-policy-banner")).toBeVisible();
    await page.getByTestId("run-simulate-btn").click();
    await expect(page.getByTestId("simulate-verdict-pill")).toHaveText("deny");

    // 7. Mode 3 Draft & Blast Radius
    await page.getByTestId("mode-tab-draft").click();
    await page.getByTestId("run-blast-radius-btn").click();
    await expect(page.getByTestId("blast-cell-noChange")).toBeVisible();

    expect(consoleErrors).toEqual([]);
  });
});
