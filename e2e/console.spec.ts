import { expect, test, type Page } from "@playwright/test";

function scan(rejectedCount = 0, valid = true) {
  return {
    room: "lobby", scannedAt: "2026-09-04T00:00:00Z", rejectedCount,
    events: valid ? [{
      message: { seq: "42", ts: "2026-09-04T00:00:00Z", from: "test-sender", text: "Fixture evidence only" },
      provenance: { room: "lobby", contentHash: "a".repeat(64), verification: "unsigned" },
      risk: { action: "allow", score: 0, findings: [] },
    }] : [],
  };
}

async function assertFits(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
}

test("partial scans retain valid evidence and fit the viewport", async ({ page }, info) => {
  await page.route("**/api/scan?**", route => route.fulfill({ json: scan(2) }));
  await page.goto("/");
  await expect(page.getByRole("status")).toContainText("2 malformed records excluded");
  await expect(page.getByRole("table").getByText("Fixture evidence only")).toBeVisible();
  await assertFits(page);
  await page.screenshot({ path: info.outputPath("partial-scan.png"), fullPage: true });
});

test("all-invalid and genuinely empty windows have different states", async ({ page }) => {
  let invalid = true;
  await page.route("**/api/scan?**", route => route.fulfill({ json: scan(invalid ? 2 : 0, false) }));
  await page.goto("/");
  await expect(page.getByText("No valid records in this response")).toBeVisible();
  await expect(page.getByText("This room returned no retained messages")).toHaveCount(0);
  invalid = false;
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByText("This room returned no retained messages")).toBeVisible();
});

test("failed refresh preserves evidence with an explicit stale warning", async ({ page }) => {
  let fail = false;
  await page.route("**/api/scan?**", route => route.fulfill(fail
    ? { status: 502, json: { error: "Technocore responded 503" } }
    : { json: scan() }));
  await page.goto("/");
  await expect(page.getByRole("table").getByText("Fixture evidence only")).toBeVisible();
  fail = true;
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  const staleWarning = page.getByRole("alert").filter({ hasText: "Showing previous results from lobby" });
  await expect(staleWarning).toBeVisible();
  await expect(page.getByRole("table").getByText("Fixture evidence only")).toBeVisible();
  await assertFits(page);
  fail = false;
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await expect(staleWarning).toHaveCount(0);
});

test("initial outage is not reported as an empty room", async ({ page }) => {
  await page.route("**/api/scan?**", route => route.fulfill({ status: 502, json: { error: "Technocore responded 503" } }));
  await page.goto("/");
  await expect(page.getByText("Technocore messages are temporarily unavailable")).toBeVisible();
  await expect(page.getByText("This room returned no retained messages")).toHaveCount(0);
});

test("timeout releases the scan control for retry", async ({ page }) => {
  await page.route("**/api/scan?**", async route => {
    await new Promise(resolve => setTimeout(resolve, 25_000));
    await route.abort().catch(() => undefined);
  });
  await page.goto("/");
  await expect(page.getByRole("alert").filter({ hasText: "timed out" })).toBeVisible({ timeout: 24_000 });
  await expect(page.getByRole("button", { name: "Scan", exact: true })).toBeEnabled();
});
