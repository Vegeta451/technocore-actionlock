import { expect, test } from "@playwright/test";

test("receipt docs link to the published conformance vectors", async ({ page, request }, info) => {
  await page.goto("/docs#receipts");
  const link = page.getByRole("link", { name: "fixed JSON, UTF-8 and SHA-256 vectors" });
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute("href", "/conformance/canonical-json-v1.json");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.locator("#receipts").screenshot({ path: info.outputPath("receipt-docs.png") });
  const response = await request.get("/conformance/canonical-json-v1.json");
  expect(response.ok()).toBe(true);
  const fixture = await response.json();
  expect(fixture.profile).toBe("actionlock-cjson-v1");
  expect(fixture.vectors).toHaveLength(6);
});
