import { test, expect } from "@playwright/test";

test("session inspection is explicit and distinguishes cache from verification", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Secrets", exact: true }).click();
  await page.getByRole("tab", { name: "AWS Vault", exact: true }).click();
  await expect(page.getByText("Refresh sessions to see your local profiles.", { exact: true })).toBeVisible();
  await expect(page.getByText("demo-readonly", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Refresh sessions" }).click();
  await expect(page.getByRole("rowheader", { name: "demo-readonly" })).toBeVisible();
  await expect(page.getByText("Cached · unverified", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "demo-readonly", exact: true }).click();
  await expect(page.getByRole("table").getByText("Expired", { exact: true })).toBeVisible();
  await expect(page.getByText("SSO cache present · expiry unknown")).toBeVisible();
  await page.screenshot({ path: "test-results/secrets-inventory.png", fullPage: true });
});

test("a failed refresh cannot leave a stale success table", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Secrets", exact: true }).click();
  await page.getByRole("tab", { name: "AWS Vault", exact: true }).click();
  await page.getByRole("button", { name: "Refresh sessions" }).click();
  await expect(page.getByRole("rowheader", { name: "demo-readonly" })).toBeVisible();
  await page.evaluate(() => window.history.replaceState({}, "", "?access=error"));
  await page.getByRole("button", { name: "Refresh sessions" }).click();
  await expect(page.getByRole("alert")).toContainText("could not list metadata");
  await expect(page.getByRole("table")).toHaveCount(0);
});

test("empty inventory is distinct from an unread cache", async ({ page }) => {
  await page.goto("/?access=empty");
  await page.getByRole("button", { name: "Secrets", exact: true }).click();
  await page.getByRole("tab", { name: "AWS Vault", exact: true }).click();
  await page.getByRole("button", { name: "Refresh sessions" }).click();
  await expect(page.getByText("No configured profiles or cache entries were found.")).toBeVisible();
  await expect(page.getByRole("searchbox")).toHaveCount(0);
  await expect(page.getByText("Metadata available", { exact: true })).toBeVisible();
});
