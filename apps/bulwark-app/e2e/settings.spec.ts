import { test, expect } from "@playwright/test";
import { goToView } from "./fixtures";

test.describe("settings — appearance", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await goToView(page, "Settings");
    await expect(page.getByRole("heading", { name: "Settings", exact: true })).toBeVisible();
  });

  test("dark mode toggles the .dark class on <html>", async ({ page }) => {
    const html = page.locator("html");
    await page.getByRole("button", { name: "Dark", exact: true }).click();
    await expect(html).toHaveClass(/dark/);
    await page.getByRole("button", { name: "Light", exact: true }).click();
    await expect(html).not.toHaveClass(/dark/);
  });

  test("choosing an accent colour sets data-accent on <html>", async ({ page }) => {
    // Default accent is orange (no data-accent); pick a distinct one.
    await page.getByRole("button", { name: "Aqua" }).first().click();
    await expect(page.locator("html")).toHaveAttribute("data-accent", "aqua");
  });

  test("shows the appearance, monitoring and SSH sections", async ({ page }) => {
    for (const section of [/appearance/i, /continuous monitoring/i, /ssh hardening/i]) {
      await expect(page.getByText(section).first()).toBeVisible();
    }
  });
});
