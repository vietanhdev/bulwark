import { test, expect } from "@playwright/test";
import { VIEWS, goToView, visibleText } from "./fixtures";

test.describe("navigation", () => {
  for (const { label, title, signature } of VIEWS) {
    test(`navigates to "${label}" and renders its content`, async ({ page }) => {
      await page.goto("/");
      await goToView(page, label);
      // The view's own heading becomes visible...
      await expect(page.getByRole("heading", { name: title, exact: true })).toBeVisible();
      // ...and a section unique to that view is present, proving it's the right one.
      await expect(visibleText(page, signature)).toBeVisible();
    });
  }

  test("can move back and forth between views without losing state", async ({ page }) => {
    await page.goto("/");
    await goToView(page, "Rule catalog");
    await expect(page.getByRole("heading", { name: "Rule catalog", exact: true })).toBeVisible();
    await goToView(page, "History");
    await expect(page.getByRole("heading", { name: "History", exact: true })).toBeVisible();
    await goToView(page, "Scan");
    await expect(page.getByRole("heading", { name: "Scan", exact: true })).toBeVisible();
  });
});
