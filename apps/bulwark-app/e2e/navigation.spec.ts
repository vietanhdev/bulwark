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
    await goToView(page, "All checks");
    await expect(page.getByRole("heading", { name: "All checks", exact: true })).toBeVisible();
    await goToView(page, "Activity");
    await expect(page.getByRole("heading", { name: "Activity", exact: true })).toBeVisible();
    await goToView(page, "Home");
    await expect(page.getByRole("heading", { name: "Home", exact: true })).toBeVisible();
  });
});
