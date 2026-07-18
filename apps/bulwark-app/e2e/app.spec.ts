import { test, expect } from "@playwright/test";
import { VIEWS, expectShellReady } from "./fixtures";

test.describe("app shell", () => {
  test("loads with the Bulwark title and no console errors", async ({ page }) => {
    const errors: string[] = [];
    page.on("console", (m) => {
      if (m.type() === "error") errors.push(m.text());
    });
    page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));

    await page.goto("/");
    await expect(page).toHaveTitle(/Bulwark/);
    await expectShellReady(page);

    expect(errors, `console errors:\n${errors.join("\n")}`).toEqual([]);
  });

  test("sidebar lists every navigation item", async ({ page }) => {
    await page.goto("/");
    const nav = page.locator("nav");
    for (const { label } of VIEWS) {
      await expect(nav.getByRole("button", { name: new RegExp(label) }).first()).toBeVisible();
    }
  });

  test("opens on the overview/home view by default", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Home", exact: true })).toBeVisible();
  });
});
