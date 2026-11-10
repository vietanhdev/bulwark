import { test, expect } from "@playwright/test";
import { expectShellReady } from "./fixtures";

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

  test("primary navigation stays compact", async ({ page }) => {
    await page.goto("/");
    const nav = page.locator("nav");
    for (const label of ["Scan", "Secrets", "Tools", "Settings"]) {
      await expect(nav.getByRole("button", { name: new RegExp(label) }).first()).toBeVisible();
    }
  });

  test("opens on Scan without automatically running it", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Scan", exact: true })).toBeVisible();
  });
});
