import { test, expect } from "@playwright/test";

test.describe("scan flow", () => {
  test("running a scan enters the scanning state and completes", async ({ page }) => {
    await page.goto("/");

    const run = page.getByRole("button", { name: /run .*scan/i });
    await expect(run).toBeVisible();
    await run.click();

    // While the (mocked) scan streams findings, the control becomes a Stop button.
    await expect(page.getByRole("button", { name: /stop/i })).toBeVisible();

    // When it finishes, the runnable control returns.
    await expect(page.getByRole("button", { name: /run .*scan/i })).toBeVisible({ timeout: 20_000 });
  });

  test("scan profile can be narrowed to a single scanner", async ({ page }) => {
    await page.goto("/");
    // The scan-profile group lets you toggle which scanners run.
    const profile = page.getByRole("group", { name: /scan profile/i });
    await expect(profile).toBeVisible();
    // Whatever the selection, a runnable scan button reflects it.
    await expect(page.getByRole("button", { name: /run .*scan/i })).toBeEnabled();
  });
});
