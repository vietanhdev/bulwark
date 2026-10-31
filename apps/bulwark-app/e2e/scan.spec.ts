import { test, expect } from "@playwright/test";

test.describe("scan flow", () => {
  test("running a scan enters the scanning state and completes", async ({ page }) => {
    await page.goto("/");

    const run = page.getByRole("button", { name: /scan now/i });
    await expect(run).toBeVisible();
    await run.click();

    // While the (mocked) scan streams findings, the control becomes a Stop button.
    await expect(page.getByRole("button", { name: /stop/i })).toBeVisible();

    // When it finishes, the runnable control returns.
    await expect(page.getByRole("button", { name: /scan now/i })).toBeVisible({ timeout: 20_000 });
  });

  test("scan profile can be narrowed to a single scanner", async ({ page }) => {
    await page.goto("/");
    // What "Scan now" covers is one line in the summary card; "Change" reveals the toggles.
    const summary = page.getByText(/^checks:/i).first();
    await expect(summary).toBeVisible();
    await page.getByRole("button", { name: /^change$/i }).click();
    // AI assistant checks are part of Checkups: there is no separate toggle for them.
    await expect(page.getByRole("switch", { name: /ai assistants/i })).toHaveCount(0);
    const virus = page.getByRole("switch", { name: /virus scan/i });
    await expect(virus).toHaveAttribute("aria-checked", "false");
    await virus.click();
    await expect(virus).toHaveAttribute("aria-checked", "true");
    await expect(summary).toContainText(/virus scan/i);
    await expect(page.getByRole("button", { name: /scan now/i })).toBeEnabled();
  });
});

test.describe("AI assistant findings", () => {
  test("appear in the Home list with a preview-first remove action", async ({ page }) => {
    await page.goto("/");
    // Each problem is one collapsed row: title and recommendation, details behind a click.
    const row = page.getByRole("button", { name: /anthropic api key exposed/i });
    await expect(row).toBeVisible();
    await expect(row).toHaveAttribute("aria-expanded", "false");
    await expect(row).toContainText(/remove the secret from the file/i);
    await expect(page.getByRole("button", { name: /remove secret from this file/i })).toHaveCount(0);
    await row.click();
    const remove = page.getByRole("button", { name: /remove secret from this file/i });
    await expect(remove).toBeVisible();
    await remove.click();
    // The preview states what will change and that nothing has been written yet.
    await expect(page.getByText(/nothing has been written yet/i)).toBeVisible();
    await expect(page.getByRole("button", { name: /^remove 1 secret$/i })).toBeVisible();
    // There is no separate AI assistants page any more.
    await expect(page.locator("nav").getByRole("button", { name: /ai assistants/i })).toHaveCount(0);
  });
});

test.describe("SSH key protection", () => {
  test("the unprotected-key problem offers a passphrase form inline", async ({ page }) => {
    await page.goto("/");
    const row = page.getByRole("button", { name: /ssh private key is not passphrase-protected/i });
    await expect(row).toBeVisible();
    await expect(row).toContainText(/lock the key with a passphrase/i);
    await row.click();
    await expect(page.getByText("Add a passphrase to these keys now", { exact: true })).toBeVisible();
    // The shared steps show once for both keys.
    await expect(page.getByText(/in the bulwark app, open this issue/i)).toHaveCount(1);
    // Steps render as a numbered list, not one paragraph.
    await expect(
      page
        .locator("ol li")
        .filter({ hasText: /ssh-add/ })
        .first(),
    ).toBeVisible();
    const fields = page.getByPlaceholder(/passphrase/i);
    await fields.nth(0).fill("correct horse battery staple");
    await fields.nth(1).fill("correct horse battery staple");
    await page.getByRole("button", { name: /protect unencrypted keys/i }).click();
    await expect(page.getByText(/1 protected/i)).toBeVisible();
  });
});
