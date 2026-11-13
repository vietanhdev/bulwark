import { test, expect } from "@playwright/test";
test("Fix now reviews and cancels without applying, with busy controls", async ({ page }) => {
  await page.goto("/?fixSlow=1");
  const fix = page.getByRole("button", { name: "Fix now", exact: true });
  await expect(fix).toBeEnabled();
  await fix.click();
  const dialog = page.getByRole("dialog", { name: "Review safe fixes" });
  await expect(dialog).toBeVisible();
  await expect(page.getByRole("button", { name: "Scan now", exact: true })).toBeDisabled();
  await expect(dialog.getByRole("status")).toContainText("no changes are being applied");
  await expect(dialog.getByText(/Nothing has been written yet/)).toBeVisible();
  await expect(dialog.getByText(/PasswordAuthentication and PermitRootLogin are excluded/)).toBeVisible();
  // Like `bulwarkctl fix all`: the banner and password-age fixes are named, not applied.
  await expect(dialog.getByText(/left out, because they change wording or policy/)).toBeVisible();
  await expect(dialog.getByText("PASS_MAX_DAYS", { exact: true })).toHaveCount(0);
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.getByRole("button", { name: "Scan now", exact: true })).toBeEnabled();
  await page.getByRole("button", { name: "Scan now", exact: true }).click();
  await expect(fix).toBeDisabled();
});
test("no evaluated eligible fixes leaves a descriptive disabled control", async ({ page }) => {
  await page.goto("/?sshDenied=1");
  const fix = page.getByRole("button", { name: "Fix now", exact: true });
  await expect(fix).toBeDisabled();
  await expect(fix).toHaveAccessibleDescription(/No supported safe fixes/);
});
test("cancelled privilege preview remains an error, not a clean result", async ({ page }) => {
  await page.goto("/?fixError=1");
  await page.getByRole("button", { name: "Fix now", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText(/Synthetic privilege request cancelled/)).toBeVisible();
  await expect(dialog.getByRole("button", { name: /Apply/ })).toHaveCount(0);
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await expect(dialog).not.toBeVisible();
});
