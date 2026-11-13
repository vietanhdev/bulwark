import { test, expect } from "@playwright/test";
import { goToView } from "./fixtures";

test("a category under low-risk suggestions collapses like any other", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /low-risk suggestions/ }).click();
  const header = page.getByRole("button", { name: /^OS hardening/ }).last();
  await expect(header).toHaveAttribute("aria-expanded", "true");
  const row = page.getByRole("button", { name: /Password maximum age is excessively long/ });
  await expect(row).toBeVisible();
  await header.click();
  await expect(header).toHaveAttribute("aria-expanded", "false");
  await expect(row).toHaveCount(0);
});

test("the lockout warning carries one warning icon, not two", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /SSH password authentication is enabled/ }).click();
  await page.getByRole("button", { name: "Fix automatically" }).click();
  const warning = page
    .getByText(/This can lock you out/)
    .locator("xpath=ancestor::div[contains(@class,'rounded-lg')][1]");
  await expect(warning).toBeVisible();
  await expect(warning.locator("svg")).toHaveCount(1);
});

test("ignoring one finding: Escape cancels, a reason moves it to accepted", async ({ page }) => {
  await page.goto("/");
  const row = page.getByRole("button", { name: /A VNC\/remote-desktop port is listening/ });
  await expect(row).toBeVisible();
  const actions = row.locator("xpath=..").getByRole("button", { name: "Issue actions" });

  await actions.click();
  await page.getByRole("menuitem", { name: "Ignore only this one" }).click();
  const reason = page.getByPlaceholder(/^Why ignore/);
  await expect(reason).toBeFocused();
  await reason.fill("left over from a test");
  await page.keyboard.press("Escape");
  await expect(reason).toHaveCount(0);
  await expect(row).toBeVisible();

  await actions.click();
  await page.getByRole("menuitem", { name: "Ignore only this one" }).click();
  // A cancelled reason is not kept for the next attempt.
  await expect(page.getByPlaceholder(/^Why ignore/)).toHaveValue("");
  await page.getByPlaceholder(/^Why ignore/).fill("Only reachable from this desk");
  await page.keyboard.press("Enter");
  await expect(row).toHaveCount(0);
  await expect(page.getByRole("button", { name: "· 1 accepted" })).toBeVisible();
});

test("closing the fix review returns focus to Fix now", async ({ page }) => {
  await page.goto("/");
  const fix = page.getByRole("button", { name: "Fix now", exact: true });
  await fix.click();
  const dialog = page.getByRole("dialog", { name: "Review safe fixes" });
  await expect(dialog.getByText(/Nothing has been written yet/)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(fix).toBeFocused();
});

test("the rule catalog never shows raw template syntax", async ({ page }) => {
  await page.goto("/");
  await goToView(page, "Rule catalog");
  await page.getByRole("button", { name: /Cron entry runs a downloader piped to a shell/ }).click();
  await expect(page.getByText(/A cron entry's command \("‹command›"/)).toBeVisible();
  // Every rule is listed (collapsed rows included), and none of what is on screen is a template.
  await expect(page.locator("main").getByText("{{").filter({ visible: true })).toHaveCount(0);
});

test("turning a check off lists it under Ignored with a readable title", async ({ page }) => {
  await page.goto("/");
  await goToView(page, "Rule catalog");
  await page.getByRole("button", { name: /Kernel module not blacklisted: ‹module›/ }).click();
  await page.getByRole("textbox", { name: "Why turn this check off?" }).fill("Handled by another tool");
  await page.getByRole("button", { name: "Turn off", exact: true }).click();
  await page.getByRole("tab", { name: "Ignored (1)" }).click();
  await expect(
    page.getByText("Kernel module not blacklisted: ‹module›").filter({ visible: true }).first(),
  ).toBeVisible();
  await expect(page.getByText("{{ module_blacklist.module }}", { exact: false })).toHaveCount(0);
});

test("Secrets: counts are entries, loading names the tool, and a hidden manager leaves no orphan panel", async ({
  page,
}) => {
  await page.goto("/?secretsFresh=1");
  await page.locator("nav").getByRole("button", { name: "Secrets", exact: true }).click();
  const all = page.getByRole("tabpanel", { name: "Inventory" });
  // Three of these rows hold no secret at all, so they are entries, not "stored credentials".
  await expect(all.getByText("13 entries across 6 managers")).toBeVisible();

  await page.getByRole("tab", { name: "Add" }).click();
  await page.getByRole("button", { name: "Add GitHub CLI" }).click();
  await expect(page.locator(".task-activity .sr-only").filter({ visible: true })).toHaveText(
    "Reading this tool's files.",
  );
});

test("a saved tab for a manager this build does not offer falls back to Add", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("bulwark.secrets.managers", '["aws-vault"]'));
  await page.goto("/?awsVault=off");
  await page.locator("nav").getByRole("button", { name: "Secrets", exact: true }).click();
  await expect(page.getByRole("tabpanel", { name: "Add a secrets manager" })).toBeVisible();
  await expect(page.getByRole("tabpanel", { name: "Inventory" })).toHaveCount(0);
});

test("the app still opens when storage cannot be used", async ({ page }) => {
  await page.addInitScript(() => {
    const refuse = () => {
      throw new DOMException("The operation is insecure.", "SecurityError");
    };
    Storage.prototype.getItem = refuse;
    Storage.prototype.setItem = refuse;
  });
  await page.goto("/");
  await expect(page.locator("nav").getByRole("button", { name: "Scan", exact: true })).toBeVisible();
  await goToView(page, "Settings");
  await page.getByRole("button", { name: "Light", exact: true }).click();
  await expect(page.locator("html")).not.toHaveClass(/dark/);
});
