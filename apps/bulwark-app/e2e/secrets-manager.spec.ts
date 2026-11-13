import { test, expect } from "@playwright/test";

test("first run adds the managers found on this computer and reads them automatically", async ({ page }) => {
  await page.goto("/?secretsFresh=1");
  await page.locator("nav").getByRole("button", { name: "Secrets", exact: true }).click();
  // Nothing was chosen yet, so every detected manager becomes a tab without a click.
  const all = page.getByRole("tabpanel", { name: "Inventory" });
  await expect(all).toBeVisible();
  await expect(all.getByRole("rowheader", { name: /ghcr\.io/ })).toBeVisible();
  await expect(all.getByRole("rowheader", { name: /legacy-ci/ })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Docker" })).toBeVisible();
  // Not detected on this computer: offered in the market, not added.
  await expect(page.getByRole("tab", { name: "GitHub CLI" })).toHaveCount(0);
  await page.getByRole("tab", { name: "Add" }).click();
  await expect(page.getByRole("button", { name: "Add GitHub CLI" })).toBeVisible();
});

test("Secrets reads again whenever it is opened", async ({ page }) => {
  await page.goto("/?secretsFresh=1");
  const nav = page.locator("nav");
  await nav.getByRole("button", { name: "Secrets", exact: true }).click();
  await expect(
    page.getByRole("tabpanel", { name: "Inventory" }).getByRole("rowheader").first(),
  ).toBeVisible();
  const reads = () =>
    page.evaluate(() => (window as unknown as { __inventoryReads?: number }).__inventoryReads ?? 0);
  const before = await reads();
  await nav.getByRole("button", { name: "Scan", exact: true }).click();
  await nav.getByRole("button", { name: "Secrets", exact: true }).click();
  await expect.poll(reads).toBeGreaterThan(before);
  // The previous result stays on screen during the refresh.
  await expect(
    page.getByRole("tabpanel", { name: "Inventory" }).getByRole("rowheader").first(),
  ).toBeVisible();
});

test("removing every manager is remembered, not undone by detection", async ({ page }) => {
  await page.goto("/?secretsFresh=1");
  await page.locator("nav").getByRole("button", { name: "Secrets", exact: true }).click();
  await expect(page.getByRole("tab", { name: "Inventory" })).toBeVisible();
  for (const tab of await page.getByRole("tab").allInnerTexts()) {
    const name = tab.trim();
    if (["Inventory", "Add"].includes(name)) continue;
    await page.getByRole("tab", { name, exact: true }).click();
    await page.getByRole("button", { name: `Remove ${name} from Secrets` }).click();
  }
  await expect(page.getByRole("tab", { name: "Inventory" })).toHaveCount(0);
  await page.goto("/"); // a plain load: keeps the saved (empty) choice
  await page.locator("nav").getByRole("button", { name: "Secrets", exact: true }).click();
  await expect(page.getByRole("tabpanel", { name: "Add a secrets manager" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Inventory" })).toHaveCount(0);
});

test("the inventory combines every added file-based manager and never shows values", async ({ page }) => {
  await page.goto("/");
  await page.locator("nav").getByRole("button", { name: "Secrets", exact: true }).click();
  const all = page.getByRole("tabpanel", { name: "Inventory" });
  await expect(all).toBeVisible();
  await expect(all.getByRole("rowheader", { name: /legacy-ci/ })).toBeVisible();
  await expect(all.getByRole("rowheader", { name: /docker\.io/ })).toBeVisible();
  await expect(all.getByText("AWS Vault is read only from its own tab.")).toBeVisible();
});

test("a manager whose files are missing explains how to set it up, and tabs can be removed", async ({
  page,
}) => {
  await page.goto("/");
  await page.locator("nav").getByRole("button", { name: "Secrets", exact: true }).click();
  await page.getByRole("tab", { name: "Add" }).click();
  await page.getByRole("button", { name: "Add GitHub CLI" }).click();
  const gh = page.getByRole("tabpanel", { name: "GitHub CLI" });
  await expect(gh.getByText("No configuration for this tool was found in your home folder.")).toBeVisible();
  await expect(gh.getByText("gh auth login")).toBeVisible();
  await gh.getByRole("button", { name: "Remove GitHub CLI from Secrets" }).click();
  await expect(page.getByRole("tab", { name: "GitHub CLI" })).toHaveCount(0);
});

test("plain-text entries lead to Scan, and tool token files are listed by tool", async ({ page }) => {
  await page.goto("/");
  await page.locator("nav").getByRole("button", { name: "Secrets", exact: true }).click();
  await page.getByRole("tab", { name: "Tool tokens" }).click();
  const tokens = page.getByRole("tabpanel", { name: "Tool tokens" });
  await expect(tokens.getByRole("rowheader", { name: /^Cargo/ })).toBeVisible();
  await expect(tokens.getByText("1 entry is kept in plain text.")).toBeVisible();
  await tokens.getByRole("button", { name: "Review in Scan" }).click();
  await expect(page.locator("nav").getByRole("button", { name: "Scan", exact: true })).toHaveAttribute(
    "aria-current",
    "page",
  );
});

test("the AWS Vault preview is hidden unless the build offers it, even if a tab was saved", async ({
  page,
}) => {
  await page.addInitScript(() =>
    localStorage.setItem("bulwark.secrets.managers", JSON.stringify(["aws-vault", "docker"])),
  );
  await page.goto("/?awsVault=off");
  await page.locator("nav").getByRole("button", { name: "Secrets", exact: true }).click();
  await expect(page.getByRole("tab", { name: "Docker" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "AWS Vault" })).toHaveCount(0);
  await expect(page.getByText("AWS Vault is read only from its own tab.")).toHaveCount(0);
  await page.getByRole("tab", { name: "Add" }).click();
  await expect(page.getByRole("button", { name: "Add AWS CLI" })).toBeVisible();
  await expect(page.getByRole("button", { name: /AWS Vault/ })).toHaveCount(0);
  // The saved choice is kept, so turning the preview on later brings the tab back.
  expect(await page.evaluate(() => localStorage.getItem("bulwark.secrets.managers"))).toContain("aws-vault");
});
