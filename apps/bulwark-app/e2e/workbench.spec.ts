import { test, expect } from "@playwright/test";
import { goToView } from "./fixtures";

test("developer focus filters findings without inventing a narrower scan", async ({ page }) => {
  await page.goto("/");
  await goToView(page, "Configuration");
  await expect(page.getByRole("button", { name: "Developer focus", exact: true })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await expect(page.getByRole("button", { name: /SSH password authentication is enabled/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /A VNC\/remote-desktop port is listening/ })).toHaveCount(0);
  await page.getByRole("button", { name: "All configuration", exact: true }).click();
  await expect(page.getByRole("button", { name: /A VNC\/remote-desktop port is listening/ })).toBeVisible();
  await page.getByText("What gets checked?", { exact: true }).click();
  await expect(page.getByText(/does not narrow the scan/)).toBeVisible();
  await goToView(page, "Secrets");
  await page.getByRole("tab", { name: "AWS Vault", exact: true }).click();
  await goToView(page, "Configuration");
  await expect(page.getByRole("button", { name: "All configuration", exact: true })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
});

test("compact navigation reaches every tool without horizontal page overflow", async ({ page }) => {
  await page.setViewportSize({ width: 720, height: 520 });
  await page.goto("/");
  for (const label of [
    "Secrets",
    "Configuration",
    "Scan",
    "Remote hosts",
    "File changes",
    "Malware scan",
    "Rule catalog",
    "History",
    "Settings",
  ]) {
    await goToView(page, label);
    await expect(page.getByRole("heading", { name: label, exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  }
});

test("configuration keeps permission-skipped results neutral", async ({ page }) => {
  await page.goto("/?sshDenied=1");
  await goToView(page, "Configuration");
  await expect(
    page.getByText("Some checks still need administrator access.", { exact: true }).filter({ visible: true }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Run privileged checks", exact: true })).toBeVisible();
  await expect(page.getByText(/passes every configuration check/)).toHaveCount(0);
});

test("session caveats stay available through progressive disclosure", async ({ page }) => {
  await page.goto("/");
  await goToView(page, "Secrets");
  await page.getByRole("tab", { name: "AWS Vault", exact: true }).click();
  await expect(page.getByText("Cached metadata only; refresh does not sign you in.")).toBeVisible();
  await expect(page.getByText(/Running shells and sessions created outside AWS Vault/)).not.toBeVisible();
  await page.getByText("About session status", { exact: true }).click();
  await expect(page.getByText(/Running shells and sessions created outside AWS Vault/)).toBeVisible();
  await expect(page.getByText(/does not unlock a password manager or reveal credentials/)).toBeVisible();
});

test("Scan owns the run and retains active work across tabs", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Scan", exact: true })).toBeVisible();
  await expect(page.locator("nav").getByRole("button", { name: "Findings", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Scan now", exact: true }).click();
  await expect(page.getByRole("button", { name: "Stop", exact: true })).toBeVisible();
  await goToView(page, "Secrets");
  await page.getByRole("tab", { name: "AWS Vault", exact: true }).click();
  await expect(page.getByRole("button", { name: "Scan now", exact: true })).not.toBeVisible();
  await goToView(page, "Scan");
  await expect(page.getByRole("button", { name: "Scan now", exact: true })).toBeVisible({ timeout: 20000 });
  await expect(page.locator(".task-activity")).toHaveCount(0);
});

test("new and failed scans do not claim completed checks", async ({ page }) => {
  await page.goto("/?scanEmpty=1&scanError=1");
  await expect(page.getByRole("heading", { name: "Ready to check your setup" })).toBeVisible();
  const guide = page.getByRole("list", { name: "Getting started" });
  await expect(guide.getByRole("listitem")).toHaveCount(4);
  await expect(guide.getByRole("button", { name: "Start the first scan" })).toBeVisible();
  await page.getByRole("button", { name: "Scan now", exact: true }).click();
  await expect(page.getByRole("button", { name: "Scan now", exact: true })).toBeVisible({ timeout: 20000 });
  await expect(page.getByRole("heading", { name: "Scan needs attention" })).toBeVisible();
  await expect(page.getByText("Synthetic configuration check failed.", { exact: false })).toBeVisible();
  await expect(page.locator(".task-activity")).toHaveCount(0);
  await expect(page.getByText("Every check that ran came back clean.")).toHaveCount(0);
});

test("hidden document pauses loops and resumes without changing accessible status", async ({ page }) => {
  await page.goto("/?accessSlow=1");
  await goToView(page, "Secrets");
  await page.getByRole("tab", { name: "AWS Vault", exact: true }).click();
  await page.getByRole("button", { name: "Refresh sessions", exact: true }).click();
  await page.evaluate(() => {
    Object.defineProperty(document, "hidden", { configurable: true, value: true });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect(page.locator(".task-mark")).toHaveCSS("animation-play-state", "paused");
  const phrase = await page.locator(".activity-phrase").textContent();
  await page.waitForTimeout(3400);
  await expect(page.locator(".activity-phrase")).toHaveText(phrase!);
  await page.evaluate(() => {
    Object.defineProperty(document, "hidden", { configurable: true, value: false });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect(page.locator(".task-mark")).toHaveCSS("animation-play-state", "running");
  await expect(page.locator(".task-activity .sr-only")).toHaveText("Reading local AWS Vault metadata.");
  await expect(page.locator(".task-activity")).toHaveCount(0, { timeout: 10000 });
});

test("compact task navigation has one selection and supports keyboard focus", async ({ page }) => {
  await page.setViewportSize({ width: 720, height: 520 });
  await page.goto("/");
  const nav = page.getByRole("navigation", { name: "Workbench" });
  await expect(nav.locator('[aria-current="page"]')).toHaveCount(1);
  const sessions = nav.getByRole("button", { name: "Secrets", exact: true });
  await sessions.click();
  await expect(sessions).toHaveAttribute("aria-current", "page");
  await page.keyboard.press("Tab");
  const tools = nav.getByRole("button", { name: "Tools", exact: true });
  await expect(tools).toBeFocused();
  await expect(tools).toHaveCSS("outline-style", "solid");
  await page.keyboard.press("Enter");
  await expect(tools).toHaveAttribute("aria-current", "page");
  await page.keyboard.press("Tab");
  const settings = nav.getByRole("button", { name: "Settings", exact: true });
  await expect(settings).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(settings).toHaveAttribute("aria-current", "page");
  await expect(nav.locator('[aria-current="page"]')).toHaveCount(1);
  for (const button of await nav.getByRole("button").all()) {
    await expect(button).toHaveCSS("height", "38px");
    await expect(button.locator("svg")).toHaveCSS("width", "19px");
  }
  await page.emulateMedia({ reducedMotion: "reduce" });
  await expect(sessions).toHaveCSS("transition-duration", "0s");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
