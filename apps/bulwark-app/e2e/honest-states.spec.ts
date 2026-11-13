import { test, expect, type Page } from "@playwright/test";
import { goToView } from "./fixtures";
import { connectionState, type Machine } from "../src/lib/machines";
import { expiryText } from "../src/lib/access-metadata";
import { withPlaceholders } from "../src/lib/fix-text";

// What these have in common: a state that proved nothing (a check that did not run, a failed
// write, a machine that never answered) was drawn as a good result.

const machine = (last_status: Machine["last_status"]) => ({ scanning: false, last_status }) as Machine;

test("only a successful or post-sign-in attempt reads as connected", () => {
  expect(connectionState(machine({ state: "ok" }))).toMatchObject({ dot: "ok", label: "Connected" });
  // The scan failed after signing in, so the connection itself worked.
  expect(connectionState(machine({ state: "failed", kind: "sudo_requires_password" })).dot).toBe("ok");
  expect(connectionState(machine({ state: "failed", kind: "unreachable" }))).toMatchObject({
    dot: "warn",
    problem: true,
  });
  // An unrecognised ssh failure may mean the machine never answered: neutral, never green.
  expect(connectionState(machine({ state: "failed", kind: "other" }))).toEqual({
    dot: "idle",
    label: "Not confirmed",
    problem: false,
  });
  expect(connectionState(machine(null)).dot).toBe("idle");
});

test("expiry and rule text read as written for a person", () => {
  const now = Date.parse("2026-01-01T00:00:00Z");
  expect(expiryText("2026-01-02T00:00:00Z", now)).toBe("Expires in 1 day");
  expect(expiryText("2026-01-03T00:00:00Z", now)).toBe("Expires in 2 days");
  expect(withPlaceholders('command ("{{ cron_entries.command }}")')).toBe('command ("‹command›")');
});

async function openMachine(page: Page, query: string, name: RegExp) {
  await page.goto(`/${query}`);
  await goToView(page, "Remote hosts");
  await page.getByRole("button", { name }).filter({ visible: true }).click();
}

test("a machine whose last attempt failed in an unknown way is not shown connected", async ({ page }) => {
  await page.goto("/?machines=unclassified");
  await goToView(page, "Remote hosts");
  const card = page.getByRole("button", { name: /web-1/ }).filter({ visible: true });
  await expect(card).toContainText("Not confirmed");
  await expect(card).not.toContainText("Connected");
});

test("old results from an unreachable machine are not a green all-clear", async ({ page }) => {
  await openMachine(page, "?machines=staleClean", /studio-laptop/);
  await expect(page.getByText(/may be out of date/)).toBeVisible();
  await expect(
    page.getByText("The last successful scan of studio-laptop found no open issues."),
  ).toBeVisible();
  await expect(page.getByText("No open issues on studio-laptop.")).toHaveCount(0);
});

test("results that cannot be read end in a message, not an endless spinner", async ({ page }) => {
  await openMachine(page, "?machines=findingsError", /web-1/);
  await expect(
    page.getByText("The stored results for web-1 could not be read", { exact: false }),
  ).toBeVisible();
});

test("pausing every machine is reflected on each card and in its details", async ({ page }) => {
  await page.goto("/");
  await goToView(page, "Remote hosts");
  await expect(page.getByText(/^Next scan/).first()).toBeVisible();
  await page.getByRole("switch", { name: "Scheduled scans" }).click();
  await expect(
    page.getByText("Scheduled scans are paused for every machine", { exact: false }),
  ).toBeVisible();
  await expect(page.getByText(/^Next scan/)).toHaveCount(0);
  await page.getByRole("button", { name: /web-1/ }).filter({ visible: true }).click();
  await expect(page.locator("dt", { hasText: "Next attempt" }).locator("+ dd")).toHaveText("Paused");
});

test("machine settings: named switches, a checked port, an honest Saved and a dialog that keeps focus", async ({
  page,
}) => {
  await openMachine(page, "", /web-1/);
  await page.getByRole("tab", { name: "Settings" }).click();
  await expect(page.getByRole("switch", { name: "Include checks that need root" })).toBeVisible();
  await expect(page.getByRole("switch", { name: "Scheduled scans" })).toBeVisible();

  await page.getByLabel("Port").fill("99999");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("The port must be a number between 1 and 65535.")).toBeVisible();
  await expect(page.getByText("Saved.")).toHaveCount(0);

  await page.getByLabel("Port").fill("2222");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Saved.")).toBeVisible();
  await page.getByLabel("Name").fill("web-one");
  await expect(page.getByText("Saved.")).toHaveCount(0);

  const remove = page.getByRole("button", { name: "Remove machine…" });
  await remove.click();
  const dialog = page.getByRole("dialog", { name: "Remove web-1?" });
  await expect(dialog).toBeVisible();
  for (let i = 0; i < 6; i++) {
    await page.keyboard.press("Tab");
    expect(await page.evaluate(() => Boolean(document.activeElement?.closest('[role="dialog"]')))).toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(remove).toBeFocused();
});

test("File changes claims nothing when the last scan did not check the files", async ({ page }) => {
  await page.goto("/?sshDenied=1");
  await goToView(page, "File changes");
  await expect(page.getByText("The last scan did not check these files.")).toBeVisible();
  await expect(page.getByText("No watched file has changed.")).toHaveCount(0);
});

test("File changes still says nothing changed when its checks ran clean", async ({ page }) => {
  await page.goto("/");
  await goToView(page, "File changes");
  await expect(page.getByText("No watched file has changed.")).toBeVisible();
});

test("SSH permissions that could not be checked are not reported as correct", async ({ page }) => {
  await page.goto("/?sshPerms=failed");
  await goToView(page, "Settings");
  await page.getByRole("button", { name: "Check permissions" }).click();
  await expect(page.getByText("2 files could not be checked or changed.")).toBeVisible();
  await expect(page.getByText("file modes are not supported on this platform").first()).toBeVisible();
  await expect(page.getByText("All checked permissions are already correct.")).toHaveCount(0);
});

test("a secret that could not be removed is not reported as removed", async ({ page }) => {
  await page.goto("/?redactFail=1");
  await page.getByRole("button", { name: /Anthropic API key exposed/ }).click();
  await page.getByRole("button", { name: "Remove secret from this file" }).click();
  await page.getByRole("button", { name: "Remove 1 secret" }).click();
  await expect(page.getByText(/Nothing was removed\. .*permission denied/)).toBeVisible();
  await expect(page.getByText(/^Removed\./)).toHaveCount(0);
});

test("Windows settings do not offer Unix-only fixes or wording", async ({ page }) => {
  await page.goto("/?platform=windows");
  await goToView(page, "Settings");
  await expect(page.getByRole("heading", { name: "Protect SSH keys" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Fix ~/.ssh permissions" })).toHaveCount(0);
  await expect(page.getByText(/need administrator access never run unattended/)).toBeVisible();
  await expect(page.getByText("/etc/sudoers")).toHaveCount(0);
});

test("real-time protection with no folder is not described as watching", async ({ page }) => {
  await page.goto("/");
  await goToView(page, "Malware scan");
  await page.getByRole("switch", { name: "Real-time protection" }).click();
  await expect(page.getByText("Watching for new files")).toBeVisible();
  for (const folder of ["/home/user/Downloads", "/home/user/Desktop"])
    await page.getByRole("button", { name: `Stop using ${folder}` }).click();
  await expect(page.getByText("On, but no folder to watch")).toBeVisible();
  await expect(page.getByText("Watching for new files")).toHaveCount(0);
});

test("a file the privileged checks could not read is a note on Configuration too", async ({ page }) => {
  await page.goto("/?scanUnread=1");
  await goToView(page, "Configuration");
  await page.getByRole("button", { name: "Run privileged checks" }).click();
  await expect(page.getByText(/1 file could not be checked/).filter({ visible: true })).toBeVisible();
  await expect(page.getByText(/^credential_stores: could not check/)).toHaveCount(0);
});

test("history counts by the pages' own names and draws an empty part neutral", async ({ page }) => {
  await page.goto("/");
  await goToView(page, "History");
  const row = page.getByText("File changes", { exact: true }).filter({ visible: true }).locator("xpath=..");
  await expect(row).toContainText("0");
  expect(await row.evaluate((el) => (el as HTMLElement).style.getPropertyValue("--rail-color"))).toBe(
    "var(--sev-info)",
  );
  await expect(page.getByText("Agent Security")).toHaveCount(0);
});

for (const [platform, name] of [
  ["windows", "Windows"],
  ["macos", "macOS"],
] as const) {
  test(`File changes says it does not apply on ${name}, where its checks never run`, async ({ page }) => {
    await page.goto(`/?platform=${platform}`);
    await goToView(page, "File changes");
    await expect(page.getByText(`Not available on ${name} yet.`)).toBeVisible();
    await expect(page.getByRole("button", { name: "Record baseline" })).toHaveCount(0);
    await expect(page.getByText("No watched file has changed.")).toHaveCount(0);
  });
}

test("a watcher left on without ClamAV says so and can still be switched off", async ({ page }) => {
  await page.goto("/?clamav=missing&realtime=on");
  await goToView(page, "Malware scan");
  const toggle = page.getByRole("switch", { name: "Real-time protection" });
  await expect(page.getByText("On, but nothing to scan with")).toBeVisible();
  await expect(page.getByText("Watching for new files")).toHaveCount(0);
  await expect(toggle).toBeEnabled();
  await toggle.click();
  await expect(page.getByText("Not watching")).toBeVisible();
  await expect(toggle).toBeDisabled();
});
