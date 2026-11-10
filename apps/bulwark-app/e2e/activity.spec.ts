import { test, expect } from "@playwright/test";
import { goToView } from "./fixtures";

for (const outcome of ["success", "error"]) {
  test(`metadata activity stops on ${outcome}`, async ({ page }) => {
    await page.goto(`/?accessSlow=1${outcome === "error" ? "&access=error" : ""}`);
    await page.getByRole("button", { name: "Secrets", exact: true }).click();
    await page.getByRole("tab", { name: "AWS Vault", exact: true }).click();
    await page.getByRole("button", { name: "Refresh sessions", exact: true }).click();
    const activity = page.locator(".task-activity");
    await expect(activity).toBeVisible();
    // One stable line per task: rotating copy read as restless (user decision, 2026-11-09).
    const phrase = await activity.locator(".activity-phrase").textContent();
    await page.waitForTimeout(3400);
    await expect(activity.locator(".activity-phrase")).toHaveText(phrase!);
    await expect(activity.locator(".sr-only")).toHaveText("Reading local AWS Vault metadata.");
    await expect(activity).toHaveCount(0, { timeout: 10000 });
    if (outcome === "error") {
      await expect(page.getByRole("alert")).toBeVisible();
      await expect(page.getByRole("table")).toHaveCount(0);
    } else await expect(page.getByRole("rowheader", { name: "demo-readonly" })).toBeVisible();
  });
}

test("reduced motion keeps activity still and its phrase stable", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/?accessSlow=1");
  await page.getByRole("button", { name: "Secrets", exact: true }).click();
  await page.getByRole("tab", { name: "AWS Vault", exact: true }).click();
  await page.getByRole("button", { name: "Refresh sessions", exact: true }).click();
  const activity = page.locator(".task-activity");
  await expect(activity).toBeVisible();
  await expect(activity.locator(".task-mark")).toHaveCSS("animation-name", "none");
  const phrase = await activity.locator(".activity-phrase").textContent();
  await page.waitForTimeout(3500);
  await expect(activity.locator(".activity-phrase")).toHaveText(phrase!);
  await expect(activity).toHaveCount(0, { timeout: 10000 });
});

test("an entirely skipped SSH scan does not claim all clear", async ({ page }) => {
  await page.goto("/?sshDenied=1");
  await goToView(page, "Scan");
  await expect(page.getByRole("heading", { name: "Checks need access" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Run them", exact: true })).toBeVisible();
  await expect(page.getByText("All clear", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Some checks still need administrator access.")).toBeVisible();
});

/** Elements in the visible view running an endless animation. Spinners on real work are allowed. */
async function idleLoops(page: import("@playwright/test").Page) {
  return page.evaluate(
    () =>
      [...document.querySelectorAll(".view-transition:not(.hidden) *")].filter((el) => {
        const style = getComputedStyle(el);
        return (
          style.animationName !== "none" &&
          style.animationIterationCount === "infinite" &&
          !el.closest(".task-activity") &&
          !el.classList.contains("animate-spin")
        );
      }).length,
  );
}

test("nothing loops while idle; the task mark loops only during work", async ({ page }) => {
  await page.goto("/?accessSlow=1");
  for (const label of ["Scan", "Secrets", "Tools", "Settings"]) {
    await goToView(page, label);
    expect(await idleLoops(page)).toBe(0);
  }
  await goToView(page, "Secrets");
  await page.getByRole("tab", { name: "AWS Vault", exact: true }).click();
  await expect(page.locator(".task-mark")).toHaveCount(0);
  await page.getByRole("button", { name: "Refresh sessions", exact: true }).click();
  const sweep = page.locator(".task-mark");
  await expect(sweep).toHaveCSS("animation-iteration-count", "infinite");
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await expect(sweep).toHaveCSS("animation-play-state", "paused");
  await page.getByRole("button", { name: "Secrets", exact: true }).click();
  await page.getByRole("tab", { name: "AWS Vault", exact: true }).click();
  await expect(sweep).toHaveCSS("animation-play-state", "running");
  await page.emulateMedia({ reducedMotion: "reduce" });
  await expect(sweep).toHaveCSS("animation-name", "none");
  await expect(page.locator(".task-activity")).toHaveCount(0, { timeout: 10000 });
});
