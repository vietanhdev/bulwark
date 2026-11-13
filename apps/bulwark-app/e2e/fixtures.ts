import { type Page, expect } from "@playwright/test";

// The primary views, keyed by their sidebar label. `title` is the heading
// the view renders when active; `signature` is a section unique to that view, so
// a test proves the *right* view is showing (all views stay mounted and are
// CSS-hidden when inactive, so assertions must be visibility-aware).
export const VIEWS = [
  { label: "Secrets", title: "Secrets", signature: /(entry|entries) across|reading your tools/i },
  {
    label: "Scan",
    title: "Scan",
    signature: /findings? to review|no findings in completed checks|ready to check your setup/i,
  },
  { label: "Configuration", title: "Configuration", signature: /issues? to fix|no findings/i },
  { label: "Malware scan", title: "Malware scan", signature: /real-time protection/i },
  { label: "File changes", title: "File changes", signature: /what.?s watched/i },
  { label: "Rule catalog", title: "Rule catalog", signature: /kernel hardening/i },
  { label: "History", title: "History", signature: /findings over time/i },
  { label: "Settings", title: "Settings", signature: /appearance/i },
  { label: "Tools", title: "Tools", signature: /a few deeper tools/i },
  { label: "Remote hosts", title: "Remote hosts", signature: /inspect other machines/i },
] as const;

/** Click a sidebar nav item (scoped to the <nav> so labels that also appear in
 *  page content don't create ambiguity). */
export async function goToView(page: Page, label: string) {
  if (!["Scan", "Secrets", "Tools", "Settings"].includes(label)) {
    await page.locator("nav").getByRole("button", { name: "Tools", exact: true }).click();
    await page.getByRole("button", { name: label, exact: true }).filter({ visible: true }).click();
  } else await page.locator("nav").getByRole("button", { name: label, exact: true }).click();
}

/** Assert the app shell has rendered (used as a ready-check after goto). */
export async function expectShellReady(page: Page) {
  await expect(page.locator("nav").getByRole("button", { name: "Secrets" })).toBeVisible();
}

/** First VISIBLE element with the given text. Inactive views stay mounted and
 *  hidden, so the same label (e.g. a category name) can exist several times in
 *  the DOM — only the copy in the active view is visible. */
export function visibleText(page: Page, text: string | RegExp) {
  return page.getByText(text).filter({ visible: true }).first();
}
