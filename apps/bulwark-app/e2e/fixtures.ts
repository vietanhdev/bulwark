import { type Page, expect } from "@playwright/test";

// The eight primary views, keyed by their sidebar label. `title` is the heading
// the view renders when active; `signature` is a section unique to that view, so
// a test proves the *right* view is showing (all views stay mounted and are
// CSS-hidden when inactive, so assertions must be visibility-aware).
export const VIEWS = [
  { label: "Home", title: "Home", signature: /scan scope/i },
  { label: "Checkups", title: "Checkups", signature: /issues to fix|all clear|no issues/i },
  { label: "Virus scan", title: "Virus scan", signature: /real-time protection/i },
  { label: "AI assistants", title: "AI assistants", signature: /findings/i },
  { label: "File changes", title: "File changes", signature: /what.?s watched/i },
  { label: "All checks", title: "All checks", signature: /kernel hardening/i },
  { label: "Activity", title: "Activity", signature: /findings over time/i },
  { label: "Settings", title: "Settings", signature: /appearance/i },
] as const;

/** Click a sidebar nav item (scoped to the <nav> so labels that also appear in
 *  page content don't create ambiguity). */
export async function goToView(page: Page, label: string) {
  await page
    .locator("nav")
    .getByRole("button", { name: new RegExp(label) })
    .first()
    .click();
}

/** Assert the app shell has rendered (used as a ready-check after goto). */
export async function expectShellReady(page: Page) {
  await expect(page.locator("nav").getByRole("button", { name: "Home" })).toBeVisible();
}

/** First VISIBLE element with the given text. Inactive views stay mounted and
 *  hidden, so the same label (e.g. a category name) can exist several times in
 *  the DOM — only the copy in the active view is visible. */
export function visibleText(page: Page, text: string | RegExp) {
  return page.getByText(text).filter({ visible: true }).first();
}
