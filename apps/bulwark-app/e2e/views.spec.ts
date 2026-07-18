import { test, expect } from "@playwright/test";
import { goToView, visibleText } from "./fixtures";

// Deeper per-view coverage: each view renders its signature sections (stable UI
// labels, not fixture data). Assertions are visibility-aware because inactive
// views stay mounted and hidden.
const VIEW_SECTIONS: { label: string; sections: RegExp[] }[] = [
  { label: "Home", sections: [/scans/i, /scan scope/i] },
  { label: "Checkups", sections: [/issues to fix|all clear|no issues/i] },
  { label: "Virus scan", sections: [/real-time protection/i, /manual scan/i] },
  { label: "AI assistants", sections: [/findings/i] },
  { label: "File changes", sections: [/what.?s watched/i, /integrity findings/i] },
  { label: "All checks", sections: [/accounts.*services/i, /kernel hardening/i, /filesystem permissions/i] },
  { label: "Activity", sections: [/findings over time/i, /open by severity/i, /scan history/i] },
  { label: "Settings", sections: [/appearance/i, /continuous monitoring/i, /ssh hardening/i] },
];

test.describe("view content", () => {
  for (const { label, sections } of VIEW_SECTIONS) {
    test(`"${label}" renders its sections`, async ({ page }) => {
      await page.goto("/");
      await goToView(page, label);
      for (const section of sections) {
        await expect(visibleText(page, section)).toBeVisible();
      }
    });
  }

  test("All checks groups checks into rule categories with counts", async ({ page }) => {
    await page.goto("/");
    await goToView(page, "All checks");
    // Category headings carry a numeric count (e.g. "KERNEL HARDENING 21").
    await expect(visibleText(page, /kernel hardening/i)).toBeVisible();
    await expect(visibleText(page, /\b\d+\b/)).toBeVisible();
  });
});
