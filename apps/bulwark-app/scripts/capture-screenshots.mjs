/**
 * Captures the README / docs screenshots from the real frontend, backed by fixtures.
 *
 * Why not screenshot the actual Tauri window: this project's dev environment has no working
 * desktop capture tool for it (see docs/public/screenshots/README.md). Instead the same
 * unmodified React app is served with every `@tauri-apps/api/*` import swapped for a
 * fixture-backed mock (`VITE_MOCK_TAURI=true`, see src/mocks/tauri/README.md).
 *
 * That indirection is not just a workaround, it's a requirement: screenshots must never be taken
 * from a real machine's scan. A genuine Agent Security scan surfaces the developer's actual
 * leaked API keys, real project paths, and real transcript locations — publishing that to a
 * README would be the exact failure the feature exists to prevent. Fixtures keep the images
 * honest about the UI and inert about the contents.
 *
 * Playwright is intentionally NOT a dependency of this app — it's only needed to regenerate
 * images, and a browser automation stack has no business in the shipped frontend's tree. Install
 * it somewhere scratch and point Node at it.
 *
 * Usage:
 *   npm install --prefix /tmp/pw playwright && npx playwright install chromium
 *   VITE_MOCK_TAURI=true npx vite --port 4173 --strictPort &
 *   NODE_PATH=/tmp/pw/node_modules node scripts/capture-screenshots.mjs [baseUrl]
 *
 * Output: docs/public/screenshots/*.png at 1800x1320 — a 2x capture of the app's real default
 * window size (900x660, per src-tauri/tauri.conf.json). Keep that ratio: a screenshot at some
 * other shape is a picture of a window nobody actually opens.
 */
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// Resolved through NODE_PATH so the scratch install is found without adding a dependency here.
const { chromium } = createRequire(import.meta.url)("playwright");

const BASE_URL = process.argv[2] ?? "http://localhost:4173";
const OUT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../../docs/public/screenshots");

/**
 * Each shot: the sidebar tab to open, an optional interaction to reach the state worth showing,
 * and the file to write. The Antivirus view is only interesting *after* a scan — an idle one is a
 * picture of a button — so that capture drives the mock scan to completion first.
 */
const SHOTS = [
  { tab: null, file: "overview.png", dark: false }, // Home is the landing view
  // One problem opened: why it matters, the one-click fix, and Details. Replaces the old separate
  // AI assistants screen, which is now part of Checkups.
  { tab: null, file: "fix.png", open: /ssh private key is not passphrase-protected/i },
  { tab: "Remote hosts", file: "machines.png" },
  // One machine opened: its connection and last scan side by side, and its issues grouped the same
  // way Home groups this computer's.
  { tab: "Remote hosts", file: "machine.png", open: /web-1/ },
  { tab: "Tools", file: "tools.png" },
  { tab: "Tools", file: "tools-light.png", dark: false },
  { tab: "Configuration", file: "compliance.png" },
  { tab: "Malware scan", file: "antivirus.png", run: "Run malware scan", settleMs: 8000 },
  { tab: "Rule catalog", file: "rules.png" },
  { tab: "Settings", file: "settings.png" },
  // Secrets opens on its combined Inventory (read automatically from the mock's file-based managers).
  { tab: "Secrets", file: "secrets-inventory.png" },
  { tab: "Secrets", file: "secrets-inventory-light.png", dark: false },
  { tab: "Secrets", subtab: "Add", file: "secrets-market.png" },
  { tab: null, file: "overview-dark.png", dark: true },
];

const browser = await chromium.launch();
const page = await browser.newPage({
  viewport: { width: 900, height: 660 },
  deviceScaleFactor: 2,
});

await page.goto(BASE_URL, { waitUntil: "networkidle" });

const nav = page.locator("nav");

for (const { tab, subtab, file, run, settleMs, open, dark = true } of SHOTS) {
  await page.evaluate((d) => document.documentElement.classList.toggle("dark", d), !!dark);
  // Scoped to the sidebar, and matched by substring rather than exactly.
  const label = tab ?? "Scan";
  if (!["Scan", "Secrets", "Tools", "Settings"].includes(label)) {
    await nav.getByRole("button", { name: "Tools", exact: true }).click();
    await page.getByRole("button", { name: label, exact: true }).filter({ visible: true }).click();
  } else await nav.getByRole("button", { name: label, exact: true }).click();
  // The views fetch through the mocked `invoke`, which simulates latency on purpose. Settle
  // before shooting, or we capture a half-populated page.
  await page.waitForTimeout(1000);
  if (subtab) {
    await page.getByRole("tab", { name: subtab, exact: true }).click();
    await page.waitForTimeout(400);
  }

  if (run) {
    await page.getByRole("button", { name: run, exact: true }).click();
    await page.waitForTimeout(settleMs ?? 5000);
  }
  if (open) {
    const row = page.getByRole("button", { name: open }).first();
    if ((await row.getAttribute("aria-expanded")) !== "true") await row.click();
    await page.waitForTimeout(400);
  }

  // `omitBackground` captures the transparent page background as alpha rather than filling it
  // white — so the window's rounded corners (`.app-shell` radius, `body` is transparent) read as a
  // real floating window instead of being squared off into the PNG's corners.
  await page.screenshot({ path: resolve(OUT_DIR, file), omitBackground: true });
  console.log(`captured ${file}`);
}
await nav.getByRole("button", { name: "Scan", exact: true }).click();
await page.getByRole("button", { name: "Fix now", exact: true }).click();
await page
  .getByRole("dialog")
  .getByText(/Nothing has been written yet/)
  .waitFor();
await page.screenshot({ path: resolve(OUT_DIR, "fix-review.png"), omitBackground: true });
await page.getByRole("dialog").getByRole("button", { name: "Cancel", exact: true }).click();
await page.evaluate(() => document.documentElement.classList.remove("dark"));

// ── Hero variants ────────────────────────────────────────────────────────────
// The same Home screen in several sidebar + accent colours, transparent-cornered, so the website
// can fan/stack them to show Bulwark's theming at a glance. The first is the default theme.
const HERO = [
  { chrome: "graphite", accent: "aqua" },
  { chrome: "blue", accent: "blue" },
  { chrome: "green", accent: "green" },
  { chrome: "aubergine", accent: "orange" },
];
await nav.getByRole("button", { name: "Secrets", exact: true }).click();
await page.waitForTimeout(800);
for (const { chrome, accent } of HERO) {
  await page.evaluate(
    ({ chrome, accent }) => {
      const el = document.documentElement;
      if (chrome === "aubergine") delete el.dataset.chrome;
      else el.dataset.chrome = chrome;
      if (accent === "orange") delete el.dataset.accent;
      else el.dataset.accent = accent;
    },
    { chrome, accent },
  );
  await page.waitForTimeout(300);
  await page.screenshot({ path: resolve(OUT_DIR, `hero-${chrome}.png`), omitBackground: true });
  console.log(`captured hero-${chrome}.png`);
}

// ── First run ────────────────────────────────────────────────────────────────
// What a new user sees before any scan: the numbered getting-started guide. `?scanEmpty` makes the
// mock report no stored scan. A fresh load also resets the hero colours above.
await page.goto(`${BASE_URL}/?scanEmpty=1`, { waitUntil: "networkidle" });
await page.evaluate(() => document.documentElement.classList.add("dark"));
await page.getByRole("list", { name: "Getting started" }).waitFor();
await page.screenshot({ path: resolve(OUT_DIR, "first-run.png"), omitBackground: true });
console.log("captured first-run.png");

await browser.close();
