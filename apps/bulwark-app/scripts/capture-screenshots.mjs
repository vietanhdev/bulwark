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
 * Output: docs/public/screenshots/*.png at 2560x1600 — a 2x capture of the app's real default
 * window size (1280x800, per src-tauri/tauri.conf.json). Keep that ratio: a screenshot at some
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
  { tab: null, file: "overview.png" }, // Overview is the landing view
  { tab: "Compliance", file: "compliance.png" },
  { tab: "Antivirus", file: "antivirus.png", run: "Run a virus scan", settleMs: 8000 },
  { tab: "Agent Security", file: "agent-security.png" },
  { tab: "Rules", file: "rules.png" },
];

const browser = await chromium.launch();
const page = await browser.newPage({
  viewport: { width: 1280, height: 800 },
  deviceScaleFactor: 2,
});

await page.goto(BASE_URL, { waitUntil: "networkidle" });

const nav = page.locator("nav");

for (const { tab, file, run, settleMs } of SHOTS) {
  if (tab) {
    // Scoped to the sidebar, and matched by substring rather than exactly: "Agent Security"
    // carries a "New" badge, which lands in the button's accessible name.
    await nav.getByRole("button", { name: tab }).first().click();
  }
  // The views fetch through the mocked `invoke`, which simulates latency on purpose. Settle
  // before shooting, or we capture a half-populated page.
  await page.waitForTimeout(1000);

  if (run) {
    await page.getByRole("button", { name: run, exact: true }).click();
    await page.waitForTimeout(settleMs ?? 5000);
  }

  await page.screenshot({ path: resolve(OUT_DIR, file) });
  console.log(`captured ${file}`);
}

await browser.close();
