/**
 * Records a short product-demo video of the real frontend (fixture-backed, VITE_MOCK_TAURI=true),
 * the same way capture-screenshots.mjs takes stills. Playwright records a webm; ffmpeg then makes an
 * optimized GIF and an MP4 for the README / marketing.
 *
 * Usage:
 *   VITE_MOCK_TAURI=true npx vite --port 4173 --strictPort &
 *   NODE_PATH=/tmp/pw/node_modules node scripts/record-demo.mjs [baseUrl]
 *
 * Output: docs/public/demo.webm — a ~22s scan → findings → theming flow.
 */
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { readdirSync, renameSync } from "node:fs";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const BASE_URL = process.argv[2] ?? "http://localhost:4173";
const OUT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../../docs/public");
const W = 1280;
const H = 800;
const SCALE = 2; // record at 2x (retina) so text stays crisp after downscaling
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await chromium.launch({
  // Force a stable device scale in headless so the captured frames are genuinely 2x.
  args: [`--force-device-scale-factor=${SCALE}`, "--high-dpi-support=1"],
});
const context = await browser.newContext({
  viewport: { width: W, height: H },
  deviceScaleFactor: SCALE,
  recordVideo: { dir: OUT_DIR, size: { width: W * SCALE, height: H * SCALE } },
});
const page = await context.newPage();
// Never let a mis-named selector stall the take for 30s — fail fast and keep the flow moving.
page.setDefaultTimeout(3500);

await page.addInitScript(() => {
  try {
    localStorage.removeItem("bulwark-theme");
    localStorage.removeItem("bulwark-accent");
    localStorage.removeItem("bulwark-chrome");
  } catch {}
});
await page.goto(BASE_URL, { waitUntil: "networkidle" });
// Give the frameless window's rounded corners a calm ground in the opaque video.
await page.addStyleTag({ content: "html,body{background:#17121a !important;}" });

const nav = page.locator("nav");
const clickNav = (name) =>
  nav
    .getByRole("button", { name })
    .first()
    .click()
    .catch(() => {});
const clickBtn = (name, exact = false) =>
  page
    .getByRole("button", { name, exact })
    .first()
    .click()
    .catch(() => {});

// Smooth, eased scroll of the content area — many tiny wheel steps instead of one jump.
async function smoothScroll(total, ms = 900, steps = 30) {
  const per = total / steps;
  const gap = ms / steps;
  for (let i = 0; i < steps; i++) {
    await page.mouse.wheel(0, per);
    await wait(gap);
  }
}

// 1. Home, at rest.
await wait(1300);

// 2. Run a scan — findings stream in with the plain-language buckets.
await clickBtn("Run 2 scans");
await wait(3400);
await smoothScroll(360, 1100);
await wait(900);
await smoothScroll(-360, 900);
await wait(600);

// 3. The differentiator — AI assistants (findings are already loaded from the snapshot).
await clickNav("AI assistants");
await wait(1500);
await smoothScroll(320, 1000);
await wait(1000);
await smoothScroll(-320, 800);
await wait(500);

// 4. Make it yours — live theme + colour switching (the tokens transition smoothly).
await clickNav("Settings");
await wait(1100);
await clickBtn("Green accent");
await wait(950);
await clickBtn("Teal sidebar");
await wait(950);
await clickBtn("Dark", true);
await wait(1250);
await clickBtn("Blue accent");
await wait(950);
await clickBtn("Indigo sidebar");
await wait(1150);

// 5. Back to a light Home to close the loop.
await clickBtn("Light", true);
await wait(650);
await clickNav("Home");
await wait(1700);

await context.close();
await browser.close();

const vids = readdirSync(OUT_DIR).filter((f) => f.endsWith(".webm"));
vids.sort();
if (vids.length) {
  renameSync(resolve(OUT_DIR, vids[vids.length - 1]), resolve(OUT_DIR, "demo.webm"));
  console.log("wrote docs/public/demo.webm");
} else {
  console.error("no webm produced");
  process.exit(1);
}
