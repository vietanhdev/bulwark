/**
 * Records a crisp product-demo of the real frontend (fixture-backed, VITE_MOCK_TAURI=true).
 *
 * Why frame-by-frame PNGs instead of Playwright's built-in video: Playwright records webm with a
 * lossy VP8 encoder that visibly blurs text — even at 2x it looks soft. Capturing lossless PNG
 * frames at 2x (retina) and assembling them with ffmpeg keeps every frame pixel-sharp, at the cost
 * of running ~12fps rather than 30. For a mostly-discrete UI walkthrough that reads as crisp, not
 * low-res, which is the whole point.
 *
 * Usage:
 *   VITE_MOCK_TAURI=true npx vite --port 4173 --strictPort &
 *   FRAME_DIR=/tmp/bw-frames node scripts/record-demo.mjs [baseUrl]
 *   FRAME_DIR=/tmp/bw-frames scripts/encode-demo.sh   # -> docs/public/demo.mp4 + demo.gif
 *
 * Output: numbered PNG frames in $FRAME_DIR (2560x1600 each).
 */
import { createRequire } from "node:module";
import { mkdirSync, rmSync } from "node:fs";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const BASE_URL = process.argv[2] ?? "http://localhost:4173";
const FRAME_DIR = process.env.FRAME_DIR ?? "/tmp/bw-frames";
const W = 1280;
const H = 800;
const SCALE = 2;
const FPS = 12;
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

rmSync(FRAME_DIR, { recursive: true, force: true });
mkdirSync(FRAME_DIR, { recursive: true });

const browser = await chromium.launch({
  args: [`--force-device-scale-factor=${SCALE}`, "--high-dpi-support=1"],
});
const context = await browser.newContext({
  viewport: { width: W, height: H },
  deviceScaleFactor: SCALE,
  colorScheme: "light",
});
const page = await context.newPage();
page.setDefaultTimeout(3500);

await page.addInitScript(() => {
  try {
    localStorage.removeItem("bulwark-theme");
    localStorage.removeItem("bulwark-accent");
    localStorage.removeItem("bulwark-chrome");
  } catch {}
});
await page.goto(BASE_URL, { waitUntil: "networkidle" });
// Record the window edge-to-edge with square corners. The page that embeds the video rounds and
// clips it (see docs/.vitepress/theme/HeroDemo.vue); baking the window's own rounded corners and
// a backdrop colour into the frames showed as a mismatched, "cropped" corner on any page
// background that wasn't exactly that colour.
await page.addStyleTag({
  content:
    ".app-shell{border-radius:0 !important;border:0 !important;} html,body{background:transparent !important;}",
});

let idx = 0;
const snap = () => page.screenshot({ path: `${FRAME_DIR}/f${String(idx++).padStart(5, "0")}.png` });

// Capture crisp frames for `ms` while the page animates (each screenshot takes real time, so this
// naturally paces the capture; the page's own CSS transitions play out across the frames).
async function hold(ms) {
  const frames = Math.max(1, Math.round((ms / 1000) * FPS));
  const gap = ms / frames;
  for (let i = 0; i < frames; i++) {
    await snap();
    await wait(gap);
  }
}
// Scroll in discrete steps, one crisp frame per step — smooth-looking without CSS smooth-scroll.
async function scrollBy(total, frames = 14) {
  for (let i = 0; i < frames; i++) {
    await page.mouse.wheel(0, total / frames);
    await snap();
    await wait(10);
  }
}

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
// Scenes follow the workbench: Scan -> open a finding -> Fix now review -> Secrets (inventory, one
// tool, the list of tools) -> Tools ->
// Settings (theme), then back to Scan. Fixture data only (VITE_MOCK_TAURI), nothing real.

// 1. Scan, at rest, then run a scan.
await hold(1200);
await clickBtn("Scan now");
await hold(2600);

// 2. Open a finding: why it matters and its fix.
await clickBtn(/ssh private key is not passphrase-protected/i);
await hold(1800);
await clickBtn(/anthropic api key exposed/i);
await hold(1600);

// 3. Fix now: a preview of every change; nothing is written until Apply.
await clickBtn(/^fix now$/i, false);
await hold(3000);
await clickBtn(/^cancel$/i);
await hold(500);

// 4. Secrets: one inventory of what each tool holds and how it is stored (names only, never
//    values). On a fresh profile every detected tool is added and read automatically, so the
//    Inventory is already filled. Then one tool's own tab, then the list of tools you can add.
const clickTab = (name) =>
  page
    .getByRole("tab", { name, exact: true })
    .click()
    .catch(() => {});
await clickNav(/^secrets$/i);
await hold(2600);
await clickTab("AWS CLI");
await hold(1500);
await clickTab("Add");
await hold(1700);

// 5. Tools: deeper tools when needed.
await clickNav(/^tools$/i);
await hold(1800);

// 6. Live theme + colour switching.
await clickNav(/^settings$/i);
await hold(900);
await clickBtn("Light", true);
await hold(1100);
await clickBtn("Blue accent");
await hold(700);
await clickBtn("Indigo chrome");
await hold(900);
await clickBtn("Aqua accent");
await clickBtn("Graphite chrome");
await hold(700);
await clickBtn("Dark", true);
await hold(800);

// 7. Back to Scan.
await clickNav(/^scan$/i);
await hold(1400);

await browser.close();
console.log(`${idx} frames -> ${FRAME_DIR}`);
