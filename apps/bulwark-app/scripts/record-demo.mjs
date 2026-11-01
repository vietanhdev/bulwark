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
 *   FRAME_DIR=/tmp/bw-frames NODE_PATH=/tmp/pw/node_modules node scripts/record-demo.mjs [baseUrl]
 *   # then ffmpeg -framerate 12 -i "$FRAME_DIR/f%05d.png" ... (see the shell step)
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

// 1. Home, at rest.
await hold(1200);

// 2. Run a scan — problems stream in, grouped by cause.
await clickBtn("Scan now");
await hold(3200);

// 3. Open a problem: why it matters, the one-click fix, then Details.
await clickBtn(/ssh private key is not passphrase-protected/i);
await hold(1400);
await clickBtn(/^add a passphrase$/i);
await hold(1200);
await clickBtn(/anthropic api key exposed/i);
await hold(1300);
await scrollBy(260);
await hold(900);
await scrollBy(-260);
await hold(300);

// 4. Remote machines: each one's system at a glance, then one opened — its connection and last
//    scan side by side, and its issues grouped like Home's.
await clickNav("Remote");
await hold(1500);
await page
  .getByRole("button", { name: /web-1/ })
  .first()
  .click()
  .catch(() => {});
await hold(1400);
await scrollBy(420);
await hold(1100);
await scrollBy(-420);
await hold(300);

// 5. Live theme + colour switching.
await clickNav("Settings");
await hold(1000);
await clickBtn("Dark", true);
await hold(1100);
await clickBtn("Blue accent");
await hold(750);
await clickBtn("Indigo sidebar");
await hold(950);
await clickBtn("Aqua accent");
await hold(600);
await clickBtn("Graphite sidebar");
await hold(800);

// 6. Back to a light Home.
await clickBtn("Light", true);
await hold(450);
await clickNav("Home");
await hold(1500);

await context.close();
await browser.close();
console.log(`captured ${idx} frames at ${W * SCALE}x${H * SCALE} into ${FRAME_DIR}`);
