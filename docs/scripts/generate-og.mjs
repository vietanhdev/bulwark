// Generates the 1200x630 social-preview cards in docs/public/og/, one per page.
//
// This script exists because the original cards were generated ad-hoc and the generator was
// never checked in — so when ten new articles landed, nobody noticed they had no card, and
// they shipped a `twitter:card: summary_large_image` with no image (a blank preview, which is
// worse than no tags at all). Keeping the generator in the repo makes the card set a
// build-checkable artifact rather than something that silently drifts.
//
// Each card's text is derived from the page itself — the H1 for the title, the `description`
// frontmatter for the subtitle — so a card can't fall out of sync with the article it
// advertises. The only per-page overrides are in CARD_TITLES below, for pages whose H1 is too
// long to read at thumbnail size.
//
//   node scripts/generate-og.mjs           # write any missing cards
//   node scripts/generate-og.mjs --all     # re-render every card (after a design change)
//   node scripts/generate-og.mjs --check   # exit 1 if any page lacks a card (for CI)

import { chromium } from "playwright";
import { readFileSync, existsSync, readdirSync, mkdirSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";

const DOCS = join(dirname(fileURLToPath(import.meta.url)), "..");
const OG_DIR = join(DOCS, "public", "og");
const SITE = "bulwark.nrl.ai";

// The full H1 is the default card title. Override only where the H1 is too long to stay
// legible at the size a social card is actually viewed (roughly 40 chars is the ceiling).
const CARD_TITLES = {
  "index.md": "Bulwark",
  "guide/architecture.md": "Architecture",
  "guide/agent-security.md": "AI Agent Security",
  "articles/ai-coding-assistant-security.md": "AI Coding Assistant Security",
  "articles/ssh-hardening-checklist.md": "SSH Hardening on Linux",
  "articles/linux-persistence-techniques.md": "How Attackers Persist on Linux",
  "articles/choosing-a-linux-security-scanner.md": "Choosing a Linux Security Scanner",
  "articles/sysctl-kernel-hardening.md": "sysctl Kernel Hardening",
  "articles/sudoers-hardening-checklist.md": "Sudoers Hardening on Linux",
  "articles/is-my-linux-server-hacked.md": "Is My Linux Server Hacked?",
  "articles/auditd-rules-cheat-sheet.md": "auditd Rules Cheat Sheet",
  "articles/rkhunter-chkrootkit-false-positives.md": "Reading rkhunter & chkrootkit Output",
  "articles/does-linux-need-antivirus.md": "Does Linux Need Antivirus?",
  "articles/systemd-service-sandboxing.md": "systemd Service Sandboxing",
  "articles/bulwark-vs-wazuh.md": "Bulwark vs. Wazuh",
  "articles/cis-mitre-mapping.md": "Mapping Rules to CIS & MITRE ATT&CK",
  "articles/fail2ban-vs-crowdsec-vs-denyhosts.md": "fail2ban vs. CrowdSec vs. denyhosts",
};

/** Every page that should carry a card: the landing page, the guide, and all articles.
 *
 * Guide pages are listed explicitly rather than globbed, so adding one means adding it here too.
 * That is a footgun worth knowing about: a page absent from this list silently falls back to the
 * site-wide card (see `ogSlugFor` in config.mts), so it *looks* fine — `og:check` passes — while
 * every link to it previews as the generic homepage blurb. `guide/agent-security.md` was added
 * for exactly that reason. */
function pagesNeedingCards() {
  const pages = ["index.md", "guide/architecture.md", "guide/agent-security.md"];
  for (const f of readdirSync(join(DOCS, "articles")).sort()) {
    if (f.endsWith(".md")) pages.push(`articles/${f}`);
  }
  return pages;
}

/** Pull the H1 and the `description` frontmatter straight out of the markdown. */
function readPage(relPath) {
  const raw = readFileSync(join(DOCS, relPath), "utf8");

  const fm = raw.match(/^---\n([\s\S]*?)\n---/);
  let description = "";
  if (fm) {
    const lines = fm[1].split("\n");
    const start = lines.findIndex((l) => /^description:/.test(l));
    if (start !== -1) {
      const head = lines[start].replace(/^description:\s*/, "");
      if (/^>-?$|^\|-?$/.test(head.trim())) {
        // Folded/literal block: take every subsequent indented line. (Matching this with a
        // single regex is where the first version of this script went wrong — `$` under /m
        // matches every line ending, so a lazy match stopped after line one and every card
        // shipped a subtitle truncated mid-sentence.)
        const body = [];
        for (let i = start + 1; i < lines.length; i++) {
          if (!/^\s+\S/.test(lines[i])) break;
          body.push(lines[i].trim());
        }
        description = body.join(" ");
      } else {
        description = head;
      }
    }
  }
  // index.md is a VitePress hero layout with no H1 and no description frontmatter.
  const h1 = raw.match(/^#\s+(.+)$/m)?.[1] ?? "";
  const heroTagline = raw.match(/^\s*tagline:\s*(.+)$/m)?.[1] ?? "";

  const title = CARD_TITLES[relPath] ?? h1;
  let subtitle = (description || heroTagline)
    .replace(/\s+/g, " ")
    .replace(/^["']|["']$/g, "")
    .trim();

  // Several descriptions open by restating the page title ("fail2ban vs CrowdSec vs denyhosts
  // — which SSH brute-force defense..."), which on a card reads as the title printed twice.
  // If the lead-in clause is the title again, drop it and promote the rest.
  const norm = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
  const [lead, ...rest] = subtitle.split(" — ");
  if (rest.length && norm(lead) === norm(title)) {
    subtitle = rest.join(" — ").replace(/^./, (c) => c.toUpperCase());
  }

  // The descriptions run 140–170 chars, which wraps to three lines in the card's text column
  // and still clears the footer. Only cut if a description ever grows past that, and cut at a
  // word boundary so it never ends mid-word.
  if (subtitle.length > 175) {
    subtitle = subtitle.slice(0, 172).replace(/\s+\S*$/, "") + "…";
  }

  return { slug: relPath === "index.md" ? "home" : basename(relPath, ".md"), title, subtitle };
}

const esc = (s) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** The card template. Mirrors the existing cards: teal shield mark, heavy title, angled wedge. */
function cardHtml({ title, subtitle }) {
  return `<!doctype html><html><head><meta charset="utf-8"><style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    width: 1200px; height: 630px; position: relative; overflow: hidden;
    background: #f8fafc;
    font-family: "Roboto", "Inter", "Liberation Sans", sans-serif;
    -webkit-font-smoothing: antialiased;
  }
  /* The angled wedge on the right edge — same teal, heavily tinted. */
  .wedge {
    position: absolute; top: 0; right: 0; width: 420px; height: 630px;
    background: #d7ecec;
    clip-path: polygon(58% 0, 100% 0, 100% 100%, 100% 100%, 22% 100%);
  }
  /* Fixed text column, vertically centred between the brand mark and the footer. This is why
     a two-line title (fail2ban vs. CrowdSec vs. denyhosts) plus a three-line subtitle still
     clears bulwark.nrl.ai instead of colliding with it. */
  .inner { position: relative; padding: 84px 0 0 90px; width: 880px; }
  .brand { display: flex; align-items: center; gap: 16px; margin-bottom: 58px; }
  .brand svg { width: 42px; height: 42px; display: block; }
  .brand span { font-size: 33px; font-weight: 700; color: #0d7a7a; letter-spacing: -0.01em; }
  h1 {
    font-size: 58px; font-weight: 800; line-height: 1.12; color: #0b0d0e;
    letter-spacing: -0.022em; max-width: 800px;
  }
  p {
    margin-top: 26px; font-size: 25px; line-height: 1.42; color: #5b6570;
    max-width: 790px; font-weight: 400;
  }
  .site {
    position: absolute; left: 90px; bottom: 62px;
    font-size: 20px; font-weight: 700; color: #0d7a7a;
  }
</style></head><body>
  <div class="wedge"></div>
  <div class="inner">
    <div class="brand">
      <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
        <path d="M50 4 L91 19 V49 C91 73 73 90 50 97 C27 90 9 73 9 49 V19 Z" fill="#0d7a7a"/>
      </svg>
      <span>Bulwark</span>
    </div>
    <h1>${esc(title)}</h1>
    ${subtitle ? `<p>${esc(subtitle)}</p>` : ""}
  </div>
  <div class="site">${SITE}</div>
</body></html>`;
}

const args = process.argv.slice(2);
const renderAll = args.includes("--all");
const checkOnly = args.includes("--check");

const pages = pagesNeedingCards().map(readPage);

if (checkOnly) {
  const missing = pages.filter((p) => !existsSync(join(OG_DIR, `${p.slug}.png`)));
  if (missing.length) {
    console.error(`Missing OG cards for ${missing.length} page(s):`);
    for (const p of missing) console.error(`  - ${p.slug}  ("${p.title}")`);
    console.error(`\nRun: node scripts/generate-og.mjs`);
    process.exit(1);
  }
  console.log(`All ${pages.length} pages have an OG card.`);
  process.exit(0);
}

mkdirSync(OG_DIR, { recursive: true });
const todo = renderAll ? pages : pages.filter((p) => !existsSync(join(OG_DIR, `${p.slug}.png`)));

if (!todo.length) {
  console.log("Every page already has a card. Use --all to re-render after a design change.");
  process.exit(0);
}

const browser = await chromium.launch();
const page = await browser.newPage({
  viewport: { width: 1200, height: 630 },
  deviceScaleFactor: 1,
});

let overflowed = 0;
for (const card of todo) {
  await page.setContent(cardHtml(card), { waitUntil: "load" });
  await page.evaluate(() => document.fonts.ready);

  // A card whose text runs under the footer or off the canvas still screenshots "successfully"
  // — it just ships broken. Measure the real laid-out boxes and say so instead.
  const clash = await page.evaluate(() => {
    const text = document.querySelector("p") ?? document.querySelector("h1");
    const site = document.querySelector(".site");
    const t = text.getBoundingClientRect();
    const s = site.getBoundingClientRect();
    return { bottom: Math.round(t.bottom), footerTop: Math.round(s.top) };
  });
  if (clash.bottom > clash.footerTop - 12) {
    console.warn(
      `  ! ${card.slug}: text overruns the footer (${clash.bottom}px vs ${clash.footerTop}px) — ` +
        `shorten its CARD_TITLES entry or its description.`,
    );
    overflowed++;
  }

  await page.screenshot({ path: join(OG_DIR, `${card.slug}.png`) });
  console.log(`  ✓ ${card.slug}.png  —  ${card.title}`);
}

await browser.close();
console.log(`\nWrote ${todo.length} card(s) to docs/public/og/.`);
if (overflowed) {
  console.error(`\n${overflowed} card(s) overflowed. Fix before shipping.`);
  process.exit(1);
}
