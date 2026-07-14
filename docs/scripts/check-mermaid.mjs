// Renders every ```mermaid block in the docs against the *exact* mermaid version the site ships
// (docs/node_modules/mermaid) and fails if any comes back as "Syntax error in text". This exists
// because a broken diagram is invisible until render time: the VitePress build passes regardless,
// and mermaid only fails client-side in the browser — so nothing catches it until a human loads the
// page. It renders (not just `mermaid.parse()`, which is lenient and accepts things the renderer
// then rejects) in a headless browser, because mermaid needs a DOM.
//
// Runs from the raw diagram source, so no build or dev server is needed. Playwright is a docs
// devDependency, so this resolves it locally; CI installs the Chromium browser binary
// (`npx playwright install chromium`) that headless rendering needs.
//
//   npm run mermaid:check
//
// Exit 0 if every diagram renders, 1 (listing file:line and the mermaid error) if any doesn't.
import { createRequire } from "node:module";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const DOCS = join(dirname(fileURLToPath(import.meta.url)), "..");
const MERMAID_JS = require.resolve("mermaid/dist/mermaid.min.js", {
  paths: [DOCS],
});

/** Every `.md` under docs/ except node_modules and the build output. */
function markdownFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    if (
      name === "node_modules" ||
      name === ".vitepress" ||
      name.startsWith(".")
    )
      continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) out.push(...markdownFiles(p));
    else if (name.endsWith(".md")) out.push(p);
  }
  return out;
}

/** Pull out each fenced ```mermaid block as { code, line } (1-based line of the opening fence). */
function mermaidBlocks(text) {
  const lines = text.split("\n");
  const blocks = [];
  let start = -1;
  let buf = [];
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (start === -1 && t.startsWith("```mermaid")) {
      start = i;
      buf = [];
    } else if (start !== -1 && t.startsWith("```")) {
      blocks.push({ code: buf.join("\n"), line: start + 1 });
      start = -1;
    } else if (start !== -1) {
      buf.push(lines[i]);
    }
  }
  return blocks;
}

const files = markdownFiles(DOCS);
const browser = await chromium.launch();
const page = await browser.newPage();
await page.goto("about:blank");
// Inject by content, not by file:// URL — a blank page refuses to load a local-file script.
await page.addScriptTag({ content: readFileSync(MERMAID_JS, "utf8") });
// Match the site's rendering config (theme is what vitepress-plugin-mermaid drives), so this
// validates the diagrams the way they'll actually render, not a default-config approximation.
await page.evaluate(() =>
  window.mermaid.initialize({ startOnLoad: false, theme: "base" }),
);

let checked = 0;
const failures = [];
for (const file of files) {
  const rel = relative(DOCS, file);
  for (const { code, line } of mermaidBlocks(readFileSync(file, "utf8"))) {
    checked++;
    const error = await page.evaluate(async (src) => {
      // Actually RENDER, not just parse: mermaid.parse() is lenient (it accepts things the renderer
      // then chokes on), so parse-only would miss exactly the diagrams that break in the browser.
      // A syntax failure either throws or comes back as an SVG whose text is "Syntax error in text".
      try {
        const id = "mmchk_" + Math.floor(Math.random() * 1e9);
        const { svg } = await window.mermaid.render(id, src);
        return /Syntax error in text/i.test(svg)
          ? "renders as a mermaid error diagram"
          : null;
      } catch (e) {
        return String(e && e.message ? e.message : e);
      }
    }, code);
    if (error) {
      failures.push({ rel, line, error: error.replace(/\s+/g, " ").trim() });
    }
  }
}

await browser.close();

if (failures.length) {
  console.error(
    `\n✗ ${failures.length} of ${checked} mermaid diagram(s) have syntax errors:\n`,
  );
  for (const f of failures) {
    console.error(`  ${f.rel}:${f.line}`);
    console.error(`    ${f.error.slice(0, 300)}`);
  }
  console.error(
    `\nTip: quote labels with special characters ("A[\\"text (x)\\"]"); mermaid 11 wants <br/> for line breaks in labels, not \\n.`,
  );
  process.exit(1);
}
console.log(
  `✓ all ${checked} mermaid diagram(s) render cleanly (mermaid ${MERMAID_JS.includes("node_modules") ? "from node_modules" : ""}).`,
);
