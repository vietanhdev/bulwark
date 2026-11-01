---
layout: home

hero:
  name: Bulwark
  text: Local-first security for developers and their AI coding agents
  tagline: Finds the risky agent settings and leaked keys attackers look for, and fixes them. Nothing leaves your machine.
  actions:
    - theme: brand
      text: Download
      link: /download
    - theme: alt
      text: Browse every check
      link: /checks/
    - theme: alt
      text: View on GitHub
      link: https://github.com/vietanhdev/bulwark
---

<div class="bw-home">

<section class="bw-stats" aria-label="Bulwark at a glance">
  <div class="bw-stat">
    <span class="bw-stat-num">123</span>
    <span class="bw-stat-label">built-in checks</span>
  </div>
  <div class="bw-stat">
    <span class="bw-stat-num">25</span>
    <span class="bw-stat-label">AI coding agents covered</span>
  </div>
  <div class="bw-stat">
    <span class="bw-stat-num">1</span>
    <span class="bw-stat-label">page per check, with the fix</span>
  </div>
  <div class="bw-stat">
    <span class="bw-stat-num">0</span>
    <span class="bw-stat-label">accounts or telemetry</span>
  </div>
</section>

<section class="bw-section">

<p class="bw-eyebrow">What Bulwark checks</p>

<h2 class="bw-h2">What attackers look for on a developer machine</h2>

<p class="bw-sub">Your AI agents run with your keys and your shell. That's where attacks start now.</p>

<div class="bw-bento">
  <article class="bw-card bw-card-hero">
    <div class="bw-card-tag">The focus</div>
    <div class="bw-card-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>
    </div>
    <h3>AI coding agents</h3>
    <p>Project hooks, auto-approve modes, unpinned MCP servers, hidden instructions, and keys left in chats — across Claude Code, Cursor, Copilot, Codex, Gemini and 20 more.</p>
    <p class="bw-card-meta"><code>bulwarkctl ai scan</code></p>
  </article>

  <article class="bw-card">
    <div class="bw-card-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3M16 7l3 3M14 9l2 2"/></svg>
    </div>
    <h3>Secrets, supply chain and exposed services</h3>
    <p>Plaintext cloud keys, SSH keys without a passphrase, malicious packages, exposed dev databases.</p>
  </article>

  <article class="bw-card">
    <div class="bw-card-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 00-5.4 5.4l-6 6V21h3.3l6-6a4 4 0 005.4-5.4l-2.3 2.3-2.2-.4-.4-2.2 2.3-2.3z"/></svg>
    </div>
    <h3>One-click fixes</h3>
    <p>Previewed first, backed up always.</p>
  </article>


  <article class="bw-card">
    <div class="bw-card-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/></svg>
    </div>
    <h3>OS hardening and malware</h3>
    <p>SSH, sudo, kernel, firewall, persistence, rootkits, and ClamAV.</p>
  </article>

  <article class="bw-card">
    <div class="bw-card-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/></svg>
    </div>
    <h3>Linux, macOS and Windows</h3>
    <p>A desktop app and a single-file CLI on each.</p>
  </article>

</div>

</section>

<section class="bw-section">

<p class="bw-eyebrow">From the terminal</p>

<h2 class="bw-h2">A report you can read in ten seconds</h2>

<p class="bw-sub">What to fix, why, and how. Worst first.</p>

<div class="bw-term" role="img" aria-label="Terminal output of bulwarkctl ai scan: four problems, worst first, each with why it matters and the fix">
<div class="bw-term-bar"><span></span><span></span><span></span><em>bulwarkctl ai scan</em></div>
<pre><span class="t-dim">$</span> bulwarkctl ai scan
<b>Bulwark 0.12.0</b> <span class="t-dim">· AI coding agents · 1 project · 4 agent files checked</span>
<span></span>
<b>4 problems to fix</b>  <span class="t-crit">1 critical</span><span class="t-dim"> · </span><span class="t-high">3 high</span>
<span></span>
  <span class="t-crit">● Critical</span> <b>Project-supplied agent hooks run shell commands automatically</b>
             This project settings file defines hooks. Claude Code hooks run shell
             commands automatically on tool/session events — a project-supplied …
             <span class="t-ok">→</span> Remove the hooks from the repository's agent config.
             <span class="t-dim">in: ~/Projects/api/.claude/settings.json:1</span>
<span></span>
  <span class="t-high">● High    </span> <b>An MCP server runs an unpinned package from a registry</b>
             MCP server "fs" launches an unpinned package via npx.
             <span class="t-ok">→</span> Pin the MCP server to an exact version.
             <span class="t-dim">in: ~/Projects/api/.mcp.json:1</span>
  <span class="t-dim">…</span>
<span></span>
<span class="t-ok">→</span> 1 agent file holds leaked secrets Bulwark can remove — <b>bulwarkctl ai redact</b></pre>
</div>

<p class="bw-sub"><a href="/guide/agent-security">AI agent checks →</a> · <a href="/download">Install the CLI →</a></p>

</section>

<section class="bw-section">

<p class="bw-eyebrow">Remote machines</p>

<h2 class="bw-h2">Keep watch over your servers too</h2>

<p class="bw-sub">Over the SSH you already use. No agent, no server. Alerts on Telegram or e-mail.</p>

<p><img src="/diagrams/remote.svg" alt="Agentless remote monitoring: Bulwark signs in over your SSH, scans Linux servers, Macs, Windows PCs and WSL, and alerts on Telegram or e-mail" class="bw-diagram" /></p>

<div class="bw-gallery">
  <figure>
    <img src="/screenshots/machines.png" alt="Remote: each machine with its system, connection state and last scan" />
    <figcaption>Every machine at a glance.</figcaption>
  </figure>
  <figure>
    <img src="/screenshots/machine.png" alt="One remote machine: connection and last scan side by side, and its issues grouped by cause" />
    <figcaption>One machine, its issues grouped.</figcaption>
  </figure>
</div>

<p class="bw-sub"><a href="/guide/remote-monitoring">How remote monitoring works →</a></p>

</section>

<section class="bw-section">

<p class="bw-eyebrow">Under the hood</p>

<h2 class="bw-h2">One engine, nothing hidden</h2>

<p class="bw-sub">Every check is a small YAML rule you can read or write.</p>

<p><img src="/diagrams/architecture.svg" alt="Bulwark architecture: the desktop app and the CLI share one Rust engine; collectors, the AI-assistant scanner, the log scanner and ClamAV feed a rule engine of 100 YAML rules plus your own; findings are explained, scored honestly and stored locally; remote machines are scanned over SSH; alerts go to Telegram or e-mail" class="bw-diagram" /></p>

<p class="bw-sub"><a href="/guide/architecture">Read the architecture →</a> · <a href="https://github.com/vietanhdev/bulwark">Contribute a check →</a></p>

</section>

<section class="bw-section bw-how">

<p class="bw-eyebrow">How it works</p>

<h2 class="bw-h2">Scan, understand, fix</h2>

<div class="bw-steps">
  <div class="bw-step">
    <span class="bw-step-num">01</span>
    <h3>Scan</h3>
    <p>One click, or <code>bulwarkctl scan</code>.</p>
  </div>
  <div class="bw-step">
    <span class="bw-step-num">02</span>
    <h3>Understand</h3>
    <p>Each problem says why it matters, in a sentence.</p>
  </div>
  <div class="bw-step">
    <span class="bw-step-num">03</span>
    <h3>Fix</h3>
    <p>One click, or copyable steps.</p>
  </div>
</div>

</section>

<section class="bw-section">

<p class="bw-eyebrow">Make it yours</p>

<h2 class="bw-h2">Light, dark, and your colours</h2>

<p class="bw-sub">Eight accents, six sidebars, light or dark.</p>

<div class="bw-fan">
  <img src="/screenshots/hero-aubergine.png" alt="Bulwark with an orange accent on an aubergine sidebar" class="bw-fan-img bw-fan-4" />
  <img src="/screenshots/hero-green.png" alt="Bulwark with a green theme" class="bw-fan-img bw-fan-3" />
  <img src="/screenshots/hero-blue.png" alt="Bulwark with a blue theme" class="bw-fan-img bw-fan-2" />
  <img src="/screenshots/hero-graphite.png" alt="Bulwark with the default aqua on graphite theme" class="bw-fan-img bw-fan-1" />
</div>

</section>

<section class="bw-section">

<p class="bw-eyebrow">A closer look</p>

<h2 class="bw-h2">See it in action</h2>

<div class="bw-gallery">
  <figure>
    <img src="/screenshots/overview.png" alt="Home: the problems to fix, grouped by cause and ranked by severity" />
    <figcaption>What to fix, worst first.</figcaption>
  </figure>
  <figure>
    <img src="/screenshots/fix.png" alt="An opened problem: why it matters, a one-click fix, and details" />
    <figcaption>Why it matters, and the fix.</figcaption>
  </figure>
  <figure>
    <img src="/screenshots/overview-dark.png" alt="Home in dark mode" />
    <figcaption>Dark mode.</figcaption>
  </figure>
  <figure>
    <img src="/screenshots/antivirus.png" alt="Virus scan with ClamAV, showing a detected test file" />
    <figcaption>ClamAV virus scan.</figcaption>
  </figure>
</div>

</section>

<section class="bw-cta" aria-label="Get Bulwark">
  <h2>Find what attackers look for first.</h2>
  <p>Free, open source, fully local.</p>
  <div class="bw-cta-actions">
    <a class="bw-btn bw-btn-brand" href="/download">Download Bulwark</a>
    <a class="bw-btn bw-btn-alt" href="/checks/">Browse every check</a>
  </div>
</section>

</div>

<style>
.bw-diagram {
  display: block;
  width: 100%;
  max-width: 1152px;
  height: auto;
  margin: 8px auto 20px;
  border-radius: 18px;
  box-shadow: 0 8px 28px rgba(15, 30, 45, 0.10);
}
.bw-home {
  max-width: 1152px;
  margin: 0 auto;
  padding: 0 24px;
}
.bw-section {
  margin-top: 5rem;
}
.bw-eyebrow {
  text-align: center;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--vp-c-brand-1);
  margin: 0 0 0.5rem;
}
.bw-h2 {
  text-align: center;
  border: 0 !important;
  padding-top: 0;
  margin: 0;
  font-size: 2.25rem;
  line-height: 1.15;
  letter-spacing: -0.02em;
  font-weight: 700;
}
/* `.bw-home` raises specificity over VitePress's `.vp-doc p { margin: 16px 0 }`, which otherwise
   wins on load order and drops the auto margins — every intro paragraph sat left of centre. */
.bw-home .bw-sub {
  text-align: center;
  max-width: 44rem;
  margin: 0.9rem auto 0;
  color: var(--vp-c-text-2);
  line-height: 1.6;
}

/* Stats band — separates the demo video from the feature grid and adds instant credibility. */
.bw-stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1rem;
  margin-top: 4.5rem;
  padding: 1.75rem 1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 18px;
  background: color-mix(in srgb, var(--vp-c-bg-soft) 70%, transparent);
  backdrop-filter: blur(6px);
}
.bw-stat {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.15rem;
}
.bw-stat-num {
  font-size: 2.4rem;
  font-weight: 700;
  line-height: 1;
  letter-spacing: -0.03em;
  background: var(--vp-home-hero-name-background);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}
.bw-stat-label {
  font-size: 0.85rem;
  color: var(--vp-c-text-2);
  text-align: center;
}

/* Bento feature grid — varied widths with one accented hero tile, so it reads as a considered
   layout rather than a flat wall of equal boxes. */
.bw-bento {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 1.25rem;
  margin-top: 2.75rem;
}
.bw-card {
  display: flex;
  flex-direction: column;
  padding: 1.5rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 16px;
  background: var(--vp-c-bg-soft);
  transition:
    transform 0.2s ease,
    box-shadow 0.2s ease,
    border-color 0.2s ease;
}
.bw-card:hover {
  transform: translateY(-3px);
  border-color: color-mix(in srgb, var(--vp-c-brand-1) 45%, var(--vp-c-divider));
  box-shadow: 0 16px 36px -18px rgba(20, 40, 60, 0.3);
}
.dark .bw-card:hover {
  box-shadow: 0 16px 36px -14px rgba(0, 0, 0, 0.6);
}
.bw-card h3 {
  margin: 0 0 0.5rem;
  font-size: 1.15rem;
  font-weight: 650;
  line-height: 1.3;
}
.bw-card p {
  margin: 0;
  font-size: 0.92rem;
  line-height: 1.6;
  color: var(--vp-c-text-2);
}
.bw-card p + p {
  margin-top: 0.6rem;
}
.bw-card code {
  font-size: 0.82em;
  padding: 0.1em 0.4em;
  border-radius: 5px;
  background: var(--vp-c-default-soft);
}
.bw-card-icon {
  width: 42px;
  height: 42px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 11px;
  margin-bottom: 1rem;
  color: var(--vp-c-brand-1);
  background: var(--vp-c-brand-soft);
}
.bw-card-icon svg {
  width: 22px;
  height: 22px;
}
.bw-card-meta {
  margin-top: 0.9rem !important;
  font-size: 0.8rem !important;
  font-weight: 500;
  color: var(--vp-c-text-3) !important;
}

/* Hero tile: the AI-assistant differentiator, spanning three columns and set apart with a warm
   product-coloured wash and a small tag. */
.bw-card-hero {
  grid-column: 1;
  grid-row: span 2;
  position: relative;
  border-color: color-mix(in srgb, #1f8a8c 30%, var(--vp-c-divider));
  background:
    radial-gradient(90% 70% at 100% 0%, color-mix(in srgb, #1f8a8c 12%, transparent), transparent 70%),
    var(--vp-c-bg-soft);
}
.bw-card-hero .bw-card-icon {
  color: var(--vp-c-brand-1);
  background: color-mix(in srgb, #1f8a8c 15%, transparent);
}
.dark .bw-card-hero .bw-card-icon {
  color: var(--vp-c-brand-1);
}
.bw-card-hero h3 {
  font-size: 1.4rem;
}
.bw-card-hero p {
  font-size: 0.98rem;
}
.bw-card-tag {
  align-self: flex-start;
  font-size: 0.72rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--vp-c-brand-1);
  background: color-mix(in srgb, #1f8a8c 14%, transparent);
  padding: 0.28rem 0.7rem;
  border-radius: 999px;
  margin-bottom: 1rem;
}
.dark .bw-card-tag {
  color: var(--vp-c-brand-1);
}
/* The two stacked cards after the hero fall into the right column beside the tall hero tile;
   the remaining four flow as two balanced rows underneath. Auto-placement handles the rest. */

/* How it works — a genuine three-step sequence, so the numbering carries real order. */
.bw-steps {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1.5rem;
  margin-top: 2.75rem;
  counter-reset: step;
}
.bw-step {
  position: relative;
  padding: 1.75rem 1.5rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 16px;
  background: var(--vp-c-bg-soft);
}
.bw-step-num {
  font-family: "IBM Plex Mono", ui-monospace, monospace;
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--vp-c-brand-1);
}
.bw-step h3 {
  margin: 0.6rem 0 0.5rem;
  font-size: 1.2rem;
  font-weight: 650;
}
.bw-step p {
  margin: 0;
  font-size: 0.92rem;
  line-height: 1.6;
  color: var(--vp-c-text-2);
}
.bw-how .bw-steps { position: relative; }
.bw-step code {
  font-size: 0.82em;
  padding: 0.1em 0.4em;
  border-radius: 5px;
  background: var(--vp-c-default-soft);
}

/* Colours fan (unchanged behaviour, restyled container). */
.bw-fan {
  position: relative;
  height: 460px;
  margin: 3rem auto 0;
  max-width: 900px;
}
.bw-fan-img {
  position: absolute;
  top: 0;
  left: 50%;
  width: 660px;
  max-width: 90%;
  border-radius: 14px;
  box-shadow: 0 20px 50px -12px rgba(0, 0, 0, 0.45);
  transition: transform 0.35s ease;
}
.bw-fan-1 { transform: translateX(-50%) rotate(0deg); z-index: 4; }
.bw-fan-2 { transform: translateX(-64%) rotate(-6deg) translateY(18px); z-index: 3; }
.bw-fan-3 { transform: translateX(-36%) rotate(6deg) translateY(18px); z-index: 2; }
.bw-fan-4 { transform: translateX(-50%) rotate(0deg) translateY(36px) scale(0.97); z-index: 1; opacity: 0.9; }
.bw-fan:hover .bw-fan-2 { transform: translateX(-78%) rotate(-9deg) translateY(10px); }
.bw-fan:hover .bw-fan-3 { transform: translateX(-22%) rotate(9deg) translateY(10px); }

.bw-gallery {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 1.75rem;
  margin-top: 2.75rem;
}
.bw-gallery img {
  width: 100%;
  border-radius: 12px;
  box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.3);
}
.bw-gallery figcaption {
  margin-top: 0.7rem;
  font-size: 0.875rem;
  color: var(--vp-c-text-2);
}

/* Closing CTA band. */
.bw-cta {
  max-width: 1152px;
  margin: 7rem auto 2rem;
  padding: 4rem 2rem;
  text-align: center;
  border-radius: 24px;
  border: 1px solid color-mix(in srgb, var(--vp-c-brand-1) 25%, var(--vp-c-divider));
  background:
    radial-gradient(70% 120% at 50% 0%, color-mix(in srgb, var(--vp-c-brand-1) 14%, transparent), transparent 70%),
    var(--vp-c-bg-soft);
}
.bw-cta h2 {
  border: 0 !important;
  padding-top: 0;
  margin: 0 auto;
  max-width: 20ch;
  font-size: 2rem;
  line-height: 1.15;
  letter-spacing: -0.02em;
  font-weight: 700;
}
.bw-cta p {
  margin: 0.75rem auto 0;
  color: var(--vp-c-text-2);
}
.bw-cta-actions {
  display: flex;
  justify-content: center;
  gap: 0.75rem;
  margin-top: 1.75rem;
  flex-wrap: wrap;
}
/* These are <a> tags rendered inside .vp-doc, whose `a` rule (brand colour + underline) would
   otherwise win on specificity — hence the explicit `a.bw-btn` selectors and !important on the
   text colour/decoration so the label is legible and un-underlined. */
.bw-cta a.bw-btn {
  display: inline-block;
  padding: 0.7rem 1.6rem;
  border-radius: 999px;
  font-size: 0.95rem;
  font-weight: 600;
  text-decoration: none !important;
  transition: transform 0.15s ease, box-shadow 0.15s ease, opacity 0.15s ease;
}
.bw-cta a.bw-btn:hover { transform: translateY(-1px); }
.bw-cta a.bw-btn-brand {
  color: #ffffff !important;
  background: var(--vp-button-brand-bg);
  box-shadow: 0 8px 20px -8px color-mix(in srgb, var(--vp-button-brand-bg) 70%, transparent);
}
.bw-cta a.bw-btn-brand:hover {
  background: var(--vp-button-brand-hover-bg);
  box-shadow: 0 10px 24px -8px color-mix(in srgb, var(--vp-button-brand-bg) 75%, transparent);
}
.bw-cta a.bw-btn-alt {
  color: var(--vp-c-text-1) !important;
  border: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg);
}
.bw-cta a.bw-btn-alt:hover { border-color: var(--vp-c-brand-1); }

/* The CLI sample: a terminal window in the CLI's own colours, dark in both themes. */
.bw-term {
  max-width: 50rem;
  margin: 2rem auto 0;
  border-radius: 14px;
  overflow: hidden;
  background: #0f1720;
  border: 1px solid #253241;
  box-shadow: 0 18px 48px -18px rgba(10, 20, 30, 0.45);
}
.bw-term-bar {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 10px 14px;
  background: #18222e;
  border-bottom: 1px solid #253241;
}
.bw-term-bar span { width: 11px; height: 11px; border-radius: 50%; background: #3a4757; }
.bw-term-bar span:nth-child(1) { background: #ff5f57; }
.bw-term-bar span:nth-child(2) { background: #febc2e; }
.bw-term-bar span:nth-child(3) { background: #28c840; }
.bw-term-bar em {
  margin-left: 10px;
  font-style: normal;
  font-size: 0.78rem;
  color: #8b98a8;
  font-family: var(--vp-font-family-mono);
}
.bw-term pre {
  margin: 0;
  padding: 1.1rem 1.3rem 1.3rem;
  overflow-x: auto;
  font-family: var(--vp-font-family-mono);
  font-size: 0.8rem;
  line-height: 1.6;
  color: #d7dee7;
  background: transparent;
}
.bw-term b { color: #f3f6fa; font-weight: 700; }
.bw-term .t-dim { color: #7c8a9b; }
.bw-term .t-crit { color: #ff6b6b; font-weight: 700; }
.bw-term .t-high { color: #ff9a6b; }
.bw-term .t-ok { color: #4fd18b; }

/* Tablet: collapse the bento and grids to two columns. */
@media (max-width: 900px) {
  .bw-bento { grid-template-columns: repeat(2, 1fr); }
  .bw-card,
  .bw-card-hero,
  .bw-card-hero + .bw-card,
  .bw-card-hero + .bw-card + .bw-card {
    grid-column: span 1;
  }
  .bw-card-hero { grid-row: auto; grid-column: 1 / -1; }
  .bw-steps { grid-template-columns: 1fr; }
  .bw-gallery { grid-template-columns: 1fr; }
}

/* Phone: single column throughout. */
@media (max-width: 640px) {
  .bw-section { margin-top: 4rem; }
  .bw-h2 { font-size: 1.85rem; }
  .bw-stats { grid-template-columns: repeat(2, 1fr); gap: 1.25rem 1rem; }
  .bw-bento { grid-template-columns: 1fr; }
  .bw-fan { height: 300px; }
  .bw-fan-2, .bw-fan-3, .bw-fan-4 { display: none; }
  .bw-cta { padding: 3rem 1.5rem; }
  .bw-cta h2 { font-size: 1.6rem; }
  .bw-term pre { font-size: 0.66rem; padding: 0.9rem 1rem 1rem; }
}
</style>
