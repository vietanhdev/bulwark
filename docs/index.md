---
layout: home

hero:
  name: Bulwark
  text: Security & antivirus for your Linux computer
  tagline: >-
    Checks your machine's real configuration, scans for viruses, and watches your AI coding
    assistants — then explains every finding in plain language, with a one-click fix.
  actions:
    - theme: brand
      text: Download
      link: /download
    - theme: alt
      text: Antivirus for Linux
      link: /articles/linux-antivirus-ubuntu-fedora
    - theme: alt
      text: View on GitHub
      link: https://github.com/vietanhdev/bulwark
---

<div class="bw-home">

<section class="bw-stats" aria-label="Bulwark at a glance">
  <div class="bw-stat">
    <span class="bw-stat-num">85</span>
    <span class="bw-stat-label">built-in checks</span>
  </div>
  <div class="bw-stat">
    <span class="bw-stat-num">11</span>
    <span class="bw-stat-label">security categories</span>
  </div>
  <div class="bw-stat">
    <span class="bw-stat-num">5</span>
    <span class="bw-stat-label">AI assistants watched</span>
  </div>
  <div class="bw-stat">
    <span class="bw-stat-num">0</span>
    <span class="bw-stat-label">network calls</span>
  </div>
</section>

<section class="bw-section">

<p class="bw-eyebrow">What Bulwark does</p>

<h2 class="bw-h2">One scan, your whole machine</h2>

<p class="bw-sub">From SSH keys and sudoers to leaked API keys in your AI assistant's memory — every check runs locally and explains itself in plain language.</p>

<div class="bw-bento">
  <article class="bw-card bw-card-hero">
    <div class="bw-card-tag">What sets Bulwark apart</div>
    <div class="bw-card-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>
    </div>
    <h3>AI coding-assistant security</h3>
    <p>Scans Claude Code, Cursor, Copilot, Codex and Gemini for secrets leaked into transcripts and memory — and for agent config a prompt injection could turn into code execution: malicious MCP servers, auto-approve "YOLO mode", the Rules File Backdoor.</p>
    <p class="bw-card-meta">20 checks mapped to real CVEs · opt-in redaction</p>
  </article>

  <article class="bw-card">
    <div class="bw-card-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 00-5.4 5.4l-6 6V21h3.3l6-6a4 4 0 005.4-5.4l-2.3 2.3-2.2-.4-.4-2.2 2.3-2.3z"/></svg>
    </div>
    <h3>One-click fixes</h3>
    <p>Tighten <code>~/.ssh</code> permissions, harden <code>sshd_config</code>, add a passphrase to every unprotected key, redact leaked secrets — dry-run first, reversible, with a backup.</p>
  </article>

  <article class="bw-card">
    <div class="bw-card-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/></svg>
    </div>
    <h3>Real virus scanning</h3>
    <p>Full ClamAV integration with live per-file progress, engine and database age, and a distro-aware install command when it's missing.</p>
  </article>

  <article class="bw-card">
    <div class="bw-card-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 01-2 2H8l-4 4V5a2 2 0 012-2h13a2 2 0 012 2z"/><path d="M8 9h8M8 13h5"/></svg>
    </div>
    <h3>Plain-language, not jargon</h3>
    <p>"Your computer needs a little attention" — not a wall of CVE IDs. Every issue is ranked and names the exact file to change, with a Safety score for the whole machine.</p>
  </article>

  <article class="bw-card">
    <div class="bw-card-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12a8 8 0 0114-5.3L20 8M20 4v4h-4"/><path d="M20 12a8 8 0 01-14 5.3L4 16M4 20v-4h4"/></svg>
    </div>
    <h3>Continuous, fully local</h3>
    <p>A background loop re-scans on a schedule and speaks up only when something new appears. No network calls, ever — your history lives in a local database.</p>
  </article>

  <article class="bw-card">
    <div class="bw-card-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>
    </div>
    <h3>Scan the fleet over SSH</h3>
    <p><code>bulwarkctl scan --ssh user@host</code> checks another machine over your existing SSH — keys, agent and jump hosts included. One laptop, every server.</p>
  </article>

  <article class="bw-card">
    <div class="bw-card-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/></svg>
    </div>
    <h3>Native CLI and desktop app</h3>
    <p>One Rust engine, two front-doors: a terminal on a headless box, or a themable desktop app. Same rule pack, same local history.</p>
  </article>
</div>

</section>

<section class="bw-section bw-how">

<p class="bw-eyebrow">How it works</p>

<h2 class="bw-h2">Scan, understand, fix</h2>

<div class="bw-steps">
  <div class="bw-step">
    <span class="bw-step-num">01</span>
    <h3>Scan</h3>
    <p>One click runs every check you enable — system configuration, viruses, and your AI coding assistants. No account, no setup.</p>
  </div>
  <div class="bw-step">
    <span class="bw-step-num">02</span>
    <h3>Understand</h3>
    <p>Findings are sorted Important → FYI, each named to the exact file or setting, with a Safety score that tells you where the whole machine stands.</p>
  </div>
  <div class="bw-step">
    <span class="bw-step-num">03</span>
    <h3>Fix</h3>
    <p>Apply the safe fixes with a dry-run and a backup, or copy the exact command. Every change is reversible by design.</p>
  </div>
</div>

</section>

<section class="bw-section">

<p class="bw-eyebrow">Make it yours</p>

<h2 class="bw-h2">One app, your colours</h2>

<p class="bw-sub">Light or dark, with an accent and sidebar colour you pick. Bulwark is built to look like part of the desktop it protects — not a visitor.</p>

<div class="bw-fan">
  <img src="/screenshots/hero-green.png" alt="Bulwark with a green theme" class="bw-fan-img bw-fan-4" />
  <img src="/screenshots/hero-blue.png" alt="Bulwark with a blue theme" class="bw-fan-img bw-fan-3" />
  <img src="/screenshots/hero-teal.png" alt="Bulwark with a teal theme" class="bw-fan-img bw-fan-2" />
  <img src="/screenshots/hero-aubergine.png" alt="Bulwark with the default aubergine theme" class="bw-fan-img bw-fan-1" />
</div>

</section>

<section class="bw-section">

<p class="bw-eyebrow">A closer look</p>

<h2 class="bw-h2">See it in action</h2>

<div class="bw-gallery">
  <figure>
    <img src="/screenshots/overview.png" alt="Home — a plain-language look at how safe this computer is" />
    <figcaption>Home — your Safety score and what to fix first, in plain language.</figcaption>
  </figure>
  <figure>
    <img src="/screenshots/agent-security.png" alt="AI assistants — secrets and risky agent config" />
    <figcaption>AI assistants — leaked secrets and risky agent configuration, with redaction.</figcaption>
  </figure>
  <figure>
    <img src="/screenshots/compliance.png" alt="Checkups — configuration findings grouped by subsystem" />
    <figcaption>Checkups — configuration findings by subsystem, each with the exact fix.</figcaption>
  </figure>
  <figure>
    <img src="/screenshots/settings.png" alt="Settings — theme, accent and sidebar colour pickers" />
    <figcaption>Settings — theme, accent and sidebar colour, monitoring cadence, SSH tools.</figcaption>
  </figure>
</div>

</section>

<section class="bw-cta" aria-label="Get Bulwark">
  <h2>Harden your Linux machine in one scan.</h2>
  <p>Free, open source, and everything stays on your computer.</p>
  <div class="bw-cta-actions">
    <a class="bw-btn bw-btn-brand" href="/download">Download Bulwark</a>
    <a class="bw-btn bw-btn-alt" href="https://github.com/vietanhdev/bulwark">View on GitHub</a>
  </div>
</section>

</div>

<style>
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
.bw-sub {
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
  border-color: color-mix(in srgb, #db4f1c 30%, var(--vp-c-divider));
  background:
    radial-gradient(90% 70% at 100% 0%, color-mix(in srgb, #db4f1c 12%, transparent), transparent 70%),
    var(--vp-c-bg-soft);
}
.bw-card-hero .bw-card-icon {
  color: #c2410c;
  background: color-mix(in srgb, #db4f1c 15%, transparent);
}
.dark .bw-card-hero .bw-card-icon {
  color: #fb923c;
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
  color: #c2410c;
  background: color-mix(in srgb, #db4f1c 14%, transparent);
  padding: 0.28rem 0.7rem;
  border-radius: 999px;
  margin-bottom: 1rem;
}
.dark .bw-card-tag {
  color: #fdba74;
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
}
</style>
