---
layout: home

hero:
  name: Bulwark
  text: Security & antivirus for your Linux computer
  tagline: >-
    For everyone on Ubuntu, Fedora, Debian, Arch and beyond — and especially developers and AI
    users. Bulwark checks your machine's real configuration, scans for viruses, watches your AI
    coding assistants, and explains every finding in plain language with a one-click fix.
  image:
    src: /hero-illustration.svg
    alt: Bulwark's shield mark, with a pulsing ring animation and category check nodes
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

features:
  - title: Plain-language, not jargon
    details: >-
      "Your computer needs a little attention" — not a wall of CVE IDs. Every issue is sorted into
      Important / Should fix / Worth doing, names the exact file or setting, and comes with a
      concrete fix. A Safety score tells you where you stand at a glance.
  - title: One-click fixes
    details: >-
      Bulwark doesn't just find problems — it fixes the safe ones. Tighten ~/.ssh permissions,
      harden sshd_config, add a passphrase to every unprotected SSH key, redact leaked secrets — all
      dry-run first, reversible, with a backup. `bulwarkctl fix` on the CLI, buttons in the app.
  - title: Real virus scanning
    details: >-
      Full ClamAV integration with live per-file progress, engine/database version and age, and a
      distro-aware install command when ClamAV isn't present — on Ubuntu, Fedora, Debian, Arch and
      more. Signature-based malware detection, built in.
  - title: AI coding-assistant security
    details: >-
      Scans Claude Code, Cursor, Copilot, Codex and Gemini for secrets leaked into transcripts and
      memory, and for agent config a prompt injection could turn into code execution — malicious MCP
      servers, auto-approve "YOLO mode", the Rules File Backdoor. 20 checks mapped to real CVEs.
  - title: Scan the whole fleet over SSH
    details: >-
      `bulwarkctl scan --ssh user@host` checks another machine over your existing SSH — reusing your
      keys, agent and jump hosts. It runs an installed Bulwark or pushes itself, then brings the
      results home. One laptop, every server.
  - title: Native CLI and desktop app
    details: >-
      One Rust engine, two front-doors. Scan from a terminal on a headless box, or run the desktop
      app — both share the same rule pack and local history. Light/dark, with an accent and sidebar
      colour you choose, so it looks like it belongs on your desktop.
  - title: Continuous, and fully local
    details: >-
      A background loop re-scans on a schedule and tells you only when something genuinely new shows
      up. No network calls from the engine, ever — your scan history lives in a local SQLite database
      under ~/.local/share/bulwark. Nothing leaves the machine.
---

<div class="bw-showcase">

## One app, your colours

<p class="bw-sub">Light or dark, with an accent and sidebar colour you pick. Bulwark is built to look like part of the desktop it protects — not a visitor.</p>

<div class="bw-fan">
  <img src="/screenshots/hero-green.png" alt="Bulwark with a green theme" class="bw-fan-img bw-fan-4" />
  <img src="/screenshots/hero-blue.png" alt="Bulwark with a blue theme" class="bw-fan-img bw-fan-3" />
  <img src="/screenshots/hero-teal.png" alt="Bulwark with a teal theme" class="bw-fan-img bw-fan-2" />
  <img src="/screenshots/hero-aubergine.png" alt="Bulwark with the default aubergine theme" class="bw-fan-img bw-fan-1" />
</div>

## See it in action

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

</div>

<style>
.bw-showcase {
  max-width: 1152px;
  margin: 4rem auto 0;
  padding: 0 24px;
}
.bw-showcase h2 {
  text-align: center;
  border: 0;
  font-size: 2rem;
  margin-top: 4rem;
  padding-top: 0;
}
.bw-sub {
  text-align: center;
  max-width: 42rem;
  margin: 0.5rem auto 0;
  color: var(--vp-c-text-2);
}
.bw-fan {
  position: relative;
  height: 460px;
  margin: 2.5rem auto 0;
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
  gap: 1.5rem;
  margin-top: 2.5rem;
}
.bw-gallery img {
  width: 100%;
  border-radius: 12px;
  box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.3);
}
.bw-gallery figcaption {
  margin-top: 0.6rem;
  font-size: 0.875rem;
  color: var(--vp-c-text-2);
}
@media (max-width: 720px) {
  .bw-fan { height: 320px; }
  .bw-fan-img { width: 100%; }
  .bw-fan-2, .bw-fan-3, .bw-fan-4 { display: none; }
  .bw-gallery { grid-template-columns: 1fr; }
}
</style>
