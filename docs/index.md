---
layout: home
description: Scan your dev machine for risky AI-agent settings, MCP servers, leaked keys, plain-text credentials and unsafe package-manager configs — in seconds. Nothing leaves your computer.
hero:
  name: Bulwark
  text: Spot risky setups.<br>Fix them safely.
  tagline: Scan your dev machine for risky AI-agent settings, MCP servers, leaked keys, plain-text credentials and unsafe package-manager configs — in seconds.
  actions:
    - theme: brand
      text: Get started
      link: /guide/get-started
    - theme: alt
      text: See the app
      link: /desktop
    - theme: alt
      text: Downloads
      link: /download
---

<div class="workbench-home">

<section>

## Three steps to a safer dev machine

<div class="workflow-grid">
<article><h3>1. Scan</h3><p>One click checks your AI agents, MCP servers, keys, credentials and package-manager settings. Each problem is explained in plain words. A check that could not run is shown as skipped, never as passed.</p><a href="/guide/get-started">Run your first scan</a></article>
<article><h3>2. Fix</h3><p><strong>Fix now</strong> shows every change before anything is written. You confirm, Bulwark applies, and a new scan proves it worked. Changes that could lock you out are never applied in bulk.</p><a href="/guide/remediation">How fixing works</a></article>
<article><h3>3. Know your secrets</h3><p><strong>Secrets</strong> lists which tools hold your credentials (AWS, Docker, Git, GitHub CLI, npm, PyPI, Kubernetes) and whether each sits in a keychain or in plain text. Names only, never values.</p><a href="/guide/secrets">See your inventory</a></article>
</div>

</section>
<section class="review-feature">

## Review first. Apply deliberately.

**Fix now** sits beside **Scan now**. It opens a preview listing every file and setting it would change. Nothing is written until you confirm, and some fixes ask for your administrator password. SSH sign-in changes that could lock you out are left for you to review one at a time.

![From scan to fix in five steps: scan, understand, preview every change, apply only after you confirm, then check again. Results stay on this computer, secrets are shown masked, a skipped check never counts as passed, and risky SSH changes are reviewed one at a time.](/diagrams/scan-to-fix.svg)

![Synthetic safe-fix review opened from Scan; proposed changes require confirmation](/screenshots/fix-review.png)

[Read the fix workflow](/guide/remediation)

</section>
<section>

## More than developer tools

Beyond developer tools, the same scan checks SSH, file permissions, startup programs, exposed services and operating-system settings. **Tools** adds file-change tracking, optional ClamAV malware scans and checks of other machines over SSH.

Everything runs on your computer. Bulwark only connects out when you set up remote machines or alerts yourself.

![Where Bulwark fits: developer tools and AI agents are its main focus; it covers the operating system; it partly covers malware and live attacks (pair with antivirus or EDR) and your code's dependencies (pair with npm audit, Snyk, Socket or Dependabot).](/diagrams/where-it-fits.svg)

[Browse the rule catalog](/checks/) · [Use the CLI](/cli) · [Architecture and boundaries](/guide/architecture)

</section>
<section>

## Small and calm on the desktop

A small window with light and dark themes, full keyboard support and no distracting animation.

![Secrets in light mode: one inventory of the credentials each tool holds, with sample data](/screenshots/secrets-inventory-light.png)

</section>
</div>

<style>
.workbench-home { max-width:1040px; margin:0 auto; padding:0 24px 64px; }
.workbench-home section { margin-top:3rem; }
.workbench-home h2 { border:0; font-size:1.7rem; line-height:1.25; letter-spacing:-.025em; }
.workbench-home p { max-width:76ch; line-height:1.75; color:var(--vp-c-text-2); }
.workbench-home a { color:var(--vp-c-brand-1); text-decoration:underline; text-underline-offset:3px; }
.workbench-home img { margin:1.5rem 0; border:1px solid var(--vp-c-divider); border-radius:9px; width:100%; }
.workflow-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:1.6rem; }
.workflow-grid h3 { font-size:1.2rem; margin-bottom:.5rem; }
.workflow-grid article { border-top:1px solid var(--vp-c-divider); padding-top:1rem; }
@media(max-width:720px) { .workflow-grid { grid-template-columns:1fr; } .workbench-home h2 { font-size:1.5rem; } }
</style>
