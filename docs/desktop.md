---
title: The Bulwark desktop app
description: The Bulwark desktop app for Linux, macOS and Windows. Scan with one click, read each problem in plain language, fix it with one click, and keep watch over your other machines.
---

# The desktop app

Everything the CLI checks, with one click to scan and one click to fix. Linux, macOS and Windows.

![Bulwark's home screen: problems grouped by cause, worst first, each with its one-line fix](/screenshots/overview.png)

<div class="feature-grid">

<div>

### Plain language, worst first

Each problem says what it is, why it matters and how to fix it. Open one for the details and the exact
place it was found.

</div>

<div>

### One-click fixes

Safe fixes are previewed first and backed up always. Risky ones, like turning off SSH passwords, stay
a deliberate choice.

</div>

<div>

### Keeps watch

Rescans in the background, notices when a watched file changes, and tells you only about what is new.

</div>

<div>

### Your other machines

Servers, Macs and Windows PCs over the SSH you already use, with alerts on Telegram or e-mail.
[How it works →](/guide/remote-monitoring)

</div>

</div>

![All checks: every rule Bulwark runs, searchable, with your own checks beside them](/screenshots/rules.png)

![The Remote page: each machine's system, connection, open issues and next scan](/screenshots/machines.png)

The desktop app includes the command line as `bulwark`, so `bulwark scan` and
`bulwark agent install` work without installing anything else.

[Download the desktop app →](/download)

<style>
.feature-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0 1.5rem;
  margin: 1.5rem 0;
}
.feature-grid h3 { margin-top: 0.5rem; }
@media (max-width: 640px) {
  .feature-grid { grid-template-columns: 1fr; }
}
</style>
