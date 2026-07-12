---
layout: home

hero:
  name: Bulwark
  text: Secure your Linux desktop or server
  tagline: >-
    Built for everyone running Linux — and especially for developers and AI users navigating
    an increasingly AI-driven world. Bulwark checks your machine's real configuration, explains
    every finding in plain language, and keeps watching after the scan ends.
  image:
    src: /hero-illustration.svg
    alt: Bulwark's shield mark, with a pulsing ring animation and category check nodes
  actions:
    - theme: brand
      text: Download
      link: /download
    - theme: alt
      text: Read the architecture
      link: /guide/architecture
    - theme: alt
      text: View on GitHub
      link: https://github.com/vietanhdev/bulwark

features:
  - title: Native CLI and desktop GUI
    details: >-
      One Rust engine (bulwark-core), two thin front-doors. Scan from a terminal over SSH
      on a headless box, or run the Tauri GUI on your desktop — both share the same rule
      pack and the same local scan history.
  - title: Declarative, extensible rules
    details: >-
      59 rules across 11 categories — SSH hardening, persistence, sudoers, kernel/sysctl
      hardening, file permissions, logging, rootkit indicators — each a plain YAML file
      with a condition, a plain-language explanation, and a fix. No Rust required to add one.
  - title: Explains findings, doesn't just list them
    details: >-
      Every finding names the exact file, directive, or process involved, in plain language,
      with a concrete fix — not a bare rule ID you have to go look up.
  - title: Real ClamAV integration, not a reimplementation
    details: >-
      Streams live per-file scan progress, reports the installed engine/database version and
      age, and shows a distro-aware install command when ClamAV isn't present at all.
  - title: Continuous, not just on-demand
    details: >-
      A background monitoring loop re-scans on a schedule and reconciles findings across
      runs, so switching tabs or closing the window (to the system tray) never loses
      in-progress state.
  - title: Fully local, no telemetry
    details: >-
      No network calls from bulwark-core, ever. Scan history lives in a local SQLite
      database under ~/.local/share/bulwark — nothing leaves the machine.
---

## Screenshots

<div class="screenshot-gallery">

![Overview — the host's verdict, its hardening index, and every finding with a copyable fix](/screenshots/overview.png)

![Antivirus — ClamAV signature scanning and real-time folder watching](/screenshots/antivirus.png)

![Compliance — Bulwark's rules mapped to CIS Benchmarks and MITRE ATT&CK](/screenshots/compliance.png)

![Rules — the full rule pack, searchable and filterable by severity](/screenshots/rules.png)

</div>
