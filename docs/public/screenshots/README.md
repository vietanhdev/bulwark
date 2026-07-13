- `overview.png` — the Overview: the host's verdict, its hardening index, the four scan-type
  tiles (Compliance, Antivirus, Agent Security, File integrity), and the findings list grouped
  by category
- `agent-security.png` — the Agent Security view: secrets found in AI assistant context, and
  dangerous agent configuration, each with its CVE / ATT&CK reference
- `antivirus.png` — the Antivirus view: ClamAV signature status and real-time folder watching
- `compliance.png` — the Compliance view: every configuration finding on the host, grouped by
  subsystem, each with why it matters and the exact command to fix it
- `rules.png` — the Rules view: the full rule pack, searchable and filterable by severity, with
  the CIS / MITRE ATT&CK framework coverage in a second tab

All five are 2560x1600 (a 2x capture of 1280x800), which is exactly the app's default window
size and aspect ratio — see `apps/bulwark-app/src-tauri/tauri.conf.json`. Keep it that way when
recapturing: a screenshot at some other ratio is a picture of a window nobody actually opens.

## How these were captured

This project's sandboxed dev environment has no working screen-capture tool for the actual
Tauri window (`gnome-screenshot`/`import`/`xwd` all fail on an X11/pixman rendering bug —
`GdkPixbuf-CRITICAL: assertion 'GDK_IS_PIXBUF (pixbuf)' failed`), so these weren't taken by
screenshotting the running desktop app directly. Instead, the real frontend (the same
`apps/bulwark-app/src/` React code, unmodified) was opened in a plain Playwright-controlled
browser with every `@tauri-apps/api/*` import swapped for a fixture-backed mock — see
`apps/bulwark-app/src/mocks/tauri/README.md` for exactly how. The rule content shown is 100%
real (parsed from the actual `rules/**/*.yaml` files, not hand-written); only which findings
are "open" and what live values they interpolate is representative fixture data, since a real
scan of whatever machine happens to build this project isn't representative of a typical user's
host.

There is a second, harder reason the Agent Security shot in particular must come from fixtures
rather than a real scan: a genuine agent scan surfaces the developer's *actual* leaked API keys,
real project paths, and real transcript locations. Publishing that to a README would be precisely
the leak this feature exists to prevent. The fixtures are inert — fake paths, masked keys.

To recapture (e.g. after a UI change), use the committed script — it drives the mock app in a
headless browser and writes all five images at the right size:

```bash
cd apps/bulwark-app
npm install --prefix /tmp/pw playwright && npx playwright install chromium
VITE_MOCK_TAURI=true npx vite --port 4173 --strictPort &
NODE_PATH=/tmp/pw/node_modules node scripts/capture-screenshots.mjs
```

then drive it with Playwright at a 1280x800 viewport and `deviceScaleFactor: 2`.

Two things are worth doing rather than screenshotting whatever is on screen at the time:

- **Wait for the status shield's colour transition to settle.** It animates from its neutral
  "not scanned yet" grey to the verdict colour on load. Chromium reports an interpolated
  `oklab()` while a colour transition is mid-flight and the authored `oklch()` once it lands,
  so poll for the latter instead of guessing a sleep — a fixed wait caught it grey more than
  once.
- **Actually run the virus scan** for `antivirus.png` rather than capturing the idle page. The
  mock streams a real EICAR detection, and a screenshot of the feature doing its job is worth
  more than one of a button.

A real screenshot of the packaged app (`cargo tauri build`, then screenshot on a normal Linux
desktop) is equally valid and does not need to go through the mock — the mock exists to unblock
this specific environment, not because it is the preferred method in general.
