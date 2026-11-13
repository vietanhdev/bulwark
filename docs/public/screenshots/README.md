- `first-run.png` — Scan before the first scan: the four numbered steps
- `overview.png` — Scan: the problems to fix, grouped by cause (secrets, supply chain, exposed
  services, AI agents, SSH, …) and ranked by severity
- `overview-dark.png` — Scan in dark mode
- `fix.png` — Scan with one problem opened: why it matters, the one-click fix, and Details
- `fix-review.png` — the Fix now preview: proposed changes, with Apply and Cancel
- `secrets-inventory.png`, `secrets-inventory-light.png` — Secrets: one row per stored credential
- `secrets-market.png` — Secrets → Add: the supported tools and whether each was found
- `tools.png`, `tools-light.png` — Tools: the six tools on one page
- `compliance.png` — Tools → Configuration: configuration findings grouped the same way
- `antivirus.png` — Tools → Malware scan: ClamAV signature status, folder watching, and a finished scan
- `rules.png` — Tools → Rule catalog: the full rule pack, searchable and filterable by severity
- `machines.png` — Tools → Remote hosts: every monitored machine with its system, connection and
  last scan
- `machine.png` — one remote machine opened: connection and last scan side by side, and its issues
  grouped the same way Scan groups this computer's
- `settings.png` — Settings: theme, accent colour and window chrome, monitoring, AI assistant checks
- `hero-<chrome>.png` — Scan in four window-chrome/accent pairings for the website's theme fan;
  `hero-graphite.png` is the default (aqua on graphite)

All of them are 1800x1320 (a 2x capture of 900x660), which is exactly the app's default window
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

There is a second, harder reason the shots that show agent findings must come from fixtures
rather than a real scan: a genuine agent scan surfaces the developer's *actual* leaked API keys,
real project paths, and real transcript locations. Publishing that to a README would be precisely
the leak this feature exists to prevent. The fixtures are inert — fake paths, masked keys.

To recapture (e.g. after a UI change), use the committed script — it drives the mock app in a
headless browser and writes every image above at the right size:

```bash
cd apps/bulwark-app
npm install --prefix /tmp/pw playwright && npx playwright install chromium
VITE_MOCK_TAURI=true npx vite --port 4173 --strictPort &
NODE_PATH=/tmp/pw/node_modules node scripts/capture-screenshots.mjs
```

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
