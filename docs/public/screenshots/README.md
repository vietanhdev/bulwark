- `dashboard.png` — the Dashboard view after a scan (status hero + findings list)
- `antivirus.png` — the Antivirus view, showing a completed scan with a detected threat
- `compliance.png` — the Compliance view showing the hardening index

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

To recapture (e.g. after a UI change): `cd apps/bulwark-app && VITE_MOCK_TAURI=true npm run dev`,
open the printed localhost URL in a browser, navigate to each view, and screenshot at whatever
size/tooling is available in that environment. A real screenshot of the actual packaged app
(`cargo tauri build` + screenshot on a normal Linux desktop) would be equally valid and is not
required to go through the mock — the mock exists to unblock this specific environment, not
because it's the preferred method in general.
