Drop real screenshots here with these exact filenames — README.md and the docs site already
link to them at these paths, so nothing else needs editing once they exist:

- `dashboard.png` — the Dashboard view after a scan (status hero + findings list)
- `antivirus.png` — the Antivirus view, ideally mid-scan showing live progress
- `compliance.png` — the Compliance view showing the hardening index

Captured from a real Linux desktop session (`cargo tauri dev` or a packaged build) — this
directory is empty because the sandboxed environment this project has been developed in has no
working screen-capture tooling (`gnome-screenshot`/`import`/`xwd` all fail on an X11/pixman
rendering bug). 1280px-wide PNGs or similar are a reasonable size target.
