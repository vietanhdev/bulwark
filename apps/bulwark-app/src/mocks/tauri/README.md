# Tauri API mocks (screenshot capture only)

This directory exists for exactly one purpose: rendering the real app UI in a plain browser
(via Playwright) to capture screenshots for `docs/public/screenshots/`, since this project's
sandboxed dev environment has no working screen-capture tool for the actual Tauri window
(`gnome-screenshot`/`import`/`xwd` all fail on an X11/pixman rendering bug — see
`../../../../docs/public/screenshots/README.md`).

It is **never active** in a real `cargo tauri dev`/build — `vite.config.ts` only aliases
`@tauri-apps/api/*` to these mocks when `VITE_MOCK_TAURI=true` is set, which nothing in the
normal dev/build/CI path sets.

## Usage

```bash
VITE_MOCK_TAURI=true npm run dev
```

Then open the app in a real browser at the printed localhost URL. Every `invoke()` the frontend
makes is served from `fixtures/` — real rule content (parsed from the actual `rules/**/*.yaml`
via a one-off script, not hand-transcribed) plus a hand-picked, representative set of findings
rendered from real rule templates. Nothing here talks to a real filesystem or runs a real scan;
it's fixture data shaped exactly like what the real Tauri commands return.

## Regenerating `fixtures/rules.json`

If the rule pack changes and the fixture goes stale:

```bash
python3 -c "
import yaml, json, glob
rules = []
for path in sorted(glob.glob('../../../../rules/**/*.yaml', recursive=True)):
    with open(path) as f:
        r = yaml.safe_load(f)
    rules.append({
        'id': r['id'], 'title': r['title'], 'category': r['category'],
        'severity': r['severity'], 'collector': r['collector'],
        'references': r.get('references', []), 'explain': r.get('explain', '').strip(),
        'fix': r.get('fix', ''), 'os': r.get('os', ['linux']), 'profiles': r.get('profiles', []),
    })
json.dump(rules, open('fixtures/rules.json', 'w'), indent=2)
"
```
