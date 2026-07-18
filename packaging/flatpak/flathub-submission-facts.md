# Flathub submission — technical reference

**This is a fact sheet, not a PR description.** Flathub's requirements state:

> Submission pull requests must not be generated, opened, or automated using AI tools or
> agents. Review comments, reply, descriptions also must not be be LLM-generated.
> Applications containing AI-generated or AI-assisted code, documentation, or any other
> content are not allowed. Repeatedly violating these policies may result in a permanent
> ban from future submissions and activities.

So the PR description, the checklist answers and any review replies have to be written by a
human. What follows is verifiable technical detail about how this Flatpak is built and why
it needs the permissions it asks for — facts to check against the manifest, not prose to
copy.

Read the policy in full before deciding whether to submit at all:
https://docs.flathub.org/docs/for-app-authors/requirements

## Build facts

| | |
|---|---|
| App ID | `com.vietanhdev.bulwark` |
| Runtime | `org.gnome.Platform` 50 |
| Source | pinned to a `v*` tag **and** its commit hash |
| Offline build | cargo + npm deps pre-generated into `cargo-sources.json` / `node-sources.json` |
| Extra module | `shared-modules/libappindicator` (GNOME runtime ships no appindicator or dbusmenu) |
| Licence | Apache-2.0 |

Regenerate the submission tree with `scripts/flatpak-gen-flathub-manifest.sh <tag>`; it
derives the manifest from the dev one so the two cannot drift.

## Permissions, and why each is present

- **`--filesystem=host:ro`** — flagged by `flatpak-builder-lint`, so it needs an explicit
  case. Bulwark audits host configuration: `/etc/ssh/sshd_config`, `/etc/login.defs`,
  `/etc/sudoers.d`, cron directories, systemd units, file modes and ownership. Read-only;
  the GUI never writes host state. No portal exposes system configuration files, and
  enumerating individual paths would both be long and go stale the moment a rule reads
  something new — a scanner that cannot read what it audits reports a clean host, which is
  a worse failure than refusing to start. Longer write-up:
  `flathub-permissions-rationale.md`.
- **`--share=network`** — the app makes no network calls; `bulwark-core` has no network
  code and "fully local, no telemetry" is a documented product claim. It is required
  because GLib installs the portal-backed proxy resolver and network monitor inside every
  Flatpak, and WebKit calls them while loading the *local* page. Without it
  xdg-desktop-portal returns `NotAllowed: This call is not available inside the sandbox`
  and the UI never renders. Source: `xdg-desktop-portal` `proxy-resolver.c` and
  `network-monitor.c`, both gated on `xdp_app_info_has_network()`.
- **`--own-name` / `--talk-name=org.com_vietanhdev_bulwark.SingleInstance`** — required by
  `tauri-plugin-single-instance`
  (https://v2.tauri.app/plugin/single-instance/#usage-in-snap-and-flatpak). Relaunching
  re-focuses the existing window instead of starting a second copy. The name is derived
  from the Tauri identifier, which now matches the app-id — Flathub rejects owning a name
  outside it.
- **`--talk-name=org.freedesktop.Notifications`** — scan-completion notifications.
- **`--talk-name=org.kde.StatusNotifierWatcher`** — tray icon. Load-bearing rather than
  decorative: closing the window hides it and background monitoring continues, so the tray
  is the way back to the window.
- **`--talk-name=org.freedesktop.Flatpak`** — flagged by the linter, and the widest thing
  requested. It runs two host tools that cannot live in the sandbox: the host's `clamscan`
  (the engine and its ~250 MB signature database are maintained by the distribution;
  bundling a copy would mean shipping an AV engine plus a database stale on arrival), and
  `pkexec` for privileged scans, which elevate against a host-installed `bulwarkctl`. Both
  are gated in code on the permission actually being available, so a build without it
  degrades to an explanation rather than a broken button, and unprivileged scanning — most
  of what the app does — never touches this path. Precedent:
  flathub/io.github.linx_systems.ClamUI, a published ClamAV GUI, ships this permission
  alongside a full read-write `--filesystem=host`; this app pairs it with a read-only one.

## Verified before submitting

- Offline build from a clean `git archive` tree on `flatpak-builder`.
- Installed, launched, UI renders, a scan runs and persists to
  `~/.var/app/com.vietanhdev.bulwark`.
- Verified inside the sandbox: `flatpak-spawn --host clamscan --version` reaches the host
  engine, and a real scan of a host path returns per-file results through the portal.
- Also verified in a clean container (its own filesystem, no host data): the Flatpak
  renders, resolves its rule pack and produces findings.
- `flatpak info --show-permissions` matches the manifest (worth checking directly: flag
  order silently changes the result — `--own-name` before `--talk-name` downgrades the
  grant to `talk`).
- `flatpak-builder-lint` run on the generated manifest; `finish-args-host-ro-filesystem-access`
  is the remaining error and is the one needing a reviewer decision.

## Known limitation

Privileged scans require the Bulwark command-line tool to be installed on the host as well:
the sandbox elevates through the portal against the host's `bulwarkctl`, since `/app` does
not exist outside the sandbox. Without it the app says so and names the packages that
provide it. Everything that does not need root works regardless. The AppStream description
states this, so nobody meets it as a surprise.

## Before submitting

- PR must target the **`new-pr`** base branch, not `master`.
- Keep the template's checklist lines and HTML comments intact and answer inline. PR #9392
  was auto-closed ("Checklist(s) not completed or missing") because the template had been
  replaced with prose.
- The video must show this Flatpak running. It will display real findings from the machine
  it runs on — a public list of that host's weaknesses. Review it before posting.

## Quality practice — verifiable facts

Not a statement to paste. Flathub asks about AI involvement and expects the answer in the
submitter's own words; these are the checkable facts to draw on. Every number below can be
reproduced from the repository.

**Automated checks on every push** (`.github/workflows/ci.yml`):
- `cargo test --workspace` — 20 test suites
- `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`
- `rules validate rules/` over the full rule pack
- frontend typecheck, eslint, prettier, Playwright browser tests (26)
- `scripts/check-packaging-consistency.sh` — static packaging invariants
- CLI install-and-scan on Ubuntu, Debian, Fedora and Arch containers
- snap build

**Release gates** (`.github/workflows/release.yml`), all of which must pass before publish:
- package contents asserted (rule pack present in each artifact, not just "build exited 0")
- install-and-scan verified on Ubuntu 22.04 / 24.04 / 26.04, Debian 12, Fedora 41
- AppImage linkage check
- `verify-gui-launch` — installs each GUI package, launches it under Xvfb, and screenshots
  the window, failing if it renders fewer than 50 distinct colours or loads a dev URL

**Testing philosophy, and why it looks like this.** Several checks exist because something
shipped broken while every existing check passed. The Flatpak once started, resolved its
rule pack, held its PID and drew nothing, because the checks drove the bundled CLI rather
than the GUI. That is why the launch test screenshots the window, and why the packaging
check greps for the `custom-protocol` build flag whose absence silently produces a dev
build. Each of those assertions was verified to fail when deliberately broken.

**Domain grounding.** The rule pack is derived from published benchmarks (Lynis, MITRE
ATT&CK, HackTricks); the research is in `research/`. Secret detection vendors gitleaks'
rules and is pinned by a differential test that compiles every rule in both original and
rewritten form and asserts identical captures, plus 378 false-positive fixtures across 79
rules extracted from gitleaks itself.

**Shipping record.** Published and install-verified on Ubuntu PPA, AUR and Fedora COPR, with
`.deb`, `.rpm`, tarball and AppImage on GitHub releases.
