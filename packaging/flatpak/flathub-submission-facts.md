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
- **Not requested: `org.freedesktop.Flatpak`.** Privileged scans would need it. That is a
  sandbox escape, so the Flatpak simply does not offer privileged scanning, and the
  AppStream description says so.

## Verified before submitting

- Offline build from a clean `git archive` tree on `flatpak-builder`.
- Installed, launched, UI renders, a scan runs and persists to
  `~/.var/app/com.vietanhdev.bulwark`.
- `flatpak info --show-permissions` matches the manifest (worth checking directly: flag
  order silently changes the result — `--own-name` before `--talk-name` downgrades the
  grant to `talk`).
- `flatpak-builder-lint` run on the generated manifest; `finish-args-host-ro-filesystem-access`
  is the remaining error and is the one needing a reviewer decision.

## Known limitation

Privileged scans do not work in the sandbox — no `pkexec`, and reaching the host's would
require the escape above. Unprivileged configuration scanning is fully functional. The
AppStream description states this so users are not surprised.

## Before submitting

- PR must target the **`new-pr`** base branch, not `master`.
- Keep the template's checklist lines and HTML comments intact and answer inline. PR #9392
  was auto-closed ("Checklist(s) not completed or missing") because the template had been
  replaced with prose.
- The video must show this Flatpak running. It will display real findings from the machine
  it runs on — a public list of that host's weaknesses. Review it before posting.
