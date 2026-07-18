# Flathub permission rationale — `com.vietanhdev.bulwark`

Paste the relevant part into the Flathub submission PR description. Reviewers ask
about broad filesystem access, so answer it before they have to.

---

## Requested permission

The complete permission set is deliberately small:

```yaml
- --share=ipc
- --socket=wayland
- --socket=fallback-x11
- --device=dri
- --filesystem=host:ro                    # the one needing justification
- --filesystem=xdg-data/bulwark:create    # its own SQLite findings history
- --talk-name=org.freedesktop.Notifications
- --talk-name=org.kde.StatusNotifierWatcher
```

No network permission. No `--talk-name=org.freedesktop.Flatpak` (no sandbox
escape). No writable host access.

## Why `--filesystem=host:ro` is required

Bulwark is a **host security auditor**. Its entire function is to inspect the
configuration of the machine it runs on and report misconfigurations — sshd
settings, account and password policy, systemd units, cron jobs, kernel sysctls,
permissions on sensitive files, file-integrity baselines, log configuration. An
auditor that cannot read the host has nothing to audit.

**The paths are not enumerable at build time.** This is the crux, and it is why
narrower permissions do not work:

- `sshd_config` pulls in `Include` drop-ins that may live under any directory the
  admin chose.
- systemd units and overrides are found across `/etc/systemd`, `/usr/lib/systemd`,
  `/run/systemd`, plus per-unit drop-in directories.
- cron entries span `/etc/crontab`, `/etc/cron.d`, `/etc/cron.{hourly,daily,…}`,
  and per-user crontabs.
- Kernel and account policy is read from `/etc`, `/proc`, and `/sys`.
- **Every new rule adds new paths.** The rule pack is data (declarative YAML), so
  the set of files read changes with a rule update, not with a code release.

`--filesystem=host-etc:ro` is insufficient (we also read `/proc`, `/sys`,
`/usr/lib/systemd`, `/var`). `system-files` / `personal-files` cannot enumerate
arbitrary absolute paths, and enumerating them would be wrong anyway: the list is
open-ended by design.

## Why this is a comparatively low-risk grant

- **Read-only.** `:ro`, not `host`. A scan never modifies host state. The
  application's own writes are confined to `xdg-data/bulwark` (its findings
  database) — which is why that separate, narrow, writable grant exists.
- **No network access at all.** The manifest requests no network permission, and
  the scanning engine makes no network calls and sends no telemetry. Whatever the
  app reads cannot leave the machine.
- **The remediation features are not available in this build.** Fixes that would
  modify host files require root, which the sandbox cannot obtain (see below), so
  the Flatpak is effectively read-only in practice as well as by permission.

## Privileged scans are *not* performed in the sandbox

Bulwark's distribution packages elevate for root-only checks via `pkexec`. A
Flatpak sandbox cannot do this (no setuid, no system polkit agent), and **this
build does not attempt it** — privileged checks are simply reported as
unavailable, and the metainfo tells users so:

> inside the Flatpak sandbox Bulwark reads the host read-only, so unprivileged
> configuration scans work as normal. Checks that require root are unavailable in
> this build — use the distribution packages or the command-line tool for those.

Note that we deliberately **do not** request `--talk-name=org.freedesktop.Flatpak`.
A `flatpak-spawn --host` escape hatch would let the app run host commands, and we
would rather ship reduced functionality than request a permission the code does
not use. There is no sandbox escape in this build.

## Precedent

Read-only host access is granted on Flathub to tools whose purpose is inspecting
the host — backup, disk/filesystem analysers, and system-information utilities.
Bulwark is the same shape: it reads broadly, writes nothing, and sends nothing.
