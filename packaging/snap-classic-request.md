# Snap Store — classic confinement request for `bulwark`

> ⚠️ **On the published criteria and two close precedents, this request is likely to be
> refused.**
>
> The [review policy](https://snapcraft.io/docs/reference/administration/reviewing-classic-confinement-snaps/)
> decides by **supported category**, and its *not-supported* list names Bulwark's
> requirements: *"access to /etc"*, *"direct access to sudo"*, *"direct access to pkexec"*.
> There is no security-audit or system-administration category among the supported ones.
>
> Both precedents were refused on purely categorical grounds without the technical
> case being engaged: `cybertection-guardbot` (pkexec + full-filesystem antivirus,
> Bulwark's exact feature pair) and `sentinelscan` (a read-only Ubuntu security
> scanner, Bulwark feature for feature, pointed at the `system-backup` interface
> instead).
>
> Filing anyway is still reasonable: it costs one forum post and about two weeks to
> a first response, and a definitive determination beats inferring from precedent.
> Do not build product plans on approval. Fuller write-up in `packaging/README.md`.

**Posted on 2026-11-12:** <https://forum.snapcraft.io/t/classic-confinement-request-for-bulwark/54165>.
Follow the thread there; this file is the record of what was asked.

The text below was rewritten that day, after a store reviewer rejected the first upload
with a pointer to the request process. An earlier draft named a supported category that does
not exist and said a strict build had been tried under `snappy-debug`; no record of such a run
exists, so this one says plainly that none of the categories fits and that no strict build
was shipped, and asks which interfaces could be auto-connected if the answer is "use strict".
It follows the template in the category's pinned topic. The two checkboxes at the end are
statements by the person posting; the second is left unticked because no strict build was
tried. A new forum account may put only two links in a post, which is why the launch-test
script is named, not linked.

It went in as a **new topic** in the `classic-confinement` subcategory of Store requests
(replies under the process topic are not reviewed), titled **Classic confinement request for
bulwark**. Keep the `snapcraft.yaml` link pointing at a committed file on the default branch.

---

- **name**: bulwark
- **description**: Desktop app and command-line tool that check the Linux computer they are installed on for security misconfigurations and signs of intrusion (SSH server settings, accounts and password policy, sudoers, systemd units, cron jobs, kernel settings, file permissions, file integrity), and explain each finding with a suggested fix. Scans run locally and send nothing anywhere.
- **snapcraft**: https://github.com/vietanhdev/bulwark/blob/main/snap/snapcraft.yaml
- **upstream**: https://github.com/vietanhdev/bulwark (Apache-2.0)
- **upstream-relation**: I am the author and maintainer of the upstream project and of this snap.
- **supported-category**: None of the listed categories fits, and I would rather say so than stretch one. Bulwark is a host security auditor. I know that "access to /etc" and "direct access to pkexec" are on the unsupported list, so I am asking for this to be looked at as a case outside the lists. The reasoning below is about why the alternatives suggested there (layouts, system-files, asking the user to run under sudo) do not cover it.
- **reasoning**:

**What the snap does on the host**

- It reads host configuration and state: `/etc/ssh/sshd_config` and every file its `Include` lines point to, `/etc/passwd`, the mode and owner of `/etc/shadow`, `/etc/sudoers` and `/etc/sudoers.d`, `/etc/login.defs`, systemd unit folders and their drop-ins, cron folders and crontabs, GRUB configuration, kernel settings under `/proc/sys`, listening ports, and modprobe blacklists.
- It reads a small set of files in the user's home folder: `~/.ssh` (keys, config, `authorized_keys`), shell startup files, and the config files of developer tools, to report things like an unprotected private key or a token stored in plain text.
- It runs a few of the host's own programs and reads their output: `systemctl`, `journalctl`, `crontab`, `sha256sum`, and the host's `clamscan` when ClamAV is installed.
- For the checks that need root, the desktop app starts its bundled CLI through `pkexec`, with one polkit prompt per scan.
- A scan changes nothing. Fixes are separate, opt-in commands that preview by default. They tighten permissions under `/etc` and `~/.ssh`, and can add a hardening block to `/etc/ssh/sshd_config`, which is checked with the host's `sshd -t` before it is kept.
- There is no daemon, no listening socket and no telemetry. The app connects out only when the user sets up one of two optional features: checking another machine over the system `ssh`, or sending alerts.

**Why I think strict confinement does not cover it**

1. Reading the host's configuration is what the tool is for, not something it does out of habit. `system-files` needs a fixed list of paths. Here part of the list comes from the host itself: `Include` lines in `sshd_config`, unit drop-in folders and cron folders.
2. `system-backup` would give a read-only copy of the host under `/var/lib/snapd/hostfs`. That would cover much of the reading if the engine were changed to look there. It would not cover asking the host's own tools (`sshd -t`, `systemctl`, `crontab`), and it would not cover the fixes, which write to `/etc`.
3. I see no interface for the root step. The unsupported list suggests telling the user to run under sudo. The CLI in this snap already works that way. The desktop app has no way to do the same, and inside a strict snap root would still be confined to the same read-only view.
4. The antivirus check uses the host's ClamAV and its signature database on purpose, so that it scans with what the system administrator installed and keeps up to date.

**What I have and have not tried**

I have not shipped a strict build. The points above come from comparing the interface documentation with what the code does, not from a strict snap that failed. The classic snap is built from source in CI on every change, and CI installs it and starts the real window on a machine that has no WebKit of its own (`scripts/test-snap-gui.sh` in the repository above).

If the answer is that this belongs in strict with `system-backup` and the observe interfaces, I would be glad to know which of them could be auto-connected for this snap. That would tell me whether a reduced, read-only strict snap is worth building instead.

The same application is already published as .deb, .rpm and AppImage, and the CLI through a PPA, COPR and the AUR, so nothing here depends on the snap for its users. The snap would be for people who prefer to install from the Snap Store.

[x] I understand that strict confinement is generally preferred over classic.

[] I've tried the existing interfaces to make the snap to work under strict confinement.
