# Publishing Bulwark as an Ubuntu package

Three channels, split by what each half of Bulwark needs:

| Component | Channel | Install command | Why |
|---|---|---|---|
| `bulwarkctl` (CLI) | **Launchpad PPA** | `sudo add-apt-repository ppa:vietanhng/bulwark && sudo apt install bulwarkctl` | Source-built by Launchpad; deps vendored for the offline builder. |
| `bulwark-app` (GUI) | **Snap (classic)** | `sudo snap install bulwark --classic` | Privileged scans need `pkexec` + host `/etc` access, which only classic confinement allows. |
| `bulwark-app` (GUI) | **Flatpak / Flathub** | `flatpak install flathub com.vietanhdev.bulwark` | Broadest cross-distro GUI reach — but sandboxed, so privileged scans are limited (see below). |

> The GitHub-release `.deb`/`.rpm`/AppImage built by `.github/workflows/release.yml`
> stay as-is — this is *additional* distribution, not a replacement.

Layout:
- `ppa/debian/` — the CLI's Debian source packaging; built by `scripts/build-ppa-source.sh`.
- `../snap/snapcraft.yaml` — the GUI's classic snap recipe.
- `flatpak/` — the GUI's Flatpak manifest + desktop/metainfo; offline deps built
  by `scripts/flatpak-gen-sources.sh`.

### Confinement, at a glance — this is *why* the channels differ

The GUI's privileged path is `pkexec bulwark scan --privileged` plus reading host
`/etc`. How much of that survives depends entirely on the sandbox:

| Channel | Sandbox | Privileged scan | Read host `/etc` |
|---|---|---|---|
| `.deb`/`.rpm`/AppImage | none | ✅ works | ✅ |
| Snap **classic** | none (approval-gated) | ✅ works | ✅ |
| Snap strict | yes | ❌ | interfaces only |
| **Flatpak** | yes (no opt-out) | ⚠️ only via `flatpak-spawn --host` + host CLI + app-code change | ✅ with `--filesystem=host:ro` |

Flatpak is the widest-reach GUI channel but the most constrained — it can never be
unconfined. Ship it knowing privileged scanning is a documented follow-up, not a
day-one feature.

---

## Why not just upload the `cargo deb` `.deb`?

A PPA does not accept a pre-built binary `.deb`. Launchpad's build farm compiles
the package itself, **per Ubuntu series, on machines with no network access**. So
the source package must carry every dependency with it. The CLI packaging here
handles that by:

1. Trimming the workspace to `bulwark-core` + `bulwarkctl` (dropping the Tauri and
   agent members, which the CLI does not need — this keeps the vendored tree small).
2. `cargo vendor`-ing every crate into `vendor/` and adding a `.cargo/config.toml`
   that redirects crates-io to it.
3. Building the `.orig` tarball from that tree, so the Launchpad build runs with
   `CARGO_NET_OFFLINE=true` and never touches the network.

This model is validated end-to-end: the trimmed, vendored tree builds a working
`bulwarkctl 0.7.0` offline, and `dpkg-source` produces a clean `3.0 (quilt)`
source package (~24 MB compressed) that lints clean.

---

## One-time Launchpad setup

1. Create a Launchpad account: <https://launchpad.net>.
2. Sign the Ubuntu Code of Conduct (required to upload).
3. Add your **GPG key** to your Launchpad profile — Launchpad only accepts uploads
   signed by a key it knows, and it emails you an encrypted token to confirm you
   hold the private key.
   ```bash
   gpg --full-generate-key                 # if you don't have one
   gpg --list-secret-keys --keyid-format long   # note the KEYID
   gpg --send-keys --keyserver keyserver.ubuntu.com <KEYID>
   ```
4. Add your **SSH key** to your Launchpad profile.
5. Create the PPA: profile → "Create a new PPA" → name it `bulwark`. It becomes
   `ppa:vietanhng/bulwark`.

Install the upload tooling on your machine (Ubuntu/Debian):
```bash
sudo apt install devscripts dput debhelper dpkg-dev cargo rustc
```

---

## Publishing the CLI to the PPA

```bash
# Build a SIGNED source package for one Ubuntu series.
scripts/build-ppa-source.sh --series noble --sign-key <KEYID>

# Upload it. Launchpad builds the .deb for every supported arch and emails you.
dput ppa:vietanhng/bulwark target/ppa/bulwark_0.7.0-0ppa1~noble1_source.changes
```

To publish for several series, run once per series (each gets its own
`~seriesN` version so upgrades sort correctly):
```bash
for s in noble oracular plucky; do
  scripts/build-ppa-source.sh --series "$s" --sign-key <KEYID>
  dput ppa:vietanhng/bulwark target/ppa/bulwark_0.7.0-0ppa1~${s}1_source.changes
done
```

Re-uploading the **same** upstream version to the **same** series (e.g. to fix a
packaging bug) needs a bumped PPA revision — Launchpad rejects a duplicate
version:
```bash
scripts/build-ppa-source.sh --series noble --ppa-rev 2 --sign-key <KEYID>
```

Omit `--sign-key` for a local unsigned test build (produces the source package but
`dput` will refuse it).

### ⚠️ The one thing that can actually fail: the builder's `rustc`

Launchpad compiles with the **target series' archive `rustc`**, which lags the
toolchain you develop with:

| Series | archive `rustc` (approx) |
|---|---|
| 24.04 noble | ~1.75 |
| 24.10 / 25.04 | newer, still behind |

If any dependency's minimum supported Rust version exceeds the series' `rustc`,
that series' build will fail (this is the single most common reason Rust PPAs
fail). Two fixes:

- Prefer newer series, and/or declare an honest `rust-version` in
  `[workspace.package]` so the mismatch surfaces at `cargo build` time instead of
  on Launchpad.
- If you need a newer toolchain than the archive offers, add a Rust-toolchain PPA
  to the source package's `Build-Depends` (e.g. a `~ppa` `rustc`).

**Rehearse before uploading.** Uploads are one-way (you can't delete a version,
only supersede it). Build the exact series in a clean chroot first:
```bash
sudo apt install sbuild
# ... configure an sbuild chroot for noble, then:
sbuild -d noble target/ppa/bulwark_0.7.0-0ppa1~noble1.dsc
```

---

## Publishing the GUI as a classic snap

Snapcraft build environments **do** have network access, so the snap build fetches
npm and cargo deps normally — no vendoring. The recipe is `snap/snapcraft.yaml`.

```bash
sudo snap install snapcraft --classic
sudo snap install lxd && sudo lxd init --auto   # snapcraft's default build backend
snapcraft                                        # produces bulwark_0.7.0_amd64.snap
```

### Classic confinement requires approval

Because the snap is `confinement: classic`, you cannot just push it to a stable
channel. The flow is:

1. Register the name once: `snapcraft register bulwark`.
2. Request classic confinement on the forum
   (<https://forum.snapcraft.io/c/store-requests>), explaining that Bulwark is a
   host security auditor that must run `pkexec` and read system files — a strict
   sandbox defeats its purpose. Approval is manual and case-by-case.
3. After approval: `snapcraft upload --release=stable bulwark_0.7.0_amd64.snap`.

Until approval, you can still test locally without a store round-trip:
```bash
snapcraft                       # build
sudo snap install --classic --dangerous bulwark_0.7.0_amd64.snap
```

### Two things to verify on a real machine

`snapcraft.yaml` has two spots that **cannot be validated without an actual
snapcraft build** (flagged with `TODO(verify)` in the file):

1. **Rule-pack path.** The GUI resolves `rules/`, `decoders/`, `log-rules/` via
   Tauri's resource dir at runtime. Confirm the path Tauri computes inside the
   snap matches where the recipe installs them; adjust if the app can't find its
   rules. Symptom of a mismatch: "couldn't find a 'rules' directory."
2. **polkit policy.** A classic snap can't install
   `polkit/com.bulwark.policy` into the host's `/usr/share/polkit-1/actions`, so
   `pkexec` falls back to the distro-default polkit action (usually
   `auth_admin_keep`) instead of Bulwark's `auth_admin`. Same opt-in caveat that
   the plain `.deb`/`.rpm` already have (see the root `AGENTS.md`/`CLAUDE.md`
   "Open question — the polkit policy is not packaged"). Document it for snap
   users or ship `install-polkit.sh` alongside.

---

## Publishing the GUI as a Flatpak (Flathub)

Flatpak reaches every distro but is **always sandboxed** — there is no classic
escape hatch as with Snap. Files: `packaging/flatpak/com.vietanhdev.bulwark.yaml`
(manifest), the `.desktop` + `.metainfo.xml` beside it, and two generated offline
source manifests.

Like Launchpad, Flatpak builds offline, so cargo **and** npm deps are pre-fetched:

```bash
# 0. Install flatpak-builder + the SDK the manifest needs (one-time).
#    Prefer the Flatpak build of flatpak-builder — it dodges distro mirror lag
#    (a stale mirror can 404 the apt package). The apt package works too.
flatpak install -y flathub org.flatpak.Builder    # or: sudo apt install flatpak-builder
flatpak install -y flathub org.gnome.Sdk//50 \
    org.freedesktop.Sdk.Extension.rust-stable//25.08 \
    org.freedesktop.Sdk.Extension.node20//25.08

# 1. Generate the offline cargo/node source manifests (needs network).
scripts/flatpak-gen-sources.sh          # -> packaging/flatpak/{cargo,node}-sources.json
git add packaging/flatpak/*-sources.json   # commit them; they pin the offline build

# 2. Build. Use the helper — a raw `flatpak-builder` from the repo root would copy
#    the whole working tree (multi-GB target/ + node_modules) into the sandbox and,
#    if state dirs live under target/, recurse into itself (100+ GB). The helper
#    stages a clean `git archive` tree with build/state dirs OUTSIDE the repo.
scripts/flatpak-build-local.sh

# 3. Install & run (the helper prints the exact --install command).
flatpak run com.vietanhdev.bulwark
```

**Validated end-to-end** on a real `flatpak-builder 1.4.8` run (GNOME 50 runtime):
the offline npm + cargo build compiles both binaries, `appstreamcli compose`
accepts the metainfo, and all finish-args apply. Both former `TODO(verify)` gaps
are now closed — (a) `cargo build -p bulwark-app` links cleanly against the GNOME
runtime's **WebKitGTK** (ABI compatible), and (b) the **rule pack resolves in the
sandbox**: the bundled CLI lists all 65 rules from `/app/bin/rules` with no
`--rules-dir`, and the GUI's in-process scans use the same next-to-exe resolver.
(One thing still needs a graphical session to eyeball: the GUI window actually
rendering — `flatpak run` it on a desktop.)

### The privileged-scan limitation (read this before promising features)

A Flatpak sandbox **cannot** run `pkexec` (no setuid, no polkit agent). Two
consequences:

1. **Unprivileged scans** work: the manifest grants `--filesystem=host:ro`, so
   config/SSH/log collectors can read host state read-only.
2. **Privileged scans need real work.** The only route out of the sandbox is
   `flatpak-spawn --host pkexec bulwarkctl scan --privileged …`, which requires
   **both** the `--talk-name=org.freedesktop.Flatpak` permission (already in the
   manifest) **and** `bulwarkctl` installed on the host (i.e. from the PPA above),
   **and** an app-code change: `resolve_cli_binary`/`scan_privileged` must detect
   the sandbox (`/.flatpak-info` present) and rewrite the invocation to go through
   `flatpak-spawn --host`. That code doesn't exist yet — until it does, the
   Flatpak is unprivileged-only. Don't implement it without a live flatpak to test
   against; the sandbox-detection + host-CLI-resolution is exactly the kind of
   path logic that silently misbehaves when guessed.

### App-id note for Flathub

The manifest uses `com.vietanhdev.bulwark`. Note this differs from the **Tauri app
identifier** still set in `tauri.conf.json` (`com.vietanhnv.bulwark`); for the
cleanest desktop integration those should match, but changing the Tauri one moves
the app's config/data dirs, so it's left as a separate decision.

Flathub requires the app-id prefix to be a domain you control. `com.vietanhdev.bulwark`
satisfies this — the maintainer owns `vietanhdev.com`, so this app-id is Flathub-ready
and needs no rename. (Had that not been the case, the fallbacks would be
`io.github.vietanhdev.bulwark` or `ai.nrl.bulwark`.)

---

## CI publishing (GitHub Actions)

Three **manual** workflows (Actions tab → *Run workflow*). None fire on tag/push —
a PPA/Snap upload hits a live store and a PPA upload is irreversible, so publishing
is always a deliberate click.

| Workflow | What it does | Secrets used |
|---|---|---|
| `publish-ppa.yml` | Builds the signed source package(s) and `dput`s to `ppa:vietanhng/bulwark`. Inputs: `series`, `ppa_rev`. | `LAUNCHPAD_GPG_PRIVATE_KEY`, `LAUNCHPAD_GPG_PASSPHRASE` |
| `publish-snap.yml` | Builds the snap and releases to a channel. Input: `channel` (default `edge`). | `SNAPCRAFT_STORE_CREDENTIALS` |
| `publish-flatpak.yml` | Builds `bulwark.flatpak`, uploads it as an artifact; attaches to a release if `release_tag` is given. | none |

### GPG signing key (PPA) — already provisioned

An RSA-4096 signing key was generated for `vietanh.dev@gmail.com` and wired up:

- **Fingerprint:** `44054E3BC7B5E0F11AA26344665B0501813B5351`
- The **private** key + its passphrase are stored as the repo secrets
  `LAUNCHPAD_GPG_PRIVATE_KEY` / `LAUNCHPAD_GPG_PASSPHRASE` (the passphrase is the
  `PPA_PASSWORD` from the local `.env`). The **public** key is at
  `~/bulwark-ppa-pubkey.asc` and was published to `keyserver.ubuntu.com`.
- CI signs non-interactively via a `gpg.conf` `passphrase-file` + `pinentry-mode
  loopback` (validated — the agent-preset method fails headless).

**One manual step remains on Launchpad:** profile → *OpenPGP keys* → *Import an
OpenPGP key* → paste the fingerprint above. Launchpad emails an **encrypted**
confirmation token; decrypt it with `gpg --decrypt` (the key is in your local
keyring) and paste the link back. Only after this does Launchpad accept uploads
signed by the key.

### Snap Store credentials

The Snap Store uses the **same Ubuntu One account** as Launchpad, but CI can't use
the account password — it needs an exported **macaroon**. Generate it once (needs
`snapcraft` locally) and store it:

```bash
snapcraft register bulwark          # once, if the name isn't yours yet
snapcraft export-login --snaps=bulwark \
  --acls package_push,package_release --channels edge,beta,candidate,stable - \
  > snapcraft-creds.txt
gh secret set SNAPCRAFT_STORE_CREDENTIALS < snapcraft-creds.txt
rm snapcraft-creds.txt
```

Classic confinement can't publish to `stable` until the name is granted classic
(forum review) — publish to `edge`/`beta` meanwhile.

---

## Version bumps

`scripts/bump-version.sh` currently updates the six in-tree version declarations
but **not** these packaging files. When cutting a release that will be published
here, also update:

- `snap/snapcraft.yaml` → `version:`
- `packaging/flatpak/com.vietanhdev.bulwark.metainfo.xml` → add a `<release>`, and
  re-run `scripts/flatpak-gen-sources.sh` if lockfiles changed.
- The PPA source version is derived automatically from `[workspace.package]`
  version by `scripts/build-ppa-source.sh`, so it needs no manual edit.

If PPA/snap publishing becomes routine, add `snap/snapcraft.yaml` to the file list
in `scripts/bump-version.sh` so a bump keeps it in sync (that list is the single
source of truth for what a bump touches).
