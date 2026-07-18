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
`~seriesN` version so upgrades sort correctly). **Only upload to *active* series** —
a PPA rejects End-of-Life ones. Check the live list before choosing:
```bash
# active Ubuntu series (status != Obsolete) that a PPA will accept:
curl -s "https://api.launchpad.net/1.0/ubuntu/series" | \
  python3 -c 'import sys,json;[print(s["version"],s["name"],s["status"]) for s in json.load(sys.stdin)["entries"] if s["active"]]'
# as of 0.8.0: noble (24.04 LTS), resolute (26.04 LTS), stonking (26.10 devel).
# oracular/plucky/questing have gone EOL and are rejected.

for s in noble resolute stonking; do
  scripts/build-ppa-source.sh --series "$s" --sign-key <KEYID>
  dput ppa:vietanhng/bulwark target/ppa/bulwark_*~${s}1_source.changes
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

| Series | archive `rustc`/`cargo` | PPA support |
|---|---|---|
| 24.04 noble (LTS) | 1.75.0 | ❌ **unsupported** — see below |
| 26.04 resolute (LTS) | 1.93.1 | ✅ |
| 26.10 stonking (devel) | newest | ✅ |

**noble (24.04 LTS) cannot be supported.** Its cargo 1.75 cannot even *parse* this
workspace's `Cargo.lock` (lockfile format v4, which needs cargo ≥ 1.78) — the build
dies in ~38 s with `error: failed to parse lock file`. Downgrading the lockfile to
v3 would only move the failure into the compile, since rustc 1.75 (Dec 2023) is far
older than the dependency tree requires. noble users should install the
GitHub-release `.deb` instead.

### ⚠️ Upload every series of a version in ONE run

A version has exactly **one** `.orig` tarball, shared by all series. The first
series uploads it (`-sa`); later series reference it (`-sd`). Two consequences:

- `scripts/build-ppa-source.sh` builds the orig once per run and **reuses the
  file** for subsequent series, so they are byte-identical by construction.
- **Never split a version's series across separate runs.** The orig contains the
  whole source tree, so any commit landing in between changes it, and Launchpad
  rejects the later series with *"already exists, but uploaded version has
  different contents"*. (This is exactly how the 0.8.1 resolute/stonking uploads
  were rejected after noble had already been accepted from an earlier commit.)

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

### Submitting to Flathub

Building the Flatpak is **not** publishing it. `publish-flatpak.yml` only produces a
`bulwark.flatpak` bundle; Flathub is a separate PR to `flathub/flathub`, reviewed by
a human, after which Flathub creates `flathub/com.vietanhdev.bulwark` and builds from
*that* repo — not from this one.

That last point drives the whole process. Flathub's buildbot has no copy of this
working tree, so the dev manifest's `type: dir, path: ../..` source is meaningless
there; the submitted manifest must fetch a **tagged commit** of this repo instead.
Maintaining a second manifest by hand is how the two drift, so it's generated:

```bash
scripts/flatpak-gen-flathub-manifest.sh          # defaults to the newest v* tag
scripts/flatpak-gen-flathub-manifest.sh v0.8.1   # or pin one
```

It inherits everything from the dev manifest and rewrites *only* the source block to
`type: git` + `tag` + `commit`, then stages `build/flathub-submission/` with the
manifest, the two generated `*-sources.json`, the `.desktop`, the `.metainfo.xml` and
a `flathub.json` pinning `x86_64`/`aarch64`.

**Tag first, then generate.** The build installs the metainfo *from the fetched
source tree*, so a fix that is only in your working copy is invisible to Flathub —
you would ship the tagged file and wonder why the screenshots never appeared. The
script refuses a tag that isn't pushed to `origin`, but it cannot tell you the tag is
stale. Cut a fresh tag whenever anything under `packaging/flatpak/` changes.

Then lint both artifacts (this is what Flathub runs, and it must be clean):

```bash
cd build/flathub-submission
flatpak run --command=flatpak-builder-lint org.flatpak.Builder appstream com.vietanhdev.bulwark.metainfo.xml
flatpak run --command=flatpak-builder-lint org.flatpak.Builder manifest com.vietanhdev.bulwark.yaml
```

Finally: fork `flathub/flathub` (**uncheck** "copy the master branch only"), branch
off `new-pr`, copy the staged files in, and open the PR against the **`new-pr` base
branch** — not `master`.

#### The two permissions Flathub will argue with

`appstream` passes clean. `manifest` reports two errors that are *not* bugs to
silently paper over:

| Linter error | Status |
|---|---|
| `finish-args-host-ro-filesystem-access` | **Needs a Flathub exception.** `--filesystem=host:ro` is the product: an auditor that can't read the host's `/etc` has nothing to audit. Request the exception in the PR with that justification — don't drop the permission to make the linter quiet, that ships a scanner which silently sees nothing. |
| `finish-args-unnecessary-xdg-data-bulwark-create-access` | **Unresolved — needs a live sandbox test.** The linter calls `--filesystem=xdg-data/bulwark:create` redundant because the app already gets a writable `~/.var/app/<id>/data`. But it was added for a real, observed failure ("attempt to write a readonly database") caused by `--filesystem=host:ro`. Removing it blind risks reintroducing that. Build, run a scan in the sandbox, and confirm the history persists *before* deciding. |

`--talk-name=org.freedesktop.Flatpak` was **removed**: it exists for `flatpak-spawn
--host pkexec` privileged scans, and that code path isn't implemented. The linter
errors on it, and asking reviewers for a sandbox escape the code never exercises is a
straightforward way to fail review. Add it back in the same change that implements
privileged scanning.

#### Still outstanding

- **Domain verification.** Flathub may require a token at
  `https://vietanhdev.com/.well-known/org.flathub.VerifiedApps.txt`. Only the domain
  owner can place it — note the app-id domain is `vietanhdev.com`, while the app's
  homepage is `bulwark.nrl.ai`.
- **A full offline build from the generated manifest** has not been run. The dev
  manifest is validated end-to-end, but the `type: git` source has only been linted,
  not built.

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

**Classic confinement is gated on approval for _every_ channel** (edge included),
not just `stable` — a classic snap is rejected on upload until the registered name
is granted classic. Two one-time steps, in order:

1. **Register the name:** `snapcraft register bulwark` (or [snapcraft.io/register-snap](https://snapcraft.io/register-snap)).
2. **Request classic:** open a topic in the *Store requests* category —
   [forum.snapcraft.io/c/store-requests/19](https://forum.snapcraft.io/c/store-requests/19) —
   with the snap name, the source URL, and the justification (host security
   auditor: needs `pkexec` + host `/etc`, which a strict sandbox blocks). A
   reviewer grants classic manually (days to weeks). Only then can any publish
   (including `edge`) succeed.

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
