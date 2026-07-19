---
title: Download
description: Download Bulwark for Linux — desktop app (.deb, .rpm, AppImage) and CLI (.deb, .rpm, PPA, AUR, COPR, tarball).
---

<script setup>
import { ref, onMounted, computed } from "vue";

const REPO = "vietanhdev/bulwark";
const RELEASES_URL = `https://github.com/${REPO}/releases`;

const release = ref(null);
const failed = ref(false);

// Fetched at view time rather than baked in at build time: the docs site and the release
// pipeline deploy independently, so a hard-coded version here would go stale the moment a
// release ships without a docs rebuild. If GitHub is unreachable or rate-limits the request
// (60/hour per IP unauthenticated), `failed` flips and every button falls back to the
// releases page, which always works.
onMounted(async () => {
  try {
    const res = await fetch(`https://api.github.com/repos/${REPO}/releases/latest`);
    if (!res.ok) throw new Error(String(res.status));
    release.value = await res.json();
  } catch {
    failed.value = true;
  }
});

const version = computed(() => release.value?.tag_name ?? null);

// Matched by predicate rather than by exact filename, so the page survives a version bump
// (the version is embedded in every asset name) without needing an edit here.
function find(pred) {
  return release.value?.assets?.find((a) => pred(a.name)) ?? null;
}

// Every predicate below pins an ARCHITECTURE suffix, and that is load-bearing rather than
// tidiness. `find` returns the FIRST asset matching the predicate, and the release now carries
// both x86_64 and arm64 builds — so a predicate like `startsWith("bulwarkctl") && endsWith(".deb")`
// matches both and hands whichever GitHub happens to list first. The failure is silent and
// user-side: the page looks right, the download works, and the package refuses to install with
// "package architecture (arm64) does not match system (amd64)". Never loosen these.
const is = {
  guiDeb: (n) => n.startsWith("bulwark-desktop") && n.endsWith("_amd64.deb"),
  guiRpm: (n) => n.startsWith("bulwark-desktop") && n.endsWith(".x86_64.rpm"),
  guiAppImage: (n) => n.endsWith("-x86_64.AppImage"),

  guiDebArm: (n) => n.startsWith("bulwark-desktop") && n.endsWith("_arm64.deb"),
  guiRpmArm: (n) => n.startsWith("bulwark-desktop") && n.endsWith(".aarch64.rpm"),
  guiAppImageArm: (n) => n.endsWith("-aarch64.AppImage"),

  cliDeb: (n) => n.startsWith("bulwarkctl") && n.endsWith("_amd64.deb"),
  cliRpm: (n) => n.startsWith("bulwarkctl") && n.endsWith(".x86_64.rpm"),
  cliTarball: (n) => n.startsWith("bulwarkctl") && n.endsWith("-x86_64-linux.tar.gz"),

  cliDebArm: (n) => n.startsWith("bulwarkctl") && n.endsWith("_arm64.deb"),
  cliRpmArm: (n) => n.startsWith("bulwarkctl") && n.endsWith(".aarch64.rpm"),
  cliTarballArm: (n) => n.startsWith("bulwarkctl") && n.endsWith("-aarch64-linux.tar.gz"),
};

// Always yields a working link: the direct asset once a release exists, the releases page
// otherwise (no release cut yet, or the API call failed).
function url(pred) {
  return find(pred)?.browser_download_url ?? RELEASES_URL;
}
function size(pred) {
  const a = find(pred);
  return a ? `${(a.size / 1024 / 1024).toFixed(1)} MB` : "";
}
</script>

# Download Bulwark

<p class="dl-version">
  <template v-if="version">
    Latest release: <strong>{{ version }}</strong> · <a :href="RELEASES_URL">all releases</a>
  </template>
  <template v-else-if="failed">
    <a :href="RELEASES_URL">View all releases on GitHub →</a>
  </template>
  <template v-else>Looking up the latest release…</template>
</p>

Linux, **x86_64 and arm64**. Built on Ubuntu 22.04 (glibc 2.35), so it runs on **Ubuntu 22.04+, Debian 12+, and Fedora 36+**. Every release is installed and scan-tested in a clean container on Ubuntu 22.04, 24.04 and 26.04, Debian 12, and Fedora 41 before it ships — including the current Ubuntu LTS. The arm64 builds are compiled and tested on native arm64 machines, not emulated, and the desktop app is launched and screenshotted on both architectures before release.

::: tip Which one do I need?
Run `uname -m`. `x86_64` (also called amd64) is a typical desktop, laptop or cloud VM; `aarch64` (also called arm64) is a Raspberry Pi 4/5, an Ampere or AWS Graviton server, or a Linux VM on Apple silicon. The download buttons below give you x86_64 — arm64 links are in the code blocks beneath each one.
:::

## Desktop app

The GUI: dashboard, ClamAV scanning with real-time protection, compliance view, and scan history.

<div class="dl-grid">
  <a class="dl-card" :href="url(is.guiDeb)">
    <span class="dl-card-title">Debian / Ubuntu</span>
    <span class="dl-card-sub">.deb<template v-if="size(is.guiDeb)"> · {{ size(is.guiDeb) }}</template></span>
  </a>
  <a class="dl-card" :href="url(is.guiRpm)">
    <span class="dl-card-title">Fedora / RHEL</span>
    <span class="dl-card-sub">.rpm<template v-if="size(is.guiRpm)"> · {{ size(is.guiRpm) }}</template></span>
  </a>
  <a class="dl-card" :href="url(is.guiAppImage)">
    <span class="dl-card-title">Any distro</span>
    <span class="dl-card-sub">AppImage<template v-if="size(is.guiAppImage)"> · {{ size(is.guiAppImage) }}</template></span>
  </a>
</div>

```bash
# Debian / Ubuntu
sudo dpkg -i bulwark-desktop_*_amd64.deb        # x86_64
sudo dpkg -i bulwark-desktop_*_arm64.deb        # arm64

# Fedora / RHEL
sudo rpm -i bulwark-desktop-*.x86_64.rpm        # x86_64
sudo rpm -i bulwark-desktop-*.aarch64.rpm       # arm64

# AppImage — portable, nothing to install
chmod +x bulwark-desktop-*-x86_64.AppImage      # x86_64 (arm64: -aarch64.AppImage)
./bulwark-desktop-*-x86_64.AppImage
```

Direct arm64 downloads:
<span v-if="find(is.guiDebArm)"><a :href="url(is.guiDebArm)">.deb</a> · </span><span v-if="find(is.guiRpmArm)"><a :href="url(is.guiRpmArm)">.rpm</a> · </span><a :href="url(is.guiAppImageArm)">AppImage</a>

### Snap and Flatpak — not currently available

Bulwark is **not** published on the Snap Store or Flathub, and installing it from
either is not possible today. Both stores sandbox applications, and both restrict
the host access a security auditor needs: Flathub's inclusion policy excludes
system utilities used on the host, and the Snap Store's classic-confinement
criteria exclude reading `/etc` and using `pkexec` — which is how Bulwark's
privileged scans work.

Packaging for both exists in the repository and builds correctly, so this may
change. Until it does, use the `.deb`, `.rpm`, AppImage or PPA above. Those are
unconfined, so they run the complete product: privileged scans, host ClamAV
integration and all.

## CLI

`bulwarkctl` scans from a terminal — no display session, so it works over plain SSH on a
headless box. Same engine and same rule pack as the GUI.

<div class="dl-grid">
  <a class="dl-card" :href="url(is.cliDeb)">
    <span class="dl-card-title">Debian / Ubuntu</span>
    <span class="dl-card-sub">.deb</span>
  </a>
  <a class="dl-card" :href="url(is.cliRpm)">
    <span class="dl-card-title">Fedora / RHEL</span>
    <span class="dl-card-sub">.rpm</span>
  </a>
  <a class="dl-card" :href="url(is.cliTarball)">
    <span class="dl-card-title">Any distro</span>
    <span class="dl-card-sub">tarball</span>
  </a>
</div>

```bash
# x86_64
sudo dpkg -i bulwarkctl_*_amd64.deb    # or: sudo rpm -i bulwarkctl-*.x86_64.rpm

# arm64
sudo dpkg -i bulwarkctl_*_arm64.deb    # or: sudo rpm -i bulwarkctl-*.aarch64.rpm

bulwarkctl scan
```

Direct arm64 downloads:
<span v-if="find(is.cliDebArm)"><a :href="url(is.cliDebArm)">.deb</a> · </span><span v-if="find(is.cliRpmArm)"><a :href="url(is.cliRpmArm)">.rpm</a> · </span><a :href="url(is.cliTarballArm)">tarball</a>

### Ubuntu PPA

For Ubuntu, install from the PPA to get automatic updates via `apt`:

```bash
sudo add-apt-repository ppa:vietanhng/bulwark
sudo apt update
sudo apt install bulwarkctl
bulwarkctl scan
```

## Verify your download

Every release ships a `SHA256SUMS` file. Check what you downloaded against it before
installing:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

## Build from source

Bulwark is Apache-2.0. If you'd rather build it yourself — see the
[architecture guide](/guide/architecture) and [contributing guide](/guide/contributing):

```bash
git clone https://github.com/vietanhdev/bulwark
cd bulwark
cargo build --release --workspace                          # engine + CLI
cd apps/bulwark-app && npm install && cargo tauri build     # desktop app
```

<style scoped>
.dl-version {
  color: var(--vp-c-text-2);
  font-size: 0.95em;
  margin-top: -0.5rem;
}
.dl-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  margin: 20px 0;
}
.dl-card {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 14px 16px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 10px;
  text-decoration: none !important;
  transition:
    border-color 0.2s,
    background-color 0.2s;
}
.dl-card:hover {
  border-color: var(--vp-c-brand-1);
  background-color: var(--vp-c-bg-soft);
}
.dl-card-title {
  font-weight: 600;
  color: var(--vp-c-text-1);
}
.dl-card-sub {
  font-size: 0.85em;
  color: var(--vp-c-text-2);
  font-family: var(--vp-font-family-mono);
}
</style>
