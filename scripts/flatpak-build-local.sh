#!/usr/bin/env bash
# Build the Bulwark GUI Flatpak locally, the safe way.
#
# The manifest's source is `type: dir, path: ../..` (the repo). A naive
# `flatpak-builder` run from inside the repo would copy the ENTIRE working tree
# into the sandbox — including the multi-GB target/ and apps/bulwark-app/node_modules,
# and (if the build/state dirs live under target/) the build dir into itself,
# which blows up to 100+ GB. This script avoids all of that by:
#   1. staging a CLEAN tree via `git archive HEAD` (tracked files only — no target/,
#      no node_modules), then overlaying the untracked packaging/flatpak files
#      (manifest, .desktop, .metainfo, and the generated *-sources.json);
#   2. running flatpak-builder with the staging dir, build dir and state dir all
#      OUTSIDE the repo, on real disk.
#
# Prereqs: run scripts/flatpak-gen-sources.sh first (generates the offline
# cargo/node source manifests), and have `flatpak-builder` on PATH plus the
# org.gnome.{Platform,Sdk}//50 + rust-stable/node20//25.08 SDK extensions installed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ID="com.vietanhdev.bulwark"
MANIFEST="packaging/flatpak/${APP_ID}.yaml"

# Everything lives here — outside the repo, on the same real disk as $HOME.
WORK="${BULWARK_FLATPAK_WORK:-${REPO_ROOT}/../.bulwark-flatpak}"
STAGE="${WORK}/src"
BUILD_DIR="${WORK}/build"
STATE_DIR="${WORK}/state"

command -v flatpak-builder >/dev/null || { echo "ERROR: flatpak-builder not on PATH" >&2; exit 1; }
[[ -f "${REPO_ROOT}/packaging/flatpak/cargo-sources.json" && -f "${REPO_ROOT}/packaging/flatpak/node-sources.json" ]] \
  || { echo "ERROR: run scripts/flatpak-gen-sources.sh first (missing *-sources.json)" >&2; exit 1; }

echo ">> staging clean tree at ${STAGE}"
rm -rf "${STAGE}"
mkdir -p "${STAGE}"
git -C "${REPO_ROOT}" archive --format=tar HEAD | tar -x -C "${STAGE}"
# Overlay the packaging dir, whose generated *-sources.json are gitignored and so never
# come out of `git archive`.
#
# Note the trailing `/.`: it copies the directory's *contents*. `cp -r src dst` nests
# instead (dst/flatpak/...) whenever dst already exists — and it does exist, because the
# manifest and metainfo are tracked and arrive via git archive. That nesting left
# cargo-sources.json one level too deep, flatpak-builder failed to deserialize the whole
# `sources` list (including the `type: dir` source), and the build ran against an empty
# tree with a bare "Can't open cargo-sources.json" warning as the only clue. It was a
# latent bug that only bit once these files were committed.
mkdir -p "${STAGE}/packaging/flatpak"
cp -r "${REPO_ROOT}/packaging/flatpak/." "${STAGE}/packaging/flatpak/"

# flatpak-builder treats an unreadable sources file as a *warning*, drops the entire
# `sources` list, and then builds an empty tree — the failure surfaces hundreds of lines
# later as a confusing "package.json not found". Fail here instead, where the cause is
# obvious.
for f in cargo-sources.json node-sources.json; do
  [[ -f "${STAGE}/packaging/flatpak/${f}" ]] \
    || { echo "ERROR: ${f} missing from the staged tree (${STAGE}/packaging/flatpak/)" >&2; exit 1; }
done

# shared-modules is a git submodule, so a plain `git clone` leaves it empty and
# flatpak-builder fails on a missing module file rather than on the real cause.
[[ -f "${STAGE}/packaging/flatpak/shared-modules/libappindicator/libappindicator-gtk3-12.10.json" ]] \
  || { echo "ERROR: packaging/flatpak/shared-modules is empty — run: git submodule update --init" >&2; exit 1; }

echo ">> building ${APP_ID} (offline, native flatpak-builder)"
cd "${STAGE}"
# --disable-rofiles-fuse: harmless here and dodges FUSE trouble in nested/container
# environments; drop it if your host has working rofiles-fuse and you want the
# extra write-protection during the build.
flatpak-builder \
  --user --force-clean --disable-rofiles-fuse \
  --state-dir="${STATE_DIR}" \
  "${BUILD_DIR}" \
  "${MANIFEST}"

echo
echo ">> build tree: ${BUILD_DIR}/files"
echo ">> to install & run:"
echo "     flatpak-builder --user --force-clean --install --state-dir='${STATE_DIR}' '${BUILD_DIR}' '${STAGE}/${MANIFEST}'"
echo "     flatpak run ${APP_ID}"
