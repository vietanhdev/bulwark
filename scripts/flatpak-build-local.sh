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
# Overlay untracked packaging bits the manifest + build reference.
mkdir -p "${STAGE}/packaging"
cp -r "${REPO_ROOT}/packaging/flatpak" "${STAGE}/packaging/flatpak"

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
