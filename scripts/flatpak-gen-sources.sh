#!/usr/bin/env bash
# Generate the offline dependency manifests the Flatpak build needs:
#   packaging/flatpak/cargo-sources.json   (from Cargo.lock)
#   packaging/flatpak/node-sources.json    (from apps/bulwark-app/package-lock.json)
#
# Flatpak (like Launchpad) builds with NO network, so both cargo and npm deps must
# be declared up front. This uses the upstream flatpak-builder-tools generators.
# Run it whenever Cargo.lock or package-lock.json changes, and DO commit the two
# generated JSON files (they're what makes the offline build reproducible).
#
# Requires network + python3. The generators pull their own python deps; if they
# fail on imports, `pipx install` them or run inside a venv (see errors below).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
OUT="$REPO_ROOT/packaging/flatpak"

command -v python3 >/dev/null || { echo "ERROR: python3 required" >&2; exit 1; }

# Fetch the generators (cached under target/).
TOOLS_DIR="$REPO_ROOT/target/flatpak-builder-tools"
if [[ ! -d "$TOOLS_DIR/.git" ]]; then
  echo ">> cloning flatpak-builder-tools"
  git clone --depth 1 https://github.com/flatpak/flatpak-builder-tools "$TOOLS_DIR"
else
  echo ">> updating flatpak-builder-tools"
  git -C "$TOOLS_DIR" pull --ff-only || true
fi

echo ">> generating cargo-sources.json from Cargo.lock"
# flatpak-cargo-generator needs python 'aiohttp' + 'tomlkit' (and 'toml' on older
# versions). Test for ALL of them — a system that has aiohttp but not tomlkit must
# still fall back to the venv, or the generator dies with ModuleNotFoundError.
python3 - <<'PY' 2>/dev/null || PIP_NEEDED=1
import aiohttp, tomlkit  # noqa
PY
if [[ "${PIP_NEEDED:-0}" == "1" ]]; then
  echo "   (installing aiohttp/tomlkit/toml into a venv)"
  python3 -m venv "$REPO_ROOT/target/flatpak-venv"
  # shellcheck disable=SC1091
  source "$REPO_ROOT/target/flatpak-venv/bin/activate"
  pip install --quiet aiohttp tomlkit toml
fi
python3 "$TOOLS_DIR/cargo/flatpak-cargo-generator.py" \
  "$REPO_ROOT/Cargo.lock" -o "$OUT/cargo-sources.json"

echo ">> generating node-sources.json from apps/bulwark-app/package-lock.json"
# flatpak-node-generator is now a python package (node/flatpak_node_generator);
# run it as a module with node/ on PYTHONPATH. It targets npm lockfile v2/v3.
PYTHONPATH="$TOOLS_DIR/node" python3 -m flatpak_node_generator npm \
  "$REPO_ROOT/apps/bulwark-app/package-lock.json" \
  -o "$OUT/node-sources.json"

echo
echo "Wrote:"
ls -lh "$OUT/cargo-sources.json" "$OUT/node-sources.json" 2>/dev/null | awk '{print "  " $5, $NF}'
echo "Commit these two files. Then build with:"
echo "  flatpak-builder --user --install --force-clean build-dir packaging/flatpak/com.vietanhnv.bulwark.yaml"
