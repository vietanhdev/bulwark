#!/usr/bin/env bash
#
# Bump the project version everywhere it is declared, in one atomic step.
#
# The version lives in SIX places that must never disagree — the release workflow refuses to
# build a tag whose number doesn't match Cargo.toml, and a GUI whose tauri.conf.json,
# package.json and Cargo.toml drift produces artifacts whose filenames and embedded --version
# output contradict each other. Bumping them by hand is how you ship `bulwarkctl_0.5.0.deb`
# that reports `0.4.0`. This script is the single source of truth for "what a version bump
# touches"; if a new file starts carrying the version, add it here, not to your memory.
#
# Usage:
#   scripts/bump-version.sh 0.5.0     # set every declaration to 0.5.0 and sync Cargo.lock
#   scripts/bump-version.sh --check   # verify all declarations already agree (CI-friendly; no writes)
#
# After a bump: review `git diff`, commit (Conventional Commits, e.g. `chore(release): 0.5.0`),
# then cut the release with `git tag v0.5.0 && git push origin v0.5.0`. The tag drives CI.
set -euo pipefail

cd "$(dirname "$0")/.."

# Every place the version is declared, as "file<TAB>human description". Keep this list exhaustive.
CARGO_TOML="Cargo.toml"
CTL_CARGO="crates/bulwarkctl/Cargo.toml"
ROOT_PKG="package.json"
APP_PKG="apps/bulwark-app/package.json"
TAURI_CONF="apps/bulwark-app/src-tauri/tauri.conf.json"
MOCK_APP="apps/bulwark-app/src/mocks/tauri/app.ts"
# Not a declaration this script rewrites — it's a changelog, and only a human can write
# the release notes. But its newest <release> must still name the current version, because
# Flathub renders these notes on the store page: bump without touching it and the app page
# advertises the previous release forever. So it is checked, not set.
METAINFO="packaging/flatpak/com.vietanhdev.bulwark.metainfo.xml"

# Pull the current version out of each file with a pattern specific enough that it can't match
# a dependency's version or an unrelated field.
read_cargo_toml()  { sed -n 's/^version = "\(.*\)"/\1/p' "$CARGO_TOML" | head -1; }
read_ctl_dep()     { sed -n 's/.*bulwark-core = { path = "..\/bulwark-core", version = "\(.*\)".*/\1/p' "$CTL_CARGO" | head -1; }
read_root_pkg()    { sed -n 's/^  "version": "\(.*\)",/\1/p' "$ROOT_PKG" | head -1; }
read_app_pkg()     { sed -n 's/^  "version": "\(.*\)",/\1/p' "$APP_PKG" | head -1; }
read_tauri()       { sed -n 's/^  "version": "\(.*\)",/\1/p' "$TAURI_CONF" | head -1; }
read_mock()        { sed -n 's/^  return "\(.*\)";/\1/p' "$MOCK_APP" | head -1; }
# Newest entry only — <releases> is newest-first, so head -1 is the current release.
read_metainfo()    { sed -n 's/.*<release version="\([^"]*\)".*/\1/p' "$METAINFO" | head -1; }

report() {
  printf '  %-48s %s\n' "$1" "$2"
}

check() {
  local ct cd rp ap tc mk
  ct=$(read_cargo_toml); cd=$(read_ctl_dep); rp=$(read_root_pkg)
  ap=$(read_app_pkg);    tc=$(read_tauri);   mk=$(read_mock)
  echo "Current version declarations:"
  report "$CARGO_TOML (workspace)"           "$ct"
  report "$CTL_CARGO (bulwark-core dep pin)" "$cd"
  report "$ROOT_PKG"                         "$rp"
  report "$APP_PKG"                          "$ap"
  report "$TAURI_CONF"                       "$tc"
  report "$MOCK_APP (screenshot mock)"       "$mk"
  # Every non-empty value must be identical. An empty read means the pattern stopped matching —
  # a file was reformatted — which is itself a failure worth surfacing loudly.
  for v in "$ct" "$cd" "$rp" "$ap" "$tc" "$mk"; do
    if [ -z "$v" ]; then
      echo "ERROR: a version declaration could not be read — a file's format drifted from this script's patterns." >&2
      exit 1
    fi
    if [ "$v" != "$ct" ]; then
      echo "ERROR: version declarations disagree (see above). Run: scripts/bump-version.sh $ct" >&2
      exit 1
    fi
  done
  # Checked separately and last, because the fix is different: you don't re-run this
  # script, you hand-write a changelog entry.
  local mi
  mi=$(read_metainfo)
  report "$METAINFO (newest release entry)" "${mi:-<unreadable>}"
  if [ -z "$mi" ]; then
    echo "ERROR: could not read a <release version=...> from $METAINFO." >&2
    exit 1
  fi
  if [ "$mi" != "$ct" ]; then
    echo "ERROR: $METAINFO tops out at $mi but the version is $ct." >&2
    echo "       Flathub renders these notes on the store page, so shipping without an" >&2
    echo "       entry advertises $mi to every visitor. Add a <release version=\"$ct\">" >&2
    echo "       block (newest first) describing what changed, then re-run --check." >&2
    exit 1
  fi
  echo "OK: all six declarations agree at $ct, and the metainfo changelog matches"
}

if [ "${1:-}" = "--check" ]; then
  check
  exit 0
fi

NEW="${1:-}"
if ! printf '%s' "$NEW" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
  echo "Usage: scripts/bump-version.sh <semver>   (e.g. 0.5.0)   |   scripts/bump-version.sh --check" >&2
  exit 2
fi

OLD=$(read_cargo_toml)
if [ "$OLD" = "$NEW" ]; then
  echo "Already at $NEW — nothing to do (run --check to verify every file agrees)."
  exit 0
fi

# Each edit is asserted: sed silently changing nothing is exactly how a half-bumped tree ships.
edit() { # file  sed-expression  human-label
  local file="$1" expr="$2" label="$3"
  local before after
  before=$(cat "$file")
  after=$(printf '%s' "$before" | sed -E "$expr")
  if [ "$before" = "$after" ]; then
    echo "ERROR: no change made to $file ($label) — its format may have drifted." >&2
    exit 1
  fi
  printf '%s\n' "$after" > "$file"
  report "$file" "$label"
}

echo "Bumping $OLD -> $NEW"
edit "$CARGO_TOML"  "s/^version = \"$OLD\"/version = \"$NEW\"/"                                                              "workspace version"
edit "$CTL_CARGO"   "s/(bulwark-core = \{ path = \"..\/bulwark-core\", version = )\"$OLD\"/\1\"$NEW\"/"                       "bulwark-core dep pin"
edit "$ROOT_PKG"    "s/^(  \"version\": )\"$OLD\",/\1\"$NEW\",/"                                                             "root package.json"
edit "$APP_PKG"     "s/^(  \"version\": )\"$OLD\",/\1\"$NEW\",/"                                                             "app package.json"
edit "$TAURI_CONF"  "s/^(  \"version\": )\"$OLD\",/\1\"$NEW\",/"                                                             "tauri.conf.json"
edit "$MOCK_APP"    "s/^(  return )\"$OLD\";/\1\"$NEW\";/"                                                                   "screenshot mock getVersion"

# Sync Cargo.lock so the workspace crates' recorded versions match. Offline + minimal so this
# neither hits the network nor upgrades unrelated dependencies.
echo "Syncing Cargo.lock..."
cargo update --workspace --offline >/dev/null 2>&1 || cargo update --workspace >/dev/null 2>&1 || true

echo
check
echo
echo "Next:"
echo "  git diff                       # review"
echo "  git commit -am \"chore(release): $NEW\""
echo "  git tag v$NEW && git push origin v$NEW   # drives the release workflow"
