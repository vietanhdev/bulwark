#!/usr/bin/env bash
# Build a signed Debian *source* package for the Bulwark CLI, ready to `dput` to a
# Launchpad PPA. See packaging/README.md for the one-time Launchpad account setup
# and the full publish workflow.
#
# Why this exists: Launchpad's build farm compiles the .deb itself, on machines
# with NO network. So we cannot rely on `cargo` fetching crates at build time.
# This script assembles a source tarball that already contains every dependency
# (vendored) plus a .cargo/config.toml redirecting crates-io to it, so the build
# on Launchpad runs fully offline. The premise is validated end-to-end: the same
# trimmed+vendored tree builds a working bulwarkctl with CARGO_NET_OFFLINE=true.
#
# Usage:
#   scripts/build-ppa-source.sh [--series noble] [--ppa-rev 1] [--sign-key KEYID]
#   scripts/build-ppa-source.sh --series noble --sign-key ABCD1234   # signed, uploadable
#   scripts/build-ppa-source.sh --series noble                       # unsigned, for local test
#
# Then, for a signed build:
#   dput ppa:vietanhng/bulwark <build>/bulwark_<version>_source.changes
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---- args ---------------------------------------------------------------------
SERIES="noble"          # target Ubuntu series (noble, oracular, plucky, jammy, ...)
PPA_REV="1"             # bump when re-uploading the SAME upstream version to the SAME series
SIGN_KEY=""             # gpg key id/email; empty => unsigned (-us -uc), NOT uploadable
MAINTAINER="Viet Anh Nguyen <vietanh.dev@gmail.com>"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --series)   SERIES="$2"; shift 2 ;;
    --ppa-rev)  PPA_REV="$2"; shift 2 ;;
    --sign-key) SIGN_KEY="$2"; shift 2 ;;
    -h|--help)  grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

for tool in git cargo dpkg-buildpackage dpkg-source python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: '$tool' not found on PATH" >&2; exit 1; }
done

# ---- version ------------------------------------------------------------------
# Single source of truth: the workspace [workspace.package] version.
UPSTREAM="$(python3 - <<'PY'
import re
s=open("Cargo.toml").read()
m=re.search(r'\[workspace\.package\][^\[]*?version\s*=\s*"([^"]+)"', s, re.S)
print(m.group(1))
PY
)"
# Launchpad-friendly version: 0.7.0-0ppa1~noble1. The ~seriesN suffix sorts BELOW
# the plain 0.7.0-0ppa1, so the same upstream can coexist across series and a
# later series always upgrades cleanly.
DEB_VERSION="${UPSTREAM}-0ppa${PPA_REV}~${SERIES}1"
echo ">> upstream=${UPSTREAM}  series=${SERIES}  deb=${DEB_VERSION}"

# ---- staging ------------------------------------------------------------------
BUILD_DIR="${REPO_ROOT}/target/ppa"
SRC_DIR="${BUILD_DIR}/bulwark-${UPSTREAM}"
rm -rf "$SRC_DIR"
mkdir -p "$SRC_DIR"

echo ">> exporting clean tree (git archive HEAD)"
git archive --format=tar HEAD | tar -x -C "$SRC_DIR"
cp Cargo.lock "$SRC_DIR/"

echo ">> trimming workspace to bulwark-core + bulwarkctl (drops the Tauri/agent members)"
python3 - "$SRC_DIR/Cargo.toml" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
s = re.sub(r'members\s*=\s*\[[^\]]*\]',
           'members = [\n    "crates/bulwark-core",\n    "crates/bulwarkctl",\n]',
           s, count=1)
open(p, "w").write(s)
PY

echo ">> vendoring dependencies (needs network; runs on THIS machine, not the builder)"
( cd "$SRC_DIR" && cargo vendor --versioned-dirs --locked vendor >/dev/null 2>&1 \
    || cargo vendor --versioned-dirs vendor >/dev/null )
mkdir -p "$SRC_DIR/.cargo"
cat > "$SRC_DIR/.cargo/config.toml" <<'EOF'
# Written by scripts/build-ppa-source.sh. Redirects all crates-io lookups to the
# vendored copy so the Launchpad builder never touches the network.
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF
echo ">> vendor size: $(du -sh "$SRC_DIR/vendor" | cut -f1)"

# ---- orig tarball (upstream = everything EXCEPT debian/) -----------------------
# DETERMINISTIC: the same upstream version keys ONE orig filename
# (bulwark_<v>.orig.tar.xz) shared across every series' upload. Launchpad rejects
# a re-uploaded orig whose bytes differ from the first, so a non-reproducible
# tarball breaks all series after the first ("already exists but uploaded version
# has different contents"). Fixed sort/mtime/owner + xz -T0-off make every run
# byte-identical. (cargo vendor is itself deterministic for a fixed Cargo.lock.)
ORIG="${BUILD_DIR}/bulwark_${UPSTREAM}.orig.tar.xz"
echo ">> creating $ORIG (deterministic)"
rm -f "$ORIG"
tar --create \
    --sort=name \
    --mtime='2020-01-01 00:00:00Z' \
    --owner=0 --group=0 --numeric-owner \
    --pax-option='exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime' \
    --exclude='./debian' \
    -C "$BUILD_DIR" \
    --transform "s,^\./,bulwark-${UPSTREAM}/," \
    -C "$SRC_DIR" . \
  | xz -6 -T1 > "$ORIG"

# ---- debian/ packaging + changelog -------------------------------------------
echo ">> installing debian/ packaging"
cp -r "${REPO_ROOT}/packaging/ppa/debian" "$SRC_DIR/debian"
chmod +x "$SRC_DIR/debian/rules"

# devscripts (dch) may be absent; write the changelog directly. RFC2822 date.
CHANGELOG_DATE="$(date -R)"
cat > "$SRC_DIR/debian/changelog" <<EOF
bulwark (${DEB_VERSION}) ${SERIES}; urgency=medium

  * PPA build of Bulwark CLI ${UPSTREAM} for ${SERIES}.
    Dependencies vendored for the offline Launchpad builder.

 -- ${MAINTAINER}  ${CHANGELOG_DATE}
EOF

# ---- build the source package -------------------------------------------------
echo ">> building source package"
SIGN_ARGS=(-us -uc)
if [[ -n "$SIGN_KEY" ]]; then
  SIGN_ARGS=(--sign-key="$SIGN_KEY")
fi
# -S: source only.  -sa: include the .orig tarball in the upload (first time for
# this upstream version).  -d: don't check build-deps on this machine.
( cd "$SRC_DIR" && dpkg-buildpackage -S -sa -d "${SIGN_ARGS[@]}" )

echo
echo "=============================================================================="
echo "Source package built under: ${BUILD_DIR}"
ls -1 "${BUILD_DIR}"/bulwark_"${DEB_VERSION}"* 2>/dev/null || true
if [[ -n "$SIGN_KEY" ]]; then
  echo
  echo "Upload with:"
  echo "  dput ppa:vietanhng/bulwark ${BUILD_DIR}/bulwark_${DEB_VERSION}_source.changes"
else
  echo
  echo "UNSIGNED build (local test only). Re-run with --sign-key <KEYID> to upload."
fi
echo "=============================================================================="
