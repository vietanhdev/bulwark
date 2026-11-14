#!/usr/bin/env bash
# Rehearse Launchpad's build of the desktop PPA source (`bulwark-desktop`), then the upgrade a
# user takes. Needs Docker and the network (for the build image and the release .debs), but the
# build itself runs with the network cut, as on Launchpad.
#
#   1. Unpack the .dsc in a clean ubuntu:<series> container, install only its Build-Depends,
#      and snapshot that container (`unshare -n` is not available inside a plain container).
#   2. From the snapshot, `dpkg-buildpackage -b` with `--network none`.
#   3. In a fresh ubuntu:<series>: install the GitHub release's bulwark-desktop .deb and the
#      bulwarkctl .deb of the same upstream version, then install the PPA's `bulwark` .deb over
#      them. Asserts that apt treats it as an upgrade, that nothing conflicts with bulwarkctl,
#      that both binaries report the upstream version, and that the installed layout is the one
#      the GUI resolves at run time.
#   4. With --launch: the real GUI launch test (scripts/test-gui-packages-docker.sh) against the
#      built .deb on the same series.
#
# Usage:
#   scripts/test-ppa-desktop-build.sh --series resolute --dsc target/ppa-desktop/bulwark-desktop_<v>.dsc [--launch]
#
# Output: the binary packages land in target/ppa-desktop-out/<series>/.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERIES="" DSC="" LAUNCH=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --series) SERIES="$2"; shift 2 ;;
    --dsc)    DSC="$2"; shift 2 ;;
    --launch) LAUNCH=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$SERIES" && -f "$DSC" ]] || { echo "usage: $0 --series S --dsc FILE.dsc [--launch]" >&2; exit 2; }

DSC_DIR="$(cd "$(dirname "$DSC")" && pwd)"
DSC_NAME="$(basename "$DSC")"
VERSION="$(awk '$1 == "Version:" {print $2}' "$DSC")"
UPSTREAM="${VERSION%%-*}"
case "$(uname -m)" in
  x86_64)  DEB_ARCH=amd64 ;;
  aarch64) DEB_ARCH=arm64 ;;
  *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;;
esac
OUT="${REPO_ROOT}/target/ppa-desktop-out/${SERIES}"
IMAGE_TAG="bulwark-ppa-desktop-deps:${SERIES}"
rm -rf "$OUT"; mkdir -p "$OUT"
# Same budget as the rest of this repo's Docker builds: a full Tauri compile on every core makes
# a workstation unusable.
CPUS="${CPUS:-4}"

echo ">> [1/4] ${SERIES}: Build-Depends of ${DSC_NAME}"
CID="ppa-desktop-deps-${SERIES}-$$"
docker rm -f "$CID" >/dev/null 2>&1 || true
docker run --name "$CID" -v "${DSC_DIR}:/src:ro" "ubuntu:${SERIES}" bash -c "
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends build-essential dpkg-dev debhelper devscripts equivs >/dev/null
  mkdir /w && cd /w
  dpkg-source -x /src/${DSC_NAME} src >/dev/null
  cd src
  mk-build-deps -i -r -t 'apt-get -y -qq --no-install-recommends' debian/control >/dev/null 2>&1
  dpkg-checkbuilddeps
"
docker commit "$CID" "$IMAGE_TAG" >/dev/null
docker rm "$CID" >/dev/null

echo ">> [2/4] ${SERIES}: offline binary build (--network none)"
if ! docker run --rm --network none --cpus="$CPUS" -e CARGO_BUILD_JOBS="$CPUS" \
    -v "${OUT}:/out" "$IMAGE_TAG" bash -c "
      set -e
      cd /w/src
      dpkg-buildpackage -b -us -uc > /out/build.log 2>&1
      cp ../*.deb /out/
      chown -R $(id -u):$(id -g) /out"; then
  tail -40 "${OUT}/build.log" >&2
  echo "ERROR: offline build failed on ${SERIES}; full log: ${OUT}/build.log" >&2
  exit 1
fi
PPA_DEB="$(ls "${OUT}"/bulwark_*_"${DEB_ARCH}".deb)"
echo "   built $(basename "$PPA_DEB")"
# The fields an upgrade from the release .deb depends on.
[[ "$(dpkg-deb -f "$PPA_DEB" Package)" == bulwark ]] || { echo "ERROR: package is not named 'bulwark'" >&2; exit 1; }
dpkg --compare-versions "$(dpkg-deb -f "$PPA_DEB" Version)" gt "$UPSTREAM" \
  || { echo "ERROR: $(dpkg-deb -f "$PPA_DEB" Version) does not sort above the release's $UPSTREAM" >&2; exit 1; }

echo ">> [3/4] ${SERIES}: install over the v${UPSTREAM} release .debs"
REL="${OUT}/release"; mkdir -p "$REL"
gh release download "v${UPSTREAM}" -R vietanhdev/bulwark -D "$REL" --clobber \
  -p "bulwark-desktop_${UPSTREAM}_${DEB_ARCH}.deb" -p "bulwarkctl_${UPSTREAM}_${DEB_ARCH}.deb"
docker run --rm -v "${OUT}:/out:ro" "ubuntu:${SERIES}" bash -c "
  set -eu
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends /out/release/bulwark-desktop_${UPSTREAM}_${DEB_ARCH}.deb \
    /out/release/bulwarkctl_${UPSTREAM}_${DEB_ARCH}.deb >/dev/null
  echo \"   release:  bulwark \$(dpkg-query -W -f='\${Version}' bulwark), bulwarkctl \$(dpkg-query -W -f='\${Version}' bulwarkctl)\"
  apt-get install -y --no-install-recommends /out/$(basename "$PPA_DEB") > /tmp/apt.log 2>&1 \
    || { cat /tmp/apt.log; echo 'FAIL: the PPA package did not install over the release'; exit 1; }
  grep -q 'Unpacking bulwark .*over (${UPSTREAM})' /tmp/apt.log \
    || { cat /tmp/apt.log; echo 'FAIL: not installed as an upgrade of the release package'; exit 1; }
  test \"\$(dpkg-query -W -f='\${Version}' bulwark)\" = '${VERSION}'
  test \"\$(dpkg-query -W -f='\${Status}' bulwarkctl)\" = 'install ok installed'
  echo \"   upgraded: bulwark \$(dpkg-query -W -f='\${Version}' bulwark), bulwarkctl still installed\"
  echo \"   \$(bulwark-app --version) | \$(bulwark --version) | \$(bulwarkctl --version)\"
  test \"\$(bulwark-app --version)\" = 'bulwark-app ${UPSTREAM}'
  test \"\$(bulwark --version)\" = 'bulwarkctl ${UPSTREAM}'
  test \"\$(find /usr/lib/bulwark/rules -name '*.yaml' | wc -l)\" -ge 50
  test -s /usr/share/polkit-1/actions/com.bulwark.policy
  grep -q '^Exec=bulwark-app\$' /usr/share/applications/bulwark.desktop
  test -s /usr/share/icons/hicolor/128x128/apps/bulwark-app.png
  test \"\$(bulwark rules list --rules-dir /usr/lib/bulwark/rules | grep -c '^BLWK-')\" -gt 0
  # The release package's files are gone or replaced: dpkg owns every path once, by bulwark.
  dpkg -L bulwark | grep -qx /usr/bin/bulwark-app
  echo '   upgrade OK'
"

if [[ "$LAUNCH" == 1 ]]; then
  echo ">> [4/4] ${SERIES}: GUI launch test of the PPA .deb"
  LA="${OUT}/launch"; rm -rf "$LA"; mkdir -p "$LA"
  # The launch harness matches the release's file name.
  cp "$PPA_DEB" "${LA}/bulwark-desktop_${UPSTREAM}_${DEB_ARCH}.deb"
  ASSETS="$LA" "${REPO_ROOT}/scripts/test-gui-packages-docker.sh" "deb:ubuntu:${SERIES}"
else
  echo ">> [4/4] skipped GUI launch test (pass --launch)"
fi
echo ">> ${SERIES}: OK"
