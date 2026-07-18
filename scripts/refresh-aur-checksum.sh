#!/usr/bin/env bash
# Refresh the AUR PKGBUILD/.SRCINFO sha256 against the published source tarball.
#
# Split out from bump-version.sh on purpose: the checksum can only be computed once the tag
# exists on GitHub, which is *after* the bump commit. Putting it in the bump would either
# force a network call into every version change or bake in a checksum for a tarball nobody
# has published yet.
#
# Usage:
#   scripts/refresh-aur-checksum.sh [version]     # default: version from the PKGBUILD
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKGBUILD="${REPO_ROOT}/packaging/aur/PKGBUILD"
SRCINFO="${REPO_ROOT}/packaging/aur/.SRCINFO"

VERSION="${1:-$(sed -n 's/^pkgver=\(.*\)/\1/p' "${PKGBUILD}" | head -1)}"
[[ -n "${VERSION}" ]] || { echo "ERROR: could not determine version" >&2; exit 1; }

URL="https://github.com/vietanhdev/bulwark/archive/refs/tags/v${VERSION}.tar.gz"
echo ">> fetching ${URL}"

TMP="$(mktemp)"
trap 'rm -f "${TMP}"' EXIT
curl -fsSL "${URL}" -o "${TMP}" \
  || { echo "ERROR: could not fetch the tarball — is tag v${VERSION} pushed?" >&2; exit 1; }

SHA="$(sha256sum "${TMP}" | cut -d' ' -f1)"
echo ">> sha256: ${SHA}"

OLD="$(sed -n "s/^sha256sums=('\(.*\)')/\1/p" "${PKGBUILD}" | head -1)"
if [[ "${OLD}" == "${SHA}" ]]; then
  echo ">> already correct — nothing to do"
  exit 0
fi

sed -i -E "s/^sha256sums=\('.*'\)/sha256sums=('${SHA}')/" "${PKGBUILD}"
sed -i -E "s/^\tsha256sums = .*/\tsha256sums = ${SHA}/" "${SRCINFO}"

# Assert, rather than trust sed: a silent no-op here ships a package that fails to install
# for every user with "integrity check failed".
grep -q "${SHA}" "${PKGBUILD}" || { echo "ERROR: PKGBUILD not updated" >&2; exit 1; }
grep -q "${SHA}" "${SRCINFO}"  || { echo "ERROR: .SRCINFO not updated" >&2; exit 1; }

echo ">> updated ${OLD:0:16}… -> ${SHA:0:16}…"
echo
echo ">> verify with a real makepkg before pushing to the AUR:"
echo "     docker run --rm -v \"\$PWD/packaging/aur:/pkg\" archlinux:latest bash -c '"
echo "       pacman -Sy --noconfirm --needed base-devel >/dev/null &&"
echo "       useradd -m b && cp /pkg/PKGBUILD /home/b/ && chown -R b /home/b &&"
echo "       su b -c \"cd /home/b && makepkg --verifysource\"'"
