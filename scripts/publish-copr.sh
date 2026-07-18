#!/usr/bin/env bash
# Publish the Bulwark CLI to Fedora COPR.
#
# Auth: COPR uses an API *token*, never a password. Log in at
# https://copr.fedorainfracloud.org/api/ and save the config block it prints
# verbatim to ~/.config/copr (chmod 600). This script refuses to run without it
# rather than prompting, so no credential is ever typed into a terminal it
# doesn't control.
#
# The SRPM is built inside a Fedora container: rpmbuild isn't present on this
# dev machine, and building it on the same distro that will consume it is the
# only way to know the spec's BuildRequires actually resolve.
#
# Usage:
#   scripts/publish-copr.sh [version]     # default: version from the spec
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="${REPO_ROOT}/packaging/copr/bulwarkctl.spec"
PROJECT="bulwarkctl"

[[ -f "${HOME}/.config/copr" ]] || {
  cat >&2 <<'EOF'
ERROR: no COPR API token at ~/.config/copr

  1. Log in at https://copr.fedorainfracloud.org/api/
  2. Copy the whole [copr-cli] block it displays
  3. Save it to ~/.config/copr, then: chmod 600 ~/.config/copr

The token expires periodically; regenerate it the same way if this starts
failing with a 403.
EOF
  exit 1
}

VERSION="${1:-$(sed -n 's/^Version: *//p' "${SPEC}")}"
[[ -n "${VERSION}" ]] || { echo "ERROR: could not determine version" >&2; exit 1; }

# The spec fetches Source0 from the tag, so the tag must exist on the remote or
# the COPR builder gets a 404 partway through a build that already queued.
git -C "${REPO_ROOT}" ls-remote --tags --exit-code origin "refs/tags/v${VERSION}" >/dev/null 2>&1 \
  || { echo "ERROR: tag v${VERSION} is not pushed to origin — the COPR builder can't fetch it." >&2; exit 1; }

echo ">> building SRPM for bulwarkctl ${VERSION} in a Fedora container"
OUT="${REPO_ROOT}/build/copr"
rm -rf "${OUT}"; mkdir -p "${OUT}"

docker run --rm -v "${SPEC}:/spec/bulwarkctl.spec:ro" -v "${OUT}:/out" fedora:latest bash -euo pipefail -c '
  dnf install -y -q rpm-build rpmdevtools curl >/dev/null
  rpmdev-setuptree
  cp /spec/bulwarkctl.spec ~/rpmbuild/SPECS/
  spectool -g -R ~/rpmbuild/SPECS/bulwarkctl.spec
  rpmbuild -bs ~/rpmbuild/SPECS/bulwarkctl.spec
  cp ~/rpmbuild/SRPMS/*.src.rpm /out/
'

SRPM="$(ls -1 "${OUT}"/*.src.rpm | head -n1)"
echo ">> built ${SRPM##*/}"

command -v copr-cli >/dev/null || { echo "ERROR: copr-cli not installed (pip install --user copr-cli)" >&2; exit 1; }

# Target every currently-active Fedora x86_64 chroot rather than a hardcoded
# list, which silently goes stale every six months when Fedora branches.
mapfile -t CHROOTS < <(copr-cli list-chroots | grep -E '^fedora-([0-9]+)-x86_64$' | sort -V | tail -3)
[[ ${#CHROOTS[@]} -gt 0 ]] || { echo "ERROR: no active fedora x86_64 chroots found" >&2; exit 1; }
echo ">> chroots: ${CHROOTS[*]}"

if ! copr-cli list 2>/dev/null | grep -qx "${PROJECT}"; then
  echo ">> creating COPR project ${PROJECT}"
  # Build the flag list as separate argv entries. "${CHROOTS[@]/#/--chroot }"
  # looks equivalent but embeds the space *inside* one argument, so copr-cli
  # sees a single unrecognized "--chroot fedora-43-x86_64" token and bails.
  CHROOT_ARGS=()
  for c in "${CHROOTS[@]}"; do CHROOT_ARGS+=(--chroot "${c}"); done
  # --enable-net on is REQUIRED, not optional: mock disables builder networking by
  # default, and the spec fetches crates from crates.io during %build. Without it every
  # build fails with "Could not resolve host: index.crates.io".
  copr-cli create "${PROJECT}" \
    --description "Linux host security and misconfiguration scanner (CLI)" \
    --instructions "sudo dnf copr enable $(copr-cli whoami)/${PROJECT} && sudo dnf install bulwarkctl" \
    --enable-net on \
    "${CHROOT_ARGS[@]}"
else
  # Idempotent: an existing project may predate the flag (this cost one failed build).
  copr-cli modify "${PROJECT}" --enable-net on >/dev/null 2>&1 || true
fi

echo ">> submitting build"
copr-cli build "${PROJECT}" "${SRPM}"

echo
echo ">> done. Verify the published package actually installs and runs:"
echo "     docker run --rm fedora:latest bash -c '"
echo "       dnf install -y -q dnf-plugins-core &&"
echo "       dnf copr enable -y \$(copr-cli whoami)/${PROJECT} &&"
echo "       dnf install -y -q bulwarkctl && bulwarkctl --version && bulwarkctl rules list | grep -c BLWK-'"
