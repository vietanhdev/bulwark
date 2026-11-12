#!/usr/bin/env bash
# Build snap/snapcraft.yaml on a GitHub-hosted runner, in an LXD container, and report the
# path of the .snap as the step output `snap`.
#
# This replaces snapcore/action-build. Its newest release (v1.3.0) still declares the Node 20
# runtime GitHub has deprecated, so every run carried a warning that only upstream could
# remove, and it passes snapcraft two manifest flags snapcraft itself reports as deprecated.
# What the action did is a handful of commands, kept here in the order it ran them.
#
# CI only: it changes the runner's firewall policy and group membership.
set -euo pipefail

if [ -z "${GITHUB_ACTIONS:-}" ]; then
  echo "build-snap-ci.sh is for CI runners (it reconfigures the host). Locally: snapcraft pack" >&2
  exit 1
fi

user=$(id -un)

# snapd refuses to work when / is not owned by root, which some runner images get wrong.
sudo chown root:root /

# Docker on the runner sets the FORWARD chain to DROP, which leaves LXD containers without
# network, and the build downloads its toolchain.
sudo iptables -P FORWARD ACCEPT

sudo groupadd --force --system lxd
sudo usermod --append --groups lxd "$user"
if [ -x /snap/bin/lxd ]; then
  sudo snap refresh lxd || true
else
  sudo snap install lxd
fi
sudo lxd init --auto

[ -x /snap/bin/snapcraft ] || sudo snap install --classic snapcraft
/snap/bin/snapcraft --version

# `sudo -u` starts a fresh session, so the lxd group added above applies without logging in again.
sudo -u "$user" -E env SNAPCRAFT_BUILD_ENVIRONMENT=lxd /snap/bin/snapcraft pack --verbose

shopt -s nullglob
snaps=(./*.snap)
if [ "${#snaps[@]}" -ne 1 ]; then
  echo "::error::expected exactly one .snap in $PWD, found ${#snaps[@]}: ${snaps[*]:-none}" >&2
  exit 1
fi
snap="$PWD/${snaps[0]#./}"
ls -l "$snap"
echo "snap=$snap" >> "$GITHUB_OUTPUT"
