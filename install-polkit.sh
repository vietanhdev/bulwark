#!/bin/bash

# Bulwark Polkit Policy Installation Script
# Installs the polkit policy that lets the GUI (bulwark-app) run the privileged subset
# of a scan (e.g. reading /etc/sudoers) via pkexec, without running the whole app as root.
# Mirrors ThinkUtils' install-polkit.sh (https://github.com/vietanhdev/ThinkUtils).

set -euo pipefail

# Resolve paths relative to THIS script, not the caller's working directory. The script runs as
# root (checked below) and installs a privilege-granting polkit action; a CWD-relative source path
# would let `sudo ./install-polkit.sh` from an attacker-seeded directory install a rogue policy.
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
POLICY_FILE="$SCRIPT_DIR/polkit/com.bulwark.policy"
INSTALL_DIR="/usr/share/polkit-1/actions"

echo "Bulwark Polkit Policy Installer"
echo "================================"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

if [ ! -f "$POLICY_FILE" ]; then
    echo "Error: Policy file not found at $POLICY_FILE"
    exit 1
fi

if [ ! -d "$INSTALL_DIR" ]; then
    echo "Error: Polkit not found. Please install polkit first:"
    echo "  Ubuntu/Debian: sudo apt install policykit-1"
    echo "  Fedora: sudo dnf install polkit"
    echo "  Arch: sudo pacman -S polkit"
    exit 1
fi

echo "Installing polkit policy..."
cp "$POLICY_FILE" "$INSTALL_DIR/"
chmod 644 "$INSTALL_DIR/com.bulwark.policy"

echo ""
echo "Polkit policy installed successfully."
echo ""
echo "bulwark-app can now run the privileged subset of a scan (e.g. reading /etc/sudoers)."
echo "You'll be prompted for your admin password each time you run a privileged scan"
echo "(auth_admin — no standing 'run as root without asking' window is left open)."
echo ""
echo "Note: the CLI (bulwarkctl) doesn't use pkexec at all — for headless/SSH use, run"
echo "'sudo bulwarkctl scan --privileged' directly instead."
echo ""
