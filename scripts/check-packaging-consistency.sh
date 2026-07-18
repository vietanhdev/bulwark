#!/usr/bin/env bash
# Static consistency checks across the sandboxed packaging manifests.
#
# These exist because of a bug that took hours to find and seconds to prevent: the
# Flatpak opened a transparent, empty window showing
#
#   GDBus.Error:org.freedesktop.portal.Error.NotAllowed: This call is not available inside the sandbox
#
# tauri-plugin-single-instance claims a session-bus name at startup, a sandbox refuses any
# name the manifest has not declared, and the plugin is registered first — so the failure
# lands before there is a UI to report it in. Nothing in the build catches that: the
# manifest is valid, the build succeeds, the binary runs, and the app is simply unusable.
#
# The declared name is derived from tauri.conf.json's *identifier*, not from the Flatpak
# app-id, so the two legitimately differ here and a human reading the manifest cannot tell
# whether it is right. That is precisely the kind of thing a machine should check.
#
# Fast, offline, no build required. Run from CI on every push.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

TAURI_CONF="apps/bulwark-app/src-tauri/tauri.conf.json"
FLATPAK_MANIFEST="packaging/flatpak/com.vietanhdev.bulwark.yaml"
SNAP_MANIFEST="snap/snapcraft.yaml"

fail=0
note() { printf '  %s\n' "$1"; }
bad()  { printf '\033[0;31mFAIL\033[0m %s\n' "$1"; fail=1; }
ok()   { printf '\033[0;32mok\033[0m   %s\n' "$1"; }

# --- 1. single-instance D-Bus name -------------------------------------------------
# Mirrors the plugin's own derivation: identifier, dots and dashes -> underscores.
# https://v2.tauri.app/plugin/single-instance/#usage-in-snap-and-flatpak
IDENTIFIER="$(python3 -c "import json;print(json.load(open('${TAURI_CONF}'))['identifier'])")"
[[ -n "${IDENTIFIER}" ]] || { echo "ERROR: could not read identifier from ${TAURI_CONF}" >&2; exit 1; }
DBUS_NAME="org.$(printf '%s' "${IDENTIFIER}" | tr '.-' '__').SingleInstance"

echo "single-instance D-Bus name derived from identifier '${IDENTIFIER}':"
note "${DBUS_NAME}"
echo

if grep -qF -- "--own-name=${DBUS_NAME}" "${FLATPAK_MANIFEST}"; then
  ok "flatpak manifest owns ${DBUS_NAME}"
else
  bad "flatpak manifest is missing --own-name=${DBUS_NAME}"
  note "Without it the app starts, draws an empty window, and reports a bare GDBus"
  note "NotAllowed error. See ${FLATPAK_MANIFEST}."
fi

if grep -qF -- "--talk-name=${DBUS_NAME}" "${FLATPAK_MANIFEST}"; then
  ok "flatpak manifest talks to ${DBUS_NAME}"
else
  bad "flatpak manifest is missing --talk-name=${DBUS_NAME}"
fi

# Order is load-bearing and invisible: both flags write the same metadata key, so the last
# one wins, and `own` outranks `talk`. own-name listed first is silently downgraded to
# talk — the manifest reads correctly, the build succeeds, and the app stays broken. This
# actually happened; it cost a whole build cycle after the fix was already "in".
OWN_LINE="$(grep -nF -- "--own-name=${DBUS_NAME}" "${FLATPAK_MANIFEST}" | head -1 | cut -d: -f1)"
TALK_LINE="$(grep -nF -- "--talk-name=${DBUS_NAME}" "${FLATPAK_MANIFEST}" | head -1 | cut -d: -f1)"
if [[ -n "${OWN_LINE}" && -n "${TALK_LINE}" ]]; then
  if (( OWN_LINE > TALK_LINE )); then
    ok "--own-name comes after --talk-name (so the grant resolves to 'own')"
  else
    bad "--own-name (line ${OWN_LINE}) must come AFTER --talk-name (line ${TALK_LINE})"
    note "Both write the same key; the last wins. own-name first silently degrades to"
    note "'=talk' and the single-instance plugin cannot claim the name."
  fi
fi

if grep -qF "name: ${DBUS_NAME}" "${SNAP_MANIFEST}"; then
  ok "snap manifest declares ${DBUS_NAME}"
else
  bad "snap manifest is missing a dbus slot/plug named ${DBUS_NAME}"
fi

# --- 2. WebKit rendering workarounds -----------------------------------------------
# WebKitGTK's DMA-BUF renderer and accelerated compositing both fail inside the Flatpak
# sandbox on many drivers, and the symptom is an app that runs perfectly while painting
# nothing. tauri-apps/tauri#8970, #10626.
for var in WEBKIT_DISABLE_DMABUF_RENDERER WEBKIT_DISABLE_COMPOSITING_MODE; do
  if grep -qF -- "--env=${var}=1" "${FLATPAK_MANIFEST}"; then
    ok "flatpak manifest sets ${var}"
  else
    bad "flatpak manifest is missing --env=${var}=1 (blank-window risk)"
  fi
done

# --- 3. the rule pack must travel with the app -------------------------------------
# A packaged build with no rules is a scanner that reports a clean host. Each manifest
# has its own way of shipping the pack, so assert per manifest rather than centrally.
if grep -q "cp -r rules decoders log-rules" "${FLATPAK_MANIFEST}"; then
  ok "flatpak manifest installs the rule pack"
else
  bad "flatpak manifest no longer installs rules/decoders/log-rules"
fi

# --- 4. versions in lockstep --------------------------------------------------------
# bump-version.sh owns this, but it is only run by hand; CI should notice drift even if
# somebody edits a version directly.
if scripts/bump-version.sh --check >/dev/null 2>&1; then
  ok "all version declarations agree"
else
  bad "version declarations disagree — run scripts/bump-version.sh --check"
fi

echo
if [[ ${fail} -eq 0 ]]; then
  echo "packaging consistency: PASS"
else
  echo "packaging consistency: FAIL"
fi
exit ${fail}
