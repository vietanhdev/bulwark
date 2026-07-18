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
TAURI_CARGO="apps/bulwark-app/src-tauri/Cargo.toml"
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

# Flathub's linter rejects owning a bus name outside the app-id prefix
# (finish-args-own-name-...), and the name above comes from the identifier, so the
# identifier and the Flatpak app-id have to agree. They did not until 0.8.6 — the app-id
# said vietanhdev and the identifier said vietanhnv — and the submission failed lint.
APP_ID="$(sed -n 's/^app-id: *//p' "${FLATPAK_MANIFEST}" | head -1)"
if [[ "${APP_ID}" == "${IDENTIFIER}" ]]; then
  ok "tauri identifier matches the Flatpak app-id (${APP_ID})"
else
  bad "tauri identifier '${IDENTIFIER}' != Flatpak app-id '${APP_ID}'"
  note "Flathub rejects owning a D-Bus name outside the app-id, and that name is derived"
  note "from the identifier — so these must be equal for the submission to pass lint."
fi


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

# --- 2. the webview must be able to load at all --------------------------------------
# The one that actually mattered. GLib installs the portal-backed proxy resolver and
# network monitor inside every Flatpak, WebKit calls them while loading the page, and
# xdg-desktop-portal refuses with "This call is not available inside the sandbox" unless
# xdp_app_info_has_network() — which is true only with --share=network. Without it the
# app starts, setup() completes, the WebKit process spawns, and the UI never renders.
if grep -qE '^\s*-\s*--share=network\s*$' "${FLATPAK_MANIFEST}"; then
  ok "flatpak manifest shares network (portal proxy-resolver calls succeed)"
else
  bad "flatpak manifest is missing --share=network"
  note "WebKit cannot load even a local page without it: the portal proxy-resolver and"
  note "network-monitor calls fail, and the UI silently never renders."
fi

# WEBKIT_DISABLE_COMPOSITING_MODE is deliberately NOT asserted: it disables the path that
# `transparent: true` depends on, and none of the surveyed Tauri Flathub apps set it.
if grep -qF -- "--env=WEBKIT_DISABLE_DMABUF_RENDERER=1" "${FLATPAK_MANIFEST}"; then
  ok "flatpak manifest sets WEBKIT_DISABLE_DMABUF_RENDERER"
else
  bad "flatpak manifest is missing --env=WEBKIT_DISABLE_DMABUF_RENDERER=1"
fi

# --- 3. production builds must enable custom-protocol --------------------------------
# The single worst bug of this whole packaging effort. Tauri's build script computes
#   let dev = !custom_protocol;
# so a build WITHOUT the `custom-protocol` feature is a *dev* build: the app loads
# `devUrl` (http://localhost:1420) instead of the assets embedded from `frontendDist`.
# It compiles, installs, starts, resolves its rule pack, completes setup — and then shows
# an empty window, because nothing is listening on the dev port on a user's machine.
#
# `cargo tauri build` enables the feature implicitly, so the .deb/.rpm/AppImage were always
# fine. The Flatpak and Snap invoke plain `cargo build --release`, and both shipped a GUI
# that could not possibly render. Any packaging that builds the app with bare cargo must
# pass this feature.
for m in "${FLATPAK_MANIFEST}" "${SNAP_MANIFEST}"; do
  if grep -qE "cargo build .*-p bulwark-app" "${m}"; then
    if grep -qE "cargo build .*-p bulwark-app.*--features custom-protocol" "${m}"; then
      ok "$(basename "${m}") builds bulwark-app with --features custom-protocol"
    else
      bad "$(basename "${m}") builds bulwark-app WITHOUT --features custom-protocol"
      note "That produces a dev build which loads devUrl and renders an empty window."
    fi
  fi
done

# And the feature has to exist, or the flag above is a build error rather than a fix.
if grep -qF 'custom-protocol = ["tauri/custom-protocol"]' "${TAURI_CARGO}"; then
  ok "src-tauri/Cargo.toml defines the custom-protocol feature"
else
  bad "src-tauri/Cargo.toml does not define custom-protocol = [\"tauri/custom-protocol\"]"
fi

# --- 4. the rule pack must travel with the app -------------------------------------
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
