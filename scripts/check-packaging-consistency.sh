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
# tauri-plugin-single-instance claims <identifier>.SingleInstance on the session bus (since
# plugin 2.4; before that it was "org." + the identifier with underscores). This check used to
# mirror the OLD derivation and assert that both manifests declared it, long after the plugin
# had stopped asking for that name: a stale permission, verified on every run. Found only
# when the Snap Store rejected the upload for carrying it.
#
# So this section now asserts what is actually true of each channel:
#   - Flatpak: an app may own its own app-id and anything under it without a finish-arg, so
#     the name needs no declaration PROVIDED identifier == app-id. An --own-name for it is
#     then either stale or redundant, and Flathub's linter rejects one outside the app-id.
#   - Snap (classic): the store refuses any plugs/slots on a classic snap, and an unconfined
#     app needs none.
# What proves the name is really claimed is not this grep but the launch tests, which start
# the app twice on a session bus (scripts/test-snap-gui.sh, publish-flatpak.yml).
IDENTIFIER="$(python3 -c "import json;print(json.load(open('${TAURI_CONF}'))['identifier'])")"
[[ -n "${IDENTIFIER}" ]] || { echo "ERROR: could not read identifier from ${TAURI_CONF}" >&2; exit 1; }
DBUS_NAME="${IDENTIFIER}.SingleInstance"

echo "single-instance D-Bus name (identifier '${IDENTIFIER}'):"
note "${DBUS_NAME}"
echo

# The derivation above holds only while the app does not name the bus itself.
if grep -rqE '\.dbus_id\(' apps/bulwark-app/src-tauri/src; then
  bad "the app sets a custom dbus_id, so the single-instance name is no longer ${DBUS_NAME}"
  note "Update this check and the manifests to the name the app now asks for."
else
  ok "the app uses the plugin's default bus name"
fi

APP_ID="$(sed -n 's/^app-id: *//p' "${FLATPAK_MANIFEST}" | head -1)"
if [[ "${APP_ID}" == "${IDENTIFIER}" ]]; then
  ok "tauri identifier matches the Flatpak app-id (${APP_ID}), so ${DBUS_NAME} is the app's own"
else
  bad "tauri identifier '${IDENTIFIER}' != Flatpak app-id '${APP_ID}'"
  note "Flatpak lets an app own only names under its app-id without a finish-arg, and"
  note "Flathub rejects an --own-name outside it. With these different, a second launch"
  note "cannot reach the first, and the fix is to make them equal, not to add a permission."
fi

if grep -qE -- '^[[:space:]]*-[[:space:]]+--(own|talk)-name=.*SingleInstance' "${FLATPAK_MANIFEST}"; then
  bad "flatpak manifest declares a SingleInstance bus name"
  note "The app's name (${DBUS_NAME}) is under its own app-id and needs no finish-arg."
  note "Any other spelling is one the app does not ask for (the pre-2.4 plugin name was"
  note "org.<identifier_with_underscores>.SingleInstance) and fails Flathub's lint."
else
  ok "flatpak manifest declares no SingleInstance name (none is needed under the app-id)"
fi

SNAP_BUS="$(python3 - "${SNAP_MANIFEST}" <<'PYEOF'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1]))
found = []
for key in ("plugs", "slots"):
    if m.get(key):
        found.append(key)
    for name, app in (m.get("apps") or {}).items():
        if (app or {}).get(key):
            found.append(f"apps.{name}.{key}")
print(m.get("confinement", "unset"), ",".join(found))
PYEOF
)"
SNAP_CONFINEMENT="${SNAP_BUS%% *}"
SNAP_DECLARED="${SNAP_BUS#* }"
if [[ "${SNAP_CONFINEMENT}" != "classic" ]]; then
  bad "snapcraft.yaml is no longer classic (${SNAP_CONFINEMENT}): this check knows nothing about its bus access"
  note "A confined snap must declare a dbus slot and plug named ${DBUS_NAME}; teach this check."
elif [[ -n "${SNAP_DECLARED}" ]]; then
  bad "snapcraft.yaml is classic and declares ${SNAP_DECLARED}"
  note "The Snap Store rejects the upload: \"confinement 'classic' not allowed with plugs/slots\"."
else
  ok "snapcraft.yaml is classic and declares no plugs or slots"
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

# Neither WEBKIT_DISABLE_* variable is required, and shipping them has a cost: DMABUF
# forces WebKit onto a slower CPU rendering path (visibly sluggish UI), COMPOSITING_MODE
# breaks `transparent: true`. Both were added on a guess and removed once the real cause
# (--share=network + custom-protocol) was found. Warn rather than fail, so re-adding one is
# a deliberate, noticed act.
for v in WEBKIT_DISABLE_DMABUF_RENDERER WEBKIT_DISABLE_COMPOSITING_MODE; do
  if grep -qF -- "--env=${v}=1" "${FLATPAK_MANIFEST}"; then
    note "NOTE: ${v} is set — it slows rendering for every user. Keep it only with evidence."
  fi
done

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
#
# A manifest that builds through `tauri build` is fine by construction (the snap does, since it
# ships the AppImage bundle). One that does neither is a manifest this check cannot vouch for.
for m in "${FLATPAK_MANIFEST}" "${SNAP_MANIFEST}"; do
  if grep -qE "cargo build .*-p bulwark-app" "${m}"; then
    if grep -qE "cargo build .*-p bulwark-app.*--features custom-protocol" "${m}"; then
      ok "$(basename "${m}") builds bulwark-app with --features custom-protocol"
    else
      bad "$(basename "${m}") builds bulwark-app WITHOUT --features custom-protocol"
      note "That produces a dev build which loads devUrl and renders an empty window."
    fi
  elif grep -qE "^[[:space:]]*([A-Z_]+=[^[:space:]]+ )*(npx|npm run|cargo) tauri build" "${m}"; then
    ok "$(basename "${m}") builds the app through 'tauri build' (custom-protocol is implied)"
  else
    bad "$(basename "${m}") builds the app neither with 'tauri build' nor with --features custom-protocol"
    note "A bare cargo build of bulwark-app is a dev build: it loads devUrl and renders an empty window."
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

# --- 5. architectures in lockstep ----------------------------------------------------
# The same failure shape as the version drift above, one axis over. Every distro channel
# declares its own supported architectures, in its own syntax, in a different file — and
# nothing compared them, so widening one and forgetting another was a silent no-op. The
# symptom is not a build error: AUR/COPR simply never build the arch for the users who
# needed it, and nobody finds out because a package that was never built cannot fail.
#
# release.yml's build matrix is the single source of truth, because it is the thing that
# actually produces artifacts. Adding an arch there and forgetting these files is now a
# red check rather than a discovery months later.
RELEASE_WF=".github/workflows/release.yml"

read -r CLI_ARCHES GUI_ARCHES <<<"$(python3 - "${RELEASE_WF}" <<'PY'
import sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
inc = wf["jobs"]["linux"]["strategy"]["matrix"]["include"]
cli = sorted(e["arch"] for e in inc)
gui = sorted(e["arch"] for e in inc if e.get("gui"))
print(",".join(cli), ",".join(gui))
PY
)"
[[ -n "${CLI_ARCHES}" ]] || { echo "ERROR: could not read the build matrix from ${RELEASE_WF}" >&2; exit 1; }

echo
echo "architectures declared by the release build matrix:"
note "CLI: ${CLI_ARCHES}"
note "GUI: ${GUI_ARCHES}"
echo

# Normalise an arbitrary whitespace/quote-separated arch list to a sorted comma list, so a
# reordering or a quoting-style change is not reported as drift.
norm_arches() { tr -d "'\"" | tr ' \t' '\n' | sed '/^$/d' | sort -u | paste -sd, -; }

cmp_arches() {
  local label="$1" got="$2" want="$3"
  if [[ "${got}" == "${want}" ]]; then
    ok "${label} declares ${got}"
  else
    bad "${label} declares '${got}' but the release matrix builds '${want}'"
    note "An arch the release builds but this channel omits is simply never shipped there;"
    note "an arch it claims but the release never builds is a package that cannot exist."
  fi
}

# AUR: bash array, e.g. arch=('x86_64' 'aarch64')
PKGBUILD_ARCHES="$(sed -n "s/^arch=(\(.*\))$/\1/p" packaging/aur/PKGBUILD | norm_arches)"
cmp_arches "AUR PKGBUILD" "${PKGBUILD_ARCHES}" "${CLI_ARCHES}"

# .SRCINFO is GENERATED from the PKGBUILD by `makepkg --printsrcinfo`, and is what the AUR
# actually reads. Editing the PKGBUILD without regenerating it is the single most common AUR
# packaging mistake: the PKGBUILD looks right and the AUR keeps serving the old metadata.
SRCINFO_ARCHES="$(sed -n 's/^[[:space:]]*arch = //p' packaging/aur/.SRCINFO | norm_arches)"
cmp_arches ".SRCINFO" "${SRCINFO_ARCHES}" "${CLI_ARCHES}"
if [[ "${SRCINFO_ARCHES}" != "${PKGBUILD_ARCHES}" ]]; then
  note "regenerate it: cd packaging/aur && makepkg --printsrcinfo > .SRCINFO"
fi

# COPR: rpm spec, space-separated after the tag.
SPEC_ARCHES="$(sed -n 's/^ExclusiveArch:[[:space:]]*//p' packaging/copr/bulwarkctl.spec | norm_arches)"
cmp_arches "COPR spec ExclusiveArch" "${SPEC_ARCHES}" "${CLI_ARCHES}"

# Flathub ships the GUI, so it tracks the GUI arch list rather than the CLI one — but it is
# checked as a SUBSET, not for equality, and the asymmetry is the point.
#
# Flathub BUILDS every arch named in only-arches, on its own infrastructure, from the Flatpak
# manifest's own offline cargo/node sources. Our release pipeline proving that the .deb GUI
# builds and launches on aarch64 therefore does NOT prove the Flatpak will: different build
# system, different runtime, different inputs. Claiming an arch there before one has actually
# been built turns an untested target into a failed submission.
#
# So: naming an arch Flathub that the release does not build is a hard error (that package
# cannot exist), while omitting one is a legitimate per-channel decision — reported, so it
# stays a visible choice rather than something quietly forgotten.
# The PPA is the one channel that is dual-arch without declaring either arch by name:
# Launchpad builds whatever the series enables, driven by `Architecture: any`. That is correct,
# but only while it stays `any` — narrowing it to `amd64` would silently stop producing arm64
# builds with nothing else in the repo changing. Assert the mechanism rather than a list.
PPA_CONTROL="packaging/ppa/debian/control"
if grep -qE '^Architecture:[[:space:]]*any[[:space:]]*$' "${PPA_CONTROL}"; then
  ok "PPA debian/control is Architecture: any (Launchpad builds every enabled arch)"
else
  bad "PPA debian/control is not 'Architecture: any'"
  note "Launchpad derives the PPA's architectures from this field alone. Anything narrower"
  note "silently stops producing builds for the arches the download page advertises."
fi

# The snap declares its arches explicitly so the restriction is reviewable. Checked for
# *presence and subset*, not equality: the snap is deliberately amd64-only (classic confinement
# is unapproved, so the channel publishes nothing), but it must never claim an arch the release
# does not build a GUI for. Without that key snapcraft silently builds host-arch-only,
# which is how this was an undeclared decision for as long as it was.
SNAP_ARCHES="$(python3 - "${SNAP_MANIFEST}" <<'PY'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1]))
# core24 declares `platforms:` (a map keyed by arch); core22 declares `architectures:` (a list
# of build-on/build-for entries). Read whichever the manifest's base uses.
arches = set(m.get("platforms") or {})
for entry in m.get("architectures") or []:
    if isinstance(entry, str):
        arches.add(entry)
        continue
    target = entry.get("build-for") or entry.get("build-on") or []
    arches.update([target] if isinstance(target, str) else target)
# snapcraft spells Debian arch names here; map to the uname spelling the matrix uses.
xlate = {"amd64": "x86_64", "arm64": "aarch64", "armhf": "arm"}
print(",".join(sorted(xlate.get(k, k) for k in arches)))
PY
)"
if [[ -z "${SNAP_ARCHES}" ]]; then
  bad "snapcraft.yaml declares no architectures: or platforms: key — its architecture is an accident of the runner"
else
  snap_extra=""
  for a in ${SNAP_ARCHES//,/ }; do
    case ",${GUI_ARCHES}," in *",${a},"*) ;; *) snap_extra="${snap_extra} ${a}" ;; esac
  done
  if [[ -n "${snap_extra}" ]]; then
    bad "snapcraft.yaml claims${snap_extra}, which the release does not build a GUI for"
  else
    ok "snapcraft.yaml declares ${SNAP_ARCHES} (a subset of the built ${GUI_ARCHES})"
  fi
fi

FLATHUB_GEN="scripts/flatpak-gen-flathub-manifest.sh"
FLATHUB_ARCHES="$(sed -n 's/.*"only-arches":[[:space:]]*\[\(.*\)\].*/\1/p' "${FLATHUB_GEN}" | tr -d ',' | norm_arches)"
flathub_extra=""
for a in ${FLATHUB_ARCHES//,/ }; do
  case ",${GUI_ARCHES}," in *",${a},"*) ;; *) flathub_extra="${flathub_extra} ${a}" ;; esac
done
if [[ -n "${flathub_extra}" ]]; then
  bad "Flathub only-arches claims${flathub_extra}, which the release does not build a GUI for"
elif [[ "${FLATHUB_ARCHES}" == "${GUI_ARCHES}" ]]; then
  ok "Flathub only-arches (GUI) declares ${FLATHUB_ARCHES}"
else
  ok "Flathub only-arches (GUI) declares ${FLATHUB_ARCHES} — a subset of the built ${GUI_ARCHES}"
  note "Not drift by itself: Flathub builds each declared arch itself, from the Flatpak"
  note "manifest's own offline sources, so a GUI arch proven elsewhere is not proven there."
  note "Widen it once a real aarch64 flatpak-builder run has succeeded."
fi

# --- 6. the window must be able to find its own icon ---------------------------------
# On Wayland (Ubuntu's default) GNOME does not read X11's WM_CLASS; it matches a window
# to its .desktop entry on the Wayland app_id, and falls back to a generic icon when no
# entry matches. GTK advertises the *binary name* as that app_id — verified on a live
# session with WAYLAND_DEBUG=1, which logs xdg_toplevel.set_app_id("bulwark-app") — not
# tauri.conf.json's identifier and not the .desktop file's basename, both of which differ
# here. So StartupWMClass is the only thing holding the association together, in three
# separately-authored desktop entries, and a wrong value fails silently and only on the
# user's desktop.
echo
APP_ID="$(python3 -c "import json;print(json.load(open('${TAURI_CONF}'))['mainBinaryName'])")"
note "expected Wayland app_id (= mainBinaryName): ${APP_ID}"

# The .deb/.rpm template uses Tauri's {{exec}} placeholder, which expands to exactly this
# binary name; asserting the placeholder keeps it correct through a rename.
DEB_TEMPLATE="apps/bulwark-app/src-tauri/bulwark.desktop"
if grep -qx 'StartupWMClass={{exec}}' "${DEB_TEMPLATE}"; then
  ok ".deb/.rpm desktop template ties StartupWMClass to {{exec}}"
else
  bad "${DEB_TEMPLATE} must declare StartupWMClass={{exec}} (the Wayland app_id)"
fi

for f in "packaging/flatpak/com.vietanhdev.bulwark.desktop" "${SNAP_MANIFEST}"; do
  got="$(sed -n 's/^[[:space:]]*StartupWMClass=//p' "${f}" | head -1)"
  if [[ "${got}" == "${APP_ID}" ]]; then
    ok "$(basename "${f}") declares StartupWMClass=${got}"
  else
    bad "$(basename "${f}") declares StartupWMClass='${got}', expected '${APP_ID}'"
    note "GNOME/Wayland will show a generic icon for the window instead of Bulwark's."
  fi
done

# Icon sizes. tauri-bundler derives the hicolor directory from each PNG's *actual pixel
# dimensions*, appending "@2" when the filename ends in @2x — so 128x128@2x.png (really
# 256px) was installed to 256x256@2/, a scale-2 slot that the spec says holds a 512px
# image. HiDPI users therefore got a half-resolution icon, and no @2x filename can ever
# land in a correct directory under that rule. Ship plain sizes only.
mapfile -t ICONS < <(python3 -c "
import json
for i in json.load(open('${TAURI_CONF}'))['bundle']['icon']: print(i)")
if printf '%s\n' "${ICONS[@]}" | grep -q '@2x'; then
  bad "${TAURI_CONF} bundle.icon still lists an @2x PNG"
  note "tauri-bundler sizes the hicolor dir from real pixels and appends @2, so an @2x"
  note "entry always lands in a scale-2 directory that wants an image twice its size."
else
  ok "bundle.icon lists no @2x entry"
fi
# 48px is the size GNOME asks for most (dash, alt-tab, window list). Without it the
# loader downscales the nearest larger icon, which is visibly softer.
if printf '%s\n' "${ICONS[@]}" | grep -q '48x48\.png'; then
  ok "bundle.icon ships a native 48x48"
else
  bad "${TAURI_CONF} bundle.icon has no 48x48.png — GNOME's most-requested icon size"
fi

echo
echo "CI access: every workflow job runs only for the owner"
# CONTRIBUTING.md § CI access: jobs start only when vietanhdev triggers them (pushes, PRs and
# reruns from anyone else, Dependabot included, start nothing). A new job added without the
# guard would silently reopen that door, so every job in every workflow must carry it.
for wf in .github/workflows/*.yml; do
  unguarded=$(awk '
    /^jobs:/ { injobs = 1; next }
    injobs && /^[^ #]/ { injobs = 0 }
    injobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
      if (job != "" && !guarded) print job
      job = $1; sub(/:$/, "", job); guarded = 0; next
    }
    injobs && /^    if:.*github\.triggering_actor == .vietanhdev./ { guarded = 1 }
    END { if (job != "" && !guarded) print job }
  ' "${wf}")
  if [[ -z "${unguarded}" ]]; then
    ok "${wf}: all jobs owner-only"
  else
    for j in ${unguarded}; do
      bad "${wf}: job '${j}' has no \`if: github.triggering_actor == 'vietanhdev'\` guard"
    done
  fi
done

echo
if [[ ${fail} -eq 0 ]]; then
  echo "packaging consistency: PASS"
else
  echo "packaging consistency: FAIL"
fi
exit ${fail}
