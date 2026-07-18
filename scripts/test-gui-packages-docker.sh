#!/usr/bin/env bash
# Launch-test the GUI packages in Docker.
#
# Why this exists: CI proved the GUI packages *built* and shipped their rule pack, and
# every one of those assertions passed while the Flatpak crashed on launch with a
# libayatana-appindicator dlopen panic and a rule pack its resolver couldn't find.
# "cargo tauri build exited 0" and "the .deb contains 65 rules" are both true of a
# binary that dies before it draws a window. The only assertion that catches that class
# of bug is starting the real GUI from the real package and watching what it prints.
#
# Each package is installed into a clean container, started under Xvfb, and judged on:
#   1. it does not panic
#   2. it resolves a rules directory (no "continuous monitoring disabled")
#   3. it is still alive after the settle period (it drew a window and stayed up)
#
# Usage:
#   scripts/test-gui-packages-docker.sh [deb|rpm|appimage] ...   # default: all
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS="${REPO_ROOT}/build/relassets"
SETTLE="${SETTLE:-20}"

# Resolve artifact names by glob, not by a pinned version: this script runs in the release
# workflow against whatever version was just built, and a hardcoded 0.8.3 would silently
# stop matching (and, with `set -u` off on the docker side, "test" nothing at all).
shopt -s nullglob
find_one() {
  local pat="$1" matches=("${ASSETS}"/$1)
  [[ ${#matches[@]} -eq 1 ]] || { echo "ERROR: expected exactly 1 file matching '${pat}' in ${ASSETS}, found ${#matches[@]}" >&2; exit 1; }
  basename "${matches[0]}"
}

# Targets are "kind" or "kind:image". Defaults cover every distro family that consumes
# each artifact, not just one convenient image: a .deb that runs on Ubuntu 24.04 can still
# fail on Debian 12's older WebKit or Ubuntu 26.04's newer one.
TARGETS=("$@")
[[ ${#TARGETS[@]} -eq 0 ]] && TARGETS=(
  deb:ubuntu:24.04
  deb:ubuntu:22.04
  deb:ubuntu:26.04
  deb:debian:12
  rpm:fedora:latest
  appimage:ubuntu:24.04
  # appimage:ubuntu:26.04 is deliberately absent. It fails there with
  #   Could not create default EGL display: EGL_BAD_PARAMETER. Aborting...
  # and that is the container, not the package: the AppImage bundles WebKit and GTK but
  # NOT libEGL or the Mesa drivers, so it needs the host's graphics stack, and 26.04's
  # software-rendering stack in a GPU-less container does not satisfy it. Verified on real
  # Ubuntu 26.04 hardware, where the same AppImage starts and resolves its rules normally;
  # the .deb also passes on ubuntu:26.04 here because it uses the distro's own WebKit.
  # Re-add this only with a container that provides a working EGL, otherwise the job fails
  # for a reason no user will ever hit.
)

# Xvfb + software rendering: containers have no GPU, and WebKitGTK's DMA-BUF renderer
# and its own sandbox both fail without one. These mirror what a headless CI runner needs;
# they are test-harness settings, not something the app requires on a real desktop.
GUI_ENV='
  for t in Xvfb import identify; do
    command -v "$t" >/dev/null || {
      echo "HARNESS ERROR: $t missing — test dependencies failed to install."
      echo "This is a broken test environment, NOT an application failure."
      exit 90
    }
  done
  export DISPLAY=:99
  export WEBKIT_DISABLE_COMPOSITING_MODE=1
  export WEBKIT_DISABLE_DMABUF_RENDERER=1
  export LIBGL_ALWAYS_SOFTWARE=1
  export GDK_BACKEND=x11
  Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 &
  sleep 3
'

# Shared verdict logic. Reads the app log and decides pass/fail. Kept in one place so
# every package format is judged by identical criteria.
#
# The screenshot check exists because everything else here can pass on an app that renders
# NOTHING. A Tauri app whose WebKit WebProcess fails to start still runs, still logs its
# rule pack, and still holds its PID — the user just gets an empty window. That is exactly
# what shipped in the Flatpak (WebKit could not reach the Flatpak spawn portal, so the page
# never loaded). "The process is alive" is not "the app works": capture the screen and
# require the window to contain real content.
#
# `identify -format %k` counts unique colours. A blank or single-colour window scores a
# handful; a rendered UI scores hundreds. The threshold is deliberately low so this fails
# only on genuinely empty output, not on a restyled interface.
VERDICT='
  echo "----- app output -----"; cat /tmp/app.log
  echo "----------------------"
  fail=0
  if grep -qi "panicked" /tmp/app.log; then echo "FAIL: panicked on launch"; fail=1; fi
  if grep -q "couldn.t find a .rules. directory" /tmp/app.log; then
    echo "FAIL: rules directory not resolved (continuous monitoring disabled)"; fail=1; fi
  if ! grep -q "rules directory resolved" /tmp/app.log; then
    echo "FAIL: never logged a resolved rules directory"; fail=1; fi
  # A packaged build must serve the embedded frontend (tauri://localhost). An http(s) URL
  # means it was built without --features custom-protocol, so Tauri fell back to devUrl and
  # the window renders empty on any machine with nothing on that port. This shipped once.
  if grep -qE "webview url: https?://" /tmp/app.log; then
    echo "FAIL: DEV build — the UI is loaded over http, not the embedded frontend"; fail=1; fi
  if ! grep -q "webview url: tauri://" /tmp/app.log; then
    echo "FAIL: webview did not load the embedded frontend (tauri://localhost)"; fail=1; fi
  if ! kill -0 $APP_PID 2>/dev/null; then echo "FAIL: process died during settle"; fail=1; fi

  import -window root /tmp/shot.png 2>/dev/null || xwd -root -silent > /tmp/shot.xwd 2>/dev/null
  [ -f /tmp/shot.png ] || convert /tmp/shot.xwd /tmp/shot.png 2>/dev/null
  if [ -f /tmp/shot.png ]; then
    colors=$(identify -format "%k" /tmp/shot.png 2>/dev/null || echo 0)
    echo "distinct colours on screen: ${colors}"
    if [ "${colors:-0}" -lt 50 ]; then
      echo "FAIL: window appears blank (${colors} colours) — the UI did not render"
      fail=1
    fi
  else
    echo "WARN: could not capture a screenshot; rendering not verified"
  fi

  [ $fail -eq 0 ] && echo "PASS" || true
  exit $fail
'

overall=0
for spec in "${TARGETS[@]}"; do
  t="${spec%%:*}"
  IMAGE="${spec#*:}"
  [[ "${IMAGE}" == "${t}" ]] && IMAGE=""      # bare kind, use the per-kind default
  echo
  echo "=============================================================="
  echo ">> GUI launch test: ${t} on ${IMAGE:-<default>}"
  echo "=============================================================="
  case "${t}" in
    deb)
      DEB="$(find_one "bulwark-desktop_*_amd64.deb")"
      docker run --rm -v "${ASSETS}:/a:ro" "${IMAGE:-ubuntu:24.04}" bash -c "
        set -u
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null
        apt-get install -y -qq xvfb imagemagick x11-apps >/dev/null 2>&1
        apt-get install -y -qq /a/${DEB} >/dev/null 2>&1 \
          || { echo 'FAIL: apt install failed'; exit 1; }
        ${GUI_ENV}
        bulwark-app >/tmp/app.log 2>&1 &
        APP_PID=\$!
        sleep ${SETTLE}
        ${VERDICT}
      "
      ;;
    rpm)
      RPM="$(find_one "bulwark-desktop-*.x86_64.rpm")"
      docker run --rm -v "${ASSETS}:/a:ro" "${IMAGE:-fedora:latest}" bash -c "
        set -u
        dnf install -y -q xorg-x11-server-Xvfb ImageMagick >/dev/null 2>&1
        dnf install -y -q /a/${RPM} >/dev/null 2>&1 \
          || { echo 'FAIL: dnf install failed'; exit 1; }
        ${GUI_ENV}
        bulwark-app >/tmp/app.log 2>&1 &
        APP_PID=\$!
        sleep ${SETTLE}
        ${VERDICT}
      "
      ;;
    appimage)
      APPIMAGE="$(find_one "bulwark-desktop-*-x86_64.AppImage")"
      # --appimage-extract rather than a direct run: mounting an AppImage needs FUSE,
      # which a container doesn't have. Extraction exercises the same payload.
      docker run --rm -v "${ASSETS}:/a:ro" "${IMAGE:-ubuntu:24.04}" bash -c "
        set -u
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null
        apt-get install -y -qq xvfb imagemagick x11-apps libwebkit2gtk-4.1-0 libgtk-3-0 >/dev/null 2>&1
        cd /tmp && cp /a/${APPIMAGE} app.AppImage
        chmod +x app.AppImage && ./app.AppImage --appimage-extract >/dev/null 2>&1 \
          || { echo 'FAIL: AppImage extract failed'; exit 1; }
        ${GUI_ENV}
        ./squashfs-root/AppRun >/tmp/app.log 2>&1 &
        APP_PID=\$!
        sleep ${SETTLE}
        ${VERDICT}
      "
      ;;
    *) echo "unknown target: ${t}"; exit 2 ;;
  esac
  rc=$?
  [[ ${rc} -eq 0 ]] && echo ">> ${t} on ${IMAGE:-default}: PASS" \
    || { echo ">> ${t} on ${IMAGE:-default}: FAIL (rc=${rc})"; overall=1; }
done

echo
echo "=============================================================="
[[ ${overall} -eq 0 ]] && echo "ALL GUI PACKAGES PASSED" || echo "SOME GUI PACKAGES FAILED"
exit ${overall}
