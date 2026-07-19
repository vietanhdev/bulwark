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
#   1. it does not panic, and its log carries none of the known non-fatal failure
#      signatures (GDBus NotAllowed, dlopen/undefined symbol, GLib CRITICAL, ...)
#   2. it resolves a rules directory (no "continuous monitoring disabled")
#   3. it serves the embedded frontend (tauri://), not a dev-server URL
#   4. it is still alive after the settle period
#   5. a WebKitWebProcess exists — the web engine actually started
#   6. a window titled Bulwark is mapped at a usable size
#   7. the window is not blank (distinct-colour count) and the display changed
#      versus a baseline captured before launch
#   8. real TEXT is on screen (OCR) — i.e. the React app mounted and painted,
#      not merely a themed background
#   9. it exits cleanly on SIGTERM rather than hanging or crashing on teardown
#
# 5, 6, 8 and 9 exist because 1-4 and the colour count are all satisfiable by an app that
# renders nothing usable. That gap is not academic on a second architecture:
# JavaScriptCore has its own arm64 JIT, so "native shell paints, JS never runs" is an
# arch-specific failure whose only tell is the absence of rendered text.
#
# Usage:
#   scripts/test-gui-packages-docker.sh [deb|rpm|appimage] ...   # default: all
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS="${REPO_ROOT}/build/relassets"
SETTLE="${SETTLE:-20}"

# Which architecture's artifacts to test. Defaults to the machine running the script, because
# the containers below run the real GUI — so this must be the host's native arch or every
# launch dies with "exec format error". The release workflow runs one instance of this script
# per arch, on that arch's own runner, rather than emulating: a WebKit GUI under qemu-user is
# both extremely slow and prone to failing for reasons no user would ever hit, which would make
# a red result uninformative. ARCH= is honoured for a manual run with binfmt already set up.
ARCH="${ARCH:-$(uname -m)}"
case "${ARCH}" in
  x86_64)  DEB_ARCH=amd64 ;;
  aarch64) DEB_ARCH=arm64 ;;
  *) echo "ERROR: unsupported ARCH '${ARCH}' (expected x86_64 or aarch64)" >&2; exit 1 ;;
esac
echo ">> testing ${ARCH} artifacts (.deb arch: ${DEB_ARCH})"

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
  # xdotool/compare/pgrep join the guard because the checks that depend on them are hard
  # FAILs: a missing tool would otherwise read as "no window found" or "nothing drawn" and
  # blame the application for a broken image. tesseract is deliberately NOT here — its check
  # degrades to a warning, so its absence must not fail the run.
  for t in Xvfb import identify compare xdotool pgrep; do
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
  # Baseline of the EMPTY display, captured before the app starts. The colour-count check
  # alone cannot tell "the app painted a UI" from "Xvfb has a noisy default root"; comparing
  # against this does, and it stays valid if the app is restyled.
  import -window root /tmp/baseline.png 2>/dev/null || true
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
#
# The colour count is necessary but NOT sufficient, and it is weakest exactly where this
# suite is now being asked to do the most work — a second CPU architecture. A window that
# paints its background and chrome but never runs the app scores in the hundreds and passes.
# That is not a hypothetical on arm64: JavaScriptCore ships a separate arm64 JIT, so "the
# native shell renders but the JS never executed" is an arch-specific failure mode the colour
# count is blind to by construction. The checks below close that gap from three directions —
# the WebKit process tree (did the web engine start), OCR (did JS paint real text), and a
# baseline diff (did the screen change at all) — so a pass means the React app actually ran.
VERDICT='
  echo "----- app output -----"; cat /tmp/app.log
  echo "----------------------"
  fail=0
  if grep -qi "panicked" /tmp/app.log; then echo "FAIL: panicked on launch"; fail=1; fi

  # Signatures of failures that do NOT panic and do NOT kill the process — the app keeps
  # running and the user gets a broken window. Each of these has a real precedent: the
  # Flatpak printed a bare GDBus NotAllowed, and the appindicator crash was a dlopen of a
  # library the runtime lacked. Cheap to check, and silence here is meaningful.
  for sig in "GDBus.Error" "NotAllowed" "undefined symbol" "cannot open shared object" \
             "Segmentation fault" "GLib-GObject-CRITICAL" "Failed to load module" \
             "libEGL warning: failed" "WebKitWebProcess.*crashed" "Exec format error"; do
    if grep -qE "${sig}" /tmp/app.log; then
      echo "FAIL: app log contains a known-bad signature: ${sig}"; fail=1; fi
  done
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

  # 1. The web engine actually started. Tauri spawns WebKitWebProcess (renders the page) and
  #    WebKitNetworkProcess. The GUI shell can be alive and logging with NO WebProcess at all —
  #    that is precisely the shape of the Flatpak bug — and every log-based check above passes
  #    in that state. This is the cheapest direct evidence that there is something to render
  #    with, and unlike the pixel checks it cannot be satisfied by a background colour.
  if pgrep -f "WebKitWebProcess" >/dev/null 2>&1; then
    echo "OK: WebKitWebProcess is running (the web engine started)"
  else
    echo "FAIL: no WebKitWebProcess — the webview never started, so nothing can render"
    fail=1
  fi

  # 2. A real, mapped, sensibly-sized window exists. `import -window root` will happily
  #    screenshot a desktop with no window on it, so assert the window itself. Also catches a
  #    window that maps at 0x0 or 1x1, which renders "content" that no user can see.
  WID="$(xdotool search --name "Bulwark" 2>/dev/null | head -1)"
  if [ -n "${WID}" ]; then
    GEO="$(xdotool getwindowgeometry "${WID}" 2>/dev/null | tr "\n" " ")"
    echo "window: id=${WID} ${GEO}"
    W="$(xdotool getwindowgeometry --shell "${WID}" 2>/dev/null | sed -n "s/^WIDTH=//p")"
    H="$(xdotool getwindowgeometry --shell "${WID}" 2>/dev/null | sed -n "s/^HEIGHT=//p")"
    if [ "${W:-0}" -lt 400 ] || [ "${H:-0}" -lt 300 ]; then
      echo "FAIL: window is ${W}x${H} — too small to be a usable UI"; fail=1
    fi
  else
    echo "FAIL: no window titled Bulwark is mapped on the display"
    fail=1
    WID=""
  fi

  # Prefer a shot of the window itself; fall back to the root so the pixel checks still run
  # even if the window could not be located.
  if [ -n "${WID}" ]; then
    import -window "${WID}" /tmp/shot.png 2>/dev/null || import -window root /tmp/shot.png 2>/dev/null
  else
    import -window root /tmp/shot.png 2>/dev/null || xwd -root -silent > /tmp/shot.xwd 2>/dev/null
  fi
  [ -f /tmp/shot.png ] || convert /tmp/shot.xwd /tmp/shot.png 2>/dev/null

  if [ -f /tmp/shot.png ]; then
    colors=$(identify -format "%k" /tmp/shot.png 2>/dev/null || echo 0)
    echo "distinct colours on screen: ${colors}"
    if [ "${colors:-0}" -lt 50 ]; then
      echo "FAIL: window appears blank (${colors} colours) — the UI did not render"
      fail=1
    fi

    # 3. The screen actually CHANGED versus the empty display captured before launch. Guards
    #    the colour count from the opposite direction: a noisy or patterned root window could
    #    satisfy it while the app contributed nothing.
    #
    #    Compared root-to-root on purpose. The shot above may be of the window, and `compare`
    #    ERRORS on differing dimensions rather than reporting a difference — which this case
    #    statement would read as "not zero" and quietly pass. Comparing two full-screen
    #    captures keeps the geometry identical so the metric is always meaningful.
    if [ -f /tmp/baseline.png ]; then
      import -window root /tmp/shot_root.png 2>/dev/null || true
      if [ -f /tmp/shot_root.png ]; then
        DIFF="$(compare -metric AE /tmp/baseline.png /tmp/shot_root.png null: 2>&1 || true)"
        echo "pixels changed vs the pre-launch display: ${DIFF}"
        # AE = count of differing pixels, so this is an integer and an exact-zero test is
        # meaningful. Anything non-numeric means compare failed and the check is inconclusive.
        case "${DIFF}" in
          ""|*[!0-9]*) echo "WARN: could not measure the pre/post difference (${DIFF})" ;;
          0)           echo "FAIL: display is pixel-identical to before launch — nothing was drawn"; fail=1 ;;
          *)           echo "OK: ${DIFF} pixels changed after launch" ;;
        esac
      fi
    fi

    # 4. Real TEXT is on screen. This is the check that proves the *React app* ran rather than
    #    just the native shell: WebKit painting a themed background is not the same as the
    #    frontend mounting and laying out. It is also the only check here that would catch a
    #    JavaScriptCore failure specific to this architecture — JS silently not executing
    #    leaves a plausibly-coloured, plausibly-sized, completely useless window.
    #
    #    Deliberately lenient about WHICH text: OCR on a 1280x800 software-rendered screenshot
    #    is not reliable enough to demand an exact string, and pinning one would make every UI
    #    copy change a release-blocking failure. Any known nav label, or failing that a
    #    reasonable quantity of recognised characters, is enough to distinguish "text rendered"
    #    from "nothing rendered" — which is the only distinction being asked for.
    if command -v tesseract >/dev/null 2>&1; then
      tesseract /tmp/shot.png /tmp/ocr >/dev/null 2>&1 || true
      OCRTXT="$(cat /tmp/ocr.txt 2>/dev/null || echo "")"
      echo "----- OCR -----"; echo "${OCRTXT}" | head -20; echo "---------------"
      if echo "${OCRTXT}" | grep -qiE "bulwark|home|checkups|scans|settings|activity|system|reference"; then
        echo "OK: recognised real UI text on screen (the frontend mounted and painted)"
      else
        NALNUM="$(echo "${OCRTXT}" | tr -cd "[:alnum:]" | wc -c)"
        echo "no known label matched; recognised alphanumeric characters: ${NALNUM}"
        if [ "${NALNUM:-0}" -lt 30 ]; then
          echo "FAIL: essentially no text on screen — the UI did not render its content"
          fail=1
        else
          echo "OK: substantial text present, though no known label matched (UI copy may have changed)"
        fi
      fi
    else
      echo "WARN: tesseract missing — text rendering not verified"
    fi
  else
    echo "WARN: could not capture a screenshot; rendering not verified"
  fi

  # 5. It shuts down cleanly. A crash on the teardown path is still a crash the user meets
  #    every time they close the window, and nothing above would ever reach it.
  kill -TERM $APP_PID 2>/dev/null || true
  for i in $(seq 1 20); do kill -0 $APP_PID 2>/dev/null || break; sleep 1; done
  if kill -0 $APP_PID 2>/dev/null; then
    echo "FAIL: did not exit within 20s of SIGTERM (hung on shutdown)"
    kill -KILL $APP_PID 2>/dev/null || true
    fail=1
  else
    wait $APP_PID 2>/dev/null; rc=$?
    # 143 = SIGTERM, the expected outcome. 139/134 are a segfault/abort during teardown.
    case "${rc}" in
      0|143) echo "OK: exited cleanly on SIGTERM (rc=${rc})" ;;
      139)   echo "FAIL: segfaulted during shutdown"; fail=1 ;;
      134)   echo "FAIL: aborted during shutdown"; fail=1 ;;
      *)     echo "NOTE: exited with rc=${rc} on SIGTERM" ;;
    esac
  fi
  if grep -qi "panicked" /tmp/app.log; then
    echo "FAIL: panicked (message appeared during shutdown)"; fail=1; fi

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
      DEB="$(find_one "bulwark-desktop_*_${DEB_ARCH}.deb")"
      docker run --rm -v "${ASSETS}:/a:ro" "${IMAGE:-ubuntu:24.04}" bash -c "
        set -u
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null
        apt-get install -y -qq xvfb imagemagick x11-apps xdotool procps tesseract-ocr >/dev/null 2>&1
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
      RPM="$(find_one "bulwark-desktop-*.${ARCH}.rpm")"
      docker run --rm -v "${ASSETS}:/a:ro" "${IMAGE:-fedora:latest}" bash -c "
        set -u
        dnf install -y -q xorg-x11-server-Xvfb ImageMagick xdotool procps-ng tesseract >/dev/null 2>&1
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
      APPIMAGE="$(find_one "bulwark-desktop-*-${ARCH}.AppImage")"
      # --appimage-extract rather than a direct run: mounting an AppImage needs FUSE,
      # which a container doesn't have. Extraction exercises the same payload.
      docker run --rm -v "${ASSETS}:/a:ro" "${IMAGE:-ubuntu:24.04}" bash -c "
        set -u
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null
        apt-get install -y -qq xvfb imagemagick x11-apps xdotool procps tesseract-ocr libwebkit2gtk-4.1-0 libgtk-3-0 >/dev/null 2>&1
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
