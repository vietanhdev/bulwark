#!/usr/bin/env bash
# Launch the INSTALLED snap's GUI on a virtual display and decide whether it works.
#
# Run it after `sudo snap install --dangerous --classic bulwark_*.snap`, on a machine where
# sudo does not prompt (a CI runner). ci.yml's snap-build job and publish-snap.yml both call it,
# so a snap that cannot start is a red pull request and can never be uploaded.
#
# Why this exists: for months the only checks on the snap drove `bulwark.cli`, the bundled CLI,
# which shares a folder with the GUI and not a line of its code. They all passed on a snap whose
# GUI died on start with "libwebkit2gtk-4.1.so.0: cannot open shared object file". A CLI check
# cannot see a GUI that never draws.
#
# What the host provides here is deliberately small: a virtual display, the graphics stack and
# the two text-shaping libraries every desktop has. WebKit and GTK are NOT installed, and the
# script refuses to run if the machine already has WebKit, because then a snap that forgot to
# carry its own would pass.
set -uo pipefail

SETTLE="${SETTLE:-25}"
LOG="$(mktemp)"
SHOT="$(mktemp --suffix=.png)"

sudo apt-get update -qq >/dev/null
sudo apt-get install -y -qq --no-install-recommends \
  xvfb imagemagick x11-apps procps dbus \
  libegl1 libgl1 libgl1-mesa-dri libgles2 libfribidi0 libharfbuzz0b >/dev/null

if dpkg-query -W -f='${Status}\n' 'libwebkit2gtk-4.1-0' 2>/dev/null | grep -q "install ok installed"; then
  echo "FAIL: this machine has its own WebKitGTK, so the test cannot tell whether the snap carries one"
  exit 1
fi

fail=0

# The menu entry must point at an icon that exists. A theme name would resolve to nothing: a
# snap's icon folders are not on the host's icon search path.
DESKTOP="/snap/bulwark/current/meta/gui/bulwark.desktop"
if [ -f "$DESKTOP" ]; then
  icon="$(sed -n 's/^Icon=//p' "$DESKTOP" | head -1)"
  icon="${icon/\$\{SNAP\}//snap/bulwark/current}"
  if [ -f "$icon" ]; then
    echo "menu entry icon: $icon"
  else
    echo "FAIL: the menu entry's icon does not exist: $icon"; fail=1
  fi
else
  echo "FAIL: the snap has no menu entry ($DESKTOP)"; fail=1
fi

export DISPLAY=:99
Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 &
XVFB_PID=$!
sleep 3
# The settings the AppImage harness uses for the same bundled WebKit on a GPU-less machine
# (scripts/test-gui-packages-docker.sh).
export WEBKIT_DISABLE_COMPOSITING_MODE=1 WEBKIT_DISABLE_DMABUF_RENDERER=1
export LIBGL_ALWAYS_SOFTWARE=1 GDK_BACKEND=x11
# No accessibility bus on a runner: without this GTK logs "AT-SPI: Error retrieving accessibility
# bus address" on every start.
export NO_AT_BRIDGE=1

# A session bus, as every desktop has. Without one the app starts anyway and simply skips
# single-instance, so a test with no bus can never notice a snap that is not allowed to claim
# its bus name. That is how a recipe the Snap Store rejects stayed green here.
BUS="$(dbus-daemon --session --fork --print-address=1 --print-pid=1)"
DBUS_SESSION_BUS_ADDRESS="$(printf '%s\n' "$BUS" | sed -n 1p)"
BUS_PID="$(printf '%s\n' "$BUS" | sed -n 2p)"
export DBUS_SESSION_BUS_ADDRESS
[ -n "$DBUS_SESSION_BUS_ADDRESS" ] || { echo "FAIL: could not start a session bus"; exit 1; }

# From a folder that is not the snap's: the bundle's WebKit finds its helper processes through
# a relative path, so a launcher that forgot to change directory fails only when started from
# somewhere else, which is how every user starts it.
cd "$(mktemp -d)" || exit 1
bulwark >"$LOG" 2>&1 &
APP_PID=$!
sleep "$SETTLE"

echo "----- GUI output -----"; cat "$LOG"; echo "----------------------"

grep -qi "panicked" "$LOG" && { echo "FAIL: GUI panicked"; fail=1; }
grep -q "error while loading shared libraries" "$LOG" && {
  echo "FAIL: the GUI could not load a library it needs"; fail=1; }
grep -q "rules directory resolved" "$LOG" || {
  echo "FAIL: GUI never resolved a rules directory"; fail=1; }
grep -qE "webview url: https?://" "$LOG" && {
  echo "FAIL: DEV build — UI served over http instead of the embedded frontend"; fail=1; }
grep -q "webview url: tauri://" "$LOG" || {
  echo "FAIL: webview never loaded the embedded frontend"; fail=1; }
kill -0 "$APP_PID" 2>/dev/null || { echo "FAIL: GUI process died"; fail=1; }

# The web engine must be running, and it must be the snap's own. A window can exist and paint
# its frame while the page never loads because the helper process could not be started.
web_pids="$(pgrep -f 'WebKitWebProcess' || true)"
if [ -z "$web_pids" ]; then
  echo "FAIL: no WebKitWebProcess is running, so no page was loaded"; fail=1
else
  for p in $web_pids; do
    exe="$(readlink "/proc/$p/exe" 2>/dev/null || true)"
    case "$exe" in
      /snap/bulwark/*) echo "web process: $exe" ;;
      "") ;;
      *) echo "FAIL: the web process is not the snap's own: $exe"; fail=1 ;;
    esac
  done
fi

# And prove it painted. Everything above is true of an app that draws an empty window; a
# rendered interface scores hundreds of distinct colours, an empty one a handful.
import -window root "$SHOT" 2>/dev/null || true
if [ -s "$SHOT" ]; then
  colors="$(identify -format "%k" "$SHOT" 2>/dev/null || echo 0)"
  echo "distinct colours on screen: ${colors}"
  [ "${colors:-0}" -lt 50 ] && { echo "FAIL: window is blank (${colors} colours)"; fail=1; }
else
  echo "FAIL: no screenshot could be captured"; fail=1
fi

# Starting it again must hand over to the running app and exit, not open a second one. This
# is the only check that proves the app could claim its name on the session bus.
if kill -0 "$APP_PID" 2>/dev/null; then
  timeout 20 bulwark >"$LOG.second" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "second launch handed over to the first and exited"
  else
    echo "FAIL: a second launch did not hand over to the running app (exit $rc)"
    sed 's/^/  second: /' "$LOG.second" | head -20
    fail=1
  fi
  kill -0 "$APP_PID" 2>/dev/null || { echo "FAIL: the first app died when a second was started"; fail=1; }
fi

# Closing the app is something every user does. It must stop when asked.
kill "$APP_PID" 2>/dev/null || true
for _ in 1 2 3 4 5 6 7 8 9 10; do
  kill -0 "$APP_PID" 2>/dev/null || break
  sleep 1
done
if kill -0 "$APP_PID" 2>/dev/null; then
  echo "FAIL: the GUI did not stop within 10 seconds of being asked to"; fail=1
  kill -9 "$APP_PID" 2>/dev/null || true
fi
kill "$XVFB_PID" 2>/dev/null || true
[ -n "${BUS_PID:-}" ] && kill "$BUS_PID" 2>/dev/null || true

[ "$fail" -eq 0 ] && echo "snap GUI launch OK"
exit "$fail"
