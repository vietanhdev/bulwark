#!/usr/bin/env python3
"""Render the desktop app's Linux icons from apps/bulwark-app/src-tauri/icons/app-icon.svg.

The app icon is drawn in the Ubuntu/Yaru idiom (the shield as the silhouette, soft drop shadow,
optical size matched to the system's own icons) and every PNG the bundles, the Flatpak, the tray
and the window list use is rendered from that one SVG — so the icon is reproducible, not a set of
hand-exported files that drift. `icon.svg` (the shield on a graphite tile) is the brand mark for
the README and docs and is not touched. Windows/macOS store assets (.ico, .icns, Square*) are not
regenerated here.

Needs librsvg's GObject bindings (system Python on Ubuntu/Debian/Fedora):

    /usr/bin/python3 scripts/render-app-icons.py
"""

import pathlib

import cairo
import gi

gi.require_version("Rsvg", "2.0")
from gi.repository import Rsvg  # noqa: E402

ICONS = pathlib.Path(__file__).resolve().parent.parent / "apps/bulwark-app/src-tauri/icons"
SOURCE = ICONS / "app-icon.svg"

# file name -> pixel size
TARGETS = {
    "16x16.png": 16,
    "24x24.png": 24,
    "32x32.png": 32,
    "48x48.png": 48,
    "64x64.png": 64,
    "128x128.png": 128,
    "128x128@2x.png": 256,
    "256x256.png": 256,
    "512x512.png": 512,
    "icon.png": 512,
}


def render(size: int, out: pathlib.Path) -> None:
    handle = Rsvg.Handle.new_from_file(str(SOURCE))
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
    viewport = Rsvg.Rectangle()
    viewport.x, viewport.y, viewport.width, viewport.height = 0, 0, size, size
    handle.render_document(cairo.Context(surface), viewport)
    surface.write_to_png(str(out))


TRAY_SOURCE = ICONS / "tray-icon.svg"
TRAY_SIZE = 64


def render_tray_rgba() -> None:
    """The tray glyph as raw, straight-alpha RGBA, so the app can embed it without an image
    decoder (no new crates for the offline Flatpak/PPA builds)."""
    handle = Rsvg.Handle.new_from_file(str(TRAY_SOURCE))
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, TRAY_SIZE, TRAY_SIZE)
    viewport = Rsvg.Rectangle()
    viewport.x, viewport.y, viewport.width, viewport.height = 0, 0, TRAY_SIZE, TRAY_SIZE
    handle.render_document(cairo.Context(surface), viewport)
    surface.flush()
    data = surface.get_data()  # premultiplied, native-endian ARGB32 (BGRA in memory on LE)
    out = bytearray()
    for i in range(0, TRAY_SIZE * TRAY_SIZE * 4, 4):
        b, g, r, a = data[i], data[i + 1], data[i + 2], data[i + 3]
        if a:
            r, g, b = (min(255, c * 255 // a) for c in (r, g, b))
        out += bytes((r, g, b, a))
    (ICONS / "tray-icon.rgba").write_bytes(out)
    surface.write_to_png(str(ICONS / "tray-icon.png"))  # for looking at, not used by the app
    print(f"{'tray-icon.rgba':16} {TRAY_SIZE}px")


def main() -> None:
    for name, size in TARGETS.items():
        render(size, ICONS / name)
        print(f"{name:16} {size}px")
    render_tray_rgba()


if __name__ == "__main__":
    main()
