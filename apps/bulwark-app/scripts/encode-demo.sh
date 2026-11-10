#!/usr/bin/env bash
# Encode the frames written by record-demo.mjs into the site/README demo:
#   docs/public/demo.mp4  1440x900, 12 fps, H.264 (the site's hero video)
#   docs/public/demo.gif   880x550,  8 fps, palette-optimised (the README)
# Usage: FRAME_DIR=/tmp/bw-frames scripts/encode-demo.sh
set -euo pipefail
FRAME_DIR=${FRAME_DIR:-/tmp/bw-frames}
OUT=$(cd "$(dirname "$0")/../../.." && pwd)/docs/public
[ -f "$FRAME_DIR/f00000.png" ] || { echo "no frames in $FRAME_DIR (run record-demo.mjs first)" >&2; exit 1; }

ffmpeg -v error -y -framerate 12 -i "$FRAME_DIR/f%05d.png" \
  -vf "scale=1440:900:flags=lanczos" -c:v libx264 -preset slow -crf 20 -pix_fmt yuv420p \
  -movflags +faststart "$OUT/demo.mp4"

ffmpeg -v error -y -framerate 12 -i "$FRAME_DIR/f%05d.png" \
  -vf "fps=8,scale=880:550:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" \
  "$OUT/demo.gif"

ls -la "$OUT/demo.mp4" "$OUT/demo.gif"
