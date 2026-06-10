#!/usr/bin/env bash
# Interactive enroll via libfprint's examples/enroll.
# Run this directly in your SSH session (TTY required for stdin prompts).
#
# Usage: ./scripts/enroll.sh
#   then answer:
#     - finger number (e.g. 1)
#     - Y/N for update existing print
#     - touch the sensor 5 times when prompted
set -euo pipefail

DEV_DIR="${DEV_DIR:-$HOME/dev}"
BUILD_DIR="${BUILD_DIR:-$DEV_DIR/libfprint-build}"
PREFIX="${PREFIX:-/opt/libfprint-gm168}"
REPO_DIR="${REPO_DIR:-$DEV_DIR/goodix-gm168}"
GM168_DIR="${GOODIX_GM168_DIR:-$HOME/.goodix-gm168}"

mkdir -p "$REPO_DIR/logs" "$GM168_DIR"
LOG="$REPO_DIR/logs/$(date +%Y%m%d-%H%M%S)-enroll.log"

# In debug mode: delegate to enroll_grid.sh — it collects per-stage images
# and assembles them into an annotated PNG grid automatically.
if [[ "${GM168_DEBUG:-0}" == "1" ]]; then
    echo "[enroll] GM168_DEBUG=1 → handing off to enroll_grid.sh"
    exec "$(dirname "$0")/enroll_grid.sh" "$@"
fi

# shellcheck disable=SC1091
source "$(dirname "$0")/_lib.sh"
gm168_kill_old_sessions
gm168_unlock_usb
gm168_set_default_env

# Frame dumps (/tmp/gm168_*.pgm/.bin) are only produced by a GM168_DEBUG
# build (scripts/grid_dumps.sh debug-build). Clean stale dumps anyway so
# timestamps don't confuse grid_dumps.py if a debug build is active.
rm -f /tmp/gm168_*.bin /tmp/gm168_*.pgm 2>/dev/null || true

echo "[enroll] log → $LOG"
echo "[enroll] starting libfprint examples/enroll — interactive"
echo

env \
    LD_LIBRARY_PATH="$PREFIX/lib64" \
    GI_TYPELIB_PATH="$PREFIX/lib64/girepository-1.0" \
    GOODIX_GM168_DIR="$GM168_DIR" \
    G_MESSAGES_DEBUG=all \
    LIBFPRINT_DEBUG=3 \
    "$BUILD_DIR/examples/enroll" 2>&1 | tee "$LOG"

echo
echo "[enroll] done — log: $LOG"
# Frame dumps only exist if built with -DGM168_DEBUG (see grid_dumps.sh debug-build).
[[ -n "$(ls /tmp/gm168_*.pgm 2>/dev/null)" ]] && \
    echo "[enroll] frame dumps: $(ls /tmp/gm168_*.pgm 2>/dev/null | wc -l) files in /tmp/gm168_*.pgm"
