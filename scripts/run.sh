#!/usr/bin/env bash
# Run a libfprint example against the patched build, with full debug output.
# Run on Fedora laptop. Default action: enroll.
#
# Usage: run.sh [enroll|verify|list|capture]
set -euo pipefail

DEV_DIR="${DEV_DIR:-$HOME/dev}"
REPO_DIR="${REPO_DIR:-$DEV_DIR/goodix-gm168}"
BUILD_DIR="${BUILD_DIR:-$DEV_DIR/libfprint-build}"
PREFIX="${PREFIX:-/opt/libfprint-gm168}"

ACTION="${1:-enroll}"
EXAMPLE="$BUILD_DIR/examples/$ACTION"

if [[ ! -x "$EXAMPLE" ]]; then
    echo "[run] $EXAMPLE not found — did you build with -Dgtk-examples? Try $BUILD_DIR/examples/"
    ls "$BUILD_DIR/examples/" 2>/dev/null || true
    exit 1
fi

mkdir -p "$REPO_DIR/logs"
GM168_DIR="${GOODIX_GM168_DIR:-$HOME/.goodix-gm168}"
mkdir -p "$GM168_DIR"

# shellcheck disable=SC1091
source "$(dirname "$0")/_lib.sh"
gm168_kill_old_sessions
gm168_unlock_usb
gm168_set_default_env
LOG="$REPO_DIR/logs/$(date +%Y%m%d-%H%M%S)-${ACTION}.log"

echo "[run] action=$ACTION  log=$LOG"
echo "[run] make sure system fprintd is stopped: sudo systemctl stop fprintd"

# Clean stale per-frame dumps so we know what this run produced.
rm -f /tmp/gm168_*.bin 2>/dev/null || true

env \
    LD_LIBRARY_PATH="$PREFIX/lib64" \
    GI_TYPELIB_PATH="$PREFIX/lib64/girepository-1.0" \
    GOODIX_GM168_DIR="$GM168_DIR" \
    G_MESSAGES_DEBUG=all \
    LIBFPRINT_DEBUG=3 \
    GM168_DEBUG=1 \
    "$EXAMPLE" 2>&1 | tee "$LOG"

echo "[run] done — log: $LOG"
echo "[run] frame dumps: /tmp/gm168_*.bin"
