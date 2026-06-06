#!/usr/bin/env bash
# Interactive verify against the most recently enrolled print.
# Run after ./scripts/enroll.sh has completed at least one full enrollment.
set -euo pipefail

DEV_DIR="${DEV_DIR:-$HOME/dev}"
BUILD_DIR="${BUILD_DIR:-$DEV_DIR/libfprint-build}"
PREFIX="${PREFIX:-/opt/libfprint-gm168}"
REPO_DIR="${REPO_DIR:-$DEV_DIR/goodix-gm168}"
GM168_DIR="${GOODIX_GM168_DIR:-$HOME/.goodix-gm168}"

mkdir -p "$REPO_DIR/logs"
LOG="$REPO_DIR/logs/$(date +%Y%m%d-%H%M%S)-verify.log"

# shellcheck disable=SC1091
source "$(dirname "$0")/_lib.sh"
gm168_kill_old_sessions
gm168_unlock_usb
gm168_set_default_env

rm -f /tmp/gm168_*.bin 2>/dev/null || true

echo "[verify] log → $LOG"
echo "[verify] starting libfprint examples/verify — interactive"
echo

env \
    LD_LIBRARY_PATH="$PREFIX/lib64" \
    GI_TYPELIB_PATH="$PREFIX/lib64/girepository-1.0" \
    GOODIX_GM168_DIR="$GM168_DIR" \
    G_MESSAGES_DEBUG=all \
    LIBFPRINT_DEBUG=3 \
    "$BUILD_DIR/examples/verify" 2>&1 | tee "$LOG"

echo
echo "[verify] done — log: $LOG"
