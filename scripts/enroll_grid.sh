#!/usr/bin/env bash
# enroll_grid.sh — run enroll, collect every accepted stage image, compose a grid PNG.
#
# Works with ANY build (no -DGM168_DEBUG required). The libfprint examples/enroll
# binary writes enrolled.pgm to CWD after each stage; we copy it on each
# "passed" line and feed everything to enroll_grid.py for annotation.
#
# Output:
#   logs/enroll-grid-<TS>/stage_NNN.pgm   per-stage fingerprint images
#   logs/enroll-grid-<TS>/enroll.log      full driver log
#   logs/enroll-grid-<TS>.png             annotated grid
#
# Usage:
#   ./scripts/enroll_grid.sh             # interactive, default cols=4
#   ./scripts/enroll_grid.sh --cols 3
#   ./scripts/enroll_grid.sh --scale 5
set -euo pipefail

DEV_DIR="${DEV_DIR:-$HOME/dev}"
BUILD_DIR="${BUILD_DIR:-$DEV_DIR/libfprint-build}"
PREFIX="${PREFIX:-/opt/libfprint-gm168}"
REPO_DIR="${REPO_DIR:-$DEV_DIR/goodix-gm168}"
GM168_DIR="${GOODIX_GM168_DIR:-$HOME/.goodix-gm168}"

EXAMPLE="$BUILD_DIR/examples/enroll"
if [[ ! -x "$EXAMPLE" ]]; then
    echo "[enroll_grid] ERROR: $EXAMPLE not found. Run build.sh first." >&2
    exit 1
fi

# Parse extra args for the Python compositor.
EXTRA_ARGS=("$@")

TS="$(date +%Y%m%d-%H%M%S)"
SESSION_DIR="$REPO_DIR/logs/enroll-grid-$TS"
LOG="$SESSION_DIR/enroll.log"
GRID_PNG="$REPO_DIR/logs/enroll-grid-$TS.png"

mkdir -p "$SESSION_DIR" "$GM168_DIR"

# shellcheck disable=SC1091
source "$(dirname "$0")/_lib.sh"
gm168_kill_old_sessions
gm168_unlock_usb
gm168_set_default_env

echo "[enroll_grid] session  → $SESSION_DIR"
echo "[enroll_grid] grid PNG → $GRID_PNG"
echo ""

# Run enroll in the session directory so enrolled.pgm lands there.
# Pipe combined output through a stage-sniffer that copies enrolled.pgm
# after each accepted stage. stdin is kept connected to the real TTY so
# the user can answer "finger number" / "Y/N" prompts normally.
#
# stdbuf -oL forces line-buffering on tee so output appears immediately
# even when stdout is a pipe (avoids "frozen" appearance between stages).
#
# Pipeline: enroll (stdin=/dev/tty) → stdbuf tee LOG → sniffer → terminal
cd "$SESSION_DIR"

STAGE_SEQ=0   # monotonic counter across all "passed" events
TOTAL_STAGES=12

env \
    LD_LIBRARY_PATH="$PREFIX/lib64" \
    GI_TYPELIB_PATH="$PREFIX/lib64/girepository-1.0" \
    GOODIX_GM168_DIR="$GM168_DIR" \
    GM168_LOG_DIR="$SESSION_DIR" \
    G_MESSAGES_DEBUG=all \
    LIBFPRINT_DEBUG=3 \
    "$EXAMPLE" </dev/tty 2>&1 \
| stdbuf -oL tee "$LOG" \
| while IFS= read -r line; do
    # Echo every line so the user sees the interactive prompts.
    printf '%s\n' "$line"

    # Detect "Enroll stage N of M passed."
    if [[ "$line" =~ Enroll\ stage\ ([0-9]+)\ of\ ([0-9]+)\ passed ]]; then
        n="${BASH_REMATCH[1]}"
        TOTAL_STAGES="${BASH_REMATCH[2]}"
        STAGE_SEQ=$(( STAGE_SEQ + 1 ))
        dst="$SESSION_DIR/stage_$(printf '%03d' "$STAGE_SEQ").pgm"
        if [[ -f "$SESSION_DIR/enrolled.pgm" ]]; then
            cp "$SESSION_DIR/enrolled.pgm" "$dst"
            remaining=$(( TOTAL_STAGES - n ))
            echo ""
            echo "  ✓ Stage $n/$TOTAL_STAGES saved → $(basename "$dst")"
            if [[ "$remaining" -gt 0 ]]; then
                echo "  ↑ Lift finger, then touch again  ($remaining more to go)"
            else
                echo "  ✓ All $TOTAL_STAGES stages complete!"
            fi
            echo ""
        else
            echo "[enroll_grid] WARNING: enrolled.pgm missing at stage $STAGE_SEQ" >&2
        fi

    # Detect failed stage — log it so the user knows to retry.
    elif [[ "$line" =~ Enroll\ stage\ ([0-9]+)\ of\ ([0-9]+)\ failed ]]; then
        n="${BASH_REMATCH[1]}"
        echo ""
        echo "  ✗ Stage $n failed (driver rejected image) — touch again to retry"
        echo ""
    fi
done || true   # pipe exits when enroll finishes — not an error

cd - >/dev/null

echo ""
PGM_COUNT=$(ls "$SESSION_DIR"/stage_*.pgm 2>/dev/null | wc -l)
if [[ "$PGM_COUNT" -eq 0 ]]; then
    echo "[enroll_grid] No stage images collected — enroll produced no accepted stages."
    echo "[enroll_grid] Log: $LOG"
    exit 0
fi

echo "[enroll_grid] Collected $PGM_COUNT stage image(s). Composing grid…"

python3 "$(dirname "$0")/enroll_grid.py" \
    --in   "$SESSION_DIR" \
    --log  "$LOG" \
    --out  "$GRID_PNG" \
    "${EXTRA_ARGS[@]}"

echo ""
echo "[enroll_grid] done"
echo "[enroll_grid]   images : $SESSION_DIR"
echo "[enroll_grid]   log    : $LOG"
echo "[enroll_grid]   grid   : $GRID_PNG"
