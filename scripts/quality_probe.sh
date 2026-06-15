#!/usr/bin/env bash
# quality_probe.sh — run libfprint examples/enroll and extract the
# per-touch NBIS quality scores under one or more driver configs.
#
# enroll is interactive — it asks for a finger number and then waits for
# 5 (or however many stages the driver advertises) finger touches.  This
# wrapper just plumbs env vars in and tee's the raw log so we can grep
# the quality lines afterwards.
#
# Usage:
#   ./scripts/quality_probe.sh                    # default config
#   ./scripts/quality_probe.sh weak80             # one named preset
#   ./scripts/quality_probe.sh baseline weak80    # multiple back-to-back
#
# Presets (extend by editing the case below):
#   baseline   — driver defaults
#   cal2       — GM168_USE_CAL2=1
#   cal2_med   — GM168_USE_CAL2=1 GM168_USE_MEDIAN=1
#   weak80     — cal2_med + GM168_WEAK_GAP=80
#
# Output:
#   logs/quality-YYYYMMDD-HHMMSS/<preset>.log   — full enroll stdout/err
#   logs/quality-YYYYMMDD-HHMMSS/summary.txt    — per-preset quality scores
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${PREFIX:-/opt/libfprint-goodix-gm168}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="$REPO_DIR/logs/quality-$TS"
mkdir -p "$OUT_DIR"

if [[ $# -eq 0 ]]; then
    set -- baseline
fi

# locate enroll bin
ENROLL_BIN=""
for cand in \
    "$PREFIX/libexec/libfprint-2/examples/enroll" \
    "$PREFIX/libexec/installed-tests/libfprint-2/examples/enroll" \
    "$HOME/.cache/goodix-gm168/build/examples/enroll" ; do
    if [[ -x "$cand" ]]; then ENROLL_BIN="$cand"; break; fi
done
if [[ -z "$ENROLL_BIN" ]]; then
    echo "ERROR: enroll binary not found under $PREFIX or build cache" >&2
    echo "  copy it: sudo cp ~/.cache/goodix-gm168/build/examples/enroll \\" >&2
    echo "                  $PREFIX/libexec/libfprint-2/examples/" >&2
    exit 1
fi
echo "[probe] enroll bin: $ENROLL_BIN"

LIBDIR="$PREFIX/lib64"; [[ -d "$LIBDIR" ]] || LIBDIR="$PREFIX/lib"
PSK_DIR="${GOODIX_GM168_DIR:-$HOME/.goodix-gm168}"
if [[ ! -f "$PSK_DIR/psk.bin" && -f /etc/goodix-gm168/psk.bin ]]; then
    mkdir -p "$PSK_DIR"
    sudo cat /etc/goodix-gm168/psk.bin > "$PSK_DIR/psk.bin"
    chmod 600 "$PSK_DIR/psk.bin"
fi

# stop fprintd + unlock USB once for the whole session
sudo systemctl stop fprintd 2>/dev/null || true
USB=$(lsusb -d 27c6:589a | awk '{printf "/dev/bus/usb/%s/%s", $2, substr($4,1,3)}')
[[ -n "$USB" ]] && sudo chmod 666 "$USB" 2>/dev/null || true

SUMMARY="$OUT_DIR/summary.txt"
: > "$SUMMARY"

for preset in "$@"; do
    case "$preset" in
        baseline) ENV_VARS=() ;;
        cal2)     ENV_VARS=("GM168_USE_CAL2=1") ;;
        cal2_med) ENV_VARS=("GM168_USE_CAL2=1" "GM168_USE_MEDIAN=1") ;;
        weak80)   ENV_VARS=("GM168_USE_CAL2=1" "GM168_USE_MEDIAN=1" "GM168_WEAK_GAP=80") ;;
        weak40)   ENV_VARS=("GM168_USE_CAL2=1" "GM168_USE_MEDIAN=1" "GM168_WEAK_GAP=40") ;;
        *) echo "[probe] unknown preset: $preset" >&2; continue ;;
    esac

    LOG="$OUT_DIR/$preset.log"
    echo
    echo "══════════════════════════════════════════════════"
    echo "[probe] preset: $preset"
    [[ ${#ENV_VARS[@]} -gt 0 ]] && echo "[probe]  env: ${ENV_VARS[*]}" || echo "[probe]  env: (none — driver defaults)"
    echo "[probe]  → enroll will ask for a finger number then 5+ touches"
    echo "[probe]  → answer '1' for finger then touch the sensor each time it prompts"
    echo "[probe]  → log: $LOG"
    echo

    # libfprint examples/enroll reads finger index from stdin; pipe in '1\n'
    # then keep stdin open so it can wait for touches via the libfprint
    # device events (not stdin).  Use script(1) to give it a tty so the
    # prompts render correctly.
    set +e
    env LD_LIBRARY_PATH="$LIBDIR" \
        GOODIX_GM168_DIR="$PSK_DIR" \
        G_MESSAGES_DEBUG=goodix_gm168 \
        "${ENV_VARS[@]}" \
        "$ENROLL_BIN" 2>&1 | tee "$LOG"
    rc=$?
    set -e

    # Extract per-touch quality scores.  Driver emits them via gm168_log /
    # fp_dbg as "quality=<float>" or "SUBMIT quality=<float>" lines.
    {
        echo "── $preset ────────────────────────"
        echo "  exit: $rc"
        grep -oE "quality[=: ][0-9]+(\.[0-9]+)?" "$LOG" | head -20 | sed 's/^/  /'
        grep -oE "Enroll stage [0-9]+ of [0-9]+ (passed|failed)[^.]*\." "$LOG" | sed 's/^/  /'
        # NBIS minutiae count if libfprint logs it
        grep -oE "nminutiae=[0-9]+" "$LOG" | sed 's/^/  /'
        echo
    } | tee -a "$SUMMARY"

    sleep 1
done

echo
echo "═══════════════════════════════════════════════════"
echo "[probe] DONE — summary at: $SUMMARY"
echo
cat "$SUMMARY"
