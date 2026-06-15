#!/usr/bin/env bash
# single_touch.sh — capture one fingerprint touch with full pipeline dump.
#
# Runs locally on the laptop with the sensor.  Stops fprintd, opens USB,
# triggers ONE capture via libfprint's examples/img-capture, then renders
# the four pipeline stages (RAW / BG / RAW-BG / FINAL) into a grid PNG.
#
# Requires a libfprint build that includes the GM168_DUMP_FRAMES env-hook
# (commit on main: "driver: runtime frame-dump flag for one-shot diag").
#
# Usage:
#   ./scripts/single_touch.sh                 # use installed /opt build
#   PREFIX=$HOME/dev/libfprint-build ./scripts/single_touch.sh
#                                              # use a custom build tree
#   ./scripts/single_touch.sh --keep           # don't delete the tmp dump dir
#
# Output:
#   logs/single-touch-YYYYMMDD-HHMMSS.png      — pipeline grid
#   logs/single-touch-YYYYMMDD-HHMMSS/         — raw dumps (if --keep)
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$REPO_DIR/logs"
mkdir -p "$LOG_DIR"

TS="$(date +%Y%m%d-%H%M%S)"
DUMP_DIR="$(mktemp -d -t gm168-single-XXXXXX)"
OUT_PNG="$LOG_DIR/single-touch-$TS.png"

KEEP_DUMPS=0
PREFIX="${PREFIX:-/opt/libfprint-goodix-gm168}"
CAPTURE_BIN="${CAPTURE_BIN:-}"

for arg in "$@"; do
    case "$arg" in
        --keep)  KEEP_DUMPS=1 ;;
        --help|-h)
            sed -n '2,/^set -euo/p' "$0" | sed -E 's/^# ?//; /^set -euo/d'
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

cleanup () {
    if [[ "$KEEP_DUMPS" -eq 0 ]]; then
        rm -rf "$DUMP_DIR"
    else
        echo "[single_touch] kept dump dir: $DUMP_DIR"
    fi
}
trap cleanup EXIT

# --- Sanity: sensor visible? -----------------------------------------------
if ! lsusb -d 27c6:589a >/dev/null 2>&1; then
    echo "[single_touch] ERROR: GM168SEC (27c6:589a) not on USB bus." >&2
    exit 1
fi

# --- Locate the capture binary ---------------------------------------------
if [[ -z "$CAPTURE_BIN" ]]; then
    for cand in \
        "$PREFIX/libexec/libfprint-2/examples/img-capture" \
        "$PREFIX/libexec/installed-tests/libfprint-2/examples/img-capture" \
        "$HOME/.cache/goodix-gm168/build/examples/img-capture" \
        "$HOME/dev/libfprint-build/examples/img-capture" \
        "$HOME/dev/libfprint/build/examples/img-capture" ; do
        if [[ -x "$cand" ]]; then CAPTURE_BIN="$cand"; break; fi
    done
fi
if [[ -z "$CAPTURE_BIN" || ! -x "$CAPTURE_BIN" ]]; then
    echo "[single_touch] ERROR: cannot find img-capture binary." >&2
    echo "  set CAPTURE_BIN=/path/to/img-capture or build libfprint first." >&2
    exit 1
fi
echo "[single_touch] capture bin: $CAPTURE_BIN"
echo "[single_touch] dump dir   : $DUMP_DIR"

# --- Stop fprintd so it doesn't grab the USB device ------------------------
if systemctl is-active --quiet fprintd 2>/dev/null; then
    sudo -n systemctl stop fprintd || sudo systemctl stop fprintd
fi
RESTORE_FPRINTD=0
if systemctl is-enabled fprintd >/dev/null 2>&1; then
    RESTORE_FPRINTD=1
fi

# --- Open USB device permissions -------------------------------------------
USB_NODE=$(lsusb -d 27c6:589a | awk '{printf "/dev/bus/usb/%s/%s", $2, substr($4,1,3)}')
if [[ -e "$USB_NODE" ]]; then
    sudo -n chmod 666 "$USB_NODE" 2>/dev/null || sudo chmod 666 "$USB_NODE"
fi

# --- Trigger ONE capture ---------------------------------------------------
PSK_DIR="${GOODIX_GM168_DIR:-$HOME/.goodix-gm168}"
if [[ ! -f "$PSK_DIR/psk.bin" && -f /etc/goodix-gm168/psk.bin ]]; then
    # The driver looks at GOODIX_GM168_DIR first, then /etc.  Mirror the
    # production PSK into the user dir so we don't need root just to read it.
    install -d "$PSK_DIR"
    sudo cat /etc/goodix-gm168/psk.bin > "$PSK_DIR/psk.bin"
    chmod 600 "$PSK_DIR/psk.bin"
fi

LIBDIR="$PREFIX/lib64"
[[ -d "$LIBDIR" ]] || LIBDIR="$PREFIX/lib"

echo "[single_touch] *** touch the sensor when prompted ***"
timeout 30 env \
    LD_LIBRARY_PATH="$LIBDIR" \
    GOODIX_GM168_DIR="$PSK_DIR" \
    GM168_DUMP_FRAMES=1 \
    GM168_DUMP_DIR="$DUMP_DIR" \
    G_MESSAGES_DEBUG=goodix_gm168 \
    "$CAPTURE_BIN" "$DUMP_DIR/raw.pnm" \
    2>&1 | tee "$DUMP_DIR/capture.log" | grep -iE "init|tls handshake|capture|frame dump|touch|error" || true

# --- Verify we got dumps ---------------------------------------------------
shopt -s nullglob
RAW_DUMPS=( "$DUMP_DIR"/gm168_*_raw16.bin )
shopt -u nullglob
if [[ ${#RAW_DUMPS[@]} -eq 0 ]]; then
    echo "[single_touch] ERROR: no frame dumps captured." >&2
    echo "  Check that the driver is the one with GM168_DUMP_FRAMES support." >&2
    echo "  $DUMP_DIR/capture.log may have details." >&2
    [[ -s "$DUMP_DIR/capture.log" ]] && tail -20 "$DUMP_DIR/capture.log" >&2
    KEEP_DUMPS=1
    exit 1
fi

echo "[single_touch] got ${#RAW_DUMPS[@]} frame dump(s)"

# --- Render grid -----------------------------------------------------------
python3 "$REPO_DIR/scripts/single_touch_render.py" \
    --in  "$DUMP_DIR" \
    --out "$OUT_PNG"

echo
echo "[single_touch] DONE — grid PNG: $OUT_PNG"

# --- Restore fprintd if it was active --------------------------------------
if [[ "$RESTORE_FPRINTD" -eq 1 ]]; then
    sudo -n systemctl start fprintd 2>/dev/null || sudo systemctl start fprintd || true
fi
