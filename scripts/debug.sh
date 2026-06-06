#!/usr/bin/env bash
# Debug runner with two output streams:
#   - raw log    → logs/<ts>-<action>-raw.log    (full firehose, every fp_dbg)
#   - clean log  → logs/<ts>-<action>-clean.log  (filtered, human-readable)
#                  ...also tee'd to your terminal as it runs
#
# Usage:
#   ./scripts/debug.sh                # default action: enroll
#   ./scripts/debug.sh enroll
#   ./scripts/debug.sh verify
#   ./scripts/debug.sh img-capture
#
# The driver-only filter keeps:
#   - BG capture / BG averaged (hash, sum, min, max)
#   - TLS handshake events
#   - INIT_* state labels (the named ones, not SSM "entering state NN")
#   - capture completed, decoded payload heads
#   - finger status changes, "Scan your finger" prompts
#   - NBIS / quality / stage events
#   - any WARNING / ERROR / Failed / fp_warn
#
# Drops:
#   - per-state SSM transitions ("entering state NN")
#   - ack_cb hex dumps (RAW IN ...)
#   - decode_img per-frame TLS header lines
#   - tls_feed byte-count chatter
#   - libfprint-image_device internal state change spam
set -euo pipefail

DEV_DIR="${DEV_DIR:-$HOME/dev}"
BUILD_DIR="${BUILD_DIR:-$DEV_DIR/libfprint-build}"
PREFIX="${PREFIX:-/opt/libfprint-gm168}"
REPO_DIR="${REPO_DIR:-$DEV_DIR/goodix-gm168}"
GM168_DIR="${GOODIX_GM168_DIR:-$HOME/.goodix-gm168}"

ACTION="${1:-enroll}"
EXAMPLE="$BUILD_DIR/examples/$ACTION"

if [[ ! -x "$EXAMPLE" ]]; then
    echo "[debug] $EXAMPLE not found. Available:"
    ls "$BUILD_DIR/examples/" 2>/dev/null | grep -vE '\.(p|o)$' || true
    exit 1
fi

mkdir -p "$REPO_DIR/logs" "$GM168_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
RAW="$REPO_DIR/logs/${TS}-${ACTION}-raw.log"
CLEAN="$REPO_DIR/logs/${TS}-${ACTION}-clean.log"

# shellcheck disable=SC1091
source "$(dirname "$0")/_lib.sh"
gm168_kill_old_sessions
gm168_unlock_usb
gm168_set_default_env

# Clean per-frame dumps so logs/dumps from previous runs aren't mixed in.
rm -f /tmp/gm168_*.bin 2>/dev/null || true

# Keep-pattern — anything matching prints. Order matters only for clarity.
KEEP='BG averaged|BG capture |TLS handshake|INIT_RESET|INIT_WAKEUP|INIT_VERSION|INIT_OTP|INIT_SESSION|INIT_BG_|INIT_CAL|INIT_REARM|Device completely armed|change_state:|CAP_PROCESS|CAP_RX|capture: decrypted|Decoded frame|fp_warn|WARNING|ERROR|Failed|Error |Quality|quality|nbis|NBIS|stage|Stage|Scan your finger|Choose the finger|finger status|FP_FINGER|Match|match|No match|enroll-completed|enroll-stage|enroll-failed|verify-completed|verify-no-match|verify-match|EOF encountered|psk\.bin|sealed\.bin|Initialization|Initializing FpContext'

# Drop-pattern — explicit overrides (silent even if KEEP matches).
DROP='entering state [0-9]+|ack_cb: RAW IN|decode_img: Found TLS header|decode_img: TLS header|tls_feed wrote|libfprint-image_device-DEBUG:.*state change|libfprint-SSM-DEBUG:'

echo "[debug] action=$ACTION"
echo "[debug] raw   → $RAW"
echo "[debug] clean → $CLEAN  (mirrored to terminal below)"
echo "[debug] env   CAL2=${GM168_USE_CAL2:-off}  CLAHE=${GM168_USE_CLAHE:-off}  MEDIAN=${GM168_USE_MEDIAN:-off}  WALLIS=${GM168_USE_WALLIS:-off}/${GM168_NO_WALLIS:-on-default}"
echo "------------------------------------------------------------"

env \
    LD_LIBRARY_PATH="$PREFIX/lib64" \
    GI_TYPELIB_PATH="$PREFIX/lib64/girepository-1.0" \
    GOODIX_GM168_DIR="$GM168_DIR" \
    G_MESSAGES_DEBUG=all \
    LIBFPRINT_DEBUG=3 \
    "$EXAMPLE" 2>&1 \
  | tee "$RAW" \
  | grep --line-buffered -vE "$DROP" \
  | grep --line-buffered -E "$KEEP" \
  | tee "$CLEAN"

echo "------------------------------------------------------------"
echo "[debug] done"
echo "[debug] raw  : $(wc -l <"$RAW") lines"
echo "[debug] clean: $(wc -l <"$CLEAN") lines"
DUMPS=$(ls /tmp/gm168_*.bin 2>/dev/null | wc -l)
[[ "$DUMPS" -gt 0 ]] && echo "[debug] frame dumps: $DUMPS files in /tmp/gm168_*.bin"
