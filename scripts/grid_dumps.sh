#!/usr/bin/env bash
# Pull /tmp/gm168_*_fpimg.pgm dumps from the laptop and compose a grid PNG.
#
# Requires the driver to be built with -DGM168_DEBUG. The first invocation
# without dumps will print instructions for enabling that.
#
# Usage:
#   ./scripts/grid_dumps.sh debug-build   # remote: enable -DGM168_DEBUG + rebuild
#   ./scripts/grid_dumps.sh clean         # remote: rm /tmp/gm168_*
#   ./scripts/grid_dumps.sh               # pull dumps + compose grid
#   ./scripts/grid_dumps.sh --no-log      # skip quality annotations
#
# Output: logs/grid-<TS>.png and logs/grid-<TS>/ (raw dumps).
set -euo pipefail

REMOTE_HOST="${GM168_HOST:-mrcook1e@192.168.1.14}"
REMOTE_PORT="${GM168_PORT:-2200}"
REMOTE_DIR="${GM168_REMOTE_DIR:-/home/mrcook1e/dev/goodix-gm168}"
BUILD_DIR_REMOTE="${GM168_REMOTE_BUILD:-/home/mrcook1e/dev/libfprint-build}"

HERE="$(cd "$(dirname "$0")/.." && pwd)"

SSH() { ssh -p "$REMOTE_PORT" "$REMOTE_HOST" "$@"; }
SCP() { scp -P "$REMOTE_PORT" "$@"; }

cmd="${1:-grid}"

case "$cmd" in
    debug-build)
        echo "[grid] enabling -DGM168_DEBUG on remote and rebuilding"
        SSH "set -e
            cd '$BUILD_DIR_REMOTE'
            meson configure -Dc_args='-DGM168_DEBUG' >/dev/null
            meson compile
            sudo meson install
            echo '[grid] debug build installed at /opt/libfprint-gm168'"
        exit 0
        ;;
    release-build)
        echo "[grid] disabling -DGM168_DEBUG on remote and rebuilding"
        SSH "set -e
            cd '$BUILD_DIR_REMOTE'
            meson configure -Dc_args='' >/dev/null
            meson compile
            sudo meson install
            echo '[grid] release build installed at /opt/libfprint-gm168'"
        exit 0
        ;;
    clean)
        echo "[grid] removing /tmp/gm168_* on remote"
        SSH "rm -f /tmp/gm168_*"
        exit 0
        ;;
    --no-log)
        WANT_LOG=0
        ;;
    grid|"")
        WANT_LOG=1
        ;;
    *)
        echo "unknown command: $cmd" >&2
        echo "usage: $0 [debug-build|release-build|clean|grid|--no-log]" >&2
        exit 1
        ;;
esac

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="$HERE/logs/grid-$TS"
mkdir -p "$OUT_DIR"

echo "[grid] pulling /tmp/gm168_*_fpimg.pgm  →  $OUT_DIR"
if ! SCP "$REMOTE_HOST:/tmp/gm168_*_fpimg.pgm" "$OUT_DIR/" 2>/dev/null; then
    rmdir "$OUT_DIR" 2>/dev/null || true
    echo "[grid] no dumps found on remote."
    echo "[grid] you need a GM168_DEBUG-enabled build. Steps:"
    echo "[grid]   1) ./scripts/grid_dumps.sh debug-build"
    echo "[grid]   2) trigger one or more captures (debug.sh enroll / img-capture)"
    echo "[grid]   3) ./scripts/grid_dumps.sh"
    exit 1
fi

# Also pull raw16.bin and bg16.bin if present — enables --with-raw and
# --with-bgdiff for forensic analysis (decoder vs preprocessor split).
SCP "$REMOTE_HOST:/tmp/gm168_*_raw16.bin" "$OUT_DIR/" 2>/dev/null || true
SCP "$REMOTE_HOST:/tmp/gm168_*_bg16.bin"  "$OUT_DIR/" 2>/dev/null || true
RAW_COUNT=$(ls "$OUT_DIR"/*_raw16.bin 2>/dev/null | wc -l)
BG_COUNT=$(ls "$OUT_DIR"/*_bg16.bin 2>/dev/null | wc -l)
[[ "$RAW_COUNT" -gt 0 ]] && echo "[grid] also pulled $RAW_COUNT raw16 dumps"
[[ "$BG_COUNT" -gt 0 ]]  && echo "[grid] also pulled $BG_COUNT bg16 dumps"

PGM_COUNT=$(ls "$OUT_DIR"/*.pgm 2>/dev/null | wc -l)
echo "[grid] pulled $PGM_COUNT dumps"
if [[ "$PGM_COUNT" -eq 0 ]]; then
    echo "[grid] no .pgm files in $OUT_DIR after scp — bailing"
    exit 1
fi

LOG_ARG=()
if [[ "${WANT_LOG:-1}" == "1" ]]; then
    # Pull the most recent enroll-clean / img-capture-clean log to annotate
    # tiles with quality scores.
    REMOTE_LOG="$(SSH "ls -t '$REMOTE_DIR'/logs/*-clean.log 2>/dev/null | head -1")"
    if [[ -n "$REMOTE_LOG" ]]; then
        echo "[grid] pulling matching log: $(basename "$REMOTE_LOG")"
        SCP "$REMOTE_HOST:$REMOTE_LOG" "$OUT_DIR/source.log"
        LOG_ARG=(--log "$OUT_DIR/source.log")
    fi
fi

OUT_PNG="$HERE/logs/grid-$TS.png"
EXTRA_ARGS=()
[[ "${RAW_COUNT:-0}" -gt 0 ]] && EXTRA_ARGS+=(--with-raw)
[[ "${BG_COUNT:-0}" -gt 0 && "${RAW_COUNT:-0}" -gt 0 ]] && EXTRA_ARGS+=(--with-bgdiff)
python3 "$HERE/scripts/grid_dumps.py" \
    --in "$OUT_DIR" \
    --out "$OUT_PNG" \
    "${LOG_ARG[@]}" \
    "${EXTRA_ARGS[@]}"

echo "[grid] done"
echo "[grid]   raw dumps: $OUT_DIR"
echo "[grid]   grid PNG : $OUT_PNG"
