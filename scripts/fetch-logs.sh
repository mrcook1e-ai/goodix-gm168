#!/usr/bin/env bash
# Pull logs + frame dumps from the Fedora laptop back to PC.
# Run on PC.
set -euo pipefail

REMOTE_HOST="${GM168_HOST:-mrcook1e@192.168.1.23}"
REMOTE_PORT="${GM168_PORT:-22}"
REMOTE_DIR="${GM168_REMOTE_DIR:-/home/mrcook1e/dev/goodix-gm168}"

HERE="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
DEST="$HERE/_fetched/$STAMP"

mkdir -p "$DEST"
echo "[fetch] ${REMOTE_HOST}:${REMOTE_DIR}/logs/  -->  $DEST/logs/"
rsync -az -e "ssh -p $REMOTE_PORT" \
    "${REMOTE_HOST}:${REMOTE_DIR}/logs/" "$DEST/logs/" || true

echo "[fetch] ${REMOTE_HOST}:/tmp/gm168_*.bin  -->  $DEST/dumps/"
mkdir -p "$DEST/dumps"
rsync -az -e "ssh -p $REMOTE_PORT" \
    "${REMOTE_HOST}:/tmp/gm168_*.bin" "$DEST/dumps/" 2>/dev/null || \
    echo "[fetch]   no /tmp/gm168_*.bin on remote"

echo "[fetch] done — $DEST"
