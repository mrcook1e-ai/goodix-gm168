#!/usr/bin/env bash
# Push the working tree from this PC to the Fedora laptop.
# Run on PC (Git Bash / WSL). Requires passwordless SSH on port 2200.
set -euo pipefail

REMOTE_HOST="${GM168_HOST:-mrcook1e@192.168.1.14}"
REMOTE_PORT="${GM168_PORT:-2200}"
REMOTE_DIR="${GM168_REMOTE_DIR:-/home/mrcook1e/dev/goodix-gm168}"

HERE="$(cd "$(dirname "$0")/.." && pwd)"

echo "[deploy] $HERE  -->  ${REMOTE_HOST}:${REMOTE_DIR} (port ${REMOTE_PORT})"

ssh -p "$REMOTE_PORT" "$REMOTE_HOST" "mkdir -p '$REMOTE_DIR'"

if command -v rsync >/dev/null 2>&1; then
    rsync -az --delete \
        --exclude='.git/' \
        --exclude='build/' \
        --exclude='logs/' \
        --exclude='_fetched/' \
        --exclude='*.bndb' \
        -e "ssh -p $REMOTE_PORT" \
        "$HERE"/ \
        "${REMOTE_HOST}:${REMOTE_DIR}/"
else
    # Fallback: tar pipe (no --delete, but fine for dev iteration).
    # Used on Windows Git Bash where rsync isn't shipped.
    tar -cz \
        --exclude='./.git' \
        --exclude='./build' \
        --exclude='./logs' \
        --exclude='./_fetched' \
        --exclude='*.bndb' \
        -C "$HERE" . \
      | ssh -p "$REMOTE_PORT" "$REMOTE_HOST" "tar -xz -C '$REMOTE_DIR'"
fi

echo "[deploy] done"
