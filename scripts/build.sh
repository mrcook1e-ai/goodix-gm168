#!/usr/bin/env bash
# Build patched libfprint into /opt/libfprint-gm168.
# Run on Fedora laptop. Idempotent.
set -euo pipefail

DEV_DIR="${DEV_DIR:-$HOME/dev}"
REPO_DIR="${REPO_DIR:-$DEV_DIR/goodix-gm168}"
LIBFPRINT_DIR="${LIBFPRINT_DIR:-$DEV_DIR/libfprint}"
BUILD_DIR="${BUILD_DIR:-$DEV_DIR/libfprint-build}"
PREFIX="${PREFIX:-/opt/libfprint-gm168}"

PATCH="$REPO_DIR/patches/libfprint-add-gm168.patch"
SRC_DST="$LIBFPRINT_DIR/libfprint/drivers/goodix_gm168"

if [[ ! -d "$LIBFPRINT_DIR/.git" ]]; then
    echo "[build] libfprint not found at $LIBFPRINT_DIR — run bootstrap-fedora.sh first"
    exit 1
fi

echo "[build] sync driver sources into libfprint tree"
mkdir -p "$SRC_DST"
rsync -a --delete \
    --exclude='meson.build' \
    "$REPO_DIR/src/" "$SRC_DST/"
# The in-tree meson.build is provided by the patch, not by our standalone one.

echo "[build] apply patch (if not already applied)"
cd "$LIBFPRINT_DIR"
if git apply --check "$PATCH" 2>/dev/null; then
    git apply "$PATCH"
    echo "[build]   patch applied"
else
    echo "[build]   patch already applied (or conflicts — check 'git status')"
fi

echo "[build] meson setup ($PREFIX)"
if [[ ! -d "$BUILD_DIR" ]]; then
    meson setup "$BUILD_DIR" "$LIBFPRINT_DIR" \
        --prefix="$PREFIX" \
        --libdir=lib64 \
        -Ddrivers=default \
        -Dudev_rules=disabled \
        -Dgtk-examples=false \
        -Ddoc=false \
        -Dintrospection=false
else
    meson setup --reconfigure "$BUILD_DIR" "$LIBFPRINT_DIR" \
        --prefix="$PREFIX" \
        --libdir=lib64
fi

echo "[build] compile"
meson compile -C "$BUILD_DIR"

echo "[build] install (needs sudo for $PREFIX)"
sudo meson install -C "$BUILD_DIR"

echo "[build] done — prefix=$PREFIX"
