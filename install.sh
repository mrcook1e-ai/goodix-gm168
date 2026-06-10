#!/usr/bin/env bash
# install.sh — one-shot installer for the goodix-gm168 libfprint driver.
#
# What it does:
#   1. Verifies you're on Fedora 41+ (only tested target).
#   2. dnf-installs the build prerequisites.
#   3. Clones libfprint 1.94.10 if it isn't already in ~/.cache.
#   4. Applies the goodix-gm168 patch and builds libfprint with our
#      driver into /opt/libfprint-goodix-gm168/.
#   5. Drops the libfprint-2.so symlinks system-wide so fprintd picks
#      them up without modifying /usr.
#   6. Installs the udev rule and creates /etc/goodix-gm168/.
#   7. Restarts fprintd if it's running.
#
# After this script you still need to drop a 32-byte psk.bin into
# /etc/goodix-gm168/ — see INSTALL.md "PSK bootstrap".
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/mrcook1e-ai/goodix-gm168/main/install.sh | bash
# or in a checkout:
#   bash install.sh

set -euo pipefail

# --- Config -----------------------------------------------------------
LIBFPRINT_VER="${LIBFPRINT_VER:-1.94.10}"
PREFIX="${PREFIX:-/opt/libfprint-goodix-gm168}"
CACHE_DIR="${CACHE_DIR:-$HOME/.cache/goodix-gm168}"
REPO_URL="${REPO_URL:-https://github.com/mrcook1e-ai/goodix-gm168.git}"
REPO_REF="${REPO_REF:-main}"

# --- Sanity -----------------------------------------------------------
log()  { printf '\033[1;34m[install]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[install] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

if ! command -v dnf >/dev/null 2>&1; then
    die "dnf not found — this installer only supports Fedora.  See INSTALL.md for manual build."
fi
if ! grep -q '^ID=fedora' /etc/os-release 2>/dev/null; then
    die "not running on Fedora — see INSTALL.md for manual build."
fi

FEDORA_VER=$(awk -F= '/^VERSION_ID=/{print $2}' /etc/os-release | tr -d '"')
if [ "${FEDORA_VER:-0}" -lt 41 ]; then
    die "Fedora $FEDORA_VER too old — tested on 41+."
fi

if ! lsusb 2>/dev/null | grep -qi '27c6:589a'; then
    log "warning: no 27c6:589a device on the USB bus right now."
    log "  installing anyway, but verify the device is the GM168SEC before enrolling."
fi

# --- Deps -------------------------------------------------------------
log "installing build prerequisites via dnf (sudo)"
sudo dnf install -y --setopt=install_weak_deps=False \
    git meson ninja-build gcc pkgconf-pkg-config \
    glib2-devel gobject-introspection-devel \
    libgusb-devel openssl-devel \
    cairo-devel pixman-devel \
    systemd-devel libgudev-devel \
    nss-devel mbedtls-devel \
    fprintd >/dev/null

# --- Source layout ----------------------------------------------------
mkdir -p "$CACHE_DIR"
cd "$CACHE_DIR"

if [ -d goodix-gm168/.git ]; then
    log "updating existing goodix-gm168 checkout"
    git -C goodix-gm168 fetch --quiet origin
    git -C goodix-gm168 reset --hard --quiet "origin/$REPO_REF"
else
    log "cloning goodix-gm168"
    git clone --quiet --depth=20 --branch "$REPO_REF" "$REPO_URL" goodix-gm168
fi
GM168_DIR="$CACHE_DIR/goodix-gm168"

if [ -d "libfprint-$LIBFPRINT_VER" ]; then
    log "reusing cached libfprint-$LIBFPRINT_VER"
    git -C "libfprint-$LIBFPRINT_VER" reset --hard --quiet HEAD
else
    log "cloning libfprint $LIBFPRINT_VER"
    git clone --quiet --depth=1 --branch "v$LIBFPRINT_VER" \
        https://gitlab.freedesktop.org/libfprint/libfprint.git \
        "libfprint-$LIBFPRINT_VER"
fi
LIBFPRINT_DIR="$CACHE_DIR/libfprint-$LIBFPRINT_VER"

# --- Sync driver into libfprint tree + apply patch -------------------
log "copying driver sources into libfprint tree"
DST="$LIBFPRINT_DIR/libfprint/drivers/goodix_gm168"
mkdir -p "$DST"
# Exclude the standalone meson.build — the in-tree one comes from the patch.
rsync -a --delete --exclude='meson.build' "$GM168_DIR/src/" "$DST/"

log "applying libfprint patch"
( cd "$LIBFPRINT_DIR" \
  && git apply --check "$GM168_DIR/patches/libfprint-add-gm168.patch" 2>/dev/null \
  && git apply "$GM168_DIR/patches/libfprint-add-gm168.patch" ) \
  || die "patch did not apply cleanly — check $LIBFPRINT_DIR for conflicts."

# --- Build + install --------------------------------------------------
BUILD_DIR="$CACHE_DIR/build"
log "configuring meson → $PREFIX"
rm -rf "$BUILD_DIR"
meson setup "$BUILD_DIR" "$LIBFPRINT_DIR" \
    --prefix="$PREFIX" \
    --libdir=lib64 \
    -Ddrivers=default \
    -Dudev_rules=disabled \
    -Dgtk-examples=false \
    -Ddoc=false \
    -Dintrospection=false \
    >/dev/null

log "compiling"
meson compile -C "$BUILD_DIR" >/dev/null

log "installing to $PREFIX (sudo)"
sudo meson install -C "$BUILD_DIR" >/dev/null

# --- Make fprintd find our libfprint ---------------------------------
log "wiring fprintd to $PREFIX/lib64 via ld.so.conf.d"
sudo tee /etc/ld.so.conf.d/goodix-gm168.conf >/dev/null <<EOF
$PREFIX/lib64
EOF
sudo ldconfig

# --- udev + state dir ------------------------------------------------
log "installing udev rule (uaccess for 27c6:589a)"
sudo install -D -m 0644 \
    "$GM168_DIR/packaging/udev/70-goodix-gm168.rules" \
    /etc/udev/rules.d/70-goodix-gm168.rules
sudo udevadm control --reload
sudo udevadm trigger --subsystem-match=usb --attr-match=idVendor=27c6 || true

log "creating /etc/goodix-gm168/"
sudo install -d -m 0755 /etc/goodix-gm168

# --- fprintd restart -------------------------------------------------
if systemctl is-active --quiet fprintd; then
    log "restarting fprintd"
    sudo systemctl restart fprintd
fi

# --- Done ------------------------------------------------------------
cat <<EOF

  ✓ Driver built and installed.

Next steps:
  1. Get the PSK for your sensor (see INSTALL.md "PSK bootstrap").
  2. sudo install -m 600 psk.bin /etc/goodix-gm168/psk.bin
  3. fprintd-enroll

If 'fprintd-enroll' reports "No driver found", the sensor isn't on the
USB bus, or the udev rule didn't take.  Verify with:
  lsusb | grep 27c6:589a
  getfacl /dev/bus/usb/\$(lsusb | grep 27c6:589a | awk '{print \$2"/"\$4}' | tr -d ':')

EOF
