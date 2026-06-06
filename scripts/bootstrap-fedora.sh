#!/usr/bin/env bash
# One-time setup on the Fedora laptop: dev tools, libfprint deps, repo dirs,
# udev rule, plugdev group. Re-runnable.
set -euo pipefail

DEV_DIR="${DEV_DIR:-$HOME/dev}"
REPO_DIR="${REPO_DIR:-$DEV_DIR/goodix-gm168}"
LIBFPRINT_DIR="${LIBFPRINT_DIR:-$DEV_DIR/libfprint}"
PREFIX="${PREFIX:-/opt/libfprint-gm168}"
LIBFPRINT_TAG="${LIBFPRINT_TAG:-v1.94.9}"

echo "[bootstrap] install dnf packages"
sudo dnf install -y \
    git rsync make gcc pkgconf-pkg-config \
    meson ninja-build \
    glib2-devel gusb-devel openssl-devel \
    cairo-devel gobject-introspection-devel \
    libfprint nss-devel \
    pixman-devel || true

echo "[bootstrap] create dirs"
mkdir -p "$DEV_DIR" "$REPO_DIR/logs"
sudo mkdir -p "$PREFIX"
sudo chown "$USER:$USER" "$PREFIX"

if [[ ! -d "$LIBFPRINT_DIR/.git" ]]; then
    echo "[bootstrap] clone libfprint (tag $LIBFPRINT_TAG)"
    git clone https://gitlab.freedesktop.org/libfprint/libfprint.git "$LIBFPRINT_DIR"
    cd "$LIBFPRINT_DIR"
    git checkout "$LIBFPRINT_TAG"
else
    echo "[bootstrap] libfprint already cloned at $LIBFPRINT_DIR"
fi

if [[ -f "$REPO_DIR/udev/60-goodix-gm168.rules" ]]; then
    echo "[bootstrap] install udev rule"
    sudo install -m 644 "$REPO_DIR/udev/60-goodix-gm168.rules" /etc/udev/rules.d/
    sudo udevadm control --reload
    sudo udevadm trigger
fi

if ! getent group plugdev >/dev/null; then
    sudo groupadd plugdev
fi
if ! id -nG "$USER" | grep -qw plugdev; then
    sudo usermod -aG plugdev "$USER"
    echo "[bootstrap] added $USER to plugdev — log out/in for it to take effect"
fi

echo "[bootstrap] done"
echo "  dev dir:   $DEV_DIR"
echo "  libfprint: $LIBFPRINT_DIR (@$LIBFPRINT_TAG)"
echo "  prefix:    $PREFIX"
echo "Next: run ./scripts/build.sh (after deploy.sh has synced sources + patch)"
