#!/usr/bin/env bash
# One-time setup on the Fedora laptop: dev tools, libfprint deps, repo dirs,
# udev rule, plugdev group. Re-runnable.
set -euo pipefail

# Refuse to run as root — script uses $HOME/$USER and self-sudoes for
# the privileged steps. Running under sudo makes $HOME=/root which
# breaks subsequent ./scripts/release.sh runs as the normal user.
if [[ "$(id -u)" -eq 0 ]]; then
    echo "[bootstrap] ERROR: do NOT run as root / under sudo."
    echo "            Run as your normal user — the script will sudo where needed."
    exit 1
fi

DEV_DIR="${DEV_DIR:-$HOME/dev}"
REPO_DIR="${REPO_DIR:-$DEV_DIR/goodix-gm168}"
LIBFPRINT_DIR="${LIBFPRINT_DIR:-$DEV_DIR/libfprint}"
PREFIX="${PREFIX:-/opt/libfprint-gm168}"
LIBFPRINT_TAG="${LIBFPRINT_TAG:-v1.94.9}"

echo "[bootstrap] install dnf packages"
# Note: gusb-devel was renamed to libgusb-devel in newer Fedora.
# --skip-unavailable lets dnf install everything that exists; we
# verify the critical bits afterwards.
sudo dnf install -y --skip-unavailable \
    git rsync make gcc gcc-c++ pkgconf-pkg-config \
    meson ninja-build \
    glib2-devel libgusb-devel gusb-devel openssl-devel \
    cairo-devel gobject-introspection-devel \
    libfprint nss-devel \
    pixman-devel

# Verify the critical build tools landed.
missing=()
for cmd in meson ninja gcc pkg-config rsync git; do
    command -v "$cmd" >/dev/null || missing+=("$cmd")
done
if (( ${#missing[@]} > 0 )); then
    echo "[bootstrap] ERROR: missing tools after dnf: ${missing[*]}"
    echo "            Try: sudo dnf install -y ${missing[*]}"
    exit 1
fi
# Verify gusb dev headers landed under either name.
if ! pkg-config --exists gusb; then
    echo "[bootstrap] ERROR: gusb pkg-config not found after install."
    echo "            Try: sudo dnf install -y libgusb-devel"
    exit 1
fi

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
