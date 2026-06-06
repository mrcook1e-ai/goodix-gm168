#!/usr/bin/env bash
# Production install of the goodix_gm168 driver — runs natively on the
# Fedora laptop (no SSH, no remote host). Assumes the repo is checked
# out locally and bootstrap-fedora.sh has been run.
#
# What this does (idempotent, safe to re-run):
#   1. Sync src/ into the libfprint tree + clean release build (-O2, no
#      -DGM168_DEBUG), installed to /opt/libfprint-gm168
#   2. Install udev rule for VID:PID 27c6:589a
#   3. Install fprintd + polkit from Fedora repos if missing
#   4. Drop a systemd override into fprintd.service pointing at /opt
#   5. Polkit rule allowing wheel group to enroll/verify
#   6. Restart fprintd
#
# PAM integration (login screen, sudo) is NOT done by this script —
# it changes system auth behaviour. Run separately:
#   sudo authselect select sssd with-fingerprint --force
#
# Usage:
#   ./scripts/release.sh             # full release install
#   ./scripts/release.sh build       # only step 1
#   ./scripts/release.sh udev        # only step 2
#   ./scripts/release.sh fprintd     # only step 3
#   ./scripts/release.sh systemd     # only step 4-5
#   ./scripts/release.sh restart     # only step 6
#   ./scripts/release.sh status      # show current install state
#   ./scripts/release.sh backup-psk  # copy /etc PSK to logs/

set -euo pipefail

# Resolve repo root from script location (works whether called from
# repo root, scripts/, or via absolute path).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${GM168_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"

DEV_DIR="${GM168_DEV_DIR:-$HOME/dev}"
LIBFPRINT_DIR="${GM168_LIBFPRINT_DIR:-$DEV_DIR/libfprint}"
BUILD_DIR="${GM168_BUILD_DIR:-$DEV_DIR/libfprint-build}"
PREFIX="${GM168_PREFIX:-/opt/libfprint-gm168}"

step_build() {
    echo "[release] step 1: clean release build (no -DGM168_DEBUG)"
    if [[ ! -d "$LIBFPRINT_DIR/.git" ]]; then
        echo "[release] ERROR: $LIBFPRINT_DIR not found."
        echo "          Run ./scripts/bootstrap-fedora.sh first."
        exit 1
    fi

    # Sync the latest source into the libfprint tree. Without this,
    # meson compile uses the last-synced source which may be stale.
    SRC_DST="$LIBFPRINT_DIR/libfprint/drivers/goodix_gm168"
    mkdir -p "$SRC_DST"
    rsync -a --delete --exclude='meson.build' "$REPO_DIR/src/" "$SRC_DST/"

    # Apply the libfprint patch if not already applied.
    PATCH="$REPO_DIR/patches/libfprint-add-gm168.patch"
    if [[ -f "$PATCH" ]]; then
        cd "$LIBFPRINT_DIR"
        if git apply --reverse --check "$PATCH" 2>/dev/null; then
            echo "[release]   libfprint patch already applied"
        else
            echo "[release]   applying $PATCH"
            git apply "$PATCH" || echo "[release]   patch apply failed — review manually"
        fi
    fi

    # First-time configure if build dir doesn't exist.
    if [[ ! -d "$BUILD_DIR" ]]; then
        echo "[release]   first-time meson setup → $BUILD_DIR"
        meson setup "$BUILD_DIR" "$LIBFPRINT_DIR" \
            --prefix="$PREFIX" \
            --buildtype=release \
            -Dc_args='-O2 -DNDEBUG' \
            -Dintrospection=false \
            -Ddoc=false \
            -Dgtk-examples=false
    else
        cd "$BUILD_DIR"
        meson configure -Dc_args='-O2 -DNDEBUG' -Dbuildtype=release >/dev/null
    fi

    cd "$BUILD_DIR"
    meson compile
    sudo meson install
    echo "[release]   build OK, installed to $PREFIX"

    # Sanity: GM168_DEBUG strings must not be in the linked libfprint.
    SO="$PREFIX/lib64/libfprint-2.so.2.0.0"
    if strings "$SO" 2>/dev/null | grep -q 'DEBUG: dumped seq'; then
        echo "[release] WARNING: GM168_DEBUG strings still in binary"
        exit 1
    fi
    echo "[release]   confirmed: GM168_DEBUG is OFF"
}

step_udev() {
    echo "[release] step 2: udev rule for 27c6:589a"
    sudo install -m 644 "$REPO_DIR/udev/60-goodix-gm168.rules" \
        /etc/udev/rules.d/60-goodix-gm168.rules
    sudo udevadm control --reload
    sudo udevadm trigger
    echo "[release]   udev rule installed"

    ME="$(id -un)"
    # plugdev is a Debian/Ubuntu convention. Fedora uses uaccess via the
    # udev rule's TAG+="uaccess", granting access to the active console
    # user automatically — no group needed. Create the group only if it
    # already exists in some form (no-op on stock Fedora).
    if getent group plugdev >/dev/null; then
        if ! id -nG "$ME" | grep -qw plugdev; then
            echo "[release]   adding $ME to plugdev (logout required to take effect)"
            sudo usermod -aG plugdev "$ME"
        else
            echo "[release]   $ME already in plugdev"
        fi
    else
        echo "[release]   plugdev group not present (Fedora uses uaccess) — skipping"
    fi
}

step_fprintd_install() {
    echo "[release] step 3: ensure fprintd + polkit are installed"
    # polkit is mandatory: fprintd uses it to authorise device claim.
    # On minimal Fedora it isn't pulled in by fprintd's deps.
    sudo dnf install -y fprintd fprintd-pam polkit
    rpm -q fprintd polkit | head -2
}

step_systemd_override() {
    echo "[release] step 4: systemd override → use $PREFIX/lib64"
    sudo mkdir -p /etc/systemd/system/fprintd.service.d
    sudo tee /etc/systemd/system/fprintd.service.d/override.conf >/dev/null <<EOF
[Service]
# goodix_gm168 hardening — make fprintd load our patched libfprint
# instead of the stock one. Lives in /opt to keep system files untouched.
Environment=LD_LIBRARY_PATH=$PREFIX/lib64
EOF
    sudo systemctl daemon-reload
    echo "[release]   systemd override written"

    # polkit rule: allow wheel group to enroll/verify without prompt.
    # Without this, fprintd-enroll fails in shell sessions because
    # there's no polkit-agent to ask for the password.
    sudo tee /etc/polkit-1/rules.d/50-goodix-gm168-fprintd.rules >/dev/null <<'POLKIT_EOF'
/* goodix_gm168 release: allow wheel members to enroll/verify fingerprints
 * without a polkit auth prompt. Personal-workstation policy. */
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("net.reactivated.fprint.") === 0 &&
        subject.isInGroup("wheel") && subject.active) {
        return polkit.Result.YES;
    }
});
POLKIT_EOF
    echo "[release]   polkit rule installed (wheel → fprintd allowed)"
}

step_restart_fprintd() {
    echo "[release] step 5: restart fprintd and smoke-test"
    sudo systemctl restart fprintd || sudo systemctl start fprintd || true
    sudo systemctl status fprintd --no-pager | head -15 || true
    echo "---"
    fprintd-enroll --help 2>&1 | head -10 || true
    echo "[release]   fprintd reachable"
}

step_status() {
    echo "[release] current install state"
    SO="$PREFIX/lib64/libfprint-2.so.2.0.0"
    echo "--- libfprint paths ---"
    ls -la /usr/lib64/libfprint-2.so* 2>/dev/null || echo "  (no stock libfprint)"
    ls -la "$PREFIX/lib64/libfprint-2.so"* 2>/dev/null || echo "  (no /opt libfprint)"

    echo "--- goodix_gm168 driver (linked into libfprint-2.so.2) ---"
    if [[ -f "$SO" ]] && strings "$SO" | grep -q 'goodix_gm168'; then
        echo "  goodix_gm168 symbols: present"
    else
        echo "  goodix_gm168 symbols: MISSING"
    fi

    echo "--- debug strings in libfprint ---"
    if [[ -f "$SO" ]]; then
        if strings "$SO" | grep -q 'DEBUG: dumped seq'; then
            echo "  GM168_DEBUG: ON  (release.sh build to switch off)"
        else
            echo "  GM168_DEBUG: OFF (release build)"
        fi
    fi

    echo "--- udev rule ---"
    ls -la /etc/udev/rules.d/60-goodix-gm168.rules 2>/dev/null || echo "  (not installed)"

    echo "--- fprintd ---"
    command -v fprintd-enroll >/dev/null && echo "  fprintd: installed" || echo "  fprintd: not installed"
    ls /etc/systemd/system/fprintd.service.d/override.conf 2>/dev/null \
        || echo "  systemd override: not installed"
    systemctl is-active fprintd 2>/dev/null || echo "  systemd state: inactive/missing"

    echo "--- PSK ---"
    sudo ls -la /etc/goodix-gm168/psk.bin 2>/dev/null || echo "  PSK not in /etc/goodix-gm168/"
}

step_backup_psk() {
    echo "[release] backing up PSK to logs/psk-backup-<TS>.bin"
    TS="$(date +%Y%m%d-%H%M%S)"
    OUT="$REPO_DIR/logs/psk-backup-$TS.bin"
    mkdir -p "$REPO_DIR/logs"
    sudo cat /etc/goodix-gm168/psk.bin > "$OUT"
    if [[ -s "$OUT" ]]; then
        chmod 600 "$OUT"
        echo "[release] saved: $OUT"
        echo "[release] sha256: $(sha256sum "$OUT" | awk '{print $1}')"
        echo "[release] STORE THIS SAFELY (1Password, USB drive, cloud) — losing it"
        echo "          means a Windows re-unseal dance to recover."
    else
        echo "[release] backup failed"
        rm -f "$OUT"
        exit 1
    fi
}

case "${1:-all}" in
    all)
        step_build
        step_udev
        step_fprintd_install
        step_systemd_override
        step_restart_fprintd
        echo
        echo "[release] DONE. To use fingerprint for login/sudo, run separately:"
        echo "          sudo authselect select sssd with-fingerprint --force"
        echo "          (or: gnome-control-center → Users → Fingerprint Login)"
        ;;
    build)            step_build ;;
    udev)             step_udev ;;
    fprintd)          step_fprintd_install ;;
    systemd)          step_systemd_override ;;
    restart)          step_restart_fprintd ;;
    status)           step_status ;;
    backup-psk)       step_backup_psk ;;
    *)
        echo "unknown step: $1" >&2
        echo "usage: $0 [all|build|udev|fprintd|systemd|restart|status|backup-psk]" >&2
        exit 1
        ;;
esac
