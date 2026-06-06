#!/usr/bin/env bash
# Production install of the goodix_gm168 driver on the Fedora laptop.
#
# What this does (idempotent, safe to re-run):
#   1. Force a clean release build (no -DGM168_DEBUG, -O2 optimisation)
#   2. Install udev rule for VID:PID 27c6:589a
#   3. Install fprintd from Fedora repos if missing
#   4. Drop a systemd override into fprintd.service that points it at
#      our patched libfprint in /opt/libfprint-gm168
#   5. Restart fprintd, smoke-test with fprintd-enroll --help
#
# PAM integration (login screen, sudo) is NOT done by this script —
# it changes system auth behaviour. Run separately, see INSTALL.md.
#
# Usage:
#   ./scripts/release.sh             # full release install
#   ./scripts/release.sh build       # only step 1 (release build)
#   ./scripts/release.sh systemd     # only step 4-5 (fprintd override)
#   ./scripts/release.sh status      # show current install state
set -euo pipefail

REMOTE_HOST="${GM168_HOST:-mrcook1e@192.168.1.14}"
REMOTE_PORT="${GM168_PORT:-2200}"
REMOTE_DIR="${GM168_REMOTE_DIR:-/home/mrcook1e/dev/goodix-gm168}"
BUILD_DIR_REMOTE="${GM168_REMOTE_BUILD:-/home/mrcook1e/dev/libfprint-build}"
PREFIX_REMOTE="${GM168_REMOTE_PREFIX:-/opt/libfprint-gm168}"

SSH() { ssh -p "$REMOTE_PORT" "$REMOTE_HOST" "$@"; }

step_build() {
    echo "[release] step 1: clean release build (no -DGM168_DEBUG)"
    SSH "set -e
        # Sync the latest source into the libfprint tree (same rsync as
        # scripts/build.sh does). Without this, meson compile uses the
        # last-synced source which may be stale.
        SRC_DST='/home/mrcook1e/dev/libfprint/libfprint/drivers/goodix_gm168'
        mkdir -p \"\$SRC_DST\"
        rsync -a --delete --exclude='meson.build' \
            '$REMOTE_DIR/src/' \"\$SRC_DST/\"

        cd '$BUILD_DIR_REMOTE'
        # Force optimised release build, drop debug flags.
        meson configure -Dc_args='-O2 -DNDEBUG' -Dbuildtype=release >/dev/null
        meson compile
        sudo meson install
        echo '[release]   build OK, installed to $PREFIX_REMOTE'

        # Sanity: GM168_DEBUG strings must not be in the linked libfprint.
        SO='$PREFIX_REMOTE/lib64/libfprint-2.so.2.0.0'
        if strings \"\$SO\" 2>/dev/null | grep -q 'DEBUG: dumped seq'; then
            echo '[release] WARNING: GM168_DEBUG strings still in binary'
            exit 1
        fi
        echo '[release]   confirmed: GM168_DEBUG is OFF'"
}

step_udev() {
    echo "[release] step 2: udev rule for 27c6:589a"
    SSH "set -e
        sudo install -m 644 '$REMOTE_DIR/udev/60-goodix-gm168.rules' \
            /etc/udev/rules.d/60-goodix-gm168.rules
        sudo udevadm control --reload
        sudo udevadm trigger
        echo '[release]   udev rule installed'

        ME=\$(id -un)
        if ! id -nG \"\$ME\" | grep -qw plugdev; then
            echo \"[release]   adding \$ME to plugdev (logout required to take effect)\"
            sudo usermod -aG plugdev \"\$ME\"
        else
            echo \"[release]   \$ME already in plugdev\"
        fi"
}

step_fprintd_install() {
    echo "[release] step 3: ensure fprintd + polkit are installed"
    SSH "set -e
        # polkit is mandatory: fprintd uses it to authorise device claim.
        # On minimal Fedora it isn't pulled in by fprintd's deps.
        sudo dnf install -y fprintd fprintd-pam polkit
        rpm -q fprintd polkit | head -2
        # polkit autostarts via D-Bus activation; no explicit enable needed."
}

step_systemd_override() {
    echo "[release] step 4: systemd override → use $PREFIX_REMOTE/lib64"
    SSH "set -e
        sudo mkdir -p /etc/systemd/system/fprintd.service.d
        sudo tee /etc/systemd/system/fprintd.service.d/override.conf >/dev/null <<EOF
[Service]
# goodix_gm168 hardening — make fprintd load our patched libfprint
# instead of the stock one. Lives in /opt to keep system files untouched.
Environment=LD_LIBRARY_PATH=$PREFIX_REMOTE/lib64
EOF
        sudo systemctl daemon-reload
        echo '[release]   systemd override written'

        # polkit rule: allow wheel group to enroll/verify without prompt.
        # Without this, fprintd-enroll fails in shell sessions because
        # there's no polkit-agent to ask for the password.
        sudo tee /etc/polkit-1/rules.d/50-goodix-gm168-fprintd.rules >/dev/null <<'POLKIT_EOF'
/* goodix_gm168 release: allow wheel members to enroll/verify fingerprints
 * without a polkit auth prompt. Personal-workstation policy. */
polkit.addRule(function(action, subject) {
    if (action.id.indexOf(\"net.reactivated.fprint.\") === 0 &&
        subject.isInGroup(\"wheel\") && subject.active) {
        return polkit.Result.YES;
    }
});
POLKIT_EOF
        echo '[release]   polkit rule installed (wheel → fprintd allowed)'"
}

step_restart_fprintd() {
    echo "[release] step 5: restart fprintd and smoke-test"
    SSH "set -e
        sudo systemctl restart fprintd || sudo systemctl start fprintd || true
        sudo systemctl status fprintd --no-pager | head -15 || true
        # fprintd is socket-activated; running its CLI triggers it.
        echo '---'
        fprintd-enroll --help 2>&1 | head -10 || true
        echo '[release]   fprintd reachable'"
}

step_status() {
    echo "[release] current install state"
    SSH "set -e
        SO='$PREFIX_REMOTE/lib64/libfprint-2.so.2.0.0'
        echo '--- libfprint paths ---'
        ls -la /usr/lib64/libfprint-2.so* 2>/dev/null || echo '  (no stock libfprint)'
        ls -la '$PREFIX_REMOTE/lib64/libfprint-2.so'* 2>/dev/null || echo '  (no /opt libfprint)'

        echo '--- goodix_gm168 driver (linked into libfprint-2.so.2) ---'
        if [ -f \"\$SO\" ] && strings \"\$SO\" | grep -q 'goodix_gm168'; then
            echo '  goodix_gm168 symbols: present'
        else
            echo '  goodix_gm168 symbols: MISSING'
        fi

        echo '--- debug strings in libfprint ---'
        if [ -f \"\$SO\" ]; then
            if strings \"\$SO\" | grep -q 'DEBUG: dumped seq'; then
                echo '  GM168_DEBUG: ON  (release.sh build to switch off)'
            else
                echo '  GM168_DEBUG: OFF (release build)'
            fi
        fi

        echo '--- udev rule ---'
        ls -la /etc/udev/rules.d/60-goodix-gm168.rules 2>/dev/null || echo '  (not installed)'

        echo '--- fprintd ---'
        command -v fprintd-enroll >/dev/null && echo '  fprintd: installed' || echo '  fprintd: not installed'
        ls /etc/systemd/system/fprintd.service.d/override.conf 2>/dev/null \
            || echo '  systemd override: not installed'
        systemctl is-active fprintd 2>/dev/null || echo '  systemd state: inactive/missing'

        echo '--- PSK ---'
        ls -la /etc/goodix-gm168/psk.bin 2>/dev/null || echo '  PSK not in /etc; check ~/.goodix-gm168/'
        ls -la ~/.goodix-gm168/psk.bin 2>/dev/null || true"
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
    backup-psk)
        echo "[release] backing up PSK to local logs/psk-backup-<TS>.bin"
        TS=$(date +%Y%m%d-%H%M%S)
        SCP "$REMOTE_HOST:/etc/goodix-gm168/psk.bin" "$(dirname "$0")/../logs/psk-backup-$TS.bin" \
            || SSH "sudo cat /etc/goodix-gm168/psk.bin" > "$(dirname "$0")/../logs/psk-backup-$TS.bin"
        if [ -s "$(dirname "$0")/../logs/psk-backup-$TS.bin" ]; then
            echo "[release] saved: $(dirname "$0")/../logs/psk-backup-$TS.bin"
            echo "[release] STORE THIS SAFELY (1Password, USB drive, cloud) — losing it"
            echo "          means a Windows re-unseal dance to recover."
        else
            echo "[release] backup failed"
            exit 1
        fi
        ;;
    build)            step_build ;;
    udev)             step_udev ;;
    fprintd)          step_fprintd_install ;;
    systemd)          step_systemd_override ;;
    restart)          step_restart_fprintd ;;
    status)           step_status ;;
    *)
        echo "unknown step: $1" >&2
        echo "usage: $0 [all|build|udev|fprintd|systemd|restart|status]" >&2
        exit 1
        ;;
esac
