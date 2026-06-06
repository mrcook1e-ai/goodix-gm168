# Shared helpers — `source` this from runner scripts.
# Not executable on its own.

# Free the sensor from any prior process so a new run can claim it.
#   1. Stop system fprintd if it's holding the device.
#   2. Kill leftover libfprint example processes from earlier runs.
#   3. Wait a moment for the kernel to drop refs.
gm168_kill_old_sessions () {
    local quiet="${1:-}"
    local say
    if [[ "$quiet" == "-q" ]]; then
        say() { :; }
    else
        say() { echo "[kill] $*"; }
    fi

    # System fprintd would claim the USB device on its own — bad for tests.
    if systemctl is-active --quiet fprintd 2>/dev/null; then
        say "stopping system fprintd"
        sudo -n systemctl stop fprintd 2>/dev/null || true
    fi

    # Examples + identify + img-capture + verify + enroll from earlier runs.
    # Match by full path to our build dir so we don't kill unrelated procs.
    local pat='libfprint-build/examples/(enroll|verify|img-capture|identify|manage-prints)'
    if pgrep -f "$pat" >/dev/null 2>&1; then
        say "killing leftover example procs"
        pkill -TERM -f "$pat" 2>/dev/null || true
        sleep 0.3
        pkill -KILL -f "$pat" 2>/dev/null || true
    fi

    # Anything else linking our isolated libfprint.
    if pgrep -f '/opt/libfprint-gm168/lib64' >/dev/null 2>&1; then
        say "killing other procs using /opt/libfprint-gm168"
        pkill -TERM -f '/opt/libfprint-gm168/lib64' 2>/dev/null || true
        sleep 0.2
        pkill -KILL -f '/opt/libfprint-gm168/lib64' 2>/dev/null || true
    fi
}

# Re-open USB perms (usbipd-attached devices come up root:root).
gm168_unlock_usb () {
    if [[ -e /dev/bus/usb/001/002 ]]; then
        sudo -n chmod 666 /dev/bus/usb/001/002 2>/dev/null || true
    fi
}

# Default driver env shared by every runner.
#
# GM168_USE_CAL2=1 — use the pre-baked Cal1/Cal2 tables from gm168_cal.h
#                   instead of the per-activation BG capture pipeline.
#                   The tables were captured on this same sensor, so they
#                   are exact. Drops 5 BG frames × ~50ms = ~250ms off
#                   each activate AND removes the BG non-determinism we
#                   measured earlier (background hash varies frame-to-
#                   frame from physical noise even when 5/5 captures
#                   succeed). Override by exporting GM168_USE_CAL2=0
#                   in the caller's env before invoking the runner.
gm168_set_default_env () {
    # The C side treats "any non-empty value" as truthy, so we have to
    # actively unset the var to disable. Anything but "0"/"false" → ON.
    case "${GM168_USE_CAL2:-1}" in
        0|false|FALSE|no|NO) unset GM168_USE_CAL2 ;;
        *)                   export GM168_USE_CAL2=1 ;;
    esac
}
