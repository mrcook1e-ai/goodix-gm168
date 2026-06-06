#!/usr/bin/env bash
# Run on Fedora laptop after `scripts/deploy.sh` syncs the tree here.
#
# Tiered checks — each tier costs more, runs only if the cheaper one passed.
#
#   T1  unit       : compile + run standalone tests/test_*.c (no libfprint dep)
#   T2  build      : full driver build via scripts/build.sh
#   T3  smoke      : examples/list-prints starts, finds device, exits 0
#                    (does NOT need a finger touch)
#
# Usage:
#   ./tests/run_tests.sh           # T1 + T2 + T3
#   ./tests/run_tests.sh unit      # T1 only
#   ./tests/run_tests.sh build     # T1 + T2
#   ./tests/run_tests.sh smoke     # T1 + T2 + T3
set -euo pipefail

DEV_DIR="${DEV_DIR:-$HOME/dev}"
REPO_DIR="${REPO_DIR:-$DEV_DIR/goodix-gm168}"
BUILD_DIR="${BUILD_DIR:-$DEV_DIR/libfprint-build}"
PREFIX="${PREFIX:-/opt/libfprint-gm168}"
GM168_DIR="${GOODIX_GM168_DIR:-$HOME/.goodix-gm168}"

STAGE="${1:-smoke}"
LOG_DIR="$REPO_DIR/logs"
mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
LOG="$LOG_DIR/${TS}-tests-${STAGE}.log"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
log()   { printf '[tests] %s\n' "$*" | tee -a "$LOG"; }

fail() {
    red "FAIL: $*" | tee -a "$LOG"
    exit 1
}

run_t1_unit () {
    log "T1 unit — compiling tests/test_timeouts.c"
    cd "$REPO_DIR/tests"
    cc -std=c11 -Wall -Wextra -Werror -I../src test_timeouts.c -o test_timeouts \
        2>>"$LOG" || fail "T1 compile"
    ./test_timeouts | tee -a "$LOG" || fail "T1 run"
    rm -f test_timeouts
    green "T1 unit OK"
}

run_t2_build () {
    log "T2 build — running scripts/build.sh"
    cd "$REPO_DIR"
    if bash scripts/build.sh >>"$LOG" 2>&1; then
        green "T2 build OK"
    else
        tail -40 "$LOG"
        fail "T2 build (see $LOG)"
    fi
}

run_t3_smoke () {
    log "T3 smoke — list-prints (device discovery, no touch required)"
    # shellcheck disable=SC1091
    source "$REPO_DIR/scripts/_lib.sh"
    gm168_kill_old_sessions -q
    gm168_unlock_usb
    gm168_set_default_env

    local example="$BUILD_DIR/examples/list-prints"
    if [[ ! -x "$example" ]]; then
        example="$BUILD_DIR/examples/manage-prints"
    fi
    if [[ ! -x "$example" ]]; then
        log "T3 skip — no list-prints / manage-prints in $BUILD_DIR/examples"
        return 0
    fi

    # 10s hard timeout — list should finish in <1s on a working device.
    if timeout 10 env \
        LD_LIBRARY_PATH="$PREFIX/lib64" \
        GI_TYPELIB_PATH="$PREFIX/lib64/girepository-1.0" \
        GOODIX_GM168_DIR="$GM168_DIR" \
        LIBFPRINT_DEBUG=3 \
        "$example" </dev/null >>"$LOG" 2>&1
    then
        green "T3 smoke OK"
    else
        local rc=$?
        # manage-prints exits 1 when there are no prints — that's still OK
        # (it means the driver loaded and probed the device).
        if [[ $rc -eq 1 ]] && grep -q "goodix_gm168" "$LOG"; then
            green "T3 smoke OK (no prints enrolled — driver loaded)"
        else
            tail -40 "$LOG"
            fail "T3 smoke rc=$rc (see $LOG)"
        fi
    fi
}

log "log → $LOG"

case "$STAGE" in
    unit)   run_t1_unit ;;
    build)  run_t1_unit; run_t2_build ;;
    smoke)  run_t1_unit; run_t2_build; run_t3_smoke ;;
    *)      fail "unknown stage: $STAGE (want unit|build|smoke)" ;;
esac

green "ALL TESTS PASSED — stage=$STAGE"
