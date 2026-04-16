#!/bin/sh
# SPDX-License-Identifier: MIT
# Stress test runner for kbox.
#
# Usage: ./scripts/run-stress.sh [KBOX_BIN] [ROOTFS]
#
# Runs each stress test inside kbox with a timeout and reports results.

set -eu

# LKL's posix-host.c leaks semaphores on shutdown.
# Suppress via LSAN_OPTIONS suppression file (see scripts/lsan-suppressions.txt)
# rather than blanket detect_leaks=0, so kbox's own leaks are still caught.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/common.sh"
SUPP="suppressions=${SCRIPT_DIR}/lsan-suppressions.txt"
export LSAN_OPTIONS="${LSAN_OPTIONS:+${LSAN_OPTIONS}:}${SUPP}"

KBOX="${1:-./kbox}"
ROOTFS="${2:-rootfs.ext4}"
PASS=0
FAIL=0
SKIP=0

# Per-test timeout in seconds.  Individual tests have their own internal
# durations (e.g., long_running defaults to 10s), so this timeout is a
# safety net for hangs.
TIMEOUT="${STRESS_TIMEOUT:-60}"

set_colors
find_timeout_cmd

[ -x "$KBOX" ] || die "kbox binary not found at ${KBOX}"
[ -f "$ROOTFS" ] || die "rootfs image not found at ${ROOTFS}"

run_stress_test()
{
    name="$1"
    guest_path="$2"
    shift 2
    # Extra args passed to the guest program.
    guest_args="$*"

    printf "  %-40s " "$name"

    # Check if the test binary exists in the rootfs.
    if ! "$KBOX" -S "$ROOTFS" -- /bin/sh -c "test -x '$guest_path'" 2> /dev/null; then
        printf "${YELLOW}SKIP${NC} (not in rootfs)\n"
        SKIP=$((SKIP + 1))
        return
    fi

    OUTPUT=$(mktemp)

    RC=0
    if [ -n "$TIMEOUT_CMD" ]; then
        if "$TIMEOUT_CMD" "$TIMEOUT" "$KBOX" -S "$ROOTFS" -- "$guest_path" $guest_args > "$OUTPUT" 2>&1; then
            RC=0
        else
            RC=$?
        fi
    else
        if "$KBOX" -S "$ROOTFS" -- "$guest_path" $guest_args > "$OUTPUT" 2>&1; then
            RC=0
        else
            RC=$?
        fi
    fi

    # Check for PASS in output.
    if [ "$RC" -eq 0 ] && grep -q "^PASS:" "$OUTPUT"; then
        printf "${GREEN}PASS${NC}\n"
        # Print any timing/stats lines (non-PASS lines from stdout).
        grep -v "^PASS:" "$OUTPUT" | grep -v "^$" | head -5 | sed 's/^/    /'
        PASS=$((PASS + 1))
    elif [ "$RC" -eq 124 ] || [ "$RC" -eq 137 ]; then
        printf "${RED}TIMEOUT${NC} (${TIMEOUT}s)\n"
        FAIL=$((FAIL + 1))
    else
        printf "${RED}FAIL${NC} (exit=$RC)\n"
        cat "$OUTPUT" | head -20 | sed 's/^/    /'
        FAIL=$((FAIL + 1))
    fi

    rm -f "$OUTPUT"
}

echo "=== kbox stress tests ==="
echo "  binary:  ${KBOX}"
echo "  rootfs:  ${ROOTFS}"
echo "  timeout: ${TIMEOUT}s per test"
echo ""

echo "--- Resource limits ---"
run_stress_test "fd-exhaust" "/opt/stress/fd-exhaust"

echo ""
echo "--- Process management ---"
run_stress_test "rapid-fork" "/opt/stress/rapid-fork"

echo ""
echo "--- Concurrent I/O ---"
run_stress_test "concurrent-io" "/opt/stress/concurrent-io"

echo ""
echo "--- Signal handling ---"
run_stress_test "signal-race" "/opt/stress/signal-race"

echo ""
echo "--- Long-running soak ---"
# Pass 10 as duration argument (default).  Override with SOAK_DURATION env.
SOAK_DURATION="${SOAK_DURATION:-10}"
run_stress_test "long-running" "/opt/stress/long-running" "$SOAK_DURATION"

# ---- Summary ----
echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
