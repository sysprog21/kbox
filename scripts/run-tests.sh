#!/bin/sh
# SPDX-License-Identifier: MIT
# Integration test runner for kbox.
#
# Usage: ./scripts/run-tests.sh [KBOX_BIN] [ROOTFS]
#
# Each test function runs kbox with specific guest commands and checks
# the output/exit code.

set -eu

# LKL's posix-host.c leaks semaphores on shutdown.
# Suppress via LSAN_OPTIONS suppression file (see scripts/lsan-suppressions.txt)
# rather than blanket detect_leaks=0, so kbox's own leaks are still caught.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUPP="suppressions=${SCRIPT_DIR}/lsan-suppressions.txt"
export LSAN_OPTIONS="${LSAN_OPTIONS:+${LSAN_OPTIONS}:}${SUPP}"

KBOX="${1:-./kbox}"
ROOTFS="${2:-alpine.ext4}"
PASS=0
FAIL=0
SKIP=0

# Colors (if terminal supports them).
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

die() {
    echo "error: $*" >&2
    exit 1
}

[ -x "$KBOX" ] || die "kbox binary not found at ${KBOX}"
[ -f "$ROOTFS" ] || die "rootfs image not found at ${ROOTFS}"

expect_success() {
    name="$1"
    shift
    printf "  %-40s " "$name"
    OUTPUT=$(mktemp)
    if "$@" > "$OUTPUT" 2>&1; then
        printf "${GREEN}PASS${NC}\n"
        PASS=$((PASS + 1))
    else
        printf "${RED}FAIL${NC} (exit=$?)\n"
        cat "$OUTPUT" | head -20
        FAIL=$((FAIL + 1))
    fi
    rm -f "$OUTPUT"
}

expect_output() {
    name="$1"
    expected="$2"
    shift 2
    printf "  %-40s " "$name"
    OUTPUT=$(mktemp)
    "$@" > "$OUTPUT" 2>&1
    if grep -q "$expected" "$OUTPUT"; then
        printf "${GREEN}PASS${NC}\n"
        PASS=$((PASS + 1))
    else
        printf "${RED}FAIL${NC}\n"
        echo "    expected pattern: ${expected}"
        echo "    got:"
        cat "$OUTPUT" | head -10 | sed 's/^/    /'
        FAIL=$((FAIL + 1))
    fi
    rm -f "$OUTPUT"
}

echo "=== kbox integration tests ==="
echo "  binary:  ${KBOX}"
echo "  rootfs:  ${ROOTFS}"
echo ""

# ---- Basic boot and command execution ----
echo "--- Basic execution ---"

expect_success "boot-and-exit" \
    "$KBOX" image -S "$ROOTFS" -- /bin/true

expect_output "ls-root" "bin" \
    "$KBOX" image -S "$ROOTFS" -- /bin/ls

expect_output "echo-hello" "hello" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "echo hello"

expect_output "cat-passwd" "root" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "cat /etc/passwd"

# ---- File operations ----
echo ""
echo "--- File operations ---"

expect_success "mkdir-and-ls" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "mkdir -p /tmp/testdir && ls /tmp/testdir"

expect_output "write-and-read" "testdata" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "echo testdata > /tmp/testfile && cat /tmp/testfile"

expect_success "cp-file" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "echo data > /tmp/src && cp /tmp/src /tmp/dst && cat /tmp/dst"

# ---- Process and identity ----
echo ""
echo "--- Process and identity ---"

expect_output "uname-linux" "Linux" \
    "$KBOX" image -S "$ROOTFS" -- /bin/uname -s

expect_output "id-root" "uid=0" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "id"

expect_output "pwd-root" "/" \
    "$KBOX" image -S "$ROOTFS" -- /bin/pwd

expect_output "hostname" "" \
    "$KBOX" image -S "$ROOTFS" -- /bin/hostname

# ---- Virtual filesystems ----
echo ""
echo "--- Virtual filesystems ---"

expect_output "proc-mounted" "PROC_OK" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "test -d /proc/self && echo PROC_OK"

expect_output "proc-self-status" "Name:" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "cat /proc/self/status"

expect_output "sys-mounted" "SYS_OK" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "test -d /sys/kernel && echo SYS_OK"

# ---- FD and dup operations ----
echo ""
echo "--- FD operations ---"

expect_output "dup-via-shell" "hello" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "echo hello | cat"

expect_output "pipe-chain" "abc" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "echo abc | grep abc"

# ---- Directory operations ----
echo ""
echo "--- Directory operations ---"

expect_output "mkdir-nested" "c" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "mkdir -p /tmp/a/b/c && ls /tmp/a/b/"

expect_success "rmdir" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "mkdir /tmp/rmd && rmdir /tmp/rmd && ! test -d /tmp/rmd"

expect_success "rename-file" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "echo x > /tmp/old && mv /tmp/old /tmp/new && cat /tmp/new"

expect_success "unlink-file" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "echo x > /tmp/del && rm /tmp/del && ! test -f /tmp/del"

# ---- Navigation ----
echo ""
echo "--- Navigation ---"

expect_output "chdir-pwd" "/tmp" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "cd /tmp && pwd"

expect_output "chdir-root-ls" "passwd" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "cd / && ls etc/"

expect_output "workdir-flag" "/tmp" \
    "$KBOX" image -S "$ROOTFS" -w /tmp -- /bin/pwd

# ---- Identity (extended) ----
echo ""
echo "--- Identity (extended) ---"

expect_output "id-root-flag" "uid=0(root) gid=0(root)" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "id"

expect_output "whoami-root" "root" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "whoami"

# ---- Metadata ----
echo ""
echo "--- Metadata ---"

expect_success "stat-file" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "stat /etc/passwd"

expect_success "test-file-exists" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "test -f /etc/passwd"

expect_success "test-dir-exists" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "test -d /tmp"

# ---- Procfs data ----
echo ""
echo "--- Procfs data ---"

expect_output "proc-stat-cpu" "cpu " \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "head -1 /proc/stat"

expect_output "proc-meminfo" "MemTotal" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "head -1 /proc/meminfo"

expect_output "proc-self-fd" "FD_OK" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "test -d /proc/self/fd && echo FD_OK"

# ---- Time ----
echo ""
echo "--- Time ---"

expect_output "date-runs" "" \
    "$KBOX" image -S "$ROOTFS" -- /bin/date

# ---- Pipe and I/O ----
echo ""
echo "--- Pipe and I/O ---"

expect_output "pipe-simple" "hello" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "echo hello | cat"

expect_output "pipe-grep" "match" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "echo match | grep match"

expect_output "pipe-wc" "3" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "printf 'a\nb\nc\n' | wc -l"

expect_success "redirect-append" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "echo a > /tmp/ap && echo b >> /tmp/ap && test \$(wc -l < /tmp/ap) -eq 2"

# ---- Permission and access ----
echo ""
echo "--- Permissions ---"

expect_success "chmod-test" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "echo x > /tmp/ch && chmod 755 /tmp/ch && test -x /tmp/ch"

expect_success "umask-test" \
    "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "umask 022"

# ---- Guest test programs (if available) ----
echo ""
echo "--- Guest test programs ---"

for test_prog in dup-test clock-test signal-test path-escape-test errno-test; do
    if "$KBOX" image -S "$ROOTFS" -- /bin/sh -c "test -x /opt/tests/${test_prog}" 2> /dev/null; then
        expect_success "$test_prog" \
            "$KBOX" image -S "$ROOTFS" -- "/opt/tests/${test_prog}"
    else
        printf "  %-40s ${YELLOW}SKIP${NC} (not in rootfs)\n" "$test_prog"
        SKIP=$((SKIP + 1))
    fi
done

# ---- Networking (requires --net / SLIRP support) ----
echo ""
echo "--- Networking ---"

# Check if kbox was built with SLIRP support by testing --net flag.
if "$KBOX" image -S "$ROOTFS" --net -- /bin/true 2> /dev/null; then
    expect_output "net-ping-gateway" "bytes from" \
        "$KBOX" image -S "$ROOTFS" --net -- /bin/sh -c "ping -c 1 -W 3 10.0.2.2"

    expect_output "net-resolv-conf" "nameserver" \
        "$KBOX" image -S "$ROOTFS" --net -- /bin/sh -c "cat /etc/resolv.conf"

    # wget test (outbound TCP via SLIRP)
    expect_success "net-wget-external" \
        "$KBOX" image -S "$ROOTFS" --net -- /bin/sh -c "wget -q -O /dev/null http://httpbin.org/get"
else
    for t in net-ping-gateway net-resolv-conf net-wget-external; do
        printf "  %-40s ${YELLOW}SKIP${NC} (no SLIRP support)\n" "$t"
        SKIP=$((SKIP + 1))
    done
fi

# ---- Summary ----
echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
