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
. "${SCRIPT_DIR}/common.sh"
SUPP="suppressions=${SCRIPT_DIR}/lsan-suppressions.txt"
export LSAN_OPTIONS="${LSAN_OPTIONS:+${LSAN_OPTIONS}:}${SUPP}"

KBOX="${1:-./kbox}"
ROOTFS="${2:-alpine.ext4}"
PASS=0
FAIL=0
SKIP=0

set_colors

[ -x "$KBOX" ] || die "kbox binary not found at ${KBOX}"
[ -f "$ROOTFS" ] || die "rootfs image not found at ${ROOTFS}"

KBOX_TEST_TIMEOUT="${KBOX_TEST_TIMEOUT:-30}"
find_timeout_cmd

run_with_timeout()
{
    if [ -n "$TIMEOUT_CMD" ]; then
        "$TIMEOUT_CMD" "$KBOX_TEST_TIMEOUT" "$@"
    else
        "$@"
    fi
}

expect_success()
{
    name="$1"
    shift
    printf "  %-40s " "$name"
    OUTPUT=$(mktemp)
    if run_with_timeout "$@" > "$OUTPUT" 2>&1; then
        printf "${GREEN}PASS${NC}\n"
        PASS=$((PASS + 1))
    else
        rc=$?
        if [ "$rc" -eq 124 ]; then
            printf "${RED}TIMEOUT${NC}\n"
        else
            printf "${RED}FAIL${NC} (exit=$rc)\n"
        fi
        head -20 "$OUTPUT"
        FAIL=$((FAIL + 1))
    fi
    rm -f "$OUTPUT"
}

expect_output()
{
    name="$1"
    expected="$2"
    shift 2
    printf "  %-40s " "$name"
    OUTPUT=$(mktemp)
    if run_with_timeout "$@" > "$OUTPUT" 2>&1; then
        rc=0
    else
        rc=$?
    fi
    if [ "$rc" -eq 0 ] && grep -q "$expected" "$OUTPUT"; then
        printf "${GREEN}PASS${NC}\n"
        PASS=$((PASS + 1))
    else
        if [ "$rc" -eq 124 ]; then
            printf "${RED}TIMEOUT${NC}\n"
        elif [ "$rc" -ne 0 ]; then
            printf "${RED}FAIL${NC} (exit=$rc)\n"
        else
            printf "${RED}FAIL${NC}\n"
        fi
        echo "    expected pattern: ${expected}"
        echo "    got:"
        head -10 "$OUTPUT" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
    fi
    rm -f "$OUTPUT"
}

expect_output_count()
{
    name="$1"
    expected="$2"
    expected_count="$3"
    shift 3
    printf "  %-40s " "$name"
    OUTPUT=$(mktemp)
    if run_with_timeout "$@" > "$OUTPUT" 2>&1; then
        rc=0
    else
        rc=$?
    fi
    actual_count=$(grep -c "$expected" "$OUTPUT" || true)
    if [ "$rc" -eq 0 ] && [ "$actual_count" -eq "$expected_count" ]; then
        printf "${GREEN}PASS${NC}\n"
        PASS=$((PASS + 1))
    else
        if [ "$rc" -eq 124 ]; then
            printf "${RED}TIMEOUT${NC}\n"
        elif [ "$rc" -ne 0 ]; then
            printf "${RED}FAIL${NC} (exit=$rc, match_count=$actual_count/$expected_count)\n"
        else
            printf "${RED}FAIL${NC} (match_count=$actual_count/$expected_count)\n"
        fi
        echo "    expected pattern: ${expected}"
        head -20 "$OUTPUT" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
    fi
    rm -f "$OUTPUT"
}

guest_has_test()
{
    test_prog="$1"
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "test -x /opt/tests/${test_prog}" \
        2> /dev/null
}

require_guest_test()
{
    test_prog="$1"

    if guest_has_test "$test_prog"; then
        return 0
    fi

    printf "  %-40s ${RED}FAIL${NC} (missing from rootfs)\n" "$test_prog"
    FAIL=$((FAIL + 1))
    return 1
}

rewrite_mode_probe=$(mktemp)
rewrite_mode_state="broken"
if run_with_timeout "$KBOX" -S "$ROOTFS" --syscall-mode=rewrite -- /bin/true \
    > "$rewrite_mode_probe" 2>&1; then
    rewrite_mode_state="available"
elif grep -q "rewrite mode is unsupported in x86_64 ASAN builds" \
    "$rewrite_mode_probe"; then
    rewrite_mode_state="unsupported"
fi
rm -f "$rewrite_mode_probe"

echo "=== kbox integration tests ==="
echo "  binary:  ${KBOX}"
echo "  rootfs:  ${ROOTFS}"
echo ""

# ---- Basic boot and command execution ----
echo "--- Basic execution ---"

expect_success "boot-and-exit" \
    "$KBOX" -S "$ROOTFS" -- /bin/true

expect_output "ls-root" "bin" \
    "$KBOX" -S "$ROOTFS" -- /bin/ls

expect_output "echo-hello" "hello" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "echo hello"

expect_output "cat-passwd" "root" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "cat /etc/passwd"

# ---- File operations ----
echo ""
echo "--- File operations ---"

expect_success "mkdir-and-ls" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "mkdir -p /tmp/testdir && ls /tmp/testdir"

expect_output "write-and-read" "testdata" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "echo testdata > /tmp/testfile && cat /tmp/testfile"

expect_success "cp-file" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "echo data > /tmp/src && cp /tmp/src /tmp/dst && cat /tmp/dst"

# ---- Process and identity ----
echo ""
echo "--- Process and identity ---"

expect_output "uname-linux" "Linux" \
    "$KBOX" -S "$ROOTFS" -- /bin/uname -s

expect_output "id-root" "uid=0" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "id"

expect_output "pwd-root" "/" \
    "$KBOX" -S "$ROOTFS" -- /bin/pwd

expect_output "hostname" "" \
    "$KBOX" -S "$ROOTFS" -- /bin/hostname

# ---- Virtual filesystems ----
echo ""
echo "--- Virtual filesystems ---"

expect_output "proc-mounted" "PROC_OK" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "test -d /proc/self && echo PROC_OK"

expect_output "proc-self-status" "Name:" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "cat /proc/self/status"

expect_output "sys-mounted" "SYS_OK" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "test -d /sys/kernel && echo SYS_OK"

# ---- FD and dup operations ----
echo ""
echo "--- FD operations ---"

expect_output "dup-via-shell" "hello" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "echo hello | cat"

expect_output "pipe-chain" "abc" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "echo abc | grep abc"

# ---- Directory operations ----
echo ""
echo "--- Directory operations ---"

expect_output "mkdir-nested" "c" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "mkdir -p /tmp/a/b/c && ls /tmp/a/b/"

expect_success "rmdir" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "mkdir /tmp/rmd && rmdir /tmp/rmd && ! test -d /tmp/rmd"

expect_success "rename-file" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "echo x > /tmp/old && mv /tmp/old /tmp/new && cat /tmp/new"

expect_success "unlink-file" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "echo x > /tmp/del && rm /tmp/del && ! test -f /tmp/del"

# ---- Navigation ----
echo ""
echo "--- Navigation ---"

expect_output "chdir-pwd" "/tmp" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "cd /tmp && pwd"

expect_output "chdir-root-ls" "passwd" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "cd / && ls etc/"

expect_output "workdir-flag" "/tmp" \
    "$KBOX" -S "$ROOTFS" -w /tmp -- /bin/pwd

# ---- Identity (extended) ----
echo ""
echo "--- Identity (extended) ---"

expect_output "id-root-flag" "uid=0(root) gid=0(root)" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "id"

expect_output "whoami-root" "root" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "whoami"

# ---- Metadata ----
echo ""
echo "--- Metadata ---"

expect_success "stat-file" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "stat /etc/passwd"

expect_success "test-file-exists" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "test -f /etc/passwd"

expect_success "test-dir-exists" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "test -d /tmp"

# ---- Procfs data ----
echo ""
echo "--- Procfs data ---"

expect_output "proc-stat-cpu" "cpu " \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "head -1 /proc/stat"

expect_output "proc-meminfo" "MemTotal" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "head -1 /proc/meminfo"

expect_output "proc-self-fd" "FD_OK" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "test -d /proc/self/fd && echo FD_OK"

# ---- Time ----
echo ""
echo "--- Time ---"

expect_output "date-runs" "" \
    "$KBOX" -S "$ROOTFS" -- /bin/date

# ---- Pipe and I/O ----
echo ""
echo "--- Pipe and I/O ---"

expect_output "pipe-simple" "hello" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "echo hello | cat"

expect_output "pipe-grep" "match" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "echo match | grep match"

expect_output "pipe-wc" "3" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "printf 'a\nb\nc\n' | wc -l"

expect_success "redirect-append" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "echo a > /tmp/ap && echo b >> /tmp/ap && test \$(wc -l < /tmp/ap) -eq 2"

# ---- Permission and access ----
echo ""
echo "--- Permissions ---"

expect_success "chmod-test" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "echo x > /tmp/ch && chmod 755 /tmp/ch && test -x /tmp/ch"

expect_success "umask-test" \
    "$KBOX" -S "$ROOTFS" -- /bin/sh -c "umask 022"

# ---- Guest test programs (if available) ----
echo ""
echo "--- Guest test programs ---"

for test_prog in dup-test clock-test signal-test signal-safety-test path-escape-test errno-test sendfile-test; do
    if guest_has_test "$test_prog"; then
        expect_success "$test_prog" \
            "$KBOX" -S "$ROOTFS" -- "/opt/tests/${test_prog}"
    else
        printf "  %-40s ${YELLOW}SKIP${NC} (not in rootfs)\n" "$test_prog"
        SKIP=$((SKIP + 1))
    fi
done

if "$KBOX" -S "$ROOTFS" -- /bin/sh -c "test -x /opt/tests/clone3-test" 2> /dev/null; then
    expect_output_count "clone3-test" \
        "kbox: clone3 denied: namespace flags" 9 \
        "$KBOX" --forward-verbose -S "$ROOTFS" --syscall-mode=seccomp \
        -- "/opt/tests/clone3-test"
else
    printf "  %-40s ${YELLOW}SKIP${NC} (not in rootfs)\n" "clone3-test"
    SKIP=$((SKIP + 1))
fi

if require_guest_test "process-vm-deny-test"; then
    expect_output "process-vm-deny-test" "PASS: process_vm_readv denied" \
        "$KBOX" -S "$ROOTFS" --syscall-mode=seccomp \
        -- "/opt/tests/process-vm-deny-test"
fi

echo ""
echo "--- Rewrite security ---"

if [ "$rewrite_mode_state" = "available" ]; then
    if require_guest_test "jit-spray-test"; then
        expect_output "jit-spray-test" "PASS: jit_spray_boundary" \
            "$KBOX" -S "$ROOTFS" --syscall-mode=rewrite \
            -- "/opt/tests/jit-spray-test"
    fi

    if require_guest_test "jit-alias-test"; then
        expect_output "jit-alias-test" "PASS: jit_alias_blocked" \
            "$KBOX" -S "$ROOTFS" --syscall-mode=rewrite \
            -- "/opt/tests/jit-alias-test"
    fi
elif [ "$rewrite_mode_state" = "unsupported" ]; then
    for t in jit-spray-test jit-alias-test; do
        printf "  %-40s ${YELLOW}SKIP${NC} (x86_64 ASAN rewrite unsupported)\n" "$t"
        SKIP=$((SKIP + 1))
    done
else
    printf "  %-40s ${RED}FAIL${NC} (rewrite mode unavailable)\n" "rewrite-smoke"
    FAIL=$((FAIL + 1))
fi

# ---- Networking (requires --net / SLIRP support) ----
echo ""
echo "--- Networking ---"

# Check if kbox was built with SLIRP support by testing --net flag.
if "$KBOX" -S "$ROOTFS" --net -- /bin/true 2> /dev/null; then
    for test_prog in net-dns-test; do
        if "$KBOX" -S "$ROOTFS" --net -- /bin/sh -c "test -x /opt/tests/${test_prog}" \
            2> /dev/null; then
            expect_success "$test_prog" \
                "$KBOX" -S "$ROOTFS" --net -- "/opt/tests/${test_prog}"
        else
            printf "  %-40s ${YELLOW}SKIP${NC} (not in rootfs)\n" "$test_prog"
            SKIP=$((SKIP + 1))
        fi
    done

    expect_output "net-ping-gateway" "bytes from" \
        "$KBOX" -S "$ROOTFS" --net -- /bin/sh -c "ping -c 1 -W 3 10.0.2.2"

    expect_output "net-resolv-conf" "nameserver" \
        "$KBOX" -S "$ROOTFS" --net -- /bin/sh -c "cat /etc/resolv.conf"

    # wget test (outbound TCP via SLIRP)
    # Check that DNS resolves and TCP connects. The HTTP response may
    # fail (busybox wget vs chunked encoding / virtual hosting), so
    # we check for the "Connecting to" line which proves DNS + TCP.
    expect_output "net-wget-external" "Connecting to" \
        "$KBOX" -S "$ROOTFS" --net -- /bin/sh -c "wget -S -O /dev/null http://www.google.com/ 2>&1 || true"
else
    for t in net-dns-test net-ping-gateway net-resolv-conf net-wget-external; do
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
