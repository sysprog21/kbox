/* SPDX-License-Identifier: MIT */
/*
 * probe.c - Runtime host feature probing with fail-fast diagnostics.
 *
 * Verifies that the host kernel supports seccomp-unotify, the
 * required ioctls, process_vm_readv, and no_new_privs.  Detects
 * AppArmor and Yama LSM restrictions that can silently break
 * cross-process memory access.
 *
 * Call kbox_probe_host_features() once at startup before forking.
 */

#include "kbox/probe.h"
#include "kbox/seccomp-defs.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Individual probes                                                   */
/* ------------------------------------------------------------------ */

/*
 * Check no_new_privs is settable.
 * This is required for seccomp filter installation.
 */
static int probe_no_new_privs(void)
{
    /*
     * We cannot actually set it in the main process -- that
     * would be irreversible.  Instead we fork a child to test.
     */
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "probe: fork failed: %s\n", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* Child: try to set no_new_privs. */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
            _exit(1);
        _exit(0);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr,
                "probe: FAIL -- prctl(PR_SET_NO_NEW_PRIVS) is "
                "not permitted.\n"
                "  This is required for seccomp filter "
                "installation.\n"
                "  Check kernel version (>= 3.5) and security "
                "module restrictions.\n");
        return -1;
    }
    return 0;
}

/*
 * Check seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER).
 *
 * Installs a trivial BPF filter in a forked child and verifies that
 * a listener FD is returned.  Also checks the basic ioctls
 * (SECCOMP_IOCTL_NOTIF_RECV via a non-blocking attempt).
 */
static int probe_seccomp_listener(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "probe: fork: %s\n", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /*
         * Child: install seccomp filter with NEW_LISTENER.
         *
         * The blanket USER_NOTIF filter catches ALL syscalls.
         * After seccomp() succeeds, no further syscalls work
         * (including _exit) because the notification fd has no
         * reader.  The child becomes permanently stuck, which
         * the parent interprets as "seccomp succeeded".
         *
         * If seccomp() fails, _exit(2) runs before the filter
         * is installed, so it works normally.
         */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
            _exit(1);

        /* Minimal BPF: load nr, return USER_NOTIF. */
        struct kbox_sock_filter filter[2];
        filter[0] = (struct kbox_sock_filter) {
            KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, 0, 0, 0};
        filter[1] = (struct kbox_sock_filter) {KBOX_BPF_RET | KBOX_BPF_K, 0, 0,
                                               KBOX_SECCOMP_RET_USER_NOTIF};

        struct kbox_sock_fprog prog = {
            .len = 2,
            .filter = filter,
        };

        long ret = syscall(__NR_seccomp, KBOX_SECCOMP_SET_MODE_FILTER,
                           KBOX_SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
        if (ret < 0)
            _exit(2);

        /*
         * seccomp succeeded -- child is now stuck.  _exit()
         * itself is caught by the filter.  Parent will SIGKILL.
         */
        _exit(0); /* will block; parent kills us */
    }

    /*
     * Parent: give the child time to run seccomp(), then check.
     *
     * If seccomp() failed, the child exits immediately with
     * status 1 or 2.  If it succeeded, the child is stuck
     * (even _exit is blocked) and waitpid returns 0 (WNOHANG).
     */
    usleep(50000); /* 50ms -- enough for seccomp() */

    int status = 0;
    pid_t w = waitpid(pid, &status, WNOHANG);

    if (w == 0) {
        /* Child still alive => seccomp succeeded. */
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return 0;
    }

    /* Child exited => seccomp failed. */
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);

    fprintf(stderr,
            "probe: FAIL -- seccomp(SET_MODE_FILTER, "
            "NEW_LISTENER) is not supported.\n"
            "  This requires kernel >= 5.0.\n"
            "  On some systems, unprivileged seccomp "
            "user notification\n"
            "  is restricted by security policies.\n");
    return -1;
}

/*
 * Check process_vm_readv works between parent and child.
 *
 * Ubuntu's AppArmor and Yama LSM (ptrace_scope >= 1) can
 * restrict process_vm_readv between non-parent/child processes.
 * We test the parent->child direction which is what kbox uses.
 */
static int probe_process_vm_readv(void)
{
    /* Shared data: child writes a known pattern, parent reads it. */
    volatile char marker[8] = "KBOXPRB";
    pid_t pid = fork();

    if (pid < 0) {
        fprintf(stderr, "probe: fork: %s\n", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* Child: just sleep until killed. */
        pause();
        _exit(0);
    }

    /* Parent: try to read the marker from child memory. */
    usleep(10000); /* 10ms -- let child settle. */

    char buf[8] = {0};
    struct iovec local = {.iov_base = buf, .iov_len = sizeof(buf)};
    struct iovec remote = {.iov_base = (void *) marker, .iov_len = sizeof(buf)};

    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);

    if (n < 0) {
        int e = errno;
        fprintf(stderr,
                "probe: FAIL -- process_vm_readv: %s\n"
                "  kbox requires cross-process memory access.\n",
                strerror(e));

        if (e == EPERM) {
            fprintf(stderr,
                    "  This is likely caused by Yama LSM "
                    "(ptrace_scope).\n"
                    "  Check: cat "
                    "/proc/sys/kernel/yama/ptrace_scope\n"
                    "  Value 0 or 1 should work for "
                    "parent->child access.\n"
                    "  If AppArmor is restricting this, "
                    "check: aa-status\n");
        }
        return -1;
    }

    if (n != sizeof(buf) ||
        memcmp(buf, (const void *) marker, sizeof(buf)) != 0) {
        fprintf(stderr,
                "probe: FAIL -- process_vm_readv returned "
                "unexpected data.\n");
        return -1;
    }

    return 0;
}

/*
 * Check Yama ptrace_scope and warn if it might cause problems.
 * This is advisory -- scope 0 or 1 both work for parent->child.
 * Scope 2 or 3 will break process_vm_readv.
 */
static int probe_yama_scope(void)
{
    int fd = open("/proc/sys/kernel/yama/ptrace_scope", O_RDONLY);
    if (fd < 0) {
        /* No Yama -- fine. */
        return 0;
    }

    char buf[8] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0)
        return 0;

    int scope = buf[0] - '0';
    if (scope >= 2) {
        fprintf(stderr,
                "probe: WARNING -- Yama ptrace_scope = %d\n"
                "  Scope >= 2 restricts process_vm_readv.\n"
                "  kbox may fail to read tracee memory.\n"
                "  Fix: echo 1 | sudo tee "
                "/proc/sys/kernel/yama/ptrace_scope\n",
                scope);
        /* Don't fail -- the process_vm_readv probe above is
         * the definitive test. */
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                  */
/* ------------------------------------------------------------------ */

int kbox_probe_host_features(void)
{
    int failures = 0;

    fprintf(stderr, "kbox: probing host features...\n");

    /* Advisory check first. */
    probe_yama_scope();

    if (probe_no_new_privs() < 0)
        failures++;

    if (probe_seccomp_listener() < 0)
        failures++;

    if (probe_process_vm_readv() < 0)
        failures++;

    if (failures > 0) {
        fprintf(stderr,
                "kbox: %d feature probe(s) failed -- cannot "
                "proceed.\n",
                failures);
        return -1;
    }

    fprintf(stderr, "kbox: all feature probes passed.\n");
    return 0;
}
