/* SPDX-License-Identifier: MIT */
/*
 * seccomp-bpf.c - Build and install a seccomp-unotify BPF filter.
 *
 * The BPF program has four sections:
 *   1. Arch check -- kill on wrong architecture
 *   2. Allow-list -- sendmsg, exit, exit_group bypass the supervisor
 *   3. Deny-list  -- dangerous syscalls return EPERM without reaching
 *                    the supervisor (seccomp manipulation, ptrace,
 *                    namespaces, io_uring, etc.)
 *   4. Default    -- everything else goes to USER_NOTIF
 *
 * The deny list prevents the guest from:
 *   - Installing its own seccomp filters (breaking CONTINUE)
 *   - Tracing/manipulating the supervisor process
 *   - Escaping via io_uring (bypasses seccomp entirely)
 *   - Manipulating namespaces, loading kernel modules, etc.
 *
 * NOT in the deny list (must reach dispatch for validation):
 *   - kill/tgkill/tkill: ash needs these for job control
 *   - mount/umount2: dispatch forwards to LKL
 *   - readlink: dispatch handles TOCTOU safely
 *   - prlimit64: dispatch validates GET vs SET
 */

#include "kbox/seccomp.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Deny list: arch-specific syscall numbers                           */
/* ------------------------------------------------------------------ */

#if defined(__x86_64__)
static const int deny_nrs[] = {
    /* Seccomp manipulation -- guest can install filters breaking CONTINUE */
    317, /* seccomp */

    /* Tracing -- supervisor memory/process access attacks */
    101, /* ptrace */
    311, /* process_vm_writev */
    440, /* process_madvise */
    448, /* process_mrelease */

    /* Landlock -- guest can restrict CONTINUE operations */
    444, /* landlock_create_ruleset */
    445, /* landlock_add_rule */
    446, /* landlock_restrict_self */

    /* System admin -- reboot, hostname manipulation */
    169, /* reboot */
    170, /* sethostname */
    171, /* setdomainname */
    163, /* acct */

    /* Kernel modules -- code injection */
    175, /* init_module */
    313, /* finit_module */
    176, /* delete_module */
    246, /* kexec_load */
    320, /* kexec_file_load */

    /* BPF/perf -- kernel tracing and manipulation */
    321, /* bpf */
    298, /* perf_event_open */

    /* Namespaces -- container escape */
    272, /* unshare */
    308, /* setns */

    /* Security keys */
    250, /* keyctl */
    248, /* add_key */
    249, /* request_key */

    /* Process personality */
    135, /* personality */
    312, /* kcmp */

    /* io_uring -- bypasses seccomp entirely */
    425, /* io_uring_setup */
    426, /* io_uring_enter */
    427, /* io_uring_register */

    /* Dangerous FD operations */
    323, /* userfaultfd */
    434, /* pidfd_open */
    438, /* pidfd_getfd */
    447, /* memfd_secret -- breaks process_vm_readv */

    /* New mount API -- host namespace manipulation */
    428, /* open_tree */
    429, /* move_mount */
    430, /* fsopen */
    431, /* fsconfig */
    432, /* fsmount */
    433, /* fspick */
    442, /* mount_setattr */
    155, /* pivot_root */

    /* Container escape via file handles */
    304, /* open_by_handle_at */
    303, /* name_to_handle_at */

    /* Filesystem monitoring */
    300, /* fanotify_init */
    301, /* fanotify_mark */

    /* Quota */
    179, /* quotactl */
    443, /* quotactl_fd */

    /* Time manipulation */
    227, /* clock_settime */
    164, /* settimeofday */
    159, /* adjtimex */
    305, /* clock_adjtime */

    /* Privileged I/O (x86_64 only) */
    172, /* iopl */
    173, /* ioperm */
    154, /* modify_ldt */

    /* Swap */
    167, /* swapon */
    168, /* swapoff */

    /* Legacy AIO */
    206, /* io_setup */
    209, /* io_submit */
    208, /* io_getevents */
    210, /* io_cancel */
    207, /* io_destroy */

    /* Misc */
    153, /* vhangup */
};

#elif defined(__aarch64__)
static const int deny_nrs[] = {
    /* Seccomp manipulation */
    277, /* seccomp */

    /* Tracing */
    117, /* ptrace */
    271, /* process_vm_writev */
    440, /* process_madvise */
    448, /* process_mrelease */

    /* Landlock */
    444, /* landlock_create_ruleset */
    445, /* landlock_add_rule */
    446, /* landlock_restrict_self */

    /* System admin */
    142, /* reboot */
    161, /* sethostname */
    162, /* setdomainname */
    89,  /* acct */

    /* Kernel modules */
    105, /* init_module */
    273, /* finit_module */
    106, /* delete_module */
    -1,  /* kexec_load (not on aarch64) */
    294, /* kexec_file_load */

    /* BPF/perf */
    280, /* bpf */
    241, /* perf_event_open */

    /* Namespaces */
    97,  /* unshare */
    268, /* setns */

    /* Security keys */
    219, /* keyctl */
    217, /* add_key */
    218, /* request_key */

    /* Process */
    92,  /* personality */
    272, /* kcmp */

    /* io_uring */
    425, /* io_uring_setup */
    426, /* io_uring_enter */
    427, /* io_uring_register */

    /* Dangerous FD */
    282, /* userfaultfd */
    434, /* pidfd_open */
    438, /* pidfd_getfd */
    447, /* memfd_secret */

    /* New mount API */
    428, /* open_tree */
    429, /* move_mount */
    430, /* fsopen */
    431, /* fsconfig */
    432, /* fsmount */
    433, /* fspick */
    442, /* mount_setattr */
    41,  /* pivot_root */

    /* Container escape */
    264, /* open_by_handle_at */
    263, /* name_to_handle_at */

    /* Filesystem monitoring */
    262, /* fanotify_init */
    263, /* fanotify_mark -- note: shares NR with name_to_handle_at on some
            kernels */

    /* Quota */
    -1,  /* quotactl (not on aarch64) */
    443, /* quotactl_fd */

    /* Time manipulation */
    112, /* clock_settime */
    -1,  /* settimeofday (not on aarch64) */
    171, /* adjtimex */
    266, /* clock_adjtime */

    /* Swap */
    224, /* swapon */
    225, /* swapoff */

    /* Legacy AIO */
    0, /* io_setup */
    2, /* io_submit */
    4, /* io_getevents */
    3, /* io_cancel */
    1, /* io_destroy */

    /* Misc */
    58, /* vhangup */
};

#else
#error "unsupported architecture"
#endif

#define DENY_COUNT ((int) (sizeof(deny_nrs) / sizeof(deny_nrs[0])))
#define ALLOW_COUNT 3

/*
 * Maximum BPF program length.  Each deny entry is 2 instructions
 * (compare + ret_errno), each allow entry is 2 instructions.
 * Plus 4 for arch check + 1 for default.
 *
 * Use a generous upper bound for the VLA.
 */
#define MAX_PROG_LEN (4 + DENY_COUNT * 2 + ALLOW_COUNT * 2 + 1)

int kbox_install_seccomp_listener(const struct kbox_host_nrs *h)
{
    struct kbox_sock_filter filter[MAX_PROG_LEN];
    struct kbox_sock_fprog prog;
    int idx = 0;
    int i;
    long ret;

    /* [0] Load architecture from seccomp_data. */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_ARCH_OFFSET);

    /* [1] Arch check: skip kill if correct. */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, KBOX_AUDIT_ARCH_CURRENT, 1,
        0);

    /* [2] Wrong arch: kill. */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_KILL_PROCESS);

    /* [3] Load syscall number. */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);

    /*
     * Allow-list: sendmsg, exit, exit_group.
     * These bypass the supervisor entirely.
     */
#define EMIT_ALLOW(nr)                                             \
    do {                                                           \
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(   \
            KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (nr), 0, 1); \
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(   \
            KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);    \
    } while (0)

    /*
     * sendmsg MUST stay allow-listed: the child's pre-exec FD transfer
     * uses sendmsg(SCM_RIGHTS) before the supervisor loop starts.
     * Removing it deadlocks the child/parent handshake.
     *
     * Consequence: guest sendmsg() on shadow sockets bypasses the
     * supervisor and operates on the AF_UNIX socketpair, losing
     * msg_name addressing.  Callers that need addressed datagrams
     * must use sendto() (intercepted via forward_sendto).
     * recvmsg() IS intercepted and returns correct source addresses.
     *
     * To fix: restructure supervisor startup to pass the listener FD
     * via pidfd_getfd or /proc/<pid>/fd instead of SCM_RIGHTS.
     */
    EMIT_ALLOW(h->sendmsg);
    EMIT_ALLOW(h->exit);
    EMIT_ALLOW(h->exit_group);
#undef EMIT_ALLOW

    /*
     * Deny-list: dangerous syscalls get EPERM without reaching
     * the supervisor.  Skip entries with nr == -1 (not available
     * on this architecture).
     */
    for (i = 0; i < DENY_COUNT; i++) {
        if (deny_nrs[i] < 0)
            continue;
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
            KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K,
            (unsigned int) deny_nrs[i], 0, 1);
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
            KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ERRNO(EPERM));
    }

    /* Default: everything else goes to the supervisor. */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_USER_NOTIF);

    if (idx > MAX_PROG_LEN) {
        fprintf(stderr, "kbox: BPF program overflow (%d > %d)\n", idx,
                MAX_PROG_LEN);
        errno = EINVAL;
        return -1;
    }

    prog.len = (unsigned short) idx;
    prog.filter = filter;

    ret = syscall(__NR_seccomp, KBOX_SECCOMP_SET_MODE_FILTER,
                  KBOX_SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (ret < 0) {
        fprintf(stderr,
                "kbox: seccomp(SET_MODE_FILTER, "
                "NEW_LISTENER) failed: %s\n",
                strerror(errno));
        return -1;
    }

    return (int) ret;
}
