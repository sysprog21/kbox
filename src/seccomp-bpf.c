/* SPDX-License-Identifier: MIT */

/* Build and install a seccomp-unotify BPF filter.
 *
 * The BPF program has four sections:
 *   1. Arch check: kill on wrong architecture
 *   2. Allow-list: sendmsg, exit, exit_group bypass the supervisor
 *   3. Deny-list:  dangerous syscalls return EPERM without reaching the
 *      supervisor (seccomp manipulation, ptrace, namespaces, io_uring, etc.)
 *   4. Default:    everything else goes to USER_NOTIF
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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "kbox/compiler.h"
#include "seccomp.h"
#include "syscall-trap-signal.h"

/* Deny list: arch-specific syscall numbers. */

#if defined(__x86_64__)
static const int deny_nrs[] = {
    /* Seccomp manipulation: guest can install filters breaking CONTINUE */
    317, /* seccomp */

    /* Tracing: supervisor memory/process access attacks */
    101, /* ptrace */
    311, /* process_vm_writev */
    440, /* process_madvise */
    448, /* process_mrelease */

    /* Landlock: guest can restrict CONTINUE operations */
    444, /* landlock_create_ruleset */
    445, /* landlock_add_rule */
    446, /* landlock_restrict_self */

    /* System admin: reboot, hostname manipulation */
    169, /* reboot */
    170, /* sethostname */
    171, /* setdomainname */
    163, /* acct */

    /* Kernel modules: code injection */
    175, /* init_module */
    313, /* finit_module */
    176, /* delete_module */
    246, /* kexec_load */
    320, /* kexec_file_load */

    /* BPF/perf: kernel tracing and manipulation */
    321, /* bpf */
    298, /* perf_event_open */

    /* Namespaces: container escape */
    272, /* unshare */
    308, /* setns */

    /* Security keys */
    250, /* keyctl */
    248, /* add_key */
    249, /* request_key */

    /* Process personality */
    135, /* personality */
    312, /* kcmp */

    /* io_uring: bypasses seccomp entirely */
    425, /* io_uring_setup */
    426, /* io_uring_enter */
    427, /* io_uring_register */

    /* Dangerous FD operations */
    323, /* userfaultfd */
    434, /* pidfd_open */
    438, /* pidfd_getfd */
    447, /* memfd_secret: breaks process_vm_readv */

    /* New mount API: host namespace manipulation */
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
    263, /* fanotify_mark: shares NR with name_to_handle_at on some kernels */

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
#define ALLOW_COUNT 4
/* Must be >= KBOX_LOADER_MAX_MAPPINGS (49) to accept all executable
 * mappings from the loader without truncation.
 */
#define MAX_IP_RANGE_COUNT 64

/* Maximum BPF program length. Each deny entry is 2 instructions (compare +
 * ret_errno), each allow entry is 2 instructions. Trap-mode range checks use
 * 6 instructions per range plus one default-allow before the syscall-number
 * path. The trap-ranges filter also has an early rt_sigreturn allow for the
 * host signal restorer path.
 *
 * Use a generous upper bound for the VLA.
 *
 * Worst-case sizing: ~30 fixed + 8*N allow-ranges + 8 EMIT_ALLOW +
 * 5*5 shadow-allow + 5*8 host-fd-band + 2*DENY_COUNT ≈ 310 instructions
 * for typical inputs.  2048 provides >6x headroom; the post-emission check
 * catches unexpected growth without per-write bounds testing.
 */
#define MAX_PROG_LEN 2048

static void emit_fast_shadow_allow(struct kbox_sock_filter *filter,
                                   int *idx,
                                   int nr)
{
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (unsigned int) nr, 0, 3);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_ARG0_LO_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGE | KBOX_BPF_K, KBOX_FD_FAST_BASE, 0, 1);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);
}

static void emit_host_fd_band_allow(struct kbox_sock_filter *filter,
                                    int *idx,
                                    int nr,
                                    unsigned int min_fd)
{
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (unsigned int) nr, 0, 3);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_ARG0_LO_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGE | KBOX_BPF_K, min_fd, 0, 1);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);
}

static int emit_ip_range_allow(struct kbox_sock_filter *filter,
                               int *idx,
                               const struct kbox_syscall_trap_ip_range *range)
{
    uint64_t start;
    uint64_t end_inclusive;
    uint32_t hi;
    uint32_t lo_start;
    uint32_t lo_end;

    if (!filter || !idx || !range || range->start >= range->end)
        return -1;

    start = (uint64_t) range->start;
    end_inclusive = (uint64_t) range->end - 1;
    if ((start >> 32) != (end_inclusive >> 32))
        return -1;

    hi = (uint32_t) (start >> 32);
    lo_start = (uint32_t) start;
    lo_end = (uint32_t) end_inclusive;

    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_IP_HI_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, hi, 0, 4);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_IP_LO_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGE | KBOX_BPF_K, lo_start, 0, 2);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGT | KBOX_BPF_K, lo_end, 1, 0);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);
    return 0;
}

static int emit_ip_range_trap_match(
    struct kbox_sock_filter *filter,
    int *idx,
    const struct kbox_syscall_trap_ip_range *range,
    int *jump_index_out)
{
    uint64_t start;
    uint64_t end_inclusive;
    uint32_t hi;
    uint32_t lo_start;
    uint32_t lo_end;

    if (!filter || !idx || !range || !jump_index_out ||
        range->start >= range->end)
        return -1;

    start = (uint64_t) range->start;
    end_inclusive = (uint64_t) range->end - 1;
    if ((start >> 32) != (end_inclusive >> 32))
        return -1;

    hi = (uint32_t) (start >> 32);
    lo_start = (uint32_t) start;
    lo_end = (uint32_t) end_inclusive;

    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_IP_HI_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, hi, 0, 4);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_IP_LO_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGE | KBOX_BPF_K, lo_start, 0, 2);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGT | KBOX_BPF_K, lo_end, 1, 0);
    *jump_index_out = *idx;
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_K, 0, 0, 0);
    return 0;
}

static int install_seccomp_filter(
    const struct kbox_host_nrs *h,
    unsigned int default_action,
    unsigned int filter_flags,
    const struct kbox_syscall_trap_ip_range *allow_ranges,
    size_t allow_range_count)
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

    if (allow_ranges) {
        for (size_t r = 0; r < allow_range_count; r++) {
            if (emit_ip_range_allow(filter, &idx, &allow_ranges[r]) < 0) {
                errno = EINVAL;
                return -1;
            }
        }
    }

    /* Load syscall number. */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);

    /* Allow-list: sendmsg, exit, exit_group.
     * These bypass the supervisor entirely.
     */
#define EMIT_ALLOW(nr)                                             \
    do {                                                           \
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(   \
            KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (nr), 0, 1); \
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(   \
            KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);    \
    } while (0)

    /* sendmsg MUST stay allow-listed: the child's pre-exec FD transfer uses
     * sendmsg(SCM_RIGHTS) before the supervisor loop starts. Removing it
     * deadlocks the child/parent handshake.
     *
     * Consequence: guest sendmsg() on shadow sockets bypasses the supervisor
     * and operates on the AF_UNIX socketpair, losing msg_name addressing.
     * Callers that need addressed datagrams must use sendto() (intercepted via
     * forward_sendto). recvmsg() IS intercepted and returns correct source
     * addresses.
     *
     * To fix: restructure supervisor startup to pass the listener FD via
     * pidfd_getfd or /proc/<pid>/fd instead of SCM_RIGHTS.
     */
    EMIT_ALLOW(h->sendmsg);
    EMIT_ALLOW(h->exit);
    EMIT_ALLOW(h->exit_group);
    EMIT_ALLOW(h->rt_sigreturn);
#undef EMIT_ALLOW

    emit_fast_shadow_allow(filter, &idx, h->read);
    emit_fast_shadow_allow(filter, &idx, h->pread64);
    emit_fast_shadow_allow(filter, &idx, h->write);
    emit_fast_shadow_allow(filter, &idx, h->lseek);
    emit_fast_shadow_allow(filter, &idx, h->fstat);
    emit_host_fd_band_allow(filter, &idx, h->read, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->pread64, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->lseek, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->fstat, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->close, KBOX_FD_HOSTONLY_BASE);

    /* The arg0-based fast-fd checks above overwrite A with the file
     * descriptor. Reload the syscall number before the deny list so low FDs
     * do not alias deny-list syscall numbers (for example write(fd=1) vs
     * io_destroy on aarch64).
     */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);

    /* Deny-list: dangerous syscalls get EPERM without reaching the supervisor.
     * Skip entries with nr == -1 (not available on this architecture).
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
        KBOX_BPF_RET | KBOX_BPF_K, default_action);

    if (idx > MAX_PROG_LEN) {
        fprintf(stderr, "kbox: BPF program overflow (%d > %d)\n", idx,
                MAX_PROG_LEN);
        errno = EINVAL;
        return -1;
    }

    prog.len = (unsigned short) idx;
    prog.filter = filter;

    ret = syscall(__NR_seccomp, KBOX_SECCOMP_SET_MODE_FILTER, filter_flags,
                  &prog);
    if (ret < 0) {
        fprintf(stderr, "kbox: seccomp(SET_MODE_FILTER, 0x%x) failed: %s\n",
                filter_flags, strerror(errno));
        return -1;
    }

    return (int) ret;
}

int kbox_install_seccomp_listener(const struct kbox_host_nrs *h)
{
    return install_seccomp_filter(h, KBOX_SECCOMP_RET_USER_NOTIF,
                                  KBOX_SECCOMP_FILTER_FLAG_NEW_LISTENER, NULL,
                                  0);
}

int kbox_install_seccomp_trap(const struct kbox_host_nrs *h)
{
    struct kbox_syscall_trap_ip_range allow_range;

    if (kbox_syscall_trap_host_syscall_range(&allow_range) < 0) {
        errno = EINVAL;
        return -1;
    }
    return install_seccomp_filter(h, KBOX_SECCOMP_RET_TRAP, 0, &allow_range, 1);
}

/* A successful seccomp install returns into userspace with the filter already
 * active. Keep this return path free of sanitizer/runtime syscalls so the
 * launch code can branch straight into the guest.
 */
__attribute__((no_stack_protector))
#if KBOX_HAS_ASAN
__attribute__((no_sanitize("address")))
#endif
__attribute__((no_sanitize("undefined"))) static int
install_seccomp_trap_ranges_ex(
    const struct kbox_host_nrs *h,
    const struct kbox_syscall_trap_ip_range *trap_ranges,
    size_t trap_range_count)
{
    struct kbox_sock_filter filter[MAX_PROG_LEN];
    struct kbox_sock_fprog prog;
    int match_jumps[MAX_IP_RANGE_COUNT];
    struct kbox_syscall_trap_ip_range internal_ranges[16];
    int internal_jumps[16];
    size_t internal_count = 0;
    int idx = 0;
    int internal_allow_idx = -1;
    int nr_load_idx;
    int i;
    long ret;

    if (!h || !trap_ranges || trap_range_count == 0 ||
        trap_range_count > MAX_IP_RANGE_COUNT) {
        errno = EINVAL;
        return -1;
    }
    if (kbox_syscall_trap_internal_ip_ranges(
            internal_ranges,
            sizeof(internal_ranges) / sizeof(internal_ranges[0]),
            &internal_count) < 0) {
        errno = EINVAL;
        return -1;
    }

    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_ARCH_OFFSET);
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, KBOX_AUDIT_ARCH_CURRENT, 1,
        0);
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_KILL_PROCESS);

    /* The kernel's signal restorer may live outside guest exec mappings.
     * Allow rt_sigreturn before the IP gate so SIGSYS delivery can unwind
     * without reopening general host-IP syscall execution.
     */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K,
        (unsigned int) h->rt_sigreturn, 0, 1);
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);

    for (i = 0; i < (int) internal_count; i++) {
        if (emit_ip_range_trap_match(filter, &idx, &internal_ranges[i],
                                     &internal_jumps[i]) < 0) {
            errno = EINVAL;
            return -1;
        }
    }

    for (i = 0; i < (int) trap_range_count; i++) {
        if (emit_ip_range_trap_match(filter, &idx, &trap_ranges[i],
                                     &match_jumps[i]) < 0) {
            errno = EINVAL;
            return -1;
        }
    }

    /* Non-guest, non-trampoline IPs must not reach the host kernel.
     *
     * The dedicated host trampoline covers the small set of syscalls kbox
     * executes on the trapped guest thread. Guest executable mappings are
     * matched above and routed into the dispatcher path. Any other IP is
     * outside the permitted syscall origin set and is rejected.
     */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ERRNO(EPERM));

    internal_allow_idx = idx;
    for (i = 0; i < (int) internal_count; i++) {
        int rel = internal_allow_idx - (internal_jumps[i] + 1);

        if (rel < 0) {
            errno = EINVAL;
            return -1;
        }
        filter[internal_jumps[i]].k = (unsigned int) rel;
    }
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);

    nr_load_idx = idx;
    for (i = 0; i < (int) trap_range_count; i++) {
        int rel = nr_load_idx - (match_jumps[i] + 1);

        if (rel < 0) {
            errno = EINVAL;
            return -1;
        }
        filter[match_jumps[i]].k = (unsigned int) rel;
    }

    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);

#define EMIT_ALLOW(nr)                                             \
    do {                                                           \
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(   \
            KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (nr), 0, 1); \
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(   \
            KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);    \
    } while (0)

    EMIT_ALLOW(h->sendmsg);
    EMIT_ALLOW(h->exit);
    EMIT_ALLOW(h->exit_group);
    EMIT_ALLOW(h->rt_sigreturn);
#undef EMIT_ALLOW

    emit_fast_shadow_allow(filter, &idx, h->read);
    emit_fast_shadow_allow(filter, &idx, h->pread64);
    emit_fast_shadow_allow(filter, &idx, h->write);
    emit_fast_shadow_allow(filter, &idx, h->lseek);
    emit_fast_shadow_allow(filter, &idx, h->fstat);
    emit_host_fd_band_allow(filter, &idx, h->read, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->pread64, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->lseek, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->fstat, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->close, KBOX_FD_HOSTONLY_BASE);

    /* The arg0-based fast-fd checks above overwrite A with the file
     * descriptor. Reload the syscall number before the deny list so low FDs
     * do not alias deny-list syscall numbers.
     */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);

    for (i = 0; i < DENY_COUNT; i++) {
        if (deny_nrs[i] < 0)
            continue;
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
            KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K,
            (unsigned int) deny_nrs[i], 0, 1);
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
            KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ERRNO(EPERM));
    }

    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_TRAP);

    if (idx > MAX_PROG_LEN) {
        errno = EINVAL;
        return -1;
    }

    prog.len = (unsigned short) idx;
    prog.filter = filter;

    ret = syscall(__NR_seccomp, KBOX_SECCOMP_SET_MODE_FILTER, 0, &prog);
    if (ret < 0) {
        fprintf(stderr,
                "kbox: seccomp(SET_MODE_FILTER, trap ranges) failed: %s\n",
                strerror(errno));
        return -1;
    }

    return (int) ret;
}

int kbox_install_seccomp_trap_ranges(
    const struct kbox_host_nrs *h,
    const struct kbox_syscall_trap_ip_range *trap_ranges,
    size_t trap_range_count)
{
    return install_seccomp_trap_ranges_ex(h, trap_ranges, trap_range_count);
}

int kbox_install_seccomp_rewrite_ranges(
    const struct kbox_host_nrs *h,
    const struct kbox_syscall_trap_ip_range *trap_ranges,
    size_t trap_range_count)
{
    return install_seccomp_trap_ranges_ex(h, trap_ranges, trap_range_count);
}
