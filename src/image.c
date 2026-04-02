/* SPDX-License-Identifier: MIT */

/* Image mode lifecycle.
 *
 * Opens a rootfs disk image, registers it as an LKL block device, boots the
 * kernel, mounts the filesystem, chroots in, applies recommended / bind
 * mounts, sets identity, and then forks the seccomp-supervised child process.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <unistd.h>

#include "fd-table.h"
#include "kbox/compiler.h"
#include "kbox/elf.h"
#include "kbox/identity.h"
#include "kbox/image.h"
#include "kbox/mount.h"
#include "kbox/probe.h"
#include "lkl-wrap.h"
#include "loader-launch.h"
#include "net.h"
#include "rewrite.h"
#include "seccomp.h"
#include "shadow-fd.h"
#include "syscall-trap.h"
#ifdef KBOX_HAS_WEB
#include "web.h"
#endif

int kbox_rewrite_has_fork_sites_memfd(int fd,
                                      const struct kbox_host_nrs *host_nrs);

/* Determine the root image path from the three mutually exclusive options.
 * Returns the path, or NULL on error.
 */
static const char *select_root_path(const struct kbox_image_args *a)
{
    if (a->system_root)
        return a->root_dir;
    if (a->recommended)
        return a->root_dir;
    if (a->root_dir)
        return a->root_dir;

    fprintf(stderr, "no rootfs image specified (-r, -R, or -S)\n");
    return NULL;
}

/* Join mount_opts[] into a single comma-separated string.
 * Writes into buf[bufsz].  Returns buf, or "" if no options.
 */
static const char *join_mount_opts(const struct kbox_image_args *a,
                                   char *buf,
                                   size_t bufsz)
{
    size_t pos = 0;
    int i;

    buf[0] = '\0';
    for (i = 0; i < a->mount_opt_count; i++) {
        size_t len = strlen(a->mount_opts[i]);
        if (pos + len + 2 > bufsz) {
            fprintf(stderr, "kbox: mount options overflow (%zu bytes)\n",
                    bufsz);
            return NULL;
        }
        if (pos > 0)
            buf[pos++] = ',';
        memcpy(buf + pos, a->mount_opts[i], len);
        pos += len;
    }
    buf[pos] = '\0';
    return buf;
}

extern char **environ;

/* AUTO fast-path selection.
 *
 * When KBOX_AUTO_FAST_PATH is set (via Kconfig SYSCALL_FAST_PATH=y), AUTO
 * mode selects rewrite/trap for non-shell, non-networking binaries on
 * both x86_64 and aarch64.  The guest-thread local fast-path handles 50+
 * CONTINUE syscalls without service-thread IPC, giving trap/rewrite mode
 * a throughput advantage for workloads heavy on futex/brk/epoll/mmap.
 *
 * Users can override with --syscall-mode=rewrite or --syscall-mode=trap.
 */
#ifndef KBOX_AUTO_FAST_PATH
#define KBOX_AUTO_FAST_PATH 1
#endif

/* ASAN and the trap/rewrite path are fundamentally incompatible: the
 * trap path switches to a guest stack that ASAN doesn't track, and the
 * dispatch chain accesses ASAN-tracked memory.  AUTO uses seccomp under
 * ASAN; release builds get the full fast-path.  This is the correct
 * separation: ASAN tests correctness, release tests performance.
 */
#if KBOX_HAS_ASAN
#define KBOX_AUTO_ENABLE_USERSPACE_FAST_PATH 0
#else
#define KBOX_AUTO_ENABLE_USERSPACE_FAST_PATH KBOX_AUTO_FAST_PATH
#endif

static int is_shell_command(const char *command)
{
    static const char *const shells[] = {
        "sh", "bash", "ash", "zsh", "dash", "fish", "csh", "tcsh", "ksh", NULL,
    };
    const char *base = strrchr(command, '/');

    base = base ? base + 1 : command;
    for (const char *const *s = shells; *s; s++) {
        if (strcmp(base, *s) == 0)
            return 1;
    }
    return 0;
}

#if KBOX_AUTO_ENABLE_USERSPACE_FAST_PATH
/* Decide whether AUTO mode should prefer the userspace fast path (trap/rewrite)
 * over the seccomp supervisor path for a given binary.
 *
 * Considers the combined syscall site count from both the main binary and its
 * interpreter (if dynamic). The fast path is viable as long as ANY executable
 * segment has rewritable sites -- trap mode catches everything via SIGSYS, and
 * rewrite mode patches sites in both the main binary and the interpreter.
 *
 * Returns 1 to use trap/rewrite, 0 to fall back to seccomp.
 */
static int auto_prefers_userspace_fast_path(
    const struct kbox_rewrite_report *exec_report,
    const struct kbox_rewrite_report *interp_report,
    int has_fork_sites)
{
    if (!exec_report)
        return 0;

    /* Trap/rewrite mode duplicates the in-process LKL state on fork, so
     * parent and child see independent filesystem state. AUTO selects the
     * fast path for non-shell commands that do not contain fork/clone
     * wrapper sites in the main executable. The interpreter (libc) is
     * NOT scanned because it always contains fork wrappers regardless of
     * whether the specific program uses them.
     *
     * Dynamic binaries whose main executable has no fork wrappers get
     * the fast path. If the program does fork through libc, children
     * inherit their own LKL copy and run independently. This is a known
     * trade-off: cross-process filesystem coherence is not guaranteed in
     * trap/rewrite mode.
     */
    if (has_fork_sites)
        return 0;

    if (exec_report->candidate_count == 0 &&
        (!interp_report || interp_report->candidate_count == 0))
        return 0;

    return 1;
}
#endif

static void maybe_apply_virtual_procinfo_fast_path(int fd,
                                                   const char *label,
                                                   int verbose)
{
    struct kbox_rewrite_report report;
    size_t applied = 0;

    if (fd < 0)
        return;
    if (kbox_rewrite_analyze_memfd(fd, &report) < 0)
        return;
    if (report.arch != KBOX_REWRITE_ARCH_X86_64 &&
        report.arch != KBOX_REWRITE_ARCH_AARCH64)
        return;
    if (kbox_rewrite_apply_virtual_procinfo_memfd(fd, &applied, &report) < 0)
        return;
    if (verbose && applied > 0) {
        fprintf(stderr,
                "kbox: seccomp procinfo fast path: %s: patched %zu wrapper%s\n",
                label ? label : "memfd", applied, applied == 1 ? "" : "s");
    }
}

static uint32_t memfd_wrapper_family_mask(int fd,
                                          const struct kbox_host_nrs *host_nrs)
{
    uint32_t mask = 0;

    if (fd < 0 || !host_nrs)
        return 0;
    if (kbox_rewrite_wrapper_family_mask_memfd(fd, host_nrs, &mask) < 0)
        return 0;
    return mask;
}

static int wrapper_family_mask_has_stat(uint32_t mask)
{
    return (mask & KBOX_REWRITE_WRAPPER_FAMILY_STAT) != 0;
}

static int wrapper_family_mask_has_open(uint32_t mask)
{
    return (mask & KBOX_REWRITE_WRAPPER_FAMILY_OPEN) != 0;
}

static int memfd_has_stat_wrapper_fast_candidates(
    int fd,
    const struct kbox_host_nrs *host_nrs)
{
    return wrapper_family_mask_has_stat(
        memfd_wrapper_family_mask(fd, host_nrs));
}

static int memfd_has_open_wrapper_fast_candidates(
    int fd,
    const struct kbox_host_nrs *host_nrs)
{
    return wrapper_family_mask_has_open(
        memfd_wrapper_family_mask(fd, host_nrs));
}

struct wrapper_candidate_count_ctx {
    size_t count;
    int filter_enabled;
    enum kbox_rewrite_wrapper_candidate_kind kind_filter;
};

static int count_wrapper_candidate_cb(
    const struct kbox_rewrite_wrapper_candidate *candidate,
    void *opaque)
{
    struct wrapper_candidate_count_ctx *ctx = opaque;

    if (!candidate || !ctx)
        return -1;
    if (ctx->filter_enabled && candidate->kind != ctx->kind_filter)
        return 0;
    ctx->count++;
    return 0;
}

static size_t memfd_count_wrapper_family_candidates(
    int fd,
    const struct kbox_host_nrs *host_nrs,
    uint32_t family_mask)
{
    struct wrapper_candidate_count_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.filter_enabled = 0;
    if (fd < 0 || !host_nrs || family_mask == 0)
        return 0;
    if (kbox_rewrite_visit_memfd_wrapper_candidates(
            fd, host_nrs, family_mask, count_wrapper_candidate_cb, &ctx) < 0) {
        return 0;
    }
    return ctx.count;
}

static size_t memfd_count_wrapper_family_candidates_by_kind(
    int fd,
    const struct kbox_host_nrs *host_nrs,
    uint32_t family_mask,
    enum kbox_rewrite_wrapper_candidate_kind kind)
{
    struct wrapper_candidate_count_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.filter_enabled = 1;
    ctx.kind_filter = kind;
    if (fd < 0 || !host_nrs || family_mask == 0)
        return 0;
    if (kbox_rewrite_visit_memfd_wrapper_candidates(
            fd, host_nrs, family_mask, count_wrapper_candidate_cb, &ctx) < 0) {
        return 0;
    }
    return ctx.count;
}

static size_t memfd_count_phase1_path_candidates(
    int fd,
    const struct kbox_host_nrs *host_nrs)
{
    struct kbox_rewrite_wrapper_candidate candidates[16];
    size_t count = 0;

    if (fd < 0 || !host_nrs)
        return 0;
    if (kbox_rewrite_collect_memfd_phase1_path_candidates(
            fd, host_nrs, candidates,
            sizeof(candidates) / sizeof(candidates[0]), &count) < 0) {
        return 0;
    }
    return count;
}

struct wrapper_candidate_log_ctx {
    const char *label;
    const char *family_name;
    const char *prefix;
};

static const char *wrapper_candidate_kind_name(
    enum kbox_rewrite_wrapper_candidate_kind kind)
{
    switch (kind) {
    case KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT:
        return "direct";
    case KBOX_REWRITE_WRAPPER_CANDIDATE_SYSCALL_CANCEL:
        return "cancel";
    default:
        return "unknown";
    }
}

static int log_wrapper_candidate_cb(
    const struct kbox_rewrite_wrapper_candidate *candidate,
    void *opaque)
{
    const struct wrapper_candidate_log_ctx *ctx = opaque;

    if (!candidate || !ctx)
        return -1;
    fprintf(stderr,
            "kbox: %s %s%s: off=0x%llx vaddr=0x%llx "
            "nr=%llu kind=%s\n",
            ctx->label ? ctx->label : "memfd",
            ctx->family_name ? ctx->family_name : "path",
            ctx->prefix ? ctx->prefix : "-wrapper candidate",
            (unsigned long long) candidate->file_offset,
            (unsigned long long) candidate->vaddr,
            (unsigned long long) candidate->nr,
            wrapper_candidate_kind_name(candidate->kind));
    return 0;
}

static void maybe_log_wrapper_family_candidates(
    const char *label,
    int fd,
    const struct kbox_host_nrs *host_nrs,
    uint32_t family_mask,
    const char *family_name,
    int verbose)
{
    struct kbox_rewrite_wrapper_candidate candidates[16];
    struct wrapper_candidate_log_ctx ctx;
    size_t count = 0;

    if (!verbose || fd < 0 || !host_nrs || family_mask == 0)
        return;
    if (kbox_rewrite_collect_memfd_wrapper_candidates(
            fd, host_nrs, family_mask, candidates,
            sizeof(candidates) / sizeof(candidates[0]), &count) < 0) {
        return;
    }
    ctx.label = label;
    ctx.family_name = family_name;
    ctx.prefix = "-wrapper candidate";
    for (size_t i = 0;
         i < count && i < (sizeof(candidates) / sizeof(candidates[0])); i++) {
        (void) log_wrapper_candidate_cb(&candidates[i], &ctx);
    }
}

static void maybe_log_phase1_path_candidates(
    const char *label,
    int fd,
    const struct kbox_host_nrs *host_nrs,
    int verbose)
{
    struct kbox_rewrite_wrapper_candidate candidates[16];
    struct wrapper_candidate_log_ctx ctx;
    size_t count = 0;

    if (!verbose || fd < 0 || !host_nrs)
        return;
    if (kbox_rewrite_collect_memfd_phase1_path_candidates(
            fd, host_nrs, candidates,
            sizeof(candidates) / sizeof(candidates[0]), &count) < 0) {
        return;
    }
    ctx.label = label;
    ctx.family_name = "phase1-path";
    ctx.prefix = " target";
    for (size_t i = 0;
         i < count && i < (sizeof(candidates) / sizeof(candidates[0])); i++) {
        (void) log_wrapper_candidate_cb(&candidates[i], &ctx);
    }
}

static size_t count_envp(char *const *envp)
{
    size_t n = 0;

    if (!envp)
        return 0;
    while (envp[n])
        n++;
    return n;
}

static const char **build_loader_argv(const char *command,
                                      const char *const *extra_args,
                                      int extra_argc)
{
    size_t argc = (size_t) extra_argc + 1;
    const char **argv = calloc(argc + 1, sizeof(*argv));

    if (!argv)
        return NULL;
    argv[0] = command;
    for (int i = 0; i < extra_argc; i++)
        argv[i + 1] = extra_args[i];
    return argv;
}

static int prepare_userspace_launch(const struct kbox_image_args *args,
                                    const char *command,
                                    int exec_memfd,
                                    int interp_memfd,
                                    uid_t override_uid,
                                    gid_t override_gid,
                                    struct kbox_loader_launch *launch)
{
    unsigned char launch_random[KBOX_LOADER_RANDOM_SIZE];
    struct kbox_loader_launch_spec spec;
    const char **argv = NULL;
    size_t argc = (size_t) args->extra_argc + 1;
    uint32_t uid = (uint32_t) (args->root_id || args->system_root
                                   ? 0
                                   : (override_uid != (uid_t) -1 ? override_uid
                                                                 : getuid()));
    uint32_t gid = (uint32_t) (args->root_id || args->system_root
                                   ? 0
                                   : (override_gid != (gid_t) -1 ? override_gid
                                                                 : getgid()));
    int rc;

    if (!launch || exec_memfd < 0)
        return -1;

    /* Fill AT_RANDOM with real entropy for stack canary and libc PRNG seeding.
     * Fall back to zeros only if getrandom is unavailable.
     */
    memset(launch_random, 0, sizeof(launch_random));
    {
        ssize_t n = getrandom(launch_random, sizeof(launch_random), 0);
        (void) n;
    }

    argv = build_loader_argv(command, args->extra_args, args->extra_argc);
    if (!argv)
        return -1;

    memset(&spec, 0, sizeof(spec));
    spec.exec_fd = exec_memfd;
    spec.interp_fd = interp_memfd;
    spec.argv = argv;
    spec.argc = argc;
    spec.envp = (const char *const *) environ;
    spec.envc = count_envp(environ);
    spec.execfn = command;
    spec.random_bytes = launch_random;
    spec.page_size = (uint64_t) sysconf(_SC_PAGESIZE);
    spec.stack_top = 0x700000010000ULL;
    spec.main_load_bias = 0x600000000000ULL;
    spec.interp_load_bias = 0x610000000000ULL;
    spec.uid = uid;
    spec.euid = uid;
    spec.gid = gid;
    spec.egid = gid;
    spec.secure = 0;

    rc = kbox_loader_prepare_launch(&spec, launch);
    free(argv);
    return rc;
}

static const struct kbox_host_nrs *select_host_nrs(void)
{
#if defined(__x86_64__)
    return &HOST_NRS_X86_64;
#elif defined(__aarch64__)
    return &HOST_NRS_AARCH64;
#else
    return NULL;
#endif
}

static int collect_trap_exec_ranges(const struct kbox_loader_launch *launch,
                                    struct kbox_syscall_trap_ip_range *ranges,
                                    size_t range_cap,
                                    size_t *range_count)
{
    struct kbox_loader_exec_range exec_ranges[KBOX_LOADER_MAX_MAPPINGS];
    size_t exec_count = 0;

    if (!launch || !ranges || !range_count)
        return -1;
    if (kbox_loader_collect_exec_ranges(
            launch, exec_ranges, KBOX_LOADER_MAX_MAPPINGS, &exec_count) < 0) {
        return -1;
    }
    if (exec_count > range_cap)
        return -1;

    for (size_t i = 0; i < exec_count; i++) {
        ranges[i].start = (uintptr_t) exec_ranges[i].start;
        ranges[i].end = (uintptr_t) exec_ranges[i].end;
    }
    *range_count = exec_count;
    return 0;
}

static void drop_launch_caps(void)
{
    prctl(47 /* PR_CAP_AMBIENT */, 4 /* PR_CAP_AMBIENT_CLEAR_ALL */, 0, 0, 0);
    for (int cap = 0; cap <= 63; cap++)
        prctl(24 /* PR_CAPBSET_DROP */, cap, 0, 0, 0);
}

static int set_launch_rlimits(void)
{
    struct rlimit nofile = {65536, 65536};
    struct rlimit rtprio = {0, 0};
    struct rlimit current;
    rlim_t required_nofile = (rlim_t) (KBOX_FD_BASE + KBOX_FD_TABLE_MAX);

    if (setrlimit(RLIMIT_NOFILE, &nofile) != 0)
        return -1;
    if (getrlimit(RLIMIT_NOFILE, &current) != 0)
        return -1;
    if (current.rlim_cur < required_nofile) {
        errno = EMFILE;
        return -1;
    }
    if (setrlimit(RLIMIT_RTPRIO, &rtprio) != 0)
        return -1;
    return 0;
}

static void dump_loader_launch(const struct kbox_loader_launch *launch)
{
    if (!launch)
        return;

    fprintf(stderr, "kbox: trap launch: pc=0x%llx sp=0x%llx mappings=%zu\n",
            (unsigned long long) launch->transfer.pc,
            (unsigned long long) launch->transfer.sp,
            launch->layout.mapping_count);
    for (size_t i = 0; i < launch->layout.mapping_count; i++) {
        const struct kbox_loader_mapping *mapping = &launch->layout.mappings[i];

        fprintf(stderr,
                "kbox: trap launch: map[%zu] src=%d addr=0x%llx size=0x%llx "
                "prot=%d flags=0x%x file_off=0x%llx file_size=0x%llx "
                "zero_fill=0x%llx+0x%llx\n",
                i, mapping->source, (unsigned long long) mapping->addr,
                (unsigned long long) mapping->size, mapping->prot,
                mapping->flags, (unsigned long long) mapping->file_offset,
                (unsigned long long) mapping->file_size,
                (unsigned long long) mapping->zero_fill_start,
                (unsigned long long) mapping->zero_fill_size);
    }
}

static void init_launch_ctx(struct kbox_supervisor_ctx *ctx,
                            struct kbox_fd_table *fd_table,
                            const struct kbox_image_args *args,
                            const struct kbox_sysnrs *sysnrs,
                            const struct kbox_host_nrs *host_nrs,
                            struct kbox_web_ctx *web_ctx)
{
    kbox_fd_table_init(fd_table);
    for (int i = 0; i < 3; i++)
        kbox_fd_table_insert_at(fd_table, i, KBOX_LKL_FD_SHADOW_ONLY, 0);
    memset(ctx, 0, sizeof(*ctx));
#if KBOX_STAT_CACHE_ENABLED
    for (int ci = 0; ci < KBOX_STAT_CACHE_MAX; ci++)
        ctx->stat_cache[ci].lkl_fd = -1;
#endif
    ctx->sysnrs = sysnrs;
    ctx->host_nrs = host_nrs;
    ctx->fd_table = fd_table;
    ctx->listener_fd = -1;
    ctx->proc_self_fd_dirfd = -1;
    ctx->proc_mem_fd = -1;
    ctx->child_pid = getpid();
    ctx->host_root = NULL;
    ctx->verbose = args->verbose;
    ctx->root_identity = args->root_id || args->system_root;
    ctx->override_uid = (uid_t) -1;
    ctx->override_gid = (gid_t) -1;
    ctx->normalize = args->normalize;
    ctx->guest_mem_ops = &kbox_current_guest_mem_ops;
    ctx->active_guest_mem.ops = &kbox_current_guest_mem_ops;
    ctx->active_guest_mem.opaque = 0;
    ctx->fd_inject_ops = NULL;
    ctx->web = web_ctx;
}

/* After the exec-range seccomp filter is installed, the success path must
 * branch directly into guest code. ASAN/UBSAN runtimes and stack-protector
 * epilogues may issue host syscalls from unregistered IPs, which the filter
 * rejects with EPERM.
 */
__attribute__((no_stack_protector))
#if KBOX_HAS_ASAN
__attribute__((no_sanitize("address")))
#endif
__attribute__((no_sanitize("undefined"))) static int
install_exec_filter_and_transfer(
    int (*install_filter)(const struct kbox_host_nrs *h,
                          const struct kbox_syscall_trap_ip_range *trap_ranges,
                          size_t trap_range_count),
    const struct kbox_host_nrs *host_nrs,
    const struct kbox_syscall_trap_ip_range *ranges,
    size_t range_count,
    const struct kbox_loader_transfer_state *transfer)
{
    if (!install_filter || !host_nrs || !ranges || range_count == 0 ||
        !transfer) {
        errno = EINVAL;
        return -1;
    }
    if (install_filter(host_nrs, ranges, range_count) < 0)
        return -1;

    kbox_loader_transfer_to_guest(transfer);
}

static int run_trap_launch(const struct kbox_image_args *args,
                           const struct kbox_sysnrs *sysnrs,
                           struct kbox_loader_launch *launch,
                           struct kbox_web_ctx *web_ctx)
{
    struct kbox_syscall_trap_ip_range ranges[KBOX_LOADER_MAX_MAPPINGS];
    const struct kbox_host_nrs *host_nrs = select_host_nrs();
    struct kbox_fd_table fd_table;
    struct kbox_supervisor_ctx ctx;
    struct kbox_syscall_trap_runtime runtime;
    size_t range_count = 0;

    if (!host_nrs || !launch)
        return -1;
#if defined(__x86_64__) && KBOX_HAS_ASAN
    (void) sysnrs;
    (void) web_ctx;
    fprintf(stderr,
            "kbox: trap mode is unsupported in x86_64 ASAN builds; "
            "use --syscall-mode=seccomp or BUILD=release\n");
    errno = ENOTSUP;
    return -1;
#endif
    if (collect_trap_exec_ranges(launch, ranges, KBOX_LOADER_MAX_MAPPINGS,
                                 &range_count) < 0) {
        fprintf(stderr,
                "kbox: trap launch failed: cannot collect guest exec ranges\n");
        return -1;
    }
    if (args->verbose)
        dump_loader_launch(launch);

    init_launch_ctx(&ctx, &fd_table, args, sysnrs, host_nrs, web_ctx);

    runtime.sqpoll = args->sqpoll;
    if (kbox_syscall_trap_runtime_install(&runtime, &ctx) < 0) {
        fprintf(stderr,
                "kbox: trap launch failed: cannot install SIGSYS handler\n");
        return -1;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "prctl(PR_SET_NO_NEW_PRIVS): %s\n", strerror(errno));
        kbox_syscall_trap_runtime_uninstall(&runtime);
        return -1;
    }

    drop_launch_caps();
    if (set_launch_rlimits() < 0) {
        fprintf(stderr, "kbox: trap launch failed: RLIMIT_NOFILE too low\n");
        kbox_syscall_trap_runtime_uninstall(&runtime);
        return -1;
    }

    /* Install the IP-gated trap filter for the guest's executable ranges.
     * The userspace trap runtime handles the intercepted syscalls; kbox's
     * own text stays outside the trapped ranges and executes natively.
     */
    if (args->verbose) {
        for (size_t ri = 0; ri < range_count; ri++)
            fprintf(stderr, "kbox: trap exec range[%zu]: %p-%p\n", ri,
                    (void *) ranges[ri].start, (void *) ranges[ri].end);
    }
    if (install_exec_filter_and_transfer(kbox_install_seccomp_trap_ranges,
                                         host_nrs, ranges, range_count,
                                         &launch->transfer) < 0) {
        fprintf(stderr,
                "kbox: trap launch failed: cannot install guest trap filter\n");
        kbox_syscall_trap_runtime_uninstall(&runtime);
        return -1;
    }
    __builtin_unreachable();
}

static int run_rewrite_launch(const struct kbox_image_args *args,
                              const struct kbox_sysnrs *sysnrs,
                              struct kbox_loader_launch *launch,
                              struct kbox_web_ctx *web_ctx)
{
    struct kbox_syscall_trap_ip_range ranges[KBOX_LOADER_MAX_MAPPINGS];
    const struct kbox_host_nrs *host_nrs = select_host_nrs();
    struct kbox_fd_table fd_table;
    struct kbox_supervisor_ctx ctx;
    struct kbox_syscall_trap_runtime trap_runtime;
    struct kbox_rewrite_runtime rewrite_runtime;
    size_t range_count;

    if (!host_nrs || !launch)
        return -1;
#if defined(__x86_64__)
#if KBOX_HAS_ASAN
    fprintf(stderr,
            "kbox: rewrite mode is unsupported in x86_64 ASAN builds; "
            "use --syscall-mode=seccomp or BUILD=release\n");
    errno = ENOTSUP;
    return -1;
#endif
    if (args->verbose) {
        fprintf(
            stderr,
            "kbox: rewrite launch on x86_64 currently falls back to trap\n");
    }
    return run_trap_launch(args, sysnrs, launch, web_ctx);
#endif
    if (collect_trap_exec_ranges(launch, ranges, KBOX_LOADER_MAX_MAPPINGS,
                                 &range_count) < 0) {
        fprintf(
            stderr,
            "kbox: rewrite launch failed: cannot collect guest exec ranges\n");
        return -1;
    }
    if (args->verbose)
        dump_loader_launch(launch);

    init_launch_ctx(&ctx, &fd_table, args, sysnrs, host_nrs, web_ctx);

    if (kbox_rewrite_runtime_install(&rewrite_runtime, &ctx, launch) < 0) {
        fprintf(
            stderr,
            "kbox: rewrite launch failed: cannot install rewrite runtime: %s\n",
            strerror(errno));
        return -1;
    }

    trap_runtime.sqpoll = args->sqpoll;
    if (kbox_syscall_trap_runtime_install(&trap_runtime, &ctx) < 0) {
        fprintf(stderr,
                "kbox: rewrite launch failed: cannot install SIGSYS handler\n");
        kbox_rewrite_runtime_reset(&rewrite_runtime);
        return -1;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "prctl(PR_SET_NO_NEW_PRIVS): %s\n", strerror(errno));
        kbox_syscall_trap_runtime_uninstall(&trap_runtime);
        kbox_rewrite_runtime_reset(&rewrite_runtime);
        return -1;
    }

    drop_launch_caps();
    if (set_launch_rlimits() < 0) {
        fprintf(stderr, "kbox: rewrite launch failed: RLIMIT_NOFILE too low\n");
        kbox_syscall_trap_runtime_uninstall(&trap_runtime);
        kbox_rewrite_runtime_reset(&rewrite_runtime);
        return -1;
    }

    if (install_exec_filter_and_transfer(kbox_install_seccomp_rewrite_ranges,
                                         host_nrs, ranges, range_count,
                                         &launch->transfer) < 0) {
        fprintf(
            stderr,
            "kbox: rewrite launch failed: cannot install guest trap filter\n");
        kbox_syscall_trap_runtime_uninstall(&trap_runtime);
        kbox_rewrite_runtime_reset(&rewrite_runtime);
        return -1;
    }
    __builtin_unreachable();
}

/* Public entry point. */

int kbox_run_image(const struct kbox_image_args *args)
{
    const char *root_path;
    int image_fd;
    struct lkl_disk disk;
    int disk_id;
    char mount_buf[256];
    char opts_buf[1024];
    const char *opts;
    const char *fs_type;
    const char *work_dir;
    const char *command;
    const struct kbox_sysnrs *sysnrs;
    enum kbox_syscall_mode probe_mode;
    long ret;
    struct kbox_bind_spec bind_specs[KBOX_MAX_BIND_MOUNTS];
    int bind_count = 0;
    int i;
    uid_t override_uid = (uid_t) -1;
    gid_t override_gid = (gid_t) -1;
    int rewrite_requested = 0;

    /* Resolve parameters with defaults. */
    root_path = select_root_path(args);
    if (!root_path)
        return -1;

    fs_type = args->fs_type ? args->fs_type : "ext4";
    work_dir = args->work_dir ? args->work_dir : "/";
    command = args->command ? args->command : "/bin/sh";
    probe_mode = args->syscall_mode;
    rewrite_requested = args->syscall_mode == KBOX_SYSCALL_MODE_REWRITE;

    /* AUTO enables rewrite analysis for non-shell commands so the
     * auto_prefers_userspace_fast_path() selection function can see the
     * exec_report and make an informed decision.  Shell commands always
     * fall back to seccomp (fork coherence), so skip the analysis.
     */
    if (args->syscall_mode == KBOX_SYSCALL_MODE_AUTO) {
#if KBOX_AUTO_ENABLE_USERSPACE_FAST_PATH
        if (!is_shell_command(command) && !args->net)
            rewrite_requested = 1;
#else
        /* On current x86_64 and aarch64 builds, AUTO is intentionally
         * pinned to seccomp. Skip rewrite/trap analysis entirely and probe
         * the supervisor path directly so startup does not do dead work or
         * print duplicate probe messages.
         */
        probe_mode = KBOX_SYSCALL_MODE_SECCOMP;
#endif
    }

    /* Parse bind mount specs. */
    for (i = 0; i < args->bind_mount_count; i++) {
        if (kbox_parse_bind_spec(args->bind_mounts[i], &bind_specs[i]) < 0)
            return -1;
        bind_count++;
    }

    /* Open image file. */
    image_fd = open(root_path, O_RDWR);
    if (image_fd < 0) {
        fprintf(stderr, "open(%s): %s\n", root_path, strerror(errno));
        return -1;
    }

    /* Register as LKL block device. */
    memset(&disk, 0, sizeof(disk));
    disk.dev = NULL;
    disk.fd = image_fd;
    disk.ops = &lkl_dev_blk_ops;

    disk_id = lkl_disk_add(&disk);
    if (disk_id < 0) {
        fprintf(stderr, "lkl_disk_add: %s (%d)\n",
                kbox_err_text((long) disk_id), disk_id);
        return -1;
    }

    /* Register netdev before boot (LKL probes during boot). */
    if (args->net) {
        if (kbox_net_add_device() < 0)
            return -1;
    }

    /* Boot the LKL kernel. */
    if (kbox_boot_kernel(args->cmdline) < 0) {
        if (args->net)
            kbox_net_cleanup();
        return -1;
    }

    /* Mount the filesystem. */
    opts = join_mount_opts(args, opts_buf, sizeof(opts_buf));
    if (!opts) {
        if (args->net)
            kbox_net_cleanup();
        return -1;
    }
    ret = lkl_mount_dev((unsigned) disk_id, args->part, fs_type, 0,
                        opts[0] ? opts : NULL, mount_buf, sizeof(mount_buf));
    if (ret < 0) {
        fprintf(stderr, "lkl_mount_dev: %s (%ld)\n", kbox_err_text(ret), ret);
        if (args->net)
            kbox_net_cleanup();
        return -1;
    }

    /* Detect syscall ABI. */
    sysnrs = detect_sysnrs();
    if (!sysnrs) {
        fprintf(stderr, "detect_sysnrs failed\n");
        if (args->net)
            kbox_net_cleanup();
        return -1;
    }

    /* Chroot into mountpoint. */
    ret = kbox_lkl_chroot(sysnrs, mount_buf);
    if (ret < 0) {
        fprintf(stderr, "chroot(%s): %s\n", mount_buf, kbox_err_text(ret));
        if (args->net)
            kbox_net_cleanup();
        return -1;
    }

    /* Recommended mounts. */
    if (args->recommended || args->system_root) {
        if (kbox_apply_recommended_mounts(sysnrs, args->mount_profile) < 0) {
            if (args->net)
                kbox_net_cleanup();
            return -1;
        }
    }

    /* Bind mounts. */
    if (bind_count > 0) {
        if (kbox_apply_bind_mounts(sysnrs, bind_specs, bind_count) < 0) {
            if (args->net)
                kbox_net_cleanup();
            return -1;
        }
    }

    /* Working directory. */
    ret = kbox_lkl_chdir(sysnrs, work_dir);
    if (ret < 0) {
        fprintf(stderr, "chdir(%s): %s\n", work_dir, kbox_err_text(ret));
        if (args->net)
            kbox_net_cleanup();
        return -1;
    }

    /* Identity. */
    if (args->change_id) {
        if (kbox_parse_change_id(args->change_id, &override_uid,
                                 &override_gid) < 0) {
            if (args->net)
                kbox_net_cleanup();
            return -1;
        }
    }

    {
        int root_id = args->root_id || args->system_root;
        if (kbox_apply_guest_identity(sysnrs, root_id, override_uid,
                                      override_gid) < 0) {
            if (args->net)
                kbox_net_cleanup();
            return -1;
        }
    }

    /* Probe host features.  Rewrite mode skips seccomp-specific probes. */
    if (kbox_probe_host_features(probe_mode) < 0) {
        if (args->net)
            kbox_net_cleanup();
        return -1;
    }

    /* Networking: configure interface (optional). */
    if (args->net) {
        if (kbox_net_configure(sysnrs) < 0) {
            kbox_net_cleanup();
            return -1;
        }
    }

    /* Web observatory (optional). */
    struct kbox_web_ctx *web_ctx = NULL;
#ifdef KBOX_HAS_WEB
    if (args->web || args->trace_format) {
        struct kbox_web_config wcfg;
        memset(&wcfg, 0, sizeof(wcfg));
        wcfg.enable_web = args->web;
        wcfg.port = args->web_port;
        wcfg.bind = args->web_bind;
        wcfg.guest_name = command;
        if (args->trace_format) {
            wcfg.enable_trace = 1;
            wcfg.trace_fd = STDERR_FILENO;
        }
        web_ctx = kbox_web_init(&wcfg, sysnrs);
        if (!web_ctx) {
            fprintf(stderr, "warning: failed to initialize web observatory\n");
            /* Non-fatal: continue without telemetry */
        }
    }
#endif

    /* Extract binary from LKL into memfd.
     *
     * The child process will exec via fexecve(memfd), because the binary lives
     * inside the LKL-mounted filesystem and does not exist on the host.
     *
     * For dynamically-linked binaries, ELF contains a PT_INTERP segment naming
     * the interpreter (e.g. /lib/ld-musl-x86_64.so.1). The host kernel resolves
     * PT_INTERP from the host VFS, not the LKL image, so the interpreter cannot
     * be found. Fix: extract the interpreter into a second memfd and patch
     * PT_INTERP in the main binary to /proc/self/fd/<interp_fd>. The kernel
     * opens /proc/self/fd/N during load_elf_binary (before close-on-exec), so
     * both memfds can keep MFD_CLOEXEC.
     */
    {
        long lkl_fd;
        int exec_memfd;
        int interp_memfd = -1;
        int rc = -1;
        struct kbox_loader_launch launch;

        memset(&launch, 0, sizeof(launch));

        lkl_fd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, command, O_RDONLY, 0);
        if (lkl_fd < 0) {
            fprintf(stderr, "cannot open %s in image: %s\n", command,
                    kbox_err_text(lkl_fd));
            goto err_net;
        }

        exec_memfd = kbox_shadow_create(sysnrs, lkl_fd);
        kbox_lkl_close(sysnrs, lkl_fd);

        if (exec_memfd < 0) {
            fprintf(stderr, "cannot create memfd for %s: %s\n", command,
                    strerror(-exec_memfd));
            goto err_net;
        }

        /* Check for PT_INTERP (dynamic binary). */
        {
            struct kbox_rewrite_report exec_report;
            struct kbox_rewrite_trampoline_probe exec_probe;
            const struct kbox_host_nrs *host_nrs = select_host_nrs();
            int scan_path_wrapper_candidates =
                rewrite_requested ||
                (args->syscall_mode == KBOX_SYSCALL_MODE_AUTO && args->verbose);
            int exec_report_ok = 0;
            int exec_has_stat_wrapper_fast_candidates = 0;
            int exec_has_open_wrapper_fast_candidates = 0;
            size_t exec_stat_wrapper_candidate_count = 0;
            size_t exec_open_wrapper_candidate_count = 0;
            size_t exec_stat_wrapper_direct_count = 0;
            size_t exec_open_wrapper_direct_count = 0;
            size_t exec_open_wrapper_cancel_count = 0;
            size_t exec_phase1_path_candidate_count = 0;
            unsigned char *elf_buf = NULL;
            size_t elf_buf_len = 0;
#if KBOX_AUTO_ENABLE_USERSPACE_FAST_PATH
            struct kbox_rewrite_report interp_report_outer;
            int interp_report_ok = 0;
#endif
            int interp_has_stat_wrapper_fast_candidates = 0;
            int interp_has_open_wrapper_fast_candidates = 0;
            size_t interp_stat_wrapper_candidate_count = 0;
            size_t interp_open_wrapper_candidate_count = 0;
            size_t interp_stat_wrapper_direct_count = 0;
            size_t interp_open_wrapper_direct_count = 0;
            size_t interp_open_wrapper_cancel_count = 0;
            size_t interp_phase1_path_candidate_count = 0;

            if (rewrite_requested &&
                kbox_rewrite_analyze_memfd(exec_memfd, &exec_report) == 0) {
                exec_report_ok = 1;

                if (args->verbose) {
                    fprintf(stderr,
                            "kbox: syscall rewrite analysis: %s: arch=%s "
                            "exec-segments=%zu candidates=%zu\n",
                            command, kbox_rewrite_arch_name(exec_report.arch),
                            exec_report.exec_segment_count,
                            exec_report.candidate_count);
                    if (kbox_rewrite_probe_trampoline(exec_report.arch,
                                                      &exec_probe) == 0) {
                        fprintf(stderr,
                                "kbox: rewrite trampoline probe: %s: "
                                "feasible=%s reason=%s\n",
                                kbox_rewrite_arch_name(exec_probe.arch),
                                exec_probe.feasible ? "yes" : "no",
                                exec_probe.reason ? exec_probe.reason : "?");
                    }
                }
            }
            if (scan_path_wrapper_candidates) {
                exec_has_stat_wrapper_fast_candidates =
                    memfd_has_stat_wrapper_fast_candidates(exec_memfd,
                                                           host_nrs);
                exec_has_open_wrapper_fast_candidates =
                    memfd_has_open_wrapper_fast_candidates(exec_memfd,
                                                           host_nrs);
                exec_stat_wrapper_candidate_count =
                    memfd_count_wrapper_family_candidates(
                        exec_memfd, host_nrs, KBOX_REWRITE_WRAPPER_FAMILY_STAT);
                exec_stat_wrapper_direct_count =
                    memfd_count_wrapper_family_candidates_by_kind(
                        exec_memfd, host_nrs, KBOX_REWRITE_WRAPPER_FAMILY_STAT,
                        KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT);
                exec_open_wrapper_candidate_count =
                    memfd_count_wrapper_family_candidates(
                        exec_memfd, host_nrs, KBOX_REWRITE_WRAPPER_FAMILY_OPEN);
                exec_open_wrapper_direct_count =
                    memfd_count_wrapper_family_candidates_by_kind(
                        exec_memfd, host_nrs, KBOX_REWRITE_WRAPPER_FAMILY_OPEN,
                        KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT);
                exec_open_wrapper_cancel_count =
                    memfd_count_wrapper_family_candidates_by_kind(
                        exec_memfd, host_nrs, KBOX_REWRITE_WRAPPER_FAMILY_OPEN,
                        KBOX_REWRITE_WRAPPER_CANDIDATE_SYSCALL_CANCEL);
                exec_phase1_path_candidate_count =
                    memfd_count_phase1_path_candidates(exec_memfd, host_nrs);
                maybe_log_wrapper_family_candidates(
                    command, exec_memfd, host_nrs,
                    KBOX_REWRITE_WRAPPER_FAMILY_STAT, "stat", args->verbose);
                maybe_log_wrapper_family_candidates(
                    command, exec_memfd, host_nrs,
                    KBOX_REWRITE_WRAPPER_FAMILY_OPEN, "open", args->verbose);
                maybe_log_phase1_path_candidates(command, exec_memfd, host_nrs,
                                                 args->verbose);
            }

            if (kbox_read_elf_header_window_fd(exec_memfd, &elf_buf,
                                               &elf_buf_len) == 0) {
                char interp_path[256];
                uint64_t pt_offset, pt_filesz;
                int ilen;
                ilen = kbox_find_elf_interp_loc(
                    elf_buf, elf_buf_len, interp_path, sizeof(interp_path),
                    &pt_offset, &pt_filesz);
                munmap(elf_buf, elf_buf_len);

                if (ilen < 0) {
                    fprintf(stderr,
                            "kbox: malformed ELF: cannot parse "
                            "program headers for %s\n",
                            command);
                    close(exec_memfd);
                    goto err_net;
                }

                if (ilen > 0) {
                    struct kbox_rewrite_report interp_report;
                    /* Dynamic binary: extract the interpreter from LKL. */
                    long interp_lkl_fd = kbox_lkl_openat(
                        sysnrs, AT_FDCWD_LINUX, interp_path, O_RDONLY, 0);
                    if (interp_lkl_fd < 0) {
                        fprintf(stderr,
                                "cannot open interpreter %s in image: %s\n",
                                interp_path, kbox_err_text(interp_lkl_fd));
                        close(exec_memfd);
                        goto err_net;
                    }

                    interp_memfd = kbox_shadow_create(sysnrs, interp_lkl_fd);
                    kbox_lkl_close(sysnrs, interp_lkl_fd);

                    if (interp_memfd < 0) {
                        fprintf(stderr,
                                "cannot create memfd for interpreter %s: %s\n",
                                interp_path, strerror(-interp_memfd));
                        close(exec_memfd);
                        goto err_net;
                    }

                    /* Patch PT_INTERP in the main binary memfd to point to
                     * /proc/self/fd/<interp_memfd>. The child inherits both
                     * memfds via fork; the kernel resolves the patched path
                     * during exec.
                     */
                    char new_interp[64];
                    int new_len = snprintf(new_interp, sizeof(new_interp),
                                           "/proc/self/fd/%d", interp_memfd);

                    if ((uint64_t) (new_len + 1) > pt_filesz) {
                        fprintf(stderr,
                                "PT_INTERP segment too small for "
                                "patched path (%d+1 > %lu)\n",
                                new_len, (unsigned long) pt_filesz);
                        close(interp_memfd);
                        close(exec_memfd);
                        goto err_net;
                    }

                    /* Write the new path, zero-filling the rest of the
                     * PT_INTERP segment. pwrite does not change the file
                     * offset.
                     */
                    char patch[256];
                    size_t patch_len = (size_t) pt_filesz;
                    if (patch_len > sizeof(patch))
                        patch_len = sizeof(patch);
                    memset(patch, 0, patch_len);
                    memcpy(patch, new_interp, (size_t) new_len);

                    if (pwrite(exec_memfd, patch, patch_len,
                               (off_t) pt_offset) != (ssize_t) patch_len) {
                        fprintf(stderr, "failed to patch PT_INTERP: %s\n",
                                strerror(errno));
                        close(interp_memfd);
                        close(exec_memfd);
                        goto err_net;
                    }

                    if (args->verbose) {
                        fprintf(stderr,
                                "kbox: dynamic binary %s: "
                                "interpreter %s -> /proc/self/fd/%d\n",
                                command, interp_path, interp_memfd);
                    }

                    if (rewrite_requested &&
                        kbox_rewrite_analyze_memfd(interp_memfd,
                                                   &interp_report) == 0) {
#if KBOX_AUTO_ENABLE_USERSPACE_FAST_PATH
                        interp_report_outer = interp_report;
                        interp_report_ok = 1;
#endif
                        interp_has_stat_wrapper_fast_candidates =
                            memfd_has_stat_wrapper_fast_candidates(interp_memfd,
                                                                   host_nrs);
                        interp_has_open_wrapper_fast_candidates =
                            memfd_has_open_wrapper_fast_candidates(interp_memfd,
                                                                   host_nrs);
                        if (args->verbose) {
                            fprintf(stderr,
                                    "kbox: syscall rewrite analysis: %s: "
                                    "arch=%s exec-segments=%zu "
                                    "candidates=%zu\n",
                                    interp_path,
                                    kbox_rewrite_arch_name(interp_report.arch),
                                    interp_report.exec_segment_count,
                                    interp_report.candidate_count);
                        }
                    }
                    if (scan_path_wrapper_candidates) {
                        interp_has_stat_wrapper_fast_candidates =
                            memfd_has_stat_wrapper_fast_candidates(interp_memfd,
                                                                   host_nrs);
                        interp_has_open_wrapper_fast_candidates =
                            memfd_has_open_wrapper_fast_candidates(interp_memfd,
                                                                   host_nrs);
                        interp_stat_wrapper_candidate_count =
                            memfd_count_wrapper_family_candidates(
                                interp_memfd, host_nrs,
                                KBOX_REWRITE_WRAPPER_FAMILY_STAT);
                        interp_stat_wrapper_direct_count =
                            memfd_count_wrapper_family_candidates_by_kind(
                                interp_memfd, host_nrs,
                                KBOX_REWRITE_WRAPPER_FAMILY_STAT,
                                KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT);
                        interp_open_wrapper_candidate_count =
                            memfd_count_wrapper_family_candidates(
                                interp_memfd, host_nrs,
                                KBOX_REWRITE_WRAPPER_FAMILY_OPEN);
                        interp_open_wrapper_direct_count =
                            memfd_count_wrapper_family_candidates_by_kind(
                                interp_memfd, host_nrs,
                                KBOX_REWRITE_WRAPPER_FAMILY_OPEN,
                                KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT);
                        interp_open_wrapper_cancel_count =
                            memfd_count_wrapper_family_candidates_by_kind(
                                interp_memfd, host_nrs,
                                KBOX_REWRITE_WRAPPER_FAMILY_OPEN,
                                KBOX_REWRITE_WRAPPER_CANDIDATE_SYSCALL_CANCEL);
                        interp_phase1_path_candidate_count =
                            memfd_count_phase1_path_candidates(interp_memfd,
                                                               host_nrs);
                        maybe_log_wrapper_family_candidates(
                            interp_path, interp_memfd, host_nrs,
                            KBOX_REWRITE_WRAPPER_FAMILY_STAT, "stat",
                            args->verbose);
                        maybe_log_wrapper_family_candidates(
                            interp_path, interp_memfd, host_nrs,
                            KBOX_REWRITE_WRAPPER_FAMILY_OPEN, "open",
                            args->verbose);
                        maybe_log_phase1_path_candidates(
                            interp_path, interp_memfd, host_nrs, args->verbose);
                    }
                }
            }

            if (args->verbose && (exec_has_stat_wrapper_fast_candidates ||
                                  exec_has_open_wrapper_fast_candidates ||
                                  interp_has_stat_wrapper_fast_candidates ||
                                  interp_has_open_wrapper_fast_candidates)) {
                fprintf(stderr,
                        "kbox: path-wrapper fast-path candidates: "
                        "exec(stat=%s/%zu direct=%zu "
                        "open=%s/%zu direct=%zu cancel=%zu) "
                        "interp(stat=%s/%zu direct=%zu "
                        "open=%s/%zu direct=%zu cancel=%zu)\n",
                        exec_has_stat_wrapper_fast_candidates ? "yes" : "no",
                        exec_stat_wrapper_candidate_count,
                        exec_stat_wrapper_direct_count,
                        exec_has_open_wrapper_fast_candidates ? "yes" : "no",
                        exec_open_wrapper_candidate_count,
                        exec_open_wrapper_direct_count,
                        exec_open_wrapper_cancel_count,
                        interp_has_stat_wrapper_fast_candidates ? "yes" : "no",
                        interp_stat_wrapper_candidate_count,
                        interp_stat_wrapper_direct_count,
                        interp_has_open_wrapper_fast_candidates ? "yes" : "no",
                        interp_open_wrapper_candidate_count,
                        interp_open_wrapper_direct_count,
                        interp_open_wrapper_cancel_count);
                fprintf(stderr,
                        "kbox: phase1 direct path-wrapper targets: "
                        "exec=%zu interp=%zu\n",
                        exec_phase1_path_candidate_count,
                        interp_phase1_path_candidate_count);
            }

            /* Trap fast path: 3x faster than seccomp (3.5us vs 10.8us
             * per syscall with FSGSBASE).
             *
             * Limitation: fork in trap mode duplicates the in-process
             * LKL state, so child processes see their own filesystem
             * copy.  Shell scripts that fork+exec (e.g., sh -c 'mkdir
             * /tmp/x && ls /tmp/x') lose cross-process filesystem
             * coherence.  AUTO uses trap only for direct commands
             * (no shell wrapper).  Shell invocations fall back to
             * seccomp where the supervisor is a separate process and
             * all children share one LKL instance.
             */
            {
                int use_trap = (args->syscall_mode == KBOX_SYSCALL_MODE_TRAP);
                if (args->syscall_mode == KBOX_SYSCALL_MODE_AUTO) {
                    if (!is_shell_command(command)) {
#if !KBOX_AUTO_ENABLE_USERSPACE_FAST_PATH
                        use_trap = 0;
#else
                        int fork_sites = 0;

                        /* Scan the main binary for fork/clone wrappers.
                         * Do NOT scan the interpreter: libc always
                         * contains fork wrappers regardless of whether
                         * the specific program uses them. Scanning it
                         * would reject every dynamic binary.
                         */
                        if (exec_report_ok) {
                            const struct kbox_host_nrs *hnrs =
                                select_host_nrs();
                            if (hnrs)
                                fork_sites = kbox_rewrite_has_fork_sites_memfd(
                                                 exec_memfd, hnrs) > 0;
                        }
                        use_trap = auto_prefers_userspace_fast_path(
                            exec_report_ok ? &exec_report : NULL,
                            interp_report_ok ? &interp_report_outer : NULL,
                            fork_sites);
                        /* Cancel-style open wrappers are now handled
                         * correctly: all LKL-touching dispatches go through
                         * the service thread, so no aarch64 override needed.
                         */
#endif
                        if (args->verbose && !use_trap) {
                            fprintf(stderr,
                                    "kbox: --syscall-mode=auto: preferring "
                                    "seccomp for this executable\n");
                        }
                    }
                }
                if (!use_trap)
                    goto skip_trap;
            }
            {
                int prep_ok;

                maybe_apply_virtual_procinfo_fast_path(exec_memfd, command,
                                                       args->verbose);
                maybe_apply_virtual_procinfo_fast_path(
                    interp_memfd, "PT_INTERP", args->verbose);

                prep_ok = prepare_userspace_launch(args, command, exec_memfd,
                                                   interp_memfd, override_uid,
                                                   override_gid, &launch) == 0;
                if (!prep_ok) {
                    if (args->syscall_mode == KBOX_SYSCALL_MODE_TRAP) {
                        fprintf(stderr,
                                "kbox: --syscall-mode=trap launch preparation "
                                "failed.\n");
                        kbox_loader_launch_reset(&launch);
                        if (interp_memfd >= 0)
                            close(interp_memfd);
                        close(exec_memfd);
                        goto err_net;
                    }

                    if (args->verbose) {
                        fprintf(
                            stderr,
                            "kbox: --syscall-mode=auto: trap launch "
                            "preparation failed, falling back to seccomp\n");
                    }
                } else {
                    if (args->syscall_mode == KBOX_SYSCALL_MODE_AUTO) {
                        if (exec_report_ok &&
                            kbox_rewrite_probe_trampoline(exec_report.arch,
                                                          &exec_probe) == 0 &&
                            exec_probe.feasible) {
                            if (args->verbose) {
                                fprintf(stderr,
                                        "kbox: --syscall-mode=auto: trying "
                                        "rewrite fast path\n");
                            }
                            /* run_rewrite_launch is noreturn on success.
                             * If it returns, the install failed before any
                             * irreversible process state changes (the first
                             * fallible step is kbox_rewrite_runtime_install,
                             * which cleans up on failure). Fall through to
                             * seccomp -- skipping trap because the loader
                             * layout was prepared for rewrite mode and may
                             * not be reusable as-is for a plain trap launch.
                             */
                            (void) run_rewrite_launch(args, sysnrs, &launch,
                                                      web_ctx);
                            if (args->verbose) {
                                fprintf(stderr,
                                        "kbox: --syscall-mode=auto: rewrite "
                                        "failed, falling back to seccomp\n");
                            }
                            kbox_loader_launch_reset(&launch);
                            goto skip_trap;
                        }
                        if (args->verbose) {
                            fprintf(stderr,
                                    "kbox: --syscall-mode=auto: selecting trap "
                                    "fast path\n");
                        }
                    }

                    /* run_trap_launch is noreturn on success.  Only returns
                     * on failure.  For explicit --syscall-mode=trap, this is
                     * a hard error.  For AUTO, we already handled rewrite
                     * fallback above; trap failure here also falls through
                     * to seccomp.
                     */
                    (void) run_trap_launch(args, sysnrs, &launch, web_ctx);

                    if (args->syscall_mode != KBOX_SYSCALL_MODE_AUTO) {
                        if (interp_memfd >= 0)
                            close(interp_memfd);
                        close(exec_memfd);
                        kbox_loader_launch_reset(&launch);
                        goto err_net;
                    }
                    if (args->verbose) {
                        fprintf(stderr,
                                "kbox: --syscall-mode=auto: trap failed, "
                                "falling back to seccomp\n");
                    }
                    kbox_loader_launch_reset(&launch);
                }
            }

        skip_trap:
            /* AUTO reaching here means the trap fast path was skipped
             * (shell command) and seccomp will be used.  Verify the
             * supervisor features are available before proceeding.
             */
            if (args->syscall_mode == KBOX_SYSCALL_MODE_AUTO &&
                probe_mode != KBOX_SYSCALL_MODE_SECCOMP &&
                kbox_probe_host_features(KBOX_SYSCALL_MODE_SECCOMP) < 0) {
                close(exec_memfd);
                if (interp_memfd >= 0)
                    close(interp_memfd);
                goto err_net;
            }
            if (args->syscall_mode == KBOX_SYSCALL_MODE_TRAP) {
                /* Unreachable: trap is handled above. */
                close(exec_memfd);
                if (interp_memfd >= 0)
                    close(interp_memfd);
                goto err_net;
            }

            if (args->syscall_mode == KBOX_SYSCALL_MODE_REWRITE) {
                maybe_apply_virtual_procinfo_fast_path(exec_memfd, command,
                                                       args->verbose);
                maybe_apply_virtual_procinfo_fast_path(
                    interp_memfd, "PT_INTERP", args->verbose);
                int prep_ok = prepare_userspace_launch(
                                  args, command, exec_memfd, interp_memfd,
                                  override_uid, override_gid, &launch) == 0;

                if (!prep_ok) {
                    fprintf(stderr,
                            "kbox: --syscall-mode=rewrite launch preparation "
                            "failed.\n");
                } else {
                    if (!exec_report_ok) {
                        fprintf(stderr,
                                "kbox: --syscall-mode=rewrite executable "
                                "analysis failed.\n");
                    } else if (kbox_rewrite_probe_trampoline(
                                   exec_report.arch, &exec_probe) == 0 &&
                               !exec_probe.feasible) {
                        fprintf(stderr,
                                "kbox: --syscall-mode=rewrite trampoline probe "
                                "failed for %s: %s\n",
                                kbox_rewrite_arch_name(exec_probe.arch),
                                exec_probe.reason ? exec_probe.reason : "?");
                    } else {
                        if (interp_memfd >= 0)
                            close(interp_memfd);
                        close(exec_memfd);
                        rc = run_rewrite_launch(args, sysnrs, &launch, web_ctx);
                        kbox_loader_launch_reset(&launch);
                        goto err_net;
                    }
                }
                kbox_loader_launch_reset(&launch);
                if (interp_memfd >= 0)
                    close(interp_memfd);
                close(exec_memfd);
                goto err_net;
            }

            if (args->syscall_mode == KBOX_SYSCALL_MODE_AUTO && args->verbose) {
                fprintf(stderr,
                        "kbox: --syscall-mode=auto: falling back to seccomp\n");
            }
        }

        maybe_apply_virtual_procinfo_fast_path(exec_memfd, command,
                                               args->verbose);
        maybe_apply_virtual_procinfo_fast_path(interp_memfd, "PT_INTERP",
                                               args->verbose);

        /* Fork, seccomp, exec, supervise. */
        rc = kbox_run_supervisor(
            sysnrs, command, args->extra_args, args->extra_argc, NULL,
            exec_memfd, args->verbose, args->root_id || args->system_root,
            args->normalize, web_ctx);
        if (interp_memfd >= 0)
            close(interp_memfd);
        close(exec_memfd);

    err_net:
#ifdef KBOX_HAS_WEB
        if (web_ctx)
            kbox_web_shutdown(web_ctx);
#endif
        if (args->net)
            kbox_net_cleanup();
        return rc;
    }
}
