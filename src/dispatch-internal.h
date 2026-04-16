/* SPDX-License-Identifier: MIT */

#ifndef KBOX_DISPATCH_INTERNAL_H
#define KBOX_DISPATCH_INTERNAL_H

/* Internal header for the seccomp dispatch subsystem. Exposes shared helpers
 * from seccomp-dispatch.c so that handler functions extracted into separate
 * translation units (dispatch-net.c, dispatch-id.c, dispatch-exec.c,
 * dispatch-misc.c) can call them.
 */

#include <stdio.h>

#include "fd-table.h"
#include "lkl-wrap.h"
#include "seccomp.h"

/* Sentinel values for the host_fd field in kbox_fd_entry.
 *
 * KBOX_FD_HOST_SAME_FD_SHADOW: host_fd is a same-fd shadow (memfd injected
 *     at the tracee's FD number via SECCOMP_IOCTL_NOTIF_ADDFD).
 * KBOX_FD_LOCAL_ONLY_SHADOW: host_fd is a local-only shadow (supervisor
 *     holds the memfd; trap/rewrite mode, no tracee injection).
 *
 * KBOX_LKL_FD_SHADOW_ONLY (lkl_fd sentinel) is defined in fd-table.h.
 */
#define KBOX_FD_HOST_SAME_FD_SHADOW (-2)
#define KBOX_FD_LOCAL_ONLY_SHADOW (-3)

/* Shared scratch buffer for I/O dispatch. The dispatcher is single-threaded and
 * non-reentrant: only one syscall is dispatched at a time.
 */
extern uint8_t dispatch_scratch[KBOX_IO_CHUNK_LEN];

/* Argument extraction helpers. */

static inline int64_t to_c_long_arg(uint64_t v)
{
    return (int64_t) v;
}

/* Sign-extend a 32-bit dirfd argument. seccomp_data.args[] zero-extends 32-bit
 * values, so AT_FDCWD (-100) arrives as 0xFFFFFF9C. This helper restores the
 * sign.
 */
static inline long to_dirfd_arg(uint64_t v)
{
    return (long) (int) (uint32_t) v;
}

/* Return nonzero if req was delivered via SIGSYS trap or syscall rewrite rather
 * than the seccomp user-notification path.
 */
static inline int request_uses_trap_signals(
    const struct kbox_syscall_request *req)
{
    return req && (req->source == KBOX_SYSCALL_SOURCE_TRAP ||
                   req->source == KBOX_SYSCALL_SOURCE_REWRITE);
}

/* Return 1 if an FD-based I/O syscall should fail with EBADF rather than
 * CONTINUE for a not-in-table FD.  Only tracked FDs (lkl_fd >= 0 for LKL
 * files, KBOX_LKL_FD_SHADOW_ONLY for host-passthrough pipes/eventfds/proc
 * opens) are allowed.  All untracked FDs (lkl_fd == -1) are denied to block
 * I/O on host FDs leaked via the openat TOCTOU race.
 */
static inline int fd_should_deny_io(long fd, long lkl_fd)
{
    (void) fd;
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY || lkl_fd >= 0)
        return 0;
    return 1;
}

static inline void track_host_passthrough_fd(struct kbox_fd_table *t, int fd)
{
    if (kbox_fd_table_insert_at(t, fd, KBOX_LKL_FD_SHADOW_ONLY, 0) < 0)
        fprintf(stderr, "kbox: warning: host-passthrough FD %d untrackable\n",
                fd);
}

/* Look up the FD table entry for a virtual or low-range FD. Returns NULL if fd
 * is out of range or t is NULL.
 */
static inline struct kbox_fd_entry *fd_table_entry(struct kbox_fd_table *t,
                                                   long fd)
{
    if (!t)
        return NULL;
    if (fd >= KBOX_FD_BASE && fd < KBOX_FD_BASE + KBOX_FD_TABLE_MAX)
        return &t->entries[fd - KBOX_FD_BASE];
    if (fd >= KBOX_LOW_FD_MAX && fd < KBOX_FD_BASE)
        return &t->mid_fds[fd - KBOX_LOW_FD_MAX];
    if (fd >= 0 && fd < KBOX_LOW_FD_MAX)
        return &t->low_fds[fd];
    return NULL;
}

/* Evict an LKL FD from the stat cache so stale fstat results are never
 * returned after the FD is closed and its number reused.
 */
static inline void invalidate_stat_cache_fd(struct kbox_supervisor_ctx *ctx,
                                            long lkl_fd)
{
#if KBOX_STAT_CACHE_ENABLED
    for (int i = 0; i < KBOX_STAT_CACHE_MAX; i++)
        if (ctx->stat_cache[i].lkl_fd == lkl_fd)
            ctx->stat_cache[i].lkl_fd = -1;
#else
    (void) ctx;
    (void) lkl_fd;
#endif
}

/* Close an LKL FD and evict it from the stat cache. Every LKL close in the
 * dispatch code should go through this wrapper to prevent stale fstat results
 * when the LKL FD number is reused.
 */
static inline long lkl_close_and_invalidate(struct kbox_supervisor_ctx *ctx,
                                            long lkl_fd)
{
    invalidate_stat_cache_fd(ctx, lkl_fd);
    return kbox_lkl_close(ctx->sysnrs, lkl_fd);
}

/* Open-flag ABI translation (aarch64 host <-> asm-generic LKL).
 *
 * aarch64 and asm-generic define four O_* flags differently:
 *
 *   Flag         aarch64     asm-generic (LKL)
 *   O_DIRECTORY  0x04000     0x10000
 *   O_NOFOLLOW   0x08000     0x20000
 *   O_DIRECT     0x10000     0x04000
 *   O_LARGEFILE  0x20000     0x08000
 *
 * x86_64 values already match asm-generic so no translation is needed.
 */
#if defined(__aarch64__)

#define HOST_O_DIRECTORY 0x04000
#define HOST_O_NOFOLLOW 0x08000
#define HOST_O_DIRECT 0x10000
#define HOST_O_LARGEFILE 0x20000

#define LKL_O_DIRECTORY 0x10000
#define LKL_O_NOFOLLOW 0x20000
#define LKL_O_DIRECT 0x04000
#define LKL_O_LARGEFILE 0x08000

static inline long host_to_lkl_open_flags(long flags)
{
    long out = flags & ~(HOST_O_DIRECTORY | HOST_O_NOFOLLOW | HOST_O_DIRECT |
                         HOST_O_LARGEFILE);
    if (flags & HOST_O_DIRECTORY)
        out |= LKL_O_DIRECTORY;
    if (flags & HOST_O_NOFOLLOW)
        out |= LKL_O_NOFOLLOW;
    if (flags & HOST_O_DIRECT)
        out |= LKL_O_DIRECT;
    if (flags & HOST_O_LARGEFILE)
        out |= LKL_O_LARGEFILE;
    return out;
}

static inline long lkl_to_host_open_flags(long flags)
{
    long out = flags & ~(LKL_O_DIRECTORY | LKL_O_NOFOLLOW | LKL_O_DIRECT |
                         LKL_O_LARGEFILE);
    if (flags & LKL_O_DIRECTORY)
        out |= HOST_O_DIRECTORY;
    if (flags & LKL_O_NOFOLLOW)
        out |= HOST_O_NOFOLLOW;
    if (flags & LKL_O_DIRECT)
        out |= HOST_O_DIRECT;
    if (flags & LKL_O_LARGEFILE)
        out |= HOST_O_LARGEFILE;
    return out;
}

#else /* x86_64: flags already match asm-generic */

static inline long host_to_lkl_open_flags(long flags)
{
    return flags;
}

static inline long lkl_to_host_open_flags(long flags)
{
    return flags;
}

#endif

/* Guest memory access. */

int guest_mem_read(const struct kbox_supervisor_ctx *ctx,
                   pid_t pid,
                   uint64_t remote_addr,
                   void *out,
                   size_t len);
int guest_mem_write(const struct kbox_supervisor_ctx *ctx,
                    pid_t pid,
                    uint64_t remote_addr,
                    const void *in,
                    size_t len);
int guest_mem_write_force(const struct kbox_supervisor_ctx *ctx,
                          pid_t pid,
                          uint64_t remote_addr,
                          const void *in,
                          size_t len);
int guest_mem_read_string(const struct kbox_supervisor_ctx *ctx,
                          pid_t pid,
                          uint64_t remote_addr,
                          char *buf,
                          size_t max_len);
int guest_mem_read_open_how(const struct kbox_supervisor_ctx *ctx,
                            pid_t pid,
                            uint64_t remote_addr,
                            uint64_t size,
                            struct kbox_open_how *out);
int guest_mem_write_small_metadata(const struct kbox_supervisor_ctx *ctx,
                                   pid_t pid,
                                   uint64_t remote_addr,
                                   const void *in,
                                   size_t len);
int read_guest_string(const struct kbox_supervisor_ctx *ctx,
                      pid_t pid,
                      uint64_t addr,
                      char *buf,
                      size_t size);

/* FD injection into the tracee. */

int request_addfd(const struct kbox_supervisor_ctx *ctx,
                  const struct kbox_syscall_request *req,
                  int srcfd,
                  uint32_t newfd_flags);
int request_addfd_at(const struct kbox_supervisor_ctx *ctx,
                     const struct kbox_syscall_request *req,
                     int srcfd,
                     int target_fd,
                     uint32_t newfd_flags);

/* Path resolution and translation. */

long resolve_open_dirfd(const char *path,
                        long dirfd,
                        const struct kbox_fd_table *table);
int translate_guest_path(const struct kbox_supervisor_ctx *ctx,
                         pid_t pid,
                         uint64_t addr,
                         const char *host_root,
                         char *translated,
                         size_t size);
int translate_request_path(const struct kbox_syscall_request *req,
                           const struct kbox_supervisor_ctx *ctx,
                           size_t path_idx,
                           const char *host_root,
                           char *translated,
                           size_t size);
int translate_request_at_path(const struct kbox_syscall_request *req,
                              struct kbox_supervisor_ctx *ctx,
                              size_t dirfd_idx,
                              size_t path_idx,
                              char *translated,
                              size_t size,
                              long *lkl_dirfd);
int should_continue_for_dirfd(long lkl_dirfd);
int guest_addr_is_writable(pid_t pid, uint64_t addr);
int guest_range_has_shared_file_write_mapping(pid_t pid,
                                              uint64_t addr,
                                              uint64_t len);
int dup_tracee_fd(pid_t pid, int tracee_fd);
void translate_proc_self(const char *path,
                         pid_t pid,
                         char *sv_path,
                         size_t sv_path_len);

/* FD utilities. */

int child_fd_is_open(const struct kbox_supervisor_ctx *ctx, long fd);
long allocate_passthrough_hostonly_fd(struct kbox_supervisor_ctx *ctx);
long next_hostonly_fd_hint(const struct kbox_supervisor_ctx *ctx);
int ensure_proc_self_fd_dir(struct kbox_supervisor_ctx *ctx);
int ensure_proc_mem_fd(struct kbox_supervisor_ctx *ctx);

/* Stat ABI conversion. */

void kbox_lkl_stat_to_host(const struct kbox_lkl_stat *src, struct stat *dst);
void normalize_host_stat_if_needed(struct kbox_supervisor_ctx *ctx,
                                   const char *path,
                                   struct stat *host_stat);
void normalize_statx_if_needed(struct kbox_supervisor_ctx *ctx,
                               const char *path,
                               uint8_t *statx_buf);

/* Shadow FD management. */

int ensure_same_fd_shadow(struct kbox_supervisor_ctx *ctx,
                          const struct kbox_syscall_request *req,
                          long fd,
                          long lkl_fd);
int try_cached_shadow_open_dispatch(struct kbox_supervisor_ctx *ctx,
                                    const struct kbox_syscall_request *req,
                                    long flags,
                                    const char *translated,
                                    struct kbox_dispatch *out);
int try_cached_shadow_stat_dispatch(struct kbox_supervisor_ctx *ctx,
                                    const char *translated,
                                    uint64_t remote_stat,
                                    pid_t pid);
int ensure_path_shadow_cache(struct kbox_supervisor_ctx *ctx,
                             const char *translated);
void invalidate_path_shadow_cache(struct kbox_supervisor_ctx *ctx);
void invalidate_translated_path_cache(struct kbox_supervisor_ctx *ctx);
void note_shadow_writeback_open(struct kbox_supervisor_ctx *ctx,
                                struct kbox_fd_entry *entry);
void note_shadow_writeback_close(struct kbox_supervisor_ctx *ctx,
                                 struct kbox_fd_entry *entry);
int try_writeback_shadow_open(struct kbox_supervisor_ctx *ctx,
                              const struct kbox_syscall_request *req,
                              long lkl_fd,
                              long flags,
                              const char *translated,
                              struct kbox_dispatch *out);
int sync_shadow_writeback(struct kbox_supervisor_ctx *ctx,
                          struct kbox_fd_entry *entry);

/* Handler functions: dispatch-net.c (networking syscalls). */

struct kbox_dispatch forward_socket(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_bind(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_connect(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_sendto(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_recvfrom(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_recvmsg(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_getsockopt(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_setsockopt(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_getsockname(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_getpeername(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_shutdown(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx);

/* Handler functions: dispatch-id.c (identity syscalls). */

struct kbox_dispatch dispatch_get_uid(
    long (*lkl_func)(const struct kbox_sysnrs *),
    struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch dispatch_get_gid(
    long (*lkl_func)(const struct kbox_sysnrs *),
    struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch dispatch_set_id(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_dispatch (*lkl_forward)(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx));
struct kbox_dispatch forward_getresuid(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_getresuid_override(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    uid_t override_val);
struct kbox_dispatch forward_getresgid(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_getresgid_override(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    gid_t override_val);
struct kbox_dispatch forward_getgroups(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_getgroups_override(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    gid_t override_val);
struct kbox_dispatch forward_setuid(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_setreuid(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_setresuid(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_setgid(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_setregid(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_setresgid(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_setgroups(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_setfsgid(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_umask(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx);

/* Handler functions: dispatch-exec.c (exec, mprotect, clone3). */

struct kbox_dispatch forward_execve(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx,
                                    int is_execveat);
struct kbox_dispatch forward_mprotect(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_clone3(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx);

/* Handler functions: dispatch-misc.c (time, info, device, memory). */

struct kbox_dispatch forward_clock_gettime(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_clock_getres(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_gettimeofday(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_uname(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_getrandom(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_syslog(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_prctl(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_pipe2(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_ioctl(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_pwrite64(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_writev(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_readv(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_ftruncate(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_fallocate(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_flock(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_fsync(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_fdatasync(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_sync(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_symlinkat(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_linkat(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_utimensat(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_readlinkat(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_mmap(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_eventfd(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_timerfd_create(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch forward_epoll_create1(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx);

/* Clone namespace flags (portable fallbacks for older headers). */

#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000ULL
#endif
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080ULL
#endif
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000ULL
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000ULL
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000ULL
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000ULL
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000ULL
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000ULL
#endif
#ifndef CLONE_THREAD
#define CLONE_THREAD 0x00010000ULL
#endif

#define CLONE_NEW_MASK                                              \
    (CLONE_NEWNS | CLONE_NEWTIME | CLONE_NEWCGROUP | CLONE_NEWUTS | \
     CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET)

#endif /* KBOX_DISPATCH_INTERNAL_H */
