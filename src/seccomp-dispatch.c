/* SPDX-License-Identifier: MIT */

/* Syscall dispatch engine for the seccomp supervisor.
 *
 * Each intercepted syscall notification is dispatched to a handler that either
 * forwards it through LKL (RETURN) or lets host kernel handle it (CONTINUE).
 * This is the beating heart of kbox: every file open, read, write, stat, and
 * directory operation the tracee makes gets routed through here.
 *
 */

#include <errno.h>
#include <fcntl.h>
/* seccomp types via seccomp.h -> seccomp-defs.h */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

/* pidfd_getfd is used to obtain a supervisor copy of a tracee FD that shares
 * the same file description (needed for emulating dup on host-passthrough FDs).
 * Available since Linux 5.6; kbox requires 5.13+ for seccomp USER_NOTIF.
 */
#ifndef __NR_pidfd_open
#if defined(__x86_64__)
#define __NR_pidfd_open 434
#elif defined(__aarch64__)
#define __NR_pidfd_open 434
#endif
#endif
#ifndef __NR_pidfd_getfd
#if defined(__x86_64__)
#define __NR_pidfd_getfd 438
#elif defined(__aarch64__)
#define __NR_pidfd_getfd 438
#endif
#endif
#ifndef __NR_faccessat2
#if defined(__x86_64__)
#define __NR_faccessat2 439
#elif defined(__aarch64__)
#define __NR_faccessat2 439
#endif
#endif
#ifndef __NR_statx
#if defined(__x86_64__)
#define __NR_statx 332
#elif defined(__aarch64__)
#define __NR_statx 291
#endif
#endif

#include "dispatch-internal.h"
#include "fd-table.h"
#include "kbox/elf.h"
#include "kbox/identity.h"
#include "kbox/path.h"
#include "lkl-wrap.h"
#include "loader-launch.h"
#include "net.h"
#include "procmem.h"
#include "rewrite.h"
#include "seccomp.h"
#include "shadow-fd.h"
#include "syscall-nr.h"
#include "syscall-trap-signal.h"
#include "syscall-trap.h"

/* Static scratch buffer for I/O dispatch. Dispatcher is single-threaded and
 * non-reentrant: only one syscall is dispatched at a time. Using static buffer
 * instead of malloc avoids heap allocation from the SIGSYS handler in trap /
 * rewrite mode, where the guest may hold glibc heap locks.
 */
uint8_t dispatch_scratch[KBOX_IO_CHUNK_LEN];

static int request_blocks_reserved_sigsys(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    uint64_t set_ptr;
    size_t sigset_size;
    unsigned char mask[16];
    size_t read_len;
    int rc;

    if (!req)
        return 0;
    set_ptr = kbox_syscall_request_arg(req, 1);
    sigset_size = (size_t) kbox_syscall_request_arg(req, 3);
    if (set_ptr == 0 || sigset_size == 0)
        return 0;

    read_len = sigset_size;
    if (read_len > sizeof(mask))
        read_len = sizeof(mask);
    memset(mask, 0, sizeof(mask));

    rc = guest_mem_read(ctx, kbox_syscall_request_pid(req), set_ptr, mask,
                        read_len);
    if (rc < 0)
        return rc;

    return kbox_syscall_trap_sigset_blocks_reserved(mask, read_len) ? 1 : 0;
}

static struct kbox_dispatch emulate_trap_rt_sigprocmask(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long how = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t set_ptr = kbox_syscall_request_arg(req, 1);
    uint64_t old_ptr = kbox_syscall_request_arg(req, 2);
    size_t sigset_size = (size_t) kbox_syscall_request_arg(req, 3);
    unsigned char current[sizeof(sigset_t)];
    unsigned char next[sizeof(sigset_t)];
    unsigned char pending[sizeof(sigset_t)];
    unsigned char set_mask[sizeof(sigset_t)];
    size_t mask_len;

    if (sigset_size == 0 || sigset_size > sizeof(current))
        return kbox_dispatch_errno(EINVAL);
    mask_len = sigset_size;

    /* In TRAP mode the signal mask lives in the ucontext delivered by kernel;
     * modifying it there takes effect when the handler returns.
     * In REWRITE mode there is no ucontext; the rewrite dispatch runs as normal
     * function call, so fall back to sigprocmask(2) directly.
     */
    if (kbox_syscall_trap_get_sigmask(current, sizeof(current)) < 0) {
        sigset_t tmp;
        if (sigprocmask(SIG_SETMASK, NULL, &tmp) < 0)
            return kbox_dispatch_errno(EIO);
        memcpy(current, &tmp, sizeof(current));
    }

    memset(set_mask, 0, sizeof(set_mask));
    memcpy(next, current, sizeof(next));

    if (set_ptr != 0) {
        int rc = guest_mem_read(ctx, kbox_syscall_request_pid(req), set_ptr,
                                set_mask, mask_len);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
    }

    if (old_ptr != 0) {
        int rc = guest_mem_write(ctx, kbox_syscall_request_pid(req), old_ptr,
                                 current, mask_len);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
    }

    if (set_ptr != 0) {
        switch (how) {
        case SIG_BLOCK:
            for (size_t i = 0; i < mask_len; i++)
                next[i] |= set_mask[i];
            break;
        case SIG_UNBLOCK:
            for (size_t i = 0; i < mask_len; i++)
                next[i] &= (unsigned char) ~set_mask[i];
            break;
        case SIG_SETMASK:
            memcpy(next, set_mask, mask_len);
            break;
        default:
            return kbox_dispatch_errno(EINVAL);
        }
    }

    if (kbox_syscall_trap_set_sigmask(next, sizeof(next)) < 0) {
        sigset_t apply;
        memcpy(&apply, next, sizeof(next));
        if (sigprocmask(SIG_SETMASK, &apply, NULL) < 0)
            return kbox_dispatch_errno(EIO);
    }

    if (kbox_syscall_trap_get_pending(pending, sizeof(pending)) == 0) {
        for (size_t i = 0; i < sizeof(pending); i++)
            pending[i] &= next[i];
        (void) kbox_syscall_trap_set_pending(pending, sizeof(pending));
    }

    return kbox_dispatch_value(0);
}

static int trap_sigmask_contains_signal(int signo)
{
    sigset_t current;

    if (signo <= 0)
        return 0;
    if (kbox_syscall_trap_get_sigmask(&current, sizeof(current)) < 0)
        return 0;
    return sigismember(&current, signo) == 1;
}

static struct kbox_dispatch emulate_trap_rt_sigpending(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    uint64_t set_ptr = kbox_syscall_request_arg(req, 0);
    size_t sigset_size = (size_t) kbox_syscall_request_arg(req, 1);
    unsigned char pending[sizeof(sigset_t)];
    int rc;

    (void) ctx;

    if (set_ptr == 0)
        return kbox_dispatch_errno(EFAULT);
    if (sigset_size == 0 || sigset_size > sizeof(pending))
        return kbox_dispatch_errno(EINVAL);
    if (kbox_syscall_trap_get_pending(pending, sizeof(pending)) < 0)
        return kbox_dispatch_errno(EIO);

    rc = guest_mem_write(ctx, kbox_syscall_request_pid(req), set_ptr, pending,
                         sigset_size);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    return kbox_dispatch_value(0);
}

struct kbox_fd_inject_ops {
    int (*addfd)(const struct kbox_supervisor_ctx *ctx,
                 uint64_t cookie,
                 int srcfd,
                 uint32_t newfd_flags);
    int (*addfd_at)(const struct kbox_supervisor_ctx *ctx,
                    uint64_t cookie,
                    int srcfd,
                    int target_fd,
                    uint32_t newfd_flags);
};

static int seccomp_request_addfd(const struct kbox_supervisor_ctx *ctx,
                                 uint64_t cookie,
                                 int srcfd,
                                 uint32_t newfd_flags)
{
    return kbox_notify_addfd(ctx->listener_fd, cookie, srcfd, newfd_flags);
}

static int seccomp_request_addfd_at(const struct kbox_supervisor_ctx *ctx,
                                    uint64_t cookie,
                                    int srcfd,
                                    int target_fd,
                                    uint32_t newfd_flags)
{
    return kbox_notify_addfd_at(ctx->listener_fd, cookie, srcfd, target_fd,
                                newfd_flags);
}

static const struct kbox_fd_inject_ops seccomp_fd_inject_ops = {
    .addfd = seccomp_request_addfd,
    .addfd_at = seccomp_request_addfd_at,
};

static int local_request_addfd(const struct kbox_supervisor_ctx *ctx,
                               uint64_t cookie,
                               int srcfd,
                               uint32_t newfd_flags)
{
    int ret;

    (void) ctx;
    (void) cookie;
#ifdef F_DUPFD_CLOEXEC
    if (newfd_flags & O_CLOEXEC) {
        ret = (int) kbox_syscall_trap_host_syscall6(SYS_fcntl, (uint64_t) srcfd,
                                                    (uint64_t) F_DUPFD_CLOEXEC,
                                                    0, 0, 0, 0);
        return ret >= 0 ? ret : -(int) -ret;
    }
#endif
    ret = (int) kbox_syscall_trap_host_syscall6(SYS_fcntl, (uint64_t) srcfd,
                                                (uint64_t) F_DUPFD, 0, 0, 0, 0);
    return ret >= 0 ? ret : -(int) -ret;
}

static int local_request_addfd_at(const struct kbox_supervisor_ctx *ctx,
                                  uint64_t cookie,
                                  int srcfd,
                                  int target_fd,
                                  uint32_t newfd_flags)
{
    (void) ctx;
    (void) cookie;
#ifdef __linux__
    {
        int ret = (int) kbox_syscall_trap_host_syscall6(
            SYS_dup3, (uint64_t) srcfd, (uint64_t) target_fd,
            (uint64_t) ((newfd_flags & O_CLOEXEC) ? O_CLOEXEC : 0), 0, 0, 0);
        return ret >= 0 ? ret : -(int) -ret;
    }
#else
    (void) srcfd;
    (void) target_fd;
    (void) newfd_flags;
    return -ENOSYS;
#endif
}

static const struct kbox_fd_inject_ops local_fd_inject_ops = {
    .addfd = local_request_addfd,
    .addfd_at = local_request_addfd_at,
};

int request_addfd(const struct kbox_supervisor_ctx *ctx,
                  const struct kbox_syscall_request *req,
                  int srcfd,
                  uint32_t newfd_flags)
{
    if (!ctx || !ctx->fd_inject_ops || !ctx->fd_inject_ops->addfd || !req)
        return -EINVAL;
    return ctx->fd_inject_ops->addfd(ctx, kbox_syscall_request_cookie(req),
                                     srcfd, newfd_flags);
}

int request_addfd_at(const struct kbox_supervisor_ctx *ctx,
                     const struct kbox_syscall_request *req,
                     int srcfd,
                     int target_fd,
                     uint32_t newfd_flags)
{
    if (!ctx || !ctx->fd_inject_ops || !ctx->fd_inject_ops->addfd_at || !req)
        return -EINVAL;
    return ctx->fd_inject_ops->addfd_at(ctx, kbox_syscall_request_cookie(req),
                                        srcfd, target_fd, newfd_flags);
}

void kbox_dispatch_prepare_request_ctx(struct kbox_supervisor_ctx *ctx,
                                       const struct kbox_syscall_request *req)
{
    if (!ctx || !req)
        return;

    ctx->active_guest_mem = req->guest_mem;
    if (!ctx->active_guest_mem.ops) {
        ctx->active_guest_mem.ops = &kbox_process_vm_guest_mem_ops;
        ctx->active_guest_mem.opaque = (uintptr_t) req->pid;
    }
    ctx->guest_mem_ops = ctx->active_guest_mem.ops;
    if (!ctx->fd_inject_ops) {
        if (req->source == KBOX_SYSCALL_SOURCE_TRAP ||
            req->source == KBOX_SYSCALL_SOURCE_REWRITE) {
            ctx->fd_inject_ops = &local_fd_inject_ops;
        } else {
            ctx->fd_inject_ops = &seccomp_fd_inject_ops;
        }
    }
}

int guest_mem_read(const struct kbox_supervisor_ctx *ctx,
                   pid_t pid,
                   uint64_t remote_addr,
                   void *out,
                   size_t len)
{
    (void) pid;
    return kbox_guest_mem_read(&ctx->active_guest_mem, remote_addr, out, len);
}

int guest_mem_write(const struct kbox_supervisor_ctx *ctx,
                    pid_t pid,
                    uint64_t remote_addr,
                    const void *in,
                    size_t len)
{
    (void) pid;
    return kbox_guest_mem_write(&ctx->active_guest_mem, remote_addr, in, len);
}

int guest_mem_write_force(const struct kbox_supervisor_ctx *ctx,
                          pid_t pid,
                          uint64_t remote_addr,
                          const void *in,
                          size_t len)
{
    (void) pid;
    return kbox_guest_mem_write_force(&ctx->active_guest_mem, remote_addr, in,
                                      len);
}

int guest_mem_read_string(const struct kbox_supervisor_ctx *ctx,
                          pid_t pid,
                          uint64_t remote_addr,
                          char *buf,
                          size_t max_len)
{
    (void) pid;
    return kbox_guest_mem_read_string(&ctx->active_guest_mem, remote_addr, buf,
                                      max_len);
}

int guest_mem_read_open_how(const struct kbox_supervisor_ctx *ctx,
                            pid_t pid,
                            uint64_t remote_addr,
                            uint64_t size,
                            struct kbox_open_how *out)
{
    (void) pid;

    return kbox_guest_mem_read_open_how(&ctx->active_guest_mem, remote_addr,
                                        size, out);
}

/* Stat ABI conversion. */

/* Convert LKL's generic-arch stat layout to the host's struct stat.
 *
 * LKL always fills stat buffers using the asm-generic layout regardless of the
 * host architecture. On x86_64 the two layouts differ:
 *   generic: st_mode (u32) at offset 16, st_nlink (u32) at offset 20
 *   x86_64:  st_nlink (u64) at offset 16, st_mode (u32) at offset 24
 *
 * On aarch64 the kernel uses the generic layout, but C library's struct stat
 * may still have different padding, so convert explicitly on all arch.
 */
void kbox_lkl_stat_to_host(const struct kbox_lkl_stat *src, struct stat *dst)
{
    memset(dst, 0, sizeof(*dst));
    dst->st_dev = (dev_t) src->st_dev;
    dst->st_ino = (ino_t) src->st_ino;
    dst->st_mode = (mode_t) src->st_mode;
    dst->st_nlink = (nlink_t) src->st_nlink;
    dst->st_uid = (uid_t) src->st_uid;
    dst->st_gid = (gid_t) src->st_gid;
    dst->st_rdev = (dev_t) src->st_rdev;
    dst->st_size = (off_t) src->st_size;
    dst->st_blksize = (blksize_t) src->st_blksize;
    dst->st_blocks = (blkcnt_t) src->st_blocks;
    dst->st_atim.tv_sec = (time_t) src->st_atime_sec;
    dst->st_atim.tv_nsec = (long) src->st_atime_nsec;
    dst->st_mtim.tv_sec = (time_t) src->st_mtime_sec;
    dst->st_mtim.tv_nsec = (long) src->st_mtime_nsec;
    dst->st_ctim.tv_sec = (time_t) src->st_ctime_sec;
    dst->st_ctim.tv_nsec = (long) src->st_ctime_nsec;
}

/* Dispatch result constructors. */

struct kbox_dispatch kbox_dispatch_continue(void)
{
    return (struct kbox_dispatch) {
        .kind = KBOX_DISPATCH_CONTINUE,
        .val = 0,
        .error = 0,
    };
}

struct kbox_dispatch kbox_dispatch_errno(int err)
{
    if (err <= 0)
        err = EIO;
    return (struct kbox_dispatch) {
        .kind = KBOX_DISPATCH_RETURN,
        .val = 0,
        .error = err,
    };
}

struct kbox_dispatch kbox_dispatch_value(int64_t val)
{
    return (struct kbox_dispatch) {
        .kind = KBOX_DISPATCH_RETURN,
        .val = val,
        .error = 0,
    };
}

struct kbox_dispatch kbox_dispatch_from_lkl(long ret)
{
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    return kbox_dispatch_value((int64_t) ret);
}

/* Path and FD helper functions. */

/* Check if the original guest path at a given arg index starts with '/'.
 * Used to gate virtual-path CONTINUE on originally-absolute paths: relative
 * paths like "./proc" normalize to "/proc" but should go through LKL, while
 * absolute "/proc/self/status" should CONTINUE to the host kernel.
 */
static bool guest_path_is_absolute(const struct kbox_supervisor_ctx *ctx,
                                   const struct kbox_syscall_request *req,
                                   size_t arg_idx)
{
    uint8_t first = 0;
    if (guest_mem_read(ctx, kbox_syscall_request_pid(req),
                       kbox_syscall_request_arg(req, arg_idx), &first, 1) == 0)
        return first == '/';
    return false;
}

static bool should_continue_virtual_path(const struct kbox_supervisor_ctx *ctx,
                                         const struct kbox_syscall_request *req,
                                         size_t path_idx,
                                         const char *translated)
{
    return kbox_is_lkl_virtual_path(translated) &&
           guest_path_is_absolute(ctx, req, path_idx);
}

/* Resolve dirfd for *at() syscalls.
 *
 * If the path is absolute, AT_FDCWD is fine regardless of dirfd. If dirfd is
 * AT_FDCWD, pass it through. Otherwise look up the virtual FD in the table to
 * get the LKL fd.  Returns -1 if the fd is not in the table (caller should
 * CONTINUE).
 */
long resolve_open_dirfd(const char *path,
                        long dirfd,
                        const struct kbox_fd_table *table)
{
    if (path[0] == '/')
        return AT_FDCWD_LINUX;
    if (dirfd == AT_FDCWD_LINUX)
        return AT_FDCWD_LINUX;
    return kbox_fd_table_get_lkl(table, dirfd);
}

int read_guest_string(const struct kbox_supervisor_ctx *ctx,
                      pid_t pid,
                      uint64_t addr,
                      char *buf,
                      size_t size)
{
    return guest_mem_read_string(ctx, pid, addr, buf, size);
}

static struct kbox_translated_path_cache_entry *find_translated_path_cache(
    struct kbox_supervisor_ctx *ctx,
    const char *guest_path)
{
    size_t i;

    if (!ctx || !guest_path)
        return NULL;
    for (i = 0; i < KBOX_TRANSLATED_PATH_CACHE_MAX; i++) {
        struct kbox_translated_path_cache_entry *entry =
            &ctx->translated_path_cache[i];
        if (entry->valid &&
            entry->generation == ctx->path_translation_generation &&
            strcmp(entry->guest_path, guest_path) == 0) {
            return entry;
        }
    }
    return NULL;
}

static struct kbox_translated_path_cache_entry *reserve_translated_path_cache(
    struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return NULL;
    for (i = 0; i < KBOX_TRANSLATED_PATH_CACHE_MAX; i++) {
        if (!ctx->translated_path_cache[i].valid)
            return &ctx->translated_path_cache[i];
    }
    return &ctx->translated_path_cache[0];
}

static struct kbox_literal_path_cache_entry *find_literal_path_cache(
    struct kbox_supervisor_ctx *ctx,
    pid_t pid,
    uint64_t guest_addr)
{
    size_t i;

    if (!ctx || guest_addr == 0)
        return NULL;
    for (i = 0; i < KBOX_LITERAL_PATH_CACHE_MAX; i++) {
        struct kbox_literal_path_cache_entry *entry =
            &ctx->literal_path_cache[i];
        if (entry->valid &&
            entry->generation == ctx->path_translation_generation &&
            entry->pid == pid && entry->guest_addr == guest_addr) {
            return entry;
        }
    }
    return NULL;
}

static struct kbox_literal_path_cache_entry *reserve_literal_path_cache(
    struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return NULL;
    for (i = 0; i < KBOX_LITERAL_PATH_CACHE_MAX; i++) {
        if (!ctx->literal_path_cache[i].valid)
            return &ctx->literal_path_cache[i];
    }
    return &ctx->literal_path_cache[0];
}

int guest_addr_is_writable(pid_t pid, uint64_t addr)
{
    char maps_path[64];
    FILE *fp;
    char line[256];

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int) pid);
    fp = fopen(maps_path, "re");
    if (!fp)
        return 1;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start, end;
        char perms[8];

        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3)
            continue;
        if (addr < start || addr >= end)
            continue;
        fclose(fp);
        return strchr(perms, 'w') != NULL;
    }

    fclose(fp);
    return 1;
}

int guest_range_has_shared_file_write_mapping(pid_t pid,
                                              uint64_t addr,
                                              uint64_t len)
{
    char maps_path[64];
    FILE *fp;
    char line[512];
    uint64_t end_addr;

    if (len == 0)
        return 0;
    if (__builtin_add_overflow(addr, len, &end_addr))
        end_addr = UINT64_MAX;

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int) pid);
    fp = fopen(maps_path, "re");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start, end, inode;
        unsigned long long offset;
        char perms[8];
        char dev[32];

        if (sscanf(line, "%llx-%llx %7s %llx %31s %llu", &start, &end, perms,
                   &offset, dev, &inode) != 6)
            continue;
        (void) offset;
        (void) dev;
        if (inode == 0)
            continue;
        if (end <= addr || start >= end_addr)
            continue;
        if (strchr(perms, 's') == NULL || strchr(perms, 'w') == NULL)
            continue;
        fclose(fp);
        return 1;
    }

    fclose(fp);
    return 0;
}

void invalidate_translated_path_cache(struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return;
    ctx->path_translation_generation++;
    for (i = 0; i < KBOX_TRANSLATED_PATH_CACHE_MAX; i++)
        ctx->translated_path_cache[i].valid = 0;
    for (i = 0; i < KBOX_LITERAL_PATH_CACHE_MAX; i++)
        ctx->literal_path_cache[i].valid = 0;
}

int translate_guest_path(const struct kbox_supervisor_ctx *ctx,
                         pid_t pid,
                         uint64_t addr,
                         const char *host_root,
                         char *translated,
                         size_t size)
{
    struct kbox_supervisor_ctx *mutable_ctx =
        (struct kbox_supervisor_ctx *) ctx;
    char pathbuf[KBOX_MAX_PATH];
    struct kbox_literal_path_cache_entry *literal_entry;
    struct kbox_translated_path_cache_entry *entry;

    literal_entry = find_literal_path_cache(mutable_ctx, pid, addr);
    if (literal_entry) {
        size_t len = strlen(literal_entry->translated);

        if (len >= size)
            return -ENAMETOOLONG;
        memcpy(translated, literal_entry->translated, len + 1);
        return 0;
    }

    int rc = read_guest_string(ctx, pid, addr, pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return rc;

    entry = find_translated_path_cache(mutable_ctx, pathbuf);
    if (entry) {
        if (strlen(entry->translated) >= size)
            return -ENAMETOOLONG;
        memcpy(translated, entry->translated, strlen(entry->translated) + 1);
        return 0;
    }

    rc = kbox_translate_path_for_lkl(pid, pathbuf, host_root, translated, size);
    if (rc < 0)
        return rc;

    entry = reserve_translated_path_cache(mutable_ctx);
    if (entry) {
        entry->valid = 1;
        entry->generation = mutable_ctx->path_translation_generation;
        strncpy(entry->guest_path, pathbuf, sizeof(entry->guest_path) - 1);
        entry->guest_path[sizeof(entry->guest_path) - 1] = '\0';
        strncpy(entry->translated, translated, sizeof(entry->translated) - 1);
        entry->translated[sizeof(entry->translated) - 1] = '\0';
    }

    if (!guest_addr_is_writable(pid, addr)) {
        literal_entry = reserve_literal_path_cache(mutable_ctx);
        if (literal_entry) {
            literal_entry->valid = 1;
            literal_entry->generation =
                mutable_ctx->path_translation_generation;
            literal_entry->pid = pid;
            literal_entry->guest_addr = addr;
            strncpy(literal_entry->translated, translated,
                    sizeof(literal_entry->translated) - 1);
            literal_entry->translated[sizeof(literal_entry->translated) - 1] =
                '\0';
        }
    }
    return 0;
}

int translate_request_path(const struct kbox_syscall_request *req,
                           const struct kbox_supervisor_ctx *ctx,
                           size_t path_idx,
                           const char *host_root,
                           char *translated,
                           size_t size)
{
    return translate_guest_path(ctx, kbox_syscall_request_pid(req),
                                kbox_syscall_request_arg(req, path_idx),
                                host_root, translated, size);
}

static bool host_dirfd_targets_proc(const struct kbox_supervisor_ctx *ctx,
                                    long fd)
{
    char link_path[64];
    char target[KBOX_MAX_PATH];
    ssize_t n;

    if (!ctx || ctx->child_pid <= 0 || fd < 0)
        return false;

    snprintf(link_path, sizeof(link_path), /* format-ok */
             "/proc/%d/fd/%ld", (int) ctx->child_pid, fd);
    n = readlink(link_path, target, sizeof(target) - 1);
    if (n < 0)
        return false;
    target[n] = '\0';

    if (strcmp(target, "/proc") == 0)
        return true;
    return strncmp(target, "/proc/", 6) == 0;
}

int translate_request_at_path(const struct kbox_syscall_request *req,
                              struct kbox_supervisor_ctx *ctx,
                              size_t dirfd_idx,
                              size_t path_idx,
                              char *translated,
                              size_t size,
                              long *lkl_dirfd)
{
    long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, dirfd_idx));

    /* If dirfd is not AT_FDCWD and not tracked in our FD table, this is a
     * host-kernel FD (e.g., from a CONTINUE'd openat on /proc or /sys).
     * For relative or empty paths the host kernel must resolve them against
     * that dirfd, so signal CONTINUE by setting *lkl_dirfd = -1.
     *
     * Reject unsafe relative lookups instead of translating them through LKL:
     * translating "../../etc/passwd" against the guest cwd would silently
     * change syscall semantics, and continuing it against the host dirfd could
     * escape the virtual namespace.
     *
     * For absolute paths dirfd is irrelevant and normal translation proceeds.
     */
    if (raw_dirfd != AT_FDCWD_LINUX && raw_dirfd >= 0 &&
        kbox_fd_table_get_lkl(ctx->fd_table, raw_dirfd) < 0) {
        char pathbuf[KBOX_MAX_PATH];
        bool proc_dirfd = host_dirfd_targets_proc(ctx, raw_dirfd);
        int rc = read_guest_string(ctx, kbox_syscall_request_pid(req),
                                   kbox_syscall_request_arg(req, path_idx),
                                   pathbuf, sizeof(pathbuf));
        if (rc < 0)
            return rc;
        if (pathbuf[0] != '/') {
            if (kbox_relative_path_has_dotdot(pathbuf) ||
                (proc_dirfd && kbox_relative_proc_escape_path(pathbuf))) {
                return -EPERM;
            }
            *lkl_dirfd = -1;
            if (size > 0)
                translated[0] = '\0';
            return 0;
        }
        /* Absolute path: dirfd is ignored, so normal translation is safe. */
    }

    int rc = translate_request_path(req, ctx, path_idx, ctx->host_root,
                                    translated, size);
    if (rc < 0)
        return rc;

    *lkl_dirfd = resolve_open_dirfd(translated, raw_dirfd, ctx->fd_table);
    return 0;
}

int should_continue_for_dirfd(long lkl_dirfd)
{
    return lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX;
}

int child_fd_is_open(const struct kbox_supervisor_ctx *ctx, long fd)
{
    char link_path[64];
    char target[1];

    if (!ctx || ctx->child_pid <= 0 || fd < 0)
        return 0;
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%ld",
             (int) ctx->child_pid, fd);
    if (readlink(link_path, target, sizeof(target)) >= 0)
        return 1;
    return errno != ENOENT;
}

long allocate_passthrough_hostonly_fd(struct kbox_supervisor_ctx *ctx)
{
    long base_fd = KBOX_FD_HOSTONLY_BASE;
    long end_fd = KBOX_FD_BASE + KBOX_FD_TABLE_MAX;
    long start_fd;
    long fd;

    if (!ctx || !ctx->fd_table)
        return -1;

    start_fd = ctx->fd_table->next_hostonly_fd;
    if (start_fd < base_fd || start_fd >= end_fd)
        start_fd = base_fd;

    for (fd = start_fd; fd < end_fd; fd++) {
        if (!child_fd_is_open(ctx, fd)) {
            ctx->fd_table->next_hostonly_fd = fd + 1;
            return fd;
        }
    }
    for (fd = base_fd; fd < start_fd; fd++) {
        if (!child_fd_is_open(ctx, fd)) {
            ctx->fd_table->next_hostonly_fd = fd + 1;
            return fd;
        }
    }

    return -1;
}

long next_hostonly_fd_hint(const struct kbox_supervisor_ctx *ctx)
{
    long fd;
    long end_fd = KBOX_FD_BASE + KBOX_FD_TABLE_MAX;

    if (!ctx || !ctx->fd_table)
        return -1;

    fd = ctx->fd_table->next_hostonly_fd;
    if (fd < KBOX_FD_HOSTONLY_BASE || fd >= end_fd)
        fd = KBOX_FD_HOSTONLY_BASE;
    return fd;
}

int ensure_proc_self_fd_dir(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx)
        return -1;
    if (ctx->proc_self_fd_dirfd >= 0)
        return ctx->proc_self_fd_dirfd;

    ctx->proc_self_fd_dirfd =
        open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    return ctx->proc_self_fd_dirfd;
}

int ensure_proc_mem_fd(struct kbox_supervisor_ctx *ctx)
{
    char path[64];

    if (!ctx || ctx->child_pid <= 0)
        return -1;
    if (ctx->proc_mem_fd >= 0)
        return ctx->proc_mem_fd;

    snprintf(path, sizeof(path), "/proc/%d/mem", (int) ctx->child_pid);
    ctx->proc_mem_fd = open(path, O_RDWR | O_CLOEXEC);
    return ctx->proc_mem_fd;
}

int guest_mem_write_small_metadata(const struct kbox_supervisor_ctx *ctx,
                                   pid_t pid,
                                   uint64_t remote_addr,
                                   const void *in,
                                   size_t len)
{
    struct kbox_supervisor_ctx *mutable_ctx =
        (struct kbox_supervisor_ctx *) ctx;
    ssize_t n;
    int fd;

    if (!ctx || !in)
        return -EFAULT;
    if (len == 0)
        return 0;
    if (remote_addr == 0)
        return -EFAULT;
    if (pid != ctx->child_pid ||
        ctx->active_guest_mem.ops != &kbox_process_vm_guest_mem_ops)
        return guest_mem_write(ctx, pid, remote_addr, in, len);

    fd = ensure_proc_mem_fd(mutable_ctx);
    if (fd < 0)
        return guest_mem_write(ctx, pid, remote_addr, in, len);

    n = pwrite(fd, in, len, (off_t) remote_addr);
    if (n < 0)
        return guest_mem_write(ctx, pid, remote_addr, in, len);
    if ((size_t) n != len)
        return -EIO;
    return 0;
}

/* Build the host-side path for a guest-relative (translated) path.
 * When host_root is set, translated is relative to host_root (the prefix was
 * stripped by kbox_translate_path_for_lkl).  Re-prefix it so open() resolves
 * against the correct directory instead of the supervisor's real root.
 */
static int build_host_open_path(const struct kbox_supervisor_ctx *ctx,
                                const char *translated,
                                char *out,
                                size_t out_size)
{
    int n;

    if (!ctx->host_root) {
        n = snprintf(out, out_size, "%s", translated);
        return (n >= 0 && (size_t) n < out_size) ? 0 : -1;
    }

    /* translated is absolute (starts with '/'), skip the leading '/' when
     * joining to avoid double-slash.
     */
    const char *tail = translated;
    if (*tail == '/')
        tail++;
    n = snprintf(out, out_size, "%s/%s", ctx->host_root, tail);
    return (n >= 0 && (size_t) n < out_size) ? 0 : -1;
}

int reopen_cached_shadow_fd(struct kbox_supervisor_ctx *ctx,
                            const struct kbox_path_shadow_cache_entry *entry)
{
    char fd_name[32];
    int dirfd;
    int fd;

    if (!entry)
        return -1;
    if (entry->path[0] != '\0') {
        char host_path[KBOX_MAX_PATH];
        if (build_host_open_path(ctx, entry->path, host_path,
                                 sizeof(host_path)) == 0) {
            fd = open(host_path, O_RDONLY | O_CLOEXEC);
            if (fd >= 0)
                return fd;
        }
    }
    fd = entry->memfd;
    if (fd < 0)
        return -1;
    dirfd = ensure_proc_self_fd_dir(ctx);
    if (dirfd < 0)
        return -1;
    snprintf(fd_name, sizeof(fd_name), "%d", fd);
    return openat(dirfd, fd_name, O_RDONLY | O_CLOEXEC);
}

/* Promote a read-only regular LKL FD to a host-visible shadow at the same guest
 * FD number on first eligible read-only access. This avoids paying memfd copy
 * cost at open time while still letting later read/lseek/fstat/mmap operations
 * run on a real host FD.
 *
 * Returns:
 *   1  shadow is available (same-fd injected for seccomp, local-only for
 *      trap/rewrite)
 *   0  shadow promotion not applicable
 *  -1  promotion attempted but failed
 */
int ensure_same_fd_shadow(struct kbox_supervisor_ctx *ctx,
                          const struct kbox_syscall_request *req,
                          long fd,
                          long lkl_fd)
{
    struct kbox_fd_entry *entry;
    long flags;
    int memfd;

    off_t cur_off;

    if (!ctx || !req || !ctx->fd_table || fd < 0 || lkl_fd < 0)
        return 0;

    entry = fd_table_entry(ctx->fd_table, fd);
    if (!entry)
        return 0;
    if (entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW ||
        entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW) {
        return 1;
    }
    if (entry->host_fd >= 0)
        return 0;

    flags = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_GETFL, 0);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY)
        return 0;

    memfd = kbox_shadow_create(ctx->sysnrs, lkl_fd);
    if (memfd < 0)
        return -1;
    kbox_shadow_seal(memfd);

    cur_off = (off_t) kbox_lkl_lseek(ctx->sysnrs, lkl_fd, 0, SEEK_CUR);
    if (cur_off >= 0 && lseek(memfd, cur_off, SEEK_SET) < 0) {
        close(memfd);
        return -1;
    }

    /* Keep lazy read shadows local to the supervisor in all modes.
     * Injecting them at the guest FD number lets read(2)/lseek(2) CONTINUE,
     * but it reintroduces a close/open reuse race under concurrent seccomp
     * notifications. The local-shadow handlers already cover read/lseek/fstat
     * safely, so prefer them over same-fd injection here.
     */
    entry->host_fd = KBOX_FD_LOCAL_ONLY_SHADOW;
    entry->shadow_sp = memfd;
    entry->shadow_writeback = 0;

    if (ctx->verbose) {
        fprintf(stderr, "kbox: lazy shadow promote fd=%ld lkl_fd=%ld mode=%s\n",
                fd, lkl_fd,
                entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW ? "same-fd"
                                                              : "local-only");
    }
    return 1;
}

static struct kbox_dispatch forward_local_shadow_read_like(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *entry,
    long lkl_fd,
    int is_pread)
{
    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    size_t count;
    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;
    pid_t pid = kbox_syscall_request_pid(req);

    if (!entry || entry->shadow_sp < 0)
        return kbox_dispatch_continue();
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    count = (size_t) count_raw;
    if (count == 0)
        return kbox_dispatch_value(0);
    if (count > 1024 * 1024)
        count = 1024 * 1024;

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        ssize_t nr;

        if (chunk_len > count - total)
            chunk_len = count - total;
        if (is_pread) {
            long offset = to_c_long_arg(kbox_syscall_request_arg(req, 3));
            nr = pread(entry->shadow_sp, scratch, chunk_len,
                       (off_t) (offset + (long) total));
        } else {
            nr = read(entry->shadow_sp, scratch, chunk_len);
        }
        if (nr < 0) {
            if (total == 0)
                return kbox_dispatch_errno(errno);
            break;
        }
        if (nr == 0)
            break;
        if (guest_mem_write(ctx, pid, remote_buf + total, scratch,
                            (size_t) nr) < 0) {
            return kbox_dispatch_errno(EFAULT);
        }
        total += (size_t) nr;
        if ((size_t) nr < chunk_len)
            break;
    }

    if (!is_pread) {
        off_t cur_off = lseek(entry->shadow_sp, 0, SEEK_CUR);
        if (cur_off >= 0)
            (void) kbox_lkl_lseek(ctx->sysnrs, lkl_fd, (long) cur_off,
                                  SEEK_SET);
    }

    return kbox_dispatch_value((int64_t) total);
}

static struct kbox_dispatch forward_local_shadow_lseek(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *entry,
    long lkl_fd)
{
    long off;
    long whence;
    off_t ret;

    if (!entry || entry->shadow_sp < 0)
        return kbox_dispatch_continue();

    off = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    whence = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    ret = lseek(entry->shadow_sp, (off_t) off, (int) whence);
    if (ret < 0)
        return kbox_dispatch_errno(errno);

    (void) kbox_lkl_lseek(ctx->sysnrs, lkl_fd, (long) ret, SEEK_SET);
    return kbox_dispatch_value((int64_t) ret);
}

static struct kbox_dispatch forward_local_shadow_fstat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *entry)
{
    struct stat host_stat;
    uint64_t remote_stat = kbox_syscall_request_arg(req, 1);

    if (!entry || entry->shadow_sp < 0)
        return kbox_dispatch_continue();
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);
    if (fstat(entry->shadow_sp, &host_stat) < 0)
        return kbox_dispatch_errno(errno);
    if (guest_mem_write(ctx, kbox_syscall_request_pid(req), remote_stat,
                        &host_stat, sizeof(host_stat)) < 0) {
        return kbox_dispatch_errno(EFAULT);
    }
    return kbox_dispatch_value(0);
}

/* statx struct field offsets (standard on x86_64 and aarch64). */
#define STATX_MODE_OFFSET 0x20
#define STATX_UID_OFFSET 0x48
#define STATX_GID_OFFSET 0x4c
#define STATX_BUF_SIZE 0x100

static struct kbox_dispatch finish_open_dispatch(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    long lkl_fd,
    long flags,
    const char *translated)
{
    struct kbox_dispatch shadow_dispatch;

    if (req && try_cached_shadow_open_dispatch(ctx, req, flags, translated,
                                               &shadow_dispatch)) {
        return shadow_dispatch;
    }

    if (req && try_writeback_shadow_open(ctx, req, lkl_fd, flags, translated,
                                         &shadow_dispatch)) {
        return shadow_dispatch;
    }

    long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd,
                                    kbox_is_tty_like_path(translated));
    if (vfd < 0) {
        lkl_close_and_invalidate(ctx, lkl_fd);
        return kbox_dispatch_errno(EMFILE);
    }
    if (flags & O_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, vfd, 1);
    return kbox_dispatch_value((int64_t) vfd);
}

void normalize_host_stat_if_needed(struct kbox_supervisor_ctx *ctx,
                                   const char *path,
                                   struct stat *host_stat)
{
    if (!ctx->normalize)
        return;

    uint32_t n_mode, n_uid, n_gid;
    if (!kbox_normalized_permissions(path, &n_mode, &n_uid, &n_gid))
        return;

    host_stat->st_mode = (host_stat->st_mode & S_IFMT) | (n_mode & ~S_IFMT);
    host_stat->st_uid = n_uid;
    host_stat->st_gid = n_gid;
}

void normalize_statx_if_needed(struct kbox_supervisor_ctx *ctx,
                               const char *path,
                               uint8_t *statx_buf)
{
    if (!ctx->normalize)
        return;

    uint32_t n_mode, n_uid, n_gid;
    if (!kbox_normalized_permissions(path, &n_mode, &n_uid, &n_gid))
        return;

    uint16_t mode_le = (uint16_t) n_mode;
    memcpy(&statx_buf[STATX_MODE_OFFSET], &mode_le, 2);
    memcpy(&statx_buf[STATX_UID_OFFSET], &n_uid, 4);
    memcpy(&statx_buf[STATX_GID_OFFSET], &n_gid, 4);
}

void invalidate_path_shadow_cache(struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return;
    for (i = 0; i < KBOX_PATH_SHADOW_CACHE_MAX; i++) {
        if (ctx->path_shadow_cache[i].valid &&
            ctx->path_shadow_cache[i].memfd >= 0) {
            close(ctx->path_shadow_cache[i].memfd);
        }
        memset(&ctx->path_shadow_cache[i], 0,
               sizeof(ctx->path_shadow_cache[i]));
        ctx->path_shadow_cache[i].memfd = -1;
    }
    invalidate_translated_path_cache(ctx);
}

static struct kbox_path_shadow_cache_entry *find_path_shadow_cache(
    struct kbox_supervisor_ctx *ctx,
    const char *translated)
{
    size_t i;

    if (!ctx || !translated)
        return NULL;
    for (i = 0; i < KBOX_PATH_SHADOW_CACHE_MAX; i++) {
        struct kbox_path_shadow_cache_entry *entry = &ctx->path_shadow_cache[i];
        if (entry->valid && strcmp(entry->path, translated) == 0)
            return entry;
    }
    return NULL;
}

static struct kbox_path_shadow_cache_entry *reserve_path_shadow_cache_slot(
    struct kbox_supervisor_ctx *ctx,
    const char *translated)
{
    size_t i;
    struct kbox_path_shadow_cache_entry *entry;

    entry = find_path_shadow_cache(ctx, translated);
    if (entry)
        return entry;

    for (i = 0; i < KBOX_PATH_SHADOW_CACHE_MAX; i++) {
        entry = &ctx->path_shadow_cache[i];
        if (!entry->valid)
            return entry;
    }

    entry = &ctx->path_shadow_cache[0];
    if (entry->memfd >= 0)
        close(entry->memfd);
    memset(entry, 0, sizeof(*entry));
    entry->memfd = -1;
    return entry;
}

int ensure_path_shadow_cache(struct kbox_supervisor_ctx *ctx,
                             const char *translated)
{
    struct kbox_path_shadow_cache_entry *entry;
    struct stat host_stat;
    int host_fd;

    if (!ctx || !translated || translated[0] == '\0' ||
        ctx->active_writeback_shadows > 0 ||
        kbox_is_lkl_virtual_path(translated) ||
        kbox_is_tty_like_path(translated))
        return 0;

    entry = find_path_shadow_cache(ctx, translated);
    if (entry)
        return 1;

    {
        char host_path[KBOX_MAX_PATH];
        if (build_host_open_path(ctx, translated, host_path,
                                 sizeof(host_path)) < 0)
            return 0;
        host_fd = open(host_path, O_RDONLY | O_CLOEXEC);
    }
    if (host_fd < 0)
        return 0;

    if (fstat(host_fd, &host_stat) < 0) {
        close(host_fd);
        return 0;
    }
    if (!S_ISREG(host_stat.st_mode)) {
        close(host_fd);
        return 0;
    }
    normalize_host_stat_if_needed(ctx, translated, &host_stat);

    entry = reserve_path_shadow_cache_slot(ctx, translated);
    if (!entry) {
        close(host_fd);
        return 0;
    }

    entry->valid = 1;
    entry->memfd = host_fd;
    strncpy(entry->path, translated, sizeof(entry->path) - 1);
    entry->path[sizeof(entry->path) - 1] = '\0';
    entry->host_stat = host_stat;
    return 1;
}

int try_cached_shadow_open_dispatch(struct kbox_supervisor_ctx *ctx,
                                    const struct kbox_syscall_request *req,
                                    long flags,
                                    const char *translated,
                                    struct kbox_dispatch *out)
{
    struct kbox_path_shadow_cache_entry *entry;
    int injected;
    int dup_fd;

    if (!ctx || !req || !translated || !out)
        return 0;
    if ((flags & O_ACCMODE) != O_RDONLY)
        return 0;
    if (flags & ~(O_RDONLY | O_CLOEXEC))
        return 0;
    if (!ensure_path_shadow_cache(ctx, translated))
        return 0;

    entry = find_path_shadow_cache(ctx, translated);
    if (!entry || entry->memfd < 0)
        return 0;

    dup_fd = reopen_cached_shadow_fd(ctx, entry);
    if (dup_fd < 0)
        return 0;

    /* Let the kernel pick a fresh host-visible FD. Reusing a fixed target FD
     * races with concurrent close(2): the supervisor removes its bookkeeping
     * before the kernel replays the close, so another thread can reuse that FD
     * number and have the older close tear down the new file.
     */
    injected =
        request_addfd(ctx, req, dup_fd, (flags & O_CLOEXEC) ? O_CLOEXEC : 0);
    close(dup_fd);
    if (injected < 0)
        return 0;

    *out = kbox_dispatch_value((int64_t) injected);
    return 1;
}

int try_cached_shadow_stat_dispatch(struct kbox_supervisor_ctx *ctx,
                                    const char *translated,
                                    uint64_t remote_stat,
                                    pid_t pid)
{
    struct kbox_path_shadow_cache_entry *entry;

    if (!ctx || !translated || remote_stat == 0)
        return 0;
    if (!ensure_path_shadow_cache(ctx, translated))
        return 0;

    entry = find_path_shadow_cache(ctx, translated);
    if (!entry)
        return 0;

    return guest_mem_write_small_metadata(ctx, pid, remote_stat,
                                          &entry->host_stat,
                                          sizeof(entry->host_stat)) == 0;
}

void note_shadow_writeback_open(struct kbox_supervisor_ctx *ctx,
                                struct kbox_fd_entry *entry)
{
    if (!ctx || !entry || entry->shadow_writeback)
        return;
    entry->shadow_writeback = 1;
    ctx->active_writeback_shadows++;
    invalidate_path_shadow_cache(ctx);
}

void note_shadow_writeback_close(struct kbox_supervisor_ctx *ctx,
                                 struct kbox_fd_entry *entry)
{
    if (!ctx || !entry || !entry->shadow_writeback)
        return;
    entry->shadow_writeback = 0;
    if (ctx->active_writeback_shadows > 0)
        ctx->active_writeback_shadows--;
}

int try_writeback_shadow_open(struct kbox_supervisor_ctx *ctx,
                              const struct kbox_syscall_request *req,
                              long lkl_fd,
                              long flags,
                              const char *translated,
                              struct kbox_dispatch *out)
{
    struct kbox_fd_entry *entry;
    int memfd;
    int injected;
    long vfd;

    if (!ctx || !req || !out || lkl_fd < 0 || !translated)
        return 0;
    if ((flags & O_ACCMODE) == O_RDONLY)
        return 0;
    if (kbox_is_lkl_virtual_path(translated) ||
        kbox_is_tty_like_path(translated))
        return 0;

    memfd = kbox_shadow_create(ctx->sysnrs, lkl_fd);
    if (memfd < 0)
        return 0;
    /* Do NOT seal: this shadow is for a writable FD; the tracee needs
     * write access.  Only read-only shadows (ensure_same_fd_shadow) are
     * sealed.
     */

    vfd = kbox_fd_table_insert_fast(ctx->fd_table, lkl_fd, 0);
    if (vfd < 0) {
        close(memfd);
        return 0;
    }

    injected = request_addfd_at(ctx, req, memfd, (int) vfd,
                                (flags & O_CLOEXEC) ? O_CLOEXEC : 0);
    if (injected < 0) {
        kbox_fd_table_remove(ctx->fd_table, vfd);
        close(memfd);
        return 0;
    }

    entry = fd_table_entry(ctx->fd_table, vfd);
    if (!entry) {
        kbox_fd_table_remove(ctx->fd_table, vfd);
        close(memfd);
        return 0;
    }

    entry->host_fd = KBOX_FD_HOST_SAME_FD_SHADOW;
    entry->shadow_sp = memfd;
    note_shadow_writeback_open(ctx, entry);
    if (ctx->verbose) {
        fprintf(stderr,
                "kbox: writable shadow promote fd=%ld lkl_fd=%ld path=%s\n",
                vfd, lkl_fd, translated);
    }
    *out = kbox_dispatch_value((int64_t) vfd);
    return 1;
}

typedef long (*kbox_getdents_fn)(const struct kbox_sysnrs *sysnrs,
                                 long fd,
                                 void *buf,
                                 long count);

static struct kbox_dispatch forward_getdents_common(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    kbox_getdents_fn getdents_fn)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    uint64_t remote_dirp = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    size_t count, n;
    uint8_t *buf;
    long ret;
    int wrc;

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);

    count = (size_t) count_raw;
    if (count == 0)
        return kbox_dispatch_value(0);
    if (remote_dirp == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count > KBOX_IO_CHUNK_LEN)
        count = KBOX_IO_CHUNK_LEN;

    buf = dispatch_scratch;

    ret = getdents_fn(ctx->sysnrs, lkl_fd, buf, (long) count);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    n = (size_t) ret;
    if (n > count)
        return kbox_dispatch_errno(EIO);

    wrc = guest_mem_write(ctx, kbox_syscall_request_pid(req), remote_dirp, buf,
                          n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    return kbox_dispatch_value((int64_t) n);
}

int dup_tracee_fd(pid_t pid, int tracee_fd);

/* Gate a CONTINUE syscall that takes an FD in arg0.  Deny if the FD is
 * untracked and in a blocked range; otherwise let the host kernel handle it.
 */
static struct kbox_dispatch forward_fd_gated_continue(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (fd_should_deny_io(fd, lkl_fd))
        return kbox_dispatch_errno(EBADF);
    return kbox_dispatch_continue();
}

/* Gate epoll_ctl: two FD args (epfd=arg0, fd=arg2). */
static struct kbox_dispatch forward_epoll_ctl_gated(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long epfd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long lkl_ep = kbox_fd_table_get_lkl(ctx->fd_table, epfd);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (fd_should_deny_io(epfd, lkl_ep) || fd_should_deny_io(fd, lkl_fd))
        return kbox_dispatch_errno(EBADF);
    return kbox_dispatch_continue();
}

/* Translate /proc/self and /proc/thread-self references to the tracee's
 * actual PID so the supervisor operates on the tracee's proc entries rather
 * than its own.
 */
void translate_proc_self(const char *path,
                         pid_t pid,
                         char *sv_path,
                         size_t sv_path_len)
{
    if (strncmp(path, "/proc/thread-self/", 18) == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/task/%d/%s", (int) pid,
                 (int) pid, path + 18);
    else if (strcmp(path, "/proc/thread-self") == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/task/%d", (int) pid,
                 (int) pid);
    else if (strncmp(path, "/proc/self/", 11) == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/%s", (int) pid, path + 11);
    else if (strcmp(path, "/proc/self") == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d", (int) pid);
    else
        snprintf(sv_path, sv_path_len, "%s", path);
}

/* Emulate an open that would otherwise CONTINUE to the host kernel, tracking
 * the resulting FD as host-passthrough.  The supervisor opens the file in its
 * own namespace, injects the FD into the tracee via ADDFD, and records it in
 * the FD table.  For /proc/self paths, the supervisor translates to
 * /proc/{pid} so the opened file reflects the tracee, not the supervisor.
 *
 * supervisor_dirfd: AT_FDCWD for absolute paths, or a supervisor-owned copy
 *                   of the tracee's dirfd (caller must close after return).
 */
static struct kbox_dispatch emulate_host_open_tracked(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    int supervisor_dirfd,
    const char *path,
    int host_flags,
    mode_t mode)
{
    char sv_path[KBOX_MAX_PATH];
    pid_t pid = kbox_syscall_request_pid(req);
    translate_proc_self(path, pid, sv_path, sizeof(sv_path));

    int host_fd =
        openat(supervisor_dirfd, sv_path, host_flags & ~O_CLOEXEC, mode);
    if (host_fd < 0)
        return kbox_dispatch_errno(errno);

    uint32_t af = (host_flags & O_CLOEXEC) ? O_CLOEXEC : 0;
    int tracee_fd = request_addfd(ctx, req, host_fd, af);
    close(host_fd);
    if (tracee_fd < 0)
        return kbox_dispatch_errno(-tracee_fd);

    track_host_passthrough_fd(ctx->fd_table, tracee_fd);
    if (host_flags & O_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, tracee_fd, 1);
    return kbox_dispatch_value(tracee_fd);
}

/* forward_openat. */

static struct kbox_dispatch forward_openat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long host_flags_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = host_to_lkl_open_flags(host_flags_raw);
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    if (should_continue_virtual_path(ctx, req, 1, translated) ||
        kbox_is_tty_like_path(translated))
        return emulate_host_open_tracked(ctx, req, AT_FDCWD, translated,
                                         (int) host_flags_raw, (mode_t) mode);

    if (should_continue_for_dirfd(lkl_dirfd)) {
        long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
        int sv_dirfd =
            dup_tracee_fd(kbox_syscall_request_pid(req), (int) raw_dirfd);
        if (sv_dirfd < 0)
            return kbox_dispatch_errno(-sv_dirfd);
        struct kbox_dispatch d =
            emulate_host_open_tracked(ctx, req, sv_dirfd, translated,
                                      (int) host_flags_raw, (mode_t) mode);
        close(sv_dirfd);
        return d;
    }

    {
        struct kbox_dispatch cached_dispatch;
        if (try_cached_shadow_open_dispatch(ctx, req, flags, translated,
                                            &cached_dispatch))
            return cached_dispatch;
    }

    long ret = kbox_lkl_openat(ctx->sysnrs, lkl_dirfd, translated, flags, mode);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC))
        invalidate_path_shadow_cache(ctx);
    return finish_open_dispatch(ctx, req, ret, flags, translated);
}

/* forward_openat2. */

static struct kbox_dispatch forward_openat2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    struct kbox_open_how how;
    rc = guest_mem_read_open_how(ctx, kbox_syscall_request_pid(req),
                                 kbox_syscall_request_arg(req, 2),
                                 kbox_syscall_request_arg(req, 3), &how);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    long host_flags2_raw = (long) how.flags;
    how.flags = (uint64_t) host_to_lkl_open_flags((long) how.flags);

    if (should_continue_virtual_path(ctx, req, 1, translated) ||
        kbox_is_tty_like_path(translated))
        return emulate_host_open_tracked(ctx, req, AT_FDCWD, translated,
                                         (int) host_flags2_raw,
                                         (mode_t) how.mode);

    if (should_continue_for_dirfd(lkl_dirfd)) {
        long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
        int sv_dirfd =
            dup_tracee_fd(kbox_syscall_request_pid(req), (int) raw_dirfd);
        if (sv_dirfd < 0)
            return kbox_dispatch_errno(-sv_dirfd);
        struct kbox_dispatch d =
            emulate_host_open_tracked(ctx, req, sv_dirfd, translated,
                                      (int) host_flags2_raw, (mode_t) how.mode);
        close(sv_dirfd);
        return d;
    }

    if (((long) how.flags & O_ACCMODE) == O_RDONLY) {
        struct kbox_dispatch cached_dispatch;
        if (try_cached_shadow_open_dispatch(ctx, req, (long) how.flags,
                                            translated, &cached_dispatch)) {
            return cached_dispatch;
        }
    }

    long ret = kbox_lkl_openat2(ctx->sysnrs, lkl_dirfd, translated, &how,
                                (long) sizeof(how));
    if (ret == -ENOSYS) {
        if (how.resolve != 0)
            return kbox_dispatch_errno(EOPNOTSUPP);
        ret = kbox_lkl_openat(ctx->sysnrs, lkl_dirfd, translated,
                              (long) how.flags, (long) how.mode);
    }
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    if (((long) how.flags & O_ACCMODE) != O_RDONLY ||
        ((long) how.flags & O_TRUNC)) {
        invalidate_path_shadow_cache(ctx);
    }
    return finish_open_dispatch(ctx, req, ret, (long) how.flags, translated);
}

/* forward_open_legacy (x86_64 open(2), nr=2). */

static struct kbox_dispatch forward_open_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                    sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long host_flags_legacy = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long flags = host_to_lkl_open_flags(host_flags_legacy);
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (should_continue_virtual_path(ctx, req, 0, translated) ||
        kbox_is_tty_like_path(translated))
        return emulate_host_open_tracked(ctx, req, AT_FDCWD, translated,
                                         (int) host_flags_legacy,
                                         (mode_t) mode);

    {
        struct kbox_dispatch cached_dispatch;
        if (try_cached_shadow_open_dispatch(ctx, req, flags, translated,
                                            &cached_dispatch))
            return cached_dispatch;
    }

    long ret =
        kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, translated, flags, mode);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC))
        invalidate_path_shadow_cache(ctx);
    return finish_open_dispatch(ctx, req, ret, flags, translated);
}

int sync_shadow_writeback(struct kbox_supervisor_ctx *ctx,
                          struct kbox_fd_entry *entry)
{
    struct stat st;
    uint8_t *buf = NULL;
    off_t off = 0;

    if (!ctx || !entry || !entry->shadow_writeback || entry->shadow_sp < 0 ||
        entry->lkl_fd < 0)
        return 0;

    if (fstat(entry->shadow_sp, &st) < 0)
        return -errno;
    if (kbox_lkl_ftruncate(ctx->sysnrs, entry->lkl_fd, (long) st.st_size) < 0)
        return -EIO;
    if (lseek(entry->shadow_sp, 0, SEEK_SET) < 0)
        return -errno;

    buf = dispatch_scratch;

    while (off < st.st_size) {
        size_t chunk = KBOX_IO_CHUNK_LEN;
        ssize_t rd;
        long wr;

        if ((off_t) chunk > st.st_size - off)
            chunk = (size_t) (st.st_size - off);
        rd = read(entry->shadow_sp, buf, chunk);
        if (rd < 0)
            return -errno;
        if (rd == 0)
            break;
        wr = kbox_lkl_pwrite64(ctx->sysnrs, entry->lkl_fd, buf, (long) rd,
                               (long) off);
        if (wr < 0)
            return (int) wr;
        off += rd;
    }

    return 0;
}

/* forward_close. */

static struct kbox_dispatch forward_close(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
    int same_fd_shadow = entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW;

    if (lkl_fd >= 0)
        invalidate_stat_cache_fd(ctx, lkl_fd);

    if (entry && entry->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY) {
        /* Host-passthrough FDs (pipes, eventfds, stdio): the host kernel
         * tracks per-process FD lifecycle, so close via CONTINUE is correct.
         * Keep the FD table entry alive because the table is shared across
         * all supervised processes (parent + children after fork).  If the
         * child closes a pipe FD, the entry must remain so the parent (or
         * a sibling) that still holds the same FD number isn't denied.
         * Shadow socket entries (shadow_sp >= 0) hold supervisor resources
         * that must be released, so those are still removed.
         */
        if (entry->shadow_sp >= 0)
            kbox_fd_table_remove(ctx->fd_table, fd);
        return kbox_dispatch_continue();
    }

    if (lkl_fd >= 0) {
        if (same_fd_shadow) {
            if (entry && entry->shadow_writeback)
                (void) sync_shadow_writeback(ctx, entry);
            note_shadow_writeback_close(ctx, entry);
            lkl_close_and_invalidate(ctx, lkl_fd);
            kbox_fd_table_remove(ctx->fd_table, fd);
            return kbox_dispatch_continue();
        }

        long ret = lkl_close_and_invalidate(ctx, lkl_fd);
        if (ret < 0 && fd >= KBOX_FD_BASE)
            return kbox_dispatch_errno((int) (-ret));
        kbox_fd_table_remove(ctx->fd_table, fd);

        /* Low FD redirect (from dup2): close the LKL side above,
         * then CONTINUE so the host kernel also closes its copy of
         * this FD number.
         */
        if (fd < KBOX_LOW_FD_MAX)
            return kbox_dispatch_continue();

        return kbox_dispatch_value(0);
    }

    /* Not a virtual FD.  Check if this is a host FD that was injected
     * as shadow (the tracee closes it by the host number).  If so,
     * close the LKL side and let the host kernel close the host FD
     * via CONTINUE.
     */
    long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
    if (vfd >= 0) {
        struct kbox_fd_entry *shadow_entry = fd_table_entry(ctx->fd_table, vfd);
        long lkl = kbox_fd_table_get_lkl(ctx->fd_table, vfd);

        if (shadow_entry && shadow_entry->shadow_writeback)
            (void) sync_shadow_writeback(ctx, shadow_entry);
        note_shadow_writeback_close(ctx, shadow_entry);
        if (lkl >= 0)
            invalidate_stat_cache_fd(ctx, lkl);
        kbox_fd_table_remove(ctx->fd_table, vfd);

        if (lkl >= 0) {
            /* Only close the LKL socket and deregister from the
             * event loop if no other fd_table entry references the
             * same lkl_fd (handles dup'd shadow sockets).
             */
            int still_ref = 0;
            for (long i = 0; i < KBOX_FD_TABLE_MAX && !still_ref; i++) {
                if (ctx->fd_table->entries[i].lkl_fd == lkl)
                    still_ref = 1;
            }
            for (long i = 0; i < KBOX_MID_FD_MAX && !still_ref; i++) {
                if (ctx->fd_table->mid_fds[i].lkl_fd == lkl)
                    still_ref = 1;
            }
            for (long i = 0; i < KBOX_LOW_FD_MAX && !still_ref; i++) {
                if (ctx->fd_table->low_fds[i].lkl_fd == lkl)
                    still_ref = 1;
            }
            if (!still_ref) {
                kbox_net_deregister_socket((int) lkl);
                lkl_close_and_invalidate(ctx, lkl);
            }
        }
        return kbox_dispatch_continue();
    }

    return kbox_dispatch_continue();
}

/* forward_read_like (read and pread64). */

static struct kbox_dispatch forward_read_like(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int is_pread)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    {
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
        if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
            return kbox_dispatch_continue();
    }
    {
        int shadow_rc = ensure_same_fd_shadow(ctx, req, fd, lkl_fd);
        if (shadow_rc > 0) {
            struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
            if (entry && entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW) {
                return forward_local_shadow_read_like(req, ctx, entry, lkl_fd,
                                                      is_pread);
            }
            return kbox_dispatch_continue();
        }
    }

    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count == 0)
        return kbox_dispatch_value(0);

    pid_t pid = kbox_syscall_request_pid(req);
    size_t max_count = 1024 * 1024;
    if (count > max_count)
        count = max_count;

    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        if (chunk_len > count - total)
            chunk_len = count - total;

        long ret;
        if (is_pread) {
            long offset = to_c_long_arg(kbox_syscall_request_arg(req, 3));
            ret = kbox_lkl_pread64(ctx->sysnrs, lkl_fd, scratch,
                                   (long) chunk_len, offset + (long) total);
        } else {
            ret = kbox_lkl_read(ctx->sysnrs, lkl_fd, scratch, (long) chunk_len);
        }

        if (ret < 0) {
            if (total == 0) {
                return kbox_dispatch_errno((int) (-ret));
            }
            break;
        }

        size_t n = (size_t) ret;
        if (n == 0)
            break;

        uint64_t remote = remote_buf + total;
        if (ctx->verbose) {
            fprintf(
                stderr,
                "kbox: %s fd=%ld lkl_fd=%ld remote=0x%llx chunk=%zu ret=%ld\n",
                is_pread ? "pread64" : "read", fd, lkl_fd,
                (unsigned long long) remote, chunk_len, ret);
        }
        int wrc = guest_mem_write(ctx, pid, remote, scratch, n);
        if (wrc < 0) {
            return kbox_dispatch_errno(-wrc);
        }

        total += n;
        if (n < chunk_len)
            break;
    }

    return kbox_dispatch_value((int64_t) total);
}

/* forward_write. */

static struct kbox_dispatch forward_write(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
        return kbox_dispatch_continue();

    invalidate_stat_cache_fd(ctx, lkl_fd);

    int mirror_host = kbox_fd_table_mirror_tty(ctx->fd_table, fd);

    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count == 0)
        return kbox_dispatch_value(0);

    pid_t pid = kbox_syscall_request_pid(req);
    size_t max_count = 1024 * 1024;
    if (count > max_count)
        count = max_count;

    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        if (chunk_len > count - total)
            chunk_len = count - total;

        uint64_t remote = remote_buf + total;
        int rrc = guest_mem_read(ctx, pid, remote, scratch, chunk_len);
        if (rrc < 0) {
            if (total > 0)
                break;
            return kbox_dispatch_errno(-rrc);
        }

        long ret =
            kbox_lkl_write(ctx->sysnrs, lkl_fd, scratch, (long) chunk_len);
        if (ret < 0) {
            if (total == 0) {
                return kbox_dispatch_errno((int) (-ret));
            }
            break;
        }

        size_t n = (size_t) ret;

        /* Mirror to host stdout if this is a TTY fd.  The guest fd
         * is a virtual number (4096+) that does not exist on the
         * host side, so we write to stdout instead.
         */
        if (mirror_host && n > 0) {
            ssize_t written = write(STDOUT_FILENO, scratch, n);
            (void) written;
        }

        total += n;
        if (n < chunk_len)
            break;
    }

    if (total > 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_value((int64_t) total);
}

/* forward_sendfile. */

/* Emulate sendfile(out_fd, in_fd, *offset, count).
 *
 * If both FDs are host-visible (shadow memfds, stdio, or other host FDs
 * not in the virtual table), let the host kernel handle it via CONTINUE.
 * Otherwise, emulate via LKL read + host/LKL write.
 *
 * busybox cat uses sendfile and some builds loop on ENOSYS instead of
 * falling back to read+write, so returning ENOSYS is not viable.
 */
static struct kbox_dispatch forward_sendfile(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long out_fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long in_fd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    uint64_t offset_ptr = kbox_syscall_request_arg(req, 2);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    long in_lkl = kbox_fd_table_get_lkl(ctx->fd_table, in_fd);
    long out_lkl = kbox_fd_table_get_lkl(ctx->fd_table, out_fd);

    /* Resolve shadow FDs: if in_fd is a host FD injected via ADDFD (shadow
     * memfd), find_by_host_fd locates the virtual entry that holds the LKL
     * FD for the same file.
     */
    if (in_lkl < 0) {
        long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, in_fd);
        if (vfd >= 0)
            in_lkl = kbox_fd_table_get_lkl(ctx->fd_table, vfd);
    }
    if (out_lkl < 0) {
        long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, out_fd);
        if (vfd >= 0)
            out_lkl = kbox_fd_table_get_lkl(ctx->fd_table, vfd);
    }

    /* Both FDs have no LKL backing: the host kernel handles sendfile
     * if both are known host FDs. Deny if either is in a denied range.
     */
    if (in_lkl < 0 && out_lkl < 0) {
        if (fd_should_deny_io(in_fd, in_lkl) ||
            fd_should_deny_io(out_fd, out_lkl))
            return kbox_dispatch_errno(EBADF);
        return kbox_dispatch_continue();
    }

    /* At least one FD is virtual/LKL-backed: emulate via read + write.
     * Source must have an LKL FD for emulation; host-passthrough sources
     * cannot be read via LKL.
     */
    if (in_lkl < 0)
        return kbox_dispatch_errno(EBADF);

    if (count_raw <= 0)
        return kbox_dispatch_value(0);
    size_t count = (size_t) count_raw;
    if (count > 1024 * 1024)
        count = 1024 * 1024;

    /* Read optional offset from tracee memory. */
    pid_t pid = kbox_syscall_request_pid(req);
    off_t offset = 0;
    int has_offset = (offset_ptr != 0);
    if (has_offset) {
        int rc = guest_mem_read(ctx, pid, offset_ptr, &offset, sizeof(offset));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
    }

    uint8_t *scratch = dispatch_scratch;

    size_t total = 0;

    while (total < count) {
        size_t chunk = KBOX_IO_CHUNK_LEN;
        if (chunk > count - total)
            chunk = count - total;

        /* Read from source (LKL fd). */
        long nr;
        if (has_offset)
            nr = kbox_lkl_pread64(ctx->sysnrs, in_lkl, scratch, (long) chunk,
                                  offset + (long) total);
        else
            nr = kbox_lkl_read(ctx->sysnrs, in_lkl, scratch, (long) chunk);

        if (nr < 0) {
            if (total == 0) {
                return kbox_dispatch_errno((int) (-nr));
            }
            break;
        }
        if (nr == 0)
            break;

        size_t n = (size_t) nr;

        /* Write to destination. */
        if (out_lkl >= 0) {
            long wr = kbox_lkl_write(ctx->sysnrs, out_lkl, scratch, (long) n);
            if (wr < 0) {
                if (total == 0) {
                    return kbox_dispatch_errno((int) (-wr));
                }
                break;
            }
        } else {
            /* Destination is a host FD (e.g. stdout).  The supervisor
             * shares the FD table with the tracee (from fork), so write()
             * goes to the same file description.
             */
            ssize_t wr = write((int) out_fd, scratch, n);
            if (wr < 0) {
                if (total == 0) {
                    return kbox_dispatch_errno(errno);
                }
                break;
            }
        }

        total += n;
        if (n < chunk)
            break;
    }

    /* Update offset in tracee memory if provided. */
    if (has_offset && total > 0) {
        off_t new_off = offset + (off_t) total;
        guest_mem_write(ctx, pid, offset_ptr, &new_off, sizeof(new_off));
    }

    return kbox_dispatch_value((int64_t) total);
}

/* forward_lseek. */

static struct kbox_dispatch forward_lseek(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    {
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
        if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
            return kbox_dispatch_continue();
    }
    {
        int shadow_rc = ensure_same_fd_shadow(ctx, req, fd, lkl_fd);
        if (shadow_rc > 0) {
            struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
            if (entry && entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW)
                return forward_local_shadow_lseek(req, ctx, entry, lkl_fd);
            return kbox_dispatch_continue();
        }
    }

    long off = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long whence = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long ret = kbox_lkl_lseek(ctx->sysnrs, lkl_fd, off, whence);
    if (ctx->verbose) {
        fprintf(stderr,
                "kbox: lseek fd=%ld lkl_fd=%ld off=%ld whence=%ld ret=%ld\n",
                fd, lkl_fd, off, whence, ret);
    }
    return kbox_dispatch_from_lkl(ret);
}

static int find_available_tracee_fd(pid_t pid, int minfd);
static void cleanup_replaced_fd_tracking(struct kbox_supervisor_ctx *ctx,
                                         long fd);

/* forward_fcntl. */

static struct kbox_dispatch forward_fcntl(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY) {
        long pt_cmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
        if (pt_cmd == F_DUPFD || pt_cmd == F_DUPFD_CLOEXEC) {
            /* Emulate F_DUPFD on host-passthrough FD: get a supervisor copy
             * via pidfd_getfd, inject at the first free tracee FD >= minfd,
             * and track the result.
             */
            long minfd = to_c_long_arg(kbox_syscall_request_arg(req, 2));
            uint32_t af = (pt_cmd == F_DUPFD_CLOEXEC) ? O_CLOEXEC : 0;
            int target_fd;

            if (minfd < 0)
                return kbox_dispatch_errno(EINVAL);
            target_fd = find_available_tracee_fd(kbox_syscall_request_pid(req),
                                                 (int) minfd);
            if (target_fd < 0)
                return kbox_dispatch_errno(-target_fd);

            int copy = dup_tracee_fd(kbox_syscall_request_pid(req), (int) fd);
            if (copy < 0)
                return kbox_dispatch_errno(-copy);
            int tracee_new = request_addfd_at(ctx, req, copy, target_fd, af);
            close(copy);
            if (tracee_new < 0)
                return kbox_dispatch_errno(-tracee_new);
            track_host_passthrough_fd(ctx->fd_table, tracee_new);
            if (pt_cmd == F_DUPFD_CLOEXEC)
                kbox_fd_table_set_cloexec(ctx->fd_table, tracee_new, 1);
            return kbox_dispatch_value(tracee_new);
        }
        if (pt_cmd == F_SETFD) {
            long carg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
            kbox_fd_table_set_cloexec(ctx->fd_table, fd,
                                      (carg & FD_CLOEXEC) ? 1 : 0);
        }
        return kbox_dispatch_continue();
    }

    if (lkl_fd < 0) {
        /* Shadow socket: handle F_DUPFD* and F_SETFL. */
        long svfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
        if (svfd >= 0) {
            long scmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
            if (scmd == F_DUPFD || scmd == F_DUPFD_CLOEXEC) {
                long minfd = to_c_long_arg(kbox_syscall_request_arg(req, 2));
                /* When minfd > 0, skip ADDFD (can't honor the minimum)
                 * and let CONTINUE handle it correctly.  The dup is
                 * untracked but no FD leaks.
                 */
                struct kbox_fd_entry *orig = NULL;
                if (minfd > 0)
                    goto fcntl_shadow_continue;
                orig = fd_table_entry(ctx->fd_table, svfd);
                if (orig && orig->shadow_sp >= 0) {
                    uint32_t af = (scmd == F_DUPFD_CLOEXEC) ? O_CLOEXEC : 0;
                    int nh = request_addfd(ctx, req, orig->shadow_sp, af);
                    if (nh >= 0) {
                        long nv = kbox_fd_table_insert(ctx->fd_table,
                                                       orig->lkl_fd, 0);
                        if (nv < 0)
                            return kbox_dispatch_errno(EMFILE);
                        kbox_fd_table_set_host_fd(ctx->fd_table, nv, nh);
                        /* Clear stale SHADOW_ONLY at the ADDFD-allocated FD
                         * so resolve_lkl_socket finds the shadow socket.
                         */
                        {
                            struct kbox_fd_entry *stale =
                                fd_table_entry(ctx->fd_table, nh);
                            if (stale && nh != nv &&
                                stale->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
                                kbox_fd_table_remove(ctx->fd_table, nh);
                        }
                        int ns = dup(orig->shadow_sp);
                        if (ns >= 0) {
                            struct kbox_fd_entry *ne = NULL;
                            ne = fd_table_entry(ctx->fd_table, nv);
                            if (ne) {
                                ne->shadow_sp = ns;
                                if (scmd == F_DUPFD_CLOEXEC)
                                    ne->cloexec = 1;
                            } else {
                                close(ns);
                            }
                        }
                        return kbox_dispatch_value((int64_t) nh);
                    }
                }
            }
            if (scmd == F_SETFL) {
                long sarg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
                long slkl = kbox_fd_table_get_lkl(ctx->fd_table, svfd);
                if (slkl >= 0)
                    kbox_lkl_fcntl(ctx->sysnrs, slkl, F_SETFL, sarg);
            }
            if (scmd == F_SETFD) {
                /* Keep fd-table cloexec in sync with host kernel. */
                long sarg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
                kbox_fd_table_set_cloexec(ctx->fd_table, svfd,
                                          (sarg & FD_CLOEXEC) ? 1 : 0);
            }
            goto fcntl_shadow_continue;
        }
        if (!fd_should_deny_io(fd, lkl_fd))
            goto fcntl_shadow_continue;
        return kbox_dispatch_errno(EBADF);
    fcntl_shadow_continue:
        return kbox_dispatch_continue();
    }

    long cmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long arg = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        long ret = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, cmd, arg);
        if (ret < 0)
            return kbox_dispatch_errno((int) (-ret));

        int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, fd);
        long new_vfd = kbox_fd_table_insert(ctx->fd_table, ret, mirror);
        if (new_vfd < 0) {
            lkl_close_and_invalidate(ctx, ret);
            return kbox_dispatch_errno(EMFILE);
        }
        if (cmd == F_DUPFD_CLOEXEC)
            kbox_fd_table_set_cloexec(ctx->fd_table, new_vfd, 1);
        return kbox_dispatch_value((int64_t) new_vfd);
    }

    /* F_SETFL: translate host open flags to LKL before forwarding. */
    if (cmd == F_SETFL)
        arg = host_to_lkl_open_flags(arg);

    long ret = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, cmd, arg);

    /* F_GETFL: translate LKL open flags back to host before returning. */
    if (cmd == F_GETFL && ret >= 0)
        ret = lkl_to_host_open_flags(ret);

    return kbox_dispatch_from_lkl(ret);
}

/* Obtain a supervisor-side copy of a tracee FD that shares the same file
 * description.  Uses pidfd_getfd (Linux 5.6+) which preserves the file
 * description identity (same position, flags, etc.) -- unlike
 * open(/proc/pid/fd/N) which creates a new description.
 * Returns a supervisor FD on success, -errno on failure.
 */
int dup_tracee_fd(pid_t pid, int tracee_fd)
{
    int pidfd = (int) syscall(__NR_pidfd_open, (int) pid, (unsigned int) 0);
    if (pidfd < 0)
        return -errno;
    int copy = (int) syscall(__NR_pidfd_getfd, pidfd, (unsigned int) tracee_fd,
                             (unsigned int) 0);
    int saved_errno = errno;
    close(pidfd);
    if (copy < 0)
        return -saved_errno;
    return copy;
}

static int find_available_tracee_fd(pid_t pid, int minfd)
{
    const int limit = 65536;
    int pidfd;

    if (minfd < 0)
        return -EINVAL;
    if (minfd >= limit)
        return -EINVAL;

    pidfd = (int) syscall(__NR_pidfd_open, (int) pid, (unsigned int) 0);
    if (pidfd < 0)
        return -errno;

    for (int candidate = minfd; candidate < limit; candidate++) {
        int probe = (int) syscall(__NR_pidfd_getfd, pidfd,
                                  (unsigned int) candidate, (unsigned int) 0);
        if (probe >= 0) {
            close(probe);
            continue;
        }
        if (errno == EBADF) {
            close(pidfd);
            return candidate;
        }
        {
            int saved_errno = errno;
            close(pidfd);
            return -saved_errno;
        }
    }

    close(pidfd);
    return -EMFILE;
}

static void cleanup_replaced_fd_tracking(struct kbox_supervisor_ctx *ctx,
                                         long fd)
{
    long stale_lkl;
    long shadow_vfd;

    if (!ctx || !ctx->fd_table)
        return;

    stale_lkl = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (stale_lkl >= 0) {
        lkl_close_and_invalidate(ctx, stale_lkl);
        kbox_fd_table_remove(ctx->fd_table, fd);
    } else if (stale_lkl == KBOX_LKL_FD_SHADOW_ONLY) {
        kbox_fd_table_remove(ctx->fd_table, fd);
    }

    shadow_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
    if (shadow_vfd >= 0) {
        long shadow_lkl = kbox_fd_table_get_lkl(ctx->fd_table, shadow_vfd);
        kbox_fd_table_remove(ctx->fd_table, shadow_vfd);
        if (shadow_lkl >= 0) {
            int ref = 0;
            for (long j = 0; j < KBOX_FD_TABLE_MAX && !ref; j++)
                if (ctx->fd_table->entries[j].lkl_fd == shadow_lkl)
                    ref = 1;
            for (long j = 0; j < KBOX_MID_FD_MAX && !ref; j++)
                if (ctx->fd_table->mid_fds[j].lkl_fd == shadow_lkl)
                    ref = 1;
            for (long j = 0; j < KBOX_LOW_FD_MAX && !ref; j++)
                if (ctx->fd_table->low_fds[j].lkl_fd == shadow_lkl)
                    ref = 1;
            if (!ref) {
                kbox_net_deregister_socket((int) shadow_lkl);
                lkl_close_and_invalidate(ctx, shadow_lkl);
            }
        }
    }
}

/* forward_dup. */

static struct kbox_dispatch forward_dup(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY) {
        /* Emulate dup on a host-passthrough FD (pipe, stdio, eventfd, etc.)
         * by obtaining a supervisor copy via pidfd_getfd, injecting it into
         * the tracee via ADDFD, and tracking the result.
         */
        int copy = dup_tracee_fd(kbox_syscall_request_pid(req), (int) fd);
        if (copy < 0)
            return kbox_dispatch_errno(-copy);
        int tracee_fd = request_addfd(ctx, req, copy, 0);
        close(copy);
        if (tracee_fd < 0)
            return kbox_dispatch_errno(-tracee_fd);
        track_host_passthrough_fd(ctx->fd_table, tracee_fd);
        return kbox_dispatch_value(tracee_fd);
    }

    if (lkl_fd < 0) {
        /* Check for shadow socket (tracee holds host_fd from ADDFD). */
        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
        if (orig_vfd < 0) {
            if (!fd_should_deny_io(fd, lkl_fd))
                return kbox_dispatch_continue();
            return kbox_dispatch_errno(EBADF);
        }

        /* Shadow socket dup: inject a new copy of the socketpair end into
         * the tracee and track the new host_fd.
         */
        struct kbox_fd_entry *orig = NULL;
        orig = fd_table_entry(ctx->fd_table, orig_vfd);
        if (!orig || orig->shadow_sp < 0)
            return kbox_dispatch_continue();

        long orig_lkl = orig->lkl_fd;
        int new_host = request_addfd(ctx, req, orig->shadow_sp, 0);
        if (new_host < 0)
            return kbox_dispatch_errno(-new_host);

        long new_vfd = kbox_fd_table_insert(ctx->fd_table, orig_lkl, 0);
        if (new_vfd < 0) {
            /* Can't track the FD; return error.  The tracee already has
             * the FD via ADDFD which we can't revoke, but returning
             * EMFILE tells the caller dup failed so it won't use it.
             */
            return kbox_dispatch_errno(EMFILE);
        }
        kbox_fd_table_set_host_fd(ctx->fd_table, new_vfd, new_host);
        {
            struct kbox_fd_entry *stale =
                fd_table_entry(ctx->fd_table, new_host);
            if (stale && new_host != new_vfd &&
                stale->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
                kbox_fd_table_remove(ctx->fd_table, new_host);
        }

        /* Propagate shadow_sp so chained dups work. */
        int new_sp = dup(orig->shadow_sp);
        if (new_sp >= 0) {
            struct kbox_fd_entry *ne = fd_table_entry(ctx->fd_table, new_vfd);
            if (ne)
                ne->shadow_sp = new_sp;
            else
                close(new_sp);
        }
        return kbox_dispatch_value((int64_t) new_host);
    }

    long ret = kbox_lkl_dup(ctx->sysnrs, lkl_fd);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, fd);
    long new_vfd = kbox_fd_table_insert(ctx->fd_table, ret, mirror);
    if (new_vfd < 0) {
        lkl_close_and_invalidate(ctx, ret);
        return kbox_dispatch_errno(EMFILE);
    }
    return kbox_dispatch_value((int64_t) new_vfd);
}

/* forward_dup2. */

static struct kbox_dispatch forward_dup2(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    long oldfd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long newfd = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    long lkl_old = kbox_fd_table_get_lkl(ctx->fd_table, oldfd);

    if (lkl_old == KBOX_LKL_FD_SHADOW_ONLY) {
        /* Emulate dup2 on a host-passthrough FD. Use pidfd_getfd to get
         * a supervisor copy sharing the same file description, then inject
         * at the target FD via ADDFD_AT.
         */
        if (oldfd == newfd)
            return kbox_dispatch_value((int64_t) newfd);
        int copy = dup_tracee_fd(kbox_syscall_request_pid(req), (int) oldfd);
        if (copy < 0)
            return kbox_dispatch_errno(-copy);
        int injected = request_addfd_at(ctx, req, copy, (int) newfd, 0);
        close(copy);
        if (injected < 0)
            return kbox_dispatch_errno(-injected);
        cleanup_replaced_fd_tracking(ctx, newfd);
        track_host_passthrough_fd(ctx->fd_table, newfd);
        return kbox_dispatch_value((int64_t) newfd);
    }

    if (lkl_old < 0) {
        /* Shadow socket dup2: dup2(fd, fd) must return fd unchanged. */
        if (oldfd == newfd)
            return kbox_dispatch_value((int64_t) newfd);

        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd);
        if (orig_vfd >= 0) {
            struct kbox_fd_entry *orig =
                fd_table_entry(ctx->fd_table, orig_vfd);
            if (orig && orig->shadow_sp >= 0) {
                int new_host =
                    request_addfd_at(ctx, req, orig->shadow_sp, (int) newfd, 0);
                if (new_host >= 0) {
                    /* Remove any stale mapping at newfd (virtual or shadow). */
                    long stale = kbox_fd_table_get_lkl(ctx->fd_table, newfd);
                    if (stale >= 0) {
                        lkl_close_and_invalidate(ctx, stale);
                        kbox_fd_table_remove(ctx->fd_table, newfd);
                    } else {
                        long sv =
                            kbox_fd_table_find_by_host_fd(ctx->fd_table, newfd);
                        if (sv >= 0) {
                            long sl = kbox_fd_table_get_lkl(ctx->fd_table, sv);
                            kbox_fd_table_remove(ctx->fd_table, sv);
                            if (sl >= 0) {
                                int ref = 0;
                                for (long j = 0; j < KBOX_FD_TABLE_MAX; j++)
                                    if (ctx->fd_table->entries[j].lkl_fd == sl)
                                        ref = 1;
                                for (long j = 0; j < KBOX_MID_FD_MAX && !ref;
                                     j++)
                                    if (ctx->fd_table->mid_fds[j].lkl_fd == sl)
                                        ref = 1;
                                for (long j = 0; j < KBOX_LOW_FD_MAX && !ref;
                                     j++)
                                    if (ctx->fd_table->low_fds[j].lkl_fd == sl)
                                        ref = 1;
                                if (!ref) {
                                    kbox_net_deregister_socket((int) sl);
                                    lkl_close_and_invalidate(ctx, sl);
                                }
                            }
                        }
                    }
                    long nv =
                        kbox_fd_table_insert(ctx->fd_table, orig->lkl_fd, 0);
                    if (nv < 0)
                        return kbox_dispatch_errno(EMFILE);
                    kbox_fd_table_set_host_fd(ctx->fd_table, nv, new_host);
                    int ns = dup(orig->shadow_sp);
                    if (ns >= 0) {
                        struct kbox_fd_entry *ne2 = NULL;
                        ne2 = fd_table_entry(ctx->fd_table, nv);
                        if (ne2)
                            ne2->shadow_sp = ns;
                        else
                            close(ns);
                    }
                    return kbox_dispatch_value((int64_t) newfd);
                }
            }
        }
        if (!fd_should_deny_io(oldfd, lkl_old)) {
            cleanup_replaced_fd_tracking(ctx, newfd);
            return kbox_dispatch_continue();
        }
        return kbox_dispatch_errno(EBADF);
    }

    if (oldfd == newfd)
        return kbox_dispatch_value((int64_t) newfd);

    /* Dup first, then close the old mapping.  This preserves the old newfd
     * if the dup fails (e.g. EMFILE), matching dup2 atomicity semantics.
     */
    long ret = kbox_lkl_dup(ctx->sysnrs, lkl_old);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long existing = kbox_fd_table_remove(ctx->fd_table, newfd);
    if (existing >= 0)
        lkl_close_and_invalidate(ctx, existing);

    int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, oldfd);
    if (kbox_fd_table_insert_at(ctx->fd_table, newfd, ret, mirror) < 0) {
        lkl_close_and_invalidate(ctx, ret);
        return kbox_dispatch_errno(EBADF);
    }
    return kbox_dispatch_value((int64_t) newfd);
}

/* forward_dup3. */

static struct kbox_dispatch forward_dup3(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    long oldfd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long newfd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    /* dup3 only accepts O_CLOEXEC; reject anything else per POSIX. */
    if (flags & ~((long) O_CLOEXEC))
        return kbox_dispatch_errno(EINVAL);

    long lkl_old = kbox_fd_table_get_lkl(ctx->fd_table, oldfd);

    if (lkl_old == KBOX_LKL_FD_SHADOW_ONLY) {
        if (oldfd == newfd)
            return kbox_dispatch_errno(EINVAL);
        uint32_t af = (flags & O_CLOEXEC) ? O_CLOEXEC : 0;
        int copy = dup_tracee_fd(kbox_syscall_request_pid(req), (int) oldfd);
        if (copy < 0)
            return kbox_dispatch_errno(-copy);
        int injected = request_addfd_at(ctx, req, copy, (int) newfd, af);
        close(copy);
        if (injected < 0)
            return kbox_dispatch_errno(-injected);
        cleanup_replaced_fd_tracking(ctx, newfd);
        track_host_passthrough_fd(ctx->fd_table, newfd);
        if (flags & O_CLOEXEC)
            kbox_fd_table_set_cloexec(ctx->fd_table, newfd, 1);
        return kbox_dispatch_value((int64_t) newfd);
    }

    if (lkl_old < 0) {
        /* Shadow socket dup3: dup3(fd, fd, ...) must return EINVAL. */
        if (oldfd == newfd) {
            if (kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd) >= 0)
                return kbox_dispatch_errno(EINVAL);
        }

        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd);
        if (orig_vfd >= 0) {
            struct kbox_fd_entry *orig =
                fd_table_entry(ctx->fd_table, orig_vfd);
            if (orig && orig->shadow_sp >= 0) {
                uint32_t af = (flags & O_CLOEXEC) ? O_CLOEXEC : 0;
                int new_host = request_addfd_at(ctx, req, orig->shadow_sp,
                                                (int) newfd, af);
                if (new_host >= 0) {
                    /* Remove stale mapping at newfd (virtual or shadow). */
                    long stale3 = kbox_fd_table_get_lkl(ctx->fd_table, newfd);
                    if (stale3 >= 0) {
                        lkl_close_and_invalidate(ctx, stale3);
                        kbox_fd_table_remove(ctx->fd_table, newfd);
                    } else {
                        long sv3 =
                            kbox_fd_table_find_by_host_fd(ctx->fd_table, newfd);
                        if (sv3 >= 0) {
                            long sl3 =
                                kbox_fd_table_get_lkl(ctx->fd_table, sv3);
                            kbox_fd_table_remove(ctx->fd_table, sv3);
                            if (sl3 >= 0) {
                                int r3 = 0;
                                for (long j = 0; j < KBOX_FD_TABLE_MAX; j++)
                                    if (ctx->fd_table->entries[j].lkl_fd == sl3)
                                        r3 = 1;
                                for (long j = 0; j < KBOX_MID_FD_MAX && !r3;
                                     j++)
                                    if (ctx->fd_table->mid_fds[j].lkl_fd == sl3)
                                        r3 = 1;
                                for (long j = 0; j < KBOX_LOW_FD_MAX && !r3;
                                     j++)
                                    if (ctx->fd_table->low_fds[j].lkl_fd == sl3)
                                        r3 = 1;
                                if (!r3) {
                                    kbox_net_deregister_socket((int) sl3);
                                    lkl_close_and_invalidate(ctx, sl3);
                                }
                            }
                        }
                    }
                    long nv =
                        kbox_fd_table_insert(ctx->fd_table, orig->lkl_fd, 0);
                    if (nv < 0)
                        return kbox_dispatch_errno(EMFILE);
                    kbox_fd_table_set_host_fd(ctx->fd_table, nv, new_host);
                    int ns3 = dup(orig->shadow_sp);
                    if (ns3 >= 0) {
                        struct kbox_fd_entry *ne3 = NULL;
                        ne3 = fd_table_entry(ctx->fd_table, nv);
                        if (ne3) {
                            ne3->shadow_sp = ns3;
                            if (flags & O_CLOEXEC)
                                ne3->cloexec = 1;
                        } else {
                            close(ns3);
                        }
                    }
                    return kbox_dispatch_value((int64_t) newfd);
                }
            }
        }
        if (!fd_should_deny_io(oldfd, lkl_old)) {
            cleanup_replaced_fd_tracking(ctx, newfd);
            return kbox_dispatch_continue();
        }
        return kbox_dispatch_errno(EBADF);
    }

    if (oldfd == newfd)
        return kbox_dispatch_errno(EINVAL);

    long ret = kbox_lkl_dup(ctx->sysnrs, lkl_old);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long existing = kbox_fd_table_remove(ctx->fd_table, newfd);
    if (existing >= 0)
        lkl_close_and_invalidate(ctx, existing);

    int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, oldfd);
    if (kbox_fd_table_insert_at(ctx->fd_table, newfd, ret, mirror) < 0) {
        lkl_close_and_invalidate(ctx, ret);
        return kbox_dispatch_errno(EBADF);
    }
    if (flags & O_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, newfd, 1);
    return kbox_dispatch_value((int64_t) newfd);
}

/* forward_fstat. */

static struct kbox_dispatch forward_fstat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    /* If a shadow already exists (from a prior mmap), let the host handle
     * fstat against the memfd.  Do NOT create a shadow here; fstat is a
     * metadata query that LKL answers directly without the expensive
     * memfd_create + pread loop.
     */
    {
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
        if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
            return kbox_dispatch_continue();
        if (entry && entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW)
            return forward_local_shadow_fstat(req, ctx, entry);
    }

    uint64_t remote_stat = kbox_syscall_request_arg(req, 1);
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Check the stat cache first to avoid an LKL round-trip. */
#if KBOX_STAT_CACHE_ENABLED
    for (int ci = 0; ci < KBOX_STAT_CACHE_MAX; ci++) {
        if (ctx->stat_cache[ci].lkl_fd == lkl_fd) {
            int wrc = guest_mem_write_small_metadata(
                ctx, kbox_syscall_request_pid(req), remote_stat,
                &ctx->stat_cache[ci].st, sizeof(ctx->stat_cache[ci].st));
            if (wrc < 0)
                return kbox_dispatch_errno(-wrc);
            return kbox_dispatch_value(0);
        }
    }
#endif

    struct kbox_lkl_stat kst;
    memset(&kst, 0, sizeof(kst));
    long ret = kbox_lkl_fstat(ctx->sysnrs, lkl_fd, &kst);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    struct stat host_stat;
    kbox_lkl_stat_to_host(&kst, &host_stat);

    /* Insert into stat cache (overwrite oldest slot via round-robin). */
#if KBOX_STAT_CACHE_ENABLED
    {
        static unsigned stat_cache_rr;
        unsigned slot = stat_cache_rr % KBOX_STAT_CACHE_MAX;
        stat_cache_rr++;
        ctx->stat_cache[slot].lkl_fd = lkl_fd;
        ctx->stat_cache[slot].st = host_stat;
    }
#endif

    int wrc = guest_mem_write_small_metadata(ctx, kbox_syscall_request_pid(req),
                                             remote_stat, &host_stat,
                                             sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* forward_newfstatat. */

static struct kbox_dispatch forward_newfstatat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    uint64_t remote_stat = kbox_syscall_request_arg(req, 2);
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    /* Host dirfd or virtual path: call host fstatat with a local path copy
     * to eliminate the TOCTOU window where a sibling thread could swap the
     * path between validation and the kernel re-read.
     */
    if (should_continue_for_dirfd(lkl_dirfd) ||
        should_continue_virtual_path(ctx, req, 1, translated)) {
        char sv_path[KBOX_MAX_PATH];
        int sv_dirfd = AT_FDCWD;
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        if (should_continue_for_dirfd(lkl_dirfd)) {
            long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
            sv_dirfd = dup_tracee_fd(pid, (int) raw_dirfd);
            if (sv_dirfd < 0)
                return kbox_dispatch_errno(-sv_dirfd);
        }
        struct stat host_stat;
        int host_rc = fstatat(sv_dirfd, sv_path, &host_stat, (int) flags);
        int saved = errno;
        if (sv_dirfd != AT_FDCWD)
            close(sv_dirfd);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        normalize_host_stat_if_needed(ctx, translated, &host_stat);
        int wrc = guest_mem_write_small_metadata(ctx, pid, remote_stat,
                                                 &host_stat, sizeof(host_stat));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
        return kbox_dispatch_value(0);
    }

    if (translated[0] != '\0' &&
        try_cached_shadow_stat_dispatch(ctx, translated, remote_stat, pid)) {
        return kbox_dispatch_value(0);
    }

    struct kbox_lkl_stat kst;
    memset(&kst, 0, sizeof(kst));

    long ret;
    if (translated[0] == '\0' && (flags & AT_EMPTY_PATH))
        ret = kbox_lkl_fstat(ctx->sysnrs, lkl_dirfd, &kst);
    else
        ret = kbox_lkl_newfstatat(ctx->sysnrs, lkl_dirfd, translated, &kst,
                                  flags);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    struct stat host_stat;
    kbox_lkl_stat_to_host(&kst, &host_stat);
    normalize_host_stat_if_needed(ctx, translated, &host_stat);

    int wrc = guest_mem_write_small_metadata(ctx, pid, remote_stat, &host_stat,
                                             sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* Guest-thread local fast-path.  Handles syscalls that never touch LKL and
 * can be resolved on the calling thread without a service-thread round-trip.
 * Returns 1 if handled (result in *out), 0 if the caller must use the service
 * thread.  Safe to call from the SIGSYS handler or rewrite trampoline context.
 *
 * Three tiers:
 *   1. Pure emulation: cached constant values (getpid, getppid, gettid).
 *   2. Always-CONTINUE: host kernel handles the syscall unmodified.
 *   3. Conditional emulation: e.g. arch_prctl(SET_FS) in trap/rewrite.
 *
 * LKL-touching syscalls (stat, openat, read on LKL FDs, etc.) are NOT
 * handled here; they MUST go through the service thread.
 */
int kbox_dispatch_try_local_fast_path(const struct kbox_host_nrs *h,
                                      int nr,
                                      struct kbox_dispatch *out)
{
    if (!h || !out)
        return 0;

    /* Tier 1: pure emulation. */
    if (nr == h->getpid) {
        *out = kbox_dispatch_value(1);
        return 1;
    }
    if (nr == h->getppid) {
        *out = kbox_dispatch_value(0);
        return 1;
    }
    if (nr == h->gettid) {
        *out = kbox_dispatch_value(1);
        return 1;
    }

    /* Tier 2: always-CONTINUE; host kernel handles these directly. */
    if (nr == h->brk || nr == h->futex || nr == h->rseq ||
        nr == h->set_tid_address || nr == h->set_robust_list ||
        nr == h->munmap || nr == h->mremap || nr == h->membarrier ||
        nr == h->madvise || nr == h->wait4 || nr == h->waitid ||
        nr == h->exit || nr == h->exit_group || nr == h->rt_sigreturn ||
        nr == h->rt_sigaltstack || nr == h->setitimer || nr == h->getitimer ||
        nr == h->setpgid || nr == h->getpgid || nr == h->getsid ||
        nr == h->setsid || nr == h->fork || nr == h->vfork ||
        nr == h->sched_yield || nr == h->sched_setparam ||
        nr == h->sched_getparam || nr == h->sched_setscheduler ||
        nr == h->sched_getscheduler || nr == h->sched_get_priority_max ||
        nr == h->sched_get_priority_min || nr == h->sched_setaffinity ||
        nr == h->sched_getaffinity || nr == h->getrlimit ||
        nr == h->getrusage || nr == h->ppoll || nr == h->pselect6 ||
        nr == h->poll || nr == h->nanosleep || nr == h->clock_nanosleep ||
        nr == h->statfs || nr == h->sysinfo) {
        *out = kbox_dispatch_continue();
        return 1;
    }

    return 0;
}

/* forward_statx. */

static struct kbox_dispatch forward_statx(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    int flags = (int) to_c_long_arg(kbox_syscall_request_arg(req, 2));
    unsigned mask = (unsigned) to_c_long_arg(kbox_syscall_request_arg(req, 3));
    uint64_t remote_statx = kbox_syscall_request_arg(req, 4);
    if (remote_statx == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Host dirfd or virtual path: call host statx with a local path copy. */
    if (should_continue_for_dirfd(lkl_dirfd) ||
        should_continue_virtual_path(ctx, req, 1, translated)) {
        char sv_path[KBOX_MAX_PATH];
        int sv_dirfd = AT_FDCWD;
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        if (should_continue_for_dirfd(lkl_dirfd)) {
            long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
            sv_dirfd = dup_tracee_fd(pid, (int) raw_dirfd);
            if (sv_dirfd < 0)
                return kbox_dispatch_errno(-sv_dirfd);
        }
        uint8_t statx_buf[STATX_BUF_SIZE];
        memset(statx_buf, 0, sizeof(statx_buf));
        long host_rc = syscall(__NR_statx, sv_dirfd, sv_path, flags,
                               (unsigned int) mask, statx_buf);
        int saved = errno;
        if (sv_dirfd != AT_FDCWD)
            close(sv_dirfd);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        normalize_statx_if_needed(ctx, translated, statx_buf);
        int wrc = guest_mem_write(ctx, pid, remote_statx, statx_buf,
                                  sizeof(statx_buf));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
        return kbox_dispatch_value(0);
    }

    uint8_t statx_buf[STATX_BUF_SIZE];
    memset(statx_buf, 0, sizeof(statx_buf));

    long ret = kbox_lkl_statx(ctx->sysnrs, lkl_dirfd, translated, flags, mask,
                              statx_buf);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    normalize_statx_if_needed(ctx, translated, statx_buf);

    int wrc =
        guest_mem_write(ctx, pid, remote_statx, statx_buf, sizeof(statx_buf));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* forward_faccessat / forward_faccessat2. */

static struct kbox_dispatch do_faccessat(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx,
                                         long flags)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    /* Host dirfd or virtual path: call host faccessat with local path copy. */
    if (should_continue_for_dirfd(lkl_dirfd) ||
        should_continue_virtual_path(ctx, req, 1, translated)) {
        char sv_path[KBOX_MAX_PATH];
        int sv_dirfd = AT_FDCWD;
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        if (should_continue_for_dirfd(lkl_dirfd)) {
            long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
            sv_dirfd = dup_tracee_fd(pid, (int) raw_dirfd);
            if (sv_dirfd < 0)
                return kbox_dispatch_errno(-sv_dirfd);
        }
        int host_rc = (int) syscall(__NR_faccessat2, sv_dirfd, sv_path,
                                    (int) mode, (int) flags);
        int saved = errno;
        if (sv_dirfd != AT_FDCWD)
            close(sv_dirfd);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        return kbox_dispatch_value(0);
    }

    long ret =
        kbox_lkl_faccessat2(ctx->sysnrs, lkl_dirfd, translated, mode, flags);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_faccessat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_faccessat(req, ctx, 0);
}

static struct kbox_dispatch forward_faccessat2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_faccessat(req, ctx,
                        to_c_long_arg(kbox_syscall_request_arg(req, 3)));
}

/* forward_getdents64. */

static struct kbox_dispatch forward_getdents64(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_getdents_common(req, ctx, kbox_lkl_getdents64);
}

/* forward_getdents (legacy). */

static struct kbox_dispatch forward_getdents(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_getdents_common(req, ctx, kbox_lkl_getdents);
}

/* forward_chdir. */

static struct kbox_dispatch forward_chdir(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                    sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    long ret = kbox_lkl_chdir(ctx->sysnrs, translated);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    invalidate_translated_path_cache(ctx);
    return kbox_dispatch_value(0);
}

/* forward_fchdir. */

static struct kbox_dispatch forward_fchdir(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    long ret = kbox_lkl_fchdir(ctx->sysnrs, lkl_fd);
    if (ret >= 0)
        invalidate_translated_path_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_getcwd. */

static struct kbox_dispatch forward_getcwd(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_buf = kbox_syscall_request_arg(req, 0);
    int64_t size_raw = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (size_raw <= 0)
        return kbox_dispatch_errno(EINVAL);

    size_t size = (size_t) size_raw;
    if (size > KBOX_MAX_PATH)
        size = KBOX_MAX_PATH;

    char out[KBOX_MAX_PATH];
    long ret = kbox_lkl_getcwd(ctx->sysnrs, out, (long) size);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    size_t n = (size_t) ret;
    if (n == 0 || n > size)
        return kbox_dispatch_errno(EIO);

    int wrc = guest_mem_write(ctx, pid, remote_buf, out, n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

/* Shared skeleton for simple *at() syscalls: translate path + resolve dirfd,
 * then delegate to a callback for the actual LKL call.
 */

typedef long (*at_path_invoke_fn)(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx,
                                  long lkl_dirfd,
                                  const char *translated);

static struct kbox_dispatch forward_at_path_call(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    at_path_invoke_fn invoke,
    at_path_invoke_fn host_invoke,
    int invalidate_on_success)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Host dirfd: call the host syscall with a supervisor-owned copy of the
     * tracee's dirfd to avoid the TOCTOU re-read.
     */
    if (should_continue_for_dirfd(lkl_dirfd)) {
        if (!host_invoke)
            return kbox_dispatch_errno(ENOENT);
        long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
        int sv_dirfd = dup_tracee_fd(pid, (int) raw_dirfd);
        if (sv_dirfd < 0)
            return kbox_dispatch_errno(-sv_dirfd);
        long ret = host_invoke(req, ctx, (long) sv_dirfd, translated);
        close(sv_dirfd);
        if (invalidate_on_success && ret >= 0)
            invalidate_path_shadow_cache(ctx);
        if (ret < 0)
            return kbox_dispatch_errno((int) (-ret));
        return kbox_dispatch_value(ret);
    }

    long ret = invoke(req, ctx, lkl_dirfd, translated);
    if (invalidate_on_success && ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

static long invoke_mkdirat(const struct kbox_syscall_request *req,
                           struct kbox_supervisor_ctx *ctx,
                           long lkl_dirfd,
                           const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    return kbox_lkl_mkdirat(ctx->sysnrs, lkl_dirfd, translated, mode);
}

static long host_invoke_mkdirat(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                long sv_dirfd,
                                const char *path)
{
    (void) ctx;
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (mkdirat((int) sv_dirfd, path, (mode_t) mode) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_mkdirat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_at_path_call(req, ctx, invoke_mkdirat, host_invoke_mkdirat,
                                1);
}

static long invoke_unlinkat(const struct kbox_syscall_request *req,
                            struct kbox_supervisor_ctx *ctx,
                            long lkl_dirfd,
                            const char *translated)
{
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    return kbox_lkl_unlinkat(ctx->sysnrs, lkl_dirfd, translated, flags);
}

static long host_invoke_unlinkat(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 long sv_dirfd,
                                 const char *path)
{
    (void) ctx;
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (unlinkat((int) sv_dirfd, path, (int) flags) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_unlinkat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_at_path_call(req, ctx, invoke_unlinkat, host_invoke_unlinkat,
                                1);
}

/* forward_renameat / forward_renameat2. */

static struct kbox_dispatch do_renameat(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx,
                                        long flags)
{
    char oldtrans[KBOX_MAX_PATH];
    char newtrans[KBOX_MAX_PATH];
    long olddirfd, newdirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, oldtrans,
                                       sizeof(oldtrans), &olddirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    rc = translate_request_at_path(req, ctx, 2, 3, newtrans, sizeof(newtrans),
                                   &newdirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Host dirfd on either side: call host renameat2 with supervisor-owned
     * copies of the tracee's dirfds.
     */
    if (should_continue_for_dirfd(olddirfd) ||
        should_continue_for_dirfd(newdirfd)) {
        int sv_old = AT_FDCWD;
        int sv_new = AT_FDCWD;
        if (should_continue_for_dirfd(olddirfd)) {
            long raw = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
            sv_old = dup_tracee_fd(pid, (int) raw);
            if (sv_old < 0)
                return kbox_dispatch_errno(-sv_old);
        } else {
            sv_old = (int) olddirfd;
        }
        if (should_continue_for_dirfd(newdirfd)) {
            long raw = to_dirfd_arg(kbox_syscall_request_arg(req, 2));
            sv_new = dup_tracee_fd(pid, (int) raw);
            if (sv_new < 0) {
                if (should_continue_for_dirfd(olddirfd))
                    close(sv_old);
                return kbox_dispatch_errno(-sv_new);
            }
        } else {
            sv_new = (int) newdirfd;
        }
        int host_rc = (int) syscall(__NR_renameat2, sv_old, oldtrans, sv_new,
                                    newtrans, (unsigned int) flags);
        int saved = errno;
        if (should_continue_for_dirfd(olddirfd))
            close(sv_old);
        if (should_continue_for_dirfd(newdirfd))
            close(sv_new);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        invalidate_path_shadow_cache(ctx);
        return kbox_dispatch_value(0);
    }

    long ret = kbox_lkl_renameat2(ctx->sysnrs, olddirfd, oldtrans, newdirfd,
                                  newtrans, flags);
    if (ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_renameat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_renameat(req, ctx, 0);
}

static struct kbox_dispatch forward_renameat2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_renameat(req, ctx,
                       to_c_long_arg(kbox_syscall_request_arg(req, 4)));
}

static long invoke_fchmodat(const struct kbox_syscall_request *req,
                            struct kbox_supervisor_ctx *ctx,
                            long lkl_dirfd,
                            const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    return kbox_lkl_fchmodat(ctx->sysnrs, lkl_dirfd, translated, mode, flags);
}

static long host_invoke_fchmodat(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 long sv_dirfd,
                                 const char *path)
{
    (void) ctx;
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (fchmodat((int) sv_dirfd, path, (mode_t) mode, 0) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_fchmodat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_at_path_call(req, ctx, invoke_fchmodat, host_invoke_fchmodat,
                                0);
}

static long invoke_fchownat(const struct kbox_syscall_request *req,
                            struct kbox_supervisor_ctx *ctx,
                            long lkl_dirfd,
                            const char *translated)
{
    long owner = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long group = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 4));
    return kbox_lkl_fchownat(ctx->sysnrs, lkl_dirfd, translated, owner, group,
                             flags);
}

static long host_invoke_fchownat(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 long sv_dirfd,
                                 const char *path)
{
    (void) ctx;
    long owner = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long group = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 4));
    if (fchownat((int) sv_dirfd, path, (uid_t) owner, (gid_t) group,
                 (int) flags) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_fchownat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_at_path_call(req, ctx, invoke_fchownat, host_invoke_fchownat,
                                0);
}

/* forward_mount. */

static struct kbox_dispatch forward_mount(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    char srcbuf[KBOX_MAX_PATH];
    char tgtbuf[KBOX_MAX_PATH];
    char fsbuf[KBOX_MAX_PATH];
    char databuf[KBOX_MAX_PATH];
    int rc;

    const char *source = NULL;
    if (kbox_syscall_request_arg(req, 0) != 0) {
        rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 0),
                                   srcbuf, sizeof(srcbuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        source = srcbuf;
    }

    rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 1),
                               tgtbuf, sizeof(tgtbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    const char *fstype = NULL;
    if (kbox_syscall_request_arg(req, 2) != 0) {
        rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 2),
                                   fsbuf, sizeof(fsbuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        fstype = fsbuf;
    }

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    const void *data = NULL;
    if (kbox_syscall_request_arg(req, 4) != 0) {
        rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 4),
                                   databuf, sizeof(databuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        data = databuf;
    }

    /* Translate paths through normalization and host-root confinement. */
    char translated_tgt[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, tgtbuf, ctx->host_root,
                                     translated_tgt, sizeof(translated_tgt));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Translate the source for bind mounts (MS_BIND uses a path, not a
     * device).  Non-bind sources (device names, "none") pass through
     * unmodified.
     */
    char translated_src[KBOX_MAX_PATH];
    const char *effective_src = source;
    if (source && (flags & 0x1000 /* MS_BIND */)) {
        rc =
            kbox_translate_path_for_lkl(pid, srcbuf, ctx->host_root,
                                        translated_src, sizeof(translated_src));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        effective_src = translated_src;
    }

    long ret = kbox_lkl_mount(ctx->sysnrs, effective_src, translated_tgt,
                              fstype, flags, data);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_umount2. */

static struct kbox_dispatch forward_umount2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 0),
                               pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_umount2(ctx->sysnrs, translated, flags);
    return kbox_dispatch_from_lkl(ret);
}

/* Legacy x86_64 syscall forwarders (stat, lstat, access, etc.). */

static struct kbox_dispatch forward_stat_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int nofollow)
{
    char translated[KBOX_MAX_PATH];
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                    sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    uint64_t remote_stat = kbox_syscall_request_arg(req, 1);
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Virtual path: call host fstatat with a local path copy. */
    if (should_continue_virtual_path(ctx, req, 0, translated)) {
        char sv_path[KBOX_MAX_PATH];
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        int stat_flags = nofollow ? AT_SYMLINK_NOFOLLOW : 0;
        struct stat host_stat;
        if (fstatat(AT_FDCWD, sv_path, &host_stat, stat_flags) < 0)
            return kbox_dispatch_errno(errno);
        normalize_host_stat_if_needed(ctx, translated, &host_stat);
        int wrc = guest_mem_write_small_metadata(ctx, pid, remote_stat,
                                                 &host_stat, sizeof(host_stat));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
        return kbox_dispatch_value(0);
    }

    if (translated[0] != '\0' &&
        try_cached_shadow_stat_dispatch(ctx, translated, remote_stat, pid)) {
        return kbox_dispatch_value(0);
    }

    long flags = nofollow ? AT_SYMLINK_NOFOLLOW : 0;

    struct kbox_lkl_stat kst;
    memset(&kst, 0, sizeof(kst));
    long ret = kbox_lkl_newfstatat(ctx->sysnrs, AT_FDCWD_LINUX, translated,
                                   &kst, flags);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    struct stat host_stat;
    kbox_lkl_stat_to_host(&kst, &host_stat);
    normalize_host_stat_if_needed(ctx, translated, &host_stat);

    int wrc = guest_mem_write_small_metadata(ctx, pid, remote_stat, &host_stat,
                                             sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* Shared skeleton for legacy (non-*at) path syscalls: translate a single
 * path from arg[0], then delegate to a callback for the LKL call.
 */

typedef long (*legacy_path_invoke_fn)(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx,
                                      const char *translated);

static struct kbox_dispatch forward_legacy_path_call(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    legacy_path_invoke_fn invoke,
    legacy_path_invoke_fn host_invoke)
{
    char translated[KBOX_MAX_PATH];
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                    sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Virtual path: call host syscall with a local path copy. */
    if (should_continue_virtual_path(ctx, req, 0, translated)) {
        if (!host_invoke)
            return kbox_dispatch_errno(ENOENT);
        char sv_path[KBOX_MAX_PATH];
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        long ret = host_invoke(req, ctx, sv_path);
        if (ret < 0)
            return kbox_dispatch_errno((int) (-ret));
        return kbox_dispatch_value(ret);
    }
    return kbox_dispatch_from_lkl(invoke(req, ctx, translated));
}

static long invoke_access_legacy(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    return kbox_lkl_faccessat2(ctx->sysnrs, AT_FDCWD_LINUX, translated, mode,
                               0);
}

static long host_invoke_access_legacy(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx,
                                      const char *path)
{
    (void) ctx;
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    if (faccessat(AT_FDCWD, path, (int) mode, 0) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_access_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_access_legacy,
                                    host_invoke_access_legacy);
}

static long invoke_mkdir_legacy(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    return kbox_lkl_mkdir(ctx->sysnrs, translated, (int) mode);
}

static long host_invoke_mkdir_legacy(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx,
                                     const char *path)
{
    (void) ctx;
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    if (mkdir(path, (mode_t) mode) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_mkdir_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_mkdir_legacy,
                                    host_invoke_mkdir_legacy);
}

static long invoke_unlink_legacy(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 const char *translated)
{
    (void) req;
    return kbox_lkl_unlinkat(ctx->sysnrs, AT_FDCWD_LINUX, translated, 0);
}

static long host_invoke_unlink_legacy(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx,
                                      const char *path)
{
    (void) req;
    (void) ctx;
    if (unlink(path) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_unlink_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_unlink_legacy,
                                    host_invoke_unlink_legacy);
}

static long invoke_rmdir_legacy(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                const char *translated)
{
    (void) req;
    return kbox_lkl_unlinkat(ctx->sysnrs, AT_FDCWD_LINUX, translated,
                             AT_REMOVEDIR);
}

static long host_invoke_rmdir_legacy(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx,
                                     const char *path)
{
    (void) req;
    (void) ctx;
    if (rmdir(path) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_rmdir_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_rmdir_legacy,
                                    host_invoke_rmdir_legacy);
}

static struct kbox_dispatch forward_rename_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char oldtrans[KBOX_MAX_PATH];
    char newtrans[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, oldtrans,
                                    sizeof(oldtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    rc = translate_request_path(req, ctx, 1, ctx->host_root, newtrans,
                                sizeof(newtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long ret = kbox_lkl_renameat2(ctx->sysnrs, AT_FDCWD_LINUX, oldtrans,
                                  AT_FDCWD_LINUX, newtrans, 0);
    return kbox_dispatch_from_lkl(ret);
}

static long invoke_chmod_legacy(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    return kbox_lkl_fchmodat(ctx->sysnrs, AT_FDCWD_LINUX, translated, mode, 0);
}

static long host_invoke_chmod_legacy(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx,
                                     const char *path)
{
    (void) ctx;
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    if (chmod(path, (mode_t) mode) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_chmod_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_chmod_legacy,
                                    host_invoke_chmod_legacy);
}

static long invoke_chown_legacy(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                const char *translated)
{
    long owner = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long group = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    return kbox_lkl_fchownat(ctx->sysnrs, AT_FDCWD_LINUX, translated, owner,
                             group, 0);
}

static long host_invoke_chown_legacy(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx,
                                     const char *path)
{
    (void) ctx;
    long owner = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long group = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (chown(path, (uid_t) owner, (gid_t) group) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_chown_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_chown_legacy,
                                    host_invoke_chown_legacy);
}

/* Syscall dispatch tables.
 *
 * X-macros eliminate the repetitive if-chains for the two most common dispatch
 * patterns. Each _(field, handler) entry expands to
 *   if (nr == h->field) return handler(req, ctx);
 *
 * Complex cases (extra args, guards, inline logic) remain as explicit if-blocks
 * after the table expansions.
 */

/* DISPATCH_FORWARD: forwarded to a handler that takes (req, ctx). */
#define DISPATCH_FORWARD_TABLE(_)                                             \
    /* Legacy x86_64 syscalls. */                                             \
    _(access, forward_access_legacy)                                          \
    _(mkdir, forward_mkdir_legacy)                                            \
    _(rmdir, forward_rmdir_legacy)                                            \
    _(unlink, forward_unlink_legacy)                                          \
    _(rename, forward_rename_legacy)                                          \
    _(chmod, forward_chmod_legacy)                                            \
    _(chown, forward_chown_legacy)                                            \
    _(open, forward_open_legacy)                                              \
    /* File open/create. */                                                   \
    _(openat, forward_openat)                                                 \
    _(openat2, forward_openat2)                                               \
    /* Metadata. */                                                           \
    _(fstat, forward_fstat)                                                   \
    _(newfstatat, forward_newfstatat)                                         \
    _(statx, forward_statx)                                                   \
    _(faccessat2, forward_faccessat2)                                         \
    /* Directories. */                                                        \
    _(getdents64, forward_getdents64)                                         \
    _(getdents, forward_getdents)                                             \
    _(mkdirat, forward_mkdirat)                                               \
    _(unlinkat, forward_unlinkat)                                             \
    _(renameat2, forward_renameat2)                                           \
    _(fchmodat, forward_fchmodat)                                             \
    _(fchownat, forward_fchownat)                                             \
    /* Navigation. */                                                         \
    _(chdir, forward_chdir)                                                   \
    _(fchdir, forward_fchdir)                                                 \
    _(getcwd, forward_getcwd)                                                 \
    /* Mount. */                                                              \
    _(mount, forward_mount)                                                   \
    _(umount2, forward_umount2)                                               \
    /* FD operations. */                                                      \
    _(close, forward_close)                                                   \
    _(fcntl, forward_fcntl)                                                   \
    _(dup, forward_dup)                                                       \
    _(dup2, forward_dup2)                                                     \
    _(dup3, forward_dup3)                                                     \
    /* I/O. */                                                                \
    _(write, forward_write)                                                   \
    _(lseek, forward_lseek)                                                   \
    /* Networking. */                                                         \
    _(socket, forward_socket)                                                 \
    _(bind, forward_bind)                                                     \
    _(connect, forward_connect)                                               \
    _(sendto, forward_sendto)                                                 \
    _(recvfrom, forward_recvfrom)                                             \
    _(recvmsg, forward_recvmsg)                                               \
    _(getsockopt, forward_getsockopt)                                         \
    _(setsockopt, forward_setsockopt)                                         \
    _(getsockname, forward_getsockname)                                       \
    _(getpeername, forward_getpeername)                                       \
    _(shutdown, forward_shutdown)                                             \
    /* I/O extended. */                                                       \
    _(pwrite64, forward_pwrite64)                                             \
    _(writev, forward_writev)                                                 \
    _(readv, forward_readv)                                                   \
    _(ftruncate, forward_ftruncate)                                           \
    _(fallocate, forward_fallocate)                                           \
    _(flock, forward_flock)                                                   \
    _(fsync, forward_fsync)                                                   \
    _(fdatasync, forward_fdatasync)                                           \
    _(sync, forward_sync)                                                     \
    _(ioctl, forward_ioctl)                                                   \
    /* File operations. */                                                    \
    _(readlinkat, forward_readlinkat)                                         \
    _(pipe2, forward_pipe2)                                                   \
    _(symlinkat, forward_symlinkat)                                           \
    _(linkat, forward_linkat)                                                 \
    _(utimensat, forward_utimensat)                                           \
    _(sendfile, forward_sendfile)                                             \
    /* Time. */                                                               \
    _(clock_gettime, forward_clock_gettime)                                   \
    _(clock_getres, forward_clock_getres)                                     \
    _(gettimeofday, forward_gettimeofday)                                     \
    /* Process lifecycle. */                                                  \
    _(umask, forward_umask)                                                   \
    _(uname, forward_uname)                                                   \
    _(getrandom, forward_getrandom)                                           \
    _(syslog, forward_syslog)                                                 \
    _(prctl, forward_prctl)                                                   \
    /* Threading. */                                                          \
    _(clone3, forward_clone3)                                                 \
    /* FD-creating syscalls tracked as host-passthrough. */                   \
    _(eventfd2, forward_eventfd)                                              \
    _(timerfd_create, forward_timerfd_create)                                 \
    _(epoll_create1, forward_epoll_create1)                                   \
    /* FD-consuming syscalls gated by deny check (were in CONTINUE table). */ \
    _(epoll_ctl, forward_epoll_ctl_gated)                                     \
    _(epoll_wait, forward_fd_gated_continue)                                  \
    _(epoll_pwait, forward_fd_gated_continue)                                 \
    _(timerfd_settime, forward_fd_gated_continue)                             \
    _(timerfd_gettime, forward_fd_gated_continue)                             \
    _(fstatfs, forward_fd_gated_continue)

/* DISPATCH_CONTINUE: host kernel handles directly, no LKL involvement.
 * Only non-FD syscalls remain here; FD-based syscalls are in the handler
 * table so their FD arguments can be validated.
 */
/* clang-format off */
#define DISPATCH_CONTINUE_TABLE(_)                                             \
    _(setpgid) _(getpgid) _(getsid) _(setsid) _(brk) _(wait4) _(waitid)        \
    _(exit) _(exit_group) _(rt_sigreturn) _(rt_sigaltstack) _(setitimer)       \
    _(getitimer) _(set_tid_address) _(set_robust_list) _(futex) _(rseq)        \
    _(fork) _(vfork) _(membarrier) _(madvise) _(getrlimit) _(getrusage)        \
    /* Scheduling. */                                                          \
    _(sched_yield) _(sched_setparam) _(sched_getparam) _(sched_setscheduler)   \
    _(sched_getscheduler) _(sched_get_priority_max) _(sched_get_priority_min)  \
    _(sched_setaffinity) _(sched_getaffinity)                                  \
    /* I/O multiplexing (non-FD-creating multiplexers only). */                \
    _(ppoll) _(pselect6) _(poll)                                               \
    /* Sleep. */                                                               \
    _(nanosleep) _(clock_nanosleep)                                            \
    /* Filesystem info (path-based statfs stays; FD-based fstatfs moved). */   \
    _(statfs) _(sysinfo)
/* clang-format on */

struct kbox_dispatch kbox_dispatch_request(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req)
{
    const struct kbox_host_nrs *h = ctx->host_nrs;
    int nr;

    if (!ctx || !req)
        return kbox_dispatch_errno(EINVAL);

    kbox_dispatch_prepare_request_ctx(ctx, req);
    nr = req->nr;

    if (ctx->verbose) {
        const char *name = syscall_name_from_nr(h, nr);
        fprintf(stderr, "%s syscall: pid=%u nr=%d (%s)\n",
                req->source == KBOX_SYSCALL_SOURCE_SECCOMP ? "seccomp notify"
                                                           : "in-process",
                kbox_syscall_request_pid(req), nr, name ? name : "unknown");
    }

    /* Table-driven dispatch: forward to handler. */

#define _(field, handler) \
    if (nr == h->field)   \
        return handler(req, ctx);
    DISPATCH_FORWARD_TABLE(_)
#undef _

    /* Table-driven dispatch: CONTINUE to host kernel. */

#define _(field)        \
    if (nr == h->field) \
        return kbox_dispatch_continue();
    DISPATCH_CONTINUE_TABLE(_)
#undef _

    /* Entries with extra arguments or guards. */

    if (nr == h->stat)
        return forward_stat_legacy(req, ctx, 0);
    if (nr == h->lstat)
        return forward_stat_legacy(req, ctx, 1);
    if (nr == h->read)
        return forward_read_like(req, ctx, 0);
    if (nr == h->pread64)
        return forward_read_like(req, ctx, 1);
    if (nr == h->faccessat && h->faccessat > 0)
        return forward_faccessat(req, ctx);
    if (nr == h->renameat && h->renameat > 0)
        return forward_renameat(req, ctx);
    if (nr == h->copy_file_range)
        return kbox_dispatch_errno(ENOSYS);
    if (nr == h->execve)
        return forward_execve(req, ctx, 0);
    if (nr == h->execveat)
        return forward_execve(req, ctx, 1);

    /* Process info: constant return values. */

    if (nr == h->getpid)
        return kbox_dispatch_value(1);
    if (nr == h->getppid)
        return kbox_dispatch_value(0);
    if (nr == h->gettid)
        return kbox_dispatch_value(1);

    /* Identity: UID. */

    if (nr == h->getuid)
        return dispatch_get_uid(kbox_lkl_getuid, ctx);
    if (nr == h->geteuid)
        return dispatch_get_uid(kbox_lkl_geteuid, ctx);
    if (nr == h->getresuid) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getresuid_override(req, ctx, 0);
            if (ctx->override_uid != (uid_t) -1)
                return forward_getresuid_override(req, ctx, ctx->override_uid);
            return kbox_dispatch_continue();
        }
        return forward_getresuid(req, ctx);
    }

    /* Identity: GID. */

    if (nr == h->getgid)
        return dispatch_get_gid(kbox_lkl_getgid, ctx);
    if (nr == h->getegid)
        return dispatch_get_gid(kbox_lkl_getegid, ctx);
    if (nr == h->getresgid) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getresgid_override(req, ctx, 0);
            if (ctx->override_gid != (gid_t) -1)
                return forward_getresgid_override(req, ctx, ctx->override_gid);
            return kbox_dispatch_continue();
        }
        return forward_getresgid(req, ctx);
    }

    /* Identity: groups. */

    if (nr == h->getgroups) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getgroups_override(req, ctx, 0);
            if (ctx->override_gid != (gid_t) -1)
                return forward_getgroups_override(req, ctx, ctx->override_gid);
            return kbox_dispatch_continue();
        }
        return forward_getgroups(req, ctx);
    }

    /* Identity: set*. */

    if (nr == h->setuid)
        return dispatch_set_id(req, ctx, forward_setuid);
    if (nr == h->setreuid)
        return dispatch_set_id(req, ctx, forward_setreuid);
    if (nr == h->setresuid)
        return dispatch_set_id(req, ctx, forward_setresuid);
    if (nr == h->setgid)
        return dispatch_set_id(req, ctx, forward_setgid);
    if (nr == h->setregid)
        return dispatch_set_id(req, ctx, forward_setregid);
    if (nr == h->setresgid)
        return dispatch_set_id(req, ctx, forward_setresgid);
    if (nr == h->setgroups)
        return dispatch_set_id(req, ctx, forward_setgroups);
    if (nr == h->setfsgid)
        return dispatch_set_id(req, ctx, forward_setfsgid);

    /* Legacy eventfd syscall (one arg, no flags). eventfd2 is in the handler
     * table; the raw eventfd(2) syscall does not take a flags argument.
     */
    if (nr == h->eventfd) {
        unsigned int initval = (unsigned int) kbox_syscall_request_arg(req, 0);
        int host_fd = eventfd(initval, 0);
        if (host_fd < 0)
            return kbox_dispatch_errno(errno);
        int tfd = request_addfd(ctx, req, host_fd, 0);
        close(host_fd);
        if (tfd < 0)
            return kbox_dispatch_errno(-tfd);
        track_host_passthrough_fd(ctx->fd_table, tfd);
        return kbox_dispatch_value(tfd);
    }

    /* Legacy pipe syscall: one arg, create host pipe2 and inject via ADDFD. */

    if (nr == h->pipe) {
        pid_t ppid = kbox_syscall_request_pid(req);
        uint64_t remote_pfd = kbox_syscall_request_arg(req, 0);
        if (remote_pfd == 0)
            return kbox_dispatch_errno(EFAULT);

        int host_pfds[2];
        if (pipe(host_pfds) < 0)
            return kbox_dispatch_errno(errno);

        int tfd0 = request_addfd(ctx, req, host_pfds[0], 0);
        if (tfd0 < 0) {
            close(host_pfds[0]);
            close(host_pfds[1]);
            return kbox_dispatch_errno(-tfd0);
        }
        int tfd1 = request_addfd(ctx, req, host_pfds[1], 0);
        if (tfd1 < 0) {
            close(host_pfds[0]);
            close(host_pfds[1]);
            return kbox_dispatch_errno(-tfd1);
        }
        close(host_pfds[0]);
        close(host_pfds[1]);

        track_host_passthrough_fd(ctx->fd_table, tfd0);
        track_host_passthrough_fd(ctx->fd_table, tfd1);

        int gfds[2] = {tfd0, tfd1};
        int pwrc = guest_mem_write(ctx, ppid, remote_pfd, gfds, sizeof(gfds));
        if (pwrc < 0)
            return kbox_dispatch_errno(-pwrc);
        return kbox_dispatch_value(0);
    }

    /* Signals. */

    if (nr == h->rt_sigaction) {
        if (request_uses_trap_signals(req) &&
            kbox_syscall_trap_signal_is_reserved(
                (int) to_c_long_arg(kbox_syscall_request_arg(req, 0)))) {
            if (ctx->verbose) {
                fprintf(stderr,
                        "kbox: reserved SIGSYS handler change denied "
                        "(pid=%u source=%d)\n",
                        kbox_syscall_request_pid(req), req->source);
            }
            return kbox_dispatch_errno(EPERM);
        }
        {
            int signo = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));
            if (signo == 11 /* SIGSEGV */ || signo == 7 /* SIGBUS */)
                kbox_procmem_signal_changed();
        }
        return kbox_dispatch_continue();
    }
    if (nr == h->rt_sigprocmask) {
        if (request_uses_trap_signals(req)) {
            long how = to_c_long_arg(kbox_syscall_request_arg(req, 0));
            int blocks_reserved = request_blocks_reserved_sigsys(req, ctx);

            if (blocks_reserved < 0)
                return kbox_dispatch_errno(-blocks_reserved);
            if (how != SIG_UNBLOCK && blocks_reserved) {
                if (ctx->verbose) {
                    fprintf(stderr,
                            "kbox: reserved SIGSYS mask change denied "
                            "(pid=%u source=%d how=%ld)\n",
                            kbox_syscall_request_pid(req), req->source, how);
                }
                return kbox_dispatch_errno(EPERM);
            }
            return emulate_trap_rt_sigprocmask(req, ctx);
        }
        return kbox_dispatch_continue();
    }
    if (nr == h->rt_sigpending) {
        if (request_uses_trap_signals(req))
            return emulate_trap_rt_sigpending(req, ctx);
        return kbox_dispatch_continue();
    }
    if (h->alarm >= 0 && nr == h->alarm)
        return kbox_dispatch_continue();

    /* Signal delivery: PID validation + virtual-to-real translation.
     *
     * kill/tgkill/tkill share PID validation (guest process tree only), virtual
     * PID 1 -> real PID translation, and trap-mode pending signal bookkeeping.
     * The helper below covers the common tail.
     */

#define IS_GUEST_PID(p) \
    ((p) == ctx->child_pid || (p) == kbox_syscall_request_pid(req) || (p) == 1)

#define DENY_NON_GUEST(pid_val, name)              \
    do {                                           \
        if (!IS_GUEST_PID(pid_val)) {              \
            if (ctx->verbose)                      \
                fprintf(stderr,                    \
                        "kbox: " name              \
                        "(%d) "                    \
                        "denied: not guest PID\n", \
                        (int) (pid_val));          \
            return kbox_dispatch_errno(EPERM);     \
        }                                          \
    } while (0)

    if (nr == h->kill) {
        pid_t target = (pid_t) kbox_syscall_request_arg(req, 0);
        int sig = (int) kbox_syscall_request_arg(req, 1);
        if (!IS_GUEST_PID(target) && target != 0)
            DENY_NON_GUEST(target, "kill");
        pid_t real = ctx->child_pid;
        long ret = syscall(SYS_kill, real, sig);
        if (ret < 0)
            return kbox_dispatch_errno(errno);
        if (request_uses_trap_signals(req) && trap_sigmask_contains_signal(sig))
            (void) kbox_syscall_trap_add_pending_signal(sig);
        return kbox_dispatch_value(0);
    }
    if (nr == h->tgkill) {
        pid_t tgid = (pid_t) kbox_syscall_request_arg(req, 0);
        pid_t tid = (pid_t) kbox_syscall_request_arg(req, 1);
        int sig = (int) kbox_syscall_request_arg(req, 2);
        DENY_NON_GUEST(tgid, "tgkill");
        pid_t real_tgid = ctx->child_pid;
        pid_t real_tid = (tid == 1) ? kbox_syscall_request_pid(req) : tid;
        long ret = syscall(SYS_tgkill, real_tgid, real_tid, sig);
        if (ret < 0)
            return kbox_dispatch_errno(errno);
        if (request_uses_trap_signals(req) &&
            real_tid == kbox_syscall_request_pid(req) &&
            trap_sigmask_contains_signal(sig))
            (void) kbox_syscall_trap_add_pending_signal(sig);
        return kbox_dispatch_value(0);
    }
    if (nr == h->tkill) {
        pid_t target = (pid_t) kbox_syscall_request_arg(req, 0);
        int sig = (int) kbox_syscall_request_arg(req, 1);
        DENY_NON_GUEST(target, "tkill");
        pid_t real_tid = (target == 1) ? kbox_syscall_request_pid(req) : target;
        long ret = syscall(SYS_tkill, real_tid, sig);
        if (ret < 0)
            return kbox_dispatch_errno(errno);
        if (request_uses_trap_signals(req) &&
            real_tid == kbox_syscall_request_pid(req) &&
            trap_sigmask_contains_signal(sig))
            (void) kbox_syscall_trap_add_pending_signal(sig);
        return kbox_dispatch_value(0);
    }
#undef DENY_NON_GUEST
#undef IS_GUEST_PID
    if (nr == h->pidfd_send_signal)
        return kbox_dispatch_errno(EPERM);

    /* arch_prctl: intercept SET_FS/GET_FS in trap/rewrite mode. */

    if (nr == h->arch_prctl) {
        if (request_uses_trap_signals(req)) {
            long subcmd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
            if (subcmd == 0x1002 /* ARCH_SET_FS */) {
                kbox_syscall_trap_set_guest_fs(
                    kbox_syscall_request_arg(req, 1));
                return kbox_dispatch_value(0);
            }
            if (subcmd == 0x1003 /* ARCH_GET_FS */) {
                uint64_t out_ptr = kbox_syscall_request_arg(req, 1);
                uint64_t fs = kbox_syscall_trap_get_guest_fs();
                if (out_ptr == 0)
                    return kbox_dispatch_errno(EFAULT);
                int wrc = guest_mem_write(ctx, kbox_syscall_request_pid(req),
                                          out_ptr, &fs, sizeof(fs));
                if (wrc < 0)
                    return kbox_dispatch_errno(-wrc);
                return kbox_dispatch_value(0);
            }
        }
        return kbox_dispatch_continue();
    }

    /* clone: validate namespace and thread flags. */

    if (nr == h->clone) {
        uint64_t cflags = kbox_syscall_request_arg(req, 0);
        if (cflags & CLONE_NEW_MASK) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: clone denied: namespace flags 0x%llx "
                        "(pid=%u)\n",
                        (unsigned long long) (cflags & CLONE_NEW_MASK),
                        kbox_syscall_request_pid(req));
            return kbox_dispatch_errno(EPERM);
        }
        if ((cflags & CLONE_THREAD) && request_uses_trap_signals(req)) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: clone denied: CLONE_THREAD in trap/rewrite mode "
                        "(pid=%u, use --syscall-mode=seccomp)\n",
                        kbox_syscall_request_pid(req));
            return kbox_dispatch_errno(EPERM);
        }
        return kbox_dispatch_continue();
    }

    /* Memory mapping: invalidate path cache, then forward/CONTINUE. */

    if (nr == h->mmap) {
        invalidate_translated_path_cache(ctx);
        return forward_mmap(req, ctx);
    }
    if (nr == h->munmap) {
        invalidate_translated_path_cache(ctx);
        return kbox_dispatch_continue();
    }
    if (nr == h->mprotect) {
        invalidate_translated_path_cache(ctx);
        return forward_mprotect(req, ctx);
    }
    if (nr == h->mremap) {
        invalidate_translated_path_cache(ctx);
        return kbox_dispatch_continue();
    }

    /* prlimit64: GET is safe, SET is restricted. */

    if (nr == h->prlimit64) {
        uint64_t new_limit_ptr = kbox_syscall_request_arg(req, 2);
        if (new_limit_ptr == 0)
            return kbox_dispatch_continue();
        int resource = (int) kbox_syscall_request_arg(req, 1);
        if (resource == 4 /* RLIMIT_CORE */ || resource == 9 /* RLIMIT_AS */)
            return kbox_dispatch_continue();
        if (ctx->verbose)
            fprintf(stderr, "kbox: prlimit64 SET resource=%d denied\n",
                    resource);
        return kbox_dispatch_errno(EPERM);
    }

    /* readlink: TOCTOU risk, forward to LKL via readlinkat. */

    if (nr == h->readlink) {
        char path[4096];
        int ret = guest_mem_read_string(ctx, kbox_syscall_request_pid(req),
                                        kbox_syscall_request_arg(req, 0), path,
                                        sizeof(path));
        if (ret < 0)
            return kbox_dispatch_errno(-ret);
        long bufsiz = (long) kbox_syscall_request_arg(req, 2);
        char buf[4096];
        if (bufsiz > (long) sizeof(buf))
            bufsiz = (long) sizeof(buf);
        long lret =
            kbox_lkl_readlinkat(ctx->sysnrs, AT_FDCWD_LINUX, path, buf, bufsiz);
        if (lret < 0)
            return kbox_dispatch_from_lkl(lret);
        ret = guest_mem_write(ctx, kbox_syscall_request_pid(req),
                              kbox_syscall_request_arg(req, 1), buf,
                              (size_t) lret);
        if (ret < 0)
            return kbox_dispatch_errno(-ret);
        return kbox_dispatch_value(lret);
    }

    /* Default: deny unknown syscalls. */
    if (ctx->verbose)
        fprintf(stderr, "kbox: DENY unknown syscall nr=%d (pid=%u)\n", nr,
                kbox_syscall_request_pid(req));
    return kbox_dispatch_errno(ENOSYS);
}

struct kbox_dispatch kbox_dispatch_syscall(struct kbox_supervisor_ctx *ctx,
                                           const void *notif_ptr)
{
    struct kbox_syscall_request req;

    if (kbox_syscall_request_from_notif(notif_ptr, &req) < 0)
        return kbox_dispatch_errno(EINVAL);
    return kbox_dispatch_request(ctx, &req);
}
