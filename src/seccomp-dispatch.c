/* SPDX-License-Identifier: MIT */
/*
 * seccomp-dispatch.c - Syscall dispatch engine for the seccomp supervisor.
 *
 * Each intercepted syscall notification is dispatched to a handler that
 * either forwards it through LKL (RETURN) or lets the host kernel handle
 * it (CONTINUE).  This is the beating heart of kbox: every file open,
 * read, write, stat, and directory operation the tracee makes gets
 * routed through here.
 *
 */

#include "kbox/elf.h"
#include "kbox/fd-table.h"
#include "kbox/identity.h"
#include "kbox/lkl-wrap.h"
#include "kbox/net.h"
#include "kbox/path.h"
#include "kbox/procmem.h"
#include "kbox/seccomp.h"
#include "kbox/shadow-fd.h"
#include "kbox/syscall-nr.h"

#include <errno.h>
#include <fcntl.h>
/* seccomp types via kbox/seccomp.h -> kbox/seccomp-defs.h */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Argument extraction helpers                                        */
/* ------------------------------------------------------------------ */

static inline int64_t to_c_long_arg(uint64_t v)
{
    return (int64_t) v;
}

static inline long to_dirfd_arg(uint64_t v)
{
    return (long) (int) (uint32_t) v;
}

/* ------------------------------------------------------------------ */
/* Open-flag ABI translation (aarch64 host <-> asm-generic LKL)       */
/* ------------------------------------------------------------------ */

/*
 * aarch64 and asm-generic define four O_* flags differently:
 *
 *   Flag         aarch64     asm-generic (LKL)
 *   O_DIRECTORY  0x04000     0x10000
 *   O_NOFOLLOW   0x08000     0x20000
 *   O_DIRECT     0x10000     0x04000
 *   O_LARGEFILE  0x20000     0x08000
 *
 * x86_64 values already match asm-generic so no translation is needed there.
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

/* ------------------------------------------------------------------ */
/* Stat ABI conversion                                                */
/* ------------------------------------------------------------------ */

/*
 * Convert LKL's generic-arch stat layout to the host's struct stat.
 *
 * LKL always fills stat buffers using the asm-generic layout regardless
 * of the host architecture.  On x86_64 the two layouts differ:
 *   generic: st_mode (u32) at offset 16, st_nlink (u32) at offset 20
 *   x86_64:  st_nlink (u64) at offset 16, st_mode (u32) at offset 24
 *
 * On aarch64 the kernel uses the generic layout, but the C library's
 * struct stat may still have different padding, so convert explicitly
 * on all architectures.
 */
static void kbox_lkl_stat_to_host(const struct kbox_lkl_stat *src,
                                  struct stat *dst)
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

/* ------------------------------------------------------------------ */
/* Dispatch result constructors                                       */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* Path and FD helper functions                                       */
/* ------------------------------------------------------------------ */

/*
 * Resolve dirfd for *at() syscalls.
 *
 * If the path is absolute, AT_FDCWD is fine regardless of dirfd.
 * If the dirfd is AT_FDCWD, pass it through.
 * Otherwise look up the virtual FD in the table to get the LKL fd.
 * Returns -1 if the fd is not in the table (caller should CONTINUE).
 */
static long resolve_open_dirfd(const char *path,
                               long dirfd,
                               const struct kbox_fd_table *table)
{
    if (path[0] == '/')
        return AT_FDCWD_LINUX;
    if (dirfd == AT_FDCWD_LINUX)
        return AT_FDCWD_LINUX;
    return kbox_fd_table_get_lkl(table, dirfd);
}

/*
 * Attempt to create a shadow memfd for an O_RDONLY regular file and
 * inject it into the tracee.  On success, records the host_fd in the
 * FD table and returns the host-visible FD number via *out_fd.
 *
 * Returns 1 if shadowing succeeded (caller should return *out_fd),
 * 0 if shadowing is not applicable or failed (caller falls through
 * to the virtual FD path).
 */
static int try_shadow_open(struct kbox_supervisor_ctx *ctx,
                           const struct kbox_seccomp_notif *notif,
                           long lkl_fd,
                           long flags,
                           const char *translated,
                           long *out_fd)
{
    /* Only shadow O_RDONLY opens of non-virtual, non-TTY paths. */
    if ((flags & O_ACCMODE) != O_RDONLY)
        return 0;
    if (kbox_is_lkl_virtual_path(translated))
        return 0;
    if (kbox_is_tty_like_path(translated))
        return 0;

    int memfd = kbox_shadow_create(ctx->sysnrs, lkl_fd);
    if (memfd < 0)
        return 0; /* not shadowable -- fall through to virtual FD */

    /*
     * Inject the memfd into the tracee.  The tracee gets its own
     * FD pointing at the same memfd; we close our copy afterward.
     */
    int host_fd = kbox_notify_addfd(ctx->listener_fd, notif->id, memfd, 0);
    if (host_fd < 0) {
        close(memfd);
        return 0;
    }

    /* Track in FD table: virtual FD holds both lkl_fd and host_fd. */
    long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd, 0);
    if (vfd < 0) {
        close(memfd);
        kbox_lkl_close(ctx->sysnrs, lkl_fd);
        *out_fd = -EMFILE;
        return 1;
    }
    kbox_fd_table_set_host_fd(ctx->fd_table, vfd, (long) host_fd);

    close(memfd); /* tracee has its own copy */
    *out_fd = (long) host_fd;
    return 1;
}

/* ------------------------------------------------------------------ */
/* forward_openat                                                     */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_openat(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    long dirfd_raw = to_dirfd_arg(notif->data.args[0]);
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[1], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long flags = host_to_lkl_open_flags(to_c_long_arg(notif->data.args[2]));
    long mode = to_c_long_arg(notif->data.args[3]);

    /* Image mode: translate path for LKL. */
    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    if (kbox_is_lkl_virtual_path(translated))
        return kbox_dispatch_continue();
    if (kbox_is_tty_like_path(translated))
        return kbox_dispatch_continue();

    long lkl_dirfd = resolve_open_dirfd(translated, dirfd_raw, ctx->fd_table);
    if (lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    long ret = kbox_lkl_openat(ctx->sysnrs, lkl_dirfd, translated, flags, mode);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    /* Try shadow FD for O_RDONLY regular files (enables mmap). */
    long shadow_fd;
    if (try_shadow_open(ctx, notif, ret, flags, translated, &shadow_fd)) {
        if (shadow_fd < 0)
            return kbox_dispatch_errno((int) (-shadow_fd));
        return kbox_dispatch_value((int64_t) shadow_fd);
    }

    int mirror = kbox_is_tty_like_path(translated);
    long vfd = kbox_fd_table_insert(ctx->fd_table, ret, mirror);
    if (vfd < 0) {
        kbox_lkl_close(ctx->sysnrs, ret);
        return kbox_dispatch_errno(EMFILE);
    }
    return kbox_dispatch_value((int64_t) vfd);
}

/* ------------------------------------------------------------------ */
/* forward_openat2                                                    */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_openat2(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    long dirfd_raw = to_dirfd_arg(notif->data.args[0]);
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[1], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    struct kbox_open_how how;
    rc = kbox_vm_read_open_how(pid, notif->data.args[2], notif->data.args[3],
                               &how);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    how.flags = (uint64_t) host_to_lkl_open_flags((long) how.flags);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    if (kbox_is_lkl_virtual_path(translated))
        return kbox_dispatch_continue();
    if (kbox_is_tty_like_path(translated))
        return kbox_dispatch_continue();

    long lkl_dirfd = resolve_open_dirfd(translated, dirfd_raw, ctx->fd_table);
    if (lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

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

    /* Try shadow FD for O_RDONLY regular files (enables mmap). */
    long shadow_fd2;
    if (try_shadow_open(ctx, notif, ret, (long) how.flags, translated,
                        &shadow_fd2)) {
        if (shadow_fd2 < 0)
            return kbox_dispatch_errno((int) (-shadow_fd2));
        return kbox_dispatch_value((int64_t) shadow_fd2);
    }

    int mirror = kbox_is_tty_like_path(translated);
    long vfd = kbox_fd_table_insert(ctx->fd_table, ret, mirror);
    if (vfd < 0) {
        kbox_lkl_close(ctx->sysnrs, ret);
        return kbox_dispatch_errno(EMFILE);
    }
    return kbox_dispatch_value((int64_t) vfd);
}

/* ------------------------------------------------------------------ */
/* forward_open_legacy (x86_64 open(2), nr=2)                         */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_open_legacy(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[0], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long flags = host_to_lkl_open_flags(to_c_long_arg(notif->data.args[1]));
    long mode = to_c_long_arg(notif->data.args[2]);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    if (kbox_is_lkl_virtual_path(translated))
        return kbox_dispatch_continue();
    if (kbox_is_tty_like_path(translated))
        return kbox_dispatch_continue();

    long ret =
        kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, translated, flags, mode);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    /* Try shadow FD for O_RDONLY regular files (enables mmap). */
    long shadow_fd3;
    if (try_shadow_open(ctx, notif, ret, flags, translated, &shadow_fd3)) {
        if (shadow_fd3 < 0)
            return kbox_dispatch_errno((int) (-shadow_fd3));
        return kbox_dispatch_value((int64_t) shadow_fd3);
    }

    int mirror = kbox_is_tty_like_path(translated);
    long vfd = kbox_fd_table_insert(ctx->fd_table, ret, mirror);
    if (vfd < 0) {
        kbox_lkl_close(ctx->sysnrs, ret);
        return kbox_dispatch_errno(EMFILE);
    }
    return kbox_dispatch_value((int64_t) vfd);
}

/* ------------------------------------------------------------------ */
/* forward_close                                                      */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_close(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd >= 0) {
        long ret = kbox_lkl_close(ctx->sysnrs, lkl_fd);
        if (ret < 0 && fd >= KBOX_FD_BASE)
            return kbox_dispatch_errno((int) (-ret));
        kbox_fd_table_remove(ctx->fd_table, fd);

        /*
         * Low FD redirect (from dup2): close the LKL side above,
         * then CONTINUE so the host kernel also closes its copy
         * of this FD number.
         */
        if (fd < KBOX_LOW_FD_MAX)
            return kbox_dispatch_continue();

        return kbox_dispatch_value(0);
    }

    /*
     * Not a virtual FD.  Check if this is a host FD that was
     * injected as a shadow (the tracee closes it by the host number).
     * If so, close the LKL side and let the host kernel close the
     * host FD via CONTINUE.
     */
    long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
    if (vfd >= 0) {
        long lkl = kbox_fd_table_get_lkl(ctx->fd_table, vfd);
        kbox_fd_table_remove(ctx->fd_table, vfd);

        if (lkl >= 0) {
            /* Only close the LKL socket and deregister from the event
             * loop if no other fd_table entry references the same
             * lkl_fd (handles dup'd shadow sockets). */
            int still_ref = 0;
            for (long i = 0; i < KBOX_FD_TABLE_MAX && !still_ref; i++) {
                if (ctx->fd_table->entries[i].lkl_fd == lkl)
                    still_ref = 1;
            }
            for (long i = 0; i < KBOX_LOW_FD_MAX && !still_ref; i++) {
                if (ctx->fd_table->low_fds[i].lkl_fd == lkl)
                    still_ref = 1;
            }
            if (!still_ref) {
                kbox_net_deregister_socket((int) lkl);
                kbox_lkl_close(ctx->sysnrs, lkl);
            }
        }
        return kbox_dispatch_continue();
    }

    return kbox_dispatch_continue();
}

/* ------------------------------------------------------------------ */
/* forward_read_like (read and pread64)                               */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_read_like(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx,
    int is_pread)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    uint64_t remote_buf = notif->data.args[1];
    int64_t count_raw = to_c_long_arg(notif->data.args[2]);
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count == 0)
        return kbox_dispatch_value(0);

    pid_t pid = notif->pid;
    size_t max_count = 1024 * 1024;
    if (count > max_count)
        count = max_count;

    size_t total = 0;
    uint8_t *scratch = malloc(KBOX_IO_CHUNK_LEN);
    if (!scratch)
        return kbox_dispatch_errno(ENOMEM);

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        if (chunk_len > count - total)
            chunk_len = count - total;

        long ret;
        if (is_pread) {
            long offset = to_c_long_arg(notif->data.args[3]);
            ret = kbox_lkl_pread64(ctx->sysnrs, lkl_fd, scratch,
                                   (long) chunk_len, offset + (long) total);
        } else {
            ret = kbox_lkl_read(ctx->sysnrs, lkl_fd, scratch, (long) chunk_len);
        }

        if (ret < 0) {
            if (total == 0) {
                free(scratch);
                return kbox_dispatch_errno((int) (-ret));
            }
            break;
        }

        size_t n = (size_t) ret;
        if (n == 0)
            break;

        uint64_t remote = remote_buf + total;
        int wrc = kbox_vm_write(pid, remote, scratch, n);
        if (wrc < 0) {
            free(scratch);
            return kbox_dispatch_errno(-wrc);
        }

        total += n;
        if (n < chunk_len)
            break;
    }

    free(scratch);
    return kbox_dispatch_value((int64_t) total);
}

/* ------------------------------------------------------------------ */
/* forward_write                                                      */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_write(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    int mirror_host = kbox_fd_table_mirror_tty(ctx->fd_table, fd);

    uint64_t remote_buf = notif->data.args[1];
    int64_t count_raw = to_c_long_arg(notif->data.args[2]);
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count == 0)
        return kbox_dispatch_value(0);

    pid_t pid = notif->pid;
    size_t max_count = 1024 * 1024;
    if (count > max_count)
        count = max_count;

    size_t total = 0;
    uint8_t *scratch = malloc(KBOX_IO_CHUNK_LEN);
    if (!scratch)
        return kbox_dispatch_errno(ENOMEM);

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        if (chunk_len > count - total)
            chunk_len = count - total;

        uint64_t remote = remote_buf + total;
        int rrc = kbox_vm_read(pid, remote, scratch, chunk_len);
        if (rrc < 0) {
            if (total > 0)
                break;
            free(scratch);
            return kbox_dispatch_errno(-rrc);
        }

        long ret =
            kbox_lkl_write(ctx->sysnrs, lkl_fd, scratch, (long) chunk_len);
        if (ret < 0) {
            if (total == 0) {
                free(scratch);
                return kbox_dispatch_errno((int) (-ret));
            }
            break;
        }

        size_t n = (size_t) ret;

        /*
         * Mirror to host stdout if this is a TTY fd.
         * The guest fd is a virtual number (4096+) that does not exist
         * on the host side, so we write to stdout instead.
         */
        if (mirror_host && n > 0) {
            (void) write(STDOUT_FILENO, scratch, n);
        }

        total += n;
        if (n < chunk_len)
            break;
    }

    free(scratch);
    return kbox_dispatch_value((int64_t) total);
}

/* ------------------------------------------------------------------ */
/* forward_sendfile                                                   */
/* ------------------------------------------------------------------ */

/*
 * Emulate sendfile(out_fd, in_fd, *offset, count).
 *
 * If both FDs are host-visible (shadow memfds, stdio, or other host
 * FDs not in the virtual table), let the host kernel handle it via
 * CONTINUE.  Otherwise, emulate via LKL read + host/LKL write.
 *
 * busybox cat uses sendfile and some builds loop on ENOSYS instead
 * of falling back to read+write, so returning ENOSYS is not viable.
 */
static struct kbox_dispatch forward_sendfile(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long out_fd = to_c_long_arg(notif->data.args[0]);
    long in_fd = to_c_long_arg(notif->data.args[1]);
    uint64_t offset_ptr = notif->data.args[2];
    int64_t count_raw = to_c_long_arg(notif->data.args[3]);

    long in_lkl = kbox_fd_table_get_lkl(ctx->fd_table, in_fd);
    long out_lkl = kbox_fd_table_get_lkl(ctx->fd_table, out_fd);

    /*
     * Resolve shadow FDs: if in_fd is a host FD injected via ADDFD
     * (shadow memfd), find_by_host_fd locates the virtual entry
     * that holds the LKL FD for the same file.
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

    /*
     * Both FDs are host-visible (shadow memfds, stdio, pipes, etc.)
     * and neither has LKL backing.  The host kernel handles sendfile.
     */
    if (in_lkl < 0 && out_lkl < 0)
        return kbox_dispatch_continue();

    /*
     * At least one FD is virtual/LKL-backed: emulate via read + write.
     * Source must have an LKL FD for emulation.
     */
    if (in_lkl < 0)
        return kbox_dispatch_errno(EBADF);

    if (count_raw <= 0)
        return kbox_dispatch_value(0);
    size_t count = (size_t) count_raw;
    if (count > 1024 * 1024)
        count = 1024 * 1024;

    /* Read optional offset from tracee memory. */
    pid_t pid = notif->pid;
    off_t offset = 0;
    int has_offset = (offset_ptr != 0);
    if (has_offset) {
        int rc = kbox_vm_read(pid, offset_ptr, &offset, sizeof(offset));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
    }

    uint8_t *scratch = malloc(KBOX_IO_CHUNK_LEN);
    if (!scratch)
        return kbox_dispatch_errno(ENOMEM);

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
                free(scratch);
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
                    free(scratch);
                    return kbox_dispatch_errno((int) (-wr));
                }
                break;
            }
        } else {
            /*
             * Destination is a host FD (e.g. stdout).  The supervisor
             * shares the FD table with the tracee (from fork), so
             * write() goes to the same file description.
             */
            ssize_t wr = write((int) out_fd, scratch, n);
            if (wr < 0) {
                if (total == 0) {
                    free(scratch);
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
        kbox_vm_write(pid, offset_ptr, &new_off, sizeof(new_off));
    }

    free(scratch);
    return kbox_dispatch_value((int64_t) total);
}

/* ------------------------------------------------------------------ */
/* forward_lseek                                                      */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_lseek(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    long off = to_c_long_arg(notif->data.args[1]);
    long whence = to_c_long_arg(notif->data.args[2]);
    long ret = kbox_lkl_lseek(ctx->sysnrs, lkl_fd, off, whence);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_fcntl                                                      */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_fcntl(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0) {
        /* Shadow socket: handle F_DUPFD* and F_SETFL. */
        long svfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
        if (svfd >= 0) {
            long scmd = to_c_long_arg(notif->data.args[1]);
            if (scmd == F_DUPFD || scmd == F_DUPFD_CLOEXEC) {
                long minfd = to_c_long_arg(notif->data.args[2]);
                /* When minfd > 0, skip ADDFD (can't honor the
                 * minimum) and let CONTINUE handle it correctly.
                 * The dup is untracked but no FD leaks. */
                struct kbox_fd_entry *orig = NULL;
                if (minfd > 0)
                    goto fcntl_continue;
                if (svfd >= KBOX_FD_BASE)
                    orig = &ctx->fd_table->entries[svfd - KBOX_FD_BASE];
                else if (svfd < KBOX_LOW_FD_MAX)
                    orig = &ctx->fd_table->low_fds[svfd];
                if (orig && orig->shadow_sp >= 0) {
                    uint32_t af = (scmd == F_DUPFD_CLOEXEC) ? O_CLOEXEC : 0;
                    int nh = kbox_notify_addfd(ctx->listener_fd, notif->id,
                                               orig->shadow_sp, af);
                    if (nh >= 0) {
                        long nv = kbox_fd_table_insert(ctx->fd_table,
                                                       orig->lkl_fd, 0);
                        if (nv < 0)
                            return kbox_dispatch_errno(EMFILE);
                        kbox_fd_table_set_host_fd(ctx->fd_table, nv, nh);
                        int ns = dup(orig->shadow_sp);
                        if (ns >= 0) {
                            struct kbox_fd_entry *ne = NULL;
                            if (nv >= KBOX_FD_BASE)
                                ne = &ctx->fd_table->entries[nv - KBOX_FD_BASE];
                            else if (nv < KBOX_LOW_FD_MAX)
                                ne = &ctx->fd_table->low_fds[nv];
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
                long sarg = to_c_long_arg(notif->data.args[2]);
                long slkl = kbox_fd_table_get_lkl(ctx->fd_table, svfd);
                if (slkl >= 0)
                    kbox_lkl_fcntl(ctx->sysnrs, slkl, F_SETFL, sarg);
            }
            if (scmd == F_SETFD) {
                /* Keep fd-table cloexec in sync with host kernel. */
                long sarg = to_c_long_arg(notif->data.args[2]);
                kbox_fd_table_set_cloexec(ctx->fd_table, svfd,
                                          (sarg & FD_CLOEXEC) ? 1 : 0);
            }
        }
    fcntl_continue:
        return kbox_dispatch_continue();
    }

    long cmd = to_c_long_arg(notif->data.args[1]);
    long arg = to_c_long_arg(notif->data.args[2]);

    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        long ret = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, cmd, arg);
        if (ret < 0)
            return kbox_dispatch_errno((int) (-ret));

        int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, fd);
        long new_vfd = kbox_fd_table_insert(ctx->fd_table, ret, mirror);
        if (new_vfd < 0) {
            kbox_lkl_close(ctx->sysnrs, ret);
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

/* ------------------------------------------------------------------ */
/* forward_dup                                                        */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_dup(const struct kbox_seccomp_notif *notif,
                                        struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0) {
        /* Check for shadow socket (tracee holds host_fd from ADDFD). */
        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
        if (orig_vfd < 0)
            return kbox_dispatch_continue();

        /* Shadow socket dup: inject a new copy of the socketpair end
         * into the tracee and track the new host_fd. */
        struct kbox_fd_entry *orig = NULL;
        if (orig_vfd >= KBOX_FD_BASE)
            orig = &ctx->fd_table->entries[orig_vfd - KBOX_FD_BASE];
        else if (orig_vfd < KBOX_LOW_FD_MAX)
            orig = &ctx->fd_table->low_fds[orig_vfd];
        if (!orig || orig->shadow_sp < 0)
            return kbox_dispatch_continue();

        long orig_lkl = orig->lkl_fd;
        int new_host =
            kbox_notify_addfd(ctx->listener_fd, notif->id, orig->shadow_sp, 0);
        if (new_host < 0)
            return kbox_dispatch_errno(-new_host);

        long new_vfd = kbox_fd_table_insert(ctx->fd_table, orig_lkl, 0);
        if (new_vfd < 0) {
            /* Can't track the FD -- return error. The tracee already
             * has the FD via ADDFD which we can't revoke, but returning
             * EMFILE tells the caller dup failed so it won't use it. */
            return kbox_dispatch_errno(EMFILE);
        }
        kbox_fd_table_set_host_fd(ctx->fd_table, new_vfd, new_host);

        /* Propagate shadow_sp so chained dups work. */
        int new_sp = dup(orig->shadow_sp);
        if (new_sp >= 0) {
            struct kbox_fd_entry *ne = NULL;
            if (new_vfd >= KBOX_FD_BASE)
                ne = &ctx->fd_table->entries[new_vfd - KBOX_FD_BASE];
            else if (new_vfd < KBOX_LOW_FD_MAX)
                ne = &ctx->fd_table->low_fds[new_vfd];
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
        kbox_lkl_close(ctx->sysnrs, ret);
        return kbox_dispatch_errno(EMFILE);
    }
    return kbox_dispatch_value((int64_t) new_vfd);
}

/* ------------------------------------------------------------------ */
/* forward_dup2                                                       */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_dup2(const struct kbox_seccomp_notif *notif,
                                         struct kbox_supervisor_ctx *ctx)
{
    long oldfd = to_c_long_arg(notif->data.args[0]);
    long newfd = to_c_long_arg(notif->data.args[1]);

    long lkl_old = kbox_fd_table_get_lkl(ctx->fd_table, oldfd);
    if (lkl_old < 0) {
        /* Shadow socket dup2: dup2(fd, fd) must return fd unchanged. */
        if (oldfd == newfd)
            return kbox_dispatch_value((int64_t) newfd);

        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd);
        if (orig_vfd >= 0) {
            struct kbox_fd_entry *orig = NULL;
            if (orig_vfd >= KBOX_FD_BASE)
                orig = &ctx->fd_table->entries[orig_vfd - KBOX_FD_BASE];
            else if (orig_vfd < KBOX_LOW_FD_MAX)
                orig = &ctx->fd_table->low_fds[orig_vfd];
            if (orig && orig->shadow_sp >= 0) {
                int new_host =
                    kbox_notify_addfd_at(ctx->listener_fd, notif->id,
                                         orig->shadow_sp, (int) newfd, 0);
                if (new_host >= 0) {
                    /* Remove any stale mapping at newfd (virtual or shadow). */
                    long stale = kbox_fd_table_get_lkl(ctx->fd_table, newfd);
                    if (stale >= 0) {
                        kbox_lkl_close(ctx->sysnrs, stale);
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
                                for (long j = 0; j < KBOX_LOW_FD_MAX && !ref;
                                     j++)
                                    if (ctx->fd_table->low_fds[j].lkl_fd == sl)
                                        ref = 1;
                                if (!ref) {
                                    kbox_net_deregister_socket((int) sl);
                                    kbox_lkl_close(ctx->sysnrs, sl);
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
                        if (nv >= KBOX_FD_BASE)
                            ne2 = &ctx->fd_table->entries[nv - KBOX_FD_BASE];
                        else if (nv < KBOX_LOW_FD_MAX)
                            ne2 = &ctx->fd_table->low_fds[nv];
                        if (ne2)
                            ne2->shadow_sp = ns;
                        else
                            close(ns);
                    }
                    return kbox_dispatch_value((int64_t) newfd);
                }
            }
        }
        /*
         * oldfd is a host FD.  If newfd has a stale LKL redirect
         * (from a previous dup2), clean it up before the host
         * kernel overwrites the FD.  Without this, the shell's
         * dup2(saved_stdout, 1) leaves a stale low_fds entry
         * that traps all subsequent writes to FD 1 in LKL.
         */
        long stale = kbox_fd_table_get_lkl(ctx->fd_table, newfd);
        if (stale >= 0) {
            kbox_lkl_close(ctx->sysnrs, stale);
            kbox_fd_table_remove(ctx->fd_table, newfd);
        } else {
            long sv = kbox_fd_table_find_by_host_fd(ctx->fd_table, newfd);
            if (sv >= 0) {
                long sl = kbox_fd_table_get_lkl(ctx->fd_table, sv);
                kbox_fd_table_remove(ctx->fd_table, sv);
                if (sl >= 0) {
                    int ref = 0;
                    for (long j = 0; j < KBOX_FD_TABLE_MAX; j++)
                        if (ctx->fd_table->entries[j].lkl_fd == sl)
                            ref = 1;
                    for (long j = 0; j < KBOX_LOW_FD_MAX && !ref; j++)
                        if (ctx->fd_table->low_fds[j].lkl_fd == sl)
                            ref = 1;
                    if (!ref) {
                        kbox_net_deregister_socket((int) sl);
                        kbox_lkl_close(ctx->sysnrs, sl);
                    }
                }
            }
        }
        return kbox_dispatch_continue();
    }

    if (oldfd == newfd)
        return kbox_dispatch_value((int64_t) newfd);

    /*
     * Dup first, then close the old mapping.  This preserves the
     * old newfd if the dup fails (e.g. EMFILE), matching dup2
     * atomicity semantics.
     */
    long ret = kbox_lkl_dup(ctx->sysnrs, lkl_old);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long existing = kbox_fd_table_remove(ctx->fd_table, newfd);
    if (existing >= 0)
        kbox_lkl_close(ctx->sysnrs, existing);

    int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, oldfd);
    if (kbox_fd_table_insert_at(ctx->fd_table, newfd, ret, mirror) < 0) {
        kbox_lkl_close(ctx->sysnrs, ret);
        return kbox_dispatch_errno(EBADF);
    }
    return kbox_dispatch_value((int64_t) newfd);
}

/* ------------------------------------------------------------------ */
/* forward_dup3                                                       */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_dup3(const struct kbox_seccomp_notif *notif,
                                         struct kbox_supervisor_ctx *ctx)
{
    long oldfd = to_c_long_arg(notif->data.args[0]);
    long newfd = to_c_long_arg(notif->data.args[1]);
    long flags = to_c_long_arg(notif->data.args[2]);

    /* dup3 only accepts O_CLOEXEC; reject anything else per POSIX. */
    if (flags & ~((long) O_CLOEXEC))
        return kbox_dispatch_errno(EINVAL);

    long lkl_old = kbox_fd_table_get_lkl(ctx->fd_table, oldfd);
    if (lkl_old < 0) {
        /* Shadow socket dup3: dup3(fd, fd, ...) must return EINVAL. */
        if (oldfd == newfd) {
            if (kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd) >= 0)
                return kbox_dispatch_errno(EINVAL);
        }

        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd);
        if (orig_vfd >= 0) {
            struct kbox_fd_entry *orig = NULL;
            if (orig_vfd >= KBOX_FD_BASE)
                orig = &ctx->fd_table->entries[orig_vfd - KBOX_FD_BASE];
            else if (orig_vfd < KBOX_LOW_FD_MAX)
                orig = &ctx->fd_table->low_fds[orig_vfd];
            if (orig && orig->shadow_sp >= 0) {
                uint32_t af = (flags & O_CLOEXEC) ? O_CLOEXEC : 0;
                int new_host =
                    kbox_notify_addfd_at(ctx->listener_fd, notif->id,
                                         orig->shadow_sp, (int) newfd, af);
                if (new_host >= 0) {
                    /* Remove stale mapping at newfd (virtual or shadow). */
                    long stale3 = kbox_fd_table_get_lkl(ctx->fd_table, newfd);
                    if (stale3 >= 0) {
                        kbox_lkl_close(ctx->sysnrs, stale3);
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
                                for (long j = 0; j < KBOX_LOW_FD_MAX && !r3;
                                     j++)
                                    if (ctx->fd_table->low_fds[j].lkl_fd == sl3)
                                        r3 = 1;
                                if (!r3) {
                                    kbox_net_deregister_socket((int) sl3);
                                    kbox_lkl_close(ctx->sysnrs, sl3);
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
                        if (nv >= KBOX_FD_BASE)
                            ne3 = &ctx->fd_table->entries[nv - KBOX_FD_BASE];
                        else if (nv < KBOX_LOW_FD_MAX)
                            ne3 = &ctx->fd_table->low_fds[nv];
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
        /* Same stale-redirect cleanup as forward_dup2. */
        long stale = kbox_fd_table_get_lkl(ctx->fd_table, newfd);
        if (stale >= 0) {
            kbox_lkl_close(ctx->sysnrs, stale);
            kbox_fd_table_remove(ctx->fd_table, newfd);
        } else {
            long sv = kbox_fd_table_find_by_host_fd(ctx->fd_table, newfd);
            if (sv >= 0) {
                long sl = kbox_fd_table_get_lkl(ctx->fd_table, sv);
                kbox_fd_table_remove(ctx->fd_table, sv);
                if (sl >= 0) {
                    int ref = 0;
                    for (long j = 0; j < KBOX_FD_TABLE_MAX; j++)
                        if (ctx->fd_table->entries[j].lkl_fd == sl)
                            ref = 1;
                    for (long j = 0; j < KBOX_LOW_FD_MAX && !ref; j++)
                        if (ctx->fd_table->low_fds[j].lkl_fd == sl)
                            ref = 1;
                    if (!ref) {
                        kbox_net_deregister_socket((int) sl);
                        kbox_lkl_close(ctx->sysnrs, sl);
                    }
                }
            }
        }
        return kbox_dispatch_continue();
    }

    if (oldfd == newfd)
        return kbox_dispatch_errno(EINVAL);

    long ret = kbox_lkl_dup(ctx->sysnrs, lkl_old);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long existing = kbox_fd_table_remove(ctx->fd_table, newfd);
    if (existing >= 0)
        kbox_lkl_close(ctx->sysnrs, existing);

    int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, oldfd);
    if (kbox_fd_table_insert_at(ctx->fd_table, newfd, ret, mirror) < 0) {
        kbox_lkl_close(ctx->sysnrs, ret);
        return kbox_dispatch_errno(EBADF);
    }
    if (flags & O_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, newfd, 1);
    return kbox_dispatch_value((int64_t) newfd);
}

/* ------------------------------------------------------------------ */
/* forward_fstat                                                      */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_fstat(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    uint64_t remote_stat = notif->data.args[1];
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    struct kbox_lkl_stat kst;
    memset(&kst, 0, sizeof(kst));
    long ret = kbox_lkl_fstat(ctx->sysnrs, lkl_fd, &kst);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    struct stat host_stat;
    kbox_lkl_stat_to_host(&kst, &host_stat);

    pid_t pid = notif->pid;
    int wrc = kbox_vm_write(pid, remote_stat, &host_stat, sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* ------------------------------------------------------------------ */
/* forward_newfstatat                                                 */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_newfstatat(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    long dirfd_raw = to_dirfd_arg(notif->data.args[0]);
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[1], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long lkl_dirfd = resolve_open_dirfd(translated, dirfd_raw, ctx->fd_table);
    if (lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    uint64_t remote_stat = notif->data.args[2];
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    long flags = to_c_long_arg(notif->data.args[3]);

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

    /* Normalize permissions if enabled. */
    if (ctx->normalize) {
        uint32_t n_mode, n_uid, n_gid;
        if (kbox_normalized_permissions(translated, &n_mode, &n_uid, &n_gid)) {
            host_stat.st_mode =
                (host_stat.st_mode & S_IFMT) | (n_mode & ~S_IFMT);
            host_stat.st_uid = n_uid;
            host_stat.st_gid = n_gid;
        }
    }

    int wrc = kbox_vm_write(pid, remote_stat, &host_stat, sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* ------------------------------------------------------------------ */
/* forward_statx                                                      */
/* ------------------------------------------------------------------ */

/* statx struct field offsets (standard on x86_64 and aarch64). */
#define STATX_MODE_OFFSET 0x20
#define STATX_UID_OFFSET 0x48
#define STATX_GID_OFFSET 0x4c
#define STATX_BUF_SIZE 0x100

static struct kbox_dispatch forward_statx(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    long dirfd_raw = to_dirfd_arg(notif->data.args[0]);
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[1], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long lkl_dirfd = resolve_open_dirfd(translated, dirfd_raw, ctx->fd_table);
    if (lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    int flags = (int) to_c_long_arg(notif->data.args[2]);
    unsigned mask = (unsigned) to_c_long_arg(notif->data.args[3]);
    uint64_t remote_statx = notif->data.args[4];
    if (remote_statx == 0)
        return kbox_dispatch_errno(EFAULT);

    uint8_t statx_buf[STATX_BUF_SIZE];
    memset(statx_buf, 0, sizeof(statx_buf));

    long ret = kbox_lkl_statx(ctx->sysnrs, lkl_dirfd, translated, flags, mask,
                              statx_buf);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    /* Normalize permissions if enabled. */
    if (ctx->normalize) {
        uint32_t n_mode, n_uid, n_gid;
        if (kbox_normalized_permissions(translated, &n_mode, &n_uid, &n_gid)) {
            uint16_t mode_le = (uint16_t) n_mode;
            memcpy(&statx_buf[STATX_MODE_OFFSET], &mode_le, 2);
            memcpy(&statx_buf[STATX_UID_OFFSET], &n_uid, 4);
            memcpy(&statx_buf[STATX_GID_OFFSET], &n_gid, 4);
        }
    }

    int wrc = kbox_vm_write(pid, remote_statx, statx_buf, sizeof(statx_buf));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* ------------------------------------------------------------------ */
/* forward_faccessat / forward_faccessat2                             */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch do_faccessat(const struct kbox_seccomp_notif *notif,
                                         struct kbox_supervisor_ctx *ctx,
                                         long flags)
{
    pid_t pid = notif->pid;
    long dirfd_raw = to_dirfd_arg(notif->data.args[0]);
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[1], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long lkl_dirfd = resolve_open_dirfd(translated, dirfd_raw, ctx->fd_table);
    if (lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    long mode = to_c_long_arg(notif->data.args[2]);
    long ret =
        kbox_lkl_faccessat2(ctx->sysnrs, lkl_dirfd, translated, mode, flags);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_faccessat(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    return do_faccessat(notif, ctx, 0);
}

static struct kbox_dispatch forward_faccessat2(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    return do_faccessat(notif, ctx, to_c_long_arg(notif->data.args[3]));
}

/* ------------------------------------------------------------------ */
/* forward_getdents64                                                 */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_getdents64(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    uint64_t remote_dirp = notif->data.args[1];
    int64_t count_raw = to_c_long_arg(notif->data.args[2]);
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;

    if (count == 0)
        return kbox_dispatch_value(0);
    if (remote_dirp == 0)
        return kbox_dispatch_errno(EFAULT);

    size_t max_count = 1024 * 1024;
    if (count > max_count)
        count = max_count;

    uint8_t *buf = malloc(count);
    if (!buf)
        return kbox_dispatch_errno(ENOMEM);

    long ret = kbox_lkl_getdents64(ctx->sysnrs, lkl_fd, buf, (long) count);
    if (ret < 0) {
        free(buf);
        return kbox_dispatch_errno((int) (-ret));
    }

    size_t n = (size_t) ret;
    if (n > count) {
        free(buf);
        return kbox_dispatch_errno(EIO);
    }

    pid_t pid = notif->pid;
    int wrc = kbox_vm_write(pid, remote_dirp, buf, n);
    free(buf);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

/* ------------------------------------------------------------------ */
/* forward_getdents (legacy)                                          */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_getdents(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    uint64_t remote_dirp = notif->data.args[1];
    int64_t count_raw = to_c_long_arg(notif->data.args[2]);
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;

    if (count == 0)
        return kbox_dispatch_value(0);
    if (remote_dirp == 0)
        return kbox_dispatch_errno(EFAULT);

    size_t max_count = 1024 * 1024;
    if (count > max_count)
        count = max_count;

    uint8_t *buf = malloc(count);
    if (!buf)
        return kbox_dispatch_errno(ENOMEM);

    long ret = kbox_lkl_getdents(ctx->sysnrs, lkl_fd, buf, (long) count);
    if (ret < 0) {
        free(buf);
        return kbox_dispatch_errno((int) (-ret));
    }

    size_t n = (size_t) ret;
    if (n > count) {
        free(buf);
        return kbox_dispatch_errno(EIO);
    }

    pid_t pid = notif->pid;
    int wrc = kbox_vm_write(pid, remote_dirp, buf, n);
    free(buf);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

/* ------------------------------------------------------------------ */
/* forward_chdir                                                      */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_chdir(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[0], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long ret = kbox_lkl_chdir(ctx->sysnrs, translated);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    return kbox_dispatch_value(0);
}

/* ------------------------------------------------------------------ */
/* forward_fchdir                                                     */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_fchdir(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    long ret = kbox_lkl_fchdir(ctx->sysnrs, lkl_fd);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_getcwd                                                     */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_getcwd(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    uint64_t remote_buf = notif->data.args[0];
    int64_t size_raw = to_c_long_arg(notif->data.args[1]);

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

    int wrc = kbox_vm_write(pid, remote_buf, out, n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

/* ------------------------------------------------------------------ */
/* forward_mkdirat                                                    */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_mkdirat(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    long dirfd_raw = to_dirfd_arg(notif->data.args[0]);
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[1], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long lkl_dirfd = resolve_open_dirfd(translated, dirfd_raw, ctx->fd_table);
    if (lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    long mode = to_c_long_arg(notif->data.args[2]);
    long ret = kbox_lkl_mkdirat(ctx->sysnrs, lkl_dirfd, translated, mode);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_unlinkat                                                   */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_unlinkat(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    long dirfd_raw = to_dirfd_arg(notif->data.args[0]);
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[1], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long lkl_dirfd = resolve_open_dirfd(translated, dirfd_raw, ctx->fd_table);
    if (lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    long flags = to_c_long_arg(notif->data.args[2]);
    long ret = kbox_lkl_unlinkat(ctx->sysnrs, lkl_dirfd, translated, flags);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_renameat / forward_renameat2                               */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch do_renameat(const struct kbox_seccomp_notif *notif,
                                        struct kbox_supervisor_ctx *ctx,
                                        long flags)
{
    pid_t pid = notif->pid;
    long olddirfd_raw = to_dirfd_arg(notif->data.args[0]);
    char oldpathbuf[KBOX_MAX_PATH];
    int rc;

    rc = kbox_vm_read_string(pid, notif->data.args[1], oldpathbuf,
                             sizeof(oldpathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long newdirfd_raw = to_dirfd_arg(notif->data.args[2]);
    char newpathbuf[KBOX_MAX_PATH];

    rc = kbox_vm_read_string(pid, notif->data.args[3], newpathbuf,
                             sizeof(newpathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char oldtrans[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, oldpathbuf, ctx->host_root, oldtrans,
                                     sizeof(oldtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char newtrans[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, newpathbuf, ctx->host_root, newtrans,
                                     sizeof(newtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long olddirfd = resolve_open_dirfd(oldtrans, olddirfd_raw, ctx->fd_table);
    if (olddirfd < 0 && olddirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    long newdirfd = resolve_open_dirfd(newtrans, newdirfd_raw, ctx->fd_table);
    if (newdirfd < 0 && newdirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    long ret = kbox_lkl_renameat2(ctx->sysnrs, olddirfd, oldtrans, newdirfd,
                                  newtrans, flags);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_renameat(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    return do_renameat(notif, ctx, 0);
}

static struct kbox_dispatch forward_renameat2(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    return do_renameat(notif, ctx, to_c_long_arg(notif->data.args[4]));
}

/* ------------------------------------------------------------------ */
/* forward_fchmodat                                                   */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_fchmodat(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    long dirfd_raw = to_dirfd_arg(notif->data.args[0]);
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[1], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long lkl_dirfd = resolve_open_dirfd(translated, dirfd_raw, ctx->fd_table);
    if (lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    long mode = to_c_long_arg(notif->data.args[2]);
    long flags = to_c_long_arg(notif->data.args[3]);
    long ret =
        kbox_lkl_fchmodat(ctx->sysnrs, lkl_dirfd, translated, mode, flags);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_fchownat                                                   */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_fchownat(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    long dirfd_raw = to_dirfd_arg(notif->data.args[0]);
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[1], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long lkl_dirfd = resolve_open_dirfd(translated, dirfd_raw, ctx->fd_table);
    if (lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    long owner = to_c_long_arg(notif->data.args[2]);
    long group = to_c_long_arg(notif->data.args[3]);
    long flags = to_c_long_arg(notif->data.args[4]);
    long ret = kbox_lkl_fchownat(ctx->sysnrs, lkl_dirfd, translated, owner,
                                 group, flags);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_mount                                                      */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_mount(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    char srcbuf[KBOX_MAX_PATH];
    char tgtbuf[KBOX_MAX_PATH];
    char fsbuf[KBOX_MAX_PATH];
    char databuf[KBOX_MAX_PATH];
    int rc;

    const char *source = NULL;
    if (notif->data.args[0] != 0) {
        rc = kbox_vm_read_string(pid, notif->data.args[0], srcbuf,
                                 sizeof(srcbuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        source = srcbuf;
    }

    rc = kbox_vm_read_string(pid, notif->data.args[1], tgtbuf, sizeof(tgtbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    const char *fstype = NULL;
    if (notif->data.args[2] != 0) {
        rc =
            kbox_vm_read_string(pid, notif->data.args[2], fsbuf, sizeof(fsbuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        fstype = fsbuf;
    }

    long flags = to_c_long_arg(notif->data.args[3]);

    const void *data = NULL;
    if (notif->data.args[4] != 0) {
        rc = kbox_vm_read_string(pid, notif->data.args[4], databuf,
                                 sizeof(databuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        data = databuf;
    }

    long ret = kbox_lkl_mount(ctx->sysnrs, source, tgtbuf, fstype, flags, data);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_umount2                                                    */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_umount2(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[0], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long flags = to_c_long_arg(notif->data.args[1]);
    long ret = kbox_lkl_umount2(ctx->sysnrs, pathbuf, flags);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* Legacy x86_64 syscall forwarders (stat, lstat, access, etc.)       */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_stat_legacy(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx,
    int nofollow)
{
    pid_t pid = notif->pid;
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[0], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    uint64_t remote_stat = notif->data.args[1];
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    long flags = nofollow ? AT_SYMLINK_NOFOLLOW : 0;

    struct kbox_lkl_stat kst;
    memset(&kst, 0, sizeof(kst));
    long ret = kbox_lkl_newfstatat(ctx->sysnrs, AT_FDCWD_LINUX, translated,
                                   &kst, flags);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    struct stat host_stat;
    kbox_lkl_stat_to_host(&kst, &host_stat);

    if (ctx->normalize) {
        uint32_t n_mode, n_uid, n_gid;
        if (kbox_normalized_permissions(translated, &n_mode, &n_uid, &n_gid)) {
            host_stat.st_mode =
                (host_stat.st_mode & S_IFMT) | (n_mode & ~S_IFMT);
            host_stat.st_uid = n_uid;
            host_stat.st_gid = n_gid;
        }
    }

    int wrc = kbox_vm_write(pid, remote_stat, &host_stat, sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

static struct kbox_dispatch forward_access_legacy(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[0], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long mode = to_c_long_arg(notif->data.args[1]);
    long ret =
        kbox_lkl_faccessat2(ctx->sysnrs, AT_FDCWD_LINUX, translated, mode, 0);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_mkdir_legacy(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[0], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long mode = to_c_long_arg(notif->data.args[1]);
    long ret = kbox_lkl_mkdir(ctx->sysnrs, translated, (int) mode);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_unlink_legacy(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[0], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long ret = kbox_lkl_unlinkat(ctx->sysnrs, AT_FDCWD_LINUX, translated, 0);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_rmdir_legacy(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[0], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long ret = kbox_lkl_unlinkat(ctx->sysnrs, AT_FDCWD_LINUX, translated,
                                 AT_REMOVEDIR);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_rename_legacy(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    char oldpathbuf[KBOX_MAX_PATH];
    char newpathbuf[KBOX_MAX_PATH];
    int rc;

    rc = kbox_vm_read_string(pid, notif->data.args[0], oldpathbuf,
                             sizeof(oldpathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    rc = kbox_vm_read_string(pid, notif->data.args[1], newpathbuf,
                             sizeof(newpathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char oldtrans[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, oldpathbuf, ctx->host_root, oldtrans,
                                     sizeof(oldtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char newtrans[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, newpathbuf, ctx->host_root, newtrans,
                                     sizeof(newtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long ret = kbox_lkl_renameat2(ctx->sysnrs, AT_FDCWD_LINUX, oldtrans,
                                  AT_FDCWD_LINUX, newtrans, 0);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_chmod_legacy(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[0], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long mode = to_c_long_arg(notif->data.args[1]);
    long ret =
        kbox_lkl_fchmodat(ctx->sysnrs, AT_FDCWD_LINUX, translated, mode, 0);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_chown_legacy(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[0], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long owner = to_c_long_arg(notif->data.args[1]);
    long group = to_c_long_arg(notif->data.args[2]);
    long ret = kbox_lkl_fchownat(ctx->sysnrs, AT_FDCWD_LINUX, translated, owner,
                                 group, 0);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* Identity forwarders: getuid, geteuid, getresuid, etc.              */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_getresuid(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    uint64_t ruid_ptr = notif->data.args[0];
    uint64_t euid_ptr = notif->data.args[1];
    uint64_t suid_ptr = notif->data.args[2];

    if (ruid_ptr != 0) {
        long r = kbox_lkl_getuid(ctx->sysnrs);
        if (r < 0)
            return kbox_dispatch_errno((int) (-r));
        unsigned val = (unsigned) r;
        int wrc = kbox_vm_write(pid, ruid_ptr, &val, sizeof(val));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    if (euid_ptr != 0) {
        long r = kbox_lkl_geteuid(ctx->sysnrs);
        if (r < 0)
            return kbox_dispatch_errno((int) (-r));
        unsigned val = (unsigned) r;
        int wrc = kbox_vm_write(pid, euid_ptr, &val, sizeof(val));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    if (suid_ptr != 0) {
        /* saved-set-uid = effective uid (LKL has no separate saved). */
        long r = kbox_lkl_geteuid(ctx->sysnrs);
        if (r < 0)
            return kbox_dispatch_errno((int) (-r));
        unsigned val = (unsigned) r;
        int wrc = kbox_vm_write(pid, suid_ptr, &val, sizeof(val));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    return kbox_dispatch_value(0);
}

static struct kbox_dispatch forward_getresuid_override(
    const struct kbox_seccomp_notif *notif,
    uid_t uid)
{
    pid_t pid = notif->pid;
    unsigned val = (unsigned) uid;
    int i;

    for (i = 0; i < 3; i++) {
        uint64_t ptr = notif->data.args[i];
        if (ptr != 0) {
            int wrc = kbox_vm_write(pid, ptr, &val, sizeof(val));
            if (wrc < 0)
                return kbox_dispatch_errno(EIO);
        }
    }
    return kbox_dispatch_value(0);
}

static struct kbox_dispatch forward_getresgid(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    uint64_t rgid_ptr = notif->data.args[0];
    uint64_t egid_ptr = notif->data.args[1];
    uint64_t sgid_ptr = notif->data.args[2];

    if (rgid_ptr != 0) {
        long r = kbox_lkl_getgid(ctx->sysnrs);
        if (r < 0)
            return kbox_dispatch_errno((int) (-r));
        unsigned val = (unsigned) r;
        int wrc = kbox_vm_write(pid, rgid_ptr, &val, sizeof(val));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    if (egid_ptr != 0) {
        long r = kbox_lkl_getegid(ctx->sysnrs);
        if (r < 0)
            return kbox_dispatch_errno((int) (-r));
        unsigned val = (unsigned) r;
        int wrc = kbox_vm_write(pid, egid_ptr, &val, sizeof(val));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    if (sgid_ptr != 0) {
        long r = kbox_lkl_getegid(ctx->sysnrs);
        if (r < 0)
            return kbox_dispatch_errno((int) (-r));
        unsigned val = (unsigned) r;
        int wrc = kbox_vm_write(pid, sgid_ptr, &val, sizeof(val));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    return kbox_dispatch_value(0);
}

static struct kbox_dispatch forward_getresgid_override(
    const struct kbox_seccomp_notif *notif,
    gid_t gid)
{
    pid_t pid = notif->pid;
    unsigned val = (unsigned) gid;
    int i;

    for (i = 0; i < 3; i++) {
        uint64_t ptr = notif->data.args[i];
        if (ptr != 0) {
            int wrc = kbox_vm_write(pid, ptr, &val, sizeof(val));
            if (wrc < 0)
                return kbox_dispatch_errno(EIO);
        }
    }
    return kbox_dispatch_value(0);
}

static struct kbox_dispatch forward_getgroups(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long size = to_c_long_arg(notif->data.args[0]);
    uint64_t list = notif->data.args[1];

    if (size < 0)
        return kbox_dispatch_errno(EINVAL);

    /* Probe to get actual group count. */
    long count = kbox_lkl_getgroups(ctx->sysnrs, 0, NULL);
    if (count < 0)
        return kbox_dispatch_errno((int) (-count));

    if (size == 0)
        return kbox_dispatch_value((int64_t) count);

    /* Caller's buffer must be large enough. */
    if (size < count)
        return kbox_dispatch_errno(EINVAL);

    size_t byte_len = (size_t) count * sizeof(unsigned);
    unsigned *buf = malloc(byte_len > 0 ? byte_len : 1);
    if (!buf)
        return kbox_dispatch_errno(ENOMEM);

    long ret = kbox_lkl_getgroups(ctx->sysnrs, count, buf);
    if (ret < 0) {
        free(buf);
        return kbox_dispatch_errno((int) (-ret));
    }

    if (list != 0 && ret > 0) {
        size_t write_len = (size_t) ret * sizeof(unsigned);
        pid_t pid = notif->pid;
        int wrc = kbox_vm_write(pid, list, buf, write_len);
        if (wrc < 0) {
            free(buf);
            return kbox_dispatch_errno(-wrc);
        }
    }

    free(buf);
    return kbox_dispatch_value((int64_t) ret);
}

static struct kbox_dispatch forward_getgroups_override(
    const struct kbox_seccomp_notif *notif,
    gid_t gid)
{
    long size = to_c_long_arg(notif->data.args[0]);
    if (size < 0)
        return kbox_dispatch_errno(EINVAL);
    if (size == 0)
        return kbox_dispatch_value(1);

    uint64_t list = notif->data.args[1];
    if (list == 0)
        return kbox_dispatch_errno(EFAULT);

    pid_t pid = notif->pid;
    unsigned val = (unsigned) gid;
    int wrc = kbox_vm_write(pid, list, &val, sizeof(val));
    if (wrc < 0)
        return kbox_dispatch_errno(EIO);

    return kbox_dispatch_value(1);
}

/* ------------------------------------------------------------------ */
/* Identity set forwarders                                            */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_setuid(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long uid = to_c_long_arg(notif->data.args[0]);
    return kbox_dispatch_from_lkl(kbox_lkl_setuid(ctx->sysnrs, uid));
}

static struct kbox_dispatch forward_setreuid(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long ruid = to_c_long_arg(notif->data.args[0]);
    long euid = to_c_long_arg(notif->data.args[1]);
    return kbox_dispatch_from_lkl(kbox_lkl_setreuid(ctx->sysnrs, ruid, euid));
}

static struct kbox_dispatch forward_setresuid(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long ruid = to_c_long_arg(notif->data.args[0]);
    long euid = to_c_long_arg(notif->data.args[1]);
    long suid = to_c_long_arg(notif->data.args[2]);
    return kbox_dispatch_from_lkl(
        kbox_lkl_setresuid(ctx->sysnrs, ruid, euid, suid));
}

static struct kbox_dispatch forward_setgid(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long gid = to_c_long_arg(notif->data.args[0]);
    return kbox_dispatch_from_lkl(kbox_lkl_setgid(ctx->sysnrs, gid));
}

static struct kbox_dispatch forward_setregid(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long rgid = to_c_long_arg(notif->data.args[0]);
    long egid = to_c_long_arg(notif->data.args[1]);
    return kbox_dispatch_from_lkl(kbox_lkl_setregid(ctx->sysnrs, rgid, egid));
}

static struct kbox_dispatch forward_setresgid(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long rgid = to_c_long_arg(notif->data.args[0]);
    long egid = to_c_long_arg(notif->data.args[1]);
    long sgid = to_c_long_arg(notif->data.args[2]);
    return kbox_dispatch_from_lkl(
        kbox_lkl_setresgid(ctx->sysnrs, rgid, egid, sgid));
}

static struct kbox_dispatch forward_setgroups(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long size = to_c_long_arg(notif->data.args[0]);
    uint64_t list = notif->data.args[1];

    if (size < 0 || size > 65536)
        return kbox_dispatch_errno(EINVAL);

    if (size == 0)
        return kbox_dispatch_from_lkl(kbox_lkl_setgroups(ctx->sysnrs, 0, NULL));

    size_t byte_len = (size_t) size * sizeof(unsigned);
    unsigned *buf = malloc(byte_len);
    if (!buf)
        return kbox_dispatch_errno(ENOMEM);

    pid_t pid = notif->pid;
    int rrc = kbox_vm_read(pid, list, buf, byte_len);
    if (rrc < 0) {
        free(buf);
        return kbox_dispatch_errno(-rrc);
    }

    long ret = kbox_lkl_setgroups(ctx->sysnrs, size, buf);
    free(buf);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_setfsgid(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long gid = to_c_long_arg(notif->data.args[0]);
    return kbox_dispatch_from_lkl(kbox_lkl_setfsgid(ctx->sysnrs, gid));
}

/* ------------------------------------------------------------------ */
/* forward_socket                                                     */
/* ------------------------------------------------------------------ */

/*
 * Shadow socket design:
 *   1. Create an LKL socket (lives inside LKL's network stack)
 *   2. Create a host socketpair (sp[0]=supervisor, sp[1]=tracee)
 *   3. Inject sp[1] into the tracee via ADDFD
 *   4. Register sp[0]+lkl_fd with the SLIRP event loop
 *   5. The event loop pumps data between sp[0] and the LKL socket
 *
 * The tracee sees a real host FD, so poll/epoll/read/write all work
 * natively via the host kernel.  Only control-plane ops (connect,
 * getsockopt, etc.) need explicit forwarding.
 */
/*
 * INET sockets with SLIRP active get a shadow socket bridge so data
 * flows through the host kernel socketpair (bypassing BKL contention
 * in blocking LKL recv/send calls).  Non-INET sockets and INET sockets
 * without SLIRP use the standard virtual FD path.
 *
 * Limitation: listen/accept on shadow sockets fail because the AF_UNIX
 * socketpair doesn't support inbound connections.  Server sockets must
 * be used without --net or via a future deferred-bridge approach.
 */
static struct kbox_dispatch forward_socket(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long domain = to_c_long_arg(notif->data.args[0]);
    long type_raw = to_c_long_arg(notif->data.args[1]);
    long protocol = to_c_long_arg(notif->data.args[2]);

    int base_type = (int) type_raw & 0xFF;

    long ret = kbox_lkl_socket(ctx->sysnrs, domain, type_raw, protocol);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long lkl_fd = ret;

    /* Virtual FD path when shadow bridge is not applicable:
     * - SLIRP not active (no --net)
     * - Non-INET domain (AF_UNIX, AF_NETLINK, etc.)
     * - Non-stream/datagram type (SOCK_RAW, etc.) -- socketpair(AF_UNIX)
     *   only supports SOCK_STREAM and SOCK_DGRAM */
    if (!kbox_net_is_active() ||
        (domain != 2 /* AF_INET */ && domain != 10 /* AF_INET6 */) ||
        (base_type != SOCK_STREAM && base_type != SOCK_DGRAM)) {
        long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd, 0);
        if (vfd < 0) {
            kbox_lkl_close(ctx->sysnrs, lkl_fd);
            return kbox_dispatch_errno(EMFILE);
        }
        return kbox_dispatch_value((int64_t) vfd);
    }

    /* Shadow socket bridge for INET with SLIRP. */
    int sp[2];
    if (socketpair(AF_UNIX, base_type | SOCK_CLOEXEC, 0, sp) < 0) {
        kbox_lkl_close(ctx->sysnrs, lkl_fd);
        return kbox_dispatch_errno(errno);
    }
    fcntl(sp[0], F_SETFL, O_NONBLOCK);
    if (type_raw & SOCK_NONBLOCK)
        fcntl(sp[1], F_SETFL, O_NONBLOCK);

    long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd, 0);
    if (vfd < 0) {
        close(sp[0]);
        close(sp[1]);
        kbox_lkl_close(ctx->sysnrs, lkl_fd);
        return kbox_dispatch_errno(EMFILE);
    }

    if (kbox_net_register_socket((int) lkl_fd, sp[0], base_type) < 0) {
        close(sp[0]);
        close(sp[1]);
        /* Fall back to virtual FD. */
        return kbox_dispatch_value((int64_t) vfd);
    }

    uint32_t addfd_flags = 0;
    if (type_raw & SOCK_CLOEXEC)
        addfd_flags = O_CLOEXEC;
    int host_fd =
        kbox_notify_addfd(ctx->listener_fd, notif->id, sp[1], addfd_flags);
    if (host_fd < 0) {
        /* Deregister closes sp[0] and marks inactive. */
        kbox_net_deregister_socket((int) lkl_fd);
        close(sp[1]);
        kbox_fd_table_remove(ctx->fd_table, vfd);
        kbox_lkl_close(ctx->sysnrs, lkl_fd);
        return kbox_dispatch_errno(-host_fd);
    }
    kbox_fd_table_set_host_fd(ctx->fd_table, vfd, host_fd);

    {
        struct kbox_fd_entry *e = NULL;
        if (vfd >= KBOX_FD_BASE)
            e = &ctx->fd_table->entries[vfd - KBOX_FD_BASE];
        else if (vfd >= 0 && vfd < KBOX_LOW_FD_MAX)
            e = &ctx->fd_table->low_fds[vfd];
        if (e) {
            e->shadow_sp = sp[1];
            if (type_raw & SOCK_CLOEXEC)
                e->cloexec = 1;
        }
    }

    return kbox_dispatch_value((int64_t) host_fd);
}

/* ------------------------------------------------------------------ */
/* forward_bind / forward_connect                                     */
/* ------------------------------------------------------------------ */

static long resolve_lkl_socket(struct kbox_supervisor_ctx *ctx, long fd);

static struct kbox_dispatch forward_bind(const struct kbox_seccomp_notif *notif,
                                         struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = resolve_lkl_socket(ctx, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = notif->pid;
    uint64_t addr_ptr = notif->data.args[1];
    int64_t len_raw = to_c_long_arg(notif->data.args[2]);
    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;

    if (addr_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    if (len > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t buf[4096];
    int rrc = kbox_vm_read(pid, addr_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long ret = kbox_lkl_bind(ctx->sysnrs, lkl_fd, buf, (long) len);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_connect                                                    */
/* ------------------------------------------------------------------ */

/*
 * Resolve LKL FD from a tracee FD.  The tracee may hold either a
 * virtual FD (>= KBOX_FD_BASE) or a host FD from a shadow socket
 * (injected via ADDFD).  Try both paths.
 */
static long resolve_lkl_socket(struct kbox_supervisor_ctx *ctx, long fd)
{
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd >= 0)
        return lkl_fd;

    /* Shadow socket: tracee uses the host_fd directly. */
    long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
    if (vfd >= 0)
        return kbox_fd_table_get_lkl(ctx->fd_table, vfd);

    return -1;
}

static struct kbox_dispatch forward_connect(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = resolve_lkl_socket(ctx, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = notif->pid;
    uint64_t addr_ptr = notif->data.args[1];
    int64_t len_raw = to_c_long_arg(notif->data.args[2]);
    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;

    if (addr_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    if (len > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t buf[4096];
    int rrc = kbox_vm_read(pid, addr_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long ret = kbox_lkl_connect(ctx->sysnrs, lkl_fd, buf, (long) len);

    /*
     * Propagate -EINPROGRESS directly for nonblocking sockets.
     * The tracee's poll(POLLOUT) on the AF_UNIX socketpair returns
     * immediately (spurious wakeup), but getsockopt(SO_ERROR) is
     * forwarded to the LKL socket and returns the real handshake
     * status.  The tracee retries poll+getsockopt until SO_ERROR
     * clears -- standard nonblocking connect flow.
     */
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_getsockopt                                                 */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_getsockopt(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = notif->pid;
    long level = to_c_long_arg(notif->data.args[1]);
    long optname = to_c_long_arg(notif->data.args[2]);
    uint64_t optval_ptr = notif->data.args[3];
    uint64_t optlen_ptr = notif->data.args[4];

    if (optval_ptr == 0 || optlen_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Read the optlen from tracee. */
    unsigned int optlen;
    int rrc = kbox_vm_read(pid, optlen_ptr, &optlen, sizeof(optlen));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    if (optlen > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t optval[4096];
    unsigned int out_len = optlen;

    long ret = kbox_lkl_getsockopt(ctx->sysnrs, lkl_fd, level, optname, optval,
                                   &out_len);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    /* Write min(out_len, optlen) to avoid leaking stack data. */
    unsigned int write_len = out_len < optlen ? out_len : optlen;
    int wrc = kbox_vm_write(pid, optval_ptr, optval, write_len);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    wrc = kbox_vm_write(pid, optlen_ptr, &out_len, sizeof(out_len));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* ------------------------------------------------------------------ */
/* forward_setsockopt                                                 */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_setsockopt(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = notif->pid;
    long level = to_c_long_arg(notif->data.args[1]);
    long optname = to_c_long_arg(notif->data.args[2]);
    uint64_t optval_ptr = notif->data.args[3];
    long optlen = to_c_long_arg(notif->data.args[4]);

    if (optlen < 0 || optlen > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t optval[4096] = {0};
    if (optval_ptr != 0 && optlen > 0) {
        int rrc = kbox_vm_read(pid, optval_ptr, optval, (size_t) optlen);
        if (rrc < 0)
            return kbox_dispatch_errno(-rrc);
    }

    long ret = kbox_lkl_setsockopt(ctx->sysnrs, lkl_fd, level, optname,
                                   optval_ptr ? optval : NULL, optlen);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_getsockname / forward_getpeername                          */
/* ------------------------------------------------------------------ */

typedef long (*sockaddr_query_fn)(const struct kbox_sysnrs *s,
                                  long fd,
                                  void *addr,
                                  void *addrlen);

static struct kbox_dispatch forward_sockaddr_query(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx,
    sockaddr_query_fn query)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = notif->pid;
    uint64_t addr_ptr = notif->data.args[1];
    uint64_t len_ptr = notif->data.args[2];

    if (addr_ptr == 0 || len_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    unsigned int addrlen;
    int rrc = kbox_vm_read(pid, len_ptr, &addrlen, sizeof(addrlen));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    if (addrlen > 4096)
        addrlen = 4096;

    uint8_t addr[4096];
    unsigned int out_len = addrlen;

    long ret = query(ctx->sysnrs, lkl_fd, addr, &out_len);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    unsigned int write_len = out_len < addrlen ? out_len : addrlen;
    int wrc = kbox_vm_write(pid, addr_ptr, addr, write_len);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    wrc = kbox_vm_write(pid, len_ptr, &out_len, sizeof(out_len));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

static struct kbox_dispatch forward_getsockname(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_sockaddr_query(notif, ctx, kbox_lkl_getsockname);
}

static struct kbox_dispatch forward_getpeername(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_sockaddr_query(notif, ctx, kbox_lkl_getpeername);
}

/* ------------------------------------------------------------------ */
/* forward_shutdown                                                   */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_shutdown(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    long how = to_c_long_arg(notif->data.args[1]);
    long ret = kbox_lkl_shutdown(ctx->sysnrs, lkl_fd, how);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_sendto / forward_recvfrom / forward_sendmsg / forward_recvmsg */
/* ------------------------------------------------------------------ */

/*
 * forward_sendto: for shadow sockets with a destination address,
 * forward the data + address directly to the LKL socket.
 * This is needed for unconnected UDP (DNS resolver uses sendto
 * with sockaddr_in without prior connect).
 *
 * sendto(fd, buf, len, flags, dest_addr, addrlen)
 *   args[0]=fd, args[1]=buf, args[2]=len, args[3]=flags,
 *   args[4]=dest_addr, args[5]=addrlen
 */
static struct kbox_dispatch forward_sendto(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    uint64_t dest_ptr = notif->data.args[4];
    if (dest_ptr == 0)
        return kbox_dispatch_continue(); /* no dest addr: stream data path */

    /* Has a destination address: forward via LKL sendto. */
    pid_t pid = notif->pid;
    uint64_t buf_ptr = notif->data.args[1];
    int64_t len_raw = to_c_long_arg(notif->data.args[2]);
    long flags = to_c_long_arg(notif->data.args[3]);
    int64_t addrlen_raw = to_c_long_arg(notif->data.args[5]);

    if (len_raw < 0 || addrlen_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;
    size_t addrlen = (size_t) addrlen_raw;

    if (len > 65536)
        len = 65536;
    if (addrlen > 128)
        return kbox_dispatch_errno(EINVAL);

    uint8_t buf[65536];
    uint8_t addr[128];

    int rrc = kbox_vm_read(pid, buf_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);
    rrc = kbox_vm_read(pid, dest_ptr, addr, addrlen);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long ret = kbox_lkl_sendto(ctx->sysnrs, lkl_fd, buf, (long) len, flags,
                               addr, (long) addrlen);
    return kbox_dispatch_from_lkl(ret);
}

/*
 * forward_recvfrom: for shadow sockets, receive data + source address
 * from the LKL socket and write them back to the tracee.
 *
 * recvfrom(fd, buf, len, flags, src_addr, addrlen)
 *   args[0]=fd, args[1]=buf, args[2]=len, args[3]=flags,
 *   args[4]=src_addr, args[5]=addrlen
 */
static struct kbox_dispatch forward_recvfrom(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    uint64_t src_ptr = notif->data.args[4];
    if (src_ptr == 0)
        return kbox_dispatch_continue(); /* no addr buffer: stream path */

    pid_t pid = notif->pid;
    uint64_t buf_ptr = notif->data.args[1];
    int64_t len_raw = to_c_long_arg(notif->data.args[2]);
    long flags = to_c_long_arg(notif->data.args[3]);
    uint64_t addrlen_ptr = notif->data.args[5];

    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;
    if (len > 65536)
        len = 65536;

    unsigned int addrlen = 0;
    if (addrlen_ptr != 0) {
        int rrc = kbox_vm_read(pid, addrlen_ptr, &addrlen, sizeof(addrlen));
        if (rrc < 0)
            return kbox_dispatch_errno(-rrc);
    }
    if (addrlen > 128)
        addrlen = 128;

    uint8_t buf[65536];
    uint8_t addr[128];
    unsigned int out_addrlen = addrlen;

    long ret = kbox_lkl_recvfrom(ctx->sysnrs, lkl_fd, buf, (long) len, flags,
                                 addr, &out_addrlen);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    int wrc = kbox_vm_write(pid, buf_ptr, buf, (size_t) ret);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    if (src_ptr != 0 && out_addrlen > 0) {
        unsigned int write_len = out_addrlen < addrlen ? out_addrlen : addrlen;
        wrc = kbox_vm_write(pid, src_ptr, addr, write_len);
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    if (addrlen_ptr != 0) {
        wrc =
            kbox_vm_write(pid, addrlen_ptr, &out_addrlen, sizeof(out_addrlen));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    return kbox_dispatch_value(ret);
}

/*
 * forward_sendmsg: intercept for shadow sockets so that msg_name
 * (destination address) reaches the LKL socket.  For non-shadow
 * sockets or connected stream sockets without msg_name, CONTINUE
 * lets the host kernel handle the AF_UNIX socketpair write.
 *
 * sendmsg(fd, msg, flags)
 *   args[0]=fd, args[1]=msg_ptr, args[2]=flags
 *
 * struct msghdr { void *msg_name; socklen_t msg_namelen;
 *   struct iovec *msg_iov; size_t msg_iovlen; ... }
 */
/* Unreachable: sendmsg is BPF allow-listed for SCM_RIGHTS.
 * Kept for documentation; will be wired when FD transfer is refactored. */
__attribute__((unused)) static struct kbox_dispatch forward_sendmsg(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = notif->pid;
    uint64_t msg_ptr = notif->data.args[1];
    long flags = to_c_long_arg(notif->data.args[2]);

    if (msg_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Read the msghdr from the tracee. */
    struct {
        uint64_t msg_name;
        uint32_t msg_namelen;
        uint32_t __pad0;
        uint64_t msg_iov;
        uint64_t msg_iovlen;
        uint64_t msg_control;
        uint64_t msg_controllen;
        int msg_flags;
    } mh;
    int rrc = kbox_vm_read(pid, msg_ptr, &mh, sizeof(mh));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    /* No destination address: stream data path via CONTINUE. */
    if (mh.msg_name == 0 || mh.msg_namelen == 0)
        return kbox_dispatch_continue();

    /* Has destination address: read iov data and address, forward to LKL. */
    uint8_t addr[128];
    if (mh.msg_namelen > sizeof(addr))
        return kbox_dispatch_errno(EINVAL);
    rrc = kbox_vm_read(pid, mh.msg_name, addr, mh.msg_namelen);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    /* Gather all iovec data into a contiguous buffer. */
    if (mh.msg_iovlen == 0)
        return kbox_dispatch_value(0);

    uint8_t buf[65536];
    size_t total = 0;
    size_t niov = (size_t) mh.msg_iovlen;
    if (niov > 64)
        niov = 64;

    struct {
        uint64_t iov_base;
        uint64_t iov_len;
    } iovs[64];
    size_t iov_bytes = niov * sizeof(iovs[0]);
    rrc = kbox_vm_read(pid, mh.msg_iov, iovs, iov_bytes);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    for (size_t v = 0; v < niov && total < sizeof(buf); v++) {
        size_t chunk = (size_t) iovs[v].iov_len;
        if (total + chunk > sizeof(buf))
            chunk = sizeof(buf) - total;
        if (chunk > 0 && iovs[v].iov_base != 0) {
            rrc = kbox_vm_read(pid, iovs[v].iov_base, buf + total, chunk);
            if (rrc < 0)
                return kbox_dispatch_errno(-rrc);
            total += chunk;
        }
    }

    long ret = kbox_lkl_sendto(ctx->sysnrs, lkl_fd, buf, (long) total, flags,
                               addr, (long) mh.msg_namelen);
    return kbox_dispatch_from_lkl(ret);
}

/*
 * forward_recvmsg: intercept for shadow sockets so that msg_name
 * (source address) is populated from the LKL socket, not the
 * AF_UNIX socketpair.
 *
 * recvmsg(fd, msg, flags)
 *   args[0]=fd, args[1]=msg_ptr, args[2]=flags
 */
static struct kbox_dispatch forward_recvmsg(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = notif->pid;
    uint64_t msg_ptr = notif->data.args[1];
    long flags = to_c_long_arg(notif->data.args[2]);

    if (msg_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    struct {
        uint64_t msg_name;
        uint32_t msg_namelen;
        uint32_t __pad0;
        uint64_t msg_iov;
        uint64_t msg_iovlen;
        uint64_t msg_control;
        uint64_t msg_controllen;
        int msg_flags;
    } mh;
    int rrc = kbox_vm_read(pid, msg_ptr, &mh, sizeof(mh));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    /* No msg_name: for connected stream sockets, CONTINUE via socketpair. */
    if (mh.msg_name == 0 || mh.msg_namelen == 0)
        return kbox_dispatch_continue();

    /* Read all iovecs to determine total buffer capacity. */
    if (mh.msg_iovlen == 0)
        return kbox_dispatch_value(0);

    size_t niov = (size_t) mh.msg_iovlen;
    if (niov > 64)
        niov = 64;

    struct {
        uint64_t iov_base;
        uint64_t iov_len;
    } iovs[64];
    rrc = kbox_vm_read(pid, mh.msg_iov, iovs, niov * sizeof(iovs[0]));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    size_t total_cap = 0;
    for (size_t v = 0; v < niov; v++)
        total_cap += (size_t) iovs[v].iov_len;
    if (total_cap > 65536)
        total_cap = 65536;

    uint8_t buf[65536];
    uint8_t addr[128];
    unsigned int addrlen = mh.msg_namelen < sizeof(addr)
                               ? mh.msg_namelen
                               : (unsigned int) sizeof(addr);
    unsigned int out_addrlen = addrlen;

    long ret = kbox_lkl_recvfrom(ctx->sysnrs, lkl_fd, buf, (long) total_cap,
                                 flags, addr, &out_addrlen);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    /* Scatter received data across tracee iov buffers. */
    size_t written = 0;
    for (size_t v = 0; v < niov && written < (size_t) ret; v++) {
        size_t chunk = (size_t) ret - written;
        if (chunk > (size_t) iovs[v].iov_len)
            chunk = (size_t) iovs[v].iov_len;
        if (chunk > 0 && iovs[v].iov_base != 0) {
            int wrc2 =
                kbox_vm_write(pid, iovs[v].iov_base, buf + written, chunk);
            if (wrc2 < 0)
                return kbox_dispatch_errno(-wrc2);
            written += chunk;
        }
    }

    /* Write source address to tracee msg_name. */
    if (out_addrlen > 0) {
        unsigned int write_len =
            out_addrlen < mh.msg_namelen ? out_addrlen : mh.msg_namelen;
        int awrc = kbox_vm_write(pid, mh.msg_name, addr, write_len);
        if (awrc < 0)
            return kbox_dispatch_errno(-awrc);
    }

    /* Update msg_namelen in the msghdr. */
    int nwrc = kbox_vm_write(pid, msg_ptr + 8 /* offset of msg_namelen */,
                             &out_addrlen, sizeof(out_addrlen));
    if (nwrc < 0)
        return kbox_dispatch_errno(-nwrc);

    return kbox_dispatch_value(ret);
}

/* ------------------------------------------------------------------ */
/* forward_clock_gettime                                              */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_clock_gettime(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    int clockid = (int) to_c_long_arg(notif->data.args[0]);
    uint64_t remote_ts = notif->data.args[1];

    if (remote_ts == 0)
        return kbox_dispatch_errno(EFAULT);

    struct timespec ts;
    if (clock_gettime(clockid, &ts) < 0)
        return kbox_dispatch_errno(errno);

    int wrc = kbox_vm_write(pid, remote_ts, &ts, sizeof(ts));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* ------------------------------------------------------------------ */
/* forward_clock_getres                                               */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_clock_getres(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    int clockid = (int) to_c_long_arg(notif->data.args[0]);
    uint64_t remote_ts = notif->data.args[1];

    struct timespec ts;
    if (clock_getres(clockid, remote_ts ? &ts : NULL) < 0)
        return kbox_dispatch_errno(errno);

    if (remote_ts != 0) {
        int wrc = kbox_vm_write(pid, remote_ts, &ts, sizeof(ts));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    return kbox_dispatch_value(0);
}

/* ------------------------------------------------------------------ */
/* forward_gettimeofday                                               */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_gettimeofday(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    uint64_t remote_tv = notif->data.args[0];
    uint64_t remote_tz = notif->data.args[1];

    /*
     * Use clock_gettime(CLOCK_REALTIME) as the underlying source,
     * which works on both x86_64 and aarch64.
     */
    if (remote_tv != 0) {
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
            return kbox_dispatch_errno(errno);

        struct {
            long tv_sec;
            long tv_usec;
        } tv;
        tv.tv_sec = ts.tv_sec;
        tv.tv_usec = ts.tv_nsec / 1000;

        int wrc = kbox_vm_write(pid, remote_tv, &tv, sizeof(tv));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    if (remote_tz != 0) {
        /* Return zeroed timezone (UTC). */
        struct {
            int tz_minuteswest;
            int tz_dsttime;
        } tz = {0, 0};

        int wrc = kbox_vm_write(pid, remote_tz, &tz, sizeof(tz));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    return kbox_dispatch_value(0);
}

/* ------------------------------------------------------------------ */
/* forward_readlinkat                                                  */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_readlinkat(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    long dirfd_raw = to_dirfd_arg(notif->data.args[0]);
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc =
        kbox_vm_read_string(pid, notif->data.args[1], pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    uint64_t remote_buf = notif->data.args[2];
    int64_t bufsiz_raw = to_c_long_arg(notif->data.args[3]);
    if (bufsiz_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t bufsiz = (size_t) bufsiz_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long lkl_dirfd = resolve_open_dirfd(translated, dirfd_raw, ctx->fd_table);
    if (lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    if (bufsiz > KBOX_MAX_PATH)
        bufsiz = KBOX_MAX_PATH;

    char linkbuf[KBOX_MAX_PATH];
    long ret = kbox_lkl_readlinkat(ctx->sysnrs, lkl_dirfd, translated, linkbuf,
                                   (long) bufsiz);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    size_t n = (size_t) ret;
    int wrc = kbox_vm_write(pid, remote_buf, linkbuf, n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

/* ------------------------------------------------------------------ */
/* forward_pipe2                                                       */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_pipe2(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    uint64_t remote_pipefd = notif->data.args[0];
    long flags = to_c_long_arg(notif->data.args[1]);

    if (remote_pipefd == 0)
        return kbox_dispatch_errno(EFAULT);

    /*
     * Create a real host pipe and inject both ends into the tracee
     * via SECCOMP_IOCTL_NOTIF_ADDFD.  This makes pipes fully native:
     *
     *   - dup2/close/read/write on pipe FDs → CONTINUE (host kernel)
     *   - Proper fork semantics: both parent and child share the
     *     real pipe, no virtual FD table conflicts.
     *   - No LKL overhead for IPC data transfer.
     */
    int host_pipefd[2];
    if (pipe2(host_pipefd, (int) flags) < 0)
        return kbox_dispatch_errno(errno);

    uint32_t cloexec_flag = (flags & O_CLOEXEC) ? O_CLOEXEC : 0;

    int tracee_fd0 = kbox_notify_addfd(ctx->listener_fd, notif->id,
                                       host_pipefd[0], cloexec_flag);
    if (tracee_fd0 < 0) {
        close(host_pipefd[0]);
        close(host_pipefd[1]);
        return kbox_dispatch_errno(-tracee_fd0);
    }

    int tracee_fd1 = kbox_notify_addfd(ctx->listener_fd, notif->id,
                                       host_pipefd[1], cloexec_flag);
    if (tracee_fd1 < 0) {
        close(host_pipefd[0]);
        close(host_pipefd[1]);
        return kbox_dispatch_errno(-tracee_fd1);
    }

    /* Supervisor copies no longer needed; tracee owns its own copies. */
    close(host_pipefd[0]);
    close(host_pipefd[1]);

    int guest_fds[2] = {tracee_fd0, tracee_fd1};
    int wrc = kbox_vm_write(pid, remote_pipefd, guest_fds, sizeof(guest_fds));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* ------------------------------------------------------------------ */
/* forward_uname                                                       */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_uname(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    uint64_t remote_buf = notif->data.args[0];

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);

    struct utsname uts;
    memset(&uts, 0, sizeof(uts));
    snprintf(uts.sysname, sizeof(uts.sysname), "Linux");
    snprintf(uts.nodename, sizeof(uts.nodename), "kbox");
    snprintf(uts.release, sizeof(uts.release), "6.8.0-kbox");
    snprintf(uts.version, sizeof(uts.version), "#1 SMP");
#if defined(__x86_64__)
    snprintf(uts.machine, sizeof(uts.machine), "x86_64");
#elif defined(__aarch64__)
    snprintf(uts.machine, sizeof(uts.machine), "aarch64");
#else
    snprintf(uts.machine, sizeof(uts.machine), "unknown");
#endif

    int wrc = kbox_vm_write(pid, remote_buf, &uts, sizeof(uts));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* ------------------------------------------------------------------ */
/* forward_getrandom                                                   */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_getrandom(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    uint64_t remote_buf = notif->data.args[0];
    int64_t buflen_raw = to_c_long_arg(notif->data.args[1]);

    if (buflen_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t buflen = (size_t) buflen_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (buflen == 0)
        return kbox_dispatch_value(0);

    /*
     * Read from /dev/urandom via LKL.  Fall back to host if LKL
     * does not have the device available.
     */
    size_t max_chunk = 256;
    if (buflen > max_chunk)
        buflen = max_chunk;

    uint8_t scratch[256];
    long fd = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, "/dev/urandom",
                              O_RDONLY, 0);
    if (fd < 0) {
        /* Fallback: let host kernel handle it. */
        return kbox_dispatch_continue();
    }

    long ret = kbox_lkl_read(ctx->sysnrs, fd, scratch, (long) buflen);
    kbox_lkl_close(ctx->sysnrs, fd);

    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    size_t n = (size_t) ret;
    int wrc = kbox_vm_write(pid, remote_buf, scratch, n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

/* ------------------------------------------------------------------ */
/* forward_syslog (klogctl)                                            */
/* ------------------------------------------------------------------ */

/*
 * syslog(type, buf, len) -- forward to LKL so dmesg shows the LKL
 * kernel's ring buffer, not the host's.
 *
 * Types that read into buf (2=READ, 3=READ_ALL, 4=READ_CLEAR):
 *   call LKL with a scratch buffer, then copy to tracee.
 * Types that just return a value (0,1,5-10):
 *   forward type+len, return the result directly.
 */
#define SYSLOG_ACTION_READ 2
#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_READ_CLEAR 4
#define SYSLOG_ACTION_SIZE_BUFFER 10

static struct kbox_dispatch forward_syslog(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    long type = to_c_long_arg(notif->data.args[0]);
    uint64_t remote_buf = notif->data.args[1];
    long len = to_c_long_arg(notif->data.args[2]);

    int needs_buf =
        (type == SYSLOG_ACTION_READ || type == SYSLOG_ACTION_READ_ALL ||
         type == SYSLOG_ACTION_READ_CLEAR);

    if (!needs_buf) {
        /* No buffer transfer: SIZE_BUFFER, CONSOLE_ON/OFF, etc. */
        long ret = lkl_syscall6(ctx->sysnrs->syslog, type, 0, len, 0, 0, 0);
        return kbox_dispatch_from_lkl(ret);
    }

    if (len <= 0)
        return kbox_dispatch_errno(EINVAL);
    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);

    /*
     * Static buffer -- safe because the supervisor is single-threaded.
     * Clamp to the actual LKL ring buffer size so READ_CLEAR never
     * discards data beyond what we can copy out.  The ring buffer size
     * is fixed at boot, so cache it after the first query.
     * Hard-cap at 1MB (the static buffer size) as a safety ceiling.
     */
    static uint8_t scratch[1024 * 1024];
    static long cached_ring_sz;
    if (!cached_ring_sz) {
        long sz = lkl_syscall6(ctx->sysnrs->syslog, SYSLOG_ACTION_SIZE_BUFFER,
                               0, 0, 0, 0, 0);
        cached_ring_sz = (sz > 0) ? sz : -1;
    }
    if (cached_ring_sz > 0 && len > cached_ring_sz)
        len = cached_ring_sz;
    if (len > (long) sizeof(scratch))
        len = (long) sizeof(scratch);

    long ret =
        lkl_syscall6(ctx->sysnrs->syslog, type, (long) scratch, len, 0, 0, 0);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    size_t n = (size_t) ret;
    int wrc = kbox_vm_write(pid, remote_buf, scratch, n);

    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

/* ------------------------------------------------------------------ */
/* forward_prctl                                                       */
/* ------------------------------------------------------------------ */

#ifndef PR_SET_NAME
#define PR_SET_NAME 15
#endif
#ifndef PR_GET_NAME
#define PR_GET_NAME 16
#endif
#ifndef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 4
#endif
#ifndef PR_GET_DUMPABLE
#define PR_GET_DUMPABLE 3
#endif

static struct kbox_dispatch forward_prctl(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long option = to_c_long_arg(notif->data.args[0]);

    /*
     * Block PR_SET_DUMPABLE(0): clearing dumpability makes
     * process_vm_readv fail, which would bypass clone3
     * namespace-flag sanitization (the supervisor can't read
     * clone_args.flags from a non-dumpable process).
     * Return success without actually clearing -- the tracee
     * thinks it worked, but the supervisor retains read access.
     */
    if (option == PR_SET_DUMPABLE && to_c_long_arg(notif->data.args[1]) == 0)
        return kbox_dispatch_value(0);
    /* Match: report dumpable even if guest tried to clear it. */
    if (option == PR_GET_DUMPABLE)
        return kbox_dispatch_value(1);

    /*
     * Only forward PR_SET_NAME and PR_GET_NAME to LKL.
     * Everything else passes through to the host kernel.
     *
     * PR_SET_NAME/PR_GET_NAME use a 16-byte name buffer.  The tracee
     * passes a pointer in arg2 which is in the tracee's address space,
     * not ours.  We must copy through kbox_vm_read/kbox_vm_write.
     */
    if (option != PR_SET_NAME && option != PR_GET_NAME)
        return kbox_dispatch_continue();

    pid_t pid = notif->pid;
    uint64_t remote_name = notif->data.args[1];
    if (remote_name == 0)
        return kbox_dispatch_errno(EFAULT);

    /* PR_SET_NAME: read 16-byte name from tracee, pass local copy to LKL. */
    if (option == PR_SET_NAME) {
        char name[16];
        int rrc = kbox_vm_read(pid, remote_name, name, sizeof(name));
        if (rrc < 0)
            return kbox_dispatch_errno(-rrc);
        name[15] = '\0'; /* ensure NUL termination */
        long ret =
            lkl_syscall6(ctx->sysnrs->prctl, option, (long) name, 0, 0, 0, 0);
        return kbox_dispatch_from_lkl(ret);
    }

    /* PR_GET_NAME: get name from LKL into local buffer, write to tracee. */
    char name[16] = {0};
    long ret =
        lkl_syscall6(ctx->sysnrs->prctl, option, (long) name, 0, 0, 0, 0);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);
    int wrc = kbox_vm_write(pid, remote_name, name, sizeof(name));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    return kbox_dispatch_value(0);
}

/* ------------------------------------------------------------------ */
/* forward_umask                                                       */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_umask(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long mask = to_c_long_arg(notif->data.args[0]);
    long ret = kbox_lkl_umask(ctx->sysnrs, mask);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_pwrite64                                                    */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_pwrite64(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    uint64_t remote_buf = notif->data.args[1];
    int64_t count_raw = to_c_long_arg(notif->data.args[2]);
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;
    long offset = to_c_long_arg(notif->data.args[3]);

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count == 0)
        return kbox_dispatch_value(0);

    pid_t pid = notif->pid;
    size_t max_count = 1024 * 1024;
    if (count > max_count)
        count = max_count;

    size_t total = 0;
    uint8_t *scratch = malloc(KBOX_IO_CHUNK_LEN);
    if (!scratch)
        return kbox_dispatch_errno(ENOMEM);

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        if (chunk_len > count - total)
            chunk_len = count - total;

        uint64_t remote = remote_buf + total;
        int rrc = kbox_vm_read(pid, remote, scratch, chunk_len);
        if (rrc < 0) {
            if (total > 0)
                break;
            free(scratch);
            return kbox_dispatch_errno(-rrc);
        }

        long ret = kbox_lkl_pwrite64(ctx->sysnrs, lkl_fd, scratch,
                                     (long) chunk_len, offset + (long) total);
        if (ret < 0) {
            if (total == 0) {
                free(scratch);
                return kbox_dispatch_errno((int) (-ret));
            }
            break;
        }

        size_t n = (size_t) ret;
        total += n;
        if (n < chunk_len)
            break;
    }

    free(scratch);
    return kbox_dispatch_value((int64_t) total);
}

/* ------------------------------------------------------------------ */
/* forward_writev                                                      */
/* ------------------------------------------------------------------ */

/*
 * iovec layout matches the kernel's: { void *iov_base; size_t iov_len; }
 * On 64-bit: 16 bytes per entry.
 */
#define IOV_ENTRY_SIZE 16
#define IOV_MAX_COUNT 1024

static struct kbox_dispatch forward_writev(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = notif->pid;
    uint64_t remote_iov = notif->data.args[1];
    int64_t iovcnt_raw = to_c_long_arg(notif->data.args[2]);

    if (iovcnt_raw <= 0 || iovcnt_raw > IOV_MAX_COUNT)
        return kbox_dispatch_errno(EINVAL);
    if (remote_iov == 0)
        return kbox_dispatch_errno(EFAULT);

    int iovcnt = (int) iovcnt_raw;
    size_t iov_bytes = (size_t) iovcnt * IOV_ENTRY_SIZE;
    uint8_t *iov_buf = malloc(iov_bytes);
    if (!iov_buf)
        return kbox_dispatch_errno(ENOMEM);

    int rrc = kbox_vm_read(pid, remote_iov, iov_buf, iov_bytes);
    if (rrc < 0) {
        free(iov_buf);
        return kbox_dispatch_errno(-rrc);
    }

    int mirror_host = kbox_fd_table_mirror_tty(ctx->fd_table, fd);
    size_t total = 0;
    uint8_t *scratch = malloc(KBOX_IO_CHUNK_LEN);
    if (!scratch) {
        free(iov_buf);
        return kbox_dispatch_errno(ENOMEM);
    }

    int err = 0;
    int i;
    for (i = 0; i < iovcnt; i++) {
        uint64_t base;
        uint64_t len;
        memcpy(&base, &iov_buf[i * IOV_ENTRY_SIZE], 8);
        memcpy(&len, &iov_buf[i * IOV_ENTRY_SIZE + 8], 8);

        if (base == 0 || len == 0)
            continue;

        size_t seg_total = 0;
        while (seg_total < len) {
            size_t chunk = KBOX_IO_CHUNK_LEN;
            if (chunk > len - seg_total)
                chunk = len - seg_total;

            rrc = kbox_vm_read(pid, base + seg_total, scratch, chunk);
            if (rrc < 0) {
                err = -rrc;
                goto done;
            }

            long ret =
                kbox_lkl_write(ctx->sysnrs, lkl_fd, scratch, (long) chunk);
            if (ret < 0) {
                err = (int) (-ret);
                goto done;
            }

            size_t n = (size_t) ret;
            if (mirror_host && n > 0)
                (void) write(STDOUT_FILENO, scratch, n);

            seg_total += n;
            total += n;
            if (n < chunk)
                goto done;
        }
    }

done:
    free(scratch);
    free(iov_buf);
    if (total == 0 && err)
        return kbox_dispatch_errno(err);
    return kbox_dispatch_value((int64_t) total);
}

/* ------------------------------------------------------------------ */
/* forward_readv                                                       */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_readv(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = notif->pid;
    uint64_t remote_iov = notif->data.args[1];
    int64_t iovcnt_raw = to_c_long_arg(notif->data.args[2]);

    if (iovcnt_raw <= 0 || iovcnt_raw > IOV_MAX_COUNT)
        return kbox_dispatch_errno(EINVAL);
    if (remote_iov == 0)
        return kbox_dispatch_errno(EFAULT);

    int iovcnt = (int) iovcnt_raw;
    size_t iov_bytes = (size_t) iovcnt * IOV_ENTRY_SIZE;
    uint8_t *iov_buf = malloc(iov_bytes);
    if (!iov_buf)
        return kbox_dispatch_errno(ENOMEM);

    int rrc = kbox_vm_read(pid, remote_iov, iov_buf, iov_bytes);
    if (rrc < 0) {
        free(iov_buf);
        return kbox_dispatch_errno(-rrc);
    }

    size_t total = 0;
    uint8_t *scratch = malloc(KBOX_IO_CHUNK_LEN);
    if (!scratch) {
        free(iov_buf);
        return kbox_dispatch_errno(ENOMEM);
    }

    int i;
    for (i = 0; i < iovcnt; i++) {
        uint64_t base;
        uint64_t len;
        memcpy(&base, &iov_buf[i * IOV_ENTRY_SIZE], 8);
        memcpy(&len, &iov_buf[i * IOV_ENTRY_SIZE + 8], 8);

        if (base == 0 || len == 0)
            continue;

        size_t seg_total = 0;
        while (seg_total < len) {
            size_t chunk = KBOX_IO_CHUNK_LEN;
            if (chunk > len - seg_total)
                chunk = len - seg_total;

            long ret =
                kbox_lkl_read(ctx->sysnrs, lkl_fd, scratch, (long) chunk);
            if (ret < 0) {
                if (total == 0) {
                    free(scratch);
                    free(iov_buf);
                    return kbox_dispatch_errno((int) (-ret));
                }
                goto done_readv;
            }

            size_t n = (size_t) ret;
            if (n == 0)
                goto done_readv;

            int wrc = kbox_vm_write(pid, base + seg_total, scratch, n);
            if (wrc < 0) {
                free(scratch);
                free(iov_buf);
                return kbox_dispatch_errno(-wrc);
            }

            seg_total += n;
            total += n;
            if (n < chunk)
                goto done_readv;
        }
    }

done_readv:
    free(scratch);
    free(iov_buf);
    return kbox_dispatch_value((int64_t) total);
}

/* ------------------------------------------------------------------ */
/* forward_ftruncate                                                   */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_ftruncate(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    long length = to_c_long_arg(notif->data.args[1]);
    long ret = kbox_lkl_ftruncate(ctx->sysnrs, lkl_fd, length);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_fallocate                                                   */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_fallocate(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    long mode = to_c_long_arg(notif->data.args[1]);
    long offset = to_c_long_arg(notif->data.args[2]);
    long len = to_c_long_arg(notif->data.args[3]);
    long ret = kbox_lkl_fallocate(ctx->sysnrs, lkl_fd, mode, offset, len);
    if (ret == -ENOSYS)
        return kbox_dispatch_errno(ENOSYS);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_flock                                                       */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_flock(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    long operation = to_c_long_arg(notif->data.args[1]);
    long ret = kbox_lkl_flock(ctx->sysnrs, lkl_fd, operation);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_fsync                                                       */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_fsync(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    long ret = kbox_lkl_fsync(ctx->sysnrs, lkl_fd);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_fdatasync                                                   */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_fdatasync(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    long ret = kbox_lkl_fdatasync(ctx->sysnrs, lkl_fd);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_sync                                                        */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_sync(const struct kbox_seccomp_notif *notif,
                                         struct kbox_supervisor_ctx *ctx)
{
    (void) notif;
    long ret = kbox_lkl_sync(ctx->sysnrs);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_symlinkat                                                   */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_symlinkat(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    char targetbuf[KBOX_MAX_PATH];
    char linkpathbuf[KBOX_MAX_PATH];
    int rc;

    rc = kbox_vm_read_string(pid, notif->data.args[0], targetbuf,
                             sizeof(targetbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long newdirfd_raw = to_dirfd_arg(notif->data.args[1]);

    rc = kbox_vm_read_string(pid, notif->data.args[2], linkpathbuf,
                             sizeof(linkpathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char linktrans[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, linkpathbuf, ctx->host_root,
                                     linktrans, sizeof(linktrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long newdirfd = resolve_open_dirfd(linktrans, newdirfd_raw, ctx->fd_table);
    if (newdirfd < 0 && newdirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    /* Target is stored as-is (not translated). */
    long ret = kbox_lkl_symlinkat(ctx->sysnrs, targetbuf, newdirfd, linktrans);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_linkat                                                      */
/* ------------------------------------------------------------------ */

static struct kbox_dispatch forward_linkat(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    long olddirfd_raw = to_dirfd_arg(notif->data.args[0]);
    char oldpathbuf[KBOX_MAX_PATH];
    int rc;

    rc = kbox_vm_read_string(pid, notif->data.args[1], oldpathbuf,
                             sizeof(oldpathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long newdirfd_raw = to_dirfd_arg(notif->data.args[2]);
    char newpathbuf[KBOX_MAX_PATH];

    rc = kbox_vm_read_string(pid, notif->data.args[3], newpathbuf,
                             sizeof(newpathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long flags = to_c_long_arg(notif->data.args[4]);

    char oldtrans[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, oldpathbuf, ctx->host_root, oldtrans,
                                     sizeof(oldtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char newtrans[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, newpathbuf, ctx->host_root, newtrans,
                                     sizeof(newtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long olddirfd = resolve_open_dirfd(oldtrans, olddirfd_raw, ctx->fd_table);
    if (olddirfd < 0 && olddirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    long newdirfd = resolve_open_dirfd(newtrans, newdirfd_raw, ctx->fd_table);
    if (newdirfd < 0 && newdirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    long ret = kbox_lkl_linkat(ctx->sysnrs, olddirfd, oldtrans, newdirfd,
                               newtrans, flags);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_utimensat                                                   */
/* ------------------------------------------------------------------ */

/* struct timespec is 16 bytes on 64-bit: tv_sec(8) + tv_nsec(8). */
#define TIMESPEC_SIZE 16

static struct kbox_dispatch forward_utimensat(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = notif->pid;
    long dirfd_raw = to_dirfd_arg(notif->data.args[0]);

    /*
     * pathname can be NULL for utimensat (operates on dirfd itself).
     * In that case args[1] == 0.
     */
    char pathbuf[KBOX_MAX_PATH];
    const char *translated_path = NULL;
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc;

    if (notif->data.args[1] != 0) {
        rc = kbox_vm_read_string(pid, notif->data.args[1], pathbuf,
                                 sizeof(pathbuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);

        rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root,
                                         translated, sizeof(translated));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);

        translated_path = translated;
        lkl_dirfd = resolve_open_dirfd(translated, dirfd_raw, ctx->fd_table);
        if (lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX)
            return kbox_dispatch_continue();
    } else {
        translated_path = NULL;
        /* dirfd must be a virtual FD when path is NULL. */
        lkl_dirfd = kbox_fd_table_get_lkl(ctx->fd_table, dirfd_raw);
        if (lkl_dirfd < 0)
            return kbox_dispatch_continue();
    }

    /* Read the times array (2 x struct timespec) if provided. */
    uint8_t times_buf[TIMESPEC_SIZE * 2];
    const void *times = NULL;
    if (notif->data.args[2] != 0) {
        rc = kbox_vm_read(pid, notif->data.args[2], times_buf,
                          sizeof(times_buf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        times = times_buf;
    }

    long flags = to_c_long_arg(notif->data.args[3]);
    long ret = kbox_lkl_utimensat(ctx->sysnrs, lkl_dirfd, translated_path,
                                  times, flags);
    return kbox_dispatch_from_lkl(ret);
}

/* ------------------------------------------------------------------ */
/* forward_ioctl                                                       */
/* ------------------------------------------------------------------ */

/* Terminal ioctl constants. */
#ifndef TCGETS
#define TCGETS 0x5401
#endif
#ifndef TCSETS
#define TCSETS 0x5402
#endif
#ifndef TIOCGWINSZ
#define TIOCGWINSZ 0x5413
#endif
#ifndef TIOCSWINSZ
#define TIOCSWINSZ 0x5414
#endif
#ifndef TIOCGPGRP
#define TIOCGPGRP 0x540F
#endif
#ifndef TIOCSPGRP
#define TIOCSPGRP 0x5410
#endif
#ifndef TIOCSCTTY
#define TIOCSCTTY 0x540E
#endif

static struct kbox_dispatch forward_ioctl(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(notif->data.args[0]);
    long cmd = to_c_long_arg(notif->data.args[1]);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0) {
        /*
         * Host FD (stdin/stdout/stderr or pipe).  Most ioctls pass
         * through to the host kernel.  However, job-control ioctls
         * (TIOCSPGRP/TIOCGPGRP) fail with EPERM under seccomp-unotify
         * because the supervised child is not the session leader.
         * Return ENOTTY so shells fall back to non-job-control mode
         * instead of aborting.
         */
        if (cmd == TIOCSPGRP || cmd == TIOCGPGRP || cmd == TIOCSCTTY)
            return kbox_dispatch_errno(ENOTTY);
        return kbox_dispatch_continue();
    }

    (void) lkl_fd;

    /*
     * For virtual FDs backed by LKL, terminal ioctls return ENOTTY
     * since LKL file-backed FDs are not terminals.  Non-terminal
     * ioctls also return ENOTTY, matching regular-file semantics.
     */
    return kbox_dispatch_errno(ENOTTY);
}

/* ------------------------------------------------------------------ */
/* forward_mmap                                                       */
/* ------------------------------------------------------------------ */

/*
 * mmap dispatch: the only case we intercept is a virtual FD with no
 * host shadow.  Everything else (MAP_ANONYMOUS, shadow FDs, host FDs)
 * passes through to the host kernel via CONTINUE.
 */
static struct kbox_dispatch forward_mmap(const struct kbox_seccomp_notif *notif,
                                         struct kbox_supervisor_ctx *ctx)
{
    /*
     * mmap fd is a 32-bit int.  In seccomp_data.args[] it is
     * zero-extended to uint64_t, so -1 appears as 0xffffffff.
     * Use to_dirfd_arg to properly sign-extend from 32 bits.
     */
    long fd = to_dirfd_arg(notif->data.args[4]);

    /* MAP_ANONYMOUS: fd is -1, no FD involved. */
    if (fd == -1)
        return kbox_dispatch_continue();

    /*
     * If fd is a virtual FD (tracked in our table) and has no host
     * shadow, the host kernel cannot resolve it.  Return ENODEV.
     * This covers both high-range (>= KBOX_FD_BASE) and low-range
     * (dup2 redirects) virtual FDs.
     */
    if (kbox_fd_table_get_lkl(ctx->fd_table, fd) >= 0) {
        long host = kbox_fd_table_get_host_fd(ctx->fd_table, fd);
        if (host < 0)
            return kbox_dispatch_errno(ENODEV);
    }

    /* fd is a real host FD (shadow or native): let the kernel handle it. */
    return kbox_dispatch_continue();
}

/* ------------------------------------------------------------------ */
/* Identity dispatch helpers                                          */
/*                                                                    */
/* In host+root_identity mode, get* returns 0 and set* returns 0.     */
/* In host+override mode, get* returns the override value.            */
/* In host+neither mode, CONTINUE to host kernel.                     */
/* In image mode, forward to LKL.                                     */
/* ------------------------------------------------------------------ */

/*
 * Macro to reduce repetition in the identity dispatch.  For a given
 * identity syscall, check the mode and route accordingly.
 *
 * GET_ID: host+root -> override(0), host+!root+override -> override(uid/gid),
 *         host+!root+!override -> CONTINUE, image -> forward to LKL.
 */
#define DISPATCH_GET_UID(notif, ctx, override_val, lkl_func)          \
    do {                                                              \
        if (ctx->host_root) {                                         \
            if (ctx->root_identity)                                   \
                return kbox_dispatch_value(0);                        \
            if (ctx->override_uid != (uid_t) - 1)                     \
                return kbox_dispatch_value((int64_t) (override_val)); \
            return kbox_dispatch_continue();                          \
        }                                                             \
        return kbox_dispatch_from_lkl(lkl_func(ctx->sysnrs));         \
    } while (0)

#define DISPATCH_GET_GID(notif, ctx, override_val, lkl_func)          \
    do {                                                              \
        if (ctx->host_root) {                                         \
            if (ctx->root_identity)                                   \
                return kbox_dispatch_value(0);                        \
            if (ctx->override_gid != (gid_t) - 1)                     \
                return kbox_dispatch_value((int64_t) (override_val)); \
            return kbox_dispatch_continue();                          \
        }                                                             \
        return kbox_dispatch_from_lkl(lkl_func(ctx->sysnrs));         \
    } while (0)

#define DISPATCH_SET_ID(notif, ctx, lkl_forward) \
    do {                                         \
        if (ctx->host_root) {                    \
            if (ctx->root_identity)              \
                return kbox_dispatch_value(0);   \
            return kbox_dispatch_continue();     \
        }                                        \
        return lkl_forward(notif, ctx);          \
    } while (0)

/* ------------------------------------------------------------------ */
/* forward_execve                                                     */
/* ------------------------------------------------------------------ */

/*
 * AT_EMPTY_PATH flag for execveat -- indicates fexecve() usage.
 * Defined here to avoid pulling in the full linux/fcntl.h.
 */
#define KBOX_AT_EMPTY_PATH 0x1000

/*
 * Handle execve/execveat from inside the image.
 *
 * For fexecve (execveat with AT_EMPTY_PATH on a host memfd):
 *   CONTINUE -- the host kernel handles it directly.  This is the
 *   initial exec path from image.c.
 *
 * For in-image exec (e.g. shell runs /bin/ls):
 *   1. Read the pathname from tracee memory
 *   2. Open the binary from LKL, create a memfd
 *   3. Check for PT_INTERP; if dynamic, extract interpreter into
 *      a second memfd and patch PT_INTERP to /proc/self/fd/N
 *   4. Inject memfds into the tracee via ADDFD
 *   5. Overwrite the pathname in tracee memory with /proc/self/fd/N
 *   6. CONTINUE -- kernel re-reads the rewritten path and execs
 *
 * The seccomp-unotify guarantees the tracee is blocked during steps
 * 1-5, and the kernel has not yet copied the pathname (getname
 * happens after the seccomp check), so the overwrite is race-free.
 */
static struct kbox_dispatch forward_execve(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx,
    int is_execveat)
{
    pid_t pid = notif->pid;

    /*
     * Detect fexecve: execveat(fd, "", argv, envp, AT_EMPTY_PATH).
     * This is the initial exec from image.c on the host memfd.
     * Let the kernel handle it directly.
     */
    if (is_execveat) {
        long flags = to_c_long_arg(notif->data.args[4]);
        if (flags & KBOX_AT_EMPTY_PATH)
            return kbox_dispatch_continue();
    }

    /* Read pathname from tracee memory. */
    uint64_t path_addr =
        is_execveat ? notif->data.args[1] : notif->data.args[0];
    char pathbuf[KBOX_MAX_PATH];
    int rc = kbox_vm_read_string(pid, path_addr, pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Translate path for LKL. */
    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Virtual paths (/proc, /sys, /dev): let the host handle them. */
    if (kbox_is_lkl_virtual_path(translated))
        return kbox_dispatch_continue();

    /* Open the binary from LKL. */
    long lkl_fd =
        kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, translated, O_RDONLY, 0);
    if (lkl_fd < 0)
        return kbox_dispatch_errno((int) (-lkl_fd));

    /* Create a memfd with the binary contents. */
    int exec_memfd = kbox_shadow_create(ctx->sysnrs, lkl_fd);
    kbox_lkl_close(ctx->sysnrs, lkl_fd);

    if (exec_memfd < 0)
        return kbox_dispatch_errno(-exec_memfd);

    /*
     * Check for PT_INTERP (dynamic binary).
     * Read the first 4 KB -- enough for any reasonable ELF header
     * plus the full program header table.
     */
    {
        unsigned char elf_buf[4096];
        ssize_t nr_read = pread(exec_memfd, elf_buf, sizeof(elf_buf), 0);

        if (nr_read > 0) {
            char interp_path[256];
            uint64_t pt_offset, pt_filesz;
            int ilen = kbox_find_elf_interp_loc(
                elf_buf, (size_t) nr_read, interp_path, sizeof(interp_path),
                &pt_offset, &pt_filesz);

            if (ilen > 0) {
                /*
                 * Dynamic binary.  Extract the interpreter from LKL
                 * and inject it into the tracee.
                 */
                long interp_lkl = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX,
                                                  interp_path, O_RDONLY, 0);
                if (interp_lkl < 0) {
                    if (ctx->verbose)
                        fprintf(stderr,
                                "kbox: exec %s: cannot open "
                                "interpreter %s: %s\n",
                                pathbuf, interp_path,
                                kbox_err_text(interp_lkl));
                    close(exec_memfd);
                    return kbox_dispatch_errno((int) (-interp_lkl));
                }

                int interp_memfd = kbox_shadow_create(ctx->sysnrs, interp_lkl);
                kbox_lkl_close(ctx->sysnrs, interp_lkl);

                if (interp_memfd < 0) {
                    close(exec_memfd);
                    return kbox_dispatch_errno(-interp_memfd);
                }

                /*
                 * Inject the interpreter memfd first so we know
                 * its FD number in the tracee for the PT_INTERP
                 * patch.  O_CLOEXEC is safe: the kernel resolves
                 * /proc/self/fd/N via open_exec() before
                 * begin_new_exec() closes CLOEXEC descriptors.
                 */
                int tracee_interp_fd = kbox_notify_addfd(
                    ctx->listener_fd, notif->id, interp_memfd, O_CLOEXEC);
                close(interp_memfd);

                if (tracee_interp_fd < 0) {
                    close(exec_memfd);
                    return kbox_dispatch_errno(-tracee_interp_fd);
                }

                /*
                 * Patch PT_INTERP in the exec memfd to point at
                 * the injected interpreter: /proc/self/fd/<N>.
                 */
                char new_interp[64];
                int new_len = snprintf(new_interp, sizeof(new_interp),
                                       "/proc/self/fd/%d", tracee_interp_fd);

                if ((uint64_t) (new_len + 1) > pt_filesz) {
                    close(exec_memfd);
                    return kbox_dispatch_errno(ENOMEM);
                }

                char patch[256];
                size_t patch_len = (size_t) pt_filesz;
                if (patch_len > sizeof(patch))
                    patch_len = sizeof(patch);
                memset(patch, 0, patch_len);
                memcpy(patch, new_interp, (size_t) new_len);

                if (pwrite(exec_memfd, patch, patch_len, (off_t) pt_offset) !=
                    (ssize_t) patch_len) {
                    close(exec_memfd);
                    return kbox_dispatch_errno(EIO);
                }

                if (ctx->verbose)
                    fprintf(stderr,
                            "kbox: exec %s: interpreter %s "
                            "-> /proc/self/fd/%d\n",
                            pathbuf, interp_path, tracee_interp_fd);
            }
        }
    }

    /*
     * Inject the exec memfd into the tracee.  O_CLOEXEC keeps the
     * tracee's FD table clean after exec succeeds.
     */
    int tracee_exec_fd =
        kbox_notify_addfd(ctx->listener_fd, notif->id, exec_memfd, O_CLOEXEC);
    close(exec_memfd);

    if (tracee_exec_fd < 0)
        return kbox_dispatch_errno(-tracee_exec_fd);

    /*
     * Overwrite the pathname in the tracee's memory with
     * /proc/self/fd/<N>.  The kernel has not yet copied the
     * pathname (getname happens after the seccomp check), so
     * when we CONTINUE, it reads our rewritten path.
     *
     * argv[0] aliasing: some shells pass the same pointer for
     * pathname and argv[0].  If we overwrite the pathname, we
     * corrupt argv[0].  Detect this and fix it by writing the
     * original path right after the new path in the same buffer,
     * then updating the argv[0] pointer in the argv array.
     *
     * Try process_vm_writev first (fast path).  If that fails
     * (e.g. pathname is in .rodata), fall back to /proc/pid/mem
     * which can write through page protections.
     */
    char new_path[64];
    int new_path_len = snprintf(new_path, sizeof(new_path), "/proc/self/fd/%d",
                                tracee_exec_fd);

    /*
     * Check if argv[0] is aliased with the pathname.
     * argv pointer is args[1] for execve, args[2] for execveat.
     */
    uint64_t argv_addr =
        is_execveat ? notif->data.args[2] : notif->data.args[1];
    uint64_t argv0_ptr = 0;
    int argv0_aliased = 0;

    if (argv_addr != 0) {
        rc = kbox_vm_read(pid, argv_addr, &argv0_ptr, sizeof(argv0_ptr));
        if (rc == 0 && argv0_ptr == path_addr)
            argv0_aliased = 1;
    }

    /*
     * Build the write buffer: new_path + NUL + original_path + NUL.
     * The original path goes right after the new path so we can
     * point argv[0] at it.
     */
    size_t orig_len = strlen(pathbuf);
    size_t total_write = (size_t) (new_path_len + 1);

    if (argv0_aliased)
        total_write += orig_len + 1;

    char write_buf[KBOX_MAX_PATH + 64];
    if (total_write > sizeof(write_buf))
        return kbox_dispatch_errno(ENAMETOOLONG);

    memcpy(write_buf, new_path, (size_t) (new_path_len + 1));
    if (argv0_aliased)
        memcpy(write_buf + new_path_len + 1, pathbuf, orig_len + 1);

    rc = kbox_vm_write(pid, path_addr, write_buf, total_write);
    if (rc < 0) {
        rc = kbox_vm_write_force(pid, path_addr, write_buf, total_write);
        if (rc < 0) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: exec %s: cannot rewrite "
                        "pathname: %s\n",
                        pathbuf, strerror(-rc));
            return kbox_dispatch_errno(ENOEXEC);
        }
    }

    /*
     * If argv[0] was aliased, update the argv[0] pointer to
     * point at the original path copy (right after the new path).
     */
    if (argv0_aliased) {
        uint64_t new_argv0 = path_addr + (uint64_t) (new_path_len + 1);
        rc = kbox_vm_write(pid, argv_addr, &new_argv0, sizeof(new_argv0));
        if (rc < 0)
            kbox_vm_write_force(pid, argv_addr, &new_argv0, sizeof(new_argv0));
    }

    if (ctx->verbose)
        fprintf(stderr, "kbox: exec %s -> /proc/self/fd/%d\n", pathbuf,
                tracee_exec_fd);

    /* Clean up CLOEXEC entries before the kernel exec closes them.
     * Without this, stale shadow socket mappings survive exec and
     * can collide with FD numbers reused by the new image. */
    kbox_fd_table_close_cloexec(ctx->fd_table, ctx->sysnrs);

    return kbox_dispatch_continue();
}

/* ------------------------------------------------------------------ */
/* clone3 namespace-flag sanitization                                 */
/* ------------------------------------------------------------------ */

/*
 * CLONE_NEW* flags that clone3 can smuggle in via clone_args.flags.
 * The BPF deny-list blocks unshare/setns, but clone3 bypasses it
 * unless we check here.
 */
#define CLONE_NEWNS 0x00020000ULL
#define CLONE_NEWTIME 0x00000080ULL
#define CLONE_NEWCGROUP 0x02000000ULL
#define CLONE_NEWUTS 0x04000000ULL
#define CLONE_NEWIPC 0x08000000ULL
#define CLONE_NEWUSER 0x10000000ULL
#define CLONE_NEWPID 0x20000000ULL
#define CLONE_NEWNET 0x40000000ULL

#define CLONE_NEW_MASK                                              \
    (CLONE_NEWNS | CLONE_NEWTIME | CLONE_NEWCGROUP | CLONE_NEWUTS | \
     CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET)

static struct kbox_dispatch forward_clone3(
    const struct kbox_seccomp_notif *notif,
    struct kbox_supervisor_ctx *ctx)
{
    uint64_t flags;
    int rc;

    /*
     * clone3(struct clone_args *args, size_t size).
     * flags is the first uint64_t field in clone_args.
     * We only need to read the first 8 bytes.
     */
    rc = kbox_vm_read(notif->pid, notif->data.args[0], &flags, sizeof(flags));
    if (rc < 0) {
        /*
         * Can't read tracee memory -- fail closed with EPERM.
         *
         * CONTINUE is unsafe here: a tracee can clear dumpability
         * via prctl(PR_SET_DUMPABLE, 0), causing process_vm_readv
         * to fail with EPERM.  If we CONTINUE, clone3 reaches the
         * host kernel with unchecked namespace flags -- a sandbox
         * escape.  Returning EPERM is the only safe option.
         */
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: clone3 denied -- cannot read clone_args "
                    "(pid=%u, rc=%d)\n",
                    notif->pid, rc);
        return kbox_dispatch_errno(EPERM);
    }

    if (flags & CLONE_NEW_MASK) {
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: clone3 denied -- namespace flags 0x%llx "
                    "(pid=%u)\n",
                    (unsigned long long) (flags & CLONE_NEW_MASK), notif->pid);
        return kbox_dispatch_errno(EPERM);
    }

    return kbox_dispatch_continue();
}

/* ------------------------------------------------------------------ */
/* Main dispatch function                                             */
/* ------------------------------------------------------------------ */

struct kbox_dispatch kbox_dispatch_syscall(struct kbox_supervisor_ctx *ctx,
                                           const void *notif_ptr)
{
    const struct kbox_seccomp_notif *notif = notif_ptr;
    const struct kbox_host_nrs *h = ctx->host_nrs;
    int nr = notif->data.nr;

    if (ctx->verbose) {
        const char *name = syscall_name_from_nr(h, nr);
        fprintf(stderr, "seccomp notify: pid=%u nr=%d (%s)\n", notif->pid, nr,
                name ? name : "unknown");
    }

    /* === Legacy x86_64 Syscalls === */

    if (nr == h->stat)
        return forward_stat_legacy(notif, ctx, 0);
    if (nr == h->lstat)
        return forward_stat_legacy(notif, ctx, 1);
    if (nr == h->access)
        return forward_access_legacy(notif, ctx);
    if (nr == h->mkdir)
        return forward_mkdir_legacy(notif, ctx);
    if (nr == h->rmdir)
        return forward_rmdir_legacy(notif, ctx);
    if (nr == h->unlink)
        return forward_unlink_legacy(notif, ctx);
    if (nr == h->rename)
        return forward_rename_legacy(notif, ctx);
    if (nr == h->chmod)
        return forward_chmod_legacy(notif, ctx);
    if (nr == h->chown)
        return forward_chown_legacy(notif, ctx);
    if (nr == h->open)
        return forward_open_legacy(notif, ctx);

    /* === File Open/Create === */

    if (nr == h->openat)
        return forward_openat(notif, ctx);
    if (nr == h->openat2)
        return forward_openat2(notif, ctx);

    /* === Metadata === */

    if (nr == h->fstat)
        return forward_fstat(notif, ctx);
    if (nr == h->newfstatat)
        return forward_newfstatat(notif, ctx);
    if (nr == h->statx)
        return forward_statx(notif, ctx);
    if (nr == h->faccessat && h->faccessat > 0)
        return forward_faccessat(notif, ctx);
    if (nr == h->faccessat2)
        return forward_faccessat2(notif, ctx);

    /* === Directories === */

    if (nr == h->getdents64)
        return forward_getdents64(notif, ctx);
    if (nr == h->getdents)
        return forward_getdents(notif, ctx);
    if (nr == h->mkdirat)
        return forward_mkdirat(notif, ctx);
    if (nr == h->unlinkat)
        return forward_unlinkat(notif, ctx);
    if (nr == h->renameat && h->renameat > 0)
        return forward_renameat(notif, ctx);
    if (nr == h->renameat2)
        return forward_renameat2(notif, ctx);
    if (nr == h->fchmodat)
        return forward_fchmodat(notif, ctx);
    if (nr == h->fchownat)
        return forward_fchownat(notif, ctx);

    /* === Navigation === */

    if (nr == h->chdir)
        return forward_chdir(notif, ctx);
    if (nr == h->fchdir)
        return forward_fchdir(notif, ctx);
    if (nr == h->getcwd)
        return forward_getcwd(notif, ctx);

    /* === Identity: UID === */

    if (nr == h->getuid) {
        DISPATCH_GET_UID(notif, ctx, ctx->override_uid, kbox_lkl_getuid);
    }
    if (nr == h->geteuid) {
        DISPATCH_GET_UID(notif, ctx, ctx->override_uid, kbox_lkl_geteuid);
    }
    if (nr == h->getresuid) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getresuid_override(notif, 0);
            if (ctx->override_uid != (uid_t) -1)
                return forward_getresuid_override(notif, ctx->override_uid);
            return kbox_dispatch_continue();
        }
        return forward_getresuid(notif, ctx);
    }

    /* === Identity: GID === */

    if (nr == h->getgid) {
        DISPATCH_GET_GID(notif, ctx, ctx->override_gid, kbox_lkl_getgid);
    }
    if (nr == h->getegid) {
        DISPATCH_GET_GID(notif, ctx, ctx->override_gid, kbox_lkl_getegid);
    }
    if (nr == h->getresgid) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getresgid_override(notif, 0);
            if (ctx->override_gid != (gid_t) -1)
                return forward_getresgid_override(notif, ctx->override_gid);
            return kbox_dispatch_continue();
        }
        return forward_getresgid(notif, ctx);
    }

    /* === Identity: Groups === */

    if (nr == h->getgroups) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getgroups_override(notif, 0);
            if (ctx->override_gid != (gid_t) -1)
                return forward_getgroups_override(notif, ctx->override_gid);
            return kbox_dispatch_continue();
        }
        return forward_getgroups(notif, ctx);
    }

    /* === Identity: set* === */

    if (nr == h->setuid)
        DISPATCH_SET_ID(notif, ctx, forward_setuid);
    if (nr == h->setreuid)
        DISPATCH_SET_ID(notif, ctx, forward_setreuid);
    if (nr == h->setresuid)
        DISPATCH_SET_ID(notif, ctx, forward_setresuid);
    if (nr == h->setgid)
        DISPATCH_SET_ID(notif, ctx, forward_setgid);
    if (nr == h->setregid)
        DISPATCH_SET_ID(notif, ctx, forward_setregid);
    if (nr == h->setresgid)
        DISPATCH_SET_ID(notif, ctx, forward_setresgid);
    if (nr == h->setgroups)
        DISPATCH_SET_ID(notif, ctx, forward_setgroups);
    if (nr == h->setfsgid)
        DISPATCH_SET_ID(notif, ctx, forward_setfsgid);

    /* === Mount === */

    if (nr == h->mount)
        return forward_mount(notif, ctx);
    if (nr == h->umount2)
        return forward_umount2(notif, ctx);

    /* === FD Operations === */

    if (nr == h->close)
        return forward_close(notif, ctx);
    if (nr == h->fcntl)
        return forward_fcntl(notif, ctx);
    if (nr == h->dup)
        return forward_dup(notif, ctx);
    if (nr == h->dup2)
        return forward_dup2(notif, ctx);
    if (nr == h->dup3)
        return forward_dup3(notif, ctx);

    /* === I/O === */

    if (nr == h->read)
        return forward_read_like(notif, ctx, 0);
    if (nr == h->pread64)
        return forward_read_like(notif, ctx, 1);
    if (nr == h->write)
        return forward_write(notif, ctx);
    if (nr == h->lseek)
        return forward_lseek(notif, ctx);

    /* === Networking === */

    if (nr == h->socket)
        return forward_socket(notif, ctx);
    if (nr == h->bind)
        return forward_bind(notif, ctx);
    if (nr == h->connect)
        return forward_connect(notif, ctx);
    if (nr == h->sendto)
        return forward_sendto(notif, ctx);
    if (nr == h->recvfrom)
        return forward_recvfrom(notif, ctx);
    /* sendmsg: BPF allow-listed (SCM_RIGHTS), never reaches here.
     * Shadow socket callers should use sendto for addressed datagrams. */
    if (nr == h->recvmsg)
        return forward_recvmsg(notif, ctx);
    if (nr == h->getsockopt)
        return forward_getsockopt(notif, ctx);
    if (nr == h->setsockopt)
        return forward_setsockopt(notif, ctx);
    if (nr == h->getsockname)
        return forward_getsockname(notif, ctx);
    if (nr == h->getpeername)
        return forward_getpeername(notif, ctx);
    if (nr == h->shutdown)
        return forward_shutdown(notif, ctx);

    /* === I/O Extended === */

    if (nr == h->pwrite64)
        return forward_pwrite64(notif, ctx);
    if (nr == h->writev)
        return forward_writev(notif, ctx);
    if (nr == h->readv)
        return forward_readv(notif, ctx);
    if (nr == h->ftruncate)
        return forward_ftruncate(notif, ctx);
    if (nr == h->fallocate)
        return forward_fallocate(notif, ctx);
    if (nr == h->flock)
        return forward_flock(notif, ctx);
    if (nr == h->fsync)
        return forward_fsync(notif, ctx);
    if (nr == h->fdatasync)
        return forward_fdatasync(notif, ctx);
    if (nr == h->sync)
        return forward_sync(notif, ctx);
    if (nr == h->ioctl)
        return forward_ioctl(notif, ctx);

    /* === File Operations === */

    if (nr == h->readlinkat)
        return forward_readlinkat(notif, ctx);
    if (nr == h->pipe2)
        return forward_pipe2(notif, ctx);
    if (nr == h->pipe) {
        /*
         * Legacy pipe(2) has only one arg: pipefd.  Create a host
         * pipe and inject via ADDFD, same as the pipe2 path.
         */
        pid_t ppid = notif->pid;
        uint64_t remote_pfd = notif->data.args[0];
        if (remote_pfd == 0)
            return kbox_dispatch_errno(EFAULT);

        int host_pfds[2];
        if (pipe(host_pfds) < 0)
            return kbox_dispatch_errno(errno);

        int tfd0 =
            kbox_notify_addfd(ctx->listener_fd, notif->id, host_pfds[0], 0);
        if (tfd0 < 0) {
            close(host_pfds[0]);
            close(host_pfds[1]);
            return kbox_dispatch_errno(-tfd0);
        }
        int tfd1 =
            kbox_notify_addfd(ctx->listener_fd, notif->id, host_pfds[1], 0);
        if (tfd1 < 0) {
            close(host_pfds[0]);
            close(host_pfds[1]);
            return kbox_dispatch_errno(-tfd1);
        }
        close(host_pfds[0]);
        close(host_pfds[1]);

        int gfds[2] = {tfd0, tfd1};
        int pwrc = kbox_vm_write(ppid, remote_pfd, gfds, sizeof(gfds));
        if (pwrc < 0)
            return kbox_dispatch_errno(-pwrc);
        return kbox_dispatch_value(0);
    }
    if (nr == h->symlinkat)
        return forward_symlinkat(notif, ctx);
    if (nr == h->linkat)
        return forward_linkat(notif, ctx);
    if (nr == h->utimensat)
        return forward_utimensat(notif, ctx);
    if (nr == h->sendfile)
        return forward_sendfile(notif, ctx);
    if (nr == h->copy_file_range)
        return kbox_dispatch_errno(ENOSYS);

    /* === Process Info === */

    if (nr == h->getpid)
        return kbox_dispatch_value(1);
    if (nr == h->getppid)
        return kbox_dispatch_value(0);
    if (nr == h->gettid)
        return kbox_dispatch_value(1);
    if (nr == h->setpgid)
        return kbox_dispatch_continue();
    if (nr == h->getpgid)
        return kbox_dispatch_continue();
    if (nr == h->getsid)
        return kbox_dispatch_continue();
    if (nr == h->setsid)
        return kbox_dispatch_continue();

    /* === Time === */

    if (nr == h->clock_gettime)
        return forward_clock_gettime(notif, ctx);
    if (nr == h->clock_getres)
        return forward_clock_getres(notif, ctx);
    if (nr == h->gettimeofday)
        return forward_gettimeofday(notif, ctx);

    /* === Process Lifecycle === */

    if (nr == h->umask)
        return forward_umask(notif, ctx);
    if (nr == h->uname)
        return forward_uname(notif, ctx);
    if (nr == h->brk)
        return kbox_dispatch_continue();
    if (nr == h->getrandom)
        return forward_getrandom(notif, ctx);
    if (nr == h->syslog)
        return forward_syslog(notif, ctx);
    if (nr == h->prctl)
        return forward_prctl(notif, ctx);
    if (nr == h->wait4)
        return kbox_dispatch_continue();
    if (nr == h->waitid)
        return kbox_dispatch_continue();

    /* === Signals (CONTINUE) === */
    /* Signal disposition and masking are per-process host kernel state. */

    if (nr == h->rt_sigaction)
        return kbox_dispatch_continue(); /* signal handler registration */
    if (nr == h->rt_sigprocmask)
        return kbox_dispatch_continue(); /* signal mask manipulation */
    if (nr == h->rt_sigreturn)
        return kbox_dispatch_continue(); /* return from signal handler */
    if (nr == h->rt_sigpending)
        return kbox_dispatch_continue(); /* pending signal query */
    if (nr == h->rt_sigaltstack)
        return kbox_dispatch_continue(); /* alternate signal stack */
    if (nr == h->setitimer)
        return kbox_dispatch_continue(); /* interval timer */
    if (nr == h->getitimer)
        return kbox_dispatch_continue(); /* query interval timer */
    if (h->alarm >= 0 && nr == h->alarm)
        return kbox_dispatch_continue(); /* alarm (not on aarch64) */

    /* === Signal Delivery (dispatch: PID validation) === */
    /*
     * kill/tgkill/tkill must go through dispatch (not BPF deny) because
     * ash needs them for job control.  We validate the target PID belongs
     * to the guest process tree.  PID is in register args (no TOCTOU).
     */

    /*
     * Accept the guest's virtual PID (1) as equivalent to the
     * real host PID.  getpid/gettid return 1, so raise() calls
     * tgkill(1, 1, sig) which must reach the host kernel with
     * the real PID.  Also accept notif->pid (the tracee's actual
     * host PID from the seccomp notification).
     */
#define IS_GUEST_PID(p) \
    ((p) == ctx->child_pid || (p) == (pid_t) notif->pid || (p) == 1)

    if (nr == h->kill) {
        pid_t target = (pid_t) notif->data.args[0];
        int sig = (int) notif->data.args[1];
        if (!IS_GUEST_PID(target) && target != 0) {
            if (ctx->verbose)
                fprintf(stderr, "kbox: kill(%d) denied -- not guest PID\n",
                        target);
            return kbox_dispatch_errno(EPERM);
        }
        /*
         * Emulate kill() from the supervisor.  Virtual PID 1 and
         * process-group 0 must target the real child PID, not the
         * host's PID 1 or the supervisor's process group.
         */
        {
            pid_t real_target = ctx->child_pid;
            if (target == 0 || IS_GUEST_PID(target))
                real_target = ctx->child_pid;
            long ret = syscall(SYS_kill, real_target, sig);
            if (ret < 0)
                return kbox_dispatch_errno(errno);
            return kbox_dispatch_value(0);
        }
    }
    if (nr == h->tgkill) {
        pid_t tgid = (pid_t) notif->data.args[0];
        pid_t tid = (pid_t) notif->data.args[1];
        int sig = (int) notif->data.args[2];
        if (!IS_GUEST_PID(tgid)) {
            if (ctx->verbose)
                fprintf(stderr, "kbox: tgkill(%d) denied -- not guest PID\n",
                        tgid);
            return kbox_dispatch_errno(EPERM);
        }
        /*
         * The guest passes its virtual PID (1) but the host kernel
         * needs the real PID.  We can't modify syscall args via
         * seccomp-unotify, so emulate: call tgkill with the real
         * PID from the supervisor.  The tracee's tid is its real
         * host tid (gettid returns virtual 1, but the seccomp
         * notification contains the real tid in notif->pid).
         */
        {
            pid_t real_tgid = ctx->child_pid;
            pid_t real_tid = (tid == 1) ? (pid_t) notif->pid : tid;
            long ret = syscall(SYS_tgkill, real_tgid, real_tid, sig);
            if (ret < 0)
                return kbox_dispatch_errno(errno);
            return kbox_dispatch_value(0);
        }
    }
    if (nr == h->tkill) {
        pid_t target = (pid_t) notif->data.args[0];
        int sig = (int) notif->data.args[1];
        if (!IS_GUEST_PID(target)) {
            if (ctx->verbose)
                fprintf(stderr, "kbox: tkill(%d) denied -- not guest PID\n",
                        target);
            return kbox_dispatch_errno(EPERM);
        }
        {
            pid_t real_tid = (target == 1) ? (pid_t) notif->pid : target;
            long ret = syscall(SYS_tkill, real_tid, sig);
            if (ret < 0)
                return kbox_dispatch_errno(errno);
            return kbox_dispatch_value(0);
        }
    }
#undef IS_GUEST_PID
    if (nr == h->pidfd_send_signal) {
        /* pidfd_send_signal is rare; deny by default for now. */
        return kbox_dispatch_errno(EPERM);
    }

    /* === Threading (CONTINUE) === */
    /* Thread management is host kernel state; LKL is not involved. */

    if (nr == h->set_tid_address)
        return kbox_dispatch_continue(); /* set clear_child_tid pointer */
    if (nr == h->set_robust_list)
        return kbox_dispatch_continue(); /* robust futex list */
    if (nr == h->futex)
        return kbox_dispatch_continue(); /* fast userspace mutex */
    if (nr == h->clone3)
        return forward_clone3(notif, ctx); /* sanitize namespace flags */
    if (nr == h->arch_prctl)
        return kbox_dispatch_continue(); /* x86_64 FS/GS base */
    if (nr == h->rseq)
        return kbox_dispatch_continue(); /* restartable sequences */
    if (nr == h->clone) {
        /* Legacy clone: flags are in args[0] directly (not a struct). */
        uint64_t cflags = notif->data.args[0];
        if (cflags & CLONE_NEW_MASK) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: clone denied -- namespace flags 0x%llx "
                        "(pid=%u)\n",
                        (unsigned long long) (cflags & CLONE_NEW_MASK),
                        notif->pid);
            return kbox_dispatch_errno(EPERM);
        }
        return kbox_dispatch_continue();
    }
    if (nr == h->fork)
        return kbox_dispatch_continue(); /* legacy fork */
    if (nr == h->vfork)
        return kbox_dispatch_continue(); /* legacy vfork */

    /* === Memory Mapping === */

    if (nr == h->mmap)
        return forward_mmap(notif, ctx);
    if (nr == h->munmap)
        return kbox_dispatch_continue(); /* unmap pages */
    if (nr == h->mprotect)
        return kbox_dispatch_continue(); /* change page protections */
    if (nr == h->mremap)
        return kbox_dispatch_continue(); /* remap pages */
    if (nr == h->membarrier)
        return kbox_dispatch_continue(); /* memory barrier (musl threads) */

    /* === Scheduling (CONTINUE) === */
    /* Scheduler ops are safe -- RLIMIT_RTPRIO=0 prevents RT starvation. */

    if (nr == h->sched_yield)
        return kbox_dispatch_continue();
    if (nr == h->sched_setparam)
        return kbox_dispatch_continue();
    if (nr == h->sched_getparam)
        return kbox_dispatch_continue();
    if (nr == h->sched_setscheduler)
        return kbox_dispatch_continue();
    if (nr == h->sched_getscheduler)
        return kbox_dispatch_continue();
    if (nr == h->sched_get_priority_max)
        return kbox_dispatch_continue();
    if (nr == h->sched_get_priority_min)
        return kbox_dispatch_continue();
    if (nr == h->sched_setaffinity)
        return kbox_dispatch_continue();
    if (nr == h->sched_getaffinity)
        return kbox_dispatch_continue();

    /* === Resource Management === */

    /*
     * prlimit64: GET operations are safe (read-only).  SET operations
     * on dangerous resources (RLIMIT_NPROC, RLIMIT_NOFILE, RLIMIT_RTPRIO)
     * are blocked to prevent the guest from escaping resource limits.
     */
    if (nr == h->prlimit64) {
        uint64_t new_limit_ptr = notif->data.args[2];
        if (new_limit_ptr == 0)
            return kbox_dispatch_continue(); /* GET only */
        /* SET operation: check which resource. */
        int resource = (int) notif->data.args[1];
        /* Allow safe resources: RLIMIT_CORE(4), RLIMIT_AS(9), etc. */
        if (resource == 4 /* RLIMIT_CORE */ || resource == 9 /* RLIMIT_AS */)
            return kbox_dispatch_continue();
        if (ctx->verbose)
            fprintf(stderr, "kbox: prlimit64 SET resource=%d denied\n",
                    resource);
        return kbox_dispatch_errno(EPERM);
    }
    if (nr == h->madvise)
        return kbox_dispatch_continue(); /* memory advice */
    if (nr == h->getrlimit)
        return kbox_dispatch_continue(); /* read resource limits */
    if (nr == h->getrusage)
        return kbox_dispatch_continue(); /* read resource usage */

    /* === I/O Multiplexing (CONTINUE) === */
    /* All polling/select variants are pure host kernel operations. */

    if (nr == h->epoll_create1)
        return kbox_dispatch_continue();
    if (nr == h->epoll_ctl)
        return kbox_dispatch_continue();
    if (nr == h->epoll_wait)
        return kbox_dispatch_continue();
    if (nr == h->epoll_pwait)
        return kbox_dispatch_continue();
    if (nr == h->ppoll)
        return kbox_dispatch_continue();
    if (nr == h->pselect6)
        return kbox_dispatch_continue();
    if (nr == h->poll)
        return kbox_dispatch_continue(); /* legacy poll (musl/busybox) */

    /* === Sleep/Timer (CONTINUE) === */
    /* Time waiting is pure host kernel; no LKL involvement. */

    if (nr == h->nanosleep)
        return kbox_dispatch_continue();
    if (nr == h->clock_nanosleep)
        return kbox_dispatch_continue();
    if (nr == h->timerfd_create)
        return kbox_dispatch_continue();
    if (nr == h->timerfd_settime)
        return kbox_dispatch_continue();
    if (nr == h->timerfd_gettime)
        return kbox_dispatch_continue();
    if (nr == h->eventfd)
        return kbox_dispatch_continue();
    if (nr == h->eventfd2)
        return kbox_dispatch_continue();

    /* === Filesystem Info (CONTINUE/dispatch) === */

    if (nr == h->statfs)
        return kbox_dispatch_continue(); /* filesystem stats */
    if (nr == h->fstatfs)
        return kbox_dispatch_continue(); /* filesystem stats by fd */
    if (nr == h->sysinfo)
        return kbox_dispatch_continue(); /* system info (busybox free) */

    /*
     * readlink: takes a path pointer (TOCTOU risk).  Forward to LKL
     * via readlinkat instead of CONTINUE.
     */
    if (nr == h->readlink) {
        char path[4096];
        int ret = kbox_vm_read_string(notif->pid, notif->data.args[0], path,
                                      sizeof(path));
        if (ret < 0)
            return kbox_dispatch_errno(-ret);
        long bufsiz = (long) notif->data.args[2];
        char buf[4096];
        if (bufsiz > (long) sizeof(buf))
            bufsiz = (long) sizeof(buf);
        long lret =
            kbox_lkl_readlinkat(ctx->sysnrs, AT_FDCWD_LINUX, path, buf, bufsiz);
        if (lret < 0)
            return kbox_dispatch_from_lkl(lret);
        ret =
            kbox_vm_write(notif->pid, notif->data.args[1], buf, (size_t) lret);
        if (ret < 0)
            return kbox_dispatch_errno(-ret);
        return kbox_dispatch_value(lret);
    }

    /* === Exec (in-image binary extraction + pathname rewrite) === */

    if (nr == h->execve)
        return forward_execve(notif, ctx, 0);
    if (nr == h->execveat)
        return forward_execve(notif, ctx, 1);

    /* === Default: deny unknown syscalls === */
    if (ctx->verbose)
        fprintf(stderr, "kbox: DENY unknown syscall nr=%d (pid=%u)\n", nr,
                notif->pid);
    return kbox_dispatch_errno(ENOSYS);
}
