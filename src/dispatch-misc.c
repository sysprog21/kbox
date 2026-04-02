/* SPDX-License-Identifier: MIT */

/* Miscellaneous syscall handlers for the seccomp dispatch engine.
 *
 * Time queries, pipe creation, uname, getrandom, prctl, extended I/O
 * (pwrite, writev, readv), truncation, sync, links, and ioctl.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "dispatch-internal.h"
#include "kbox/path.h"

struct kbox_dispatch forward_clock_gettime(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    int clockid = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t remote_ts = kbox_syscall_request_arg(req, 1);

    if (remote_ts == 0)
        return kbox_dispatch_errno(EFAULT);

    struct timespec ts;
    if (clock_gettime(clockid, &ts) < 0)
        return kbox_dispatch_errno(errno);

    int wrc = guest_mem_write(ctx, pid, remote_ts, &ts, sizeof(ts));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_clock_getres(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    int clockid = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t remote_ts = kbox_syscall_request_arg(req, 1);

    struct timespec ts;
    if (clock_getres(clockid, remote_ts ? &ts : NULL) < 0)
        return kbox_dispatch_errno(errno);

    if (remote_ts != 0) {
        int wrc = guest_mem_write(ctx, pid, remote_ts, &ts, sizeof(ts));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_gettimeofday(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_tv = kbox_syscall_request_arg(req, 0);
    uint64_t remote_tz = kbox_syscall_request_arg(req, 1);

    /* Use clock_gettime(CLOCK_REALTIME) as the underlying source, which works
     * on both x86_64 and aarch64.
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

        int wrc = guest_mem_write(ctx, pid, remote_tv, &tv, sizeof(tv));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    if (remote_tz != 0) {
        /* Return zeroed timezone (UTC). */
        struct {
            int tz_minuteswest;
            int tz_dsttime;
        } tz = {0, 0};

        int wrc = guest_mem_write(ctx, pid, remote_tz, &tz, sizeof(tz));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_readlinkat(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    uint64_t remote_buf = kbox_syscall_request_arg(req, 2);
    int64_t bufsiz_raw = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    if (bufsiz_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t bufsiz = (size_t) bufsiz_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);

    if (bufsiz > KBOX_MAX_PATH)
        bufsiz = KBOX_MAX_PATH;

    /* Host dirfd: call host readlinkat with a supervisor-owned copy. */
    if (should_continue_for_dirfd(lkl_dirfd)) {
        long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
        int sv_dirfd = dup_tracee_fd(pid, (int) raw_dirfd);
        if (sv_dirfd < 0)
            return kbox_dispatch_errno(-sv_dirfd);
        char linkbuf[KBOX_MAX_PATH];
        ssize_t n = readlinkat(sv_dirfd, translated, linkbuf, bufsiz);
        int saved = errno;
        close(sv_dirfd);
        if (n < 0)
            return kbox_dispatch_errno(saved);
        int wrc = guest_mem_write(ctx, pid, remote_buf, linkbuf, (size_t) n);
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
        return kbox_dispatch_value((int64_t) n);
    }

    char linkbuf[KBOX_MAX_PATH];
    long ret = kbox_lkl_readlinkat(ctx->sysnrs, lkl_dirfd, translated, linkbuf,
                                   (long) bufsiz);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    size_t n = (size_t) ret;
    int wrc = guest_mem_write(ctx, pid, remote_buf, linkbuf, n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

struct kbox_dispatch forward_pipe2(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_pipefd = kbox_syscall_request_arg(req, 0);
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    if (remote_pipefd == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Create a real host pipe and inject both ends into the tracee via
     * SECCOMP_IOCTL_NOTIF_ADDFD.  This makes pipes fully native:
     *   - dup2/close/read/write on pipe FDs -> CONTINUE (host kernel)
     *   - Proper fork semantics: both parent and child share the real
     *     pipe, no virtual FD table conflicts.
     *   - No LKL overhead for IPC data transfer.
     */
    int host_pipefd[2];
    if (pipe2(host_pipefd, (int) flags) < 0)
        return kbox_dispatch_errno(errno);

    uint32_t cloexec_flag = (flags & O_CLOEXEC) ? O_CLOEXEC : 0;

    int tracee_fd0 = request_addfd(ctx, req, host_pipefd[0], cloexec_flag);
    if (tracee_fd0 < 0) {
        close(host_pipefd[0]);
        close(host_pipefd[1]);
        return kbox_dispatch_errno(-tracee_fd0);
    }

    int tracee_fd1 = request_addfd(ctx, req, host_pipefd[1], cloexec_flag);
    if (tracee_fd1 < 0) {
        close(host_pipefd[0]);
        close(host_pipefd[1]);
        return kbox_dispatch_errno(-tracee_fd1);
    }

    /* Supervisor copies no longer needed; tracee owns its own copies. */
    close(host_pipefd[0]);
    close(host_pipefd[1]);

    /* Track both pipe FDs as host-passthrough so I/O handlers CONTINUE them
     * instead of returning EBADF.
     */
    track_host_passthrough_fd(ctx->fd_table, tracee_fd0);
    track_host_passthrough_fd(ctx->fd_table, tracee_fd1);

    int guest_fds[2] = {tracee_fd0, tracee_fd1};
    int wrc =
        guest_mem_write(ctx, pid, remote_pipefd, guest_fds, sizeof(guest_fds));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_uname(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_buf = kbox_syscall_request_arg(req, 0);

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

    int wrc = guest_mem_write(ctx, pid, remote_buf, &uts, sizeof(uts));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_getrandom(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_buf = kbox_syscall_request_arg(req, 0);
    int64_t buflen_raw = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    if (buflen_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t buflen = (size_t) buflen_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (buflen == 0)
        return kbox_dispatch_value(0);

    /* Read from /dev/urandom via LKL.  Fall back to host if LKL does not
     * have the device available.
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
    lkl_close_and_invalidate(ctx, fd);

    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    size_t n = (size_t) ret;
    int wrc = guest_mem_write(ctx, pid, remote_buf, scratch, n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

/* syslog(type, buf, len): forward to LKL so dmesg shows the LKL kernel's ring
 * buffer, not the host's.
 *
 * Types that read into buf (2=READ, 3=READ_ALL, 4=READ_CLEAR): call LKL with
 * a scratch buffer, then copy to tracee.
 * Types that just return a value (0,1,5-10): forward type+len, return the
 * result directly.
 */
#define SYSLOG_ACTION_READ 2
#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_READ_CLEAR 4
#define SYSLOG_ACTION_SIZE_BUFFER 10

struct kbox_dispatch forward_syslog(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    long type = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    long len = to_c_long_arg(kbox_syscall_request_arg(req, 2));

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

    /* Static buffer; safe because the supervisor is single-threaded.
     * Clamp to the actual LKL ring buffer size so READ_CLEAR never discards
     * data beyond what we can copy out. The ring buffer size is fixed at boot,
     * so cache it after the first query. Hard-cap at 1MB (the static buffer
     * size) as a safety ceiling.
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
    int wrc = guest_mem_write(ctx, pid, remote_buf, scratch, n);

    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

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

struct kbox_dispatch forward_prctl(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx)
{
    long option = to_c_long_arg(kbox_syscall_request_arg(req, 0));

    /* Block PR_SET_DUMPABLE(0): clearing dumpability makes process_vm_readv
     * fail, which would bypass clone3 namespace-flag sanitization (supervisor
     * can't read clone_args.flags from a non-dumpable process). Return success
     * without actually clearing; the tracee thinks it worked, but supervisor
     * retains read access.
     */
    if (option == PR_SET_DUMPABLE &&
        to_c_long_arg(kbox_syscall_request_arg(req, 1)) == 0)
        return kbox_dispatch_value(0);
    /* Match: report dumpable even if guest tried to clear it. */
    if (option == PR_GET_DUMPABLE)
        return kbox_dispatch_value(1);

    /* Only forward PR_SET_NAME and PR_GET_NAME to LKL. Everything else passes
     * through to the host kernel.
     *
     * PR_SET_NAME/PR_GET_NAME use a 16-byte name buffer. The tracee passes a
     * pointer in arg2 which is in the tracee's address space, not ours. We must
     * copy through kbox_vm_read/kbox_vm_write.
     */
    if (option != PR_SET_NAME && option != PR_GET_NAME)
        return kbox_dispatch_continue();

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_name = kbox_syscall_request_arg(req, 1);
    if (remote_name == 0)
        return kbox_dispatch_errno(EFAULT);

    /* PR_SET_NAME: read 16-byte name from tracee, pass local copy to LKL. */
    if (option == PR_SET_NAME) {
        char name[16];
        int rrc = guest_mem_read(ctx, pid, remote_name, name, sizeof(name));
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
    int wrc = guest_mem_write(ctx, pid, remote_name, name, sizeof(name));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_pwrite64(const struct kbox_syscall_request *req,
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

    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;
    long offset = to_c_long_arg(kbox_syscall_request_arg(req, 3));

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

        long ret = kbox_lkl_pwrite64(ctx->sysnrs, lkl_fd, scratch,
                                     (long) chunk_len, offset + (long) total);
        if (ret < 0) {
            if (total == 0) {
                return kbox_dispatch_errno((int) (-ret));
            }
            break;
        }

        size_t n = (size_t) ret;
        total += n;
        if (n < chunk_len)
            break;
    }

    if (total > 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_value((int64_t) total);
}

/* iovec layout matches the kernel's: { void *iov_base; size_t iov_len; }
 * On 64-bit: 16 bytes per entry.
 */
#define IOV_ENTRY_SIZE 16
/* Match the kernel's UIO_MAXIOV.  The iov_buf is static (not stack-allocated)
 * because in trap/rewrite mode dispatch runs in signal handler context where
 * 16 KB on the stack risks overflow on threads with small stacks. Dispatcher is
 * single-threaded (documented invariant), so a static buffer is safe.
 */
#define IOV_MAX_COUNT 1024
static uint8_t iov_scratch[IOV_MAX_COUNT * IOV_ENTRY_SIZE];

/* Shared iov scatter/gather dispatcher for writev and readv.
 *
 * is_write selects the direction: 1 = guest->LKL (writev), 0 = LKL->guest
 * (readv). The chunked loop, iov parsing, and error handling are identical in
 * both directions.
 */
static struct kbox_dispatch dispatch_iov_transfer(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int is_write)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    if (is_write)
        invalidate_stat_cache_fd(ctx, lkl_fd);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_iov = kbox_syscall_request_arg(req, 1);
    int64_t iovcnt_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (iovcnt_raw < 0 || iovcnt_raw > IOV_MAX_COUNT)
        return kbox_dispatch_errno(EINVAL);
    if (iovcnt_raw == 0)
        return kbox_dispatch_value(0);
    if (remote_iov == 0)
        return kbox_dispatch_errno(EFAULT);

    int iovcnt = (int) iovcnt_raw;
    size_t iov_bytes = (size_t) iovcnt * IOV_ENTRY_SIZE;

    int rrc = guest_mem_read(ctx, pid, remote_iov, iov_scratch, iov_bytes);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    int mirror_host =
        is_write ? kbox_fd_table_mirror_tty(ctx->fd_table, fd) : 0;
    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;
    int err = 0;

    int i;
    for (i = 0; i < iovcnt; i++) {
        uint64_t base;
        uint64_t len;
        memcpy(&base, &iov_scratch[i * IOV_ENTRY_SIZE], 8);
        memcpy(&len, &iov_scratch[i * IOV_ENTRY_SIZE + 8], 8);

        if (base == 0 || len == 0)
            continue;

        size_t seg_total = 0;
        while (seg_total < len) {
            size_t chunk = KBOX_IO_CHUNK_LEN;
            if (chunk > len - seg_total)
                chunk = len - seg_total;

            if (is_write) {
                rrc =
                    guest_mem_read(ctx, pid, base + seg_total, scratch, chunk);
                if (rrc < 0) {
                    err = -rrc;
                    goto done;
                }
            }

            long ret =
                is_write
                    ? kbox_lkl_write(ctx->sysnrs, lkl_fd, scratch, (long) chunk)
                    : kbox_lkl_read(ctx->sysnrs, lkl_fd, scratch, (long) chunk);
            if (ret < 0) {
                err = (int) (-ret);
                goto done;
            }

            size_t n = (size_t) ret;
            if (n == 0)
                goto done;

            if (is_write) {
                if (mirror_host) {
                    ssize_t written = write(STDOUT_FILENO, scratch, n);
                    (void) written;
                }
            } else {
                int wrc =
                    guest_mem_write(ctx, pid, base + seg_total, scratch, n);
                if (wrc < 0)
                    return kbox_dispatch_errno(-wrc);
            }

            seg_total += n;
            total += n;
            if (n < chunk)
                goto done;
        }
    }

done:
    if (is_write && total > 0)
        invalidate_path_shadow_cache(ctx);
    if (total == 0 && err)
        return kbox_dispatch_errno(err);
    return kbox_dispatch_value((int64_t) total);
}

struct kbox_dispatch forward_writev(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    return dispatch_iov_transfer(req, ctx, 1);
}

struct kbox_dispatch forward_readv(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx)
{
    return dispatch_iov_transfer(req, ctx, 0);
}

struct kbox_dispatch forward_ftruncate(const struct kbox_syscall_request *req,
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

    long length = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_ftruncate(ctx->sysnrs, lkl_fd, length);
    if (ret >= 0) {
        invalidate_path_shadow_cache(ctx);
        invalidate_stat_cache_fd(ctx, lkl_fd);
    }
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_fallocate(const struct kbox_syscall_request *req,
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

    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long offset = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long len = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    long ret = kbox_lkl_fallocate(ctx->sysnrs, lkl_fd, mode, offset, len);
    if (ret == -ENOSYS)
        return kbox_dispatch_errno(ENOSYS);
    if (ret >= 0) {
        invalidate_path_shadow_cache(ctx);
        invalidate_stat_cache_fd(ctx, lkl_fd);
    }
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_flock(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    long operation = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_flock(ctx->sysnrs, lkl_fd, operation);
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_fsync(const struct kbox_syscall_request *req,
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
    if (entry && entry->shadow_writeback) {
        int rc = sync_shadow_writeback(ctx, entry);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        return kbox_dispatch_value(0);
    }

    long ret = kbox_lkl_fsync(ctx->sysnrs, lkl_fd);
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_fdatasync(const struct kbox_syscall_request *req,
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
    if (entry && entry->shadow_writeback) {
        int rc = sync_shadow_writeback(ctx, entry);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        return kbox_dispatch_value(0);
    }

    long ret = kbox_lkl_fdatasync(ctx->sysnrs, lkl_fd);
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_sync(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx)
{
    (void) req;
    long ret = kbox_lkl_sync(ctx->sysnrs);
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_symlinkat(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    char targetbuf[KBOX_MAX_PATH];
    int rc;

    rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 0),
                               targetbuf, sizeof(targetbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char linktrans[KBOX_MAX_PATH];
    long newdirfd;
    rc = translate_request_at_path(req, ctx, 1, 2, linktrans, sizeof(linktrans),
                                   &newdirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Host dirfd: call host symlinkat with a supervisor-owned copy. */
    if (should_continue_for_dirfd(newdirfd)) {
        long raw = to_dirfd_arg(kbox_syscall_request_arg(req, 1));
        int sv_dirfd = dup_tracee_fd(pid, (int) raw);
        if (sv_dirfd < 0)
            return kbox_dispatch_errno(-sv_dirfd);
        int host_rc = symlinkat(targetbuf, sv_dirfd, linktrans);
        int saved = errno;
        close(sv_dirfd);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        invalidate_path_shadow_cache(ctx);
        return kbox_dispatch_value(0);
    }

    /* Target is stored as-is (not translated). */
    long ret = kbox_lkl_symlinkat(ctx->sysnrs, targetbuf, newdirfd, linktrans);
    if (ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_linkat(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    int rc;
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 4));

    char oldtrans[KBOX_MAX_PATH];
    long olddirfd;
    rc = translate_request_at_path(req, ctx, 0, 1, oldtrans, sizeof(oldtrans),
                                   &olddirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char newtrans[KBOX_MAX_PATH];
    long newdirfd;
    rc = translate_request_at_path(req, ctx, 2, 3, newtrans, sizeof(newtrans),
                                   &newdirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Host dirfd on either side: call host linkat with supervisor copies. */
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
        int host_rc = linkat(sv_old, oldtrans, sv_new, newtrans, (int) flags);
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

    long ret = kbox_lkl_linkat(ctx->sysnrs, olddirfd, oldtrans, newdirfd,
                               newtrans, flags);
    if (ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

/* struct timespec is 16 bytes on 64-bit: tv_sec(8) + tv_nsec(8). */
#define TIMESPEC_SIZE 16

struct kbox_dispatch forward_utimensat(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    long dirfd_raw = to_dirfd_arg(kbox_syscall_request_arg(req, 0));

    /* pathname can be NULL for utimensat (operates on dirfd itself). In that
     * case args[1] == 0.
     */
    const char *translated_path = NULL;
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc;
    int need_host_emulation = 0;

    if (kbox_syscall_request_arg(req, 1) != 0) {
        rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        translated_path = translated;
        if (should_continue_for_dirfd(lkl_dirfd))
            need_host_emulation = 1;
    } else {
        translated_path = NULL;
        /* dirfd must be a virtual FD when path is NULL. */
        lkl_dirfd = kbox_fd_table_get_lkl(ctx->fd_table, dirfd_raw);
        if (lkl_dirfd < 0)
            need_host_emulation = 1;
    }

    /* Read the times array (2 x struct timespec) if provided. */
    uint8_t times_buf[TIMESPEC_SIZE * 2];
    const void *times = NULL;
    if (kbox_syscall_request_arg(req, 2) != 0) {
        rc = guest_mem_read(ctx, pid, kbox_syscall_request_arg(req, 2),
                            times_buf, sizeof(times_buf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        times = times_buf;
    }

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    /* Host dirfd (or host-passthrough FD with NULL path): call host utimensat
     * with a supervisor-owned copy of the tracee's dirfd.
     */
    if (need_host_emulation) {
        int sv_dirfd = dup_tracee_fd(pid, (int) dirfd_raw);
        if (sv_dirfd < 0)
            return kbox_dispatch_errno(-sv_dirfd);
        int host_rc = utimensat(sv_dirfd, translated_path,
                                (const struct timespec *) times, (int) flags);
        int saved = errno;
        close(sv_dirfd);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        invalidate_path_shadow_cache(ctx);
        return kbox_dispatch_value(0);
    }

    long ret = kbox_lkl_utimensat(ctx->sysnrs, lkl_dirfd, translated_path,
                                  times, flags);
    if (ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

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

struct kbox_dispatch forward_ioctl(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long cmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY) {
        /* Host-passthrough FD (stdin/stdout/stderr, pipe, eventfd, etc.).
         * Most ioctls pass through to the host kernel.  Job-control ioctls
         * fail with EPERM under seccomp-unotify because the supervised child
         * is not the session leader.  Return ENOTTY so shells fall back to
         * non-job-control mode instead of aborting.
         */
        if (cmd == TIOCSPGRP || cmd == TIOCGPGRP || cmd == TIOCSCTTY)
            return kbox_dispatch_errno(ENOTTY);
        return kbox_dispatch_continue();
    }
    if (lkl_fd < 0) {
        if (!fd_should_deny_io(fd, lkl_fd)) {
            if (cmd == TIOCSPGRP || cmd == TIOCGPGRP || cmd == TIOCSCTTY)
                return kbox_dispatch_errno(ENOTTY);
            return kbox_dispatch_continue();
        }
        return kbox_dispatch_errno(EBADF);
    }

    /* For virtual FDs backed by LKL, terminal ioctls yield -ENOTTY since LKL
     * file-backed FDs are not terminals. Non-terminal ioctls also yield
     * -ENOTTY, matching regular-file semantics.
     */
    return kbox_dispatch_errno(ENOTTY);
}

/* Intercepted FD-creating syscalls: eventfd, timerfd_create, epoll_create1.
 *
 * Previously these went through CONTINUE, leaving their FDs untracked. That
 * allowed read/write on leaked host FDs to also CONTINUE. Now we create the
 * FD in the supervisor, inject it via ADDFD, and track it as host-passthrough
 * so the EBADF policy for untracked FDs does not break legitimate I/O.
 */

struct kbox_dispatch forward_eventfd(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx)
{
    unsigned int initval = (unsigned int) kbox_syscall_request_arg(req, 0);
    int flags = (int) to_c_long_arg(kbox_syscall_request_arg(req, 1));

    int host_fd = eventfd(initval, flags & ~EFD_CLOEXEC);
    if (host_fd < 0)
        return kbox_dispatch_errno(errno);

    uint32_t addfd_flags = (flags & EFD_CLOEXEC) ? O_CLOEXEC : 0;
    int tracee_fd = request_addfd(ctx, req, host_fd, addfd_flags);
    close(host_fd);
    if (tracee_fd < 0)
        return kbox_dispatch_errno(-tracee_fd);

    track_host_passthrough_fd(ctx->fd_table, tracee_fd);
    if (flags & EFD_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, tracee_fd, 1);

    return kbox_dispatch_value(tracee_fd);
}

struct kbox_dispatch forward_timerfd_create(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    int clockid = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));
    int flags = (int) to_c_long_arg(kbox_syscall_request_arg(req, 1));

    int host_fd = timerfd_create(clockid, flags & ~TFD_CLOEXEC);
    if (host_fd < 0)
        return kbox_dispatch_errno(errno);

    uint32_t addfd_flags = (flags & TFD_CLOEXEC) ? O_CLOEXEC : 0;
    int tracee_fd = request_addfd(ctx, req, host_fd, addfd_flags);
    close(host_fd);
    if (tracee_fd < 0)
        return kbox_dispatch_errno(-tracee_fd);

    track_host_passthrough_fd(ctx->fd_table, tracee_fd);
    if (flags & TFD_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, tracee_fd, 1);

    return kbox_dispatch_value(tracee_fd);
}

struct kbox_dispatch forward_epoll_create1(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    int flags = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));

    int host_fd = epoll_create1(flags & ~EPOLL_CLOEXEC);
    if (host_fd < 0)
        return kbox_dispatch_errno(errno);

    uint32_t addfd_flags = (flags & EPOLL_CLOEXEC) ? O_CLOEXEC : 0;
    int tracee_fd = request_addfd(ctx, req, host_fd, addfd_flags);
    close(host_fd);
    if (tracee_fd < 0)
        return kbox_dispatch_errno(-tracee_fd);

    track_host_passthrough_fd(ctx->fd_table, tracee_fd);
    if (flags & EPOLL_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, tracee_fd, 1);

    return kbox_dispatch_value(tracee_fd);
}
