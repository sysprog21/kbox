/* SPDX-License-Identifier: MIT */

/* Network syscall handlers for the seccomp dispatch engine. */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dispatch-internal.h"
#include "net.h"

/* Shadow socket design:
 *   1. Create an LKL network socket inside LKL's network stack
 *   2. Create a host socketpair (sp[0]=supervisor, sp[1]=tracee)
 *   3. Inject sp[1] into the tracee via ADDFD
 *   4. Register sp[0]+lkl_fd with the SLIRP event loop
 *   5. The event loop pumps data between sp[0] and the LKL socket
 *
 * The tracee sees a real host FD, so poll/epoll/read/write all work natively
 * via the host kernel. Only control-plane ops (connect, getsockopt, etc.) need
 * explicit forwarding.
 *
 * INET sockets with SLIRP active get a shadow socket bridge so data flows
 * through the host kernel socketpair (bypassing BKL contention in blocking LKL
 * recv/send calls). Non-INET sockets and INET sockets without SLIRP use the
 * standard virtual FD path.
 *
 * Limitation: listen/accept on shadow sockets fail because AF_UNIX socketpair
 * doesn't support inbound connections. Server sockets must be used without
 * --net or via a future deferred-bridge approach.
 */
struct kbox_dispatch forward_socket(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    long domain = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long type_raw = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long protocol = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    int base_type = (int) type_raw & 0xFF;

    long ret = kbox_lkl_socket(ctx->sysnrs, domain, type_raw, protocol);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long lkl_fd = ret;

    /* Virtual FD path when shadow bridge is not applicable:
     * - SLIRP not active (no --net)
     * - Non-INET domain (AF_UNIX, AF_NETLINK, etc.)
     * - Non-stream/datagram type (SOCK_RAW, etc.): socketpair(AF_UNIX) only
     *   supports SOCK_STREAM and SOCK_DGRAM
     */
    if (!kbox_net_is_active() ||
        (domain != 2 /* AF_INET */ && domain != 10 /* AF_INET6 */) ||
        (base_type != SOCK_STREAM && base_type != SOCK_DGRAM)) {
        long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd, 0);
        if (vfd < 0) {
            lkl_close_and_invalidate(ctx, lkl_fd);
            return kbox_dispatch_errno(EMFILE);
        }
        return kbox_dispatch_value((int64_t) vfd);
    }

    /* Shadow socket bridge for INET with SLIRP. */
    int sp[2];
    if (socketpair(AF_UNIX, base_type | SOCK_CLOEXEC, 0, sp) < 0) {
        lkl_close_and_invalidate(ctx, lkl_fd);
        return kbox_dispatch_errno(errno);
    }
    fcntl(sp[0], F_SETFL, O_NONBLOCK);
    if (type_raw & SOCK_NONBLOCK)
        fcntl(sp[1], F_SETFL, O_NONBLOCK);

    long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd, 0);
    if (vfd < 0) {
        close(sp[0]);
        close(sp[1]);
        lkl_close_and_invalidate(ctx, lkl_fd);
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
    int host_fd = request_addfd(ctx, req, sp[1], addfd_flags);
    if (host_fd < 0) {
        /* Deregister closes sp[0] and marks inactive. */
        kbox_net_deregister_socket((int) lkl_fd);
        close(sp[1]);
        kbox_fd_table_remove(ctx->fd_table, vfd);
        lkl_close_and_invalidate(ctx, lkl_fd);
        return kbox_dispatch_errno(-host_fd);
    }
    kbox_fd_table_set_host_fd(ctx->fd_table, vfd, host_fd);

    /* The ADDFD-injected host_fd may land on a low FD number that already
     * has a SHADOW_ONLY entry (from pipe tracking or inherited FD scan).
     * Overwrite it so resolve_lkl_socket finds the LKL socket via the
     * direct lookup path instead of returning the stale SHADOW_ONLY.
     */
    if (host_fd != vfd) {
        struct kbox_fd_entry *low = fd_table_entry(ctx->fd_table, host_fd);
        if (low && low->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
            kbox_fd_table_remove(ctx->fd_table, host_fd);
    }

    {
        struct kbox_fd_entry *e = fd_table_entry(ctx->fd_table, vfd);
        if (e) {
            e->shadow_sp = sp[1];
            if (type_raw & SOCK_CLOEXEC)
                e->cloexec = 1;
        }
    }

    return kbox_dispatch_value((int64_t) host_fd);
}

static long resolve_lkl_socket(struct kbox_supervisor_ctx *ctx, long fd);

struct kbox_dispatch forward_bind(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;

    if (addr_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    if (len > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t buf[4096];
    int rrc = guest_mem_read(ctx, pid, addr_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long ret = kbox_lkl_bind(ctx->sysnrs, lkl_fd, buf, (long) len);
    return kbox_dispatch_from_lkl(ret);
}

/* Resolve LKL FD from a tracee FD.  The tracee may hold either a virtual FD
 * (>= KBOX_FD_BASE) or a host FD from a shadow-socket bridge via ADDFD.
 * Try both paths.
 */
static long resolve_lkl_socket(struct kbox_supervisor_ctx *ctx, long fd)
{
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd >= 0 || lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
        return lkl_fd;

    /* Shadow socket: tracee uses the host_fd directly. */
    long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
    if (vfd >= 0)
        return kbox_fd_table_get_lkl(ctx->fd_table, vfd);

    return -1;
}

struct kbox_dispatch forward_connect(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;

    if (addr_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    if (len > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t buf[4096];
    int rrc = guest_mem_read(ctx, pid, addr_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long ret = kbox_lkl_connect(ctx->sysnrs, lkl_fd, buf, (long) len);

    /* Propagate -EINPROGRESS directly for nonblocking sockets. The tracee's
     * poll(POLLOUT) on the AF_UNIX socketpair returns immediately (spurious
     * wakeup), but getsockopt(SO_ERROR) is forwarded to the LKL socket and
     * returns the real handshake status. The tracee retries poll+getsockopt
     * until SO_ERROR clears; standard nonblocking connect flow.
     */
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_getsockopt(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    long level = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long optname = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    uint64_t optval_ptr = kbox_syscall_request_arg(req, 3);
    uint64_t optlen_ptr = kbox_syscall_request_arg(req, 4);

    if (optval_ptr == 0 || optlen_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Read the optlen from tracee. */
    unsigned int optlen;
    int rrc = guest_mem_read(ctx, pid, optlen_ptr, &optlen, sizeof(optlen));
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
    int wrc = guest_mem_write(ctx, pid, optval_ptr, optval, write_len);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    wrc = guest_mem_write(ctx, pid, optlen_ptr, &out_len, sizeof(out_len));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_setsockopt(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    long level = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long optname = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    uint64_t optval_ptr = kbox_syscall_request_arg(req, 3);
    long optlen = to_c_long_arg(kbox_syscall_request_arg(req, 4));

    if (optlen < 0 || optlen > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t optval[4096] = {0};
    if (optval_ptr != 0 && optlen > 0) {
        int rrc = guest_mem_read(ctx, pid, optval_ptr, optval, (size_t) optlen);
        if (rrc < 0)
            return kbox_dispatch_errno(-rrc);
    }

    long ret = kbox_lkl_setsockopt(ctx->sysnrs, lkl_fd, level, optname,
                                   optval_ptr ? optval : NULL, optlen);
    return kbox_dispatch_from_lkl(ret);
}

typedef long (*sockaddr_query_fn)(const struct kbox_sysnrs *s,
                                  long fd,
                                  void *addr,
                                  void *addrlen);

static struct kbox_dispatch forward_sockaddr_query(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    sockaddr_query_fn query)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    uint64_t len_ptr = kbox_syscall_request_arg(req, 2);

    if (addr_ptr == 0 || len_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    unsigned int addrlen;
    int rrc = guest_mem_read(ctx, pid, len_ptr, &addrlen, sizeof(addrlen));
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
    int wrc = guest_mem_write(ctx, pid, addr_ptr, addr, write_len);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    wrc = guest_mem_write(ctx, pid, len_ptr, &out_len, sizeof(out_len));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_getsockname(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    return forward_sockaddr_query(req, ctx, kbox_lkl_getsockname);
}

struct kbox_dispatch forward_getpeername(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    return forward_sockaddr_query(req, ctx, kbox_lkl_getpeername);
}

struct kbox_dispatch forward_shutdown(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    long how = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_shutdown(ctx->sysnrs, lkl_fd, how);
    return kbox_dispatch_from_lkl(ret);
}

/* For shadow sockets with a destination address, forward the data + address
 * directly to the LKL socket. This is needed for unconnected UDP (DNS resolver
 * uses sendto with sockaddr_in without prior connect).
 *
 * sendto(fd, buf, len, flags, dest_addr, addrlen)
 *   args[0]=fd, args[1]=buf, args[2]=len, args[3]=flags,
 *   args[4]=dest_addr, args[5]=addrlen
 */
struct kbox_dispatch forward_sendto(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    uint64_t dest_ptr = kbox_syscall_request_arg(req, 4);
    if (dest_ptr == 0)
        return kbox_dispatch_continue(); /* no dest addr: stream data path */

    /* Has a destination address: forward via LKL sendto. */
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t buf_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    int64_t addrlen_raw = to_c_long_arg(kbox_syscall_request_arg(req, 5));

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

    int rrc = guest_mem_read(ctx, pid, buf_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);
    rrc = guest_mem_read(ctx, pid, dest_ptr, addr, addrlen);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long ret = kbox_lkl_sendto(ctx->sysnrs, lkl_fd, buf, (long) len, flags,
                               addr, (long) addrlen);
    return kbox_dispatch_from_lkl(ret);
}

/* For shadow sockets, receive data + source address from the LKL socket and
 * write them back to the tracee.
 *
 * recvfrom(fd, buf, len, flags, src_addr, addrlen)
 *   args[0]=fd, args[1]=buf, args[2]=len, args[3]=flags,
 *   args[4]=src_addr, args[5]=addrlen
 */
struct kbox_dispatch forward_recvfrom(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    uint64_t src_ptr = kbox_syscall_request_arg(req, 4);
    if (src_ptr == 0)
        return kbox_dispatch_continue(); /* no addr buffer: stream path */

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t buf_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    uint64_t addrlen_ptr = kbox_syscall_request_arg(req, 5);

    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;
    if (len > 65536)
        len = 65536;

    unsigned int addrlen = 0;
    if (addrlen_ptr != 0) {
        int rrc =
            guest_mem_read(ctx, pid, addrlen_ptr, &addrlen, sizeof(addrlen));
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

    int wrc = guest_mem_write(ctx, pid, buf_ptr, buf, (size_t) ret);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    if (src_ptr != 0 && out_addrlen > 0) {
        unsigned int write_len = out_addrlen < addrlen ? out_addrlen : addrlen;
        wrc = guest_mem_write(ctx, pid, src_ptr, addr, write_len);
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    if (addrlen_ptr != 0) {
        wrc = guest_mem_write(ctx, pid, addrlen_ptr, &out_addrlen,
                              sizeof(out_addrlen));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    return kbox_dispatch_value(ret);
}

/* Intercept for shadow sockets so that msg_name (source
 * address) is populated from the LKL socket, not the AF_UNIX socketpair.
 *
 * recvmsg(fd, msg, flags)
 *   args[0]=fd, args[1]=msg_ptr, args[2]=flags
 */
struct kbox_dispatch forward_recvmsg(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t msg_ptr = kbox_syscall_request_arg(req, 1);
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));

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
    int rrc = guest_mem_read(ctx, pid, msg_ptr, &mh, sizeof(mh));
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
    rrc = guest_mem_read(ctx, pid, mh.msg_iov, iovs, niov * sizeof(iovs[0]));
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
            int wrc2 = guest_mem_write(ctx, pid, iovs[v].iov_base,
                                       buf + written, chunk);
            if (wrc2 < 0)
                return kbox_dispatch_errno(-wrc2);
            written += chunk;
        }
    }

    /* Write source address to tracee msg_name. */
    if (out_addrlen > 0) {
        unsigned int write_len =
            out_addrlen < mh.msg_namelen ? out_addrlen : mh.msg_namelen;
        int awrc = guest_mem_write(ctx, pid, mh.msg_name, addr, write_len);
        if (awrc < 0)
            return kbox_dispatch_errno(-awrc);
    }

    /* Update msg_namelen in the msghdr. */
    int nwrc =
        guest_mem_write(ctx, pid, msg_ptr + 8 /* offset of msg_namelen */,
                        &out_addrlen, sizeof(out_addrlen));
    if (nwrc < 0)
        return kbox_dispatch_errno(-nwrc);

    /* Zero msg_controllen and msg_flags: the recvfrom path does not
     * produce ancillary data. Without this, CMSG_FIRSTHDR() in the
     * tracee would parse uninitialized memory from the msg_control
     * buffer.
     */
    uint64_t zero8 = 0;
    int zero4 = 0;
    int cwrc;
    /* msg_controllen is at offset 40 (after msg_control at 32). */
    cwrc = guest_mem_write(ctx, pid, msg_ptr + 40, &zero8, sizeof(zero8));
    if (cwrc < 0)
        return kbox_dispatch_errno(-cwrc);
    /* msg_flags is at offset 48. */
    cwrc = guest_mem_write(ctx, pid, msg_ptr + 48, &zero4, sizeof(zero4));
    if (cwrc < 0)
        return kbox_dispatch_errno(-cwrc);

    return kbox_dispatch_value(ret);
}
