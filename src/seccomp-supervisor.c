/* SPDX-License-Identifier: MIT */
/* seccomp-supervisor.c - Fork, install seccomp, exec, supervise.
 *
 * The supervisor creates a socketpair, forks a child process, installs
 * a seccomp-unotify BPF filter in the child, sends the listener FD
 * back over the socketpair, and then execs the target command.  The
 * parent sits in a poll loop receiving intercepted syscalls, forwarding
 * them to LKL, and sending responses back.
 *
 */

#include <errno.h>
/* seccomp types via seccomp.h -> seccomp-defs.h */
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fd-table.h"
#include "seccomp.h"
#include "syscall-nr.h"
#ifdef KBOX_HAS_WEB
#include "web.h"
#endif

/* Notification types (kbox_seccomp_notif etc.) are provided by
 * seccomp-defs.h via seccomp.h.
 */

/* SCM_RIGHTS helpers. */

/* Create a UNIX socketpair.
 * On success fds[0] and fds[1] are filled; returns 0.
 * On failure returns -1 with a message on stderr.
 */
static int socketpair_create(int fds[2])
{
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        fprintf(stderr, "socketpair: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/* Send a single file descriptor over a UNIX socket using SCM_RIGHTS.
 */
static int send_fd(int sock, int fd)
{
    char buf = 0;
    struct iovec iov = {
        .iov_base = &buf,
        .iov_len = 1,
    };

    /* Ancillary data buffer.  CMSG_SPACE gives the padded size
     * needed to carry one int.
     */
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;

    struct msghdr msg;
    struct cmsghdr *cmsg;

    memset(&cmsg_buf, 0, sizeof(cmsg_buf));
    memset(&msg, 0, sizeof(msg));

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.buf;
    msg.msg_controllen = sizeof(cmsg_buf.buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    {
        ssize_t sret;
        do {
            sret = sendmsg(sock, &msg, 0);
        } while (sret < 0 && errno == EINTR);
        if (sret < 0) {
            fprintf(stderr, "sendmsg(SCM_RIGHTS): %s\n", strerror(errno));
            return -1;
        }
    }
    return 0;
}

/* Receive a single file descriptor from a UNIX socket via SCM_RIGHTS.
 * Returns the received FD on success, -1 on error.
 */
static int recv_fd(int sock)
{
    char buf;
    struct iovec iov = {
        .iov_base = &buf,
        .iov_len = 1,
    };

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;

    struct msghdr msg;
    struct cmsghdr *cmsg;
    ssize_t n;
    int fd;

    memset(&cmsg_buf, 0, sizeof(cmsg_buf));
    memset(&msg, 0, sizeof(msg));

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.buf;
    msg.msg_controllen = sizeof(cmsg_buf.buf);

    do {
        n = recvmsg(sock, &msg, 0);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
        fprintf(stderr, "recvmsg(SCM_RIGHTS): %s\n", strerror(errno));
        return -1;
    }
    if (n == 0) {
        fprintf(stderr, "recvmsg: peer closed socket before sending fd\n");
        return -1;
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg) {
        fprintf(stderr, "recvmsg: missing cmsg header\n");
        return -1;
    }
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        fprintf(stderr, "recvmsg: unexpected cmsg type\n");
        return -1;
    }
    if (cmsg->cmsg_len < CMSG_LEN(sizeof(int))) {
        fprintf(stderr, "recvmsg: short cmsg payload\n");
        return -1;
    }

    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

/* Build a seccomp_notif_resp from a dispatch result. */

/* KBOX_NOTIF_FLAG_CONTINUE from seccomp-defs.h */

static void build_response(struct kbox_seccomp_notif_resp *resp,
                           uint64_t id,
                           const struct kbox_dispatch *d)
{
    memset(resp, 0, sizeof(*resp));
    resp->id = id;

    switch (d->kind) {
    case KBOX_DISPATCH_CONTINUE:
        resp->flags = KBOX_NOTIF_FLAG_CONTINUE;
        resp->val = 0;
        resp->error = 0;
        break;
    case KBOX_DISPATCH_RETURN:
        resp->flags = 0;
        resp->val = d->val;
        /* seccomp_notif_resp.error is a negative errno value.
         * The kernel negates it to produce the tracee's errno:
         *   error = -ENOENT (-2)  =>  tracee errno = 2 (ENOENT)
         * kbox_dispatch_errno stores positive values, so negate here.
         */
        resp->error = d->error ? -d->error : 0;
        break;
    }
}

/* Child wait helper. */

/* Check child status via non-blocking waitpid.
 * Returns:
 *   1  if child exited; *exit_code is filled with the exit status.
 *   0  if child is still running.
 *  -1  on waitpid failure.
 */
static int check_child(pid_t pid, int *exit_code)
{
    int status = 0;
    pid_t w;

    w = waitpid(pid, &status, WNOHANG);
    if (w < 0)
        return -1;
    if (w == 0)
        return 0;

    if (WIFEXITED(status)) {
        *exit_code = WEXITSTATUS(status);
        return 1;
    }
    if (WIFSIGNALED(status)) {
        *exit_code = 128 + WTERMSIG(status);
        return 1;
    }
    return 0;
}

/* Supervisor loop. */

/* Sit in a poll loop on two FDs:
 *   - listener_fd: seccomp notifications from the child.
 *   - sigchld_fd:  signalfd for SIGCHLD (instant child-exit wakeup).
 *
 * On SIGCHLD or POLLHUP, recheck child via non-blocking waitpid.
 * On POLLIN for the listener, receive notification, dispatch, respond.
 *
 * SIGCHLD must already be blocked by the caller before fork() so the
 * signal cannot be lost between fork and signalfd creation.
 *
 * Returns the child exit code, or -1 on fatal error.
 */
static int supervise_loop(struct kbox_supervisor_ctx *ctx)
{
    struct kbox_seccomp_notif notif;
    struct kbox_seccomp_notif_resp resp;
    struct kbox_syscall_request req;
    struct kbox_dispatch d;
    struct pollfd pfds[2];
    int exit_code = -1;
    int ret;
    int sigchld_fd;
    int poll_timeout;

    /* Create a signalfd for SIGCHLD so poll() wakes immediately when the child
     * exits. SIGCHLD must already be blocked by the caller (before fork) to
     * avoid losing the signal in the race between fork and this point.
     */
    {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGCHLD);
        sigchld_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    }
    if (sigchld_fd < 0) {
        fprintf(stderr, "signalfd: %s\n", strerror(errno));
        return -1;
    }

    poll_timeout = -1;
#ifdef KBOX_HAS_WEB
    if (ctx->web)
        poll_timeout = 100;
#endif

    for (;;) {
        /* Poll for seccomp notifications and SIGCHLD simultaneously.
         * In the normal non-web steady state we block here instead of
         * doing a non-blocking waitpid() on every iteration; that extra
         * wait syscall shows up directly in the seccomp fast path on
         * syscall-heavy workloads.
         */
        pfds[0].fd = ctx->listener_fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = sigchld_fd;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;

        ret = poll(pfds, 2, poll_timeout);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "poll(listener): %s\n", strerror(errno));
            goto out;
        }
        if (ret == 0) {
#ifdef KBOX_HAS_WEB
            /* Timer-driven telemetry sampling on poll timeout. */
            if (ctx->web) {
                kbox_web_set_fd_used(ctx->web,
                                     kbox_fd_table_count(ctx->fd_table));
                kbox_web_tick(ctx->web);
            }
#endif
            continue;
        }

        /* SIGCHLD received: drain the signalfd and check child. */
        if (pfds[1].revents & POLLIN) {
            struct signalfd_siginfo si;
            while (read(sigchld_fd, &si, sizeof(si)) > 0)
                ;
            ret = check_child(ctx->child_pid, &exit_code);
            if (ret < 0) {
                fprintf(stderr, "waitpid: %s\n", strerror(errno));
                goto out;
            }
            if (ret == 1)
                goto out;
        }

        /* POLLHUP / POLLERR on listener => recheck child. */
        if (pfds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) {
            ret = check_child(ctx->child_pid, &exit_code);
            if (ret < 0) {
                fprintf(stderr, "waitpid: %s\n", strerror(errno));
                goto out;
            }
            if (ret == 1)
                goto out;
            continue;
        }

        /* No data on listener FD. */
        if (!(pfds[0].revents & POLLIN))
            continue;

        /* Receive notification. */
        ret = kbox_notify_recv(ctx->listener_fd, &notif);
        if (ret < 0) {
            int e = -ret;
            if (e == EINTR || e == EAGAIN || e == ENOENT) {
#ifdef KBOX_HAS_WEB
                if (e == ENOENT && ctx->web)
                    kbox_web_counters(ctx->web)->recv_enoent++;
#endif
                if (e == ENOENT) {
                    ret = check_child(ctx->child_pid, &exit_code);
                    if (ret < 0) {
                        fprintf(stderr, "waitpid: %s\n", strerror(errno));
                        goto out;
                    }
                    if (ret == 1)
                        goto out;
                }
                continue;
            }
            fprintf(stderr, "kbox_notify_recv: %s\n", strerror(e));
            goto out;
        }

        /* Dispatch to LKL (with optional latency measurement). */
#ifdef KBOX_HAS_WEB
        uint64_t t_dispatch_start = 0;
        if (ctx->web)
            t_dispatch_start = kbox_clock_ns();
#endif
        if (kbox_syscall_request_from_notif(&notif, &req) < 0) {
            fprintf(stderr, "kbox: failed to decode seccomp notification\n");
            goto out;
        }
        d = kbox_dispatch_request(ctx, &req);

        /* Build and send response. */
        build_response(&resp, notif.id, &d);
        ret = kbox_notify_send(ctx->listener_fd, &resp);

#ifdef KBOX_HAS_WEB
        /* Record telemetry after send (includes full round-trip). */
        if (ctx->web) {
            uint64_t latency = kbox_clock_ns() - t_dispatch_start;

            enum kbox_disposition disp;
            if (d.kind == KBOX_DISPATCH_CONTINUE)
                disp = KBOX_DISP_CONTINUE;
            else if (d.error == ENOSYS)
                disp = KBOX_DISP_ENOSYS;
            else
                disp = KBOX_DISP_RETURN;

            const char *sname = syscall_name_from_nr(ctx->host_nrs, req.nr);

            kbox_web_record_syscall(ctx->web, (uint32_t) req.pid, req.nr, sname,
                                    req.args, disp, d.val, d.error, latency);
        }
#endif

        if (ret < 0) {
            int e = -ret;
            /* ENOENT: tracee died between recv and send.
             * EBADF: notification ID invalidated (thread exit
             *        in a multi-threaded guest).
             * Both are harmless; loop around, waitpid picks
             * up the exit.
             */
            if (e == ENOENT || e == EBADF) {
#ifdef KBOX_HAS_WEB
                if (e == ENOENT && ctx->web)
                    kbox_web_counters(ctx->web)->send_enoent++;
#endif
                ret = check_child(ctx->child_pid, &exit_code);
                if (ret < 0) {
                    fprintf(stderr, "waitpid: %s\n", strerror(errno));
                    goto out;
                }
                if (ret == 1)
                    goto out;
                continue;
            }
            fprintf(stderr, "kbox_notify_send: %s\n", strerror(e));
            goto out;
        }
    }

out:
    close(sigchld_fd);
    return exit_code;
}

/* Public entry point. */

int kbox_run_supervisor(const struct kbox_sysnrs *sysnrs,
                        const char *command,
                        const char *const *args,
                        int nargs,
                        const char *host_root,
                        int exec_memfd,
                        int verbose,
                        int root_identity,
                        int normalize,
                        struct kbox_web_ctx *web)
{
    int sp[2]; /* socketpair */
    pid_t pid;
    int listener_fd;
    int exit_code;
    int status;
    struct kbox_fd_table fd_table;
    struct kbox_supervisor_ctx ctx;
    sigset_t old_mask;

    /* Architecture-specific host syscall numbers for the BPF filter. */
#if defined(__x86_64__)
    const struct kbox_host_nrs *host_nrs = &HOST_NRS_X86_64;
#elif defined(__aarch64__)
    const struct kbox_host_nrs *host_nrs = &HOST_NRS_AARCH64;
#else
#error "Unsupported architecture"
#endif

    /* 1. Create socketpair for passing the listener FD. */
    if (socketpair_create(sp) < 0)
        return -1;

    /* Block SIGCHLD before fork so the parent cannot lose the signal
     * in the window between fork and signalfd creation.  Save the
     * caller's mask so both parent and child can restore it later.
     */
    {
        sigset_t chld_mask;
        sigemptyset(&chld_mask);
        sigaddset(&chld_mask, SIGCHLD);
        if (sigprocmask(SIG_BLOCK, &chld_mask, &old_mask) < 0) {
            fprintf(stderr, "sigprocmask(SIG_BLOCK): %s\n", strerror(errno));
            close(sp[0]);
            close(sp[1]);
            return -1;
        }
    }

    /* 2. Fork. */
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        close(sp[0]);
        close(sp[1]);
        if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0)
            fprintf(stderr, "sigprocmask(SIG_SETMASK): %s\n", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* Child process. */
        close(sp[0]);

        /* Raise RLIMIT_NOFILE so the host kernel allows FD numbers
         * above the default limit (typically 1024).  The guest shell
         * (busybox ash) saves/restores FDs via fcntl(F_DUPFD, minfd)
         * where minfd can be above 4096 when virtual FDs are in use.
         * Without this, the host kernel returns EINVAL.
         */
        {
            struct rlimit rl;
            rl.rlim_cur = 65536;
            rl.rlim_max = 65536;
            setrlimit(RLIMIT_NOFILE, &rl);
        }

        /* Prevent RT scheduling starvation: cap RLIMIT_RTPRIO to 0
         * so sched_setscheduler(SCHED_FIFO/RR) fails with EPERM.
         * This makes sched_* CONTINUE entries safe.
         */
        {
            struct rlimit rtlim = {0, 0};
            setrlimit(RLIMIT_RTPRIO, &rtlim);
        }

        /* 3a. No new privileges: required for seccomp. */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            fprintf(stderr, "prctl(PR_SET_NO_NEW_PRIVS): %s\n",
                    strerror(errno));
            _exit(127);
        }

        /* Drop all ambient capabilities and clear the bounding set.
         * This limits what the child can do even if it somehow
         * gains privileges.  Errors are ignored: a given cap number
         * may not exist on this kernel.
         */
        prctl(47 /* PR_CAP_AMBIENT */, 4 /* PR_CAP_AMBIENT_CLEAR_ALL */, 0, 0,
              0);
        for (int cap = 0; cap <= 63; cap++)
            prctl(24 /* PR_CAPBSET_DROP */, cap, 0, 0, 0);

        /* 3b. Install BPF filter, get listener FD. */
        listener_fd = kbox_install_seccomp_listener(host_nrs);
        if (listener_fd < 0) {
            fprintf(stderr, "kbox_install_seccomp_listener failed\n");
            _exit(127);
        }

        /* 3c. Send listener FD to parent via SCM_RIGHTS.
         * sendmsg is in the BPF allow list so this bypasses seccomp. */
        if (send_fd(sp[1], listener_fd) < 0)
            _exit(127);

        /* 3d. Close socket and listener; parent owns them now. */
        close(sp[1]);
        close(listener_fd);

        /* 3e. Restore the inherited signal mask before exec. */
        if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0) {
            fprintf(stderr, "sigprocmask(SIG_SETMASK): %s\n", strerror(errno));
            _exit(127);
        }

        /* 3f. Build argv and exec.
         *
         * argv[0] = command, then args[0..nargs], then NULL.
         *
         * If exec_memfd >= 0 (image mode), use fexecve to exec
         * the memfd directly.  This allows running binaries from
         * the LKL filesystem without them existing on the host.
         */
        {
            const char **argv;
            int i;

            argv = malloc((size_t) (nargs + 2) * sizeof(char *));
            if (!argv)
                _exit(127);

            argv[0] = command;
            for (i = 0; i < nargs; i++)
                argv[i + 1] = args[i];
            argv[nargs + 1] = NULL;

            if (exec_memfd >= 0)
                fexecve(exec_memfd, (char *const *) argv, environ);
            else
                execv(command, (char *const *) argv);

            /* exec only returns on failure. */
            fprintf(stderr, "exec(%s): %s\n", command, strerror(errno));
            free(argv);
        }
        _exit(127);
    }

    /* Parent process. */
    close(sp[1]);

    /* 4a. Receive listener FD from child. */
    listener_fd = recv_fd(sp[0]);
    close(sp[0]);

    if (listener_fd < 0) {
        /* Child probably died.  Reap and report. */
        pid_t w;
        status = 0;
        w = waitpid(pid, &status, WNOHANG);
        if (w == 0) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
        }
        fprintf(stderr, "failed to receive seccomp listener fd\n");
        if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0)
            fprintf(stderr, "sigprocmask(SIG_SETMASK): %s\n", strerror(errno));
        return -1;
    }

    /* 4b. Set up supervisor context. */
    kbox_fd_table_init(&fd_table);

    memset(&ctx, 0, sizeof(ctx));
    ctx.sysnrs = sysnrs;
    ctx.host_nrs = host_nrs;
    ctx.fd_table = &fd_table;
    ctx.listener_fd = listener_fd;
    ctx.proc_self_fd_dirfd = -1;
    ctx.proc_mem_fd = -1;
    ctx.child_pid = pid;
    ctx.host_root = host_root;
    ctx.verbose = verbose;
    ctx.root_identity = root_identity;
    ctx.override_uid = (uid_t) -1;
    ctx.override_gid = (gid_t) -1;
    ctx.normalize = normalize;
    ctx.guest_mem_ops = &kbox_process_vm_guest_mem_ops;
    ctx.fd_inject_ops = NULL;
    ctx.web = web;

    /* 4c. Enter supervisor loop. */
    exit_code = supervise_loop(&ctx);

    /* Restore the caller's signal mask now that the signalfd is closed. */
    if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0)
        fprintf(stderr, "sigprocmask(SIG_SETMASK): %s\n", strerror(errno));

    if (ctx.proc_mem_fd >= 0)
        close(ctx.proc_mem_fd);
    if (ctx.proc_self_fd_dirfd >= 0)
        close(ctx.proc_self_fd_dirfd);
    close(listener_fd);

    if (exit_code < 0) {
        if (kill(pid, SIGKILL) < 0 && errno != ESRCH)
            fprintf(stderr, "kill(%d): %s\n", (int) pid, strerror(errno));
        while (waitpid(pid, &status, 0) < 0) {
            if (errno == EINTR)
                continue;
            if (errno != ECHILD)
                fprintf(stderr, "waitpid: %s\n", strerror(errno));
            break;
        }
        return -1;
    }
    if (exit_code != 0) {
        fprintf(stderr, "child exited with status %d\n", exit_code);
        return -1;
    }
    return 0;
}
