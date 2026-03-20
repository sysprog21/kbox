/* SPDX-License-Identifier: MIT */
#ifndef KBOX_SECCOMP_H
#define KBOX_SECCOMP_H

#include <stdint.h>
#include <sys/types.h>

#include "kbox/fd-table.h"
#include "kbox/seccomp-defs.h"
#include "kbox/syscall-nr.h"

/*
 * Seccomp-unotify supervisor.
 *
 * The supervisor installs a BPF filter in the child process, then
 * sits in a loop receiving notifications for intercepted syscalls,
 * forwarding them to LKL, and sending responses back.
 */

/*
 * Dispatch result.  Either CONTINUE (let the host kernel handle it)
 * or RETURN (inject a specific return value/error).
 */
struct kbox_dispatch {
    enum {
        KBOX_DISPATCH_CONTINUE,
        KBOX_DISPATCH_RETURN,
    } kind;
    int64_t val;
    int error;
};

/*
 * Supervisor context.  Replaces 9+ parameter function signatures
 * from the Rust code.
 */
struct kbox_web_ctx; /* forward declaration */

struct kbox_supervisor_ctx {
    const struct kbox_sysnrs *sysnrs;
    const struct kbox_host_nrs *host_nrs;
    struct kbox_fd_table *fd_table;
    int listener_fd;
    pid_t child_pid;
    const char *host_root; /* NULL for image mode */
    int verbose;
    int root_identity;
    uid_t override_uid;
    gid_t override_gid;
    int normalize;
    struct kbox_web_ctx *web; /* NULL if telemetry disabled */
};

/* --- BPF filter (seccomp-bpf.c) --- */

/*
 * Build and install a seccomp listener.
 *
 * Returns the listener FD on success, -1 on error.
 * The child process must call this before exec.
 */
int kbox_install_seccomp_listener(const struct kbox_host_nrs *h);

/* --- Notify wrappers (seccomp-notify.c) --- */

/* seccomp ioctl: receive a notification. Returns 0 or -errno. */
int kbox_notify_recv(int listener_fd, void *notif);

/* seccomp ioctl: send a response. Returns 0 or -errno. */
int kbox_notify_send(int listener_fd, const void *resp);

/* seccomp ioctl: inject an FD into the tracee. Returns remote FD or -errno. */
int kbox_notify_addfd(int listener_fd,
                      uint64_t id,
                      int srcfd,
                      uint32_t newfd_flags);

/* Like kbox_notify_addfd but installs the FD at a specific number (for
 * dup2/dup3). */
int kbox_notify_addfd_at(int listener_fd,
                         uint64_t id,
                         int srcfd,
                         int target_fd,
                         uint32_t newfd_flags);

/* --- Dispatch (seccomp-dispatch.c) --- */

/*
 * Dispatch a single seccomp notification.
 * Returns a dispatch result to send back to the tracee.
 */
struct kbox_dispatch kbox_dispatch_syscall(struct kbox_supervisor_ctx *ctx,
                                           const void *notif);

/* Helper constructors for dispatch results. */
struct kbox_dispatch kbox_dispatch_continue(void);
struct kbox_dispatch kbox_dispatch_errno(int err);
struct kbox_dispatch kbox_dispatch_value(int64_t val);
struct kbox_dispatch kbox_dispatch_from_lkl(long ret);

/* --- Supervisor (seccomp-supervisor.c) --- */

/*
 * Fork a child process, install seccomp, exec the command,
 * and run the supervisor loop.
 *
 * Returns 0 on success or -1 on error.
 */
int kbox_run_supervisor(const struct kbox_sysnrs *sysnrs,
                        const char *command,
                        const char *const *args,
                        int nargs,
                        const char *host_root,
                        int exec_memfd,
                        int verbose,
                        int root_identity,
                        int normalize,
                        struct kbox_web_ctx *web);

/* I/O chunk size for forwarding read/write through LKL. */
#define KBOX_IO_CHUNK_LEN (128 * 1024)

#endif /* KBOX_SECCOMP_H */
