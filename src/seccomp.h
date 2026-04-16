/* SPDX-License-Identifier: MIT */
#ifndef KBOX_SECCOMP_H
#define KBOX_SECCOMP_H

#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "fd-table.h"
#include "kbox/path.h"
#include "procmem.h"
#include "seccomp-defs.h"
#include "syscall-nr.h"
#include "syscall-trap-signal.h"

struct kbox_dispatch {
    enum {
        KBOX_DISPATCH_CONTINUE,
        KBOX_DISPATCH_RETURN,
    } kind;
    int64_t val;
    int error;
};

struct kbox_web_ctx;
struct kbox_fd_inject_ops;

#define KBOX_PATH_SHADOW_CACHE_MAX 8
#define KBOX_TRANSLATED_PATH_CACHE_MAX 8
#define KBOX_LITERAL_PATH_CACHE_MAX 8

struct kbox_path_shadow_cache_entry {
    int valid;
    int memfd;
    char path[KBOX_MAX_PATH];
    struct stat host_stat;
};

struct kbox_translated_path_cache_entry {
    int valid;
    unsigned generation;
    char guest_path[KBOX_MAX_PATH];
    char translated[KBOX_MAX_PATH];
};

struct kbox_literal_path_cache_entry {
    int valid;
    unsigned generation;
    pid_t pid;
    uint64_t guest_addr;
    char translated[KBOX_MAX_PATH];
};

enum kbox_syscall_source {
    KBOX_SYSCALL_SOURCE_SECCOMP = 0,
    KBOX_SYSCALL_SOURCE_TRAP,
    KBOX_SYSCALL_SOURCE_REWRITE,
};

struct kbox_syscall_regs {
    int nr;
    uint64_t instruction_pointer;
    uint64_t args[6];
};

struct kbox_syscall_request {
    enum kbox_syscall_source source;
    pid_t pid;
    uint64_t cookie;
    int nr;
    uint64_t instruction_pointer;
    uint64_t args[6];
    struct kbox_guest_mem guest_mem;
};

static inline pid_t kbox_syscall_request_pid(
    const struct kbox_syscall_request *req)
{
    return req->pid;
}

static inline uint64_t kbox_syscall_request_cookie(
    const struct kbox_syscall_request *req)
{
    return req->cookie;
}

static inline uint64_t kbox_syscall_request_arg(
    const struct kbox_syscall_request *req,
    size_t idx)
{
    return idx < 6 ? req->args[idx] : 0;
}

struct kbox_supervisor_ctx {
    const struct kbox_sysnrs *sysnrs;
    const struct kbox_host_nrs *host_nrs;
    struct kbox_fd_table *fd_table;
    int listener_fd;
    int proc_self_fd_dirfd;
    int proc_mem_fd;
    int inherited_fds_tracked;
    pid_t child_pid;
    const char *host_root;
    int verbose;
    int root_identity;
    uid_t override_uid;
    gid_t override_gid;
    int normalize;
    const struct kbox_guest_mem_ops *guest_mem_ops;
    struct kbox_guest_mem active_guest_mem;
    const struct kbox_fd_inject_ops *fd_inject_ops;
    struct kbox_web_ctx *web;
    unsigned active_writeback_shadows;
    unsigned path_translation_generation;
    struct kbox_path_shadow_cache_entry
        path_shadow_cache[KBOX_PATH_SHADOW_CACHE_MAX];
    struct kbox_translated_path_cache_entry
        translated_path_cache[KBOX_TRANSLATED_PATH_CACHE_MAX];
    struct kbox_literal_path_cache_entry
        literal_path_cache[KBOX_LITERAL_PATH_CACHE_MAX];

    /* LRU stat cache: avoids repeated LKL inode lookups for fstat on the
     * same FD.  Keyed by lkl_fd.  Invalidated on write/truncate/close.
     */
#ifdef KBOX_STAT_CACHE_SIZE
#define KBOX_STAT_CACHE_MAX KBOX_STAT_CACHE_SIZE
#else
#define KBOX_STAT_CACHE_MAX 16
#endif
#if KBOX_STAT_CACHE_MAX > 0
#define KBOX_STAT_CACHE_ENABLED 1
#define KBOX_STAT_CACHE_STORAGE_MAX KBOX_STAT_CACHE_MAX
#else
#define KBOX_STAT_CACHE_ENABLED 0
#define KBOX_STAT_CACHE_STORAGE_MAX 1
#endif
    struct {
        long lkl_fd; /* -1 = empty slot */
        struct stat st;
    } stat_cache[KBOX_STAT_CACHE_STORAGE_MAX];
};

int kbox_install_seccomp_listener(const struct kbox_host_nrs *h);
int kbox_install_seccomp_trap(const struct kbox_host_nrs *h);
int kbox_install_seccomp_trap_ranges(
    const struct kbox_host_nrs *h,
    const struct kbox_syscall_trap_ip_range *trap_ranges,
    size_t trap_range_count);
int kbox_install_seccomp_rewrite_ranges(
    const struct kbox_host_nrs *h,
    const struct kbox_syscall_trap_ip_range *trap_ranges,
    size_t trap_range_count);
int kbox_notify_recv(int listener_fd, void *notif);
int kbox_notify_send(int listener_fd, const void *resp);
int kbox_notify_addfd(int listener_fd,
                      uint64_t id,
                      int srcfd,
                      uint32_t newfd_flags);
int kbox_notify_addfd_at(int listener_fd,
                         uint64_t id,
                         int srcfd,
                         int target_fd,
                         uint32_t newfd_flags);
int kbox_syscall_request_init_from_regs(struct kbox_syscall_request *out,
                                        enum kbox_syscall_source source,
                                        pid_t pid,
                                        uint64_t cookie,
                                        const struct kbox_syscall_regs *regs,
                                        const struct kbox_guest_mem *guest_mem);
void kbox_dispatch_prepare_request_ctx(struct kbox_supervisor_ctx *ctx,
                                       const struct kbox_syscall_request *req);
struct kbox_dispatch kbox_dispatch_syscall(struct kbox_supervisor_ctx *ctx,
                                           const void *notif);
int kbox_syscall_request_from_notif(const void *notif,
                                    struct kbox_syscall_request *out);
struct kbox_dispatch kbox_dispatch_request(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req);
int kbox_dispatch_try_local_fast_path(const struct kbox_host_nrs *h,
                                      int nr,
                                      struct kbox_dispatch *out);
struct kbox_dispatch kbox_dispatch_continue(void);
struct kbox_dispatch kbox_dispatch_errno(int err);
struct kbox_dispatch kbox_dispatch_value(int64_t val);
struct kbox_dispatch kbox_dispatch_from_lkl(long ret);
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

#define KBOX_IO_CHUNK_LEN (128 * 1024)

#endif /* KBOX_SECCOMP_H */
