/* SPDX-License-Identifier: MIT */
#ifndef KBOX_LKL_WRAP_H
#define KBOX_LKL_WRAP_H

#include <stddef.h>
#include <stdint.h>

#include "kbox/syscall-nr.h"

/*
 * LKL disk descriptor.  This must match the prefix of LKL's struct lkl_disk
 * (defined in tools/lkl/include/lkl.h).  We declare it here rather than
 * including the full LKL header tree.
 *
 * WARNING: if upstream LKL reorders or adds fields before 'ops', kbox will
 * silently corrupt the struct.  The CI build-lkl workflow verifies symbol
 * presence but cannot detect layout changes.  When upgrading the pinned LKL
 * commit, manually verify this struct matches upstream.
 */
struct lkl_disk {
    void *dev;
    int fd;
    void *ops;
};

/*
 * LKL FFI declarations.
 * These come from liblkl.a; we declare them here rather than
 * including the full LKL header tree.
 */
extern unsigned char lkl_host_ops;
extern void lkl_dev_blk_ops;

int lkl_init(void *ops);
int lkl_start_kernel(const char *fmt, ...);
void lkl_cleanup(void);

const char *lkl_strerror(int err);
long lkl_syscall(long no, const long *params);

int lkl_disk_add(struct lkl_disk *disk);
long lkl_mount_dev(unsigned disk_id,
                   unsigned part,
                   const char *fs_type,
                   int flags,
                   const char *opts,
                   char *mnt_str,
                   unsigned mnt_str_len);

/*
 * Convenience wrappers.
 */

/* Generic 6-argument LKL syscall. */
long lkl_syscall6(long nr,
                  long a1,
                  long a2,
                  long a3,
                  long a4,
                  long a5,
                  long a6);

/* Human-readable error text for an LKL return code. */
const char *kbox_err_text(long code);

/* Boot the LKL kernel with the given command line. Returns 0 or -1. */
int kbox_boot_kernel(const char *cmdline);

/* Ensure /dev/console exists inside LKL. */
void kbox_ensure_dev_console(const struct kbox_sysnrs *s);

/*
 * Typed LKL syscall wrappers (thin, inline-friendly).
 */
long kbox_lkl_mount(const struct kbox_sysnrs *s,
                    const char *src,
                    const char *target,
                    const char *fstype,
                    long flags,
                    const void *data);
long kbox_lkl_umount2(const struct kbox_sysnrs *s,
                      const char *target,
                      long flags);
long kbox_lkl_openat(const struct kbox_sysnrs *s,
                     long dirfd,
                     const char *path,
                     long flags,
                     long mode);
long kbox_lkl_close(const struct kbox_sysnrs *s, long fd);
long kbox_lkl_read(const struct kbox_sysnrs *s, long fd, void *buf, long len);
long kbox_lkl_write(const struct kbox_sysnrs *s,
                    long fd,
                    const void *buf,
                    long len);
long kbox_lkl_pread64(const struct kbox_sysnrs *s,
                      long fd,
                      void *buf,
                      long len,
                      long offset);
long kbox_lkl_lseek(const struct kbox_sysnrs *s,
                    long fd,
                    long offset,
                    long whence);
long kbox_lkl_fcntl(const struct kbox_sysnrs *s, long fd, long cmd, long arg);
long kbox_lkl_dup(const struct kbox_sysnrs *s, long fd);
long kbox_lkl_dup3(const struct kbox_sysnrs *s,
                   long oldfd,
                   long newfd,
                   long flags);
long kbox_lkl_fstat(const struct kbox_sysnrs *s, long fd, void *buf);
long kbox_lkl_newfstatat(const struct kbox_sysnrs *s,
                         long dirfd,
                         const char *path,
                         void *buf,
                         long flags);
long kbox_lkl_faccessat2(const struct kbox_sysnrs *s,
                         long dirfd,
                         const char *path,
                         long mode,
                         long flags);
long kbox_lkl_statx(const struct kbox_sysnrs *s,
                    long dirfd,
                    const char *path,
                    int flags,
                    unsigned mask,
                    void *buf);
long kbox_lkl_getdents(const struct kbox_sysnrs *s,
                       long fd,
                       void *dirp,
                       long count);
long kbox_lkl_getdents64(const struct kbox_sysnrs *s,
                         long fd,
                         void *dirp,
                         long count);
long kbox_lkl_mkdirat(const struct kbox_sysnrs *s,
                      long dirfd,
                      const char *path,
                      long mode);
long kbox_lkl_mkdir(const struct kbox_sysnrs *s, const char *path, int mode);
long kbox_lkl_unlinkat(const struct kbox_sysnrs *s,
                       long dirfd,
                       const char *path,
                       long flags);
long kbox_lkl_renameat2(const struct kbox_sysnrs *s,
                        long olddirfd,
                        const char *oldpath,
                        long newdirfd,
                        const char *newpath,
                        long flags);
long kbox_lkl_fchmodat(const struct kbox_sysnrs *s,
                       long dirfd,
                       const char *path,
                       long mode,
                       long flags);
long kbox_lkl_fchownat(const struct kbox_sysnrs *s,
                       long dirfd,
                       const char *path,
                       long owner,
                       long group,
                       long flags);
long kbox_lkl_mknodat(const struct kbox_sysnrs *s,
                      long dirfd,
                      const char *path,
                      long mode,
                      long dev);
long kbox_lkl_chroot(const struct kbox_sysnrs *s, const char *path);
long kbox_lkl_chdir(const struct kbox_sysnrs *s, const char *path);
long kbox_lkl_fchdir(const struct kbox_sysnrs *s, long fd);
long kbox_lkl_getcwd(const struct kbox_sysnrs *s, char *buf, long size);
long kbox_lkl_socket(const struct kbox_sysnrs *s,
                     long domain,
                     long type,
                     long protocol);
long kbox_lkl_connect(const struct kbox_sysnrs *s,
                      long fd,
                      const void *addr,
                      long addrlen);
long kbox_lkl_execve(const struct kbox_sysnrs *s,
                     const char *path,
                     const char *const *argv,
                     const char *const *envp);
long kbox_lkl_exit(const struct kbox_sysnrs *s, int status);
long kbox_lkl_wait4(const struct kbox_sysnrs *s,
                    long pid,
                    int *wstatus,
                    long options,
                    void *rusage);
long kbox_lkl_getuid(const struct kbox_sysnrs *s);
long kbox_lkl_geteuid(const struct kbox_sysnrs *s);
long kbox_lkl_getresuid(const struct kbox_sysnrs *s,
                        unsigned *ruid,
                        unsigned *euid,
                        unsigned *suid);
long kbox_lkl_getgid(const struct kbox_sysnrs *s);
long kbox_lkl_getegid(const struct kbox_sysnrs *s);
long kbox_lkl_getresgid(const struct kbox_sysnrs *s,
                        unsigned *rgid,
                        unsigned *egid,
                        unsigned *sgid);
long kbox_lkl_setuid(const struct kbox_sysnrs *s, long uid);
long kbox_lkl_setreuid(const struct kbox_sysnrs *s, long ruid, long euid);
long kbox_lkl_setresuid(const struct kbox_sysnrs *s,
                        long ruid,
                        long euid,
                        long suid);
long kbox_lkl_setgid(const struct kbox_sysnrs *s, long gid);
long kbox_lkl_setregid(const struct kbox_sysnrs *s, long rgid, long egid);
long kbox_lkl_setresgid(const struct kbox_sysnrs *s,
                        long rgid,
                        long egid,
                        long sgid);
long kbox_lkl_getgroups(const struct kbox_sysnrs *s, long size, unsigned *list);
long kbox_lkl_setgroups(const struct kbox_sysnrs *s,
                        long size,
                        const unsigned *list);
long kbox_lkl_setfsgid(const struct kbox_sysnrs *s, long gid);
long kbox_lkl_mmap(const struct kbox_sysnrs *s,
                   long addr,
                   long len,
                   long prot,
                   long flags,
                   long fd,
                   long offset);
long kbox_lkl_munmap(const struct kbox_sysnrs *s, long addr, long len);

/*
 * LKL always uses the generic-arch (asm-generic) struct stat layout,
 * which differs from x86_64.  In particular:
 *   - generic: st_mode at offset 16 (uint32), st_nlink at offset 20
 *   - x86_64:  st_nlink at offset 16 (uint64), st_mode at offset 24
 *
 * Using the host struct stat with kbox_lkl_fstat produces garbage
 * because LKL fills the buffer in generic layout but the host reads
 * it as x86_64 layout.  Use this struct instead.
 */
struct kbox_lkl_stat {
    uint64_t st_dev;        /* 0 */
    uint64_t st_ino;        /* 8 */
    uint32_t st_mode;       /* 16 */
    uint32_t st_nlink;      /* 20 */
    uint32_t st_uid;        /* 24 */
    uint32_t st_gid;        /* 28 */
    uint64_t st_rdev;       /* 32 */
    uint64_t __pad1;        /* 40 */
    int64_t st_size;        /* 48 */
    int32_t st_blksize;     /* 56 */
    int32_t __pad2;         /* 60 */
    int64_t st_blocks;      /* 64 */
    int64_t st_atime_sec;   /* 72 */
    uint64_t st_atime_nsec; /* 80 */
    int64_t st_mtime_sec;   /* 88 */
    uint64_t st_mtime_nsec; /* 96 */
    int64_t st_ctime_sec;   /* 104 */
    uint64_t st_ctime_nsec; /* 112 */
    uint32_t __unused4;     /* 120 */
    uint32_t __unused5;     /* 124 */
};
/* Total: 128 bytes, matching sizeof(struct stat) in asm-generic. */
_Static_assert(sizeof(struct kbox_lkl_stat) == 128,
               "kbox_lkl_stat must be 128 bytes (asm-generic ABI)");
_Static_assert(offsetof(struct kbox_lkl_stat, st_mode) == 16,
               "st_mode must be at offset 16 (asm-generic ABI)");
_Static_assert(offsetof(struct kbox_lkl_stat, st_size) == 48,
               "st_size must be at offset 48 (asm-generic ABI)");

/*
 * openat2 support structure.
 */
struct kbox_open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};
_Static_assert(sizeof(struct kbox_open_how) == 24,
               "kbox_open_how must be 24 bytes (openat2 ABI)");

long kbox_lkl_openat2(const struct kbox_sysnrs *s,
                      long dirfd,
                      const char *path,
                      const struct kbox_open_how *how,
                      long size);

long kbox_lkl_pwrite64(const struct kbox_sysnrs *s,
                       long fd,
                       const void *buf,
                       long len,
                       long offset);
long kbox_lkl_readlinkat(const struct kbox_sysnrs *s,
                         long dirfd,
                         const char *path,
                         char *buf,
                         long bufsiz);
long kbox_lkl_pipe2(const struct kbox_sysnrs *s, int *pipefd, long flags);
long kbox_lkl_umask(const struct kbox_sysnrs *s, long mask);
long kbox_lkl_ftruncate(const struct kbox_sysnrs *s, long fd, long length);
long kbox_lkl_fallocate(const struct kbox_sysnrs *s,
                        long fd,
                        long mode,
                        long offset,
                        long len);
long kbox_lkl_flock(const struct kbox_sysnrs *s, long fd, long operation);
long kbox_lkl_fsync(const struct kbox_sysnrs *s, long fd);
long kbox_lkl_fdatasync(const struct kbox_sysnrs *s, long fd);
long kbox_lkl_sync(const struct kbox_sysnrs *s);
long kbox_lkl_symlinkat(const struct kbox_sysnrs *s,
                        const char *target,
                        long newdirfd,
                        const char *linkpath);
long kbox_lkl_linkat(const struct kbox_sysnrs *s,
                     long olddirfd,
                     const char *oldpath,
                     long newdirfd,
                     const char *newpath,
                     long flags);
long kbox_lkl_utimensat(const struct kbox_sysnrs *s,
                        long dirfd,
                        const char *path,
                        const void *times,
                        long flags);

/* --- Socket wrappers --- */

long kbox_lkl_bind(const struct kbox_sysnrs *s,
                   long fd,
                   const void *addr,
                   long addrlen);
long kbox_lkl_getsockopt(const struct kbox_sysnrs *s,
                         long fd,
                         long level,
                         long optname,
                         void *optval,
                         void *optlen);
long kbox_lkl_setsockopt(const struct kbox_sysnrs *s,
                         long fd,
                         long level,
                         long optname,
                         const void *optval,
                         long optlen);
long kbox_lkl_getsockname(const struct kbox_sysnrs *s,
                          long fd,
                          void *addr,
                          void *addrlen);
long kbox_lkl_getpeername(const struct kbox_sysnrs *s,
                          long fd,
                          void *addr,
                          void *addrlen);
long kbox_lkl_shutdown(const struct kbox_sysnrs *s, long fd, long how);
long kbox_lkl_sendto(const struct kbox_sysnrs *s,
                     long fd,
                     const void *buf,
                     long len,
                     long flags,
                     const void *addr,
                     long addrlen);
long kbox_lkl_recvfrom(const struct kbox_sysnrs *s,
                       long fd,
                       void *buf,
                       long len,
                       long flags,
                       void *addr,
                       void *addrlen);

/* Forward declarations for netdev ops. */
struct iovec;
struct lkl_netdev;

/* --- LKL network device FFI --- */

/*
 * LKL virtio-net device operations.  Must match LKL's struct lkl_dev_net_ops
 * in tools/lkl/include/lkl_host.h.  We declare a compatible struct rather
 * than pulling in the full LKL headers.
 *
 * iov-based TX/RX: each callback receives a scatter/gather array.
 * poll: returns a bitmask of LKL_DEV_NET_POLL_{RX,TX,HUP}.
 * poll_hup: wakes the poll callback (e.g. write a byte to a wakeup pipe).
 * free: cleanup on device removal.
 */
struct lkl_dev_net_ops {
    int (*tx)(struct lkl_netdev *nd, struct iovec *iov, int cnt);
    int (*rx)(struct lkl_netdev *nd, struct iovec *iov, int cnt);
    int (*poll)(struct lkl_netdev *nd);
    void (*poll_hup)(struct lkl_netdev *nd);
    void (*free)(struct lkl_netdev *nd);
};

struct lkl_netdev {
    struct lkl_dev_net_ops *ops;
    int id;
    int has_vnet_hdr;
    unsigned char mac[6];
};

struct lkl_netdev_args {
    unsigned char mac[6];
    unsigned offload;
};

#define LKL_DEV_NET_POLL_RX 1
#define LKL_DEV_NET_POLL_TX 2
#define LKL_DEV_NET_POLL_HUP 4

extern int lkl_netdev_add(struct lkl_netdev *nd, struct lkl_netdev_args *args);
extern int lkl_netdev_get_ifindex(int id);
extern int lkl_if_up(int ifindex);
extern int lkl_if_set_ipv4(int ifindex,
                           unsigned int addr,
                           unsigned int netmask_len);
extern int lkl_set_ipv4_gateway(unsigned int addr);
extern int lkl_if_add_linklocal(int ifindex,
                                int af,
                                void *addr,
                                int netprefix_len);
extern int lkl_if_add_gateway(int ifindex, int af, void *gwaddr);
extern int lkl_if_set_ipv4_gateway(int ifindex,
                                   unsigned int src_addr,
                                   unsigned int src_masklen,
                                   unsigned int via_addr);

#endif /* KBOX_LKL_WRAP_H */
