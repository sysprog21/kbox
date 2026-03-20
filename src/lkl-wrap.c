/* SPDX-License-Identifier: MIT */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysmacros.h>

#include "kbox/lkl-wrap.h"
#include "kbox/syscall-nr.h"

#define O_RDWR 02
#define O_CREAT 0100
#define O_CLOEXEC 02000000
#define S_IFCHR 0060000

long lkl_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
    long args[6] = {a1, a2, a3, a4, a5, a6};
    return lkl_syscall(nr, args);
}

const char *kbox_err_text(long code)
{
    return lkl_strerror((int) code);
}

int kbox_boot_kernel(const char *cmdline)
{
    const char *effective = cmdline;
    char buf[512];
    int ret;

    if (!cmdline || !*cmdline) {
        effective = "console=null";
    } else if (!strstr(cmdline, "console=")) {
        snprintf(buf, sizeof(buf), "%s console=null", cmdline);
        effective = buf;
    }

    ret = lkl_init(&lkl_host_ops);
    if (ret < 0) {
        fprintf(stderr, "lkl_init failed: %s (%d)\n", lkl_strerror(ret), ret);
        return -1;
    }

    ret = lkl_start_kernel("%s", effective);
    if (ret < 0) {
        fprintf(stderr, "lkl_start_kernel failed: %s (%d)\n", lkl_strerror(ret),
                ret);
        lkl_cleanup();
        return -1;
    }

    return 0;
}

void kbox_ensure_dev_console(const struct kbox_sysnrs *s)
{
    long r, fd;

    r = kbox_lkl_mkdir(s, "/dev", 0755);
    if (r < 0 && r != -17)
        fprintf(stderr, "exec preflight: mkdir /dev failed: %s (%ld)\n",
                lkl_strerror((int) r), r);

    fd = kbox_lkl_openat(s, AT_FDCWD_LINUX, "/dev/console", O_RDWR | O_CLOEXEC,
                         0);
    if (fd >= 0) {
        kbox_lkl_close(s, fd);
        fprintf(stderr, "exec preflight: /dev/console already present\n");
        return;
    }
    fprintf(stderr,
            "exec preflight: /dev/console open failed before mknod: "
            "%s (%ld)\n",
            lkl_strerror((int) fd), fd);

    r = kbox_lkl_mknodat(s, AT_FDCWD_LINUX, "/dev/console", S_IFCHR | 0600,
                         (long) makedev(5, 1));
    if (r < 0 && r != -17) {
        fprintf(stderr,
                "exec preflight: mknod /dev/console failed: "
                "%s (%ld)\n",
                lkl_strerror((int) r), r);
        return;
    }

    fd = kbox_lkl_openat(s, AT_FDCWD_LINUX, "/dev/console", O_RDWR | O_CLOEXEC,
                         0);
    if (fd >= 0) {
        kbox_lkl_close(s, fd);
        fprintf(stderr,
                "exec preflight: /dev/console open succeeded "
                "after mknod\n");
        return;
    }

    fprintf(stderr,
            "exec preflight: /dev/console open still failed: "
            "%s (%ld); trying regular-file emulation\n",
            lkl_strerror((int) fd), fd);

    kbox_lkl_unlinkat(s, AT_FDCWD_LINUX, "/dev/console", 0);
    fd = kbox_lkl_openat(s, AT_FDCWD_LINUX, "/dev/console",
                         O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd >= 0) {
        fprintf(stderr,
                "exec preflight: emulated /dev/console as "
                "regular file (fd=%ld)\n",
                fd);
        kbox_lkl_close(s, fd);
    } else {
        fprintf(stderr,
                "exec preflight: regular-file /dev/console "
                "emulation failed: %s (%ld)\n",
                lkl_strerror((int) fd), fd);
    }
}

/* --- Typed LKL syscall wrappers --- */

long kbox_lkl_mount(const struct kbox_sysnrs *s,
                    const char *src,
                    const char *target,
                    const char *fstype,
                    long flags,
                    const void *data)
{
    return lkl_syscall6(s->mount, (long) src, (long) target, (long) fstype,
                        flags, (long) data, 0);
}

long kbox_lkl_umount2(const struct kbox_sysnrs *s,
                      const char *target,
                      long flags)
{
    return lkl_syscall6(s->umount2, (long) target, flags, 0, 0, 0, 0);
}

long kbox_lkl_openat(const struct kbox_sysnrs *s,
                     long dirfd,
                     const char *path,
                     long flags,
                     long mode)
{
    return lkl_syscall6(s->openat, dirfd, (long) path, flags, mode, 0, 0);
}

long kbox_lkl_openat2(const struct kbox_sysnrs *s,
                      long dirfd,
                      const char *path,
                      const struct kbox_open_how *how,
                      long size)
{
    return lkl_syscall6(s->openat2, dirfd, (long) path, (long) how, size, 0, 0);
}

long kbox_lkl_close(const struct kbox_sysnrs *s, long fd)
{
    return lkl_syscall6(s->close, fd, 0, 0, 0, 0, 0);
}

long kbox_lkl_read(const struct kbox_sysnrs *s, long fd, void *buf, long len)
{
    return lkl_syscall6(s->read, fd, (long) buf, len, 0, 0, 0);
}

long kbox_lkl_write(const struct kbox_sysnrs *s,
                    long fd,
                    const void *buf,
                    long len)
{
    return lkl_syscall6(s->write, fd, (long) buf, len, 0, 0, 0);
}

long kbox_lkl_pread64(const struct kbox_sysnrs *s,
                      long fd,
                      void *buf,
                      long len,
                      long offset)
{
    return lkl_syscall6(s->pread64, fd, (long) buf, len, offset, 0, 0);
}

long kbox_lkl_lseek(const struct kbox_sysnrs *s,
                    long fd,
                    long offset,
                    long whence)
{
    return lkl_syscall6(s->lseek, fd, offset, whence, 0, 0, 0);
}

long kbox_lkl_fcntl(const struct kbox_sysnrs *s, long fd, long cmd, long arg)
{
    return lkl_syscall6(s->fcntl, fd, cmd, arg, 0, 0, 0);
}

long kbox_lkl_dup(const struct kbox_sysnrs *s, long fd)
{
    return lkl_syscall6(s->dup, fd, 0, 0, 0, 0, 0);
}

long kbox_lkl_dup3(const struct kbox_sysnrs *s,
                   long oldfd,
                   long newfd,
                   long flags)
{
    return lkl_syscall6(s->dup3, oldfd, newfd, flags, 0, 0, 0);
}

long kbox_lkl_fstat(const struct kbox_sysnrs *s, long fd, void *buf)
{
    return lkl_syscall6(s->fstat, fd, (long) buf, 0, 0, 0, 0);
}

long kbox_lkl_newfstatat(const struct kbox_sysnrs *s,
                         long dirfd,
                         const char *path,
                         void *buf,
                         long flags)
{
    return lkl_syscall6(s->newfstatat, dirfd, (long) path, (long) buf, flags, 0,
                        0);
}

long kbox_lkl_faccessat2(const struct kbox_sysnrs *s,
                         long dirfd,
                         const char *path,
                         long mode,
                         long flags)
{
    return lkl_syscall6(s->faccessat2, dirfd, (long) path, mode, flags, 0, 0);
}

long kbox_lkl_statx(const struct kbox_sysnrs *s,
                    long dirfd,
                    const char *path,
                    int flags,
                    unsigned mask,
                    void *buf)
{
    return lkl_syscall6(s->statx, dirfd, (long) path, (long) flags, (long) mask,
                        (long) buf, 0);
}

long kbox_lkl_getdents(const struct kbox_sysnrs *s,
                       long fd,
                       void *dirp,
                       long count)
{
    return lkl_syscall6(s->getdents, fd, (long) dirp, count, 0, 0, 0);
}

long kbox_lkl_getdents64(const struct kbox_sysnrs *s,
                         long fd,
                         void *dirp,
                         long count)
{
    return lkl_syscall6(s->getdents64, fd, (long) dirp, count, 0, 0, 0);
}

long kbox_lkl_mkdirat(const struct kbox_sysnrs *s,
                      long dirfd,
                      const char *path,
                      long mode)
{
    return lkl_syscall6(s->mkdirat, dirfd, (long) path, mode, 0, 0, 0);
}

long kbox_lkl_mkdir(const struct kbox_sysnrs *s, const char *path, int mode)
{
    if (s->mkdirat_style)
        return lkl_syscall6(s->mkdir_no, AT_FDCWD_LINUX, (long) path,
                            (long) mode, 0, 0, 0);
    return lkl_syscall6(s->mkdir_no, (long) path, (long) mode, 0, 0, 0, 0);
}

long kbox_lkl_unlinkat(const struct kbox_sysnrs *s,
                       long dirfd,
                       const char *path,
                       long flags)
{
    return lkl_syscall6(s->unlinkat, dirfd, (long) path, flags, 0, 0, 0);
}

long kbox_lkl_renameat2(const struct kbox_sysnrs *s,
                        long olddirfd,
                        const char *oldpath,
                        long newdirfd,
                        const char *newpath,
                        long flags)
{
    return lkl_syscall6(s->renameat2, olddirfd, (long) oldpath, newdirfd,
                        (long) newpath, flags, 0);
}

long kbox_lkl_fchmodat(const struct kbox_sysnrs *s,
                       long dirfd,
                       const char *path,
                       long mode,
                       long flags)
{
    return lkl_syscall6(s->fchmodat, dirfd, (long) path, mode, flags, 0, 0);
}

long kbox_lkl_fchownat(const struct kbox_sysnrs *s,
                       long dirfd,
                       const char *path,
                       long owner,
                       long group,
                       long flags)
{
    return lkl_syscall6(s->fchownat, dirfd, (long) path, owner, group, flags,
                        0);
}

long kbox_lkl_mknodat(const struct kbox_sysnrs *s,
                      long dirfd,
                      const char *path,
                      long mode,
                      long dev)
{
    return lkl_syscall6(s->mknodat, dirfd, (long) path, mode, dev, 0, 0);
}

long kbox_lkl_chroot(const struct kbox_sysnrs *s, const char *path)
{
    return lkl_syscall6(s->chroot, (long) path, 0, 0, 0, 0, 0);
}

long kbox_lkl_chdir(const struct kbox_sysnrs *s, const char *path)
{
    return lkl_syscall6(s->chdir, (long) path, 0, 0, 0, 0, 0);
}

long kbox_lkl_fchdir(const struct kbox_sysnrs *s, long fd)
{
    return lkl_syscall6(s->fchdir, fd, 0, 0, 0, 0, 0);
}

long kbox_lkl_getcwd(const struct kbox_sysnrs *s, char *buf, long size)
{
    return lkl_syscall6(s->getcwd, (long) buf, size, 0, 0, 0, 0);
}

long kbox_lkl_socket(const struct kbox_sysnrs *s,
                     long domain,
                     long type,
                     long protocol)
{
    return lkl_syscall6(s->socket, domain, type, protocol, 0, 0, 0);
}

long kbox_lkl_connect(const struct kbox_sysnrs *s,
                      long fd,
                      const void *addr,
                      long addrlen)
{
    return lkl_syscall6(s->connect, fd, (long) addr, addrlen, 0, 0, 0);
}

long kbox_lkl_execve(const struct kbox_sysnrs *s,
                     const char *path,
                     const char *const *argv,
                     const char *const *envp)
{
    return lkl_syscall6(s->execve, (long) path, (long) argv, (long) envp, 0, 0,
                        0);
}

long kbox_lkl_exit(const struct kbox_sysnrs *s, int status)
{
    return lkl_syscall6(s->exit, (long) status, 0, 0, 0, 0, 0);
}

long kbox_lkl_wait4(const struct kbox_sysnrs *s,
                    long pid,
                    int *wstatus,
                    long options,
                    void *rusage)
{
    return lkl_syscall6(s->wait4, pid, (long) wstatus, options, (long) rusage,
                        0, 0);
}

long kbox_lkl_getuid(const struct kbox_sysnrs *s)
{
    return lkl_syscall6(s->getuid, 0, 0, 0, 0, 0, 0);
}

long kbox_lkl_geteuid(const struct kbox_sysnrs *s)
{
    return lkl_syscall6(s->geteuid, 0, 0, 0, 0, 0, 0);
}

long kbox_lkl_getresuid(const struct kbox_sysnrs *s,
                        unsigned *ruid,
                        unsigned *euid,
                        unsigned *suid)
{
    return lkl_syscall6(s->getresuid, (long) ruid, (long) euid, (long) suid, 0,
                        0, 0);
}

long kbox_lkl_getgid(const struct kbox_sysnrs *s)
{
    return lkl_syscall6(s->getgid, 0, 0, 0, 0, 0, 0);
}

long kbox_lkl_getegid(const struct kbox_sysnrs *s)
{
    return lkl_syscall6(s->getegid, 0, 0, 0, 0, 0, 0);
}

long kbox_lkl_getresgid(const struct kbox_sysnrs *s,
                        unsigned *rgid,
                        unsigned *egid,
                        unsigned *sgid)
{
    return lkl_syscall6(s->getresgid, (long) rgid, (long) egid, (long) sgid, 0,
                        0, 0);
}

long kbox_lkl_setuid(const struct kbox_sysnrs *s, long uid)
{
    return lkl_syscall6(s->setuid, uid, 0, 0, 0, 0, 0);
}

long kbox_lkl_setreuid(const struct kbox_sysnrs *s, long ruid, long euid)
{
    return lkl_syscall6(s->setreuid, ruid, euid, 0, 0, 0, 0);
}

long kbox_lkl_setresuid(const struct kbox_sysnrs *s,
                        long ruid,
                        long euid,
                        long suid)
{
    return lkl_syscall6(s->setresuid, ruid, euid, suid, 0, 0, 0);
}

long kbox_lkl_setgid(const struct kbox_sysnrs *s, long gid)
{
    return lkl_syscall6(s->setgid, gid, 0, 0, 0, 0, 0);
}

long kbox_lkl_setregid(const struct kbox_sysnrs *s, long rgid, long egid)
{
    return lkl_syscall6(s->setregid, rgid, egid, 0, 0, 0, 0);
}

long kbox_lkl_setresgid(const struct kbox_sysnrs *s,
                        long rgid,
                        long egid,
                        long sgid)
{
    return lkl_syscall6(s->setresgid, rgid, egid, sgid, 0, 0, 0);
}

long kbox_lkl_getgroups(const struct kbox_sysnrs *s, long size, unsigned *list)
{
    return lkl_syscall6(s->getgroups, size, (long) list, 0, 0, 0, 0);
}

long kbox_lkl_setgroups(const struct kbox_sysnrs *s,
                        long size,
                        const unsigned *list)
{
    return lkl_syscall6(s->setgroups, size, (long) list, 0, 0, 0, 0);
}

long kbox_lkl_setfsgid(const struct kbox_sysnrs *s, long gid)
{
    return lkl_syscall6(s->setfsgid, gid, 0, 0, 0, 0, 0);
}

long kbox_lkl_mmap(const struct kbox_sysnrs *s,
                   long addr,
                   long len,
                   long prot,
                   long flags,
                   long fd,
                   long offset)
{
    return lkl_syscall6(s->mmap, addr, len, prot, flags, fd, offset);
}

long kbox_lkl_munmap(const struct kbox_sysnrs *s, long addr, long len)
{
    return lkl_syscall6(s->munmap, addr, len, 0, 0, 0, 0);
}

long kbox_lkl_pwrite64(const struct kbox_sysnrs *s,
                       long fd,
                       const void *buf,
                       long len,
                       long offset)
{
    return lkl_syscall6(s->pwrite64, fd, (long) buf, len, offset, 0, 0);
}

long kbox_lkl_readlinkat(const struct kbox_sysnrs *s,
                         long dirfd,
                         const char *path,
                         char *buf,
                         long bufsiz)
{
    return lkl_syscall6(s->readlinkat, dirfd, (long) path, (long) buf, bufsiz,
                        0, 0);
}

long kbox_lkl_pipe2(const struct kbox_sysnrs *s, int *pipefd, long flags)
{
    return lkl_syscall6(s->pipe2, (long) pipefd, flags, 0, 0, 0, 0);
}

long kbox_lkl_umask(const struct kbox_sysnrs *s, long mask)
{
    return lkl_syscall6(s->umask, mask, 0, 0, 0, 0, 0);
}

long kbox_lkl_ftruncate(const struct kbox_sysnrs *s, long fd, long length)
{
    return lkl_syscall6(s->ftruncate, fd, length, 0, 0, 0, 0);
}

long kbox_lkl_fallocate(const struct kbox_sysnrs *s,
                        long fd,
                        long mode,
                        long offset,
                        long len)
{
    return lkl_syscall6(s->fallocate, fd, mode, offset, len, 0, 0);
}

long kbox_lkl_flock(const struct kbox_sysnrs *s, long fd, long operation)
{
    return lkl_syscall6(s->flock, fd, operation, 0, 0, 0, 0);
}

long kbox_lkl_fsync(const struct kbox_sysnrs *s, long fd)
{
    return lkl_syscall6(s->fsync, fd, 0, 0, 0, 0, 0);
}

long kbox_lkl_fdatasync(const struct kbox_sysnrs *s, long fd)
{
    return lkl_syscall6(s->fdatasync, fd, 0, 0, 0, 0, 0);
}

long kbox_lkl_sync(const struct kbox_sysnrs *s)
{
    return lkl_syscall6(s->sync, 0, 0, 0, 0, 0, 0);
}

long kbox_lkl_symlinkat(const struct kbox_sysnrs *s,
                        const char *target,
                        long newdirfd,
                        const char *linkpath)
{
    return lkl_syscall6(s->symlinkat, (long) target, newdirfd, (long) linkpath,
                        0, 0, 0);
}

long kbox_lkl_linkat(const struct kbox_sysnrs *s,
                     long olddirfd,
                     const char *oldpath,
                     long newdirfd,
                     const char *newpath,
                     long flags)
{
    return lkl_syscall6(s->linkat, olddirfd, (long) oldpath, newdirfd,
                        (long) newpath, flags, 0);
}

long kbox_lkl_utimensat(const struct kbox_sysnrs *s,
                        long dirfd,
                        const char *path,
                        const void *times,
                        long flags)
{
    return lkl_syscall6(s->utimensat, dirfd, (long) path, (long) times, flags,
                        0, 0);
}

/* --- Socket wrappers --- */

long kbox_lkl_bind(const struct kbox_sysnrs *s,
                   long fd,
                   const void *addr,
                   long addrlen)
{
    return lkl_syscall6(s->bind, fd, (long) addr, addrlen, 0, 0, 0);
}

long kbox_lkl_getsockopt(const struct kbox_sysnrs *s,
                         long fd,
                         long level,
                         long optname,
                         void *optval,
                         void *optlen)
{
    return lkl_syscall6(s->getsockopt, fd, level, optname, (long) optval,
                        (long) optlen, 0);
}

long kbox_lkl_setsockopt(const struct kbox_sysnrs *s,
                         long fd,
                         long level,
                         long optname,
                         const void *optval,
                         long optlen)
{
    return lkl_syscall6(s->setsockopt, fd, level, optname, (long) optval,
                        optlen, 0);
}

long kbox_lkl_getsockname(const struct kbox_sysnrs *s,
                          long fd,
                          void *addr,
                          void *addrlen)
{
    return lkl_syscall6(s->getsockname, fd, (long) addr, (long) addrlen, 0, 0,
                        0);
}

long kbox_lkl_getpeername(const struct kbox_sysnrs *s,
                          long fd,
                          void *addr,
                          void *addrlen)
{
    return lkl_syscall6(s->getpeername, fd, (long) addr, (long) addrlen, 0, 0,
                        0);
}

long kbox_lkl_shutdown(const struct kbox_sysnrs *s, long fd, long how)
{
    return lkl_syscall6(s->shutdown, fd, how, 0, 0, 0, 0);
}

long kbox_lkl_sendto(const struct kbox_sysnrs *s,
                     long fd,
                     const void *buf,
                     long len,
                     long flags,
                     const void *addr,
                     long addrlen)
{
    return lkl_syscall6(s->sendto, fd, (long) buf, len, flags, (long) addr,
                        addrlen);
}

long kbox_lkl_recvfrom(const struct kbox_sysnrs *s,
                       long fd,
                       void *buf,
                       long len,
                       long flags,
                       void *addr,
                       void *addrlen)
{
    return lkl_syscall6(s->recvfrom, fd, (long) buf, len, flags, (long) addr,
                        (long) addrlen);
}
