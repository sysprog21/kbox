/* SPDX-License-Identifier: MIT */
#ifndef KBOX_SYSCALL_NR_H
#define KBOX_SYSCALL_NR_H

#include <stdbool.h>

/*
 * Architecture-specific LKL syscall number tables.
 *
 * One struct, two instances.  Replaces 120+ HOST_NR_* constants with
 * #[cfg] duplication from the Rust code.
 */
struct kbox_sysnrs {
    /* Navigation */
    long chdir, fchdir, getcwd;

    /* Execution */
    long execve, exit, wait4;

    /* Identity (uid/gid) */
    long getuid, geteuid, getresuid;
    long getgid, getegid, getresgid;
    long setuid, setreuid, setresuid;
    long setgid, setregid, setresgid;
    long getgroups, setgroups, setfsgid;

    /* Filesystem admin */
    long chroot, mknodat;
    long mkdir_no;      /* legacy mkdir or mkdirat depending on arch */
    bool mkdirat_style; /* true: mkdir_no uses AT_FDCWD form */
    long mount, umount2;

    /* File I/O */
    long openat, openat2, fcntl, socket, connect;
    long bind, sendto, recvfrom, sendmsg, recvmsg;
    long getsockopt, setsockopt, getsockname, getpeername, shutdown;

    /* FD manipulation */
    long dup, dup3, close;

    /* I/O */
    long read, write, pread64, pwrite64, lseek;
    long readv, writev;
    long readlinkat;

    /* Metadata */
    long fstat, newfstatat, faccessat2, statx;

    /* Directories */
    long getdents, getdents64;
    long mkdirat, unlinkat, renameat2;
    long fchmodat, fchownat;
    long symlinkat, linkat, utimensat;

    /* Memory mapping */
    long mmap, munmap;

    /* File manipulation */
    long ftruncate, fallocate, flock;
    long fsync, fdatasync, sync;
    long pipe2;
    long sendfile, copy_file_range;

    /* Process info */
    long umask;
    long uname;
    long getrandom;
    long prctl;
    long syslog;
};

extern const struct kbox_sysnrs SYSNRS_X86_64;
extern const struct kbox_sysnrs SYSNRS_GENERIC; /* aarch64 / generic */

#define AT_FDCWD_LINUX (-100L)

/*
 * Host-side syscall numbers for BPF filter construction.
 * Kept per-architecture.
 */
struct kbox_host_nrs {
    int openat, openat2, open;
    int stat, lstat, access;
    int rename, mkdir, rmdir, unlink;
    int chmod, chown;
    int fstat, newfstatat, statx, faccessat, faccessat2;
    int getdents64, getdents;
    int mkdirat, unlinkat, renameat, renameat2;
    int fchmodat, fchownat;
    int close;
    int sendmsg, socket, connect, bind, listen, accept, accept4;
    int sendto, recvfrom, recvmsg;
    int getsockopt, setsockopt, getsockname, getpeername, shutdown;
    int exit, exit_group;
    int fcntl, dup, dup2, dup3;
    int read, write, pread64, lseek;
    int chdir, fchdir, getcwd;
    int getuid, geteuid, getresuid;
    int getgid, getegid, getresgid;
    int setuid, setreuid, setresuid;
    int setgid, setregid, setresgid;
    int getgroups, setgroups, setfsgid;
    int mount, umount2;
    int execve, execveat;

    /* Process info */
    int getpid, getppid, gettid;
    int setpgid, getpgid, getsid, setsid;

    /* Time */
    int clock_gettime, clock_getres, gettimeofday;

    /* File operations */
    int readlinkat, pipe2, pipe;
    int sendfile, copy_file_range;
    int pwrite64, writev, readv;
    int ftruncate, fallocate, flock;
    int fsync, fdatasync, sync;
    int symlinkat, linkat, utimensat;
    int ioctl;

    /* Kernel info */
    int syslog;

    /* Process lifecycle */
    int umask, uname, brk, getrandom, prctl;
    int wait4, waitid;

    /* Signals */
    int rt_sigaction, rt_sigprocmask, rt_sigreturn;
    int rt_sigpending, rt_sigaltstack;
    int kill, tgkill, tkill;
    int pidfd_send_signal;
    int setitimer, getitimer, alarm;

    /* Threading */
    int set_tid_address, set_robust_list;
    int futex, clone3, arch_prctl, rseq;
    int clone, fork, vfork;

    /* Memory mapping */
    int mmap, munmap, mprotect, mremap;
    int membarrier;

    /* Scheduling */
    int sched_yield;
    int sched_setparam, sched_getparam;
    int sched_setscheduler, sched_getscheduler;
    int sched_get_priority_max, sched_get_priority_min;
    int sched_setaffinity, sched_getaffinity;

    /* Resource management */
    int prlimit64, madvise;
    int getrlimit, getrusage;

    /* I/O multiplexing */
    int epoll_create1, epoll_ctl, epoll_wait, epoll_pwait;
    int ppoll, pselect6;
    int poll;

    /* Timers and events */
    int nanosleep, clock_nanosleep;
    int timerfd_create, timerfd_settime, timerfd_gettime;
    int eventfd, eventfd2;

    /* Filesystem info */
    int statfs, fstatfs;
    int sysinfo;

    /* Readlink (dispatch, not CONTINUE) */
    int readlink;
};

extern const struct kbox_host_nrs HOST_NRS_X86_64;
extern const struct kbox_host_nrs HOST_NRS_AARCH64;

/* Detect which syscall ABI the booted LKL kernel uses. */
const struct kbox_sysnrs *detect_sysnrs(void);

/* Map host syscall number to name (for diagnostics). */
const char *syscall_name_from_nr(const struct kbox_host_nrs *h, int nr);

#endif /* KBOX_SYSCALL_NR_H */
