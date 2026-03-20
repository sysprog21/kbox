/* SPDX-License-Identifier: MIT */
#include <stdio.h>

#include "kbox/syscall-nr.h"

/* Forward declaration -- implemented in lkl-wrap.c */
long lkl_syscall6(long nr,
                  long a1,
                  long a2,
                  long a3,
                  long a4,
                  long a5,
                  long a6);

const struct kbox_sysnrs SYSNRS_X86_64 = {
    .chdir = 80,
    .fchdir = 81,
    .getcwd = 79,
    .execve = 59,
    .exit = 60,
    .wait4 = 61,
    .getuid = 102,
    .geteuid = 107,
    .getresuid = 118,
    .getgid = 104,
    .getegid = 108,
    .getresgid = 120,
    .setuid = 105,
    .setreuid = 113,
    .setresuid = 117,
    .setgid = 106,
    .setregid = 114,
    .setresgid = 119,
    .getgroups = 115,
    .setgroups = 116,
    .setfsgid = 123,
    .chroot = 161,
    .mknodat = 259,
    .mkdir_no = 83,
    .mkdirat_style = false,
    .mount = 165,
    .umount2 = 166,
    .openat = 257,
    .openat2 = 437,
    .fcntl = 72,
    .socket = 41,
    .connect = 42,
    .bind = 49,
    .sendto = 44,
    .recvfrom = 45,
    .sendmsg = 46,
    .recvmsg = 47,
    .getsockopt = 55,
    .setsockopt = 54,
    .getsockname = 51,
    .getpeername = 52,
    .shutdown = 48,
    .dup = 32,
    .dup3 = 292,
    .close = 3,
    .read = 0,
    .write = 1,
    .pread64 = 17,
    .pwrite64 = 18,
    .lseek = 8,
    .readv = 19,
    .writev = 20,
    .readlinkat = 267,
    .fstat = 5,
    .newfstatat = 262,
    .faccessat2 = 439,
    .statx = 332,
    .getdents = 78,
    .getdents64 = 217,
    .mkdirat = 258,
    .unlinkat = 263,
    .renameat2 = 316,
    .fchmodat = 268,
    .fchownat = 260,
    .symlinkat = 266,
    .linkat = 265,
    .utimensat = 280,
    .mmap = 9,
    .munmap = 11,
    .ftruncate = 77,
    .fallocate = 285,
    .flock = 73,
    .fsync = 74,
    .fdatasync = 75,
    .sync = 162,
    .pipe2 = 293,
    .sendfile = 40,
    .copy_file_range = 326,
    .umask = 95,
    .uname = 63,
    .getrandom = 318,
    .prctl = 157,
    .syslog = 116,
};

const struct kbox_sysnrs SYSNRS_GENERIC = {
    .chdir = 49,
    .fchdir = 50,
    .getcwd = 17,
    .execve = 221,
    .exit = 93,
    .wait4 = 260,
    .getuid = 174,
    .geteuid = 175,
    .getresuid = 148,
    .getgid = 176,
    .getegid = 177,
    .getresgid = 150,
    .setuid = 146,
    .setreuid = 145,
    .setresuid = 147,
    .setgid = 144,
    .setregid = 143,
    .setresgid = 149,
    .getgroups = 158,
    .setgroups = 159,
    .setfsgid = 152,
    .chroot = 51,
    .mknodat = 33,
    .mkdir_no = 34,
    .mkdirat_style = true,
    .mount = 40,
    .umount2 = 39,
    .openat = 56,
    .openat2 = 437,
    .fcntl = 25,
    .socket = 198,
    .connect = 203,
    .bind = 200,
    .sendto = 206,
    .recvfrom = 207,
    .sendmsg = 211,
    .recvmsg = 212,
    .getsockopt = 209,
    .setsockopt = 208,
    .getsockname = 204,
    .getpeername = 205,
    .shutdown = 210,
    .dup = 23,
    .dup3 = 24,
    .close = 57,
    .read = 63,
    .write = 64,
    .pread64 = 67,
    .pwrite64 = 68,
    .lseek = 62,
    .readv = 65,
    .writev = 66,
    .readlinkat = 78,
    .fstat = 80,
    .newfstatat = 79,
    .faccessat2 = 439,
    .statx = 291,
    .getdents = -1,
    .getdents64 = 61,
    .mkdirat = 34,
    .unlinkat = 35,
    .renameat2 = 276,
    .fchmodat = 53,
    .fchownat = 54,
    .symlinkat = 36,
    .linkat = 37,
    .utimensat = 88,
    .mmap = 222,
    .munmap = 215,
    .ftruncate = 46,
    .fallocate = 47,
    .flock = 32,
    .fsync = 82,
    .fdatasync = 83,
    .sync = 81,
    .pipe2 = 59,
    .sendfile = 71,
    .copy_file_range = 285,
    .umask = 166,
    .uname = 160,
    .getrandom = 278,
    .prctl = 167,
    .syslog = 116,
};

const struct kbox_host_nrs HOST_NRS_X86_64 = {
    .openat = 257,
    .openat2 = 437,
    .open = 2,
    .stat = 4,
    .lstat = 6,
    .access = 21,
    .rename = 82,
    .mkdir = 83,
    .rmdir = 84,
    .unlink = 87,
    .chmod = 90,
    .chown = 92,
    .fstat = 5,
    .newfstatat = 262,
    .statx = 332,
    .faccessat = 269,
    .faccessat2 = 439,
    .getdents64 = 217,
    .getdents = 78,
    .mkdirat = 258,
    .unlinkat = 263,
    .renameat = 264,
    .renameat2 = 316,
    .fchmodat = 268,
    .fchownat = 260,
    .close = 3,
    .sendmsg = 46,
    .socket = 41,
    .connect = 42,
    .bind = 49,
    .listen = 50,
    .accept = 43,
    .accept4 = 288,
    .sendto = 44,
    .recvfrom = 45,
    .recvmsg = 47,
    .getsockopt = 55,
    .setsockopt = 54,
    .getsockname = 51,
    .getpeername = 52,
    .shutdown = 48,
    .exit = 60,
    .exit_group = 231,
    .fcntl = 72,
    .dup = 32,
    .dup2 = 33,
    .dup3 = 292,
    .read = 0,
    .write = 1,
    .pread64 = 17,
    .lseek = 8,
    .chdir = 80,
    .fchdir = 81,
    .getcwd = 79,
    .getuid = 102,
    .geteuid = 107,
    .getresuid = 118,
    .getgid = 104,
    .getegid = 108,
    .getresgid = 120,
    .setuid = 105,
    .setreuid = 113,
    .setresuid = 117,
    .setgid = 106,
    .setregid = 114,
    .setresgid = 119,
    .getgroups = 115,
    .setgroups = 116,
    .setfsgid = 123,
    .mount = 165,
    .umount2 = 166,
    .execve = 59,
    .execveat = 322,
    .getpid = 39,
    .getppid = 110,
    .gettid = 186,
    .setpgid = 109,
    .getpgid = 121,
    .getsid = 124,
    .setsid = 112,
    .clock_gettime = 228,
    .clock_getres = 229,
    .gettimeofday = 96,
    .readlinkat = 267,
    .pipe2 = 293,
    .pipe = 22,
    .sendfile = 40,
    .copy_file_range = 326,
    .pwrite64 = 18,
    .writev = 20,
    .readv = 19,
    .ftruncate = 77,
    .fallocate = 285,
    .flock = 73,
    .fsync = 74,
    .fdatasync = 75,
    .sync = 162,
    .symlinkat = 266,
    .linkat = 265,
    .utimensat = 280,
    .ioctl = 16,
    .syslog = 103,
    .umask = 95,
    .uname = 63,
    .brk = 12,
    .getrandom = 318,
    .prctl = 157,
    .wait4 = 61,
    .waitid = 247,
    .rt_sigaction = 13,
    .rt_sigprocmask = 14,
    .rt_sigreturn = 15,
    .rt_sigpending = 127,
    .rt_sigaltstack = 131,
    .kill = 62,
    .tgkill = 234,
    .tkill = 200,
    .pidfd_send_signal = 424,
    .setitimer = 38,
    .getitimer = 36,
    .alarm = 37,
    .set_tid_address = 218,
    .set_robust_list = 273,
    .futex = 202,
    .clone3 = 435,
    .arch_prctl = 158,
    .rseq = 334,
    .clone = 56,
    .fork = 57,
    .vfork = 58,
    .mmap = 9,
    .munmap = 11,
    .mprotect = 10,
    .mremap = 25,
    .membarrier = 324,
    .sched_yield = 24,
    .sched_setparam = 142,
    .sched_getparam = 143,
    .sched_setscheduler = 144,
    .sched_getscheduler = 145,
    .sched_get_priority_max = 146,
    .sched_get_priority_min = 147,
    .sched_setaffinity = 203,
    .sched_getaffinity = 204,
    .prlimit64 = 302,
    .madvise = 28,
    .getrlimit = 97,
    .getrusage = 98,
    .epoll_create1 = 291,
    .epoll_ctl = 233,
    .epoll_wait = 232,
    .epoll_pwait = 281,
    .ppoll = 271,
    .pselect6 = 270,
    .poll = 7,
    .nanosleep = 35,
    .clock_nanosleep = 230,
    .timerfd_create = 283,
    .timerfd_settime = 286,
    .timerfd_gettime = 287,
    .eventfd = 284,
    .eventfd2 = 290,
    .statfs = 137,
    .fstatfs = 138,
    .sysinfo = 99,
    .readlink = 89,
};

const struct kbox_host_nrs HOST_NRS_AARCH64 = {
    .openat = 56,
    .openat2 = 437,
    .open = -1,
    .stat = -1,
    .lstat = -1,
    .access = -1,
    .rename = -1,
    .mkdir = -1,
    .rmdir = -1,
    .unlink = -1,
    .chmod = -1,
    .chown = -1,
    .fstat = 80,
    .newfstatat = 79,
    .statx = 291,
    .faccessat = 48,
    .faccessat2 = 439,
    .getdents64 = 61,
    .getdents = -1,
    .mkdirat = 34,
    .unlinkat = 35,
    .renameat = 38,
    .renameat2 = 276,
    .fchmodat = 53,
    .fchownat = 54,
    .close = 57,
    .sendmsg = 211,
    .socket = 198,
    .connect = 203,
    .bind = 200,
    .listen = 201,
    .accept = 202,
    .accept4 = 242,
    .sendto = 206,
    .recvfrom = 207,
    .recvmsg = 212,
    .getsockopt = 209,
    .setsockopt = 208,
    .getsockname = 204,
    .getpeername = 205,
    .shutdown = 210,
    .exit = 93,
    .exit_group = 94,
    .fcntl = 25,
    .dup = 23,
    .dup2 = -1,
    .dup3 = 24,
    .read = 63,
    .write = 64,
    .pread64 = 67,
    .lseek = 62,
    .chdir = 49,
    .fchdir = 50,
    .getcwd = 17,
    .getuid = 174,
    .geteuid = 175,
    .getresuid = 148,
    .getgid = 176,
    .getegid = 177,
    .getresgid = 150,
    .setuid = 146,
    .setreuid = 145,
    .setresuid = 147,
    .setgid = 144,
    .setregid = 143,
    .setresgid = 149,
    .getgroups = 158,
    .setgroups = 159,
    .setfsgid = 152,
    .mount = 40,
    .umount2 = 39,
    .execve = 221,
    .execveat = 281,
    .getpid = 172,
    .getppid = 173,
    .gettid = 178,
    .setpgid = 154,
    .getpgid = 155,
    .getsid = 156,
    .setsid = 157,
    .clock_gettime = 113,
    .clock_getres = 114,
    .gettimeofday = -1,
    .readlinkat = 78,
    .pipe2 = 59,
    .pipe = -1,
    .sendfile = 71,
    .copy_file_range = 285,
    .pwrite64 = 68,
    .writev = 66,
    .readv = 65,
    .ftruncate = 46,
    .fallocate = 47,
    .flock = 32,
    .fsync = 82,
    .fdatasync = 83,
    .sync = 81,
    .symlinkat = 36,
    .linkat = 37,
    .utimensat = 88,
    .ioctl = 29,
    .syslog = 116,
    .umask = 166,
    .uname = 160,
    .brk = 214,
    .getrandom = 278,
    .prctl = 167,
    .wait4 = 260,
    .waitid = 95,
    .rt_sigaction = 134,
    .rt_sigprocmask = 135,
    .rt_sigreturn = 139,
    .rt_sigpending = 136,
    .rt_sigaltstack = 132,
    .kill = 129,
    .tgkill = 131,
    .tkill = 130,
    .pidfd_send_signal = 424,
    .setitimer = 103,
    .getitimer = 102,
    .alarm = -1, /* not available on aarch64 */
    .set_tid_address = 96,
    .set_robust_list = 99,
    .futex = 98,
    .clone3 = 435,
    .arch_prctl = -1,
    .rseq = 293,
    .clone = 220,
    .fork = -1,
    .vfork = -1,
    .mmap = 222,
    .munmap = 215,
    .mprotect = 226,
    .mremap = 216,
    .membarrier = 283,
    .sched_yield = 124,
    .sched_setparam = 118,
    .sched_getparam = 121,
    .sched_setscheduler = 119,
    .sched_getscheduler = 120,
    .sched_get_priority_max = 125,
    .sched_get_priority_min = 126,
    .sched_setaffinity = 122,
    .sched_getaffinity = 123,
    .prlimit64 = 261,
    .madvise = 233,
    .getrlimit = -1,
    .getrusage = 165,
    .epoll_create1 = 20,
    .epoll_ctl = 21,
    .epoll_wait = -1,
    .epoll_pwait = 22,
    .ppoll = 73,
    .pselect6 = 72,
    .poll = -1,
    .nanosleep = 101,
    .clock_nanosleep = 115,
    .timerfd_create = 85,
    .timerfd_settime = 86,
    .timerfd_gettime = 87,
    .eventfd = -1,
    .eventfd2 = 19,
    .statfs = -1,
    .fstatfs = 44,
    .sysinfo = 179,
    .readlink = -1,
};

#ifndef KBOX_UNIT_TEST
/*
 * LKL ARCH=lkl always uses the asm-generic ABI.  No runtime probing
 * needed -- the generic syscall table is the only one that applies.
 *
 * The old mkdir-based runtime probe is retained under KBOX_DEBUG_ABI_PROBE
 * for development diagnostics only.
 */
const struct kbox_sysnrs *detect_sysnrs(void)
{
    return &SYSNRS_GENERIC;
}

#ifdef KBOX_DEBUG_ABI_PROBE
static int is_mkdir_result(long r)
{
    if (r == 0)
        return 1;
    if (r == -17 /* EEXIST */ || r == -30 /* EROFS */ ||
        r == -13 /* EACCES */ || r == -1 /* EPERM */ || r == -28 /* ENOSPC */ ||
        r == -2 /* ENOENT */ || r == -20 /* ENOTDIR */)
        return 1;
    return 0;
}

const struct kbox_sysnrs *detect_sysnrs_probe(void)
{
    long r_x86, r_gen;

    if (SYSNRS_X86_64.mkdirat_style) {
        r_x86 = lkl_syscall6(SYSNRS_X86_64.mkdir_no, AT_FDCWD_LINUX,
                             (long) "/__abi_probe_x64", 0755, 0, 0, 0);
    } else {
        r_x86 = lkl_syscall6(SYSNRS_X86_64.mkdir_no, (long) "/__abi_probe_x64",
                             0755, 0, 0, 0, 0);
    }
    if (is_mkdir_result(r_x86))
        return &SYSNRS_X86_64;

    if (SYSNRS_GENERIC.mkdirat_style) {
        r_gen = lkl_syscall6(SYSNRS_GENERIC.mkdir_no, AT_FDCWD_LINUX,
                             (long) "/__abi_probe_generic", 0755, 0, 0, 0);
    } else {
        r_gen = lkl_syscall6(SYSNRS_GENERIC.mkdir_no,
                             (long) "/__abi_probe_generic", 0755, 0, 0, 0, 0);
    }
    if (is_mkdir_result(r_gen))
        return &SYSNRS_GENERIC;

    fprintf(stderr,
            "detect_sysnrs: unable to detect syscall ABI "
            "(x86_64 probe=%ld, generic probe=%ld)\n",
            r_x86, r_gen);
    return NULL;
}
#endif /* KBOX_DEBUG_ABI_PROBE */
#endif /* !KBOX_UNIT_TEST */

/*
 * Map a host syscall number to its name for diagnostic output.
 * Returns "unknown" if the number does not match any entry.
 */
const char *syscall_name_from_nr(const struct kbox_host_nrs *h, int nr)
{
/* Skip fields set to -1 (arch-unavailable) to avoid false matches. */
#define CHECK(field)                         \
    do {                                     \
        if (h->field >= 0 && h->field == nr) \
            return #field;                   \
    } while (0)
    CHECK(openat);
    CHECK(openat2);
    CHECK(open);
    CHECK(stat);
    CHECK(lstat);
    CHECK(access);
    CHECK(rename);
    CHECK(mkdir);
    CHECK(rmdir);
    CHECK(unlink);
    CHECK(chmod);
    CHECK(chown);
    CHECK(fstat);
    CHECK(newfstatat);
    CHECK(statx);
    CHECK(faccessat);
    CHECK(faccessat2);
    CHECK(getdents64);
    CHECK(getdents);
    CHECK(mkdirat);
    CHECK(unlinkat);
    CHECK(renameat);
    CHECK(renameat2);
    CHECK(fchmodat);
    CHECK(fchownat);
    CHECK(close);
    CHECK(sendmsg);
    CHECK(socket);
    CHECK(connect);
    CHECK(bind);
    CHECK(listen);
    CHECK(accept);
    CHECK(accept4);
    CHECK(sendto);
    CHECK(recvfrom);
    CHECK(recvmsg);
    CHECK(getsockopt);
    CHECK(setsockopt);
    CHECK(getsockname);
    CHECK(getpeername);
    CHECK(shutdown);
    CHECK(exit);
    CHECK(exit_group);
    CHECK(fcntl);
    CHECK(dup);
    CHECK(dup2);
    CHECK(dup3);
    CHECK(read);
    CHECK(write);
    CHECK(pread64);
    CHECK(lseek);
    CHECK(chdir);
    CHECK(fchdir);
    CHECK(getcwd);
    CHECK(getuid);
    CHECK(geteuid);
    CHECK(getresuid);
    CHECK(getgid);
    CHECK(getegid);
    CHECK(getresgid);
    CHECK(setuid);
    CHECK(setreuid);
    CHECK(setresuid);
    CHECK(setgid);
    CHECK(setregid);
    CHECK(setresgid);
    CHECK(getgroups);
    CHECK(setgroups);
    CHECK(setfsgid);
    CHECK(mount);
    CHECK(umount2);
    CHECK(execve);
    CHECK(execveat);
    CHECK(getpid);
    CHECK(getppid);
    CHECK(gettid);
    CHECK(setpgid);
    CHECK(getpgid);
    CHECK(getsid);
    CHECK(setsid);
    CHECK(clock_gettime);
    CHECK(clock_getres);
    CHECK(gettimeofday);
    CHECK(readlinkat);
    CHECK(pipe2);
    CHECK(pipe);
    CHECK(sendfile);
    CHECK(copy_file_range);
    CHECK(pwrite64);
    CHECK(writev);
    CHECK(readv);
    CHECK(ftruncate);
    CHECK(fallocate);
    CHECK(flock);
    CHECK(fsync);
    CHECK(fdatasync);
    CHECK(sync);
    CHECK(symlinkat);
    CHECK(linkat);
    CHECK(utimensat);
    CHECK(ioctl);
    CHECK(umask);
    CHECK(uname);
    CHECK(brk);
    CHECK(getrandom);
    CHECK(syslog);
    CHECK(prctl);
    CHECK(wait4);
    CHECK(waitid);
    CHECK(rt_sigaction);
    CHECK(rt_sigprocmask);
    CHECK(rt_sigreturn);
    CHECK(rt_sigpending);
    CHECK(rt_sigaltstack);
    CHECK(kill);
    CHECK(tgkill);
    CHECK(tkill);
    CHECK(pidfd_send_signal);
    CHECK(setitimer);
    CHECK(getitimer);
    /* alarm may be -1 on aarch64 */
    CHECK(set_tid_address);
    CHECK(set_robust_list);
    CHECK(futex);
    CHECK(clone3);
    CHECK(arch_prctl);
    CHECK(rseq);
    CHECK(clone);
    CHECK(fork);
    CHECK(vfork);
    CHECK(mmap);
    CHECK(munmap);
    CHECK(mprotect);
    CHECK(mremap);
    CHECK(membarrier);
    CHECK(sched_yield);
    CHECK(sched_setparam);
    CHECK(sched_getparam);
    CHECK(sched_setscheduler);
    CHECK(sched_getscheduler);
    CHECK(sched_get_priority_max);
    CHECK(sched_get_priority_min);
    CHECK(sched_setaffinity);
    CHECK(sched_getaffinity);
    CHECK(prlimit64);
    CHECK(madvise);
    CHECK(getrlimit);
    CHECK(getrusage);
    CHECK(epoll_create1);
    CHECK(epoll_ctl);
    CHECK(epoll_wait);
    CHECK(epoll_pwait);
    CHECK(ppoll);
    CHECK(pselect6);
    CHECK(poll);
    CHECK(nanosleep);
    CHECK(clock_nanosleep);
    CHECK(timerfd_create);
    CHECK(timerfd_settime);
    CHECK(timerfd_gettime);
    CHECK(eventfd);
    CHECK(eventfd2);
    CHECK(statfs);
    CHECK(fstatfs);
    CHECK(sysinfo);
    CHECK(readlink);
#undef CHECK
    return "unknown";
}
