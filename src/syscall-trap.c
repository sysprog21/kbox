/* SPDX-License-Identifier: MIT */

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#include "kbox/compiler.h"
#include "syscall-trap.h"

static struct kbox_syscall_trap_runtime *active_trap_runtime;

#ifndef FUTEX_WAIT_PRIVATE
#define FUTEX_WAIT_PRIVATE 128
#endif

#ifndef FUTEX_WAKE_PRIVATE
#define FUTEX_WAKE_PRIVATE 129
#endif

static inline struct kbox_syscall_trap_runtime *load_active_trap_runtime(void)
{
    return __atomic_load_n(&active_trap_runtime, __ATOMIC_ACQUIRE);
}

static inline void store_active_trap_runtime(
    struct kbox_syscall_trap_runtime *runtime)
{
    __atomic_store_n(&active_trap_runtime, runtime, __ATOMIC_RELEASE);
}

#define STR2(x) #x
#define XSTR(x) STR2(x)

static int wait_for_pending_dispatch(struct kbox_syscall_trap_runtime *runtime);

#if defined(__x86_64__)
#define KBOX_ARCH_SET_FS 0x1002
#define KBOX_ARCH_GET_FS 0x1003

/* FSGSBASE detection.  On kernels 5.9+ with CR4.FSGSBASE set, rdfsbase
 * and wrfsbase are available in userspace.  These take ~2ns vs ~1.5us
 * for arch_prctl via the host trampoline.  Probed once at install time.
 */
static int have_fsgsbase = -1;
static sigjmp_buf fsgsbase_probe_jmpbuf;

static void fsgsbase_probe_sigill(int signo)
{
    (void) signo;
    siglongjmp(fsgsbase_probe_jmpbuf, 1);
}

static void probe_fsgsbase(void)
{
    struct sigaction sa, old;
    uint64_t val;

    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = fsgsbase_probe_sigill;
    sa.sa_flags = 0;

    if (sigaction(SIGILL, &sa, &old) < 0) {
        have_fsgsbase = 0;
        return;
    }

    if (sigsetjmp(fsgsbase_probe_jmpbuf, 1) == 0) {
        __asm__ volatile("rdfsbase %0" : "=r"(val));
        have_fsgsbase = 1;
    } else {
        have_fsgsbase = 0;
    }

    sigaction(SIGILL, &old, NULL);
}

static uint64_t read_host_fs_base(void)
{
    uint64_t val;

    if (have_fsgsbase) {
        __asm__ volatile("rdfsbase %0" : "=r"(val));
        return val;
    }
    val = 0;
    kbox_syscall_trap_host_arch_prctl_get_fs(&val);
    return val;
}

static void write_host_fs_base(uint64_t val)
{
    if (have_fsgsbase) {
        __asm__ volatile("wrfsbase %0" : : "r"(val) : "memory");
        return;
    }
    kbox_syscall_trap_host_arch_prctl_set_fs(val);
}
#endif

#if defined(__x86_64__)
extern char kbox_syscall_trap_host_syscall_start[];
extern char kbox_syscall_trap_host_syscall_ip_label[];
extern char kbox_syscall_trap_host_syscall_end[];
extern char kbox_syscall_trap_host_futex_wait_start[];
extern char kbox_syscall_trap_host_futex_wait_end[];
extern char kbox_syscall_trap_host_futex_wake_start[];
extern char kbox_syscall_trap_host_futex_wake_end[];
extern char kbox_syscall_trap_host_exit_group_start[];
extern char kbox_syscall_trap_host_exit_group_end[];
extern char kbox_syscall_trap_host_execve_start[];
extern char kbox_syscall_trap_host_execve_end[];
extern char kbox_syscall_trap_host_execveat_start[];
extern char kbox_syscall_trap_host_execveat_end[];
extern char kbox_syscall_trap_host_clone_start[];
extern char kbox_syscall_trap_host_clone_end[];
extern char kbox_syscall_trap_host_clone3_start[];
extern char kbox_syscall_trap_host_clone3_end[];
extern char kbox_syscall_trap_host_fork_start[];
extern char kbox_syscall_trap_host_fork_end[];
extern char kbox_syscall_trap_host_vfork_start[];
extern char kbox_syscall_trap_host_vfork_end[];
extern char kbox_syscall_trap_host_arch_prctl_get_fs_start[];
extern char kbox_syscall_trap_host_arch_prctl_get_fs_end[];
extern char kbox_syscall_trap_host_arch_prctl_set_fs_start[];
extern char kbox_syscall_trap_host_arch_prctl_set_fs_end[];
extern char kbox_syscall_trap_host_rt_sigprocmask_unblock_start[];
extern char kbox_syscall_trap_host_rt_sigprocmask_unblock_end[];

__asm__(
    ".text\n"
    ".globl kbox_syscall_trap_host_syscall6\n"
    ".type kbox_syscall_trap_host_syscall6,@function\n"
    ".globl kbox_syscall_trap_host_syscall_start\n"
    "kbox_syscall_trap_host_syscall_start:\n"
    "kbox_syscall_trap_host_syscall6:\n"
    "mov %rdi, %rax\n"
    "mov %rsi, %rdi\n"
    "mov %rdx, %rsi\n"
    "mov %rcx, %rdx\n"
    "mov %r8, %r10\n"
    "mov %r9, %r8\n"
    "mov 8(%rsp), %r9\n"
    ".globl kbox_syscall_trap_host_syscall_ip_label\n"
    "kbox_syscall_trap_host_syscall_ip_label:\n"
    "syscall\n"
    ".globl kbox_syscall_trap_host_syscall_end\n"
    "kbox_syscall_trap_host_syscall_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_syscall6, "
    ".-kbox_syscall_trap_host_syscall6\n"

    ".globl kbox_syscall_trap_host_futex_wait_private\n"
    ".type kbox_syscall_trap_host_futex_wait_private,@function\n"
    ".globl kbox_syscall_trap_host_futex_wait_start\n"
    "kbox_syscall_trap_host_futex_wait_start:\n"
    "kbox_syscall_trap_host_futex_wait_private:\n"
    "mov %rsi, %rdx\n"
    "mov $" XSTR(FUTEX_WAIT_PRIVATE) ", %esi\n"
    "xor %r10d, %r10d\n"
    "xor %r8d, %r8d\n"
    "xor %r9d, %r9d\n"
    "mov $" XSTR(__NR_futex) ", %eax\n"
    "syscall\n"
    ".globl kbox_syscall_trap_host_futex_wait_end\n"
    "kbox_syscall_trap_host_futex_wait_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_futex_wait_private, "
    ".-kbox_syscall_trap_host_futex_wait_private\n"

    ".globl kbox_syscall_trap_host_futex_wake_private\n"
    ".type kbox_syscall_trap_host_futex_wake_private,@function\n"
    ".globl kbox_syscall_trap_host_futex_wake_start\n"
    "kbox_syscall_trap_host_futex_wake_start:\n"
    "kbox_syscall_trap_host_futex_wake_private:\n"
    "mov %rsi, %rdx\n"
    "mov $" XSTR(FUTEX_WAKE_PRIVATE) ", %esi\n"
    "xor %r10d, %r10d\n"
    "xor %r8d, %r8d\n"
    "xor %r9d, %r9d\n"
    "mov $" XSTR(__NR_futex) ", %eax\n"
    "syscall\n"
    ".globl kbox_syscall_trap_host_futex_wake_end\n"
    "kbox_syscall_trap_host_futex_wake_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_futex_wake_private, "
    ".-kbox_syscall_trap_host_futex_wake_private\n"

    ".globl kbox_syscall_trap_host_exit_group_now\n"
    ".type kbox_syscall_trap_host_exit_group_now,@function\n"
    ".globl kbox_syscall_trap_host_exit_group_start\n"
    "kbox_syscall_trap_host_exit_group_start:\n"
    "kbox_syscall_trap_host_exit_group_now:\n"
    "mov $" XSTR(__NR_exit_group) ", %eax\n"
    "syscall\n"
    ".globl kbox_syscall_trap_host_exit_group_end\n"
    "kbox_syscall_trap_host_exit_group_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_exit_group_now, "
    ".-kbox_syscall_trap_host_exit_group_now\n"

    ".globl kbox_syscall_trap_host_execve_now\n"
    ".type kbox_syscall_trap_host_execve_now,@function\n"
    ".globl kbox_syscall_trap_host_execve_start\n"
    "kbox_syscall_trap_host_execve_start:\n"
    "kbox_syscall_trap_host_execve_now:\n"
    "xor %r10d, %r10d\n"
    "xor %r8d, %r8d\n"
    "xor %r9d, %r9d\n"
    "mov $" XSTR(__NR_execve) ", %eax\n"
    "syscall\n"
    ".globl kbox_syscall_trap_host_execve_end\n"
    "kbox_syscall_trap_host_execve_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_execve_now, "
    ".-kbox_syscall_trap_host_execve_now\n"

    ".globl kbox_syscall_trap_host_execveat_now\n"
    ".type kbox_syscall_trap_host_execveat_now,@function\n"
    ".globl kbox_syscall_trap_host_execveat_start\n"
    "kbox_syscall_trap_host_execveat_start:\n"
    "kbox_syscall_trap_host_execveat_now:\n"
    "mov %rcx, %r10\n"
    "xor %r9d, %r9d\n"
    "mov $" XSTR(__NR_execveat) ", %eax\n"
    "syscall\n"
    ".globl kbox_syscall_trap_host_execveat_end\n"
    "kbox_syscall_trap_host_execveat_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_execveat_now, "
    ".-kbox_syscall_trap_host_execveat_now\n"

    ".globl kbox_syscall_trap_host_clone_now\n"
    ".type kbox_syscall_trap_host_clone_now,@function\n"
    ".globl kbox_syscall_trap_host_clone_start\n"
    "kbox_syscall_trap_host_clone_start:\n"
    "kbox_syscall_trap_host_clone_now:\n"
    "mov %rcx, %r10\n"
    "xor %r9d, %r9d\n"
    "mov $" XSTR(__NR_clone) ", %eax\n"
    "syscall\n"
    ".globl kbox_syscall_trap_host_clone_end\n"
    "kbox_syscall_trap_host_clone_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_clone_now, "
    ".-kbox_syscall_trap_host_clone_now\n"

    ".globl kbox_syscall_trap_host_clone3_now\n"
    ".type kbox_syscall_trap_host_clone3_now,@function\n"
    ".globl kbox_syscall_trap_host_clone3_start\n"
    "kbox_syscall_trap_host_clone3_start:\n"
    "kbox_syscall_trap_host_clone3_now:\n"
    "xor %edx, %edx\n"
    "xor %r10d, %r10d\n"
    "xor %r8d, %r8d\n"
    "xor %r9d, %r9d\n"
    "mov $" XSTR(__NR_clone3) ", %eax\n"
    "syscall\n"
    ".globl kbox_syscall_trap_host_clone3_end\n"
    "kbox_syscall_trap_host_clone3_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_clone3_now, "
    ".-kbox_syscall_trap_host_clone3_now\n"

    ".globl kbox_syscall_trap_host_fork_now\n"
    ".type kbox_syscall_trap_host_fork_now,@function\n"
    ".globl kbox_syscall_trap_host_fork_start\n"
    "kbox_syscall_trap_host_fork_start:\n"
    "kbox_syscall_trap_host_fork_now:\n"
    "mov $" XSTR(__NR_fork) ", %eax\n"
    "syscall\n"
    ".globl kbox_syscall_trap_host_fork_end\n"
    "kbox_syscall_trap_host_fork_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_fork_now, "
    ".-kbox_syscall_trap_host_fork_now\n"

    ".globl kbox_syscall_trap_host_vfork_now\n"
    ".type kbox_syscall_trap_host_vfork_now,@function\n"
    ".globl kbox_syscall_trap_host_vfork_start\n"
    "kbox_syscall_trap_host_vfork_start:\n"
    "kbox_syscall_trap_host_vfork_now:\n"
    "mov $" XSTR(__NR_vfork) ", %eax\n"
    "syscall\n"
    ".globl kbox_syscall_trap_host_vfork_end\n"
    "kbox_syscall_trap_host_vfork_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_vfork_now, "
    ".-kbox_syscall_trap_host_vfork_now\n"

    ".globl kbox_syscall_trap_host_arch_prctl_get_fs\n"
    ".type kbox_syscall_trap_host_arch_prctl_get_fs,@function\n"
    ".globl kbox_syscall_trap_host_arch_prctl_get_fs_start\n"
    "kbox_syscall_trap_host_arch_prctl_get_fs_start:\n"
    "kbox_syscall_trap_host_arch_prctl_get_fs:\n"
    "mov %rdi, %rsi\n"
    "mov $" XSTR(KBOX_ARCH_GET_FS) ", %edi\n"
    "xor %edx, %edx\n"
    "xor %r10d, %r10d\n"
    "xor %r8d, %r8d\n"
    "xor %r9d, %r9d\n"
    "mov $" XSTR(__NR_arch_prctl) ", %eax\n"
    "syscall\n"
    ".globl kbox_syscall_trap_host_arch_prctl_get_fs_end\n"
    "kbox_syscall_trap_host_arch_prctl_get_fs_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_arch_prctl_get_fs, "
    ".-kbox_syscall_trap_host_arch_prctl_get_fs\n"

    ".globl kbox_syscall_trap_host_arch_prctl_set_fs\n"
    ".type kbox_syscall_trap_host_arch_prctl_set_fs,@function\n"
    ".globl kbox_syscall_trap_host_arch_prctl_set_fs_start\n"
    "kbox_syscall_trap_host_arch_prctl_set_fs_start:\n"
    "kbox_syscall_trap_host_arch_prctl_set_fs:\n"
    "mov %rdi, %rsi\n"
    "mov $" XSTR(KBOX_ARCH_SET_FS) ", %edi\n"
    "xor %edx, %edx\n"
    "xor %r10d, %r10d\n"
    "xor %r8d, %r8d\n"
    "xor %r9d, %r9d\n"
    "mov $" XSTR(__NR_arch_prctl) ", %eax\n"
    "syscall\n"
    ".globl kbox_syscall_trap_host_arch_prctl_set_fs_end\n"
    "kbox_syscall_trap_host_arch_prctl_set_fs_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_arch_prctl_set_fs, "
    ".-kbox_syscall_trap_host_arch_prctl_set_fs\n"

    ".globl kbox_syscall_trap_host_rt_sigprocmask_unblock\n"
    ".type kbox_syscall_trap_host_rt_sigprocmask_unblock,@function\n"
    ".globl kbox_syscall_trap_host_rt_sigprocmask_unblock_start\n"
    "kbox_syscall_trap_host_rt_sigprocmask_unblock_start:\n"
    "kbox_syscall_trap_host_rt_sigprocmask_unblock:\n"
    "mov %rsi, %r10\n"
    "mov %rdi, %rsi\n"
    "xor %edx, %edx\n"
    "xor %r8d, %r8d\n"
    "xor %r9d, %r9d\n"
    "mov $" XSTR(SIG_UNBLOCK) ", %edi\n"
    "mov $" XSTR(__NR_rt_sigprocmask) ", %eax\n"
    "syscall\n"
    ".globl kbox_syscall_trap_host_rt_sigprocmask_unblock_end\n"
    "kbox_syscall_trap_host_rt_sigprocmask_unblock_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_rt_sigprocmask_unblock, "
    ".-kbox_syscall_trap_host_rt_sigprocmask_unblock\n");

extern int64_t kbox_syscall_trap_host_syscall6(long nr,
                                               uint64_t a0,
                                               uint64_t a1,
                                               uint64_t a2,
                                               uint64_t a3,
                                               uint64_t a4,
                                               uint64_t a5);
extern int64_t kbox_syscall_trap_host_futex_wait_private(int *addr,
                                                         int expected);
extern int64_t kbox_syscall_trap_host_futex_wake_private(int *addr, int count);
extern int64_t kbox_syscall_trap_host_exit_group_now(int status);
extern int64_t kbox_syscall_trap_host_execve_now(const char *pathname,
                                                 char *const argv[],
                                                 char *const envp[]);
extern int64_t kbox_syscall_trap_host_execveat_now(int dirfd,
                                                   const char *pathname,
                                                   char *const argv[],
                                                   char *const envp[],
                                                   int flags);
extern int64_t kbox_syscall_trap_host_clone_now(uint64_t a0,
                                                uint64_t a1,
                                                uint64_t a2,
                                                uint64_t a3,
                                                uint64_t a4);
extern int64_t kbox_syscall_trap_host_clone3_now(const void *uargs,
                                                 size_t size);
extern int64_t kbox_syscall_trap_host_fork_now(void);
extern int64_t kbox_syscall_trap_host_vfork_now(void);
extern int64_t kbox_syscall_trap_host_arch_prctl_get_fs(uint64_t *out);
extern int64_t kbox_syscall_trap_host_arch_prctl_set_fs(uint64_t val);
extern int64_t kbox_syscall_trap_host_rt_sigprocmask_unblock(
    const uint64_t *mask,
    size_t sigset_size);
#elif defined(__aarch64__)
__asm__(
    ".text\n"
    ".globl kbox_syscall_trap_host_syscall6\n"
    ".type kbox_syscall_trap_host_syscall6,%function\n"
    ".globl kbox_syscall_trap_host_syscall_start\n"
    "kbox_syscall_trap_host_syscall_start:\n"
    "kbox_syscall_trap_host_syscall6:\n"
    "mov x8, x0\n"
    "mov x0, x1\n"
    "mov x1, x2\n"
    "mov x2, x3\n"
    "mov x3, x4\n"
    "mov x4, x5\n"
    "mov x5, x6\n"
    ".globl kbox_syscall_trap_host_syscall_ip_label\n"
    "kbox_syscall_trap_host_syscall_ip_label:\n"
    "svc #0\n"
    ".globl kbox_syscall_trap_host_syscall_end\n"
    "kbox_syscall_trap_host_syscall_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_syscall6, "
    ".-kbox_syscall_trap_host_syscall6\n"

    ".globl kbox_syscall_trap_host_futex_wait_private\n"
    ".type kbox_syscall_trap_host_futex_wait_private,%function\n"
    ".globl kbox_syscall_trap_host_futex_wait_start\n"
    "kbox_syscall_trap_host_futex_wait_start:\n"
    "kbox_syscall_trap_host_futex_wait_private:\n"
    "mov x8, #" XSTR(__NR_futex) "\n"
    "mov x2, x1\n"
    "mov x1, #" XSTR(FUTEX_WAIT_PRIVATE) "\n"
    "mov x3, xzr\n"
    "mov x4, xzr\n"
    "mov x5, xzr\n"
    "svc #0\n"
    ".globl kbox_syscall_trap_host_futex_wait_end\n"
    "kbox_syscall_trap_host_futex_wait_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_futex_wait_private, "
    ".-kbox_syscall_trap_host_futex_wait_private\n"

    ".globl kbox_syscall_trap_host_futex_wake_private\n"
    ".type kbox_syscall_trap_host_futex_wake_private,%function\n"
    ".globl kbox_syscall_trap_host_futex_wake_start\n"
    "kbox_syscall_trap_host_futex_wake_start:\n"
    "kbox_syscall_trap_host_futex_wake_private:\n"
    "mov x8, #" XSTR(__NR_futex) "\n"
    "mov x2, x1\n"
    "mov x1, #" XSTR(FUTEX_WAKE_PRIVATE) "\n"
    "mov x3, xzr\n"
    "mov x4, xzr\n"
    "mov x5, xzr\n"
    "svc #0\n"
    ".globl kbox_syscall_trap_host_futex_wake_end\n"
    "kbox_syscall_trap_host_futex_wake_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_futex_wake_private, "
    ".-kbox_syscall_trap_host_futex_wake_private\n"

    ".globl kbox_syscall_trap_host_exit_group_now\n"
    ".type kbox_syscall_trap_host_exit_group_now,%function\n"
    ".globl kbox_syscall_trap_host_exit_group_start\n"
    "kbox_syscall_trap_host_exit_group_start:\n"
    "kbox_syscall_trap_host_exit_group_now:\n"
    "mov x8, #" XSTR(__NR_exit_group) "\n"
    "svc #0\n"
    ".globl kbox_syscall_trap_host_exit_group_end\n"
    "kbox_syscall_trap_host_exit_group_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_exit_group_now, "
    ".-kbox_syscall_trap_host_exit_group_now\n"

    ".globl kbox_syscall_trap_host_execve_now\n"
    ".type kbox_syscall_trap_host_execve_now,%function\n"
    ".globl kbox_syscall_trap_host_execve_start\n"
    "kbox_syscall_trap_host_execve_start:\n"
    "kbox_syscall_trap_host_execve_now:\n"
    "mov x8, #" XSTR(__NR_execve) "\n"
    "svc #0\n"
    ".globl kbox_syscall_trap_host_execve_end\n"
    "kbox_syscall_trap_host_execve_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_execve_now, "
    ".-kbox_syscall_trap_host_execve_now\n"

    ".globl kbox_syscall_trap_host_execveat_now\n"
    ".type kbox_syscall_trap_host_execveat_now,%function\n"
    ".globl kbox_syscall_trap_host_execveat_start\n"
    "kbox_syscall_trap_host_execveat_start:\n"
    "kbox_syscall_trap_host_execveat_now:\n"
    "mov x8, #" XSTR(__NR_execveat) "\n"
    "svc #0\n"
    ".globl kbox_syscall_trap_host_execveat_end\n"
    "kbox_syscall_trap_host_execveat_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_execveat_now, "
    ".-kbox_syscall_trap_host_execveat_now\n"

    ".globl kbox_syscall_trap_host_clone_now\n"
    ".type kbox_syscall_trap_host_clone_now,%function\n"
    ".globl kbox_syscall_trap_host_clone_start\n"
    "kbox_syscall_trap_host_clone_start:\n"
    "kbox_syscall_trap_host_clone_now:\n"
    "mov x8, #" XSTR(__NR_clone) "\n"
    "svc #0\n"
    ".globl kbox_syscall_trap_host_clone_end\n"
    "kbox_syscall_trap_host_clone_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_clone_now, "
    ".-kbox_syscall_trap_host_clone_now\n"

    ".globl kbox_syscall_trap_host_clone3_now\n"
    ".type kbox_syscall_trap_host_clone3_now,%function\n"
    ".globl kbox_syscall_trap_host_clone3_start\n"
    "kbox_syscall_trap_host_clone3_start:\n"
    "kbox_syscall_trap_host_clone3_now:\n"
    "mov x8, #" XSTR(__NR_clone3) "\n"
    "svc #0\n"
    ".globl kbox_syscall_trap_host_clone3_end\n"
    "kbox_syscall_trap_host_clone3_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_clone3_now, "
    ".-kbox_syscall_trap_host_clone3_now\n"

    ".globl kbox_syscall_trap_host_rt_sigprocmask_unblock\n"
    ".type kbox_syscall_trap_host_rt_sigprocmask_unblock,%function\n"
    ".globl kbox_syscall_trap_host_rt_sigprocmask_unblock_start\n"
    "kbox_syscall_trap_host_rt_sigprocmask_unblock_start:\n"
    "kbox_syscall_trap_host_rt_sigprocmask_unblock:\n"
    "mov x8, #" XSTR(__NR_rt_sigprocmask) "\n"
    "mov x3, x1\n"
    "mov x1, x0\n"
    "mov x0, #" XSTR(SIG_UNBLOCK) "\n"
    "mov x2, xzr\n"
    "mov x4, xzr\n"
    "mov x5, xzr\n"
    "svc #0\n"
    ".globl kbox_syscall_trap_host_rt_sigprocmask_unblock_end\n"
    "kbox_syscall_trap_host_rt_sigprocmask_unblock_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_rt_sigprocmask_unblock, "
    ".-kbox_syscall_trap_host_rt_sigprocmask_unblock\n");
#elif (defined(__riscv) && __riscv_xlen == 64)
__asm__(
    ".text\n"
    ".globl kbox_syscall_trap_host_syscall6\n"
    ".type kbox_syscall_trap_host_syscall6,%function\n"
    ".globl kbox_syscall_trap_host_syscall_start\n"
    "kbox_syscall_trap_host_syscall_start:\n"
    "kbox_syscall_trap_host_syscall6:\n"
    "mv a7, a0\n"
    "mv a0, a1\n"
    "mv a1, a2\n"
    "mv a2, a3\n"
    "mv a3, a4\n"
    "mv a4, a5\n"
    "mv a5, a6\n"
    ".globl kbox_syscall_trap_host_syscall_ip_label\n"
    "kbox_syscall_trap_host_syscall_ip_label:\n"
    "ecall\n"
    ".globl kbox_syscall_trap_host_syscall_end\n"
    "kbox_syscall_trap_host_syscall_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_syscall6, "
    ".-kbox_syscall_trap_host_syscall6\n"

    ".globl kbox_syscall_trap_host_futex_wait_private\n"
    ".type kbox_syscall_trap_host_futex_wait_private,%function\n"
    ".globl kbox_syscall_trap_host_futex_wait_start\n"
    "kbox_syscall_trap_host_futex_wait_private:\n"
    "kbox_syscall_trap_host_futex_wait_start:"
    "li a7, " XSTR(__NR_futex) "\n"
    "mv a2, a1\n"
    "li a1, " XSTR(FUTEX_WAIT_PRIVATE) "\n"
    "li a3, 0\n"
    "li a4, 0\n"
    "li a5, 0\n"
    "ecall\n"
    ".globl kbox_syscall_trap_host_futex_wait_end\n"
    "kbox_syscall_trap_host_futex_wait_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_futex_wait_private, "
    ".-kbox_syscall_trap_host_futex_wait_private\n"

    ".globl kbox_syscall_trap_host_futex_wake_private\n"
    ".type kbox_syscall_trap_host_futex_wake_private,%function\n"
    ".globl kbox_syscall_trap_host_futex_wake_start\n"
    "kbox_syscall_trap_host_futex_wake_start:\n"
    "kbox_syscall_trap_host_futex_wake_private:\n"
    "li a7, " XSTR(__NR_futex) "\n"
    "mv a2, a1\n"
    "li a1, " XSTR(FUTEX_WAKE_PRIVATE) "\n"
    "li a3, 0\n"
    "li a4, 0\n"
    "li a5, 0\n"
    "ecall\n"
    ".globl kbox_syscall_trap_host_futex_wake_end\n"
    "kbox_syscall_trap_host_futex_wake_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_futex_wake_private, "
    ".-kbox_syscall_trap_host_futex_wake_private\n"

    ".globl kbox_syscall_trap_host_exit_group_now\n"
    ".type kbox_syscall_trap_host_exit_group_now,%function\n"
    ".globl kbox_syscall_trap_host_exit_group_start\n"
    "kbox_syscall_trap_host_exit_group_start:\n"
    "kbox_syscall_trap_host_exit_group_now:\n"
    "li a7, " XSTR(__NR_exit_group) "\n"
    "ecall\n"
    ".globl kbox_syscall_trap_host_exit_group_end\n"
    "kbox_syscall_trap_host_exit_group_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_exit_group_now, "
    ".-kbox_syscall_trap_host_exit_group_now\n"

    ".globl kbox_syscall_trap_host_execve_now\n"
    ".type kbox_syscall_trap_host_execve_now,%function\n"
    ".globl kbox_syscall_trap_host_execve_start\n"
    "kbox_syscall_trap_host_execve_start:\n"
    "kbox_syscall_trap_host_execve_now:\n"
    "li a7, " XSTR(__NR_execve) "\n"
    "ecall\n"
    ".globl kbox_syscall_trap_host_execve_end\n"
    "kbox_syscall_trap_host_execve_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_execve_now, "
    ".-kbox_syscall_trap_host_execve_now\n"

    ".globl kbox_syscall_trap_host_execveat_now\n"
    ".type kbox_syscall_trap_host_execveat_now,%function\n"
    ".globl kbox_syscall_trap_host_execveat_start\n"
    "kbox_syscall_trap_host_execveat_start:\n"
    "kbox_syscall_trap_host_execveat_now:\n"
    "li a7, " XSTR(__NR_execveat) "\n"
    "ecall\n"
    ".globl kbox_syscall_trap_host_execveat_end\n"
    "kbox_syscall_trap_host_execveat_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_execveat_now, "
    ".-kbox_syscall_trap_host_execveat_now\n"

    ".globl kbox_syscall_trap_host_clone_now\n"
    ".type kbox_syscall_trap_host_clone_now,%function\n"
    ".globl kbox_syscall_trap_host_clone_start\n"
    "kbox_syscall_trap_host_clone_start:\n"
    "kbox_syscall_trap_host_clone_now:\n"
    "li a7, " XSTR(__NR_clone) "\n"
    "ecall\n"
    ".globl kbox_syscall_trap_host_clone_end\n"
    "kbox_syscall_trap_host_clone_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_clone_now, "
    ".-kbox_syscall_trap_host_clone_now\n"

    ".globl kbox_syscall_trap_host_clone3_now\n"
    ".type kbox_syscall_trap_host_clone3_now,%function\n"
    ".globl kbox_syscall_trap_host_clone3_start\n"
    "kbox_syscall_trap_host_clone3_start:\n"
    "kbox_syscall_trap_host_clone3_now:\n"
    "li a7, " XSTR(__NR_clone3) "\n"
    "ecall\n"
    ".globl kbox_syscall_trap_host_clone3_end\n"
    "kbox_syscall_trap_host_clone3_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_clone3_now, "
    ".-kbox_syscall_trap_host_clone3_now\n"

    ".globl kbox_syscall_trap_host_rt_sigprocmask_unblock\n"
    ".type kbox_syscall_trap_host_rt_sigprocmask_unblock,%function\n"
    ".globl kbox_syscall_trap_host_rt_sigprocmask_unblock_start\n"
    "kbox_syscall_trap_host_rt_sigprocmask_unblock_start:\n"
    "kbox_syscall_trap_host_rt_sigprocmask_unblock:\n"
    "li a7, " XSTR(__NR_rt_sigprocmask) "\n"
    "mv a3, a1\n"
    "mv a1, a0\n"
    "li a0, " XSTR(SIG_UNBLOCK) "\n"
    "li a2, 0\n"
    "li a4, 0\n"
    "li a5, 0\n"
    "ecall\n"
    ".globl kbox_syscall_trap_host_rt_sigprocmask_unblock_end\n"
    "kbox_syscall_trap_host_rt_sigprocmask_unblock_end:\n"
    "ret\n"
    ".size kbox_syscall_trap_host_rt_sigprocmask_unblock, "
    ".-kbox_syscall_trap_host_rt_sigprocmask_unblock\n");
#endif

#if defined(__aarch64__) || (defined(__riscv) && __riscv_xlen == 64)
extern char kbox_syscall_trap_host_syscall_start[];
extern char kbox_syscall_trap_host_syscall_ip_label[];
extern char kbox_syscall_trap_host_syscall_end[];
extern char kbox_syscall_trap_host_futex_wait_start[];
extern char kbox_syscall_trap_host_futex_wait_end[];
extern char kbox_syscall_trap_host_futex_wake_start[];
extern char kbox_syscall_trap_host_futex_wake_end[];
extern char kbox_syscall_trap_host_exit_group_start[];
extern char kbox_syscall_trap_host_exit_group_end[];
extern char kbox_syscall_trap_host_execve_start[];
extern char kbox_syscall_trap_host_execve_end[];
extern char kbox_syscall_trap_host_execveat_start[];
extern char kbox_syscall_trap_host_execveat_end[];
extern char kbox_syscall_trap_host_clone_start[];
extern char kbox_syscall_trap_host_clone_end[];
extern char kbox_syscall_trap_host_clone3_start[];
extern char kbox_syscall_trap_host_clone3_end[];
extern char kbox_syscall_trap_host_rt_sigprocmask_unblock_start[];
extern char kbox_syscall_trap_host_rt_sigprocmask_unblock_end[];


extern int64_t kbox_syscall_trap_host_syscall6(long nr,
                                               uint64_t a0,
                                               uint64_t a1,
                                               uint64_t a2,
                                               uint64_t a3,
                                               uint64_t a4,
                                               uint64_t a5);
extern int64_t kbox_syscall_trap_host_futex_wait_private(int *addr,
                                                         int expected);
extern int64_t kbox_syscall_trap_host_futex_wake_private(int *addr, int count);
extern int64_t kbox_syscall_trap_host_exit_group_now(int status);
extern int64_t kbox_syscall_trap_host_execve_now(const char *pathname,
                                                 char *const argv[],
                                                 char *const envp[]);
extern int64_t kbox_syscall_trap_host_execveat_now(int dirfd,
                                                   const char *pathname,
                                                   char *const argv[],
                                                   char *const envp[],
                                                   int flags);
extern int64_t kbox_syscall_trap_host_clone_now(uint64_t a0,
                                                uint64_t a1,
                                                uint64_t a2,
                                                uint64_t a3,
                                                uint64_t a4);
extern int64_t kbox_syscall_trap_host_clone3_now(const void *uargs,
                                                 size_t size);
extern int64_t kbox_syscall_trap_host_rt_sigprocmask_unblock(
    const uint64_t *mask,
    size_t sigset_size);
#endif

static int direct_trap_execute(struct kbox_syscall_trap_runtime *runtime,
                               const struct kbox_syscall_request *req,
                               struct kbox_dispatch *out)
{
    if (!runtime || !runtime->ctx || !req || !out)
        return -1;

    /* Fast-path: handle LKL-free syscalls directly on the guest thread. */
    if (runtime->ctx->host_nrs &&
        kbox_dispatch_try_local_fast_path(runtime->ctx->host_nrs, req->nr, out))
        return 0;

    if (runtime->service_running) {
        if (kbox_syscall_trap_runtime_capture(runtime, req) < 0)
            return -1;
        if (wait_for_pending_dispatch(runtime) < 0)
            return -1;
        return kbox_syscall_trap_runtime_take_dispatch(runtime, out);
    }

    *out = kbox_dispatch_request(runtime->ctx, req);
    return 0;
}

static const struct kbox_syscall_trap_ops direct_trap_ops = {
    .execute = direct_trap_execute,
};

static ssize_t trap_host_write(int fd, const void *buf, size_t len)
{
    return (ssize_t) kbox_syscall_trap_host_syscall6(__NR_write, (uint64_t) fd,
                                                     (uint64_t) (uintptr_t) buf,
                                                     (uint64_t) len, 0, 0, 0);
}

static int trap_host_futex_wait(int *addr, int expected)
{
    int64_t rc;

    do {
        rc = kbox_syscall_trap_host_futex_wait_private(addr, expected);
    } while (rc == -EINTR);

    if (rc == 0 || rc == -EAGAIN)
        return 0;
    return -1;
}

static int trap_host_futex_wake(int *addr)
{
    int64_t rc;

    do {
        rc = kbox_syscall_trap_host_futex_wake_private(addr, INT_MAX);
    } while (rc == -EINTR);

    return rc < 0 ? -1 : 0;
}

static int trap_futex_wake(int *addr)
{
    long rc;

    do {
        rc = syscall(SYS_futex, addr, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
    } while (rc < 0 && errno == EINTR);

    return rc < 0 ? -1 : 0;
}

static int wait_for_pending_dispatch(struct kbox_syscall_trap_runtime *runtime)
{
    enum {
        SPIN_ITERS = 1024,
    };

    if (!runtime)
        return -1;

    if (runtime->sqpoll) {
        /* SQPOLL: busy-poll without futex. */
        while (!__atomic_load_n(&runtime->has_pending_dispatch,
                                __ATOMIC_ACQUIRE)) {
            if (!runtime->service_running ||
                __atomic_load_n(&runtime->service_stop, __ATOMIC_ACQUIRE))
                return -1;
#if defined(__x86_64__)
            __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
            __asm__ volatile("yield" ::: "memory");
#endif
        }
        return 0;
    }

    /* Spin briefly before falling back to futex.  1024 iterations is
     * ~1.5-3us on modern hardware -- catches fast LKL cache hits.
     */
    for (int i = 0; i < SPIN_ITERS; i++) {
        if (__atomic_load_n(&runtime->has_pending_dispatch, __ATOMIC_ACQUIRE))
            return 0;
        if (!runtime->service_running ||
            __atomic_load_n(&runtime->service_stop, __ATOMIC_ACQUIRE))
            return -1;
#if defined(__x86_64__)
        __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
        __asm__ volatile("yield" ::: "memory");
#endif
    }

    for (;;) {
        if (__atomic_load_n(&runtime->has_pending_dispatch, __ATOMIC_ACQUIRE))
            return 0;
        if (!runtime->service_running ||
            __atomic_load_n(&runtime->service_stop, __ATOMIC_ACQUIRE))
            return -1;
        if (trap_host_futex_wait(&runtime->has_pending_dispatch, 0) < 0)
            return -1;
    }
}

__attribute__((noreturn)) static void trap_host_exit_group(int status)
{
    (void) kbox_syscall_trap_host_exit_group_now(status);
    __builtin_unreachable();
}

int kbox_syscall_trap_reserved_signal(void)
{
    return SIGSYS;
}

int kbox_syscall_trap_signal_is_reserved(int signum)
{
    return signum == kbox_syscall_trap_reserved_signal();
}

int kbox_syscall_trap_sigset_blocks_reserved(const void *mask, size_t len)
{
    const unsigned char *bytes = mask;
    unsigned int signo = (unsigned int) kbox_syscall_trap_reserved_signal();
    unsigned int bit = signo - 1U;
    unsigned int byte_index = bit / 8U;
    unsigned int bit_index = bit % 8U;

    if (!mask || len <= byte_index)
        return 0;
    return (bytes[byte_index] & (1U << bit_index)) != 0;
}

uintptr_t kbox_syscall_trap_host_syscall_ip(void)
{
#if defined(__x86_64__) || defined(__aarch64__) || \
    (defined(__riscv) && __riscv_xlen == 64)
    return (uintptr_t) kbox_syscall_trap_host_syscall_ip_label;
#else
    return 0;
#endif
}

int kbox_syscall_trap_host_syscall_range(struct kbox_syscall_trap_ip_range *out)
{
#if defined(__x86_64__) || defined(__aarch64__) || \
    (defined(__riscv) && __riscv_xlen == 64)
    uintptr_t start = (uintptr_t) kbox_syscall_trap_host_syscall_start;
    uintptr_t end = (uintptr_t) kbox_syscall_trap_host_syscall_end;

    if (!out || start >= end)
        return -1;
    out->start = start;
    /* seccomp reports a post-syscall instruction pointer. On some x86_64
     * builds that can land slightly past the raw `syscall` instruction,
     * so leave a small tail window after the trampoline body instead of
     * assuming the first byte of `ret` is always enough.
     */
    out->end = end + 16;
    return 0;
#else
    (void) out;
    return -1;
#endif
}

static int append_ip_range(struct kbox_syscall_trap_ip_range *out,
                           size_t cap,
                           size_t *count,
                           uintptr_t start,
                           uintptr_t end)
{
    if (!out || !count || *count >= cap || start >= end)
        return -1;
    out[*count].start = start;
    out[*count].end = end + 16;
    (*count)++;
    return 0;
}

int kbox_syscall_trap_internal_ip_ranges(struct kbox_syscall_trap_ip_range *out,
                                         size_t cap,
                                         size_t *count)
{
    size_t n = 0;

    if (!out || !count)
        return -1;

#if defined(__x86_64__)
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_futex_wait_start,
                        (uintptr_t) kbox_syscall_trap_host_futex_wait_end) < 0)
        return -1;
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_futex_wake_start,
                        (uintptr_t) kbox_syscall_trap_host_futex_wake_end) < 0)
        return -1;
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_exit_group_start,
                        (uintptr_t) kbox_syscall_trap_host_exit_group_end) < 0)
        return -1;
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_execve_start,
                        (uintptr_t) kbox_syscall_trap_host_execve_end) < 0)
        return -1;
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_execveat_start,
                        (uintptr_t) kbox_syscall_trap_host_execveat_end) < 0)
        return -1;
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_clone_start,
                        (uintptr_t) kbox_syscall_trap_host_clone_end) < 0)
        return -1;
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_clone3_start,
                        (uintptr_t) kbox_syscall_trap_host_clone3_end) < 0)
        return -1;
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_fork_start,
                        (uintptr_t) kbox_syscall_trap_host_fork_end) < 0)
        return -1;
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_vfork_start,
                        (uintptr_t) kbox_syscall_trap_host_vfork_end) < 0)
        return -1;
    if (append_ip_range(
            out, cap, &n,
            (uintptr_t) kbox_syscall_trap_host_arch_prctl_get_fs_start,
            (uintptr_t) kbox_syscall_trap_host_arch_prctl_get_fs_end) < 0)
        return -1;
    if (append_ip_range(
            out, cap, &n,
            (uintptr_t) kbox_syscall_trap_host_arch_prctl_set_fs_start,
            (uintptr_t) kbox_syscall_trap_host_arch_prctl_set_fs_end) < 0)
        return -1;
    if (append_ip_range(
            out, cap, &n,
            (uintptr_t) kbox_syscall_trap_host_rt_sigprocmask_unblock_start,
            (uintptr_t) kbox_syscall_trap_host_rt_sigprocmask_unblock_end) < 0)
        return -1;
#elif defined(__aarch64__) || (defined(__riscv) && __riscv_xlen == 64)
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_futex_wait_start,
                        (uintptr_t) kbox_syscall_trap_host_futex_wait_end) < 0)
        return -1;
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_futex_wake_start,
                        (uintptr_t) kbox_syscall_trap_host_futex_wake_end) < 0)
        return -1;
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_exit_group_start,
                        (uintptr_t) kbox_syscall_trap_host_exit_group_end) < 0)
        return -1;
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_execve_start,
                        (uintptr_t) kbox_syscall_trap_host_execve_end) < 0)
        return -1;
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_execveat_start,
                        (uintptr_t) kbox_syscall_trap_host_execveat_end) < 0)
        return -1;
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_clone_start,
                        (uintptr_t) kbox_syscall_trap_host_clone_end) < 0)
        return -1;
    if (append_ip_range(out, cap, &n,
                        (uintptr_t) kbox_syscall_trap_host_clone3_start,
                        (uintptr_t) kbox_syscall_trap_host_clone3_end) < 0)
        return -1;
    if (append_ip_range(
            out, cap, &n,
            (uintptr_t) kbox_syscall_trap_host_rt_sigprocmask_unblock_start,
            (uintptr_t) kbox_syscall_trap_host_rt_sigprocmask_unblock_end) < 0)
        return -1;
#else
    return -1;
#endif

    *count = n;
    return 0;
}

int kbox_syscall_regs_from_sigsys(const siginfo_t *info,
                                  const void *ucontext_ptr,
                                  struct kbox_syscall_regs *out)
{
    const ucontext_t *uc = ucontext_ptr;

    if (!info || !ucontext_ptr || !out)
        return -1;
    if (info->si_signo != SIGSYS)
        return -1;

    memset(out, 0, sizeof(*out));

#if defined(__x86_64__)
    out->nr = (info->si_syscall != 0) ? info->si_syscall
                                      : (int) uc->uc_mcontext.gregs[REG_RAX];
    out->instruction_pointer = (uint64_t) uc->uc_mcontext.gregs[REG_RIP];
    out->args[0] = (uint64_t) uc->uc_mcontext.gregs[REG_RDI];
    out->args[1] = (uint64_t) uc->uc_mcontext.gregs[REG_RSI];
    out->args[2] = (uint64_t) uc->uc_mcontext.gregs[REG_RDX];
    out->args[3] = (uint64_t) uc->uc_mcontext.gregs[REG_R10];
    out->args[4] = (uint64_t) uc->uc_mcontext.gregs[REG_R8];
    out->args[5] = (uint64_t) uc->uc_mcontext.gregs[REG_R9];
    return 0;
#elif defined(__aarch64__)
    out->nr = (info->si_syscall != 0) ? info->si_syscall
                                      : (int) uc->uc_mcontext.regs[8];
    out->instruction_pointer = (uint64_t) uc->uc_mcontext.pc;
    out->args[0] = (uint64_t) uc->uc_mcontext.regs[0];
    out->args[1] = (uint64_t) uc->uc_mcontext.regs[1];
    out->args[2] = (uint64_t) uc->uc_mcontext.regs[2];
    out->args[3] = (uint64_t) uc->uc_mcontext.regs[3];
    out->args[4] = (uint64_t) uc->uc_mcontext.regs[4];
    out->args[5] = (uint64_t) uc->uc_mcontext.regs[5];
    return 0;
#elif defined(__riscv) && __riscv_xlen == 64
    out->nr = (info->si_syscall != 0) ? info->si_syscall
                                      : (int) uc->uc_mcontext.__gregs[17];
    out->instruction_pointer = (uint64_t) uc->uc_mcontext.__gregs[0];
    out->args[0] = (uint64_t) uc->uc_mcontext.__gregs[10];
    out->args[1] = (uint64_t) uc->uc_mcontext.__gregs[11];
    out->args[2] = (uint64_t) uc->uc_mcontext.__gregs[12];
    out->args[3] = (uint64_t) uc->uc_mcontext.__gregs[13];
    out->args[4] = (uint64_t) uc->uc_mcontext.__gregs[14];
    out->args[5] = (uint64_t) uc->uc_mcontext.__gregs[15];
    return 0;
#else
    (void) uc;
    return -1;
#endif
}

int kbox_syscall_request_from_sigsys(struct kbox_syscall_request *out,
                                     pid_t pid,
                                     const siginfo_t *info,
                                     const void *ucontext_ptr,
                                     const struct kbox_guest_mem *guest_mem)
{
    struct kbox_syscall_regs regs;
    struct kbox_guest_mem current_guest_mem;

    if (kbox_syscall_regs_from_sigsys(info, ucontext_ptr, &regs) < 0)
        return -1;
    if (!guest_mem) {
        current_guest_mem.ops = &kbox_current_guest_mem_ops;
        current_guest_mem.opaque = 0;
        guest_mem = &current_guest_mem;
    }
    return kbox_syscall_request_init_from_regs(out, KBOX_SYSCALL_SOURCE_TRAP,
                                               pid, 0, &regs, guest_mem);
}

int kbox_syscall_dispatch_sigsys(struct kbox_supervisor_ctx *ctx,
                                 pid_t pid,
                                 const siginfo_t *info,
                                 void *ucontext_ptr)
{
    struct kbox_syscall_trap_runtime runtime;

    if (kbox_syscall_trap_runtime_init(&runtime, ctx, NULL) < 0)
        return -1;
    runtime.pid = pid;
    return kbox_syscall_trap_handle(&runtime, info, ucontext_ptr);
}

int kbox_syscall_trap_runtime_init(struct kbox_syscall_trap_runtime *runtime,
                                   struct kbox_supervisor_ctx *ctx,
                                   const struct kbox_syscall_trap_ops *ops)
{
    if (!runtime || !ctx)
        return -1;

    memset(runtime, 0, sizeof(*runtime));
    runtime->ctx = ctx;
    runtime->ops = ops ? ops : &direct_trap_ops;
    runtime->pid = getpid();
    runtime->wake_fd = -1;
    return 0;
}

static int64_t host_syscall_from_request(const struct kbox_syscall_request *req)
{
    long ret;

    if (!req)
        return -EINVAL;

    errno = 0;
    ret = syscall((long) req->nr, (unsigned long) req->args[0],
                  (unsigned long) req->args[1], (unsigned long) req->args[2],
                  (unsigned long) req->args[3], (unsigned long) req->args[4],
                  (unsigned long) req->args[5]);
    if (ret < 0)
        return -errno;
    return (int64_t) ret;
}

static int host_syscall_requires_guest_thread(
    const struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req)
{
    const struct kbox_host_nrs *h;
    int nr;

    if (!ctx || !ctx->host_nrs || !req)
        return 1;

    h = ctx->host_nrs;
    nr = req->nr;

    if (nr == h->execve || nr == h->execveat || nr == h->exit ||
        nr == h->exit_group || nr == h->rt_sigprocmask ||
        nr == h->rt_sigaltstack || nr == h->clone3 || nr == h->clone ||
        nr == h->fork || nr == h->vfork) {
        return 1;
    }

    return 0;
}

void kbox_syscall_trap_runtime_set_wake_fd(
    struct kbox_syscall_trap_runtime *runtime,
    int wake_fd)
{
    if (!runtime)
        return;
    runtime->wake_fd = wake_fd;
    runtime->owns_wake_fd = 0;
}

int kbox_syscall_trap_runtime_capture(struct kbox_syscall_trap_runtime *runtime,
                                      const struct kbox_syscall_request *req)
{
    if (!runtime || !req)
        return -1;
    if (__atomic_load_n(&runtime->has_pending_request, __ATOMIC_ACQUIRE))
        return -1;

    runtime->pending_request = *req;
    __atomic_store_n(&runtime->has_pending_request, 1, __ATOMIC_RELEASE);

    if (runtime->wake_fd >= 0) {
        uint64_t wake_value = 1;
        ssize_t wr;

        if (runtime->service_running) {
            wr = trap_host_write(runtime->wake_fd, &wake_value,
                                 sizeof(wake_value));
        } else {
            wr = write(runtime->wake_fd, &wake_value, sizeof(wake_value));
        }
        if (wr >= 0)
            return 0;
        if (runtime->service_running) {
            if (wr == -EAGAIN || wr == -EWOULDBLOCK)
                return 0;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
        }
        return -1;
    }

    return runtime->service_running
               ? trap_host_futex_wake(&runtime->has_pending_request)
               : 0;
}

int kbox_syscall_trap_runtime_take_pending(
    struct kbox_syscall_trap_runtime *runtime,
    struct kbox_syscall_request *out)
{
    if (!runtime || !out ||
        !__atomic_load_n(&runtime->has_pending_request, __ATOMIC_ACQUIRE))
        return -1;

    *out = runtime->pending_request;
    __atomic_store_n(&runtime->has_pending_request, 0, __ATOMIC_RELEASE);
    return 0;
}

int kbox_syscall_trap_runtime_complete(
    struct kbox_syscall_trap_runtime *runtime,
    const struct kbox_dispatch *dispatch)
{
    if (!runtime || !dispatch)
        return -1;

    runtime->pending_dispatch = *dispatch;
    __atomic_store_n(&runtime->has_pending_dispatch, 1, __ATOMIC_RELEASE);
    if (trap_futex_wake(&runtime->has_pending_dispatch) < 0)
        return -1;
    runtime->last_dispatch = *dispatch;
    runtime->has_last_dispatch = 1;
    return 0;
}

int kbox_syscall_trap_runtime_take_dispatch(
    struct kbox_syscall_trap_runtime *runtime,
    struct kbox_dispatch *out)
{
    if (!runtime || !out ||
        !__atomic_load_n(&runtime->has_pending_dispatch, __ATOMIC_ACQUIRE))
        return -1;

    *out = runtime->pending_dispatch;
    __atomic_store_n(&runtime->has_pending_dispatch, 0, __ATOMIC_RELEASE);
    return 0;
}

int kbox_syscall_trap_active_dispatch(const struct kbox_syscall_request *req,
                                      struct kbox_dispatch *out)
{
    struct kbox_syscall_trap_runtime *runtime = load_active_trap_runtime();

    if (!runtime || !req || !out || !runtime->ctx || !runtime->service_running)
        return -1;
    if (kbox_syscall_trap_runtime_capture(runtime, req) < 0)
        return -1;
    if (wait_for_pending_dispatch(runtime) < 0)
        return -1;
    return kbox_syscall_trap_runtime_take_dispatch(runtime, out);
}

pid_t kbox_syscall_trap_active_pid(void)
{
    struct kbox_syscall_trap_runtime *runtime = load_active_trap_runtime();

    if (!runtime)
        return (pid_t) -1;
    return runtime->pid;
}

int kbox_syscall_trap_runtime_dispatch_pending(
    struct kbox_syscall_trap_runtime *runtime,
    struct kbox_dispatch *out)
{
    struct kbox_syscall_request req;
    struct kbox_dispatch dispatch;

    if (!runtime || !runtime->ctx)
        return -1;
    if (kbox_syscall_trap_runtime_take_pending(runtime, &req) < 0)
        return -1;

    dispatch = kbox_dispatch_request(runtime->ctx, &req);
    if (dispatch.kind == KBOX_DISPATCH_CONTINUE &&
        !host_syscall_requires_guest_thread(runtime->ctx, &req)) {
        int64_t ret = host_syscall_from_request(&req);

        if (ret < 0)
            dispatch = kbox_dispatch_errno((int) -ret);
        else
            dispatch = kbox_dispatch_value(ret);
    }
    if (kbox_syscall_trap_runtime_complete(runtime, &dispatch) < 0)
        return -1;
    if (out)
        *out = dispatch;
    return 0;
}

static void *trap_service_thread_main(void *opaque)
{
    struct kbox_syscall_trap_runtime *runtime = opaque;

    while (runtime &&
           !__atomic_load_n(&runtime->service_stop, __ATOMIC_ACQUIRE)) {
        if (runtime->wake_fd >= 0) {
            uint64_t wake_value = 0;
            ssize_t rd;

            rd = read(runtime->wake_fd, &wake_value, sizeof(wake_value));
            if (rd < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (rd == 0)
                break;
        } else if (runtime->sqpoll) {
            /* SQPOLL mode (io_uring paradigm): the service thread
             * busy-polls has_pending_request without ever sleeping.
             * Eliminates all futex scheduling latency at the cost of
             * dedicating one CPU core.  Use for latency-critical
             * workloads or benchmarking.
             */
            while (!__atomic_load_n(&runtime->service_stop, __ATOMIC_ACQUIRE) &&
                   !__atomic_load_n(&runtime->has_pending_request,
                                    __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
                __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
                __asm__ volatile("yield" ::: "memory");
#endif
            }
            if (__atomic_load_n(&runtime->service_stop, __ATOMIC_ACQUIRE))
                break;
        } else {
            /* Spin briefly before futex to catch back-to-back requests
             * without a kernel round-trip.
             */
            for (int i = 0; i < 1024; i++) {
                if (__atomic_load_n(&runtime->has_pending_request,
                                    __ATOMIC_ACQUIRE))
                    goto dispatch;
                if (__atomic_load_n(&runtime->service_stop, __ATOMIC_ACQUIRE))
                    break;
#if defined(__x86_64__)
                __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
                __asm__ volatile("yield" ::: "memory");
#endif
            }
            while (!__atomic_load_n(&runtime->service_stop, __ATOMIC_ACQUIRE) &&
                   !__atomic_load_n(&runtime->has_pending_request,
                                    __ATOMIC_ACQUIRE)) {
                if (syscall(SYS_futex, &runtime->has_pending_request,
                            FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0) < 0 &&
                    errno != EINTR && errno != EAGAIN)
                    break;
            }
            if (__atomic_load_n(&runtime->service_stop, __ATOMIC_ACQUIRE))
                break;
        }

    dispatch:
        while (
            __atomic_load_n(&runtime->has_pending_request, __ATOMIC_ACQUIRE)) {
            if (kbox_syscall_trap_runtime_dispatch_pending(runtime, NULL) < 0)
                break;
        }
    }

    return NULL;
}

int kbox_syscall_trap_runtime_service_start(
    struct kbox_syscall_trap_runtime *runtime)
{
    if (!runtime)
        return -1;
    if (runtime->service_running)
        return 0;

    __atomic_store_n(&runtime->service_stop, 0, __ATOMIC_RELEASE);
    if (pthread_create(&runtime->service_thread, NULL, trap_service_thread_main,
                       runtime) != 0) {
        return -1;
    }

    runtime->service_running = 1;
    return 0;
}

int kbox_syscall_trap_runtime_service_stop(
    struct kbox_syscall_trap_runtime *runtime)
{
    if (!runtime)
        return -1;
    if (!runtime->service_running)
        return 0;

    __atomic_store_n(&runtime->service_stop, 1, __ATOMIC_RELEASE);
    if (runtime->wake_fd >= 0) {
        uint64_t wake_value = 1;
        ssize_t wr = write(runtime->wake_fd, &wake_value, sizeof(wake_value));
        (void) wr;
    } else {
        (void) trap_futex_wake(&runtime->has_pending_request);
    }
    if (pthread_join(runtime->service_thread, NULL) != 0)
        return -1;

    runtime->service_running = 0;
    if (runtime->owns_wake_fd && runtime->wake_fd >= 0) {
        close(runtime->wake_fd);
        runtime->wake_fd = -1;
        runtime->owns_wake_fd = 0;
    }
    return 0;
}

int kbox_syscall_trap_handle(struct kbox_syscall_trap_runtime *runtime,
                             const siginfo_t *info,
                             void *ucontext_ptr)
{
    struct kbox_syscall_request req;
    struct kbox_dispatch dispatch;

    if (!runtime || !runtime->ctx || !runtime->ops || !runtime->ops->execute) {
        return -1;
    }
    if (kbox_syscall_request_from_sigsys(&req, runtime->pid, info, ucontext_ptr,
                                         NULL) < 0) {
        return -1;
    }

    runtime->last_request = req;
    runtime->has_last_request = 1;
    runtime->active_ucontext = ucontext_ptr;
    if (runtime->ops->execute(runtime, &req, &dispatch) < 0)
        return -1;
    runtime->last_dispatch = dispatch;
    runtime->has_last_dispatch = 1;
    /* The kernel clobbers RAX with -ENOSYS when delivering SIGSYS for
     * SECCOMP_RET_TRAP.  Restore the original syscall number so that
     * host_syscall() (called for CONTINUE dispatches) reads the correct nr.
     */
#if defined(__x86_64__)
    ((ucontext_t *) ucontext_ptr)->uc_mcontext.gregs[REG_RAX] = (greg_t) req.nr;
#endif
    if (kbox_syscall_result_to_sigsys(ucontext_ptr, &dispatch) < 0)
        return -1;
    runtime->active_ucontext = NULL;
    return 0;
}

/* Execute a raw host syscall on behalf of the guest.  Used for CONTINUE in
 * trap mode: the kernel already blocked the original syscall via RET_TRAP,
 * so we must issue it from the handler.  The hook's own syscall instruction
 * is in the ALLOW IP range and will not trigger seccomp again.
 */
static int64_t host_syscall(const ucontext_t *uc)
{
#if defined(__x86_64__)
    long nr = uc->uc_mcontext.gregs[REG_RAX];

    if (nr == __NR_exit || nr == __NR_exit_group)
        return kbox_syscall_trap_host_exit_group_now(
            (int) uc->uc_mcontext.gregs[REG_RDI]);
    if (nr == __NR_execve)
        return kbox_syscall_trap_host_execve_now(
            (const char *) (uintptr_t) uc->uc_mcontext.gregs[REG_RDI],
            (char *const *) (uintptr_t) uc->uc_mcontext.gregs[REG_RSI],
            (char *const *) (uintptr_t) uc->uc_mcontext.gregs[REG_RDX]);
    if (nr == __NR_execveat)
        return kbox_syscall_trap_host_execveat_now(
            (int) uc->uc_mcontext.gregs[REG_RDI],
            (const char *) (uintptr_t) uc->uc_mcontext.gregs[REG_RSI],
            (char *const *) (uintptr_t) uc->uc_mcontext.gregs[REG_RDX],
            (char *const *) (uintptr_t) uc->uc_mcontext.gregs[REG_R10],
            (int) uc->uc_mcontext.gregs[REG_R8]);
    if (nr == __NR_clone)
        return kbox_syscall_trap_host_clone_now(
            (uint64_t) uc->uc_mcontext.gregs[REG_RDI],
            (uint64_t) uc->uc_mcontext.gregs[REG_RSI],
            (uint64_t) uc->uc_mcontext.gregs[REG_RDX],
            (uint64_t) uc->uc_mcontext.gregs[REG_R10],
            (uint64_t) uc->uc_mcontext.gregs[REG_R8]);
    if (nr == __NR_clone3)
        return kbox_syscall_trap_host_clone3_now(
            (const void *) (uintptr_t) uc->uc_mcontext.gregs[REG_RDI],
            (size_t) uc->uc_mcontext.gregs[REG_RSI]);
    if (nr == __NR_fork)
        return kbox_syscall_trap_host_fork_now();
    if (nr == __NR_vfork)
        return kbox_syscall_trap_host_vfork_now();

    return kbox_syscall_trap_host_syscall6(
        nr, (uint64_t) uc->uc_mcontext.gregs[REG_RDI],
        (uint64_t) uc->uc_mcontext.gregs[REG_RSI],
        (uint64_t) uc->uc_mcontext.gregs[REG_RDX],
        (uint64_t) uc->uc_mcontext.gregs[REG_R10],
        (uint64_t) uc->uc_mcontext.gregs[REG_R8],
        (uint64_t) uc->uc_mcontext.gregs[REG_R9]);
#elif defined(__aarch64__)
    long nr = (long) uc->uc_mcontext.regs[8];

    if (nr == __NR_exit || nr == __NR_exit_group)
        return kbox_syscall_trap_host_exit_group_now(
            (int) uc->uc_mcontext.regs[0]);
    if (nr == __NR_execve)
        return kbox_syscall_trap_host_execve_now(
            (const char *) (uintptr_t) uc->uc_mcontext.regs[0],
            (char *const *) (uintptr_t) uc->uc_mcontext.regs[1],
            (char *const *) (uintptr_t) uc->uc_mcontext.regs[2]);
    if (nr == __NR_execveat)
        return kbox_syscall_trap_host_execveat_now(
            (int) uc->uc_mcontext.regs[0],
            (const char *) (uintptr_t) uc->uc_mcontext.regs[1],
            (char *const *) (uintptr_t) uc->uc_mcontext.regs[2],
            (char *const *) (uintptr_t) uc->uc_mcontext.regs[3],
            (int) uc->uc_mcontext.regs[4]);
    if (nr == __NR_clone)
        return kbox_syscall_trap_host_clone_now(
            (uint64_t) uc->uc_mcontext.regs[0],
            (uint64_t) uc->uc_mcontext.regs[1],
            (uint64_t) uc->uc_mcontext.regs[2],
            (uint64_t) uc->uc_mcontext.regs[3],
            (uint64_t) uc->uc_mcontext.regs[4]);
    if (nr == __NR_clone3)
        return kbox_syscall_trap_host_clone3_now(
            (const void *) (uintptr_t) uc->uc_mcontext.regs[0],
            (size_t) uc->uc_mcontext.regs[1]);

    return kbox_syscall_trap_host_syscall6(
        nr, (uint64_t) uc->uc_mcontext.regs[0],
        (uint64_t) uc->uc_mcontext.regs[1], (uint64_t) uc->uc_mcontext.regs[2],
        (uint64_t) uc->uc_mcontext.regs[3], (uint64_t) uc->uc_mcontext.regs[4],
        (uint64_t) uc->uc_mcontext.regs[5]);
#elif defined(__riscv) && (__riscv_xlen == 64)
    long nr = (long) uc->uc_mcontext.__gregs[17];

    if (nr == __NR_exit || nr == __NR_exit_group)
        return kbox_syscall_trap_host_exit_group_now(
            (int) uc->uc_mcontext.__gregs[10]);
    if (nr == __NR_execve)
        return kbox_syscall_trap_host_execve_now(
            (const char *) (uintptr_t) uc->uc_mcontext.__gregs[10],
            (char *const *) (uintptr_t) uc->uc_mcontext.__gregs[11],
            (char *const *) (uintptr_t) uc->uc_mcontext.__gregs[12]);
    if (nr == __NR_execveat)
        return kbox_syscall_trap_host_execveat_now(
            (int) uc->uc_mcontext.__gregs[10],
            (const char *) (uintptr_t) uc->uc_mcontext.__gregs[11],
            (char *const *) (uintptr_t) uc->uc_mcontext.__gregs[12],
            (char *const *) (uintptr_t) uc->uc_mcontext.__gregs[13],
            (int) uc->uc_mcontext.__gregs[14]);
    if (nr == __NR_clone)
        return kbox_syscall_trap_host_clone_now(
            (uint64_t) uc->uc_mcontext.__gregs[10],
            (uint64_t) uc->uc_mcontext.__gregs[11],
            (uint64_t) uc->uc_mcontext.__gregs[12],
            (uint64_t) uc->uc_mcontext.__gregs[13],
            (uint64_t) uc->uc_mcontext.__gregs[14]);
    if (nr == __NR_clone3)
        return kbox_syscall_trap_host_clone3_now(
            (const void *) (uintptr_t) uc->uc_mcontext.__gregs[10],
            (size_t) uc->uc_mcontext.__gregs[11]);

    return kbox_syscall_trap_host_syscall6(
        nr, (uint64_t) uc->uc_mcontext.__gregs[10],
        (uint64_t) uc->uc_mcontext.__gregs[11],
        (uint64_t) uc->uc_mcontext.__gregs[12],
        (uint64_t) uc->uc_mcontext.__gregs[13],
        (uint64_t) uc->uc_mcontext.__gregs[14],
        (uint64_t) uc->uc_mcontext.__gregs[15]);
#else
    (void) uc;
    return -ENOSYS;
#endif
}

int kbox_syscall_result_to_sigsys(void *ucontext_ptr,
                                  const struct kbox_dispatch *dispatch)
{
    ucontext_t *uc = ucontext_ptr;
    int64_t ret;

    if (!uc || !dispatch)
        return -1;

    if (dispatch->kind == KBOX_DISPATCH_CONTINUE) {
        /* In trap mode, CONTINUE means "let the host kernel handle
         * this syscall."  RET_TRAP blocks the original syscall, so
         * returning from the handler does NOT re-execute it.  We must
         * issue the syscall ourselves from the handler and write the
         * host kernel's return value into the ucontext.
         */
        ret = host_syscall(uc);
    } else if (dispatch->error != 0) {
        ret = -(int64_t) dispatch->error;
    } else {
        ret = dispatch->val;
    }

#if defined(__x86_64__)
    uc->uc_mcontext.gregs[REG_RAX] = (greg_t) ret;
    return 0;
#elif defined(__aarch64__)
    uc->uc_mcontext.regs[0] = (uint64_t) ret;
    return 0;
#elif defined(__riscv) && (__riscv_xlen == 64)
    uc->uc_mcontext.__gregs[10] = (uint64_t) ret;
    return 0;
#else
    return -1;
#endif
}

/* The SIGSYS handler must not have stack-protector instrumentation.
 * When the guest has set its own FS base via arch_prctl(SET_FS), the
 * signal handler is entered with FS pointing to guest TLS.  The stack
 * canary lives at %fs:0x28; if FS points to guest TLS, the canary
 * value is wrong and the function aborts on return.
 *
 * By disabling the stack protector for this one function, we can
 * safely swap FS to kbox's TLS before calling any C dispatch code
 * (which does have canaries and will work correctly with kbox's FS).
 */
/* The SIGSYS handler runs on the guest thread with a seccomp BPF filter
 * active.  The filter rejects syscalls from unregistered IP ranges with
 * EPERM.  ASAN instrumentation inserts load/store checks that may issue
 * syscalls from ASAN runtime IPs (outside registered ranges), deadlocking
 * the dispatch.  Disable both ASAN and stack protectors.
 */
__attribute__((no_stack_protector))
#if KBOX_HAS_ASAN
__attribute__((no_sanitize("address")))
#endif
static void
trap_sigsys_handler(int signo, siginfo_t *info, void *ucontext_ptr)
{
    struct kbox_syscall_trap_runtime *runtime = load_active_trap_runtime();

    if (signo != SIGSYS || !runtime || !runtime->ctx) {
        trap_host_exit_group(127);
    }

#if defined(__x86_64__)
    /* Save guest FS base and restore kbox's FS base so the dispatcher
     * (which uses stack canaries, errno, etc.) runs with correct TLS.
     */
    runtime->guest_fs_base = read_host_fs_base();
    write_host_fs_base(runtime->host_fs_base);
#endif

    if (kbox_syscall_trap_handle(runtime, info, ucontext_ptr) < 0) {
#if defined(__x86_64__)
        write_host_fs_base(runtime->guest_fs_base);
#endif
        trap_host_exit_group(127);
    }

#if defined(__x86_64__)
    /* Restore guest FS base.  If the dispatched syscall was
     * arch_prctl(SET_FS), guest_fs_base was updated by the
     * interceptor in seccomp-dispatch.c.
     */
    write_host_fs_base(runtime->guest_fs_base);
#endif
}

int kbox_syscall_trap_runtime_install(struct kbox_syscall_trap_runtime *runtime,
                                      struct kbox_supervisor_ctx *ctx)
{
    struct sigaction sa;
    int sqpoll;

    if (!runtime || !ctx)
        return -1;

    sqpoll = runtime->sqpoll;
    if (kbox_syscall_trap_runtime_init(runtime, ctx, NULL) < 0)
        return -1;
    runtime->sqpoll = sqpoll;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = trap_sigsys_handler;
    sa.sa_flags = SA_SIGINFO;

    store_active_trap_runtime(runtime);

#if defined(__x86_64__)
    /* Probe for FSGSBASE support before reading the FS base.
     * rdfsbase/wrfsbase are ~750x faster than the arch_prctl
     * trampoline (~2ns vs ~1.5us).  Only probed once.
     */
    if (have_fsgsbase < 0)
        probe_fsgsbase();

    /* Save the host FS base before installing the handler.  This is
     * kbox's own TLS pointer.  The handler will restore it on entry
     * and swap to the guest's FS base on exit.
     */
    runtime->host_fs_base = read_host_fs_base();
    runtime->guest_fs_base = runtime->host_fs_base;
#endif

    if (kbox_syscall_trap_runtime_service_start(runtime) < 0) {
        store_active_trap_runtime(NULL);
        return -1;
    }

    if (sigaction(SIGSYS, &sa, &runtime->old_sigsys) < 0) {
        (void) kbox_syscall_trap_runtime_service_stop(runtime);
        store_active_trap_runtime(NULL);
        return -1;
    }

    runtime->installed = 1;
    return 0;
}

void kbox_syscall_trap_runtime_uninstall(
    struct kbox_syscall_trap_runtime *runtime)
{
    if (!runtime || !runtime->installed)
        return;

    (void) kbox_syscall_trap_runtime_service_stop(runtime);
    sigaction(SIGSYS, &runtime->old_sigsys, NULL);
    if (load_active_trap_runtime() == runtime)
        store_active_trap_runtime(NULL);
    runtime->installed = 0;
}

uint64_t kbox_syscall_trap_get_guest_fs(void)
{
#if defined(__x86_64__)
    struct kbox_syscall_trap_runtime *runtime = load_active_trap_runtime();

    if (runtime)
        return runtime->guest_fs_base;
#endif
    return 0;
}

void kbox_syscall_trap_set_guest_fs(uint64_t val)
{
#if defined(__x86_64__)
    struct kbox_syscall_trap_runtime *runtime = load_active_trap_runtime();

    if (runtime)
        runtime->guest_fs_base = val;
#endif
    (void) val;
}

int kbox_syscall_trap_get_sigmask(void *out, size_t len)
{
    ucontext_t *uc;
    struct kbox_syscall_trap_runtime *runtime = load_active_trap_runtime();

    if (!runtime || !runtime->active_ucontext || !out)
        return -1;

    uc = runtime->active_ucontext;
    if (len > sizeof(uc->uc_sigmask))
        len = sizeof(uc->uc_sigmask);
    memcpy(out, &uc->uc_sigmask, len);
    return 0;
}

int kbox_syscall_trap_set_sigmask(const void *mask, size_t len)
{
    ucontext_t *uc;
    struct kbox_syscall_trap_runtime *runtime = load_active_trap_runtime();

    if (!runtime || !runtime->active_ucontext || !mask)
        return -1;

    uc = runtime->active_ucontext;
    if (len > sizeof(uc->uc_sigmask))
        len = sizeof(uc->uc_sigmask);
    memcpy(&uc->uc_sigmask, mask, len);
    return 0;
}

int kbox_syscall_trap_get_pending(void *out, size_t len)
{
    struct kbox_syscall_trap_runtime *runtime = load_active_trap_runtime();

    if (!runtime || !out)
        return -1;

    if (len > sizeof(runtime->emulated_pending))
        len = sizeof(runtime->emulated_pending);
    memcpy(out, &runtime->emulated_pending, len);
    return 0;
}

int kbox_syscall_trap_set_pending(const void *mask, size_t len)
{
    struct kbox_syscall_trap_runtime *runtime = load_active_trap_runtime();

    if (!runtime || !mask)
        return -1;

    if (len > sizeof(runtime->emulated_pending))
        len = sizeof(runtime->emulated_pending);
    memcpy(&runtime->emulated_pending, mask, len);
    return 0;
}

int kbox_syscall_trap_add_pending_signal(int signo)
{
    sigset_t next;
    struct kbox_syscall_trap_runtime *runtime = load_active_trap_runtime();

    if (!runtime || signo <= 0)
        return -1;

    next = runtime->emulated_pending;
    if (sigaddset(&next, signo) < 0)
        return -1;
    runtime->emulated_pending = next;
    return 0;
}
