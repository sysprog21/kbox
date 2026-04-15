/* SPDX-License-Identifier: MIT */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

#include "seccomp.h"
#include "syscall-nr.h"
#include "syscall-trap.h"
#include "test-runner.h"

static const struct kbox_guest_mem_ops trap_guest_mem_ops = {
    .read = NULL,
    .write = NULL,
    .write_force = NULL,
    .read_string = NULL,
    .read_open_how = NULL,
};

static int custom_execute_calls;
static int custom_execute_last_nr;

static int custom_trap_execute(struct kbox_syscall_trap_runtime *runtime,
                               const struct kbox_syscall_request *req,
                               struct kbox_dispatch *out)
{
    (void) runtime;
    custom_execute_calls++;
    custom_execute_last_nr = req ? req->nr : -1;
    out->kind = KBOX_DISPATCH_RETURN;
    out->val = req ? (req->nr + 10) : -1;
    out->error = 0;
    return 0;
}

static const struct kbox_syscall_trap_ops custom_trap_ops = {
    .execute = custom_trap_execute,
};

static int capture_only_execute(struct kbox_syscall_trap_runtime *runtime,
                                const struct kbox_syscall_request *req,
                                struct kbox_dispatch *out)
{
    (void) out;
    return kbox_syscall_trap_runtime_capture(runtime, req);
}

static const struct kbox_syscall_trap_ops capture_only_trap_ops = {
    .execute = capture_only_execute,
};

static void init_sigsys(siginfo_t *info, int nr)
{
    memset(info, 0, sizeof(*info));
    info->si_signo = SIGSYS;
    info->si_code = 1;
    info->si_syscall = nr;
}

static void test_sigsys_decode_rejects_non_sigsys(void)
{
    siginfo_t info;
    ucontext_t uc;
    struct kbox_syscall_regs regs;

    memset(&info, 0, sizeof(info));
    memset(&uc, 0, sizeof(uc));
    info.si_signo = SIGUSR1;
    ASSERT_EQ(kbox_syscall_regs_from_sigsys(&info, &uc, &regs), -1);
}

static void test_reserved_sigsys_helpers(void)
{
    unsigned char mask[8];

    memset(mask, 0, sizeof(mask));
    ASSERT_EQ(kbox_syscall_trap_reserved_signal(), SIGSYS);
    ASSERT_EQ(kbox_syscall_trap_signal_is_reserved(SIGSYS), 1);
    ASSERT_EQ(kbox_syscall_trap_signal_is_reserved(SIGUSR1), 0);
    ASSERT_EQ(kbox_syscall_trap_sigset_blocks_reserved(mask, sizeof(mask)), 0);

    mask[(SIGSYS - 1) / 8] = (unsigned char) (1U << ((SIGSYS - 1) % 8));
    ASSERT_EQ(kbox_syscall_trap_sigset_blocks_reserved(mask, sizeof(mask)), 1);
}

static void test_host_syscall_range_contains_ip(void)
{
    struct kbox_syscall_trap_ip_range range;
    uintptr_t ip = kbox_syscall_trap_host_syscall_ip();

#if defined(__x86_64__) || defined(__aarch64__) || \
    (defined(__riscv) && (__riscv_xlen == 64))
    ASSERT_EQ(kbox_syscall_trap_host_syscall_range(&range), 0);
    ASSERT_TRUE(range.start < range.end);
    ASSERT_TRUE(ip >= range.start);
    ASSERT_TRUE(ip < range.end);
#else
    ASSERT_EQ(kbox_syscall_trap_host_syscall_range(&range), -1);
    ASSERT_EQ(ip, (uintptr_t) 0);
#endif
}

#if defined(__x86_64__)
static void test_sigsys_decode_x86_64_registers(void)
{
    siginfo_t info;
    ucontext_t uc;
    struct kbox_syscall_regs regs;

    memset(&uc, 0, sizeof(uc));
    init_sigsys(&info, 257);
    uc.uc_mcontext.gregs[REG_RIP] = 0x401234;
    uc.uc_mcontext.gregs[REG_RDI] = 11;
    uc.uc_mcontext.gregs[REG_RSI] = 22;
    uc.uc_mcontext.gregs[REG_RDX] = 33;
    uc.uc_mcontext.gregs[REG_R10] = 44;
    uc.uc_mcontext.gregs[REG_R8] = 55;
    uc.uc_mcontext.gregs[REG_R9] = 66;
    uc.uc_mcontext.gregs[REG_RAX] = 999;

    ASSERT_EQ(kbox_syscall_regs_from_sigsys(&info, &uc, &regs), 0);
    ASSERT_EQ(regs.nr, 257);
    ASSERT_EQ(regs.instruction_pointer, 0x401234);
    ASSERT_EQ(regs.args[0], 11);
    ASSERT_EQ(regs.args[5], 66);
}
#elif defined(__aarch64__)
static void test_sigsys_decode_aarch64_registers(void)
{
    siginfo_t info;
    ucontext_t uc;
    struct kbox_syscall_regs regs;

    memset(&uc, 0, sizeof(uc));
    init_sigsys(&info, 56);
    uc.uc_mcontext.pc = 0x4000;
    uc.uc_mcontext.regs[0] = 101;
    uc.uc_mcontext.regs[1] = 202;
    uc.uc_mcontext.regs[2] = 303;
    uc.uc_mcontext.regs[3] = 404;
    uc.uc_mcontext.regs[4] = 505;
    uc.uc_mcontext.regs[5] = 606;
    uc.uc_mcontext.regs[8] = 999;

    ASSERT_EQ(kbox_syscall_regs_from_sigsys(&info, &uc, &regs), 0);
    ASSERT_EQ(regs.nr, 56);
    ASSERT_EQ(regs.instruction_pointer, 0x4000);
    ASSERT_EQ(regs.args[0], 101);
    ASSERT_EQ(regs.args[5], 606);
}
#elif defined(__riscv) && (__riscv_xlen == 64)
static void test_sigsys_decode_riscv64_registers(void)
{
    siginfo_t info;
    ucontext_t uc;
    struct kbox_syscall_regs regs;

    memset(&uc, 0, sizeof(uc));
    init_sigsys(&info, 56);
    uc.uc_mcontext.__gregs[0] = 0x4000;
    uc.uc_mcontext.__gregs[10] = 101;
    uc.uc_mcontext.__gregs[11] = 202;
    uc.uc_mcontext.__gregs[12] = 303;
    uc.uc_mcontext.__gregs[13] = 404;
    uc.uc_mcontext.__gregs[14] = 505;
    uc.uc_mcontext.__gregs[15] = 606;
    uc.uc_mcontext.__gregs[16] = 999;

    ASSERT_EQ(kbox_syscall_regs_from_sigsys(&info, &uc, &regs), 0);
    ASSERT_EQ(regs.nr, 56);
    ASSERT_EQ(regs.instruction_pointer, 0x4000);
    ASSERT_EQ(regs.args[0], 101);
    ASSERT_EQ(regs.args[5], 606);
}
#endif

static void test_sigsys_request_builder_uses_trap_source(void)
{
    siginfo_t info;
    ucontext_t uc;
    int expected_rc = -1;
    struct kbox_guest_mem guest_mem = {
        .ops = &trap_guest_mem_ops,
        .opaque = 0x1234,
    };
    struct kbox_syscall_request req;

    memset(&uc, 0, sizeof(uc));
#if defined(__x86_64__)
    init_sigsys(&info, 60);
    uc.uc_mcontext.gregs[REG_RIP] = 0x5000;
    uc.uc_mcontext.gregs[REG_RDI] = 7;
    expected_rc = 0;
#elif defined(__aarch64__)
    init_sigsys(&info, 93);
    uc.uc_mcontext.pc = 0x5000;
    uc.uc_mcontext.regs[0] = 7;
    expected_rc = 0;
#elif defined(__riscv) && (__riscv_xlen == 64)
    init_sigsys(&info, 93);
    uc.uc_mcontext.__gregs[0] = 0x5000;
    uc.uc_mcontext.__gregs[10] = 7;
    expected_rc = 0;
#else
    memset(&info, 0, sizeof(info));
    info.si_signo = SIGSYS;
#endif

    ASSERT_EQ(
        kbox_syscall_request_from_sigsys(&req, 777, &info, &uc, &guest_mem),
        expected_rc);
#if defined(__x86_64__) || defined(__aarch64__) || \
    (defined(__riscv) && (__riscv_xlen == 64))
    ASSERT_EQ(req.source, KBOX_SYSCALL_SOURCE_TRAP);
    ASSERT_EQ(req.pid, 777);
    ASSERT_EQ(req.cookie, 0);
    ASSERT_EQ(req.instruction_pointer, 0x5000);
    ASSERT_EQ(req.args[0], 7);
    ASSERT_EQ(req.guest_mem.ops, &trap_guest_mem_ops);
    ASSERT_EQ(req.guest_mem.opaque, (uintptr_t) 0x1234);
#endif
}

static void test_sigsys_request_builder_defaults_current_guest_mem(void)
{
    siginfo_t info;
    ucontext_t uc;
    int expected_rc = -1;
    struct kbox_syscall_request req;

    memset(&uc, 0, sizeof(uc));
#if defined(__x86_64__)
    init_sigsys(&info, 39);
    uc.uc_mcontext.gregs[REG_RIP] = 0x6000;
    expected_rc = 0;
#elif defined(__aarch64__)
    init_sigsys(&info, 172);
    uc.uc_mcontext.pc = 0x6000;
    expected_rc = 0;
#elif defined(__riscv) && (__riscv_xlen == 64)
    init_sigsys(&info, 172);
    uc.uc_mcontext.__gregs[0] = 0x6000;
    expected_rc = 0;
#else
    memset(&info, 0, sizeof(info));
    info.si_signo = SIGSYS;
#endif

    ASSERT_EQ(kbox_syscall_request_from_sigsys(&req, 123, &info, &uc, NULL),
              expected_rc);
#if defined(__x86_64__) || defined(__aarch64__) || \
    (defined(__riscv) && (__riscv_xlen == 64))
    ASSERT_EQ(req.guest_mem.ops, &kbox_current_guest_mem_ops);
    ASSERT_EQ(req.guest_mem.opaque, 0);
#endif
}

static void test_sigsys_result_writer(void)
{
    ucontext_t uc;
    int expected_rc = -1;
    struct kbox_dispatch dispatch;

    memset(&uc, 0, sizeof(uc));
    dispatch.kind = KBOX_DISPATCH_RETURN;
    dispatch.val = 1234;
    dispatch.error = 0;

#if defined(__x86_64__) || defined(__aarch64__) || \
    (defined(__riscv) && (__riscv_xlen == 64))
    expected_rc = 0;
#endif
    ASSERT_EQ(kbox_syscall_result_to_sigsys(&uc, &dispatch), expected_rc);
#if defined(__x86_64__)
    ASSERT_EQ(uc.uc_mcontext.gregs[REG_RAX], 1234);
#elif defined(__aarch64__)
    ASSERT_EQ(uc.uc_mcontext.regs[0], 1234);
#elif defined(__riscv) && (__riscv_xlen == 64)
    ASSERT_EQ(uc.uc_mcontext.__gregs[10], 1234);
#endif
}

static void test_sigsys_continue_executes_host_syscall(void)
{
    ucontext_t uc;
    struct kbox_dispatch dispatch;
    int expected_rc = -1;

    memset(&uc, 0, sizeof(uc));
    dispatch.kind = KBOX_DISPATCH_CONTINUE;
    dispatch.val = 0;
    dispatch.error = 0;

#if defined(__x86_64__)
    uc.uc_mcontext.gregs[REG_RAX] = HOST_NRS_X86_64.getpid;
    expected_rc = 0;
#elif defined(__aarch64__)
    uc.uc_mcontext.regs[8] = HOST_NRS_GENERIC.getpid;
    expected_rc = 0;
#elif defined(__riscv) && (__riscv_xlen == 64)
    uc.uc_mcontext.__gregs[17] = HOST_NRS_GENERIC.getpid;
    expected_rc = 0;
#endif

    ASSERT_EQ(kbox_syscall_result_to_sigsys(&uc, &dispatch), expected_rc);
#if defined(__x86_64__)
    ASSERT_EQ(uc.uc_mcontext.gregs[REG_RAX], getpid());
#elif defined(__aarch64__)
    ASSERT_EQ(uc.uc_mcontext.regs[0], (uint64_t) getpid());
#elif defined(__riscv) && (__riscv_xlen == 64)
    ASSERT_EQ(uc.uc_mcontext.__gregs[10], (uint64_t) getpid());
#endif
}

static void test_sigsys_runtime_install_uninstall(void)
{
    struct kbox_supervisor_ctx ctx;
    struct kbox_syscall_trap_runtime runtime;

    memset(&ctx, 0, sizeof(ctx));
#if defined(__x86_64__)
    ctx.host_nrs = &HOST_NRS_X86_64;
#elif defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
    ctx.host_nrs = &HOST_NRS_GENERIC;
#endif

    ASSERT_EQ(kbox_syscall_trap_runtime_install(&runtime, &ctx), 0);
    ASSERT_EQ(runtime.ctx, &ctx);
    ASSERT_EQ(runtime.pid, getpid());
    ASSERT_EQ(runtime.installed, 1);
    kbox_syscall_trap_runtime_uninstall(&runtime);
    ASSERT_EQ(runtime.installed, 0);
}

static void test_sigsys_runtime_install_preserves_sqpoll(void)
{
    struct kbox_supervisor_ctx ctx;
    struct kbox_syscall_trap_runtime runtime;

    memset(&ctx, 0, sizeof(ctx));
    memset(&runtime, 0, sizeof(runtime));
#if defined(__x86_64__)
    ctx.host_nrs = &HOST_NRS_X86_64;
#elif defined(__aarch64__)
    ctx.host_nrs = &HOST_NRS_GENERIC;
#elif defined(__riscv) && (__riscv_xlen == 64)
    ctx.host_nrs = &HOST_NRS_GENERIC;
#endif
    runtime.sqpoll = 1;

#if defined(__x86_64__) || defined(__aarch64__) || \
    (defined(__riscv) && (__riscv_xlen == 64))
    ASSERT_EQ(kbox_syscall_trap_runtime_install(&runtime, &ctx), 0);
    ASSERT_EQ(runtime.sqpoll, 1);
    kbox_syscall_trap_runtime_uninstall(&runtime);
#else
    ASSERT_EQ(kbox_syscall_trap_runtime_init(&runtime, &ctx, NULL), 0);
    ASSERT_EQ(runtime.sqpoll, 0);
#endif
}

static void test_sigsys_trap_handle_uses_runtime_executor(void)
{
    struct kbox_supervisor_ctx ctx;
    struct kbox_syscall_trap_runtime runtime;
    siginfo_t info;
    ucontext_t uc;
    int expected_rc = -1;

    memset(&ctx, 0, sizeof(ctx));
    memset(&uc, 0, sizeof(uc));
    custom_execute_calls = 0;
    custom_execute_last_nr = -1;

#if defined(__x86_64__)
    init_sigsys(&info, 39);
    uc.uc_mcontext.gregs[REG_RIP] = 0x7100;
    expected_rc = 0;
#elif defined(__aarch64__)
    init_sigsys(&info, 172);
    uc.uc_mcontext.pc = 0x7100;
    expected_rc = 0;
#elif defined(__riscv) && (__riscv_xlen == 64)
    init_sigsys(&info, 172);
    uc.uc_mcontext.__gregs[0] = 0x7100;
    expected_rc = 0;
#else
    memset(&info, 0, sizeof(info));
    info.si_signo = SIGSYS;
#endif

    ASSERT_EQ(kbox_syscall_trap_runtime_init(&runtime, &ctx, &custom_trap_ops),
              0);
    ASSERT_EQ(kbox_syscall_trap_handle(&runtime, &info, &uc), expected_rc);
#if defined(__x86_64__)
    ASSERT_EQ(uc.uc_mcontext.gregs[REG_RAX], info.si_syscall + 10);
#elif defined(__aarch64__)
    ASSERT_EQ(uc.uc_mcontext.regs[0], (uint64_t) info.si_syscall + 10);
#elif defined(__riscv) && (__riscv_xlen == 64)
    ASSERT_EQ(uc.uc_mcontext.__gregs[10], (uint64_t) info.si_syscall + 10);
#endif
    ASSERT_EQ(custom_execute_calls, 1);
    ASSERT_EQ(custom_execute_last_nr, info.si_syscall);
    ASSERT_EQ(runtime.has_last_request, 1);
    ASSERT_EQ(runtime.has_last_dispatch, 1);
    ASSERT_EQ(runtime.last_request.nr, info.si_syscall);
    ASSERT_EQ(runtime.last_dispatch.val, info.si_syscall + 10);
}

static void test_sigsys_dispatch_helper(void)
{
    struct kbox_supervisor_ctx ctx;
    siginfo_t info;
    ucontext_t uc;
    int expected_rc = -1;

    memset(&ctx, 0, sizeof(ctx));
    memset(&uc, 0, sizeof(uc));
#if defined(__x86_64__)
    ctx.host_nrs = &HOST_NRS_X86_64;
    init_sigsys(&info, 39);
    uc.uc_mcontext.gregs[REG_RIP] = 0x7000;
    expected_rc = 0;
#elif defined(__aarch64__)
    ctx.host_nrs = &HOST_NRS_GENERIC;
    init_sigsys(&info, 172);
    uc.uc_mcontext.pc = 0x7000;
    expected_rc = 0;
#elif defined(__riscv) && (__riscv_xlen == 64)
    ctx.host_nrs = &HOST_NRS_GENERIC;
    init_sigsys(&info, 172);
    uc.uc_mcontext.__gregs[0] = 0x7000;
    expected_rc = 0;
#else
    memset(&info, 0, sizeof(info));
    info.si_signo = SIGSYS;
#endif

    ASSERT_EQ(kbox_syscall_dispatch_sigsys(&ctx, 55, &info, &uc), expected_rc);
#if defined(__x86_64__)
    ASSERT_EQ(uc.uc_mcontext.gregs[REG_RAX], info.si_syscall);
#elif defined(__aarch64__)
    ASSERT_EQ(uc.uc_mcontext.regs[0], (uint64_t) info.si_syscall);
#endif
}

static void test_trap_runtime_capture_and_dispatch_pending(void)
{
    struct kbox_supervisor_ctx ctx;
    struct kbox_syscall_trap_runtime runtime;
    siginfo_t info;
    ucontext_t uc;
    struct kbox_dispatch dispatch;
    int expected_rc = -1;

    memset(&ctx, 0, sizeof(ctx));
    memset(&uc, 0, sizeof(uc));
#if defined(__x86_64__)
    ctx.host_nrs = &HOST_NRS_X86_64;
    init_sigsys(&info, 39);
    uc.uc_mcontext.gregs[REG_RIP] = 0x7200;
    expected_rc = 0;
#elif defined(__aarch64__)
    ctx.host_nrs = &HOST_NRS_GENERIC;
    init_sigsys(&info, 172);
    uc.uc_mcontext.pc = 0x7200;
    expected_rc = 0;
#elif defined(__riscv) && (__riscv_xlen == 64)
    ctx.host_nrs = &HOST_NRS_GENERIC;
    init_sigsys(&info, 172);
    uc.uc_mcontext.__gregs[0] = 0x7200;
    expected_rc = 0;
#else
    memset(&info, 0, sizeof(info));
    info.si_signo = SIGSYS;
#endif

    ASSERT_EQ(
        kbox_syscall_trap_runtime_init(&runtime, &ctx, &capture_only_trap_ops),
        0);
    ASSERT_EQ(kbox_syscall_request_from_sigsys(&runtime.pending_request,
                                               runtime.pid, &info, &uc, NULL),
              expected_rc);
#if defined(__x86_64__) || defined(__aarch64__)
    runtime.has_pending_request = 1;
    ASSERT_EQ(kbox_syscall_trap_runtime_dispatch_pending(&runtime, &dispatch),
              0);
    ASSERT_EQ(dispatch.val, info.si_syscall);
    ASSERT_EQ(runtime.has_pending_request, 0);
    ASSERT_EQ(runtime.has_pending_dispatch, 1);
    ASSERT_EQ(runtime.last_dispatch.val, info.si_syscall);
#endif
}

static void test_trap_runtime_capture_wakes_fd(void)
{
    struct kbox_supervisor_ctx ctx;
    struct kbox_syscall_trap_runtime runtime;
    struct kbox_syscall_request req;
    int pipefd[2];
    uint64_t wake_value = 0;

    memset(&ctx, 0, sizeof(ctx));
    memset(&req, 0, sizeof(req));
    req.nr = 42;
    ASSERT_EQ(pipe(pipefd), 0);
    ASSERT_EQ(kbox_syscall_trap_runtime_init(&runtime, &ctx, NULL), 0);
    kbox_syscall_trap_runtime_set_wake_fd(&runtime, pipefd[1]);

    ASSERT_EQ(kbox_syscall_trap_runtime_capture(&runtime, &req), 0);
    ASSERT_EQ(runtime.has_pending_request, 1);
    ASSERT_EQ(read(pipefd[0], &wake_value, sizeof(wake_value)),
              (long) sizeof(wake_value));
    ASSERT_EQ((long) wake_value, 1);

    close(pipefd[0]);
    close(pipefd[1]);
}

static void test_trap_runtime_service_thread_dispatches(void)
{
    struct kbox_supervisor_ctx ctx;
    struct kbox_syscall_trap_runtime runtime;
    struct kbox_syscall_request req;
    struct kbox_dispatch dispatch;
    int i;

    memset(&ctx, 0, sizeof(ctx));
#if defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
    ctx.host_nrs = &HOST_NRS_GENERIC;
#else
    ctx.host_nrs = &HOST_NRS_X86_64;
#endif
    memset(&req, 0, sizeof(req));
    req.nr = 77;

    ASSERT_EQ(
        kbox_syscall_trap_runtime_init(&runtime, &ctx, &capture_only_trap_ops),
        0);
    ASSERT_EQ(kbox_syscall_trap_runtime_service_start(&runtime), 0);
    ASSERT_EQ(kbox_syscall_trap_runtime_capture(&runtime, &req), 0);

    for (i = 0; i < 200; i++) {
        if (__atomic_load_n(&runtime.has_pending_dispatch, __ATOMIC_ACQUIRE))
            break;
        usleep(1000);
    }

    ASSERT_EQ(__atomic_load_n(&runtime.has_pending_dispatch, __ATOMIC_ACQUIRE),
              1);
    ASSERT_EQ(kbox_syscall_trap_runtime_take_dispatch(&runtime, &dispatch), 0);
    ASSERT_EQ(dispatch.val, 77);
    ASSERT_EQ(kbox_syscall_trap_runtime_service_stop(&runtime), 0);
}

static void test_trap_active_dispatch_uses_service_thread(void)
{
    struct kbox_supervisor_ctx ctx;
    struct kbox_syscall_trap_runtime runtime;
    struct kbox_syscall_request req;
    struct kbox_dispatch dispatch;

    memset(&ctx, 0, sizeof(ctx));
    memset(&req, 0, sizeof(req));
#if defined(__x86_64__)
    ctx.host_nrs = &HOST_NRS_X86_64;
#elif defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
    ctx.host_nrs = &HOST_NRS_GENERIC;
#endif
    req.nr = 88;

#if defined(__x86_64__) || defined(__aarch64__) || \
    (defined(__riscv) && (__riscv_xlen == 64))
    ASSERT_EQ(kbox_syscall_trap_runtime_install(&runtime, &ctx), 0);
    ASSERT_EQ(kbox_syscall_trap_active_pid(), runtime.pid);
    ASSERT_EQ(kbox_syscall_trap_active_dispatch(&req, &dispatch), 0);
    ASSERT_EQ(dispatch.val, 88);
    kbox_syscall_trap_runtime_uninstall(&runtime);
#else
    ASSERT_EQ(kbox_syscall_trap_active_pid(), (pid_t) -1);
    ASSERT_EQ(kbox_syscall_trap_active_dispatch(&req, &dispatch), -1);
#endif
}

static void test_trap_active_dispatch_fails_cleanly_during_sqpoll_stop(void)
{
    struct kbox_supervisor_ctx ctx;
    struct kbox_syscall_trap_runtime runtime;
    struct kbox_syscall_request req;
    struct kbox_dispatch dispatch;

    memset(&ctx, 0, sizeof(ctx));
    memset(&req, 0, sizeof(req));
#if defined(__x86_64__)
    ctx.host_nrs = &HOST_NRS_X86_64;
#elif defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
    ctx.host_nrs = &HOST_NRS_GENERIC;
#endif
    req.nr = 99;

#if defined(__x86_64__) || defined(__aarch64__) || \
    (defined(__riscv) && (__riscv_xlen == 64))
    ASSERT_EQ(kbox_syscall_trap_runtime_install(&runtime, &ctx), 0);
    runtime.sqpoll = 1;
    __atomic_store_n(&runtime.service_stop, 1, __ATOMIC_RELEASE);
    ASSERT_EQ(kbox_syscall_trap_active_dispatch(&req, &dispatch), -1);
    kbox_syscall_trap_runtime_uninstall(&runtime);
#else
    ASSERT_EQ(kbox_syscall_trap_active_dispatch(&req, &dispatch), -1);
#endif
}

void test_syscall_trap_init(void)
{
    TEST_REGISTER(test_sigsys_decode_rejects_non_sigsys);
    TEST_REGISTER(test_reserved_sigsys_helpers);
    TEST_REGISTER(test_host_syscall_range_contains_ip);
#if defined(__x86_64__)
    TEST_REGISTER(test_sigsys_decode_x86_64_registers);
#elif defined(__aarch64__)
    TEST_REGISTER(test_sigsys_decode_aarch64_registers);
#elif defined(__riscv) && (__riscv_xlen == 64)
    TEST_REGISTER(test_sigsys_decode_riscv64_registers);
#endif
    TEST_REGISTER(test_sigsys_request_builder_uses_trap_source);
    TEST_REGISTER(test_sigsys_request_builder_defaults_current_guest_mem);
    TEST_REGISTER(test_sigsys_result_writer);
    TEST_REGISTER(test_sigsys_continue_executes_host_syscall);
    TEST_REGISTER(test_sigsys_runtime_install_uninstall);
    TEST_REGISTER(test_sigsys_runtime_install_preserves_sqpoll);
    TEST_REGISTER(test_sigsys_trap_handle_uses_runtime_executor);
    TEST_REGISTER(test_sigsys_dispatch_helper);
    TEST_REGISTER(test_trap_runtime_capture_and_dispatch_pending);
    TEST_REGISTER(test_trap_runtime_capture_wakes_fd);
    TEST_REGISTER(test_trap_runtime_service_thread_dispatches);
    TEST_REGISTER(test_trap_active_dispatch_uses_service_thread);
    TEST_REGISTER(test_trap_active_dispatch_fails_cleanly_during_sqpoll_stop);
}
