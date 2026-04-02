/* SPDX-License-Identifier: MIT */

#include <string.h>

#include "kbox/compiler.h"
#include "loader-transfer.h"

int kbox_loader_prepare_transfer(const struct kbox_loader_handoff *handoff,
                                 struct kbox_loader_transfer_state *state)
{
    if (!handoff || !state)
        return -1;
    if (handoff->entry_map_end <= handoff->entry_map_start ||
        handoff->stack_map_end <= handoff->stack_map_start) {
        return -1;
    }
    if (handoff->entry.pc < handoff->entry_map_start ||
        handoff->entry.pc >= handoff->entry_map_end) {
        return -1;
    }
    if (handoff->entry.sp < handoff->stack_map_start ||
        handoff->entry.sp >= handoff->stack_map_end) {
        return -1;
    }
    if ((handoff->entry.sp & 0xfu) != 0)
        return -1;

    memset(state, 0, sizeof(*state));
    state->arch = handoff->entry.arch;
    state->pc = handoff->entry.pc;
    state->sp = handoff->entry.sp;
    memcpy(state->regs, handoff->entry.regs, sizeof(state->regs));
    state->entry_map_start = handoff->entry_map_start;
    state->entry_map_end = handoff->entry_map_end;
    state->stack_map_start = handoff->stack_map_start;
    state->stack_map_end = handoff->stack_map_end;
    return 0;
}

/* The transfer boundary must not run sanitizer/runtime callbacks or stack
 * protector epilogues. It switches to the guest stack and branches into
 * guest code after the exec-range seccomp filter is active.
 */
__attribute__((noreturn)) __attribute__((no_stack_protector))
#if KBOX_HAS_ASAN
__attribute__((no_sanitize("address")))
#endif
__attribute__((no_sanitize("undefined"))) void
kbox_loader_transfer_to_guest(const struct kbox_loader_transfer_state *state)
{
    if (!state)
        __builtin_trap();

#if defined(__x86_64__)
    if (state->arch != KBOX_LOADER_ENTRY_ARCH_X86_64)
        __builtin_trap();
    register uint64_t rdi __asm__("rdi") = state->regs[0];
    register uint64_t rsi __asm__("rsi") = state->regs[1];
    register uint64_t rdx __asm__("rdx") = state->regs[2];
    register uint64_t r10 __asm__("r10") = state->regs[3];
    register uint64_t r8 __asm__("r8") = state->regs[4];
    register uint64_t r9 __asm__("r9") = state->regs[5];
    uint64_t sp = state->sp;
    uint64_t pc = state->pc;

    __asm__ volatile(
        "mov %0, %%rsp\n\t"
        "jmp *%1\n\t"
        :
        : "r"(sp), "r"(pc), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8),
          "r"(r9)
        : "memory");
#elif defined(__aarch64__)
    if (state->arch != KBOX_LOADER_ENTRY_ARCH_AARCH64)
        __builtin_trap();
    register uint64_t x0 __asm__("x0") = state->regs[0];
    register uint64_t x1 __asm__("x1") = state->regs[1];
    register uint64_t x2 __asm__("x2") = state->regs[2];
    register uint64_t x3 __asm__("x3") = state->regs[3];
    register uint64_t x4 __asm__("x4") = state->regs[4];
    register uint64_t x5 __asm__("x5") = state->regs[5];
    register uint64_t x16 __asm__("x16") = state->pc;
    uint64_t sp = state->sp;

    __asm__ volatile(
        "mov sp, %0\n\t"
        "br x16\n\t"
        :
        : "r"(sp), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5),
          "r"(x16)
        : "memory");
#else
    (void) state;
    __builtin_trap();
#endif

    __builtin_unreachable();
}
