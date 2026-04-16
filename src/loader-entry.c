/* SPDX-License-Identifier: MIT */

#include <string.h>

#include "loader-entry.h"

static int machine_to_entry_arch(uint16_t machine,
                                 enum kbox_loader_entry_arch *arch_out)
{
    if (!arch_out)
        return -1;

    switch (machine) {
    case 0x3e:
        *arch_out = KBOX_LOADER_ENTRY_ARCH_X86_64;
        return 0;
    case 0xb7:
        *arch_out = KBOX_LOADER_ENTRY_ARCH_AARCH64;
        return 0;
    case 0xf3:
        *arch_out = KBOX_LOADER_ENTRY_ARCH_RISCV64;
        return 0;
    default:
        return -1;
    }
}

int kbox_loader_build_entry_state(const struct kbox_loader_layout *layout,
                                  struct kbox_loader_entry_state *state)
{
    uint16_t machine;

    if (!layout || !state)
        return -1;

    machine = layout->has_interp ? layout->interp_plan.machine
                                 : layout->main_plan.machine;
    memset(state, 0, sizeof(*state));
    if (machine_to_entry_arch(machine, &state->arch) < 0)
        return -1;
    state->pc = layout->initial_pc;
    state->sp = layout->initial_sp;
    return 0;
}
