/* SPDX-License-Identifier: MIT */
#ifndef KBOX_LOADER_ENTRY_H
#define KBOX_LOADER_ENTRY_H

#include <stdint.h>

#include "loader-layout.h"

enum kbox_loader_entry_arch {
    KBOX_LOADER_ENTRY_ARCH_X86_64,
    KBOX_LOADER_ENTRY_ARCH_AARCH64,
    KBOX_LOADER_ENTRY_ARCH_RISCV64
};

struct kbox_loader_entry_state {
    enum kbox_loader_entry_arch arch;
    uint64_t pc;
    uint64_t sp;
    uint64_t regs[6];
};

int kbox_loader_build_entry_state(const struct kbox_loader_layout *layout,
                                  struct kbox_loader_entry_state *state);

#endif /* KBOX_LOADER_ENTRY_H */
