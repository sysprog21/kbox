# LKL API Surface Used by kbox

This document identifies the LKL symbols kbox depends on, their purpose,
and known ABI considerations. Use this to verify that a given liblkl.a
build is compatible with kbox.

## Required Symbols

These must be exported by liblkl.a. The build-lkl CI workflow verifies
each one via `nm`.

### Core Lifecycle

| Symbol | Type | Purpose |
|--------|------|---------|
| `lkl_init` | function | Initialize LKL host operations |
| `lkl_start_kernel` | function | Boot the in-process kernel |
| `lkl_cleanup` | function | Shut down the kernel |
| `lkl_strerror` | function | Convert LKL error code to string |

### Syscall Interface

| Symbol | Type | Purpose |
|--------|------|---------|
| `lkl_syscall` | function | Raw syscall dispatch (nr + params array) |

All 64 `kbox_lkl_*` wrappers in `lkl-wrap.c` route through a single
`lkl_syscall6()` helper that packs 6 args into the params array and
calls `lkl_syscall()`. This is the only runtime entry point into the
kernel.

### Block Device

| Symbol | Type | Purpose |
|--------|------|---------|
| `lkl_disk_add` | function | Register ext4 image as virtual block device |
| `lkl_mount_dev` | function | Mount a disk partition by ID |

### Extern Globals

| Symbol | Type | Purpose |
|--------|------|---------|
| `lkl_host_ops` | data | Host operation callbacks (threading, memory, etc.) |
| `lkl_dev_blk_ops` | data | Block device operation callbacks |

kbox takes the address of these and passes them to `lkl_init()` and
`lkl_disk_add()` respectively. The exact struct layouts are opaque --
kbox never reads or writes their fields directly.

## ABI Contract

kbox declares its own LKL FFI in `include/kbox/lkl-wrap.h` rather than
including LKL's header tree. This means:

1. kbox compiles without `lkl.h` or `lkl/autoconf.h`.
2. The binding is purely at the symbol level -- function signatures must
   match but header compatibility is not required.
3. Any change to the signatures of the 9 symbols above is a breaking
   change for kbox.

### struct lkl_disk

kbox declares a minimal `struct lkl_disk` with three fields:
```c
struct lkl_disk {
    void *dev;
    int fd;
    void *ops;
};
```
This must match the beginning of LKL's actual struct. If LKL reorders
or adds fields before `ops`, kbox breaks silently.

### Syscall Number ABI

LKL may use x86_64-native or asm-generic syscall numbers depending on
the build. kbox resolves this at compile time via `probe.c`, which
detects the ABI by calling known syscalls and comparing results. The
`struct kbox_sysnrs` in `syscall-nr.h` stores the detected numbers.

### struct stat ABI

LKL always uses the asm-generic stat layout (128 bytes). The x86_64
host uses a different layout (144 bytes). kbox defines `struct
kbox_lkl_stat` to match the asm-generic layout and converts to host
format via `kbox_lkl_stat_to_host()` before writing to tracee memory.

## Rust Codebase Comparison

The original Rust implementation (reference, never committed to this
repo) used the same core LKL symbols via FFI bindings generated from
`lkl.h`. The C rewrite eliminates the FFI layer entirely -- it links
directly against the same symbols.

Key differences from the Rust approach:

| Aspect | Rust | C |
|--------|------|---|
| LKL header dependency | `lkl.h` via bindgen | None (manual declarations) |
| Syscall dispatch | detect_sysnrs() runtime probing | Compile-time constants + probe.c |
| stat handling | Host struct stat (buggy) | kbox_lkl_stat + field-by-field conversion |
| Build complexity | Cargo + bindgen + cc crate | Single Makefile, static link |
| virtiofsd | Required (host mode) | Eliminated (host mode deferred) |

No LKL symbols were added or removed between the Rust and C
implementations. The API surface is identical -- what changed is how
kbox consumes it.

## Verification

Run this on a liblkl.a to verify compatibility:

```bash
#!/bin/sh
for sym in lkl_init lkl_start_kernel lkl_cleanup lkl_syscall \
           lkl_strerror lkl_disk_add lkl_mount_dev \
           lkl_host_ops lkl_dev_blk_ops; do
    if nm liblkl.a 2>/dev/null | grep -q " [TDBRdb] ${sym}$"; then
        printf "  %-24s OK\n" "$sym"
    else
        printf "  %-24s MISSING\n" "$sym"
    fi
done
```
