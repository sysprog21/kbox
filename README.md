# kbox

`kbox` boots a real Linux kernel as an in-process library
([LKL, the Linux Kernel Library](https://github.com/lkl/linux)) and routes
intercepted syscalls to it. Programs get real
[VFS](https://www.kernel.org/doc/html/latest/filesystems/vfs.html), real
[ext4](https://www.kernel.org/doc/html/latest/filesystems/ext4/), real
[procfs](https://www.kernel.org/doc/html/latest/filesystems/proc.html),
at near-native syscall speed, without root privileges, containers, VMs,
or [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html).

It serves two roles:

- a rootless [`chroot`](https://man7.org/linux/man-pages/man2/chroot.2.html) /
  [`proot`](https://proot-me.github.io/) alternative with kernel-level
  syscall accuracy, and
- a high-observability execution substrate for AI agent tool calls.

The name `kbox` started as shorthand for "kernel sandboxing", but the
project outgrew that label: a real Linux kernel in-process gives you
semantic fidelity, introspection, and dispatch flexibility that a plain
sandbox cannot. Think of it as a rootless execution substrate that
happens to contain the kernel, not as a box around one.

## At a glance

```
┌──────────────────────────────────────────────────┐
│                   kbox process                   │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │ guest binary (Alpine, musl, gcc, ...)      │  │
│  │ loaded from rootfs.ext4                    │  │
│  └─────────────────┬──────────────────────────┘  │
│                    ▼ syscall                     │
│  ┌────────────────────────────────────────────┐  │
│  │  interception (auto-select)                │  │
│  │  ┌────────┐  ┌──────┐  ┌─────────┐         │  │
│  │  │seccomp │  │SIGSYS│  │ binary  │         │  │
│  │  │unotify │  │ trap │  │ rewrite │         │  │
│  │  └────────┘  └──────┘  └─────────┘         │  │
│  └─────────────────┬──────────────────────────┘  │
│                    ▼                             │
│  ┌────────────────────────────────────────────┐  │
│  │  unified dispatch (kbox_dispatch_request)  │  │
│  └──────┬────────────────────────────┬────────┘  │
│         ▼                            ▼           │
│  ┌──────────────┐             ┌──────────────┐   │
│  │ REAL Linux   │             │ host kernel  │   │
│  │ kernel (LKL) │             │ futex / brk  │   │
│  │ ext4 / VFS / │             │ mmap signals │   │
│  │ procfs / net │             └──────────────┘   │
│  └──────┬───────┘                                │
│         │ in-proc /proc reads                    │
│         │ (no ftrace, no perf, no root)          │
│         ▼                                        │
│  ┌─────────────────────────────┐                 │
│  │ web observatory* + GDB hooks│ ────────────────┼──▶ browser
│  │ (in-proc kernel inspection) │                 │    dashboard
│  └─────────────────────────────┘                 │
└──────────────────────────────────────────────────┘
```

The Linux kernel itself (LKL) is linked into the kbox binary and
runs in the same address space as the supervisor. In trap and rewrite
mode, the guest also shares that address space, so guest, kernel, and
dispatch all live in one process. In seccomp mode, the guest runs as a
forked child while LKL stays in the supervisor; the supervisor handles
syscall notifications and forwards them to the in-process kernel. Either
way: no VM, no container daemon, no `ptrace`, no separate kernel.

\* The web observatory and per-syscall event stream are currently driven
by the seccomp supervisor. Trap and rewrite modes still boot LKL
in-process and remain inspectable via GDB, but do not yet emit telemetry
events. Pin `--syscall-mode=seccomp` if you need the dashboard.

## What makes kbox unique

| Property | kbox | `chroot` | `proot` | UML | gVisor | containers |
|----------|:----:|:--------:|:-------:|:---:|:------:|:----------:|
| Rootless, no daemon                    | yes | no | yes | yes | yes | depends |
| Real Linux kernel for syscalls         | yes | yes | no  | yes | no  | yes |
| In-process kernel                      | yes | n/a | no  | no  | no  | no |
| No `ptrace` dispatch                   | yes | n/a | no  | no  | yes | yes |
| Near-native latency                    | yes | yes | no  | no  | no  | yes |
| Host-side guest `/proc` inspection     | yes | no | no  | no  | no  | no |
| Built-in latency tracing               | yes | no | via `strace` | no | partial | no |
| Web observatory                        | yes | no | no | no | no | no |
| Rewrite mode                           | yes | no | no | no | no | no |

The point is the combination. Most tools cover one or two of these
properties; kbox combines a real Linux kernel, in-process execution,
rootless operation, observability, and low overhead in one design.
It implements the in-process kernel with LKL.
It also exposes a browser observatory for telemetry and inspection.

The rewrite mode is kbox-specific and applies to eligible direct
binaries, where patched syscall sites provide the fastest dispatch path.

## Why kbox

Running Linux userspace programs in a rootless, unprivileged environment
requires intercepting their syscalls and providing a convincing kernel
interface. Existing tools fall short:

- [`chroot`](https://man7.org/linux/man-pages/man2/chroot.2.html)
  requires root privileges (or
  [user namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html),
  which are unavailable on many systems including
  [Termux](https://termux.dev/) and locked-down shared hosts).
- [`proot`](https://proot-me.github.io/) uses
  [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html) for
  syscall interception. `ptrace` is slow, cannot faithfully emulate all
  syscalls, breaks under complex multi-threaded workloads, and its path
  translation is vulnerable to
  [TOCTOU](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)
  races.
- [User Mode Linux (UML)](http://user-mode-linux.sourceforge.net/) runs
  as a separate supervisor/guest process tree with `ptrace`-based syscall
  routing, imposing overhead and complexity that
  [LKL](https://github.com/lkl/linux) avoids by running in-process.
- [gVisor](https://gvisor.dev/) implements a userspace kernel from
  scratch, with millions of lines reimplementing Linux semantics, inevitably
  diverging from the real kernel on edge cases.

kbox takes a different approach: boot the actual
[Linux kernel](https://www.kernel.org/) as an in-process library and
route intercepted syscalls to it. The kernel that handles your `open()`
is the same kernel that runs on servers in production. No
reimplementation, no approximation.

kbox offers three interception tiers
([seccomp-unotify](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html),
[SIGSYS trap](https://man7.org/linux/man-pages/man2/seccomp.2.html),
binary rewriting), each trading isolation for speed. The default
`auto` mode picks the fastest tier per command. See
[docs/interception-tiers.md](docs/interception-tiers.md) for the
trade-offs and selection rules.

## Building

Linux only (host kernel 5.0+ for
[seccomp-unotify](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html),
5.9+ for
[FSGSBASE](https://docs.kernel.org/arch/x86/x86_64/fsgs.html) trap
optimization). Requires [GCC](https://gcc.gnu.org/) and
[GNU Make](https://www.gnu.org/software/make/). `liblkl.a` is fetched
automatically from a
[nightly pre-release](https://github.com/sysprog21/kbox/releases/tag/lkl-nightly)
on first build. No [`libseccomp`](https://github.com/seccomp/libseccomp)
dependency.

```bash
make defconfig              # bootstrap default config
make                        # debug build (ASAN + UBSAN enabled)
make BUILD=release          # release build
make KBOX_HAS_WEB=1         # enable web-based kernel observatory
```

For cross-compilation, use `ARCH` and `CC`:

```bash
make BUILD=release ARCH=aarch64 CC=aarch64-linux-gnu-gcc
```

To use a custom LKL:

```bash
make LKL_DIR=/path/to/lkl   # point to a directory with liblkl.a + lkl.h
make FORCE_LKL_BUILD=1      # force a from-source LKL rebuild
```

## Quick start

Build a test rootfs image (requires
[`e2fsprogs`](https://e2fsprogs.sourceforge.net/), no root needed). The
script auto-detects the host architecture and downloads the matching
[Alpine minirootfs](https://alpinelinux.org/downloads/):

```bash
make rootfs                                       # host arch
make ARCH=aarch64 CC=aarch64-linux-gnu-gcc rootfs # cross
```

Run a guest binary:

```bash
# Interactive shell with recommended mounts + root identity
./kbox -S alpine.ext4 -- /bin/sh -i

# Run a specific command
./kbox -S alpine.ext4 -- /bin/ls -la /

# Raw mount only (no /proc, /sys, /dev), for targeted commands
./kbox -r alpine.ext4 -- /bin/cat /etc/os-release

# Custom kernel cmdline, bind mount, explicit identity
./kbox -r alpine.ext4 -k "mem=2048M loglevel=7" \
    -b /home/user/data:/mnt/data --change-id 1000:1000 -- /bin/sh -i
```

Use `/bin/sh -i` for interactive sessions; the `-i` flag forces
interactive mode regardless of terminal detection.

### Selecting an interception mode

`--syscall-mode` controls the dispatch mechanism:

```bash
# Auto (default): rewrite/trap for direct binaries, seccomp for shells
./kbox -S alpine.ext4 -- /bin/ls /

# Force seccomp (most compatible, handles fork+exec)
./kbox -S alpine.ext4 --syscall-mode=seccomp -- /bin/sh -i

# Force trap (single-exec commands, SIGSYS dispatch)
./kbox -r alpine.ext4 --syscall-mode=trap -- /bin/cat /etc/hostname

# Force rewrite (patched syscall sites, fastest stat path)
./kbox -r alpine.ext4 --syscall-mode=rewrite -- /opt/tests/bench-test 200
```

Run `./kbox --help` for the full option list.

## Documentation

| Topic | Document |
|-------|----------|
| Three syscall interception tiers and auto selection | [docs/interception-tiers.md](docs/interception-tiers.md) |
| Internal design: dispatch routing, FD table, shadow FDs, ABI translation | [docs/architecture.md](docs/architecture.md) |
| Threat model and deployment tiers | [docs/security-model.md](docs/security-model.md) |
| Using kbox as an AI agent execution layer | [docs/ai-agents.md](docs/ai-agents.md) |
| Web dashboard and telemetry endpoints | [docs/web-observatory.md](docs/web-observatory.md) |
| GDB workflow and helper commands | [docs/gdb-workflow.md](docs/gdb-workflow.md) |
| LKL API surface used by kbox | [docs/lkl-api-surface.md](docs/lkl-api-surface.md) |
| LKL threading modes | [docs/lkl-threading-modes.md](docs/lkl-threading-modes.md) |
| Syscall parity specification | [docs/syscall-parity-spec.md](docs/syscall-parity-spec.md) |
| `cancel-wrapper` fast path | [docs/cancel-wrapper.md](docs/cancel-wrapper.md) |

## Testing

```bash
make check                  # all tests (unit + integration + stress)
make check-unit             # unit tests under ASAN/UBSAN
make check-integration      # integration tests against a rootfs image
make check-stress           # stress test programs
```

Unit tests (portable subset runs on macOS, full suite on Linux) have no
LKL dependency. Linux-only tests cover the trap runtime, userspace
loader, rewrite engine, site classification, procmem, and syscall
request decoding. Integration tests run guest binaries inside kbox
against an [Alpine](https://alpinelinux.org/)
[ext4](https://www.kernel.org/doc/html/latest/filesystems/ext4/) image.
Stress tests exercise fork storms, FD exhaustion, concurrent I/O, signal
races, and long-running processes.

All tests run clean under
[AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
and
[UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).
Guest binaries are compiled without sanitizers (shadow memory interferes
with
[`process_vm_readv`](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)).

## Targets

- x86_64
- aarch64
- riscv64 (Only the trap mode and the seccomp mode are available)

## License

`kbox` is available under a permissive
[MIT](https://opensource.org/license/mit)-style license.
Use of this source code is governed by a MIT license that can be found
in the [LICENSE](LICENSE) file.
