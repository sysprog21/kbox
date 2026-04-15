# kbox Architecture

This document describes the internal design of kbox: how syscalls are
routed through the dispatch engine, the key subsystems that back the
guest's view of the kernel, and the ABI translation layer that bridges
LKL's asm-generic headers with native host structures.

For a high-level overview of the three interception tiers and the
project's goals, see the top-level [README](../README.md).

## Syscall routing

Every intercepted syscall is dispatched to one of three dispositions:

- **LKL forward** (~100 handlers, of which 74 live in
  `DISPATCH_FORWARD_TABLE` and the rest are inline cases in
  `kbox_dispatch_request` for legacy stat variants, identity, execve,
  and similar): filesystem operations (open, read,
  write, stat, getdents, mkdir, unlink, rename), metadata (chmod,
  chown, utimensat), identity (getuid, setuid, getgroups), and
  networking (socket, connect). In seccomp mode, the supervisor reads
  arguments from tracee memory via `process_vm_readv` and writes
  results via `process_vm_writev`. In trap/rewrite mode, guest memory
  is accessed directly via `memcpy` (same address space) with
  `sigsetjmp`-based fault recovery that returns `-EFAULT` for unmapped
  pointers. An FD-local stat cache (16 entries, round-robin) avoids
  repeated LKL inode lookups for fstat.
- **Host CONTINUE** (~50 entries): scheduling (sched_yield,
  sched_setscheduler), signals (rt_sigaction, kill, tgkill), memory
  management (mprotect, brk, munmap, mremap, madvise), I/O
  multiplexing (poll, ppoll, pselect6), threading (futex, clone,
  set_tid_address, rseq), time (nanosleep, clock_nanosleep), and more.
  In seccomp mode, the kernel replays the syscall. In trap/rewrite
  mode, the guest-thread local fast-path
  (`kbox_dispatch_try_local_fast_path` in `src/seccomp-dispatch.c`)
  returns CONTINUE directly without touching the service thread for
  about 40 entries: brk, futex, rseq, set_tid_address, set_robust_list,
  munmap, mremap, membarrier, madvise, wait4, waitid, exit, exit_group,
  rt_sigreturn, rt_sigaltstack, setitimer/getitimer, setpgid/getpgid,
  getsid/setsid, fork, vfork, the full sched_* family, getrlimit,
  getrusage, ppoll, pselect6, poll, nanosleep, clock_nanosleep, statfs,
  and sysinfo. `mmap`, `epoll_*`, and other syscalls that need W^X
  enforcement, shadow validation, or FD-table gating are excluded from
  the fast-path and go through full dispatch (`forward_mmap`,
  `forward_fd_gated_continue`).
- **Emulated**: process identity (getpid returns 1, gettid returns 1),
  uname (synthetic LKL values), getrandom (LKL `/dev/urandom`),
  clock_gettime/gettimeofday (host clock, direct passthrough for
  latency).

All three tiers share the same dispatch engine (`kbox_dispatch_request`).
The `kbox_syscall_request` abstraction decouples the dispatch logic
from the notification transport: seccomp notifications, SIGSYS signal
info, and rewrite trampoline calls all produce the same request struct.

Unknown syscalls receive `ENOSYS`. Over 50 dangerous syscalls (mount,
reboot, init_module, bpf, ptrace, etc.) are rejected with `EPERM`
directly in the BPF filter before reaching the supervisor.

## Key subsystems

### Virtual FD table (`fd-table.c`)

Maintains a mapping from guest FD numbers to LKL-internal FDs. Three
ranges back the table: low FDs (0..1023) populated by dup2/dup3 and
stdio-compatible redirection, mid FDs (1024..32767) for tracked
host-passthrough descriptors, and high FDs (32768..36863) for normal
LKL allocation, capped at `KBOX_FD_TABLE_MAX=4096` entries. This split
avoids collisions between host-kernel FDs (pipes, inherited
descriptors, eventfds) and LKL-managed FDs.

### Shadow FDs (`shadow-fd.c`, `dispatch-misc.c`)

The supervisor mirrors selected guest file opens into host-visible
memfds so that native `mmap` and other host-side loaders work without
LKL involvement. This is essential for dynamic linking: the ELF
loader maps `.text` and `.rodata` segments via mmap, which requires a
real host FD. Three flavors coexist:

- **Read-only sealed shadows**: when the guest opens a regular file
  `O_RDONLY`, the supervisor copies the LKL file contents into a
  sealed memfd and hands the memfd number to the tracee. These are
  point-in-time snapshots with no write-back, capped at 256MB. The
  host kernel handles subsequent reads, fstats, and mmaps directly via
  `CONTINUE`.
- **Writeback shadows**: writable opens (`O_RDWR`/`O_WRONLY`) get a
  shadow that the supervisor still backs with a memfd, but the entry
  is marked `shadow_writeback` (`fd-table.h`) and the supervisor
  flushes dirty pages back to the LKL file in `sync_shadow_writeback`
  on close, fsync, and similar synchronization points
  (`dispatch-misc.c:736,759`). `active_writeback_shadows` is tracked
  on the supervisor context so the dispatcher knows when writes are
  outstanding.
- **Path shadow cache**: an 8-entry cache
  (`KBOX_PATH_SHADOW_CACHE_MAX` in `seccomp.h`) reuses memfds across
  repeated reads or stats of the same path, avoiding redundant LKL
  copies for hot read paths like libc and ld-musl. The cache is
  invalidated whenever the guest writes to a path that could overlap
  a cached entry.

### Path translation (`path.c`)

Lexical normalization with 6 escape-prevention checks. Paths starting
with `/proc`, `/sys`, `/dev` are routed to the host kernel via
CONTINUE. Everything else goes through LKL. The normalizer handles
`..` traversal, double slashes, and symlink-based escape attempts
(`/proc/self/root`, `/proc/<pid>/cwd`).

### ELF extraction (`elf.c`, `image.c`)

Binaries are extracted from the LKL filesystem into memfds for
`fexecve`. For dynamically-linked binaries, the PT_INTERP segment
names an interpreter (e.g., `/lib/ld-musl-x86_64.so.1`) that does not
exist on the host. The supervisor extracts the interpreter into a
second memfd and patches PT_INTERP in the main binary to
`/proc/self/fd/N`. The host kernel resolves this during
`load_elf_binary`, before close-on-exec runs.

### Pipe architecture

`pipe()`/`pipe2()` create real host pipes injected into the tracee via
`SECCOMP_IOCTL_NOTIF_ADDFD`. No LKL involvement; the host kernel
manages fork inheritance and close semantics natively. This is why
shell pipelines work: both parent and child share real pipe FDs that
the host kernel handles.

### Trap fast path (`syscall-trap.c`, `loader-*.c`)

For direct binary commands, kbox loads the guest ELF into the current
process via a userspace loader (7 modules: entry, handoff, image,
layout, launch, stack, transfer). A BPF filter traps guest-range
instruction pointers via `SECCOMP_RET_TRAP`, delivering SIGSYS. The
signal handler saves/restores the FS base (FSGSBASE instructions on
kernel 5.9+, arch_prctl fallback) so kbox and guest each use their own
TLS. A service thread runs the full dispatch; the handler captures the
request and spins until the result is ready, keeping heap-allocating
code out of signal context. `arch_prctl(SET_FS)` is intercepted to
maintain dual TLS state.

### Rewrite engine (`rewrite.c`, `x86-decode.c`)

Scans executable PT_LOAD segments for syscall instructions and patches
them to branch directly into dispatch trampolines, eliminating the
SIGSYS signal overhead for patched sites.

On **aarch64**, `SVC #0` (4 bytes, fixed-width) is replaced with a `B`
branch to a per-site trampoline allocated past the segment end. The
trampoline saves registers, loads the origin address, and calls the C
dispatch function directly on the guest thread. No signal frame, no
service thread context switch. Veneer pages with
`LDR x16, [PC+8]; BR x16` indirect stubs bridge sites beyond the
±128MB `B`-instruction range, with slot reuse to avoid wasting a full
page per veneer. This is why aarch64 rewrite achieves ~3us stat (vs
22us in seccomp): the dispatch runs in-process with LKL serving from
the inode cache.

On **x86_64**, an instruction-boundary-aware length decoder
(`x86-decode.c`) walks true instruction boundaries, eliminating false
matches of `0F 05`/`0F 34` bytes inside immediates, displacements, and
SIB encodings. Only 8-byte wrapper sites (`mov $NR, %eax; syscall;
ret`) are patched to `jmp rel32` targeting a wrapper trampoline that
encodes the syscall number and origin address. Bare 2-byte `syscall`
instructions are not rewritten because the only same-width replacement
(`call *%rax`, `FF D0`) would jump to the syscall number in RAX rather
than a code address. Unpatched sites fall through to the SIGSYS trap
path. However, the guest-thread local fast-path
(`kbox_dispatch_try_local_fast_path`) handles ~40 high-frequency
syscalls (futex, brk, poll/ppoll/pselect6, munmap, mremap, madvise,
sched_yield, the rest of the sched_* family, wait4/waitid, fork/vfork,
setpgid/getpgid, statfs, sysinfo, clock_nanosleep, etc.) directly on
the guest thread without any service-thread IPC, giving trap mode a
measurable advantage over seccomp for operations surrounded by these
host-kernel calls. `mmap` and `epoll_*` are deliberately excluded
because they need W^X enforcement, shadow validation, or FD-table
gating that the fast-path cannot perform.

On **riscv64**, the rewrite mode is not available now.

Each site is classified as WRAPPER (simple `syscall; ret` pattern,
eligible for inline virtualized return: getpid=1, gettid=1, getppid=0)
or COMPLEX (result consumed internally by helpers like `raise()` that
feed gettid into tgkill; must use full dispatch). An origin map
validates dispatch calls against known rewrite sites and carries the
per-site classification. During re-exec (`trap_userspace_exec`), the
rewrite runtime is re-installed on the new binary. Multi-threaded
guests (`CLONE_THREAD`) are blocked in trap/rewrite mode; use
`--syscall-mode=seccomp` for threaded workloads.

## ABI translation

LKL is built as `ARCH=lkl`, which uses asm-generic headers. On x86_64,
`struct stat` differs between asm-generic (128 bytes, `st_mode` at
offset 16) and the native layout (144 bytes, `st_mode` at offset 24).
Reading `st_mode` from an LKL-filled buffer using a host `struct stat`
reads `st_uid` instead. kbox uses `struct kbox_lkl_stat` matching the
asm-generic layout, with field-by-field conversion via
`kbox_lkl_stat_to_host()` before writing to tracee memory. Compile-time
`_Static_assert` checks enforce struct sizes and critical field
offsets.

seccomp `args[]` zero-extends 32-bit values: fd=-1 becomes
`0x00000000FFFFFFFF`, not `0xFFFFFFFFFFFFFFFF`. All handlers extracting
signed arguments (AT_FDCWD, MAP_ANONYMOUS fd) truncate to 32 bits
before sign-extending: `(long)(int)(uint32_t)args[N]`.

On aarch64, four `O_*` flags differ between the host and asm-generic:
`O_DIRECTORY`, `O_NOFOLLOW`, `O_DIRECT`, `O_LARGEFILE`. The dispatch
layer translates these bidirectionally.

## Web observatory implementation

The dashboard (`--web` flag, `KBOX_HAS_WEB=1` build) reads LKL's
in-process `/proc` directly. Implementation notes:

- Telemetry is currently driven exclusively by the seccomp supervisor
  loop. `kbox_web_record_syscall` is only called from
  `src/seccomp-supervisor.c:423`, and `kbox_web_tick()` runs from the
  same supervisor poll loop. Trap and rewrite modes do not yet emit
  per-syscall events or drive the periodic sampler -- the supervisor
  context is initialized (so the HTTP server stays up) but the event
  ring stays empty for those modes. Pin `--syscall-mode=seccomp` if
  you need the full audit trail.
- The telemetry sampler runs on the seccomp supervisor's poll timeout
  (100ms tick), reading LKL `/proc/stat`, `/proc/meminfo`,
  `/proc/vmstat`, `/proc/loadavg` via `kbox_lkl_openat`/`kbox_lkl_read`.
  A bounded per-tick parsing budget prevents expensive `/proc` parsing
  from starving seccomp dispatch. Per-type softirq totals come from
  the `softirq` line in `/proc/stat`, not `/proc/softirqs`.
- The HTTP server runs in a dedicated pthread with its own epoll set.
  Shared state (snapshots, event ring) is protected by a single mutex.
  Counter fields use `atomic_int` for cross-thread flags.
- The event ring buffer holds 1024 entries split into 768 for sampled
  routine events (1% probabilistic sampling for high-frequency
  syscalls like read/write) and 256 reserved for errors and rare
  events (execve, clone, exit -- always captured). Events are
  sequence-numbered to prevent SSE duplicate delivery.
- Dispatch instrumentation in seccomp mode adds ~25ns overhead per
  intercepted syscall (one `clock_gettime(CLOCK_MONOTONIC)` call before
  and after dispatch).
- All frontend assets (Chart.js 4.4.7, vanilla JS, CSS) are compiled
  into the binary via `xxd -i` at build time. No CDN, no npm, no
  runtime file I/O. The entire dashboard is self-contained in the
  kbox binary.
- When neither `--web` nor `--trace-format json` is passed, the
  observability subsystem is completely inert -- no threads, no
  sockets, no overhead. `--trace-format json` initializes the
  telemetry context (so the supervisor records events to stderr) but
  skips the HTTP server thread and socket setup. When `KBOX_HAS_WEB`
  is not set at build time, the web code compiles to empty translation
  units.
