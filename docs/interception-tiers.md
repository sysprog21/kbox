# Interception tiers

kbox offers three syscall interception mechanisms, each trading isolation
for speed. The default `--syscall-mode=auto` selects the fastest tier
that works for a given workload.

## The three tiers

### Seccomp-unotify (most compatible)

Syscall notifications are delivered to a separate supervisor process via
`SECCOMP_RET_USER_NOTIF`. Strongest isolation, lowest overhead for file
I/O. The supervisor dispatches to LKL and injects results back via two
ioctl round-trips per syscall.

```
                 ┌────────────────┐
                 │  guest child   │  (seccomp BPF: USER_NOTIF)
                 └──────┬─────────┘
                        │ syscall notification
                 ┌──────▼──────────┐          ┌──────────────────┐
                 │  supervisor     │────────▶ │  web observatory │
                 │  (dispatch)     │ counters │  (HTTP + SSE)    │
                 └────┬───────┬────┘ events   └────────┬─────────┘
          LKL path    │       │  host path             │
          ┌───────────▼──┐ ┌──▼──────────┐             ▼
          │  LKL kernel  │ │ host kernel │     ┌──────────────┐
          │  (in-proc)   │ │             │     │  web browser │
          └──────────────┘ └─────────────┘     └──────────────┘
```

### SIGSYS trap (lower latency)

An in-process signal handler intercepts syscalls via `SECCOMP_RET_TRAP`.
No cross-process round-trip, but the signal frame build/restore and a
service-thread hand-off (eventfd + futex) add overhead. Best for metadata
operations on aarch64 where the USER_NOTIF round-trip cost is
proportionally higher.

```
                 ┌─────────────────────────────────────────┐
                 │            single process               │
                 │  ┌─────────────┐   ┌──────────────────┐ │
                 │  │ guest code  │──▶│ SIGSYS handler   │ │
                 │  │ (loaded ELF)│   │ (dispatch thread)│ │
                 │  └─────────────┘   └───┬────────┬─────┘ │
                 │              LKL path  │        │ host  │
                 │          ┌─────────────▼──┐ ┌───▼─────┐ │
                 │          │  LKL kernel    │ │ host    │ │
                 │          │  (in-proc)     │ │ kernel  │ │
                 │          └────────────────┘ └─────────┘ │
                 └─────────────────────────────────────────┘
```

### Binary rewriting (near-native for process-info syscalls)

Syscall instructions are patched to call a trampoline at load time.

On **aarch64**, `SVC #0` is replaced with a `B` branch into a per-site
trampoline that calls the dispatch function directly on the guest thread,
with zero signal overhead, zero context switches, and zero FS base
switching. `stat` from the LKL inode cache completes in-process without
any kernel round-trip.

On **x86_64**, only 8-byte wrapper sites (`mov $NR; syscall; ret`) are
patched; bare 2-byte `syscall` instructions cannot currently be rewritten
in-place (the only same-width replacement, `call *%rax`, would jump to
the syscall number in RAX), so unpatched sites fall through to the
SIGSYS trap path. Process-info syscalls (`getpid`, `gettid`) at wrapper
sites return virtualized values inline at native speed.

For the rewrite engine internals (instruction decoding, veneer pages,
site classification), see [architecture.md](architecture.md#rewrite-engine-rewritec-x86-decodec).

## Auto mode selection

`--syscall-mode=auto` selects the fastest tier per command:

- Non-shell direct binaries use rewrite/trap on both x86_64 and aarch64
  (faster `open+close` and `lseek+read` via the local fast-path that
  bypasses the service thread for 40+ LKL-free syscalls).
- Shell invocations and networking commands use seccomp (fork/exec
  coherence and SLIRP poll loop require the supervisor).

The selection is based on binary analysis: the main executable is
scanned for fork/clone wrapper sites, and binaries that can fork fall
back to seccomp. A guest-thread local fast-path
(`kbox_dispatch_try_local_fast_path`) handles `brk`, `futex`,
`poll`/`ppoll`/`pselect6`, `munmap`, `mremap`, `madvise`, `sched_yield`,
and other host-kernel operations with zero IPC overhead. `mmap` and
`epoll` are not in this set; they go through full dispatch for W^X
enforcement and FD gating. An FD-local stat cache avoids repeated LKL
inode lookups for `fstat` on the same file descriptor.

If the selected tier fails at install time, `auto` falls through to the
next tier. ASAN builds pin `auto` to seccomp; the trap path's guest-stack
switch is incompatible with sanitizer memory tracking.

## Launch flow

1. The supervisor opens a rootfs disk image and registers it as an LKL
   block device.
2. LKL boots a real Linux kernel inside the process (no VM, no separate
   process tree).
3. The filesystem is mounted via LKL, and the supervisor sets the guest's
   virtual root via LKL's internal chroot.
4. The launch path depends on the syscall mode:
   - **Seccomp**: a child process is forked with a BPF filter that
     delivers syscalls as user notifications. The supervisor receives
     each notification, dispatches to LKL or the host kernel, and
     injects results back.
   - **Trap**: the guest binary is loaded into the current process via a
     userspace ELF loader. A BPF filter traps guest-range syscalls via
     `SECCOMP_RET_TRAP`, delivering SIGSYS. A service thread runs the
     dispatch; the signal handler captures the request and spins until
     the result is ready. No cross-process round-trip.
   - **Rewrite**: same as trap, but additionally patches syscall
     instructions to branch directly into dispatch trampolines,
     eliminating the SIGSYS signal overhead entirely for patched sites.
     W^X enforcement blocks simultaneous `PROT_WRITE|PROT_EXEC` in guest
     memory.

For routing details (LKL forward, host CONTINUE, emulated dispositions),
see [architecture.md](architecture.md#syscall-routing).
