# LKL Threading Modes and Impact on kbox

LKL supports two host threading configurations. This document describes
each mode, their behavioral differences, and the impact on the kbox
supervisor design.

## Single-Threaded Mode (Current Default)

One host thread runs all kernel tasks via LKL's internal cooperative
scheduler. The kernel boots with `lkl_start_kernel()` and all subsequent
`lkl_syscall()` calls execute on the calling thread.

Characteristics:
- A blocking LKL syscall (e.g., `read` on a pipe with no data) blocks
  ALL kernel activity. No other kernel task can run until the syscall
  returns or is interrupted.
- Kernel-internal scheduling is serialized. LKL's scheduler picks the
  next task cooperatively, but all execution happens on one host thread.
- Nondeterminism still exists from: host scheduling of the supervisor
  thread, signals, clocks, `getrandom()`, and seccomp notification
  ordering.
- GDB debugging is simpler: one thread of kernel execution, reproducible
  ordering of kernel-internal events.

Why this is the right default for kbox:
- The supervisor's poll loop (seccomp notification FD) runs on a
  separate host thread from LKL. The two threads synchronize via
  `lkl_syscall()` calls -- the supervisor thread enters LKL to perform
  filesystem/identity operations, then returns to the poll loop.
- Concurrent kernel entry is safe even in single-threaded mode because
  LKL's `lkl_host_ops` mutex serializes all kernel entry points.
  `lkl_syscall()` acquires the host semaphore before entering kernel
  code and releases it on return. This means the supervisor thread and
  any LKL-internal timer/softirq threads never execute kernel code
  concurrently -- they are serialized by the host mutex. There is no
  data race.
- kbox never calls blocking LKL syscalls from the supervisor. All LKL
  calls are non-blocking filesystem operations (openat, read, stat,
  getdents, etc.) on the ext4 image.
- Single-threaded mode eliminates SMP race conditions inside the kernel,
  which is irrelevant for kbox's use case (filesystem serving, not
  concurrent kernel driver testing).

## Multi-Threaded Mode

Multiple host pthreads can enter kernel code concurrently. LKL creates
real kernel threads backed by host pthreads. Spinlocks and RCU operate
with real contention.

Characteristics:
- True concurrent execution of kernel code paths. Multiple `lkl_syscall()`
  calls from different host threads execute in parallel inside the kernel.
- Real spinlock contention, RCU grace periods with actual read-side
  concurrency, and scheduler load balancing (if configured for SMP).
- Requires `lkl_host_ops` to provide proper mutex/semaphore/thread
  primitives. LKL's default `posix-host.c` implements these via pthreads.
- Higher fidelity for concurrency experiments but harder to debug.

When multi-threaded mode matters:
- Educational labs studying lock contention, RCU, or SMP scheduling.
- Testing concurrent filesystem operations under real kernel locking.
- Performance benchmarking of kernel code paths under contention.

Impact on kbox supervisor:
- The supervisor's poll loop and LKL syscall calls would need proper
  synchronization if multiple supervisor threads entered LKL
  concurrently. The current single-supervisor-thread design avoids this.
- The virtual FD table (`fd_table.c`) is not thread-safe. If kbox ever
  supports concurrent dispatch from multiple supervisor threads, the FD
  table needs locking.
- LKL's `posix-host.c` leaks semaphores on shutdown in both modes.
  `ASAN_OPTIONS=detect_leaks=0` suppresses the false positive.

## Configuration

LKL's threading mode is determined at build time by the kernel
configuration and at runtime by `lkl_host_ops`. The default
`posix-host.c` host operations support both modes.

To force single-threaded behavior:
- Boot with kernel command line containing `lkl.cpus=1` (if supported
  by the LKL build).
- Or ensure only one host thread ever calls `lkl_syscall()`.

kbox currently does the latter implicitly: only the supervisor thread
calls LKL, and it does so sequentially (no concurrent LKL calls).

## Recommendation

Single-threaded mode for MVP and all Groups A-D. Multi-threaded mode
is only needed for Group E educational labs that study kernel concurrency
primitives (Lab 09: Locking and RCU). Enabling it requires:
1. Thread-safe FD table (add pthread_mutex or use atomic operations).
2. Audit all supervisor state for thread safety.
3. Explicit `--lkl-threads=N` CLI flag (default 1).

This is post-MVP work and should not gate any current deliverables.
