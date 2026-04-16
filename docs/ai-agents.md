# AI agent integration

AI agents that execute tool calls (compile, test, run scripts, query
filesystems) need three things from their execution layer: faithful Linux
behavior so tools work correctly, visibility into what happened when a
tool call fails, and low per-invocation overhead so the agent loop stays
fast.

Typical container execution surfaces only process-level outcomes (exit
code, stderr) unless you add external host-side instrumentation (cgroups,
eBPF, perf); even then, host-side counters show resource accounting but
not the guest kernel's own procfs view or full allocator internals.
`strace` shows syscall arguments from the outside but cannot see
kernel-internal state like memory pressure or load average trends. kbox
occupies a different point in the design space: the kernel runs
in-process, so every internal data structure is directly readable by the
supervisor while the guest executes.

## What kbox provides for agents

- **Kernel-internal observability**: because LKL runs in the same address
  space, kbox samples `/proc/stat`, `/proc/meminfo`, `/proc/vmstat`, and
  `/proc/loadavg` from LKL's own procfs (not the host's). The current
  telemetry API exposes context switch rates, memory breakdown (free,
  buffers, cached, slab), page fault counters, load averages, and
  per-type softirq totals for the guest workload specifically. When an
  agent tool call hangs, the orchestrator can query `/api/snapshot` to
  help differentiate CPU-heavy behavior from memory pressure. Deeper
  kernel internals (runqueues, buddy free lists, per-cache slab details)
  are not exported by the web API today, but because LKL is in-process
  they are directly inspectable via GDB.
- **Per-syscall audit trail**: in seccomp mode (the strongest-isolation
  tier, and the auto-mode default for shells, networking, and ASAN
  builds), every intercepted syscall passes through `kbox_dispatch_request`
  with a `clock_gettime` measurement before and after dispatch (~25ns
  overhead). The SSE event stream (`/api/events`) and JSON trace mode
  (`--trace-format json`) produce structured records of every dispatch
  decision: which syscall, which disposition (LKL forward, host CONTINUE,
  or emulated), and how long it took. Trap and rewrite modes do not
  currently emit these per-syscall records; agent frameworks that need
  a complete trail should pin `--syscall-mode=seccomp`. BPF-denied
  syscalls (`ptrace`, `bpf`, `reboot`, `init_module`, etc.) return
  `EPERM` before the supervisor sees them.
- **Real Linux semantics**: agents get Linux kernel semantics for VFS,
  ext4, and procfs via LKL, not a userspace syscall reimplementation.
  Compilers, package managers, and test harnesses see real kernel
  behavior. This eliminates a class of agent failures where the tool
  works on a developer machine but breaks in the sandbox because the
  sandbox's syscall emulation is incomplete.
- **Low per-call overhead**: in-process LKL boot, no VM or container
  daemon. The `auto` mode selects the fastest interception tier per
  command: trap/rewrite for direct binaries (~3us stat on aarch64,
  ~1.4x faster `lseek+read` on x86_64 vs seccomp), seccomp for shell
  pipelines. Short-lived tool calls complete without amortizing
  multi-second startup costs that dominate agent latency budgets.
- **Programmable dispatch point**: the unified dispatch engine is the
  natural insertion point for future per-agent policy (path allowlists,
  socket rules, syscall quotas). All three interception tiers share
  this path. The underlying request abstraction (`kbox_syscall_request`)
  already decouples policy decisions from the notification transport,
  but no user-facing policy hook exists yet.
- **Deterministic initial rootfs**: the ext4 disk image provides a known
  starting state. For reproducible agent evaluation, mount read-only or
  clone the image per run; the default mount is read-write. Combined
  with `--syscall-mode=seccomp` (strongest isolation) and a fixed kernel
  cmdline, this gives repeatable initial conditions for benchmark
  comparisons across agent runs.

## Recommended agent deployment

```
host -> [outer boundary] -> kbox -> agent tool process
```

For trusted tool execution (compilation, linting, unit tests), kbox
alone is sufficient. For untrusted or adversarial inputs, wrap kbox in a
namespace jail (`bwrap --unshare-all`) or a microVM. The outer boundary
provides the security guarantee; kbox provides Linux semantics and
observability inside it.

## Observability for agent frameworks

The observability endpoints (`/api/snapshot`, `/api/events`, `/api/enosys`)
expose telemetry that agent orchestrators can consume directly:

| What to monitor | Endpoint | Why it matters |
|----------------|----------|---------------|
| Syscall rate by family | `/api/snapshot` | Detect runaway loops (e.g., agent stuck in open/close cycle) |
| ENOSYS hit counts | `/api/enosys` | Identify unsupported syscalls the guest binary needs |
| Kernel memory pressure | `/api/snapshot` | Catch OOM before the guest is killed |
| Per-call latency | `/api/events` (SSE) | Profile tool-call overhead for agent cost budgeting |

See [web-observatory.md](web-observatory.md) for the dashboard and full
endpoint reference.
