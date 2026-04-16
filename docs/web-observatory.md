# Web-based kernel observatory

The kernel runs in the same address space as the supervisor. Every data
structure (scheduler runqueues, page cache state, VFS dentries, slab
allocator metadata) is directly readable, either via the web telemetry
sampler or via GDB. kbox exploits this by sampling LKL's internal
`/proc` files and streaming the data to a browser dashboard.

This is not `strace`. `strace` shows syscall arguments and return values
from the outside. The web observatory shows guest-kernel counters that
`strace` cannot reach: context switches accumulating, memory pressure
rising, softirq totals climbing, ENOSYS hits piling up.

Note: the dashboard is currently driven by the seccomp supervisor, so it
works in seccomp mode (`--syscall-mode=seccomp`, the auto default for
shells and `--net`). Trap and rewrite modes do not yet drive the sampler
or emit per-syscall events.

Traditional kernel observation requires root (ftrace, perf), serial
connections (KGDB), or kernel recompilation (printk). LKL eliminates all
of these barriers. The supervisor calls `kbox_lkl_openat("/proc/stat")`
and reads LKL's own procfs (not the host's) from an unprivileged
process.

## Usage

```bash
# Build with web support
make KBOX_HAS_WEB=1 BUILD=release

# Launch with observatory on default port 8080
./kbox -S alpine.ext4 --web -- /bin/sh -i

# Custom port and bind address (e.g., access from outside a VM)
./kbox -S alpine.ext4 --web=9090 --web-bind 0.0.0.0 -- /bin/sh -i

# JSON trace to stderr without HTTP server
./kbox -S alpine.ext4 --trace-format json -- /bin/ls /
```

Open `http://127.0.0.1:8080/` in a browser. The dashboard shows:

- **Syscall activity**: stacked time-series of dispatch rate by family
  (file I/O, directory, FD ops, identity, memory, signals, scheduler).
  Computed as deltas between 3-second polling intervals.
- **Memory**: stacked area chart of LKL kernel memory breakdown (free,
  buffers, cached, slab, used) read from `/proc/meminfo`.
- **Scheduler**: context switch rate from `/proc/stat` and load average
  from `/proc/loadavg`.
- **Interrupts**: per-type softirq totals (TIMER, NET_RX, NET_TX, BLOCK,
  SCHED, etc.) parsed from the `softirq` line in `/proc/stat`.
- **Event feed**: scrolling SSE stream of individual syscall dispatches
  with per-call latency, color-coded by disposition, filterable,
  click-to-expand.
- **System gauges**: SVG arc gauges for syscalls/s, context switches/s,
  memory pressure, FD table occupancy.

## API endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Dashboard SPA (compiled-in HTML/JS/CSS via `xxd -i`) |
| `/api/snapshot` | GET | Current telemetry snapshot (JSON) |
| `/api/events` | GET | SSE stream of dispatch events |
| `/api/history` | GET | Historical snapshots for chart backfill |
| `/api/enosys` | GET | Per-syscall-number ENOSYS hit counts |
| `/stats` | GET | Quick health summary |
| `/api/control` | POST | Pause/resume telemetry sampling |

All frontend assets (Chart.js, vanilla JS, CSS) are compiled into the
binary at build time: no CDN, no npm, no runtime file I/O. When
neither `--web` nor `--trace-format json` is passed, the observability
subsystem is completely inert. With web telemetry or JSON tracing
enabled, dispatch instrumentation in seccomp mode adds ~25ns overhead
per intercepted syscall. The sampler runs on the seccomp supervisor's
100ms poll loop, and the event ring keeps 1024 entries split into 768
routine slots plus 256 reserved error/rare-event slots.

For implementation details (telemetry context, event ring sizing,
sampling strategy), see [architecture.md](architecture.md#web-observatory-implementation).
