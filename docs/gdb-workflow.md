# GDB Debugging Workflow for kbox + LKL

kbox boots the Linux kernel as a userspace library (LKL). When LKL
is built with CONFIG_DEBUG_INFO, the entire kernel lives in the same
address space as kbox. GDB can set breakpoints on kernel functions,
inspect task_struct fields, and read kernel memory -- no QEMU, no
KGDB, no serial cables.

## Prerequisites

- kbox built with debug symbols (`make BUILD=debug`)
- LKL vmlinux with DWARF debug info
- GDB 7.2+ with Python support
- LKL scripts/gdb/ directory (for upstream helpers)

## Quick Start

```bash
# Terminal 1: start kbox under GDB
cd /path/to/kbox
gdb ./kbox

# Inside GDB:
(gdb) add-symbol-file /path/to/lkl/vmlinux
(gdb) source scripts/gdb/kbox-gdb.py
(gdb) kbox-lkl-load /path/to/lkl
(gdb) set args -S rootfs.ext4 -- /bin/sh
(gdb) run
```

## Loading Helpers

kbox provides two sets of GDB helpers:

### kbox-gdb.py (kbox-specific)

```
source scripts/gdb/kbox-gdb.py
```

Commands:
- `kbox-fdtable` -- print the virtual FD table (low_fds + high entries)
- `kbox-break-syscall NR` -- break when syscall number NR is dispatched
- `kbox-ctx` -- print supervisor context (listener_fd, child_pid, etc.)
- `kbox-syscall-trace` -- trace seccomp dispatch -> LKL syscall path
- `kbox-vfs-path PATH` -- simulate guest path translation
- `kbox-task-walk` -- walk LKL task list with tracee PID correlation
- `kbox-mem-check` -- inspect LKL buddy allocator and slab caches

### Upstream vmlinux-gdb.py (LKL kernel)

LKL lacks module support, so the upstream vmlinux-gdb.py fails on
the MOD_TEXT symbol. The `kbox-lkl-load` command patches this:

```
(gdb) kbox-lkl-load /path/to/lkl
```

This enables:
- `lx-dmesg` -- dump LKL kernel ring buffer
- `lx-ps` -- list all LKL kernel tasks with PIDs and states
- `lx-version` -- print LKL kernel version string

## Debugging Scenarios

### 1. Trace a syscall end-to-end

Set a conditional breakpoint on a specific syscall number:

```
(gdb) kbox-break-syscall 257    # openat
(gdb) continue
```

When the breakpoint fires, examine the notification:

```
(gdb) print notif_ptr->data.nr        # host syscall number
(gdb) print notif_ptr->data.args[0]   # dirfd
(gdb) print notif_ptr->data.args[1]   # pathname (guest address)
(gdb) print notif_ptr->pid            # tracee PID
```

Step into the LKL kernel:

```
(gdb) break do_sys_openat2
(gdb) continue
# Now inside the real kernel VFS path
(gdb) print filename->name
(gdb) bt
```

### 2. Inspect the FD table during I/O

Break inside a dispatch function:

```
(gdb) break forward_read_like
(gdb) continue
(gdb) kbox-fdtable
```

Output shows both low FD redirects (dup2 targets, FDs 0-1023) and
high range entries (>= 32768), including host shadow FDs:

```
FD Table (next_fd=32770):
     VFD    LKL_FD   HOST_FD   TTY  CLOEXEC
-------------------------------------------
       1         3        -1     0        0
   32768         0        14     0        0
   32769         1        -1     1        0
```

### 3. Examine LKL kernel memory

After hitting any breakpoint during execution:

```
(gdb) kbox-mem-check
```

Shows buddy allocator free pages per order, all slab caches with
object sizes, and memory pressure (used percentage).

### 4. Walk the kernel task list

```
(gdb) kbox-task-walk
```

Shows all LKL kernel tasks with states (RUNNING, INTERRUPTIBLE,
IDLE) and correlates PID 1 with the kbox tracee TID:

```
   PID             STATE              COMM  TRACEE TID
     0           RUNNING           swapper
     1   UNINTERRUPTIBLE             host0  <-> 12345 (tracee)
     2     INTERRUPTIBLE          kthreadd
     9     INTERRUPTIBLE       ksoftirqd/0
    16     INTERRUPTIBLE           kswapd0
```

### 5. Debug path translation

```
(gdb) kbox-vfs-path /proc/../etc/shadow
```

Shows normalization, virtual path detection, and escape checking:

```
Path analysis: '/proc/../etc/shadow'
  mode: image
  normalized: '/proc/../etc/shadow' -> '/etc/shadow'
  resolved: /etc/shadow
  verdict: ACCEPT (image mode, pass through)
```

### 6. Read the LKL kernel log

```
(gdb) lx-dmesg
```

Full kernel boot log: memory initialization, driver probing,
filesystem mounting, network stack setup.

### 7. Inspect LKL scheduler state

```
(gdb) lx-ps
```

All kernel threads with PIDs: swapper, kthreadd, kswapd0,
ksoftirqd, kworkers, jbd2, ext4 journal threads.

## Architecture Notes

- Virtual paths (/proc, /sys, /dev) dispatch as CONTINUE -- the
  host kernel serves them. LKL's internal /proc is only accessible
  through GDB (lx-dmesg, lx-ps).
- Shadow FDs: O_RDONLY files get memfd shadows. The tracee holds
  the host memfd FD, while the FD table tracks both lkl_fd and
  host_fd. Use `kbox-fdtable` to see the mapping.
- Pipes use host kernel pipes via SECCOMP_IOCTL_NOTIF_ADDFD. No
  LKL involvement. They do NOT appear in the virtual FD table.
- Low FD redirects (dup2 to FDs 0-1023) are tracked in low_fds[].
  These are populated by dup2/dup3 for shell I/O redirections.

## Fork Mode

kbox forks a child (the tracee). GDB must follow the parent:

```
(gdb) set follow-fork-mode parent
(gdb) set detach-on-fork on
```

When running under GDB with ASAN, disable LSAN (incompatible with ptrace):

```bash
ASAN_OPTIONS=detect_leaks=0 gdb --args ./kbox -S alpine.ext4 -c /bin/sh
```

## Coordinated Syscall Tracing

The `kbox-syscall-trace` command sets breakpoints on three points:
1. `kbox_dispatch_syscall`: seccomp dispatch entry
2. `lkl_syscall`: LKL kernel entry
3. `lkl_syscall6`: LKL wrapper

On each hit, it prints the syscall number, decoded name, arguments,
virtual FD translation (if applicable), and LKL parameters:

```
(gdb) kbox-syscall-trace
Syscall trace active:
  dispatch bp #1 at kbox_dispatch_syscall
  LKL entry bp #2 at lkl_syscall
  LKL wrap  bp #3 at lkl_syscall6
Tracing will print on each hit. Use 'delete' to stop.
```

This traces the full path: seccomp notification -> kbox dispatch ->
LKL kernel (VFS/scheduler/net) -> result injection back to the tracee.

## Kernel Internals via GDB

Because LKL runs in-process, you can inspect kernel data structures
directly:

```
(gdb) print init_task.pid                      # PID 0 (swapper)
(gdb) print init_task.comm                     # "swapper"
(gdb) break do_sys_openat2                     # Break in kernel VFS
(gdb) break schedule                           # Break in scheduler
(gdb) break cpu_startup_entry                  # Break in idle loop
(gdb) print contig_page_data.node_zones[0]     # Zone info
```

## Scheduler Experiments (Educational)

After `kbox-lkl-load`, you can read and write scheduler parameters
through LKL's sysctl interface (if /proc/sys is mounted writable
inside the guest):

```
# Inside the guest shell:
cat /proc/sys/kernel/sched_base_slice_ns
echo 5000000 > /proc/sys/kernel/sched_base_slice_ns

# Or via GDB on kernel globals:
(gdb) print sysctl_sched_base_slice
# NOTE: kernel 6.6 uses EEVDF. The CFS-era knobs (sched_min_granularity_ns,
# sched_latency_ns, sched_wakeup_granularity_ns) no longer exist.
```

RT bandwidth capping prevents total starvation of non-RT tasks:
```
sysctl -w kernel.sched_rt_runtime_us=100000   # 10% RT bandwidth
```
