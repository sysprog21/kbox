# Security model

kbox reduces the host kernel attack surface via seccomp BPF filtering and
routes filesystem and networking syscalls through LKL rather than the host.
Performance-critical operations like `mmap`, `futex`, `brk`, and `epoll`
still execute on the host kernel. Over 50 dangerous syscalls (`reboot`,
`init_module`, `bpf`, `ptrace`, `pivot_root`, the new mount API
`fsmount`/`move_mount`, etc.) are rejected with `EPERM` in the BPF
filter before reaching the supervisor. Classic `mount(2)` is intercepted
and routed to LKL's VFS rather than denied outright.

Path translation blocks escape attempts on LKL-routed filesystem paths
(`..` traversal, `/proc/self/root`, symlink tricks). Host-routed
pseudo-filesystems (`/proc`, `/sys`, `/dev`) remain governed by the host
kernel and BPF policy. W^X enforcement prevents simultaneous
`PROT_WRITE|PROT_EXEC` in guest memory.

However, seccomp filtering is a [building block for sandboxes, not a
sandbox itself](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html).
kbox runs LKL and the supervisor in the same address space as the guest
(especially in trap/rewrite mode). This design delivers low overhead and
deep observability, but it means a memory-safety bug in the dispatch path
or LKL could be exploitable by a crafted guest binary.

## Deployment tiers

Three deployment tiers, in ascending isolation strength:

| Tier | Threat model | Setup |
|------|-------------|-------|
| kbox alone | Trusted/semi-trusted code: build tools, test suites, static analysis, research, teaching | `./kbox -S rootfs.ext4 -- /bin/sh -i` |
| kbox + namespace/LSM | Agent tool execution with defense-in-depth: CI runners, automated code review | Wrap with `bwrap`, Landlock, or cgroup limits (adds containment and resource controls, not hardware isolation) |
| outer sandbox + kbox | Untrusted code, multi-tenant: hostile payloads, student submissions, public-facing agent APIs | Run kbox inside a microVM (Firecracker, Cloud Hypervisor) for hardware-enforced isolation, or inside gVisor for userspace-kernel isolation |

kbox is designed as an inner-layer sandbox. For hostile code containment,
pair it with an outer isolation boundary. Only microVMs provide
hardware-enforced address space separation; gVisor and namespace jails
reduce the attack surface without hardware isolation.
