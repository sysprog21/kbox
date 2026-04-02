/* SPDX-License-Identifier: MIT */

/* Process memory access for seccomp-unotify.
 *
 * Wraps process_vm_readv/writev to read/write tracee memory without ptrace.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include "procmem.h"

static inline pid_t guest_pid(const struct kbox_guest_mem *guest)
{
    return (pid_t) guest->opaque;
}

/* Fault-tolerant direct memory access for in-process (trap/rewrite) mode.
 *
 * In trap/rewrite mode the guest shares the supervisor's address space.
 * Guest-provided addresses are directly dereferenceable via memcpy, which
 * is ~10x faster than pread(/proc/self/mem) or process_vm_readv.  However,
 * a guest can pass an unmapped address.  Rather than crashing the supervisor,
 * we install a SIGSEGV/SIGBUS handler that longjmps back to the caller
 * with -EFAULT.
 *
 * The handler is installed once and stays persistent.  A generation counter
 * tracks guest rt_sigaction(SIGSEGV/SIGBUS) calls; safe_memcpy reinstalls
 * only when the generation changes.  The guest's prior handler is saved
 * and forwarded to when the fault is not from safe_memcpy (fault_armed=0).
 *
 * Thread safety: the jmp_buf is thread-local.  The single-threaded guest
 * constraint (CLONE_THREAD returns ENOSYS) ensures safe_memcpy and guest
 * rt_sigaction are serialized through the same service thread dispatch.
 */
static __thread sigjmp_buf fault_jmp;
static __thread volatile sig_atomic_t fault_armed;

/* Generation counter: bumped by kbox_procmem_signal_changed() whenever
 * a guest rt_sigaction(SIGSEGV/SIGBUS) is dispatched.  safe_memcpy
 * reinstalls the handler only when the generation changes, avoiding
 * 4 sigaction syscalls per call on the hot path.
 */
static volatile unsigned fault_handler_gen =
    1; /* Start at 1 so first call installs */
static __thread unsigned
    fault_handler_local_gen; /* Thread-local starts at 0 → mismatch */

/* Saved guest handlers: when kbox installs its fault handler, the guest's
 * prior handlers are preserved here and forwarded to when fault_armed is 0.
 */
static struct sigaction saved_guest_segv;
static struct sigaction saved_guest_bus;

static void fault_handler(int sig, siginfo_t *info, void *ucontext);

static void restore_default_and_reraise(int sig)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
    raise(sig);
}

static int action_uses_fault_handler(const struct sigaction *sa)
{
    const void *fault_handler_ptr = (const void *) (uintptr_t) &fault_handler;

    if (!sa)
        return 0;
    if ((sa->sa_flags & SA_SIGINFO) != 0)
        return sa->sa_sigaction == fault_handler;
    return (const void *) (uintptr_t) sa->sa_handler == fault_handler_ptr;
}

static void fault_handler(int sig, siginfo_t *info, void *ucontext)
{
    if (fault_armed)
        siglongjmp(fault_jmp, 1);

    /* Not our fault -- forward to the guest's handler if one was saved. */
    const struct sigaction *guest =
        (sig == SIGSEGV) ? &saved_guest_segv : &saved_guest_bus;
    if ((guest->sa_flags & SA_SIGINFO) != 0 && guest->sa_sigaction) {
        guest->sa_sigaction(sig, info, ucontext);
        return;
    }
    if (guest->sa_handler == SIG_IGN)
        return;
    if (guest->sa_handler != SIG_DFL) {
        guest->sa_handler(sig);
        return;
    }
    restore_default_and_reraise(sig);
}

static void install_fault_handler(void)
{
    struct sigaction old_segv;
    struct sigaction old_bus;
    struct sigaction sa;

    memset(&old_segv, 0, sizeof(old_segv));
    memset(&old_bus, 0, sizeof(old_bus));
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);
    if (!action_uses_fault_handler(&old_segv))
        saved_guest_segv = old_segv;
    if (!action_uses_fault_handler(&old_bus))
        saved_guest_bus = old_bus;
    fault_handler_local_gen = fault_handler_gen;
}

void kbox_procmem_signal_changed(void)
{
    __atomic_add_fetch(&fault_handler_gen, 1, __ATOMIC_RELEASE);
}

/* Hot path: sigsetjmp + memcpy only (no sigaction syscalls).  The fault
 * handler is installed once and reinstalled only when the guest modifies
 * SIGSEGV/SIGBUS via rt_sigaction.  The guest's prior handler is saved
 * and forwarded to for non-memcpy faults.
 */
static int safe_memcpy(void *dst, const void *src, size_t len)
{
    unsigned gen = __atomic_load_n(&fault_handler_gen, __ATOMIC_ACQUIRE);

    if (gen != fault_handler_local_gen)
        install_fault_handler();

    if (sigsetjmp(fault_jmp, 0) != 0) {
        fault_armed = 0;
        return -EFAULT;
    }
    fault_armed = 1;

    memcpy(dst, src, len);
    fault_armed = 0;
    return 0;
}

int kbox_current_read(uint64_t remote_addr, void *out, size_t len)
{
    if (len == 0)
        return 0;
    if (remote_addr == 0 || !out)
        return -EFAULT;
    return safe_memcpy(out, (const void *) (uintptr_t) remote_addr, len);
}

int kbox_current_write(uint64_t remote_addr, const void *in, size_t len)
{
    if (len == 0)
        return 0;
    if (remote_addr == 0 || !in)
        return -EFAULT;
    return safe_memcpy((void *) (uintptr_t) remote_addr, in, len);
}

int kbox_current_write_force(uint64_t remote_addr, const void *in, size_t len)
{
    static const char proc_self_mem[] = "/proc/self/mem";
    int fd;
    ssize_t n;

    if (len == 0)
        return 0;
    if (remote_addr == 0 || !in)
        return -EFAULT;

    fd = open(proc_self_mem, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;

    n = pwrite(fd, in, len, (off_t) remote_addr);
    if (n < 0) {
        int saved_errno = errno;
        close(fd);
        return -saved_errno;
    }
    close(fd);

    if ((size_t) n != len)
        return -EIO;
    return 0;
}

int kbox_current_read_string(uint64_t remote_addr, char *buf, size_t max_len)
{
    const char *src;

    if (remote_addr == 0)
        return -EFAULT;
    if (!buf)
        return -EFAULT;
    if (max_len == 0)
        return -EINVAL;
    if (max_len > (size_t) INT_MAX)
        max_len = (size_t) INT_MAX;

    src = (const char *) (uintptr_t) remote_addr;

    {
        unsigned gen = __atomic_load_n(&fault_handler_gen, __ATOMIC_ACQUIRE);

        if (gen != fault_handler_local_gen)
            install_fault_handler();

        if (sigsetjmp(fault_jmp, 0) != 0) {
            fault_armed = 0;
            return -EFAULT;
        }
        fault_armed = 1;

        for (size_t i = 0; i < max_len; i++) {
            buf[i] = src[i];
            if (buf[i] == '\0') {
                fault_armed = 0;
                return (int) i;
            }
        }
        fault_armed = 0;
    }

    buf[0] = '\0';
    return -ENAMETOOLONG;
}

int kbox_current_read_open_how(uint64_t remote_addr,
                               uint64_t size,
                               struct kbox_open_how *out)
{
    uint64_t expected = (uint64_t) sizeof(struct kbox_open_how);

    if (remote_addr == 0)
        return -EFAULT;
    if (size < expected)
        return -EINVAL;
    if (size > expected)
        return -E2BIG;

    memset(out, 0, sizeof(*out));
    return kbox_current_read(remote_addr, out, sizeof(*out));
}

int kbox_vm_read(pid_t pid, uint64_t remote_addr, void *out, size_t len)
{
    struct iovec local_iov;
    struct iovec remote_iov;
    ssize_t ret;

    if (len == 0)
        return 0;
    if (remote_addr == 0 || !out)
        return -EFAULT;

    local_iov.iov_base = out;
    local_iov.iov_len = len;
    remote_iov.iov_base = (void *) (uintptr_t) remote_addr;
    remote_iov.iov_len = len;

    ret = syscall(SYS_process_vm_readv, pid, &local_iov, 1, &remote_iov, 1, 0);
    if (ret < 0)
        return -errno;
    if ((size_t) ret != len)
        return -EIO;
    return 0;
}

int kbox_vm_write(pid_t pid, uint64_t remote_addr, const void *in, size_t len)
{
    struct iovec local_iov;
    struct iovec remote_iov;
    ssize_t ret;

    if (len == 0)
        return 0;
    if (remote_addr == 0 || !in)
        return -EFAULT;

    /* process_vm_writev takes a non-const iov_base, but we only read from the
     * local buffer. The cast is safe.
     */
    local_iov.iov_base = (void *) (uintptr_t) in;
    local_iov.iov_len = len;
    remote_iov.iov_base = (void *) (uintptr_t) remote_addr;
    remote_iov.iov_len = len;

    ret = syscall(SYS_process_vm_writev, pid, &local_iov, 1, &remote_iov, 1, 0);
    if (ret < 0)
        return -errno;
    if ((size_t) ret != len)
        return -EIO;
    return 0;
}

int kbox_vm_read_string(pid_t pid,
                        uint64_t remote_addr,
                        char *buf,
                        size_t max_len)
{
    struct iovec local_iov;
    struct iovec remote_iov;
    size_t total = 0;

    enum {
        KBOX_STRING_READ_CHUNK = 256,
    };

    if (remote_addr == 0)
        return -EFAULT;
    if (max_len == 0)
        return -EINVAL;

    while (total < max_len) {
        ssize_t n;
        size_t i;
        size_t chunk = max_len - total;

        if (chunk > KBOX_STRING_READ_CHUNK)
            chunk = KBOX_STRING_READ_CHUNK;

        local_iov.iov_base = buf + total;
        local_iov.iov_len = chunk;
        remote_iov.iov_base =
            (void *) (uintptr_t) (remote_addr + (uint64_t) total);
        remote_iov.iov_len = chunk;

        n = syscall(SYS_process_vm_readv, pid, &local_iov, 1, &remote_iov, 1,
                    0);
        if (n <= 0)
            return errno ? -errno : -EIO;

        for (i = 0; i < (size_t) n; i++) {
            if (buf[total + i] == '\0')
                return (int) (total + i);
        }

        total += (size_t) n;

        /* Short read before NUL means the next page isn't readable. */
        if ((size_t) n < chunk)
            return -EFAULT;
    }

    if (max_len > 0)
        buf[0] = '\0';
    return -ENAMETOOLONG;
}

int kbox_vm_read_open_how(pid_t pid,
                          uint64_t remote_addr,
                          uint64_t size,
                          struct kbox_open_how *out)
{
    uint64_t expected = (uint64_t) sizeof(struct kbox_open_how);

    if (remote_addr == 0)
        return -EFAULT;
    if (size < expected)
        return -EINVAL;
    if (size > expected)
        return -E2BIG;

    memset(out, 0, sizeof(*out));
    return kbox_vm_read(pid, remote_addr, out, sizeof(*out));
}

int kbox_vm_write_force(pid_t pid,
                        uint64_t remote_addr,
                        const void *in,
                        size_t len)
{
    char proc_path[64];
    int fd;
    ssize_t n;

    if (len == 0)
        return 0;
    if (remote_addr == 0 || !in)
        return -EFAULT;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/mem", (int) pid);
    fd = open(proc_path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;

    n = pwrite(fd, in, len, (off_t) remote_addr);
    if (n < 0) {
        int saved_errno = errno;
        close(fd);
        return -saved_errno;
    }
    close(fd);
    if ((size_t) n != len)
        return -EIO;
    return 0;
}

static int process_vm_guest_read(const struct kbox_guest_mem *guest,
                                 uint64_t remote_addr,
                                 void *out,
                                 size_t len)
{
    return kbox_vm_read(guest_pid(guest), remote_addr, out, len);
}

static int process_vm_guest_write(const struct kbox_guest_mem *guest,
                                  uint64_t remote_addr,
                                  const void *in,
                                  size_t len)
{
    return kbox_vm_write(guest_pid(guest), remote_addr, in, len);
}

static int process_vm_guest_write_force(const struct kbox_guest_mem *guest,
                                        uint64_t remote_addr,
                                        const void *in,
                                        size_t len)
{
    return kbox_vm_write_force(guest_pid(guest), remote_addr, in, len);
}

static int process_vm_guest_read_string(const struct kbox_guest_mem *guest,
                                        uint64_t remote_addr,
                                        char *buf,
                                        size_t max_len)
{
    return kbox_vm_read_string(guest_pid(guest), remote_addr, buf, max_len);
}

static int process_vm_guest_read_open_how(const struct kbox_guest_mem *guest,
                                          uint64_t remote_addr,
                                          uint64_t size,
                                          struct kbox_open_how *out)
{
    return kbox_vm_read_open_how(guest_pid(guest), remote_addr, size, out);
}

static int current_guest_read(const struct kbox_guest_mem *guest,
                              uint64_t remote_addr,
                              void *out,
                              size_t len)
{
    (void) guest;
    return kbox_current_read(remote_addr, out, len);
}

static int current_guest_write(const struct kbox_guest_mem *guest,
                               uint64_t remote_addr,
                               const void *in,
                               size_t len)
{
    (void) guest;
    return kbox_current_write(remote_addr, in, len);
}

static int current_guest_write_force(const struct kbox_guest_mem *guest,
                                     uint64_t remote_addr,
                                     const void *in,
                                     size_t len)
{
    (void) guest;
    return kbox_current_write_force(remote_addr, in, len);
}

static int current_guest_read_string(const struct kbox_guest_mem *guest,
                                     uint64_t remote_addr,
                                     char *buf,
                                     size_t max_len)
{
    (void) guest;
    return kbox_current_read_string(remote_addr, buf, max_len);
}

static int current_guest_read_open_how(const struct kbox_guest_mem *guest,
                                       uint64_t remote_addr,
                                       uint64_t size,
                                       struct kbox_open_how *out)
{
    (void) guest;
    return kbox_current_read_open_how(remote_addr, size, out);
}

const struct kbox_guest_mem_ops kbox_process_vm_guest_mem_ops = {
    .read = process_vm_guest_read,
    .write = process_vm_guest_write,
    .write_force = process_vm_guest_write_force,
    .read_string = process_vm_guest_read_string,
    .read_open_how = process_vm_guest_read_open_how,
};

const struct kbox_guest_mem_ops kbox_current_guest_mem_ops = {
    .read = current_guest_read,
    .write = current_guest_write,
    .write_force = current_guest_write_force,
    .read_string = current_guest_read_string,
    .read_open_how = current_guest_read_open_how,
};

int kbox_guest_mem_read(const struct kbox_guest_mem *guest,
                        uint64_t remote_addr,
                        void *out,
                        size_t len)
{
    if (!guest || !guest->ops || !guest->ops->read)
        return -EINVAL;
    return guest->ops->read(guest, remote_addr, out, len);
}

int kbox_guest_mem_write(const struct kbox_guest_mem *guest,
                         uint64_t remote_addr,
                         const void *in,
                         size_t len)
{
    if (!guest || !guest->ops || !guest->ops->write)
        return -EINVAL;
    return guest->ops->write(guest, remote_addr, in, len);
}

int kbox_guest_mem_write_force(const struct kbox_guest_mem *guest,
                               uint64_t remote_addr,
                               const void *in,
                               size_t len)
{
    if (!guest || !guest->ops || !guest->ops->write_force)
        return -EINVAL;
    return guest->ops->write_force(guest, remote_addr, in, len);
}

int kbox_guest_mem_read_string(const struct kbox_guest_mem *guest,
                               uint64_t remote_addr,
                               char *buf,
                               size_t max_len)
{
    if (!guest || !guest->ops || !guest->ops->read_string)
        return -EINVAL;
    return guest->ops->read_string(guest, remote_addr, buf, max_len);
}

int kbox_guest_mem_read_open_how(const struct kbox_guest_mem *guest,
                                 uint64_t remote_addr,
                                 uint64_t size,
                                 struct kbox_open_how *out)
{
    if (!guest || !guest->ops || !guest->ops->read_open_how)
        return -EINVAL;
    return guest->ops->read_open_how(guest, remote_addr, size, out);
}
