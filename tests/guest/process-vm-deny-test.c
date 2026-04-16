/* SPDX-License-Identifier: MIT */
/* Guest test: verify process_vm_readv is blocked by the seccomp BPF deny list.
 *
 * The guest has no legitimate need to read another process's address space.
 * kbox itself uses process_vm_readv in the supervisor -> child direction only.
 * The guest-side syscall must therefore fail with EPERM before reaching the
 * seccomp-unotify supervisor path.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#define CHECK(cond, msg)                                    \
    do {                                                    \
        if (!(cond)) {                                      \
            fprintf(stderr, "FAIL: %s (%s)\n", msg, #cond); \
            exit(1);                                        \
        }                                                   \
    } while (0)

int main(void)
{
    uint32_t src = 0x12345678u;
    uint32_t dst = 0;
    struct iovec local = {.iov_base = &dst, .iov_len = sizeof(dst)};
    struct iovec remote = {.iov_base = &src, .iov_len = sizeof(src)};
    long rc;

    errno = 0;
    rc = syscall(__NR_process_vm_readv, getpid(), &local, 1, &remote, 1, 0);
    CHECK(rc < 0, "process_vm_readv should fail");
    CHECK(errno == EPERM, "process_vm_readv errno should be EPERM");
    printf("PASS: process_vm_readv denied\n");
    return 0;
}
