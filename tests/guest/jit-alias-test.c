/* SPDX-License-Identifier: MIT */
/* Guest probe: check whether a shared RW/RX alias of the same backing object
 * is possible under trap/rewrite mode.
 *
 * This is a boundary probe for the still-open per-object W^X gap. It is not
 * wired into default integration because the current expected outcome is host
 * and implementation dependent while the mitigation remains incomplete.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define CHECK(cond, msg)                        \
    do {                                        \
        if (!(cond)) {                          \
            fprintf(stderr, "FAIL: %s\n", msg); \
            exit(1);                            \
        }                                       \
    } while (0)

static void fail_now(const char *msg)
{
    size_t len;
    ssize_t written;

    CHECK(msg != NULL, "failure message must not be null");
    len = strlen(msg);
    if (len > 0) {
        written = write(STDERR_FILENO, msg, len);
        (void) written;
    }
    _exit(1);
}

static void fill_pattern(unsigned char *buf, size_t len)
{
    CHECK(buf != NULL && len > 0, "pattern buffer too small");
    memset(buf, 0xa5, len);
}

int main(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    char path[] = "/tmp/jit-alias-XXXXXX";
    void *rw_map;
    void *rx_map;
    unsigned char *rw;
    int fd;
    int mmap_errno;
    int rc;

    CHECK(page_size > 0, "page size must be positive");

    fd = mkstemp(path);
    CHECK(fd >= 0, "mkstemp");
    unlink(path);
    CHECK(ftruncate(fd, page_size) == 0, "ftruncate");

    rw_map = mmap(NULL, (size_t) page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                  fd, 0);
    if (rw_map == MAP_FAILED) {
        fprintf(stderr, "FAIL: shared RW mmap\n");
        close(fd);
        return 1;
    }
    rw = rw_map;

    errno = 0;
    rx_map = mmap(NULL, (size_t) page_size, PROT_READ | PROT_EXEC, MAP_SHARED,
                  fd, 0);
    if (rx_map == MAP_FAILED) {
        mmap_errno = errno;
        errno = 0;
        rc = mprotect(rw, (size_t) page_size, PROT_READ | PROT_EXEC);
        if (rc == 0)
            fail_now("FAIL: jit_alias_shared_exec_mprotect_allowed\n");
        printf("PASS: jit_alias_blocked mmap_errno=%d mprotect_errno=%d\n",
               mmap_errno, errno);
        munmap(rw, (size_t) page_size);
        close(fd);
        return 0;
    }
    // cppcheck-suppress nullPointerOutOfMemory
    memset(rw, 0, (size_t) page_size);
    fill_pattern(rw, (size_t) page_size);
    fail_now("FAIL: jit_alias_shared_exec_mmap_allowed\n");
}
