/* SPDX-License-Identifier: MIT */
/* Guest probe: check whether shared-file executable aliases are blocked under
 * trap/rewrite mode.
 *
 * This covers both direct shared executable mappings and executable promotion
 * through a second alias of the same backing object.
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
    void *ro_map;
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

    ro_map = mmap(NULL, (size_t) page_size, PROT_READ, MAP_SHARED, fd, 0);
    if (ro_map == MAP_FAILED)
        fail_now("FAIL: shared RO alias mmap\n");

    errno = 0;
    rc = mprotect(ro_map, (size_t) page_size, PROT_READ | PROT_EXEC);
    if (rc == 0)
        fail_now("FAIL: jit_alias_shared_exec_mprotect_allowed\n");
    CHECK(errno == EACCES, "shared alias RX mprotect should fail with EACCES");
    (void) munmap(ro_map, (size_t) page_size);

    errno = 0;
    ro_map = mmap(NULL, (size_t) page_size, PROT_READ | PROT_EXEC, MAP_SHARED,
                  fd, 0);
    if (ro_map == MAP_FAILED) {
        mmap_errno = errno;
        CHECK(mmap_errno == EACCES, "shared RX mmap should fail with EACCES");
        printf("PASS: jit_alias_blocked mmap_errno=%d mprotect_errno=%d\n",
               mmap_errno, EACCES);
        munmap(rw, (size_t) page_size);
        close(fd);
        return 0;
    }
    // cppcheck-suppress nullPointerOutOfMemory
    memset(rw, 0, (size_t) page_size);
    fill_pattern(rw, (size_t) page_size);
    fail_now("FAIL: jit_alias_shared_exec_mmap_allowed\n");
}
