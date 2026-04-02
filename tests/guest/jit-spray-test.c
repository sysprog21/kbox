/* SPDX-License-Identifier: MIT */
/* Guest test: validate the current JIT-spray boundary in trap/rewrite mode.
 *
 * This is intentionally scoped to what kbox enforces today:
 *   - deny mmap(PROT_WRITE|PROT_EXEC)
 *   - deny mprotect(..., PROT_WRITE|PROT_EXEC)
 *   - allow RW -> RX transitions (scan-on-X is not implemented yet)
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define CHECK(cond, msg)                                    \
    do {                                                    \
        if (!(cond)) {                                      \
            fprintf(stderr, "FAIL: %s (%s)\n", msg, #cond); \
            exit(1);                                        \
        }                                                   \
    } while (0)

static void expect_errno_ptr(void *ptr, int expected_errno, const char *what)
{
    CHECK(ptr == MAP_FAILED, what);
    CHECK(errno == expected_errno, what);
}

static void expect_errno_int(int rc, int expected_errno, const char *what)
{
    CHECK(rc < 0, what);
    CHECK(errno == expected_errno, what);
}

int main(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    void *page;

    CHECK(page_size > 0, "page size must be positive");

    errno = 0;
    {
        void *rwx_map;

        rwx_map =
            mmap(NULL, (size_t) page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        expect_errno_ptr(rwx_map, EACCES,
                         "anonymous RWX mmap should be denied");
    }

    {
        page = mmap(NULL, (size_t) page_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    }
    CHECK(page != MAP_FAILED, "anonymous RW mmap should succeed");

    errno = 0;
    expect_errno_int(
        mprotect(page, (size_t) page_size, PROT_READ | PROT_WRITE | PROT_EXEC),
        EACCES, "RWX mprotect should be denied");

    memset(page, 0x90, (size_t) page_size);
    CHECK(mprotect(page, (size_t) page_size, PROT_READ | PROT_EXEC) == 0,
          "RW->RX mprotect should succeed");
    (void) munmap(page, (size_t) page_size);

    printf("PASS: jit_spray_boundary\n");
    return 0;
}
