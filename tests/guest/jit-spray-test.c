/* SPDX-License-Identifier: MIT */
/* Guest test: validate the current JIT-spray boundary in trap/rewrite mode.
 *
 * This is intentionally scoped to what kbox enforces today:
 *   - deny mmap(PROT_WRITE|PROT_EXEC)
 *   - deny mprotect(..., PROT_WRITE|PROT_EXEC)
 *   - allow clean RW -> RX transitions
 *   - deny runtime-emitted syscall-wrapper code at RW -> RX promotion time
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
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

#if defined(__aarch64__)
static size_t emit_getpid_wrapper(unsigned char *buf)
{
    uint32_t movz = 0xd2800008u | (((uint32_t) SYS_getpid & 0xffffu) << 5);
    uint32_t svc = 0xd4000001u;
    uint32_t ret = 0xd65f03c0u;

    CHECK(buf != NULL, "wrapper buffer");
    memcpy(buf + 0, &movz, sizeof(movz));
    memcpy(buf + 4, &svc, sizeof(svc));
    memcpy(buf + 8, &ret, sizeof(ret));
    return 12;
}
#elif defined(__x86_64__)
static size_t emit_getpid_wrapper(unsigned char *buf)
{
    uint32_t nr = (uint32_t) SYS_getpid;

    CHECK(buf != NULL, "wrapper buffer");
    buf[0] = 0xb8;
    memcpy(buf + 1, &nr, sizeof(nr));
    buf[5] = 0x0f;
    buf[6] = 0x05;
    buf[7] = 0xc3;
    return 8;
}
#endif

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

#if defined(__aarch64__) || defined(__x86_64__)
    {
        unsigned char *code =
            mmap(NULL, (size_t) page_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

        CHECK(code != MAP_FAILED, "wrapper RW mmap should succeed");
        // cppcheck-suppress nullPointerOutOfMemory
        memset(code, 0x90, (size_t) page_size);
        (void) emit_getpid_wrapper(code);
        __builtin___clear_cache((char *) code, (char *) code + page_size);
        errno = 0;
        expect_errno_int(
            mprotect(code, (size_t) page_size, PROT_READ | PROT_EXEC), EACCES,
            "wrapper RW->RX mprotect should be denied");
        (void) munmap(code, (size_t) page_size);
    }
#endif

    printf("PASS: jit_spray_boundary\n");
    return 0;
}
