/* SPDX-License-Identifier: MIT */

#include <errno.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string.h>

#include "procmem.h"
#include "test-runner.h"

static void test_current_guest_mem_read_write(void)
{
    char buf[16] = "hello";
    char out[16];

    memset(out, 0, sizeof(out));
    ASSERT_EQ(kbox_current_read((uint64_t) (uintptr_t) buf, out, 6), 0);
    ASSERT_STREQ(out, "hello");

    ASSERT_EQ(kbox_current_write((uint64_t) (uintptr_t) buf, "world", 6), 0);
    ASSERT_STREQ(buf, "world");
}

static void test_current_guest_mem_read_string(void)
{
    char buf[16];
    const char *src = "abc";

    memset(buf, 0, sizeof(buf));
    ASSERT_EQ(
        kbox_current_read_string((uint64_t) (uintptr_t) src, buf, sizeof(buf)),
        3);
    ASSERT_STREQ(buf, "abc");
}

static void test_current_guest_mem_ops_wrapper(void)
{
    char value[8] = "xyz";
    char out[8];
    struct kbox_guest_mem guest = {
        .ops = &kbox_current_guest_mem_ops,
        .opaque = 0,
    };

    memset(out, 0, sizeof(out));
    ASSERT_EQ(kbox_guest_mem_read(&guest, (uint64_t) (uintptr_t) value, out, 4),
              0);
    ASSERT_STREQ(out, "xyz");
}

static void test_current_guest_mem_rejects_bad_pointer(void)
{
    char out[8];

    ASSERT_EQ(kbox_current_read(0, out, sizeof(out)), -EFAULT);
    ASSERT_EQ(kbox_current_write(0, "x", 1), -EFAULT);
    ASSERT_EQ(kbox_current_read_string(0, out, sizeof(out)), -EFAULT);
    ASSERT_EQ(
        kbox_current_read_string((uint64_t) (uintptr_t) out, NULL, sizeof(out)),
        -EFAULT);
}

static void test_current_guest_mem_force_write_cross_page(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    char verify[4];
    char *mapping;

    ASSERT_TRUE(page_size > 0);
    mapping = mmap(NULL, (size_t) page_size * 2, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(mapping, MAP_FAILED);

    memcpy(mapping + page_size - 2, "xxxx", 4);
    ASSERT_EQ(mprotect(mapping, (size_t) page_size * 2, PROT_READ), 0);
    ASSERT_EQ(kbox_current_write_force(
                  (uint64_t) (uintptr_t) (mapping + page_size - 2), "ABCD", 4),
              0);
    ASSERT_EQ(
        kbox_current_read((uint64_t) (uintptr_t) (mapping + page_size - 2),
                          verify, sizeof(verify)),
        0);
    ASSERT_EQ(memcmp(verify, "ABCD", 4), 0);
    ASSERT_EQ(munmap(mapping, (size_t) page_size * 2), 0);
}

static void test_current_guest_mem_unmapped_pointer_returns_error(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    char *mapping;
    pid_t pid;
    int status = 0;

    ASSERT_TRUE(page_size > 0);
    mapping = mmap(NULL, (size_t) page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(mapping, MAP_FAILED);
    ASSERT_EQ(munmap(mapping, (size_t) page_size), 0);

    pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        char out[4];
        int rc =
            kbox_current_read((uint64_t) (uintptr_t) mapping, out, sizeof(out));

        _exit(rc < 0 ? 0 : 1);
    }

    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(WEXITSTATUS(status), 0);
}

static void test_vm_write_force_rejects_bad_pointer(void)
{
    ASSERT_EQ(kbox_vm_write_force(getpid(), 0, "x", 1), -EFAULT);
    ASSERT_EQ(kbox_vm_write_force(getpid(), 1, NULL, 1), -EFAULT);
    ASSERT_EQ(kbox_vm_write_force(getpid(), 0, NULL, 0), 0);
}

/* kbox_vm_read_string returns -EFAULT on unmapped memory (not stale errno). */
static void test_vm_read_string_unmapped_returns_efault(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    char *mapping;
    char buf[64];
    pid_t pid;
    int status = 0;

    ASSERT_TRUE(page_size > 0);
    mapping = mmap(NULL, (size_t) page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(mapping, MAP_FAILED);
    ASSERT_EQ(munmap(mapping, (size_t) page_size), 0);

    /* Fork so process_vm_readv targets our own child (same address space
     * layout after fork, but the mapping is unmapped in the child too).
     */
    pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        int rc = kbox_vm_read_string(getpid(), (uint64_t) (uintptr_t) mapping,
                                     buf, sizeof(buf));
        _exit(rc == -EFAULT ? 0 : 1);
    }

    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(WEXITSTATUS(status), 0);
}

/* kbox_vm_read_string on valid NUL-terminated string returns length. */
static void test_vm_read_string_valid(void)
{
    char buf[64];
    const char *src = "hello";
    int rc = kbox_vm_read_string(getpid(), (uint64_t) (uintptr_t) src, buf,
                                 sizeof(buf));
    ASSERT_EQ(rc, 5);
    ASSERT_STREQ(buf, "hello");
}

/* kbox_vm_read_string rejects NULL pointer. */
static void test_vm_read_string_null_returns_efault(void)
{
    char buf[64];
    ASSERT_EQ(kbox_vm_read_string(getpid(), 0, buf, sizeof(buf)), -EFAULT);
}

/* Cross-page short read: string without NUL at end of readable page,
 * next page unmapped.  process_vm_readv returns a short read (< chunk),
 * and since no NUL was found, kbox_vm_read_string returns -EFAULT.
 */
static void test_vm_read_string_cross_page_short_read(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    char *mapping;
    char buf[64];
    pid_t pid;
    int status = 0;

    ASSERT_TRUE(page_size > 0);

    /* Map two pages, then unmap the second so reads crossing the boundary
     * produce a short read from process_vm_readv.
     */
    mapping = mmap(NULL, (size_t) page_size * 2, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(mapping, MAP_FAILED);

    /* Fill end of first page with non-NUL bytes (no terminator). */
    memset(mapping + page_size - 4, 'A', 4);
    ASSERT_EQ(munmap(mapping + page_size, (size_t) page_size), 0);

    pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        /* Read starting 4 bytes before page boundary.  The first chunk
         * succeeds (short read of 4 bytes, no NUL), then the next chunk
         * hits unmapped memory -> returns -EFAULT.
         */
        int rc = kbox_vm_read_string(
            getpid(), (uint64_t) (uintptr_t) (mapping + page_size - 4), buf,
            sizeof(buf));
        _exit(rc == -EFAULT ? 0 : 1);
    }

    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(WEXITSTATUS(status), 0);
    munmap(mapping, (size_t) page_size);
}

void test_procmem_init(void)
{
    TEST_REGISTER(test_current_guest_mem_read_write);
    TEST_REGISTER(test_current_guest_mem_read_string);
    TEST_REGISTER(test_current_guest_mem_ops_wrapper);
    TEST_REGISTER(test_current_guest_mem_rejects_bad_pointer);
    TEST_REGISTER(test_current_guest_mem_force_write_cross_page);
    TEST_REGISTER(test_current_guest_mem_unmapped_pointer_returns_error);
    TEST_REGISTER(test_vm_write_force_rejects_bad_pointer);
    TEST_REGISTER(test_vm_read_string_unmapped_returns_efault);
    TEST_REGISTER(test_vm_read_string_valid);
    TEST_REGISTER(test_vm_read_string_null_returns_efault);
    TEST_REGISTER(test_vm_read_string_cross_page_short_read);
}
