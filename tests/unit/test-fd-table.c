/* SPDX-License-Identifier: MIT */
#include <string.h>

#include "fd-table.h"
#include "test-runner.h"

static void test_fd_table_init_zeros(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    ASSERT_EQ(t.next_fd, KBOX_FD_BASE);
    for (int i = 0; i < KBOX_FD_TABLE_MAX; i++)
        ASSERT_EQ(t.entries[i].lkl_fd, -1);
    for (int i = 0; i < KBOX_LOW_FD_MAX; i++)
        ASSERT_EQ(t.low_fds[i].lkl_fd, -1);
    for (int i = 0; i < KBOX_MID_FD_MAX; i++)
        ASSERT_EQ(t.mid_fds[i].lkl_fd, -1);
}

static void test_fd_table_insert_basic(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd = kbox_fd_table_insert(&t, 42, 0);
    ASSERT_EQ(vfd, KBOX_FD_BASE);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, vfd), 42);
}

static void test_fd_table_insert_sequential(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd1 = kbox_fd_table_insert(&t, 10, 0);
    long vfd2 = kbox_fd_table_insert(&t, 20, 0);
    long vfd3 = kbox_fd_table_insert(&t, 30, 0);
    ASSERT_EQ(vfd1, KBOX_FD_BASE);
    ASSERT_EQ(vfd2, KBOX_FD_BASE + 1);
    ASSERT_EQ(vfd3, KBOX_FD_BASE + 2);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, vfd1), 10);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, vfd2), 20);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, vfd3), 30);
}

static void test_fd_table_remove(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd = kbox_fd_table_insert(&t, 99, 0);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, vfd), 99);
    long old = kbox_fd_table_remove(&t, vfd);
    ASSERT_EQ(old, 99);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, vfd), -1);
}

static void test_fd_table_remove_nonexistent(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long old = kbox_fd_table_remove(&t, KBOX_FD_BASE + 500);
    ASSERT_EQ(old, -1);
}

static void test_fd_table_insert_at(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    int rc = kbox_fd_table_insert_at(&t, KBOX_FD_BASE + 100, 77, 1);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, KBOX_FD_BASE + 100), 77);
    ASSERT_TRUE(kbox_fd_table_mirror_tty(&t, KBOX_FD_BASE + 100));
}

static void test_fd_table_mirror_tty(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd1 = kbox_fd_table_insert(&t, 10, 0);
    long vfd2 = kbox_fd_table_insert(&t, 20, 1);
    ASSERT_TRUE(!kbox_fd_table_mirror_tty(&t, vfd1));
    ASSERT_TRUE(kbox_fd_table_mirror_tty(&t, vfd2));
}

static void test_fd_table_cloexec(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd = kbox_fd_table_insert(&t, 55, 0);
    ASSERT_EQ(kbox_fd_table_get_cloexec(&t, vfd), 0);
    kbox_fd_table_set_cloexec(&t, vfd, 1);
    ASSERT_EQ(kbox_fd_table_get_cloexec(&t, vfd), 1);
    kbox_fd_table_set_cloexec(&t, vfd, 0);
    ASSERT_EQ(kbox_fd_table_get_cloexec(&t, vfd), 0);
}

static void test_fd_table_out_of_range(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    /* Mid-range host FDs are now directly trackable. */
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, KBOX_LOW_FD_MAX), -1);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, KBOX_FD_BASE - 1), -1);
    /* Above range */
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, KBOX_FD_BASE + KBOX_FD_TABLE_MAX), -1);
}

static void test_fd_table_insert_at_low_range(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);

    /* Boundary: FD 0 (stdin redirect via dup2) */
    int rc = kbox_fd_table_insert_at(&t, 0, 10, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, 0), 10);

    /* Mid-range: FD 100 */
    rc = kbox_fd_table_insert_at(&t, 100, 55, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, 100), 55);

    /* Boundary: FD 1023 (last valid low slot) */
    rc = kbox_fd_table_insert_at(&t, KBOX_LOW_FD_MAX - 1, 77, 1);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, KBOX_LOW_FD_MAX - 1), 77);
    ASSERT_TRUE(kbox_fd_table_mirror_tty(&t, KBOX_LOW_FD_MAX - 1));

    /* Mid-range host FD: FD 1024 */
    rc = kbox_fd_table_insert_at(&t, KBOX_LOW_FD_MAX, 66, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, KBOX_LOW_FD_MAX), 66);

    /* Low-range remove */
    long old = kbox_fd_table_remove(&t, 100);
    ASSERT_EQ(old, 55);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, 100), -1);

    /* Low-range host_fd operations */
    kbox_fd_table_set_host_fd(&t, 0, 42);
    ASSERT_EQ(kbox_fd_table_get_host_fd(&t, 0), 42);
    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, 42), 0);
}

static void test_fd_table_overwrite_at(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd = kbox_fd_table_insert(&t, 10, 0);
    kbox_fd_table_insert_at(&t, vfd, 20, 1);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, vfd), 20);
    ASSERT_TRUE(kbox_fd_table_mirror_tty(&t, vfd));
}

static void test_fd_table_host_fd_init(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    for (int i = 0; i < KBOX_FD_TABLE_MAX; i++)
        ASSERT_EQ(t.entries[i].host_fd, -1);
}

static void test_fd_table_host_fd_default(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd = kbox_fd_table_insert(&t, 42, 0);
    ASSERT_EQ(kbox_fd_table_get_host_fd(&t, vfd), -1);
}

static void test_fd_table_set_get_host_fd(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd = kbox_fd_table_insert(&t, 42, 0);
    kbox_fd_table_set_host_fd(&t, vfd, 99);
    ASSERT_EQ(kbox_fd_table_get_host_fd(&t, vfd), 99);
}

static void test_fd_table_find_by_host_fd(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd1 = kbox_fd_table_insert(&t, 10, 0);
    long vfd2 = kbox_fd_table_insert(&t, 20, 0);
    kbox_fd_table_set_host_fd(&t, vfd2, 77);

    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, 77), vfd2);
    /* vfd1 has no host_fd set; should not match */
    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, -1), -1);

    (void) vfd1;
}

static void test_fd_table_find_by_host_fd_unknown(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    kbox_fd_table_insert(&t, 10, 0);
    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, 999), -1);
}

static void test_fd_table_remove_resets_host_fd(void)
{
    struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd = kbox_fd_table_insert(&t, 42, 0);
    kbox_fd_table_set_host_fd(&t, vfd, 88);
    ASSERT_EQ(kbox_fd_table_get_host_fd(&t, vfd), 88);
    kbox_fd_table_remove(&t, vfd);
    /* After removal, slot is free; get_host_fd returns -1. */
    ASSERT_EQ(kbox_fd_table_get_host_fd(&t, vfd), -1);
    /* Reverse lookup should also fail. */
    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, 88), -1);
}

static void test_fd_table_find_by_host_fd_duplicate_holder_survives(void)
{
    /* After duplicate set_host_fd the reverse map enters the MULTI
     * sentinel state and find_by_host_fd falls through to the linear
     * scan, which returns the first matching entry in scan order.
     * Once one holder is removed, the remaining holder is still
     * findable (via either the fast path or the slow scan).
     */
    struct kbox_fd_table t;
    long vfd1;
    long vfd2;
    long found;

    kbox_fd_table_init(&t);
    vfd1 = kbox_fd_table_insert(&t, 10, 0);
    vfd2 = kbox_fd_table_insert(&t, 20, 0);
    kbox_fd_table_set_host_fd(&t, vfd1, 77);
    kbox_fd_table_set_host_fd(&t, vfd2, 77);

    found = kbox_fd_table_find_by_host_fd(&t, 77);
    ASSERT_TRUE(found == vfd1 || found == vfd2);
    ASSERT_EQ(kbox_fd_table_remove(&t, vfd2), 20);
    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, 77), vfd1);
}

static void test_fd_table_find_by_host_fd_requires_api(void)
{
    /* Invariant: positive host_fd values must be installed via
     * kbox_fd_table_set_host_fd so the O(1) reverse map stays
     * consistent. Direct writes to entry->host_fd with positive
     * values bypass the reverse map and are intentionally not
     * findable; the authoritative-NONE fast path in
     * find_by_host_fd returns -1 without scanning. Only the
     * negative sentinel values (KBOX_FD_HOST_SAME_FD_SHADOW and
     * KBOX_FD_LOCAL_ONLY_SHADOW) may be written directly, and
     * only on entries whose host_fd is already negative.
     */
    struct kbox_fd_table t;
    long vfd;

    kbox_fd_table_init(&t);
    vfd = kbox_fd_table_insert(&t, 10, 0);
    t.entries[vfd - KBOX_FD_BASE].host_fd = 123;
    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, 123), -1);
}

void test_fd_table_init(void)
{
    TEST_REGISTER(test_fd_table_init_zeros);
    TEST_REGISTER(test_fd_table_insert_basic);
    TEST_REGISTER(test_fd_table_insert_sequential);
    TEST_REGISTER(test_fd_table_remove);
    TEST_REGISTER(test_fd_table_remove_nonexistent);
    TEST_REGISTER(test_fd_table_insert_at);
    TEST_REGISTER(test_fd_table_mirror_tty);
    TEST_REGISTER(test_fd_table_cloexec);
    TEST_REGISTER(test_fd_table_out_of_range);
    TEST_REGISTER(test_fd_table_insert_at_low_range);
    TEST_REGISTER(test_fd_table_overwrite_at);
    TEST_REGISTER(test_fd_table_host_fd_init);
    TEST_REGISTER(test_fd_table_host_fd_default);
    TEST_REGISTER(test_fd_table_set_get_host_fd);
    TEST_REGISTER(test_fd_table_find_by_host_fd);
    TEST_REGISTER(test_fd_table_find_by_host_fd_unknown);
    TEST_REGISTER(test_fd_table_remove_resets_host_fd);
    TEST_REGISTER(test_fd_table_find_by_host_fd_duplicate_holder_survives);
    TEST_REGISTER(test_fd_table_find_by_host_fd_requires_api);
}
