/* SPDX-License-Identifier: MIT */
#include <string.h>

#include "fd-table.h"
#include "test-runner.h"
#define KBOX_HOST_VFD_NONE ((int32_t) -1)
#define KBOX_HOST_VFD_MULTI ((int32_t) -2)

static void test_fd_table_multi_downgrade_regression(void)
{
    struct kbox_fd_table t;
    long vfd1, vfd2;
    long host_fd = 42;

    kbox_fd_table_init(&t);

    vfd1 = kbox_fd_table_insert(&t, 10, 0);
    kbox_fd_table_set_host_fd(&t, vfd1, host_fd);

    ASSERT_EQ(t.host_to_vfd[host_fd], vfd1);
    ASSERT_EQ(t.host_fd_refs[host_fd], 1);

    /* MULTI state*/
    vfd2 = kbox_fd_table_insert(&t, 20, 0);
    kbox_fd_table_set_host_fd(&t, vfd2, host_fd);

    ASSERT_EQ(t.host_to_vfd[host_fd], KBOX_HOST_VFD_MULTI);
    ASSERT_EQ(t.host_fd_refs[host_fd], 2);

    /* Downgrade back to Single*/
    kbox_fd_table_remove(&t, vfd2);

    ASSERT_EQ(t.host_to_vfd[host_fd], vfd1);
    ASSERT_EQ(t.host_fd_refs[host_fd], 1);

    /* Should return the exact vfd */
    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, host_fd), vfd1);
}

void test_fd_table_refcount_init(void)
{
    TEST_REGISTER(test_fd_table_multi_downgrade_regression);
}
