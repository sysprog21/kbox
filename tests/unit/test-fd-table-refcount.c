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

#ifdef KBOX_PERF_TESTS
#include <stdio.h>
#include <time.h>
#define PERF_ITERATIONS 1000000
static double time_diff_ns(struct timespec *start, struct timespec *end)
{
    return ((double) (end->tv_sec - start->tv_sec) * 1e9) +
           (double) (end->tv_nsec - start->tv_nsec);
}

static void test_fd_table_o1_characteristics(void)
{
    struct kbox_fd_table t;
    int ns_to_test[] = {64, 256, 1024, 4096, 16384};
    int num_sizes = sizeof(ns_to_test) / sizeof(ns_to_test[0]);

    double baseline_present_ns = 0;
    double baseline_absent_ns = 0;

    printf("\n--- O(1) Characteristic Perf Test ---\n");

    for (int i = 0; i < num_sizes; i++) {
        int n = ns_to_test[i];
        kbox_fd_table_init(&t);
        long target_present = 0;
        long target_absent = 65535;

        for (long j = 0, host_fd = 0; j < n; j++) {
            long vfd = j;
            kbox_fd_table_insert_at(&t, vfd, j, 0);

            /* linear congruential generator to prevent caching */
            host_fd = (16645 * host_fd + 10139) % 65536;
            kbox_fd_table_set_host_fd(&t, vfd, host_fd);
            if (j == n / 2) {
                target_present = host_fd;
            }
        }

        struct timespec start, end;
        double present_time_ns, absent_time_ns;

        long sum_present = 0;
        long sum_absent = 0;

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int k = 0; k < PERF_ITERATIONS; k++) {
            sum_present += kbox_fd_table_find_by_host_fd(&t, target_present);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        present_time_ns = time_diff_ns(&start, &end) / PERF_ITERATIONS;

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int k = 0; k < PERF_ITERATIONS; k++) {
            sum_absent += kbox_fd_table_find_by_host_fd(&t, target_absent);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        absent_time_ns = time_diff_ns(&start, &end) / PERF_ITERATIONS;

        printf("N = %-5d | Present: %6.2f ns/op | Absent: %6.2f ns/op\n", n,
               present_time_ns, absent_time_ns);

        if (i == 0) {
            baseline_present_ns = present_time_ns;
            baseline_absent_ns = absent_time_ns;
        } else {
            /* The per-lookup cost ratio across N must stay under ~2x */
            double present_ratio = present_time_ns / baseline_present_ns;
            double absent_ratio = absent_time_ns / baseline_absent_ns;

            ASSERT_TRUE(present_ratio < 2);
            ASSERT_TRUE(absent_ratio < 2);
        }
    }
}
#endif
void test_fd_table_refcount_init(void)
{
    TEST_REGISTER(test_fd_table_multi_downgrade_regression);

#ifdef KBOX_PERF_TESTS
    PERF_REGISTER(test_fd_table_o1_characteristics);
#endif
}
