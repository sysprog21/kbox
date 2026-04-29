/* SPDX-License-Identifier: MIT */
/* Guest test: verify sendfile with a shadow-memfd input FD.
 * sendfile must resolve the host fd through that shadow path via
 * find_by_host_fd(); this test confirms data integrity end-to-end.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <unistd.h>

#define TEST_DATA "kbox shadow sendfile integration test data"
#define TEST_FILE "/opt/sendfile_test_data.txt"
#define OUT_FILE "/opt/sendfile_out_test.txt"

#define CHECK(cond, msg)                                               \
    do {                                                               \
        if (!(cond)) {                                                 \
            fprintf(stderr, "FAIL: %s (errno: %d - %s)\n", msg, errno, \
                    strerror(errno));                                  \
            exit(1);                                                   \
        }                                                              \
    } while (0)

int main(void)
{
    size_t test_len = strlen(TEST_DATA);

    /* Create input file in LKL rootfs with test data. */
    int setup_fd =
        open(TEST_FILE, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
    CHECK(setup_fd >= 0, "create input file");
    CHECK(write(setup_fd, TEST_DATA, test_len) == (ssize_t) test_len,
          "write test data to input file");
    close(setup_fd);

    /* Open O_RDONLY to trigger shadow memfd creation; sendfile must resolve
     * the LKL fd via find_by_host_fd() through that shadow path. */
    int in_fd = open(TEST_FILE, O_RDONLY | O_CLOEXEC);
    CHECK(in_fd >= 0, "open input file as O_RDONLY (creates shadow memfd)");

    /* Regular file output — pipes are not valid sendfile targets (EINVAL). */
    int out_fd = open(OUT_FILE, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
    CHECK(out_fd >= 0, "create regular output file for sendfile target");

    size_t remaining = test_len;
    size_t total_sent = 0;
    while (remaining > 0) {
        ssize_t sent = sendfile(out_fd, in_fd, NULL, remaining);
        CHECK(sent >= 0, "sendfile from shadow in_fd to regular out_fd");
        if (sent == 0)
            break;
        total_sent += (size_t) sent;
        remaining -= (size_t) sent;
    }

    CHECK(total_sent == test_len, "transferred all data via sendfile");
    close(out_fd);

    /* Verify content written by sendfile. */
    int verify_fd = open(OUT_FILE, O_RDONLY | O_CLOEXEC);
    CHECK(verify_fd >= 0, "re-open output file for verification");

    char verify_buf[256] = {0};
    size_t file_received = 0;
    while (file_received < total_sent) {
        ssize_t nread = read(verify_fd, verify_buf + file_received,
                             total_sent - file_received);
        CHECK(nread >= 0, "read from output file");
        if (nread == 0)
            break;
        file_received += (size_t) nread;
    }

    CHECK(file_received == total_sent, "received all data from output file");
    verify_buf[file_received] = '\0';
    CHECK(strcmp(verify_buf, TEST_DATA) == 0, "data matches TEST_DATA");

    close(verify_fd);
    close(in_fd);
    unlink(TEST_FILE);
    unlink(OUT_FILE);

    printf("PASS: sendfile_test\n");
    return 0;
}
