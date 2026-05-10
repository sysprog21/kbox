/* SPDX-License-Identifier: MIT */
/* Guest test: verify sendfile when out_fd is a writeback shadow FD.
 * Opening a regular file O_WRONLY causes the supervisor to inject a
 * writable shadow memfd (shadow_writeback=1).  forward_sendfile() must
 * route writes to that shadow_sp; otherwise the memfd was never written
 * close time. This test catches that regression by verifying data
 * integrity after close.
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

    /* O_RDONLY: supervisor creates a read-only shadow memfd and records
     * the LKL fd in the fd table; forward_sendfile() picks it up via
     * kbox_fd_table_get_lkl() directly. */
    int in_fd = open(TEST_FILE, O_RDONLY | O_CLOEXEC);
    CHECK(in_fd >= 0, "open input file O_RDONLY");

    /* O_WRONLY on a regular path: supervisor injects a writable shadow memfd
     * (shadow_writeback=1, shadow_sp=memfd).  forward_sendfile() must write
     * to shadow_sp — not the LKL fd — so that sync_shadow_writeback() at
     * close time has data to flush back.  Pipes are not valid sendfile
     * targets (EINVAL), so a regular file is used here. */
    int out_fd = open(OUT_FILE, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
    CHECK(out_fd >= 0,
          "create output file O_WRONLY (becomes writeback shadow FD)");

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
