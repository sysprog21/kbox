/* SPDX-License-Identifier: MIT */
/* Guest test: verify dup, dup2, dup3, and pipe semantics.
 * Compiled statically and placed in the rootfs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(cond, msg)                        \
    do {                                        \
        if (!(cond)) {                          \
            fprintf(stderr, "FAIL: %s\n", msg); \
            exit(1);                            \
        }                                       \
    } while (0)

int main(void)
{
    int pipefd[2];

    /* dup basic */
    int fd = open("/dev/null", O_WRONLY);
    CHECK(fd >= 0, "open /dev/null");
    int fd2 = dup(fd);
    CHECK(fd2 >= 0, "dup");
    CHECK(fd2 != fd, "dup returned different fd");
    close(fd2);
    close(fd);

    /* dup2 to specific fd */
    fd = open("/dev/null", O_WRONLY);
    CHECK(fd >= 0, "open /dev/null for dup2");
    int target = fd + 10;
    int rc = dup2(fd, target);
    CHECK(rc == target, "dup2 to specific fd");
    close(target);
    close(fd);

    /* pipe + read/write */
    CHECK(pipe2(pipefd, 0) == 0, "pipe");
    const char *msg = "hello";
    ssize_t nw = write(pipefd[1], msg, strlen(msg));
    CHECK(nw == (ssize_t) strlen(msg), "write to pipe");

    char buf[16] = {0};
    ssize_t nr = read(pipefd[0], buf, sizeof(buf) - 1);
    CHECK(nr == (ssize_t) strlen(msg), "read from pipe");
    CHECK(strcmp(buf, msg) == 0, "pipe data matches");
    close(pipefd[0]);
    close(pipefd[1]);

    /* dup3 with O_CLOEXEC */
    fd = open("/dev/null", O_WRONLY);
    CHECK(fd >= 0, "open /dev/null for dup3");
    target = fd + 20;
    rc = dup3(fd, target, O_CLOEXEC);
    CHECK(rc == target, "dup3 with O_CLOEXEC");
    int flags = fcntl(target, F_GETFD);
    CHECK(flags >= 0, "fcntl F_GETFD");
    CHECK(flags & FD_CLOEXEC, "dup3 set CLOEXEC");
    close(target);
    close(fd);

    /* fcntl(F_DUPFD*) honors the requested minimum on host-passthrough FDs. */
    CHECK(pipe2(pipefd, 0) == 0, "pipe for F_DUPFD");
    target = fcntl(pipefd[0], F_DUPFD, 64);
    CHECK(target >= 64, "F_DUPFD honored minimum");
    close(target);

    target = fcntl(pipefd[0], F_DUPFD_CLOEXEC, 65);
    CHECK(target >= 65, "F_DUPFD_CLOEXEC honored minimum");
    flags = fcntl(target, F_GETFD);
    CHECK(flags >= 0, "fcntl F_GETFD after F_DUPFD_CLOEXEC");
    CHECK(flags & FD_CLOEXEC, "F_DUPFD_CLOEXEC set CLOEXEC");
    close(target);
    close(pipefd[0]);
    close(pipefd[1]);

    printf("PASS: dup_test\n");
    return 0;
}
