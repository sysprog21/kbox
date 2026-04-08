/* SPDX-License-Identifier: MIT */
/* Guest test: verify TCP connectivity through SLIRP using a direct
 * connect/send/recv cycle against a host HTTP server.
 */
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(cond, msg)                        \
    do {                                        \
        if (!(cond)) {                          \
            fprintf(stderr, "FAIL: %s\n", msg); \
            exit(1);                            \
        }                                       \
    } while (0)

/* SLIRP gateway address — maps to the host. */
#define GATEWAY_ADDR "10.0.2.2"
#define HTTP_PORT 8080
#define TIMEOUT_MS 5000

static const char http_request[] = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";

int main(void)
{
    int fd;
    struct sockaddr_in srv = {0};
    struct pollfd pfd = {0};
    char buf[512];

    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0, "socket(AF_INET, SOCK_STREAM)");

    srv.sin_family = AF_INET;
    srv.sin_port = htons(HTTP_PORT);
    CHECK(inet_pton(AF_INET, GATEWAY_ADDR, &srv.sin_addr) == 1,
          "inet_pton gateway");

    CHECK(connect(fd, (struct sockaddr *) &srv, sizeof(srv)) == 0,
          "connect to gateway HTTP server");

    CHECK(send(fd, http_request, sizeof(http_request) - 1, 0) ==
              (ssize_t) (sizeof(http_request) - 1),
          "send HTTP GET");

    pfd.fd = fd;
    pfd.events = POLLIN;
    CHECK(poll(&pfd, 1, TIMEOUT_MS) == 1 && (pfd.revents & POLLIN),
          "poll for HTTP response");

    CHECK(recv(fd, buf, sizeof(buf) - 1, 0) > 0, "recv HTTP response");
    buf[sizeof(buf) - 1] = '\0';

    CHECK(strncmp(buf, "HTTP/1.", 7) == 0, "HTTP response starts with HTTP/1.");

    close(fd);

    printf("PASS: net_tcp_test\n");
    return 0;
}
