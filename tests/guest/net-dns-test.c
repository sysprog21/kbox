/* SPDX-License-Identifier: MIT */
/*
 * Guest test: verify DNS resolution through SLIRP using direct UDP queries.
 */
#include <arpa/inet.h>
#include <poll.h>
#include <stdint.h>
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

static size_t encode_qname(uint8_t *out, size_t cap, const char *name)
{
    size_t used = 0;
    const char *p = name;

    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t) (dot - p) : strlen(p);
        if (len == 0 || len > 63 || used + 1 + len + 1 > cap)
            return 0;
        out[used++] = (uint8_t) len;
        memcpy(out + used, p, len);
        used += len;
        if (!dot)
            break;
        p = dot + 1;
    }

    if (used >= cap)
        return 0;
    out[used++] = 0;
    return used;
}

static int dns_query_example(uint32_t *ipv4_out)
{
    uint8_t query[512];
    uint8_t reply[512];
    size_t qlen = 0;
    int fd = -1;
    struct sockaddr_in dns = {0};
    struct pollfd pfd = {0};

    memset(query, 0, sizeof(query));
    query[0] = 0x12;
    query[1] = 0x34;
    query[2] = 0x01;
    query[5] = 0x01;
    qlen = 12;
    qlen += encode_qname(query + qlen, sizeof(query) - qlen, "example.com");
    if (qlen == 12)
        return -1;
    query[qlen++] = 0x00;
    query[qlen++] = 0x01;
    query[qlen++] = 0x00;
    query[qlen++] = 0x01;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    dns.sin_family = AF_INET;
    dns.sin_port = htons(53);
    if (inet_pton(AF_INET, "10.0.2.3", &dns.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (sendto(fd, query, qlen, 0, (struct sockaddr *) &dns, sizeof(dns)) !=
        (ssize_t) qlen) {
        close(fd);
        return -1;
    }

    pfd.fd = fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, 3000) != 1 || !(pfd.revents & POLLIN)) {
        close(fd);
        return -1;
    }

    ssize_t n = recvfrom(fd, reply, sizeof(reply), 0, NULL, NULL);
    close(fd);
    if (n < 12)
        return -1;
    if (reply[0] != 0x12 || reply[1] != 0x34)
        return -1;
    if ((reply[3] & 0x0F) != 0)
        return -1;

    uint16_t ancount = (uint16_t) ((reply[6] << 8) | reply[7]);
    size_t off = qlen;
    for (uint16_t i = 0; i < ancount && off + 12 <= (size_t) n; i++) {
        uint16_t type;
        uint16_t class_;
        uint16_t rdlen;

        if ((reply[off] & 0xC0) == 0xC0) {
            off += 2;
        } else {
            while (off < (size_t) n && reply[off] != 0)
                off += (size_t) reply[off] + 1;
            off++;
        }
        if (off + 10 > (size_t) n)
            break;

        type = (uint16_t) ((reply[off] << 8) | reply[off + 1]);
        class_ = (uint16_t) ((reply[off + 2] << 8) | reply[off + 3]);
        rdlen = (uint16_t) ((reply[off + 8] << 8) | reply[off + 9]);
        off += 10;
        if (off + rdlen > (size_t) n)
            break;

        if (type == 1 && class_ == 1 && rdlen == 4) {
            memcpy(ipv4_out, reply + off, 4);
            return 0;
        }
        off += rdlen;
    }

    return -1;
}

int main(void)
{
    uint32_t addr = 0;

    CHECK(dns_query_example(&addr) == 0, "resolve example.com A record");
    CHECK(addr != 0, "non-zero IPv4 answer");

    printf("PASS: net_dns_test\n");
    return 0;
}
