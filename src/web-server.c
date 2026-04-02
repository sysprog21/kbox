/* SPDX-License-Identifier: MIT */
/* web-server.c - Embedded HTTP/1.1 server for the web observatory.
 *
 * Minimal server supporting:
 *   GET /            -> SPA (compiled-in assets, Phase 2)
 *   GET /api/snapshot -> Current telemetry JSON
 *   GET /api/events  -> SSE event stream
 *   GET /stats       -> Quick health summary
 *   POST /api/control -> Pause/resume/set_interval
 *
 * Runs in a dedicated pthread.  Non-blocking I/O via epoll.
 * Bind 127.0.0.1 by default.  Max 8 SSE connections.
 */

#ifdef KBOX_HAS_WEB

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "fd-table.h"
#include "lkl-wrap.h"
#include "syscall-nr.h"
#include "web.h"

/* Constants. */

#define WEB_MAX_SSE_CLIENTS 8
#define WEB_MAX_CLIENTS 32
#define WEB_REQ_LINE_MAX 8192
#define WEB_RESP_BUF_SIZE 65536
#define WEB_POST_MAX 65536
#define WEB_DEFAULT_PORT 8080
#define WEB_DEFAULT_BIND "127.0.0.1"
#define WEB_SAMPLE_PCTL 1 /* default 1% sampling for routine events */

/* Snapshot ring buffer (last N minutes at 10 samples/sec) */
#define SNAP_RING_SIZE 600 /* ~1 minute at 100ms */

/* Web context. */

struct kbox_sse_client {
    int fd;
    uint64_t last_seq;
};

struct kbox_web_ctx {
    /* Configuration */
    struct kbox_web_config cfg;
    const struct kbox_sysnrs *sysnrs;

    /* Telemetry state */
    struct kbox_telemetry_counters counters;
    struct kbox_telemetry_snapshot snapshot;
    struct kbox_telemetry_snapshot snap_ring[SNAP_RING_SIZE];
    int snap_ring_head;
    int snap_ring_count;
    uint64_t boot_time_ns;
    uint64_t last_fast_tick;
    atomic_int paused;

    /* Event ring */
    struct kbox_event_ring events;
    uint32_t rng_state;

    /* HTTP server */
    int listen_fd;
    int epoll_fd;
    pthread_t server_thread;
    atomic_int server_running;
    int shutdown_pipe[2]; /* write to signal shutdown */

    /* SSE clients */
    struct kbox_sse_client sse_clients[WEB_MAX_SSE_CLIENTS];
    int sse_count;

    /* FD table usage (set by supervisor via kbox_web_set_fd_used) */
    uint32_t fd_used;

    /* Thread safety */
    pthread_mutex_t lock;
};

/* HTTP parsing. */

struct http_request {
    char method[8];
    char path[256];
};

static int parse_request_line(const char *line, struct http_request *req)
{
    memset(req, 0, sizeof(*req));

    /* Parse: METHOD SP PATH SP VERSION CRLF */
    const char *p = line;
    int i = 0;

    /* Method */
    while (*p && *p != ' ' && i < 7)
        req->method[i++] = *p++;
    req->method[i] = '\0';
    if (*p != ' ')
        return -1;
    p++;

    /* Path */
    i = 0;
    while (*p && *p != ' ' && *p != '?' && i < 255)
        req->path[i++] = *p++;
    req->path[i] = '\0';

    /* Skip query string and version */
    return 0;
}

/* HTTP responses. */

/* Write all bytes to fd, handling partial writes.
 * Temporarily sets the fd to blocking mode for reliable delivery.
 */
static void write_all(int fd, const void *buf, size_t len)
{
    /* Switch to blocking for reliable write */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0 && (flags & O_NONBLOCK))
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    const char *p = buf;
    size_t rem = len;
    while (rem > 0) {
        ssize_t n = write(fd, p, rem);
        if (n <= 0)
            break;
        p += n;
        rem -= (size_t) n;
    }

    /* Restore non-blocking */
    if (flags >= 0 && (flags & O_NONBLOCK))
        fcntl(fd, F_SETFL, flags);
}

static void send_response(int fd,
                          int status,
                          const char *content_type,
                          const char *body,
                          int body_len)
{
    char hdr[512];
    const char *status_text;
    switch (status) {
    case 200:
        status_text = "OK";
        break;
    case 404:
        status_text = "Not Found";
        break;
    case 405:
        status_text = "Method Not Allowed";
        break;
    default:
        status_text = "Internal Server Error";
        break;
    }

    int hdr_len = snprintf(hdr, sizeof(hdr),
                           "HTTP/1.1 %d %s\r\n"
                           "Content-Type: %s\r\n"
                           "Content-Length: %d\r\n"
                           "Access-Control-Allow-Origin: *\r\n"
                           "Connection: close\r\n"
                           "\r\n",
                           status, status_text, content_type, body_len);
    if (hdr_len < 0 || hdr_len >= (int) sizeof(hdr))
        hdr_len = (int) sizeof(hdr) - 1;

    write_all(fd, hdr, (size_t) hdr_len);
    if (body_len > 0)
        write_all(fd, body, (size_t) body_len);
}

static void send_json(int fd, const char *json, int len)
{
    send_response(fd, 200, "application/json", json, len);
}

static void send_404(int fd)
{
    const char *body = "{\"error\":\"not found\"}";
    send_response(fd, 404, "application/json", body, (int) strlen(body));
}

static void send_405(int fd)
{
    const char *body = "{\"error\":\"method not allowed\"}";
    send_response(fd, 405, "application/json", body, (int) strlen(body));
}

/* SSE. */

static int start_sse(struct kbox_web_ctx *ctx, int fd)
{
    if (ctx->sse_count >= WEB_MAX_SSE_CLIENTS) {
        const char *body = "{\"error\":\"too many SSE clients\"}";
        send_response(fd, 503, "application/json", body, (int) strlen(body));
        return -1;
    }

    /* Send SSE headers */
    const char *hdr =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";

    if (write(fd, hdr, strlen(hdr)) < 0)
        return -1;

    /* Remove the FD from epoll; SSE connections are managed
     * exclusively by flush_sse_clients(), not the main read loop.
     * This prevents the main loop from closing the FD on a
     * subsequent read event (which could reuse the FD number).
     */
    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL);

    /* Register SSE client */
    struct kbox_sse_client *c = &ctx->sse_clients[ctx->sse_count++];
    c->fd = fd;
    c->last_seq = ctx->events.write_seq;

    return 0; /* fd kept open */
}

struct sse_push_ctx {
    int fd;
    int failed;
};

static void sse_push_event(const struct kbox_event *evt, void *userdata)
{
    struct sse_push_ctx *pc = userdata;
    if (pc->failed)
        return;

    char json[2048];
    int len = kbox_event_to_json(evt, json, sizeof(json));
    if (len <= 0)
        return;

    const char *type = "syscall";

    char sse_buf[2200];
    int sse_len = snprintf(sse_buf, sizeof(sse_buf), "event: %s\ndata: %s\n\n",
                           type, json);
    if (sse_len < 0 || sse_len >= (int) sizeof(sse_buf))
        sse_len = (int) sizeof(sse_buf) - 1;

    if (write(pc->fd, sse_buf, (size_t) sse_len) < 0)
        pc->failed = 1;
}

static void flush_sse_clients(struct kbox_web_ctx *ctx)
{
    int i = 0;
    while (i < ctx->sse_count) {
        struct kbox_sse_client *c = &ctx->sse_clients[i];
        struct sse_push_ctx pc = {.fd = c->fd, .failed = 0};

        c->last_seq = kbox_event_ring_iterate(&ctx->events, c->last_seq,
                                              sse_push_event, &pc);

        if (pc.failed) {
            /* Client disconnected; remove. */
            close(c->fd);
            ctx->sse_clients[i] = ctx->sse_clients[--ctx->sse_count];
            continue; /* re-check same index */
        }
        i++;
    }
}

/* Compiled-in web assets (generated by scripts/gen-web-assets.sh). */

extern int kbox_web_asset_find(const char *path,
                               const unsigned char **data,
                               unsigned int *len);

static const char *content_type_for(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot)
        return "text/html"; /* "/" and other extensionless paths */
    if (strcmp(dot, ".html") == 0)
        return "text/html";
    if (strcmp(dot, ".css") == 0)
        return "text/css";
    if (strcmp(dot, ".js") == 0)
        return "application/javascript";
    if (strcmp(dot, ".svg") == 0)
        return "image/svg+xml";
    if (strcmp(dot, ".png") == 0)
        return "image/png";
    if (strcmp(dot, ".json") == 0)
        return "application/json";
    return "application/octet-stream";
}

/* Route dispatch. */

/* Handle a single HTTP request.
 * Returns 0 if the connection should be closed, 1 if kept alive (SSE).
 */
static int handle_request(struct kbox_web_ctx *ctx,
                          int fd,
                          const struct http_request *req,
                          const char *body)
{
    char buf[WEB_RESP_BUF_SIZE];

    /* Static assets under / and /js/. */
    if (strcmp(req->method, "GET") == 0 &&
        strncmp(req->path, "/api/", 5) != 0 &&
        strcmp(req->path, "/stats") != 0) {
        const unsigned char *data;
        unsigned int data_len;
        if (kbox_web_asset_find(req->path, &data, &data_len) == 0) {
            send_response(fd, 200, content_type_for(req->path),
                          (const char *) data, (int) data_len);
            return 0;
        }
    }

    /* GET /api/snapshot */
    if (strcmp(req->path, "/api/snapshot") == 0) {
        if (strcmp(req->method, "GET") != 0)
            return send_405(fd), 0;
        pthread_mutex_lock(&ctx->lock);
        int len = kbox_snapshot_to_json(&ctx->snapshot, buf, sizeof(buf));
        pthread_mutex_unlock(&ctx->lock);
        send_json(fd, buf, len);
        return 0;
    }

    /* GET /api/events (SSE) */
    if (strcmp(req->path, "/api/events") == 0) {
        if (strcmp(req->method, "GET") != 0)
            return send_405(fd), 0;
        pthread_mutex_lock(&ctx->lock);
        int rc = start_sse(ctx, fd);
        pthread_mutex_unlock(&ctx->lock);
        return (rc == 0) ? 1 : 0; /* keep alive on success */
    }

    /* GET /api/history: historical snapshots from ring buffer. */
    if (strcmp(req->path, "/api/history") == 0) {
        if (strcmp(req->method, "GET") != 0)
            return send_405(fd), 0;

        pthread_mutex_lock(&ctx->lock);
        int count = ctx->snap_ring_count;
        int head = ctx->snap_ring_head;

        /* Build JSON array of snapshots (oldest first) */
        int pos = 0;
        pos += snprintf(buf + pos, sizeof(buf) - (size_t) pos,
                        "{\"count\":%d,\"snapshots\":[", count);
        if (pos >= (int) sizeof(buf))
            pos = (int) sizeof(buf) - 1;

        for (int i = 0; i < count && pos < (int) sizeof(buf) - 2048; i++) {
            int idx = (head - count + i + SNAP_RING_SIZE) % SNAP_RING_SIZE;
            if (i > 0)
                buf[pos++] = ',';
            pos += kbox_snapshot_to_json(&ctx->snap_ring[idx], buf + pos,
                                         (int) sizeof(buf) - pos);
            if (pos >= (int) sizeof(buf))
                pos = (int) sizeof(buf) - 1;
        }
        pos += snprintf(buf + pos, sizeof(buf) - (size_t) pos, "]}");
        if (pos >= (int) sizeof(buf))
            pos = (int) sizeof(buf) - 1;
        pthread_mutex_unlock(&ctx->lock);

        send_json(fd, buf, pos);
        return 0;
    }

    /* GET /stats */
    if (strcmp(req->path, "/stats") == 0) {
        if (strcmp(req->method, "GET") != 0)
            return send_405(fd), 0;
        pthread_mutex_lock(&ctx->lock);
        int len = kbox_stats_to_json(&ctx->snapshot, ctx->cfg.guest_name, buf,
                                     sizeof(buf));
        pthread_mutex_unlock(&ctx->lock);
        send_json(fd, buf, len);
        return 0;
    }

    /* GET /api/enosys */
    if (strcmp(req->path, "/api/enosys") == 0) {
        if (strcmp(req->method, "GET") != 0)
            return send_405(fd), 0;
        pthread_mutex_lock(&ctx->lock);
        int len =
            kbox_enosys_to_json(&ctx->snapshot.counters, buf, sizeof(buf));
        pthread_mutex_unlock(&ctx->lock);
        send_json(fd, buf, len);
        return 0;
    }

    /* POST /api/control */
    if (strcmp(req->path, "/api/control") == 0) {
        if (strcmp(req->method, "POST") != 0)
            return send_405(fd), 0;

        /* Parse action from POST body */
        pthread_mutex_lock(&ctx->lock);
        if (body && strstr(body, "pause"))
            ctx->paused = 1;
        else if (body && strstr(body, "resume"))
            ctx->paused = 0;
        pthread_mutex_unlock(&ctx->lock);

        const char *ok = "{\"ok\":true}";
        send_json(fd, ok, (int) strlen(ok));
        return 0;
    }

    send_404(fd);
    return 0;
}

/* Server thread. */

static void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void *server_thread_fn(void *arg)
{
    struct kbox_web_ctx *ctx = arg;
    struct epoll_event events[WEB_MAX_CLIENTS];

    /* Block signals in this thread */
    sigset_t mask;
    sigfillset(&mask);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    while (ctx->server_running) {
        int nfds = epoll_wait(ctx->epoll_fd, events, WEB_MAX_CLIENTS, 200);
        if (nfds < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;

            /* Shutdown signal */
            if (fd == ctx->shutdown_pipe[0]) {
                ctx->server_running = 0;
                break;
            }

            /* New connection */
            if (fd == ctx->listen_fd) {
                struct sockaddr_in addr;
                socklen_t alen = sizeof(addr);
                int client =
                    accept(ctx->listen_fd, (struct sockaddr *) &addr, &alen);
                if (client < 0)
                    continue;

                set_nonblocking(client);
                struct epoll_event ev = {.events = EPOLLIN, .data.fd = client};
                epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, client, &ev);
                continue;
            }

            /* Client data */
            if (events[i].events & EPOLLIN) {
                char reqbuf[WEB_REQ_LINE_MAX];
                ssize_t n = read(fd, reqbuf, sizeof(reqbuf) - 1);
                if (n <= 0) {
                    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                    close(fd);
                    continue;
                }
                reqbuf[n] = '\0';

                /* Reject oversized requests */
                if (n >= WEB_REQ_LINE_MAX - 1) {
                    const char *err =
                        "HTTP/1.1 413 Payload Too Large\r\n"
                        "Connection: close\r\n\r\n";
                    ssize_t written = write(fd, err, strlen(err));
                    (void) written;
                    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                    close(fd);
                    continue;
                }

                struct http_request req;
                if (parse_request_line(reqbuf, &req) < 0) {
                    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                    close(fd);
                    continue;
                }

                /* Find body after \r\n\r\n */
                const char *body = strstr(reqbuf, "\r\n\r\n");
                if (body)
                    body += 4;

                int keep = handle_request(ctx, fd, &req, body);
                if (!keep) {
                    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                    close(fd);
                }
            }
        }

        /* Periodically flush SSE events */
        pthread_mutex_lock(&ctx->lock);
        flush_sse_clients(ctx);
        pthread_mutex_unlock(&ctx->lock);
    }

    return NULL;
}

/* Syscall family classification. */

static enum kbox_syscall_family kbox_syscall_to_family(int host_nr)
{
#ifdef __x86_64__
    switch (host_nr) {
    case __NR_read:
    case __NR_write:
    case __NR_pread64:
    case __NR_pwrite64:
    case __NR_sendfile:
        return KBOX_FAM_FILE_IO;

    case __NR_getdents64:
    case __NR_mkdir:
    case __NR_rmdir:
    case __NR_unlink:
    case __NR_rename:
    case __NR_readlink:
    case __NR_symlink:
    case __NR_link:
    case __NR_mkdirat:
    case __NR_unlinkat:
    case __NR_renameat2:
    case __NR_readlinkat:
    case __NR_symlinkat:
    case __NR_linkat:
        return KBOX_FAM_DIR;

    case __NR_open:
    case __NR_openat:
    case __NR_close:
    case __NR_dup:
    case __NR_dup2:
    case __NR_dup3:
    case __NR_fcntl:
    case __NR_fstat:
    case __NR_newfstatat:
    case __NR_statx:
    case __NR_lseek:
    case __NR_flock:
    case __NR_fsync:
    case __NR_fdatasync:
    case __NR_ftruncate:
    case __NR_fallocate:
        return KBOX_FAM_FD_OPS;

    case __NR_getuid:
    case __NR_geteuid:
    case __NR_getgid:
    case __NR_getegid:
    case __NR_setuid:
    case __NR_setgid:
    case __NR_setreuid:
    case __NR_setregid:
    case __NR_getgroups:
    case __NR_setgroups:
    case __NR_setresuid:
    case __NR_setresgid:
    case __NR_getresuid:
    case __NR_getresgid:
    case __NR_setfsuid:
    case __NR_setfsgid:
        return KBOX_FAM_IDENTITY;

    case __NR_mmap:
    case __NR_mprotect:
    case __NR_munmap:
    case __NR_mremap:
    case __NR_brk:
    case __NR_madvise:
        return KBOX_FAM_MEMORY;

    case __NR_rt_sigaction:
    case __NR_rt_sigprocmask:
    case __NR_rt_sigreturn:
    case __NR_kill:
    case __NR_tgkill:
    case __NR_tkill:
    case __NR_signalfd4:
        return KBOX_FAM_SIGNALS;

    case __NR_sched_yield:
    case __NR_sched_setparam:
    case __NR_sched_getparam:
    case __NR_sched_setscheduler:
    case __NR_sched_getscheduler:
    case __NR_sched_get_priority_max:
    case __NR_sched_get_priority_min:
    case __NR_sched_setaffinity:
    case __NR_sched_getaffinity:
        return KBOX_FAM_SCHEDULER;

    default:
        return KBOX_FAM_OTHER;
    }
#elif defined(__aarch64__)
    /* aarch64 uses different syscall numbers; group by name instead */
    (void) host_nr;
    return KBOX_FAM_OTHER;
#else
    (void) host_nr;
    return KBOX_FAM_OTHER;
#endif
}

/* Public API. */

struct kbox_web_ctx *kbox_web_init(const struct kbox_web_config *cfg,
                                   const struct kbox_sysnrs *sysnrs)
{
    struct kbox_web_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->cfg = *cfg;
    ctx->sysnrs = sysnrs;
    ctx->boot_time_ns = kbox_clock_ns();
    ctx->rng_state = (uint32_t) ctx->boot_time_ns;

    if (ctx->cfg.port == 0)
        ctx->cfg.port = WEB_DEFAULT_PORT;
    if (!ctx->cfg.bind)
        ctx->cfg.bind = WEB_DEFAULT_BIND;
    if (ctx->cfg.sample_ms == 0)
        ctx->cfg.sample_ms = 100;

    pthread_mutex_init(&ctx->lock, NULL);
    kbox_event_ring_init(&ctx->events);

    ctx->shutdown_pipe[0] = -1;
    ctx->shutdown_pipe[1] = -1;
    ctx->listen_fd = -1;
    ctx->epoll_fd = -1;

    if (!cfg->enable_web)
        return ctx; /* telemetry-only mode, no HTTP server */

    /* Create TCP listener */
    ctx->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->listen_fd < 0) {
        fprintf(stderr, "web: socket: %s\n", strerror(errno));
        free(ctx);
        return NULL;
    }

    int opt = 1;
    setsockopt(ctx->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    set_nonblocking(ctx->listen_fd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t) ctx->cfg.port);
    if (inet_pton(AF_INET, ctx->cfg.bind, &addr.sin_addr) != 1) {
        fprintf(stderr, "web: invalid bind address: %s\n", ctx->cfg.bind);
        close(ctx->listen_fd);
        free(ctx);
        return NULL;
    }

    if (bind(ctx->listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        fprintf(stderr, "web: bind(%s:%d): %s\n", ctx->cfg.bind, ctx->cfg.port,
                strerror(errno));
        close(ctx->listen_fd);
        free(ctx);
        return NULL;
    }

    if (listen(ctx->listen_fd, 16) < 0) {
        fprintf(stderr, "web: listen: %s\n", strerror(errno));
        close(ctx->listen_fd);
        free(ctx);
        return NULL;
    }

    /* Create epoll + shutdown pipe */
    if (pipe(ctx->shutdown_pipe) < 0) {
        close(ctx->listen_fd);
        free(ctx);
        return NULL;
    }
    set_nonblocking(ctx->shutdown_pipe[0]);

    ctx->epoll_fd = epoll_create1(0);
    if (ctx->epoll_fd < 0) {
        close(ctx->listen_fd);
        close(ctx->shutdown_pipe[0]);
        close(ctx->shutdown_pipe[1]);
        free(ctx);
        return NULL;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = ctx->listen_fd;
    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->listen_fd, &ev);

    ev.data.fd = ctx->shutdown_pipe[0];
    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->shutdown_pipe[0], &ev);

    /* Start server thread */
    ctx->server_running = 1;
    if (pthread_create(&ctx->server_thread, NULL, server_thread_fn, ctx) != 0) {
        fprintf(stderr, "web: pthread_create: %s\n", strerror(errno));
        close(ctx->listen_fd);
        close(ctx->epoll_fd);
        close(ctx->shutdown_pipe[0]);
        close(ctx->shutdown_pipe[1]);
        free(ctx);
        return NULL;
    }

    fprintf(stderr, "kbox: web observatory at http://%s:%d/\n", ctx->cfg.bind,
            ctx->cfg.port);
    return ctx;
}

void kbox_web_shutdown(struct kbox_web_ctx *ctx)
{
    if (!ctx)
        return;

    if (ctx->server_running) {
        ctx->server_running = 0;
        /* Signal the server thread to wake up and exit */
        if (ctx->shutdown_pipe[1] >= 0) {
            ssize_t written = write(ctx->shutdown_pipe[1], "x", 1);
            (void) written;
        }
        pthread_join(ctx->server_thread, NULL);
    }

    /* Close SSE clients */
    for (int i = 0; i < ctx->sse_count; i++)
        close(ctx->sse_clients[i].fd);

    if (ctx->listen_fd >= 0)
        close(ctx->listen_fd);
    if (ctx->epoll_fd >= 0)
        close(ctx->epoll_fd);
    if (ctx->shutdown_pipe[0] >= 0)
        close(ctx->shutdown_pipe[0]);
    if (ctx->shutdown_pipe[1] >= 0)
        close(ctx->shutdown_pipe[1]);

    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}

void kbox_web_tick(struct kbox_web_ctx *ctx)
{
    if (!ctx || atomic_load(&ctx->paused))
        return;

    uint64_t now = kbox_clock_ns();
    uint64_t fast_interval_ns = (uint64_t) ctx->cfg.sample_ms * 1000000ULL;

    if (now - ctx->last_fast_tick < fast_interval_ns)
        return;

    ctx->last_fast_tick = now;

    /* Sample telemetry from LKL /proc files */
    struct kbox_telemetry_snapshot snap;
    kbox_telemetry_sample(ctx->sysnrs, &snap, ctx->boot_time_ns, ctx->fd_used,
                          KBOX_FD_TABLE_CAPACITY, &ctx->counters);

    /* Store snapshot under lock (web server thread reads it) */
    pthread_mutex_lock(&ctx->lock);
    ctx->snapshot = snap;

    /* Append to ring buffer */
    ctx->snap_ring[ctx->snap_ring_head] = snap;
    ctx->snap_ring_head = (ctx->snap_ring_head + 1) % SNAP_RING_SIZE;
    if (ctx->snap_ring_count < SNAP_RING_SIZE)
        ctx->snap_ring_count++;
    pthread_mutex_unlock(&ctx->lock);

    /* Trace to JSON fd if enabled */
    if (ctx->cfg.enable_trace && ctx->cfg.trace_fd >= 0) {
        char json[4096];
        int len = kbox_snapshot_to_json(&snap, json, sizeof(json) - 1);
        if (len > 0 && len < (int) sizeof(json) - 1) {
            json[len] = '\n';
            ssize_t written =
                write(ctx->cfg.trace_fd, json, (size_t) (len + 1));
            (void) written;
        }
    }
}

void kbox_web_record_syscall(struct kbox_web_ctx *ctx,
                             uint32_t pid,
                             int syscall_nr,
                             const char *syscall_name,
                             const uint64_t args[6],
                             enum kbox_disposition disp,
                             int64_t ret_val,
                             int error_nr,
                             uint64_t latency_ns)
{
    if (!ctx)
        return;

    /* Update counters (single-threaded, no locking needed) */
    struct kbox_telemetry_counters *c = &ctx->counters;
    c->syscall_total++;
    c->latency_total_ns += latency_ns;
    if (latency_ns > c->latency_max_ns)
        c->latency_max_ns = latency_ns;

    switch (disp) {
    case KBOX_DISP_CONTINUE:
        c->disp_continue++;
        break;
    case KBOX_DISP_RETURN:
        c->disp_return++;
        break;
    case KBOX_DISP_ENOSYS:
        c->disp_enosys++;
        if (syscall_nr >= 0 && syscall_nr < 1024) {
            c->enosys_hits[syscall_nr]++;
        } else {
            c->enosys_overflow++;
            c->enosys_overflow_last_nr = syscall_nr;
        }
        break;
    default:
        break;
    }

    /* Classify and count family */
    c->family[kbox_syscall_to_family(syscall_nr)]++;

    /* Push to event ring */
    struct kbox_syscall_event evt = {
        .timestamp_ns = kbox_clock_ns(),
        .pid = pid,
        .syscall_nr = syscall_nr,
        .syscall_name = syscall_name,
        .disposition = disp,
        .return_value = ret_val,
        .error_nr = error_nr,
        .latency_ns = latency_ns,
    };
    if (args)
        memcpy(evt.args, args, sizeof(evt.args));

    pthread_mutex_lock(&ctx->lock);
    kbox_event_push_syscall(&ctx->events, &ctx->rng_state, WEB_SAMPLE_PCTL,
                            &evt);
    pthread_mutex_unlock(&ctx->lock);

    /* Trace individual events to JSON fd */
    if (ctx->cfg.enable_trace && ctx->cfg.trace_fd >= 0) {
        struct kbox_event e;
        memset(&e, 0, sizeof(e));
        e.type = KBOX_EVT_SYSCALL;
        e.syscall = evt;
        char json[2048];
        int len = kbox_event_to_json(&e, json, sizeof(json) - 1);
        if (len > 0 && len < (int) sizeof(json) - 1) {
            json[len] = '\n';
            ssize_t written =
                write(ctx->cfg.trace_fd, json, (size_t) (len + 1));
            (void) written;
        }
    }
}


struct kbox_telemetry_counters *kbox_web_counters(struct kbox_web_ctx *ctx)
{
    return ctx ? &ctx->counters : NULL;
}

void kbox_web_set_fd_used(struct kbox_web_ctx *ctx, uint32_t n)
{
    if (ctx)
        ctx->fd_used = n;
}

#endif /* KBOX_HAS_WEB */
