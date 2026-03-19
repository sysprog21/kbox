/* SPDX-License-Identifier: MIT */
/*
 * web-telemetry.c - Telemetry sampler for the web observatory.
 *
 * Two-tier timer reads LKL-internal /proc files:
 *   Fast tick (100ms): /proc/stat, /proc/meminfo, /proc/vmstat, /proc/loadavg
 *   Slow tick (500ms): /proc/sched_debug, /proc/slabinfo, /proc/buddyinfo
 *
 * All reads go through kbox_lkl_openat/kbox_lkl_read -- these access
 * LKL's own procfs, not the host's.
 */

#ifdef KBOX_HAS_WEB

#include "kbox/web.h"

#include "kbox/lkl-wrap.h"
#include "kbox/syscall-nr.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* AT_FDCWD for LKL (asm-generic) */
#ifndef AT_FDCWD_LINUX
#define AT_FDCWD_LINUX (-100)
#endif

/* ------------------------------------------------------------------ */
/* Clock helpers                                                       */
/* ------------------------------------------------------------------ */

uint64_t kbox_clock_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

/* ------------------------------------------------------------------ */
/* LKL /proc reading                                                   */
/* ------------------------------------------------------------------ */

/*
 * Read a small /proc file from LKL into buf.
 * Returns bytes read or 0 on failure.
 */
static int read_lkl_proc(const struct kbox_sysnrs *s,
                         const char *path,
                         char *buf,
                         int bufsz)
{
    long fd = kbox_lkl_openat(s, AT_FDCWD_LINUX, path, 0 /* O_RDONLY */, 0);
    if (fd < 0)
        return 0;

    long nr = kbox_lkl_read(s, fd, buf, bufsz - 1);
    kbox_lkl_close(s, fd);

    if (nr <= 0)
        return 0;

    buf[nr] = '\0';
    return (int) nr;
}

/* ------------------------------------------------------------------ */
/* /proc parsers                                                       */
/* ------------------------------------------------------------------ */

/*
 * Parse /proc/stat for context switch count and softirq totals.
 */
static void parse_proc_stat(const char *buf,
                            struct kbox_telemetry_snapshot *snap)
{
    const char *p;

    p = strstr(buf, "ctxt ");
    if (p)
        snap->context_switches = strtoull(p + 5, NULL, 10);

    p = strstr(buf, "softirq ");
    if (p) {
        p += 8;
        /* Total followed by per-type counts on the same line */
        char *endp;
        snap->softirq_total = strtoull(p, &endp, 10);
        for (int i = 0; i < 10 && *endp; i++) {
            p = endp;
            snap->softirqs[i] = strtoull(p, &endp, 10);
            if (endp == p)
                break;
        }
    }
}

/*
 * Parse /proc/meminfo for memory stats (kB values).
 */
static void parse_proc_meminfo(const char *buf,
                               struct kbox_telemetry_snapshot *snap)
{
    const char *p;

    p = strstr(buf, "MemTotal:");
    if (p)
        snap->mem_total = strtoull(p + 9, NULL, 10);

    p = strstr(buf, "MemFree:");
    if (p)
        snap->mem_free = strtoull(p + 8, NULL, 10);

    p = strstr(buf, "MemAvailable:");
    if (p)
        snap->mem_available = strtoull(p + 13, NULL, 10);

    p = strstr(buf, "Buffers:");
    if (p)
        snap->buffers = strtoull(p + 8, NULL, 10);

    p = strstr(buf, "Cached:");
    if (p)
        snap->cached = strtoull(p + 7, NULL, 10);

    p = strstr(buf, "Slab:");
    if (p)
        snap->slab = strtoull(p + 5, NULL, 10);
}

/*
 * Parse /proc/vmstat for page fault counters.
 */
static void parse_proc_vmstat(const char *buf,
                              struct kbox_telemetry_snapshot *snap)
{
    const char *p;

    p = strstr(buf, "pgfault ");
    if (p)
        snap->pgfault = strtoull(p + 8, NULL, 10);

    p = strstr(buf, "pgmajfault ");
    if (p)
        snap->pgmajfault = strtoull(p + 11, NULL, 10);
}

/*
 * Parse /proc/loadavg.
 * Format: "0.01 0.05 0.00 1/42 123"
 * Store as fixed-point * 100.
 */
static void parse_proc_loadavg(const char *buf,
                               struct kbox_telemetry_snapshot *snap)
{
    double l1, l5, l15;
    if (sscanf(buf, "%lf %lf %lf", &l1, &l5, &l15) == 3) {
        snap->loadavg_1 = (uint32_t) (l1 * 100.0);
        snap->loadavg_5 = (uint32_t) (l5 * 100.0);
        snap->loadavg_15 = (uint32_t) (l15 * 100.0);
    }
}

/* ------------------------------------------------------------------ */
/* Sampler tick                                                        */
/* ------------------------------------------------------------------ */

/*
 * Per-tick time budget in nanoseconds (5ms).
 * If parsing exceeds this, skip remaining slow-tick files.
 */
#define TICK_BUDGET_NS (5 * 1000000ULL)

void kbox_telemetry_sample(const struct kbox_sysnrs *s,
                           struct kbox_telemetry_snapshot *snap,
                           uint64_t boot_time_ns,
                           uint32_t fd_used,
                           uint32_t fd_max,
                           const struct kbox_telemetry_counters *counters)
{
    char buf[4096];
    uint64_t tick_start = kbox_clock_ns();

    memset(snap, 0, sizeof(*snap));
    snap->version = KBOX_SNAPSHOT_VERSION;
    snap->timestamp_ns = tick_start;
    snap->uptime_ns = tick_start - boot_time_ns;
    snap->fd_table_used = fd_used;
    snap->fd_table_max = fd_max;

    /* Fast-tick files */
    if (read_lkl_proc(s, "/proc/stat", buf, sizeof(buf)))
        parse_proc_stat(buf, snap);

    if (read_lkl_proc(s, "/proc/meminfo", buf, sizeof(buf)))
        parse_proc_meminfo(buf, snap);

    if (read_lkl_proc(s, "/proc/vmstat", buf, sizeof(buf)))
        parse_proc_vmstat(buf, snap);

    if (read_lkl_proc(s, "/proc/loadavg", buf, sizeof(buf)))
        parse_proc_loadavg(buf, snap);

    /* Check budget before slow-tick files */
    if (kbox_clock_ns() - tick_start > TICK_BUDGET_NS)
        goto done;

    /* Slow-tick files (placeholder for Phase 2: sched_debug, slabinfo) */

done:
    /* Copy dispatch counters */
    snap->counters = *counters;
}

/* ------------------------------------------------------------------ */
/* JSON serialization                                                  */
/* ------------------------------------------------------------------ */

int kbox_snapshot_to_json(const struct kbox_telemetry_snapshot *snap,
                          char *buf,
                          int bufsz)
{
    return snprintf(
        buf, (size_t) bufsz,
        "{"
        "\"version\":%u,"
        "\"timestamp_ns\":%" PRIu64
        ","
        "\"uptime_ns\":%" PRIu64
        ","
        "\"context_switches\":%" PRIu64
        ","
        "\"softirq_total\":%" PRIu64
        ","
        "\"softirqs\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
        ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
        "],"
        "\"mem\":{\"total\":%" PRIu64 ",\"free\":%" PRIu64
        ",\"available\":%" PRIu64 ",\"buffers\":%" PRIu64 ",\"cached\":%" PRIu64
        ",\"slab\":%" PRIu64
        "},"
        "\"pgfault\":%" PRIu64 ",\"pgmajfault\":%" PRIu64
        ","
        "\"loadavg\":[%u.%02u,%u.%02u,%u.%02u],"
        "\"fd\":{\"used\":%u,\"max\":%u},"
        "\"dispatch\":{\"total\":%" PRIu64 ",\"continue\":%" PRIu64
        ",\"return\":%" PRIu64 ",\"enosys\":%" PRIu64
        "},"
        "\"family\":{\"file_io\":%" PRIu64 ",\"dir\":%" PRIu64
        ",\"fd_ops\":%" PRIu64 ",\"identity\":%" PRIu64 ",\"memory\":%" PRIu64
        ",\"signals\":%" PRIu64 ",\"scheduler\":%" PRIu64 ",\"other\":%" PRIu64
        "},"
        "\"latency\":{\"total_ns\":%" PRIu64 ",\"max_ns\":%" PRIu64
        "}"
        "}",
        snap->version, snap->timestamp_ns, snap->uptime_ns,
        snap->context_switches, snap->softirq_total, snap->softirqs[0],
        snap->softirqs[1], snap->softirqs[2], snap->softirqs[3],
        snap->softirqs[4], snap->softirqs[5], snap->softirqs[6],
        snap->softirqs[7], snap->softirqs[8], snap->softirqs[9],
        snap->mem_total, snap->mem_free, snap->mem_available, snap->buffers,
        snap->cached, snap->slab, snap->pgfault, snap->pgmajfault,
        snap->loadavg_1 / 100, snap->loadavg_1 % 100, snap->loadavg_5 / 100,
        snap->loadavg_5 % 100, snap->loadavg_15 / 100, snap->loadavg_15 % 100,
        snap->fd_table_used, snap->fd_table_max, snap->counters.syscall_total,
        snap->counters.disp_continue, snap->counters.disp_return,
        snap->counters.disp_enosys, snap->counters.family[KBOX_FAM_FILE_IO],
        snap->counters.family[KBOX_FAM_DIR],
        snap->counters.family[KBOX_FAM_FD_OPS],
        snap->counters.family[KBOX_FAM_IDENTITY],
        snap->counters.family[KBOX_FAM_MEMORY],
        snap->counters.family[KBOX_FAM_SIGNALS],
        snap->counters.family[KBOX_FAM_SCHEDULER],
        snap->counters.family[KBOX_FAM_OTHER], snap->counters.latency_total_ns,
        snap->counters.latency_max_ns);
}

/*
 * Escape a string for safe JSON embedding.
 * Handles: " \ and control characters (< 0x20).
 */
static int escape_json_str(const char *src, char *dst, int dstsz)
{
    int pos = 0;
    if (!src) {
        if (dstsz > 0)
            dst[0] = '\0';
        return 0;
    }
    for (; *src && pos < dstsz - 6; src++) {
        unsigned char c = (unsigned char) *src;
        if (c == '"' || c == '\\') {
            dst[pos++] = '\\';
            dst[pos++] = (char) c;
        } else if (c < 0x20) {
            pos += snprintf(dst + pos, (size_t) (dstsz - pos), "\\u%04x", c);
        } else {
            dst[pos++] = (char) c;
        }
    }
    if (pos < dstsz)
        dst[pos] = '\0';
    return pos;
}

int kbox_stats_to_json(const struct kbox_telemetry_snapshot *snap,
                       const char *guest_name,
                       char *buf,
                       int bufsz)
{
    uint64_t uptime_s = snap->uptime_ns / 1000000000ULL;
    uint64_t mem_used_mb = 0;
    char escaped[256];

    if (snap->mem_total > snap->mem_free)
        mem_used_mb = (snap->mem_total - snap->mem_free) / 1024;

    escape_json_str(guest_name ? guest_name : "unknown", escaped,
                    sizeof(escaped));
    return snprintf(buf, (size_t) bufsz,
                    "{\"uptime_s\":%" PRIu64 ",\"syscall_count\":%" PRIu64
                    ",\"guest\":\"%s\",\"lkl_mem_used_mb\":%" PRIu64 "}",
                    uptime_s, snap->counters.syscall_total, escaped,
                    mem_used_mb);
}

/* ------------------------------------------------------------------ */
/* ENOSYS hit tracking (JSON export)                                   */
/* ------------------------------------------------------------------ */

int kbox_enosys_to_json(const struct kbox_telemetry_counters *c,
                        char *buf,
                        int bufsz)
{
    int pos = 0;
    int first = 1;

    pos += snprintf(buf + pos, (size_t) (bufsz - pos), "{\"enosys_hits\":{");

    for (int i = 0; i < 1024; i++) {
        if (c->enosys_hits[i] == 0)
            continue;
        if (!first)
            pos += snprintf(buf + pos, (size_t) (bufsz - pos), ",");
        pos += snprintf(buf + pos, (size_t) (bufsz - pos), "\"%d\":%" PRIu64, i,
                        c->enosys_hits[i]);
        first = 0;
        if (pos >= bufsz - 64)
            break;
    }

    pos += snprintf(buf + pos, (size_t) (bufsz - pos),
                    "},\"overflow\":%" PRIu64 ",\"overflow_last_nr\":%d}",
                    c->enosys_overflow, c->enosys_overflow_last_nr);
    return pos;
}

#endif /* KBOX_HAS_WEB */
