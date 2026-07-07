/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "kbox/cli.h"
#include "kbox/ftrace.h"
#include "lkl-wrap.h"

#define KBOX_TRACE_DIR "/.kbox-tracing"

static int write_tracefs(const struct kbox_sysnrs *s,
                         const char *name,
                         const char *val)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", KBOX_TRACE_DIR, name);
    long fd = kbox_lkl_openat(s, AT_FDCWD_LINUX, path, O_WRONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "ftrace: open %s: %s\n", path, kbox_err_text(fd));
        return -1;
    }
    long n = kbox_lkl_write(s, fd, val, (long) strlen(val));
    kbox_lkl_close(s, fd);
    if (n < 0) {
        fprintf(stderr, "ftrace: write %s='%s': %s\n", path, val,
                kbox_err_text(n));
        return -1;
    }
    return 0;
}

static long read_lkl_file(const struct kbox_sysnrs *s,
                          const char *lkl_path,
                          char *buf,
                          long cap)
{
    long fd = kbox_lkl_openat(s, AT_FDCWD_LINUX, lkl_path, O_RDONLY, 0);
    if (fd < 0)
        return -1;
    long total = 0, n;
    while (total < cap - 1 &&
           (n = kbox_lkl_read(s, fd, buf + total, cap - 1 - total)) > 0)
        total += n;
    kbox_lkl_close(s, fd);
    buf[total < 0 ? 0 : total] = '\0';
    return total;
}

static long dump_lkl_to_host(const struct kbox_sysnrs *s,
                             const char *lkl_path,
                             const char *host_path)
{
    long fd = kbox_lkl_openat(s, AT_FDCWD_LINUX, lkl_path, O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "ftrace: open %s: %s\n", lkl_path, kbox_err_text(fd));
        return -1;
    }
    FILE *out = fopen(host_path, "w");
    if (!out) {
        fprintf(stderr, "ftrace: fopen %s: %s\n", host_path, strerror(errno));
        kbox_lkl_close(s, fd);
        return -1;
    }
    char buf[8192];
    long total = 0, n;
    while ((n = kbox_lkl_read(s, fd, buf, (long) sizeof(buf))) > 0) {
        fwrite(buf, 1, (size_t) n, out);
        total += n;
    }
    fclose(out);
    kbox_lkl_close(s, fd);
    return total;
}

static void dump_available_tracers(const struct kbox_sysnrs *s)
{
    char buf[512];
    if (read_lkl_file(s, KBOX_TRACE_DIR "/available_tracers", buf,
                      sizeof(buf)) > 0)
        fprintf(stderr, "ftrace: available_tracers: %s", buf);
}

static int mount_tracefs(const struct kbox_sysnrs *s)
{
    long ret = kbox_lkl_mkdir(s, KBOX_TRACE_DIR, 0755);
    if (ret < 0 && ret != -EEXIST) {
        fprintf(stderr, "ftrace: mkdir %s: %s\n", KBOX_TRACE_DIR,
                kbox_err_text(ret));
        return -1;
    }
    ret = kbox_lkl_mount(s, "tracefs", KBOX_TRACE_DIR, "tracefs", 0, NULL);
    if (ret < 0 && ret != -EBUSY) {
        fprintf(stderr, "ftrace: mount tracefs at %s: %s\n", KBOX_TRACE_DIR,
                kbox_err_text(ret));
        return -1;
    }
    return 0;
}

static int enable_events(const struct kbox_sysnrs *s,
                         const struct kbox_image_args *args)
{
    if (!args->ftrace_outdir) {
        fprintf(stderr, "ftrace: --ftrace-events requires --ftrace-outdir\n");
        return -1;
    }
    write_tracefs(s, "events/enable", "0");
    write_tracefs(s, "current_tracer", "nop");
    if (write_tracefs(s, "trace_clock", "boot") < 0)
        fprintf(stderr,
                "ftrace: trace_clock=boot unavailable, using default clock "
                "(start_ts alignment may differ)\n");
    write_tracefs(s, "options/record-tgid", "1");

    char list[512];
    snprintf(list, sizeof(list), "%s", args->ftrace_events);
    int enabled = 0;
    char *save = NULL;
    for (char *tok = strtok_r(list, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        char ev[256];
        snprintf(ev, sizeof(ev), "events/%s/enable", tok);
        if (write_tracefs(s, ev, "1") == 0)
            enabled++;
        else
            fprintf(stderr, "ftrace: event '%s' not found\n", tok);
    }
    if (enabled == 0) {
        fprintf(stderr, "ftrace: no events enabled\n");
        return -1;
    }

    write_tracefs(s, "tracing_on", "1");

    mkdir(args->ftrace_outdir, 0755);
    char up[128];
    if (read_lkl_file(s, "/proc/uptime", up, sizeof(up)) > 0) {
        char *sp = up;
        while (*sp && *sp != ' ' && *sp != '\n')
            sp++;
        *sp = '\0';
        char tspath[512];
        snprintf(tspath, sizeof(tspath), "%s/start_ts", args->ftrace_outdir);
        FILE *f = fopen(tspath, "w");
        if (f) {
            fprintf(f, "%s\n", up);
            fclose(f);
        } else {
            fprintf(stderr, "ftrace: fopen %s: %s\n", tspath, strerror(errno));
        }
    } else {
        fprintf(stderr,
                "ftrace: warning: could not read LKL /proc/uptime "
                "for start_ts\n");
    }

    fprintf(stderr, "ftrace: %d event(s) enabled, recording to %s\n", enabled,
            args->ftrace_outdir);
    return 0;
}

static void dump_events(const struct kbox_sysnrs *s,
                        const struct kbox_image_args *args)
{
    write_tracefs(s, "tracing_on", "0");
    mkdir(args->ftrace_outdir, 0755);
    char logpath[512];
    snprintf(logpath, sizeof(logpath), "%s/ftrace.log", args->ftrace_outdir);
    long n = dump_lkl_to_host(s, KBOX_TRACE_DIR "/trace", logpath);
    if (n >= 0)
        fprintf(stderr, "ftrace: wrote %ld bytes to %s\n", n, logpath);
}

static int enable_tracer(const struct kbox_sysnrs *s,
                         const struct kbox_image_args *args)
{
    if (args->ftrace_filter) {
        const char *ff = (strcmp(args->ftrace_tracer, "function_graph") == 0)
                             ? "set_graph_function"
                             : "set_ftrace_filter";
        if (write_tracefs(s, ff, args->ftrace_filter) < 0)
            fprintf(stderr,
                    "ftrace: warning: filter '%s' rejected "
                    "(need CONFIG_DYNAMIC_FTRACE and a valid symbol)\n",
                    args->ftrace_filter);
    }
    if (write_tracefs(s, "current_tracer", args->ftrace_tracer) < 0) {
        fprintf(/* format-ok */
                stderr,
                "ftrace: cannot select tracer '%s' "
                "(LKL has no HAVE_FUNCTION_GRAPH_TRACER; use "
                "--ftrace-events)\n",
                args->ftrace_tracer);
        dump_available_tracers(s);
        return -1;
    }
    write_tracefs(s, "tracing_on", "1");
    fprintf(stderr, "ftrace: tracer '%s' active%s%s\n", args->ftrace_tracer,
            args->ftrace_filter ? ", filter " : "",
            args->ftrace_filter ? args->ftrace_filter : "");
    return 0;
}

int kbox_ftrace_enable(const struct kbox_sysnrs *s,
                       const struct kbox_image_args *args)
{
    if (!args->ftrace_events && !args->ftrace_tracer)
        return 0;

    if (mount_tracefs(s) < 0)
        return -1;

    write_tracefs(s, "tracing_on", "0");
    write_tracefs(s, "trace", "");

    if (args->ftrace_events)
        return enable_events(s, args);
    return enable_tracer(s, args);
}

void kbox_ftrace_dump(const struct kbox_sysnrs *s,
                      const struct kbox_image_args *args)
{
    if (args->ftrace_events && args->ftrace_outdir) {
        dump_events(s, args);
        return;
    }
    if (args->ftrace_tracer && args->ftrace_dump) {
        write_tracefs(s, "tracing_on", "0");
        long n =
            dump_lkl_to_host(s, KBOX_TRACE_DIR "/trace", args->ftrace_dump);
        if (n >= 0)
            fprintf(stderr, "ftrace: wrote %ld bytes to %s\n", n,
                    args->ftrace_dump);
    }
}
