/* SPDX-License-Identifier: MIT */

#ifndef KBOX_CLI_H
#define KBOX_CLI_H

#include <stdbool.h>
#include "kbox/mount.h"

/* CLI argument structures and parsing. */

#define KBOX_MAX_BIND_MOUNTS 32
#define KBOX_MAX_MOUNT_OPTS 16

enum kbox_syscall_mode {
    KBOX_SYSCALL_MODE_SECCOMP,
    KBOX_SYSCALL_MODE_TRAP,
    KBOX_SYSCALL_MODE_REWRITE,
    KBOX_SYSCALL_MODE_AUTO,
};

struct kbox_image_args {
    const char *root_dir; /* -r: image file path */
    bool recommended;     /* -R: enable recommended mounts */
    bool system_root;     /* -S: recommended + root identity */
    const char *fs_type;  /* -t: filesystem type (default: ext4) */
    unsigned part;        /* -p: partition number (0 = whole disk) */
    const char *work_dir; /* -w: working directory (default: /) */
    const char *command;  /* -c: command to execute (default: /bin/sh) */
    const char *cmdline;  /* -k: cmdline (default: mem=1024M loglevel=4) */
    const char *mount_opts[KBOX_MAX_MOUNT_OPTS];
    int mount_opt_count;
    const char *bind_mounts[KBOX_MAX_BIND_MOUNTS];
    int bind_mount_count;
    bool root_id;                          /* -0: force uid=0 gid=0 */
    const char *change_id;                 /* --change-id UID:GID */
    bool normalize;                        /* -n: normalize permissions */
    bool verbose;                          /* --forward-verbose */
    bool net;                              /* --net: enable SLIRP networking */
    enum kbox_mount_profile mount_profile; /* --mount-profile */
    enum kbox_syscall_mode syscall_mode;   /* --syscall-mode */
    bool web;                              /* --web: enable web observatory */
    int web_port;                          /* --web=PORT (default 8080) */
    const char *web_bind;                  /* --web-bind ADDR */
    const char *trace_format;              /* --trace-format=json */
    bool sqpoll;                   /* --sqpoll: busy-poll service thread */
    const char *const *extra_args; /* remaining args after -- */
    int extra_argc;                /* count of extra_args */
};

/* Parse command-line arguments.
 * Returns 0 on success, -1 on error (message printed to stderr).
 */
int kbox_parse_args(int argc, char *argv[], struct kbox_image_args *out);

/* Print usage to stderr. */
void kbox_usage(const char *argv0);

#endif /* KBOX_CLI_H */
