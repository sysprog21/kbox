/* SPDX-License-Identifier: MIT */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kbox/cli.h"
#include "rewrite.h"

/* Long option codes for options without short equivalents */
enum {
    OPT_CHANGE_ID = 256,
    OPT_FORWARD_VERBOSE,
    OPT_MOUNT_PROFILE,
    OPT_NET,
    OPT_WEB,
    OPT_WEB_BIND,
    OPT_SYSCALL_MODE,
    OPT_TRACE_FORMAT,
    OPT_SQPOLL,
    OPT_HELP,
};

static const struct option longopts[] = {
    {"root-dir", required_argument, NULL, 'r'},
    {"recommended-root", required_argument, NULL, 'R'},
    {"system-root", required_argument, NULL, 'S'},
    {"fs-type", required_argument, NULL, 't'},
    {"part", required_argument, NULL, 'p'},
    {"work-dir", required_argument, NULL, 'w'},
    {"command", required_argument, NULL, 'c'},
    {"cmdline", required_argument, NULL, 'k'},
    {"mount-opts", required_argument, NULL, 'm'},
    {"bind-mount", required_argument, NULL, 'b'},
    {"root-id", no_argument, NULL, '0'},
    {"change-id", required_argument, NULL, OPT_CHANGE_ID},
    {"normalize", no_argument, NULL, 'n'},
    {"forward-verbose", no_argument, NULL, OPT_FORWARD_VERBOSE},
    {"mount-profile", required_argument, NULL, OPT_MOUNT_PROFILE},
    {"net", no_argument, NULL, OPT_NET},
    {"web", optional_argument, NULL, OPT_WEB},
    {"web-bind", required_argument, NULL, OPT_WEB_BIND},
    {"syscall-mode", required_argument, NULL, OPT_SYSCALL_MODE},
    {"sqpoll", no_argument, NULL, OPT_SQPOLL},
    {"trace-format", required_argument, NULL, OPT_TRACE_FORMAT},
    {"help", no_argument, NULL, OPT_HELP},
    {NULL, 0, NULL, 0},
};

static const char shortopts[] = "r:R:S:t:p:w:c:k:m:b:0nh";

void kbox_usage(const char *argv0)
{
    fprintf(
        stderr,
        "Usage: %s [OPTIONS] [-- COMMAND [ARGS...]]\n"
        "\n"
        "Boot a Linux kernel from a rootfs disk image.\n"
        "\n"
        "Options:\n"
        "  -r, --root-dir PATH        Rootfs image file path\n"
        "  -R, --recommended-root P   Image with recommended mounts\n"
        "  -S, --system-root PATH     Image with recommended mounts + root id\n"
        "  -t, --fs-type TYPE         Filesystem type (default: ext4)\n"
        "  -p, --part NUM             Partition number (0 = whole disk)\n"
        "  -w, --work-dir PATH        Working directory (default: /)\n"
        "  -c, --command CMD          Command to execute (default: /bin/sh)\n"
        "  -k, --cmdline STR          Kernel cmdline (default: mem=1024M "
        "loglevel=4)\n"
        "  -m, --mount-opts OPT       Mount option (repeatable)\n"
        "  -b, --bind-mount SRC:DST   Bind mount (repeatable)\n"
        "  -0, --root-id              Force uid=0 gid=0 inside guest\n"
        "      --change-id UID:GID    Set explicit identity\n"
        "  -n, --normalize            Normalize file permissions\n"
        "      --forward-verbose      Verbose syscall forwarding\n"
        "      --net                  Enable SLIRP user-mode networking\n"
        "      --mount-profile P      Mount profile: full (default), minimal\n"
        "      --syscall-mode MODE    Syscall path: auto (default), "
        "seccomp, trap, rewrite\n"
        "      --sqpoll               Busy-poll service thread (no futex)\n"
        "      --web[=PORT]           Enable web observatory (default: 8080)\n"
        "      --web-bind ADDR        Bind address for web (default: "
        "127.0.0.1)\n"
        "      --trace-format FMT     Trace output format (json)\n"
        "  -h, --help                 Show this help\n",
        argv0);
}

int kbox_parse_args(int argc, char *argv[], struct kbox_image_args *img)
{
    int c;
    bool command_from_option = false;

    if (!img)
        return -1;

    memset(img, 0, sizeof(*img));

    if (argc < 2) {
        kbox_usage(argv[0]);
        return -1;
    }

    img->fs_type = "ext4";
    img->work_dir = "/";
    img->command = "/bin/sh";
    img->cmdline = "mem=1024M loglevel=4";
    img->mount_profile = KBOX_MOUNT_FULL;
    img->syscall_mode = KBOX_SYSCALL_MODE_AUTO;

    /* Reset getopt state; kbox_parse_args may be called more than once
     * (e.g. across unit tests). */
    optind = 0;

    while ((c = getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
        switch (c) {
        case 'r':
            img->root_dir = optarg;
            break;
        case 'R':
            img->root_dir = optarg;
            img->recommended = true;
            break;
        case 'S':
            img->root_dir = optarg;
            img->system_root = true;
            img->recommended = true;
            img->root_id = true;
            break;
        case 't':
            img->fs_type = optarg;
            break;
        case 'p': {
            char *end;
            errno = 0;
            unsigned long v = strtoul(optarg, &end, 10);
            if (*end != '\0' || errno != 0 || v > UINT_MAX) {
                fprintf(stderr, "invalid partition: %s\n", optarg);
                return -1;
            }
            img->part = (unsigned) v;
            break;
        }
        case 'w':
            img->work_dir = optarg;
            break;
        case 'c':
            img->command = optarg;
            command_from_option = true;
            break;
        case 'k':
            img->cmdline = optarg;
            break;
        case 'm':
            if (img->mount_opt_count >= KBOX_MAX_MOUNT_OPTS) {
                fprintf(stderr, "too many mount options\n");
                return -1;
            }
            img->mount_opts[img->mount_opt_count++] = optarg;
            break;
        case 'b':
            if (img->bind_mount_count >= KBOX_MAX_BIND_MOUNTS) {
                fprintf(stderr, "too many bind mounts\n");
                return -1;
            }
            img->bind_mounts[img->bind_mount_count++] = optarg;
            break;
        case '0':
            img->root_id = true;
            break;
        case OPT_CHANGE_ID:
            img->change_id = optarg;
            break;
        case 'n':
            img->normalize = true;
            break;
        case OPT_FORWARD_VERBOSE:
            img->verbose = true;
            break;
        case OPT_NET:
#ifdef KBOX_HAS_SLIRP
            img->net = true;
#else
            fprintf(stderr,
                    "error: --net requires SLIRP support "
                    "(rebuild with KBOX_HAS_SLIRP=1)\n");
            return -1;
#endif
            break;
        case OPT_WEB:
#ifdef KBOX_HAS_WEB
            img->web = true;
            if (optarg) {
                char *end;
                unsigned long v = strtoul(optarg, &end, 10);
                if (*end != '\0' || v == 0 || v > 65535) {
                    fprintf(stderr, "invalid web port: %s\n", optarg);
                    return -1;
                }
                img->web_port = (int) v;
            }
#else
            fprintf(stderr,
                    "error: --web requires web support "
                    "(rebuild with KBOX_HAS_WEB=1)\n");
            return -1;
#endif
            break;
        case OPT_WEB_BIND:
#ifdef KBOX_HAS_WEB
            img->web_bind = optarg;
#else
            fprintf(stderr,
                    "error: --web-bind requires web support "
                    "(rebuild with KBOX_HAS_WEB=1)\n");
            return -1;
#endif
            break;
        case OPT_SYSCALL_MODE:
            if (kbox_parse_syscall_mode(optarg, &img->syscall_mode) < 0) {
                fprintf(stderr,
                        "unknown syscall mode: %s "
                        "(use 'seccomp', 'trap', 'rewrite', or 'auto')\n",
                        optarg);
                return -1;
            }
            break;
        case OPT_SQPOLL:
            img->sqpoll = true;
            break;
        case OPT_TRACE_FORMAT:
#ifdef KBOX_HAS_WEB
            if (strcmp(optarg, "json") != 0) {
                fprintf(stderr, "unknown trace format: %s (use 'json')\n",
                        optarg);
                return -1;
            }
            img->trace_format = optarg;
#else
            fprintf(stderr,
                    "error: --trace-format requires web support "
                    "(rebuild with KBOX_HAS_WEB=1)\n");
            return -1;
#endif
            break;
        case OPT_MOUNT_PROFILE:
            if (strcmp(optarg, "minimal") == 0)
                img->mount_profile = KBOX_MOUNT_MINIMAL;
            else if (strcmp(optarg, "full") == 0)
                img->mount_profile = KBOX_MOUNT_FULL;
            else {
                fprintf(stderr,
                        "unknown mount profile: %s "
                        "(use 'full' or 'minimal')\n",
                        optarg);
                return -1;
            }
            break;
        case 'h':
        case OPT_HELP:
            kbox_usage(argv[0]);
            return -1;
        default:
            kbox_usage(argv[0]);
            return -1;
        }
    }

    if (!img->root_dir) {
        fprintf(stderr, "error: one of -r, -R, or -S is required\n");
        kbox_usage(argv[0]);
        return -1;
    }

    /* Capture remaining arguments after getopt (i.e., after --). */
    if (optind < argc) {
        if (command_from_option) {
            img->extra_args = (const char *const *) &argv[optind];
            img->extra_argc = argc - optind;
        } else {
            img->command = argv[optind];
            if (optind + 1 < argc) {
                img->extra_args = (const char *const *) &argv[optind + 1];
                img->extra_argc = argc - optind - 1;
            }
        }
    }

    return 0;
}
