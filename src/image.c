/* SPDX-License-Identifier: MIT */
/*
 * image.c - Image mode lifecycle.
 *
 * Opens a rootfs disk image, registers it as an LKL block device,
 * boots the kernel, mounts the filesystem, chroots in, applies
 * recommended / bind mounts, sets identity, and then forks the
 * seccomp-supervised child process.
 *
 */

#include "kbox/image.h"
#include "kbox/elf.h"
#include "kbox/identity.h"
#include "kbox/lkl-wrap.h"
#include "kbox/mount.h"
#include "kbox/net.h"
#include "kbox/probe.h"
#include "kbox/seccomp.h"
#include "kbox/shadow-fd.h"
#ifdef KBOX_HAS_WEB
#include "kbox/web.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/*
 * Determine the root image path from the three mutually exclusive
 * options.  Returns the path, or NULL on error.
 */
static const char *select_root_path(const struct kbox_image_args *a)
{
    if (a->system_root)
        return a->root_dir;
    if (a->recommended)
        return a->root_dir;
    if (a->root_dir)
        return a->root_dir;

    fprintf(stderr, "no rootfs image specified (-r, -R, or -S)\n");
    return NULL;
}

/*
 * Join mount_opts[] into a single comma-separated string.
 * Writes into buf[bufsz].  Returns buf, or "" if no options.
 */
static const char *join_mount_opts(const struct kbox_image_args *a,
                                   char *buf,
                                   size_t bufsz)
{
    size_t pos = 0;
    int i;

    buf[0] = '\0';
    for (i = 0; i < a->mount_opt_count; i++) {
        size_t len = strlen(a->mount_opts[i]);
        if (pos + len + 2 > bufsz)
            break;
        if (pos > 0)
            buf[pos++] = ',';
        memcpy(buf + pos, a->mount_opts[i], len);
        pos += len;
    }
    buf[pos] = '\0';
    return buf;
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                  */
/* ------------------------------------------------------------------ */

int kbox_run_image(const struct kbox_image_args *args)
{
    const char *root_path;
    int image_fd;
    struct lkl_disk disk;
    int disk_id;
    char mount_buf[256];
    char opts_buf[1024];
    const char *opts;
    const char *fs_type;
    const char *work_dir;
    const char *command;
    const struct kbox_sysnrs *sysnrs;
    long ret;
    struct kbox_bind_spec bind_specs[KBOX_MAX_BIND_MOUNTS];
    int bind_count = 0;
    int i;
    uid_t override_uid = (uid_t) -1;
    gid_t override_gid = (gid_t) -1;

    /* --- Resolve parameters with defaults --- */
    root_path = select_root_path(args);
    if (!root_path)
        return -1;

    fs_type = args->fs_type ? args->fs_type : "ext4";
    work_dir = args->work_dir ? args->work_dir : "/";
    command = args->command ? args->command : "/bin/sh";

    /* --- Parse bind mount specs --- */
    for (i = 0; i < args->bind_mount_count; i++) {
        if (kbox_parse_bind_spec(args->bind_mounts[i], &bind_specs[i]) < 0)
            return -1;
        bind_count++;
    }

    /* --- Open image file --- */
    image_fd = open(root_path, O_RDWR);
    if (image_fd < 0) {
        fprintf(stderr, "open(%s): %s\n", root_path, strerror(errno));
        return -1;
    }

    /* --- Register as LKL block device --- */
    memset(&disk, 0, sizeof(disk));
    disk.dev = NULL;
    disk.fd = image_fd;
    disk.ops = &lkl_dev_blk_ops;

    disk_id = lkl_disk_add(&disk);
    if (disk_id < 0) {
        fprintf(stderr, "lkl_disk_add: %s (%d)\n",
                kbox_err_text((long) disk_id), disk_id);
        return -1;
    }

    /* --- Register netdev BEFORE boot (LKL probes during boot) --- */
    if (args->net) {
        if (kbox_net_add_device() < 0)
            return -1;
    }

    /* --- Boot the LKL kernel --- */
    if (kbox_boot_kernel(args->cmdline) < 0) {
        if (args->net)
            kbox_net_cleanup();
        return -1;
    }

    /* --- Mount the filesystem --- */
    opts = join_mount_opts(args, opts_buf, sizeof(opts_buf));
    ret = lkl_mount_dev((unsigned) disk_id, args->part, fs_type, 0,
                        opts[0] ? opts : NULL, mount_buf, sizeof(mount_buf));
    if (ret < 0) {
        fprintf(stderr, "lkl_mount_dev: %s (%ld)\n", kbox_err_text(ret), ret);
        if (args->net)
            kbox_net_cleanup();
        return -1;
    }

    /* --- Detect syscall ABI --- */
    sysnrs = detect_sysnrs();
    if (!sysnrs) {
        fprintf(stderr, "detect_sysnrs failed\n");
        if (args->net)
            kbox_net_cleanup();
        return -1;
    }

    /* --- Chroot into mountpoint --- */
    ret = kbox_lkl_chroot(sysnrs, mount_buf);
    if (ret < 0) {
        fprintf(stderr, "chroot(%s): %s\n", mount_buf, kbox_err_text(ret));
        if (args->net)
            kbox_net_cleanup();
        return -1;
    }

    /* --- Recommended mounts --- */
    if (args->recommended || args->system_root) {
        if (kbox_apply_recommended_mounts(sysnrs, args->mount_profile) < 0) {
            if (args->net)
                kbox_net_cleanup();
            return -1;
        }
    }

    /* --- Bind mounts --- */
    if (bind_count > 0) {
        if (kbox_apply_bind_mounts(sysnrs, bind_specs, bind_count) < 0) {
            if (args->net)
                kbox_net_cleanup();
            return -1;
        }
    }

    /* --- Working directory --- */
    ret = kbox_lkl_chdir(sysnrs, work_dir);
    if (ret < 0) {
        fprintf(stderr, "chdir(%s): %s\n", work_dir, kbox_err_text(ret));
        if (args->net)
            kbox_net_cleanup();
        return -1;
    }

    /* --- Identity --- */
    if (args->change_id) {
        if (kbox_parse_change_id(args->change_id, &override_uid,
                                 &override_gid) < 0) {
            if (args->net)
                kbox_net_cleanup();
            return -1;
        }
    }

    {
        int root_id = args->root_id || args->system_root;
        if (kbox_apply_guest_identity(sysnrs, root_id, override_uid,
                                      override_gid) < 0) {
            if (args->net)
                kbox_net_cleanup();
            return -1;
        }
    }

    /* --- Probe host features --- */
    if (kbox_probe_host_features() < 0) {
        if (args->net)
            kbox_net_cleanup();
        return -1;
    }

    /* --- Networking: configure interface (optional) --- */
    if (args->net) {
        if (kbox_net_configure(sysnrs) < 0) {
            kbox_net_cleanup();
            return -1;
        }
    }

    /* --- Web observatory (optional) --- */
    struct kbox_web_ctx *web_ctx = NULL;
#ifdef KBOX_HAS_WEB
    if (args->web || args->trace_format) {
        struct kbox_web_config wcfg;
        memset(&wcfg, 0, sizeof(wcfg));
        wcfg.enable_web = args->web;
        wcfg.port = args->web_port;
        wcfg.bind = args->web_bind;
        wcfg.guest_name = command;
        if (args->trace_format) {
            wcfg.enable_trace = 1;
            wcfg.trace_fd = STDERR_FILENO;
        }
        web_ctx = kbox_web_init(&wcfg, sysnrs);
        if (!web_ctx) {
            fprintf(stderr, "warning: failed to initialize web observatory\n");
            /* Non-fatal: continue without telemetry */
        }
    }
#endif

    /*
     * --- Extract binary from LKL into memfd ---
     *
     * The child process will exec via fexecve(memfd), because
     * the binary lives inside the LKL-mounted filesystem and
     * does not exist on the host.
     *
     * For dynamically-linked binaries, the ELF contains a PT_INTERP
     * segment naming the interpreter (e.g. /lib/ld-musl-x86_64.so.1).
     * The host kernel resolves PT_INTERP from the host VFS, not the
     * LKL image, so the interpreter cannot be found.  Fix: extract
     * the interpreter into a second memfd and patch PT_INTERP in the
     * main binary to /proc/self/fd/<interp_fd>.  The kernel opens
     * /proc/self/fd/N during load_elf_binary (before close-on-exec),
     * so both memfds can keep MFD_CLOEXEC.
     */
    {
        long lkl_fd;
        int exec_memfd;
        int interp_memfd = -1;
        int rc = -1;

        lkl_fd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, command, O_RDONLY, 0);
        if (lkl_fd < 0) {
            fprintf(stderr, "cannot open %s in image: %s\n", command,
                    kbox_err_text(lkl_fd));
            goto err_net;
        }

        exec_memfd = kbox_shadow_create(sysnrs, lkl_fd);
        kbox_lkl_close(sysnrs, lkl_fd);

        if (exec_memfd < 0) {
            fprintf(stderr, "cannot create memfd for %s: %s\n", command,
                    strerror(-exec_memfd));
            goto err_net;
        }

        /*
         * Check for PT_INTERP (dynamic binary).  Read the first 4 KB
         * of the memfd -- enough for the ELF header and program header
         * table of any reasonable binary.
         */
        {
            unsigned char elf_buf[4096];
            ssize_t nr = pread(exec_memfd, elf_buf, sizeof(elf_buf), 0);

            if (nr > 0) {
                char interp_path[256];
                uint64_t pt_offset, pt_filesz;
                int ilen = kbox_find_elf_interp_loc(
                    elf_buf, (size_t) nr, interp_path, sizeof(interp_path),
                    &pt_offset, &pt_filesz);

                if (ilen > 0) {
                    /*
                     * Dynamic binary: extract the interpreter from LKL.
                     */
                    long interp_lkl_fd = kbox_lkl_openat(
                        sysnrs, AT_FDCWD_LINUX, interp_path, O_RDONLY, 0);
                    if (interp_lkl_fd < 0) {
                        fprintf(stderr,
                                "cannot open interpreter %s in image: %s\n",
                                interp_path, kbox_err_text(interp_lkl_fd));
                        close(exec_memfd);
                        goto err_net;
                    }

                    interp_memfd = kbox_shadow_create(sysnrs, interp_lkl_fd);
                    kbox_lkl_close(sysnrs, interp_lkl_fd);

                    if (interp_memfd < 0) {
                        fprintf(stderr,
                                "cannot create memfd for interpreter %s: %s\n",
                                interp_path, strerror(-interp_memfd));
                        close(exec_memfd);
                        goto err_net;
                    }

                    /*
                     * Patch PT_INTERP in the main binary memfd to point
                     * to /proc/self/fd/<interp_memfd>.  The child inherits
                     * both memfds via fork; the kernel resolves the patched
                     * path during exec.
                     */
                    char new_interp[64];
                    int new_len = snprintf(new_interp, sizeof(new_interp),
                                           "/proc/self/fd/%d", interp_memfd);

                    if ((uint64_t) (new_len + 1) > pt_filesz) {
                        fprintf(stderr,
                                "PT_INTERP segment too small for "
                                "patched path (%d+1 > %lu)\n",
                                new_len, (unsigned long) pt_filesz);
                        close(interp_memfd);
                        close(exec_memfd);
                        goto err_net;
                    }

                    /*
                     * Write the new path, zero-filling the rest of the
                     * PT_INTERP segment.  pwrite does not change the
                     * file offset.
                     */
                    char patch[256];
                    size_t patch_len = (size_t) pt_filesz;
                    if (patch_len > sizeof(patch))
                        patch_len = sizeof(patch);
                    memset(patch, 0, patch_len);
                    memcpy(patch, new_interp, (size_t) new_len);

                    if (pwrite(exec_memfd, patch, patch_len,
                               (off_t) pt_offset) != (ssize_t) patch_len) {
                        fprintf(stderr, "failed to patch PT_INTERP: %s\n",
                                strerror(errno));
                        close(interp_memfd);
                        close(exec_memfd);
                        goto err_net;
                    }

                    if (args->verbose) {
                        fprintf(stderr,
                                "kbox: dynamic binary %s: "
                                "interpreter %s -> /proc/self/fd/%d\n",
                                command, interp_path, interp_memfd);
                    }
                }
            }
        }

        /* Fork, seccomp, exec, supervise. */
        rc = kbox_run_supervisor(
            sysnrs, command, args->extra_args, args->extra_argc, NULL,
            exec_memfd, args->verbose, args->root_id || args->system_root,
            args->normalize, web_ctx);
        if (interp_memfd >= 0)
            close(interp_memfd);
        close(exec_memfd);

    err_net:
#ifdef KBOX_HAS_WEB
        if (web_ctx)
            kbox_web_shutdown(web_ctx);
#endif
        if (args->net)
            kbox_net_cleanup();
        return rc;
    }
}
