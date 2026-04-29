/* SPDX-License-Identifier: MIT */
/*
 * oci-chown -- restore OCI tar-header uid/gid/mode into ext4 inodes.
 *
 * mke2fs -d inherits the invoking user's UID into ext4 inodes. When kbox is
 * launched with --root-id (forces guest uid=0), the guest sees its own files
 * owned by a non-root UID, breaking apk install scripts and setuid binaries.
 * This helper opens the freshly-built ext4 image read-write via libext2fs and
 * rewrites uid/gid/mode per inode from a manifest emitted by oci-pull.py.
 *
 * Manifest format (NUL-separated records):
 *   <uid>\t<gid>\t<mode_octal>\t<path>\0
 * The root inode may be addressed as "." (or "/" for compatibility).
 * One record per regular file / directory / hardlink. Symlinks and device
 * nodes are not in the manifest (rootless cannot mknod; lchown is irrelevant
 * for our threat model -- the guest does not interpret symlink ownership).
 *
 * Build: make -C tools/oci-chown
 * Usage: oci-chown <image.ext4> <manifest>
 */

#include <ext2fs/ext2fs.h>

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int verbose = 0;

static void __attribute__((noreturn, format(printf, 1, 2))) die(const char *fmt,
                                                                ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("oci-chown: ", stderr);
    vfprintf(stderr, fmt, ap); /* format-ok: callers pass literal fmt */
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

/*
 * Read an entire file into memory. Caller frees *out_buf.
 * Manifests are bounded in practice (~50K entries * 100 bytes = 5MB), so
 * slurping is fine. We refuse anything over 64MB to bound memory.
 */
static void slurp(const char *path, char **out_buf, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        die("open %s: %s", path, strerror(errno));
    if (fseek(f, 0, SEEK_END) < 0)
        die("fseek %s: %s", path, strerror(errno));
    long len = ftell(f);
    if (len < 0)
        die("ftell %s: %s", path, strerror(errno));
    if (len > (64L << 20))
        die("manifest too large: %ld bytes", len);
    rewind(f);

    char *buf = malloc((size_t) len + 1);
    if (!buf)
        die("malloc");
    if (len && fread(buf, 1, (size_t) len, f) != (size_t) len)
        die("read %s: short", path);
    buf[len] = '\0';
    fclose(f);
    *out_buf = buf;
    *out_len = (size_t) len;
}

/*
 * Parse a non-negative integer field terminated by `sep` from `s`. Stores
 * the parsed value in *out and the position past the separator in *next.
 * Returns 0 on success, -1 on parse error or overflow past `max`.
 *
 * Reject leading whitespace, signs, and empty fields -- the manifest emitter
 * always produces clean digits.
 */
static int parse_field(const char *s,
                       char sep,
                       unsigned long max,
                       unsigned long *out,
                       char **next)
{
    if (!s || !*s || !isdigit((unsigned char) *s))
        return -1;
    errno = 0;
    char *end;
    unsigned long v = strtoul(s, &end, (sep == ' ') ? 8 : 10);
    if (errno || *end != sep || v > max)
        return -1;
    *out = v;
    *next = end + 1;
    return 0;
}

/*
 * Apply one record. Returns 0 on success, -1 on parse failure or namei miss.
 * Lookup misses are warnings, not fatal: a manifest entry may correspond to
 * a path that mke2fs -d skipped (e.g. dangling symlink target).
 */
static int apply_record(ext2_filsys fs, const char *rec)
{
    /* parse_field uses base 10 for sep != ' '; we use TAB everywhere here.
     * The mode field is octal in the manifest, parsed manually below. */
    char *p;
    unsigned long uid;
    if (parse_field(rec, '\t', UINT32_MAX, &uid, &p) < 0)
        return -1;
    unsigned long gid;
    if (parse_field(p, '\t', UINT32_MAX, &gid, &p) < 0)
        return -1;

    /* mode is octal. */
    if (!*p || !isdigit((unsigned char) *p))
        return -1;
    errno = 0;
    char *end;
    unsigned long mode = strtoul(p, &end, 8);
    if (errno || *end != '\t' || (mode & ~0007777UL))
        return -1;
    p = end + 1;

    const char *path = p;
    if (!*path)
        return -1;

    ext2_ino_t ino;
    errcode_t err;
    if (strcmp(path, ".") == 0 || strcmp(path, "/") == 0) {
        ino = EXT2_ROOT_INO;
        err = 0;
    } else {
        err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
    }
    if (err) {
        if (verbose)
            fprintf(stderr, "  namei %s: %s\n", path, error_message(err));
        return -1;
    }

    struct ext2_inode inode;
    err = ext2fs_read_inode(fs, ino, &inode);
    if (err)
        die("read_inode %s: %s", path, error_message(err));

    inode.i_uid = (uint16_t) (uid & 0xFFFFu);
    inode.osd2.linux2.l_i_uid_high = (uint16_t) ((uid >> 16) & 0xFFFFu);
    inode.i_gid = (uint16_t) (gid & 0xFFFFu);
    inode.osd2.linux2.l_i_gid_high = (uint16_t) ((gid >> 16) & 0xFFFFu);
    /* Preserve i_mode's type bits (S_IFREG, S_IFDIR, ...); rewrite perms. */
    inode.i_mode = (uint16_t) ((inode.i_mode & ~0007777u) | (mode & 0007777u));

    err = ext2fs_write_inode(fs, ino, &inode);
    if (err)
        die("write_inode %s: %s", path, error_message(err));

    return 0;
}

int main(int argc, char **argv)
{
    if (getenv("OCI_CHOWN_VERBOSE"))
        verbose = 1;
    if (argc != 3) {
        fprintf(stderr, "usage: %s <image.ext4> <manifest>\n", argv[0]);
        return 2;
    }
    const char *image = argv[1];
    const char *manifest = argv[2];

    /* Initialize libext2fs error tables. */
    initialize_ext2_error_table();

    ext2_filsys fs;
    errcode_t err =
        ext2fs_open(image, EXT2_FLAG_RW, 0, 0, unix_io_manager, &fs);
    if (err)
        die("ext2fs_open %s: %s", image, error_message(err));

    char *buf;
    size_t buflen;
    slurp(manifest, &buf, &buflen);

    size_t applied = 0, failed = 0, rec_idx = 0;
    char *p = buf;
    char *end = buf + buflen;
    while (p < end) {
        char *rec_end = memchr(p, '\0', (size_t) (end - p));
        if (!rec_end)
            die("manifest tail not NUL-terminated at byte %zu (record #%zu)",
                (size_t) (p - buf), rec_idx);
        if (rec_end != p) {
            if (apply_record(fs, p) == 0)
                applied++;
            else
                failed++;
        }
        p = rec_end + 1;
        rec_idx++;
    }
    free(buf);

    err = ext2fs_close(fs);
    if (err)
        die("ext2fs_close: %s", error_message(err));

    fprintf(stderr, "oci-chown: rewrote %zu inode(s)", applied);
    if (failed)
        fprintf(stderr, ", %zu missed", failed);
    fputc('\n', stderr);
    return 0;
}
