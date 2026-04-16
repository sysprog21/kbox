/* SPDX-License-Identifier: MIT */
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "kbox/elf.h"
#include "test-runner.h"

#define ET_EXEC 2
#define ET_DYN 3
#define PT_LOAD 1
#define PT_INTERP 3
#define PT_PHDR 6
#define PT_GNU_STACK 0x6474e551u
#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

static void set_le16(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char) (v & 0xff);
    p[1] = (unsigned char) ((v >> 8) & 0xff);
}

static void set_le32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char) (v & 0xff);
    p[1] = (unsigned char) ((v >> 8) & 0xff);
    p[2] = (unsigned char) ((v >> 16) & 0xff);
    p[3] = (unsigned char) ((v >> 24) & 0xff);
}

static void set_le64(unsigned char *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (unsigned char) ((v >> (i * 8)) & 0xff);
}

static void init_elf64(unsigned char *buf,
                       size_t buf_size,
                       uint16_t type,
                       uint16_t machine,
                       uint64_t entry,
                       uint64_t phoff,
                       uint16_t phnum)
{
    memset(buf, 0, buf_size);
    buf[0] = 0x7f;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    set_le16(buf + 16, type);
    set_le16(buf + 18, machine);
    set_le32(buf + 20, 1);
    set_le64(buf + 24, entry);
    set_le64(buf + 32, phoff);
    set_le16(buf + 52, 64);
    set_le16(buf + 54, 56);
    set_le16(buf + 56, phnum);
}

static void set_phdr(unsigned char *buf,
                     size_t index,
                     uint32_t type,
                     uint32_t flags,
                     uint64_t offset,
                     uint64_t vaddr,
                     uint64_t filesz,
                     uint64_t memsz,
                     uint64_t align)
{
    unsigned char *ph = buf + 64 + index * 56;

    set_le32(ph + 0, type);
    set_le32(ph + 4, flags);
    set_le64(ph + 8, offset);
    set_le64(ph + 16, vaddr);
    set_le64(ph + 32, filesz);
    set_le64(ph + 40, memsz);
    set_le64(ph + 48, align);
}

/* Minimal 64-bit little-endian ELF with one PT_INTERP program header. */
static const unsigned char elf_with_interp[] = {
    /* ELF header (64 bytes) */
    0x7f,
    'E',
    'L',
    'F', /* magic */
    2,   /* class: 64-bit */
    1,   /* data: little-endian */
    1,   /* version */
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* padding */
    2,
    0, /* type: ET_EXEC */
    0x3e,
    0, /* machine: x86_64 */
    1,
    0,
    0,
    0, /* version */
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* entry */
    /* phoff = 64 (offset 32..39) */
    64,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* shoff */
    0,
    0,
    0,
    0, /* flags */
    64,
    0, /* ehsize */
    56,
    0, /* phentsize */
    1,
    0, /* phnum = 1 */
    0,
    0, /* shentsize */
    0,
    0, /* shnum */
    0,
    0, /* shstrndx */

    /* Program header (56 bytes) at offset 64 */
    3,
    0,
    0,
    0, /* p_type = PT_INTERP (3) */
    0,
    0,
    0,
    0, /* p_flags */
    /* p_offset = 120 (offset 64+8..64+15) */
    120,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* p_vaddr */
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* p_paddr */
    /* p_filesz = 28 (offset 64+32..64+39) */
    28,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* p_memsz */
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* p_align */

    /* Interpreter string at offset 120 */
    '/',
    'l',
    'i',
    'b',
    '6',
    '4',
    '/',
    'l',
    'd',
    '-',
    'l',
    'i',
    'n',
    'u',
    'x',
    '-',
    'x',
    '8',
    '6',
    '-',
    '6',
    '4',
    '.',
    's',
    'o',
    '.',
    '2',
    0,
};

/* Static binary: no PT_INTERP */
static const unsigned char elf_static[] = {
    /* ELF header (64 bytes) */
    0x7f,
    'E',
    'L',
    'F',
    2,
    1,
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    2,
    0, /* ET_EXEC */
    0x3e,
    0, /* x86_64 */
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* entry */
    64,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* phoff */
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    64,
    0,
    56,
    0,
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,

    /* PT_LOAD header (not PT_INTERP) */
    1,
    0,
    0,
    0, /* p_type = PT_LOAD (1) */
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
};

static void test_elf_parse_interp(void)
{
    char out[256];
    int len = kbox_parse_elf_interp(elf_with_interp, sizeof(elf_with_interp),
                                    out, sizeof(out));
    ASSERT_TRUE(len > 0);
    ASSERT_STREQ(out, "/lib64/ld-linux-x86-64.so.2");
}

static void test_elf_static_no_interp(void)
{
    char out[256];
    int len =
        kbox_parse_elf_interp(elf_static, sizeof(elf_static), out, sizeof(out));
    ASSERT_EQ(len, 0);
}

static void test_elf_too_short(void)
{
    unsigned char buf[32] = {0x7f, 'E', 'L', 'F'};
    char out[256];
    int len = kbox_parse_elf_interp(buf, sizeof(buf), out, sizeof(out));
    ASSERT_EQ(len, -1);
}

static void test_elf_bad_magic(void)
{
    unsigned char buf[64] = {0};
    char out[256];
    int len = kbox_parse_elf_interp(buf, sizeof(buf), out, sizeof(out));
    ASSERT_EQ(len, -1);
}

static void test_elf_32bit_rejected(void)
{
    unsigned char buf[64] = {0x7f, 'E', 'L', 'F', 1 /* 32-bit */, 1};
    char out[256];
    int len = kbox_parse_elf_interp(buf, sizeof(buf), out, sizeof(out));
    ASSERT_EQ(len, -1);
}

static void test_elf_find_interp_loc(void)
{
    char out[256];
    uint64_t offset = 0, filesz = 0;
    int len = kbox_find_elf_interp_loc(elf_with_interp, sizeof(elf_with_interp),
                                       out, sizeof(out), &offset, &filesz);
    ASSERT_TRUE(len > 0);
    ASSERT_STREQ(out, "/lib64/ld-linux-x86-64.so.2");
    ASSERT_EQ(offset, 120);
    ASSERT_EQ(filesz, 28);
}

static void test_elf_find_interp_loc_static(void)
{
    char out[256];
    uint64_t offset = 0, filesz = 0;
    int len = kbox_find_elf_interp_loc(elf_static, sizeof(elf_static), out,
                                       sizeof(out), &offset, &filesz);
    ASSERT_EQ(len, 0);
    /* offset/filesz should be unchanged (not written for static) */
    ASSERT_EQ(offset, 0);
    ASSERT_EQ(filesz, 0);
}

static void test_elf_read_header_window_fd(void)
{
    char path[128];
    unsigned char *buf = NULL;
    size_t buf_len = 0;
    int fd = test_mkstemp(path, sizeof(path), "kbox-elf-unit");

    ASSERT_TRUE(fd >= 0);
    unlink(path);
    ASSERT_EQ(write(fd, elf_with_interp, sizeof(elf_with_interp)),
              (long) sizeof(elf_with_interp));
    ASSERT_EQ(kbox_read_elf_header_window_fd(fd, &buf, &buf_len), 0);
    ASSERT_EQ(buf_len, sizeof(elf_with_interp));
    ASSERT_EQ(memcmp(buf, elf_with_interp, buf_len), 0);
    munmap(buf, buf_len);
    close(fd);
}

static void test_elf_read_header_window_fd_large_phoff(void)
{
    unsigned char elf[5000];
    char path[128];
    unsigned char *buf = NULL;
    size_t buf_len = 0;
    int fd;

    memset(elf, 0, sizeof(elf));
    memcpy(elf, elf_with_interp, 64);
    /* Move phoff to 4096 and keep one PT_INTERP entry there. */
    elf[32] = 0x00;
    elf[33] = 0x10;
    elf[34] = 0x00;
    elf[35] = 0x00;
    elf[36] = 0x00;
    elf[37] = 0x00;
    elf[38] = 0x00;
    elf[39] = 0x00;
    memcpy(elf + 4096, elf_with_interp + 64, 56);
    fd = test_mkstemp(path, sizeof(path), "kbox-elf-unit");

    ASSERT_TRUE(fd >= 0);
    unlink(path);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (long) sizeof(elf));
    ASSERT_EQ(kbox_read_elf_header_window_fd(fd, &buf, &buf_len), 0);
    ASSERT_EQ(buf_len, 4152);
    ASSERT_EQ(memcmp(buf, elf, buf_len), 0);
    munmap(buf, buf_len);
    close(fd);
}

static void test_elf_build_load_plan_exec(void)
{
    unsigned char elf[1024];
    struct kbox_elf_load_plan plan;

    init_elf64(elf, sizeof(elf), ET_EXEC, 0x3e, 0x401020, 64, 3);
    set_phdr(elf, 0, PT_LOAD, PF_R | PF_X, 0, 0x400000, 0x200, 0x300, 0x1000);
    set_phdr(elf, 1, PT_LOAD, PF_R | PF_W, 0x200, 0x401000, 0x80, 0x200,
             0x1000);
    set_phdr(elf, 2, PT_INTERP, 0, 0x180, 0, 8, 8, 1);
    memcpy(elf + 0x180, "/ld.so\0", 8);

    ASSERT_EQ(kbox_build_elf_load_plan(elf, sizeof(elf), 0x1000, &plan), 0);
    ASSERT_EQ(plan.machine, 0x3e);
    ASSERT_EQ(plan.type, ET_EXEC);
    ASSERT_EQ(plan.entry, 0x401020);
    ASSERT_EQ(plan.segment_count, 2);
    ASSERT_EQ(plan.pie, 0);
    ASSERT_EQ(plan.has_interp, 1);
    ASSERT_EQ(plan.interp_offset, 0x180);
    ASSERT_EQ(plan.interp_size, 8);
    ASSERT_EQ(plan.phdr_vaddr, 0x400040);
    ASSERT_EQ(plan.min_vaddr, 0x400000);
    ASSERT_EQ(plan.max_vaddr, 0x402000);
    ASSERT_EQ(plan.load_size, 0x2000);
    ASSERT_EQ(plan.segments[0].map_start, 0x400000);
    ASSERT_EQ(plan.segments[0].map_offset, 0);
    ASSERT_EQ(plan.segments[0].map_size, 0x1000);
    ASSERT_EQ(plan.segments[1].map_start, 0x401000);
    ASSERT_EQ(plan.segments[1].map_offset, 0);
    ASSERT_EQ(plan.segments[1].map_size, 0x1000);
}

static void test_elf_build_load_plan_pie_with_phdr_and_stack(void)
{
    unsigned char elf[1024];
    struct kbox_elf_load_plan plan;

    init_elf64(elf, sizeof(elf), ET_DYN, 0xb0, 0x120, 64, 4);
    set_phdr(elf, 0, PT_PHDR, PF_R, 64, 0x40, 224, 224, 8);
    set_phdr(elf, 1, PT_LOAD, PF_R | PF_X, 0, 0, 0x220, 0x220, 0x1000);
    set_phdr(elf, 2, PT_LOAD, PF_R | PF_W, 0x220, 0x2000, 0x40, 0x100, 0x1000);
    set_phdr(elf, 3, PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 16);

    ASSERT_EQ(kbox_build_elf_load_plan(elf, sizeof(elf), 0x1000, &plan), 0);
    ASSERT_EQ(plan.machine, 0xb0);
    ASSERT_EQ(plan.type, ET_DYN);
    ASSERT_EQ(plan.pie, 1);
    ASSERT_EQ(plan.phdr_vaddr, 0x40);
    ASSERT_EQ(plan.stack_flags, PF_R | PF_W);
    ASSERT_EQ(plan.segment_count, 2);
    ASSERT_EQ(plan.min_vaddr, 0);
    ASSERT_EQ(plan.max_vaddr, 0x3000);
    ASSERT_EQ(plan.load_size, 0x3000);
}

static void test_elf_build_load_plan_honors_large_segment_align(void)
{
    unsigned char *elf;
    size_t elf_len = 0xb1000;
    struct kbox_elf_load_plan plan;

    elf = calloc(1, elf_len);
    ASSERT_NE(elf, NULL);
    init_elf64(elf, elf_len, ET_DYN, 0xb7, 0x696cc, 64, 2);
    set_phdr(elf, 0, PT_LOAD, PF_R | PF_X, 0, 0, 0xa19f4, 0xa19f4, 0x10000);
    set_phdr(elf, 1, PT_LOAD, PF_R | PF_W, 0xafb00, 0xbfb00, 0x904, 0x3410,
             0x10000);

    ASSERT_EQ(kbox_build_elf_load_plan(elf, elf_len, 0x1000, &plan), 0);
    ASSERT_EQ(plan.segment_count, 2);
    ASSERT_EQ(plan.segments[1].map_offset, 0xa0000);
    ASSERT_EQ(plan.segments[1].map_start, 0xb0000);
    ASSERT_EQ(plan.segments[1].map_size, 0x20000);
    ASSERT_EQ(plan.max_vaddr, 0xd0000);
    free(elf);
}

static void test_elf_build_load_plan_rejects_filesz_gt_memsz(void)
{
    unsigned char elf[256];
    struct kbox_elf_load_plan plan;

    init_elf64(elf, sizeof(elf), ET_EXEC, 0x3e, 0x400000, 64, 1);
    set_phdr(elf, 0, PT_LOAD, PF_R | PF_X, 0, 0x400000, 0x200, 0x100, 0x1000);

    ASSERT_EQ(kbox_build_elf_load_plan(elf, sizeof(elf), 0x1000, &plan), -1);
}

/* PT_INTERP segment extends beyond the ELF buffer (p_offset + p_filesz >
 * buf_len). */
static void test_elf_interp_rejects_segment_overflow(void)
{
    unsigned char elf[256];
    char out[256];

    init_elf64(elf, sizeof(elf), ET_EXEC, 0x3e, 0, 64, 1);
    /* p_offset=200, p_filesz=100: 200+100=300 > 256 */
    set_phdr(elf, 0, PT_INTERP, 0, 200, 0, 100, 100, 1);

    ASSERT_EQ(kbox_parse_elf_interp(elf, sizeof(elf), out, sizeof(out)), -1);
}

/* PT_INTERP string missing NUL terminator within the segment. */
static void test_elf_interp_rejects_no_nul(void)
{
    unsigned char elf[256];
    char out[256];

    init_elf64(elf, sizeof(elf), ET_EXEC, 0x3e, 0, 64, 1);
    /* Place 4-byte PT_INTERP at offset 200, no NUL byte. */
    set_phdr(elf, 0, PT_INTERP, 0, 200, 0, 4, 4, 1);
    elf[200] = '/';
    elf[201] = 'l';
    elf[202] = 'd';
    elf[203] = 'x'; /* no NUL */

    ASSERT_EQ(kbox_parse_elf_interp(elf, sizeof(elf), out, sizeof(out)), -1);
}

/* PT_INTERP path too large for caller's output buffer. */
static void test_elf_interp_rejects_path_too_large(void)
{
    unsigned char elf[256];
    char out[4]; /* too small for "/ld.so" */

    init_elf64(elf, sizeof(elf), ET_EXEC, 0x3e, 0, 64, 1);
    set_phdr(elf, 0, PT_INTERP, 0, 200, 0, 7, 7, 1);
    memcpy(elf + 200, "/ld.so", 7); /* 6 chars + NUL = 7 bytes */

    ASSERT_EQ(kbox_parse_elf_interp(elf, sizeof(elf), out, sizeof(out)), -1);
}

/* PT_INTERP with empty string (just NUL) is rejected as malformed. */
static void test_elf_interp_rejects_empty_path(void)
{
    unsigned char elf[256];
    char out[256];

    init_elf64(elf, sizeof(elf), ET_EXEC, 0x3e, 0, 64, 1);
    set_phdr(elf, 0, PT_INTERP, 0, 200, 0, 1, 1, 1);
    elf[200] = '\0'; /* just a NUL byte */

    ASSERT_EQ(kbox_parse_elf_interp(elf, sizeof(elf), out, sizeof(out)), -1);
}

/* PT_INTERP with zero p_filesz is rejected. */
static void test_elf_interp_rejects_zero_filesz(void)
{
    unsigned char elf[256];
    char out[256];

    init_elf64(elf, sizeof(elf), ET_EXEC, 0x3e, 0, 64, 1);
    set_phdr(elf, 0, PT_INTERP, 0, 200, 0, 0, 0, 1);

    ASSERT_EQ(kbox_parse_elf_interp(elf, sizeof(elf), out, sizeof(out)), -1);
}

/* PT_INTERP with p_offset + p_filesz integer overflow is rejected.
 * p_offset is valid (within buf_len) but p_filesz is huge, causing
 * the sum to wrap around UINT64.  This exercises the __builtin_add_overflow
 * guard rather than the simpler p_offset >= buf_len check.
 */
static void test_elf_interp_rejects_offset_filesz_overflow(void)
{
    unsigned char elf[256];
    char out[256];

    init_elf64(elf, sizeof(elf), ET_EXEC, 0x3e, 0, 64, 1);
    /* p_offset=200 (valid), p_filesz=UINT64_MAX: 200 + UINT64_MAX wraps. */
    set_phdr(elf, 0, PT_INTERP, 0, 200, 0, UINT64_MAX, UINT64_MAX, 1);

    ASSERT_EQ(kbox_parse_elf_interp(elf, sizeof(elf), out, sizeof(out)), -1);
}

void test_elf_init(void)
{
    TEST_REGISTER(test_elf_parse_interp);
    TEST_REGISTER(test_elf_static_no_interp);
    TEST_REGISTER(test_elf_too_short);
    TEST_REGISTER(test_elf_bad_magic);
    TEST_REGISTER(test_elf_32bit_rejected);
    TEST_REGISTER(test_elf_find_interp_loc);
    TEST_REGISTER(test_elf_find_interp_loc_static);
    TEST_REGISTER(test_elf_read_header_window_fd);
    TEST_REGISTER(test_elf_read_header_window_fd_large_phoff);
    TEST_REGISTER(test_elf_build_load_plan_exec);
    TEST_REGISTER(test_elf_build_load_plan_pie_with_phdr_and_stack);
    TEST_REGISTER(test_elf_build_load_plan_honors_large_segment_align);
    TEST_REGISTER(test_elf_build_load_plan_rejects_filesz_gt_memsz);
    TEST_REGISTER(test_elf_interp_rejects_segment_overflow);
    TEST_REGISTER(test_elf_interp_rejects_no_nul);
    TEST_REGISTER(test_elf_interp_rejects_path_too_large);
    TEST_REGISTER(test_elf_interp_rejects_empty_path);
    TEST_REGISTER(test_elf_interp_rejects_zero_filesz);
    TEST_REGISTER(test_elf_interp_rejects_offset_filesz_overflow);
}
