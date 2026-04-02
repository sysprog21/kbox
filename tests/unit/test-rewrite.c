/* SPDX-License-Identifier: MIT */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kbox/elf.h"
#include "rewrite.h"
#include "test-runner.h"

#define EHDR_SIZE 64
#define PHDR_SIZE 56
#define PT_LOAD 1
#define PF_X 0x1
#define EM_X86_64 62
#define EM_AARCH64 183

static void put_le16(unsigned char *p, unsigned short v)
{
    p[0] = (unsigned char) (v & 0xff);
    p[1] = (unsigned char) ((v >> 8) & 0xff);
}

static void put_le32(unsigned char *p, unsigned int v)
{
    p[0] = (unsigned char) (v & 0xff);
    p[1] = (unsigned char) ((v >> 8) & 0xff);
    p[2] = (unsigned char) ((v >> 16) & 0xff);
    p[3] = (unsigned char) ((v >> 24) & 0xff);
}

static void put_le64(unsigned char *p, unsigned long long v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (unsigned char) ((v >> (i * 8)) & 0xff);
}

static void init_elf64(unsigned char *buf,
                       size_t size,
                       unsigned short machine,
                       unsigned short phnum)
{
    memset(buf, 0, size);
    buf[0] = 0x7f;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    put_le16(buf + 16, 2);
    put_le16(buf + 18, machine);
    put_le32(buf + 20, 1);
    put_le64(buf + 32, EHDR_SIZE);
    put_le16(buf + 52, EHDR_SIZE);
    put_le16(buf + 54, PHDR_SIZE);
    put_le16(buf + 56, phnum);
}

static void set_phdr(unsigned char *buf,
                     unsigned short index,
                     unsigned int type,
                     unsigned int flags,
                     unsigned long long offset,
                     unsigned long long vaddr,
                     unsigned long long filesz,
                     unsigned long long memsz)
{
    unsigned char *ph = buf + EHDR_SIZE + (size_t) index * PHDR_SIZE;

    put_le32(ph + 0, type);
    put_le32(ph + 4, flags);
    put_le64(ph + 8, offset);
    put_le64(ph + 16, vaddr);
    put_le64(ph + 24, vaddr);
    put_le64(ph + 32, filesz);
    put_le64(ph + 40, memsz);
}

static void build_x86_64_elf(unsigned char *buf, size_t size)
{
    init_elf64(buf, size, EM_X86_64, 2);
    set_phdr(buf, 0, PT_LOAD, PF_X, 176, 0x1000, 8, 8);
    set_phdr(buf, 1, PT_LOAD, 0, 184, 0x2000, 4, 4);

    buf[176] = 0x90;
    buf[177] = 0x0f;
    buf[178] = 0x05;
    buf[179] = 0x90;
    buf[180] = 0x0f;
    buf[181] = 0x34;
    buf[182] = 0xc3;
    buf[183] = 0x90;
    buf[184] = 0xaa;
    buf[185] = 0xbb;
    buf[186] = 0xcc;
    buf[187] = 0xdd;
}

static void build_x86_64_wrapper_elf_nr(unsigned char *buf,
                                        size_t size,
                                        unsigned int nr)
{
    init_elf64(buf, size, EM_X86_64, 1);
    set_phdr(buf, 0, PT_LOAD, PF_X, 120, 0x1000, 8, 8);

    buf[120] = 0xb8;
    put_le32(buf + 121, nr);
    buf[125] = 0x0f;
    buf[126] = 0x05;
    buf[127] = 0xc3;
}

static void build_x86_64_wrapper_elf(unsigned char *buf, size_t size)
{
    build_x86_64_wrapper_elf_nr(buf, size, 39);
}

static void build_aarch64_elf(unsigned char *buf, size_t size)
{
    init_elf64(buf, size, EM_AARCH64, 1);
    set_phdr(buf, 0, PT_LOAD, PF_X, 120, 0x4000, 12, 12);

    buf[120] = 0x1f;
    buf[121] = 0x20;
    buf[122] = 0x03;
    buf[123] = 0xd5;
    buf[124] = 0x01;
    buf[125] = 0x00;
    buf[126] = 0x00;
    buf[127] = 0xd4;
    buf[128] = 0xc0;
    buf[129] = 0x03;
    buf[130] = 0x5f;
    buf[131] = 0xd6;
}

static void build_aarch64_wrapper_elf_nr(unsigned char *buf,
                                         size_t size,
                                         unsigned int nr)
{
    init_elf64(buf, size, EM_AARCH64, 1);
    set_phdr(buf, 0, PT_LOAD, PF_X, 120, 0x4000, 12, 12);

    put_le32(buf + 120, 0xd2800008u | ((nr & 0xffffu) << 5));
    put_le32(buf + 124, 0xd4000001u);
    put_le32(buf + 128, 0xd65f03c0u);
}

static void build_aarch64_cancel_wrapper_elf(unsigned char *buf, size_t size)
{
    init_elf64(buf, size, EM_AARCH64, 1);
    set_phdr(buf, 0, PT_LOAD, PF_X, 120, 0x4000, 24, 24);

    put_le32(buf + 120, 0xd2800848u);
    put_le32(buf + 124, 0xd4000001u);
    put_le32(buf + 128, 0xf9400bf3u);
    put_le32(buf + 132, 0xa8c27bfdu);
    put_le32(buf + 136, 0xd50323bfu);
    put_le32(buf + 140, 0xd65f03c0u);
}

static void build_aarch64_fstatat_wrapper_elf(unsigned char *buf, size_t size)
{
    init_elf64(buf, size, EM_AARCH64, 1);
    set_phdr(buf, 0, PT_LOAD, PF_X, 120, 0x4000, 24, 24);

    put_le32(buf + 120, 0xd28009e8u); /* mov x8, #79 */
    put_le32(buf + 124, 0xd4000001u); /* svc #0 */
    put_le32(buf + 128, 0x3140041fu); /* cmn w0, #1, lsl #12 */
    put_le32(buf + 132, 0x540000a8u); /* b.hi +0x14 */
    put_le32(buf + 136, 0x52800000u); /* mov w0, #0 */
    put_le32(buf + 140, 0xd65f03c0u); /* ret */
}

static void build_aarch64_syscall_cancel_open_wrapper_elf(unsigned char *buf,
                                                          size_t size)
{
    init_elf64(buf, size, EM_AARCH64, 1);
    set_phdr(buf, 0, PT_LOAD, PF_X, 120, 0x4000, 24, 24);

    put_le32(buf + 120, 0xd2800706u); /* mov x6, #56 */
    put_le32(buf + 124, 0xd2800005u); /* mov x5, #0 */
    put_le32(buf + 128, 0xd2800004u); /* mov x4, #0 */
    put_le32(buf + 132, 0x14000002u); /* b +8 */
    put_le32(buf + 136, 0xd503201fu); /* nop */
    put_le32(buf + 140, 0xd503201fu); /* nop */
}

static void build_unknown_elf(unsigned char *buf, size_t size)
{
    init_elf64(buf, size, 0x1234, 0);
}

static int count_segments_cb(const struct kbox_elf_exec_segment *seg,
                             const unsigned char *segment_bytes,
                             void *opaque)
{
    int *count = opaque;
    (void) segment_bytes;
    if (seg->file_size == 0)
        return -1;
    (*count)++;
    return 0;
}

static void test_syscall_mode_parser(void)
{
    enum kbox_syscall_mode mode = KBOX_SYSCALL_MODE_AUTO;

    ASSERT_EQ(kbox_parse_syscall_mode("seccomp", &mode), 0);
    ASSERT_EQ(mode, KBOX_SYSCALL_MODE_SECCOMP);
    ASSERT_STREQ(kbox_syscall_mode_name(mode), "seccomp");

    ASSERT_EQ(kbox_parse_syscall_mode("trap", &mode), 0);
    ASSERT_EQ(mode, KBOX_SYSCALL_MODE_TRAP);
    ASSERT_STREQ(kbox_syscall_mode_name(mode), "trap");

    ASSERT_EQ(kbox_parse_syscall_mode("rewrite", &mode), 0);
    ASSERT_EQ(mode, KBOX_SYSCALL_MODE_REWRITE);
    ASSERT_STREQ(kbox_syscall_mode_name(mode), "rewrite");

    ASSERT_EQ(kbox_parse_syscall_mode("auto", &mode), 0);
    ASSERT_EQ(mode, KBOX_SYSCALL_MODE_AUTO);
    ASSERT_STREQ(kbox_syscall_mode_name(mode), "auto");

    ASSERT_EQ(kbox_parse_syscall_mode("bogus", &mode), -1);
}

static void test_elf_exec_segment_walker(void)
{
    unsigned char elf[192];
    int count = 0;
    int rc;

    build_x86_64_elf(elf, sizeof(elf));
    rc = kbox_visit_elf_exec_segments(elf, sizeof(elf), count_segments_cb,
                                      &count);
    ASSERT_EQ(rc, 1);
    ASSERT_EQ(count, 1);
}

static void test_rewrite_analyze_x86_64(void)
{
    unsigned char elf[192];
    struct kbox_rewrite_report report;

    build_x86_64_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_analyze_elf(elf, sizeof(elf), &report), 0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_EQ(report.exec_segment_count, 1);
    ASSERT_EQ(report.candidate_count, 2);
    ASSERT_STREQ(kbox_rewrite_arch_name(report.arch), "x86_64");
}

static void test_rewrite_analyze_x86_64_wrapper(void)
{
    unsigned char elf[160];
    struct kbox_rewrite_report report;

    build_x86_64_wrapper_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_analyze_elf(elf, sizeof(elf), &report), 0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_EQ(report.exec_segment_count, 1);
    ASSERT_EQ(report.candidate_count, 1);
}

static void test_rewrite_analyze_aarch64(void)
{
    unsigned char elf[160];
    struct kbox_rewrite_report report;

    build_aarch64_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_analyze_elf(elf, sizeof(elf), &report), 0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_AARCH64);
    ASSERT_EQ(report.exec_segment_count, 1);
    ASSERT_EQ(report.candidate_count, 1);
    ASSERT_STREQ(kbox_rewrite_arch_name(report.arch), "aarch64");
}

static void test_rewrite_rejects_unknown_machine(void)
{
    unsigned char elf[64];
    struct kbox_rewrite_report report;

    build_unknown_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_analyze_elf(elf, sizeof(elf), &report), -1);
}

struct site_list {
    struct kbox_rewrite_site sites[4];
    int count;
};

struct planned_site_list {
    struct kbox_rewrite_planned_site sites[4];
    int count;
};

static int collect_sites_cb(const struct kbox_rewrite_site *site, void *opaque)
{
    struct site_list *list = opaque;

    if (list->count >= 4)
        return -1;
    list->sites[list->count++] = *site;
    return 0;
}

static int collect_planned_sites_cb(
    const struct kbox_rewrite_planned_site *planned,
    void *opaque)
{
    struct planned_site_list *list = opaque;

    if (list->count >= 4)
        return -1;
    list->sites[list->count++] = *planned;
    return 0;
}

static void test_elf_exec_rejects_huge_phoff(void)
{
    /* Craft an ELF with e_phoff near UINT64_MAX so that phoff + i*phentsize
     * would wrap around.  The segment walker must reject this with -1 rather
     * than reading out of bounds.
     */
    unsigned char elf[192];
    int count = 0;

    build_x86_64_elf(elf, sizeof(elf));
    /* Overwrite e_phoff (offset 32, 8 bytes) with 0xFFFFFFFFFFFFFF00 */
    put_le64(elf + 32, 0xFFFFFFFFFFFFFF00ULL);
    ASSERT_EQ(kbox_visit_elf_exec_segments(elf, sizeof(elf), count_segments_cb,
                                           &count),
              -1);
    ASSERT_EQ(count, 0);
}

static void test_elf_interp_rejects_huge_phoff(void)
{
    /* Same overflow scenario but for the PT_INTERP lookup path.
     * kbox_find_elf_interp_loc must return -1 (malformed ELF), not 0
     * ("no interp" / static binary), so the caller does not silently
     * treat a corrupted dynamic ELF as static.
     */
    unsigned char elf[192];
    char interp[64];

    build_x86_64_elf(elf, sizeof(elf));
    put_le64(elf + 32, 0xFFFFFFFFFFFFFF00ULL);
    ASSERT_EQ(kbox_find_elf_interp_loc(elf, sizeof(elf), interp, sizeof(interp),
                                       NULL, NULL),
              -1);
}

static void test_rewrite_visit_x86_64_sites(void)
{
    unsigned char elf[192];
    struct site_list list;
    struct kbox_rewrite_report report;

    memset(&list, 0, sizeof(list));
    build_x86_64_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_visit_elf_sites(elf, sizeof(elf), collect_sites_cb,
                                           &list, &report),
              0);
    ASSERT_EQ(list.count, 2);
    ASSERT_EQ(list.sites[0].file_offset, 177);
    ASSERT_EQ(list.sites[0].vaddr, 0x1001);
    ASSERT_EQ(list.sites[0].segment_vaddr, 0x1000);
    ASSERT_EQ(list.sites[0].segment_mem_size, 8);
    ASSERT_EQ(list.sites[0].width, 2);
    ASSERT_EQ(list.sites[0].original[0], 0x0f);
    ASSERT_EQ(list.sites[0].original[1], 0x05);
    ASSERT_EQ(list.sites[1].file_offset, 180);
    ASSERT_EQ(list.sites[1].vaddr, 0x1004);
    ASSERT_EQ(list.sites[1].original[1], 0x34);
}

static void test_rewrite_visit_x86_64_wrapper_site(void)
{
    unsigned char elf[160];
    struct site_list list;
    struct kbox_rewrite_report report;

    memset(&list, 0, sizeof(list));
    build_x86_64_wrapper_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_visit_elf_sites(elf, sizeof(elf), collect_sites_cb,
                                           &list, &report),
              0);
    ASSERT_EQ(list.count, 1);
    ASSERT_EQ(list.sites[0].file_offset, 120);
    ASSERT_EQ(list.sites[0].vaddr, 0x1000);
    ASSERT_EQ(list.sites[0].segment_vaddr, 0x1000);
    ASSERT_EQ(list.sites[0].segment_mem_size, 8);
    ASSERT_EQ(list.sites[0].width, 8);
    ASSERT_EQ(list.sites[0].original[0], 0xb8);
    ASSERT_EQ(list.sites[0].original[5], 0x0f);
    ASSERT_EQ(list.sites[0].original[6], 0x05);
    ASSERT_EQ(list.sites[0].original[7], 0xc3);
}

static void test_rewrite_visit_aarch64_sites(void)
{
    unsigned char elf[160];
    struct site_list list;
    struct kbox_rewrite_report report;

    memset(&list, 0, sizeof(list));
    build_aarch64_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_visit_elf_sites(elf, sizeof(elf), collect_sites_cb,
                                           &list, &report),
              0);
    ASSERT_EQ(list.count, 1);
    ASSERT_EQ(list.sites[0].file_offset, 124);
    ASSERT_EQ(list.sites[0].vaddr, 0x4004);
    ASSERT_EQ(list.sites[0].segment_vaddr, 0x4000);
    ASSERT_EQ(list.sites[0].segment_mem_size, 12);
    ASSERT_EQ(list.sites[0].width, 4);
    ASSERT_EQ(list.sites[0].original[0], 0x01);
    ASSERT_EQ(list.sites[0].original[3], 0xd4);
}

static void test_rewrite_visit_aarch64_cancel_wrapper_site(void)
{
    unsigned char elf[192];
    struct site_list list;
    struct kbox_rewrite_report report;

    memset(&list, 0, sizeof(list));
    build_aarch64_cancel_wrapper_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_visit_elf_sites(elf, sizeof(elf), collect_sites_cb,
                                           &list, &report),
              0);
    ASSERT_EQ(list.count, 1);
    ASSERT_EQ(list.sites[0].file_offset, 124);
    ASSERT_EQ(list.sites[0].vaddr, 0x4004);
    ASSERT_EQ(list.sites[0].site_class, KBOX_REWRITE_SITE_WRAPPER);
}

static void test_rewrite_visit_aarch64_fstatat_wrapper_site(void)
{
    unsigned char elf[192];
    struct site_list list;
    struct kbox_rewrite_report report;

    memset(&list, 0, sizeof(list));
    build_aarch64_fstatat_wrapper_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_visit_elf_sites(elf, sizeof(elf), collect_sites_cb,
                                           &list, &report),
              0);
    ASSERT_EQ(list.count, 1);
    ASSERT_EQ(list.sites[0].file_offset, 124);
    ASSERT_EQ(list.sites[0].vaddr, 0x4004);
    ASSERT_EQ(list.sites[0].site_class, KBOX_REWRITE_SITE_WRAPPER);
}

static void test_rewrite_plan_x86_64_sites(void)
{
    unsigned char elf[192];
    struct planned_site_list list;
    struct kbox_rewrite_report report;

    memset(&list, 0, sizeof(list));
    build_x86_64_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_visit_elf_planned_sites(
                  elf, sizeof(elf), collect_planned_sites_cb, &list, &report),
              0);
    ASSERT_EQ(list.count, 2);
    ASSERT_EQ(list.sites[0].trampoline_addr, 0x1010);
    ASSERT_EQ(list.sites[0].patch.width, 2);
    ASSERT_EQ(list.sites[0].patch.bytes[0], 0xff);
    ASSERT_EQ(list.sites[0].patch.bytes[1], 0xd0);
    ASSERT_EQ(list.sites[1].trampoline_addr, 0x1030);
    ASSERT_EQ(list.sites[1].patch.width, 2);
    ASSERT_EQ(list.sites[1].patch.bytes[0], 0xff);
    ASSERT_EQ(list.sites[1].patch.bytes[1], 0xd0);
}

static void test_rewrite_plan_aarch64_sites(void)
{
    unsigned char elf[160];
    struct planned_site_list list;
    struct kbox_rewrite_report report;

    memset(&list, 0, sizeof(list));
    build_aarch64_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_visit_elf_planned_sites(
                  elf, sizeof(elf), collect_planned_sites_cb, &list, &report),
              0);
    ASSERT_EQ(list.count, 1);
    ASSERT_EQ(list.sites[0].trampoline_addr, 0x4010);
    ASSERT_EQ(list.sites[0].patch.width, 4);
    ASSERT_EQ(list.sites[0].patch.bytes[0], 0x03);
    ASSERT_EQ(list.sites[0].patch.bytes[1], 0x00);
    ASSERT_EQ(list.sites[0].patch.bytes[2], 0x00);
    ASSERT_EQ(list.sites[0].patch.bytes[3], 0x14);
}

static void test_rewrite_plan_aarch64_segment_out_of_range(void)
{
    unsigned char elf[128];
    struct planned_site_list list;
    struct kbox_rewrite_report report;

    memset(&list, 0, sizeof(list));
    init_elf64(elf, sizeof(elf), EM_AARCH64, 1);
    set_phdr(elf, 0, PT_LOAD, PF_X, 120, 0x4000, 4,
             (unsigned long long) ((128u * 1024u * 1024u) + 4096u));
    elf[120] = 0x01;
    elf[121] = 0x00;
    elf[122] = 0x00;
    elf[123] = 0xd4;
    ASSERT_EQ(kbox_rewrite_visit_elf_planned_sites(
                  elf, sizeof(elf), collect_planned_sites_cb, &list, &report),
              0);
    ASSERT_EQ(list.count, 1);
    ASSERT_EQ(list.sites[0].patch.width, 0);
}

static void test_rewrite_encode_x86_64_patch(void)
{
    struct kbox_rewrite_site site;
    struct kbox_rewrite_patch patch;

    memset(&site, 0, sizeof(site));
    site.vaddr = 0x1000;
    site.width = 2;
    site.original[0] = 0x0f;
    site.original[1] = 0x05;
    ASSERT_EQ(kbox_rewrite_encode_patch(&site, 0, &patch), 0);
    ASSERT_EQ(patch.width, 2);
    ASSERT_EQ(patch.bytes[0], 0xff);
    ASSERT_EQ(patch.bytes[1], 0xd0);
}

static void test_rewrite_encode_x86_64_wrapper_patch(void)
{
    struct kbox_rewrite_site site;
    struct kbox_rewrite_patch patch;

    memset(&site, 0, sizeof(site));
    site.vaddr = 0x1000;
    site.segment_mem_size = 8;
    site.width = 8;
    site.original[0] = 0xb8;
    site.original[1] = 0x27;
    site.original[2] = 0x00;
    site.original[3] = 0x00;
    site.original[4] = 0x00;
    site.original[5] = 0x0f;
    site.original[6] = 0x05;
    site.original[7] = 0xc3;
    ASSERT_EQ(kbox_rewrite_encode_patch(&site, 0x1100, &patch), 0);
    ASSERT_EQ(patch.width, 8);
    ASSERT_EQ(patch.bytes[0], 0xe9);
    ASSERT_EQ(patch.bytes[1], 0xfb);
    ASSERT_EQ(patch.bytes[2], 0x00);
    ASSERT_EQ(patch.bytes[3], 0x00);
    ASSERT_EQ(patch.bytes[4], 0x00);
    ASSERT_EQ(patch.bytes[5], 0x90);
    ASSERT_EQ(patch.bytes[6], 0x90);
    ASSERT_EQ(patch.bytes[7], 0x90);
}

static void test_rewrite_encode_x86_64_page_zero_trampoline(void)
{
    unsigned char page[256];

    ASSERT_EQ(kbox_rewrite_encode_x86_64_page_zero_trampoline(
                  page, sizeof(page), 0x1122334455667788ULL),
              0);
    ASSERT_EQ(page[0], 0x90);
    ASSERT_EQ(page[sizeof(page) - 13], 0x49);
    ASSERT_EQ(page[sizeof(page) - 12], 0xbb);
    ASSERT_EQ(page[sizeof(page) - 11], 0x88);
    ASSERT_EQ(page[sizeof(page) - 10], 0x77);
    ASSERT_EQ(page[sizeof(page) - 9], 0x66);
    ASSERT_EQ(page[sizeof(page) - 8], 0x55);
    ASSERT_EQ(page[sizeof(page) - 7], 0x44);
    ASSERT_EQ(page[sizeof(page) - 6], 0x33);
    ASSERT_EQ(page[sizeof(page) - 5], 0x22);
    ASSERT_EQ(page[sizeof(page) - 4], 0x11);
    ASSERT_EQ(page[sizeof(page) - 3], 0x41);
    ASSERT_EQ(page[sizeof(page) - 2], 0xff);
    ASSERT_EQ(page[sizeof(page) - 1], 0xe3);
}

static void test_rewrite_encode_aarch64_branch_patch(void)
{
    struct kbox_rewrite_site site;
    struct kbox_rewrite_patch patch;

    memset(&site, 0, sizeof(site));
    site.vaddr = 0x4000;
    site.width = 4;
    site.original[0] = 0x01;
    site.original[1] = 0x00;
    site.original[2] = 0x00;
    site.original[3] = 0xd4;
    ASSERT_EQ(kbox_rewrite_encode_patch(&site, 0x4010, &patch), 0);
    ASSERT_EQ(patch.width, 4);
    ASSERT_EQ(patch.bytes[0], 0x04);
    ASSERT_EQ(patch.bytes[1], 0x00);
    ASSERT_EQ(patch.bytes[2], 0x00);
    ASSERT_EQ(patch.bytes[3], 0x14);
}

static void test_rewrite_encode_aarch64_branch_out_of_range(void)
{
    struct kbox_rewrite_site site;
    struct kbox_rewrite_patch patch;

    memset(&site, 0, sizeof(site));
    site.vaddr = 0x4000;
    site.width = 4;
    site.original[0] = 0x01;
    site.original[1] = 0x00;
    site.original[2] = 0x00;
    site.original[3] = 0xd4;
    ASSERT_EQ(kbox_rewrite_encode_patch(&site, 0x10000000, &patch), -1);
}

static void test_rewrite_apply_x86_64_elf(void)
{
    unsigned char elf[192];
    struct kbox_rewrite_report report;
    size_t applied = 0;

    build_x86_64_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_apply_elf(elf, sizeof(elf), &applied, &report), 0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_EQ(applied, 2);
    ASSERT_EQ(elf[177], 0xff);
    ASSERT_EQ(elf[178], 0xd0);
    ASSERT_EQ(elf[180], 0xff);
    ASSERT_EQ(elf[181], 0xd0);
}

static void test_rewrite_apply_x86_64_wrapper_elf(void)
{
    unsigned char elf[160];
    struct kbox_rewrite_report report;
    size_t applied = 0;

    build_x86_64_wrapper_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_apply_elf(elf, sizeof(elf), &applied, &report), 0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_EQ(applied, 1);
    ASSERT_EQ(elf[120], 0xe9);
    ASSERT_EQ(elf[121], 0x0b);
    ASSERT_EQ(elf[122], 0x00);
    ASSERT_EQ(elf[123], 0x00);
    ASSERT_EQ(elf[124], 0x00);
    ASSERT_EQ(elf[125], 0x90);
    ASSERT_EQ(elf[126], 0x90);
    ASSERT_EQ(elf[127], 0x90);
}

static void test_rewrite_apply_aarch64_elf(void)
{
    unsigned char elf[160];
    struct kbox_rewrite_report report;
    size_t applied = 0;

    build_aarch64_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_apply_elf(elf, sizeof(elf), &applied, &report), 0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_AARCH64);
    ASSERT_EQ(applied, 1);
    ASSERT_EQ(elf[124], 0x03);
    ASSERT_EQ(elf[125], 0x00);
    ASSERT_EQ(elf[126], 0x00);
    ASSERT_EQ(elf[127], 0x14);
}

static void test_rewrite_apply_memfd_x86_64(void)
{
    unsigned char elf[192];
    struct kbox_rewrite_report report;
    size_t applied = 0;
    char path[128];
    unsigned char patched[8];
    int fd;

    build_x86_64_elf(elf, sizeof(elf));
    fd = test_mkstemp(path, sizeof(path), "kbox-rewrite-unit");
    ASSERT_TRUE(fd >= 0);
    unlink(path);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (long) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_apply_memfd(fd, &applied, &report), 0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_EQ(applied, 2);
    ASSERT_EQ(pread(fd, patched, sizeof(patched), 176), (long) sizeof(patched));
    ASSERT_EQ(patched[1], 0xff);
    ASSERT_EQ(patched[2], 0xd0);
    ASSERT_EQ(patched[4], 0xff);
    ASSERT_EQ(patched[5], 0xd0);
    close(fd);
}

static void test_rewrite_apply_virtual_procinfo_x86_64_wrapper_elf(void)
{
    unsigned char elf[160];
    struct kbox_rewrite_report report;
    size_t applied = 0;

    build_x86_64_wrapper_elf_nr(elf, sizeof(elf), 39);
    ASSERT_EQ(kbox_rewrite_apply_virtual_procinfo_elf(elf, sizeof(elf),
                                                      &applied, &report),
              0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_EQ(applied, 1);
    ASSERT_EQ(elf[120], 0xb8);
    ASSERT_EQ(elf[121], 0x01);
    ASSERT_EQ(elf[122], 0x00);
    ASSERT_EQ(elf[123], 0x00);
    ASSERT_EQ(elf[124], 0x00);
    ASSERT_EQ(elf[125], 0xc3);
    ASSERT_EQ(elf[126], 0x90);
    ASSERT_EQ(elf[127], 0x90);
}

static void test_rewrite_apply_virtual_procinfo_x86_64_getppid_wrapper_elf(void)
{
    unsigned char elf[160];
    struct kbox_rewrite_report report;
    size_t applied = 0;

    build_x86_64_wrapper_elf_nr(elf, sizeof(elf), 110);
    ASSERT_EQ(kbox_rewrite_apply_virtual_procinfo_elf(elf, sizeof(elf),
                                                      &applied, &report),
              0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_EQ(applied, 1);
    ASSERT_EQ(elf[120], 0xb8);
    ASSERT_EQ(elf[121], 0x00);
    ASSERT_EQ(elf[122], 0x00);
    ASSERT_EQ(elf[123], 0x00);
    ASSERT_EQ(elf[124], 0x00);
    ASSERT_EQ(elf[125], 0xc3);
    ASSERT_EQ(elf[126], 0x90);
    ASSERT_EQ(elf[127], 0x90);
}

static void test_rewrite_apply_virtual_procinfo_skips_non_procinfo_wrapper(void)
{
    unsigned char elf[160];
    struct kbox_rewrite_report report;
    size_t applied = 0;

    build_x86_64_wrapper_elf_nr(elf, sizeof(elf), 96);
    ASSERT_EQ(kbox_rewrite_apply_virtual_procinfo_elf(elf, sizeof(elf),
                                                      &applied, &report),
              0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_EQ(applied, 0);
    ASSERT_EQ(elf[120], 0xb8);
    ASSERT_EQ(elf[121], 0x60);
    ASSERT_EQ(elf[122], 0x00);
    ASSERT_EQ(elf[123], 0x00);
    ASSERT_EQ(elf[124], 0x00);
    ASSERT_EQ(elf[125], 0x0f);
    ASSERT_EQ(elf[126], 0x05);
    ASSERT_EQ(elf[127], 0xc3);
}

static void test_rewrite_apply_virtual_procinfo_aarch64_wrapper_elf(void)
{
    unsigned char elf[160];
    struct kbox_rewrite_report report;
    size_t applied = 0;

    build_aarch64_wrapper_elf_nr(elf, sizeof(elf), 172);
    ASSERT_EQ(kbox_rewrite_apply_virtual_procinfo_elf(elf, sizeof(elf),
                                                      &applied, &report),
              0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_AARCH64);
    ASSERT_EQ(applied, 1);
    ASSERT_EQ(elf[124], 0x20);
    ASSERT_EQ(elf[125], 0x00);
    ASSERT_EQ(elf[126], 0x80);
    ASSERT_EQ(elf[127], 0xd2);
    ASSERT_EQ(elf[128], 0xc0);
    ASSERT_EQ(elf[129], 0x03);
    ASSERT_EQ(elf[130], 0x5f);
    ASSERT_EQ(elf[131], 0xd6);
}

static void test_rewrite_apply_virtual_procinfo_aarch64_getppid_wrapper_elf(
    void)
{
    unsigned char elf[160];
    struct kbox_rewrite_report report;
    size_t applied = 0;

    build_aarch64_wrapper_elf_nr(elf, sizeof(elf), 173);
    ASSERT_EQ(kbox_rewrite_apply_virtual_procinfo_elf(elf, sizeof(elf),
                                                      &applied, &report),
              0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_AARCH64);
    ASSERT_EQ(applied, 1);
    ASSERT_EQ(elf[124], 0x00);
    ASSERT_EQ(elf[125], 0x00);
    ASSERT_EQ(elf[126], 0x80);
    ASSERT_EQ(elf[127], 0xd2);
    ASSERT_EQ(elf[128], 0xc0);
    ASSERT_EQ(elf[129], 0x03);
    ASSERT_EQ(elf[130], 0x5f);
    ASSERT_EQ(elf[131], 0xd6);
}

static void test_rewrite_apply_virtual_procinfo_skips_non_procinfo_aarch64(void)
{
    unsigned char elf[160];
    struct kbox_rewrite_report report;
    size_t applied = 0;

    build_aarch64_wrapper_elf_nr(elf, sizeof(elf), 174);
    ASSERT_EQ(kbox_rewrite_apply_virtual_procinfo_elf(elf, sizeof(elf),
                                                      &applied, &report),
              0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_AARCH64);
    ASSERT_EQ(applied, 0);
    ASSERT_EQ(elf[124], 0x01);
    ASSERT_EQ(elf[125], 0x00);
    ASSERT_EQ(elf[126], 0x00);
    ASSERT_EQ(elf[127], 0xd4);
}

static void test_rewrite_wrapper_syscall_nr_x86_64(void)
{
    struct kbox_rewrite_site site;
    uint64_t nr = 0;

    memset(&site, 0, sizeof(site));
    site.width = 8;
    site.site_class = KBOX_REWRITE_SITE_WRAPPER;
    site.original[0] = 0xb8;
    site.original[1] = 0x01;
    site.original[2] = 0x00;
    site.original[3] = 0x00;
    site.original[4] = 0x00;
    site.original[5] = 0x0f;
    site.original[6] = 0x05;
    site.original[7] = 0xc3;

    ASSERT_EQ(
        kbox_rewrite_wrapper_syscall_nr(&site, KBOX_REWRITE_ARCH_X86_64, &nr),
        0);
    ASSERT_EQ(nr, 1);
}

static void test_rewrite_wrapper_syscall_nr_aarch64(void)
{
    struct kbox_rewrite_site site;
    uint64_t nr = 0;

    memset(&site, 0, sizeof(site));
    site.width = 4;
    site.site_class = KBOX_REWRITE_SITE_WRAPPER;
    put_le32(site.original, 0xd2800848u);

    ASSERT_EQ(
        kbox_rewrite_wrapper_syscall_nr(&site, KBOX_REWRITE_ARCH_AARCH64, &nr),
        0);
    ASSERT_EQ(nr, 66);
}

static void test_rewrite_origin_map_x86_64(void)
{
    unsigned char elf[192];
    struct kbox_rewrite_origin_map map;
    struct kbox_rewrite_origin_entry entry;
    struct kbox_rewrite_report report;

    build_x86_64_elf(elf, sizeof(elf));
    kbox_rewrite_origin_map_init(&map, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_EQ(
        kbox_rewrite_origin_map_build_elf(&map, elf, sizeof(elf), &report), 0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_EQ(map.count, 2);
    ASSERT_EQ(map.entries[0].origin, 0x1003);
    ASSERT_EQ(map.entries[0].source, KBOX_LOADER_MAPPING_MAIN);
    ASSERT_EQ(map.entries[1].origin, 0x1006);
    ASSERT_EQ(map.entries[1].source, KBOX_LOADER_MAPPING_MAIN);
    ASSERT_EQ(kbox_rewrite_origin_map_contains(&map, 0x1003), 1);
    ASSERT_EQ(kbox_rewrite_origin_map_contains(&map, 0x1006), 1);
    ASSERT_EQ(kbox_rewrite_origin_map_contains(&map, 0x1001), 0);
    ASSERT_EQ(kbox_rewrite_origin_map_find(&map, 0x1006, &entry), 1);
    ASSERT_EQ(entry.origin, 0x1006);
    ASSERT_EQ(entry.source, KBOX_LOADER_MAPPING_MAIN);
    kbox_rewrite_origin_map_reset(&map);
}

static void test_rewrite_origin_map_aarch64(void)
{
    unsigned char elf[160];
    struct kbox_rewrite_origin_map map;
    struct kbox_rewrite_origin_entry entry;
    struct kbox_rewrite_report report;

    build_aarch64_elf(elf, sizeof(elf));
    kbox_rewrite_origin_map_init(&map, KBOX_REWRITE_ARCH_AARCH64);
    ASSERT_EQ(
        kbox_rewrite_origin_map_build_elf(&map, elf, sizeof(elf), &report), 0);
    ASSERT_EQ(report.arch, KBOX_REWRITE_ARCH_AARCH64);
    ASSERT_EQ(map.count, 1);
    ASSERT_EQ(map.entries[0].origin, 0x4004);
    ASSERT_EQ(map.entries[0].source, KBOX_LOADER_MAPPING_MAIN);
    ASSERT_EQ(kbox_rewrite_origin_map_contains(&map, 0x4004), 1);
    ASSERT_EQ(kbox_rewrite_origin_map_contains(&map, 0x4008), 0);
    ASSERT_EQ(kbox_rewrite_origin_map_find(&map, 0x4004, &entry), 1);
    ASSERT_EQ(entry.origin, 0x4004);
    ASSERT_EQ(entry.source, KBOX_LOADER_MAPPING_MAIN);
    kbox_rewrite_origin_map_reset(&map);
}

static void test_rewrite_origin_map_add_site_source(void)
{
    struct kbox_rewrite_origin_map map;
    struct kbox_rewrite_site site;
    struct kbox_rewrite_origin_entry entry;

    memset(&site, 0, sizeof(site));
    site.vaddr = 0x2000;
    site.width = 2;
    site.original[0] = 0x0f;
    site.original[1] = 0x05;

    kbox_rewrite_origin_map_init(&map, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_EQ(kbox_rewrite_origin_map_add_site_source(
                  &map, &site, KBOX_LOADER_MAPPING_INTERP),
              0);
    ASSERT_EQ(map.count, 1);
    ASSERT_EQ(map.entries[0].origin, 0x2002);
    ASSERT_EQ(map.entries[0].source, KBOX_LOADER_MAPPING_INTERP);
    ASSERT_EQ(kbox_rewrite_origin_map_find(&map, 0x2002, &entry), 1);
    ASSERT_EQ(entry.origin, 0x2002);
    ASSERT_EQ(entry.source, KBOX_LOADER_MAPPING_INTERP);
    ASSERT_EQ(kbox_rewrite_origin_map_find(&map, 0x2001, &entry), 0);
    kbox_rewrite_origin_map_reset(&map);
}

static void test_rewrite_origin_map_seal(void)
{
    struct kbox_rewrite_origin_map map;
    struct kbox_rewrite_site site;
    struct kbox_rewrite_origin_entry entry;

    memset(&site, 0, sizeof(site));
    site.vaddr = 0x3000;
    site.width = 2;
    site.original[0] = 0x0f;
    site.original[1] = 0x05;

    kbox_rewrite_origin_map_init(&map, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_EQ(kbox_rewrite_origin_map_add_site_source(&map, &site,
                                                      KBOX_LOADER_MAPPING_MAIN),
              0);
    ASSERT_EQ(kbox_rewrite_origin_map_seal(&map), 0);
    ASSERT_TRUE(map.sealed);
    ASSERT_TRUE(map.mapping_size >= sizeof(*map.entries));
    ASSERT_EQ(kbox_rewrite_origin_map_find(&map, 0x3002, &entry), 1);
    ASSERT_EQ(entry.origin, 0x3002);
    ASSERT_EQ(entry.source, KBOX_LOADER_MAPPING_MAIN);
    errno = 0;
    ASSERT_EQ(kbox_rewrite_origin_map_add_site_source(
                  &map, &site, KBOX_LOADER_MAPPING_INTERP),
              -1);
    ASSERT_EQ(errno, EPERM);
    kbox_rewrite_origin_map_reset(&map);
}

static void test_rewrite_probe_x86_64_page_zero_allowed(void)
{
    struct kbox_rewrite_trampoline_probe probe;

    ASSERT_EQ(kbox_rewrite_probe_x86_64_page_zero(0, &probe), 0);
    ASSERT_EQ(probe.arch, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_TRUE(probe.feasible);
    ASSERT_STREQ(probe.reason, "page-zero trampoline available");
}

static void test_rewrite_probe_x86_64_page_zero_blocked(void)
{
    struct kbox_rewrite_trampoline_probe probe;

    ASSERT_EQ(kbox_rewrite_probe_x86_64_page_zero(65536, &probe), 0);
    ASSERT_EQ(probe.arch, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_TRUE(!probe.feasible);
    ASSERT_STREQ(probe.reason, "vm.mmap_min_addr must be 0 for x86_64 rewrite");
}

static void test_rewrite_fast_host_syscall0_classification(void)
{
    struct kbox_host_nrs host_nrs;

    memset(&host_nrs, 0xff, sizeof(host_nrs));
    host_nrs.getpid = 172;
    host_nrs.getppid = 173;
    host_nrs.gettid = 178;

    ASSERT_EQ(kbox_rewrite_is_fast_host_syscall0(&host_nrs, 172), 1);
    ASSERT_EQ(kbox_rewrite_is_fast_host_syscall0(&host_nrs, 173), 1);
    ASSERT_EQ(kbox_rewrite_is_fast_host_syscall0(&host_nrs, 178), 1);
    ASSERT_EQ(kbox_rewrite_is_fast_host_syscall0(&host_nrs, 999), 0);
}

static void test_rewrite_has_wrapper_syscalls_x86_64(void)
{
    unsigned char elf[160];
    uint64_t allow[] = {1, 257};

    build_x86_64_wrapper_elf_nr(elf, sizeof(elf), 257);
    ASSERT_EQ(kbox_rewrite_has_wrapper_syscalls(
                  elf, sizeof(elf), KBOX_REWRITE_ARCH_X86_64, allow, 2),
              1);

    allow[0] = 39;
    allow[1] = 40;
    ASSERT_EQ(kbox_rewrite_has_wrapper_syscalls(
                  elf, sizeof(elf), KBOX_REWRITE_ARCH_X86_64, allow, 2),
              0);
}

static void test_rewrite_has_wrapper_syscalls_aarch64(void)
{
    unsigned char elf[192];
    uint64_t allow[] = {56, 79};

    build_aarch64_fstatat_wrapper_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_has_wrapper_syscalls(
                  elf, sizeof(elf), KBOX_REWRITE_ARCH_AARCH64, allow, 2),
              1);

    allow[0] = 172;
    allow[1] = 173;
    ASSERT_EQ(kbox_rewrite_has_wrapper_syscalls(
                  elf, sizeof(elf), KBOX_REWRITE_ARCH_AARCH64, allow, 2),
              0);
}

static void test_rewrite_has_syscall_cancel_wrapper_syscalls_aarch64(void)
{
    unsigned char elf[192];
    uint64_t allow[] = {56, 79};

    build_aarch64_syscall_cancel_open_wrapper_elf(elf, sizeof(elf));
    ASSERT_EQ(kbox_rewrite_has_wrapper_syscalls(
                  elf, sizeof(elf), KBOX_REWRITE_ARCH_AARCH64, allow, 2),
              1);

    allow[0] = 63;
    allow[1] = 80;
    ASSERT_EQ(kbox_rewrite_has_wrapper_syscalls(
                  elf, sizeof(elf), KBOX_REWRITE_ARCH_AARCH64, allow, 2),
              0);
}

static void test_rewrite_wrapper_family_mask_memfd_x86_64(void)
{
    unsigned char elf[160];
    struct kbox_host_nrs host_nrs;
    uint32_t mask = 0;
    int fd;

    memset(&host_nrs, 0xff, sizeof(host_nrs));
    host_nrs.getpid = 39;
    host_nrs.getppid = 110;
    host_nrs.gettid = 186;
    host_nrs.newfstatat = 262;
    host_nrs.fstat = 5;
    host_nrs.stat = 4;
    host_nrs.lstat = 6;
    host_nrs.openat = 257;
    host_nrs.openat2 = 437;
    host_nrs.open = 2;

    build_x86_64_wrapper_elf_nr(elf, sizeof(elf), 257);
    fd = memfd_create("rewrite-mask-x86", 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (ssize_t) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_wrapper_family_mask_memfd(fd, &host_nrs, &mask), 0);
    ASSERT_EQ(mask, (uint32_t) KBOX_REWRITE_WRAPPER_FAMILY_OPEN);
    close(fd);
}

static void test_rewrite_wrapper_family_mask_memfd_aarch64(void)
{
    unsigned char elf[192];
    struct kbox_host_nrs host_nrs;
    uint32_t mask = 0;
    int fd;

    memset(&host_nrs, 0xff, sizeof(host_nrs));
    host_nrs.getpid = 172;
    host_nrs.getppid = 173;
    host_nrs.gettid = 178;
    host_nrs.newfstatat = 79;
    host_nrs.fstat = 80;
    host_nrs.stat = -1;
    host_nrs.lstat = -1;
    host_nrs.openat = 56;
    host_nrs.openat2 = -1;
    host_nrs.open = -1;

    build_aarch64_fstatat_wrapper_elf(elf, sizeof(elf));
    fd = memfd_create("rewrite-mask-aarch64-stat", 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (ssize_t) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_wrapper_family_mask_memfd(fd, &host_nrs, &mask), 0);
    ASSERT_EQ(mask, (uint32_t) KBOX_REWRITE_WRAPPER_FAMILY_STAT);
    close(fd);

    build_aarch64_syscall_cancel_open_wrapper_elf(elf, sizeof(elf));
    fd = memfd_create("rewrite-mask-aarch64-open", 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (ssize_t) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_wrapper_family_mask_memfd(fd, &host_nrs, &mask), 0);
    ASSERT_EQ(mask, (uint32_t) KBOX_REWRITE_WRAPPER_FAMILY_OPEN);
    close(fd);
}

struct wrapper_candidate_collect {
    struct kbox_rewrite_wrapper_candidate candidates[8];
    size_t count;
};

static int collect_wrapper_candidate_cb(
    const struct kbox_rewrite_wrapper_candidate *candidate,
    void *opaque)
{
    struct wrapper_candidate_collect *collect = opaque;

    if (!candidate || !collect)
        return -1;
    if (collect->count >=
        (sizeof(collect->candidates) / sizeof(collect->candidates[0]))) {
        return -1;
    }
    collect->candidates[collect->count++] = *candidate;
    return 0;
}

static void test_rewrite_visit_memfd_wrapper_candidates_x86_64(void)
{
    unsigned char elf[160];
    struct kbox_host_nrs host_nrs;
    struct wrapper_candidate_collect collect;
    int fd;

    memset(&host_nrs, 0xff, sizeof(host_nrs));
    host_nrs.getpid = 39;
    host_nrs.getppid = 110;
    host_nrs.gettid = 186;
    host_nrs.newfstatat = 262;
    host_nrs.fstat = 5;
    host_nrs.stat = 4;
    host_nrs.lstat = 6;
    host_nrs.openat = 257;
    host_nrs.openat2 = 437;
    host_nrs.open = 2;

    memset(&collect, 0, sizeof(collect));
    build_x86_64_wrapper_elf_nr(elf, sizeof(elf), 257);
    fd = memfd_create("rewrite-candidates-x86", 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (ssize_t) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_visit_memfd_wrapper_candidates(
                  fd, &host_nrs, KBOX_REWRITE_WRAPPER_FAMILY_OPEN,
                  collect_wrapper_candidate_cb, &collect),
              0);
    ASSERT_EQ(collect.count, (size_t) 1);
    ASSERT_EQ(collect.candidates[0].arch, KBOX_REWRITE_ARCH_X86_64);
    ASSERT_EQ(collect.candidates[0].kind,
              KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT);
    ASSERT_EQ(collect.candidates[0].file_offset, (uint64_t) 120);
    ASSERT_EQ(collect.candidates[0].vaddr, (uint64_t) 0x1000);
    ASSERT_EQ(collect.candidates[0].nr, (uint64_t) 257);
    ASSERT_EQ(collect.candidates[0].family_mask,
              (uint32_t) KBOX_REWRITE_WRAPPER_FAMILY_OPEN);
    close(fd);
}

static void test_rewrite_visit_memfd_wrapper_candidates_aarch64(void)
{
    unsigned char elf[192];
    struct kbox_host_nrs host_nrs;
    struct wrapper_candidate_collect collect;
    int fd;

    memset(&host_nrs, 0xff, sizeof(host_nrs));
    host_nrs.getpid = 172;
    host_nrs.getppid = 173;
    host_nrs.gettid = 178;
    host_nrs.newfstatat = 79;
    host_nrs.fstat = 80;
    host_nrs.stat = -1;
    host_nrs.lstat = -1;
    host_nrs.openat = 56;
    host_nrs.openat2 = -1;
    host_nrs.open = -1;

    memset(&collect, 0, sizeof(collect));
    build_aarch64_fstatat_wrapper_elf(elf, sizeof(elf));
    fd = memfd_create("rewrite-candidates-aarch64-stat", 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (ssize_t) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_visit_memfd_wrapper_candidates(
                  fd, &host_nrs, KBOX_REWRITE_WRAPPER_FAMILY_STAT,
                  collect_wrapper_candidate_cb, &collect),
              0);
    ASSERT_EQ(collect.count, (size_t) 1);
    ASSERT_EQ(collect.candidates[0].arch, KBOX_REWRITE_ARCH_AARCH64);
    ASSERT_EQ(collect.candidates[0].kind,
              KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT);
    ASSERT_EQ(collect.candidates[0].file_offset, (uint64_t) 124);
    ASSERT_EQ(collect.candidates[0].vaddr, (uint64_t) 0x4004);
    ASSERT_EQ(collect.candidates[0].nr, (uint64_t) 79);
    ASSERT_EQ(collect.candidates[0].family_mask,
              (uint32_t) KBOX_REWRITE_WRAPPER_FAMILY_STAT);
    close(fd);

    memset(&collect, 0, sizeof(collect));
    build_aarch64_syscall_cancel_open_wrapper_elf(elf, sizeof(elf));
    fd = memfd_create("rewrite-candidates-aarch64-open", 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (ssize_t) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_visit_memfd_wrapper_candidates(
                  fd, &host_nrs, KBOX_REWRITE_WRAPPER_FAMILY_OPEN,
                  collect_wrapper_candidate_cb, &collect),
              0);
    ASSERT_EQ(collect.count, (size_t) 1);
    ASSERT_EQ(collect.candidates[0].arch, KBOX_REWRITE_ARCH_AARCH64);
    ASSERT_EQ(collect.candidates[0].kind,
              KBOX_REWRITE_WRAPPER_CANDIDATE_SYSCALL_CANCEL);
    ASSERT_EQ(collect.candidates[0].file_offset, (uint64_t) 132);
    ASSERT_EQ(collect.candidates[0].vaddr, (uint64_t) 0x400c);
    ASSERT_EQ(collect.candidates[0].nr, (uint64_t) 56);
    ASSERT_EQ(collect.candidates[0].family_mask,
              (uint32_t) KBOX_REWRITE_WRAPPER_FAMILY_OPEN);
    close(fd);
}

static void test_rewrite_collect_memfd_wrapper_candidates_aarch64(void)
{
    unsigned char elf[192];
    struct kbox_host_nrs host_nrs;
    struct kbox_rewrite_wrapper_candidate candidates[2];
    size_t count = 0;
    int fd;

    memset(&host_nrs, 0xff, sizeof(host_nrs));
    host_nrs.getpid = 172;
    host_nrs.getppid = 173;
    host_nrs.gettid = 178;
    host_nrs.newfstatat = 79;
    host_nrs.fstat = 80;
    host_nrs.stat = -1;
    host_nrs.lstat = -1;
    host_nrs.openat = 56;
    host_nrs.openat2 = -1;
    host_nrs.open = -1;

    build_aarch64_syscall_cancel_open_wrapper_elf(elf, sizeof(elf));
    fd = memfd_create("rewrite-collect-aarch64-open", 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (ssize_t) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_collect_memfd_wrapper_candidates(
                  fd, &host_nrs, KBOX_REWRITE_WRAPPER_FAMILY_OPEN, candidates,
                  2, &count),
              0);
    ASSERT_EQ(count, (size_t) 1);
    ASSERT_EQ(candidates[0].arch, KBOX_REWRITE_ARCH_AARCH64);
    ASSERT_EQ(candidates[0].kind,
              KBOX_REWRITE_WRAPPER_CANDIDATE_SYSCALL_CANCEL);
    ASSERT_EQ(candidates[0].file_offset, (uint64_t) 132);
    ASSERT_EQ(candidates[0].vaddr, (uint64_t) 0x400c);
    ASSERT_EQ(candidates[0].nr, (uint64_t) 56);
    close(fd);
}

static void test_rewrite_collect_memfd_wrapper_candidates_by_kind_aarch64(void)
{
    unsigned char elf[192];
    struct kbox_host_nrs host_nrs;
    struct kbox_rewrite_wrapper_candidate candidates[2];
    size_t count = 0;
    int fd;

    memset(&host_nrs, 0xff, sizeof(host_nrs));
    host_nrs.getpid = 172;
    host_nrs.getppid = 173;
    host_nrs.gettid = 178;
    host_nrs.newfstatat = 79;
    host_nrs.fstat = 80;
    host_nrs.stat = -1;
    host_nrs.lstat = -1;
    host_nrs.openat = 56;
    host_nrs.openat2 = -1;
    host_nrs.open = -1;

    build_aarch64_syscall_cancel_open_wrapper_elf(elf, sizeof(elf));
    fd = memfd_create("rewrite-collect-aarch64-open-kind", 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (ssize_t) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_collect_memfd_wrapper_candidates_by_kind(
                  fd, &host_nrs, KBOX_REWRITE_WRAPPER_FAMILY_OPEN,
                  KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT, candidates, 2, &count),
              0);
    ASSERT_EQ(count, (size_t) 0);
    ASSERT_EQ(kbox_rewrite_collect_memfd_wrapper_candidates_by_kind(
                  fd, &host_nrs, KBOX_REWRITE_WRAPPER_FAMILY_OPEN,
                  KBOX_REWRITE_WRAPPER_CANDIDATE_SYSCALL_CANCEL, candidates, 2,
                  &count),
              0);
    ASSERT_EQ(count, (size_t) 1);
    ASSERT_EQ(candidates[0].kind,
              KBOX_REWRITE_WRAPPER_CANDIDATE_SYSCALL_CANCEL);
    ASSERT_EQ(candidates[0].file_offset, (uint64_t) 132);
    ASSERT_EQ(candidates[0].vaddr, (uint64_t) 0x400c);
    close(fd);
}

static void test_rewrite_collect_memfd_phase1_path_candidates_aarch64(void)
{
    unsigned char elf[192];
    struct kbox_host_nrs host_nrs;
    struct kbox_rewrite_wrapper_candidate candidates[2];
    size_t count = 0;
    int fd;

    memset(&host_nrs, 0xff, sizeof(host_nrs));
    host_nrs.getpid = 172;
    host_nrs.getppid = 173;
    host_nrs.gettid = 178;
    host_nrs.newfstatat = 79;
    host_nrs.fstat = 80;
    host_nrs.stat = -1;
    host_nrs.lstat = -1;
    host_nrs.openat = 56;
    host_nrs.openat2 = -1;
    host_nrs.open = -1;

    build_aarch64_fstatat_wrapper_elf(elf, sizeof(elf));
    fd = memfd_create("rewrite-collect-aarch64-phase1-stat", 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (ssize_t) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_collect_memfd_phase1_path_candidates(
                  fd, &host_nrs, candidates, 2, &count),
              0);
    ASSERT_EQ(count, (size_t) 1);
    ASSERT_EQ(candidates[0].kind, KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT);
    ASSERT_EQ(candidates[0].family_mask,
              (uint32_t) KBOX_REWRITE_WRAPPER_FAMILY_STAT);
    ASSERT_EQ(candidates[0].file_offset, (uint64_t) 124);
    ASSERT_EQ(candidates[0].vaddr, (uint64_t) 0x4004);
    ASSERT_EQ(candidates[0].nr, (uint64_t) 79);
    close(fd);

    build_aarch64_wrapper_elf_nr(elf, sizeof(elf), 56);
    fd = memfd_create("rewrite-collect-aarch64-phase1-open", 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (ssize_t) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_collect_memfd_phase1_path_candidates(
                  fd, &host_nrs, candidates, 2, &count),
              0);
    ASSERT_EQ(count, (size_t) 1);
    ASSERT_EQ(candidates[0].kind, KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT);
    ASSERT_EQ(candidates[0].family_mask,
              (uint32_t) KBOX_REWRITE_WRAPPER_FAMILY_OPEN);
    ASSERT_EQ(candidates[0].file_offset, (uint64_t) 124);
    ASSERT_EQ(candidates[0].vaddr, (uint64_t) 0x4004);
    ASSERT_EQ(candidates[0].nr, (uint64_t) 56);
    close(fd);

    build_aarch64_syscall_cancel_open_wrapper_elf(elf, sizeof(elf));
    fd = memfd_create("rewrite-collect-aarch64-phase1-cancel", 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (ssize_t) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_collect_memfd_phase1_path_candidates(
                  fd, &host_nrs, candidates, 2, &count),
              0);
    ASSERT_EQ(count, (size_t) 0);
    close(fd);
}

static void test_rewrite_apply_memfd_phase1_path_candidates_aarch64(void)
{
    unsigned char elf[192];
    struct kbox_host_nrs host_nrs;
    unsigned char patched[4];
    size_t applied = 0;
    int fd;

    memset(&host_nrs, 0xff, sizeof(host_nrs));
    host_nrs.getpid = 172;
    host_nrs.getppid = 173;
    host_nrs.gettid = 178;
    host_nrs.newfstatat = 79;
    host_nrs.fstat = 80;
    host_nrs.stat = -1;
    host_nrs.lstat = -1;
    host_nrs.openat = 56;
    host_nrs.openat2 = -1;
    host_nrs.open = -1;

    build_aarch64_fstatat_wrapper_elf(elf, sizeof(elf));
    fd = memfd_create("rewrite-apply-aarch64-phase1-stat", 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (ssize_t) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_apply_memfd_phase1_path_candidates(fd, &host_nrs,
                                                              &applied, NULL),
              0);
    ASSERT_EQ(applied, (size_t) 1);
    ASSERT_EQ(pread(fd, patched, sizeof(patched), 124), (ssize_t) 4);
    ASSERT_NE(memcmp(patched, "\x01\x00\x00\xd4", 4), 0);
    close(fd);

    build_aarch64_wrapper_elf_nr(elf, sizeof(elf), 56);
    fd = memfd_create("rewrite-apply-aarch64-phase1-open", 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (ssize_t) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_apply_memfd_phase1_path_candidates(fd, &host_nrs,
                                                              &applied, NULL),
              0);
    ASSERT_EQ(applied, (size_t) 1);
    ASSERT_EQ(pread(fd, patched, sizeof(patched), 124), (ssize_t) 4);
    ASSERT_NE(memcmp(patched, "\x01\x00\x00\xd4", 4), 0);
    close(fd);

    build_aarch64_syscall_cancel_open_wrapper_elf(elf, sizeof(elf));
    fd = memfd_create("rewrite-apply-aarch64-phase1-cancel", 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ(write(fd, elf, sizeof(elf)), (ssize_t) sizeof(elf));
    ASSERT_EQ(kbox_rewrite_apply_memfd_phase1_path_candidates(fd, &host_nrs,
                                                              &applied, NULL),
              0);
    ASSERT_EQ(applied, (size_t) 0);
    ASSERT_EQ(pread(fd, patched, sizeof(patched), 132), (ssize_t) 4);
    ASSERT_EQ(memcmp(patched, "\x02\x00\x00\x14", 4), 0);
    close(fd);
}

void test_rewrite_init(void)
{
    TEST_REGISTER(test_syscall_mode_parser);
    TEST_REGISTER(test_elf_exec_segment_walker);
    TEST_REGISTER(test_rewrite_analyze_x86_64);
    TEST_REGISTER(test_rewrite_analyze_x86_64_wrapper);
    TEST_REGISTER(test_rewrite_analyze_aarch64);
    TEST_REGISTER(test_rewrite_rejects_unknown_machine);
    TEST_REGISTER(test_elf_exec_rejects_huge_phoff);
    TEST_REGISTER(test_elf_interp_rejects_huge_phoff);
    TEST_REGISTER(test_rewrite_visit_x86_64_sites);
    TEST_REGISTER(test_rewrite_visit_x86_64_wrapper_site);
    TEST_REGISTER(test_rewrite_visit_aarch64_sites);
    TEST_REGISTER(test_rewrite_visit_aarch64_cancel_wrapper_site);
    TEST_REGISTER(test_rewrite_visit_aarch64_fstatat_wrapper_site);
    TEST_REGISTER(test_rewrite_plan_x86_64_sites);
    TEST_REGISTER(test_rewrite_plan_aarch64_sites);
    TEST_REGISTER(test_rewrite_plan_aarch64_segment_out_of_range);
    TEST_REGISTER(test_rewrite_encode_x86_64_patch);
    TEST_REGISTER(test_rewrite_encode_x86_64_wrapper_patch);
    TEST_REGISTER(test_rewrite_encode_x86_64_page_zero_trampoline);
    TEST_REGISTER(test_rewrite_encode_aarch64_branch_patch);
    TEST_REGISTER(test_rewrite_encode_aarch64_branch_out_of_range);
    TEST_REGISTER(test_rewrite_apply_x86_64_elf);
    TEST_REGISTER(test_rewrite_apply_x86_64_wrapper_elf);
    TEST_REGISTER(test_rewrite_apply_aarch64_elf);
    TEST_REGISTER(test_rewrite_apply_memfd_x86_64);
    TEST_REGISTER(test_rewrite_apply_virtual_procinfo_x86_64_wrapper_elf);
    TEST_REGISTER(
        test_rewrite_apply_virtual_procinfo_x86_64_getppid_wrapper_elf);
    TEST_REGISTER(
        test_rewrite_apply_virtual_procinfo_skips_non_procinfo_wrapper);
    TEST_REGISTER(test_rewrite_apply_virtual_procinfo_aarch64_wrapper_elf);
    TEST_REGISTER(
        test_rewrite_apply_virtual_procinfo_aarch64_getppid_wrapper_elf);
    TEST_REGISTER(
        test_rewrite_apply_virtual_procinfo_skips_non_procinfo_aarch64);
    TEST_REGISTER(test_rewrite_wrapper_syscall_nr_x86_64);
    TEST_REGISTER(test_rewrite_wrapper_syscall_nr_aarch64);
    TEST_REGISTER(test_rewrite_origin_map_x86_64);
    TEST_REGISTER(test_rewrite_origin_map_aarch64);
    TEST_REGISTER(test_rewrite_origin_map_add_site_source);
    TEST_REGISTER(test_rewrite_origin_map_seal);
    TEST_REGISTER(test_rewrite_probe_x86_64_page_zero_allowed);
    TEST_REGISTER(test_rewrite_probe_x86_64_page_zero_blocked);
    TEST_REGISTER(test_rewrite_fast_host_syscall0_classification);
    TEST_REGISTER(test_rewrite_has_wrapper_syscalls_x86_64);
    TEST_REGISTER(test_rewrite_has_wrapper_syscalls_aarch64);
    TEST_REGISTER(test_rewrite_has_syscall_cancel_wrapper_syscalls_aarch64);
    TEST_REGISTER(test_rewrite_wrapper_family_mask_memfd_x86_64);
    TEST_REGISTER(test_rewrite_wrapper_family_mask_memfd_aarch64);
    TEST_REGISTER(test_rewrite_visit_memfd_wrapper_candidates_x86_64);
    TEST_REGISTER(test_rewrite_visit_memfd_wrapper_candidates_aarch64);
    TEST_REGISTER(test_rewrite_collect_memfd_wrapper_candidates_aarch64);
    TEST_REGISTER(
        test_rewrite_collect_memfd_wrapper_candidates_by_kind_aarch64);
    TEST_REGISTER(test_rewrite_collect_memfd_phase1_path_candidates_aarch64);
    TEST_REGISTER(test_rewrite_apply_memfd_phase1_path_candidates_aarch64);
}
