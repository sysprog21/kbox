/* SPDX-License-Identifier: MIT */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "kbox/elf.h"

#include "io-util.h"
#include "kbox/x86-decode.h"
#include "rewrite.h"
#include "syscall-nr.h"
#include "syscall-trap.h"

#define EM_X86_64 62
#define EM_AARCH64 183
#define AARCH64_B_OPCODE 0x14000000u
#define AARCH64_B_IMM26_MASK 0x03ffffffu
#define AARCH64_B_RANGE ((int64_t) 128 * 1024 * 1024)
#define AARCH64_LDR_LITERAL_OPCODE 0x58000000u
#define AARCH64_BR_OPCODE 0xd61f0000u
#define AARCH64_NOP_OPCODE 0xd503201fu
#define AARCH64_REWRITE_SLOT_SIZE 32u
#define X86_64_REWRITE_PAGE_ZERO_SIZE (64u * 1024u)
#define X86_64_REWRITE_WRAPPER_SLOT_SIZE 32u
#define X86_64_MOVABS_R11_OPCODE_LEN 10u
#define X86_64_JMP_R11_OPCODE_LEN 3u
#define X86_64_PAGE_ZERO_TAIL_LEN \
    (X86_64_MOVABS_R11_OPCODE_LEN + X86_64_JMP_R11_OPCODE_LEN)
#define X86_64_JMP_REL32_OPCODE_LEN 5u
#define X86_64_WRAPPER_SITE_LEN 8u
#define X86_64_TRAMPOLINE_SEARCH_STEP (64u * 1024u)
#define X86_64_TRAMPOLINE_SEARCH_LIMIT ((uint64_t) INT32_MAX - 4096u)
#define AARCH64_VENEER_SIZE 16u /* LDR x16, +8; BR x16; .quad target */
#define AARCH64_VENEER_SEARCH_STEP (64u * 1024u)
#define AARCH64_VENEER_SEARCH_LIMIT ((uint64_t) 127 * 1024 * 1024)

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

struct analyze_ctx {
    enum kbox_rewrite_arch arch;
    kbox_rewrite_site_cb cb;
    kbox_rewrite_planned_site_cb planned_cb;
    void *opaque;
    size_t candidates;
    size_t segments;
};

struct runtime_planned_site {
    struct kbox_rewrite_planned_site planned;
    uint64_t actual_site_addr;
    uint64_t actual_trampoline_addr;
    enum kbox_loader_mapping_source source;
    enum kbox_rewrite_wrapper_candidate_kind wrapper_kind;
    uint64_t wrapper_nr;
};

struct runtime_site_array {
    struct runtime_planned_site *sites;
    size_t count;
    size_t cap;
};

struct runtime_collect_ctx {
    struct runtime_site_array *array;
    uint64_t load_bias;
    enum kbox_loader_mapping_source source;
};

static struct kbox_rewrite_runtime *active_rewrite_runtime;

static inline struct kbox_rewrite_runtime *load_active_rewrite_runtime(void)
{
    return __atomic_load_n(&active_rewrite_runtime, __ATOMIC_ACQUIRE);
}

static inline void store_active_rewrite_runtime(
    struct kbox_rewrite_runtime *runtime)
{
    __atomic_store_n(&active_rewrite_runtime, runtime, __ATOMIC_RELEASE);
}

static void write_le32(unsigned char out[4], uint32_t value);
static int rewrite_is_wrapper_site(const struct kbox_rewrite_origin_map *map,
                                   uint64_t origin_addr);
static uint32_t wrapper_family_mask_for_nr(const struct kbox_host_nrs *host_nrs,
                                           uint64_t nr);
static int planned_site_matches_wrapper_candidate(
    const struct kbox_rewrite_planned_site *planned,
    const struct kbox_rewrite_wrapper_candidate *candidate);

#if defined(__aarch64__)
extern char kbox_syscall_rewrite_aarch64_entry[];
extern char kbox_syscall_rewrite_aarch64_cancel_entry[];
extern int64_t kbox_syscall_rewrite_aarch64_dispatch(uint64_t origin_addr,
                                                     uint64_t nr,
                                                     uint64_t a0,
                                                     uint64_t a1,
                                                     uint64_t a2,
                                                     uint64_t a3,
                                                     uint64_t a4,
                                                     uint64_t a5);

__asm__(
    ".text\n"
    ".globl kbox_syscall_rewrite_aarch64_entry\n"
    ".type kbox_syscall_rewrite_aarch64_entry,%function\n"
    "kbox_syscall_rewrite_aarch64_entry:\n"
    "sub sp, sp, #144\n"
    "stp x1, x2, [sp, #0]\n"
    "stp x3, x4, [sp, #16]\n"
    "stp x5, x6, [sp, #32]\n"
    "stp x7, x8, [sp, #48]\n"
    "stp x9, x10, [sp, #64]\n"
    "stp x11, x12, [sp, #80]\n"
    "stp x13, x14, [sp, #96]\n"
    "stp x15, x18, [sp, #112]\n"
    "stp x19, x30, [sp, #128]\n"
    "mov x19, x17\n"
    "mov x2, x0\n"
    "ldr x3, [sp, #0]\n"
    "ldr x4, [sp, #8]\n"
    "ldr x5, [sp, #16]\n"
    "ldr x6, [sp, #24]\n"
    "ldr x7, [sp, #32]\n"
    "ldr x1, [sp, #56]\n"
    "mov x0, x19\n"
    "bl kbox_syscall_rewrite_aarch64_dispatch\n"
    "add x16, x19, #4\n"
    "ldp x1, x2, [sp, #0]\n"
    "ldp x3, x4, [sp, #16]\n"
    "ldp x5, x6, [sp, #32]\n"
    "ldp x7, x8, [sp, #48]\n"
    "ldp x9, x10, [sp, #64]\n"
    "ldp x11, x12, [sp, #80]\n"
    "ldp x13, x14, [sp, #96]\n"
    "ldp x15, x18, [sp, #112]\n"
    "ldp x19, x30, [sp, #128]\n"
    "add sp, sp, #144\n"
    "br x16\n"
    ".size kbox_syscall_rewrite_aarch64_entry, "
    ".-kbox_syscall_rewrite_aarch64_entry\n");

__asm__(
    ".text\n"
    ".globl kbox_syscall_rewrite_aarch64_cancel_entry\n"
    ".type kbox_syscall_rewrite_aarch64_cancel_entry,%function\n"
    "kbox_syscall_rewrite_aarch64_cancel_entry:\n"
    "sub sp, sp, #144\n"
    "stp x1, x2, [sp, #0]\n"
    "stp x3, x4, [sp, #16]\n"
    "stp x5, x6, [sp, #32]\n"
    "stp x7, x8, [sp, #48]\n"
    "stp x9, x10, [sp, #64]\n"
    "stp x11, x12, [sp, #80]\n"
    "stp x13, x14, [sp, #96]\n"
    "stp x15, x18, [sp, #112]\n"
    "stp x19, x30, [sp, #128]\n"
    "mov x19, x17\n"
    "mov x2, x0\n"
    "ldr x3, [sp, #0]\n"
    "ldr x4, [sp, #8]\n"
    "ldr x5, [sp, #16]\n"
    "ldr x6, [sp, #24]\n"
    "ldr x7, [sp, #32]\n"
    "ldr x1, [sp, #40]\n"
    "mov x0, x19\n"
    "bl kbox_syscall_rewrite_aarch64_dispatch\n"
    "add x16, x19, #4\n"
    "ldp x1, x2, [sp, #0]\n"
    "ldp x3, x4, [sp, #16]\n"
    "ldp x5, x6, [sp, #32]\n"
    "ldp x7, x8, [sp, #48]\n"
    "ldp x9, x10, [sp, #64]\n"
    "ldp x11, x12, [sp, #80]\n"
    "ldp x13, x14, [sp, #96]\n"
    "ldp x15, x18, [sp, #112]\n"
    "ldp x19, x30, [sp, #128]\n"
    "add sp, sp, #144\n"
    "br x16\n"
    ".size kbox_syscall_rewrite_aarch64_cancel_entry, "
    ".-kbox_syscall_rewrite_aarch64_cancel_entry\n");
#endif

#if defined(__x86_64__)
extern char kbox_syscall_rewrite_x86_64_entry[];
extern char kbox_syscall_rewrite_x86_64_wrapper_entry[];
extern int64_t kbox_syscall_rewrite_x86_64_dispatch(uint64_t origin_addr,
                                                    uint64_t nr,
                                                    const uint64_t *args);

__asm__(
    ".text\n"
    ".globl kbox_syscall_rewrite_x86_64_entry\n"
    ".type kbox_syscall_rewrite_x86_64_entry,@function\n"
    "kbox_syscall_rewrite_x86_64_entry:\n"
    "mov (%rsp), %r11\n"
    "sub $56, %rsp\n"
    "mov %rdi, 8(%rsp)\n"
    "mov %rsi, 16(%rsp)\n"
    "mov %rdx, 24(%rsp)\n"
    "mov %r10, 32(%rsp)\n"
    "mov %r8, 40(%rsp)\n"
    "mov %r9, 48(%rsp)\n"
    "mov %r11, %rdi\n"
    "mov %rax, %rsi\n"
    "lea 8(%rsp), %rdx\n"
    "call kbox_syscall_rewrite_x86_64_dispatch\n"
    "mov 8(%rsp), %rdi\n"
    "mov 16(%rsp), %rsi\n"
    "mov 24(%rsp), %rdx\n"
    "mov 32(%rsp), %r10\n"
    "mov 40(%rsp), %r8\n"
    "mov 48(%rsp), %r9\n"
    "add $56, %rsp\n"
    "ret\n"
    ".size kbox_syscall_rewrite_x86_64_entry, "
    ".-kbox_syscall_rewrite_x86_64_entry\n");

__asm__(
    ".text\n"
    ".globl kbox_syscall_rewrite_x86_64_wrapper_entry\n"
    ".type kbox_syscall_rewrite_x86_64_wrapper_entry,@function\n"
    "kbox_syscall_rewrite_x86_64_wrapper_entry:\n"
    "sub $56, %rsp\n"
    "mov %rdi, 8(%rsp)\n"
    "mov %rsi, 16(%rsp)\n"
    "mov %rdx, 24(%rsp)\n"
    "mov %r10, 32(%rsp)\n"
    "mov %r8, 40(%rsp)\n"
    "mov %r9, 48(%rsp)\n"
    "mov %r11, %rdi\n"
    "mov %rax, %rsi\n"
    "lea 8(%rsp), %rdx\n"
    "call kbox_syscall_rewrite_x86_64_dispatch\n"
    "mov 8(%rsp), %rdi\n"
    "mov 16(%rsp), %rsi\n"
    "mov 24(%rsp), %rdx\n"
    "mov 32(%rsp), %r10\n"
    "mov 40(%rsp), %r8\n"
    "mov 48(%rsp), %r9\n"
    "add $56, %rsp\n"
    "ret\n"
    ".size kbox_syscall_rewrite_x86_64_wrapper_entry, "
    ".-kbox_syscall_rewrite_x86_64_wrapper_entry\n");
#endif

static int x86_64_is_wrapper_site(const unsigned char *segment_bytes,
                                  size_t file_size,
                                  size_t offset)
{
    if (!segment_bytes || offset + X86_64_WRAPPER_SITE_LEN > file_size)
        return 0;
    return segment_bytes[offset] == 0xb8 && segment_bytes[offset + 5] == 0x0f &&
           (segment_bytes[offset + 6] == 0x05 ||
            segment_bytes[offset + 6] == 0x34) &&
           segment_bytes[offset + 7] == 0xc3;
}

static uint32_t x86_64_wrapper_syscall_nr(const unsigned char original[8])
{
    return (uint32_t) original[1] | ((uint32_t) original[2] << 8) |
           ((uint32_t) original[3] << 16) | ((uint32_t) original[4] << 24);
}

static uint32_t aarch64_wrapper_syscall_nr(const struct kbox_rewrite_site *site)
{
    uint32_t insn;

    if (!site || site->width != 4)
        return UINT32_MAX;
    insn = (uint32_t) site->original[0] | ((uint32_t) site->original[1] << 8) |
           ((uint32_t) site->original[2] << 16) |
           ((uint32_t) site->original[3] << 24);

    /* movz x8, #imm16 or movz w8, #imm16 */
    if ((insn & 0xffe0001fu) == 0xd2800008u ||
        (insn & 0xffe0001fu) == 0x52800008u) {
        return (insn >> 5) & 0xffffu;
    }

    return UINT32_MAX;
}

static int aarch64_movz_reg_imm16(uint32_t insn,
                                  unsigned reg,
                                  uint32_t *imm_out)
{
    if (!imm_out || reg > 31)
        return -1;

    if ((insn & 0xffe0001fu) == (0xd2800000u | reg) ||
        (insn & 0xffe0001fu) == (0x52800000u | reg)) {
        *imm_out = (insn >> 5) & 0xffffu;
        return 0;
    }

    return -1;
}

static int encode_x86_64_virtual_procinfo_patch(
    const struct kbox_rewrite_site *site,
    struct kbox_rewrite_patch *patch)
{
    uint32_t nr;
    uint32_t value;

    if (!site || !patch)
        return -1;
    if (site->width != X86_64_WRAPPER_SITE_LEN || site->original[0] != 0xb8 ||
        site->original[5] != 0x0f ||
        (site->original[6] != 0x05 && site->original[6] != 0x34) ||
        site->original[7] != 0xc3) {
        return -1;
    }

    nr = x86_64_wrapper_syscall_nr(site->original);
    if (nr == (uint32_t) HOST_NRS_X86_64.getpid ||
        nr == (uint32_t) HOST_NRS_X86_64.gettid) {
        value = 1;
    } else if (nr == (uint32_t) HOST_NRS_X86_64.getppid) {
        value = 0;
    } else {
        return -1;
    }

    patch->width = X86_64_WRAPPER_SITE_LEN;
    patch->bytes[0] = 0xb8;
    patch->bytes[1] = (unsigned char) (value & 0xff);
    patch->bytes[2] = (unsigned char) ((value >> 8) & 0xff);
    patch->bytes[3] = (unsigned char) ((value >> 16) & 0xff);
    patch->bytes[4] = (unsigned char) ((value >> 24) & 0xff);
    patch->bytes[5] = 0xc3;
    patch->bytes[6] = 0x90;
    patch->bytes[7] = 0x90;
    return 0;
}

static int aarch64_prev_insn_syscall_nr(const unsigned char *image,
                                        size_t image_len,
                                        size_t site_off,
                                        uint32_t *nr_out)
{
    uint32_t insn;

    if (!image || !nr_out || site_off < 4 || site_off + 4 > image_len)
        return -1;

    insn = (uint32_t) image[site_off - 4] |
           ((uint32_t) image[site_off - 3] << 8) |
           ((uint32_t) image[site_off - 2] << 16) |
           ((uint32_t) image[site_off - 1] << 24);

    /* movz x8, #imm16 */
    if ((insn & 0xffe0001fu) == 0xd2800008u) {
        *nr_out = (insn >> 5) & 0xffffu;
        return 0;
    }

    /* movz w8, #imm16 */
    if ((insn & 0xffe0001fu) == 0x52800008u) {
        *nr_out = (insn >> 5) & 0xffffu;
        return 0;
    }

    return -1;
}

static int encode_aarch64_virtual_procinfo_patch(
    const struct kbox_rewrite_site *site,
    const unsigned char *image,
    size_t image_len,
    struct kbox_rewrite_patch *patch)
{
    uint32_t nr;
    uint32_t value;
    uint32_t next_insn;
    size_t site_off;
    uint32_t movz_x0;

    if (!site || !image || !patch || site->width != 4)
        return -1;
    if (site->original[0] != 0x01 || site->original[1] != 0x00 ||
        site->original[2] != 0x00 || site->original[3] != 0xd4) {
        return -1;
    }

    site_off = (size_t) site->file_offset;
    if (site_off + 8 > image_len)
        return -1;

    next_insn = (uint32_t) image[site_off + 4] |
                ((uint32_t) image[site_off + 5] << 8) |
                ((uint32_t) image[site_off + 6] << 16) |
                ((uint32_t) image[site_off + 7] << 24);
    if (next_insn != 0xd65f03c0u)
        return -1;

    if (aarch64_prev_insn_syscall_nr(image, image_len, site_off, &nr) < 0)
        return -1;

    if (nr == (uint32_t) HOST_NRS_AARCH64.getpid ||
        nr == (uint32_t) HOST_NRS_AARCH64.gettid) {
        value = 1;
    } else if (nr == (uint32_t) HOST_NRS_AARCH64.getppid) {
        value = 0;
    } else {
        return -1;
    }

    movz_x0 = 0xd2800000u | ((value & 0xffffu) << 5);
    patch->width = 4;
    write_le32(patch->bytes, movz_x0);
    return 0;
}

static int encode_virtual_procinfo_patch(const struct kbox_rewrite_site *site,
                                         const unsigned char *image,
                                         size_t image_len,
                                         enum kbox_rewrite_arch arch,
                                         struct kbox_rewrite_patch *patch)
{
    switch (arch) {
    case KBOX_REWRITE_ARCH_X86_64:
        return encode_x86_64_virtual_procinfo_patch(site, patch);
    case KBOX_REWRITE_ARCH_AARCH64:
        return encode_aarch64_virtual_procinfo_patch(site, image, image_len,
                                                     patch);
    default:
        return -1;
    }
}

static int rewrite_read_fd_all(int fd, unsigned char **buf_out, size_t *len_out)
{
    struct stat st;
    unsigned char *buf;
    size_t len;
    size_t total = 0;

    if (fd < 0 || !buf_out || !len_out)
        return -1;
    if (fstat(fd, &st) < 0 || st.st_size < 0)
        return -1;

    len = (size_t) st.st_size;
    if (len == 0)
        return -1;

    buf = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
               -1, 0);
    if (buf == MAP_FAILED)
        return -1;

    while (total < len) {
        ssize_t nr = pread(fd, buf + total, len - total, (off_t) total);

        if (nr < 0) {
            if (errno == EINTR)
                continue;
            munmap(buf, len);
            return -1;
        }
        if (nr == 0) {
            munmap(buf, len);
            return -1;
        }
        total += (size_t) nr;
    }

    *buf_out = buf;
    *len_out = len;
    return 0;
}

static uint64_t align_up_u64_or_zero(uint64_t value, uint64_t align)
{
    uint64_t mask;

    if (align == 0 || (align & (align - 1)) != 0)
        return 0;
    mask = align - 1;
    if (value > UINT64_MAX - mask)
        return 0;
    return (value + mask) & ~mask;
}

static int origin_map_is_sealed(const struct kbox_rewrite_origin_map *map)
{
    return map && map->sealed;
}

static int rewrite_origin_addr(const struct kbox_rewrite_site *site,
                               uint64_t *origin_out)
{
    uint64_t origin;

    if (!site || !origin_out)
        return -1;

    if (site->width == 2 && site->original[0] == 0x0f &&
        (site->original[1] == 0x05 || site->original[1] == 0x34)) {
        if (__builtin_add_overflow(site->vaddr, 2u, &origin))
            return -1;
        *origin_out = origin;
        return 0;
    }

    if (site->width == X86_64_WRAPPER_SITE_LEN && site->original[0] == 0xb8 &&
        site->original[5] == 0x0f &&
        (site->original[6] == 0x05 || site->original[6] == 0x34) &&
        site->original[7] == 0xc3) {
        *origin_out = site->vaddr;
        return 0;
    }

    if (site->width == 4 && site->original[0] == 0x01 &&
        site->original[1] == 0x00 && site->original[2] == 0x00 &&
        site->original[3] == 0xd4) {
        *origin_out = site->vaddr;
        return 0;
    }

    if (site->width == 4) {
        uint32_t insn = (uint32_t) site->original[0] |
                        ((uint32_t) site->original[1] << 8) |
                        ((uint32_t) site->original[2] << 16) |
                        ((uint32_t) site->original[3] << 24);
        if ((insn & 0xfc000000u) == 0x14000000u ||
            (insn & 0xfc000000u) == 0x94000000u) {
            *origin_out = site->vaddr;
            return 0;
        }
    }

    errno = EINVAL;
    return -1;
}

/* Site classification for caller-aware rewrite dispatch.
 *
 * x86-64 wrapper pattern: the 8-byte sequence "mov $NR, %eax; syscall; ret"
 * (B8 xx xx xx xx 0F 05 C3) is always WRAPPER: the function's only purpose
 * is to execute the syscall and return the result. This is the musl __syscall0
 * pattern and covers the vast majority of libc syscall sites.
 *
 * For 2-byte syscall sites (bare 0F 05), we look at the byte immediately
 * after the syscall: if it is C3 (ret) or 0F 1F (NOP), the site is inside a
 * leaf wrapper. Otherwise (conditional jump, further computation, another
 * syscall) the site is COMPLEX.
 *
 * aarch64 wrapper pattern: SVC #0 followed by RET (D65F03C0) within the next
 * 2 instructions (8 bytes). If the ret is immediate or separated only by a
 * MOV (return value adjustment), it's WRAPPER.
 */
enum kbox_rewrite_site_class kbox_rewrite_classify_x86_64_site(
    const unsigned char *segment_bytes,
    size_t segment_size,
    size_t site_offset,
    unsigned char site_width)
{
    if (!segment_bytes)
        return KBOX_REWRITE_SITE_UNKNOWN;

    /* 8-byte wrapper: mov $NR, %eax; syscall; ret → always WRAPPER. */
    if (site_width == X86_64_WRAPPER_SITE_LEN) {
        if (site_offset + X86_64_WRAPPER_SITE_LEN <= segment_size &&
            segment_bytes[site_offset] == 0xb8 &&
            segment_bytes[site_offset + 5] == 0x0f &&
            (segment_bytes[site_offset + 6] == 0x05 ||
             segment_bytes[site_offset + 6] == 0x34) &&
            segment_bytes[site_offset + 7] == 0xc3) {
            return KBOX_REWRITE_SITE_WRAPPER;
        }
        return KBOX_REWRITE_SITE_UNKNOWN;
    }

    /* 2-byte syscall (0F 05): check what follows. */
    if (site_width == 2) {
        size_t after = site_offset + 2;
        if (after >= segment_size)
            return KBOX_REWRITE_SITE_UNKNOWN;

        /* Immediate ret after syscall → wrapper. */
        if (segment_bytes[after] == 0xc3)
            return KBOX_REWRITE_SITE_WRAPPER;

        /* "cmp $0xfffffffffffff001, %rax; jae <error>" is the musl
         * __syscall_ret pattern: syscall; cmp; jae; ret. Still a wrapper
         * (the error path does not feed the result into another syscall).
         * Pattern: 48 3d 01 f0 ff ff (6 bytes for CMP rax, -4095)
         */
        if (after + 6 <= segment_size && segment_bytes[after] == 0x48 &&
            segment_bytes[after + 1] == 0x3d &&
            segment_bytes[after + 2] == 0x01 &&
            segment_bytes[after + 3] == 0xf0 &&
            segment_bytes[after + 4] == 0xff &&
            segment_bytes[after + 5] == 0xff) {
            return KBOX_REWRITE_SITE_WRAPPER;
        }

        /* NOP after syscall (alignment padding) then check next. */
        if (segment_bytes[after] == 0x90) {
            if (after + 1 < segment_size && segment_bytes[after + 1] == 0xc3)
                return KBOX_REWRITE_SITE_WRAPPER;
        }

        /* Anything else: inside a complex function. */
        return KBOX_REWRITE_SITE_COMPLEX;
    }

    return KBOX_REWRITE_SITE_UNKNOWN;
}

enum kbox_rewrite_site_class kbox_rewrite_classify_aarch64_site(
    const unsigned char *segment_bytes,
    size_t segment_size,
    size_t site_offset)
{
    uint32_t next_insn;

    if (!segment_bytes)
        return KBOX_REWRITE_SITE_UNKNOWN;

    /* SVC #0 is 4 bytes. Check the instruction(s) that follow. */
    if (site_offset + 8 > segment_size)
        return KBOX_REWRITE_SITE_UNKNOWN;

    /* Read the next instruction (little-endian). */
    next_insn = (uint32_t) segment_bytes[site_offset + 4] |
                ((uint32_t) segment_bytes[site_offset + 5] << 8) |
                ((uint32_t) segment_bytes[site_offset + 6] << 16) |
                ((uint32_t) segment_bytes[site_offset + 7] << 24);

    /* RET (D65F03C0) immediately after SVC → wrapper. */
    if (next_insn == 0xd65f03c0u)
        return KBOX_REWRITE_SITE_WRAPPER;

    /* CMN x0, #0xFFF (musl __syscall_ret error check):
     * Encoding: B1 00 3C 1F (CMN x0, #0xf, LSL #12) or
     *           31 00 10 01 (CMN x0, #4, common variant)
     * If followed by B.HI/B.CS → wrapper pattern.
     * Be conservative: check for a common NEG/MOV + RET within 2 insns.
     */
    if (site_offset + 12 <= segment_size) {
        uint32_t insn2 = (uint32_t) segment_bytes[site_offset + 8] |
                         ((uint32_t) segment_bytes[site_offset + 9] << 8) |
                         ((uint32_t) segment_bytes[site_offset + 10] << 16) |
                         ((uint32_t) segment_bytes[site_offset + 11] << 24);
        /* NEG x0, x0 (CB0003E0) followed by RET: error path wrapper. */
        if (next_insn == 0xCB0003E0u && insn2 == 0xd65f03c0u)
            return KBOX_REWRITE_SITE_WRAPPER;

        /* Second instruction is RET: wrapper (with one intermediate insn). */
        if (insn2 == 0xd65f03c0u)
            return KBOX_REWRITE_SITE_WRAPPER;

        /* CMN x0/w0, #imm followed by conditional branch: error-check
         * wrapper.
         * CMN x0 encoding: 0xB100xxxx where bits [21:10] are imm12.
         * CMN w0 encoding: 0x3100xxxx with the same immediate layout.
         * Then B.cond: 0x54xxxxxx.
         */
        if (((next_insn & 0xFF000000u) == 0xB1000000u ||
             (next_insn & 0xFF000000u) == 0x31000000u) &&
            (insn2 & 0xFF000000u) == 0x54000000u) {
            return KBOX_REWRITE_SITE_WRAPPER;
        }

        if (site_offset + 20 <= segment_size) {
            uint32_t insn3 =
                (uint32_t) segment_bytes[site_offset + 12] |
                ((uint32_t) segment_bytes[site_offset + 13] << 8) |
                ((uint32_t) segment_bytes[site_offset + 14] << 16) |
                ((uint32_t) segment_bytes[site_offset + 15] << 24);
            uint32_t insn4 =
                (uint32_t) segment_bytes[site_offset + 16] |
                ((uint32_t) segment_bytes[site_offset + 17] << 8) |
                ((uint32_t) segment_bytes[site_offset + 18] << 16) |
                ((uint32_t) segment_bytes[site_offset + 19] << 24);

            /* musl __internal_syscall_cancel epilogue:
             *   svc #0
             *   ldr x19, [sp, #imm]
             *   ldp x29, x30, [sp], #imm
             *   autiasp
             *   ret
             */
            if (next_insn == 0xF9400BF3u && insn2 == 0xA8C27BFDu &&
                insn3 == 0xD50323BFu && insn4 == 0xD65F03C0u) {
                return KBOX_REWRITE_SITE_WRAPPER;
            }
        }
    }

    /* Anything else: complex function. */
    return KBOX_REWRITE_SITE_COMPLEX;
}

/* Look up site classification from the origin map.
 */
int kbox_rewrite_origin_map_find_class(
    const struct kbox_rewrite_origin_map *map,
    uint64_t origin_addr,
    enum kbox_rewrite_site_class *out)
{
    struct kbox_rewrite_origin_entry entry;

    if (!map || !out)
        return -1;
    if (!kbox_rewrite_origin_map_find(map, origin_addr, &entry))
        return -1;
    *out = entry.site_class;
    return 0;
}

/* Try the rewrite fast path for a WRAPPER-site process-info syscall.
 *
 * WRAPPER sites can safely return virtualized PID values directly without
 * going through the full dispatch machinery. The result goes directly to
 * the caller and is not consumed internally by signal/thread helpers.
 *
 * Returns 1 if fast-pathed (with result written to *out), 0 if the
 * syscall must go through full dispatch.
 *
 * kbox virtualizes: getpid=1, gettid=1, getppid=0. These must match
 * the values in kbox_dispatch_request() to maintain PID model consistency.
 */
int kbox_rewrite_is_site_fast_eligible(
    const struct kbox_rewrite_origin_map *map,
    uint64_t origin_addr,
    const struct kbox_host_nrs *host_nrs,
    uint64_t nr)
{
    if (!map || !host_nrs)
        return 0;

    /* Only zero-argument process-info syscalls are eligible. */
    if ((int) nr != host_nrs->getpid && (int) nr != host_nrs->getppid &&
        (int) nr != host_nrs->gettid) {
        return 0;
    }

    return rewrite_is_wrapper_site(map, origin_addr);
}

/* Return the virtualized value for a fast-path-eligible process-info syscall.
 * Must match the values produced by kbox_dispatch_request() for the same
 * syscall numbers (getpid=1, gettid=1, getppid=0).
 */
static int64_t rewrite_fast_procinfo_value(const struct kbox_host_nrs *host_nrs,
                                           uint64_t nr)
{
    if ((int) nr == host_nrs->getpid || (int) nr == host_nrs->gettid)
        return 1;
    if ((int) nr == host_nrs->getppid)
        return 0;
    return -ENOSYS; /* Should not be reached; caller checked eligibility. */
}

int kbox_rewrite_init_trampoline_layout(
    enum kbox_rewrite_arch arch,
    const struct kbox_elf_exec_segment *seg,
    struct kbox_rewrite_trampoline_layout *layout)
{
    uint64_t seg_end;

    if (!seg || !layout)
        return -1;

    memset(layout, 0, sizeof(*layout));
    layout->arch = arch;

    switch (arch) {
    case KBOX_REWRITE_ARCH_X86_64:
        if (__builtin_add_overflow(seg->vaddr, seg->mem_size, &seg_end))
            return -1;
        layout->base_addr = align_up_u64_or_zero(seg_end, 16);
        if (layout->base_addr == 0 && seg_end != 0)
            return -1;
        layout->slot_size = X86_64_REWRITE_WRAPPER_SLOT_SIZE;
        return 0;
    case KBOX_REWRITE_ARCH_AARCH64:
        if (__builtin_add_overflow(seg->vaddr, seg->mem_size, &seg_end))
            return -1;
        layout->base_addr = align_up_u64_or_zero(seg_end, 16);
        if (layout->base_addr == 0 && seg_end != 0)
            return -1;
        layout->slot_size = AARCH64_REWRITE_SLOT_SIZE;
        return 0;
    default:
        return -1;
    }
}

int kbox_rewrite_plan_site(const struct kbox_rewrite_site *site,
                           const struct kbox_rewrite_trampoline_layout *layout,
                           size_t slot_index,
                           struct kbox_rewrite_planned_site *planned)
{
    uint64_t trampoline_addr;
    uint64_t slot_offset;

    if (!site || !layout || !planned || site->segment_mem_size == 0)
        return -1;

    memset(planned, 0, sizeof(*planned));
    planned->site = *site;

    if (layout->arch == KBOX_REWRITE_ARCH_X86_64 ||
        layout->arch == KBOX_REWRITE_ARCH_AARCH64) {
        if (layout->slot_size == 0 ||
            __builtin_mul_overflow((uint64_t) slot_index, layout->slot_size,
                                   &slot_offset) ||
            __builtin_add_overflow(layout->base_addr, slot_offset,
                                   &trampoline_addr))
            return -1;
    } else {
        return -1;
    }

    if (kbox_rewrite_encode_patch(site, trampoline_addr, &planned->patch) < 0) {
        /* For aarch64 SVC sites where B offset exceeds ±128MB, mark the
         * patch as deferred (width=0) rather than failing. The runtime
         * install path will allocate a veneer to bridge the gap.
         */
        if (site->width == 4 && site->original[0] == 0x01 &&
            site->original[1] == 0x00 && site->original[2] == 0x00 &&
            site->original[3] == 0xd4) {
            memset(&planned->patch, 0, sizeof(planned->patch));
        } else {
            return -1;
        }
    }
    planned->trampoline_addr = trampoline_addr;
    return 0;
}

static int analyze_segment(const struct kbox_elf_exec_segment *seg,
                           const unsigned char *segment_bytes,
                           void *opaque)
{
    struct analyze_ctx *ctx = opaque;
    struct kbox_rewrite_trampoline_layout layout;
    struct kbox_rewrite_site site;
    struct kbox_rewrite_planned_site planned;
    size_t slot_index = 0;
    ctx->segments++;

    if (ctx->planned_cb &&
        kbox_rewrite_init_trampoline_layout(ctx->arch, seg, &layout) < 0)
        return -1;

    if (ctx->arch == KBOX_REWRITE_ARCH_X86_64) {
        if (seg->file_size < 2)
            return 0;
        /* Walk instruction boundaries using the length decoder.
         * Only match syscall/sysenter at true instruction starts,
         * never inside immediates/displacements of longer encodings.
         */
        for (size_t i = 0; i < seg->file_size;) {
            int insn_len =
                kbox_x86_insn_length(segment_bytes + i, seg->file_size - i);
            if (insn_len <= 0) {
                /* Unknown instruction; skip one byte and resync.
                 * This is safe: we may miss a syscall in truly
                 * unknown code, but we won't corrupt anything.
                 */
                i++;
                continue;
            }

            /* Check 8-byte wrapper pattern: B8 imm32 0F05/0F34 C3.
             * The length decoder returns 5 for the MOV instruction, so we
             * must peek ahead at the next 3 bytes to detect the full
             * 8-byte wrapper sequence (3 instructions: MOV + syscall + RET).
             */
            if (insn_len == 5 &&
                x86_64_is_wrapper_site(segment_bytes, seg->file_size, i)) {
                memset(&site, 0, sizeof(site));
                site.file_offset = seg->file_offset + i;
                site.vaddr = seg->vaddr + i;
                site.segment_vaddr = seg->vaddr;
                site.segment_mem_size = seg->mem_size;
                site.width = X86_64_WRAPPER_SITE_LEN;
                memcpy(site.original, segment_bytes + i, site.width);
                site.site_class = kbox_rewrite_classify_x86_64_site(
                    segment_bytes, seg->file_size, i, X86_64_WRAPPER_SITE_LEN);
                if (ctx->cb && ctx->cb(&site, ctx->opaque) < 0)
                    return -1;
                if (ctx->planned_cb) {
                    if (kbox_rewrite_plan_site(&site, &layout, slot_index,
                                               &planned) < 0)
                        return -1;
                    if (ctx->planned_cb(&planned, ctx->opaque) < 0)
                        return -1;
                    slot_index++;
                }
                ctx->candidates++;
                i += X86_64_WRAPPER_SITE_LEN;
                continue;
            }

            /* Check 2-byte syscall (0F 05) or sysenter (0F 34) at
             * a true instruction boundary. */
            if (insn_len == 2 && segment_bytes[i] == 0x0f &&
                (segment_bytes[i + 1] == 0x05 ||
                 segment_bytes[i + 1] == 0x34)) {
                memset(&site, 0, sizeof(site));
                site.file_offset = seg->file_offset + i;
                site.vaddr = seg->vaddr + i;
                site.segment_vaddr = seg->vaddr;
                site.segment_mem_size = seg->mem_size;
                site.width = 2;
                site.original[0] = segment_bytes[i];
                site.original[1] = segment_bytes[i + 1];
                site.site_class = kbox_rewrite_classify_x86_64_site(
                    segment_bytes, seg->file_size, i, 2);
                if (ctx->cb && ctx->cb(&site, ctx->opaque) < 0)
                    return -1;
                if (ctx->planned_cb) {
                    if (kbox_rewrite_plan_site(&site, &layout, slot_index,
                                               &planned) < 0)
                        return -1;
                    if (ctx->planned_cb(&planned, ctx->opaque) < 0)
                        return -1;
                    slot_index++;
                }
                ctx->candidates++;
            }

            i += (size_t) insn_len;
        }
        return 0;
    }

    if (ctx->arch == KBOX_REWRITE_ARCH_AARCH64) {
        for (size_t i = 0; i + 3 < seg->file_size; i += 4) {
            if (segment_bytes[i] != 0x01 || segment_bytes[i + 1] != 0x00 ||
                segment_bytes[i + 2] != 0x00 || segment_bytes[i + 3] != 0xd4)
                continue;
            memset(&site, 0, sizeof(site));
            site.file_offset = seg->file_offset + i;
            site.vaddr = seg->vaddr + i;
            site.segment_vaddr = seg->vaddr;
            site.segment_mem_size = seg->mem_size;
            site.width = 4;
            memcpy(site.original, segment_bytes + i, 4);
            site.site_class = kbox_rewrite_classify_aarch64_site(
                segment_bytes, seg->file_size, i);
            if (ctx->cb && ctx->cb(&site, ctx->opaque) < 0)
                return -1;
            if (ctx->planned_cb) {
                if (kbox_rewrite_plan_site(&site, &layout, slot_index,
                                           &planned) < 0)
                    return -1;
                if (ctx->planned_cb(&planned, ctx->opaque) < 0)
                    return -1;
                slot_index++;
            }
            ctx->candidates++;
        }
        return 0;
    }

    return -1;
}

const char *kbox_syscall_mode_name(enum kbox_syscall_mode mode)
{
    switch (mode) {
    case KBOX_SYSCALL_MODE_SECCOMP:
        return "seccomp";
    case KBOX_SYSCALL_MODE_TRAP:
        return "trap";
    case KBOX_SYSCALL_MODE_REWRITE:
        return "rewrite";
    case KBOX_SYSCALL_MODE_AUTO:
        return "auto";
    }
    return "unknown";
}

int kbox_parse_syscall_mode(const char *value, enum kbox_syscall_mode *out)
{
    if (!value || !out)
        return -1;

    if (strcmp(value, "seccomp") == 0)
        *out = KBOX_SYSCALL_MODE_SECCOMP;
    else if (strcmp(value, "trap") == 0)
        *out = KBOX_SYSCALL_MODE_TRAP;
    else if (strcmp(value, "rewrite") == 0)
        *out = KBOX_SYSCALL_MODE_REWRITE;
    else if (strcmp(value, "auto") == 0)
        *out = KBOX_SYSCALL_MODE_AUTO;
    else
        return -1;

    return 0;
}

const char *kbox_rewrite_arch_name(enum kbox_rewrite_arch arch)
{
    switch (arch) {
    case KBOX_REWRITE_ARCH_X86_64:
        return "x86_64";
    case KBOX_REWRITE_ARCH_AARCH64:
        return "aarch64";
    default:
        return "unknown";
    }
}

static void write_le32(unsigned char out[4], uint32_t value)
{
    out[0] = (unsigned char) (value & 0xff);
    out[1] = (unsigned char) ((value >> 8) & 0xff);
    out[2] = (unsigned char) ((value >> 16) & 0xff);
    out[3] = (unsigned char) ((value >> 24) & 0xff);
}

static void write_le64(unsigned char out[8], uint64_t value)
{
    for (int i = 0; i < 8; i++)
        out[i] = (unsigned char) ((value >> (i * 8)) & 0xff);
}

int kbox_rewrite_encode_patch(const struct kbox_rewrite_site *site,
                              uint64_t trampoline_addr,
                              struct kbox_rewrite_patch *patch)
{
    if (!site || !patch)
        return -1;

    memset(patch, 0, sizeof(*patch));

    if (site->width == 2 && site->original[0] == 0x0f &&
        (site->original[1] == 0x05 || site->original[1] == 0x34)) {
        patch->width = 2;
        patch->bytes[0] = 0xff;
        patch->bytes[1] = 0xd0;
        return 0;
    }

    if (site->width == X86_64_WRAPPER_SITE_LEN && site->original[0] == 0xb8 &&
        site->original[5] == 0x0f &&
        (site->original[6] == 0x05 || site->original[6] == 0x34) &&
        site->original[7] == 0xc3) {
        int64_t rel32 = (int64_t) trampoline_addr -
                        (int64_t) (site->vaddr + X86_64_JMP_REL32_OPCODE_LEN);

        if (rel32 < INT32_MIN || rel32 > INT32_MAX)
            return -1;
        patch->width = X86_64_WRAPPER_SITE_LEN;
        patch->bytes[0] = 0xe9;
        write_le32(&patch->bytes[1], (uint32_t) (int32_t) rel32);
        patch->bytes[5] = 0x90;
        patch->bytes[6] = 0x90;
        patch->bytes[7] = 0x90;
        return 0;
    }

    if (site->width == 4) {
        int64_t delta;
        int64_t imm26;
        uint32_t insn;

        if ((site->vaddr & 3u) != 0 || (trampoline_addr & 3u) != 0)
            return -1;
        delta = (int64_t) trampoline_addr - (int64_t) site->vaddr;
        if (delta <= -AARCH64_B_RANGE || delta >= AARCH64_B_RANGE)
            return -1;
        if ((delta & 3) != 0)
            return -1;
        imm26 = delta >> 2;
        if (imm26 < -(1 << 25) || imm26 > ((1 << 25) - 1))
            return -1;
        insn = AARCH64_B_OPCODE | ((uint32_t) imm26 & AARCH64_B_IMM26_MASK);
        patch->width = 4;
        write_le32(patch->bytes, insn);
        return 0;
    }

    return -1;
}

int kbox_rewrite_encode_x86_64_page_zero_trampoline(unsigned char *buf,
                                                    size_t buf_len,
                                                    uint64_t entry_addr)
{
    size_t tail_off;

    if (!buf || buf_len <= X86_64_PAGE_ZERO_TAIL_LEN)
        return -1;

    memset(buf, 0x90, buf_len);
    tail_off = buf_len - X86_64_PAGE_ZERO_TAIL_LEN;
    buf[tail_off + 0] = 0x49;
    buf[tail_off + 1] = 0xbb;
    write_le64(buf + tail_off + 2, entry_addr);
    buf[tail_off + 10] = 0x41;
    buf[tail_off + 11] = 0xff;
    buf[tail_off + 12] = 0xe3;
    return 0;
}

int kbox_rewrite_probe_x86_64_page_zero(
    uint64_t mmap_min_addr,
    struct kbox_rewrite_trampoline_probe *probe)
{
    if (!probe)
        return -1;

    memset(probe, 0, sizeof(*probe));
    probe->arch = KBOX_REWRITE_ARCH_X86_64;
    probe->trampoline_addr = 0;
    if (mmap_min_addr == 0) {
        probe->feasible = 1;
        probe->reason = "page-zero trampoline available";
    } else {
        probe->feasible = 0;
        probe->reason = "vm.mmap_min_addr must be 0 for x86_64 rewrite";
    }
    return 0;
}

static int write_x86_64_wrapper_trampoline(uint64_t trampoline_addr,
                                           uint64_t origin_addr,
                                           uint32_t nr)
{
#if defined(__x86_64__)
    unsigned char slot[X86_64_REWRITE_WRAPPER_SLOT_SIZE];

    memset(slot, 0x90, sizeof(slot));
    slot[0] = 0xb8;
    write_le32(&slot[1], nr);
    slot[5] = 0x49;
    slot[6] = 0xbb;
    write_le64(&slot[7], origin_addr);
    slot[15] = 0x49;
    slot[16] = 0xba;
    write_le64(
        &slot[17],
        (uint64_t) (uintptr_t) kbox_syscall_rewrite_x86_64_wrapper_entry);
    slot[25] = 0x41;
    slot[26] = 0xff;
    slot[27] = 0xe2;
    memcpy((void *) (uintptr_t) trampoline_addr, slot, sizeof(slot));
    return 0;
#else
    (void) trampoline_addr;
    (void) origin_addr;
    (void) nr;
    return -1;
#endif
}

int kbox_rewrite_probe_trampoline(enum kbox_rewrite_arch arch,
                                  struct kbox_rewrite_trampoline_probe *probe)
{
    if (!probe)
        return -1;

    memset(probe, 0, sizeof(*probe));
    probe->arch = arch;

    switch (arch) {
    case KBOX_REWRITE_ARCH_X86_64:
        probe->feasible = 1;
        probe->reason = "x86_64 uses wrapper trampolines on stock kernels";
        probe->trampoline_addr = 0;
        return 0;
    case KBOX_REWRITE_ARCH_AARCH64:
        probe->feasible = 1;
        probe->reason = "aarch64 uses relative branch trampolines";
        probe->trampoline_addr = 0;
        return 0;
    default:
        probe->reason = "unsupported rewrite architecture";
        return -1;
    }
}
int kbox_rewrite_analyze_elf(const unsigned char *buf,
                             size_t buf_len,
                             struct kbox_rewrite_report *report)
{
    return kbox_rewrite_visit_elf_sites(buf, buf_len, NULL, NULL, report);
}

int kbox_rewrite_visit_elf_planned_sites(const unsigned char *buf,
                                         size_t buf_len,
                                         kbox_rewrite_planned_site_cb cb,
                                         void *opaque,
                                         struct kbox_rewrite_report *report)
{
    uint16_t machine = 0;
    struct analyze_ctx ctx;
    int rc;

    if (!buf || !report)
        return -1;

    memset(report, 0, sizeof(*report));

    if (kbox_elf_machine(buf, buf_len, &machine) < 0)
        return -1;

    memset(&ctx, 0, sizeof(ctx));
    ctx.cb = NULL;
    ctx.planned_cb = cb;
    ctx.opaque = opaque;
    if (machine == EM_X86_64)
        ctx.arch = KBOX_REWRITE_ARCH_X86_64;
    else if (machine == EM_AARCH64)
        ctx.arch = KBOX_REWRITE_ARCH_AARCH64;
    else
        return -1;

    rc = kbox_visit_elf_exec_segments(buf, buf_len, analyze_segment, &ctx);
    if (rc < 0)
        return -1;

    report->arch = ctx.arch;
    report->exec_segment_count = ctx.segments;
    report->candidate_count = ctx.candidates;
    return 0;
}

struct site_cb_adapter_ctx {
    kbox_rewrite_site_cb cb;
    void *opaque;
};

struct planned_site_array {
    struct kbox_rewrite_planned_site *sites;
    size_t count;
    size_t cap;
};

struct site_array {
    struct kbox_rewrite_site *sites;
    size_t count;
    size_t cap;
};

static int site_cb_adapter(const struct kbox_rewrite_planned_site *planned,
                           void *opaque)
{
    struct site_cb_adapter_ctx *ctx = opaque;

    return ctx->cb(&planned->site, ctx->opaque);
}

static int collect_planned_sites_array_cb(
    const struct kbox_rewrite_planned_site *planned,
    void *opaque)
{
    struct planned_site_array *array = opaque;
    struct kbox_rewrite_planned_site *sites;

    if (!array || !planned)
        return -1;
    if (array->count == array->cap) {
        size_t alloc_size;
        size_t new_cap = array->cap ? array->cap * 2 : 8;
        if (new_cap < array->cap ||
            __builtin_mul_overflow(new_cap, sizeof(*sites), &alloc_size))
            return -1;
        sites = realloc(array->sites, alloc_size);
        if (!sites)
            return -1;
        array->sites = sites;
        array->cap = new_cap;
    }
    array->sites[array->count++] = *planned;
    return 0;
}

static void free_site_array(struct site_array *array)
{
    if (!array)
        return;
    free(array->sites);
    array->sites = NULL;
    array->count = 0;
    array->cap = 0;
}

static int collect_sites_array_cb(const struct kbox_rewrite_site *site,
                                  void *opaque)
{
    struct site_array *array = opaque;
    struct kbox_rewrite_site *new_sites;

    if (!array || !site)
        return -1;
    if (array->count == array->cap) {
        size_t alloc_size;
        size_t new_cap = array->cap ? array->cap * 2 : 16;
        if (new_cap < array->cap ||
            __builtin_mul_overflow(new_cap, sizeof(*new_sites), &alloc_size))
            return -1;
        new_sites = realloc(array->sites, alloc_size);
        if (!new_sites)
            return -1;
        array->sites = new_sites;
        array->cap = new_cap;
    }

    array->sites[array->count++] = *site;
    return 0;
}

static void free_planned_site_array(struct planned_site_array *array)
{
    if (!array)
        return;
    free(array->sites);
    array->sites = NULL;
    array->count = 0;
    array->cap = 0;
}

int kbox_rewrite_visit_elf_sites(const unsigned char *buf,
                                 size_t buf_len,
                                 kbox_rewrite_site_cb cb,
                                 void *opaque,
                                 struct kbox_rewrite_report *report)
{
    struct site_cb_adapter_ctx adapter;

    if (!cb)
        return kbox_rewrite_visit_elf_planned_sites(buf, buf_len, NULL, NULL,
                                                    report);

    adapter.cb = cb;
    adapter.opaque = opaque;
    return kbox_rewrite_visit_elf_planned_sites(buf, buf_len, site_cb_adapter,
                                                &adapter, report);
}

/* Maximum bytes to read for rewrite analysis.  The analysis needs the ELF
 * header, program header table, and all PT_LOAD|PF_X segment contents.
 * 16 MB covers any realistic executable/interpreter without risking OOM on
 * multi-gigabyte guest binaries.  Binaries larger than this cap are rejected
 * gracefully (returns -1 with EFBIG).
 */
#define REWRITE_ANALYZE_MAX (16u * 1024 * 1024)
#define REWRITE_PHDR_MAX (256u * 1024)

static ssize_t pwrite_full(int fd,
                           const unsigned char *buf,
                           size_t size,
                           off_t off)
{
    size_t total = 0;

    while (total < size) {
        ssize_t nr = pwrite(fd, buf + total, size - total, off + (off_t) total);

        if (nr < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (nr == 0)
            break;
        total += (size_t) nr;
    }

    return (ssize_t) total;
}

struct memfd_visit_ctx {
    int fd;
    struct analyze_ctx *analyze;
    uint64_t total_bytes;
};

struct memfd_exec_segment_visit_ctx {
    int fd;
    uint64_t total_bytes;
    int (*cb)(const struct kbox_elf_exec_segment *seg,
              const unsigned char *segment_bytes,
              void *opaque);
    void *opaque;
};

static int read_segment_from_memfd(const struct kbox_elf_exec_segment *seg,
                                   void *opaque)
{
    struct memfd_visit_ctx *ctx = opaque;
    unsigned char *buf;
    ssize_t nr;
    int rc;

    if (seg->file_size == 0)
        return 0;
    if (__builtin_add_overflow(ctx->total_bytes, seg->file_size,
                               &ctx->total_bytes))
        return -1;
    if (ctx->total_bytes > REWRITE_ANALYZE_MAX) {
        errno = EFBIG;
        return -1;
    }

    buf = malloc((size_t) seg->file_size);
    if (!buf)
        return -1;

    nr = pread_full(ctx->fd, buf, (size_t) seg->file_size,
                    (off_t) seg->file_offset);
    if (nr < 0 || (uint64_t) nr != seg->file_size) {
        free(buf);
        if (nr >= 0)
            errno = EIO;
        return -1;
    }

    rc = analyze_segment(seg, buf, ctx->analyze);
    free(buf);
    return rc;
}

static int read_segment_from_memfd_cb(const struct kbox_elf_exec_segment *seg,
                                      void *opaque)
{
    struct memfd_exec_segment_visit_ctx *ctx = opaque;
    unsigned char *buf;
    ssize_t nr;
    int rc;

    if (seg->file_size == 0)
        return 0;
    if (__builtin_add_overflow(ctx->total_bytes, seg->file_size,
                               &ctx->total_bytes)) {
        return -1;
    }
    if (ctx->total_bytes > REWRITE_ANALYZE_MAX) {
        errno = EFBIG;
        return -1;
    }

    buf = malloc((size_t) seg->file_size);
    if (!buf)
        return -1;

    nr = pread_full(ctx->fd, buf, (size_t) seg->file_size,
                    (off_t) seg->file_offset);
    if (nr < 0 || (uint64_t) nr != seg->file_size) {
        free(buf);
        if (nr >= 0)
            errno = EIO;
        return -1;
    }

    rc = ctx->cb(seg, buf, ctx->opaque);
    free(buf);
    return rc;
}

static int visit_memfd_exec_segments(
    int fd,
    int (*cb)(const struct kbox_elf_exec_segment *seg,
              const unsigned char *segment_bytes,
              void *opaque),
    void *opaque)
{
    off_t end;
    unsigned char elf_hdr[64];
    unsigned char *buf;
    uint64_t phoff;
    uint16_t phentsize;
    uint16_t phnum;
    uint64_t ph_end;
    ssize_t nr;
    size_t size;
    int rc;
    struct memfd_exec_segment_visit_ctx visit;

    if (fd < 0 || !cb)
        return -1;

    end = lseek(fd, 0, SEEK_END);
    if (end <= 0)
        return -1;

    nr = pread_full(fd, elf_hdr, sizeof(elf_hdr), 0);
    if (nr < (ssize_t) sizeof(elf_hdr)) {
        if (nr >= 0)
            errno = EIO;
        return -1;
    }

    phoff = ((uint64_t) elf_hdr[32]) | ((uint64_t) elf_hdr[33] << 8) |
            ((uint64_t) elf_hdr[34] << 16) | ((uint64_t) elf_hdr[35] << 24) |
            ((uint64_t) elf_hdr[36] << 32) | ((uint64_t) elf_hdr[37] << 40) |
            ((uint64_t) elf_hdr[38] << 48) | ((uint64_t) elf_hdr[39] << 56);
    phentsize = (uint16_t) (elf_hdr[54] | ((uint16_t) elf_hdr[55] << 8));
    phnum = (uint16_t) (elf_hdr[56] | ((uint16_t) elf_hdr[57] << 8));
    if (__builtin_add_overflow(phoff, (uint64_t) phentsize * phnum, &ph_end))
        return -1;
    if (ph_end > (uint64_t) end || ph_end > REWRITE_PHDR_MAX) {
        errno = EFBIG;
        return -1;
    }

    size = (size_t) ph_end;
    buf = malloc(size);
    if (!buf)
        return -1;

    nr = pread_full(fd, buf, size, 0);
    if (nr < 0 || (size_t) nr != size) {
        free(buf);
        if (nr >= 0)
            errno = EIO;
        return -1;
    }

    memset(&visit, 0, sizeof(visit));
    visit.fd = fd;
    visit.cb = cb;
    visit.opaque = opaque;
    rc = kbox_visit_elf_exec_segment_headers(
        buf, size, read_segment_from_memfd_cb, &visit);
    free(buf);
    return rc;
}

int kbox_rewrite_analyze_memfd(int fd, struct kbox_rewrite_report *report)
{
    return kbox_rewrite_visit_memfd_sites(fd, NULL, NULL, report);
}

int kbox_rewrite_visit_memfd_sites(int fd,
                                   kbox_rewrite_site_cb cb,
                                   void *opaque,
                                   struct kbox_rewrite_report *report)
{
    struct site_cb_adapter_ctx adapter;

    if (!cb)
        return kbox_rewrite_visit_memfd_planned_sites(fd, NULL, NULL, report);

    adapter.cb = cb;
    adapter.opaque = opaque;
    return kbox_rewrite_visit_memfd_planned_sites(fd, site_cb_adapter, &adapter,
                                                  report);
}

int kbox_rewrite_visit_memfd_planned_sites(int fd,
                                           kbox_rewrite_planned_site_cb cb,
                                           void *opaque,
                                           struct kbox_rewrite_report *report)
{
    off_t end;
    unsigned char elf_hdr[64];
    unsigned char *buf;
    uint64_t phoff;
    uint16_t phentsize;
    uint16_t phnum;
    uint64_t ph_end;
    ssize_t nr;
    size_t size;
    int rc;
    uint16_t machine = 0;
    struct analyze_ctx analyze;
    struct memfd_visit_ctx visit;

    if (fd < 0 || !report)
        return -1;

    end = lseek(fd, 0, SEEK_END);
    if (end <= 0)
        return -1;

    nr = pread_full(fd, elf_hdr, sizeof(elf_hdr), 0);
    if (nr < (ssize_t) sizeof(elf_hdr)) {
        if (nr >= 0)
            errno = EIO;
        return -1;
    }

    if (kbox_elf_machine(elf_hdr, sizeof(elf_hdr), &machine) < 0)
        return -1;

    phoff = ((uint64_t) elf_hdr[32]) | ((uint64_t) elf_hdr[33] << 8) |
            ((uint64_t) elf_hdr[34] << 16) | ((uint64_t) elf_hdr[35] << 24) |
            ((uint64_t) elf_hdr[36] << 32) | ((uint64_t) elf_hdr[37] << 40) |
            ((uint64_t) elf_hdr[38] << 48) | ((uint64_t) elf_hdr[39] << 56);
    phentsize = (uint16_t) (elf_hdr[54] | ((uint16_t) elf_hdr[55] << 8));
    phnum = (uint16_t) (elf_hdr[56] | ((uint16_t) elf_hdr[57] << 8));
    if (__builtin_add_overflow(phoff, (uint64_t) phentsize * phnum, &ph_end))
        return -1;
    if (ph_end > (uint64_t) end || ph_end > REWRITE_PHDR_MAX) {
        errno = EFBIG;
        return -1;
    }

    size = (size_t) ph_end;
    buf = malloc(size);
    if (!buf)
        return -1;

    nr = pread_full(fd, buf, size, 0);
    if (nr < 0 || (size_t) nr != size) {
        free(buf);
        if (nr >= 0)
            errno = EIO;
        return -1;
    }

    memset(&analyze, 0, sizeof(analyze));
    analyze.cb = NULL;
    analyze.planned_cb = cb;
    analyze.opaque = opaque;
    if (machine == EM_X86_64)
        analyze.arch = KBOX_REWRITE_ARCH_X86_64;
    else if (machine == EM_AARCH64)
        analyze.arch = KBOX_REWRITE_ARCH_AARCH64;
    else {
        free(buf);
        return -1;
    }

    memset(&visit, 0, sizeof(visit));
    visit.fd = fd;
    visit.analyze = &analyze;
    rc = kbox_visit_elf_exec_segment_headers(buf, size, read_segment_from_memfd,
                                             &visit);
    free(buf);

    if (rc < 0)
        return -1;

    memset(report, 0, sizeof(*report));
    report->arch = analyze.arch;
    report->exec_segment_count = analyze.segments;
    report->candidate_count = analyze.candidates;
    return 0;
}

int kbox_rewrite_apply_elf(unsigned char *buf,
                           size_t buf_len,
                           size_t *applied_count,
                           struct kbox_rewrite_report *report)
{
    struct planned_site_array array;
    struct kbox_rewrite_report local_report;
    size_t applied = 0;
    int rc;

    if (!buf)
        return -1;

    memset(&array, 0, sizeof(array));
    rc = kbox_rewrite_visit_elf_planned_sites(
        buf, buf_len, collect_planned_sites_array_cb, &array,
        report ? report : &local_report);
    if (rc < 0) {
        free_planned_site_array(&array);
        return -1;
    }

    for (size_t i = 0; i < array.count; i++) {
        const struct kbox_rewrite_planned_site *planned = &array.sites[i];
        size_t off = (size_t) planned->site.file_offset;
        size_t width = planned->patch.width;

        if (width == 0 || off > buf_len || width > buf_len - off) {
            free_planned_site_array(&array);
            return -1;
        }
        if (memcmp(buf + off, planned->site.original, width) != 0) {
            free_planned_site_array(&array);
            errno = EIO;
            return -1;
        }
        memcpy(buf + off, planned->patch.bytes, width);
        applied++;
    }

    free_planned_site_array(&array);
    if (applied_count)
        *applied_count = applied;
    return 0;
}

int kbox_rewrite_apply_memfd(int fd,
                             size_t *applied_count,
                             struct kbox_rewrite_report *report)
{
    struct planned_site_array array;
    struct kbox_rewrite_report local_report;
    size_t applied = 0;
    int rc;

    if (fd < 0)
        return -1;

    memset(&array, 0, sizeof(array));
    rc = kbox_rewrite_visit_memfd_planned_sites(
        fd, collect_planned_sites_array_cb, &array,
        report ? report : &local_report);
    if (rc < 0) {
        free_planned_site_array(&array);
        return -1;
    }

    for (size_t i = 0; i < array.count; i++) {
        const struct kbox_rewrite_planned_site *planned = &array.sites[i];
        unsigned char current[KBOX_REWRITE_MAX_PATCH_BYTES];
        size_t width = planned->patch.width;
        off_t off = (off_t) planned->site.file_offset;
        ssize_t nr;

        if (width == 0 || width > sizeof(current)) {
            free_planned_site_array(&array);
            return -1;
        }
        nr = pread_full(fd, current, width, off);
        if (nr < 0 || (size_t) nr != width) {
            free_planned_site_array(&array);
            if (nr >= 0)
                errno = EIO;
            return -1;
        }
        if (memcmp(current, planned->site.original, width) != 0) {
            free_planned_site_array(&array);
            errno = EIO;
            return -1;
        }
        nr = pwrite_full(fd, planned->patch.bytes, width, off);
        if (nr < 0 || (size_t) nr != width) {
            free_planned_site_array(&array);
            if (nr >= 0)
                errno = EIO;
            return -1;
        }
        applied++;
    }

    free_planned_site_array(&array);
    if (applied_count)
        *applied_count = applied;
    return 0;
}

int kbox_rewrite_apply_virtual_procinfo_elf(unsigned char *buf,
                                            size_t buf_len,
                                            size_t *applied_count,
                                            struct kbox_rewrite_report *report)
{
    struct site_array array;
    struct kbox_rewrite_report local_report;
    size_t applied = 0;
    int rc;

    if (!buf)
        return -1;

    memset(&array, 0, sizeof(array));
    rc = kbox_rewrite_visit_elf_sites(buf, buf_len, collect_sites_array_cb,
                                      &array, report ? report : &local_report);
    if (rc < 0) {
        free_site_array(&array);
        return -1;
    }

    for (size_t i = 0; i < array.count; i++) {
        const struct kbox_rewrite_site *site = &array.sites[i];
        struct kbox_rewrite_patch patch;
        size_t off = (size_t) site->file_offset;
        size_t width;

        if (encode_virtual_procinfo_patch(
                site, buf, buf_len, report ? report->arch : local_report.arch,
                &patch) < 0)
            continue;

        width = patch.width;
        if (width == 0 || off > buf_len || width > buf_len - off) {
            free_site_array(&array);
            return -1;
        }
        if (memcmp(buf + off, site->original, width) != 0) {
            free_site_array(&array);
            errno = EIO;
            return -1;
        }
        memcpy(buf + off, patch.bytes, width);
        applied++;
    }

    free_site_array(&array);
    if (applied_count)
        *applied_count = applied;
    return 0;
}

int kbox_rewrite_apply_virtual_procinfo_memfd(
    int fd,
    size_t *applied_count,
    struct kbox_rewrite_report *report)
{
    struct site_array array;
    struct kbox_rewrite_report local_report;
    enum kbox_rewrite_arch arch;
    unsigned char *image = NULL;
    size_t image_len = 0;
    size_t applied = 0;
    int rc;

    if (fd < 0)
        return -1;

    memset(&array, 0, sizeof(array));
    rc = kbox_rewrite_visit_memfd_sites(fd, collect_sites_array_cb, &array,
                                        report ? report : &local_report);
    if (rc < 0) {
        free_site_array(&array);
        return -1;
    }

    arch = report ? report->arch : local_report.arch;
    if (arch == KBOX_REWRITE_ARCH_AARCH64) {
        if (rewrite_read_fd_all(fd, &image, &image_len) < 0) {
            free_site_array(&array);
            return -1;
        }
    }

    for (size_t i = 0; i < array.count; i++) {
        const struct kbox_rewrite_site *site = &array.sites[i];
        struct kbox_rewrite_patch patch;
        unsigned char current[KBOX_REWRITE_MAX_PATCH_BYTES];
        size_t width;
        off_t off = (off_t) site->file_offset;
        ssize_t nr;

        if (site->file_offset > (uint64_t) SIZE_MAX) {
            if (image)
                munmap(image, image_len);
            free_site_array(&array);
            errno = EOVERFLOW;
            return -1;
        }

        if (encode_virtual_procinfo_patch(site, image, image_len, arch,
                                          &patch) < 0) {
            continue;
        }

        width = patch.width;
        nr = pread_full(fd, current, width, off);
        if (nr < 0 || (size_t) nr != width) {
            if (image)
                munmap(image, image_len);
            free_site_array(&array);
            if (nr >= 0)
                errno = EIO;
            return -1;
        }
        if (memcmp(current, site->original, width) != 0) {
            if (image)
                munmap(image, image_len);
            free_site_array(&array);
            errno = EIO;
            return -1;
        }
        nr = pwrite_full(fd, patch.bytes, width, off);
        if (nr < 0 || (size_t) nr != width) {
            if (image)
                munmap(image, image_len);
            free_site_array(&array);
            if (nr >= 0)
                errno = EIO;
            return -1;
        }
        applied++;
    }

    if (image)
        munmap(image, image_len);
    free_site_array(&array);
    if (applied_count)
        *applied_count = applied;
    return 0;
}

void kbox_rewrite_origin_map_init(struct kbox_rewrite_origin_map *map,
                                  enum kbox_rewrite_arch arch)
{
    if (!map)
        return;
    memset(map, 0, sizeof(*map));
    map->arch = arch;
}

void kbox_rewrite_origin_map_reset(struct kbox_rewrite_origin_map *map)
{
    if (!map)
        return;
    if (map->entries) {
        if (map->sealed && map->mapping_size > 0)
            munmap(map->entries, map->mapping_size);
        else
            free(map->entries);
    }
    map->entries = NULL;
    map->count = 0;
    map->cap = 0;
    map->mapping_size = 0;
    map->sealed = 0;
}

int kbox_rewrite_origin_map_add_site_source(
    struct kbox_rewrite_origin_map *map,
    const struct kbox_rewrite_site *site,
    enum kbox_loader_mapping_source source)
{
    uint64_t origin;
    size_t lo, hi;
    struct kbox_rewrite_origin_entry *entries;

    if (!map || !site)
        return -1;
    if (origin_map_is_sealed(map)) {
        errno = EPERM;
        return -1;
    }
    if (rewrite_origin_addr(site, &origin) < 0) {
        if (errno == 0)
            errno = EINVAL;
        return -1;
    }

    lo = 0;
    hi = map->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (map->entries[mid].origin < origin)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo < map->count && map->entries[lo].origin == origin)
        return 0;

    if (map->count == map->cap) {
        size_t alloc_size;
        size_t new_cap = map->cap ? map->cap * 2 : 8;
        if (new_cap < map->cap ||
            __builtin_mul_overflow(new_cap, sizeof(*entries), &alloc_size))
            return -1;
        entries = realloc(map->entries, alloc_size);
        if (!entries)
            return -1;
        map->entries = entries;
        map->cap = new_cap;
    }

    if (lo < map->count) {
        memmove(&map->entries[lo + 1], &map->entries[lo],
                (map->count - lo) * sizeof(*map->entries));
    }
    map->entries[lo].origin = origin;
    map->entries[lo].source = source;
    map->entries[lo].site_class = KBOX_REWRITE_SITE_UNKNOWN;
    map->count++;
    return 0;
}

int kbox_rewrite_origin_map_add_classified(
    struct kbox_rewrite_origin_map *map,
    const struct kbox_rewrite_site *site,
    enum kbox_loader_mapping_source source,
    enum kbox_rewrite_site_class site_class)
{
    int rc = kbox_rewrite_origin_map_add_site_source(map, site, source);
    if (rc == 0 && site_class != KBOX_REWRITE_SITE_UNKNOWN) {
        /* The entry was just inserted or already existed. Find it and
         * update the classification (add_site_source returns 0 for both).
         */
        uint64_t origin;
        if (rewrite_origin_addr(site, &origin) == 0) {
            size_t lo = 0, hi = map->count;
            while (lo < hi) {
                size_t mid = lo + (hi - lo) / 2;
                if (map->entries[mid].origin < origin)
                    lo = mid + 1;
                else
                    hi = mid;
            }
            if (lo < map->count && map->entries[lo].origin == origin) {
                struct kbox_rewrite_origin_entry *entry = &map->entries[lo];
                entry->site_class = site_class;
            }
        }
    }
    return rc;
}

int kbox_rewrite_origin_map_find(const struct kbox_rewrite_origin_map *map,
                                 uint64_t origin_addr,
                                 struct kbox_rewrite_origin_entry *out)
{
    size_t lo = 0;
    size_t hi;

    if (!map || !map->entries)
        return 0;

    hi = map->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        uint64_t value = map->entries[mid].origin;

        if (value == origin_addr) {
            if (out)
                *out = map->entries[mid];
            return 1;
        }
        if (value < origin_addr)
            lo = mid + 1;
        else
            hi = mid;
    }
    return 0;
}

int kbox_rewrite_origin_map_contains(const struct kbox_rewrite_origin_map *map,
                                     uint64_t origin_addr)
{
    return kbox_rewrite_origin_map_find(map, origin_addr, NULL);
}

static int origin_map_collect_site_cb(const struct kbox_rewrite_site *site,
                                      void *opaque)
{
    return kbox_rewrite_origin_map_add_site(opaque, site);
}

int kbox_rewrite_origin_map_build_elf(struct kbox_rewrite_origin_map *map,
                                      const unsigned char *buf,
                                      size_t buf_len,
                                      struct kbox_rewrite_report *report)
{
    struct kbox_rewrite_report local_report;

    if (!map || !buf)
        return -1;

    kbox_rewrite_origin_map_reset(map);
    return kbox_rewrite_visit_elf_sites(buf, buf_len,
                                        origin_map_collect_site_cb, map,
                                        report ? report : &local_report);
}

int kbox_rewrite_origin_map_build_memfd(struct kbox_rewrite_origin_map *map,
                                        int fd,
                                        struct kbox_rewrite_report *report)
{
    struct kbox_rewrite_report local_report;

    if (!map || fd < 0)
        return -1;

    kbox_rewrite_origin_map_reset(map);
    return kbox_rewrite_visit_memfd_sites(fd, origin_map_collect_site_cb, map,
                                          report ? report : &local_report);
}

int kbox_rewrite_origin_map_seal(struct kbox_rewrite_origin_map *map)
{
    long page_size_long;
    size_t page_size;
    uint64_t bytes_u64;
    uint64_t alloc_u64;
    size_t alloc_size;
    void *sealed_map;
    struct kbox_rewrite_origin_entry *sealed_entries;

    if (!map)
        return -1;
    if (map->sealed)
        return 0;
    if (!map->entries || map->count == 0) {
        map->sealed = 1;
        return 0;
    }

    page_size_long = sysconf(_SC_PAGESIZE);
    if (page_size_long <= 0) {
        if (page_size_long == -1 && errno == 0)
            errno = EINVAL;
        return -1;
    }
    page_size = (size_t) page_size_long;
    if (page_size == 0 || (page_size & (page_size - 1)) != 0)
        return -1;
    if (__builtin_mul_overflow((uint64_t) map->count,
                               (uint64_t) sizeof(*map->entries), &bytes_u64)) {
        errno = EOVERFLOW;
        return -1;
    }
    alloc_u64 = align_up_u64_or_zero(bytes_u64, (uint64_t) page_size);
    if (alloc_u64 == 0 || alloc_u64 > (uint64_t) SIZE_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    alloc_size = (size_t) alloc_u64;

    sealed_map = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (sealed_map == MAP_FAILED)
        return -1;
    sealed_entries = sealed_map;

    // cppcheck-suppress nullPointerOutOfMemory
    memcpy(sealed_entries, map->entries, (size_t) bytes_u64);
    if (mprotect(sealed_entries, alloc_size, PROT_READ) != 0) {
        int saved = errno;
        munmap(sealed_entries, alloc_size);
        errno = saved;
        return -1;
    }

    free(map->entries);
    map->entries = sealed_entries;
    map->cap = map->count;
    map->mapping_size = alloc_size;
    map->sealed = 1;
    return 0;
}

static int runtime_site_array_append(struct runtime_site_array *array,
                                     const struct runtime_planned_site *site)
{
    struct runtime_planned_site *sites;

    if (!array || !site)
        return -1;
    if (array->count == array->cap) {
        size_t alloc_size;
        size_t new_cap = array->cap ? array->cap * 2 : 8;
        if (new_cap < array->cap ||
            __builtin_mul_overflow(new_cap, sizeof(*sites), &alloc_size))
            return -1;
        sites = realloc(array->sites, alloc_size);
        if (!sites)
            return -1;
        array->sites = sites;
        array->cap = new_cap;
    }
    array->sites[array->count++] = *site;
    return 0;
}

static void runtime_site_array_reset(struct runtime_site_array *array)
{
    if (!array)
        return;
    free(array->sites);
    array->sites = NULL;
    array->count = 0;
    array->cap = 0;
}

static int runtime_collect_planned_cb(
    const struct kbox_rewrite_planned_site *planned,
    void *opaque)
{
    struct runtime_collect_ctx *ctx = opaque;
    struct runtime_planned_site site;

    if (!ctx || !ctx->array || !planned)
        return -1;

    memset(&site, 0, sizeof(site));
    site.planned = *planned;
    site.actual_site_addr = ctx->load_bias + planned->site.vaddr;
    site.actual_trampoline_addr = ctx->load_bias + planned->trampoline_addr;
    site.source = ctx->source;
    site.wrapper_kind = KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT;
    site.wrapper_nr = UINT64_MAX;
    return runtime_site_array_append(ctx->array, &site);
}

static const struct kbox_loader_mapping *find_exec_mapping(
    const struct kbox_loader_launch *launch,
    enum kbox_loader_mapping_source source,
    uint64_t addr)
{
    size_t i;

    if (!launch)
        return NULL;

    for (i = 0; i < launch->layout.mapping_count; i++) {
        const struct kbox_loader_mapping *mapping = &launch->layout.mappings[i];
        uint64_t end;

        if (mapping->source != source || (mapping->prot & PROT_EXEC) == 0 ||
            mapping->size == 0) {
            continue;
        }
        if (__builtin_add_overflow(mapping->addr, mapping->size, &end))
            continue;
        if (addr >= mapping->addr && addr < end)
            return mapping;
    }

    return NULL;
}

#if defined(__aarch64__)
static int encode_aarch64_ldr_literal(uint32_t *out,
                                      unsigned rt,
                                      int32_t offset_bytes)
{
    int32_t imm19;

    if (!out || rt > 31 || (offset_bytes & 3) != 0)
        return -1;
    imm19 = offset_bytes >> 2;
    if (imm19 < -(1 << 18) || imm19 > ((1 << 18) - 1))
        return -1;
    *out = AARCH64_LDR_LITERAL_OPCODE | (((uint32_t) imm19 & 0x7ffffu) << 5) |
           (rt & 31u);
    return 0;
}

static uint32_t encode_aarch64_br(unsigned rn)
{
    return AARCH64_BR_OPCODE | ((rn & 31u) << 5);
}
#endif /* __aarch64__ */

static int write_aarch64_trampoline(
    uint64_t trampoline_addr,
    uint64_t origin_addr,
    enum kbox_rewrite_wrapper_candidate_kind wrapper_kind)
{
#if defined(__aarch64__)
    unsigned char slot[AARCH64_REWRITE_SLOT_SIZE];
    uint32_t insn;
    uint64_t entry_addr;

    memset(slot, 0, sizeof(slot));
    if (encode_aarch64_ldr_literal(&insn, 17, 16) < 0)
        return -1;
    write_le32(slot + 0, insn);
    if (encode_aarch64_ldr_literal(&insn, 16, 20) < 0)
        return -1;
    write_le32(slot + 4, insn);
    write_le32(slot + 8, encode_aarch64_br(16));
    write_le32(slot + 12, AARCH64_NOP_OPCODE);
    write_le64(slot + 16, origin_addr);
    entry_addr =
        (uint64_t) (uintptr_t) (wrapper_kind ==
                                        KBOX_REWRITE_WRAPPER_CANDIDATE_SYSCALL_CANCEL
                                    ? kbox_syscall_rewrite_aarch64_cancel_entry
                                    : kbox_syscall_rewrite_aarch64_entry);
    write_le64(slot + 24, entry_addr);
    memcpy((void *) (uintptr_t) trampoline_addr, slot, sizeof(slot));
    return 0;
#else
    (void) trampoline_addr;
    (void) origin_addr;
    (void) wrapper_kind;
    return -1;
#endif
}

/* Allocate a veneer page near @near_addr (within ±128MB) for aarch64 long
 * branches. The veneer is a small code page containing indirect branch stubs:
 *   LDR x16, [PC+8]
 *   BR  x16
 *   .quad <actual_trampoline_addr>
 *
 * Each veneer entry is 16 bytes (AARCH64_VENEER_SIZE). The veneer page can
 * hold page_size / 16 entries.
 *
 * Returns 0 on success with the veneer page base in *veneer_base_out.
 */
static int alloc_aarch64_veneer_page(struct kbox_rewrite_runtime *runtime,
                                     uint64_t near_addr,
                                     uint64_t *veneer_base_out)
{
#if defined(__aarch64__)
    uint64_t page_size;
    uint64_t search_lo, search_hi, addr;
    void *region;

    if (!runtime || !veneer_base_out)
        return -1;
    if (runtime->trampoline_region_count >= KBOX_LOADER_MAX_MAPPINGS)
        return -1;

    page_size = (uint64_t) sysconf(_SC_PAGESIZE);
    if (page_size == 0 || (page_size & (page_size - 1)) != 0)
        return -1;

    /* Search within B range of near_addr. */
    search_lo = near_addr > AARCH64_VENEER_SEARCH_LIMIT
                    ? near_addr - AARCH64_VENEER_SEARCH_LIMIT
                    : page_size;
    search_lo = (search_lo + page_size - 1) & ~(page_size - 1);
    if (__builtin_add_overflow(near_addr, AARCH64_VENEER_SEARCH_LIMIT,
                               &search_hi))
        search_hi = UINT64_MAX - page_size;

    /* Search upward first (likely to succeed, past the mapping). */
    for (addr = (near_addr + page_size) & ~(page_size - 1); addr <= search_hi;
         addr += AARCH64_VENEER_SEARCH_STEP) {
        region = mmap((void *) (uintptr_t) addr, (size_t) page_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (region != MAP_FAILED) {
            runtime->trampoline_regions[runtime->trampoline_region_count]
                .mapping = region;
            runtime->trampoline_regions[runtime->trampoline_region_count].size =
                (size_t) page_size;
            runtime->trampoline_region_count++;
            *veneer_base_out = (uint64_t) (uintptr_t) region;
            return 0;
        }
        if (errno != EEXIST && errno != ENOMEM)
            break;
    }

    /* Search downward. */
    for (addr = search_lo; addr < near_addr;
         addr += AARCH64_VENEER_SEARCH_STEP) {
        region = mmap((void *) (uintptr_t) addr, (size_t) page_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (region != MAP_FAILED) {
            runtime->trampoline_regions[runtime->trampoline_region_count]
                .mapping = region;
            runtime->trampoline_regions[runtime->trampoline_region_count].size =
                (size_t) page_size;
            runtime->trampoline_region_count++;
            *veneer_base_out = (uint64_t) (uintptr_t) region;
            return 0;
        }
        if (errno != EEXIST && errno != ENOMEM)
            break;
    }

    errno = ENOSPC;
    return -1;
#else
    (void) runtime;
    (void) near_addr;
    (void) veneer_base_out;
    errno = ENOTSUP;
    return -1;
#endif
}

/* Write an aarch64 veneer entry at @veneer_addr that branches to
 * @trampoline_addr (full 64-bit indirect branch). Returns 0 on success.
 */
static int write_aarch64_veneer(uint64_t veneer_addr, uint64_t trampoline_addr)
{
#if defined(__aarch64__)
    unsigned char slot[AARCH64_VENEER_SIZE];
    uint32_t ldr_insn;

    /* LDR x16, [PC+8]: loads the 64-bit value 8 bytes ahead */
    if (encode_aarch64_ldr_literal(&ldr_insn, 16, 8) < 0)
        return -1;
    write_le32(slot + 0, ldr_insn);
    write_le32(slot + 4, encode_aarch64_br(16));
    write_le64(slot + 8, trampoline_addr);
    memcpy((void *) (uintptr_t) veneer_addr, slot, sizeof(slot));
    return 0;
#else
    (void) veneer_addr;
    (void) trampoline_addr;
    return -1;
#endif
}

/* Encode an aarch64 B instruction targeting @veneer_addr from @site_vaddr.
 * Returns 0 on success with patch bytes in @patch.
 */
static int encode_aarch64_b_to_veneer(uint64_t site_vaddr,
                                      uint64_t veneer_addr,
                                      struct kbox_rewrite_patch *patch)
{
    int64_t delta;
    int32_t imm26;
    uint32_t insn;

    if (!patch)
        return -1;
    if ((site_vaddr & 3u) != 0 || (veneer_addr & 3u) != 0)
        return -1;
    delta = (int64_t) veneer_addr - (int64_t) site_vaddr;
    if (delta <= -AARCH64_B_RANGE || delta >= AARCH64_B_RANGE)
        return -1;
    if ((delta & 3) != 0)
        return -1;
    imm26 = (int32_t) (delta >> 2);
    if (imm26 < -(1 << 25) || imm26 > ((1 << 25) - 1))
        return -1;
    insn = AARCH64_B_OPCODE | ((uint32_t) imm26 & AARCH64_B_IMM26_MASK);
    patch->width = 4;
    write_le32(patch->bytes, insn);
    return 0;
}

static int64_t rewrite_dispatch_result(struct kbox_rewrite_runtime *runtime,
                                       struct kbox_dispatch *dispatch,
                                       uint64_t nr,
                                       uint64_t a0,
                                       uint64_t a1,
                                       uint64_t a2,
                                       uint64_t a3,
                                       uint64_t a4,
                                       uint64_t a5)
{
    const struct kbox_host_nrs *h = NULL;

    if (!dispatch)
        return -ENOSYS;
    if (runtime && runtime->ctx)
        h = runtime->ctx->host_nrs;

    if (dispatch->kind == KBOX_DISPATCH_CONTINUE) {
        if (h && (nr == (uint64_t) h->exit || nr == (uint64_t) h->exit_group))
            return kbox_syscall_trap_host_exit_group_now((int) a0);
        if (h && nr == (uint64_t) h->execve)
            return kbox_syscall_trap_host_execve_now(
                (const char *) (uintptr_t) a0, (char *const *) (uintptr_t) a1,
                (char *const *) (uintptr_t) a2);
        if (h && nr == (uint64_t) h->execveat)
            return kbox_syscall_trap_host_execveat_now(
                (int) a0, (const char *) (uintptr_t) a1,
                (char *const *) (uintptr_t) a2, (char *const *) (uintptr_t) a3,
                (int) a4);
        if (h && nr == (uint64_t) h->clone)
            return kbox_syscall_trap_host_clone_now(a0, a1, a2, a3, a4);
        if (h && nr == (uint64_t) h->clone3)
            return kbox_syscall_trap_host_clone3_now(
                (const void *) (uintptr_t) a0, (size_t) a1);
#if defined(__x86_64__)
        if (h && nr == (uint64_t) h->fork)
            return kbox_syscall_trap_host_fork_now();
        if (h && nr == (uint64_t) h->vfork)
            return kbox_syscall_trap_host_vfork_now();
#endif
        return kbox_syscall_trap_host_syscall6((long) nr, a0, a1, a2, a3, a4,
                                               a5);
    }
    if (dispatch->error != 0)
        return -(int64_t) dispatch->error;
    return dispatch->val;
}

static int rewrite_is_wrapper_site(const struct kbox_rewrite_origin_map *map,
                                   uint64_t origin_addr)
{
    enum kbox_rewrite_site_class site_class;

    if (!map)
        return 0;
    if (kbox_rewrite_origin_map_find_class(map, origin_addr, &site_class) < 0)
        return 0;
    return site_class == KBOX_REWRITE_SITE_WRAPPER;
}

static int rewrite_dispatch_request(struct kbox_rewrite_runtime *runtime,
                                    const struct kbox_syscall_request *req,
                                    struct kbox_dispatch *dispatch)
{
    if (!runtime || !runtime->ctx || !req || !dispatch)
        return -1;

    /* Fast-path: handle LKL-free syscalls (pure emulation, always-CONTINUE)
     * directly on the guest thread without a service-thread round-trip.
     */
    if (kbox_dispatch_try_local_fast_path(runtime->ctx->host_nrs, req->nr,
                                          dispatch))
        return 0;

    /* LKL-touching syscalls must go through the service thread.  LKL
     * requires its own thread context; calling LKL directly from the
     * guest thread races with the service thread and crashes under
     * sustained load on aarch64.
     */
    return kbox_syscall_trap_active_dispatch(req, dispatch);
}

static int rewrite_runtime_should_patch_site(
    const struct kbox_rewrite_runtime *runtime,
    const struct runtime_planned_site *site)
{
    const struct kbox_host_nrs *host_nrs;
    uint64_t nr;
    uint32_t family_mask;

    if (!runtime || !runtime->ctx || !site)
        return 0;
    if (runtime->arch != KBOX_REWRITE_ARCH_AARCH64)
        return 1;
    if (site->planned.site.site_class != KBOX_REWRITE_SITE_WRAPPER)
        return 0;

    host_nrs = runtime->ctx->host_nrs;
    if (!host_nrs)
        return 0;
    nr = site->wrapper_nr;
    if (nr == UINT64_MAX && kbox_rewrite_wrapper_syscall_nr(
                                &site->planned.site, runtime->arch, &nr) < 0) {
        return 0;
    }

    if (nr == (uint64_t) host_nrs->getpid ||
        nr == (uint64_t) host_nrs->getppid ||
        nr == (uint64_t) host_nrs->gettid) {
        return 1;
    }

    family_mask = wrapper_family_mask_for_nr(host_nrs, nr);
    if (family_mask &
        (KBOX_REWRITE_WRAPPER_FAMILY_STAT | KBOX_REWRITE_WRAPPER_FAMILY_OPEN)) {
        return 1;
    }

    return 0;
}

/* Check whether an ELF binary contains fork-family syscall sites.
 *
 * Scans 8-byte wrapper sites (mov $NR, %eax; syscall; ret) for
 * fork/clone/vfork/clone3 syscall numbers. Also checks aarch64
 * SVC sites preceded by MOV x8, #NR for the same.
 *
 * Returns 1 if any fork-family site found, 0 if none, -1 on error.
 */
struct fork_scan_ctx {
    const struct kbox_host_nrs *host_nrs;
    int found;
};

struct wrapper_nr_scan_ctx {
    enum kbox_rewrite_arch arch;
    const uint64_t *nrs;
    size_t nr_count;
    int found;
};

struct wrapper_family_scan_ctx {
    enum kbox_rewrite_arch arch;
    const struct kbox_host_nrs *host_nrs;
    uint32_t mask;
};

struct wrapper_candidate_scan_ctx {
    enum kbox_rewrite_arch arch;
    const struct kbox_host_nrs *host_nrs;
    uint32_t family_mask;
    kbox_rewrite_wrapper_candidate_cb cb;
    void *opaque;
};

struct wrapper_candidate_collect_ctx {
    struct kbox_rewrite_wrapper_candidate *out;
    size_t out_cap;
    size_t count;
    int filter_enabled;
    enum kbox_rewrite_wrapper_candidate_kind kind;
};

static int wrapper_nr_in_allowlist(const struct wrapper_nr_scan_ctx *ctx,
                                   uint64_t nr)
{
    size_t i;

    if (!ctx || !ctx->nrs)
        return 0;
    for (i = 0; i < ctx->nr_count; i++) {
        if (ctx->nrs[i] == nr)
            return 1;
    }
    return 0;
}

static int wrapper_nr_scan_segment(const struct kbox_elf_exec_segment *seg,
                                   const unsigned char *segment_bytes,
                                   void *opaque)
{
    struct wrapper_nr_scan_ctx *ctx = opaque;

    (void) seg;
    if (!ctx || !segment_bytes || ctx->found)
        return 0;

    if (ctx->arch == KBOX_REWRITE_ARCH_X86_64) {
        if (seg->file_size < X86_64_WRAPPER_SITE_LEN)
            return 0;
        for (size_t i = 0; i < seg->file_size;) {
            int insn_len =
                kbox_x86_insn_length(segment_bytes + i, seg->file_size - i);
            if (insn_len <= 0) {
                i++;
                continue;
            }
            if (insn_len == 5 &&
                x86_64_is_wrapper_site(segment_bytes, seg->file_size, i)) {
                uint64_t nr =
                    (uint64_t) x86_64_wrapper_syscall_nr(segment_bytes + i);

                if (wrapper_nr_in_allowlist(ctx, nr)) {
                    ctx->found = 1;
                    return 0;
                }
                i += X86_64_WRAPPER_SITE_LEN;
                continue;
            }
            i += (size_t) insn_len;
        }
        return 0;
    }

    if (ctx->arch == KBOX_REWRITE_ARCH_AARCH64) {
        for (size_t i = 0; i + 3 < seg->file_size; i += 4) {
            uint32_t insn;
            uint32_t nr = UINT32_MAX;
            size_t j;

            insn = (uint32_t) segment_bytes[i] |
                   ((uint32_t) segment_bytes[i + 1] << 8) |
                   ((uint32_t) segment_bytes[i + 2] << 16) |
                   ((uint32_t) segment_bytes[i + 3] << 24);
            if (aarch64_movz_reg_imm16(insn, 6, &nr) < 0)
                continue;

            /* Detect the static-musl __syscall_cancel caller pattern:
             * mov x6,#nr ... b/bl __syscall_cancel
             * This is a selector signal only for now, so a conservative
             * short-range scan is sufficient.
             */
            for (j = i + 4; j + 3 < seg->file_size && j <= i + 32; j += 4) {
                uint32_t next = (uint32_t) segment_bytes[j] |
                                ((uint32_t) segment_bytes[j + 1] << 8) |
                                ((uint32_t) segment_bytes[j + 2] << 16) |
                                ((uint32_t) segment_bytes[j + 3] << 24);

                if ((next & 0xfc000000u) == 0x14000000u ||
                    (next & 0xfc000000u) == 0x94000000u) {
                    if (wrapper_nr_in_allowlist(ctx, nr)) {
                        ctx->found = 1;
                        return 0;
                    }
                    break;
                }

                if (next == 0xd4000001u)
                    break;
            }
        }

        for (size_t i = 4; i + 3 < seg->file_size; i += 4) {
            struct kbox_rewrite_site site;
            uint64_t nr = 0;

            if (segment_bytes[i] != 0x01 || segment_bytes[i + 1] != 0x00 ||
                segment_bytes[i + 2] != 0x00 || segment_bytes[i + 3] != 0xd4) {
                continue;
            }
            if (kbox_rewrite_classify_aarch64_site(segment_bytes,
                                                   seg->file_size, i) !=
                KBOX_REWRITE_SITE_WRAPPER) {
                continue;
            }

            memset(&site, 0, sizeof(site));
            site.width = 4;
            site.site_class = KBOX_REWRITE_SITE_WRAPPER;
            memcpy(site.original, segment_bytes + i - 4, 4);
            if (kbox_rewrite_wrapper_syscall_nr(&site, ctx->arch, &nr) == 0 &&
                wrapper_nr_in_allowlist(ctx, nr)) {
                ctx->found = 1;
                return 0;
            }
        }
        return 0;
    }

    return 0;
}

static uint32_t wrapper_family_mask_for_nr(const struct kbox_host_nrs *host_nrs,
                                           uint64_t nr)
{
    uint32_t mask = 0;

    if (!host_nrs)
        return 0;
    if ((int) nr == host_nrs->getpid || (int) nr == host_nrs->getppid ||
        (int) nr == host_nrs->gettid) {
        mask |= KBOX_REWRITE_WRAPPER_FAMILY_PROCINFO;
    }
    if ((int) nr == host_nrs->newfstatat || (int) nr == host_nrs->fstat ||
        (int) nr == host_nrs->stat || (int) nr == host_nrs->lstat) {
        mask |= KBOX_REWRITE_WRAPPER_FAMILY_STAT;
    }
    if ((int) nr == host_nrs->openat || (int) nr == host_nrs->openat2 ||
        (int) nr == host_nrs->open) {
        mask |= KBOX_REWRITE_WRAPPER_FAMILY_OPEN;
    }
    return mask;
}

static int emit_wrapper_candidate(struct wrapper_candidate_scan_ctx *ctx,
                                  enum kbox_rewrite_wrapper_candidate_kind kind,
                                  uint64_t file_offset,
                                  uint64_t vaddr,
                                  uint64_t nr)
{
    struct kbox_rewrite_wrapper_candidate candidate;
    uint32_t mask;

    if (!ctx || !ctx->host_nrs || !ctx->cb)
        return -1;

    mask = wrapper_family_mask_for_nr(ctx->host_nrs, nr);
    if ((mask & ctx->family_mask) == 0)
        return 0;

    memset(&candidate, 0, sizeof(candidate));
    candidate.arch = ctx->arch;
    candidate.kind = kind;
    candidate.file_offset = file_offset;
    candidate.vaddr = vaddr;
    candidate.nr = nr;
    candidate.family_mask = mask;
    return ctx->cb(&candidate, ctx->opaque);
}

static int wrapper_family_scan_segment(const struct kbox_elf_exec_segment *seg,
                                       const unsigned char *segment_bytes,
                                       void *opaque)
{
    struct wrapper_family_scan_ctx *ctx = opaque;

    (void) seg;
    if (!ctx || !segment_bytes || !ctx->host_nrs)
        return 0;

    if (ctx->arch == KBOX_REWRITE_ARCH_X86_64) {
        if (seg->file_size < X86_64_WRAPPER_SITE_LEN)
            return 0;
        for (size_t i = 0; i < seg->file_size;) {
            int insn_len =
                kbox_x86_insn_length(segment_bytes + i, seg->file_size - i);
            if (insn_len <= 0) {
                i++;
                continue;
            }
            if (insn_len == 5 &&
                x86_64_is_wrapper_site(segment_bytes, seg->file_size, i)) {
                uint64_t nr =
                    (uint64_t) x86_64_wrapper_syscall_nr(segment_bytes + i);

                ctx->mask |= wrapper_family_mask_for_nr(ctx->host_nrs, nr);
                i += X86_64_WRAPPER_SITE_LEN;
                continue;
            }
            i += (size_t) insn_len;
        }
        return 0;
    }

    if (ctx->arch == KBOX_REWRITE_ARCH_AARCH64) {
        for (size_t i = 0; i + 3 < seg->file_size; i += 4) {
            uint32_t insn;
            uint32_t nr = UINT32_MAX;
            size_t j;

            insn = (uint32_t) segment_bytes[i] |
                   ((uint32_t) segment_bytes[i + 1] << 8) |
                   ((uint32_t) segment_bytes[i + 2] << 16) |
                   ((uint32_t) segment_bytes[i + 3] << 24);
            if (aarch64_movz_reg_imm16(insn, 6, &nr) < 0)
                continue;

            for (j = i + 4; j + 3 < seg->file_size && j <= i + 32; j += 4) {
                uint32_t next = (uint32_t) segment_bytes[j] |
                                ((uint32_t) segment_bytes[j + 1] << 8) |
                                ((uint32_t) segment_bytes[j + 2] << 16) |
                                ((uint32_t) segment_bytes[j + 3] << 24);

                if ((next & 0xfc000000u) == 0x14000000u ||
                    (next & 0xfc000000u) == 0x94000000u) {
                    ctx->mask |= wrapper_family_mask_for_nr(ctx->host_nrs, nr);
                    break;
                }

                if (next == 0xd4000001u)
                    break;
            }
        }

        for (size_t i = 4; i + 3 < seg->file_size; i += 4) {
            struct kbox_rewrite_site site;
            uint64_t nr = 0;

            if (segment_bytes[i] != 0x01 || segment_bytes[i + 1] != 0x00 ||
                segment_bytes[i + 2] != 0x00 || segment_bytes[i + 3] != 0xd4) {
                continue;
            }
            if (kbox_rewrite_classify_aarch64_site(segment_bytes,
                                                   seg->file_size, i) !=
                KBOX_REWRITE_SITE_WRAPPER) {
                continue;
            }

            memset(&site, 0, sizeof(site));
            site.width = 4;
            site.site_class = KBOX_REWRITE_SITE_WRAPPER;
            memcpy(site.original, segment_bytes + i - 4, 4);
            if (kbox_rewrite_wrapper_syscall_nr(&site, ctx->arch, &nr) == 0)
                ctx->mask |= wrapper_family_mask_for_nr(ctx->host_nrs, nr);
        }
    }

    return 0;
}

static int wrapper_candidate_scan_segment(
    const struct kbox_elf_exec_segment *seg,
    const unsigned char *segment_bytes,
    void *opaque)
{
    struct wrapper_candidate_scan_ctx *ctx = opaque;

    (void) seg;
    if (!ctx || !segment_bytes || !ctx->host_nrs || !ctx->cb)
        return 0;

    if (ctx->arch == KBOX_REWRITE_ARCH_X86_64) {
        if (seg->file_size < X86_64_WRAPPER_SITE_LEN)
            return 0;
        for (size_t i = 0; i < seg->file_size;) {
            int insn_len =
                kbox_x86_insn_length(segment_bytes + i, seg->file_size - i);
            if (insn_len <= 0) {
                i++;
                continue;
            }
            if (insn_len == 5 &&
                x86_64_is_wrapper_site(segment_bytes, seg->file_size, i)) {
                uint64_t nr =
                    (uint64_t) x86_64_wrapper_syscall_nr(segment_bytes + i);
                int rc = emit_wrapper_candidate(
                    ctx, KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT,
                    seg->file_offset + i, seg->vaddr + i, nr);
                if (rc != 0)
                    return rc;
                i += X86_64_WRAPPER_SITE_LEN;
                continue;
            }
            i += (size_t) insn_len;
        }
        return 0;
    }

    if (ctx->arch == KBOX_REWRITE_ARCH_AARCH64) {
        for (size_t i = 0; i + 3 < seg->file_size; i += 4) {
            uint32_t insn;
            uint32_t nr = UINT32_MAX;
            size_t j;

            insn = (uint32_t) segment_bytes[i] |
                   ((uint32_t) segment_bytes[i + 1] << 8) |
                   ((uint32_t) segment_bytes[i + 2] << 16) |
                   ((uint32_t) segment_bytes[i + 3] << 24);
            if (aarch64_movz_reg_imm16(insn, 6, &nr) < 0)
                continue;

            for (j = i + 4; j + 3 < seg->file_size && j <= i + 32; j += 4) {
                uint32_t next = (uint32_t) segment_bytes[j] |
                                ((uint32_t) segment_bytes[j + 1] << 8) |
                                ((uint32_t) segment_bytes[j + 2] << 16) |
                                ((uint32_t) segment_bytes[j + 3] << 24);

                if ((next & 0xfc000000u) == 0x14000000u ||
                    (next & 0xfc000000u) == 0x94000000u) {
                    int rc = emit_wrapper_candidate(
                        ctx, KBOX_REWRITE_WRAPPER_CANDIDATE_SYSCALL_CANCEL,
                        seg->file_offset + j, seg->vaddr + j, nr);
                    if (rc != 0)
                        return rc;
                    break;
                }

                if (next == 0xd4000001u)
                    break;
            }
        }

        for (size_t i = 4; i + 3 < seg->file_size; i += 4) {
            struct kbox_rewrite_site site;
            uint64_t nr = 0;

            if (segment_bytes[i] != 0x01 || segment_bytes[i + 1] != 0x00 ||
                segment_bytes[i + 2] != 0x00 || segment_bytes[i + 3] != 0xd4) {
                continue;
            }
            if (kbox_rewrite_classify_aarch64_site(segment_bytes,
                                                   seg->file_size, i) !=
                KBOX_REWRITE_SITE_WRAPPER) {
                continue;
            }

            memset(&site, 0, sizeof(site));
            site.width = 4;
            site.site_class = KBOX_REWRITE_SITE_WRAPPER;
            memcpy(site.original, segment_bytes + i - 4, 4);
            if (kbox_rewrite_wrapper_syscall_nr(&site, ctx->arch, &nr) == 0) {
                int rc = emit_wrapper_candidate(
                    ctx, KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT,
                    seg->file_offset + i, seg->vaddr + i, nr);
                if (rc != 0)
                    return rc;
            }
        }
    }

    return 0;
}

static int fork_scan_cb(const struct kbox_rewrite_site *site, void *opaque)
{
    struct fork_scan_ctx *ctx = opaque;
    const struct kbox_host_nrs *h = ctx->host_nrs;

    if (ctx->found)
        return 0; /* Already found one, just skip the rest. */

    /* x86_64 8-byte wrapper: extract syscall number from MOV imm32. */
    if (site->width == X86_64_WRAPPER_SITE_LEN && site->original[0] == 0xb8) {
        int nr = (int) x86_64_wrapper_syscall_nr(site->original);
        if (nr == h->clone || nr == h->fork || nr == h->vfork ||
            nr == h->clone3) {
            ctx->found = 1;
        }
        return 0;
    }

    /* aarch64 SVC: can't determine syscall number from the SVC site alone
     * (it's in x8, set by a prior MOV). We conservatively do NOT flag
     * aarch64 sites here; the caller uses additional heuristics.
     */

    return 0;
}

int kbox_rewrite_has_fork_sites(const unsigned char *buf,
                                size_t buf_len,
                                const struct kbox_host_nrs *host_nrs)
{
    struct fork_scan_ctx ctx;
    struct kbox_rewrite_report report;

    if (!buf || !host_nrs)
        return -1;
    ctx.host_nrs = host_nrs;
    ctx.found = 0;
    if (kbox_rewrite_visit_elf_sites(buf, buf_len, fork_scan_cb, &ctx,
                                     &report) < 0)
        return -1;
    return ctx.found;
}

int kbox_rewrite_has_fork_sites_memfd(int fd,
                                      const struct kbox_host_nrs *host_nrs)
{
    struct fork_scan_ctx ctx;
    struct kbox_rewrite_report report;

    if (fd < 0 || !host_nrs)
        return -1;
    ctx.host_nrs = host_nrs;
    ctx.found = 0;
    if (kbox_rewrite_visit_memfd_sites(fd, fork_scan_cb, &ctx, &report) < 0)
        return -1;
    return ctx.found;
}

int kbox_rewrite_has_wrapper_syscalls(const unsigned char *buf,
                                      size_t buf_len,
                                      enum kbox_rewrite_arch arch,
                                      const uint64_t *nrs,
                                      size_t nr_count)
{
    struct wrapper_nr_scan_ctx ctx;
    struct kbox_rewrite_report report;

    if (!buf || !nrs || nr_count == 0)
        return -1;
    ctx.arch = arch;
    ctx.nrs = nrs;
    ctx.nr_count = nr_count;
    ctx.found = 0;
    memset(&report, 0, sizeof(report));
    if ((arch != KBOX_REWRITE_ARCH_X86_64 &&
         arch != KBOX_REWRITE_ARCH_AARCH64) ||
        kbox_visit_elf_exec_segments(buf, buf_len, wrapper_nr_scan_segment,
                                     &ctx) < 0) {
        return -1;
    }
    return ctx.found;
}

int kbox_rewrite_has_wrapper_syscalls_memfd(int fd,
                                            const uint64_t *nrs,
                                            size_t nr_count)
{
    struct wrapper_nr_scan_ctx ctx;
    struct kbox_rewrite_report report;

    if (fd < 0 || !nrs || nr_count == 0)
        return -1;
    if (kbox_rewrite_analyze_memfd(fd, &report) < 0)
        return -1;

    ctx.arch = report.arch;
    ctx.nrs = nrs;
    ctx.nr_count = nr_count;
    ctx.found = 0;
    if (visit_memfd_exec_segments(fd, wrapper_nr_scan_segment, &ctx) < 0)
        return -1;
    return ctx.found;
}

int kbox_rewrite_wrapper_family_mask_memfd(int fd,
                                           const struct kbox_host_nrs *host_nrs,
                                           uint32_t *out_mask)
{
    struct kbox_rewrite_report report;
    struct wrapper_family_scan_ctx ctx;

    if (fd < 0 || !host_nrs || !out_mask)
        return -1;
    if (kbox_rewrite_analyze_memfd(fd, &report) < 0)
        return -1;

    ctx.arch = report.arch;
    ctx.host_nrs = host_nrs;
    ctx.mask = 0;
    if (visit_memfd_exec_segments(fd, wrapper_family_scan_segment, &ctx) < 0)
        return -1;
    *out_mask = ctx.mask;
    return 0;
}

int kbox_rewrite_visit_memfd_wrapper_candidates(
    int fd,
    const struct kbox_host_nrs *host_nrs,
    uint32_t family_mask,
    kbox_rewrite_wrapper_candidate_cb cb,
    void *opaque)
{
    struct kbox_rewrite_report report;
    struct wrapper_candidate_scan_ctx ctx;
    int rc;

    if (fd < 0 || !host_nrs || family_mask == 0 || !cb)
        return -1;
    if (kbox_rewrite_analyze_memfd(fd, &report) < 0)
        return -1;

    ctx.arch = report.arch;
    ctx.host_nrs = host_nrs;
    ctx.family_mask = family_mask;
    ctx.cb = cb;
    ctx.opaque = opaque;
    rc = visit_memfd_exec_segments(fd, wrapper_candidate_scan_segment, &ctx);
    return rc < 0 ? -1 : 0;
}

static int collect_wrapper_candidate_cb(
    const struct kbox_rewrite_wrapper_candidate *candidate,
    void *opaque)
{
    struct wrapper_candidate_collect_ctx *ctx = opaque;

    if (!candidate || !ctx)
        return -1;
    if (ctx->filter_enabled && candidate->kind != ctx->kind)
        return 0;
    if (ctx->count < ctx->out_cap && ctx->out)
        ctx->out[ctx->count] = *candidate;
    ctx->count++;
    return 0;
}

int kbox_rewrite_collect_memfd_wrapper_candidates(
    int fd,
    const struct kbox_host_nrs *host_nrs,
    uint32_t family_mask,
    struct kbox_rewrite_wrapper_candidate *out,
    size_t out_cap,
    size_t *out_count)
{
    struct wrapper_candidate_collect_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.out = out;
    ctx.out_cap = out_cap;
    if (kbox_rewrite_visit_memfd_wrapper_candidates(
            fd, host_nrs, family_mask, collect_wrapper_candidate_cb, &ctx) < 0)
        return -1;
    if (out_count)
        *out_count = ctx.count;
    return 0;
}

int kbox_rewrite_collect_memfd_wrapper_candidates_by_kind(
    int fd,
    const struct kbox_host_nrs *host_nrs,
    uint32_t family_mask,
    enum kbox_rewrite_wrapper_candidate_kind kind,
    struct kbox_rewrite_wrapper_candidate *out,
    size_t out_cap,
    size_t *out_count)
{
    struct wrapper_candidate_collect_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.out = out;
    ctx.out_cap = out_cap;
    ctx.filter_enabled = 1;
    ctx.kind = kind;
    if (kbox_rewrite_visit_memfd_wrapper_candidates(
            fd, host_nrs, family_mask, collect_wrapper_candidate_cb, &ctx) < 0)
        return -1;
    if (out_count)
        *out_count = ctx.count;
    return 0;
}

static int collect_elf_wrapper_candidates_by_kind(
    const unsigned char *buf,
    size_t buf_len,
    const struct kbox_host_nrs *host_nrs,
    uint32_t family_mask,
    enum kbox_rewrite_wrapper_candidate_kind kind,
    struct kbox_rewrite_wrapper_candidate *out,
    size_t out_cap,
    size_t *out_count)
{
    struct kbox_rewrite_report report;
    struct wrapper_candidate_scan_ctx scan;
    struct wrapper_candidate_collect_ctx collect;

    if (!buf || !host_nrs || family_mask == 0)
        return -1;
    if (kbox_rewrite_analyze_elf(buf, buf_len, &report) < 0)
        return -1;

    memset(&scan, 0, sizeof(scan));
    memset(&collect, 0, sizeof(collect));
    scan.arch = report.arch;
    scan.host_nrs = host_nrs;
    scan.family_mask = family_mask;
    scan.cb = collect_wrapper_candidate_cb;
    scan.opaque = &collect;
    collect.out = out;
    collect.out_cap = out_cap;
    collect.filter_enabled = 1;
    collect.kind = kind;
    if (kbox_visit_elf_exec_segments(
            buf, buf_len, wrapper_candidate_scan_segment, &scan) < 0) {
        return -1;
    }
    if (out_count)
        *out_count = collect.count;
    return 0;
}

static int annotate_launch_wrapper_sites_kind(
    struct runtime_site_array *array,
    const unsigned char *elf,
    size_t elf_len,
    enum kbox_loader_mapping_source source,
    const struct kbox_host_nrs *host_nrs,
    enum kbox_rewrite_wrapper_candidate_kind kind)
{
    struct kbox_rewrite_wrapper_candidate *candidates = NULL;
    size_t candidate_count = 0;
    int rc = -1;

    if (!array || !elf || !host_nrs)
        return -1;
    if (collect_elf_wrapper_candidates_by_kind(
            elf, elf_len, host_nrs,
            KBOX_REWRITE_WRAPPER_FAMILY_PROCINFO |
                KBOX_REWRITE_WRAPPER_FAMILY_STAT |
                KBOX_REWRITE_WRAPPER_FAMILY_OPEN,
            kind, NULL, 0, &candidate_count) < 0) {
        return -1;
    }
    if (candidate_count == 0)
        return 0;

    candidates = calloc(candidate_count, sizeof(*candidates));
    if (!candidates)
        return -1;
    if (collect_elf_wrapper_candidates_by_kind(
            elf, elf_len, host_nrs,
            KBOX_REWRITE_WRAPPER_FAMILY_PROCINFO |
                KBOX_REWRITE_WRAPPER_FAMILY_STAT |
                KBOX_REWRITE_WRAPPER_FAMILY_OPEN,
            kind, candidates, candidate_count, &candidate_count) < 0) {
        goto out;
    }

    for (size_t i = 0; i < array->count; i++) {
        struct runtime_planned_site *site = &array->sites[i];

        if (site->source != source) {
            continue;
        }
        for (size_t j = 0; j < candidate_count; j++) {
            if (planned_site_matches_wrapper_candidate(&site->planned,
                                                       &candidates[j])) {
                site->wrapper_kind = kind;
                site->wrapper_nr = candidates[j].nr;
                break;
            }
        }
    }

    rc = 0;
out:
    free(candidates);
    return rc;
}

static int annotate_launch_wrapper_sites(struct runtime_site_array *array,
                                         const unsigned char *elf,
                                         size_t elf_len,
                                         enum kbox_loader_mapping_source source,
                                         const struct kbox_host_nrs *host_nrs)
{
    if (annotate_launch_wrapper_sites_kind(
            array, elf, elf_len, source, host_nrs,
            KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT) < 0) {
        return -1;
    }
    if (annotate_launch_wrapper_sites_kind(
            array, elf, elf_len, source, host_nrs,
            KBOX_REWRITE_WRAPPER_CANDIDATE_SYSCALL_CANCEL) < 0) {
        return -1;
    }
    return 0;
}

int kbox_rewrite_collect_memfd_phase1_path_candidates(
    int fd,
    const struct kbox_host_nrs *host_nrs,
    struct kbox_rewrite_wrapper_candidate *out,
    size_t out_cap,
    size_t *out_count)
{
    return kbox_rewrite_collect_memfd_wrapper_candidates_by_kind(
        fd, host_nrs,
        KBOX_REWRITE_WRAPPER_FAMILY_STAT | KBOX_REWRITE_WRAPPER_FAMILY_OPEN,
        KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT, out, out_cap, out_count);
}

static int planned_site_matches_wrapper_candidate(
    const struct kbox_rewrite_planned_site *planned,
    const struct kbox_rewrite_wrapper_candidate *candidate)
{
    if (!planned || !candidate)
        return 0;
    return planned->site.file_offset == candidate->file_offset &&
           planned->site.vaddr == candidate->vaddr;
}

int kbox_rewrite_apply_memfd_phase1_path_candidates(
    int fd,
    const struct kbox_host_nrs *host_nrs,
    size_t *applied_count,
    struct kbox_rewrite_report *report)
{
    struct planned_site_array array;
    struct kbox_rewrite_report local_report;
    struct kbox_rewrite_wrapper_candidate *candidates = NULL;
    size_t candidate_count = 0;
    size_t applied = 0;
    int rc;

    if (fd < 0 || !host_nrs)
        return -1;

    memset(&array, 0, sizeof(array));
    rc = kbox_rewrite_collect_memfd_phase1_path_candidates(fd, host_nrs, NULL,
                                                           0, &candidate_count);
    if (rc < 0)
        return -1;
    if (candidate_count == 0) {
        if (applied_count)
            *applied_count = 0;
        return 0;
    }

    candidates = calloc(candidate_count, sizeof(*candidates));
    if (!candidates)
        return -1;
    rc = kbox_rewrite_collect_memfd_phase1_path_candidates(
        fd, host_nrs, candidates, candidate_count, &candidate_count);
    if (rc < 0) {
        free(candidates);
        return -1;
    }

    rc = kbox_rewrite_visit_memfd_planned_sites(
        fd, collect_planned_sites_array_cb, &array,
        report ? report : &local_report);
    if (rc < 0) {
        free(candidates);
        free_planned_site_array(&array);
        return -1;
    }

    for (size_t i = 0; i < array.count; i++) {
        const struct kbox_rewrite_planned_site *planned = &array.sites[i];
        unsigned char current[KBOX_REWRITE_MAX_PATCH_BYTES];
        size_t width = planned->patch.width;
        off_t off = (off_t) planned->site.file_offset;
        ssize_t nr;
        int matched = 0;

        for (size_t j = 0; j < candidate_count; j++) {
            if (planned_site_matches_wrapper_candidate(planned,
                                                       &candidates[j])) {
                matched = 1;
                break;
            }
        }
        if (!matched)
            continue;

        if (width == 0 || width > sizeof(current)) {
            free(candidates);
            free_planned_site_array(&array);
            return -1;
        }
        nr = pread_full(fd, current, width, off);
        if (nr < 0 || (size_t) nr != width) {
            free(candidates);
            free_planned_site_array(&array);
            if (nr >= 0)
                errno = EIO;
            return -1;
        }
        if (memcmp(current, planned->site.original, width) != 0) {
            free(candidates);
            free_planned_site_array(&array);
            errno = EIO;
            return -1;
        }
        nr = pwrite_full(fd, planned->patch.bytes, width, off);
        if (nr < 0 || (size_t) nr != width) {
            free(candidates);
            free_planned_site_array(&array);
            if (nr >= 0)
                errno = EIO;
            return -1;
        }
        applied++;
    }

    free(candidates);
    free_planned_site_array(&array);
    if (applied_count)
        *applied_count = applied;
    return 0;
}

int kbox_rewrite_is_fast_host_syscall0(const struct kbox_host_nrs *host_nrs,
                                       uint64_t nr)
{
    if (!host_nrs)
        return 0;
    return nr == (uint64_t) host_nrs->getpid ||
           nr == (uint64_t) host_nrs->getppid ||
           nr == (uint64_t) host_nrs->gettid;
}

int kbox_rewrite_wrapper_syscall_nr(const struct kbox_rewrite_site *site,
                                    enum kbox_rewrite_arch arch,
                                    uint64_t *out_nr)
{
    uint32_t nr = UINT32_MAX;

    if (!site || !out_nr || site->site_class != KBOX_REWRITE_SITE_WRAPPER)
        return -1;

    switch (arch) {
    case KBOX_REWRITE_ARCH_X86_64:
        if (site->width == X86_64_WRAPPER_SITE_LEN &&
            site->original[0] == 0xb8 && site->original[5] == 0x0f &&
            (site->original[6] == 0x05 || site->original[6] == 0x34) &&
            site->original[7] == 0xc3) {
            nr = x86_64_wrapper_syscall_nr(site->original);
        }
        break;
    case KBOX_REWRITE_ARCH_AARCH64:
        nr = aarch64_wrapper_syscall_nr(site);
        break;
    default:
        break;
    }

    if (nr == UINT32_MAX)
        return -1;
    *out_nr = nr;
    return 0;
}

#if defined(__aarch64__)
int64_t kbox_syscall_rewrite_aarch64_dispatch(uint64_t origin_addr,
                                              uint64_t nr,
                                              uint64_t a0,
                                              uint64_t a1,
                                              uint64_t a2,
                                              uint64_t a3,
                                              uint64_t a4,
                                              uint64_t a5)
{
    struct kbox_syscall_request req;
    struct kbox_syscall_regs regs;
    struct kbox_guest_mem guest_mem;
    struct kbox_dispatch dispatch;
    struct kbox_rewrite_runtime *runtime = load_active_rewrite_runtime();

    if (!runtime || !runtime->ctx ||
        !kbox_rewrite_origin_map_contains(&runtime->origin_map, origin_addr)) {
        _exit(250);
    }

    /* Site-aware fast path: return virtualized process-info values for
     * WRAPPER sites (getpid=1, gettid=1, getppid=0). COMPLEX sites
     * (e.g., raise() -> gettid -> tgkill) must use full dispatch.
     */
    if (kbox_rewrite_is_site_fast_eligible(&runtime->origin_map, origin_addr,
                                           runtime->ctx->host_nrs, nr)) {
        return rewrite_fast_procinfo_value(runtime->ctx->host_nrs, nr);
    }

    memset(&regs, 0, sizeof(regs));
    regs.nr = (int) nr;
    regs.instruction_pointer = origin_addr;
    regs.args[0] = a0;
    regs.args[1] = a1;
    regs.args[2] = a2;
    regs.args[3] = a3;
    regs.args[4] = a4;
    regs.args[5] = a5;

    guest_mem.ops = &kbox_current_guest_mem_ops;
    guest_mem.opaque = 0;
    if (kbox_syscall_request_init_from_regs(&req, KBOX_SYSCALL_SOURCE_REWRITE,
                                            runtime->ctx->child_pid, 0, &regs,
                                            &guest_mem) < 0) {
        return -ENOSYS;
    }

    if (rewrite_dispatch_request(runtime, &req, &dispatch) < 0)
        return -ENOSYS;
    return rewrite_dispatch_result(runtime, &dispatch, nr, a0, a1, a2, a3, a4,
                                   a5);
}

#endif

#if defined(__x86_64__)
int64_t kbox_syscall_rewrite_x86_64_dispatch(uint64_t origin_addr,
                                             uint64_t nr,
                                             const uint64_t *args)
{
    struct kbox_syscall_request req;
    struct kbox_syscall_regs regs;
    struct kbox_guest_mem guest_mem;
    struct kbox_dispatch dispatch;
    struct kbox_rewrite_runtime *runtime = load_active_rewrite_runtime();

    if (!runtime || !runtime->ctx || !args ||
        !kbox_rewrite_origin_map_contains(&runtime->origin_map, origin_addr)) {
        _exit(250);
    }

    if (kbox_rewrite_is_site_fast_eligible(&runtime->origin_map, origin_addr,
                                           runtime->ctx->host_nrs, nr)) {
        return rewrite_fast_procinfo_value(runtime->ctx->host_nrs, nr);
    }

    memset(&regs, 0, sizeof(regs));
    regs.nr = (int) nr;
    regs.instruction_pointer = origin_addr;
    regs.args[0] = args[0];
    regs.args[1] = args[1];
    regs.args[2] = args[2];
    regs.args[3] = args[3];
    regs.args[4] = args[4];
    regs.args[5] = args[5];

    guest_mem.ops = &kbox_current_guest_mem_ops;
    guest_mem.opaque = 0;
    if (kbox_syscall_request_init_from_regs(&req, KBOX_SYSCALL_SOURCE_REWRITE,
                                            runtime->ctx->child_pid, 0, &regs,
                                            &guest_mem) < 0) {
        return -ENOSYS;
    }

    if (rewrite_dispatch_request(runtime, &req, &dispatch) < 0)
        return -ENOSYS;
    return rewrite_dispatch_result(runtime, &dispatch, nr, args[0], args[1],
                                   args[2], args[3], args[4], args[5]);
}
#endif

struct x86_64_trampoline_region {
    size_t mapping_index;
    uint64_t base_addr;
    size_t slot_count;
    size_t used_slots;
};

static int find_exec_mapping_index(const struct kbox_loader_launch *launch,
                                   enum kbox_loader_mapping_source source,
                                   uint64_t addr)
{
    size_t i;

    if (!launch)
        return -1;

    for (i = 0; i < launch->layout.mapping_count; i++) {
        const struct kbox_loader_mapping *mapping = &launch->layout.mappings[i];
        uint64_t end;

        if (mapping->source != source || (mapping->prot & PROT_EXEC) == 0 ||
            mapping->size == 0) {
            continue;
        }
        if (__builtin_add_overflow(mapping->addr, mapping->size, &end))
            continue;
        if (addr >= mapping->addr && addr < end)
            return (int) i;
    }

    return -1;
}

static struct x86_64_trampoline_region *find_x86_64_region(
    struct x86_64_trampoline_region *regions,
    size_t region_count,
    size_t mapping_index)
{
    size_t i;

    for (i = 0; i < region_count; i++) {
        if (regions[i].mapping_index == mapping_index)
            return &regions[i];
    }
    return NULL;
}

static int alloc_x86_64_trampoline_region(
    struct kbox_rewrite_runtime *runtime,
    const struct kbox_loader_mapping *mapping,
    size_t slot_count,
    uint64_t *base_addr_out)
{
#if defined(__x86_64__)
    uint64_t page_size;
    uint64_t size;
    uint64_t start;
    uint64_t limit;
    uint64_t addr;
    void *region;

    if (!runtime || !mapping || !slot_count || !base_addr_out)
        return -1;
    if (runtime->trampoline_region_count >= KBOX_LOADER_MAX_MAPPINGS)
        return -1;

    page_size = (uint64_t) sysconf(_SC_PAGESIZE);
    if (page_size == 0 || (page_size & (page_size - 1)) != 0)
        return -1;
    size = align_up_u64_or_zero(slot_count * X86_64_REWRITE_WRAPPER_SLOT_SIZE,
                                page_size);
    if (size == 0)
        return -1;
    start = align_up_u64_or_zero(mapping->addr + mapping->size, page_size);
    if (start == 0)
        return -1;
    limit = start + X86_64_TRAMPOLINE_SEARCH_LIMIT;
    if (limit < start)
        limit = UINT64_MAX - size;

    for (addr = start; addr <= limit; addr += X86_64_TRAMPOLINE_SEARCH_STEP) {
        region = mmap((void *) (uintptr_t) addr, (size_t) size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (region != MAP_FAILED) {
            runtime->trampoline_regions[runtime->trampoline_region_count]
                .mapping = region;
            runtime->trampoline_regions[runtime->trampoline_region_count].size =
                (size_t) size;
            runtime->trampoline_region_count++;
            *base_addr_out = (uint64_t) (uintptr_t) region;
            return 0;
        }
        if (errno != EEXIST && errno != ENOMEM)
            return -1;
    }

    errno = ENOSPC;
    return -1;
#else
    (void) runtime;
    (void) mapping;
    (void) slot_count;
    (void) base_addr_out;
    errno = ENOTSUP;
    return -1;
#endif
}

static int collect_launch_sites(struct runtime_site_array *array,
                                const struct kbox_loader_launch *launch,
                                const struct kbox_host_nrs *host_nrs)
{
    struct runtime_collect_ctx ctx;
    struct kbox_rewrite_report report;

    if (!array || !launch || !host_nrs)
        return -1;

    if (launch->main_elf && launch->main_elf_len > 0) {
        memset(&ctx, 0, sizeof(ctx));
        ctx.array = array;
        ctx.load_bias = launch->layout.main_load_bias;
        ctx.source = KBOX_LOADER_MAPPING_MAIN;
        if (kbox_rewrite_visit_elf_planned_sites(
                launch->main_elf, launch->main_elf_len,
                runtime_collect_planned_cb, &ctx, &report) < 0) {
            return -1;
        }
        if (annotate_launch_wrapper_sites(
                array, launch->main_elf, launch->main_elf_len,
                KBOX_LOADER_MAPPING_MAIN, host_nrs) < 0) {
            return -1;
        }
    }

    if (launch->interp_elf && launch->interp_elf_len > 0) {
        memset(&ctx, 0, sizeof(ctx));
        ctx.array = array;
        ctx.load_bias = launch->layout.interp_load_bias;
        ctx.source = KBOX_LOADER_MAPPING_INTERP;
        if (kbox_rewrite_visit_elf_planned_sites(
                launch->interp_elf, launch->interp_elf_len,
                runtime_collect_planned_cb, &ctx, &report) < 0) {
            return -1;
        }
        if (annotate_launch_wrapper_sites(
                array, launch->interp_elf, launch->interp_elf_len,
                KBOX_LOADER_MAPPING_INTERP, host_nrs) < 0) {
            return -1;
        }
    }

    return 0;
}

static int make_exec_mappings_writable(const struct kbox_loader_launch *launch,
                                       int prot_out[KBOX_LOADER_MAX_MAPPINGS])
{
    size_t i;

    if (!launch || !prot_out)
        return -1;

    for (i = 0; i < launch->layout.mapping_count; i++) {
        const struct kbox_loader_mapping *mapping = &launch->layout.mappings[i];

        prot_out[i] = mapping->prot;
        if ((mapping->prot & PROT_EXEC) == 0 || mapping->size == 0)
            continue;
        if (mprotect((void *) (uintptr_t) mapping->addr, (size_t) mapping->size,
                     mapping->prot | PROT_WRITE) != 0) {
            return -1;
        }
    }

    return 0;
}

static void restore_exec_mapping_prot(
    const struct kbox_loader_launch *launch,
    const int prot_in[KBOX_LOADER_MAX_MAPPINGS])
{
    size_t i;

    if (!launch || !prot_in)
        return;

    for (i = 0; i < launch->layout.mapping_count; i++) {
        const struct kbox_loader_mapping *mapping = &launch->layout.mappings[i];

        if ((mapping->prot & PROT_EXEC) == 0 || mapping->size == 0)
            continue;
        mprotect((void *) (uintptr_t) mapping->addr, (size_t) mapping->size,
                 prot_in[i]);
    }
}

static void flush_exec_mappings(const struct kbox_loader_launch *launch)
{
    size_t i;

    if (!launch)
        return;

    for (i = 0; i < launch->layout.mapping_count; i++) {
        const struct kbox_loader_mapping *mapping = &launch->layout.mappings[i];

        if ((mapping->prot & PROT_EXEC) == 0 || mapping->size == 0)
            continue;
        __builtin___clear_cache(
            (char *) (uintptr_t) mapping->addr,
            (char *) (uintptr_t) (mapping->addr + mapping->size));
    }
}

void kbox_rewrite_runtime_reset(struct kbox_rewrite_runtime *runtime)
{
    size_t i;

    if (!runtime)
        return;
    if (load_active_rewrite_runtime() == runtime)
        store_active_rewrite_runtime(NULL);
    for (i = 0; i < runtime->trampoline_region_count; i++) {
        if (runtime->trampoline_regions[i].mapping &&
            runtime->trampoline_regions[i].size > 0) {
            munmap(runtime->trampoline_regions[i].mapping,
                   runtime->trampoline_regions[i].size);
        }
    }
    kbox_rewrite_origin_map_reset(&runtime->origin_map);
    memset(runtime, 0, sizeof(*runtime));
}

int kbox_rewrite_runtime_install(struct kbox_rewrite_runtime *runtime,
                                 struct kbox_supervisor_ctx *ctx,
                                 struct kbox_loader_launch *launch)
{
    struct runtime_site_array array;
    struct x86_64_trampoline_region x86_regions[KBOX_LOADER_MAX_MAPPINGS];
    int prot[KBOX_LOADER_MAX_MAPPINGS];
    size_t i;
    size_t x86_region_count = 0;
    int rc = -1;
    int writable = 0;

    if (!runtime || !ctx || !launch)
        return -1;
    if (launch->transfer.arch != KBOX_LOADER_ENTRY_ARCH_AARCH64 &&
        launch->transfer.arch != KBOX_LOADER_ENTRY_ARCH_X86_64) {
        errno = ENOTSUP;
        return -1;
    }

    memset(&array, 0, sizeof(array));
    memset(x86_regions, 0, sizeof(x86_regions));
    memset(prot, 0, sizeof(prot));
    kbox_rewrite_runtime_reset(runtime);
    runtime->ctx = ctx;
    runtime->arch = launch->transfer.arch == KBOX_LOADER_ENTRY_ARCH_X86_64
                        ? KBOX_REWRITE_ARCH_X86_64
                        : KBOX_REWRITE_ARCH_AARCH64;
    kbox_rewrite_origin_map_init(&runtime->origin_map, runtime->arch);

    if (collect_launch_sites(&array, launch, ctx->host_nrs) < 0) {
        if (ctx->verbose) {
            fprintf(stderr,
                    "kbox: rewrite install: collect_launch_sites failed: %s\n",
                    strerror(errno ? errno : EINVAL));
        }
        goto out;
    }

    if (ctx->verbose) {
        size_t direct_count = 0;
        size_t cancel_count = 0;

        for (i = 0; i < array.count; i++) {
            if (array.sites[i].wrapper_kind ==
                KBOX_REWRITE_WRAPPER_CANDIDATE_SYSCALL_CANCEL)
                cancel_count++;
            else
                direct_count++;
        }
        fprintf(
            stderr,
            "kbox: rewrite install: planned sites=%zu direct=%zu cancel=%zu\n",
            array.count, direct_count, cancel_count);
    }

    if (runtime->arch == KBOX_REWRITE_ARCH_X86_64) {
        for (i = 0; i < array.count; i++) {
            const struct runtime_planned_site *site = &array.sites[i];
            struct x86_64_trampoline_region *region;
            int mapping_index;

            if (site->planned.site.width != X86_64_WRAPPER_SITE_LEN)
                continue;

            mapping_index = find_exec_mapping_index(launch, site->source,
                                                    site->actual_site_addr);
            if (mapping_index < 0) {
                if (errno == 0)
                    errno = EINVAL;
                goto out;
            }
            region = find_x86_64_region(x86_regions, x86_region_count,
                                        (size_t) mapping_index);
            if (region) {
                region->slot_count++;
                continue;
            }

            if (x86_region_count >= KBOX_LOADER_MAX_MAPPINGS) {
                if (errno == 0)
                    errno = ENOSPC;
                goto out;
            }
            x86_regions[x86_region_count].mapping_index =
                (size_t) mapping_index;
            x86_regions[x86_region_count].slot_count = 1;
            x86_region_count++;
        }

        for (i = 0; i < x86_region_count; i++) {
            const struct kbox_loader_mapping *mapping =
                &launch->layout.mappings[x86_regions[i].mapping_index];

            {
                int trc = alloc_x86_64_trampoline_region(
                    runtime, mapping, x86_regions[i].slot_count,
                    &x86_regions[i].base_addr);
                if (trc < 0)
                    goto out;
            }
        }
    } else {
        for (i = 0; i < array.count; i++) {
            const struct runtime_planned_site *site = &array.sites[i];
            const struct kbox_loader_mapping *mapping =
                find_exec_mapping(launch, site->source, site->actual_site_addr);
            uint64_t mapping_end;
            uint64_t tramp_end;
            struct kbox_rewrite_site actual_site;

            if (!mapping) {
                if (errno == 0)
                    errno = EINVAL;
                goto out;
            }
            if (__builtin_add_overflow(mapping->addr, mapping->size,
                                       &mapping_end)) {
                if (errno == 0)
                    errno = EOVERFLOW;
                goto out;
            }
            if (__builtin_add_overflow(site->actual_trampoline_addr,
                                       (uint64_t) AARCH64_REWRITE_SLOT_SIZE,
                                       &tramp_end)) {
                if (errno == 0)
                    errno = EOVERFLOW;
                goto out;
            }
            if (site->actual_trampoline_addr < mapping->addr ||
                tramp_end > mapping_end) {
                errno = ENOSPC;
                goto out;
            }

            if (!rewrite_runtime_should_patch_site(runtime, site))
                continue;

            actual_site = site->planned.site;
            actual_site.vaddr = site->actual_site_addr;
            if (kbox_rewrite_origin_map_add_classified(
                    &runtime->origin_map, &actual_site, site->source,
                    site->planned.site.site_class) < 0) {
                if (ctx->verbose) {
                    fprintf(stderr,
                            "kbox: rewrite install: origin-map add failed "
                            "site=0x%llx tramp=0x%llx nr=%llu kind=%d: %s\n",
                            (unsigned long long) site->actual_site_addr,
                            (unsigned long long) site->actual_trampoline_addr,
                            (unsigned long long) site->wrapper_nr,
                            (int) site->wrapper_kind,
                            strerror(errno ? errno : EINVAL));
                }
                if (errno == 0)
                    errno = EINVAL;
                goto out;
            }
        }
    }

    if (make_exec_mappings_writable(launch, prot) < 0)
        goto out;
    writable = 1;

    /* Pass 1: verify all instruction bytes match before writing anything.
     * If any site has been modified (e.g., by a JIT or concurrent loader),
     * we abort without leaving the binary in a half-patched state.
     */
    for (i = 0; i < array.count; i++) {
        const struct runtime_planned_site *site = &array.sites[i];
        const unsigned char *patch_ptr =
            (const unsigned char *) (uintptr_t) site->actual_site_addr;

        if (runtime->arch == KBOX_REWRITE_ARCH_AARCH64) {
            if (!rewrite_runtime_should_patch_site(runtime, site))
                continue;
            if (memcmp(patch_ptr, site->planned.site.original,
                       site->planned.site.width) != 0) {
                errno = EIO;
                goto out;
            }
        } else if (site->planned.site.width == X86_64_WRAPPER_SITE_LEN) {
            if (memcmp(patch_ptr, site->planned.site.original,
                       site->planned.site.width) != 0) {
                errno = EIO;
                goto out;
            }
        }
    }

    /* Pass 2: write trampolines and apply patches.  All sites have been
     * verified, so failures here are internal errors (bad trampoline
     * encoding, origin map allocation).
     */
    uint64_t veneer_page_base = 0;
    size_t veneer_page_used = 0;
    size_t veneer_page_cap = 0;

    for (i = 0; i < array.count; i++) {
        const struct runtime_planned_site *site = &array.sites[i];
        unsigned char *patch_ptr =
            (unsigned char *) (uintptr_t) site->actual_site_addr;
        struct kbox_rewrite_patch patch;

        if (runtime->arch == KBOX_REWRITE_ARCH_AARCH64) {
            if (!rewrite_runtime_should_patch_site(runtime, site))
                continue;
            if (write_aarch64_trampoline(site->actual_trampoline_addr,
                                         site->actual_site_addr,
                                         site->wrapper_kind) < 0) {
                if (ctx->verbose) {
                    fprintf(stderr,
                            "kbox: rewrite install: trampoline write failed "
                            "site=0x%llx tramp=0x%llx nr=%llu kind=%d: %s\n",
                            (unsigned long long) site->actual_site_addr,
                            (unsigned long long) site->actual_trampoline_addr,
                            (unsigned long long) site->wrapper_nr,
                            (int) site->wrapper_kind,
                            strerror(errno ? errno : EINVAL));
                }
                goto out;
            }
            patch = site->planned.patch;
            /* If the pre-computed B patch is empty (range overflow during
             * planning), use a veneer near the SVC site to bridge the gap:
             * SVC site -> B veneer -> LDR+BR trampoline.
             * Reuse existing veneer pages when they have capacity and
             * are within B range of the current site.
             */
            if (patch.width == 0) {
                uint64_t veneer_addr;
                int64_t vdelta;
                int reuse = 0;

                if (veneer_page_cap > 0 && veneer_page_used < veneer_page_cap) {
                    veneer_addr = veneer_page_base +
                                  veneer_page_used * AARCH64_VENEER_SIZE;
                    vdelta = (int64_t) veneer_addr -
                             (int64_t) site->actual_site_addr;
                    if (vdelta > -AARCH64_B_RANGE && vdelta < AARCH64_B_RANGE)
                        reuse = 1;
                }
                if (!reuse) {
                    uint64_t page_size = (uint64_t) sysconf(_SC_PAGESIZE);
                    if (alloc_aarch64_veneer_page(runtime,
                                                  site->actual_site_addr,
                                                  &veneer_page_base) < 0) {
                        goto out;
                    }
                    veneer_page_used = 0;
                    veneer_page_cap =
                        page_size > 0
                            ? (size_t) (page_size / AARCH64_VENEER_SIZE)
                            : 1;
                    veneer_addr = veneer_page_base;
                }
                if (write_aarch64_veneer(veneer_addr,
                                         site->actual_trampoline_addr) < 0) {
                    goto out;
                }
                veneer_page_used++;
                if (encode_aarch64_b_to_veneer(site->actual_site_addr,
                                               veneer_addr, &patch) < 0) {
                    goto out;
                }
            }
        } else if (site->planned.site.width == X86_64_WRAPPER_SITE_LEN) {
            struct x86_64_trampoline_region *region;
            struct kbox_rewrite_site actual_site = site->planned.site;
            uint64_t trampoline_addr;
            int mapping_index = find_exec_mapping_index(launch, site->source,
                                                        site->actual_site_addr);

            if (mapping_index < 0) {
                if (errno == 0)
                    errno = EINVAL;
                goto out;
            }
            region = find_x86_64_region(x86_regions, x86_region_count,
                                        (size_t) mapping_index);
            if (!region) {
                if (errno == 0)
                    errno = ENOENT;
                goto out;
            }
            trampoline_addr =
                region->base_addr +
                region->used_slots * X86_64_REWRITE_WRAPPER_SLOT_SIZE;
            region->used_slots++;
            if (write_x86_64_wrapper_trampoline(
                    trampoline_addr, site->actual_site_addr,
                    x86_64_wrapper_syscall_nr(site->planned.site.original)) <
                0) {
                goto out;
            }
            actual_site.vaddr = site->actual_site_addr;
            if (kbox_rewrite_origin_map_add_classified(
                    &runtime->origin_map, &actual_site, site->source,
                    site->planned.site.site_class) < 0) {
                if (errno == 0)
                    errno = EINVAL;
                goto out;
            }
            if (kbox_rewrite_encode_patch(&actual_site, trampoline_addr,
                                          &patch) < 0) {
                goto out;
            }
        } else {
            continue;
        }
        memcpy(patch_ptr, patch.bytes, patch.width);
    }

    for (i = 0; i < runtime->trampoline_region_count; i++) {
        struct kbox_rewrite_runtime_trampoline_region *region =
            &runtime->trampoline_regions[i];

        if (!region->mapping || region->size == 0)
            continue;
        if (mprotect(region->mapping, region->size, PROT_READ | PROT_EXEC) !=
            0) {
            if (errno == 0)
                errno = ENOMEM;
            goto out;
        }
        __builtin___clear_cache((char *) region->mapping,
                                (char *) region->mapping + region->size);
    }

    flush_exec_mappings(launch);
    restore_exec_mapping_prot(launch, prot);
    writable = 0;
    if (kbox_rewrite_origin_map_seal(&runtime->origin_map) < 0)
        goto out;
    store_active_rewrite_runtime(runtime);
    runtime->installed = 1;
    rc = 0;

out:
    if (writable)
        restore_exec_mapping_prot(launch, prot);
    if (rc < 0)
        kbox_rewrite_runtime_reset(runtime);
    runtime_site_array_reset(&array);
    return rc;
}
