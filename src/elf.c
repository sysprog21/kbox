/* SPDX-License-Identifier: MIT */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "kbox/elf.h"

#include "io-util.h"

/* Little-endian readers. Use memcpy to avoid unaligned access on architectures
 * that trap on it (ARMv7 without SCTLR.A clear, etc.).
 */
static uint16_t read_le16(const unsigned char *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap16(v);
#endif
    return v;
}

static uint32_t read_le32(const unsigned char *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap32(v);
#endif
    return v;
}

static uint64_t read_le64(const unsigned char *p)
{
    uint64_t v;
    memcpy(&v, p, 8);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap64(v);
#endif
    return v;
}

/* ELF magic: 0x7f 'E' 'L' 'F' */
static const unsigned char elf_magic[4] = {0x7f, 'E', 'L', 'F'};

#define EI_CLASS 4     /* File class byte index */
#define EI_DATA 5      /* Data encoding byte index */
#define ELFCLASS64 2   /* 64-bit objects */
#define ELFDATA2LSB 1  /* 2's complement, little endian */
#define E_TYPE_OFF 16  /* e_type: uint16 */
#define EM_OFF 18      /* e_machine: uint16 */
#define E_ENTRY_OFF 24 /* e_entry: uint64 */
#define PT_INTERP 3    /* Program interpreter */
#define PT_LOAD 1      /* Loadable program segment */
#define PT_PHDR 6      /* Program header table */
#define PT_GNU_STACK 0x6474e551
#define ET_EXEC 2
#define ET_DYN 3
#define PF_R 0x4
#define PF_W 0x2
#define PF_X 0x1 /* Executable segment */

/* ELF64 header field offsets */
#define E_PHOFF_OFF 32     /* e_phoff: uint64 */
#define E_PHENTSIZE_OFF 54 /* e_phentsize: uint16 */
#define E_PHNUM_OFF 56     /* e_phnum: uint16 */

/* ELF64 program header field offsets (relative to phdr start) */
#define P_TYPE_OFF 0    /* p_type: uint32 */
#define P_FLAGS_OFF 4   /* p_flags: uint32 */
#define P_OFFSET_OFF 8  /* p_offset: uint64 */
#define P_VADDR_OFF 16  /* p_vaddr: uint64 */
#define P_FILESZ_OFF 32 /* p_filesz: uint64 */
#define P_MEMSZ_OFF 40  /* p_memsz: uint64 */
#define P_ALIGN_OFF 48  /* p_align: uint64 */

#define MIN_ELF_HDR 64   /* Minimum ELF64 header size */
#define MIN_PHENTSIZE 56 /* Minimum phdr entry size */
#define MAX_ELF_HDR_WINDOW (256u * 1024)

static int is_power_of_two_u64(uint64_t v)
{
    return v != 0 && (v & (v - 1)) == 0;
}

static uint64_t align_down_u64(uint64_t value, uint64_t align)
{
    return value & ~(align - 1);
}

static int align_up_u64(uint64_t value, uint64_t align, uint64_t *out)
{
    uint64_t sum;

    if (__builtin_add_overflow(value, align - 1, &sum))
        return -1;
    *out = align_down_u64(sum, align);
    return 0;
}

static int segment_map_align(uint64_t page_size,
                             uint64_t p_align,
                             uint64_t *out)
{
    uint64_t align = page_size;

    if (!out || !is_power_of_two_u64(page_size))
        return -1;
    if (p_align > 1) {
        if (!is_power_of_two_u64(p_align))
            return -1;
        if (p_align > align)
            align = p_align;
    }
    *out = align;
    return 0;
}

int kbox_parse_elf_interp(const unsigned char *buf,
                          size_t buf_len,
                          char *out,
                          size_t out_size)
{
    return kbox_find_elf_interp_loc(buf, buf_len, out, out_size, NULL, NULL);
}

int kbox_find_elf_interp_loc(const unsigned char *buf,
                             size_t buf_len,
                             char *out,
                             size_t out_size,
                             uint64_t *offset_out,
                             uint64_t *filesz_out)
{
    if (!buf || buf_len < MIN_ELF_HDR || !out || out_size == 0)
        return -1;

    if (memcmp(buf, elf_magic, 4) != 0)
        return -1;

    if (buf[EI_CLASS] != ELFCLASS64 || buf[EI_DATA] != ELFDATA2LSB)
        return -1;

    uint64_t phoff = read_le64(buf + E_PHOFF_OFF);
    uint16_t phentsize = read_le16(buf + E_PHENTSIZE_OFF);
    uint16_t phnum = read_le16(buf + E_PHNUM_OFF);

    if (phentsize < MIN_PHENTSIZE)
        return -1;

    /* Reject if phdr table starts outside the buffer (bogus e_phoff). */
    if (phnum > 0 && phoff >= buf_len)
        return -1;

    for (uint16_t i = 0; i < phnum; i++) {
        uint64_t off;
        uint64_t off_end;

        if (__builtin_add_overflow(phoff, (uint64_t) i * phentsize, &off))
            return -1;
        if (__builtin_add_overflow(off, (uint64_t) MIN_PHENTSIZE, &off_end))
            return -1;
        if (off_end > buf_len)
            break;

        uint32_t p_type = read_le32(buf + off + P_TYPE_OFF);
        if (p_type != PT_INTERP)
            continue;

        uint64_t p_offset = read_le64(buf + off + P_OFFSET_OFF);
        uint64_t p_filesz = read_le64(buf + off + P_FILESZ_OFF);

        if (p_offset >= buf_len)
            return -1;

        /* Reject if PT_INTERP segment extends beyond the mapped ELF. */
        uint64_t end;
        if (__builtin_add_overflow(p_offset, p_filesz, &end) || end > buf_len)
            return -1;

        const unsigned char *s = buf + p_offset;
        size_t slen = (size_t) p_filesz;

        /* Require NUL terminator within the segment. */
        if (slen == 0 || s[slen - 1] != '\0')
            return -1;
        slen--; /* exclude trailing NUL from length */

        if (slen == 0)
            return -1;

        /* Reject if path does not fit in caller's buffer. */
        if (slen >= out_size)
            return -1;
        memcpy(out, s, slen);
        out[slen] = '\0';

        if (offset_out)
            *offset_out = p_offset;
        if (filesz_out)
            *filesz_out = p_filesz;

        return (int) slen;
    }

    return 0;
}

int kbox_elf_machine(const unsigned char *buf,
                     size_t buf_len,
                     uint16_t *machine_out)
{
    if (!buf || buf_len < MIN_ELF_HDR || !machine_out)
        return -1;

    if (memcmp(buf, elf_magic, 4) != 0)
        return -1;

    if (buf[EI_CLASS] != ELFCLASS64 || buf[EI_DATA] != ELFDATA2LSB)
        return -1;

    *machine_out = read_le16(buf + EM_OFF);
    return 0;
}

int kbox_read_elf_header_window_fd(int fd,
                                   unsigned char **buf_out,
                                   size_t *buf_len_out)
{
    unsigned char hdr[MIN_ELF_HDR];
    uint64_t phoff;
    uint16_t phentsize;
    uint16_t phnum;
    uint64_t ph_end;
    size_t size;
    unsigned char *buf;
    ssize_t nr;
    uint64_t interp_end = 0;

    if (fd < 0 || !buf_out || !buf_len_out)
        return -1;

    nr = pread_full(fd, hdr, sizeof(hdr), 0);
    if (nr < (ssize_t) sizeof(hdr)) {
        if (nr >= 0)
            errno = EIO;
        return -1;
    }

    if (memcmp(hdr, elf_magic, 4) != 0)
        return -1;
    if (hdr[EI_CLASS] != ELFCLASS64 || hdr[EI_DATA] != ELFDATA2LSB)
        return -1;

    phoff = read_le64(hdr + E_PHOFF_OFF);
    phentsize = read_le16(hdr + E_PHENTSIZE_OFF);
    phnum = read_le16(hdr + E_PHNUM_OFF);

    if (phentsize < MIN_PHENTSIZE)
        return -1;
    if (__builtin_add_overflow(phoff, (uint64_t) phentsize * phnum, &ph_end))
        return -1;

    size = (size_t) ph_end;
    if (size < sizeof(hdr))
        size = sizeof(hdr);
    if (size > MAX_ELF_HDR_WINDOW) {
        errno = EFBIG;
        return -1;
    }

    /* Use mmap(MAP_ANONYMOUS) instead of malloc.  In trap mode, this
     * function may run from a SIGSYS signal handler where the guest
     * holds glibc heap locks, making malloc unsafe.
     */
    buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
               -1, 0);
    if (buf == MAP_FAILED)
        return -1;

    nr = pread_full(fd, buf, size, 0);
    if (nr < 0 || (size_t) nr != size) {
        munmap(buf, size);
        if (nr >= 0)
            errno = EIO;
        return -1;
    }

    for (uint16_t i = 0; i < phnum; i++) {
        uint64_t off = phoff + (uint64_t) i * phentsize;
        uint32_t p_type;
        uint64_t p_offset;
        uint64_t p_filesz;
        uint64_t end;

        if (off > size || MIN_PHENTSIZE > size - off) {
            munmap(buf, size);
            errno = EIO;
            return -1;
        }
        p_type = read_le32(buf + off + P_TYPE_OFF);
        if (p_type != PT_INTERP)
            continue;
        p_offset = read_le64(buf + off + P_OFFSET_OFF);
        p_filesz = read_le64(buf + off + P_FILESZ_OFF);
        if (__builtin_add_overflow(p_offset, p_filesz, &end)) {
            munmap(buf, size);
            return -1;
        }
        interp_end = end;
        break;
    }

    if (interp_end > size) {
        unsigned char *grown;
        size_t old_size = size;

        if (interp_end > MAX_ELF_HDR_WINDOW) {
            munmap(buf, size);
            errno = EFBIG;
            return -1;
        }
        grown = mmap(NULL, (size_t) interp_end, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (grown == MAP_FAILED) {
            munmap(buf, size);
            return -1;
        }
        munmap(buf, old_size);
        buf = grown;
        nr = pread_full(fd, buf, (size_t) interp_end, 0);
        if (nr < 0 || (uint64_t) nr != interp_end) {
            munmap(buf, (size_t) interp_end);
            if (nr >= 0)
                errno = EIO;
            return -1;
        }
        size = (size_t) interp_end;
    }

    *buf_out = buf;
    *buf_len_out = size;
    return 0;
}

int kbox_build_elf_load_plan(const unsigned char *buf,
                             size_t buf_len,
                             uint64_t page_size,
                             struct kbox_elf_load_plan *plan)
{
    uint64_t phoff;
    uint16_t phentsize;
    uint16_t phnum;
    uint64_t phdr_vaddr = 0;
    int phdr_vaddr_known = 0;

    if (!buf || !plan || buf_len < MIN_ELF_HDR ||
        !is_power_of_two_u64(page_size))
        return -1;

    if (memcmp(buf, elf_magic, 4) != 0)
        return -1;

    if (buf[EI_CLASS] != ELFCLASS64 || buf[EI_DATA] != ELFDATA2LSB)
        return -1;

    memset(plan, 0, sizeof(*plan));
    plan->type = read_le16(buf + E_TYPE_OFF);
    plan->machine = read_le16(buf + EM_OFF);
    plan->entry = read_le64(buf + E_ENTRY_OFF);
    plan->phoff = read_le64(buf + E_PHOFF_OFF);
    plan->phentsize = read_le16(buf + E_PHENTSIZE_OFF);
    plan->phnum = read_le16(buf + E_PHNUM_OFF);
    plan->pie = plan->type == ET_DYN;

    phoff = plan->phoff;
    phentsize = plan->phentsize;
    phnum = plan->phnum;

    if (plan->type != ET_EXEC && plan->type != ET_DYN)
        return -1;
    if (phentsize < MIN_PHENTSIZE)
        return -1;
    if (phnum > 0 && phoff >= buf_len)
        return -1;
    if (__builtin_mul_overflow((uint64_t) phentsize, (uint64_t) phnum,
                               &plan->phdr_size))
        return -1;

    for (uint16_t i = 0; i < phnum; i++) {
        uint64_t off;
        uint64_t off_end;
        uint32_t p_type;
        uint32_t p_flags;
        uint64_t p_offset;
        uint64_t p_vaddr;
        uint64_t p_filesz;
        uint64_t p_memsz;
        uint64_t p_align;
        uint64_t end;

        if (__builtin_add_overflow(phoff, (uint64_t) i * phentsize, &off))
            return -1;
        if (__builtin_add_overflow(off, (uint64_t) MIN_PHENTSIZE, &off_end))
            return -1;
        if (off_end > buf_len)
            return -1;

        p_type = read_le32(buf + off + P_TYPE_OFF);
        p_flags = read_le32(buf + off + P_FLAGS_OFF);
        p_offset = read_le64(buf + off + P_OFFSET_OFF);
        p_vaddr = read_le64(buf + off + P_VADDR_OFF);
        p_filesz = read_le64(buf + off + P_FILESZ_OFF);
        p_memsz = read_le64(buf + off + P_MEMSZ_OFF);
        p_align = read_le64(buf + off + P_ALIGN_OFF);

        if (p_memsz && p_filesz > p_memsz)
            return -1;

        /* Validate that p_offset + p_filesz does not overflow.  We do
         * NOT check against buf_len here because the caller may pass
         * only the ELF header window (phdr table + interp), not the
         * full file.  Segment file-content bounds are validated at map
         * time by the loader.
         */
        if (p_filesz > 0) {
            if (__builtin_add_overflow(p_offset, p_filesz, &end))
                return -1;
        }

        if (p_type == PT_INTERP) {
            plan->has_interp = 1;
            plan->interp_offset = p_offset;
            plan->interp_size = p_filesz;
            continue;
        }

        if (p_type == PT_GNU_STACK) {
            plan->stack_flags = p_flags;
            continue;
        }

        if (p_type == PT_PHDR) {
            phdr_vaddr = p_vaddr;
            phdr_vaddr_known = 1;
            continue;
        }

        if (p_type != PT_LOAD || p_memsz == 0)
            continue;

        if (plan->segment_count >= KBOX_ELF_MAX_LOAD_SEGMENTS)
            return -1;

        {
            struct kbox_elf_load_segment *seg =
                &plan->segments[plan->segment_count];
            uint64_t map_align;
            uint64_t map_start;
            uint64_t map_offset;
            uint64_t map_end;

            if (segment_map_align(page_size, p_align, &map_align) < 0)
                return -1;
            map_start = align_down_u64(p_vaddr, map_align);
            map_offset = align_down_u64(p_offset, map_align);
            if (__builtin_add_overflow(p_vaddr, p_memsz, &end))
                return -1;
            if (align_up_u64(end, map_align, &map_end) < 0)
                return -1;
            if (map_end < map_start)
                return -1;

            seg->file_offset = p_offset;
            seg->file_size = p_filesz;
            seg->vaddr = p_vaddr;
            seg->mem_size = p_memsz;
            seg->align = p_align;
            seg->map_align = map_align;
            seg->map_offset = map_offset;
            seg->map_start = map_start;
            seg->map_size = map_end - map_start;
            seg->flags = p_flags;

            if (plan->segment_count == 0 || map_start < plan->min_vaddr)
                plan->min_vaddr = map_start;
            if (plan->segment_count == 0 || map_end > plan->max_vaddr)
                plan->max_vaddr = map_end;
            plan->segment_count++;
        }

        if (!phdr_vaddr_known && plan->phdr_size > 0 &&
            p_filesz >= plan->phdr_size && phoff >= p_offset &&
            phoff - p_offset <= p_filesz - plan->phdr_size) {
            phdr_vaddr = p_vaddr + (phoff - p_offset);
            phdr_vaddr_known = 1;
        }
    }

    if (plan->segment_count == 0)
        return -1;
    if (plan->max_vaddr < plan->min_vaddr)
        return -1;

    plan->load_size = plan->max_vaddr - plan->min_vaddr;
    if (phdr_vaddr_known)
        plan->phdr_vaddr = phdr_vaddr;
    return 0;
}

int kbox_visit_elf_exec_segments(const unsigned char *buf,
                                 size_t buf_len,
                                 kbox_elf_exec_segment_cb cb,
                                 void *opaque)
{
    uint64_t phoff;
    uint16_t phentsize;
    uint16_t phnum;
    int visited = 0;

    if (!buf || !cb || buf_len < MIN_ELF_HDR)
        return -1;

    if (memcmp(buf, elf_magic, 4) != 0)
        return -1;

    if (buf[EI_CLASS] != ELFCLASS64 || buf[EI_DATA] != ELFDATA2LSB)
        return -1;

    phoff = read_le64(buf + E_PHOFF_OFF);
    phentsize = read_le16(buf + E_PHENTSIZE_OFF);
    phnum = read_le16(buf + E_PHNUM_OFF);

    if (phentsize < MIN_PHENTSIZE)
        return -1;

    if (phnum > 0 && phoff >= buf_len)
        return -1;

    for (uint16_t i = 0; i < phnum; i++) {
        uint64_t off;
        uint64_t off_end;
        uint32_t p_type;
        uint32_t p_flags;
        uint64_t p_offset;
        uint64_t p_filesz;
        uint64_t p_vaddr;
        uint64_t p_memsz;
        uint64_t end;
        struct kbox_elf_exec_segment seg;

        if (__builtin_add_overflow(phoff, (uint64_t) i * phentsize, &off))
            return -1;
        if (__builtin_add_overflow(off, (uint64_t) MIN_PHENTSIZE, &off_end))
            return -1;
        if (off_end > buf_len)
            return -1;

        p_type = read_le32(buf + off + P_TYPE_OFF);
        p_flags = read_le32(buf + off + P_FLAGS_OFF);
        if (p_type != PT_LOAD || (p_flags & PF_X) == 0)
            continue;

        p_offset = read_le64(buf + off + P_OFFSET_OFF);
        p_vaddr = read_le64(buf + off + P_VADDR_OFF);
        p_filesz = read_le64(buf + off + P_FILESZ_OFF);
        p_memsz = read_le64(buf + off + P_MEMSZ_OFF);

        if (p_filesz == 0)
            continue;
        if (p_offset >= buf_len)
            return -1;
        if (__builtin_add_overflow(p_offset, p_filesz, &end) || end > buf_len)
            return -1;

        seg.file_offset = p_offset;
        seg.file_size = p_filesz;
        seg.vaddr = p_vaddr;
        seg.mem_size = p_memsz;
        if (cb(&seg, buf + p_offset, opaque) < 0)
            return -1;
        visited++;
    }

    return visited;
}

int kbox_visit_elf_exec_segment_headers(const unsigned char *buf,
                                        size_t buf_len,
                                        kbox_elf_exec_segment_header_cb cb,
                                        void *opaque)
{
    uint64_t phoff;
    uint16_t phentsize;
    uint16_t phnum;
    int visited = 0;

    if (!buf || !cb || buf_len < MIN_ELF_HDR)
        return -1;

    if (memcmp(buf, elf_magic, 4) != 0)
        return -1;

    if (buf[EI_CLASS] != ELFCLASS64 || buf[EI_DATA] != ELFDATA2LSB)
        return -1;

    phoff = read_le64(buf + E_PHOFF_OFF);
    phentsize = read_le16(buf + E_PHENTSIZE_OFF);
    phnum = read_le16(buf + E_PHNUM_OFF);

    if (phentsize < MIN_PHENTSIZE)
        return -1;
    if (phnum > 0 && phoff >= buf_len)
        return -1;

    for (uint16_t i = 0; i < phnum; i++) {
        uint64_t off;
        uint64_t off_end;
        uint32_t p_type;
        uint32_t p_flags;
        struct kbox_elf_exec_segment seg;

        if (__builtin_add_overflow(phoff, (uint64_t) i * phentsize, &off))
            return -1;
        if (__builtin_add_overflow(off, (uint64_t) MIN_PHENTSIZE, &off_end))
            return -1;
        if (off_end > buf_len)
            return -1;

        p_type = read_le32(buf + off + P_TYPE_OFF);
        p_flags = read_le32(buf + off + P_FLAGS_OFF);
        if (p_type != PT_LOAD || (p_flags & PF_X) == 0)
            continue;

        seg.file_offset = read_le64(buf + off + P_OFFSET_OFF);
        seg.file_size = read_le64(buf + off + P_FILESZ_OFF);
        seg.vaddr = read_le64(buf + off + P_VADDR_OFF);
        seg.mem_size = read_le64(buf + off + P_MEMSZ_OFF);

        if (cb(&seg, opaque) < 0)
            return -1;
        visited++;
    }

    return visited;
}
