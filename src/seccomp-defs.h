/* SPDX-License-Identifier: MIT */

#ifndef KBOX_SECCOMP_DEFS_H
#define KBOX_SECCOMP_DEFS_H

#include <stdint.h>

#define KBOX_BPF_LD 0x00
#define KBOX_BPF_W 0x00
#define KBOX_BPF_ABS 0x20
#define KBOX_BPF_JMP 0x05
#define KBOX_BPF_JEQ 0x10
#define KBOX_BPF_JGT 0x20
#define KBOX_BPF_JGE 0x30
#define KBOX_BPF_K 0x00
#define KBOX_BPF_RET 0x06

#define KBOX_SECCOMP_RET_ALLOW 0x7fff0000U
#define KBOX_SECCOMP_RET_USER_NOTIF 0x7fc00000U
#define KBOX_SECCOMP_RET_TRAP 0x00030000U
#define KBOX_SECCOMP_RET_KILL_PROCESS 0x80000000U
#define KBOX_SECCOMP_RET_ERRNO(err) (0x00050000U | ((err) & 0x0000ffffU))

#define KBOX_SECCOMP_SET_MODE_FILTER 1
#define KBOX_SECCOMP_FILTER_FLAG_NEW_LISTENER 8

#define KBOX_SECCOMP_DATA_NR_OFFSET 0
#define KBOX_SECCOMP_DATA_ARCH_OFFSET 4
#define KBOX_SECCOMP_DATA_IP_LO_OFFSET 8
#define KBOX_SECCOMP_DATA_IP_HI_OFFSET 12
#define KBOX_SECCOMP_DATA_ARG0_LO_OFFSET 16

#if defined(__x86_64__)
#define KBOX_AUDIT_ARCH_CURRENT 0xc000003eU
#elif defined(__aarch64__)
#define KBOX_AUDIT_ARCH_CURRENT 0xc00000b7U
#elif defined(__riscv) && __riscv_xlen == 64
#define KBOX_AUDIT_ARCH_CURRENT 0xc00000f3U
#else
#error "unsupported architecture"
#endif

struct kbox_sock_filter {
    unsigned short code;
    unsigned char jt;
    unsigned char jf;
    unsigned int k;
};

struct kbox_sock_fprog {
    unsigned short len;
    struct kbox_sock_filter *filter;
};

#define KBOX_BPF_STMT(c, val) {(unsigned short) (c), 0, 0, (unsigned int) (val)}

#define KBOX_BPF_JUMP(c, val, t, f)                                  \
    {(unsigned short) (c), (unsigned char) (t), (unsigned char) (f), \
     (unsigned int) (val)}

struct kbox_seccomp_notif {
    uint64_t id;
    uint32_t pid;
    uint32_t flags;
    struct {
        int nr;
        uint32_t arch;
        uint64_t instruction_pointer;
        uint64_t args[6];
    } data;
};

struct kbox_seccomp_notif_resp {
    uint64_t id;
    int64_t val;
    int32_t error;
    uint32_t flags;
};

struct kbox_seccomp_notif_addfd {
    uint64_t id;
    uint32_t flags;
    uint32_t srcfd;
    uint32_t newfd;
    uint32_t newfd_flags;
};

#define _KBOX_IOC(dir, type, nr, size)                                \
    (((unsigned long) (dir) << 30) | ((unsigned long) (size) << 16) | \
     ((unsigned long) (type) << 8) | ((unsigned long) (nr) << 0))

#define _KBOX_IOWR(type, nr, size) _KBOX_IOC(3, (type), (nr), (size))
#define _KBOX_IOW(type, nr, size) _KBOX_IOC(1, (type), (nr), (size))

#define KBOX_SECCOMP_IOCTL_NOTIF_RECV \
    _KBOX_IOWR('!', 0, sizeof(struct kbox_seccomp_notif))

#define KBOX_SECCOMP_IOCTL_NOTIF_SEND \
    _KBOX_IOWR('!', 1, sizeof(struct kbox_seccomp_notif_resp))

#define KBOX_SECCOMP_IOCTL_NOTIF_ADDFD \
    _KBOX_IOW('!', 3, sizeof(struct kbox_seccomp_notif_addfd))

#define KBOX_NOTIF_FLAG_CONTINUE 0x00000001U

_Static_assert(sizeof(struct kbox_seccomp_notif) == 80,
               "kbox_seccomp_notif must be 80 bytes (kernel ABI)");
_Static_assert(sizeof(struct kbox_seccomp_notif_resp) == 24,
               "kbox_seccomp_notif_resp must be 24 bytes (kernel ABI)");
_Static_assert(sizeof(struct kbox_seccomp_notif_addfd) == 24,
               "kbox_seccomp_notif_addfd must be 24 bytes (kernel ABI)");

#endif /* KBOX_SECCOMP_DEFS_H */
