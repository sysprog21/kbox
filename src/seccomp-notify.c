/* SPDX-License-Identifier: MIT */
/*
 * seccomp-notify.c - ioctl wrappers for seccomp user notifications.
 *
 * Thin wrappers around the three seccomp-unotify ioctls:
 *   SECCOMP_IOCTL_NOTIF_RECV   - receive a notification
 *   SECCOMP_IOCTL_NOTIF_SEND   - send a response
 *   SECCOMP_IOCTL_NOTIF_ADDFD  - inject an FD into the tracee
 *
 */

#include "kbox/seccomp.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>

int kbox_notify_recv(int listener_fd, void *notif)
{
    int ret;

    memset(notif, 0, sizeof(struct kbox_seccomp_notif));

    ret = ioctl(listener_fd, KBOX_SECCOMP_IOCTL_NOTIF_RECV, notif);
    if (ret < 0)
        return -errno;
    return 0;
}

int kbox_notify_send(int listener_fd, const void *resp)
{
    int ret;

    ret = ioctl(listener_fd, KBOX_SECCOMP_IOCTL_NOTIF_SEND, resp);
    if (ret < 0)
        return -errno;
    return 0;
}

int kbox_notify_addfd(int listener_fd,
                      uint64_t id,
                      int srcfd,
                      uint32_t newfd_flags)
{
    struct kbox_seccomp_notif_addfd addfd;
    int ret;

    memset(&addfd, 0, sizeof(addfd));
    addfd.id = id;
    addfd.srcfd = (uint32_t) srcfd;
    addfd.newfd = 0; /* kernel picks the FD number */
    addfd.newfd_flags = newfd_flags;
    addfd.flags = 0;

    ret = ioctl(listener_fd, KBOX_SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
    if (ret < 0)
        return -errno;
    return ret; /* remote FD number */
}

int kbox_notify_addfd_at(int listener_fd,
                         uint64_t id,
                         int srcfd,
                         int target_fd,
                         uint32_t newfd_flags)
{
    struct kbox_seccomp_notif_addfd addfd;
    int ret;

    memset(&addfd, 0, sizeof(addfd));
    addfd.id = id;
    addfd.srcfd = (uint32_t) srcfd;
    addfd.newfd = (uint32_t) target_fd;
    addfd.newfd_flags = newfd_flags;
    addfd.flags = 1; /* SECCOMP_ADDFD_FLAG_SETFD: install at exact newfd */

    ret = ioctl(listener_fd, KBOX_SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
    if (ret < 0)
        return -errno;
    return ret;
}
