/* SPDX-License-Identifier: MIT */
#ifndef KBOX_NET_H
#define KBOX_NET_H

/*
 * net.h - Networking support via minislirp.
 *
 * Provides user-mode networking for the LKL guest using SLIRP.
 * Creates a virtio-net device backed by SLIRP, configures the
 * guest interface, and bridges LKL I/O with SLIRP's event loop.
 *
 * Guest network config:
 *   IP:      10.0.2.15/24
 *   Gateway: 10.0.2.2
 *   DNS:     10.0.2.3
 *
 * Limitations:
 *   - Server-side sockets (bind/listen/accept) are not supported
 *     in the initial implementation.
 *   - Unprivileged ICMP: minislirp synthesizes replies for
 *     localhost; external ICMP may not work without CAP_NET_RAW.
 */

#include "kbox/syscall-nr.h"

/*
 * Register the LKL virtio-net device and start SLIRP.
 *
 * Must be called BEFORE lkl_start_kernel because LKL probes
 * netdev during boot.  Creates pipes, SLIRP instance, event loop
 * thread, and registers the netdev with LKL.
 *
 * Returns 0 on success, -1 on error.
 */
int kbox_net_add_device(void);

/*
 * Configure the guest network interface.
 *
 * Must be called AFTER kernel boot and sysnrs detection.
 * Brings the interface up, sets IP/gateway/DNS.
 *
 * Returns 0 on success, -1 on error.
 */
int kbox_net_configure(const struct kbox_sysnrs *sysnrs);

/*
 * Tear down SLIRP networking.
 *
 * Shuts down the SLIRP instance and frees resources.
 * Called during cleanup, after the supervisor loop exits.
 */
void kbox_net_cleanup(void);

/*
 * Register a shadow socket with the SLIRP event loop.
 *
 * The event loop pumps data between supervisor_fd (one end of a
 * socketpair visible to the supervisor) and lkl_fd (the LKL-side
 * socket).  sock_type is SOCK_STREAM or SOCK_DGRAM.
 *
 * Returns 0 on success, -1 on error.
 */
/*
 * Returns 1 if SLIRP networking is initialized and active.
 */
int kbox_net_is_active(void);

int kbox_net_register_socket(int lkl_fd, int supervisor_fd, int sock_type);

/*
 * Deregister a shadow socket from the SLIRP event loop.
 *
 * Called when the tracee closes a shadow socket FD.
 * Matches by LKL FD since the supervisor_fd is internal
 * to the event loop.
 */
void kbox_net_deregister_socket(int lkl_fd);

#endif /* KBOX_NET_H */
