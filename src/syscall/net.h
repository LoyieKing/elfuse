/*
 * Socket/networking syscalls
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Translates Linux socket syscalls into macOS equivalents, handling the
 * differences in address family constants, sockaddr layout (sa_len byte),
 * socket option constants, and flag encoding (SOCK_NONBLOCK/SOCK_CLOEXEC packed
 * into the type argument).
 */

#pragma once

#include <stdint.h>
#include "core/guest.h"
#include "syscall/linux-wire.h" /* linux_iovec_t */
#include "syscall/internal.h"   /* fd_block_state_t */

struct msghdr;
struct sockaddr_storage;

/* Linux address families. */
#define LINUX_AF_UNSPEC 0
#define LINUX_AF_UNIX 1
#define LINUX_AF_INET 2
#define LINUX_AF_INET6 10
#define LINUX_AF_NETLINK 16

/* Linux Netlink protocol families. */
#define NETLINK_ROUTE 0
#define NETLINK_KOBJECT_UEVENT 15

/* Linux socket types + flags. */
#define LINUX_SOCK_STREAM 1
#define LINUX_SOCK_DGRAM 2
#define LINUX_SOCK_RAW 3
#define LINUX_SOCK_SEQPACKET 5
#define LINUX_SOCK_NONBLOCK 0x800
#define LINUX_SOCK_CLOEXEC 0x80000
/* SOCK_TYPE_MASK: the base type, with the two flag bits above masked off. */
#define LINUX_SOCK_TYPE_MASK 0xF

/* Linux SOL_SOCKET option level. */
#define LINUX_SOL_SOCKET 1

/* Linux SOL_NETLINK option level and the optnames netlink_setsockopt() and
 * netlink_getsockopt() answer. NETLINK_RX_RING/TX_RING (6/7) are deliberately
 * absent: mmap'd netlink was removed in Linux 4.10 and both spellings have
 * reported ENOPROTOOPT ever since, which is the default arm here.
 */
#define LINUX_SOL_NETLINK 270
#define LINUX_NETLINK_ADD_MEMBERSHIP 1
#define LINUX_NETLINK_DROP_MEMBERSHIP 2
#define LINUX_NETLINK_PKTINFO 3
#define LINUX_NETLINK_BROADCAST_ERROR 4
#define LINUX_NETLINK_NO_ENOBUFS 5
#define LINUX_NETLINK_LISTEN_ALL_NSID 8
#define LINUX_NETLINK_LIST_MEMBERSHIPS 9
#define LINUX_NETLINK_CAP_ACK 10
#define LINUX_NETLINK_EXT_ACK 11
#define LINUX_NETLINK_GET_STRICT_CHK 12

/* Linux cmsg types for AF_UNIX. */
#define LINUX_SCM_CREDENTIALS 2

/* Linux ucred structure (12 bytes on aarch64). */
typedef struct {
    int32_t pid;
    uint32_t uid, gid;
} linux_ucred_t;

/* Linux SOL_SOCKET option names (differ from macOS!) */
#define LINUX_SO_DEBUG 1
#define LINUX_SO_REUSEADDR 2
#define LINUX_SO_TYPE 3
#define LINUX_SO_ERROR 4
#define LINUX_SO_DONTROUTE 5
#define LINUX_SO_BROADCAST 6
#define LINUX_SO_SNDBUF 7
#define LINUX_SO_RCVBUF 8
#define LINUX_SO_KEEPALIVE 9
#define LINUX_SO_OOBINLINE 10
#define LINUX_SO_LINGER 13

/* 20/21 are the _OLD spellings, carrying a __kernel_old_timeval; 66/67 are the
 * y2038 _NEW ones, carrying a __kernel_sock_timeval. Both are 16 bytes on LP64,
 * so the two pairs differ only in name for the guest ABI elfuse targets.
 */
#define LINUX_SO_RCVTIMEO 20
#define LINUX_SO_SNDTIMEO 21
#define LINUX_SO_RCVTIMEO_NEW 66
#define LINUX_SO_SNDTIMEO_NEW 67
#define LINUX_SO_PASSCRED 16
#define LINUX_SO_PEERCRED 17
#define LINUX_SO_ACCEPTCONN 30
#define LINUX_SO_REUSEPORT 15
#define LINUX_SO_RCVLOWAT 18
#define LINUX_SO_SNDLOWAT 19
#define LINUX_SO_PROTOCOL 38
#define LINUX_SO_DOMAIN 39

/* Linux TCP level options. */
#define LINUX_IPPROTO_TCP 6
#define LINUX_TCP_NODELAY 1
#define LINUX_TCP_KEEPIDLE 4 /* -> macOS TCP_KEEPALIVE */
#define LINUX_TCP_KEEPINTVL 5
#define LINUX_TCP_KEEPCNT 6

/* Linux IP/IPv6 level options. */
#define LINUX_IPPROTO_IP 0
#define LINUX_IPPROTO_IPV6 41
#define LINUX_IP_TOS 1
#define LINUX_IP_TTL 2
#define LINUX_IP_HDRINCL 3
#define LINUX_IP_PKTINFO 8
#define LINUX_IP_MTU_DISCOVER 10
#define LINUX_IP_RECVERR 11
#define LINUX_IP_RECVTTL 12
#define LINUX_IP_RECVTOS 13
#define LINUX_IPV6_V6ONLY 26

/* Linux msghdr (aarch64). */
typedef struct {
    uint64_t msg_name; /* Guest pointer to sockaddr */
    uint32_t msg_namelen, _pad0;
    uint64_t msg_iov; /* Guest pointer to iovec array */
    uint64_t msg_iovlen;
    uint64_t msg_control; /* Guest pointer to ancillary data */
    uint64_t msg_controllen;
    int32_t msg_flags, _pad1;
} linux_msghdr_t;

/* Linux mmsghdr (for sendmmsg/recvmmsg). */
typedef struct {
    linux_msghdr_t msg_hdr;
    uint32_t msg_len, _pad;
} linux_mmsghdr_t;

/* Socket syscall handlers. */

int64_t sys_socket(guest_t *g, int domain, int type, int protocol);
int64_t sys_socketpair(guest_t *g,
                       int domain,
                       int type,
                       int protocol,
                       uint64_t sv_gva);
int64_t sys_bind(guest_t *g, int fd, uint64_t addr_gva, uint32_t addrlen);
int64_t sys_listen(int fd, int backlog);
int64_t sys_accept(guest_t *g, int fd, uint64_t addr_gva, uint64_t addrlen_gva);
int64_t sys_accept4(guest_t *g,
                    int fd,
                    uint64_t addr_gva,
                    uint64_t addrlen_gva,
                    int flags);
int64_t sys_connect(guest_t *g, int fd, uint64_t addr_gva, uint32_t addrlen);
int64_t sys_getsockname(guest_t *g,
                        int fd,
                        uint64_t addr_gva,
                        uint64_t addrlen_gva);
int64_t sys_getpeername(guest_t *g,
                        int fd,
                        uint64_t addr_gva,
                        uint64_t addrlen_gva);
int64_t sys_sendto(guest_t *g,
                   int fd,
                   uint64_t buf_gva,
                   uint64_t len,
                   int flags,
                   uint64_t dest_gva,
                   uint32_t addrlen);
int64_t sys_recvfrom(guest_t *g,
                     int fd,
                     uint64_t buf_gva,
                     uint64_t len,
                     int flags,
                     uint64_t src_gva,
                     uint64_t addrlen_gva);
int64_t sys_setsockopt(guest_t *g,
                       int fd,
                       int level,
                       int optname,
                       uint64_t optval_gva,
                       uint32_t optlen);
int64_t sys_getsockopt(guest_t *g,
                       int fd,
                       int level,
                       int optname,
                       uint64_t optval_gva,
                       uint64_t optlen_gva);
int64_t sys_shutdown(int fd, int how);

/* Wait for a blocking socket op (recv/accept/connect/send) to become ready for
 * events (POLLIN/POLLOUT) or be interrupted by a guest signal. No-op for
 * nonblocking fds and MSG_DONTWAIT callers (pass msg_flags = 0 for ops without
 * a flags argument).
 *
 * Returns 0 to proceed or a negative Linux errno (EINTR).
 */
int64_t net_wait_or_interrupted(const fd_block_state_t *st,
                                int host_fd,
                                short events,
                                int msg_flags);

/* Preserve transferred bytes while a readiness wait parks. SYSCALL_PARKED
 * propagates to dispatch; interruption returns the partial count at the caller.
 */
int64_t net_wait_progress(const fd_block_state_t *st,
                          int host_fd,
                          short events,
                          int msg_flags,
                          uint64_t total);

/* Readiness gate for a zero-payload recv/recvfrom/recvmsg: Linux clamps the
 * receive low-water target to one byte, so an empty socket blocks (EINTR on
 * guest signal) or fails EAGAIN when nonblocking, rather than returning 0 like
 * the macOS host call. Call before the host receive when the resolved payload
 * length is zero.
 *
 * Returns 0 to proceed or a negative Linux errno (EINTR/EAGAIN).
 */
int64_t net_recv_zero_payload_gate(const fd_block_state_t *st,
                                   int host_fd,
                                   int msg_flags);

/* True when a socket send/recv should wait interruptibly and retry on EAGAIN
 * rather than surface it (guest wants blocking semantics: no MSG_DONTWAIT, fd
 * not O_NONBLOCK). Send/recv paths pair this with a per-call MSG_DONTWAIT probe
 * so the interruptible wait cannot be defeated by a post-readiness buffer-full
 * or steal race, without toggling the fd's shared O_NONBLOCK flag.
 */
bool sock_op_should_block(const fd_block_state_t *st,
                          int host_fd,
                          int msg_flags);

/* The guest-visible status flags a socket created with SOCK_NONBLOCK and/or
 * SOCK_CLOEXEC carries.
 *
 * O_NONBLOCK has to be recorded here and not only on the host descriptor:
 * elfuse owns the host flag on every socket it opens (fd_init_entry), so the
 * host flag is set whatever the guest asked for, and the shadow is the only
 * record left. Without it a SOCK_NONBLOCK socket read as blocking everywhere
 * that matters -- F_GETFL reported no O_NONBLOCK, connect waited instead of
 * reporting EINPROGRESS, and a read of an empty socket never returned.
 */
int sock_creation_flags(int nonblock, int cloexec);

/* True when MSG_WAITALL is removed before this recv reaches the host. */
bool recv_strip_waitall(int linux_flags);

/* True when the host socket is SOCK_STREAM; false when it is not or the probe
 * fails.
 */
bool host_socket_is_stream(int host_fd);

/* True when this recv must gather MSG_WAITALL itself. See the definition in
 * net.c for the measurement.
 */
bool recv_gathers_waitall(int host_fd, int linux_flags);

/* True when a socket receive that just reported EAGAIN has to be waited out and
 * retried rather than reported to the guest.
 *
 * elfuse owns O_NONBLOCK on the sockets it opens, so a host recv answers EAGAIN
 * in two cases a blocking guest socket must not see: the readiness the wait
 * reported was taken by a sibling, and MSG_WAITALL with less than the full
 * request queued, which macOS reports as EWOULDBLOCK while consuming nothing.
 * Preserves errno, which the caller reports when this returns false.
 */
bool net_recv_should_retry(const fd_block_state_t *st,
                           int host_fd,
                           int msg_flags,
                           ssize_t ret);

/* Send msg on host_fd with the blocking semantics the guest asked for, without
 * parking this vCPU thread in a host call.
 *
 * The contract is elfuse's own: wait for POLLOUT first, then a send that
 * reports EAGAIN instead of blocking, retried when a sibling took the space
 * first. macOS does not honor MSG_DONTWAIT on AF_UNIX, which is why the wait
 * comes before the send rather than the send driving it. The EAGAIN rests on
 * elfuse owning O_NONBLOCK on the host description, so a description it did not
 * open (one received over SCM_RIGHTS, inherited stdio) keeps its host flag, and
 * a send on it can still park the thread. A blocking stream send goes round
 * again until every byte has moved, as Linux does, and reports the partial
 * count when a signal or an error arrives after some bytes went; MSG_DONTWAIT,
 * a nonblocking socket, and a datagram send take one round. SO_SNDTIMEO is not
 * honored by the wait.
 *
 * msg is scratch: a partial stream send advances its iovec and drops its
 * control data and address, which belong to the first round only.
 *
 * Returns the byte count or a negative Linux errno, with SIGPIPE queued for an
 * EPIPE that moved nothing unless MSG_NOSIGNAL was given.
 */
int64_t net_send_xfer(const fd_block_state_t *st,
                      int host_fd,
                      struct msghdr *msg,
                      int linux_flags);
int64_t sys_sendmsg(guest_t *g, int fd, uint64_t msg_gva, int flags);
int64_t sys_recvmsg(guest_t *g, int fd, uint64_t msg_gva, int flags);
int64_t sys_sendmmsg(guest_t *g,
                     int fd,
                     uint64_t mmsg_gva,
                     unsigned int vlen,
                     int flags);
int64_t sys_recvmmsg(guest_t *g,
                     int fd,
                     uint64_t mmsg_gva,
                     unsigned int vlen,
                     int flags,
                     uint64_t timeout_gva);

/* Netlink emulation. */

/* Initialize netlink subsystem. Called from syscall_init(). */
void netlink_init(void);

/* Create a synthetic netlink socket fd.
 *
 * Returns guest fd, or negative errno. NETLINK_ROUTE (rtnetlink dump emulation)
 * and NETLINK_KOBJECT_UEVENT (silent socket: no events are ever delivered) are
 * supported; other protocols return -EAFNOSUPPORT.
 *
 * type is validated the way __sock_create() and netlink_create() validate it,
 * in that order: an unknown bit outside SOCK_NONBLOCK|SOCK_CLOEXEC is -EINVAL,
 * and a base type other than SOCK_RAW or SOCK_DGRAM is -ESOCKTNOSUPPORT.
 */
int64_t netlink_socket(int protocol, int type);

/* Netlink bind (always succeeds). nl_pid is recorded for getsockname and
 * nl_groups is recorded as a membership mask readable through
 * SOL_NETLINK/NETLINK_LIST_MEMBERSHIPS; no multicast event is ever synthesized
 * to deliver on it.
 */
int64_t netlink_bind(int guest_fd,
                     guest_t *g,
                     uint64_t addr_gva,
                     uint32_t addrlen);

/* setsockopt/getsockopt on a netlink fd. SOL_SOCKET and SOL_NETLINK options are
 * emulated per-fd (never forwarded to a host socket: there is none); other
 * levels report -ENOPROTOOPT.
 */
int64_t netlink_setsockopt(guest_t *g,
                           int guest_fd,
                           int level,
                           int optname,
                           uint64_t optval_gva,
                           uint32_t optlen);

int64_t netlink_getsockopt(guest_t *g,
                           int guest_fd,
                           int level,
                           int optname,
                           uint64_t optval_gva,
                           uint64_t optlen_gva);

/* Netlink sendmsg: parse the request and buffer a response. */
int64_t netlink_sendmsg(int guest_fd, guest_t *g, uint64_t msg_gva, int flags);

/* Netlink recvmsg: return buffered response data. */
int64_t netlink_recvmsg(int guest_fd, guest_t *g, uint64_t msg_gva, int flags);

int64_t netlink_read(int guest_fd,
                     guest_t *g,
                     uint64_t buf_gva,
                     uint64_t count);

int64_t netlink_send(int guest_fd, guest_t *g, uint64_t buf_gva, uint64_t len);

/* Vectored forms of the two above, taking the guest iovec array they stage. One
 * netlink request, and one response, spans the whole iovec: the send gathers
 * every entry into one request and the receive fills every entry from one
 * response, so neither stops at the first entry the way the scalar special fds
 * do.
 */
int64_t netlink_writev(int guest_fd, guest_t *g, uint64_t iov_gva, int iovcnt);

int64_t netlink_readv(int guest_fd, guest_t *g, uint64_t iov_gva, int iovcnt);

int64_t netlink_recv(int guest_fd,
                     guest_t *g,
                     uint64_t buf_gva,
                     uint64_t len,
                     int flags,
                     uint64_t src_gva,
                     uint64_t addrlen_gva);

int64_t netlink_getsockname(int guest_fd,
                            guest_t *g,
                            uint64_t addr_gva,
                            uint64_t addrlen_gva);

/* Clean up abstract socket filesystem entry for a fd being closed. */
void absock_unregister_fd(int guest_fd);

/* Get/set the fork-family identifier shared across fork IPC. The first reader
 * in a process with no id mints one and becomes the family root.
 */
uint64_t absock_get_namespace_id(void);
void absock_set_namespace_id(uint64_t namespace_id);

/* True in the process that minted the family id, the one that owns the family's
 * on-disk state. A fork child never owns it. Calling this in a process that has
 * no family id mints one and returns true, the same as reading the id.
 */
bool absock_namespace_is_owner(void);

/* True when a host sockaddr's pathname is Android's dnsproxyd socket. */
bool dns_bridge_is_proxyd(const struct sockaddr_storage *sa, int len);

/* linux_sa is the guest sockaddr before sysroot translation. When it names
 * /dev/socket/dnsproxyd, mac_sa is replaced with the host listener. Returns 1
 * when replaced, 0 when linux_sa is some other address, -1 with errno set when
 * the listener could not be started.
 */
int dns_bridge_retarget(const uint8_t *linux_sa,
                        uint32_t addrlen,
                        struct sockaddr_storage *mac_sa,
                        int *mac_len);

/* True when sa is the private path the bridge listener is bound to. */
bool dns_bridge_is_listener(const struct sockaddr_storage *sa, int len);
