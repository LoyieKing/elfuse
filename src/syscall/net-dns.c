/*
 * Host DNS bridge for Android's /dev/socket/dnsproxyd
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Bionic does not read resolv.conf. getaddrinfo, gethostbyname, gethostbyaddr,
 * res_nsend and getdnsnetid all open this socket and, when the connect fails,
 * fall back to a resolver whose nscount stays 0, which is the
 * UnknownHostException the guest reports. This file is the listener that
 * socket stands in for.
 *
 * connect() to that pathname is retargeted at a private listener. The guest fd
 * itself is what connects, so dup and fork keep sharing the one description,
 * and getpeername still reports /dev/socket/dnsproxyd. One listener thread
 * accepts, and each connection is served by a thread that exits when the reply
 * is written. The cap on those threads is a safety bound.
 *
 * Names are resolved with the host resolver, which follows the host's own
 * routing. Nothing here invents an address, pins a nameserver, or turns a
 * lookup failure into an empty success.
 */
#include <sys/un.h>
#include <sys/stat.h>

#include <resolv.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "debug/log.h"
#include "syscall/internal.h"
#include "syscall/net.h"

/* Leaf: the table is touched only to publish or drop a connection, and that
 * work calls nothing else that takes a lock. See the leaf list in internal.h.
 */
static pthread_mutex_t dns_bridge_lock = PTHREAD_MUTEX_INITIALIZER;

/* Android FrameworkListener reads one command of at most this many bytes and
 * demands a trailing NUL inside it. A larger write is "Command too large".
 */
#define DNS_CMD_MAX 4096

/* res_nsend answers are one DNS message. 8 KiB is Bionic's MAXPACKET and the
 * largest answer the client will accept into its own buffer.
 */
#define DNS_ANS_MAX 8192

/* One in-flight lookup per connection, and a cap on connections so a guest
 * that connects in a loop cannot mint host threads without bound. A safety
 * bound, not an ABI one: well above any app's resolver concurrency.
 */
#define DNS_MAX_CONN 64

/* How many addresses one reply will carry. Past this the rest are dropped,
 * which is a truncation, not a fabricated result.
 */
#define DNS_MAX_ADDR 32

/* Aliases one hostent will carry, counting the terminating empty length. */
#define DNS_MAX_ALIAS 16

/* getaddrinfo canonname and hostent name, aliases included. */
#define DNS_NAME_MAX 1025

#define DNS_CODE_RESULT "222"
#define DNS_CODE_FAILED "401"
#define DNS_CODE_BAD_ARG "501"
#define DNS_CODE_TOO_BIG "500"

#define NETID_UNSET 0u
#define NETID_USE_LOCAL_NAMESERVERS 0x80000000u

/* Linux sockaddr sizes, fixed by the UAPI and independent of the host's
 * sa_len-bearing layouts. sockaddr_in is 16, sockaddr_in6 is 28.
 */
#define LINUX_SIN_LEN 16u
#define LINUX_SIN6_LEN 28u

static int dns_listen_fd = -1;
static int dns_workers;
static char dns_path[sizeof(((struct sockaddr_un *) 0)->sun_path)];
static char dns_dir[64];
static pthread_once_t dns_once = PTHREAD_ONCE_INIT;
/* res_send shares one process-global resolver. Leaf: held only around that
 * call, which takes none of the locks in internal.h.
 */
static pthread_mutex_t dns_resolv_lock = PTHREAD_MUTEX_INITIALIZER;

static int dns_write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EPIPE;
            return -1;
        }
        off += (size_t) n;
    }
    return 0;
}

static int dns_write_be32(int fd, uint32_t value)
{
    uint32_t be = htonl(value);
    return dns_write_all(fd, &be, sizeof(be));
}

static int dns_write_code(int fd, const char *code)
{
    /* Three ASCII digits and the NUL SocketClient::sendCode always sends. */
    char buf[4];
    memcpy(buf, code, 3);
    buf[3] = '\0';
    return dns_write_all(fd, buf, sizeof(buf));
}

static int dns_write_len_data(int fd, const void *data, uint32_t len)
{
    if (dns_write_be32(fd, len) < 0)
        return -1;
    if (len == 0)
        return 0;
    return dns_write_all(fd, data, len);
}

/* Decode the base64 res_nsend uses. Returns the decoded length, or -1 when
 * the alphabet, the padding, or the output cap is wrong. No allocation.
 */
static int dns_b64_decode(const char *src, uint8_t *dst, size_t dst_cap)
{
    static const int8_t table[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57,
        58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,
        7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1,
        -1, -1,
    };
    size_t out = 0;
    uint32_t val = 0;
    int valb = -8;
    int pads = 0;
    bool ended = false;
    for (const unsigned char *p = (const unsigned char *) src; *p; p++) {
        if (*p == '=') {
            pads++;
            ended = true;
            if (pads > 2)
                return -1;
            continue;
        }
        if (ended)
            return -1;
        int8_t d = table[*p];
        if (d < 0)
            return -1;
        val = (val << 6) | (uint32_t) d;
        valb += 6;
        if (valb >= 0) {
            if (out >= dst_cap)
                return -1;
            dst[out++] = (uint8_t) ((val >> valb) & 0xff);
            valb -= 8;
            val &= 0xffffu;
        }
    }
    if (pads == 1 && valb != -6)
        return -1;
    if (pads == 2 && valb != -4)
        return -1;
    if (pads == 0 && valb != -8)
        return -1;
    return (int) out;
}


/* Pack one macOS address into the Linux sockaddr Bionic copies verbatim.
 * Returns the byte count, or 0 for a family the proxy does not return.
 */
static uint32_t dns_linux_sockaddr(const struct sockaddr *sa,
                                   socklen_t len,
                                   uint8_t *out,
                                   uint32_t cap)
{
    if (!sa)
        return 0;
    if (sa->sa_family == AF_INET &&
        len >= (socklen_t) sizeof(struct sockaddr_in)) {
        if (cap < LINUX_SIN_LEN)
            return 0;
        const struct sockaddr_in *in = (const struct sockaddr_in *) sa;
        memset(out, 0, LINUX_SIN_LEN);
        uint16_t fam = LINUX_AF_INET;
        memcpy(out, &fam, 2);
        memcpy(out + 2, &in->sin_port, 2);
        memcpy(out + 4, &in->sin_addr, 4);
        return LINUX_SIN_LEN;
    }
    if (sa->sa_family == AF_INET6 &&
        len >= (socklen_t) sizeof(struct sockaddr_in6)) {
        if (cap < LINUX_SIN6_LEN)
            return 0;
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *) sa;
        memset(out, 0, LINUX_SIN6_LEN);
        uint16_t fam = LINUX_AF_INET6;
        memcpy(out, &fam, 2);
        memcpy(out + 2, &in6->sin6_port, 2);
        memcpy(out + 4, &in6->sin6_flowinfo, 4);
        memcpy(out + 8, &in6->sin6_addr, 16);
        memcpy(out + 24, &in6->sin6_scope_id, 4);
        return LINUX_SIN6_LEN;
    }
    return 0;
}

static int dns_guest_flags(int flags);
static int dns_host_flags(int flags, bool *bad);
static int dns_host_family(int family);

static int dns_send_addrinfo(int fd, const struct addrinfo *ai)
{
    int family = ai->ai_family == AF_INET6 ? LINUX_AF_INET6 : ai->ai_family;
    int rflags = dns_guest_flags(ai->ai_flags);
    if (dns_write_be32(fd, (uint32_t) rflags) < 0 ||
        dns_write_be32(fd, (uint32_t) family) < 0 ||
        dns_write_be32(fd, (uint32_t) ai->ai_socktype) < 0 ||
        dns_write_be32(fd, (uint32_t) ai->ai_protocol) < 0)
        return -1;
    uint8_t raw[128];
    uint32_t addr_len = dns_linux_sockaddr(ai->ai_addr, ai->ai_addrlen, raw,
                                           (uint32_t) sizeof(raw));
    if (ai->ai_addr && addr_len == 0)
        return -1;
    if (dns_write_len_data(fd, raw, addr_len) < 0)
        return -1;

    if (ai->ai_canonname) {
        size_t n = strlen(ai->ai_canonname);
        if (n >= DNS_NAME_MAX)
            return -1;
        return dns_write_len_data(fd, ai->ai_canonname, (uint32_t) n + 1);
    }
    return dns_write_be32(fd, 0);
}

/* Values from bionic/libc/include/netdb.h, checked against the macOS SDK.
 * PASSIVE, CANONNAME, NUMERICHOST, ALL, V4MAPPED_CFG, ADDRCONFIG and
 * V4MAPPED use the same bits on both. NUMERICSERV does not: Bionic puts it
 * at 0x8 and macOS at 0x1000. A bit outside this set is EAI_BADFLAGS.
 */
#define LINUX_AI_PASSIVE 0x00000001
#define LINUX_AI_CANONNAME 0x00000002
#define LINUX_AI_NUMERICHOST 0x00000004
#define LINUX_AI_NUMERICSERV 0x00000008
#define LINUX_AI_ALL 0x00000100
#define LINUX_AI_V4MAPPED_CFG 0x00000200
#define LINUX_AI_ADDRCONFIG 0x00000400
#define LINUX_AI_V4MAPPED 0x00000800
#define LINUX_AI_KNOWN                                                         \
    (LINUX_AI_PASSIVE | LINUX_AI_CANONNAME | LINUX_AI_NUMERICHOST |           \
     LINUX_AI_NUMERICSERV | LINUX_AI_ALL | LINUX_AI_V4MAPPED_CFG |             \
     LINUX_AI_ADDRCONFIG | LINUX_AI_V4MAPPED)

static int dns_host_flags(int flags, bool *bad)
{
    *bad = false;
    if (flags < 0)
        return 0;
    if ((flags & ~LINUX_AI_KNOWN) != 0) {
        *bad = true;
        return 0;
    }
    int out = flags & ~LINUX_AI_NUMERICSERV;
    if (flags & LINUX_AI_NUMERICSERV)
        out |= AI_NUMERICSERV;
    return out;
}

static int dns_guest_flags(int flags)
{
    int out = flags & ~AI_NUMERICSERV;
    if (flags & AI_NUMERICSERV)
        out |= LINUX_AI_NUMERICSERV;
    return out;
}

static int dns_host_family(int family)
{
    if (family <= 0)
        return AF_UNSPEC;
    if (family == LINUX_AF_INET6)
        return AF_INET6;
    return family;
}

/* "^" is the proxy's spelling of a NULL pointer. */
static const char *dns_caret(const char *field)
{
    return (field[0] == '^' && field[1] == '\0') ? NULL : field;
}

static bool dns_parse_i32(const char *text, int *out)
{
    char *end = NULL;
    errno = 0;
    long v = strtol(text, &end, 10);
    if (errno || end == text || *end != '\0' || v < (long) INT32_MIN ||
        v > (long) INT32_MAX)
        return false;
    *out = (int) v;
    return true;
}

static bool dns_parse_u32(const char *text, uint32_t *out)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(text, &end, 10);
    if (errno || end == text || *end != '\0' || v > 0xffffffffUL)
        return false;
    *out = (uint32_t) v;
    return true;
}

/* netId 100 is the runtime's virtual default network and means "use the host
 * resolver", which is what NETID_UNSET asks netd for. Any other id is a
 * network this host does not have.
 */
static bool dns_netid_ok(uint32_t netid)
{
    netid &= ~NETID_USE_LOCAL_NAMESERVERS;
    return netid == NETID_UNSET || netid == 100u;
}


static void dns_fail_gai(int fd, int gai_rc)
{
    int32_t be = (int32_t) htonl((uint32_t) gai_rc);
    char buf[8];
    memcpy(buf, DNS_CODE_FAILED, 3);
    buf[3] = '\0';
    memcpy(buf + 4, &be, 4);
    if (dns_write_all(fd, buf, sizeof(buf)) < 0)
        log_warn("dns bridge: failed to report lookup error");
}

static void dns_cmd_getaddrinfo(int fd, int argc, char **argv)
{
    if (argc != 8) {
        dns_write_code(fd, DNS_CODE_BAD_ARG);
        return;
    }
    int flags = 0, family = 0, socktype = 0, protocol = 0;
    uint32_t netid = 0;
    if (!dns_parse_i32(argv[3], &flags) || !dns_parse_i32(argv[4], &family) ||
        !dns_parse_i32(argv[5], &socktype) ||
        !dns_parse_i32(argv[6], &protocol) || !dns_parse_u32(argv[7], &netid)) {
        dns_write_code(fd, DNS_CODE_BAD_ARG);
        return;
    }
    if (!dns_netid_ok(netid)) {
        dns_fail_gai(fd, EAI_FAIL);
        return;
    }

    const char *host = dns_caret(argv[1]);
    const char *serv = dns_caret(argv[2]);
    struct addrinfo hints;
    struct addrinfo *hintp = NULL;
    if (flags != -1 || family != -1 || socktype != -1 || protocol != -1) {
        memset(&hints, 0, sizeof(hints));
        bool bad_flags = false;
        hints.ai_flags = dns_host_flags(flags, &bad_flags);
        if (bad_flags) {
            dns_fail_gai(fd, EAI_BADFLAGS);
            return;
        }
        hints.ai_family = dns_host_family(family);
        hints.ai_socktype = socktype == -1 ? 0 : socktype;
        hints.ai_protocol = protocol == -1 ? 0 : protocol;
        hintp = &hints;
    }

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, serv, hintp, &res);
    if (rc != 0) {
        dns_fail_gai(fd, rc);
        return;
    }

    if (dns_write_code(fd, DNS_CODE_RESULT) < 0) {
        freeaddrinfo(res);
        return;
    }
    int sent = 0;
    for (struct addrinfo *ai = res; ai && sent < DNS_MAX_ADDR;
         ai = ai->ai_next, sent++) {
        if (dns_write_be32(fd, 1) < 0 || dns_send_addrinfo(fd, ai) < 0) {
            freeaddrinfo(res);
            return;
        }
    }
    if (dns_write_be32(fd, 0) < 0)
        log_warn("dns bridge: failed to terminate getaddrinfo reply");
    freeaddrinfo(res);
}

static int dns_send_hostent(int fd, const struct hostent *hp)
{
    if (!hp->h_name)
        return -1;
    size_t nlen = strlen(hp->h_name);
    if (nlen == 0 || nlen >= DNS_NAME_MAX)
        return -1;
    if (dns_write_len_data(fd, hp->h_name, (uint32_t) nlen + 1) < 0)
        return -1;

    int aliases = 0;
    if (hp->h_aliases) {
        for (char **a = hp->h_aliases; *a && aliases < DNS_MAX_ALIAS - 1;
             a++, aliases++) {
            size_t alen = strlen(*a);
            if (alen >= DNS_NAME_MAX)
                return -1;
            if (dns_write_len_data(fd, *a, (uint32_t) alen + 1) < 0)
                return -1;
        }
    }
    if (dns_write_be32(fd, 0) < 0)
        return -1;

    /* netd always ships 16 address bytes and a v4 address padded out to that,
     * and Bionic copies h_length bytes of them into the hostent buffer.
     */
    int addrtype = hp->h_addrtype;
    int length = hp->h_length;
    if (addrtype == AF_INET) {
        addrtype = LINUX_AF_INET;
        length = 4;
    } else if (addrtype == AF_INET6) {
        addrtype = LINUX_AF_INET6;
        length = 16;
    } else {
        return -1;
    }
    if (dns_write_be32(fd, (uint32_t) addrtype) < 0 ||
        dns_write_be32(fd, (uint32_t) length) < 0)
        return -1;

    int addrs = 0;
    if (hp->h_addr_list) {
        for (char **p = hp->h_addr_list; *p && addrs < DNS_MAX_ADDR;
             p++, addrs++) {
            uint8_t raw[16];
            memset(raw, 0, sizeof(raw));
            size_t copy = (size_t) hp->h_length;
            if (copy > sizeof(raw))
                copy = sizeof(raw);
            memcpy(raw, *p, copy);
            if (dns_write_len_data(fd, raw, 16) < 0)
                return -1;
        }
    }
    if (addrs == 0)
        return -1;
    return dns_write_be32(fd, 0);
}

static void dns_cmd_gethostbyname(int fd, int argc, char **argv)
{
    if (argc != 4) {
        dns_write_code(fd, DNS_CODE_BAD_ARG);
        return;
    }
    uint32_t netid = 0;
    int family = 0;
    if (!dns_parse_u32(argv[1], &netid) || !dns_parse_i32(argv[3], &family)) {
        dns_write_code(fd, DNS_CODE_BAD_ARG);
        return;
    }
    const char *name = dns_caret(argv[2]);
    int host_family = dns_host_family(family);
    if (!name ||
        (family != LINUX_AF_INET && family != LINUX_AF_INET6) ||
        !dns_netid_ok(netid)) {
        dns_write_code(fd, DNS_CODE_FAILED);
        return;
    }

    struct hostent *hp = gethostbyname2(name, host_family);
    if (!hp) {
        dns_write_code(fd, DNS_CODE_FAILED);
        return;
    }
    if (dns_write_code(fd, DNS_CODE_RESULT) < 0)
        return;
    if (dns_send_hostent(fd, hp) < 0)
        log_warn("dns bridge: failed to write gethostbyname reply");
}

static void dns_cmd_gethostbyaddr(int fd, int argc, char **argv)
{
    if (argc != 5) {
        dns_write_code(fd, DNS_CODE_BAD_ARG);
        return;
    }
    int addrlen = 0, family = 0;
    uint32_t netid = 0;
    if (!dns_parse_i32(argv[2], &addrlen) || !dns_parse_i32(argv[3], &family) ||
        !dns_parse_u32(argv[4], &netid) || !dns_netid_ok(netid)) {
        dns_write_code(fd, DNS_CODE_BAD_ARG);
        return;
    }
    uint8_t addr[16];
    memset(addr, 0, sizeof(addr));
    int host_family = dns_host_family(family);
    int expect_len = host_family == AF_INET6 ? 16 : 4;
    if ((family != LINUX_AF_INET && family != LINUX_AF_INET6) ||
        addrlen != expect_len || inet_pton(host_family, argv[1], addr) != 1) {
        dns_write_code(fd, DNS_CODE_BAD_ARG);
        return;
    }

    struct hostent *hp =
        gethostbyaddr(addr, (socklen_t) addrlen, host_family);
    if (!hp) {
        dns_write_code(fd, DNS_CODE_FAILED);
        return;
    }
    if (dns_write_code(fd, DNS_CODE_RESULT) < 0)
        return;
    if (dns_send_hostent(fd, hp) < 0)
        log_warn("dns bridge: failed to write gethostbyaddr reply");
}


static void dns_res_fail(int fd, int err)
{
    errno = err;
    if (dns_write_be32(fd, (uint32_t) linux_errno()) < 0)
        log_warn("dns bridge: failed to report resnsend error");
}

static void dns_cmd_resnsend(int fd, int argc, char **argv)
{
    if (argc != 4) {
        dns_res_fail(fd, EINVAL);
        return;
    }
    uint32_t netid = 0, flags = 0;
    if (!dns_parse_u32(argv[1], &netid) || !dns_parse_u32(argv[2], &flags)) {
        dns_res_fail(fd, EINVAL);
        return;
    }
    (void) flags;
    if (!dns_netid_ok(netid)) {
        (void) dns_write_be32(fd, (uint32_t) -64); /* Linux ENONET has no Darwin equivalent. */
        return;
    }

    uint8_t query[DNS_ANS_MAX];
    int qlen = dns_b64_decode(argv[3], query, sizeof(query));
    if (qlen < 12) {
        dns_res_fail(fd, qlen < 0 ? EILSEQ : EINVAL);
        return;
    }
    /* The query goes out as the guest wrote it. res_send follows the host
     * resolver configuration and returns that DNS message unchanged, so TXT,
     * SRV, CNAME and HTTPS stay the records the nameserver sent.
     */
    uint8_t ans[DNS_ANS_MAX];
    pthread_mutex_lock(&dns_resolv_lock);
    int alen = res_send(query, qlen, ans, (int) sizeof(ans));
    int saved = errno;
    pthread_mutex_unlock(&dns_resolv_lock);
    if (alen < 0) {
        dns_res_fail(fd, saved ? saved : EAGAIN);
        return;
    }
    if (alen < 12 || (size_t) alen > sizeof(ans)) {
        dns_res_fail(fd, EMSGSIZE);
        return;
    }
    uint32_t rcode = ans[3] & 0x0f;
    if (dns_write_be32(fd, rcode) < 0 ||
        dns_write_len_data(fd, ans, (uint32_t) alen) < 0)
        log_warn("dns bridge: failed to write resnsend reply");
}

static void dns_cmd_getdnsnetid(int fd, int argc, char **argv)
{
    if (argc != 2) {
        dns_write_code(fd, DNS_CODE_RESULT);
        dns_write_be32(fd, (uint32_t) -EINVAL);
        return;
    }
    uint32_t netid = 0;
    if (!dns_parse_u32(argv[1], &netid)) {
        dns_write_code(fd, DNS_CODE_RESULT);
        dns_write_be32(fd, (uint32_t) -EINVAL);
        return;
    }
    bool local = (netid & NETID_USE_LOCAL_NAMESERVERS) != 0;
    netid &= ~NETID_USE_LOCAL_NAMESERVERS;
    if (netid == 100u)
        netid = NETID_UNSET;
    if (local)
        netid |= NETID_USE_LOCAL_NAMESERVERS;
    dns_write_code(fd, DNS_CODE_RESULT);
    dns_write_be32(fd, netid);
}

static void dns_dispatch(int fd, char *cmd)
{
    char *argv[8];
    int argc = 0;
    char *save = NULL;
    for (char *tok = strtok_r(cmd, " ", &save); tok && argc < 8;
         tok = strtok_r(NULL, " ", &save))
        argv[argc++] = tok;
    if (argc == 0) {
        dns_write_code(fd, DNS_CODE_BAD_ARG);
        return;
    }
    if (!strcmp(argv[0], "getaddrinfo"))
        dns_cmd_getaddrinfo(fd, argc, argv);
    else if (!strcmp(argv[0], "gethostbyname"))
        dns_cmd_gethostbyname(fd, argc, argv);
    else if (!strcmp(argv[0], "gethostbyaddr"))
        dns_cmd_gethostbyaddr(fd, argc, argv);
    else if (!strcmp(argv[0], "resnsend"))
        dns_cmd_resnsend(fd, argc, argv);
    else if (!strcmp(argv[0], "getdnsnetid"))
        dns_cmd_getdnsnetid(fd, argc, argv);
    else
        dns_write_code(fd, DNS_CODE_BAD_ARG);
}

static void dns_worker_end(void)
{
    pthread_mutex_lock(&dns_bridge_lock);
    dns_workers--;
    pthread_mutex_unlock(&dns_bridge_lock);
}

static void *dns_conn_thread(void *arg)
{
    int fd = (int) (intptr_t) arg;
    char buf[DNS_CMD_MAX];
    size_t got = 0;
    int saw_nul = 0;
    while (got < sizeof(buf)) {
        ssize_t n = read(fd, buf + got, sizeof(buf) - got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        got += (size_t) n;
        if (memchr(buf, '\0', got)) {
            saw_nul = 1;
            break;
        }
    }
    if (!saw_nul) {
        if (got == sizeof(buf)) {
            char msg[] = "500 Command too large for buffer";
            dns_write_all(fd, msg, sizeof(msg));
        }
    } else {
        /* One command per connection, the way each libc caller writes it.
         * Anything past the first NUL is leftover from a pipelined writer and
         * is ignored rather than run as a second lookup.
         */
        dns_dispatch(fd, buf);
    }
    close(fd);
    dns_worker_end();
    return NULL;
}

static int dns_spawn_worker(int fd)
{
    pthread_mutex_lock(&dns_bridge_lock);
    if (dns_workers >= DNS_MAX_CONN) {
        pthread_mutex_unlock(&dns_bridge_lock);
        errno = ENOMEM;
        return -1;
    }
    dns_workers++;
    pthread_mutex_unlock(&dns_bridge_lock);

    pthread_t thr;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&thr, &attr, dns_conn_thread,
                            (void *) (intptr_t) fd);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        dns_worker_end();
        errno = rc;
        return -1;
    }
    return 0;
}

static void *dns_accept_thread(void *arg)
{
    (void) arg;
    for (;;) {
        int fd = accept(dns_listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            return NULL;
        }
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        struct timeval budget = {.tv_sec = 5, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &budget, sizeof(budget));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &budget, sizeof(budget));
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        if (dns_spawn_worker(fd) < 0)
            close(fd);
    }
}

/* Process exit only. Closing the listen fd here while the accept thread is
 * still in accept is safe because nothing reuses the number afterwards: the
 * process is going away, and atexit does not run again.
 */
static void dns_listen_cleanup(void)
{
    if (dns_listen_fd >= 0) {
        close(dns_listen_fd);
        dns_listen_fd = -1;
    }
    if (dns_path[0])
        unlink(dns_path);
    if (dns_dir[0])
        rmdir(dns_dir);
}

static void dns_listen_init(void)
{
    /* mkdtemp wants a writable template and returns a 0700 directory. The
     * socket name stays short enough for sun_path on every macOS version.
     */
    char dir[] = "/tmp/elfuse-dns-XXXXXX";
    if (!mkdtemp(dir))
        return;
    memcpy(dns_dir, dir, sizeof(dir));
    int n = snprintf(dns_path, sizeof(dns_path), "%s/s", dns_dir);
    if (n < 0 || (size_t) n >= sizeof(dns_path)) {
        rmdir(dns_dir);
        dns_dir[0] = '\0';
        return;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        goto fail;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        close(fd);
        goto fail;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, dns_path, (size_t) n + 1);
    addr.sun_len = (uint8_t) (offsetof(struct sockaddr_un, sun_path) +
                              (size_t) n + 1);
    if (bind(fd, (struct sockaddr *) &addr, addr.sun_len) < 0 ||
        listen(fd, DNS_MAX_CONN) < 0) {
        close(fd);
        goto fail;
    }
    chmod(dns_path, 0600);
    dns_listen_fd = fd;

    pthread_t thr;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&thr, &attr, dns_accept_thread, NULL);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        dns_listen_cleanup();
        return;
    }
    atexit(dns_listen_cleanup);
    return;
fail:
    dns_path[0] = '\0';
    rmdir(dns_dir);
    dns_dir[0] = '\0';
}

static bool dns_path_is(const struct sockaddr_storage *sa,
                        int len,
                        const char *path)
{
    if (!sa || len <= (int) offsetof(struct sockaddr_un, sun_path))
        return false;
    if (sa->ss_family != AF_UNIX)
        return false;
    const struct sockaddr_un *sun = (const struct sockaddr_un *) sa;
    size_t max = (size_t) len - offsetof(struct sockaddr_un, sun_path);
    if (max > sizeof(sun->sun_path))
        max = sizeof(sun->sun_path);
    size_t n = strnlen(sun->sun_path, max);
    size_t want = strlen(path);
    return n == want && memcmp(sun->sun_path, path, n) == 0;
}

bool dns_bridge_is_proxyd(const struct sockaddr_storage *sa, int len)
{
    return dns_path_is(sa, len, "/dev/socket/dnsproxyd");
}

bool dns_bridge_is_listener(const struct sockaddr_storage *sa, int len)
{
    if (!dns_path[0])
        return false;
    return dns_path_is(sa, len, dns_path);
}

int dns_bridge_retarget(const uint8_t *linux_sa,
                        uint32_t addrlen,
                        struct sockaddr_storage *mac_sa,
                        int *mac_len)
{
    if (!linux_sa || !mac_sa || !mac_len)
        return 0;
    /* Linux sockaddr_un: 2-byte family, then the path. The leading byte of
     * the path is 0 for an abstract name, which this socket is not.
     */
    if (addrlen <= 2 || linux_sa[2] == '\0')
        return 0;
    uint16_t fam = 0;
    memcpy(&fam, linux_sa, 2);
    if (fam != LINUX_AF_UNIX)
        return 0;
    uint32_t plen = addrlen - 2;
    if (plen > 108)
        plen = 108;
    char path[109];
    memcpy(path, linux_sa + 2, plen);
    path[plen] = '\0';
    static const char proxyd[] = "/dev/socket/dnsproxyd";
    if (strcmp(path, proxyd) != 0)
        return 0;

    pthread_once(&dns_once, dns_listen_init);
    if (dns_listen_fd < 0) {
        errno = ECONNREFUSED;
        return -1;
    }
    struct sockaddr_un *sun = (struct sockaddr_un *) mac_sa;
    size_t n = strlen(dns_path);
    memset(mac_sa, 0, sizeof(*mac_sa));
    sun->sun_family = AF_UNIX;
    memcpy(sun->sun_path, dns_path, n + 1);
    sun->sun_len = (uint8_t) (offsetof(struct sockaddr_un, sun_path) + n + 1);
    *mac_len = sun->sun_len;
    return 1;
}
