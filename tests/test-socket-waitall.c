/*
 * MSG_WAITALL gathers, and never parks the vCPU
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * macOS does not answer for MSG_WAITALL the way Linux does, and not even
 * consistently between processes: the same recv, on the same kind of
 * nonblocking AF_UNIX socketpair with two bytes queued and sixteen requested,
 * returns 2 in a standalone program and blocks forever inside elfuse. With
 * MSG_DONTWAIT also set, which Linux treats as "return what you have".
 *
 * A guest calling recv(MSG_WAITALL) is ordinary protocol code, and a vCPU
 * thread parked in that host call is reachable by neither hv_vcpus_exit nor the
 * wakeup pipe. So elfuse strips the flag from the host call and gathers the
 * request itself, across recv, recvmsg and recvmmsg.
 *
 * All four assertions below are Linux's own answers, so this passes on real
 * Linux; it hangs until the harness kills it on a tree that forwards the flag,
 * which is what every elfuse before this did.
 *
 * Syscalls exercised: socketpair(199), recvfrom(207), recvmsg(212), write(64),
 *                     close(57), clone(220), nanosleep(101)
 */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* Linux spellings; the guest headers may not agree with the host's. */
#define L_MSG_DONTWAIT 0x40
#define L_MSG_WAITALL 0x100
#define L_MSG_PEEK 0x02

static int drip_fd;

/* Hand over the remaining 14 bytes in pieces, so a gathering recv has to come
 * back for them rather than getting the whole request in one go.
 */
static void *feeder(void *arg)
{
    (void) arg;
    struct timespec t = {0, 50 * 1000 * 1000};
    for (int i = 0; i < 7; i++) {
        nanosleep(&t, NULL);
        if (write(drip_fd, "XX", 2) != 2)
            return NULL;
    }
    return NULL;
}

int main(void)
{
    char buf[16];
    int sv[2];

    TEST("MSG_WAITALL|MSG_DONTWAIT returns what is queued");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair failed");
        SUMMARY("test-socket-waitall");
        return 1;
    }
    if (write(sv[1], "de", 2) != 2)
        FAIL("priming write failed");
    ssize_t n = recv(sv[0], buf, sizeof(buf), L_MSG_WAITALL | L_MSG_DONTWAIT);
    EXPECT_TRUE(n == 2, "recv did not report the two bytes queued");
    close(sv[0]);
    close(sv[1]);

    TEST("recvmsg honours MSG_WAITALL|MSG_DONTWAIT the same way");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair failed");
        SUMMARY("test-socket-waitall");
        return 1;
    }
    if (write(sv[1], "de", 2) != 2)
        FAIL("priming write failed");
    struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1};
    n = recvmsg(sv[0], &m, L_MSG_WAITALL | L_MSG_DONTWAIT);
    EXPECT_TRUE(n == 2, "recvmsg did not report the two bytes queued");
    close(sv[0]);
    close(sv[1]);

    /* The case that actually regressed. sys_recvfrom stripped MSG_WAITALL
     * before the host call while the three msghdr paths asked
     * recv_gathers_waitall instead, which answers no for a peek, so the flag
     * reached macOS and macOS answered 16 for a 16-byte request with 2 bytes
     * queued -- fourteen bytes of the guest's own buffer reported as received.
     * The SEQPACKET assertions below do not catch it: macOS returns one message
     * there whether or not the flag is stripped.
     */
    TEST("recvmsg with MSG_PEEK|MSG_WAITALL returns what is queued");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair failed");
        SUMMARY("test-socket-waitall");
        return 1;
    }
    if (write(sv[1], "de", 2) != 2)
        FAIL("priming write failed");
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    m = (struct msghdr) {.msg_iov = &iov, .msg_iovlen = 1};
    n = recvmsg(sv[0], &m, L_MSG_PEEK | L_MSG_WAITALL | L_MSG_DONTWAIT);
    EXPECT_TRUE(n == 2, "recvmsg over-reported a peek");
    close(sv[0]);
    close(sv[1]);

    TEST("recvmsg returns one SOCK_SEQPACKET message with MSG_WAITALL");
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0) {
        FAIL("socketpair failed");
        SUMMARY("test-socket-waitall");
        return 1;
    }
    if (write(sv[1], "de", 2) != 2)
        FAIL("priming write failed");
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    m = (struct msghdr) {.msg_iov = &iov, .msg_iovlen = 1};
    n = recvmsg(sv[0], &m, L_MSG_WAITALL);
    EXPECT_TRUE(n == 2, "recvmsg did not stop at one SOCK_SEQPACKET message");
    close(sv[0]);
    close(sv[1]);

    TEST("recvmmsg returns one SOCK_SEQPACKET message with MSG_WAITALL");
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0) {
        FAIL("socketpair failed");
        SUMMARY("test-socket-waitall");
        return 1;
    }
    if (write(sv[1], "de", 2) != 2)
        FAIL("priming write failed");
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    struct mmsghdr mmsg = {
        .msg_hdr = {.msg_iov = &iov, .msg_iovlen = 1},
    };
    n = recvmmsg(sv[0], &mmsg, 1, L_MSG_WAITALL, NULL);
    EXPECT_TRUE(n == 1 && mmsg.msg_len == 2,
                "recvmmsg did not stop at one SOCK_SEQPACKET message");
    close(sv[0]);
    close(sv[1]);

    for (int mode = 0; mode < 4; mode++) {
        TEST(mode == 0   ? "recv gathers across worker unmounts"
             : mode == 1 ? "recvmsg gathers across worker unmounts"
             : mode == 2 ? "recvmmsg gathers across worker unmounts"
                         : "vector recvmsg gathers across worker unmounts");
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            FAIL("socketpair failed");
            SUMMARY("test-socket-waitall");
            return 1;
        }
        drip_fd = sv[1];
        if (write(sv[1], "ab", 2) != 2)
            FAIL("priming write failed");
        pthread_t t;
        if (pthread_create(&t, NULL, feeder, NULL) != 0)
            FAIL("pthread_create failed");
        memset(buf, 0, sizeof(buf));
        struct iovec receive_iov[2] = {
            {.iov_base = buf, .iov_len = mode == 3 ? 5 : sizeof(buf)},
            {.iov_base = buf + 5, .iov_len = sizeof(buf) - 5},
        };
        struct mmsghdr receive_msg = {
            .msg_hdr = {.msg_iov = receive_iov,
                        .msg_iovlen = mode == 3 ? 2 : 1},
        };
        if (mode == 0)
            n = recv(sv[0], buf, sizeof(buf), L_MSG_WAITALL);
        else if (mode == 2) {
            n = recvmmsg(sv[0], &receive_msg, 1, L_MSG_WAITALL, NULL);
            if (n == 1)
                n = receive_msg.msg_len;
        } else
            n = recvmsg(sv[0], &receive_msg.msg_hdr, L_MSG_WAITALL);
        pthread_join(t, NULL);
        EXPECT_TRUE(n == (ssize_t) sizeof(buf) &&
                        memcmp(buf, "abXXXXXXXXXXXXXX", sizeof(buf)) == 0,
                    "WAITALL lost bytes or reported a short count");
        close(sv[0]);
        close(sv[1]);
    }

    TEST("EOF ends a gather with the partial count");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair failed");
        SUMMARY("test-socket-waitall");
        return 1;
    }
    if (write(sv[1], "hi", 2) != 2)
        FAIL("priming write failed");
    close(sv[1]);
    n = recv(sv[0], buf, sizeof(buf), L_MSG_WAITALL);
    EXPECT_TRUE(n == 2, "a gather did not stop at EOF with what it had");
    close(sv[0]);

    /* A zero-length receive is gated on readiness before the host call runs,
     * and the gate decides with a one-byte MSG_PEEK rather than a poll. On a
     * pipe that peek is what reports ENOTSOCK; a poll would have said "not
     * readable" and the guest would have seen EAGAIN for a call that is not
     * valid on this descriptor at all. Measured against the reference kernel,
     * which answers ENOTSOCK.
     */
    TEST("a zero-length recvfrom on a pipe is ENOTSOCK, not EAGAIN");
    int pfd[2];
    if (pipe(pfd) != 0) {
        FAIL("pipe failed");
        SUMMARY("test-socket-waitall");
        return 1;
    }
    n = recvfrom(pfd[0], buf, 0, L_MSG_DONTWAIT, NULL, NULL);
    EXPECT_ERRNO(n, ENOTSOCK, "zero-length recvfrom on a pipe");
    close(pfd[0]);
    close(pfd[1]);

    SUMMARY("test-socket-waitall");
    return fails ? 1 : 0;
}
