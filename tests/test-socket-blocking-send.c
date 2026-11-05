/*
 * A blocking send on a stream socket moves the whole buffer
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux blocks a send(2) on a SOCK_STREAM socket until every byte is queued,
 * and reports a short count only when a signal or an error arrives after some
 * bytes moved. elfuse emulates the blocking on a socket whose host flag it owns
 * as nonblocking, and its send paths used to stop after the first host send
 * that moved anything: a 1 MiB send into an 8 KiB socket buffer returned about
 * 8192 while write(2) on the same socket returned the whole megabyte.
 *
 * A reader process sleeps and then drains slowly, so the sender has to wait
 * many times. Each send family entry point is checked: send, sendto without an
 * address, the single-iovec sendmsg fast path, a multi-iovec sendmsg, and a
 * sendmsg carrying SCM_RIGHTS, whose descriptor has to arrive once. A send with
 * MSG_DONTWAIT still reports the short count, and a blocking send that nobody
 * reads still returns to a signal.
 *
 * Syscalls exercised: socketpair(199), sendto(206), sendmsg(211),
 *                     recvmsg(212), setsockopt(208), clone(220),
 *                     wait4(260), setitimer(103), rt_sigaction(134)
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define BIG (1u << 20)

static unsigned char *buf;

struct reader {
    int fd;
    size_t got;
    int bad;
    int nfds;
};

/* Runs in the reader child; the exit status carries the verdict. */
static int drain(struct reader *r)
{
    unsigned char chunk[4096];
    usleep(200 * 1000);
    while (r->got < BIG) {
        char ctrl[CMSG_SPACE(sizeof(int) * 4)];
        struct iovec iov = {chunk, sizeof(chunk)};
        struct msghdr msg = {.msg_iov = &iov,
                             .msg_iovlen = 1,
                             .msg_control = ctrl,
                             .msg_controllen = sizeof(ctrl)};
        ssize_t n = recvmsg(r->fd, &msg, 0);
        if (n <= 0)
            break;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c;
             c = CMSG_NXTHDR(&msg, c)) {
            if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
                continue;
            int nf = (int) ((c->cmsg_len - CMSG_LEN(0)) / sizeof(int));
            int *fds = (int *) CMSG_DATA(c);
            for (int i = 0; i < nf; i++)
                close(fds[i]);
            r->nfds += nf;
        }
        for (ssize_t i = 0; i < n; i++) {
            if (chunk[i] != buf[r->got + (size_t) i])
                r->bad = 1;
        }
        r->got += (size_t) n;
        usleep(500);
    }
    if (r->got != BIG || r->bad)
        return 1;
    return 10 + r->nfds;
}

static int make_pair(int sv[2])
{
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return -1;
    int bufsz = 8192;
    if (setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz)) != 0 ||
        setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz)) != 0) {
        close(sv[0]);
        close(sv[1]);
        return -1;
    }
    return 0;
}

enum { VIA_SEND, VIA_SENDTO, VIA_SENDMSG1, VIA_SENDMSG3, VIA_SCM };

static void check_full_send(const char *name, int via)
{
    int sv[2];
    TEST(name);
    if (make_pair(sv) != 0) {
        FAIL("socketpair failed");
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(sv[0]);
        struct reader r = {.fd = sv[1]};
        _exit(drain(&r));
    }
    close(sv[1]);

    ssize_t n = -1;
    struct iovec iov[3] = {
        {buf, 1000},
        {buf + 1000, BIG / 2 - 1000},
        {buf + BIG / 2, BIG / 2},
    };
    struct iovec one = {buf, BIG};
    char ctrl[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = {.msg_iov = &one, .msg_iovlen = 1};

    switch (via) {
    case VIA_SEND:
        n = send(sv[0], buf, BIG, 0);
        break;
    case VIA_SENDTO:
        n = sendto(sv[0], buf, BIG, 0, NULL, 0);
        break;
    case VIA_SENDMSG1:
        n = sendmsg(sv[0], &msg, 0);
        break;
    case VIA_SENDMSG3:
        msg.msg_iov = iov;
        msg.msg_iovlen = 3;
        n = sendmsg(sv[0], &msg, 0);
        break;
    case VIA_SCM: {
        memset(ctrl, 0, sizeof(ctrl));
        msg.msg_control = ctrl;
        msg.msg_controllen = sizeof(ctrl);
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        int passed = 0;
        memcpy(CMSG_DATA(c), &passed, sizeof(int));
        n = sendmsg(sv[0], &msg, 0);
        break;
    }
    }
    int err = errno;

    close(sv[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    int verdict = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    int nfds = verdict - 10;

    if (n != (ssize_t) BIG) {
        errno = err;
        printf("(returned %zd) ", n);
        FAIL("blocking send returned a short count");
    } else if (verdict < 10) {
        FAIL("reader did not see the whole buffer intact");
    } else if (nfds != (via == VIA_SCM ? 1 : 0)) {
        printf("(received %d fds) ", nfds);
        FAIL("SCM_RIGHTS descriptor did not arrive exactly once");
    } else {
        PASS();
    }
}

static volatile sig_atomic_t handler_ran;

static void on_alarm(int sig)
{
    (void) sig;
    handler_ran = 1;
}

static void check_small_send_progress(void)
{
    int sv[2];
    TEST("small send uses newly freed socket space");
    if (make_pair(sv) != 0) {
        FAIL("socketpair failed");
        return;
    }
    unsigned char packet[256];
    memset(packet, 0x6d, sizeof(packet));
    ssize_t sent;
    do {
        sent = send(sv[0], packet, sizeof(packet), MSG_DONTWAIT);
    } while (sent > 0);
    int full_err = errno;
    ssize_t drained = recv(sv[1], packet, sizeof(packet), 0);
    if (sent != -1 || full_err != EAGAIN || drained != sizeof(packet)) {
        FAIL("could not fill and partially drain socket");
        close(sv[0]);
        close(sv[1]);
        return;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval timer;
    memset(&timer, 0, sizeof(timer));
    timer.it_value.tv_sec = 1;
    handler_ran = 0;
    setitimer(ITIMER_REAL, &timer, NULL);
    sent = send(sv[0], packet, 1, 0);
    memset(&timer, 0, sizeof(timer));
    setitimer(ITIMER_REAL, &timer, NULL);
    EXPECT_TRUE(sent == 1 && !handler_ran,
                "one byte must fit without waiting for another peer read");
    close(sv[0]);
    close(sv[1]);
    handler_ran = 0;
}

int main(void)
{
    buf = malloc(BIG);
    if (!buf) {
        FAIL("malloc failed");
        SUMMARY("test-socket-blocking-send");
        return 1;
    }
    for (size_t i = 0; i < BIG; i++)
        buf[i] = (unsigned char) (i * 7 % 251);

    check_full_send("send 1 MiB completes", VIA_SEND);
    check_full_send("sendto 1 MiB completes", VIA_SENDTO);
    check_full_send("sendmsg 1 iov completes", VIA_SENDMSG1);
    check_full_send("sendmsg 3 iovs completes", VIA_SENDMSG3);
    check_full_send("sendmsg SCM_RIGHTS completes", VIA_SCM);
    check_small_send_progress();

    int sv[2];
    if (make_pair(sv) != 0) {
        FAIL("socketpair failed");
        SUMMARY("test-socket-blocking-send");
        return 1;
    }

    TEST("MSG_DONTWAIT reports short");
    ssize_t n = send(sv[0], buf, BIG, MSG_DONTWAIT);
    EXPECT_TRUE(n > 0 && n < (ssize_t) BIG, "expected a partial count");

    /* The buffer is full now, so the blocking send cannot move anything until
     * the signal arrives, and has to come back with EINTR.
     */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval it;
    memset(&it, 0, sizeof(it));
    it.it_value.tv_sec = 1;
    setitimer(ITIMER_REAL, &it, NULL);

    TEST("blocking send takes a signal");
    n = send(sv[0], buf, BIG, 0);
    int err = errno;
    EXPECT_TRUE(handler_ran &&
                    ((n > 0 && n < (ssize_t) BIG) || (n < 0 && err == EINTR)),
                "send neither reported a partial count nor EINTR");

    close(sv[0]);
    close(sv[1]);
    free(buf);
    SUMMARY("test-socket-blocking-send");
    return fails ? 1 : 0;
}
