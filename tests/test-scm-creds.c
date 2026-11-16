/*
 * Test SCM_CREDENTIALS / SO_PASSCRED over AF_UNIX sockets
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: SO_PASSCRED setsockopt/getsockopt, SO_PEERCRED getsockopt for a
 * same-process socketpair, forked peers, credential changes, and error paths,
 * and SCM_CREDENTIALS ancillary data injection on recvmsg.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>

#include "test-harness.h"
#include "raw-syscall.h"

/* aarch64 Linux syscall numbers */
#define __NR_socketpair 199
#define __NR_setsockopt 208
#define __NR_getsockopt 209
#define __NR_sendmsg 211
#define __NR_recvmsg 212
#define __NR_close 57
#define __NR_getpid 172
#define __NR_socket 198

/* Linux constants */
#define LINUX_AF_UNIX 1
#define LINUX_SOCK_STREAM 1
#define LINUX_SOL_SOCKET 1
#define LINUX_SO_PASSCRED 16
#define LINUX_SO_PEERCRED 17
#define LINUX_SCM_CREDENTIALS 2
#define LINUX_AF_INET 2
#define LINUX_ENOTCONN 107
#define LINUX_ENOPROTOOPT 92

int passes = 0, fails = 0;

/* Linux ucred */
struct linux_ucred {
    int pid;
    unsigned int uid, gid;
};

/* Linux msghdr (aarch64) */
struct linux_msghdr {
    unsigned long msg_name;
    unsigned int msg_namelen, _pad0;
    unsigned long msg_iov, msg_iovlen, msg_control, msg_controllen;
    int msg_flags, _pad1;
};

/* Linux iovec */
struct linux_iov {
    unsigned long iov_base, iov_len;
};

struct accept_thread_args {
    int srv;
    int acc;
    int ready;
    pthread_mutex_t lock;
    pthread_cond_t cond;
};

static void *accept_thread_main(void *opaque)
{
    struct accept_thread_args *args = opaque;

    pthread_mutex_lock(&args->lock);
    args->ready = 1;
    pthread_cond_signal(&args->cond);
    pthread_mutex_unlock(&args->lock);

    args->acc = accept(args->srv, NULL, NULL);
    return NULL;
}

static void test_accept_inherits_passcred(void)
{
    TEST("accept inherits SO_PASSCRED");

    int srv = -1, cli = -1, acc = -1;

    /* A private directory rather than one name per pid: elfuse restarts guest
     * pids at 1, so the unlink() that used to precede bind() removed the live
     * socket of whatever concurrent run held the same name.
     */
    char dir[] = "/tmp/elfuse-scm-creds-XXXXXX";
    char path[sizeof(((struct sockaddr_un *) 0)->sun_path)];
    if (!mkdtemp(dir)) {
        FAIL("mkdtemp failed");
        return;
    }
    snprintf(path, sizeof(path), "%s/s", dir);

    srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) {
        FAIL("socket server failed");
        goto done;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    if (bind(srv, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        FAIL("bind failed");
        goto done;
    }
    if (listen(srv, 1) < 0) {
        FAIL("listen failed");
        goto done;
    }

    int one = 1;
    if (setsockopt(srv, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0) {
        FAIL("setsockopt listener SO_PASSCRED failed");
        goto done;
    }

    cli = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cli < 0) {
        FAIL("socket client failed");
        goto done;
    }
    if (connect(cli, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        FAIL("connect failed");
        goto done;
    }

    acc = accept(srv, NULL, NULL);
    if (acc < 0) {
        FAIL("accept failed");
        goto done;
    }

    int val = 0;
    socklen_t len = sizeof(val);
    if (getsockopt(acc, SOL_SOCKET, SO_PASSCRED, &val, &len) == 0 && val == 1)
        PASS();
    else
        FAIL("accepted socket did not inherit SO_PASSCRED");

done:
    if (acc >= 0)
        close(acc);
    if (cli >= 0)
        close(cli);
    if (srv >= 0)
        close(srv);
    unlink(path);
    rmdir(dir);
}

static void test_blocked_accept_sees_passcred_toggle(void)
{
    TEST("blocked accept observes SO_PASSCRED toggle");

    int srv = -1, cli = -1;
    pthread_t thread;
    int thread_started = 0;
    struct accept_thread_args args = {
        .srv = -1,
        .acc = -1,
        .ready = 0,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };
    char dir[] = "/tmp/elfuse-scm-creds-toggle-XXXXXX";
    char path[sizeof(((struct sockaddr_un *) 0)->sun_path)];
    if (!mkdtemp(dir)) {
        FAIL("mkdtemp failed");
        return;
    }
    snprintf(path, sizeof(path), "%s/s", dir);

    srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) {
        FAIL("socket server failed");
        goto done;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    if (bind(srv, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        FAIL("bind failed");
        goto done;
    }
    if (listen(srv, 1) < 0) {
        FAIL("listen failed");
        goto done;
    }

    args.srv = srv;
    if (pthread_create(&thread, NULL, accept_thread_main, &args) != 0) {
        FAIL("pthread_create failed");
        goto done;
    }
    thread_started = 1;

    pthread_mutex_lock(&args.lock);
    while (!args.ready)
        pthread_cond_wait(&args.cond, &args.lock);
    pthread_mutex_unlock(&args.lock);

    int one = 1;
    if (setsockopt(srv, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0) {
        FAIL("setsockopt listener SO_PASSCRED failed");
        goto done;
    }

    cli = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cli < 0) {
        FAIL("socket client failed");
        goto done;
    }
    if (connect(cli, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        FAIL("connect failed");
        goto done;
    }

    pthread_join(thread, NULL);
    thread_started = 0;
    if (args.acc < 0) {
        FAIL("accept failed");
        goto done;
    }

    int val = 0;
    socklen_t len = sizeof(val);
    if (getsockopt(args.acc, SOL_SOCKET, SO_PASSCRED, &val, &len) == 0 &&
        val == 1)
        PASS();
    else
        FAIL("accepted socket used stale SO_PASSCRED");

done:
    if (thread_started && args.acc < 0 && srv >= 0) {
        close(srv);
        srv = -1;
    }
    if (thread_started)
        pthread_join(thread, NULL);
    if (args.acc >= 0)
        close(args.acc);
    if (cli >= 0)
        close(cli);
    if (srv >= 0)
        close(srv);
    pthread_cond_destroy(&args.cond);
    pthread_mutex_destroy(&args.lock);
    unlink(path);
    rmdir(dir);
}

static int peer_listen(char *dir, char *path, size_t path_size)
{
    if (!mkdtemp(dir))
        return -1;
    /* The credential-change child drops to uid 1000 on a real kernel; the
     * directory and socket must stay reachable for its second connect.
     */
    (void) chmod(dir, 0777);
    snprintf(path, path_size, "%s/s", dir);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
        listen(fd, 8) < 0) {
        close(fd);
        return -1;
    }
    (void) chmod(path, 0777);
    return fd;
}

static int peer_connect(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void child_connect_hold(const char *path, int hold_fd)
{
    int fd = peer_connect(path);
    if (fd < 0)
        _exit(20);
    char byte;
    (void) read(hold_fd, &byte, 1);
    close(fd);
    _exit(0);
}

static long peer_cred(int fd, struct linux_ucred *cred, int *len)
{
    *len = (int) sizeof(*cred);
    return raw_syscall5(__NR_getsockopt, fd, LINUX_SOL_SOCKET,
                        LINUX_SO_PEERCRED, (long) cred, (long) len);
}

static void test_peercred_forked_peers(void)
{
    TEST("SO_PEERCRED reports a forked peer");

    char dir[] = "/tmp/elfuse-peercred-fork-XXXXXX";
    char path[sizeof(((struct sockaddr_un *) 0)->sun_path)];
    int srv = peer_listen(dir, path, sizeof(path));
    if (srv < 0) {
        FAIL("listener setup failed");
        rmdir(dir);
        return;
    }

    long parent_pid = raw_syscall0(__NR_getpid);
    long want_uid = (long) geteuid();
    long want_gid = (long) getegid();
    long first_pid = -1;
    int ok = 1;

    for (int i = 0; i < 2; i++) {
        int hold[2];
        if (pipe(hold) != 0) {
            printf("peer %d: pipe failed\n", i);
            ok = 0;
            break;
        }
        pid_t kid = fork();
        if (kid < 0) {
            printf("peer %d: fork failed\n", i);
            close(hold[0]);
            close(hold[1]);
            ok = 0;
            break;
        }
        if (kid == 0) {
            close(hold[1]);
            close(srv);
            child_connect_hold(path, hold[0]);
        }
        close(hold[0]);

        int acc = accept(srv, NULL, NULL);
        struct linux_ucred cred = {0};
        int len = 0;
        long r = acc < 0 ? -1 : peer_cred(acc, &cred, &len);
        if (acc < 0 || r != 0 || cred.pid != kid ||
            (long) cred.uid != want_uid || (long) cred.gid != want_gid ||
            cred.pid == (int) parent_pid) {
            printf(
                "peer %d: acc=%d r=%ld pid=%d uid=%u gid=%u want pid=%d "
                "uid=%ld gid=%ld parent=%ld\n",
                i, acc, r, cred.pid, cred.uid, cred.gid, (int) kid, want_uid,
                want_gid, parent_pid);
            ok = 0;
        }
        if (i == 0)
            first_pid = kid;
        else if (kid == first_pid) {
            printf("two peers shared pid %d\n", (int) kid);
            ok = 0;
        }

        /* A short optlen reports the truncated length and prefix. */
        unsigned char prefix = 0;
        int short_len = 1;
        long short_r =
            raw_syscall5(__NR_getsockopt, acc, LINUX_SOL_SOCKET,
                         LINUX_SO_PEERCRED, (long) &prefix, (long) &short_len);
        if (short_r != 0 || short_len != 1 ||
            prefix != (unsigned char) (kid & 0xff)) {
            printf("peer %d: short optlen r=%ld len=%d prefix=%u pid=%d\n", i,
                   short_r, short_len, prefix, (int) kid);
            ok = 0;
        }

        close(hold[1]);
        if (acc >= 0)
            close(acc);
        (void) waitpid(kid, NULL, 0);
        if (!ok)
            break;
    }

    close(srv);
    unlink(path);
    rmdir(dir);
    if (ok)
        PASS();
    else
        FAIL("SO_PEERCRED did not report the forked peer");
}

static void test_peercred_credential_change(void)
{
    if (geteuid() != 0) {
        printf("  SO_PEERCRED credential change    SKIP (needs fakeroot)\n");
        return;
    }
    TEST("SO_PEERCRED follows a peer credential change");

    char dir[] = "/tmp/elfuse-peercred-cred-XXXXXX";
    char path[sizeof(((struct sockaddr_un *) 0)->sun_path)];
    int srv = peer_listen(dir, path, sizeof(path));
    if (srv < 0) {
        FAIL("listener setup failed");
        rmdir(dir);
        return;
    }

    int ready[2], release[2];
    if (pipe(ready) != 0 || pipe(release) != 0) {
        FAIL("pipe failed");
        close(srv);
        unlink(path);
        rmdir(dir);
        return;
    }
    pid_t kid = fork();
    if (kid < 0) {
        FAIL("fork failed");
        close(ready[0]);
        close(ready[1]);
        close(release[0]);
        close(release[1]);
        close(srv);
        unlink(path);
        rmdir(dir);
        return;
    }
    if (kid == 0) {
        close(ready[1]);
        close(release[1]);
        close(srv);

        int first = peer_connect(path);
        if (first < 0)
            _exit(21);
        char byte;
        if (read(ready[0], &byte, 1) != 1)
            _exit(22);

        /* If the change fails, still connect so the parent's check fails
         * instead of waiting in accept forever.
         */
        (void) setuid(1000);
        int second = peer_connect(path);
        if (second < 0)
            _exit(23);
        (void) read(release[0], &byte, 1);
        close(first);
        close(second);
        _exit(0);
    }

    close(ready[0]);
    close(release[0]);

    int acc1 = accept(srv, NULL, NULL);
    struct linux_ucred cred1 = {0};
    int len1 = 0;
    long r1 = acc1 < 0 ? -1 : peer_cred(acc1, &cred1, &len1);
    char go = 'g';
    (void) write(ready[1], &go, 1);
    close(ready[1]);

    int acc2 = accept(srv, NULL, NULL);
    struct linux_ucred cred2 = {0};
    int len2 = 0;
    long r2 = acc2 < 0 ? -1 : peer_cred(acc2, &cred2, &len2);

    close(release[1]);
    int status = 0;
    (void) waitpid(kid, &status, 0);

    int ok = r1 == 0 && cred1.pid == kid && cred1.uid == 0 && cred1.gid == 0 &&
             r2 == 0 && cred2.pid == kid && cred2.uid == 1000 &&
             cred2.gid == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (ok)
        PASS();
    else {
        printf(
            "first r=%ld pid=%d uid=%u gid=%u; second r=%ld pid=%d uid=%u "
            "gid=%u status=0x%x (want pid=%d uid=0 then 1000)\n",
            r1, cred1.pid, cred1.uid, cred1.gid, r2, cred2.pid, cred2.uid,
            cred2.gid, status, (int) kid);
        FAIL("SO_PEERCRED did not follow the credential change");
    }

    if (acc1 >= 0)
        close(acc1);
    if (acc2 >= 0)
        close(acc2);
    close(srv);
    unlink(path);
    rmdir(dir);
}

static void test_peercred_errors_and_short_len(void)
{
    TEST("SO_PEERCRED after peer close");
    int sp[2] = {-1, -1};
    if (raw_syscall4(__NR_socketpair, LINUX_AF_UNIX, LINUX_SOCK_STREAM, 0,
                     (long) sp) < 0) {
        FAIL("socketpair failed");
    } else {
        raw_syscall1(__NR_close, sp[1]);
        struct linux_ucred cred = {0};
        int len = 0;
        long r = peer_cred(sp[0], &cred, &len);
        if (r == -LINUX_ENOTCONN)
            PASS();
        else {
            printf("got r=%ld want %d\n", r, -LINUX_ENOTCONN);
            FAIL("closed peer did not report ENOTCONN");
        }
        raw_syscall1(__NR_close, sp[0]);
    }

    TEST("SO_PEERCRED on a non-UNIX socket");
    long inet = raw_syscall3(__NR_socket, LINUX_AF_INET, LINUX_SOCK_STREAM, 0);
    if (inet < 0) {
        FAIL("socket(AF_INET) failed");
    } else {
        struct linux_ucred cred = {0};
        int len = 0;
        long r = peer_cred((int) inet, &cred, &len);
        if (r == -LINUX_ENOPROTOOPT)
            PASS();
        else {
            printf("got r=%ld want %d\n", r, -LINUX_ENOPROTOOPT);
            FAIL("AF_INET SO_PEERCRED did not report ENOPROTOOPT");
        }
        raw_syscall1(__NR_close, inet);
    }

    TEST("SO_PEERCRED on an unconnected AF_UNIX socket");
    long unix_fd =
        raw_syscall3(__NR_socket, LINUX_AF_UNIX, LINUX_SOCK_STREAM, 0);
    if (unix_fd < 0) {
        FAIL("socket(AF_UNIX) failed");
    } else {
        struct linux_ucred cred = {0};
        int len = 0;
        long r = peer_cred((int) unix_fd, &cred, &len);
        if (r == -LINUX_ENOTCONN)
            PASS();
        else {
            printf("got r=%ld want %d\n", r, -LINUX_ENOTCONN);
            FAIL("unconnected AF_UNIX did not report ENOTCONN");
        }
        raw_syscall1(__NR_close, unix_fd);
    }

    TEST("SO_PEERCRED short optlen");
    int sv[2] = {-1, -1};
    if (raw_syscall4(__NR_socketpair, LINUX_AF_UNIX, LINUX_SOCK_STREAM, 0,
                     (long) sv) < 0) {
        FAIL("socketpair failed");
    } else {
        long pid = raw_syscall0(__NR_getpid);
        unsigned char prefix = 0;
        int len = 1;
        long r = raw_syscall5(__NR_getsockopt, sv[0], LINUX_SOL_SOCKET,
                              LINUX_SO_PEERCRED, (long) &prefix, (long) &len);
        if (r == 0 && len == 1 && prefix == (unsigned char) (pid & 0xff))
            PASS();
        else {
            printf("r=%ld len=%d prefix=%u pid=%ld\n", r, len, prefix, pid);
            FAIL("short optlen did not report one copied byte");
        }
        raw_syscall1(__NR_close, sv[0]);
        raw_syscall1(__NR_close, sv[1]);
    }

    TEST("SO_PEERCRED zero optlen");
    if (raw_syscall4(__NR_socketpair, LINUX_AF_UNIX, LINUX_SOCK_STREAM, 0,
                     (long) sv) < 0) {
        FAIL("socketpair failed");
    } else {
        unsigned char byte = 0;
        int len = 0;
        long r = raw_syscall5(__NR_getsockopt, sv[0], LINUX_SOL_SOCKET,
                              LINUX_SO_PEERCRED, (long) &byte, (long) &len);
        if (r == 0 && len == 0)
            PASS();
        else {
            printf("r=%ld len=%d\n", r, len);
            FAIL("zero optlen did not report zero copied bytes");
        }
        raw_syscall1(__NR_close, sv[0]);
        raw_syscall1(__NR_close, sv[1]);
    }
}

int main(void)
{
    printf("test-scm-creds: SCM_CREDENTIALS / SO_PASSCRED\n");

    long pid = raw_syscall0(__NR_getpid);

    /* Create AF_UNIX socketpair */
    TEST("socketpair");
    int sv[2] = {-1, -1};
    long r = raw_syscall4(__NR_socketpair, LINUX_AF_UNIX, LINUX_SOCK_STREAM, 0,
                          (long) sv);
    if (r < 0)
        FAIL("socketpair failed");
    else
        PASS();

    if (r < 0)
        goto done;

    TEST("getsockopt SO_PASSCRED default");
    {
        int val = -1, len = sizeof(val);
        r = raw_syscall5(__NR_getsockopt, sv[1], LINUX_SOL_SOCKET,
                         LINUX_SO_PASSCRED, (long) &val, (long) &len);
        EXPECT_TRUE(r == 0 && val == 0,
                    "SO_PASSCRED default returned wrong value");
    }

    /* Set SO_PASSCRED on receiver */
    TEST("setsockopt SO_PASSCRED");
    int one = 1;
    r = raw_syscall5(__NR_setsockopt, sv[1], LINUX_SOL_SOCKET,
                     LINUX_SO_PASSCRED, (long) &one, sizeof(one));
    EXPECT_TRUE(r == 0, "setsockopt failed");

    /* Read back SO_PASSCRED */
    TEST("getsockopt SO_PASSCRED");
    {
        int val = 0, len = sizeof(val);
        r = raw_syscall5(__NR_getsockopt, sv[1], LINUX_SOL_SOCKET,
                         LINUX_SO_PASSCRED, (long) &val, (long) &len);
        EXPECT_TRUE(r == 0 && val == 1,
                    "getsockopt SO_PASSCRED returned wrong value");
    }

    TEST("SO_PASSCRED normalizes boolean value");
    {
        int val = 42;
        r = raw_syscall5(__NR_setsockopt, sv[1], LINUX_SOL_SOCKET,
                         LINUX_SO_PASSCRED, (long) &val, sizeof(val));
        if (r < 0) {
            FAIL("setsockopt failed");
        } else {
            val = 0;
            int len = sizeof(val);
            r = raw_syscall5(__NR_getsockopt, sv[1], LINUX_SOL_SOCKET,
                             LINUX_SO_PASSCRED, (long) &val, (long) &len);
            EXPECT_TRUE(r == 0 && val == 1,
                        "SO_PASSCRED did not normalize to 1");
        }
    }

    /* Get SO_PEERCRED */
    TEST("getsockopt SO_PEERCRED");
    {
        struct linux_ucred cred = {0};
        int len = sizeof(cred);
        r = raw_syscall5(__NR_getsockopt, sv[0], LINUX_SOL_SOCKET,
                         LINUX_SO_PEERCRED, (long) &cred, (long) &len);
        if (r == 0 && cred.pid == pid && cred.uid == getuid() &&
            cred.gid == getgid())
            PASS();
        else {
            printf("FAIL: SO_PEERCRED: r=%ld pid=%d uid=%u gid=%u (errno=%d)\n",
                   r, cred.pid, cred.uid, cred.gid, errno);
            fails++;
        }
    }

    /* Send a message on sv[0], receive on sv[1] with SCM_CREDENTIALS */
    TEST("recvmsg with SCM_CREDENTIALS");
    {
        /* Send side: 1-byte message without ancillary data */
        char send_byte = 'X';
        struct linux_iov siov = {.iov_base = (unsigned long) &send_byte,
                                 .iov_len = 1};
        struct linux_msghdr smsg = {0};
        smsg.msg_iov = (unsigned long) &siov;
        smsg.msg_iovlen = 1;
        long sent = raw_syscall3(__NR_sendmsg, sv[0], (long) &smsg, 0);
        if (sent <= 0) {
            FAIL("sendmsg failed");
            goto close_fds;
        }

        /* Receive side: expect SCM_CREDENTIALS cmsg */
        char recv_byte = 0;
        struct linux_iov riov = {.iov_base = (unsigned long) &recv_byte,
                                 .iov_len = 1};
        /* Control buffer: 16-byte Linux cmsghdr + 12-byte ucred + padding */
        char ctrl_buf[64];
        memset(ctrl_buf, 0, sizeof(ctrl_buf));
        struct linux_msghdr rmsg = {0};
        rmsg.msg_iov = (unsigned long) &riov;
        rmsg.msg_iovlen = 1;
        rmsg.msg_control = (unsigned long) ctrl_buf;
        rmsg.msg_controllen = sizeof(ctrl_buf);

        long recvd = raw_syscall3(__NR_recvmsg, sv[1], (long) &rmsg, 0);
        if (recvd <= 0) {
            FAIL("recvmsg failed");
            goto close_fds;
        }

        /* Parse the control message */
        if (rmsg.msg_controllen < 28) { /* 16 header + 12 ucred */
            printf("FAIL: controllen too small: %lu (errno=%d)\n",
                   rmsg.msg_controllen, errno);
            fails++;
            goto close_fds;
        }

        /* Linux cmsghdr: u64 len, i32 level, i32 type, then data */
        unsigned long cmsg_len;
        int cmsg_level, cmsg_type;
        memcpy(&cmsg_len, ctrl_buf, 8);
        memcpy(&cmsg_level, ctrl_buf + 8, 4);
        memcpy(&cmsg_type, ctrl_buf + 12, 4);

        struct linux_ucred recv_cred;
        memcpy(&recv_cred, ctrl_buf + 16, sizeof(recv_cred));

        if (cmsg_level == LINUX_SOL_SOCKET &&
            cmsg_type == LINUX_SCM_CREDENTIALS && recv_cred.pid == pid &&
            recv_cred.uid == getuid() && recv_cred.gid == getgid())
            PASS();
        else {
            printf(
                "FAIL: cmsg level=%d type=%d pid=%d uid=%u gid=%u "
                "(errno=%d)\n",
                cmsg_level, cmsg_type, recv_cred.pid, recv_cred.uid,
                recv_cred.gid, errno);
            fails++;
        }
    }

close_fds:
    raw_syscall1(__NR_close, sv[0]);
    raw_syscall1(__NR_close, sv[1]);

done:
    test_accept_inherits_passcred();
    test_blocked_accept_sees_passcred_toggle();
    test_peercred_forked_peers();
    test_peercred_credential_change();
    test_peercred_errors_and_short_len();
    SUMMARY("test-scm-creds");
    return fails ? 1 : 0;
}
