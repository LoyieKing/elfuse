/*
 * memfd identity across an SCM_RIGHTS transfer between elfuse processes
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The host driver launches two independent elfuse instances and connects their
 * stdio with one socketpair. The sender creates a memfd and two unlinked
 * ordinary files, then sends all three; the receiver must see the memfd's name
 * and seal set through /proc/self/fd, its size through ASHMEM_GET_SIZE, and
 * shared bytes through the transferred descriptor. The ordinary file, and one
 * whose name contains "memfd", must stay ordinary, and a slot reused after the
 * memfd must drop the identity.
 *
 * Syscalls exercised: memfd_create(279), ftruncate(46), pread64(67),
 *                     pwrite64(68), fcntl(25), ioctl(29), sendmsg(211),
 *                     recvmsg(212), mkstemp, unlink, dup2(24), read(63),
 *                     write(64), poll(ppoll 73), fgetxattr(193),
 *                     fsetxattr(190), flistxattr(194), fremovexattr(197)
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef SYS_memfd_create
#define SYS_memfd_create 279
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif

#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif

#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif

#ifndef F_SEAL_GROW
#define F_SEAL_GROW 0x0004
#endif

#define ASHMEM_GET_SIZE 0x7704
#define MEMFD_NAME "elfuse-scm-transfer"
#define MEMFD_SIZE 8192
#define SENDER_MAGIC 0x51a7c0deU
#define RECEIVER_MAGIC 0x7ec0ffeeU
#define SHARED_OFFSET 4096
#define MARKER_NAME "com.elfuse.memfd"
#define TRANSFER_TIMEOUT_MS 30000

int passes = 0, fails = 0;

static int read_fd_link(int fd, char *buf, size_t size)
{
    char path[64];
    int n = snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    if (n < 0 || (size_t) n >= sizeof(path))
        return -1;
    ssize_t len = readlink(path, buf, size);
    if (len < 0)
        return -1;
    if ((size_t) len < size)
        buf[len] = '\0';
    return (int) len;
}

static bool wait_readable(int fd, int timeout_ms)
{
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int rc;

    do {
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);
    return rc > 0;
}

static bool send_three_fds(int sock, const int *fds)
{
    union {
        char ctrl[CMSG_SPACE(3 * sizeof(int))];
        struct cmsghdr align;
    } ctrl;
    char payload = 'm';
    struct iovec iov = {.iov_base = &payload, .iov_len = 1};
    struct msghdr msg;
    struct cmsghdr *cmsg;

    memset(&ctrl, 0, sizeof(ctrl));
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.ctrl;
    msg.msg_controllen = sizeof(ctrl.ctrl);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(3 * sizeof(int));
    memcpy(CMSG_DATA(cmsg), fds, 3 * sizeof(int));

    return sendmsg(sock, &msg, 0) == 1;
}

static int recv_three_fds(int sock, int *fds)
{
    union {
        char ctrl[CMSG_SPACE(3 * sizeof(int))];
        struct cmsghdr align;
    } ctrl;
    char payload = 0;
    struct iovec iov = {.iov_base = &payload, .iov_len = 1};
    struct msghdr msg;
    struct cmsghdr *cmsg;
    int count;

    memset(&ctrl, 0, sizeof(ctrl));
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.ctrl;
    msg.msg_controllen = sizeof(ctrl.ctrl);

    if (recvmsg(sock, &msg, 0) != 1)
        return -1;
    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len < CMSG_LEN(0))
        return -1;
    count = (int) ((cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
    if (count > 3)
        count = 3;
    memcpy(fds, CMSG_DATA(cmsg), (size_t) count * sizeof(int));
    return count;
}

static int make_ordinary(const char *template, uint32_t value)
{
    char path[128];
    int n = snprintf(path, sizeof(path), "%s", template);
    if (n < 0 || (size_t) n >= sizeof(path))
        return -1;

    int fd = mkstemp(path);
    if (fd < 0)
        return -1;
    if (unlink(path) < 0 ||
        pwrite(fd, &value, sizeof(value), 0) != (ssize_t) sizeof(value)) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool marker_absent_from_list(int fd)
{
    ssize_t total = flistxattr(fd, NULL, 0);
    if (total <= 0)
        return total == 0;

    char *list = malloc((size_t) total);
    if (!list)
        return false;
    ssize_t got = flistxattr(fd, list, (size_t) total);
    if (got < 0) {
        free(list);
        return false;
    }

    bool absent = true;
    for (ssize_t off = 0; off < got; off += (ssize_t) strlen(list + off) + 1) {
        if (!strcmp(list + off, MARKER_NAME)) {
            absent = false;
            break;
        }
    }
    free(list);
    return absent;
}

static void check_marker_hidden(int fd)
{
    char value[32];

    TEST("memfd marker hidden from fgetxattr");
    errno = 0;
    EXPECT_ERRNO(fgetxattr(fd, MARKER_NAME, value, sizeof(value)), EOPNOTSUPP,
                 "guest read the memfd marker");

    TEST("memfd marker hidden from fsetxattr");
    errno = 0;
    EXPECT_ERRNO(fsetxattr(fd, MARKER_NAME, "x", 1, 0), EOPNOTSUPP,
                 "guest replaced the memfd marker");

    TEST("memfd marker hidden from fremovexattr");
    errno = 0;
    EXPECT_ERRNO(fremovexattr(fd, MARKER_NAME), EOPNOTSUPP,
                 "guest removed the memfd marker");

    TEST("memfd marker hidden from flistxattr");
    EXPECT_TRUE(marker_absent_from_list(fd), "guest listed the memfd marker");
}

static void check_path_marker_reserved(void)
{
    char path[] = "/tmp/elfuse-memfd-scm-xattr-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        TEST("memfd marker hidden from path xattr calls");
        FAIL("mkstemp failed");
        return;
    }
    close(fd);

    TEST("memfd marker hidden from getxattr");
    errno = 0;
    EXPECT_ERRNO(getxattr(path, MARKER_NAME, NULL, 0), EOPNOTSUPP,
                 "path getxattr reached the reserved name");

    TEST("memfd marker hidden from setxattr");
    errno = 0;
    EXPECT_ERRNO(setxattr(path, MARKER_NAME, "x", 1, 0), EOPNOTSUPP,
                 "path setxattr reached the reserved name");

    TEST("memfd marker hidden from removexattr");
    errno = 0;
    EXPECT_ERRNO(removexattr(path, MARKER_NAME), EOPNOTSUPP,
                 "path removexattr reached the reserved name");

    unlink(path);
}

static int sender_main(void)
{
    uint32_t sentinel = SENDER_MAGIC;
    char link[512];

    printf("test-memfd-scm sender: memfd to a second elfuse instance\n");

    int mfd = (int) syscall(SYS_memfd_create, MEMFD_NAME, MFD_ALLOW_SEALING);
    if (mfd < 0) {
        TEST("sender creates a memfd");
        FAIL("memfd_create failed");
        return 1;
    }
    if (ftruncate(mfd, MEMFD_SIZE) < 0 ||
        pwrite(mfd, &sentinel, sizeof(sentinel), 0) !=
            (ssize_t) sizeof(sentinel)) {
        TEST("sender fills the memfd");
        FAIL("ftruncate or pwrite failed");
        close(mfd);
        return 1;
    }
    if (fcntl(mfd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK) < 0) {
        TEST("sender seals the memfd");
        FAIL("F_ADD_SEALS failed");
        close(mfd);
        return 1;
    }

    int len = read_fd_link(mfd, link, sizeof(link));
    TEST("sender memfd magic link");
    EXPECT_TRUE(len >= 0 && !strcmp(link, "/memfd:" MEMFD_NAME " (deleted)"),
                "sender lost its memfd name");

    TEST("sender memfd seals");
    EXPECT_EQ(fcntl(mfd, F_GET_SEALS), F_SEAL_GROW | F_SEAL_SHRINK,
              "sender lost its seal set");

    int ordinary =
        make_ordinary("/tmp/elfuse-memfd-scm-ordinary-XXXXXX", SENDER_MAGIC);
    int prefixed =
        make_ordinary("/tmp/memfd:elfuse-scm-prefix-XXXXXX", SENDER_MAGIC);
    if (ordinary < 0 || prefixed < 0) {
        TEST("sender creates ordinary files");
        FAIL("mkstemp failed");
        close(mfd);
        if (ordinary >= 0)
            close(ordinary);
        if (prefixed >= 0)
            close(prefixed);
        return 1;
    }

    int fds[3] = {mfd, ordinary, prefixed};
    TEST("sender transfers the descriptors");
    if (!send_three_fds(STDIN_FILENO, fds)) {
        FAIL("sendmsg failed");
        close(mfd);
        close(ordinary);
        close(prefixed);
        return 1;
    }

    TEST("sender sees the receiver's write");
    bool shared = false;
    if (wait_readable(STDIN_FILENO, TRANSFER_TIMEOUT_MS)) {
        char ack = 0;
        uint32_t received = 0;
        if (read(STDIN_FILENO, &ack, 1) == 1 && ack == 'A' &&
            pread(mfd, &received, sizeof(received), SHARED_OFFSET) ==
                (ssize_t) sizeof(received) &&
            received == RECEIVER_MAGIC)
            shared = true;
    }
    close(mfd);
    close(ordinary);
    close(prefixed);
    EXPECT_TRUE(shared, "senders and receivers did not share memfd bytes");

    SUMMARY("test-memfd-scm sender");
    return fails == 0 ? 0 : 1;
}

static int receiver_main(void)
{
    int fds[3];
    int count;
    char link[512];

    printf("test-memfd-scm receiver: SCM_RIGHTS memfd from another elfuse\n");

    TEST("receiver waits for the transfer");
    if (!wait_readable(STDIN_FILENO, TRANSFER_TIMEOUT_MS)) {
        FAIL("no message arrived");
        return 1;
    }
    count = recv_three_fds(STDIN_FILENO, fds);
    if (count != 3) {
        TEST("receiver receives three descriptors");
        FAIL("recvmsg did not deliver three fds");
        return 1;
    }

    int mfd = fds[0];
    int ordinary = fds[1];
    int prefixed = fds[2];
    uint32_t received = 0;
    struct stat st;

    int len = read_fd_link(mfd, link, sizeof(link));
    TEST("received memfd magic link");
    EXPECT_TRUE(len >= 0 && !strcmp(link, "/memfd:" MEMFD_NAME " (deleted)"),
                "received memfd lost its exact name");

    TEST("received memfd fstat size");
    if (fstat(mfd, &st) == 0)
        EXPECT_EQ(st.st_size, MEMFD_SIZE, "received memfd changed size");
    else
        FAIL("fstat failed on the received memfd");

    TEST("received memfd ASHMEM_GET_SIZE");
    EXPECT_EQ(ioctl(mfd, ASHMEM_GET_SIZE, 0), MEMFD_SIZE,
              "received memfd did not answer ashmem size");

    TEST("received memfd seals");
    EXPECT_EQ(fcntl(mfd, F_GET_SEALS), F_SEAL_GROW | F_SEAL_SHRINK,
              "seals did not survive the transfer");

    TEST("received memfd seals deny a shrink");
    errno = 0;
    EXPECT_ERRNO(ftruncate(mfd, MEMFD_SIZE - 4096), EPERM,
                 "received memfd ignored its shrink seal");

    TEST("received memfd data");
    EXPECT_TRUE(pread(mfd, &received, sizeof(received), 0) ==
                        (ssize_t) sizeof(received) &&
                    received == SENDER_MAGIC,
                "received memfd did not share the sender's bytes");

    check_marker_hidden(mfd);
    check_path_marker_reserved();

    received = RECEIVER_MAGIC;
    if (pwrite(mfd, &received, sizeof(received), SHARED_OFFSET) !=
        (ssize_t) sizeof(received)) {
        TEST("receiver writes through the received memfd");
        FAIL("pwrite failed");
    }
    char ack = 'A';
    if (write(STDIN_FILENO, &ack, 1) != 1) {
        TEST("receiver acknowledges the shared write");
        FAIL("write failed");
    }

    len = read_fd_link(ordinary, link, sizeof(link));
    TEST("received ordinary file magic link");
    EXPECT_TRUE(len >= 0 && strncmp(link, "/memfd:", 7) != 0,
                "ordinary file claimed a memfd identity");
    TEST("received ordinary file ASHMEM_GET_SIZE");
    errno = 0;
    EXPECT_ERRNO(ioctl(ordinary, ASHMEM_GET_SIZE, 0), ENOTTY,
                 "ordinary file answered the ashmem probe");
    TEST("received ordinary file data");
    EXPECT_TRUE(pread(ordinary, &received, sizeof(received), 0) ==
                        (ssize_t) sizeof(received) &&
                    received == SENDER_MAGIC,
                "ordinary file did not carry its bytes");

    len = read_fd_link(prefixed, link, sizeof(link));
    TEST("received prefix-named file magic link");
    EXPECT_TRUE(len >= 0 && strncmp(link, "/memfd:", 7) != 0,
                "a path containing memfd forged the identity");
    errno = 0;
    EXPECT_ERRNO(ioctl(prefixed, ASHMEM_GET_SIZE, 0), ENOTTY,
                 "prefix-named file answered the ashmem probe");

    if (dup2(ordinary, mfd) < 0) {
        TEST("receiver reuses the memfd slot");
        FAIL("dup2 failed");
    } else {
        len = read_fd_link(mfd, link, sizeof(link));
        TEST("reused slot drops the memfd identity");
        EXPECT_TRUE(len >= 0 && strncmp(link, "/memfd:", 7) != 0,
                    "reused slot kept the received memfd identity");
        errno = 0;
        EXPECT_ERRNO(ioctl(mfd, ASHMEM_GET_SIZE, 0), ENOTTY,
                     "reused slot kept ashmem support");
        EXPECT_EQ(fcntl(mfd, F_GET_SEALS), 0,
                  "reused slot kept the received seals");
    }

    close(mfd);
    close(ordinary);
    close(prefixed);

    SUMMARY("test-memfd-scm receiver");
    return fails == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "sender"))
        return sender_main();
    if (argc > 1 && !strcmp(argv[1], "receiver"))
        return receiver_main();
    fprintf(stderr, "test-memfd-scm: expected sender or receiver\n");
    return 2;
}
