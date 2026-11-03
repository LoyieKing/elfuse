/*
 * memfd ashmem-compatibility regression test
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers libcutils __has_memfd_support, /memfd:name (deleted) magic links, and
 * ASHMEM_GET_SIZE answering only for memfds.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef SYS_memfd_create
#define SYS_memfd_create 279
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif

#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE 0x0010
#endif

#ifndef ASHMEM_GET_SIZE
#define ASHMEM_GET_SIZE 0x7704
#endif

/* NAME_MAX (255) minus the kernel's "memfd:" prefix (mm/memfd.c). */
#define MEMFD_NAME_MAX 249

int passes = 0, fails = 0;

static int create_memfd(const char *name, unsigned int flags)
{
    return (int) syscall(SYS_memfd_create, name, flags);
}

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

static void test_ashmem_probe_sequence(void)
{
    TEST("ashmem memfd support probe");

    int fd =
        create_memfd("test_android_memfd", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) {
        FAIL("memfd_create failed");
        return;
    }
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) < 0) {
        FAIL("F_ADD_SEALS F_SEAL_FUTURE_WRITE failed");
        close(fd);
        return;
    }
    size_t page = (size_t) sysconf(_SC_PAGESIZE);
    if (ftruncate(fd, (off_t) page) < 0) {
        FAIL("ftruncate failed");
        close(fd);
        return;
    }
    int size = (int) ioctl(fd, ASHMEM_GET_SIZE, 0);
    close(fd);
    EXPECT_EQ(size, (int) page,
              "ASHMEM_GET_SIZE did not report the memfd size");
}

static void test_memfd_magic_link_name(void)
{
    TEST("memfd magic link name");

    int fd = create_memfd("elfuse-memfd-link", MFD_ALLOW_SEALING);
    if (fd < 0) {
        FAIL("memfd_create failed");
        return;
    }
    char link[512];
    int len = read_fd_link(fd, link, sizeof(link));
    close(fd);
    EXPECT_TRUE(len >= 0 && !strcmp(link, "/memfd:elfuse-memfd-link (deleted)"),
                "readlink did not report /memfd:name (deleted)");
}

static void test_memfd_empty_name(void)
{
    TEST("memfd empty name magic link");

    int fd = create_memfd("", 0);
    if (fd < 0) {
        FAIL("memfd_create rejected an empty name");
        return;
    }
    char link[64];
    int len = read_fd_link(fd, link, sizeof(link));
    close(fd);
    EXPECT_TRUE(len >= 0 && !strcmp(link, "/memfd: (deleted)"),
                "empty memfd name did not round-trip");
}

static void test_memfd_name_bound(void)
{
    char name[MEMFD_NAME_MAX + 2];

    TEST("memfd name of 249 bytes");
    memset(name, 'n', MEMFD_NAME_MAX);
    name[MEMFD_NAME_MAX] = '\0';
    int fd = create_memfd(name, 0);
    EXPECT_TRUE(fd >= 0, "249-byte memfd name was rejected");
    if (fd >= 0)
        close(fd);

    TEST("memfd name of 250 bytes");
    memset(name, 'n', MEMFD_NAME_MAX + 1);
    name[MEMFD_NAME_MAX + 1] = '\0';
    errno = 0;
    EXPECT_ERRNO(create_memfd(name, 0), EINVAL,
                 "250-byte memfd name was not rejected");
}

static void test_ordinary_file_is_not_ashmem(void)
{
    char path[] = "/tmp/elfuse-memfd-ashmem-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        TEST("ordinary file ashmem probe");
        FAIL("mkstemp failed");
        return;
    }
    unlink(path);

    TEST("ordinary file ASHMEM_GET_SIZE");
    errno = 0;
    EXPECT_ERRNO(ioctl(fd, ASHMEM_GET_SIZE, 0), ENOTTY,
                 "ordinary file did not answer ENOTTY");

    TEST("ordinary file magic link");
    char link[512];
    int len = read_fd_link(fd, link, sizeof(link));
    EXPECT_TRUE(len > 0 && strncmp(link, "/memfd:", 7) != 0,
                "ordinary file claimed a memfd magic link");
    close(fd);
}

static void test_dup_shares_memfd_identity(void)
{
    TEST("dup shares memfd identity");

    int fd = create_memfd("elfuse-memfd-alias", MFD_ALLOW_SEALING);
    if (fd < 0) {
        FAIL("memfd_create failed");
        return;
    }
    if (ftruncate(fd, 8192) < 0) {
        FAIL("ftruncate failed");
        close(fd);
        return;
    }
    int dupfd = dup(fd);
    if (dupfd < 0) {
        FAIL("dup failed");
        close(fd);
        return;
    }

    char link[512];
    int len = read_fd_link(dupfd, link, sizeof(link));
    int size = (int) ioctl(dupfd, ASHMEM_GET_SIZE, 0);
    close(dupfd);
    close(fd);
    EXPECT_TRUE(len >= 0 &&
                    !strcmp(link, "/memfd:elfuse-memfd-alias (deleted)") &&
                    size == 8192,
                "dup lost the memfd identity or size");
}

static void test_reused_slot_drops_memfd_identity(void)
{
    TEST("reused fd drops memfd identity");

    int fd = create_memfd("elfuse-memfd-reused", MFD_ALLOW_SEALING);
    if (fd < 0) {
        FAIL("memfd_create failed");
        return;
    }

    char path[] = "/tmp/elfuse-memfd-reuse-XXXXXX";
    int regular = mkstemp(path);
    if (regular < 0) {
        FAIL("mkstemp failed");
        close(fd);
        return;
    }
    unlink(path);
    if (dup2(regular, fd) < 0) {
        FAIL("dup2 failed");
        close(regular);
        close(fd);
        return;
    }
    close(regular);

    errno = 0;
    int size = (int) ioctl(fd, ASHMEM_GET_SIZE, 0);
    int ioctl_errno = errno;
    char link[512];
    int len = read_fd_link(fd, link, sizeof(link));
    close(fd);
    EXPECT_TRUE(size == -1 && ioctl_errno == ENOTTY && len > 0 &&
                    strncmp(link, "/memfd:", 7) != 0,
                "reused slot kept the previous memfd identity");
}

static int child_memfd_matches(int fd, uint64_t want_size)
{
    char link[512];
    int len = read_fd_link(fd, link, sizeof(link));
    int size = (int) ioctl(fd, ASHMEM_GET_SIZE, 0);
    return len >= 0 && !strcmp(link, "/memfd:elfuse-memfd-fork (deleted)") &&
           (uint64_t) size == want_size;
}

static void test_fork_preserves_memfd_identity(void)
{
    TEST("fork preserves memfd identity");

    int fd = create_memfd("elfuse-memfd-fork", MFD_ALLOW_SEALING);
    if (fd < 0) {
        FAIL("memfd_create failed");
        return;
    }
    if (ftruncate(fd, 12288) < 0) {
        FAIL("ftruncate failed");
        close(fd);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork failed");
        close(fd);
        return;
    }
    if (pid == 0)
        _exit(child_memfd_matches(fd, 12288) ? 0 : 1);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        FAIL("waitpid failed");
        close(fd);
        return;
    }
    bool child_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    bool parent_ok = child_memfd_matches(fd, 12288);
    close(fd);
    EXPECT_TRUE(child_ok && parent_ok,
                "memfd identity did not survive fork in both processes");
}

int main(void)
{
    printf("test-memfd-ashmem: memfd identity and ashmem ioctl tests\n\n");

    test_ashmem_probe_sequence();
    test_memfd_magic_link_name();
    test_memfd_empty_name();
    test_memfd_name_bound();
    test_ordinary_file_is_not_ashmem();
    test_dup_shares_memfd_identity();
    test_reused_slot_drops_memfd_identity();
    test_fork_preserves_memfd_identity();

    SUMMARY("test-memfd-ashmem");
    return fails == 0 ? 0 : 1;
}
