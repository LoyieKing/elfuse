/*
 * --strict-sysroot containment regression
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Every case names a real file, so a regression shows up as a descriptor or an
 * on-disk entry rather than as a policy flag read back. The lane stages a
 * sysroot and a host directory outside it, then runs this binary under both
 * --sysroot and --strict-sysroot:
 *
 *   argv[1]  host directory outside the sysroot; holds secret.txt and is where
 *            a refused create must leave no evil.txt or sock
 *
 * The staged sysroot holds /d/inside.txt ("inside-sysroot"), /d/good-link
 * pointing at /d/inside.txt, /d/host-link pointing at <outside>/secret.txt,
 * /d/host-dir pointing at <outside>, /data/, and a copy of this binary at
 * /bin/strict-probe. After the guest exits the recipe asserts that
 * <outside>/evil.txt and <outside>/sock were never created and that
 * <sysroot>/data/new.txt was.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"
#include "test-util.h"

int passes = 0, fails = 0;

#define SOCK_PATH "/dev/socket/umaru/1/ctl"

/* Read @path into @buf, NUL terminated, returning the byte count or -1. */
static ssize_t read_text(const char *path, char *buf, size_t bufsz)
{
    int fd = open(path, O_RDONLY);

    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, bufsz - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return n;
}

/* True when @path cannot be read. A descriptor is the failure these cases
 * exist to catch, so only the open's own error counts as a refusal.
 */
static bool open_refused(const char *path)
{
    int fd = open(path, O_RDONLY);

    if (fd < 0)
        return true;
    close(fd);
    return false;
}

/* What a forked or exec'd child checks: the policy it inherited still refuses
 * the host literal and the guest symlink that leaves the root. Returns 0 when
 * both were refused, so the parent can assert on the exit status alone.
 */
static int probe_mode(const char *outside)
{
    char host_only[PATH_MAX];
    int bad = 0;

    if (snprintf(host_only, sizeof(host_only), "%s/secret.txt", outside) >=
        (int) sizeof(host_only))
        return 2;
    if (!open_refused(host_only)) {
        fprintf(stderr, "probe: read a host file absent from the sysroot\n");
        bad = 1;
    }
    if (!open_refused("/d/host-link")) {
        fprintf(stderr, "probe: followed a guest symlink out of the sysroot\n");
        bad = 1;
    }
    return bad;
}

/* The same fixture without --strict-sysroot. Both names resolve here, which is
 * what makes the strict refusals above a property of the policy rather than of
 * the staging; the lane runs this mode under a plain --sysroot.
 */
static int default_mode(const char *outside)
{
    char host_only[PATH_MAX];
    char buf[256];
    int bad = 0;

    if (snprintf(host_only, sizeof(host_only), "%s/secret.txt", outside) >=
        (int) sizeof(host_only))
        return 2;
    if (read_text(host_only, buf, sizeof(buf)) < 0 ||
        strcmp(buf, "SECRET-HOST-FILE\n") != 0) {
        fprintf(stderr, "default: host literal did not resolve\n");
        bad = 1;
    }
    if (read_text("/d/host-link", buf, sizeof(buf)) < 0 ||
        strcmp(buf, "SECRET-HOST-FILE\n") != 0) {
        fprintf(stderr, "default: guest symlink to the host did not resolve\n");
        bad = 1;
    }
    return bad;
}

static void socket_cases(const char *outside)
{
    static const char *const dirs[] = {
        "/dev",
        "/dev/socket",
        "/dev/socket/umaru",
        "/dev/socket/umaru/1",
    };
    struct sockaddr_un sa;
    socklen_t slen;
    struct stat st;
    int lfd = -1;

    TEST("socket directory mkdir");
    bool dirs_ok = true;
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        if (mkdir(dirs[i], 0755) != 0 && errno != EEXIST)
            dirs_ok = false;
    }
    EXPECT_TRUE(dirs_ok, "mkdir under /dev/socket");

    TEST("bind lands inside the strict root");
    lfd = unix_bind(SOCK_PATH, SOCK_STREAM, 4);
    EXPECT_TRUE(lfd >= 0, "unix_bind at /dev/socket/umaru/1/ctl");

    TEST("getsockname returns the guest bytes");
    memset(&sa, 0, sizeof(sa));
    slen = sizeof(sa);
    if (lfd < 0)
        FAIL("no listener");
    else if (getsockname(lfd, (struct sockaddr *) &sa, &slen) != 0)
        FAIL("getsockname");
    else
        EXPECT_TRUE(!strcmp(sa.sun_path, SOCK_PATH),
                    "address carried a sysroot spelling");

    TEST("stat sees the bound socket");
    EXPECT_TRUE(stat(SOCK_PATH, &st) == 0 && S_ISSOCK(st.st_mode),
                "stat on the socket path");

    TEST("connect and accept round trip");
    {
        int cfd = socket(AF_UNIX, SOCK_STREAM, 0);
        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", SOCK_PATH);
        char token = '?';
        if (cfd < 0) {
            FAIL("socket");
        } else if (connect(cfd, (struct sockaddr *) &sa, sizeof(sa)) != 0 ||
                   write(cfd, "t", 1) != 1) {
            FAIL("connect");
            close(cfd);
        } else {
            int peer = accept(lfd, NULL, NULL);
            if (peer < 0 || read(peer, &token, 1) != 1 || token != 't')
                FAIL("accept/read");
            else
                PASS();
            if (peer >= 0)
                close(peer);
            close(cfd);
        }
    }

    TEST("socket outside the root is refused");
    {
        char outside_sock[PATH_MAX];
        if (snprintf(outside_sock, sizeof(outside_sock), "%s/sock", outside) >=
            (int) sizeof(outside_sock)) {
            FAIL("outside path too long");
        } else {
            int sfd = unix_bind(outside_sock, SOCK_STREAM, 1);
            if (sfd >= 0) {
                close(sfd);
                FAIL("bound a socket outside the root");
            } else {
                PASS();
            }
        }
    }

    if (lfd >= 0)
        close(lfd);
}

int main(int argc, char **argv)
{
    if (argc >= 3 && !strcmp(argv[1], "probe"))
        return probe_mode(argv[2]);
    if (argc >= 3 && !strcmp(argv[1], "default"))
        return default_mode(argv[2]);
    if (argc < 2) {
        fprintf(stderr, "usage: %s <host-dir-outside-sysroot>\n", argv[0]);
        return 2;
    }
    char *outside = argv[1];
    char path[PATH_MAX];
    char buf[256];

    printf("test-strict-sysroot: --strict-sysroot containment\n");

    TEST("in-sysroot file reads");
    if (read_text("/d/inside.txt", buf, sizeof(buf)) < 0 ||
        strcmp(buf, "inside-sysroot\n") != 0)
        FAIL("open /d/inside.txt");
    else
        PASS();

    TEST("guest-absolute symlink inside the root resolves");
    if (read_text("/d/good-link", buf, sizeof(buf)) < 0 ||
        strcmp(buf, "inside-sysroot\n") != 0)
        FAIL("open /d/good-link");
    else
        PASS();

    TEST("host file absent from the root is refused");
    if (snprintf(path, sizeof(path), "%s/secret.txt", outside) >=
        (int) sizeof(path))
        FAIL("outside path too long");
    else if (!open_refused(path))
        FAIL("read a host file the sysroot does not hold");
    else
        PASS();

    TEST("guest symlink to the host is refused");
    EXPECT_TRUE(open_refused("/d/host-link"), "followed /d/host-link");

    TEST("symlinked directory escape is refused");
    EXPECT_TRUE(open_refused("/d/host-dir/secret.txt"),
                "read through a directory symlink out of the root");

    TEST("relative dirfd read stays in the root");
    {
        int dirfd = open("/d", O_RDONLY | O_DIRECTORY);
        if (dirfd < 0) {
            FAIL("open /d");
        } else {
            int fd = openat(dirfd, "inside.txt", O_RDONLY);
            if (fd < 0)
                FAIL("openat(dirfd, inside.txt)");
            else {
                close(fd);
                PASS();
            }
            close(dirfd);
        }
    }

    TEST("relative dirfd symlink escape is refused");
    {
        int dirfd = open("/d", O_RDONLY | O_DIRECTORY);
        if (dirfd < 0) {
            FAIL("open /d");
        } else {
            int fd = openat(dirfd, "host-link", O_RDONLY);
            if (fd < 0)
                PASS();
            else {
                close(fd);
                FAIL("openat followed a link out of the root");
            }
            close(dirfd);
        }
    }

    TEST("dirfd-relative climb is clamped at the root");
    {
        int dirfd = open("/d", O_RDONLY | O_DIRECTORY);
        if (dirfd < 0) {
            FAIL("open /d");
        } else {
            int fd =
                openat(dirfd, "../../../../../../../../etc/passwd", O_RDONLY);
            if (fd < 0)
                PASS();
            else {
                close(fd);
                FAIL("openat climbed to the host /etc/passwd");
            }
            close(dirfd);
        }
    }

    TEST("absolute path through a dirfd is still confined");
    {
        int dirfd = open("/d", O_RDONLY | O_DIRECTORY);
        if (dirfd < 0) {
            FAIL("open /d");
        } else if (snprintf(path, sizeof(path), "%s/secret.txt", outside) >=
                   (int) sizeof(path)) {
            FAIL("outside path too long");
        } else {
            int fd = openat(dirfd, path, O_RDONLY);
            if (fd < 0)
                PASS();
            else {
                close(fd);
                FAIL("openat ignored dirfd and opened the host file");
            }
            close(dirfd);
        }
    }

    TEST("cwd-relative escape is refused");
    if (chdir("/d") != 0) {
        FAIL("chdir /d");
    } else if (!open_refused("host-link")) {
        FAIL("opened the host through a cwd-relative name");
    } else if (read_text("inside.txt", buf, sizeof(buf)) < 0 ||
               strcmp(buf, "inside-sysroot\n") != 0) {
        FAIL("re-reading inside.txt from the new cwd");
    } else {
        PASS();
    }
    if (chdir("/") != 0)
        FAIL("chdir /");

    TEST("create lands inside the root");
    {
        int fd = open("/data/new.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (fd < 0) {
            FAIL("open /data/new.txt with O_CREAT");
        } else {
            ssize_t n = write(fd, "created-in-root\n", 16);
            close(fd);
            if (n != 16)
                FAIL("write /data/new.txt");
            else if (read_text("/data/new.txt", buf, sizeof(buf)) < 0 ||
                     strcmp(buf, "created-in-root\n") != 0)
                FAIL("read back /data/new.txt");
            else
                PASS();
        }
    }

    TEST("create through a host symlinked dir is refused");
    {
        int fd = open("/d/host-dir/evil.txt", O_CREAT | O_RDWR, 0644);
        if (fd < 0) {
            PASS();
        } else {
            close(fd);
            FAIL("created a file outside the root");
        }
    }

    socket_cases(outside);

    TEST("strict policy survives fork");
    {
        pid_t pid = fork();
        if (pid == 0)
            _exit(probe_mode(outside) == 0 ? 0 : 1);
        int st = pid > 0 ? reap_within(pid, 10000) : -1;
        EXPECT_TRUE(pid > 0 && st == 0, "forked child reached the host");
    }

    TEST("strict policy survives exec");
    {
        pid_t pid = fork();
        if (pid == 0) {
            char *av[] = {"strict-probe", "probe", outside, NULL};
            execve("/bin/strict-probe", av, environ);
            _exit(111);
        }
        int st = pid > 0 ? reap_within(pid, 20000) : -1;
        if (st == 111)
            FAIL("execve /bin/strict-probe failed");
        else
            EXPECT_TRUE(pid > 0 && st == 0, "exec'd guest reached the host");
    }

    SUMMARY("test-strict-sysroot");
    return fails == 0 ? 0 : 1;
}