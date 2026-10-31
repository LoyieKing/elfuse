/*
 * Host-literal fallback regression tests for case-insensitive sysroots
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * proc_resolve_sysroot_path_flags resolves absolute guest paths inside the
 * sysroot when they exist there and otherwise falls back to the literal host
 * path so guests can reach host resources (mktemp dirs, /etc/resolv.conf). On a
 * case-insensitive sysroot an earlier walk used to veto that fallback: it
 * anchored every absolute path at the sysroot root and returned ENOENT as soon
 * as a component was missing there, which broke every coreutils invocation
 * against a host mktemp directory (test-matrix "musl dyn" suite).
 *
 * The harness (mk/tests.mk) runs this binary under --sysroot with a
 * case-insensitive sysroot so the case-exact walk is active, and passes:
 *   argv[1]  host directory whose intermediate components do not exist in
 *            the sysroot; contains hello.txt ("host-visible\n")
 *   argv[2]  host file whose parent chain is fully mirrored inside the
 *            sysroot but whose final component exists only on the host
 *            ("host-final\n")
 *   argv[3]  file that exists both on the host ("host-loses\n") and in the
 *            sysroot mirror ("sysroot-wins\n"); the sysroot copy must win
 */

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test-harness.h"
#include "test-util.h"

int passes = 0, fails = 0;

static int path_join(char *out, size_t outsz, const char *dir, const char *leaf)
{
    int n = snprintf(out, outsz, "%s/%s", dir, leaf);
    return (n < 0 || (size_t) n >= outsz) ? -1 : 0;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr,
                "usage: %s <host-dir> <host-final-file> <both-sides-file>\n",
                argv[0]);
        return 1;
    }
    const char *host_dir = argv[1];
    const char *host_final = argv[2];
    const char *both_sides = argv[3];
    char path[4096];
    char moved[4096];
    char buf[64];

    printf("test-sysroot-host-fallback: host paths outside the sysroot\n");

    TEST("read through missing intermediates");
    if (path_join(path, sizeof(path), host_dir, "hello.txt") < 0)
        FAIL("path too long");
    else if (read_file_nul(path, buf, sizeof(buf)) <= 0)
        FAIL("open/read fell into the sysroot");
    else if (strcmp(buf, "host-visible\n"))
        FAIL("read wrong contents");
    else
        PASS();

    TEST("stat host file");
    {
        struct stat st;
        if (stat(path, &st) < 0 || !S_ISREG(st.st_mode))
            FAIL("stat failed");
        else
            PASS();
    }

    TEST("create/write/read-back/unlink");
    if (path_join(path, sizeof(path), host_dir, "created.txt") < 0) {
        FAIL("path too long");
    } else {
        int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
        if (fd < 0 || write_fd_all(fd, "guest-wrote\n", 12) < 0)
            FAIL("create/write failed");
        else if (close(fd), read_file_nul(path, buf, sizeof(buf)) <= 0 ||
                                strcmp(buf, "guest-wrote\n"))
            FAIL("read-back mismatch");
        else if (unlink(path) < 0)
            FAIL("unlink failed");
        else
            PASS();
    }

    TEST("mkdir/rmdir host subdir");
    if (path_join(path, sizeof(path), host_dir, "subdir") < 0)
        FAIL("path too long");
    else if (mkdir(path, 0755) < 0)
        FAIL("mkdir failed");
    else if (rmdir(path) < 0)
        FAIL("rmdir failed");
    else
        PASS();

    TEST("rename within host dir");
    if (path_join(path, sizeof(path), host_dir, "hello.txt") < 0 ||
        path_join(moved, sizeof(moved), host_dir, "moved.txt") < 0)
        FAIL("path too long");
    else if (rename(path, moved) < 0)
        FAIL("rename failed");
    else if (read_file_nul(moved, buf, sizeof(buf)) <= 0 ||
             strcmp(buf, "host-visible\n"))
        FAIL("moved file unreadable");
    else if (rename(moved, path) < 0)
        FAIL("rename back failed");
    else
        PASS();

    TEST("missing final component falls back");
    if (read_file_nul(host_final, buf, sizeof(buf)) <= 0)
        FAIL("open/read fell into the sysroot");
    else if (strcmp(buf, "host-final\n"))
        FAIL("read wrong contents");
    else
        PASS();

    TEST("sysroot copy still wins over host");
    if (read_file_nul(both_sides, buf, sizeof(buf)) <= 0)
        FAIL("read failed");
    else if (strcmp(buf, "sysroot-wins\n"))
        FAIL("host copy shadowed the sysroot");
    else
        PASS();

    TEST("sysroot passwd file wins over synthetic intercept");
    if (read_file_nul("/etc/passwd", buf, sizeof(buf)) <= 0)
        FAIL("read /etc/passwd failed");
    else if (strcmp(buf, "guest-passwd\n"))
        FAIL("did not bypass /etc/passwd synthetic intercept");
    else
        PASS();

    TEST("absent sysroot group file falls back to synthetic intercept");
    {
        FILE *groups = fopen("/etc/group", "r");
        if (!groups)
            FAIL("read /etc/group failed");
        else {
            struct group *group;
            while ((group = fgetgrent(groups)) != NULL) {
                if (!strcmp(group->gr_name, "user"))
                    break;
            }
            if (!group)
                FAIL("synthetic user group missing");
            else if (group->gr_gid != getegid())
                FAIL("synthetic user group does not match guest GID");
            else
                PASS();
            fclose(groups);
        }
    }

    TEST("blocked guest system path does not fall back to host");
    {
        int fd = open("/usr/bin/env", O_RDONLY);
        if (fd < 0 && errno == ENOENT)
            PASS();
        else {
            if (fd >= 0)
                close(fd);
            FAIL("guest system path fell back to host");
        }
    }

    TEST("dot-component guest system path does not fall back to host");
    {
        int fd = open("/tmp/../usr/bin/env", O_RDONLY);
        if (fd < 0 && errno == ENOENT)
            PASS();
        else {
            if (fd >= 0)
                close(fd);
            FAIL("dot-component system path fell back to host");
        }
    }

    TEST("allowed guest network configuration falls back to host");
    {
        int fd = open("/etc/hosts", O_RDONLY);
        if (fd >= 0) {
            close(fd);
            PASS();
        } else
            FAIL("allowed network config did not fall back to host");
    }

    SUMMARY("test-sysroot-host-fallback");
    return fails > 0 ? 1 : 0;
}
