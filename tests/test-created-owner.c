/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

static const char file_path[] = "/tmp/creator-file";
static const char renamed_path[] = "/tmp/creator-renamed";
static const char hard_path[] = "/tmp/creator-hard";
static const char dir_path[] = "/tmp/creator-dir";
static const char link_path[] = "/tmp/creator-link";
static const char dangling_path[] = "/tmp/creator-dangling";
static const char chain_path[] = "/tmp/creator-chain";
static const char target_path[] = "/tmp/creator-target";

static void expect_owner(const char *path, uid_t uid, gid_t gid)
{
    TEST(path);
    struct stat st;
    if (lstat(path, &st) != 0) {
        FAIL("lstat");
        return;
    }
    if (st.st_uid != uid || st.st_gid != gid)
        printf("owner=%u:%u expected=%u:%u\n", (unsigned int) st.st_uid,
               (unsigned int) st.st_gid, (unsigned int) uid,
               (unsigned int) gid);
    EXPECT_TRUE(st.st_uid == uid && st.st_gid == gid, "inode owner mismatch");
}

static void create_files(void)
{
    TEST("create with guest credentials");
    int fd = open(file_path, O_CREAT | O_EXCL | O_RDWR, 0666);
    if (fd < 0) {
        FAIL("open");
        return;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        FAIL("fstat");
        close(fd);
        return;
    }
    EXPECT_TRUE(st.st_uid == geteuid() && st.st_gid == getegid(),
                "new file lost creator credentials");
    close(fd);
    TEST("create directory");
    EXPECT_TRUE(mkdir(dir_path, 0777) == 0, "mkdir");
    TEST("create symlink");
    EXPECT_TRUE(symlink("creator-file", link_path) == 0, "symlink");
    TEST("create dangling symlink chain");
    EXPECT_TRUE(symlink("creator-target", dangling_path) == 0, "symlink");
    EXPECT_TRUE(symlink("creator-dangling", chain_path) == 0, "symlink");
    TEST("O_CREAT with O_EXCL rejects a dangling leaf");
    fd = open(chain_path, O_CREAT | O_EXCL | O_RDWR, 0666);
    EXPECT_TRUE(fd == -1 && errno == EEXIST,
                "exclusive open followed the symlink");
    if (fd >= 0)
        close(fd);
    TEST("O_CREAT with O_NOFOLLOW rejects a dangling leaf");
    fd = open(chain_path, O_CREAT | O_NOFOLLOW | O_RDWR, 0666);
    EXPECT_TRUE(fd == -1 && errno == ELOOP,
                "nofollow open followed the symlink");
    if (fd >= 0)
        close(fd);
    TEST("O_CREAT follows a dangling symlink chain");
    fd = open(chain_path, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        FAIL("open dangling chain");
        return;
    }
    close(fd);
    expect_owner(target_path, geteuid(), getegid());
}

static void truncate_existing(void)
{
    TEST("O_CREAT truncation retains the existing owner");
    int fd = open(file_path, O_CREAT | O_TRUNC | O_RDWR, 0666);
    if (fd < 0) {
        FAIL("open");
        return;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        FAIL("fstat");
        close(fd);
        return;
    }
    EXPECT_TRUE(st.st_uid == 2000 && st.st_gid == 2000,
                "truncation changed the creator");
    close(fd);
}

static void link_and_rename(void)
{
    TEST("hard link retains the inode");
    EXPECT_TRUE(link(file_path, hard_path) == 0, "link");
    TEST("rename retains the inode");
    EXPECT_TRUE(rename(file_path, renamed_path) == 0, "rename");
    expect_owner(hard_path, 2000, 2000);
    expect_owner(renamed_path, 2000, 2000);
}

static void change_group(void)
{
    TEST("partial chown on file");
    EXPECT_TRUE(chown(renamed_path, (uid_t) -1, 3000) == 0, "chown");
    TEST("partial chown on directory");
    EXPECT_TRUE(chown(dir_path, (uid_t) -1, 3000) == 0, "chown");
    TEST("partial chown on symlink");
    EXPECT_TRUE(lchown(link_path, (uid_t) -1, 3000) == 0, "lchown");
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <phase>\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "create") == 0) {
        create_files();
    } else if (strcmp(argv[1], "read-created") == 0) {
        expect_owner(file_path, 2000, 2000);
        expect_owner(dir_path, 2000, 2000);
        expect_owner(link_path, 2000, 2000);
        expect_owner(target_path, 2000, 2000);
        expect_owner(dangling_path, 2000, 2000);
        expect_owner(chain_path, 2000, 2000);
    } else if (strcmp(argv[1], "truncate") == 0) {
        truncate_existing();
    } else if (strcmp(argv[1], "link-rename") == 0) {
        link_and_rename();
    } else if (strcmp(argv[1], "change-times") == 0) {
        const struct timespec times[2] = {{.tv_sec = 1}, {.tv_sec = 1}};
        TEST("mtime change retains the creator");
        EXPECT_TRUE(utimensat(AT_FDCWD, renamed_path, times, 0) == 0,
                    "utimensat");
        expect_owner(renamed_path, 2000, 2000);
        expect_owner(hard_path, 2000, 2000);
    } else if (strcmp(argv[1], "partial-chown") == 0) {
        change_group();
    } else if (strcmp(argv[1], "read-partial") == 0) {
        expect_owner(renamed_path, 2000, 3000);
        expect_owner(hard_path, 2000, 3000);
        expect_owner(dir_path, 2000, 3000);
        expect_owner(link_path, 2000, 3000);
    } else if (strcmp(argv[1], "explicit-chown") == 0) {
        TEST("explicit chown replaces the creator");
        EXPECT_TRUE(chown(renamed_path, 7777, 8888) == 0, "chown");
    } else if (strcmp(argv[1], "read-explicit") == 0) {
        expect_owner(renamed_path, 7777, 8888);
        expect_owner(hard_path, 7777, 8888);
    } else {
        fprintf(stderr, "unknown phase: %s\n", argv[1]);
        return 2;
    }
    SUMMARY("test-created-owner");
    return fails == 0 ? 0 : 1;
}
