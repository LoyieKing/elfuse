/*
 * posix_spawn file actions and attributes leave the caller unchanged, and so
 * does an exec that never happens.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * dup2, close, and open run as file actions. chdir runs only when the linked
 * libc exports posix_spawn_file_actions_addchdir_np. The attribute half
 * installs a mask of SIGUSR2, puts SIGUSR1 back to SIG_DFL, and gives the child
 * its own process group. The parent blocks nothing and leaves SIGUSR1 ignored,
 * so an inherited mask or disposition cannot pass for the child's. A missing
 * posix_spawn and a fork plus execve of a missing path must both come back
 * ENOENT without moving the caller's fds, cwd, mask, or group.
 */


#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

extern char **environ;

/* This tree's glibc sysroot does not declare the chdir action. A weak reference
 * stays null when the static libc has no such member, and resolves when a newer
 * libc does. musl declares the function itself.
 */
#ifdef __GLIBC__
int posix_spawn_file_actions_addchdir_np(posix_spawn_file_actions_t *actions,
                                         const char *path)
    __attribute__((weak));
#endif

struct view {
    int marker;
    int source;
    int target;
    int opened;
    char cwd[PATH_MAX];
    char opened_path[PATH_MAX];
    sigset_t mask;
    pid_t pgroup;
};

struct child_report {
    int marker_byte;
    int source_closed;
    int marker_closed;
    int opened_matches;
    int usr2_blocked;
    int usr1_dfl;
    int own_pgroup;
    char cwd[PATH_MAX];
};

static int write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;

    while (len > 0) {
        ssize_t n = write(fd, p, len);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += n;
        len -= (size_t) n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    char *p = buf;

    while (len > 0) {
        ssize_t n = read(fd, p, len);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        p += n;
        len -= (size_t) n;
    }
    return 0;
}

static int live(int fd)
{
    return fcntl(fd, F_GETFD) >= 0;
}

static int parse_fd(const char *text)
{
    char *end = NULL;
    long value = strtol(text, &end, 10);

    if (end == text || *end != '\0' || value < 0 || value > INT_MAX)
        return -1;
    return (int) value;
}

static int save_view(struct view *view)
{
    char *cwd;

    if (!live(view->marker) || !live(view->source) || live(view->target) ||
        live(view->opened))
        return -1;
    cwd = getcwd(view->cwd, sizeof(view->cwd));
    if (cwd == NULL)
        return -1;
    if (sigprocmask(SIG_SETMASK, NULL, &view->mask) != 0)
        return -1;
    view->pgroup = getpgrp();
    return view->pgroup < 0 ? -1 : 0;
}

static int view_same(const struct view *before, const char *what)
{
    struct view now = *before;
    struct sigaction action;

    TEST(what);
    memset(&action, 0, sizeof(action));
    if (save_view(&now) != 0 || strcmp(now.cwd, before->cwd) != 0 ||
        memcmp(&now.mask, &before->mask, sizeof(now.mask)) != 0 ||
        now.pgroup != before->pgroup ||
        sigaction(SIGUSR1, NULL, &action) != 0 ||
        action.sa_handler != SIG_IGN) {
        FAIL("caller fds, cwd, mask, disposition, or group moved");
        return -1;
    }
    PASS();
    return 0;
}

/* 0 installed, 1 this libc has no chdir action, -1 the call failed. */
static int add_chdir(posix_spawn_file_actions_t *actions)
{
#ifdef __GLIBC__
    if (posix_spawn_file_actions_addchdir_np == NULL)
        return 1;
    if (posix_spawn_file_actions_addchdir_np(actions, "/tmp") != 0)
        return -1;
#else
    if (posix_spawn_file_actions_addchdir_np(actions, "/tmp") != 0)
        return -1;
#endif
    return 0;
}

static int child_main(int argc, char **argv)
{
    struct child_report report;
    sigset_t mask;
    struct sigaction action;
    struct stat opened_st;
    struct stat path_st;
    int report_fd, target, marker, source, opened;
    char byte = 0;
    ssize_t n;

    if (argc != 7)
        return 2;
    report_fd = parse_fd(argv[1]);
    target = parse_fd(argv[2]);
    marker = parse_fd(argv[3]);
    source = parse_fd(argv[4]);
    opened = parse_fd(argv[5]);
    if (report_fd < 0 || target < 0 || marker < 0 || source < 0 || opened < 0)
        return 2;

    memset(&report, 0, sizeof(report));
    if (kill(getpid(), SIGUSR2) != 0)
        return 2;
    if (sigprocmask(SIG_SETMASK, NULL, &mask) != 0 ||
        sigaction(SIGUSR1, NULL, &action) != 0)
        return 2;
    report.usr2_blocked =
        sigismember(&mask, SIGUSR2) == 1 && sigismember(&mask, SIGTERM) == 0;
    report.usr1_dfl = action.sa_handler == SIG_DFL;
    report.own_pgroup = getpgrp() == getpid();
    if (getcwd(report.cwd, sizeof(report.cwd)) == NULL)
        return 2;

    n = read(target, &byte, 1);
    report.marker_byte = n == 1 ? byte : 0;
    report.source_closed = !live(source);
    report.marker_closed = !live(marker);
    report.opened_matches = fstat(opened, &opened_st) == 0 &&
                            stat(argv[6], &path_st) == 0 &&
                            opened_st.st_ino == path_st.st_ino;
    if (write_all(report_fd, &report, sizeof(report)) != 0)
        return 2;
    return 0;
}

static void expect_child(const struct child_report *report,
                         const struct view *parent,
                         int chdir_added)
{
    TEST("child dup2 reads the marker");
    EXPECT_EQ(report->marker_byte, 'M', "dup2 target did not read the marker");
    TEST("child close drops both source descriptors");
    EXPECT_TRUE(report->source_closed && report->marker_closed,
                "child still has a descriptor the actions closed");
    TEST("child open sees the new file");
    EXPECT_TRUE(report->opened_matches, "open action missed the file");
    if (chdir_added) {
        TEST("child chdir action reaches /tmp");
        EXPECT_TRUE(strcmp(report->cwd, "/tmp") == 0, "child cwd is not /tmp");
    } else {
        TEST("child keeps the caller cwd without a chdir action");
        EXPECT_TRUE(strcmp(report->cwd, parent->cwd) == 0,
                    "child cwd changed without a chdir action");
    }
    TEST("child mask is the spawned SIGUSR2 mask");
    EXPECT_TRUE(report->usr2_blocked, "child is not blocking SIGUSR2");
    TEST("child SIGUSR1 returned to default");
    EXPECT_TRUE(report->usr1_dfl, "child kept the caller's ignored SIGUSR1");
    TEST("child has its own process group");
    EXPECT_TRUE(report->own_pgroup, "child process group is not its pid");
}

static int run_spawn(struct view *parent, const char *self)
{
    int pipefd[2] = {-1, -1};
    pid_t child = -1;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    sigset_t child_mask;
    sigset_t sigdef;
    struct child_report report;
    int status = 0;
    int spawn_rc;
    int chdir_rc;
    int rc = -1;
    bool actions_live = false;
    bool attr_live = false;
    char report_arg[16], target_arg[16], marker_arg[16], source_arg[16];
    char opened_arg[16];
    char *argv[8];

    if (pipe(pipefd) != 0)
        goto out;
    if (posix_spawn_file_actions_init(&actions) != 0)
        goto out;
    actions_live = true;
    if (posix_spawn_file_actions_adddup2(&actions, parent->source,
                                         parent->target) != 0 ||
        posix_spawn_file_actions_addclose(&actions, parent->source) != 0 ||
        posix_spawn_file_actions_addclose(&actions, parent->marker) != 0 ||
        posix_spawn_file_actions_addopen(
            &actions, parent->opened, parent->opened_path, O_RDONLY, 0) != 0 ||
        posix_spawn_file_actions_addclose(&actions, pipefd[0]) != 0)
        goto out;
    chdir_rc = add_chdir(&actions);
    if (chdir_rc < 0)
        goto out;

    if (posix_spawnattr_init(&attr) != 0)
        goto out;
    attr_live = true;
    sigemptyset(&child_mask);
    sigaddset(&child_mask, SIGUSR2);
    sigemptyset(&sigdef);
    sigaddset(&sigdef, SIGUSR1);
    if (posix_spawnattr_setsigmask(&attr, &child_mask) != 0 ||
        posix_spawnattr_setsigdefault(&attr, &sigdef) != 0 ||
        posix_spawnattr_setpgroup(&attr, 0) != 0 ||
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK |
                                            POSIX_SPAWN_SETSIGDEF |
                                            POSIX_SPAWN_SETPGROUP) != 0)
        goto out;

    snprintf(report_arg, sizeof(report_arg), "%d", pipefd[1]);
    snprintf(target_arg, sizeof(target_arg), "%d", parent->target);
    snprintf(marker_arg, sizeof(marker_arg), "%d", parent->marker);
    snprintf(source_arg, sizeof(source_arg), "%d", parent->source);
    snprintf(opened_arg, sizeof(opened_arg), "%d", parent->opened);
    argv[0] = (char *) self;
    argv[1] = report_arg;
    argv[2] = target_arg;
    argv[3] = marker_arg;
    argv[4] = source_arg;
    argv[5] = opened_arg;
    argv[6] = parent->opened_path;
    argv[7] = NULL;

    spawn_rc = posix_spawn(&child, self, &actions, &attr, argv, environ);
    if (spawn_rc != 0) {
        errno = spawn_rc;
        FAIL("posix_spawn failed");
        goto out;
    }
    close(pipefd[1]);
    pipefd[1] = -1;
    if (read_all(pipefd[0], &report, sizeof(report)) != 0 ||
        waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        FAIL("spawn child did not report");
        goto out;
    }
    child = -1;
    expect_child(&report, parent, chdir_rc == 0);
    rc = 0;

out:
    if (child > 0) {
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
    }
    if (actions_live)
        posix_spawn_file_actions_destroy(&actions);
    if (attr_live)
        posix_spawnattr_destroy(&attr);
    if (pipefd[0] >= 0)
        close(pipefd[0]);
    if (pipefd[1] >= 0)
        close(pipefd[1]);
    return rc;
}

static int run_failed_spawn(const struct view *parent)
{
    pid_t child = -1;
    char *argv[] = {(char *) "missing", NULL};
    int spawn_rc;

    TEST("posix_spawn of a missing path returns ENOENT");
    spawn_rc = posix_spawn(&child, "/nonexistent/elfuse-spawn-isolation", NULL,
                           NULL, argv, environ);
    EXPECT_EQ(spawn_rc, ENOENT, "missing posix_spawn did not return ENOENT");
    if (child > 0) {
        int status = 0;

        kill(child, SIGKILL);
        waitpid(child, &status, 0);
    }
    return view_same(parent, "caller is unchanged after the missing spawn");
}

static int run_failed_exec(const struct view *parent)
{
    pid_t child;
    int status = 0;

    child = fork();
    if (child < 0) {
        FAIL("fork before the missing exec failed");
        return -1;
    }
    if (child == 0) {
        char *argv[] = {(char *) "/nonexistent/elfuse-spawn-isolation", NULL};
        char cwd[PATH_MAX];

        execve(argv[0], argv, environ);
        if (errno != ENOENT)
            _exit(2);
        if (!live(parent->marker) || !live(parent->source) ||
            live(parent->target) || live(parent->opened))
            _exit(3);
        if (getcwd(cwd, sizeof(cwd)) == NULL || strcmp(cwd, parent->cwd) != 0)
            _exit(4);
        _exit(0);
    }
    TEST("fork plus execve of a missing path returns ENOENT");
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        FAIL("missing exec did not return ENOENT in the caller");
        return -1;
    }
    PASS();
    return view_same(parent, "caller is unchanged after the missing exec");
}

static int reserve_high(int from, int *first, int *second)
{
    int a = fcntl(from, F_DUPFD, 100);
    int b;

    if (a < 0)
        return -1;
    b = fcntl(from, F_DUPFD, a + 1);
    if (b < 0) {
        close(a);
        return -1;
    }
    if (close(a) != 0 || close(b) != 0)
        return -1;
    *first = a;
    *second = b;
    return 0;
}

int main(int argc, char **argv)
{
    char dir_template[] = "/tmp/elfuse-spawn-isolation-XXXXXX";
    char *dir = NULL;
    struct view parent;
    struct sigaction action;
    int created = -1;
    int rc = 1;

    if (argc == 7)
        return child_main(argc, argv);

    alarm(20);
    memset(&parent, 0, sizeof(parent));
    parent.marker = parent.source = parent.target = parent.opened = -1;
    dir = mkdtemp(dir_template);
    if (dir == NULL)
        return 1;
    snprintf(parent.opened_path, sizeof(parent.opened_path), "%s/opened", dir);
    {
        char marker_path[PATH_MAX];

        snprintf(marker_path, sizeof(marker_path), "%s/marker", dir);
        parent.marker = open(marker_path, O_CREAT | O_RDWR | O_TRUNC, 0600);
        if (parent.marker < 0 || write_all(parent.marker, "M", 1) != 0 ||
            lseek(parent.marker, 0, SEEK_SET) < 0)
            goto cleanup;
    }
    parent.source = dup(parent.marker);
    created = open(parent.opened_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (parent.source < 0 || created < 0 || write_all(created, "O", 1) != 0)
        goto cleanup;
    close(created);
    created = -1;
    if (reserve_high(parent.source, &parent.target, &parent.opened) != 0)
        goto cleanup;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGUSR1, &action, NULL) != 0 || save_view(&parent) != 0)
        goto cleanup;
    if (run_spawn(&parent, argv[0]) != 0 && fails == 0)
        FAIL("cannot stage the spawn");
    if (view_same(&parent, "caller is unchanged after spawn") != 0)
        goto cleanup;
    if (run_failed_spawn(&parent) != 0)
        goto cleanup;
    if (run_failed_exec(&parent) != 0)
        goto cleanup;
    rc = fails != 0;

cleanup:
    if (rc != 0 && fails == 0)
        FAIL("cannot stage spawn fixtures");
    if (created >= 0)
        close(created);
    if (parent.marker >= 0)
        close(parent.marker);
    if (parent.source >= 0)
        close(parent.source);
    if (dir != NULL) {
        char marker_path[PATH_MAX];

        snprintf(marker_path, sizeof(marker_path), "%s/marker", dir);
        unlink(marker_path);
        unlink(parent.opened_path);
        rmdir(dir);
    }
    SUMMARY("test-spawn-isolation");
    return rc;
}
