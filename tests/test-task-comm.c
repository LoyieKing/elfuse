/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

static int passes, fails;
static _Atomic int ready, release_worker;
static int worker_ok;
static pid_t worker_tid;

static int name_is(const char *expected)
{
    char name[16];
    memset(name, 0x55, sizeof(name));
    return prctl(PR_GET_NAME, name, 0, 0, 0) == 0 &&
           memcmp(name, expected, strlen(expected) + 1) == 0;
}

static int comm_is(pid_t tid, const char *expected)
{
    char path[96], value[32];
    snprintf(path, sizeof(path), "/proc/self/task/%d/comm", (int) tid);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return 0;
    ssize_t n = read(fd, value, sizeof(value));
    close(fd);
    size_t len = strlen(expected);
    return n == (ssize_t) len + 1 && memcmp(value, expected, len) == 0 &&
           value[len] == '\n';
}

static void *worker(void *unused)
{
    (void) unused;
    worker_tid = (pid_t) syscall(SYS_gettid);
    worker_ok = name_is("parent-name") &&
                prctl(PR_SET_NAME, "worker-name", 0, 0, 0) == 0 &&
                name_is("worker-name");
    atomic_store_explicit(&ready, 1, memory_order_release);
    while (!atomic_load_explicit(&release_worker, memory_order_acquire))
        usleep(1000);
    worker_ok &= name_is("renamed-worker");
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "exec-child"))
        return name_is("test-task-comm") ? 0 : 2;
    TEST("name roundtrip and truncation");
    EXPECT_TRUE(prctl(PR_SET_NAME, "1234567890123456789", 0, 0, 0) == 0 &&
                    name_is("123456789012345") &&
                    comm_is((pid_t) syscall(SYS_gettid), "123456789012345"),
                "prctl and proc comm disagree");
    TEST("bad name pointers fault");
    errno = 0;
    int set = prctl(PR_SET_NAME, (void *) 1, 0, 0, 0);
    int set_error = errno;
    errno = 0;
    int get = prctl(PR_GET_NAME, (void *) 1, 0, 0, 0);
    EXPECT_TRUE(set == -1 && set_error == EFAULT && get == -1 &&
                    errno == EFAULT && name_is("123456789012345"),
                "fault changed name or returned success");
    prctl(PR_SET_NAME, "parent-name", 0, 0, 0);
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL) != 0)
        return 3;
    while (!atomic_load_explicit(&ready, memory_order_acquire))
        usleep(1000);
    TEST("clone inherits then keeps independent task name");
    EXPECT_TRUE(worker_ok && name_is("parent-name") &&
                    comm_is(worker_tid, "worker-name"),
                "worker name missing or shared with leader");
    char path[96];
    snprintf(path, sizeof(path), "/proc/self/task/%d/comm", (int) worker_tid);
    int fd = open(path, O_WRONLY);
    TEST("same-group comm write renames worker");
    EXPECT_TRUE(fd >= 0 && write(fd, "renamed-worker", 14) == 14 &&
                    comm_is(worker_tid, "renamed-worker") &&
                    name_is("parent-name"),
                "comm write did not update target");
    TEST("zero-byte comm write preserves task name");
    EXPECT_TRUE(fd >= 0 && write(fd, "", 0) == 0 &&
                    comm_is(worker_tid, "renamed-worker"),
                "zero-byte write changed name");
    if (fd >= 0)
        close(fd);
    atomic_store_explicit(&release_worker, 1, memory_order_release);
    pthread_join(thread, NULL);
    TEST("exited task directory and comm disappear");
    struct stat st;
    EXPECT_TRUE(worker_ok && stat(path, &st) == -1 && errno == ENOENT,
                "dead task comm remains visible");
    pid_t child = fork();
    if (child == 0)
        _exit(name_is("parent-name") ? 0 : 4);
    int status = 0;
    TEST("fork inherits caller name");
    EXPECT_TRUE(child > 0 && waitpid(child, &status, 0) == child &&
                    WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "fork name changed");
    child = fork();
    if (child == 0) {
        execl(argv[0], argv[0], "exec-child", (char *) NULL);
        _exit(5);
    }
    TEST("exec resets name to executable basename");
    EXPECT_TRUE(child > 0 && waitpid(child, &status, 0) == child &&
                    WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "exec kept caller name");
    SUMMARY("test-task-comm");
    return fails != 0;
}
