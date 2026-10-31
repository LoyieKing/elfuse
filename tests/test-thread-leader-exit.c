/*
 * Thread-group leader exit followed by fork and non-leader exec
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux keeps the process alive when the initial (group leader) thread calls
 * exit and siblings remain. A sibling may fork, and a sibling may execve even
 * though it is not the leader: de_thread() retires the dead leader and the
 * exec'ing thread becomes the new leader with gettid() == getpid(), while the
 * process pid is unchanged. The forked child is an ordinary single-threaded
 * process whose parent is the original process.
 *
 * The original leader exits before any of that. The surviving thread forks a
 * child, then execs this same binary; the post-exec image verifies the kernel
 * guarantees and reaps the child. A host runtime that hands exec back to the
 * dead leader or leaks the dead leader into the new image fails here.
 *
 * Syscalls exercised: exit(93), clone(220), pipe2(59), read(63), write(64),
 *                     wait4(260), execve(221), gettid(178), getpid(172)
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes, fails;

static const char *self_path;
static int pipe_rd = -1;
static int pipe_wr = -1;
static int original_pid;
static _Atomic int worker_ready, worker_go;

static int read_thread_count(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    int n = -1;

    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "Threads: %d", &n) == 1)
            break;
    }
    fclose(f);
    return n;
}

static void wake_worker(void)
{
    (void) syscall(SYS_futex, (int *) &worker_go,
                   FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0, 0, 0);
}

static void wait_worker_go(void)
{
    struct timespec ts = {.tv_sec = 5, .tv_nsec = 0};

    while (atomic_load_explicit(&worker_go, memory_order_acquire) == 0) {
        if (syscall(SYS_futex, (int *) &worker_go,
                    FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, &ts, 0, 0) == -1 &&
            errno != EAGAIN && errno != EINTR)
            break;
    }
}

static int child_report(void)
{
    int pid = (int) getpid();
    int tid = (int) syscall(SYS_gettid);
    int nthreads = read_thread_count();
    int ppid = (int) getppid();
    int ok = pid != original_pid && tid == pid && ppid == original_pid &&
             nthreads == 1;
    char status = ok ? 'C' : 'E';
    ssize_t n;

    if (!ok) {
        fprintf(stderr,
                "test-thread-leader-exit: child check failed pid=%d tid=%d "
                "ppid=%d threads=%d\n",
                pid, tid, ppid, nthreads);
    }
    do {
        n = write(pipe_wr, &status, 1);
    } while (n < 0 && errno == EINTR);
    _exit(ok && n == 1 ? 0 : 3);
}

static void exec_post_image(pid_t child)
{
    char childbuf[32], fdbuf[32], pidbuf[32];

    snprintf(childbuf, sizeof(childbuf), "%d", (int) child);
    snprintf(fdbuf, sizeof(fdbuf), "%d", pipe_rd);
    snprintf(pidbuf, sizeof(pidbuf), "%d", original_pid);

    extern char **environ;
    char *argv[] = {
        (char *) self_path, (char *) "post-exec", childbuf, fdbuf, pidbuf, NULL,
    };
    execve(self_path, argv, environ);
    fprintf(stderr, "test-thread-leader-exit: execve(%s) failed: %s\n",
            self_path, strerror(errno));
    _exit(1);
}

static void *worker_main(void *arg)
{
    (void) arg;

    atomic_store_explicit(&worker_ready, 1, memory_order_release);
    wait_worker_go();
    if (atomic_load_explicit(&worker_go, memory_order_acquire) == 0) {
        fprintf(stderr,
                "test-thread-leader-exit: leader never released the worker\n");
        _exit(1);
    }

    /* The leader was released immediately before it issued its own exit
     * syscall. Give that syscall time to retire the leader: the worker must
     * clone and exec as a surviving thread, not race the leader's exit.
     */
    struct timespec leader_exit_grace = {
        .tv_sec = 0,
        .tv_nsec = 100 * 1000 * 1000L,
    };
    nanosleep(&leader_exit_grace, NULL);


    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "test-thread-leader-exit: fork failed: %s\n",
                strerror(errno));
        _exit(1);
    }
    if (child == 0)
        child_report();

    exec_post_image(child);
    _exit(1);
}

static int post_exec_main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "test-thread-leader-exit: bad post-exec arguments\n");
        return 1;
    }
    pid_t child = (pid_t) atoi(argv[2]);
    int fd = atoi(argv[3]);
    int expected_pid = atoi(argv[4]);

    printf("test-thread-leader-exit: post-exec image\n");

    TEST("post-exec image is single-threaded");
    int threads = read_thread_count();
    EXPECT_EQ(threads, 1, "exec image still reports sibling threads");

    TEST("process pid survives exec");
    EXPECT_EQ(getpid(), expected_pid, "exec changed the process pid");

    TEST("exec'ing sibling adopts the group-leader tid");
    EXPECT_EQ((pid_t) syscall(SYS_gettid), getpid(),
              "gettid() != getpid() after non-leader exec");

    TEST("fork after leader exit reached its child checks");
    char status = 0;
    ssize_t n;
    do {
        n = read(fd, &status, 1);
    } while (n < 0 && errno == EINTR);
    EXPECT_TRUE(n == 1 && status == 'C',
                "forked child did not report a Linux-shaped process");

    TEST("forked child is waitable after the parent exec");
    int wstatus = 0;
    pid_t reaped = waitpid(child, &wstatus, 0);
    EXPECT_TRUE(
        reaped == child && WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0,
        "forked child was not reaped with status 0");

    close(fd);
    SUMMARY("test-thread-leader-exit");
    return fails == 0 ? 0 : 1;
}

static int run_main(void)
{
    int fds[2];

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("test-thread-leader-exit: leader exit then fork/exec\n");

    if (pipe2(fds, O_CLOEXEC) != 0) {
        fprintf(stderr, "test-thread-leader-exit: pipe2 failed: %s\n",
                strerror(errno));
        return 1;
    }
    pipe_rd = fds[0];
    pipe_wr = fds[1];
    int flags = fcntl(pipe_rd, F_GETFD);
    if (flags < 0 || fcntl(pipe_rd, F_SETFD, flags & ~FD_CLOEXEC) < 0) {
        fprintf(stderr, "test-thread-leader-exit: fcntl failed: %s\n",
                strerror(errno));
        return 1;
    }

    original_pid = (int) getpid();

    pthread_t worker;
    if (pthread_create(&worker, NULL, worker_main, NULL) != 0) {
        fprintf(stderr, "test-thread-leader-exit: pthread_create failed\n");
        return 1;
    }
    pthread_detach(worker);

    for (uint64_t end = 0; end < 3000; end++) {
        if (atomic_load_explicit(&worker_ready, memory_order_acquire) != 0)
            break;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000000L};
        nanosleep(&ts, NULL);
    }
    if (atomic_load_explicit(&worker_ready, memory_order_acquire) == 0) {
        fprintf(stderr,
                "test-thread-leader-exit: worker did not reach the barrier\n");
        return 1;
    }

    /* The initial thread is the group leader. Exit it alone; the sibling runs
     * the fork and the exec. The process is not supposed to die here. A nonzero
     * leader code makes an implementation that tears the process down fail the
     * lane instead of reporting the leader's zero.
     */
    atomic_store_explicit(&worker_go, 1, memory_order_release);
    wake_worker();
    syscall(SYS_exit, 42);
    __builtin_unreachable();
}

int main(int argc, char **argv)
{
    self_path = argv[0];

    if (argc > 1 && strcmp(argv[1], "post-exec") == 0)
        return post_exec_main(argc, argv);
    return run_main();
}
