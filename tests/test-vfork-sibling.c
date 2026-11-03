/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

static int passes, fails;
static int ready_pipe[2];
static int release_pipe[2];
static char child_stack[65536] __attribute__((aligned(16)));
static int vfork_ok;
static int signal_pipe[2];
static _Atomic bool child_released;
static _Atomic bool signal_too_early;

static void signal_handler(int signum)
{
    (void) signum;
    if (!atomic_load_explicit(&child_released, memory_order_acquire))
        atomic_store_explicit(&signal_too_early, true, memory_order_relaxed);
    char byte = 1;
    (void) write(signal_pipe[1], &byte, 1);
}

static int child_main(void *unused)
{
    (void) unused;
    char ready = 1;
    if (write(ready_pipe[1], &ready, 1) != 1)
        _exit(2);
    char release;
    if (read(release_pipe[0], &release, 1) != 1)
        _exit(3);
    _exit(7);
}

static void *vfork_thread(void *unused)
{
    (void) unused;
    pid_t child = clone(child_main, child_stack + sizeof(child_stack),
                        CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    int status = 0;
    vfork_ok = child > 0 && waitpid(child, &status, 0) == child &&
               WIFEXITED(status) && WEXITSTATUS(status) == 7;
    return NULL;
}

int main(void)
{
    alarm(10);
    struct sigaction action = {.sa_handler = signal_handler};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) != 0 || pipe(signal_pipe) != 0)
        return 1;
    TEST("fork succeeds while a sibling waits for its vfork child");
    pthread_t thread;
    if (pipe(ready_pipe) != 0 || pipe(release_pipe) != 0 ||
        pthread_create(&thread, NULL, vfork_thread, NULL) != 0) {
        FAIL("cannot start vfork caller");
        return 1;
    }
    char ready;
    if (read(ready_pipe[0], &ready, 1) != 1) {
        FAIL("vfork child did not start");
        return 1;
    }
    if (pthread_kill(thread, SIGUSR1) != 0)
        FAIL("cannot signal vfork caller");
    pid_t child = fork();
    if (child == 0)
        _exit(0);
    int status = 0;
    if (child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0)
        PASS();
    else
        FAIL("sibling fork failed");
    atomic_store_explicit(&child_released, true, memory_order_release);
    ready = 1;
    if (write(release_pipe[1], &ready, 1) != 1)
        FAIL("cannot release vfork child");
    pthread_join(thread, NULL);
    TEST("vfork defers a signal until child release");
    if (read(signal_pipe[0], &ready, 1) == 1 &&
        !atomic_load_explicit(&signal_too_early, memory_order_relaxed))
        PASS();
    else
        FAIL("vfork delivered signal before child release");
    TEST("vfork resumes once and leaves the child waitable");
    if (vfork_ok)
        PASS();
    else
        FAIL("vfork child status lost");
    close(ready_pipe[0]);
    close(ready_pipe[1]);
    close(release_pipe[0]);
    close(release_pipe[1]);
    close(signal_pipe[0]);
    close(signal_pipe[1]);
    SUMMARY("test-vfork-sibling");
    return fails != 0;
}
