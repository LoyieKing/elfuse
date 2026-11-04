/*
 * Thread-directed signal routing (tgkill / pthread_kill)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A thread-directed signal must be consumed by the target thread only, not by
 * whichever thread reaches a delivery point first. Regression test for the bug
 * where sc_tgkill validated the target tid then dropped it into the single
 * process-wide pending set, so pthread_kill(worker, SIGUSR1) could be handled
 * on the main thread while the worker slept on in a blocking read.
 *
 * Also checks the anti-coalescing property: N tgkills of the same standard
 * signal to N distinct threads deliver N times, once per target, instead of
 * collapsing into a single pending bit.
 *
 * Syscalls exercised: tgkill(131), rt_sigaction(134), gettid(178),
 *                     clone(220, via pthread_create)
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_tkill
#define SYS_tkill 130
#endif

#include "test-harness.h"
#include "raw-syscall.h"

int passes = 0, fails = 0;

/* Test 1: pthread_kill targets the specific thread, not the process. */

static volatile sig_atomic_t got_sig = 0;
static volatile int handler_tid = 0;
static int worker_tid = 0;
static volatile sig_atomic_t worker_ready = 0;
static int wake_pipe[2];

static void usr1_handler(int sig)
{
    (void) sig;
    handler_tid = (int) raw_gettid();
    got_sig = 1;
}

static void *blocking_worker(void *arg)
{
    (void) arg;
    worker_tid = (int) raw_gettid();
    worker_ready = 1;

    /* Block in read() on an empty pipe. A thread-directed signal must land here
     * and interrupt this read with EINTR; a byte written by the parent is the
     * fallback that unblocks the worker if the signal was misdelivered.
     */
    char c;
    while (!got_sig) {
        ssize_t r = read(wake_pipe[0], &c, 1);
        if (r > 0)
            break; /* Parent unblocked us (misdelivery path) */
        if (r < 0 && errno == EINTR)
            continue; /* Signal handler ran; loop re-checks got_sig */
    }
    return NULL;
}

static void test_pthread_kill_targets_thread(void)
{
    TEST("pthread_kill targets the named thread");

    got_sig = 0;
    handler_tid = 0;
    worker_tid = 0;
    worker_ready = 0;

    if (pipe(wake_pipe) != 0) {
        FAIL("pipe");
        return;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = usr1_handler;
    sigemptyset(&sa.sa_mask);
    /* No SA_RESTART: the worker's read() should return EINTR after delivery. */
    sigaction(SIGUSR1, &sa, NULL);

    pthread_t worker;
    if (pthread_create(&worker, NULL, blocking_worker, NULL) != 0) {
        FAIL("pthread_create");
        return;
    }

    /* Wait for the worker to publish its tid and park in read(). */
    while (!worker_ready)
        usleep(1000);
    usleep(100000); /* 100ms: ensure the worker is inside read() */

    pthread_kill(worker, SIGUSR1);

    /* Spin in usleep so the main thread hits nanosleep epilogues -- under the
     * old process-wide routing the main thread would steal the signal here.
     */
    for (int i = 0; i < 2000 && !got_sig; i++)
        usleep(1000);

    /* Unblock the worker unconditionally so join() cannot hang, then join. */
    (void) !write(wake_pipe[1], "x", 1);
    pthread_join(worker, NULL);
    close(wake_pipe[0]);
    close(wake_pipe[1]);

    EXPECT_TRUE(got_sig && handler_tid == worker_tid,
                "signal handled on the wrong thread (process-wide routing)");
}

/* Test 2: standard signals to distinct threads do not coalesce. Each of N
 * worker threads blocks SIGUSR2, is sent one tgkill(SIGUSR2), then unblocks and
 * counts its own delivery. Coalescing into one process-wide bit would deliver
 * to at most one thread.
 */

#define N_WORKERS 4

static pthread_barrier_t sent_barrier; /* main signalled all workers */
/* Incremented from handlers running concurrently on the N worker threads, so
 * the update must be inter-thread atomic; a plain volatile RMW would lose
 * counts and make the coalescing assertion flaky on multi-core hosts. Reset
 * before the workers start and read after they join, so those accesses need no
 * atomics.
 */
static int usr2_hits = 0;

static void usr2_handler(int sig)
{
    (void) sig;
    __atomic_add_fetch(&usr2_hits, 1, __ATOMIC_SEQ_CST);
}

static void *counting_worker(void *arg)
{
    (void) arg;

    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR2);

    /* Per-thread block so the pending signal stays queued on this thread until
     * it unblocks -- no thread can consume another's instance.
     */
    pthread_sigmask(SIG_BLOCK, &block, NULL);

    /* Publish that this worker exists and is blocking SIGUSR2. */
    pthread_barrier_wait(&sent_barrier);

    /* Wait until the main thread has issued every tgkill, then unblock and let
     * this thread's own pending instance deliver.
     */
    pthread_barrier_wait(&sent_barrier);
    pthread_sigmask(SIG_UNBLOCK, &block, NULL);
    /* Give delivery a moment on the next syscall epilogue. */
    usleep(50000);
    return NULL;
}

static void test_directed_no_coalesce(void)
{
    TEST("standard signals to N threads do not coalesce");

    usr2_hits = 0;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = usr2_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR2, &sa, NULL);

    /* Block SIGUSR2 on the main thread so it is not an eligible consumer: each
     * tgkill's syscall epilogue must not steal the delivery. Under process-wide
     * routing the four sends then coalesce into one shared pending bit and only
     * one worker fires; per-thread routing keeps four distinct instances.
     */
    sigset_t block_main;
    sigemptyset(&block_main);
    sigaddset(&block_main, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &block_main, NULL);

    pthread_barrier_init(&sent_barrier, NULL, N_WORKERS + 1);

    pthread_t workers[N_WORKERS];
    int tids[N_WORKERS];
    for (int i = 0; i < N_WORKERS; i++)
        pthread_create(&workers[i], NULL, counting_worker, NULL);

    /* Wait for all workers to block SIGUSR2 and publish existence. */
    pthread_barrier_wait(&sent_barrier);

    /* Collect worker tids and send one directed SIGUSR2 to each. */
    for (int i = 0; i < N_WORKERS; i++) {
        /* pthread_kill needs the pthread_t; the handler counts globally, so we
         * only need to reach each distinct target thread.
         */
        pthread_kill(workers[i], SIGUSR2);
        (void) tids;
    }

    /* Release the workers to unblock and drain their private pending sets. */
    pthread_barrier_wait(&sent_barrier);

    for (int i = 0; i < N_WORKERS; i++)
        pthread_join(workers[i], NULL);
    pthread_barrier_destroy(&sent_barrier);

    EXPECT_TRUE(usr2_hits == N_WORKERS,
                "not every thread received its own signal instance");
}

/* Test 3: legacy tkill(2) delivers a thread-directed signal to self. */

static void test_tkill_self(void)
{
    TEST("tkill delivers to self");

    got_sig = 0;
    handler_tid = 0;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = usr1_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);

    int tid = (int) raw_gettid();
    long ret = syscall(SYS_tkill, tid, SIGUSR1);

    EXPECT_TRUE(ret == 0 && got_sig && handler_tid == tid,
                "tkill(self) did not deliver to the caller");
}

static volatile sig_atomic_t info_code, info_pid, info_uid;

static void info_handler(int sig, siginfo_t *info, void *context)
{
    (void) sig;
    (void) context;
    info_code = info->si_code;
    info_pid = info->si_pid;
    info_uid = (sig_atomic_t) info->si_uid;
}

static void test_directed_metadata(void)
{
    TEST("tkill and tgkill preserve SI_TKILL and sender credentials");
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = info_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    EXPECT_EQ(sigaction(SIGUSR1, &sa, NULL), 0, "install siginfo handler");
    for (int directed = 0; directed < 2; directed++) {
        info_code = info_pid = info_uid = -1;
        long rc = directed
                      ? syscall(SYS_tgkill, getpid(), raw_gettid(), SIGUSR1)
                      : syscall(SYS_tkill, raw_gettid(), SIGUSR1);
        EXPECT_EQ(rc, 0, "send thread-directed signal");
        EXPECT_EQ(info_code, SI_TKILL, "thread signal lost SI_TKILL");
        EXPECT_EQ(info_pid, getpid(), "thread signal sender pid is wrong");
        EXPECT_EQ(info_uid, getuid(), "thread signal sender uid is wrong");
    }
}

static _Atomic bool cancel_ready;

static void *cancel_sleeper(void *arg)
{
    (void) arg;
    atomic_store_explicit(&cancel_ready, true, memory_order_release);
    sleep(100);
    return NULL;
}

static void test_cancel_sleep(void)
{
    TEST("pthread_cancel terminates a sleeping cancellation point");
    pid_t child = fork();
    if (child == 0) {
        pthread_t worker;
        void *result = NULL;
        alarm(5);
        atomic_store_explicit(&cancel_ready, false, memory_order_relaxed);
        if (pthread_create(&worker, NULL, cancel_sleeper, NULL) != 0)
            _exit(1);
        while (!atomic_load_explicit(&cancel_ready, memory_order_acquire))
            usleep(1000);
        usleep(100000);
        if (pthread_cancel(worker) != 0 || pthread_join(worker, &result) != 0 ||
            result != PTHREAD_CANCELED)
            _exit(1);
        _exit(0);
    }
    int status = 0;
    EXPECT_TRUE(child > 0 && waitpid(child, &status, 0) == child &&
                    WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "sleeping thread ignored cancellation or failed to exit");
}

int main(void)
{
    printf("test-tgkill-directed: thread-directed signal routing\n");

    test_pthread_kill_targets_thread();
    test_directed_no_coalesce();
    test_tkill_self();
    test_directed_metadata();
    test_cancel_sleep();

    SUMMARY("test-tgkill-directed");
    return fails > 0 ? 1 : 0;
}
