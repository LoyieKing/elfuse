/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Concurrent backing resets and guest writes race repeated fork snapshots. The
 * writer publishes the low address first, so every real instant has first >=
 * last even when the writer is stopped between its two stores.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

#define SNAPSHOT_SIZE (8U * 1024U * 1024U)
#define RESET_SIZE (64U * 1024U)
#define FORK_ROUNDS 12

static int passes, fails;
static _Atomic uint64_t *first, *last;
static unsigned char *reset_memory;
static _Atomic bool stop_workers;
static _Atomic unsigned resets;
static _Atomic bool reset_failed;
static volatile sig_atomic_t waiting_child;

static void alarm_handler(int signo)
{
    (void) signo;
    if (waiting_child > 0)
        kill((pid_t) waiting_child, SIGKILL);
    _exit(1);
}

static void *write_sequence(void *arg)
{
    (void) arg;
    uint64_t sequence = 0;
    while (!atomic_load_explicit(&stop_workers, memory_order_relaxed)) {
        sequence++;
        atomic_store_explicit(first, sequence, memory_order_seq_cst);
        atomic_store_explicit(last, sequence, memory_order_seq_cst);
    }
    return NULL;
}

static void *reset_backing(void *arg)
{
    (void) arg;
    while (!atomic_load_explicit(&stop_workers, memory_order_relaxed)) {
        reset_memory[0] = 0x5a;
        if (madvise(reset_memory, RESET_SIZE, MADV_DONTNEED) != 0 ||
            reset_memory[0] != 0) {
            atomic_store_explicit(&reset_failed, true, memory_order_relaxed);
            break;
        }
        atomic_fetch_add_explicit(&resets, 1, memory_order_relaxed);
    }
    return NULL;
}

int main(void)
{
    struct sigaction sa = {.sa_handler = alarm_handler};
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) != 0)
        return 1;
    alarm(30);
    unsigned char *memory = mmap(NULL, SNAPSHOT_SIZE, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    reset_memory = mmap(NULL, RESET_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED || reset_memory == MAP_FAILED)
        return 1;
    first = (_Atomic uint64_t *) memory;
    last = (_Atomic uint64_t *) (memory + SNAPSHOT_SIZE - sizeof(*last));
    atomic_init(first, 0);
    atomic_init(last, 0);
    pthread_t writer, resetter;
    if (pthread_create(&writer, NULL, write_sequence, NULL) != 0)
        return 1;
    if (pthread_create(&resetter, NULL, reset_backing, NULL) != 0) {
        atomic_store_explicit(&stop_workers, true, memory_order_relaxed);
        pthread_join(writer, NULL);
        return 1;
    }
    while ((atomic_load_explicit(&resets, memory_order_relaxed) == 0 ||
            atomic_load_explicit(first, memory_order_seq_cst) == 0) &&
           !atomic_load_explicit(&reset_failed, memory_order_relaxed))
        sched_yield();

    TEST("repeated fork freezes guest bytes");
    bool ok = !atomic_load_explicit(&reset_failed, memory_order_relaxed);
    for (int round = 0; ok && round < FORK_ROUNDS; round++) {
        pid_t child = fork();
        if (child < 0) {
            ok = false;
            break;
        }
        if (child == 0) {
            alarm(10);
            uint64_t a = atomic_load_explicit(first, memory_order_seq_cst);
            uint64_t b = atomic_load_explicit(last, memory_order_seq_cst);
            _exit(a >= b && a != 0 ? 0 : 1);
        }
        waiting_child = (sig_atomic_t) child;
        int status;
        pid_t reaped;
        do {
            reaped = waitpid(child, &status, 0);
        } while (reaped < 0 && errno == EINTR);
        waiting_child = 0;
        ok = reaped == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    EXPECT_TRUE(ok, "fork failed, child was lost, or byte snapshot was torn");
    atomic_store_explicit(&stop_workers, true, memory_order_relaxed);
    pthread_join(writer, NULL);
    pthread_join(resetter, NULL);
    TEST("backing resets drain after fork");
    EXPECT_TRUE(!atomic_load_explicit(&reset_failed, memory_order_relaxed) &&
                    atomic_load_explicit(&resets, memory_order_relaxed) != 0,
                "backing reset failed or did not run");
    TEST("fork leaves no extra child");
    int status;
    EXPECT_ERRNO(waitpid(-1, &status, WNOHANG), ECHILD,
                 "fork left an unexpected guest child");
    munmap(memory, SNAPSHOT_SIZE);
    munmap(reset_memory, RESET_SIZE);
    alarm(0);
    SUMMARY("test-fork-quiesce-memory");
    return fails != 0;
}
