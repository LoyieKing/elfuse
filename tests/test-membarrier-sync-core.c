/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Core synchronization can interrupt either EL0 computation or the syscall
 * return tail. Both callers must retain their registers and continue running.
 */
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"

#define REGISTER_SYNC_CORE (1 << 6)
#define SYNC_CORE (1 << 5)
static _Atomic int start;
static _Atomic unsigned errors;
static _Atomic unsigned progress;
static int passes, fails;
static pthread_barrier_t overlap_start;

static void *barrier_worker(void *unused)
{
    (void) unused;
    for (unsigned i = 0; i < 100; i++) {
        pthread_barrier_wait(&overlap_start);
        if (syscall(SYS_membarrier, i % 2 ? SYNC_CORE : (1 << 3), 0, 0) != 0)
            atomic_fetch_add_explicit(&errors, 1, memory_order_relaxed);
    }
    return NULL;
}

static void *worker(void *unused)
{
    (void) unused;
    while (!atomic_load_explicit(&start, memory_order_acquire))
        ;
    uint64_t value = 0x123456789abcdef0ULL;
    for (unsigned i = 0; i < 100000; i++) {
        __asm__ __volatile__("" : "+r"(value));
        if (syscall(SYS_getppid) != getppid())
            atomic_fetch_add_explicit(&errors, 1, memory_order_relaxed);
        value = value * 6364136223846793005ULL + 1;
        atomic_fetch_add_explicit(&progress, 1, memory_order_release);
        __asm__ __volatile__("" : "+r"(value));
    }
    uint64_t expected = 0x123456789abcdef0ULL;
    for (unsigned i = 0; i < 100000; i++)
        expected = expected * 6364136223846793005ULL + 1;
    if (value != expected)
        atomic_fetch_add_explicit(&errors, 1, memory_order_relaxed);
    return NULL;
}

int main(void)
{
    if (syscall(SYS_membarrier, REGISTER_SYNC_CORE, 0, 0) != 0)
        return 1;
    pthread_t threads[3];
    for (int i = 0; i < 3; i++)
        if (pthread_create(&threads[i], NULL, worker, NULL) != 0)
            return 2;
    atomic_store_explicit(&start, 1, memory_order_release);
    bool ok = true;
    for (int i = 0; i < 1000; i++)
        ok &= syscall(SYS_membarrier, SYNC_CORE, 0, 0) == 0;
    for (int i = 0; i < 3; i++)
        ok &= pthread_join(threads[i], NULL) == 0;
    TEST("concurrent SYNC_CORE preserves syscall and computation progress");
    EXPECT_TRUE(
        ok && atomic_load_explicit(&errors, memory_order_relaxed) == 0 &&
            atomic_load_explicit(&progress, memory_order_acquire) == 300000,
        "barrier corrupted execution state or lost a worker");
    ok = pthread_barrier_init(&overlap_start, NULL, 3) == 0;
    if (!ok)
        return 3;
    for (int i = 0; i < 3; i++)
        if (pthread_create(&threads[i], NULL, barrier_worker, NULL) != 0)
            return 4;
    for (int i = 0; i < 3; i++)
        ok &= pthread_join(threads[i], NULL) == 0;
    ok &= pthread_barrier_destroy(&overlap_start) == 0;
    TEST("overlapping expedited and SYNC_CORE callers complete");
    EXPECT_TRUE(ok && atomic_load_explicit(&errors, memory_order_relaxed) == 0,
                "overlapping barrier callers failed or corrupted execution");
    SUMMARY("test-membarrier-sync-core");
    return fails != 0;
}
