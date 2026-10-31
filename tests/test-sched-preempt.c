/*
 * Forced fair timeslice preemption
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Spawns more CPU-bound threads than host vCPU slots. Without forced timeslice
 * cut-off, a spinner mounted on a slot starves its READY sibling forever. With
 * preemption, every worker's counter advances.
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

#define NTHREADS 16
#define MIN_ITERS 2000ULL
#define TIMEOUT_SEC 8

static atomic_ullong counters[NTHREADS];
static atomic_int go_flag;
static atomic_int done_flag;

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static void *spinner(void *arg)
{
    int id = (int) (intptr_t) arg;
    while (atomic_load_explicit(&go_flag, memory_order_acquire) == 0)
        ;

    while (atomic_load_explicit(&done_flag, memory_order_acquire) == 0) {
        atomic_fetch_add_explicit(&counters[id], 1, memory_order_relaxed);

        /* Pure EL0 spin, no voluntary yield. Progress for a READY sibling on
         * the same slot requires forced timeslice preemption.
         */
    }
    return NULL;
}

int main(void)
{
    int passes = 0, fails = 0;
    printf("test-sched-preempt: forced timeslice cut-off with %d spinners\n",
           NTHREADS);

    memset(counters, 0, sizeof(counters));
    atomic_store(&go_flag, 0);
    atomic_store(&done_flag, 0);

    pthread_t th[NTHREADS];
    for (int i = 0; i < NTHREADS; i++) {
        int err = pthread_create(&th[i], NULL, spinner, (void *) (intptr_t) i);
        if (err != 0) {
            fprintf(stderr, "pthread_create[%d] failed: %s\n", i,
                    strerror(err));
            return 1;
        }
    }

    atomic_store_explicit(&go_flag, 1, memory_order_release);

    uint64_t start = mono_ns();
    int all_ok = 0;
    for (;;) {
        int ready = 0;
        for (int i = 0; i < NTHREADS; i++) {
            if (atomic_load_explicit(&counters[i], memory_order_relaxed) >=
                MIN_ITERS)
                ready++;
        }
        if (ready == NTHREADS) {
            all_ok = 1;
            break;
        }
        uint64_t now = mono_ns();
        if (now - start > (uint64_t) TIMEOUT_SEC * 1000000000ULL)
            break;
        /* Brief pause so we do not drown the workers from the main thread. */
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
        nanosleep(&pause, NULL);
    }

    atomic_store_explicit(&done_flag, 1, memory_order_release);

    for (int i = 0; i < NTHREADS; i++)
        pthread_join(th[i], NULL);

    TEST("every spinner advanced under forced preemption");
    if (all_ok) {
        PASS();
    } else {
        fprintf(stderr, "  counters:");
        for (int i = 0; i < NTHREADS; i++)
            fprintf(stderr, " %llu",
                    (unsigned long long) atomic_load(&counters[i]));
        fprintf(stderr, "\n");
        FAIL("starved spinner(s), timeslice preemption did not cut over");
    }

    printf("\n%d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
