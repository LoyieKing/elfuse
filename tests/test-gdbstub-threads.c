/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static _Atomic bool done;
static _Atomic uint64_t progress;

void debugger_checkpoint(void);

__attribute__((noinline)) void debugger_checkpoint(void)
{
    __asm__ volatile("" ::: "memory");
}

static void *compute(void *arg)
{
    while (!atomic_load_explicit(&done, memory_order_relaxed))
        atomic_fetch_add_explicit(&progress, 1, memory_order_relaxed);
    return NULL;
}

static void *sleeping(void *arg)
{
    while (!atomic_load_explicit(&done, memory_order_relaxed))
        usleep(10000);
    return NULL;
}

int main(void)
{
    pthread_t busy, sleeper;
    if (pthread_create(&busy, NULL, compute, NULL) != 0 ||
        pthread_create(&sleeper, NULL, sleeping, NULL) != 0)
        return 1;
    while (atomic_load_explicit(&progress, memory_order_relaxed) < 10000)
        usleep(1000);
    debugger_checkpoint();
    atomic_store_explicit(&done, true, memory_order_relaxed);
    if (pthread_join(busy, NULL) != 0 || pthread_join(sleeper, NULL) != 0)
        return 2;
    puts("GDB_THREADS_PASS");
    return 0;
}
