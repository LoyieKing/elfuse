/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Waiters share one CPU while blocked, then gain a two-CPU affinity mask.
 * Waking both must use the idle CPU rather than preserve their shared
 * placement.
 */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "raw-syscall.h"
#include "test-harness.h"

static _Atomic int gate;
static _Atomic int entered;
static _Atomic bool stop;
static _Atomic int tids[2];
static int observed[2];
static int passes, fails;

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static bool sleeping(int tid)
{
    char path[96], line[512];
    snprintf(path, sizeof(path), "/proc/self/task/%d/stat", tid);
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    bool read_ok = fgets(line, sizeof(line), f) != NULL;
    fclose(f);
    char *end = read_ok ? strrchr(line, ')') : NULL;
    return end && end[1] == ' ' && end[2] == 'S';
}

static void *worker(void *arg)
{
    int id = (int) (intptr_t) arg;
    atomic_store_explicit(&tids[id], (int) raw_gettid(), memory_order_release);
    while (!atomic_load_explicit(&gate, memory_order_acquire))
        raw_futex_wait((int *) &gate, 0);
    observed[id] = sched_getcpu();
    atomic_fetch_add_explicit(&entered, 1, memory_order_release);
    while (!atomic_load_explicit(&stop, memory_order_acquire))
        ;
    return NULL;
}

static bool round_run(int cpu0, int cpu1, bool spread)
{
    atomic_store_explicit(&gate, 0, memory_order_relaxed);
    atomic_store_explicit(&entered, 0, memory_order_relaxed);
    atomic_store_explicit(&stop, false, memory_order_relaxed);
    for (int i = 0; i < 2; i++) {
        atomic_store_explicit(&tids[i], 0, memory_order_relaxed);
        observed[i] = -1;
    }
    cpu_set_t pin;
    CPU_ZERO(&pin);
    CPU_SET(cpu0, &pin);
    pthread_attr_t attr;
    if (pthread_attr_init(&attr))
        return false;
    if (pthread_attr_setaffinity_np(&attr, sizeof(pin), &pin)) {
        pthread_attr_destroy(&attr);
        return false;
    }
    pthread_t threads[2];
    int created = 0;
    for (; created < 2; created++)
        if (pthread_create(&threads[created], &attr, worker,
                           (void *) (intptr_t) created))
            break;
    pthread_attr_destroy(&attr);
    bool ok = created == 2;
    uint64_t deadline = mono_ns() + 2000000000ULL;
    while (ok) {
        int a = atomic_load_explicit(&tids[0], memory_order_acquire);
        int b = atomic_load_explicit(&tids[1], memory_order_acquire);
        if (a && b && sleeping(a) && sleeping(b))
            break;
        if (mono_ns() >= deadline) {
            ok = false;
            break;
        }
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
    }
    if (spread)
        CPU_SET(cpu1, &pin);
    for (int i = 0; ok && i < 2; i++)
        ok = pthread_setaffinity_np(threads[i], sizeof(pin), &pin) == 0;
    atomic_store_explicit(&gate, 1, memory_order_release);
    raw_futex_wake((int *) &gate, 2);
    deadline = mono_ns() + 2000000000ULL;
    while (atomic_load_explicit(&entered, memory_order_acquire) != created &&
           mono_ns() < deadline) {
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
    }
    ok &= atomic_load_explicit(&entered, memory_order_acquire) == created;
    atomic_store_explicit(&stop, true, memory_order_release);
    for (int i = 0; i < created; i++)
        ok &= pthread_join(threads[i], NULL) == 0;
    if (spread)
        ok &= (observed[0] == cpu0 && observed[1] == cpu1) ||
              (observed[0] == cpu1 && observed[1] == cpu0);
    else
        ok &= observed[0] == cpu0 && observed[1] == cpu0;
    printf("  observed CPUs: %d %d\n", observed[0], observed[1]);
    return ok;
}

int main(void)
{
    cpu_set_t allowed, control;
    if (sched_getaffinity(0, sizeof(allowed), &allowed))
        return 1;
    int cpus[3], n = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE && n < 3; cpu++)
        if (CPU_ISSET(cpu, &allowed))
            cpus[n++] = cpu;
    if (n < 3) {
        puts("SKIP: three allowed CPUs required");
        return 77;
    }
    CPU_ZERO(&control);
    CPU_SET(cpus[2], &control);
    if (sched_setaffinity(0, sizeof(control), &control))
        return 1;
    TEST("unrestricted fair wakeups use both idle CPUs");
    EXPECT_TRUE(round_run(cpus[0], cpus[1], true),
                "wakeups retained shared placement");
    TEST("pinned wakeups retain their allowed CPU");
    EXPECT_TRUE(round_run(cpus[0], cpus[1], false),
                "wake balance escaped affinity");
    sched_setaffinity(0, sizeof(allowed), &allowed);
    SUMMARY("test-sched-wake-balance");
    return fails != 0;
}
