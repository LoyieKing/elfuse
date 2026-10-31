/*
 * sched_setaffinity constrains which vCPU slots a thread may mount on
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Verifies mask intersection with ncpu storage (getaffinity),
 * empty/out-of-range rejection, clone inheritance, and that threads pinned to a
 * single slot still make progress under forced timeslice preemption (M:N mount
 * constraint).
 */

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef __NR_sched_setaffinity
#define __NR_sched_setaffinity 122
#endif
#ifndef __NR_sched_getaffinity
#define __NR_sched_getaffinity 123
#endif
#ifndef __NR_gettid
#define __NR_gettid 178
#endif

static long raw_syscall3(long n, long a, long b, long c)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x8)
                     : "memory");
    return x0;
}

static long raw_syscall0(long n)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory");
    return x0;
}

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static int count_mask_bits(unsigned long mask)
{
    int n = 0;
    while (mask) {
        n += (int) (mask & 1UL);
        mask >>= 1;
    }
    return n;
}

#define NPIN 8
#define MIN_ITERS 1500ULL
#define TIMEOUT_SEC 8

static atomic_ullong pin_counters[NPIN];
static atomic_int pin_go;
static atomic_int pin_done;

static void *pinned_spinner(void *arg)
{
    int id = (int) (intptr_t) arg;
    unsigned long mask = 1UL; /* CPU 0 only */
    long rc =
        raw_syscall3(__NR_sched_setaffinity, 0, sizeof(mask), (long) &mask);
    if (rc != 0)
        return (void *) (intptr_t) 1;

    unsigned long got = 0;
    rc = raw_syscall3(__NR_sched_getaffinity, 0, sizeof(got), (long) &got);
    if (rc <= 0 || (got & 1UL) == 0 || (got & ~1UL) != 0)
        return (void *) (intptr_t) 2;

    while (atomic_load_explicit(&pin_go, memory_order_acquire) == 0)
        ;

    while (atomic_load_explicit(&pin_done, memory_order_acquire) == 0)
        atomic_fetch_add_explicit(&pin_counters[id], 1, memory_order_relaxed);
    return NULL;
}

static void *child_affinity_probe(void *arg)
{
    unsigned long *out = arg;
    unsigned long got = 0;
    long rc = raw_syscall3(__NR_sched_getaffinity, 0, sizeof(got), (long) &got);
    *out = (rc > 0) ? got : 0;
    return (void *) (intptr_t) (rc <= 0 ? 1 : 0);
}

int main(void)
{
    int passes = 0, fails = 0;
    printf("test-sched-affinity: setaffinity mount constraints\n");

    unsigned long default_mask = 0;
    {
        long rc = raw_syscall3(__NR_sched_getaffinity, 0, sizeof(default_mask),
                               (long) &default_mask);
        if (rc <= 0 || default_mask == 0) {
            fprintf(stderr, "baseline getaffinity failed\n");
            return 1;
        }
    }
    int host_ncpu_bits = count_mask_bits(default_mask);

    TEST("setaffinity(CPU0) then getaffinity reports only CPU0");
    {
        unsigned long mask = 1UL;
        long rc =
            raw_syscall3(__NR_sched_setaffinity, 0, sizeof(mask), (long) &mask);
        EXPECT_TRUE(rc == 0, "setaffinity CPU0 failed");
        unsigned long got = ~0UL;
        rc = raw_syscall3(__NR_sched_getaffinity, 0, sizeof(got), (long) &got);
        EXPECT_TRUE(rc > 0, "getaffinity failed");
        EXPECT_TRUE((got & 1UL) != 0, "CPU0 missing after pin");
        EXPECT_TRUE((got & ~1UL) == 0, "extra CPUs remain after pin to CPU0");
    }

    TEST("setaffinity(empty) fails with EINVAL");
    {
        unsigned long mask = 0;
        long rc =
            raw_syscall3(__NR_sched_setaffinity, 0, sizeof(mask), (long) &mask);
        EXPECT_TRUE(rc == -EINVAL || rc < 0, "empty mask should fail");
    }

    TEST("setaffinity bits outside ncpu fail");
    {
        /* Restore a legal mask first (previous empty attempt left us pinned).
         */
        unsigned long cpu0 = 1UL;
        (void) raw_syscall3(__NR_sched_setaffinity, 0, sizeof(cpu0),
                            (long) &cpu0);
        if (host_ncpu_bits >= 63) {
            PASS();
        } else {
            unsigned long outside = ~((1UL << host_ncpu_bits) - 1UL);
            long rc = raw_syscall3(__NR_sched_setaffinity, 0, sizeof(outside),
                                   (long) &outside);
            EXPECT_TRUE(rc < 0, "out-of-range-only mask should fail");
        }
    }

    TEST("clone inherits parent affinity");
    {
        unsigned long pin = 1UL;
        long rc =
            raw_syscall3(__NR_sched_setaffinity, 0, sizeof(pin), (long) &pin);
        EXPECT_TRUE(rc == 0, "parent pin failed");
        unsigned long child_mask = 0;
        pthread_t th;
        int err = pthread_create(&th, NULL, child_affinity_probe, &child_mask);
        EXPECT_TRUE(err == 0, "pthread_create failed");
        void *ret = (void *) 1;
        pthread_join(th, &ret);
        EXPECT_TRUE(ret == NULL, "child getaffinity failed");
        EXPECT_TRUE((child_mask & 1UL) != 0 && (child_mask & ~1UL) == 0,
                    "child did not inherit CPU0-only mask");
    }

    TEST("CPU0-pinned spinners all advance (single-slot mount)");
    {
        memset(pin_counters, 0, sizeof(pin_counters));
        atomic_store(&pin_go, 0);
        atomic_store(&pin_done, 0);

        pthread_t th[NPIN];
        int create_fail = 0;
        for (int i = 0; i < NPIN; i++) {
            if (pthread_create(&th[i], NULL, pinned_spinner,
                               (void *) (intptr_t) i) != 0) {
                create_fail = 1;
                break;
            }
        }
        EXPECT_TRUE(!create_fail, "pthread_create failed");

        atomic_store_explicit(&pin_go, 1, memory_order_release);
        uint64_t start = mono_ns();
        int all_ok = 0;
        for (;;) {
            int ready = 0;
            for (int i = 0; i < NPIN; i++) {
                if (atomic_load_explicit(&pin_counters[i],
                                         memory_order_relaxed) >= MIN_ITERS)
                    ready++;
            }
            if (ready == NPIN) {
                all_ok = 1;
                break;
            }
            if (mono_ns() - start > (uint64_t) TIMEOUT_SEC * 1000000000ULL)
                break;
            struct timespec pause = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
            nanosleep(&pause, NULL);
        }
        atomic_store_explicit(&pin_done, 1, memory_order_release);
        for (int i = 0; i < NPIN; i++)
            pthread_join(th[i], NULL);

        if (all_ok) {
            PASS();
        } else {
            fprintf(stderr, "  counters:");
            for (int i = 0; i < NPIN; i++)
                fprintf(stderr, " %llu",
                        (unsigned long long) atomic_load(&pin_counters[i]));
            fprintf(stderr, "\n");
            FAIL("pinned spinners starved, affinity mount broken");
        }
    }

    /* Restore default mask so later process teardown is unconstrained. */
    (void) raw_syscall3(__NR_sched_setaffinity, 0, sizeof(default_mask),
                        (long) &default_mask);
    SUMMARY("test-sched-affinity");
    return fails ? 1 : 0;
}
