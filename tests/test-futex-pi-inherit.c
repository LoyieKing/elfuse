/*
 * PI futex priority inheritance, same VM
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A fair-priority owner holds a PI futex and sleeps on an unrelated timed
 * futex. A FIFO 50 waiter blocks on the PI lock. A FIFO 40 spinner keeps the
 * only allowed CPU busy. Without PI the fair owner cannot run until the spinner
 * ends, so the waiter acquires the lock only after the spinner stops. With real
 * inheritance the owner runs at the waiter's priority, times out, releases, and
 * the waiter acquires while the spinner is still running.
 *
 * Syscalls exercised: futex(98), sched_setscheduler(119),
 * sched_getaffinity(123), sched_setaffinity(122), clock_gettime(113),
 * pthread_create.
 */

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <linux/futex.h>

#include "test-harness.h"
#include "raw-syscall.h"

#ifndef FUTEX_PRIVATE_FLAG
#define FUTEX_PRIVATE_FLAG 128
#endif
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_PRIVATE FUTEX_PRIVATE_FLAG

_Static_assert(sizeof(_Atomic uint32_t) == sizeof(uint32_t),
               "atomic futex word must match guest layout");

int passes = 0, fails = 0;

static _Atomic uint32_t pi_word;
static _Atomic int low_ready;
static _Atomic int high_done;
static _Atomic int setup_err;
static _Atomic uint64_t high_acquired_ns;
static _Atomic uint64_t medium_end_ns;

static int test_cpu = -1;
static unsigned char cpu_mask[128];

static uint64_t now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static long futex_op(uint32_t *addr, int op, uint64_t timeout_gva)
{
    return raw_syscall6(__NR_futex, (long) addr, op, 0, (long) timeout_gva, 0,
                        0);
}

static int pin_test_cpu(void)
{
    return (int) raw_syscall3(__NR_sched_setaffinity, 0, sizeof(cpu_mask),
                              (long) cpu_mask);
}

static int find_allowed_cpu(void)
{
    memset(cpu_mask, 0, sizeof(cpu_mask));
    unsigned char allowed[128];
    memset(allowed, 0, sizeof(allowed));
    long rc = raw_syscall3(__NR_sched_getaffinity, 0, sizeof(allowed),
                           (long) allowed);
    if (rc < 0)
        return -1;
    for (int i = 0; i < (int) sizeof(allowed) * 8; i++) {
        if (allowed[i / 8] & (unsigned char) (1u << (i % 8))) {
            test_cpu = i;
            cpu_mask[i / 8] = (unsigned char) (1u << (i % 8));
            return 0;
        }
    }
    return -1;
}

static int set_policy(int policy, int prio)
{
    struct sched_param param;
    memset(&param, 0, sizeof(param));
    param.sched_priority = prio;
    return (int) raw_syscall3(__NR_sched_setscheduler, 0, policy,
                              (long) &param);
}

static void note_setup_failure(int rc)
{
    int err = rc < 0 ? -rc : EPERM;
    int zero = 0;
    (void) atomic_compare_exchange_strong_explicit(
        &setup_err, &zero, err, memory_order_relaxed, memory_order_relaxed);
    atomic_store_explicit(&high_done, 1, memory_order_release);
    raw_futex_wake((int *) &high_done, 1);
}

/* Fair owner: take the PI lock, then sleep on an unrelated futex until its
 * one-second timeout. It must be boosted to run while the RT spinner occupies
 * the CPU and release the lock.
 */
static void *owner_thread(void *arg)
{
    (void) arg;
    if (pin_test_cpu() < 0) {
        note_setup_failure(-EPERM);
        return NULL;
    }
    if (futex_op((uint32_t *) &pi_word, FUTEX_LOCK_PI | FUTEX_PRIVATE, 0) !=
        0) {
        atomic_store_explicit(&low_ready, -1, memory_order_release);
        raw_futex_wake((int *) &low_ready, 1);
        return NULL;
    }
    atomic_store_explicit(&low_ready, 1, memory_order_release);
    raw_futex_wake((int *) &low_ready, 1);

    struct timespec rel = {1, 0};
    _Atomic int release_word = 0;
    (void) futex_op((uint32_t *) &release_word, FUTEX_WAIT,
                    (uint64_t) (uintptr_t) &rel);

    (void) futex_op((uint32_t *) &pi_word, FUTEX_UNLOCK_PI | FUTEX_PRIVATE, 0);
    return NULL;
}

/* FIFO 50: block on the PI lock held by the fair owner. */
static void *high_thread(void *arg)
{
    (void) arg;
    if (pin_test_cpu() < 0) {
        note_setup_failure(-EPERM);
        return NULL;
    }
    int rc = set_policy(SCHED_FIFO, 50);
    if (rc < 0) {
        note_setup_failure(rc);
        return NULL;
    }
    int lock_rc =
        (int) futex_op((uint32_t *) &pi_word, FUTEX_LOCK_PI | FUTEX_PRIVATE, 0);
    if (lock_rc != 0) {
        note_setup_failure(lock_rc);
        return NULL;
    }
    atomic_store_explicit(&high_acquired_ns, now_ns(), memory_order_release);
    atomic_store_explicit(&high_done, 1, memory_order_release);
    raw_futex_wake((int *) &high_done, 1);
    (void) futex_op((uint32_t *) &pi_word, FUTEX_UNLOCK_PI | FUTEX_PRIVATE, 0);
    return NULL;
}

/* FIFO 40: keep the allowed CPU busy, below the waiter and below the inherited
 * owner.
 */
static void *medium_thread(void *arg)
{
    (void) arg;
    if (pin_test_cpu() < 0) {
        note_setup_failure(-EPERM);
        return NULL;
    }
    int rc = set_policy(SCHED_FIFO, 40);
    if (rc < 0) {
        note_setup_failure(rc);
        return NULL;
    }

    uint64_t start = now_ns();
    _Atomic uint64_t sink = 0;
    while (now_ns() - start < 2ULL * 1000 * 1000 * 1000) {
        uint64_t v = atomic_load_explicit(&sink, memory_order_relaxed);
        for (int i = 0; i < 10000; i++)
            v += (uint64_t) i;
        atomic_store_explicit(&sink, v, memory_order_relaxed);
    }
    atomic_store_explicit(&medium_end_ns, now_ns(), memory_order_release);
    return NULL;
}

static void wait_ready(void)
{
    for (int i = 0; i < 200; i++) {
        if (atomic_load_explicit(&low_ready, memory_order_acquire) != 0)
            return;
        struct timespec ts = {0, 10 * 1000 * 1000};
        (void) futex_op((uint32_t *) &low_ready, FUTEX_WAIT,
                        (uint64_t) (uintptr_t) &ts);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("test-futex-pi-inherit: same-VM PI donation\n");
    TEST("fair owner inherits FIFO waiter priority");

    int cpu_rc = find_allowed_cpu();
    if (cpu_rc < 0 || pin_test_cpu() < 0) {
        printf("SKIP: no allowed CPU for affinity pinning\n");
        return 77;
    }

    atomic_init(&pi_word, 0);
    atomic_init(&low_ready, 0);
    atomic_init(&high_done, 0);
    atomic_init(&setup_err, 0);
    atomic_init(&high_acquired_ns, 0);
    atomic_init(&medium_end_ns, 0);

    pthread_t low, high, medium;
    if (pthread_create(&low, NULL, owner_thread, NULL) != 0) {
        FAIL("pthread_create owner");
        SUMMARY("test-futex-pi-inherit");
        return 1;
    }
    pthread_detach(low);
    wait_ready();
    if (atomic_load_explicit(&low_ready, memory_order_acquire) != 1) {
        FAIL("owner did not acquire the PI lock");
        SUMMARY("test-futex-pi-inherit");
        return 1;
    }

    if (pthread_create(&high, NULL, high_thread, NULL) != 0 ||
        pthread_create(&medium, NULL, medium_thread, NULL) != 0) {
        FAIL("pthread_create RT workers");
        SUMMARY("test-futex-pi-inherit");
        return 1;
    }
    pthread_detach(high);

    /* Wait up to six seconds for the waiter. The medium spinner is bounded at
     * two seconds, so even without donation this returns well inside that.
     */
    uint64_t deadline = now_ns() + 6ULL * 1000 * 1000 * 1000;
    while (atomic_load_explicit(&high_done, memory_order_acquire) == 0 &&
           now_ns() < deadline) {
        struct timespec remaining = {0, 10 * 1000 * 1000};
        (void) futex_op((uint32_t *) &high_done, FUTEX_WAIT,
                        (uint64_t) (uintptr_t) &remaining);
        if (atomic_load_explicit(&setup_err, memory_order_acquire) != 0)
            break;
    }

    if (atomic_load_explicit(&setup_err, memory_order_acquire) != 0) {
        int err = atomic_load_explicit(&setup_err, memory_order_acquire);
        if (err == EPERM) {
            printf("SKIP: RT scheduling permission unavailable\n");
            _exit(77);
        }
        printf("FAIL: futex/RT setup failed: %s\n", strerror(err));
        fails++;
        SUMMARY("test-futex-pi-inherit");
        return 1;
    }

    /* The spinner is detached and bounded; waiting for its end is optional. A
     * completed acquisition while medium_end is still zero already proves the
     * waiter ran during the spinner.
     */
    uint64_t acquired =
        atomic_load_explicit(&high_acquired_ns, memory_order_acquire);
    uint64_t medium_end =
        atomic_load_explicit(&medium_end_ns, memory_order_acquire);
    if (atomic_load_explicit(&high_done, memory_order_acquire) == 0 ||
        acquired == 0) {
        FAIL("waiter never acquired the PI lock");
    } else if (medium_end != 0 && acquired >= medium_end) {
        printf(
            "FAIL: waiter acquired only after the RT spinner ended "
            "(high=%llu medium_end=%llu); no priority donation\n",
            (unsigned long long) acquired, (unsigned long long) medium_end);
        fails++;
    } else {
        PASS();
    }

    SUMMARY("test-futex-pi-inherit");
    fflush(NULL);
    return fails > 0 ? 1 : 0;
}
