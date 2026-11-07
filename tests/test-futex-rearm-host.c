/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "core/guest.h"
#include "core/shim-globals.h"
#include "runtime/thread.h"
#include "runtime/sched/exec.h"
#include "syscall/proc.h"
#include "test-harness.h"

static void *fixture_word(const guest_t *g, uint64_t addr);
static void *observed_waiter_load(thread_entry_t *t);
#undef exec_park_waiter_load
#define exec_park_waiter_load(t) observed_waiter_load(t)
#define guest_ptr fixture_word
#define guest_ptr_w fixture_word
#include "../src/runtime/futex.c"
#undef guest_ptr
#undef guest_ptr_w

static int passes, fails;
static guest_t guest;
static uint32_t first_word, second_word;
static thread_entry_t *owner;
static bool inject_rearm, rearmed;
static int64_t rearm_result;

/* Two readable futex words without creating an HVF VM. */
static void *fixture_word(const guest_t *g, uint64_t addr)
{
    (void) g;
    if (addr == (uint64_t) &first_word)
        return &first_word;
    if (addr == (uint64_t) &second_word)
        return &second_word;
    return NULL;
}

static void arm_second(void)
{
    if (sched_worker_pick(0) != owner)
        abort();
    current_thread = owner;
    exec_park_result_pending_store(owner, false);
    futex_key_t key = {.uaddr = (uint64_t) &second_word};
    rearm_result =
        futex_wait(&guest, &key, 0, 0, UINT32_MAX, 0, CLOCK_MONOTONIC);
    sched_put_current(owner, SCHED_PUT_BLOCKED);
    current_thread = NULL;
}

/* Schedule the remounted owner between the old token comparison and clear. */
static void *observed_waiter_load(thread_entry_t *t)
{
    void *snapshot =
        atomic_load_explicit(&t->async_futex_waiter, memory_order_acquire);
    if (inject_rearm && t == owner && snapshot && !exec_park_active_load(t) &&
        exec_park_result_pending_load(t)) {
        inject_rearm = false;
        arm_second();
        rearmed = true;
    }
    return snapshot;
}

static void test_rearm(bool cancel)
{
    owner = thread_alloc(cancel ? 2 : 1, 0, 0, NULL);
    if (!owner)
        abort();
    sched_task_inherit_attr(NULL, owner);
    sched_attach_thread(owner);
    sched_enqueue_thread(owner);
    if (sched_worker_pick(0) != owner)
        abort();
    current_thread = owner;
    futex_key_t key = {.uaddr = (uint64_t) &first_word};
    int64_t rc = futex_wait(&guest, &key, 0, 0, UINT32_MAX, 0, CLOCK_MONOTONIC);
    if (rc != SYSCALL_PARKED)
        abort();
    sched_put_current(owner, SCHED_PUT_BLOCKED);
    current_thread = NULL;
    rearmed = false;
    inject_rearm = true;
    if (cancel)
        futex_async_cancel(owner, -LINUX_EINTR);
    else if (futex_wake_one(&guest, (uint64_t) &first_word) != 1)
        abort();
    if (!rearmed)
        arm_second();
    inject_rearm = false;
    int woken = futex_wake_one(&guest, (uint64_t) &second_word);
    bool completed = !exec_park_active_load(owner) &&
                     sched_task_run_state(owner) == SCHED_STATE_READY;
    EXPECT_TRUE(rearm_result == SYSCALL_PARKED && woken == 1 && completed,
                "retiring the previous wait stranded its successor");
    if (sched_worker_pick(0) == owner)
        sched_put_current(owner, SCHED_PUT_DEAD);
}

int main(void)
{
    if (sched_domain_init(1) != 0)
        return 1;
    sched_set_host_ops(NULL);
    proc_init();
    guest.host_base = calloc(1, SHIM_GLOBALS_SIZE);
    if (!guest.host_base)
        return 1;
    TEST("wake then immediate futex rearm");
    test_rearm(false);
    TEST("signal then immediate futex rearm");
    test_rearm(true);
    free(guest.host_base);
    SUMMARY("test-futex-rearm-host");
    return fails != 0;
}
