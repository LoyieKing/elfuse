/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drive scheduler queues directly without HVF timing or worker startup races.
 */
#include <stdio.h>
#include <stdlib.h>

#include "runtime/thread.h"
#include "test-harness.h"

#include "../src/runtime/sched/sched.c"

_Thread_local thread_entry_t *current_thread;

static _Noreturn void unexpected(void)
{
    fputs("unexpected runtime dependency\n", stderr);
    abort();
}

#define UNUSED_CALLBACK(name)    \
    void name(thread_entry_t *t) \
    {                            \
        (void) t;                \
        unexpected();            \
    }
UNUSED_CALLBACK(futex_park_on_deadline)
UNUSED_CALLBACK(futex_park_on_interrupt)
UNUSED_CALLBACK(sleep_park_on_deadline)
UNUSED_CALLBACK(sleep_park_on_interrupt)
UNUSED_CALLBACK(io_park_on_deadline)
UNUSED_CALLBACK(io_park_on_interrupt)
UNUSED_CALLBACK(mqueue_park_on_deadline)
UNUSED_CALLBACK(mqueue_park_on_interrupt)
UNUSED_CALLBACK(sysvipc_park_on_deadline)
UNUSED_CALLBACK(sysvipc_park_on_interrupt)
UNUSED_CALLBACK(wait_park_on_deadline)
UNUSED_CALLBACK(wait_park_on_interrupt)
UNUSED_CALLBACK(signal_wait_park_on_deadline)
UNUSED_CALLBACK(signal_wait_park_on_interrupt)

void thread_for_each(void (*fn)(thread_entry_t *, void *), void *ctx)
{
    (void) fn;
    (void) ctx;
    unexpected();
}
void thread_for_each_ref(void (*fn)(thread_entry_t *, void *), void *ctx)
{
    (void) fn;
    (void) ctx;
    unexpected();
}
uint64_t thread_process_cputime_ns(void)
{
    unexpected();
}
void thread_process_cputime_split_ns(uint64_t *user, uint64_t *system)
{
    (void) user;
    (void) system;
    unexpected();
}

static thread_entry_t tasks[8];
static int passes, fails;
static unsigned live_calls, timer_wakes;
static uint64_t live_exec_ns;

static sched_live_sample_t live_sample(const thread_entry_t *t)
{
    (void) t;
    live_calls++;
    return (sched_live_sample_t) {.exec_ns = live_exec_ns, .valid = true};
}

static void wake_timer(void)
{
    timer_wakes++;
}

static void reset(void)
{
    for (unsigned i = 0; i < 8; i++) {
        if (tasks[i].sched.attrs_initialized)
            sched_detach_thread(&tasks[i]);
        sched_task_inherit_attr(NULL, &tasks[i]);
        atomic_store_explicit(&tasks[i].guest_tid, i + 1, memory_order_relaxed);
    }
    current_thread = NULL;
}

static void queue(unsigned id, int cpu, uint64_t expected)
{
    tasks[id].sched.placement_cpu = cpu;
    tasks[id].sched.expected_runtime_ns = expected;
    sched_enqueue_thread(&tasks[id]);
}

static void pinned(unsigned id, int cpu)
{
    memset(tasks[id].sched.affinity, 0, sizeof(tasks[id].sched.affinity));
    SCHED_BIT_SET(tasks[id].sched.affinity, cpu);
}

int main(void)
{
    if (sched_domain_init(3) || sched_domain_ncpu() < 3)
        return 77;
    reset();
    queue(0, 0, 8000000);
    queue(1, 1, 1000000);
    queue(2, 2, 4000000);
    tasks[3].sched.placement_cpu = 0;
    TEST("busy CPUs select the least estimated queue");
    EXPECT_EQ(find_fair_target_cpu_locked(&tasks[3]), 1,
              "placement retained overloaded preferred CPU");
    TEST("hard affinity excludes a lighter queue");
    pinned(3, 2);
    EXPECT_EQ(find_fair_target_cpu_locked(&tasks[3]), 2,
              "placement escaped hard affinity");

    tasks[3].sched.placement_cpu = 0;
    affinity_set_full(&tasks[3].sched);
    tasks[3].sched.state = SCHED_STATE_BLOCKED;
    sched_unblock(&tasks[3]);
    TEST("fair wakeup balances while every CPU is busy");
    EXPECT_EQ(tasks[3].sched.queued_cpu, 1,
              "wake placement only searched for fully idle CPUs");

    reset();
    queue(0, 0, 1000000);
    sched_worker_pick(0);
    queue(1, 1, 1000000);
    sched_worker_pick(1);
    queue(2, 2, 1000000);
    sched_worker_pick(2);
    tasks[3].sched.placement_cpu = 2;
    sched_cpus[2].dl_running_bw = 100;
    TEST("equal queue times prefer lower deadline utilization");
    EXPECT_EQ(find_fair_target_cpu_locked(&tasks[3]), 0,
              "equal queues ignored deadline demand");
    sched_cpus[2].dl_running_bw = 0;

    reset();
    queue(0, 0, 25000);
    tasks[1].sched.placement_cpu = 0;
    TEST("25us early-out preserves cache locality");
    EXPECT_EQ(find_fair_target_cpu_locked(&tasks[1]), 0,
              "sufficient local candidate was bypassed");
    sched_detach_thread(&tasks[0]);
    sched_task_inherit_attr(NULL, &tasks[0]);
    queue(0, 0, 25001);
    TEST("queue above 25us searches other CPUs");
    EXPECT_EQ(find_fair_target_cpu_locked(&tasks[1]), 1,
              "over-threshold queue stopped the search");

    reset();
    pinned(0, 0);
    tasks[0].sched.fair_cpu = 0;
    tasks[0].sched.fair_slice_ns = 1000000;
    tasks[0].sched.fair_finish_ns = UINT64_MAX - 1;
    queue(0, 0, 1000000);
    tasks[1].sched.fair_cpu = 0;
    tasks[1].sched.fair_slice_ns = 1000000;
    tasks[1].sched.fair_finish_ns = UINT64_MAX - 2;
    queue(1, 0, 2000000);
    tasks[1].sched.runtime_ns = 700;
    tasks[1].sched.runtime_user_ns = 600;
    tasks[1].sched.runtime_sys_ns = 100;
    TEST("idle CPU steals eligible affinity-compatible work");
    thread_entry_t *stolen = sched_worker_pick(1);
    EXPECT_TRUE(stolen == &tasks[1] && tasks[0].sched.queued_cpu == 0,
                "steal selected pinned work or ignored eligible sibling");
    TEST("steal preserves settled CPU accounting");
    EXPECT_TRUE(tasks[1].sched.runtime_ns == 700 &&
                    tasks[1].sched.runtime_user_ns == 600 &&
                    tasks[1].sched.runtime_sys_ns == 100,
                "migration reset or duplicated runtime");
    TEST("steal transfers load exactly once");
    EXPECT_TRUE(sched_cpus[0].total_expected_runtime_ns == 1000000 &&
                    sched_cpus[1].total_expected_runtime_ns == 2000000,
                "source or target retained duplicate estimated demand");

    reset();
    sched_task_attrs_t rt = {.policy = SCHED_POLICY_FIFO, .rt_priority = 50};
    bool rt_ok = sched_task_set_attr(&tasks[0], &rt) == 0;
    queue(0, 0, 1000000);
    sched_task_attrs_t dl = {.policy = SCHED_POLICY_DEADLINE,
                             .runtime = 1000000,
                             .deadline = 10000000,
                             .period = 10000000};
    bool dl_ok = sched_task_set_attr(&tasks[1], &dl) == 0;
    queue(1, 0, 1000000);
    TEST("idle stealing leaves Linux RT and DL queues local");
    EXPECT_TRUE(rt_ok && dl_ok && sched_worker_pick(1) == NULL &&
                    tasks[0].sched.queued_cpu == 0 &&
                    tasks[1].sched.queued_cpu == 0,
                "stealing bypassed Linux ordering or admission");

    reset();
    sched_cpus[0].virtual_ns = 10000000;
    sched_cpus[0].slope_q10 = 512;
    sched_cpus[1].virtual_ns = 20000000;
    sched_cpus[1].slope_q10 = 1024;
    tasks[0].sched.fair_cpu = 0;
    tasks[0].sched.fair_start_ns = 9000000;
    tasks[0].sched.fair_finish_ns = 12000000;
    tasks[0].sched.fair_slice_ns = 500000;
    tasks[0].sched.fair_used_ns = 125000;
    fair_migrate_transform_locked(&tasks[0], 1);
    TEST("migration converts source timeline and consumed budget");
    EXPECT_TRUE(tasks[0].sched.fair_start_ns == 18000000 &&
                    tasks[0].sched.fair_finish_ns == 24000000 &&
                    tasks[0].sched.fair_slice_ns == 1000000 &&
                    tasks[0].sched.fair_used_ns == 250000,
                "migration reset lag or consumed fraction");

    reset();
    pinned(0, 0);
    queue(0, 0, 1000000);
    thread_entry_t *accounted = sched_worker_pick(0);
    current_thread = accounted;
    sched_account_cpu_ns(accounted, 100);
    sched_account_service_ns(accounted, 200);
    TEST("quiet accounting retains user and service runtime");
    EXPECT_TRUE(accounted->sched.runtime_user_ns == 100 &&
                    accounted->sched.runtime_sys_ns == 200 &&
                    accounted->sched.runtime_ns == 300 &&
                    !sched_take_resched(accounted),
                "empty host actions lost charges or requested a switch");
    pinned(1, 0);
    queue(1, 0, 1000000);
    (void) sched_take_resched(accounted);
    uint64_t remaining =
        accounted->sched.fair_slice_ns - accounted->sched.fair_used_ns;
    uint64_t slope = sched_cpus[0].slope_q10;
    uint64_t charge = sched_fair_real_ns(remaining, (uint32_t) slope) + 1;
    sched_account_service_ns(accounted, charge);
    TEST("service budget expiry reschedules runnable sibling");
    EXPECT_TRUE(sched_take_resched(accounted) &&
                    accounted->sched.runtime_sys_ns == 200 + charge,
                "accounting discarded the nonempty kick or service charge");
    TEST("budget expiry advances to the waiting task");
    sched_put_current(accounted, SCHED_PUT_PREEMPTED);
    EXPECT_TRUE(sched_worker_pick(0) == &tasks[1],
                "budget expiry failed to advance to the waiting task");

    reset();
    queue(0, 0, 1000000);
    thread_entry_t *running = sched_worker_pick(0);
    sched_account_cpu_ns(running, 8000000);
    sched_put_current(running, SCHED_PUT_BLOCKED);
    TEST("runtime estimate follows peaks immediately");
    EXPECT_EQ(tasks[0].sched.expected_runtime_ns, 8000000,
              "peak runtime was diluted");
    sched_unblock(running);
    running = sched_worker_pick(tasks[0].sched.placement_cpu);
    sched_account_cpu_ns(running, 4000000);
    sched_put_current(running, SCHED_PUT_BLOCKED);
    TEST("runtime estimate decays by one quarter");
    EXPECT_EQ(tasks[0].sched.expected_runtime_ns, 7000000,
              "runtime estimate used a different decay");

    reset();
    sched_host_ops_t timer_ops = {
        .live_sample = live_sample,
        .wake_timer = wake_timer,
    };
    sched_set_host_ops(&timer_ops);
    pinned(0, 0);
    queue(0, 0, 1000000);
    running = sched_worker_pick(0);
    running->sched.fair_used_ns = running->sched.fair_slice_ns - 1;
    uint64_t runtime_before = running->sched.runtime_ns;
    live_calls = 0;
    TEST("solo FAIR near expiry has no scheduler budget timer");
    EXPECT_TRUE(sched_next_timer_ns() == 0 &&
                    sched_run_timers(sched_now_ns()) == 0 && live_calls == 0,
                "solo FAIR budget caused sampling or a timer wake");
    sched_account_cpu_ns(running, 1);
    TEST("solo FAIR exhausted budget leaves the task mounted");
    EXPECT_TRUE(sched_next_timer_ns() == 0 && !sched_take_resched(running) &&
                    live_calls == 0 &&
                    running->sched.runtime_ns == runtime_before + 1 &&
                    running->sched.fair_used_ns >= running->sched.fair_slice_ns,
                "solo FAIR exhaustion lost accounting or reset the budget");
    timer_wakes = 0;
    pinned(1, 0);
    queue(1, 0, 1000000);
    TEST("FAIR enqueue restores timer pressure");
    EXPECT_TRUE(timer_wakes != 0,
                "a new contender did not notify the timer backend");
    uint64_t before_timer = sched_now_ns();
    uint64_t next_timer = sched_next_timer_ns();
    TEST("FAIR contender makes an exhausted budget immediately due");
    EXPECT_TRUE(next_timer >= before_timer &&
                    next_timer <= sched_now_ns() + 1 && live_calls == 1 &&
                    sched_run_timers(sched_now_ns()) == 1 &&
                    sched_take_resched(running),
                "contention lost the live sample or expired-budget kick");
    sched_put_current(running, SCHED_PUT_PREEMPTED);
    TEST("FAIR timer expiry advances the waiting task");
    EXPECT_TRUE(sched_worker_pick(0) == &tasks[1],
                "expired FAIR activation ran ahead of its contender");

    reset();
    sched_task_attrs_t rr = {.policy = SCHED_POLICY_RR, .rt_priority = 50};
    bool rr_ok = sched_task_set_attr(&tasks[0], &rr) == 0;
    pinned(0, 0);
    queue(0, 0, 1000000);
    running = sched_worker_pick(0);
    live_calls = 0;
    TEST("solo RR retains live budget sampling and timer");
    EXPECT_TRUE(rr_ok && sched_next_timer_ns() != 0 && live_calls == 1,
                "FAIR timer suppression changed RR enforcement");
    sched_account_cpu_ns(running, SCHED_RR_QUANTUM_NS / 4);
    uint64_t rr_left = running->sched.rr_remaining_ns;
    (void) sched_next_timer_ns();
    TEST("timer sampling preserves the unused RR quantum");
    EXPECT_TRUE(rr_left == SCHED_RR_QUANTUM_NS * 3 / 4 &&
                    running->sched.rr_remaining_ns == rr_left,
                "timer sampling renewed or consumed the RR quantum");

    reset();
    dl_ok = sched_task_set_attr(&tasks[0], &dl) == 0;
    pinned(0, 0);
    queue(0, 0, 1000000);
    running = sched_worker_pick(0);
    live_calls = 0;
    TEST("solo DEADLINE retains live budget sampling and timer");
    EXPECT_TRUE(dl_ok && sched_next_timer_ns() != 0 && live_calls == 1,
                "FAIR timer suppression changed DEADLINE enforcement");
    live_exec_ns = running->sched.dl_runtime_left_ns;
    TEST("solo DEADLINE still preempts at its runtime budget");
    EXPECT_TRUE(
        sched_run_timers(sched_now_ns()) == 1 && sched_take_resched(running),
        "solo DEADLINE overrun did not request preemption");
    live_exec_ns = 0;
    sched_set_host_ops(NULL);
    reset();
    TEST("retiring tasks removes all estimated demand");
    EXPECT_TRUE(!sched_cpus[0].total_expected_runtime_ns &&
                    !sched_cpus[1].total_expected_runtime_ns &&
                    !sched_cpus[2].total_expected_runtime_ns,
                "retired tasks left placement load behind");
    SUMMARY("test-sched-placement-host");
    return fails != 0;
}
