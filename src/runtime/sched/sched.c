/*
 * Per-VM guest scheduler
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2026 The Fuchsia Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux class precedence (DEADLINE, RT, FAIR) with a Zircon-derived fair
 * scheduler: one scheduling domain per VM, one run queue and one virtual
 * timeline per logical CPU, a CPU-wide fair period, and per-task activation
 * budgets that survive blocking and migration.
 *
 * Fair activation, augmented queue selection, runtime estimation, CPU placement
 * and idle stealing derive from the Zircon fair scheduler at the pinned commit
 * 966c936b56d8d117a26ecbf2c583ec350b2325c8 (zircon/kernel/kernel/scheduler.rs).
 * Zircon is distributed under a MIT-style license; see docs/scheduler.md for
 * the pinned reference.
 *
 * The core owns ready queues, run state, accounting and scheduling attributes.
 * It never touches an HVF handle or guest register state: execution backends
 * save architecture state, report actual executed time, call
 * sched_put_current() and then sched_worker_pick(). Host wake/kick/timer
 * services are registered through sched_host_ops and are always called without
 * the scheduler lock.
 */

#include "runtime/sched/sched.h"

#include "runtime/sched/fair.h"
#include "runtime/thread.h"
#include "runtime/sched/exec.h"

#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SCHED_RT_LEVELS (SCHED_RT_PRIO_MAX + 1)
#define SCHED_RT_BITMAP_WORDS ((SCHED_RT_LEVELS + 63) / 64)

#define SCHED_BIT_SET(set, bit) \
    ((set)[(bit) / 8] |= (uint8_t) (1U << ((bit) % 8)))
#define SCHED_BIT_CLEAR(set, bit) \
    ((set)[(bit) / 8] &= (uint8_t) ~(1U << ((bit) % 8)))
#define SCHED_BIT_TEST(set, bit) (((set)[(bit) / 8] >> ((bit) % 8)) & 1U)

/* Fair custom slice bounds from Linux __setparam_fair(). */
#define SCHED_FAIR_SLICE_MIN_NS 100000ULL
#define SCHED_FAIR_SLICE_MAX_NS 100000000ULL

/* DL runtime must be at least 1 << DL_SCALE nanoseconds (Linux). */
#define SCHED_DL_MIN_RUNTIME_NS 1024ULL

/* Zircon find_target_cpu's same-cluster queue-time early-out threshold. */
#define SCHED_INTRA_CLUSTER_THRESHOLD_NS 25000ULL

typedef struct sched_cpu_state {
    sched_tree_t fair; /* keyed by activation start, augmented by finish */
    sched_tree_t dl;   /* keyed by absolute deadline (EDF) */
    thread_entry_t *rt_head[SCHED_RT_LEVELS];
    thread_entry_t *rt_tail[SCHED_RT_LEVELS];
    uint64_t rt_bitmap[SCHED_RT_BITMAP_WORDS];
    uint32_t rt_nr;

    uint64_t weight_total; /* fair weights of queued and running tasks */
    uint32_t slope_q10;    /* virtual timeline speed, Zircon Affine slope */
    uint64_t virtual_ns;   /* fair virtual timeline */
    uint64_t snap_count;   /* idle timeline snaps (diagnostic) */
    uint64_t total_expected_runtime_ns; /* queued and running tasks, Zircon */
    pthread_cond_t
        work_cond; /* host equivalent of target CPU reschedule wake */

    thread_entry_t *current;
    int current_class;
    bool need_resched;

    /* Most recent owner samples for this CPU, in nanoseconds not yet settled
     * through sched_account_cpu_ns()/sched_account_service_ns(). Filled outside
     * sched_lock.
     */
    uint64_t live_sample_ns;
    uint64_t live_service_sample_ns;

    /* Incremented by every settlement of the current mount; a sample taken
     * across a settlement is discarded instead of double-counted.
     */
    uint64_t account_seq;
    uint64_t live_sample_seq; /* account_seq captured with the samples */

    bool rt_throttled;
    uint64_t rt_period_start_ns;
    uint64_t rt_runtime_used_ns;

    uint64_t dl_this_bw;    /* all admitted DL tasks belonging to this CPU */
    uint64_t dl_running_bw; /* active (contending or non-contending) DL */
} sched_cpu_state_t;

typedef struct sched_actions {
    uint8_t wake[SCHED_CPUSET_BYTES];
    uint8_t kick[SCHED_CPUSET_BYTES];
    bool timer;
    thread_entry_t *overrun;
    thread_entry_t *prio_changed;
} sched_actions_t;

static pthread_mutex_t sched_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sched_cond = PTHREAD_COND_INITIALIZER;
static sched_cpu_state_t *sched_cpus;
static int sched_ncpu;
static int sched_host_ncpu_cache;
static bool sched_initialized;
static bool sched_shutdown_flag;
static bool sched_frozen;
static sched_host_ops_t sched_ops;
static void (*sched_prio_changed_hook)(thread_entry_t *t);
static uint64_t sched_dl_admitted_bw;
static thread_entry_t *sched_dl_head;
static thread_entry_t *sched_dl_tail;

static void sched_init_defaults_locked(thread_entry_t *t);

static void actions_init(sched_actions_t *a)
{
    memset(a, 0, sizeof(*a));
}

static void sched_dispatch(const sched_actions_t *a)
{
    if (!a->timer && !a->overrun && !a->prio_changed) {
        bool cpu_action = false;
        for (int i = 0; i < (sched_ncpu + 7) / 8; i++)
            cpu_action |= a->wake[i] != 0 || a->kick[i] != 0;
        if (!cpu_action)
            return;
    }
    sched_host_ops_t ops;
    void (*prio_hook)(thread_entry_t *t);
    bool frozen;

    pthread_mutex_lock(&sched_lock);
    ops = sched_ops;
    prio_hook = sched_prio_changed_hook;
    frozen = sched_frozen;
    pthread_mutex_unlock(&sched_lock);

    if (!frozen) {
        for (int i = 0; i < sched_ncpu; i++) {
            if (SCHED_BIT_TEST(a->wake, i) && ops.wake_cpu)
                ops.wake_cpu(i);
            if (SCHED_BIT_TEST(a->kick, i) && ops.kick_cpu)
                ops.kick_cpu(i);
        }
    }

    if (a->timer && ops.wake_timer)
        ops.wake_timer();
    if (a->overrun && ops.dl_overrun)
        ops.dl_overrun(a->overrun);
    if (a->prio_changed && prio_hook)
        prio_hook(a->prio_changed);
}

uint64_t sched_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

/* Small helpers */

static inline sched_task_state_t *TS(thread_entry_t *t)
{
    return &t->sched;
}

static inline const sched_task_state_t *CTS(const thread_entry_t *t)
{
    return &t->sched;
}

static thread_entry_t *task_from_node(sched_tree_node_t *node)
{
    return (thread_entry_t *) ((char *) node - offsetof(thread_entry_t, sched) -
                               offsetof(sched_task_state_t, node));
}

static sched_tree_node_t *tree_next(sched_tree_node_t *node)
{
    if (node->right) {
        node = node->right;
        while (node->left)
            node = node->left;
        return node;
    }
    while (node->parent && node == node->parent->right)
        node = node->parent;
    return node->parent;
}

static bool policy_is_fair(int policy)
{
    return policy == SCHED_POLICY_OTHER || policy == SCHED_POLICY_BATCH ||
           policy == SCHED_POLICY_IDLE;
}

static bool policy_is_rt(int policy)
{
    return policy == SCHED_POLICY_FIFO || policy == SCHED_POLICY_RR;
}

static bool policy_is_dl(int policy)
{
    return policy == SCHED_POLICY_DEADLINE;
}

static bool policy_valid(int policy)
{
    return policy == SCHED_POLICY_OTHER || policy == SCHED_POLICY_FIFO ||
           policy == SCHED_POLICY_RR || policy == SCHED_POLICY_BATCH ||
           policy == SCHED_POLICY_IDLE || policy == SCHED_POLICY_DEADLINE;
}

static int class_of_policy(int policy)
{
    if (policy_is_dl(policy))
        return SCHED_CLASS_DEADLINE;
    if (policy_is_rt(policy))
        return SCHED_CLASS_RT;
    if (policy_is_fair(policy))
        return SCHED_CLASS_FAIR;
    return SCHED_CLASS_NONE;
}

static int task_eff_class(const thread_entry_t *t)
{
    return class_of_policy(CTS(t)->eff_policy);
}

static uint32_t weight_for_policy(int policy, int nice)
{
    if (!policy_is_fair(policy))
        return 0;
    if (policy == SCHED_POLICY_IDLE)
        return sched_fair_weight_from_nice(SCHED_NICE_MAX);
    return sched_fair_weight_from_nice(nice);
}

static uint32_t task_eff_weight(const thread_entry_t *t)
{
    const sched_task_state_t *s = CTS(t);

    return weight_for_policy(s->eff_policy, s->eff_nice);
}

static size_t domain_mask_bytes(void)
{
    size_t bytes = (size_t) (sched_ncpu + 7) / 8;

    if (bytes < 8)
        bytes = 8;
    return bytes;
}

static bool affinity_allows(const thread_entry_t *t, int cpu)
{
    const sched_task_state_t *s = CTS(t);

    if (cpu < 0 || cpu >= sched_ncpu)
        return false;

    /* A freshly created task that has not been through inherit yet has an
     * all-zero mask; treat it as the full domain.
     */
    bool any = false;
    for (size_t i = 0; i < sizeof(s->affinity); i++)
        any |= s->affinity[i] != 0;
    if (!any)
        return true;
    return SCHED_BIT_TEST(s->affinity, cpu) != 0;
}

static void affinity_set_full(sched_task_state_t *s)
{
    memset(s->affinity, 0, sizeof(s->affinity));
    for (int i = 0; i < sched_ncpu; i++)
        SCHED_BIT_SET(s->affinity, i);
}

static bool dmask_any_in_domain(const uint8_t *mask, size_t len)
{
    for (int i = 0; i < sched_ncpu; i++) {
        size_t byte = (size_t) i / 8;
        if (byte < len && SCHED_BIT_TEST(mask, i))
            return true;
    }
    return false;
}

static bool dmask_allows(const uint8_t *mask, size_t len, int cpu)
{
    if (cpu < 0 || cpu >= sched_ncpu)
        return false;
    size_t byte = (size_t) cpu / 8;
    if (byte >= len)
        return false;
    return SCHED_BIT_TEST(mask, cpu) != 0;
}

static int find_fair_target_cpu_locked(const thread_entry_t *t)
{
    int start = CTS(t)->placement_cpu;
    if (start < 0 || start >= sched_ncpu)
        start = 0;
    int best = -1;
    uint64_t best_queue = UINT64_MAX;
    uint64_t best_dl = UINT64_MAX;

    /* Zircon find_target_cpu / CandidatePlacement in one equal-capacity
     * cluster: last CPU first, then least queue time and deadline utilization.
     */
    for (int offset = 0; offset < sched_ncpu; offset++) {
        int cpu = (start + offset) % sched_ncpu;
        if (!affinity_allows(t, cpu))
            continue;
        const sched_cpu_state_t *candidate = &sched_cpus[cpu];
        uint64_t queue = candidate->total_expected_runtime_ns;
        uint64_t dl = candidate->dl_running_bw;
        if (best < 0 || queue < best_queue ||
            (queue == best_queue && dl < best_dl)) {
            best = cpu;
            best_queue = queue;
            best_dl = dl;
            if (queue <= SCHED_INTRA_CLUSTER_THRESHOLD_NS &&
                dl <= SCHED_DL_BW_ONE)
                break;
        }
    }
    return best;
}

static int cpu_load_score(int cpu)
{
    sched_cpu_state_t *c = &sched_cpus[cpu];

    return (int) c->fair.count + (int) c->dl.count + (int) c->rt_nr +
           (c->current ? 1 : 0);
}

static int pick_cpu_locked(thread_entry_t *t)
{
    int placement = TS(t)->placement_cpu;

    if (placement >= 0 && placement < sched_ncpu &&
        affinity_allows(t, placement))
        return placement;
    if (task_eff_class(t) == SCHED_CLASS_FAIR)
        return find_fair_target_cpu_locked(t);

    int best = -1;
    int best_load = 0;
    uint64_t best_weight = UINT64_MAX;
    for (int i = 0; i < sched_ncpu; i++) {
        if (!affinity_allows(t, i))
            continue;
        int load = cpu_load_score(i);
        uint64_t weight = sched_cpus[i].weight_total;
        if (best < 0 || load < best_load ||
            (load == best_load && weight < best_weight)) {
            best = i;
            best_load = load;
            best_weight = weight;
        }
    }
    if (best >= 0)
        TS(t)->placement_cpu = best;
    return best;
}

static void cpu_need_resched_locked(sched_cpu_state_t *cpu,
                                    int cpu_index,
                                    sched_actions_t *a)
{
    cpu->need_resched = true;
    SCHED_BIT_SET(a->kick, cpu_index);
}

/* Fair scheduling */

static uint64_t fair_slice_for(const thread_entry_t *t,
                               const sched_cpu_state_t *cpu)
{
    const sched_task_state_t *s = CTS(t);

    if (s->fair_slice_custom_ns != 0) {
        uint32_t slope = cpu->slope_q10 ? cpu->slope_q10 : SCHED_FAIR_SLOPE_ONE;
        uint64_t virtual = sched_fair_virtual_delta_ns(s->fair_slice_custom_ns,
                                                       slope);
        return virtual ? virtual : 1;
    }

    uint64_t slice = sched_fair_slice_ns(s->eff_weight, cpu->weight_total);
    return slice ? slice : 1;
}

/* Adjust one task's activation budget after the CPU weight distribution
 * changes. The activation window (start/finish) is unchanged; the unused
 * portion is rescaled so the task's lag is conserved, matching Zircon's
 * adjust_fair_bandwidth().
 */
static void fair_adjust_slice_locked(thread_entry_t *t, sched_cpu_state_t *cpu)
{
    sched_task_state_t *s = TS(t);

    if (s->fair_slice_ns == 0)
        return;

    uint64_t now = cpu->virtual_ns;
    uint64_t until_finish =
        s->fair_finish_ns > now ? s->fair_finish_ns - now : 0;
    uint64_t slice = fair_slice_for(t, cpu);
    uint64_t old_slice = s->fair_slice_ns;
    uint64_t old_rem =
        old_slice > s->fair_used_ns ? old_slice - s->fair_used_ns : 0;

    __int128 delta = ((__int128) slice - (__int128) old_slice) *
                     (__int128) until_finish /
                     (__int128) SCHED_DEFAULT_FAIR_PERIOD_NS;
    __int128 rem = (__int128) old_rem + delta;

    if (rem < 0)
        rem = 0;
    if ((uint64_t) rem > until_finish)
        rem = (__int128) until_finish;
    if ((uint64_t) rem > slice)
        rem = (__int128) slice;

    s->fair_slice_ns = slice;
    s->fair_used_ns = slice - (uint64_t) rem;
}

static void fair_note_change_locked(sched_cpu_state_t *cpu)
{
    uint32_t min_weight = UINT32_MAX;

    if (cpu->fair.root)
        min_weight = cpu->fair.root->min_weight;
    if (cpu->current && cpu->current_class == SCHED_CLASS_FAIR) {
        uint32_t w = task_eff_weight(cpu->current);
        if (w && w < min_weight)
            min_weight = w;
    }
    if (min_weight == UINT32_MAX)
        min_weight = 0;

    cpu->slope_q10 = sched_fair_slope_q10(min_weight, cpu->weight_total);

    for (sched_tree_node_t *n = sched_tree_first(&cpu->fair); n;
         n = tree_next(n))
        fair_adjust_slice_locked(task_from_node(n), cpu);

    if (cpu->current && cpu->current_class == SCHED_CLASS_FAIR)
        fair_adjust_slice_locked(cpu->current, cpu);
}

static void fair_migrate_transform_locked(thread_entry_t *t, int target_cpu)
{
    sched_task_state_t *s = TS(t);
    sched_cpu_state_t *cpu = &sched_cpus[target_cpu];
    uint64_t now = cpu->virtual_ns;

    if (s->fair_slice_ns == 0) {
        s->fair_cpu = -1;
        return;
    }
    if (s->fair_cpu >= 0 && s->fair_cpu != target_cpu) {
        /* Zircon steal_work carries source variable time through monotonic time
         * before target insertion. HVF CPUs use equal processing rates; each
         * CPU's current virtual time is the common instant's anchor.
         */
        const sched_cpu_state_t *source = &sched_cpus[s->fair_cpu];
        uint32_t from =
            source->slope_q10 ? source->slope_q10 : SCHED_FAIR_SLOPE_ONE;
        uint32_t to = cpu->slope_q10 ? cpu->slope_q10 : SCHED_FAIR_SLOPE_ONE;
        __int128 start = (__int128) s->fair_start_ns - source->virtual_ns;
        __int128 finish = (__int128) s->fair_finish_ns - source->virtual_ns;
        start = (__int128) now + start * to / from;
        finish = (__int128) now + finish * to / from;
        s->fair_start_ns = start < 0            ? 0
                           : start > UINT64_MAX ? UINT64_MAX
                                                : (uint64_t) start;
        s->fair_finish_ns = finish < 0            ? 0
                            : finish > UINT64_MAX ? UINT64_MAX
                                                  : (uint64_t) finish;
        s->fair_slice_ns =
            (uint64_t) ((__uint128_t) s->fair_slice_ns * to / from);
        s->fair_used_ns =
            (uint64_t) ((__uint128_t) s->fair_used_ns * to / from);
        s->fair_cpu = target_cpu;
        return;
    }
    if (s->fair_cpu < 0)
        s->fair_cpu = target_cpu;
}

static void fair_activation_prepare_locked(thread_entry_t *t,
                                           sched_cpu_state_t *cpu,
                                           int cpu_index)
{
    sched_task_state_t *s = TS(t);

    /* Activation values are consumed by pick_locked() in the target CPU's
     * virtual timeline. Host wall time is a different axis and must never be
     * compared with fair_start/finish or used to rebase a migration.
     */
    uint64_t now = cpu->virtual_ns;

    fair_migrate_transform_locked(t, cpu_index);

    if (s->fair_slice_ns != 0 && s->fair_finish_ns > now &&
        s->fair_used_ns < s->fair_slice_ns) {
        /* Retained activation, including the unused budget. */
        return;
    }

    uint64_t start = now;
    if (s->fair_finish_ns > now)
        start = s->fair_finish_ns;
    uint64_t slice = fair_slice_for(t, cpu);

    s->fair_start_ns = start;
    s->fair_finish_ns = start + SCHED_DEFAULT_FAIR_PERIOD_NS;
    s->fair_slice_ns = slice;
    s->fair_used_ns = 0;
    s->fair_cpu = cpu_index;
}

/* RT run queue */

static bool rt_has_ready(const sched_cpu_state_t *cpu)
{
    for (int i = 0; i < SCHED_RT_BITMAP_WORDS; i++)
        if (cpu->rt_bitmap[i] != 0)
            return true;
    return false;
}

static void rt_bit_set(sched_cpu_state_t *cpu, unsigned prio)
{
    cpu->rt_bitmap[prio / 64] |= UINT64_C(1) << (prio % 64);
}

static void rt_bit_clear(sched_cpu_state_t *cpu, unsigned prio)
{
    cpu->rt_bitmap[prio / 64] &= ~(UINT64_C(1) << (prio % 64));
}

static int rt_highest_prio(const sched_cpu_state_t *cpu)
{
    for (int i = SCHED_RT_BITMAP_WORDS - 1; i >= 0; i--) {
        if (cpu->rt_bitmap[i]) {
            int bit = 63 - __builtin_clzll(cpu->rt_bitmap[i]);
            return i * 64 + bit;
        }
    }
    return -1;
}

static void rt_push_tail(sched_cpu_state_t *cpu,
                         thread_entry_t *t,
                         unsigned prio)
{
    sched_task_state_t *s = TS(t);

    s->rt_prev = cpu->rt_tail[prio];
    s->rt_next = NULL;
    if (cpu->rt_tail[prio])
        TS(cpu->rt_tail[prio])->rt_next = t;
    else
        cpu->rt_head[prio] = t;
    cpu->rt_tail[prio] = t;
    rt_bit_set(cpu, prio);
    cpu->rt_nr++;
}

static void rt_push_head(sched_cpu_state_t *cpu,
                         thread_entry_t *t,
                         unsigned prio)
{
    sched_task_state_t *s = TS(t);

    s->rt_next = cpu->rt_head[prio];
    s->rt_prev = NULL;
    if (cpu->rt_head[prio])
        TS(cpu->rt_head[prio])->rt_prev = t;
    else
        cpu->rt_tail[prio] = t;
    cpu->rt_head[prio] = t;
    rt_bit_set(cpu, prio);
    cpu->rt_nr++;
}

static void rt_remove(sched_cpu_state_t *cpu, thread_entry_t *t, unsigned prio);

/* Put an already queued RT task at the head of its priority list. Used for
 * involuntary preemption and for a priority increase, matching Linux's
 * requeue_task_rt(head) rules.
 */
static void rt_requeue_head_locked(thread_entry_t *t)
{
    sched_task_state_t *s = TS(t);

    if (!s->on_rq || s->queued_class != SCHED_CLASS_RT)
        return;
    if (s->queued_cpu < 0 || s->queued_cpu >= sched_ncpu)
        return;
    sched_cpu_state_t *cpu = &sched_cpus[s->queued_cpu];
    unsigned prio = s->eff_rt_priority;
    rt_remove(cpu, t, prio);
    rt_push_head(cpu, t, prio);
}

static void rt_remove(sched_cpu_state_t *cpu, thread_entry_t *t, unsigned prio)
{
    sched_task_state_t *s = TS(t);

    if (s->rt_prev)
        TS(s->rt_prev)->rt_next = s->rt_next;
    else
        cpu->rt_head[prio] = s->rt_next;
    if (s->rt_next)
        TS(s->rt_next)->rt_prev = s->rt_prev;
    else
        cpu->rt_tail[prio] = s->rt_prev;
    s->rt_next = NULL;
    s->rt_prev = NULL;
    if (!cpu->rt_head[prio])
        rt_bit_clear(cpu, prio);
    if (cpu->rt_nr > 0)
        cpu->rt_nr--;
}

/* Deadline scheduling */

static uint64_t dl_domain_capacity(void)
{
    return (uint64_t) sched_ncpu * SCHED_DL_BW_ONE;
}

static uint32_t dl_bw_compute(uint64_t runtime, uint64_t period)
{
    if (period == 0)
        return 0;
    __uint128_t bw = (__uint128_t) runtime * SCHED_DL_BW_ONE;
    bw = (bw + period - 1) / period;
    if (bw == 0)
        bw = 1;
    if (bw > UINT32_MAX)
        bw = UINT32_MAX;
    return (uint32_t) bw;
}

static uint64_t task_dl_abs_deadline(const thread_entry_t *t)
{
    const sched_task_state_t *s = CTS(t);

    if (s->pi_boosted && s->eff_policy == SCHED_POLICY_DEADLINE)
        return s->eff_dl_abs_deadline_ns;
    if (s->policy == SCHED_POLICY_DEADLINE)
        return s->dl_abs_deadline_ns;
    return 0;
}


static void dl_list_add_locked(thread_entry_t *t)
{
    sched_task_state_t *s = TS(t);

    s->dl_prev = sched_dl_tail;
    s->dl_next = NULL;
    if (sched_dl_tail)
        TS(sched_dl_tail)->dl_next = t;
    else
        sched_dl_head = t;
    sched_dl_tail = t;
}

static void dl_list_remove_locked(thread_entry_t *t)
{
    sched_task_state_t *s = TS(t);

    if (s->dl_prev)
        TS(s->dl_prev)->dl_next = s->dl_next;
    else if (sched_dl_head == t)
        sched_dl_head = s->dl_next;
    if (s->dl_next)
        TS(s->dl_next)->dl_prev = s->dl_prev;
    else if (sched_dl_tail == t)
        sched_dl_tail = s->dl_prev;
    s->dl_prev = NULL;
    s->dl_next = NULL;
}

static void dl_detach_bw_locked(thread_entry_t *t)
{
    sched_task_state_t *s = TS(t);

    if (s->dl_bw_cpu < 0 || s->dl_bw_cpu >= sched_ncpu)
        goto clear;
    sched_cpu_state_t *cpu = &sched_cpus[s->dl_bw_cpu];
    if (cpu->dl_this_bw >= s->dl_bw_q20)
        cpu->dl_this_bw -= s->dl_bw_q20;
    else
        cpu->dl_this_bw = 0;
    if (s->dl_bw_counted) {
        if (cpu->dl_running_bw >= s->dl_bw_q20)
            cpu->dl_running_bw -= s->dl_bw_q20;
        else
            cpu->dl_running_bw = 0;
    }
clear:
    s->dl_bw_cpu = -1;
    s->dl_bw_counted = false;
    s->dl_non_contending = false;
    s->dl_inactive_deadline_ns = 0;
}

static void dl_attach_bw_locked(thread_entry_t *t, int cpu_index)
{
    sched_task_state_t *s = TS(t);

    if (s->policy != SCHED_POLICY_DEADLINE || s->dl_bw_q20 == 0)
        return;
    if (cpu_index < 0 || cpu_index >= sched_ncpu)
        return;
    if (s->dl_bw_cpu == cpu_index)
        return;

    bool counted = s->dl_bw_counted;
    if (s->dl_bw_cpu >= 0) {
        sched_cpu_state_t *old = &sched_cpus[s->dl_bw_cpu];
        if (old->dl_this_bw >= s->dl_bw_q20)
            old->dl_this_bw -= s->dl_bw_q20;
        else
            old->dl_this_bw = 0;
        if (counted) {
            if (old->dl_running_bw >= s->dl_bw_q20)
                old->dl_running_bw -= s->dl_bw_q20;
            else
                old->dl_running_bw = 0;
        }
    }

    sched_cpu_state_t *cpu = &sched_cpus[cpu_index];
    cpu->dl_this_bw += s->dl_bw_q20;
    if (counted)
        cpu->dl_running_bw += s->dl_bw_q20;
    s->dl_bw_cpu = cpu_index;
}

static void dl_activate_bw_locked(thread_entry_t *t, int cpu_index)
{
    sched_task_state_t *s = TS(t);

    if (s->policy != SCHED_POLICY_DEADLINE || s->dl_bw_q20 == 0)
        return;
    dl_attach_bw_locked(t, cpu_index);
    if (!s->dl_bw_counted && s->dl_bw_cpu == cpu_index) {
        sched_cpus[cpu_index].dl_running_bw += s->dl_bw_q20;
        s->dl_bw_counted = true;
    }
    s->dl_non_contending = false;
    s->dl_inactive_deadline_ns = 0;
}

static void dl_forget_locked(thread_entry_t *t)
{
    sched_task_state_t *s = TS(t);

    if (s->dl_admitted) {
        if (sched_dl_admitted_bw >= s->dl_bw_q20)
            sched_dl_admitted_bw -= s->dl_bw_q20;
        else
            sched_dl_admitted_bw = 0;
        s->dl_admitted = false;
        dl_list_remove_locked(t);
    }
    dl_detach_bw_locked(t);
    s->dl_bw_q20 = 0;
    s->dl_runtime_left_ns = 0;
    s->dl_abs_deadline_ns = 0;
    s->dl_throttled = false;
    s->dl_yielded = false;
    s->dl_overrun_reported = false;
}

static void dl_replenish_locked(thread_entry_t *t, uint64_t now)
{
    sched_task_state_t *s = TS(t);
    uint64_t period = s->dl_period_ns;

    if (s->policy != SCHED_POLICY_DEADLINE)
        return;
    if (period == 0)
        period = s->dl_deadline_ns;
    if (period == 0)
        period = 1;

    uint64_t deadline = s->dl_abs_deadline_ns;
    if (deadline == 0)
        deadline = now;
    do {
        if (UINT64_MAX - deadline < period) {
            deadline = now + period;
            break;
        }
        deadline += period;
    } while (deadline <= now);

    s->dl_abs_deadline_ns = deadline;
    if (s->dl_yielded) {
        s->dl_runtime_left_ns = s->dl_runtime_ns;
    } else if (UINT64_MAX - s->dl_runtime_left_ns < s->dl_runtime_ns) {
        s->dl_runtime_left_ns = UINT64_MAX;
    } else {
        s->dl_runtime_left_ns += s->dl_runtime_ns;
    }
    s->dl_throttled = false;
    s->dl_yielded = false;
    s->dl_overrun_reported = false;
}

/* Apply the CBS wake-up rule: if the scheduling deadline passed, or if the
 * remaining runtime over the remaining deadline exceeds the reservation
 * density, start a new reservation (Linux update_dl_entity()).
 *
 * Returns false when the task is still throttled and must wait for its
 * replenishment timer.
 */
static bool dl_make_runnable_locked(thread_entry_t *t,
                                    uint64_t now,
                                    sched_actions_t *a)
{
    sched_task_state_t *s = TS(t);

    if (s->policy != SCHED_POLICY_DEADLINE)
        return true;
    if (!s->dl_admitted)
        return true;

    uint64_t period = s->dl_period_ns ? s->dl_period_ns : s->dl_deadline_ns;
    uint64_t rel = s->dl_deadline_ns ? s->dl_deadline_ns : period;
    if (period == 0 || rel == 0 || s->dl_runtime_ns == 0)
        return false;

    if (s->dl_throttled) {
        if (now < s->dl_abs_deadline_ns) {
            a->timer = true;
            return false;
        }
        dl_replenish_locked(t, now);
    }

    bool restart = false;
    if (s->dl_abs_deadline_ns == 0 || s->dl_abs_deadline_ns <= now) {
        restart = true;
    } else if (s->dl_runtime_left_ns == 0) {
        restart = true;
    } else {
        __uint128_t left = (__uint128_t) s->dl_runtime_left_ns * period;
        __uint128_t span =
            (__uint128_t) (s->dl_abs_deadline_ns - now) * s->dl_runtime_ns;
        if (left > span)
            restart = true;
    }

    if (restart) {
        s->dl_abs_deadline_ns = now + rel;
        s->dl_runtime_left_ns = s->dl_runtime_ns;
        s->dl_throttled = false;
        s->dl_yielded = false;
        s->dl_overrun_reported = false;
    }
    return true;
}

static void dl_block_bw_locked(thread_entry_t *t, uint64_t now)
{
    sched_task_state_t *s = TS(t);

    if (s->policy != SCHED_POLICY_DEADLINE || !s->dl_bw_counted ||
        s->dl_bw_cpu < 0 || s->dl_bw_cpu >= sched_ncpu)
        return;

    uint64_t zero_lag;
    if (s->dl_runtime_ns != 0) {
        __uint128_t delta = (__uint128_t) s->dl_runtime_left_ns *
                            s->dl_period_ns / s->dl_runtime_ns;
        zero_lag = s->dl_abs_deadline_ns > (uint64_t) delta
                       ? s->dl_abs_deadline_ns - (uint64_t) delta
                       : 0;
    } else {
        zero_lag = s->dl_abs_deadline_ns;
    }

    if (zero_lag <= now) {
        sched_cpu_state_t *cpu = &sched_cpus[s->dl_bw_cpu];
        if (cpu->dl_running_bw >= s->dl_bw_q20)
            cpu->dl_running_bw -= s->dl_bw_q20;
        else
            cpu->dl_running_bw = 0;
        s->dl_bw_counted = false;
        s->dl_non_contending = false;
        s->dl_inactive_deadline_ns = 0;
    } else {
        s->dl_non_contending = true;
        s->dl_inactive_deadline_ns = zero_lag;
    }
}

/* Budget charged by @ns actual nanoseconds under @s's deadline reservation. The
 * reclaim pace scales by the CPU's active bandwidth; a nonzero interval always
 * consumes at least one nanosecond.
 */
static uint64_t dl_charge_ns(const sched_task_state_t *s,
                             const sched_cpu_state_t *cpu,
                             uint64_t ns)
{
    if (!(s->flags & SCHED_FLAG_RECLAIM))
        return ns;

    /* GRUB pace: dq = -max(Ui, Uact) / Umax * dt. With no inactive and no extra
     * bandwidth this reduces to the task's own bandwidth; with spare capacity
     * the budget is consumed more slowly and the task reclaims it.
     */
    uint64_t numerator = cpu->dl_running_bw;
    if (s->dl_bw_q20 > numerator)
        numerator = s->dl_bw_q20;
    if (numerator > SCHED_DL_BW_ONE)
        numerator = SCHED_DL_BW_ONE;
    __uint128_t scaled = (__uint128_t) ns * numerator / SCHED_DL_BW_ONE;
    uint64_t charge = (uint64_t) scaled;
    if (charge == 0 && ns != 0)
        charge = 1;
    return charge;
}

static void dl_charge_locked(thread_entry_t *t,
                             sched_cpu_state_t *cpu,
                             int cpu_index,
                             uint64_t ns,
                             sched_actions_t *a)
{
    sched_task_state_t *s = TS(t);

    if (s->pi_boosted && s->eff_policy == SCHED_POLICY_DEADLINE) {
        /* A PI-boosted deadline owner runs on borrowed time: it is never
         * throttled while it holds the lock, or the chain could deadlock.
         */
        if (s->eff_dl_runtime_left_ns > ns)
            s->eff_dl_runtime_left_ns -= ns;
        else
            s->eff_dl_runtime_left_ns = 0;
        return;
    }
    if (s->policy != SCHED_POLICY_DEADLINE)
        return;

    uint64_t charge = dl_charge_ns(s, cpu, ns);

    if (s->dl_runtime_left_ns > charge) {
        s->dl_runtime_left_ns -= charge;
        return;
    }

    s->dl_runtime_left_ns = 0;
    if (!s->dl_throttled) {
        s->dl_throttled = true;
        if ((s->flags & SCHED_FLAG_DL_OVERRUN) && !s->dl_overrun_reported) {
            s->dl_overrun_reported = true;
            a->overrun = t;
        }
        cpu_need_resched_locked(cpu, cpu_index, a);
        a->timer = true;
    }
}

/* Run-queue membership */

static void task_remove_from_queue_locked(thread_entry_t *t)
{
    sched_task_state_t *s = TS(t);

    if (!s->on_rq)
        return;

    int cpu_index = s->queued_cpu;
    if (cpu_index < 0 || cpu_index >= sched_ncpu) {
        s->on_rq = false;
        s->queued_class = SCHED_CLASS_NONE;
        s->queued_cpu = -1;
        return;
    }
    sched_cpu_state_t *cpu = &sched_cpus[cpu_index];
    cpu->total_expected_runtime_ns -= s->expected_runtime_ns;

    switch (s->queued_class) {
    case SCHED_CLASS_FAIR:
        sched_tree_remove(&cpu->fair, &s->node);
        if (cpu->weight_total >= s->eff_weight)
            cpu->weight_total -= s->eff_weight;
        else
            cpu->weight_total = 0;
        s->fair_cpu = cpu_index;
        fair_note_change_locked(cpu);
        break;
    case SCHED_CLASS_RT:
        rt_remove(cpu, t, s->eff_rt_priority);
        break;
    case SCHED_CLASS_DEADLINE:
        sched_tree_remove(&cpu->dl, &s->node);
        break;
    default:
        break;
    }

    s->on_rq = false;
    s->queued_class = SCHED_CLASS_NONE;
    s->queued_cpu = -1;
}

static bool task_insert_into_queue_locked(thread_entry_t *t,
                                          int cpu_index,
                                          uint64_t now,
                                          sched_actions_t *a)
{
    sched_task_state_t *s = TS(t);
    sched_cpu_state_t *cpu = &sched_cpus[cpu_index];
    int cls = task_eff_class(t);
    bool ok = false;

    if (cls == SCHED_CLASS_FAIR) {
        fair_activation_prepare_locked(t, cpu, cpu_index);
        s->node.key_time = s->fair_start_ns;
        s->node.key_tid = (uint64_t) (uintptr_t) t;
        s->node.finish = s->fair_finish_ns;
        s->node.weight = s->eff_weight;
        cpu->weight_total += s->eff_weight;
        if (sched_tree_insert(&cpu->fair, &s->node)) {
            ok = true;
            fair_note_change_locked(cpu);
        } else {
            if (cpu->weight_total >= s->eff_weight)
                cpu->weight_total -= s->eff_weight;
            else
                cpu->weight_total = 0;
        }
    } else if (cls == SCHED_CLASS_RT) {
        unsigned prio = s->eff_rt_priority;
        if (prio > SCHED_RT_PRIO_MAX)
            prio = SCHED_RT_PRIO_MAX;
        if (prio < SCHED_RT_PRIO_MIN)
            prio = SCHED_RT_PRIO_MIN;
        s->eff_rt_priority = prio;
        if (s->eff_policy == SCHED_POLICY_RR && s->rr_remaining_ns == 0)
            s->rr_remaining_ns = SCHED_RR_QUANTUM_NS;
        rt_push_tail(cpu, t, prio);
        ok = true;
    } else if (cls == SCHED_CLASS_DEADLINE) {
        if (!dl_make_runnable_locked(t, now, a))
            return false;
        uint64_t deadline = task_dl_abs_deadline(t);
        if (deadline == 0) {
            a->timer = true;
            return false;
        }
        dl_attach_bw_locked(t, cpu_index);
        dl_activate_bw_locked(t, cpu_index);
        s->node.key_time = deadline;
        s->node.key_tid = (uint64_t) (uintptr_t) t;
        s->node.finish = deadline;
        s->node.weight = 0;
        ok = sched_tree_insert(&cpu->dl, &s->node);
    }

    if (ok) {
        cpu->total_expected_runtime_ns += s->expected_runtime_ns;
        s->on_rq = true;
        s->queued_class = cls;
        s->queued_cpu = cpu_index;
        s->state = SCHED_STATE_READY;
        s->placement_cpu = cpu_index;
    }
    return ok;
}

static void place_fair_wakeup_locked(thread_entry_t *t)
{
    if (task_eff_class(t) == SCHED_CLASS_FAIR) {
        int target = find_fair_target_cpu_locked(t);
        TS(t)->placement_cpu = target;

        /* Zircon insert(Placement::Insertion) resets the activation window
         * before bandwidth adjustment when new-wakeup accounting is disabled.
         */
        TS(t)->fair_start_ns = sched_cpus[target].virtual_ns;
        TS(t)->fair_finish_ns =
            TS(t)->fair_start_ns + SCHED_DEFAULT_FAIR_PERIOD_NS;
        TS(t)->fair_cpu = target;
    }
}

static int enqueue_ready_locked(thread_entry_t *t,
                                uint64_t now,
                                sched_actions_t *a)
{
    sched_task_state_t *s = TS(t);

    if (s->state == SCHED_STATE_DEAD)
        return 0;
    if (s->on_rq)
        return 1;

    if (atomic_load_explicit(&s->stop_reasons, memory_order_acquire) != 0) {
        /* A stop reason wins over a concurrent wake or park completion. Keep
         * the wake recorded so CONT can publish READY without losing it.
         */
        s->state = SCHED_STATE_BLOCKED;
        s->wake_pending = true;
        a->timer = true;
        return 0;
    }
    int cpu_index = s->placement_cpu;


    if (cpu_index < 0 || cpu_index >= sched_ncpu ||
        !affinity_allows(t, cpu_index))
        cpu_index = pick_cpu_locked(t);

    if (cpu_index < 0)
        cpu_index = 0;

    if (!task_insert_into_queue_locked(t, cpu_index, now, a)) {
        s->state = SCHED_STATE_READY;
        s->placement_cpu = cpu_index;
        a->timer = true;
        return 0;
    }


    if (!sched_frozen)
        SCHED_BIT_SET(a->wake, cpu_index);
    thread_entry_t *current = sched_cpus[cpu_index].current;
    if (!sched_frozen && current && current != t) {
        if (TS(current)->run_class == SCHED_CLASS_FAIR)
            a->timer = true;
        int ready_class = task_eff_class(t);
        int running_class = task_eff_class(current);
        bool preempt = ready_class > running_class;
        if (ready_class == running_class && ready_class == SCHED_CLASS_RT)
            preempt = s->eff_rt_priority > TS(current)->eff_rt_priority;
        if (ready_class == running_class && ready_class == SCHED_CLASS_DEADLINE)
            preempt = task_dl_abs_deadline(t) < task_dl_abs_deadline(current);
        if (ready_class == running_class && ready_class == SCHED_CLASS_FAIR &&
            s->eff_policy != SCHED_POLICY_BATCH)
            preempt = s->fair_start_ns <= sched_cpus[cpu_index].virtual_ns &&
                      s->fair_finish_ns < TS(current)->fair_finish_ns;
        if (preempt)
            cpu_need_resched_locked(&sched_cpus[cpu_index], cpu_index, a);
    }
    pthread_cond_signal(&sched_cpus[cpu_index].work_cond);
    pthread_cond_broadcast(&sched_cond); /* waiters without a CPU binding */
    return 1;
}

static bool cpu_has_other_runnable(const sched_cpu_state_t *cpu,
                                   const thread_entry_t *self)
{
    if (cpu->dl.root)
        return true;
    if (!cpu->rt_throttled && rt_has_ready(cpu))
        return true;
    if (cpu->fair.root)
        return true;
    if (cpu->current && cpu->current != self)
        return true;
    return false;
}

/* Whether the running task's budget is exhausted once the live execution sample
 * is included. @live_ns is the unsettled checkpoint delta: guest execution plus
 * host syscall service since the last settlement. Adding it to the settled
 * counters counts every actual nanosecond exactly once; this check never
 * charges. sched_account_cpu_ns() remains the single charge point.
 */
static bool task_live_budget_expired_locked(const thread_entry_t *t,
                                            uint64_t live_ns)
{
    const sched_task_state_t *s = CTS(t);
    int cpu_index = s->current_cpu;

    if (s->state != SCHED_STATE_RUNNING || cpu_index < 0 ||
        cpu_index >= sched_ncpu)
        return false;
    sched_cpu_state_t *cpu = &sched_cpus[cpu_index];
    if (cpu->current != t)
        return false;


    /* Both live phases feed the same runtime budgets that settlement charges,
     * so the caller sums them into one pending delta.
     */
    switch (s->run_class) {
    case SCHED_CLASS_FAIR: {
        if (s->fair_slice_ns == 0 || s->fair_cpu != cpu_index)
            return false;
        uint64_t delta = sched_fair_virtual_delta_ns(live_ns, cpu->slope_q10);
        if (s->fair_used_ns < s->fair_slice_ns &&
            s->fair_slice_ns - s->fair_used_ns > delta)
            return false;
        return cpu_has_other_runnable(cpu, t);
    }
    case SCHED_CLASS_RT:
        if (cpu->rt_runtime_used_ns >= SCHED_RT_RUNTIME_NS ||
            live_ns >= SCHED_RT_RUNTIME_NS - cpu->rt_runtime_used_ns)
            return true;
        if (s->eff_policy == SCHED_POLICY_RR && live_ns >= s->rr_remaining_ns)
            return cpu_has_other_runnable(cpu, t);
        return false;
    case SCHED_CLASS_DEADLINE:
        if (s->policy != SCHED_POLICY_DEADLINE || s->pi_boosted)
            return false;
        return s->dl_runtime_left_ns <= dl_charge_ns(s, cpu, live_ns);
    default:
        return false;
    }
}

#define SCHED_LIVE_BATCH 16

/* Refresh each CPU's unsettled execution sample. The host callback may take
 * sched_lock itself for its slot lookup, so every call is made with the
 * scheduler lock released. A CPU's mount and settlement generation are captured
 * before its sample and rechecked after it, one lock section apiece per batch,
 * so an accepted sample carries no interval that a settlement already owns. A
 * sample the backend could not take coherently leaves this CPU's unsettled
 * delta at zero for the pass: budget checks then decide from the settled
 * counters and are re-evaluated at the next pass.
 */
static void sched_sample_live_ns(void)
{
    sched_live_sample_t (*live_fn)(const thread_entry_t *) = NULL;
    struct {
        thread_entry_t *cur;
        uint64_t seq;
    } batch[SCHED_LIVE_BATCH];
    sched_live_sample_t sample[SCHED_LIVE_BATCH];

    if (!sched_initialized)
        return;
    pthread_mutex_lock(&sched_lock);
    live_fn = sched_ops.live_sample;
    pthread_mutex_unlock(&sched_lock);
    if (!live_fn)
        return;

    for (int base = 0; base < sched_ncpu; base += SCHED_LIVE_BATCH) {
        int n = sched_ncpu - base;
        if (n > SCHED_LIVE_BATCH)
            n = SCHED_LIVE_BATCH;
        pthread_mutex_lock(&sched_lock);
        for (int j = 0; j < n; j++) {
            sched_cpu_state_t *cpu = &sched_cpus[base + j];
            thread_entry_t *cur = cpu->current;
            batch[j].cur = cur && CTS(cur)->run_class == SCHED_CLASS_FAIR &&
                                   !cpu_has_other_runnable(cpu, cur)
                               ? NULL
                               : cur;
            batch[j].seq = cpu->account_seq;
        }
        pthread_mutex_unlock(&sched_lock);

        for (int j = 0; j < n; j++) {
            thread_entry_t *cur = batch[j].cur;
            if (cur) {
                sample[j] = live_fn(cur);
            } else {
                sample[j].exec_ns = 0;
                sample[j].service_ns = 0;
                sample[j].generation = 0;
                sample[j].valid = false;
            }
        }

        pthread_mutex_lock(&sched_lock);
        for (int j = 0; j < n; j++) {
            sched_cpu_state_t *cpu = &sched_cpus[base + j];
            if (sample[j].valid && cpu->current == batch[j].cur &&
                cpu->account_seq == batch[j].seq) {
                cpu->live_sample_ns = sample[j].exec_ns;
                cpu->live_service_sample_ns = sample[j].service_ns;
                cpu->live_sample_seq = batch[j].seq;
            } else {
                /* A settlement landed while sampling, or the backend was in a
                 * transition: either way this sample would double count or
                 * under-report, so the pass runs on the settled counters.
                 */
                cpu->live_sample_ns = 0;
                cpu->live_service_sample_ns = 0;
                cpu->live_sample_seq = 0;
            }
        }
        pthread_mutex_unlock(&sched_lock);
    }
}

/* Unsettled execution charged to runtime budgets: guest execution plus host
 * syscall service since the last settlement, including the phase in progress at
 * the backend, saturating on overflow.
 */
static uint64_t live_pending_ns(const sched_cpu_state_t *cpu)
{
    if (cpu->live_sample_seq != cpu->account_seq)
        return 0;
    uint64_t exec = cpu->live_sample_ns;
    uint64_t service = cpu->live_service_sample_ns;
    return UINT64_MAX - exec < service ? UINT64_MAX : exec + service;
}

/* Accounting */

static void account_locked(thread_entry_t *t,
                           uint64_t ns,
                           bool service,
                           sched_actions_t *a)
{
    sched_task_state_t *s = TS(t);

    if (!t || ns == 0)
        return;

    s->runtime_ns += ns;
    if (service)
        s->runtime_sys_ns += ns;
    else
        s->runtime_user_ns += ns;
    s->banked_runtime_ns = UINT64_MAX - s->banked_runtime_ns < ns
                               ? UINT64_MAX
                               : s->banked_runtime_ns + ns;

    int cpu_index = s->current_cpu;
    if (cpu_index < 0)
        cpu_index = s->placement_cpu;
    if (cpu_index < 0 || cpu_index >= sched_ncpu)
        return;

    sched_cpu_state_t *cpu = &sched_cpus[cpu_index];
    if (s->current_cpu == cpu_index && cpu->current == t)
        cpu->account_seq++;
    int cls = s->current_cpu >= 0 ? s->run_class : task_eff_class(t);

    if (cls == SCHED_CLASS_FAIR) {
        if (s->fair_slice_ns == 0 || s->fair_cpu != cpu_index)
            return;
        uint64_t delta = sched_fair_virtual_delta_ns(ns, cpu->slope_q10);
        cpu->virtual_ns += delta;
        s->fair_used_ns += delta;
        if (s->fair_used_ns >= s->fair_slice_ns &&
            cpu_has_other_runnable(cpu, t))
            cpu_need_resched_locked(cpu, cpu_index, a);
    } else if (cls == SCHED_CLASS_RT) {
        cpu->rt_runtime_used_ns += ns;
        if (cpu->rt_runtime_used_ns >= SCHED_RT_RUNTIME_NS) {
            cpu->rt_throttled = true;
            cpu_need_resched_locked(cpu, cpu_index, a);
            a->timer = true;
        }
        if (s->eff_policy == SCHED_POLICY_RR) {
            if (s->rr_remaining_ns > ns) {
                s->rr_remaining_ns -= ns;
            } else {
                s->rr_remaining_ns = 0;
                if (cpu_has_other_runnable(cpu, t))
                    cpu_need_resched_locked(cpu, cpu_index, a);
            }
        }
    } else if (cls == SCHED_CLASS_DEADLINE) {
        dl_charge_locked(t, cpu, cpu_index, ns, a);
    }
}

/* Selection */

static thread_entry_t *pick_locked(sched_cpu_state_t *cpu,
                                   int cpu_index,
                                   uint64_t now,
                                   sched_actions_t *a)
{
    thread_entry_t *next = NULL;
    int cls = SCHED_CLASS_NONE;

    if (cpu->dl.root) {
        sched_tree_node_t *n = sched_tree_first(&cpu->dl);
        if (n) {
            next = task_from_node(n);
            cls = SCHED_CLASS_DEADLINE;
        }
    }

    if (!next && !cpu->rt_throttled && rt_has_ready(cpu)) {
        int prio = rt_highest_prio(cpu);
        if (prio >= 0 && cpu->rt_head[prio]) {
            next = cpu->rt_head[prio];
            cls = SCHED_CLASS_RT;
        }
    }

    if (!next && cpu->fair.root) {
        if (!sched_tree_has_eligible(&cpu->fair, cpu->virtual_ns)) {
            sched_tree_node_t *first = sched_tree_first(&cpu->fair);
            if (first && first->key_time > cpu->virtual_ns) {
                cpu->virtual_ns = first->key_time;
                cpu->snap_count++;
            }
        }
        sched_tree_node_t *n =
            sched_tree_pick_eligible(&cpu->fair, cpu->virtual_ns);
        if (!n) {
            sched_tree_node_t *first = sched_tree_first(&cpu->fair);
            if (first) {
                if (first->key_time > cpu->virtual_ns) {
                    cpu->virtual_ns = first->key_time;
                    cpu->snap_count++;
                }
                n = sched_tree_pick_eligible(&cpu->fair, cpu->virtual_ns);
            }
        }
        if (n) {
            next = task_from_node(n);
            cls = SCHED_CLASS_FAIR;
        }
    }

    if (!next)
        return NULL;

    sched_task_state_t *s = TS(next);
    switch (cls) {
    case SCHED_CLASS_FAIR:
        sched_tree_remove(&cpu->fair, &s->node);
        break;
    case SCHED_CLASS_RT:
        rt_remove(cpu, next, s->eff_rt_priority);
        break;
    case SCHED_CLASS_DEADLINE:
        sched_tree_remove(&cpu->dl, &s->node);
        break;
    default:
        break;
    }

    s->on_rq = false;
    s->queued_class = SCHED_CLASS_NONE;
    s->queued_cpu = -1;
    s->state = SCHED_STATE_RUNNING;
    s->current_cpu = cpu_index;
    s->run_class = cls;
    s->run_start_ns = now;
    s->resched_requested = false;
    s->block_requested = false;

    cpu->current = next;
    cpu->current_class = cls;
    cpu->need_resched = false;
    cpu->live_sample_ns = 0;
    cpu->live_service_sample_ns = 0;
    cpu->live_sample_seq = 0;
    s->placement_cpu = cpu_index;
    a->timer = true;

    if (cls == SCHED_CLASS_FAIR) {
        fair_note_change_locked(cpu);

        /* The CPU timeline may pass this activation while it waits in the
         * queue. Do not mount a task with an already exhausted budget.
         */
        fair_activation_prepare_locked(next, cpu, cpu_index);
    }

    return next;
}

static bool steal_affinity_allows(const sched_tree_node_t *node, void *arg)
{
    const thread_entry_t *t = task_from_node((sched_tree_node_t *) node);
    int cpu = *(const int *) arg;
    return affinity_allows(t, cpu) &&
           atomic_load_explicit(&CTS(t)->stop_reasons, memory_order_relaxed) ==
               0;
}

/* Zircon steal_work: search remote queues in CPU-search order, snap the source
 * eligibility timeline, and take the earliest eligible FAIR task. Linux RT
 * order and DL admission remain local; neither queue is stolen.
 */
static bool steal_fair_work_locked(int target, uint64_t now, sched_actions_t *a)
{
    for (int offset = 1; offset < sched_ncpu; offset++) {
        int source = (target + offset) % sched_ncpu;
        sched_cpu_state_t *cpu = &sched_cpus[source];
        sched_tree_node_t *front = sched_tree_first(&cpu->fair);
        if (!front)
            continue;
        if (cpu->virtual_ns < front->key_time) {
            cpu->virtual_ns = front->key_time;
            cpu->snap_count++;
        }
        sched_tree_node_t *node = sched_tree_pick_eligible_if(
            &cpu->fair, cpu->virtual_ns, steal_affinity_allows, &target);
        if (!node)
            continue;
        thread_entry_t *t = task_from_node(node);
        task_remove_from_queue_locked(t);
        TS(t)->placement_cpu = target;
        return task_insert_into_queue_locked(t, target, now, a);
    }
    return false;
}

/* Public: host services and domain lifecycle */

void sched_set_host_ops(const sched_host_ops_t *ops)
{
    pthread_mutex_lock(&sched_lock);
    if (ops)
        sched_ops = *ops;
    else
        memset(&sched_ops, 0, sizeof(sched_ops));
    pthread_mutex_unlock(&sched_lock);
}

void sched_set_priority_changed_hook(void (*fn)(thread_entry_t *t))
{
    pthread_mutex_lock(&sched_lock);
    sched_prio_changed_hook = fn;
    pthread_mutex_unlock(&sched_lock);
}

int sched_host_ncpu(void)
{
    if (sched_host_ncpu_cache > 0)
        return sched_host_ncpu_cache;

    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1)
        n = 1;
    if (n > SCHED_MAX_CPUS)
        n = SCHED_MAX_CPUS;
    sched_host_ncpu_cache = (int) n;
    return sched_host_ncpu_cache;
}

int sched_domain_init(int ncpu)
{
    int want = ncpu > 0 ? ncpu : sched_host_ncpu();

    if (want < 1)
        return -SCHED_ERR_EINVAL;
    if (want > sched_host_ncpu())
        want = sched_host_ncpu();
    if (want > SCHED_MAX_CPUS)
        want = SCHED_MAX_CPUS;

    pthread_mutex_lock(&sched_lock);
    if (sched_initialized) {
        int rc = (ncpu <= 0 || sched_ncpu == want) ? 0 : -SCHED_ERR_EINVAL;
        pthread_mutex_unlock(&sched_lock);
        return rc;
    }

    sched_cpus = calloc((size_t) want, sizeof(*sched_cpus));
    if (!sched_cpus) {
        pthread_mutex_unlock(&sched_lock);
        return -SCHED_ERR_EBUSY;
    }
    sched_ncpu = want;
    sched_dl_admitted_bw = 0;
    sched_dl_head = NULL;
    sched_dl_tail = NULL;
    sched_shutdown_flag = false;
    sched_frozen = false;
    for (int i = 0; i < want; i++) {
        int err = pthread_cond_init(&sched_cpus[i].work_cond, NULL);
        if (err != 0) {
            for (int j = 0; j < i; j++)
                pthread_cond_destroy(&sched_cpus[j].work_cond);
            free(sched_cpus);
            sched_cpus = NULL;
            pthread_mutex_unlock(&sched_lock);
            return -SCHED_ERR_EBUSY;
        }
        sched_tree_init(&sched_cpus[i].fair);
        sched_tree_init(&sched_cpus[i].dl);
        sched_cpus[i].slope_q10 = SCHED_FAIR_SLOPE_ONE;
        sched_cpus[i].rt_period_start_ns = sched_now_ns();
        sched_cpus[i].current_class = SCHED_CLASS_NONE;
    }
    sched_initialized = true;
    pthread_mutex_unlock(&sched_lock);
    return 0;
}

void sched_init(void)
{
    if (sched_domain_init(0) != 0) {
        /* Keep a minimal single-CPU domain rather than returning without a
         * scheduler; attribution failures surface through allocation only.
         */
        (void) sched_domain_init(1);
    }
}

int sched_domain_ncpu(void)
{
    if (!sched_initialized)
        sched_init();
    return sched_ncpu;
}

/* Public: task lifecycle and execution protocol */

static void sched_init_defaults_locked(thread_entry_t *t)
{
    sched_task_state_t *s = TS(t);
    s->expected_runtime_ns = SCHED_MIN_FAIR_CAPACITY_NS;
    s->banked_runtime_ns = 0;

    s->state = SCHED_STATE_NEW;
    s->queued_class = SCHED_CLASS_NONE;
    s->queued_cpu = -1;
    s->current_cpu = -1;
    s->placement_cpu = -1;
    s->on_rq = false;
    s->attrs_initialized = true;
    s->wake_pending = false;
    s->block_requested = false;
    s->resched_requested = false;
    atomic_store_explicit(&s->stop_reasons, 0, memory_order_release);
    s->stop_requested = false;
    s->stop_blocked = false;
    s->stop_started_ns = 0;

    s->policy = SCHED_POLICY_OTHER;
    s->nice = 0;
    s->rt_priority = 0;
    s->flags = 0;
    s->fair_slice_custom_ns = 0;
    s->dl_runtime_ns = 0;
    s->dl_deadline_ns = 0;
    s->dl_period_ns = 0;

    s->eff_policy = SCHED_POLICY_OTHER;
    s->eff_nice = 0;
    s->eff_rt_priority = 0;
    s->eff_weight = sched_fair_weight_from_nice(0);
    s->eff_dl_abs_deadline_ns = 0;
    s->eff_dl_runtime_left_ns = 0;
    s->eff_dl_period_ns = 0;
    s->pi_boosted = false;
    s->boost_policy = SCHED_POLICY_OTHER;
    s->boost_prio = 0;
    s->boost_dl_abs_deadline_ns = 0;
    s->boost_dl_runtime_left_ns = 0;
    s->boost_dl_period_ns = 0;

    s->fair_start_ns = 0;
    s->fair_finish_ns = 0;
    s->fair_slice_ns = 0;
    s->fair_used_ns = 0;
    s->fair_cpu = -1;

    s->rr_remaining_ns = 0;
    s->run_class = SCHED_CLASS_NONE;

    s->dl_runtime_left_ns = 0;
    s->dl_abs_deadline_ns = 0;
    s->dl_bw_q20 = 0;
    s->dl_admitted = false;
    s->dl_bw_counted = false;
    s->dl_overrun_reported = false;
    s->dl_throttled = false;
    s->dl_yielded = false;
    s->dl_non_contending = false;
    s->dl_inactive_deadline_ns = 0;
    s->dl_bw_cpu = -1;
    s->dl_prev = NULL;
    s->dl_next = NULL;

    s->rt_next = NULL;
    s->rt_prev = NULL;
    sched_tree_init_node(&s->node);
    affinity_set_full(s);
}

void sched_attach_thread(thread_entry_t *t)
{
    sched_actions_t a;

    if (!t)
        return;
    if (!sched_initialized)
        sched_init();
    actions_init(&a);

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    if (s->state == SCHED_STATE_RUNNING && s->current_cpu >= 0) {
        pthread_mutex_unlock(&sched_lock);
        return;
    }
    if (!s->attrs_initialized)
        sched_init_defaults_locked(t);

    int cpu_index = s->placement_cpu;
    if (cpu_index < 0 || cpu_index >= sched_ncpu ||
        !affinity_allows(t, cpu_index))
        cpu_index = affinity_allows(t, 0) ? 0 : pick_cpu_locked(t);
    if (cpu_index < 0)
        cpu_index = 0;

    sched_cpu_state_t *cpu = &sched_cpus[cpu_index];
    cpu->total_expected_runtime_ns += s->expected_runtime_ns;
    s->state = SCHED_STATE_RUNNING;
    s->current_cpu = cpu_index;
    s->placement_cpu = cpu_index;
    s->run_class = task_eff_class(t);
    s->run_start_ns = sched_now_ns();
    s->resched_requested = false;
    s->block_requested = false;
    cpu->current = t;
    cpu->current_class = s->run_class;
    cpu->need_resched = false;
    if (s->run_class == SCHED_CLASS_FAIR) {
        cpu->weight_total += s->eff_weight;
        fair_note_change_locked(cpu);
    }
    if (s->policy == SCHED_POLICY_DEADLINE)
        dl_activate_bw_locked(t, cpu_index);
    a.timer = true;
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

void sched_enqueue_thread(thread_entry_t *t)
{
    sched_actions_t a;
    uint64_t now = sched_now_ns();

    if (!t)
        return;
    if (!sched_initialized)
        sched_init();
    actions_init(&a);

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    if (s->state == SCHED_STATE_DEAD || s->state == SCHED_STATE_RUNNING ||
        s->on_rq) {
        pthread_mutex_unlock(&sched_lock);
        return;
    }
    if (!s->attrs_initialized)
        sched_init_defaults_locked(t);
    s->state = SCHED_STATE_READY;
    s->wake_pending = false;
    enqueue_ready_locked(t, now, &a);
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

void sched_detach_thread(thread_entry_t *t)
{
    sched_actions_t a;

    if (!t)
        return;
    if (!sched_initialized)
        return;
    actions_init(&a);

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    if (s->on_rq)
        task_remove_from_queue_locked(t);

    if (s->current_cpu >= 0 && s->current_cpu < sched_ncpu) {
        sched_cpu_state_t *cpu = &sched_cpus[s->current_cpu];
        if (cpu->current == t) {
            cpu->total_expected_runtime_ns -= s->expected_runtime_ns;
            if (s->run_class == SCHED_CLASS_FAIR) {
                if (cpu->weight_total >= s->eff_weight)
                    cpu->weight_total -= s->eff_weight;
                else
                    cpu->weight_total = 0;
            }
            cpu->current = NULL;
            cpu->current_class = SCHED_CLASS_NONE;
            fair_note_change_locked(cpu);
        }
    }
    dl_forget_locked(t);
    s->state = SCHED_STATE_DEAD;
    s->current_cpu = -1;
    s->run_class = SCHED_CLASS_NONE;
    s->run_start_ns = 0;
    s->placement_cpu = -1;
    s->wake_pending = false;
    s->block_requested = false;
    s->resched_requested = false;
    atomic_store_explicit(&s->stop_reasons, 0, memory_order_release);
    s->stop_requested = false;
    s->stop_blocked = false;
    s->stop_started_ns = 0;
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

bool sched_task_claim_stopped(thread_entry_t *t)
{
    sched_actions_t a;
    bool claimed = false;

    if (!t)
        return false;
    if (!sched_initialized)
        sched_init();
    actions_init(&a);

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    if (s->state == SCHED_STATE_RUNNING) {
        pthread_mutex_unlock(&sched_lock);
        return false;
    }
    if (s->state == SCHED_STATE_DEAD) {
        pthread_mutex_unlock(&sched_lock);
        return true;
    }
    if (s->on_rq)
        task_remove_from_queue_locked(t);
    dl_forget_locked(t);
    s->state = SCHED_STATE_DEAD;
    s->current_cpu = -1;
    s->run_class = SCHED_CLASS_NONE;
    s->run_start_ns = 0;
    s->placement_cpu = -1;
    s->wake_pending = false;
    s->block_requested = false;
    s->resched_requested = false;
    atomic_store_explicit(&s->stop_reasons, 0, memory_order_release);
    s->stop_requested = false;
    s->stop_blocked = false;
    s->stop_started_ns = 0;
    claimed = true;
    a.timer = true;
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
    return claimed;
}

void sched_unblock(thread_entry_t *t)
{
    sched_actions_t a;
    uint64_t now = sched_now_ns();

    if (!t)
        return;
    if (!sched_initialized)
        sched_init();
    actions_init(&a);

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    if (s->state == SCHED_STATE_RUNNING) {
        /* Completion before the block commits: the put must publish READY
         * instead of BLOCKED.
         */
        s->wake_pending = true;
    } else if (s->state == SCHED_STATE_BLOCKED) {
        s->state = SCHED_STATE_READY;
        s->wake_pending = false;
        place_fair_wakeup_locked(t);
        enqueue_ready_locked(t, now, &a);
    } else if (s->state == SCHED_STATE_NEW) {
        s->state = SCHED_STATE_READY;
        enqueue_ready_locked(t, now, &a);
    }
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

void sched_block_current(void)
{
    sched_actions_t a;

    if (!sched_initialized)
        return;
    actions_init(&a);

    pthread_mutex_lock(&sched_lock);
    thread_entry_t *t = current_thread;
    if (t) {
        TS(t)->block_requested = true;
        TS(t)->resched_requested = true;
        if (TS(t)->current_cpu >= 0)
            cpu_need_resched_locked(&sched_cpus[TS(t)->current_cpu],
                                    TS(t)->current_cpu, &a);
    }
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

void sched_wake_stop(thread_entry_t *t)
{
    sched_actions_t a;
    uint64_t now = sched_now_ns();

    if (!t)
        return;
    if (!sched_initialized)
        sched_init();
    actions_init(&a);

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    if (!exec_park_active_load(t) || exec_park_kind_load(t) != PARK_KIND_STOP ||
        atomic_load_explicit(&s->stop_reasons, memory_order_acquire) != 0) {
        pthread_mutex_unlock(&sched_lock);
        return;
    }
    exec_park_active_store(t, false);
    exec_park_result_pending_store(t, false);
    exec_park_reissue_store(t, false);
    exec_park_kind_store(t, PARK_KIND_NONE);
    exec_park_deadline_ns_store(t, 0);
    if (s->state == SCHED_STATE_RUNNING) {
        s->wake_pending = true;
    } else if (s->state == SCHED_STATE_BLOCKED) {
        s->stop_blocked = false;
        s->state = SCHED_STATE_READY;
        place_fair_wakeup_locked(t);
        enqueue_ready_locked(t, now, &a);
    }
    a.timer = true;
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

void sched_stop_task(thread_entry_t *t, unsigned reasons)
{
    sched_actions_t a;
    uint64_t now;

    if (!t || reasons == 0 || !sched_initialized)
        return;
    actions_init(&a);
    now = sched_now_ns();

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    unsigned old = atomic_load_explicit(&s->stop_reasons, memory_order_acquire);
    if (old == 0)
        s->stop_started_ns = now;
    atomic_store_explicit(&s->stop_reasons, old | reasons,
                          memory_order_release);

    if (s->state == SCHED_STATE_RUNNING) {
        s->stop_requested = true;
        s->resched_requested = true;
        if (s->current_cpu >= 0 && s->current_cpu < sched_ncpu)
            cpu_need_resched_locked(&sched_cpus[s->current_cpu], s->current_cpu,
                                    &a);
    } else if (s->state == SCHED_STATE_READY) {
        if (s->on_rq)
            task_remove_from_queue_locked(t);
        s->state = SCHED_STATE_BLOCKED;
        s->stop_blocked = true;
        s->wake_pending = false;
        if (s->placement_cpu < 0 || s->placement_cpu >= sched_ncpu ||
            !affinity_allows(t, s->placement_cpu))
            s->placement_cpu = pick_cpu_locked(t);
        exec_park_active_store(t, true);
        exec_park_kind_store(t, PARK_KIND_STOP);
        exec_park_result_pending_store(t, false);
        exec_park_reissue_store(t, false);
        exec_park_deadline_ns_store(t, 0);
        if (s->policy == SCHED_POLICY_DEADLINE && !s->pi_boosted)
            dl_block_bw_locked(t, now);
        a.timer = true;
    }
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

void sched_resume_task(thread_entry_t *t, unsigned reasons)
{
    sched_actions_t a;
    uint64_t now;

    if (!t || !sched_initialized)
        return;
    actions_init(&a);
    now = sched_now_ns();

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    unsigned old = atomic_load_explicit(&s->stop_reasons, memory_order_acquire);
    atomic_store_explicit(&s->stop_reasons, old & ~reasons,
                          memory_order_release);
    if ((old & ~reasons) != 0) {
        pthread_mutex_unlock(&sched_lock);
        return;
    }

    s->stop_started_ns = 0;
    s->stop_requested = false;
    if (s->state == SCHED_STATE_RUNNING) {
        /* If the stop request was already consumed, the pending put must
         * publish READY instead of BLOCKED. A CONT that arrives before the safe
         * point simply cancels the request.
         */
        if (s->stop_blocked) {
            s->wake_pending = true;
            s->stop_blocked = false;
        }
        pthread_mutex_unlock(&sched_lock);
        return;
    }

    if (exec_park_active_load(t) && exec_park_kind_load(t) == PARK_KIND_STOP) {
        exec_park_active_store(t, false);
        exec_park_kind_store(t, PARK_KIND_NONE);
        exec_park_result_pending_store(t, false);
        exec_park_reissue_store(t, false);
        exec_park_deadline_ns_store(t, 0);
        s->stop_blocked = true;
    }

    if (s->state == SCHED_STATE_BLOCKED && !exec_park_active_load(t) &&
        (s->stop_blocked || s->wake_pending)) {
        s->state = SCHED_STATE_READY;
        s->stop_blocked = false;
        s->wake_pending = false;
        place_fair_wakeup_locked(t);
        enqueue_ready_locked(t, now, &a);
    }
    a.timer = true;
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

bool sched_take_stop_request(thread_entry_t *t, unsigned *reasons)
{
    bool requested = false;

    if (!t || !sched_initialized)
        return false;
    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    if (s->stop_requested) {
        s->stop_requested = false;
        s->stop_blocked = true;
        requested = true;
        if (reasons)
            *reasons =
                atomic_load_explicit(&s->stop_reasons, memory_order_acquire);
    }
    pthread_mutex_unlock(&sched_lock);
    return requested;
}

unsigned sched_task_stop_reasons(const thread_entry_t *t)
{
    if (!t)
        return 0;
    return atomic_load_explicit((_Atomic uint32_t *) &CTS(t)->stop_reasons,
                                memory_order_acquire);
}

bool sched_task_group_stopped(const thread_entry_t *t)
{
    return (sched_task_stop_reasons(t) & SCHED_STOP_GROUP) != 0;
}

bool sched_task_trace_stopped(const thread_entry_t *t)
{
    return (sched_task_stop_reasons(t) & SCHED_STOP_PTRACE) != 0;
}

void sched_task_set_group_stopped(thread_entry_t *t, bool stopped)
{
    if (stopped)
        sched_stop_task(t, SCHED_STOP_GROUP);
    else
        sched_resume_task(t, SCHED_STOP_GROUP);
}

void sched_task_set_trace_stopped(thread_entry_t *t, bool stopped)
{
    if (stopped)
        sched_stop_task(t, SCHED_STOP_PTRACE);
    else
        sched_resume_task(t, SCHED_STOP_PTRACE);
}

int sched_task_run_state(const thread_entry_t *t)
{
    if (!t)
        return SCHED_STATE_DEAD;
    if (!sched_initialized)
        return SCHED_STATE_NEW;
    pthread_mutex_lock(&sched_lock);
    int state = CTS(t)->state;
    pthread_mutex_unlock(&sched_lock);
    return state;
}

bool sched_task_is_running(const thread_entry_t *t)
{
    return sched_task_run_state(t) == SCHED_STATE_RUNNING;
}

void sched_put_current(thread_entry_t *t, sched_put_disposition_t how)
{
    sched_actions_t a;
    uint64_t now;

    if (!t)
        return;
    if (!sched_initialized)
        return;
    now = sched_now_ns();
    actions_init(&a);

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    int cpu_index = s->current_cpu;
    if (how == SCHED_PUT_READY && !s->yield_requested)
        how = SCHED_PUT_PREEMPTED;
    s->yield_requested = false;

    if (cpu_index < 0 || cpu_index >= sched_ncpu) {
        if (how == SCHED_PUT_DEAD) {
            if (s->on_rq)
                task_remove_from_queue_locked(t);
            dl_forget_locked(t);
            s->state = SCHED_STATE_DEAD;
            s->run_class = SCHED_CLASS_NONE;
            atomic_store_explicit(&s->stop_reasons, 0, memory_order_release);
            s->stop_requested = false;
            s->stop_blocked = false;
            s->stop_started_ns = 0;
            s->wake_pending = false;
        }
        a.timer = true;
        pthread_mutex_unlock(&sched_lock);
        sched_dispatch(&a);
        return;
    }

    sched_cpu_state_t *cpu = &sched_cpus[cpu_index];
    int old_class = s->run_class;
    uint32_t old_weight = old_class == SCHED_CLASS_FAIR ? s->eff_weight : 0;

    /* An RR task whose quantum is gone rotates to the tail even when the
     * backend reports an involuntary preemption. A higher-priority preemption
     * keeps its head position and its remaining quantum.
     */
    bool rr_quantum_expired = old_class == SCHED_CLASS_RT &&
                              s->eff_policy == SCHED_POLICY_RR &&
                              s->rr_remaining_ns == 0;
    bool fair_expired =
        old_class == SCHED_CLASS_FAIR && s->fair_used_ns >= s->fair_slice_ns;
    bool inactive =
        how == SCHED_PUT_BLOCKED || how == SCHED_PUT_DEAD ||
        atomic_load_explicit(&s->stop_reasons, memory_order_relaxed);
    cpu->total_expected_runtime_ns -= s->expected_runtime_ns;
    if (fair_expired || rr_quantum_expired || inactive) {
        /* Zircon peak_decay_delta: beta=1 for peaks, alpha=1/4 for decay. */
        uint64_t sample = s->banked_runtime_ns;
        if (sample >= s->expected_runtime_ns)
            s->expected_runtime_ns = sample;
        else
            s->expected_runtime_ns -= (s->expected_runtime_ns - sample) / 4;
        s->banked_runtime_ns = 0;
    }

    cpu->current = NULL;
    cpu->current_class = SCHED_CLASS_NONE;
    cpu->need_resched = false;
    cpu->live_sample_ns = 0;
    cpu->live_service_sample_ns = 0;
    cpu->live_sample_seq = 0;
    s->current_cpu = -1;
    s->run_class = SCHED_CLASS_NONE;
    s->run_start_ns = 0;

    if (old_class == SCHED_CLASS_FAIR) {
        if (cpu->weight_total >= old_weight)
            cpu->weight_total -= old_weight;
        else
            cpu->weight_total = 0;
        fair_note_change_locked(cpu);
    }

    if (how == SCHED_PUT_DEAD) {
        if (s->on_rq)
            task_remove_from_queue_locked(t);
        dl_forget_locked(t);
        s->state = SCHED_STATE_DEAD;
        s->placement_cpu = -1;
        s->wake_pending = false;
        s->block_requested = false;
        s->resched_requested = false;
        atomic_store_explicit(&s->stop_reasons, 0, memory_order_release);
        s->stop_requested = false;
        s->stop_blocked = false;
        s->stop_started_ns = 0;
        a.timer = true;
        pthread_mutex_unlock(&sched_lock);
        sched_dispatch(&a);
        return;
    }

    if (atomic_load_explicit(&s->stop_reasons, memory_order_acquire) != 0) {
        /* The task must not become runnable while any stop reason is set. A
         * real park keeps its own wake bookkeeping; a stop-only park is
         * published as PARK_KIND_STOP so CONT can resume it without an X0 or
         * instruction-reissue injection.
         */
        bool real_park = exec_park_active_load(t) &&
                         exec_park_kind_load(t) != PARK_KIND_STOP;
        s->state = SCHED_STATE_BLOCKED;
        s->block_requested = false;
        s->resched_requested = false;

        /* A block wins over a pending yield: retain the reservation rather than
         * carrying a stale yield flag into the next run.
         */
        s->dl_yielded = false;
        if (!real_park) {
            s->stop_blocked = true;
            s->wake_pending = false;
            exec_park_active_store(t, true);
            exec_park_kind_store(t, PARK_KIND_STOP);
            exec_park_result_pending_store(t, false);
            exec_park_reissue_store(t, false);
            exec_park_deadline_ns_store(t, 0);
        }
        if (s->placement_cpu < 0 || s->placement_cpu >= sched_ncpu ||
            !affinity_allows(t, s->placement_cpu))
            s->placement_cpu = pick_cpu_locked(t);
        else
            s->placement_cpu = cpu_index;
        if (s->policy == SCHED_POLICY_DEADLINE && !s->pi_boosted)
            dl_block_bw_locked(t, now);
        a.timer = true;
        pthread_mutex_unlock(&sched_lock);
        sched_dispatch(&a);
        return;
    }

    if (how == SCHED_PUT_BLOCKED && !s->wake_pending &&
        s->state != SCHED_STATE_READY) {
        s->state = SCHED_STATE_BLOCKED;
        s->block_requested = false;
        s->resched_requested = false;
        s->dl_yielded = false;
        if (s->placement_cpu < 0 || s->placement_cpu >= sched_ncpu ||
            !affinity_allows(t, s->placement_cpu))
            s->placement_cpu = pick_cpu_locked(t);
        else
            s->placement_cpu = cpu_index;
        if (s->policy == SCHED_POLICY_DEADLINE && !s->pi_boosted)
            dl_block_bw_locked(t, now);
        a.timer = true;
        pthread_mutex_unlock(&sched_lock);
        sched_dispatch(&a);
        return;
    }

    /* READY, or BLOCKED with a wake that completed first. */
    bool waking = s->wake_pending;
    s->wake_pending = false;
    s->state = SCHED_STATE_READY;
    s->block_requested = false;
    s->resched_requested = false;

    if (s->policy == SCHED_POLICY_DEADLINE && !s->pi_boosted && s->dl_yielded) {
        /* sched_yield() on a deadline task forces its runtime to zero; the
         * replenishment timer starts the next reservation.
         */
        s->dl_runtime_left_ns = 0;
        s->dl_throttled = true;
        s->placement_cpu =
            affinity_allows(t, cpu_index) ? cpu_index : pick_cpu_locked(t);
        a.timer = true;
        pthread_mutex_unlock(&sched_lock);
        sched_dispatch(&a);
        return;
    }
    s->dl_yielded = false;

    if (s->dl_throttled && s->policy == SCHED_POLICY_DEADLINE &&
        !s->pi_boosted) {
        /* Runnable but bandwidth-depleted until the replenishment timer. */
        s->placement_cpu =
            affinity_allows(t, cpu_index) ? cpu_index : pick_cpu_locked(t);
        a.timer = true;
        pthread_mutex_unlock(&sched_lock);
        sched_dispatch(&a);
        return;
    }

    int target = affinity_allows(t, cpu_index) ? cpu_index : pick_cpu_locked(t);
    if (target < 0)
        target = cpu_index;
    s->placement_cpu = target;
    if (waking)
        place_fair_wakeup_locked(t);
    enqueue_ready_locked(t, now, &a);
    if (how == SCHED_PUT_PREEMPTED && !rr_quantum_expired)
        rt_requeue_head_locked(t);
    a.timer = true;
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

thread_entry_t *sched_worker_pick(int cpu_index)
{
    sched_actions_t a;
    uint64_t now;

    if (!sched_initialized)
        sched_init();
    actions_init(&a);
    now = sched_now_ns();

    pthread_mutex_lock(&sched_lock);
    if (cpu_index < 0 || cpu_index >= sched_ncpu) {
        pthread_mutex_unlock(&sched_lock);
        return NULL;
    }
    sched_cpu_state_t *cpu = &sched_cpus[cpu_index];
    if (cpu->current) {
        thread_entry_t *t = cpu->current;
        pthread_mutex_unlock(&sched_lock);
        return t;
    }
    if (sched_frozen || sched_shutdown_flag) {
        pthread_mutex_unlock(&sched_lock);
        return NULL;
    }
    thread_entry_t *next = pick_locked(cpu, cpu_index, now, &a);
    if (!next && steal_fair_work_locked(cpu_index, now, &a))
        next = pick_locked(cpu, cpu_index, now, &a);
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
    return next;
}

void sched_worker_wait(int cpu_index)
{
    if (!sched_initialized)
        sched_init();

    pthread_mutex_lock(&sched_lock);
    for (;;) {
        if (sched_shutdown_flag)
            break;
        if (sched_frozen) {
            pthread_cond_wait(&sched_cond, &sched_lock);
            continue;
        }
        bool ready = false;
        if (cpu_index >= 0 && cpu_index < sched_ncpu) {
            sched_cpu_state_t *cpu = &sched_cpus[cpu_index];
            ready = cpu->fair.root || cpu->dl.root ||
                    (!cpu->rt_throttled && rt_has_ready(cpu));
        } else {
            for (int i = 0; i < sched_ncpu && !ready; i++) {
                sched_cpu_state_t *cpu = &sched_cpus[i];
                ready = cpu->fair.root || cpu->dl.root ||
                        (!cpu->rt_throttled && rt_has_ready(cpu));
            }
        }
        if (ready)
            break;
        pthread_cond_t *cond = cpu_index >= 0 && cpu_index < sched_ncpu
                                   ? &sched_cpus[cpu_index].work_cond
                                   : &sched_cond;
        pthread_cond_wait(cond, &sched_lock);
    }
    pthread_mutex_unlock(&sched_lock);
}

void sched_account_cpu_ns(thread_entry_t *t, uint64_t ns)
{
    sched_actions_t a;

    if (!t || ns == 0 || !sched_initialized)
        return;
    actions_init(&a);
    pthread_mutex_lock(&sched_lock);
    account_locked(t, ns, false, &a);
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

void sched_account_service_ns(thread_entry_t *t, uint64_t ns)
{
    sched_actions_t a;

    if (!t || ns == 0 || !sched_initialized)
        return;
    actions_init(&a);
    pthread_mutex_lock(&sched_lock);
    account_locked(t, ns, true, &a);
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

void sched_account_interval_ns(thread_entry_t *t,
                               uint64_t exec_ns,
                               uint64_t service_ns)
{
    sched_actions_t a;

    if (!t || (exec_ns == 0 && service_ns == 0) || !sched_initialized)
        return;
    actions_init(&a);
    pthread_mutex_lock(&sched_lock);
    account_locked(t, exec_ns, false, &a);
    account_locked(t, service_ns, true, &a);
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

/* Reschedule requests */

void sched_yield_current(void)
{
    sched_actions_t a;
    thread_entry_t *t = current_thread;

    if (!t || !sched_initialized)
        return;
    actions_init(&a);
    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    s->yield_requested = true;
    if (s->state == SCHED_STATE_RUNNING && s->policy == SCHED_POLICY_DEADLINE &&
        !s->pi_boosted && s->dl_admitted)
        s->dl_yielded = true;
    s->resched_requested = true;
    int cpu_index = s->current_cpu;
    if (cpu_index >= 0 && cpu_index < sched_ncpu)
        cpu_need_resched_locked(&sched_cpus[cpu_index], cpu_index, &a);
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

void sched_request_resched(thread_entry_t *t)
{
    sched_actions_t a;

    if (!t || !sched_initialized)
        return;
    actions_init(&a);
    pthread_mutex_lock(&sched_lock);
    TS(t)->resched_requested = true;
    int cpu_index = TS(t)->current_cpu;
    if (cpu_index >= 0 && cpu_index < sched_ncpu)
        cpu_need_resched_locked(&sched_cpus[cpu_index], cpu_index, &a);
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

bool sched_resched_requested(void)
{
    return sched_take_resched(current_thread);
}

bool sched_take_resched(thread_entry_t *t)
{
    sched_live_sample_t (*live_fn)(const thread_entry_t *) = NULL;
    int sample_cpu = -1;
    uint64_t sample_seq = 0;
    bool requested;

    if (!t || !sched_initialized)
        return false;

    pthread_mutex_lock(&sched_lock);
    requested = TS(t)->resched_requested || TS(t)->block_requested;
    TS(t)->resched_requested = false;
    sample_cpu = TS(t)->current_cpu;
    if (sample_cpu >= 0 && sample_cpu < sched_ncpu) {
        if (sched_cpus[sample_cpu].need_resched)
            requested = true;
        sched_cpus[sample_cpu].need_resched = false;
        sample_seq = sched_cpus[sample_cpu].account_seq;
        live_fn = sched_ops.live_sample;

        /* A solo fair task cannot exhaust a budget against another runnable
         * task. Enqueue publishes a reschedule request under this lock.
         */
        if (TS(t)->run_class == SCHED_CLASS_FAIR &&
            !cpu_has_other_runnable(&sched_cpus[sample_cpu], t))
            sample_cpu = -1;
    } else {
        sample_cpu = -1;
    }
    pthread_mutex_unlock(&sched_lock);

    /* A pending request already answers this safe point; the unsettled sample
     * cannot withdraw it, and only this path needs one.
     */
    if (requested || sample_cpu < 0)
        return requested;

    /* The host callback may take sched_lock for its slot lookup, so it is
     * always called with the scheduler lock released.
     */
    sched_live_sample_t sample = {0};
    if (live_fn)
        sample = live_fn(t);

    pthread_mutex_lock(&sched_lock);

    /* Re-check the unsettled budget at the owner safe point as well: a remote
     * timer sample may be unavailable or late, and this decision must be made
     * before the next guest entry. A settlement that raced the sample already
     * owns that interval, so the sample is dropped then.
     */
    bool live_valid = sample.valid && sched_cpus[sample_cpu].current == t &&
                      sched_cpus[sample_cpu].account_seq == sample_seq;
    uint64_t live_ns = sample.exec_ns;
    if (UINT64_MAX - live_ns < sample.service_ns)
        live_ns = UINT64_MAX;
    else
        live_ns += sample.service_ns;
    requested = task_live_budget_expired_locked(t, live_valid ? live_ns : 0);
    pthread_mutex_unlock(&sched_lock);
    return requested;
}

/* CPU queries, timers and worker control */

int sched_thread_cpu(const thread_entry_t *t)
{
    if (!t || !sched_initialized)
        return 0;
    pthread_mutex_lock(&sched_lock);
    int cpu_index = CTS(t)->current_cpu;
    if (cpu_index < 0)
        cpu_index = CTS(t)->placement_cpu;
    pthread_mutex_unlock(&sched_lock);
    return cpu_index >= 0 ? cpu_index : 0;
}

bool sched_cpu_has_ready(int cpu_index)
{
    bool has = false;

    if (!sched_initialized || cpu_index < 0 || cpu_index >= sched_ncpu)
        return false;
    pthread_mutex_lock(&sched_lock);
    sched_cpu_state_t *cpu = &sched_cpus[cpu_index];
    has = cpu->fair.root || cpu->dl.root ||
          (!cpu->rt_throttled && rt_has_ready(cpu));
    pthread_mutex_unlock(&sched_lock);
    return has;
}

int sched_ready_count(void)
{
    int count = 0;

    if (!sched_initialized)
        return 0;
    pthread_mutex_lock(&sched_lock);
    for (int i = 0; i < sched_ncpu; i++)
        count += (int) sched_cpus[i].fair.count + (int) sched_cpus[i].dl.count +
                 (int) sched_cpus[i].rt_nr;
    pthread_mutex_unlock(&sched_lock);
    return count;
}

uint64_t sched_cpu_weight_sum(int cpu_index)
{
    uint64_t weight = 0;

    if (!sched_initialized || cpu_index < 0 || cpu_index >= sched_ncpu)
        return 0;
    pthread_mutex_lock(&sched_lock);
    weight = sched_cpus[cpu_index].weight_total;
    pthread_mutex_unlock(&sched_lock);
    return weight;
}
static uint64_t dl_pace_real_ns(const thread_entry_t *t,
                                const sched_task_state_t *s,
                                const sched_cpu_state_t *cpu);


uint64_t sched_timeslice_ns(const thread_entry_t *t)
{
    uint64_t ns = 0;

    if (!t || !sched_initialized)
        return 0;
    pthread_mutex_lock(&sched_lock);
    const sched_task_state_t *s = CTS(t);
    if (s->state != SCHED_STATE_DEAD && s->current_cpu >= 0 &&
        s->current_cpu < sched_ncpu) {
        int cpu_index = s->current_cpu;
        if (s->run_class == SCHED_CLASS_FAIR &&
            s->fair_slice_ns > s->fair_used_ns) {
            uint32_t slope = sched_cpus[cpu_index].slope_q10
                                 ? sched_cpus[cpu_index].slope_q10
                                 : SCHED_FAIR_SLOPE_ONE;
            ns = sched_fair_real_ns(s->fair_slice_ns - s->fair_used_ns, slope);
        } else if (s->run_class == SCHED_CLASS_RT) {
            if (s->eff_policy == SCHED_POLICY_RR)
                ns = s->rr_remaining_ns;
        } else if (s->run_class == SCHED_CLASS_DEADLINE &&
                   s->policy == SCHED_POLICY_DEADLINE && !s->pi_boosted) {
            ns = dl_pace_real_ns(t, s, &sched_cpus[cpu_index]);
        }
    }
    pthread_mutex_unlock(&sched_lock);
    return ns;
}

static uint64_t dl_pace_ns(const sched_task_state_t *s,
                           const sched_cpu_state_t *cpu,
                           uint64_t runtime_ns)
{
    if (!(s->flags & SCHED_FLAG_RECLAIM))
        return runtime_ns;

    uint64_t numerator = cpu->dl_running_bw;
    if (s->dl_bw_q20 > numerator)
        numerator = s->dl_bw_q20;
    if (numerator > SCHED_DL_BW_ONE)
        numerator = SCHED_DL_BW_ONE;
    if (numerator == 0)
        return runtime_ns;
    uint64_t real = (uint64_t) (((__uint128_t) runtime_ns * SCHED_DL_BW_ONE +
                                 numerator - 1) /
                                numerator);
    return real ? real : 1;
}

static uint64_t dl_pace_real_ns(const thread_entry_t *t,
                                const sched_task_state_t *s,
                                const sched_cpu_state_t *cpu)
{
    (void) t;
    if (s->pi_boosted && s->eff_policy == SCHED_POLICY_DEADLINE)
        return s->eff_dl_runtime_left_ns;
    if (s->policy != SCHED_POLICY_DEADLINE)
        return 0;
    return dl_pace_ns(s, cpu, s->dl_runtime_left_ns);
}

uint64_t sched_next_timer_ns(void)
{
    uint64_t now = sched_now_ns();
    uint64_t best = 0;

    if (!sched_initialized)
        return 0;
    pthread_mutex_lock(&sched_lock);
    if (sched_frozen) {
        pthread_mutex_unlock(&sched_lock);
        return 0;
    }
    pthread_mutex_unlock(&sched_lock);

    /* The host callback may take sched_lock for its slot lookup. */
    sched_sample_live_ns();

    pthread_mutex_lock(&sched_lock);
    if (sched_frozen) {
        pthread_mutex_unlock(&sched_lock);
        return 0;
    }
    for (int i = 0; i < sched_ncpu; i++) {
        sched_cpu_state_t *cpu = &sched_cpus[i];
        if (cpu->rt_throttled) {
            uint64_t when = cpu->rt_period_start_ns + SCHED_RT_PERIOD_NS;
            if (best == 0 || when < best)
                best = when;
        }
        thread_entry_t *cur = cpu->current;
        if (!cur)
            continue;
        const sched_task_state_t *s = CTS(cur);
        uint64_t pending = live_pending_ns(cpu);
        uint64_t delta = 0;
        if (s->run_class == SCHED_CLASS_FAIR) {
            if (!cpu_has_other_runnable(cpu, cur))
                continue;
            uint64_t rem = s->fair_slice_ns > s->fair_used_ns
                               ? s->fair_slice_ns - s->fair_used_ns
                               : 0;
            uint32_t slope =
                cpu->slope_q10 ? cpu->slope_q10 : SCHED_FAIR_SLOPE_ONE;
            uint64_t used = sched_fair_virtual_delta_ns(pending, slope);
            rem = rem > used ? rem - used : 0;
            delta = sched_fair_real_ns(rem, slope);
            if (delta == 0 && cpu_has_other_runnable(cpu, cur))
                delta = 1;
        } else if (s->run_class == SCHED_CLASS_RT) {
            if (cpu->rt_runtime_used_ns >= SCHED_RT_RUNTIME_NS) {
                delta = 1;
            } else {
                uint64_t settled_left =
                    SCHED_RT_RUNTIME_NS - cpu->rt_runtime_used_ns;
                uint64_t rt_left =
                    settled_left > pending ? settled_left - pending : 0;
                if (rt_left == 0) {
                    delta = 1;
                } else if (s->eff_policy != SCHED_POLICY_RR) {
                    delta = rt_left;
                } else {
                    uint64_t rr_left = s->rr_remaining_ns > pending
                                           ? s->rr_remaining_ns - pending
                                           : 0;
                    if (rr_left == 0 && cpu_has_other_runnable(cpu, cur))
                        delta = 1;
                    else if (rr_left == 0 || rt_left < rr_left)
                        delta = rt_left;
                    else
                        delta = rr_left;
                }
            }
        } else if (s->run_class == SCHED_CLASS_DEADLINE) {
            if (s->pi_boosted && s->eff_policy == SCHED_POLICY_DEADLINE) {
                delta = dl_pace_real_ns(cur, s, cpu);
            } else if (s->policy == SCHED_POLICY_DEADLINE) {
                uint64_t charge = dl_charge_ns(s, cpu, pending);
                if (s->dl_runtime_left_ns > charge)
                    delta = dl_pace_ns(s, cpu, s->dl_runtime_left_ns - charge);
                else
                    delta = 1;
            }
        }
        if (delta) {
            uint64_t when = now + delta;
            if (best == 0 || when < best)
                best = when;
        }
    }

    for (thread_entry_t *t = sched_dl_head; t; t = TS(t)->dl_next) {
        const sched_task_state_t *s = CTS(t);
        if (!s->dl_admitted)
            continue;
        if (s->dl_throttled) {
            uint64_t when = s->dl_abs_deadline_ns;
            if (when == 0 || when <= now)
                when = now + 1;
            if (best == 0 || when < best)
                best = when;
        }
        if (s->dl_non_contending && s->dl_inactive_deadline_ns) {
            uint64_t when = s->dl_inactive_deadline_ns;
            if (when == 0 || when <= now)
                when = now + 1;
            if (best == 0 || when < best)
                best = when;
        }
    }
    pthread_mutex_unlock(&sched_lock);
    return best;
}

int sched_run_timers(uint64_t now_ns)
{
    sched_actions_t a;
    int kicked = 0;

    if (!sched_initialized)
        return 0;
    actions_init(&a);

    pthread_mutex_lock(&sched_lock);
    if (sched_frozen) {
        pthread_mutex_unlock(&sched_lock);
        return 0;
    }
    pthread_mutex_unlock(&sched_lock);

    /* Refresh owner-side execution before judging budgets; the host callback
     * may take sched_lock for its slot lookup.
     */
    sched_sample_live_ns();

    pthread_mutex_lock(&sched_lock);
    if (sched_frozen) {
        pthread_mutex_unlock(&sched_lock);
        return 0;
    }
    for (int i = 0; i < sched_ncpu; i++) {
        sched_cpu_state_t *cpu = &sched_cpus[i];
        if (cpu->rt_throttled &&
            now_ns >= cpu->rt_period_start_ns + SCHED_RT_PERIOD_NS) {
            uint64_t start = cpu->rt_period_start_ns;
            do {
                start += SCHED_RT_PERIOD_NS;
            } while (start + SCHED_RT_PERIOD_NS <= now_ns);
            cpu->rt_period_start_ns = start;
            cpu->rt_runtime_used_ns = 0;
            cpu->rt_throttled = false;
            cpu_need_resched_locked(cpu, i, &a);
            a.timer = true;
        }
    }

    for (thread_entry_t *t = sched_dl_head; t; t = TS(t)->dl_next) {
        sched_task_state_t *s = TS(t);
        if (s->dl_non_contending && s->dl_inactive_deadline_ns &&
            now_ns >= s->dl_inactive_deadline_ns) {
            if (s->dl_bw_counted && s->dl_bw_cpu >= 0 &&
                s->dl_bw_cpu < sched_ncpu) {
                sched_cpu_state_t *cpu = &sched_cpus[s->dl_bw_cpu];
                if (cpu->dl_running_bw >= s->dl_bw_q20)
                    cpu->dl_running_bw -= s->dl_bw_q20;
                else
                    cpu->dl_running_bw = 0;
            }
            s->dl_bw_counted = false;
            s->dl_non_contending = false;
            s->dl_inactive_deadline_ns = 0;
        }
        if (s->dl_throttled && s->dl_abs_deadline_ns &&
            now_ns >= s->dl_abs_deadline_ns) {
            dl_replenish_locked(t, now_ns);
            if (s->state == SCHED_STATE_READY && !s->on_rq &&
                s->current_cpu < 0) {
                s->wake_pending = false;
                enqueue_ready_locked(t, now_ns, &a);
            }
            a.timer = true;
        }
    }

    for (int i = 0; i < sched_ncpu; i++) {
        sched_cpu_state_t *cpu = &sched_cpus[i];
        thread_entry_t *cur = cpu->current;
        if (!cur)
            continue;
        sched_task_state_t *s = TS(cur);
        bool expired = false;
        uint64_t pending = live_pending_ns(cpu);
        if (pending != 0)
            expired = task_live_budget_expired_locked(cur, pending);
        if (!expired) {
            if (s->run_class == SCHED_CLASS_FAIR) {
                if (s->fair_used_ns >= s->fair_slice_ns &&
                    cpu_has_other_runnable(cpu, cur))
                    expired = true;
            } else if (s->run_class == SCHED_CLASS_RT) {
                if (s->eff_policy == SCHED_POLICY_RR &&
                    s->rr_remaining_ns == 0 && cpu_has_other_runnable(cpu, cur))
                    expired = true;
                if (cpu->rt_throttled)
                    expired = true;
            } else if (s->run_class == SCHED_CLASS_DEADLINE) {
                if (s->policy == SCHED_POLICY_DEADLINE && !s->pi_boosted &&
                    s->dl_runtime_left_ns == 0)
                    expired = true;
            }
        }
        if (expired)
            cpu_need_resched_locked(cpu, i, &a);
    }

    for (int i = 0; i < sched_ncpu; i++)
        if (SCHED_BIT_TEST(a.kick, i))
            kicked++;

    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
    return kicked;
}

void sched_worker_kick(int cpu_index)
{
    sched_host_ops_t ops;

    pthread_mutex_lock(&sched_lock);
    ops = sched_ops;
    pthread_mutex_unlock(&sched_lock);

    if (cpu_index < 0) {
        for (int i = 0; i < sched_ncpu; i++)
            if (ops.wake_cpu)
                ops.wake_cpu(i);
    } else if (cpu_index < sched_ncpu && ops.wake_cpu) {
        ops.wake_cpu(cpu_index);
    }
}

void sched_request_shutdown(void)
{
    if (!sched_initialized)
        sched_init();
    pthread_mutex_lock(&sched_lock);
    sched_shutdown_flag = true;
    pthread_cond_broadcast(&sched_cond);
    for (int i = 0; i < sched_ncpu; i++)
        pthread_cond_broadcast(&sched_cpus[i].work_cond);
    pthread_mutex_unlock(&sched_lock);

    pthread_mutex_lock(&sched_lock);
    sched_host_ops_t ops = sched_ops;
    pthread_mutex_unlock(&sched_lock);
    if (ops.kick_all)
        ops.kick_all();
    for (int i = 0; i < sched_ncpu; i++)
        if (ops.wake_cpu)
            ops.wake_cpu(i);
}

void sched_clear_shutdown(void)
{
    if (!sched_initialized)
        sched_init();
    pthread_mutex_lock(&sched_lock);
    sched_shutdown_flag = false;
    pthread_cond_broadcast(&sched_cond);
    for (int i = 0; i < sched_ncpu; i++)
        pthread_cond_broadcast(&sched_cpus[i].work_cond);
    pthread_mutex_unlock(&sched_lock);
}

bool sched_shutdown_requested(void)
{
    bool flag;

    if (!sched_initialized)
        return false;
    pthread_mutex_lock(&sched_lock);
    flag = sched_shutdown_flag;
    pthread_mutex_unlock(&sched_lock);
    return flag;
}

void sched_domain_freeze(bool frozen)
{
    sched_actions_t a;

    if (!sched_initialized)
        sched_init();
    actions_init(&a);

    pthread_mutex_lock(&sched_lock);
    sched_frozen = frozen;
    pthread_cond_broadcast(&sched_cond);
    for (int i = 0; i < sched_ncpu; i++)
        pthread_cond_broadcast(&sched_cpus[i].work_cond);
    if (!frozen) {
        for (int i = 0; i < sched_ncpu; i++)
            SCHED_BIT_SET(a.wake, i);
    }
    a.timer = true;
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
}

bool sched_domain_frozen(void)
{
    bool frozen;

    if (!sched_initialized)
        return false;
    pthread_mutex_lock(&sched_lock);
    frozen = sched_frozen;
    pthread_mutex_unlock(&sched_lock);
    return frozen;
}

static thread_entry_t *drain_one_locked(void)
{
    for (int i = 0; i < sched_ncpu; i++) {
        sched_cpu_state_t *cpu = &sched_cpus[i];
        thread_entry_t *t = NULL;
        if (cpu->fair.root)
            t = task_from_node(sched_tree_first(&cpu->fair));
        else if (rt_has_ready(cpu)) {
            int prio = rt_highest_prio(cpu);
            if (prio >= 0)
                t = cpu->rt_head[prio];
        } else if (cpu->dl.root) {
            t = task_from_node(sched_tree_first(&cpu->dl));
        }
        if (!t)
            continue;
        task_remove_from_queue_locked(t);
        dl_forget_locked(t);
        TS(t)->state = SCHED_STATE_DEAD;
        TS(t)->wake_pending = false;
        atomic_store_explicit(&TS(t)->stop_reasons, 0, memory_order_release);
        return t;
    }
    return NULL;
}

void sched_drain_ready(void (*on_thread)(thread_entry_t *t, void *arg),
                       void *arg)
{
    if (!on_thread || !sched_initialized)
        return;

    for (;;) {
        pthread_mutex_lock(&sched_lock);
        thread_entry_t *t = drain_one_locked();
        pthread_mutex_unlock(&sched_lock);
        if (!t)
            break;
        on_thread(t, arg);
    }
}

/* Scheduling attributes */

static void eff_from_base_locked(thread_entry_t *t)
{
    sched_task_state_t *s = TS(t);

    s->eff_policy = s->policy;
    s->eff_nice = s->nice;
    s->eff_rt_priority = policy_is_rt(s->policy) ? s->rt_priority : 0;
    s->eff_weight = weight_for_policy(s->policy, s->nice);
    s->eff_dl_abs_deadline_ns =
        s->policy == SCHED_POLICY_DEADLINE ? s->dl_abs_deadline_ns : 0;
    s->eff_dl_runtime_left_ns =
        s->policy == SCHED_POLICY_DEADLINE ? s->dl_runtime_left_ns : 0;
    s->eff_dl_period_ns =
        s->policy == SCHED_POLICY_DEADLINE ? s->dl_period_ns : 0;
}

static void pi_key_from_profile(int class_rank,
                                int policy,
                                int prio,
                                uint32_t weight,
                                uint64_t deadline,
                                sched_pi_key_t *out)
{
    out->class_rank = class_rank;
    out->policy = policy;
    out->priority = prio;
    out->weight = weight;
    out->deadline_ns = deadline;
}

static void base_key_locked(const thread_entry_t *t, sched_pi_key_t *out)
{
    const sched_task_state_t *s = CTS(t);

    pi_key_from_profile(
        class_of_policy(s->policy), s->policy,
        policy_is_rt(s->policy) ? (int) s->rt_priority
                                : (policy_is_fair(s->policy) ? s->nice : 0),
        weight_for_policy(s->policy, s->nice),
        s->policy == SCHED_POLICY_DEADLINE ? s->dl_abs_deadline_ns : 0, out);
}

static void boost_key_locked(const thread_entry_t *t, sched_pi_key_t *out)
{
    const sched_task_state_t *s = CTS(t);

    pi_key_from_profile(
        class_of_policy(s->boost_policy), s->boost_policy,
        policy_is_rt(s->boost_policy)
            ? s->boost_prio
            : (policy_is_fair(s->boost_policy) ? s->boost_prio : 0),
        weight_for_policy(s->boost_policy, s->boost_prio),
        s->boost_dl_abs_deadline_ns, out);
}

int sched_pi_key_cmp(const sched_pi_key_t *a, const sched_pi_key_t *b)
{
    if (!a || !b)
        return 0;
    if (a->class_rank != b->class_rank)
        return a->class_rank > b->class_rank ? -1 : 1;
    if (a->class_rank == SCHED_CLASS_RT) {
        if (a->priority != b->priority)
            return a->priority > b->priority ? -1 : 1;
        return 0;
    }
    if (a->class_rank == SCHED_CLASS_DEADLINE) {
        if (a->deadline_ns != b->deadline_ns)
            return a->deadline_ns < b->deadline_ns ? -1 : 1;
        return 0;
    }
    if (a->class_rank == SCHED_CLASS_FAIR) {
        if (a->weight != b->weight)
            return a->weight > b->weight ? -1 : 1;
        if (a->priority != b->priority)
            return a->priority < b->priority ? -1 : 1;
    }
    return 0;
}

static void recompute_effective_locked(thread_entry_t *t)
{
    sched_task_state_t *s = TS(t);

    if (!s->pi_boosted) {
        eff_from_base_locked(t);
        return;
    }

    sched_pi_key_t base, boost;
    base_key_locked(t, &base);
    boost_key_locked(t, &boost);
    if (sched_pi_key_cmp(&boost, &base) > 0) {
        /* The base profile now outranks the boost; the boost no longer changes
         * selection. Keep the stored boost inert.
         */
        eff_from_base_locked(t);
        s->pi_boosted = false;
        return;
    }

    s->eff_policy = s->boost_policy;
    s->eff_nice = policy_is_fair(s->boost_policy) ? s->boost_prio : s->nice;
    s->eff_rt_priority = policy_is_rt(s->boost_policy)
                             ? (uint32_t) s->boost_prio
                             : (policy_is_rt(s->policy) ? s->rt_priority : 0);
    s->eff_weight = weight_for_policy(s->boost_policy, s->eff_nice);
    if (s->boost_policy == SCHED_POLICY_DEADLINE) {
        s->eff_dl_abs_deadline_ns = s->boost_dl_abs_deadline_ns;
        s->eff_dl_runtime_left_ns = s->boost_dl_runtime_left_ns;
        s->eff_dl_period_ns = s->boost_dl_period_ns;
    } else {
        s->eff_dl_abs_deadline_ns = 0;
        s->eff_dl_runtime_left_ns = 0;
        s->eff_dl_period_ns = 0;
    }
}

/* Re-evaluate queue membership after the effective or base profile changed. The
 * caller has already removed a READY task from its queue.
 */
static void profile_change_finish_locked(thread_entry_t *t,
                                         int old_class,
                                         uint32_t old_weight,
                                         bool was_queued,
                                         bool was_running,
                                         int cpu_index,
                                         uint64_t now,
                                         sched_actions_t *a)
{
    sched_task_state_t *s = TS(t);

    if (was_running && cpu_index >= 0 && cpu_index < sched_ncpu) {
        sched_cpu_state_t *cpu = &sched_cpus[cpu_index];
        if (old_class == SCHED_CLASS_FAIR) {
            if (cpu->weight_total >= old_weight)
                cpu->weight_total -= old_weight;
            else
                cpu->weight_total = 0;
        }
        int cls = task_eff_class(t);
        if (cls == SCHED_CLASS_FAIR)
            cpu->weight_total += s->eff_weight;
        s->run_class = cls;
        cpu->current_class = cls;
        if (s->policy == SCHED_POLICY_DEADLINE)
            dl_activate_bw_locked(t, cpu_index);
        else
            dl_detach_bw_locked(t);
        fair_note_change_locked(cpu);
        cpu_need_resched_locked(cpu, cpu_index, a);
        a->timer = true;
        return;
    }

    if (was_queued || s->state == SCHED_STATE_READY) {
        s->state = SCHED_STATE_READY;
        int target = s->placement_cpu;
        if (target < 0 || target >= sched_ncpu || !affinity_allows(t, target))
            target = pick_cpu_locked(t);
        if (target < 0)
            target = 0;
        s->placement_cpu = target;
        enqueue_ready_locked(t, now, a);
    } else {
        int target = s->placement_cpu;
        if (target < 0 || !affinity_allows(t, target))
            target = pick_cpu_locked(t);
        if (target >= 0)
            s->placement_cpu = target;
        if (s->policy == SCHED_POLICY_DEADLINE && target >= 0)
            dl_attach_bw_locked(t, target);
        else
            dl_detach_bw_locked(t);
    }
    a->timer = true;
}

static int validate_dl_params(uint64_t runtime,
                              uint64_t deadline,
                              uint64_t period)
{
    if (deadline == 0)
        return -SCHED_ERR_EINVAL;
    if (runtime < SCHED_DL_MIN_RUNTIME_NS)
        return -SCHED_ERR_EINVAL;
    if (deadline & (UINT64_C(1) << 63))
        return -SCHED_ERR_EINVAL;
    if (period & (UINT64_C(1) << 63))
        return -SCHED_ERR_EINVAL;
    if (period == 0)
        period = deadline;
    if (period < deadline || deadline < runtime)
        return -SCHED_ERR_EINVAL;
    return 0;
}

static int apply_base_attrs_locked(thread_entry_t *t,
                                   int policy,
                                   int nice,
                                   unsigned rt_priority,
                                   unsigned flags,
                                   uint64_t fair_slice,
                                   uint64_t dl_runtime,
                                   uint64_t dl_deadline,
                                   uint64_t dl_period,
                                   uint64_t now,
                                   sched_actions_t *a)
{
    if (!t)
        return -SCHED_ERR_EINVAL;
    if (!policy_valid(policy))
        return -SCHED_ERR_EINVAL;
    if (flags & SCHED_FLAG_UTIL_CLAMP)
        return -SCHED_ERR_EOPNOTSUPP;
    if (flags & ~SCHED_FLAG_SUPPORTED)
        return -SCHED_ERR_EINVAL;
    if (nice < SCHED_NICE_MIN || nice > SCHED_NICE_MAX)
        return -SCHED_ERR_EINVAL;

    if (policy_is_rt(policy)) {
        if (rt_priority < SCHED_RT_PRIO_MIN || rt_priority > SCHED_RT_PRIO_MAX)
            return -SCHED_ERR_EINVAL;
    } else if (rt_priority != 0) {
        /* Linux: rt_policy(policy) != (priority != 0) is EINVAL. */
        return -SCHED_ERR_EINVAL;
    }

    uint64_t custom = 0;
    if (policy_is_fair(policy)) {
        if (fair_slice != 0) {
            if (fair_slice < SCHED_FAIR_SLICE_MIN_NS)
                fair_slice = SCHED_FAIR_SLICE_MIN_NS;
            if (fair_slice > SCHED_FAIR_SLICE_MAX_NS)
                fair_slice = SCHED_FAIR_SLICE_MAX_NS;
            custom = fair_slice;
        }
        dl_runtime = 0;
        dl_deadline = 0;
        dl_period = 0;
    } else {
        custom = 0;
    }

    uint32_t new_bw = 0;
    if (policy_is_dl(policy)) {
        int rc = validate_dl_params(dl_runtime, dl_deadline, dl_period);
        if (rc)
            return rc;
        if (dl_period == 0)
            dl_period = dl_deadline;
        new_bw = dl_bw_compute(dl_runtime, dl_period);
        uint64_t others = sched_dl_admitted_bw;
        if (t->sched.dl_admitted && others >= t->sched.dl_bw_q20)
            others -= t->sched.dl_bw_q20;
        if ((__uint128_t) others + new_bw > dl_domain_capacity())
            return -SCHED_ERR_EBUSY;
    } else {
        dl_runtime = 0;
        dl_deadline = 0;
        dl_period = 0;
    }

    sched_task_state_t *s = TS(t);
    bool was_queued = s->on_rq;
    bool was_running = s->current_cpu >= 0;
    int cpu_index = was_running ? s->current_cpu : s->queued_cpu;
    int old_class = was_running
                        ? s->run_class
                        : (was_queued ? s->queued_class : SCHED_CLASS_NONE);
    uint32_t old_weight = old_class == SCHED_CLASS_FAIR ? s->eff_weight : 0;
    unsigned old_rt_priority = s->eff_rt_priority;

    if (was_queued)
        task_remove_from_queue_locked(t);

    bool had_dl = s->dl_admitted;
    uint32_t old_bw = s->dl_bw_q20;

    if (had_dl && !policy_is_dl(policy)) {
        /* dl_forget_locked() owns the admission-budget decrement and the
         * admitted-list removal; subtracting here as well would underflow the
         * domain counter and admit reservations beyond capacity.
         */
        dl_forget_locked(t);
    }

    if (had_dl && policy_is_dl(policy))
        dl_detach_bw_locked(t);

    s->policy = policy;
    s->nice = nice;
    s->rt_priority = policy_is_rt(policy) ? rt_priority : 0;
    unsigned stored_flags = flags & SCHED_FLAG_RESET_ON_FORK;
    if (policy_is_dl(policy))
        stored_flags |= flags & (SCHED_FLAG_RECLAIM | SCHED_FLAG_DL_OVERRUN);
    s->flags = stored_flags;
    s->fair_slice_custom_ns = custom;

    if (policy_is_dl(policy)) {
        if (!had_dl)
            sched_dl_admitted_bw += new_bw;
        else {
            sched_dl_admitted_bw = sched_dl_admitted_bw >= old_bw
                                       ? sched_dl_admitted_bw - old_bw + new_bw
                                       : new_bw;
        }
        s->dl_runtime_ns = dl_runtime;
        s->dl_deadline_ns = dl_deadline;
        s->dl_period_ns = dl_period;
        s->dl_bw_q20 = new_bw;
        s->dl_runtime_left_ns = dl_runtime;
        s->dl_abs_deadline_ns = now + dl_deadline;
        s->dl_throttled = false;
        s->dl_yielded = false;
        s->dl_non_contending = false;
        s->dl_inactive_deadline_ns = 0;
        s->dl_bw_counted = false;
        s->dl_overrun_reported = false;
        s->dl_bw_cpu = -1;
        if (!had_dl) {
            s->dl_admitted = true;
            dl_list_add_locked(t);
        }
    }

    s->attrs_initialized = true;
    recompute_effective_locked(t);
    profile_change_finish_locked(t, old_class, old_weight, was_queued,
                                 was_running, cpu_index, now, a);
    if (was_queued && old_class == SCHED_CLASS_RT &&
        task_eff_class(t) == SCHED_CLASS_RT &&
        s->eff_rt_priority > old_rt_priority)
        rt_requeue_head_locked(t);
    a->prio_changed = t;
    return 0;
}

void sched_task_get_attr(const thread_entry_t *t, sched_task_attrs_t *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!t)
        return;
    if (!sched_initialized) {
        out->policy = SCHED_POLICY_OTHER;
        return;
    }

    pthread_mutex_lock(&sched_lock);
    const sched_task_state_t *s = CTS(t);
    out->policy = s->policy;
    out->nice = s->nice;
    out->rt_priority = s->rt_priority;
    out->flags = s->flags;
    if (s->policy == SCHED_POLICY_DEADLINE) {
        out->runtime = s->dl_runtime_ns;
        out->deadline = s->dl_deadline_ns;
        out->period = s->dl_period_ns;
    } else if (policy_is_fair(s->policy)) {
        out->runtime = s->fair_slice_custom_ns;
    }
    pthread_mutex_unlock(&sched_lock);
}

int sched_task_set_attr(thread_entry_t *t, const sched_task_attrs_t *a)
{
    sched_actions_t actions;
    int rc;
    uint64_t now;

    if (!t || !a || !sched_initialized)
        return -SCHED_ERR_EINVAL;
    actions_init(&actions);
    now = sched_now_ns();

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    int policy = a->policy;
    int nice = a->nice;
    unsigned rt_priority = a->rt_priority;
    unsigned flags = a->flags;
    uint64_t fair_slice = a->runtime;
    uint64_t dl_runtime = a->runtime;
    uint64_t dl_deadline = a->deadline;
    uint64_t dl_period = a->period;

    if (flags & SCHED_FLAG_KEEP_POLICY)
        policy = s->policy;
    if (flags & SCHED_FLAG_KEEP_PARAMS) {
        nice = s->nice;
        rt_priority = s->rt_priority;
        fair_slice = s->fair_slice_custom_ns;
        dl_runtime = s->dl_runtime_ns;
        dl_deadline = s->dl_deadline_ns;
        dl_period = s->dl_period_ns;
    }

    rc = apply_base_attrs_locked(t, policy, nice, rt_priority, flags,
                                 fair_slice, dl_runtime, dl_deadline, dl_period,
                                 now, &actions);
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&actions);
    return rc;
}

int sched_task_set_nice(thread_entry_t *t, int nice)
{
    sched_actions_t actions;
    int rc = 0;
    uint64_t now;

    if (!t || !sched_initialized)
        return -SCHED_ERR_EINVAL;
    if (nice < SCHED_NICE_MIN)
        nice = SCHED_NICE_MIN;
    if (nice > SCHED_NICE_MAX)
        nice = SCHED_NICE_MAX;

    actions_init(&actions);
    now = sched_now_ns();

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    s->nice = nice;
    if (!policy_is_fair(s->policy)) {
        /* nice is retained for getpriority but does not change RT/DL selection
         * or reset the deadline reservation.
         */
        if (!s->pi_boosted)
            eff_from_base_locked(t);
        pthread_mutex_unlock(&sched_lock);
        return 0;
    }

    rc = apply_base_attrs_locked(
        t, s->policy, nice, s->rt_priority, s->flags, s->fair_slice_custom_ns,
        s->dl_runtime_ns, s->dl_deadline_ns, s->dl_period_ns, now, &actions);
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&actions);
    return rc;
}

int sched_task_inherit_attr(const thread_entry_t *parent, thread_entry_t *child)
{
    if (!child)
        return -SCHED_ERR_EINVAL;
    if (!parent) {
        pthread_mutex_lock(&sched_lock);
        sched_init_defaults_locked(child);
        pthread_mutex_unlock(&sched_lock);
        return 0;
    }
    if (!sched_initialized)
        sched_init();

    pthread_mutex_lock(&sched_lock);
    const sched_task_state_t *ps = CTS(parent);
    sched_task_state_t *cs = TS(child);
    cs->expected_runtime_ns = SCHED_MIN_FAIR_CAPACITY_NS;
    cs->banked_runtime_ns = 0;

    bool reset = (ps->flags & SCHED_FLAG_RESET_ON_FORK) != 0;
    if (ps->policy == SCHED_POLICY_DEADLINE && !reset) {
        /* Linux sched_fork() returns -EAGAIN: a deadline reservation cannot be
         * duplicated implicitly.
         */
        pthread_mutex_unlock(&sched_lock);
        return -SCHED_ERR_EAGAIN;
    }

    cs->policy = ps->policy;
    cs->nice = ps->nice;
    cs->rt_priority = ps->rt_priority;
    cs->flags = ps->flags;
    cs->fair_slice_custom_ns = ps->fair_slice_custom_ns;
    cs->dl_runtime_ns = 0;
    cs->dl_deadline_ns = 0;
    cs->dl_period_ns = 0;

    if (reset) {
        if (policy_is_rt(cs->policy) || policy_is_dl(cs->policy)) {
            cs->policy = SCHED_POLICY_OTHER;
            cs->nice = 0;
            cs->rt_priority = 0;
        } else if (cs->nice < 0) {
            cs->nice = 0;
        }
        cs->fair_slice_custom_ns = 0;
        cs->flags &= ~SCHED_FLAG_RESET_ON_FORK;
    }

    memcpy(cs->affinity, ps->affinity, sizeof(cs->affinity));
    if (memcmp(cs->affinity, (uint8_t[SCHED_CPUSET_BYTES]) {0},
               sizeof(cs->affinity)) == 0)
        affinity_set_full(cs);

    cs->state = SCHED_STATE_NEW;
    cs->queued_class = SCHED_CLASS_NONE;
    cs->queued_cpu = -1;
    cs->current_cpu = -1;
    cs->placement_cpu = -1;
    cs->on_rq = false;
    cs->attrs_initialized = true;
    cs->wake_pending = false;
    cs->block_requested = false;
    cs->resched_requested = false;
    atomic_store_explicit(&cs->stop_reasons, 0, memory_order_release);
    cs->stop_requested = false;
    cs->stop_blocked = false;
    cs->stop_started_ns = 0;
    cs->pi_boosted = false;
    cs->boost_policy = SCHED_POLICY_OTHER;
    cs->boost_prio = 0;
    cs->boost_dl_abs_deadline_ns = 0;
    cs->boost_dl_runtime_left_ns = 0;
    cs->boost_dl_period_ns = 0;
    cs->fair_start_ns = 0;
    cs->fair_finish_ns = 0;
    cs->fair_slice_ns = 0;
    cs->fair_used_ns = 0;
    cs->fair_cpu = -1;
    cs->rr_remaining_ns = 0;
    cs->run_class = SCHED_CLASS_NONE;
    cs->dl_runtime_left_ns = 0;
    cs->dl_abs_deadline_ns = 0;
    cs->dl_bw_q20 = 0;
    cs->dl_admitted = false;
    cs->dl_bw_counted = false;
    cs->dl_overrun_reported = false;
    cs->dl_throttled = false;
    cs->dl_yielded = false;
    cs->dl_non_contending = false;
    cs->dl_inactive_deadline_ns = 0;
    cs->dl_bw_cpu = -1;
    cs->dl_prev = NULL;
    cs->dl_next = NULL;
    cs->rt_next = NULL;
    cs->rt_prev = NULL;
    sched_tree_init_node(&cs->node);
    eff_from_base_locked(child);
    pthread_mutex_unlock(&sched_lock);
    return 0;
}

bool sched_task_base_priority(const thread_entry_t *t, int *policy, int *prio)
{
    if (!t)
        return false;
    if (!sched_initialized)
        return false;
    pthread_mutex_lock(&sched_lock);
    const sched_task_state_t *s = CTS(t);
    if (policy)
        *policy = s->policy;
    if (prio) {
        if (policy_is_rt(s->policy))
            *prio = (int) s->rt_priority;
        else if (policy_is_fair(s->policy))
            *prio = s->nice;
        else
            *prio = 0;
    }
    pthread_mutex_unlock(&sched_lock);
    return true;
}

bool sched_task_effective_priority(const thread_entry_t *t,
                                   int *policy,
                                   int *prio)
{
    if (!t)
        return false;
    if (!sched_initialized)
        return false;
    pthread_mutex_lock(&sched_lock);
    const sched_task_state_t *s = CTS(t);
    if (policy)
        *policy = s->eff_policy;
    if (prio) {
        if (policy_is_rt(s->eff_policy))
            *prio = (int) s->eff_rt_priority;
        else if (policy_is_fair(s->eff_policy))
            *prio = s->eff_nice;
        else
            *prio = 0;
    }
    pthread_mutex_unlock(&sched_lock);
    return true;
}

uint64_t sched_task_rr_interval_ns(const thread_entry_t *t)
{
    uint64_t ns = 0;

    if (!t)
        return SCHED_RR_QUANTUM_NS;
    if (!sched_initialized)
        return SCHED_RR_QUANTUM_NS;

    pthread_mutex_lock(&sched_lock);
    const sched_task_state_t *s = CTS(t);
    if (s->policy == SCHED_POLICY_RR) {
        ns = SCHED_RR_QUANTUM_NS;
    } else if (policy_is_fair(s->eff_policy)) {
        int cpu_index = s->current_cpu >= 0 ? s->current_cpu : s->placement_cpu;
        uint32_t slope = SCHED_FAIR_SLOPE_ONE;
        uint64_t total = sched_cpus ? sched_cpus[0].weight_total : 0;
        if (cpu_index >= 0 && cpu_index < sched_ncpu) {
            slope = sched_cpus[cpu_index].slope_q10;
            total = sched_cpus[cpu_index].weight_total;
        }
        if (slope == 0)
            slope = SCHED_FAIR_SLOPE_ONE;
        uint64_t virtual = sched_fair_slice_ns(s->eff_weight, total);
        ns = sched_fair_real_ns(virtual, slope);
    }
    pthread_mutex_unlock(&sched_lock);
    return ns;
}

/* Affinity */

size_t sched_affinity_cpuset_bytes(void)
{
    if (!sched_initialized)
        sched_init();
    return domain_mask_bytes();
}

int sched_affinity_default_mask(uint8_t *buf, size_t len)
{
    size_t needed;

    if (!buf)
        return -1;
    if (!sched_initialized)
        sched_init();
    needed = domain_mask_bytes();
    if (len < needed)
        return -1;
    memset(buf, 0, len);
    for (int i = 0; i < sched_ncpu; i++)
        SCHED_BIT_SET(buf, i);
    return (int) needed;
}

int sched_task_get_affinity(const thread_entry_t *t, uint8_t *buf, size_t len)
{
    size_t needed;

    if (!t || !buf)
        return -SCHED_ERR_EINVAL;
    if (!sched_initialized)
        sched_init();
    needed = domain_mask_bytes();
    if (len < needed)
        return -SCHED_ERR_EINVAL;

    pthread_mutex_lock(&sched_lock);
    memset(buf, 0, len);
    memcpy(buf, CTS(t)->affinity, needed);
    pthread_mutex_unlock(&sched_lock);
    return (int) needed;
}

int sched_task_set_affinity(thread_entry_t *t, const uint8_t *mask, size_t len)
{
    sched_actions_t actions;
    uint64_t now;

    if (!t || !mask || !sched_initialized)
        return -SCHED_ERR_EINVAL;
    size_t needed = domain_mask_bytes();
    if (len < needed)
        return -SCHED_ERR_EINVAL;
    if (!dmask_any_in_domain(mask, needed))
        return -SCHED_ERR_EINVAL;

    actions_init(&actions);
    now = sched_now_ns();

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    memset(s->affinity, 0, sizeof(s->affinity));
    for (int i = 0; i < sched_ncpu; i++) {
        if (dmask_allows(mask, needed, i))
            SCHED_BIT_SET(s->affinity, i);
    }

    bool was_queued = s->on_rq;
    bool was_running = s->current_cpu >= 0;
    int cpu_index = was_running ? s->current_cpu : s->queued_cpu;

    if (was_queued) {
        task_remove_from_queue_locked(t);
        if (cpu_index < 0 || !affinity_allows(t, cpu_index))
            s->placement_cpu = pick_cpu_locked(t);
        s->state = SCHED_STATE_READY;
        enqueue_ready_locked(t, now, &actions);
    } else if (was_running) {
        if (cpu_index < 0 || cpu_index >= sched_ncpu ||
            !affinity_allows(t, cpu_index)) {
            int target = pick_cpu_locked(t);
            s->placement_cpu = target;
            cpu_need_resched_locked(&sched_cpus[cpu_index], cpu_index,
                                    &actions);
        } else {
            s->placement_cpu = cpu_index;
        }
    } else {
        if (s->placement_cpu < 0 || !affinity_allows(t, s->placement_cpu))
            s->placement_cpu = pick_cpu_locked(t);
        if (s->policy == SCHED_POLICY_DEADLINE && s->placement_cpu >= 0)
            dl_attach_bw_locked(t, s->placement_cpu);
    }
    actions.timer = true;
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&actions);
    return 0;
}

/* Local priority inheritance */

static void pi_profile_changed_locked(thread_entry_t *t,
                                      int old_class,
                                      uint32_t old_weight,
                                      bool was_queued,
                                      bool was_running,
                                      int cpu_index,
                                      uint64_t now,
                                      sched_actions_t *a)
{
    if (was_queued)
        task_remove_from_queue_locked(t);
    recompute_effective_locked(t);
    profile_change_finish_locked(t, old_class, old_weight, was_queued,
                                 was_running, cpu_index, now, a);
}

int sched_task_pi_set_priority(thread_entry_t *t, int policy, int prio)
{
    sched_actions_t actions;
    uint64_t now;

    if (!t || !sched_initialized)
        return -SCHED_ERR_EINVAL;
    if (!policy_is_fair(policy) && !policy_is_rt(policy))
        return -SCHED_ERR_EINVAL;
    if (policy_is_rt(policy)) {
        if (prio < SCHED_RT_PRIO_MIN || prio > SCHED_RT_PRIO_MAX)
            return -SCHED_ERR_EINVAL;
    } else {
        if (prio < SCHED_NICE_MIN || prio > SCHED_NICE_MAX)
            return -SCHED_ERR_EINVAL;
    }

    actions_init(&actions);
    now = sched_now_ns();

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    bool was_queued = s->on_rq;
    bool was_running = s->current_cpu >= 0;
    int cpu_index = was_running ? s->current_cpu : s->queued_cpu;
    int old_class = was_running
                        ? s->run_class
                        : (was_queued ? s->queued_class : SCHED_CLASS_NONE);
    uint32_t old_weight = old_class == SCHED_CLASS_FAIR ? s->eff_weight : 0;
    unsigned old_rt_priority = s->eff_rt_priority;

    s->boost_policy = policy;
    s->boost_prio = prio;
    s->boost_dl_abs_deadline_ns = 0;
    s->boost_dl_runtime_left_ns = 0;
    s->boost_dl_period_ns = 0;
    s->pi_boosted = true;

    pi_profile_changed_locked(t, old_class, old_weight, was_queued, was_running,
                              cpu_index, now, &actions);
    if (was_queued && old_class == SCHED_CLASS_RT &&
        task_eff_class(t) == SCHED_CLASS_RT &&
        s->eff_rt_priority > old_rt_priority)
        rt_requeue_head_locked(t);
    actions.timer = true;
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&actions);
    return 0;
}

int sched_task_pi_set_deadline(thread_entry_t *t,
                               uint64_t abs_deadline_ns,
                               uint64_t runtime_ns,
                               uint64_t period_ns)
{
    sched_actions_t actions;
    uint64_t now;

    if (!t || !sched_initialized || abs_deadline_ns == 0)
        return -SCHED_ERR_EINVAL;

    actions_init(&actions);
    now = sched_now_ns();

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    bool was_queued = s->on_rq;
    bool was_running = s->current_cpu >= 0;
    int cpu_index = was_running ? s->current_cpu : s->queued_cpu;
    int old_class = was_running
                        ? s->run_class
                        : (was_queued ? s->queued_class : SCHED_CLASS_NONE);
    uint32_t old_weight = old_class == SCHED_CLASS_FAIR ? s->eff_weight : 0;

    s->boost_policy = SCHED_POLICY_DEADLINE;
    s->boost_prio = 0;
    s->boost_dl_abs_deadline_ns = abs_deadline_ns;
    s->boost_dl_runtime_left_ns = runtime_ns;
    s->boost_dl_period_ns = period_ns;
    s->pi_boosted = true;

    pi_profile_changed_locked(t, old_class, old_weight, was_queued, was_running,
                              cpu_index, now, &actions);
    actions.timer = true;
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&actions);
    return 0;
}

void sched_task_pi_clear_priority(thread_entry_t *t)
{
    sched_actions_t actions;
    uint64_t now;

    if (!t || !sched_initialized)
        return;
    actions_init(&actions);
    now = sched_now_ns();

    pthread_mutex_lock(&sched_lock);
    sched_task_state_t *s = TS(t);
    if (!s->pi_boosted) {
        pthread_mutex_unlock(&sched_lock);
        return;
    }
    bool was_queued = s->on_rq;
    bool was_running = s->current_cpu >= 0;
    int cpu_index = was_running ? s->current_cpu : s->queued_cpu;
    int old_class = was_running
                        ? s->run_class
                        : (was_queued ? s->queued_class : SCHED_CLASS_NONE);
    uint32_t old_weight = old_class == SCHED_CLASS_FAIR ? s->eff_weight : 0;
    unsigned old_rt_priority = s->eff_rt_priority;

    s->pi_boosted = false;
    s->boost_policy = SCHED_POLICY_OTHER;
    s->boost_prio = 0;
    s->boost_dl_abs_deadline_ns = 0;
    s->boost_dl_runtime_left_ns = 0;
    s->boost_dl_period_ns = 0;

    pi_profile_changed_locked(t, old_class, old_weight, was_queued, was_running,
                              cpu_index, now, &actions);
    if (was_queued && old_class == SCHED_CLASS_RT &&
        task_eff_class(t) == SCHED_CLASS_RT &&
        s->eff_rt_priority > old_rt_priority)
        rt_requeue_head_locked(t);
    actions.timer = true;
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&actions);
}

bool sched_task_pi_key(const thread_entry_t *t, sched_pi_key_t *out)
{
    if (!t || !out || !sched_initialized)
        return false;
    pthread_mutex_lock(&sched_lock);
    const sched_task_state_t *s = CTS(t);
    out->class_rank = class_of_policy(s->eff_policy);
    out->policy = s->eff_policy;
    if (policy_is_rt(s->eff_policy)) {
        out->priority = (int) s->eff_rt_priority;
    } else if (policy_is_fair(s->eff_policy)) {
        out->priority = s->eff_nice;
    } else {
        out->priority = 0;
    }
    out->weight = task_eff_weight(t);
    out->deadline_ns = task_dl_abs_deadline(t);
    pthread_mutex_unlock(&sched_lock);
    return true;
}

/* Park and wait-timer integration */

/* Implemented by the blocking syscall modules. */
void futex_park_on_deadline(thread_entry_t *t);
void futex_park_on_interrupt(thread_entry_t *t);
void sleep_park_on_deadline(thread_entry_t *t);
void sleep_park_on_interrupt(thread_entry_t *t);
void io_park_on_deadline(thread_entry_t *t);
void io_park_on_interrupt(thread_entry_t *t);
void mqueue_park_on_deadline(thread_entry_t *t);
void mqueue_park_on_interrupt(thread_entry_t *t);
void sysvipc_park_on_deadline(thread_entry_t *t);
void sysvipc_park_on_interrupt(thread_entry_t *t);
void wait_park_on_deadline(thread_entry_t *t);
void wait_park_on_interrupt(thread_entry_t *t);

static void park_publish_ready_locked(thread_entry_t *t,
                                      uint64_t now,
                                      sched_actions_t *a)
{
    sched_task_state_t *s = TS(t);

    if (s->state == SCHED_STATE_RUNNING) {
        s->wake_pending = true;
    } else if (s->state == SCHED_STATE_BLOCKED) {
        s->state = SCHED_STATE_READY;
        place_fair_wakeup_locked(t);
        enqueue_ready_locked(t, now, a);
    }
    a->timer = true;
}

uint64_t sched_park_seq_next(thread_entry_t *t)
{
    uint64_t seq =
        atomic_fetch_add_explicit(&t->park_seq, 1, memory_order_acq_rel) + 1;
    if (seq == 0)
        seq = atomic_fetch_add_explicit(&t->park_seq, 1, memory_order_acq_rel) +
              1;
    return seq;
}

uint64_t sched_park_seq(const thread_entry_t *t)
{
    return atomic_load_explicit(&t->park_seq, memory_order_acquire);
}

bool sched_park_try_complete_seq(thread_entry_t *t,
                                 int kind,
                                 uint64_t seq,
                                 int64_t result)
{
    sched_actions_t a;
    uint64_t now = sched_now_ns();

    if (!t || !sched_initialized)
        return false;
    actions_init(&a);

    pthread_mutex_lock(&sched_lock);
    if (!exec_park_active_load(t) ||
        (kind >= 0 &&
         (exec_park_kind_load(t) != kind || sched_park_seq(t) != seq))) {
        pthread_mutex_unlock(&sched_lock);
        return false;
    }
    exec_park_result_store(t, result);
    exec_park_result_pending_store(t, true);
    exec_park_reissue_store(t, false);
    exec_park_deadline_ns_store(t, 0);
    exec_park_kind_store(t, PARK_KIND_NONE);
    t->io_park_fd = -1;
    t->io_park_deadline_ns = 0;
    t->io_syscall_deadline_ms = 0;
    exec_park_active_store(t, false);
    park_publish_ready_locked(t, now, &a);
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
    return true;
}

bool sched_park_try_complete_reissue_seq(thread_entry_t *t,
                                         int kind,
                                         uint64_t seq)
{
    sched_actions_t a;
    uint64_t now = sched_now_ns();

    if (!t || !sched_initialized)
        return false;
    actions_init(&a);

    pthread_mutex_lock(&sched_lock);
    if (!exec_park_active_load(t) ||
        (kind >= 0 &&
         (exec_park_kind_load(t) != kind || sched_park_seq(t) != seq))) {
        pthread_mutex_unlock(&sched_lock);
        return false;
    }
    exec_park_result_pending_store(t, false);
    exec_park_reissue_store(t, true);
    exec_park_deadline_ns_store(t, 0);
    exec_park_kind_store(t, PARK_KIND_NONE);
    t->io_park_fd = -1;
    t->io_park_deadline_ns = 0;
    exec_park_active_store(t, false);
    park_publish_ready_locked(t, now, &a);
    pthread_mutex_unlock(&sched_lock);
    sched_dispatch(&a);
    return true;
}

bool sched_park_try_complete(thread_entry_t *t, int64_t result)
{
    return sched_park_try_complete_seq(t, -1, 0, result);
}

bool sched_park_try_complete_reissue(thread_entry_t *t)
{
    return sched_park_try_complete_reissue_seq(t, -1, 0);
}

void sched_park_on_signal(thread_entry_t *t)
{
    if (!t || !exec_park_active_load(t))
        return;

    switch (exec_park_kind_load(t)) {
    case PARK_KIND_FUTEX:
        futex_park_on_interrupt(t);
        break;
    case PARK_KIND_SLEEP:
        sleep_park_on_interrupt(t);
        break;
    case PARK_KIND_IO:
        io_park_on_interrupt(t);
        break;
    case PARK_KIND_MQUEUE:
        mqueue_park_on_interrupt(t);
        break;
    case PARK_KIND_IPC:
        sysvipc_park_on_interrupt(t);
        break;
    case PARK_KIND_WAIT:
        wait_park_on_interrupt(t);
        break;
    case PARK_KIND_SIGNAL:
        signal_wait_park_on_interrupt(t);
        break;
    default:
        /* STOP is resumed by the debugger path, WAIT by its wait driver. */
        break;
    }
}

void sched_arm_wait_deadline(thread_entry_t *t, uint64_t abs_ns)
{
    sched_host_ops_t ops;

    if (!t)
        return;
    exec_park_deadline_ns_store(t, abs_ns);
    pthread_mutex_lock(&sched_lock);
    ops = sched_ops;
    pthread_mutex_unlock(&sched_lock);
    if (ops.wake_timer)
        ops.wake_timer();
}

void sched_disarm_wait_deadline(thread_entry_t *t)
{
    if (t)
        exec_park_deadline_ns_store(t, 0);
}

void sched_kick_wait_timer(void)
{
    sched_host_ops_t ops;

    pthread_mutex_lock(&sched_lock);
    ops = sched_ops;
    pthread_mutex_unlock(&sched_lock);
    if (ops.wake_timer)
        ops.wake_timer();
}

static void next_deadline_one(thread_entry_t *t, void *ctx)
{
    uint64_t *nearest = ctx;

    if (!exec_park_active_load(t) || exec_park_deadline_ns_load(t) == 0)
        return;
    if (exec_park_deadline_ns_load(t) < *nearest)
        *nearest = exec_park_deadline_ns_load(t);
}

uint64_t sched_next_wait_deadline_ns(void)
{
    uint64_t nearest = UINT64_MAX;

    thread_for_each(next_deadline_one, &nearest);
    return nearest == UINT64_MAX ? 0 : nearest;
}

static void fire_wait_one(thread_entry_t *t, void *ctx)
{
    uint64_t now = *(uint64_t *) ctx;

    if (!exec_park_active_load(t) || exec_park_deadline_ns_load(t) == 0)
        return;
    if (exec_park_deadline_ns_load(t) > now)
        return;

    switch (exec_park_kind_load(t)) {
    case PARK_KIND_FUTEX:
        futex_park_on_deadline(t);
        break;
    case PARK_KIND_SLEEP:
        sleep_park_on_deadline(t);
        break;
    case PARK_KIND_IO:
        io_park_on_deadline(t);
        break;
    case PARK_KIND_MQUEUE:
        mqueue_park_on_deadline(t);
        break;
    case PARK_KIND_IPC:
        sysvipc_park_on_deadline(t);
        break;
    case PARK_KIND_WAIT:
    case PARK_KIND_VFORK:
        wait_park_on_deadline(t);
        break;
    case PARK_KIND_SIGNAL:
        signal_wait_park_on_deadline(t);
        break;
    default:
        break;
    }
}

void sched_fire_expired_waits(uint64_t now_ns)
{
    thread_for_each_ref(fire_wait_one, &now_ns);
}

static void wake_parked_one(thread_entry_t *t, void *ctx)
{
    (void) ctx;
    if (exec_park_active_load(t))
        sched_park_on_signal(t);
}

void sched_wake_parked_for_pending_signal(void)
{
    thread_for_each_ref(wake_parked_one, NULL);
}

/* CPU clocks */

uint64_t sched_thread_cputime_ns(const thread_entry_t *t)
{
    uint64_t user = 0;
    uint64_t sys = 0;

    sched_thread_cputime_split_ns(t, &user, &sys);
    return user + sys;
}

uint64_t sched_process_cputime_ns(void)
{
    /* thread.c owns the active + departed aggregate and its locking. */
    return thread_process_cputime_ns();
}

/* Implemented by runtime/thread.c; includes active and departed members. */
void thread_process_cputime_split_ns(uint64_t *user_ns, uint64_t *sys_ns);

void sched_thread_cputime_split_ns(const thread_entry_t *t,
                                   uint64_t *user_ns,
                                   uint64_t *sys_ns)
{
    uint64_t user = 0;
    uint64_t sys = 0;
    uint64_t live_exec = 0;
    uint64_t live_service = 0;

    if (t && sched_initialized) {
        sched_live_sample_t (*live_fn)(const thread_entry_t *) = NULL;

        pthread_mutex_lock(&sched_lock);
        live_fn = sched_ops.live_sample;
        pthread_mutex_unlock(&sched_lock);

        /* A settlement moves the batch out of the backend's sample and into
         * these counters. The sample is taken on both sides of the snapshot:
         * equal generations mean both belong to one interval that no settlement
         * overlapped, so the counters and the sample count every nanosecond
         * once, and successive reads only ever grow. A transition in between
         * changes the generation, and the pair is taken again; the backend's
         * window is lock-free, so it always closes.
         */
        for (unsigned attempt = 0; live_fn; attempt++) {
            sched_live_sample_t first = live_fn(t);
            if (first.valid) {
                pthread_mutex_lock(&sched_lock);
                user = CTS(t)->runtime_user_ns;
                sys = CTS(t)->runtime_sys_ns;
                pthread_mutex_unlock(&sched_lock);

                sched_live_sample_t last = live_fn(t);
                if (last.valid && last.generation == first.generation) {
                    live_exec = first.exec_ns;
                    live_service = first.service_ns;
                    break;
                }
            }
            /* Let the owner finish the phase or settlement it is inside. */
            if (attempt >= 8)
                sched_yield();
        }
        if (!live_fn) {
            /* No backend: nothing has been executed outside the counters. */
            pthread_mutex_lock(&sched_lock);
            user = CTS(t)->runtime_user_ns;
            sys = CTS(t)->runtime_sys_ns;
            pthread_mutex_unlock(&sched_lock);
        }
    }
    if (user_ns)
        *user_ns = user + live_exec;
    if (sys_ns)
        *sys_ns = sys + live_service;
}

void sched_process_cputime_split_ns(uint64_t *user_ns, uint64_t *sys_ns)
{
    thread_process_cputime_split_ns(user_ns, sys_ns);
}
