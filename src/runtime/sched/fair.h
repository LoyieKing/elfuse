/*
 * Fair-scheduling math and augmented run queue
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2026 The Fuchsia Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Fair period, time-slice, virtual-timeline and run-queue mechanics follow the
 * Zircon fair scheduler at the pinned reference commit
 * 966c936b56d8d117a26ecbf2c583ec350b2325c8 (zircon/kernel/kernel/scheduler.rs,
 * "Fair bandwidth scheduling", "SubtreeInvariants" and
 * "find_earliest_eligible_thread"). Zircon is distributed under a MIT-style
 * license; the algorithm structure and the augmented-tree selection are derived
 * from that source. The Linux nice-to-weight relation and the per-CPU period
 * expansion are elfuse's own construction on top of it.
 *
 * This file is pure accounting: no HVF, thread-table, or lock dependency, so
 * the tree and the period math are unit-testable on the host.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Minimum fair capacity / real scheduling granularity: 1 ms, matching Zircon's
 * kMinimumFairCapacity.
 */
#define SCHED_MIN_FAIR_CAPACITY_NS 1000000ULL

/* Default fair period (virtual nanoseconds): 10 ms, matching Zircon's
 * kDefaultFairPeriod. The period belongs to the CPU; every fair task on that
 * CPU shares it.
 */
#define SCHED_DEFAULT_FAIR_PERIOD_NS 10000000ULL

/* Weight of nice 0 (SCHED_OTHER default). Linux's weight relation is 1024 *
 * 1.25^-nice; the table below is generated from that relation.
 */
#define SCHED_WEIGHT_NICE_0 1024U

/* Fixed-point scale of the virtual-timeline slope, matching Zircon's
 * Affine::K_PRECISION_BITS = 10. A slope of 1024 advances virtual time at the
 * same rate as actual execution; smaller slopes expand the real period.
 */
#define SCHED_FAIR_SLOPE_ONE 1024U

/* Clamp Linux nice into [-20, 19] and return the fair weight. */
uint32_t sched_fair_weight_from_nice(int nice);

/* Virtual timeline slope for a run queue whose lightest task has @min_weight
 * and whose total weight is @weight_sum. The slope is chosen so the lightest
 * task still receives SCHED_MIN_FAIR_CAPACITY_NS per expanded period:
 *
 *   slope = 10 * min_weight / weight_sum          (Zircon)
 *
 * In Q10 fixed point the result is clamped to [1, 1024]. A weight sum of 0
 * yields SCHED_FAIR_SLOPE_ONE.
 */
uint32_t sched_fair_slope_q10(uint32_t min_weight, uint64_t weight_sum);

/* Real period corresponding to @slope_q10: default period / slope. */
uint64_t sched_fair_period_ns(uint32_t slope_q10);

/* Virtual activation budget for one task: period * weight / weight_sum. Never
 * returns 0 for a nonzero weight; weight_sum 0 returns the default period.
 */
uint64_t sched_fair_slice_ns(uint32_t weight, uint64_t weight_sum);

/* Convert actual consumed execution nanoseconds into virtual nanoseconds at
 * @slope_q10.
 */
uint64_t sched_fair_virtual_delta_ns(uint64_t actual_ns, uint32_t slope_q10);

/* Convert a virtual duration back to actual execution nanoseconds (rounded up,
 * so a caller never arms a slice timer before the budget is consumed).
 */
uint64_t sched_fair_real_ns(uint64_t virtual_ns, uint32_t slope_q10);

/* Augmented run queue
 *
 * An intrusive red-black tree ordered by (key_time, key_tid). Each node carries
 * two subtree invariants:
 *
 *   min_finish: earliest finish time in the subtree
 *   min_weight: lightest fair weight in the subtree (UINT32_MAX for nodes
 *               that carry no fair weight)
 *
 * The fair tree is keyed by activation start time and augmented by finish time,
 * which allows selecting the eligible task with the earliest finish in O(log n)
 * without walking the queue. The deadline tree is keyed by absolute deadline;
 * its front node is the EDF choice.
 *
 * A task is in at most one tree at a time, so one node is embedded in
 * sched_task_state_t.
 */

typedef struct sched_tree_node {
    uint64_t key_time;   /* primary key: start (fair) or deadline (DL) */
    uint64_t key_tid;    /* unique tie-breaker */
    uint64_t finish;     /* node value: fair finish or DL deadline */
    uint32_t weight;     /* fair weight, or UINT32_MAX when not fair */
    uint32_t color;      /* SCHED_TREE_RED / SCHED_TREE_BLACK */
    uint64_t min_finish; /* subtree invariant */
    uint32_t min_weight; /* subtree invariant */
    struct sched_tree_node *left;
    struct sched_tree_node *right;
    struct sched_tree_node *parent;
} sched_tree_node_t;

enum {
    SCHED_TREE_BLACK = 0,
    SCHED_TREE_RED = 1,
};

typedef struct sched_tree {
    sched_tree_node_t *root;
    uint32_t count;
    uint64_t weight_sum; /* sum of fair weights of the nodes in the tree */
} sched_tree_t;

void sched_tree_init(sched_tree_t *tree);

/* Initialize a node before its first insertion. */
void sched_tree_init_node(sched_tree_node_t *node);

/* Insert @node. The caller sets key_time, key_tid, finish and weight first. A
 * node must not already be linked.
 *
 * Returns false when the key is already present (a duplicate identity is a
 * scheduler bug).
 */
bool sched_tree_insert(sched_tree_t *tree, sched_tree_node_t *node);

/* Remove @node from @tree. */
void sched_tree_remove(sched_tree_t *tree, sched_tree_node_t *node);

/* Leftmost node (earliest key), or NULL. */
sched_tree_node_t *sched_tree_first(const sched_tree_t *tree);

/* True when any node has key_time <= @eligible_time. */
bool sched_tree_has_eligible(const sched_tree_t *tree, uint64_t eligible_time);

/* Select the eligible node (start <= @eligible_time) with the earliest finish
 * time, as described by Zircon's find_earliest_eligible_thread.
 * Returns NULL when no node is eligible.
 */
sched_tree_node_t *sched_tree_pick_eligible(const sched_tree_t *tree,
                                            uint64_t eligible_time);

/* Recompute the augmented invariants and red-black properties.
 *
 * Returns true when the tree is well formed; used by host unit tests and debug
 * builds.
 */
bool sched_tree_validate(const sched_tree_t *tree);
