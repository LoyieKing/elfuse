/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "runtime/sched/fair.h"
#include "test-harness.h"

#define NODE_COUNT 257

static uint32_t random_next(uint32_t *seed)
{
    *seed = *seed * 1664525U + 1013904223U;
    return *seed;
}

int main(void)
{
    int passes = 0, fails = 0;
    sched_tree_t tree;
    sched_tree_node_t nodes[NODE_COUNT];
    unsigned order[NODE_COUNT];
    uint32_t seed = 17;
    sched_tree_init(&tree);
    memset(nodes, 0, sizeof(nodes));
    bool valid = true;
    for (unsigned i = 0; i < NODE_COUNT; i++) {
        sched_tree_init_node(&nodes[i]);
        nodes[i].key_time = random_next(&seed) % 100;
        nodes[i].key_tid = i;
        nodes[i].finish = nodes[i].key_time + 1 + random_next(&seed) % 1000;
        nodes[i].weight = 1 + random_next(&seed) % 90000;
        order[i] = i;
        valid &= sched_tree_insert(&tree, &nodes[i]);
        valid &= sched_tree_validate(&tree);
    }
    TEST("insert preserves balanced queue");
    EXPECT_TRUE(valid, "run queue lost an insertion or tree invariant");

    bool selection_ok = true;
    for (uint64_t now = 0; now <= 100; now++) {
        sched_tree_node_t *chosen = sched_tree_pick_eligible(&tree, now);
        uint64_t earliest = UINT64_MAX;
        bool any = false;
        for (unsigned i = 0; i < NODE_COUNT; i++) {
            if (nodes[i].key_time <= now) {
                any = true;
                if (nodes[i].finish < earliest)
                    earliest = nodes[i].finish;
            }
        }
        selection_ok &= chosen ? any && chosen->key_time <= now &&
                                     chosen->finish == earliest
                               : !any;
    }
    TEST("pick earliest eligible finish");
    EXPECT_TRUE(selection_ok, "ineligible or later-finishing task selected");

    /* Rotation regression: inserting 10,20,30 rotates 20 above 10. The sinking
     * node must drop the rotated-away subtree's minimum; a stale augmentation
     * makes the eligibility search descend into a subtree that no longer holds
     * that finish.
     */
    sched_tree_t rotated;
    sched_tree_node_t rotated_nodes[3];
    const uint64_t rotated_keys[3] = {10, 20, 30};
    const uint64_t rotated_finish[3] = {100, 50, 200};
    bool rotate_ok = true;
    sched_tree_init(&rotated);
    memset(rotated_nodes, 0, sizeof(rotated_nodes));
    for (unsigned i = 0; i < 3; i++) {
        sched_tree_init_node(&rotated_nodes[i]);
        rotated_nodes[i].key_time = rotated_keys[i];
        rotated_nodes[i].key_tid = i;
        rotated_nodes[i].finish = rotated_finish[i];
        rotated_nodes[i].weight = 10 + i;
        rotate_ok &= sched_tree_insert(&rotated, &rotated_nodes[i]);
        rotate_ok &= sched_tree_validate(&rotated);
    }
    TEST("rotation refreshes augmentation");
    EXPECT_TRUE(rotate_ok, "rotation left a stale min_finish/min_weight");

    /* Removal regression: deleting 500 then 100 rotates inside the delete
     * fixup; the surviving 400 node must lose the removed subtree's minimum.
     */
    sched_tree_t deleted;
    sched_tree_node_t deleted_nodes[5];
    const uint64_t deleted_keys[5] = {100, 200, 300, 400, 500};
    const uint64_t deleted_finish[5] = {1085, 1174, 1180, 1306, 1260};
    const uint32_t deleted_weight[5] = {48, 66, 31, 84, 19};
    bool delete_ok = true;
    sched_tree_init(&deleted);
    memset(deleted_nodes, 0, sizeof(deleted_nodes));
    for (unsigned i = 0; i < 5; i++) {
        sched_tree_init_node(&deleted_nodes[i]);
        deleted_nodes[i].key_time = deleted_keys[i];
        deleted_nodes[i].key_tid = i;
        deleted_nodes[i].finish = deleted_finish[i];
        deleted_nodes[i].weight = deleted_weight[i];
        delete_ok &= sched_tree_insert(&deleted, &deleted_nodes[i]);
    }
    delete_ok &= sched_tree_validate(&deleted);
    sched_tree_remove(&deleted, &deleted_nodes[4]);
    delete_ok &= sched_tree_validate(&deleted);
    sched_tree_remove(&deleted, &deleted_nodes[0]);
    delete_ok &= sched_tree_validate(&deleted);
    TEST("removal refreshes augmentation");
    EXPECT_TRUE(delete_ok, "delete left a stale min_finish/min_weight");

    for (unsigned i = NODE_COUNT - 1; i > 0; i--) {
        unsigned j = random_next(&seed) % (i + 1);
        unsigned tmp = order[i];
        order[i] = order[j];
        order[j] = tmp;
    }
    valid = true;
    for (unsigned i = 0; i < NODE_COUNT; i++) {
        sched_tree_remove(&tree, &nodes[order[i]]);
        valid &= sched_tree_validate(&tree);
        valid &= tree.count == NODE_COUNT - i - 1;
    }
    TEST("arbitrary removal preserves queue");
    EXPECT_TRUE(valid && !tree.root && !tree.weight_sum,
                "removal corrupted links, balance or weight accounting");

    uint32_t slope = sched_fair_slope_q10(15, 88761 + 15);
    uint64_t real = sched_fair_real_ns(1000, slope);
    TEST("expanded period converts budget safely");
    EXPECT_TRUE(
        real >= 1000 && sched_fair_virtual_delta_ns(real, slope) >= 1000,
        "round-trip conversion shortened the virtual budget");
    TEST("higher nice reduces fair weight");
    EXPECT_TRUE(
        sched_fair_weight_from_nice(-20) > sched_fair_weight_from_nice(0) &&
            sched_fair_weight_from_nice(0) > sched_fair_weight_from_nice(19),
        "nice order inverted fair bandwidth");
    SUMMARY("test-sched-fair-host");
    return fails != 0;
}
