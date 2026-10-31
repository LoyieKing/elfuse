/*
 * Fair-scheduling math and augmented run queue
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2026 The Fuchsia Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Run-queue selection, the start-time ordered augmented tree and the
 * period/slope relations are derived from the Zircon fair scheduler at commit
 * 966c936b56d8d117a26ecbf2c583ec350b2325c8 (zircon/kernel/kernel/scheduler.rs).
 * Zircon is distributed under a MIT-style license; see the pinned reference in
 * docs/scheduler.md.
 */

#include "runtime/sched/fair.h"

#include <stdint.h>
#include <string.h>

/* Exponential nice -> weight table for nice in [-20, 19]. Index = nice + 20.
 * Generated from weight(n) = round(1024 * 1.25^-n); a nice step is about 20% of
 * bandwidth, matching the Linux scheduling weight relation.
 */
static const uint32_t nice_to_weight[40] = {
    /* -20 .. -11 */
    88761,
    71755,
    56483,
    46273,
    36291,
    29154,
    23254,
    18705,
    15091,
    11916,
    /* -10 .. -1 */
    9548,
    7629,
    6100,
    4904,
    3906,
    3121,
    2501,
    1991,
    1586,
    1277,
    /* 0 .. 9 */
    1024,
    820,
    655,
    526,
    423,
    335,
    272,
    215,
    172,
    137,
    /* 10 .. 19 */
    110,
    87,
    70,
    56,
    45,
    36,
    29,
    23,
    18,
    15,
};

uint32_t sched_fair_weight_from_nice(int nice)
{
    if (nice < -20)
        nice = -20;
    if (nice > 19)
        nice = 19;
    return nice_to_weight[nice + 20];
}

uint32_t sched_fair_slope_q10(uint32_t min_weight, uint64_t weight_sum)
{
    if (weight_sum == 0 || min_weight == 0)
        return SCHED_FAIR_SLOPE_ONE;

    /* slope = 10 * min_weight / weight_sum, in Q10. The constant is 10 * 1024,
     * i.e. K_MIN_FAIR_UTILIZATION = 1 ms / 10 ms expressed in the same Q10
     * slope domain as Zircon's Affine::K_PRECISION_BITS.
     */
    uint64_t q = (uint64_t) min_weight * (10ULL * SCHED_FAIR_SLOPE_ONE);
    q /= weight_sum;

    if (q == 0)
        q = 1;
    if (q > SCHED_FAIR_SLOPE_ONE)
        q = SCHED_FAIR_SLOPE_ONE;
    return (uint32_t) q;
}

uint64_t sched_fair_period_ns(uint32_t slope_q10)
{
    if (slope_q10 == 0)
        slope_q10 = 1;
    if (slope_q10 > SCHED_FAIR_SLOPE_ONE)
        slope_q10 = SCHED_FAIR_SLOPE_ONE;
    return (SCHED_DEFAULT_FAIR_PERIOD_NS * SCHED_FAIR_SLOPE_ONE) / slope_q10;
}

uint64_t sched_fair_slice_ns(uint32_t weight, uint64_t weight_sum)
{
    if (weight == 0 || weight_sum == 0)
        return SCHED_DEFAULT_FAIR_PERIOD_NS;

    uint64_t slice =
        (SCHED_DEFAULT_FAIR_PERIOD_NS * (uint64_t) weight) / weight_sum;
    if (slice == 0)
        slice = 1;
    return slice;
}

uint64_t sched_fair_virtual_delta_ns(uint64_t actual_ns, uint32_t slope_q10)
{
    if (slope_q10 >= SCHED_FAIR_SLOPE_ONE)
        return actual_ns;

    /* Round to the nearest virtual nanosecond; truncation would let a task that
     * runs in many short bursts consume less virtual budget than one that runs
     * in a single long burst.
     */
    return (actual_ns * (uint64_t) slope_q10 + SCHED_FAIR_SLOPE_ONE / 2) /
           SCHED_FAIR_SLOPE_ONE;
}

uint64_t sched_fair_real_ns(uint64_t virtual_ns, uint32_t slope_q10)
{
    if (slope_q10 >= SCHED_FAIR_SLOPE_ONE)
        return virtual_ns;
    if (slope_q10 == 0)
        slope_q10 = 1;

    /* Round up: a slice timer must not fire while virtual budget remains. */
    return (virtual_ns * SCHED_FAIR_SLOPE_ONE + slope_q10 - 1) / slope_q10;
}

/* Augmented red-black run queue */

static uint64_t node_min_finish(const sched_tree_node_t *n)
{
    return n ? n->min_finish : UINT64_MAX;
}

static uint32_t node_min_weight(const sched_tree_node_t *n)
{
    return n ? n->min_weight : UINT32_MAX;
}

static void tree_pull(sched_tree_node_t *n)
{
    if (!n)
        return;
    n->min_finish = n->finish;
    if (node_min_finish(n->left) < n->min_finish)
        n->min_finish = node_min_finish(n->left);
    if (node_min_finish(n->right) < n->min_finish)
        n->min_finish = node_min_finish(n->right);

    n->min_weight = n->weight;
    if (node_min_weight(n->left) < n->min_weight)
        n->min_weight = node_min_weight(n->left);
    if (node_min_weight(n->right) < n->min_weight)
        n->min_weight = node_min_weight(n->right);
}

static void tree_pull_up(sched_tree_node_t *n)
{
    while (n) {
        tree_pull(n);
        n = n->parent;
    }
}

static int node_cmp(const sched_tree_node_t *a, const sched_tree_node_t *b)
{
    if (a->key_time < b->key_time)
        return -1;
    if (a->key_time > b->key_time)
        return 1;
    if (a->key_tid < b->key_tid)
        return -1;
    if (a->key_tid > b->key_tid)
        return 1;
    return 0;
}

static bool is_red(const sched_tree_node_t *n)
{
    return n && n->color == SCHED_TREE_RED;
}

static sched_tree_node_t *tree_min(sched_tree_node_t *n)
{
    while (n && n->left)
        n = n->left;
    return n;
}

static void rotate_left(sched_tree_t *tree, sched_tree_node_t *x)
{
    sched_tree_node_t *y = x->right;
    if (!y)
        return;

    x->right = y->left;
    if (y->left)
        y->left->parent = x;
    y->parent = x->parent;
    if (!x->parent)
        tree->root = y;
    else if (x == x->parent->left)
        x->parent->left = y;
    else
        x->parent->right = y;
    y->left = x;
    x->parent = y;

    /* Recompute both endpoints after the links move: x lost the y subtree and y
     * gained x. Pull x first because y's augmentation reads it.
     */
    tree_pull(x);
    tree_pull(y);
}

static void rotate_right(sched_tree_t *tree, sched_tree_node_t *x)
{
    sched_tree_node_t *y = x->left;
    if (!y)
        return;

    x->left = y->right;
    if (y->right)
        y->right->parent = x;
    y->parent = x->parent;
    if (!x->parent)
        tree->root = y;
    else if (x == x->parent->right)
        x->parent->right = y;
    else
        x->parent->left = y;
    y->right = x;
    x->parent = y;

    /* Same ordering as rotate_left: the sinking node first, then the rising
     * node that now contains it.
     */
    tree_pull(x);
    tree_pull(y);
}

static sched_tree_node_t *tree_find(const sched_tree_t *tree,
                                    const sched_tree_node_t *key)
{
    sched_tree_node_t *n = tree->root;
    while (n) {
        int c = node_cmp(key, n);
        if (c == 0)
            return n;
        n = c < 0 ? n->left : n->right;
    }
    return NULL;
}

void sched_tree_init(sched_tree_t *tree)
{
    if (!tree)
        return;
    memset(tree, 0, sizeof(*tree));
}

void sched_tree_init_node(sched_tree_node_t *node)
{
    if (!node)
        return;
    memset(node, 0, sizeof(*node));
    node->weight = UINT32_MAX;
    node->min_finish = UINT64_MAX;
    node->min_weight = UINT32_MAX;
    node->color = SCHED_TREE_BLACK;
}

bool sched_tree_insert(sched_tree_t *tree, sched_tree_node_t *node)
{
    if (!tree || !node)
        return false;
    if (node->left || node->right || node->parent)
        return false;
    if (tree_find(tree, node))
        return false;

    node->left = node->right = node->parent = NULL;
    node->color = SCHED_TREE_RED;
    tree_pull(node);

    sched_tree_node_t *parent = NULL;
    sched_tree_node_t *cur = tree->root;
    while (cur) {
        parent = cur;
        cur = node_cmp(node, cur) < 0 ? cur->left : cur->right;
    }
    node->parent = parent;
    if (!parent)
        tree->root = node;
    else if (node_cmp(node, parent) < 0)
        parent->left = node;
    else
        parent->right = node;

    /* Red-black insertion fixup. */
    sched_tree_node_t *z = node;
    while (z->parent && is_red(z->parent)) {
        sched_tree_node_t *p = z->parent;
        sched_tree_node_t *g = p->parent;
        if (!g)
            break;
        if (p == g->left) {
            sched_tree_node_t *u = g->right;
            if (is_red(u)) {
                p->color = SCHED_TREE_BLACK;
                u->color = SCHED_TREE_BLACK;
                g->color = SCHED_TREE_RED;
                z = g;
            } else {
                if (z == p->right) {
                    z = p;
                    rotate_left(tree, z);
                    p = z->parent;
                    g = p ? p->parent : NULL;
                }
                if (!p || !g)
                    break;
                p->color = SCHED_TREE_BLACK;
                g->color = SCHED_TREE_RED;
                rotate_right(tree, g);
            }
        } else {
            sched_tree_node_t *u = g->left;
            if (is_red(u)) {
                p->color = SCHED_TREE_BLACK;
                u->color = SCHED_TREE_BLACK;
                g->color = SCHED_TREE_RED;
                z = g;
            } else {
                if (z == p->left) {
                    z = p;
                    rotate_right(tree, z);
                    p = z->parent;
                    g = p ? p->parent : NULL;
                }
                if (!p || !g)
                    break;
                p->color = SCHED_TREE_BLACK;
                g->color = SCHED_TREE_RED;
                rotate_left(tree, g);
            }
        }
    }
    if (tree->root)
        tree->root->color = SCHED_TREE_BLACK;

    tree_pull_up(node);
    tree->count++;
    tree->weight_sum += node->weight;
    return true;
}

static void tree_transplant(sched_tree_t *tree,
                            sched_tree_node_t *u,
                            sched_tree_node_t *v)
{
    if (!u->parent)
        tree->root = v;
    else if (u == u->parent->left)
        u->parent->left = v;
    else
        u->parent->right = v;
    if (v)
        v->parent = u->parent;
}

static void delete_fixup(sched_tree_t *tree,
                         sched_tree_node_t *x,
                         sched_tree_node_t *x_parent)
{
    while (x != tree->root && !is_red(x)) {
        if (!x_parent)
            break;
        if (x == x_parent->left) {
            sched_tree_node_t *w = x_parent->right;
            if (is_red(w)) {
                w->color = SCHED_TREE_BLACK;
                x_parent->color = SCHED_TREE_RED;
                rotate_left(tree, x_parent);
                w = x_parent->right;
            }
            if (!w) {
                x = x_parent;
                x_parent = x->parent;
                continue;
            }
            if (!is_red(w->left) && !is_red(w->right)) {
                w->color = SCHED_TREE_RED;
                x = x_parent;
                x_parent = x->parent;
            } else {
                if (!is_red(w->right)) {
                    if (w->left)
                        w->left->color = SCHED_TREE_BLACK;
                    w->color = SCHED_TREE_RED;
                    rotate_right(tree, w);
                    w = x_parent->right;
                }
                if (!w)
                    break;
                w->color = x_parent->color;
                x_parent->color = SCHED_TREE_BLACK;
                if (w->right)
                    w->right->color = SCHED_TREE_BLACK;
                rotate_left(tree, x_parent);
                x = tree->root;
                x_parent = NULL;
            }
        } else {
            sched_tree_node_t *w = x_parent->left;
            if (is_red(w)) {
                w->color = SCHED_TREE_BLACK;
                x_parent->color = SCHED_TREE_RED;
                rotate_right(tree, x_parent);
                w = x_parent->left;
            }
            if (!w) {
                x = x_parent;
                x_parent = x->parent;
                continue;
            }
            if (!is_red(w->left) && !is_red(w->right)) {
                w->color = SCHED_TREE_RED;
                x = x_parent;
                x_parent = x->parent;
            } else {
                if (!is_red(w->left)) {
                    if (w->right)
                        w->right->color = SCHED_TREE_BLACK;
                    w->color = SCHED_TREE_RED;
                    rotate_left(tree, w);
                    w = x_parent->left;
                }
                if (!w)
                    break;
                w->color = x_parent->color;
                x_parent->color = SCHED_TREE_BLACK;
                if (w->left)
                    w->left->color = SCHED_TREE_BLACK;
                rotate_right(tree, x_parent);
                x = tree->root;
                x_parent = NULL;
            }
        }
    }
    if (x)
        x->color = SCHED_TREE_BLACK;
}

void sched_tree_remove(sched_tree_t *tree, sched_tree_node_t *node)
{
    if (!tree || !node || !tree->root)
        return;

    sched_tree_node_t *y = node;
    uint32_t y_original_color = y->color;
    sched_tree_node_t *x = NULL;
    sched_tree_node_t *x_parent = NULL;

    if (!node->left) {
        x = node->right;
        x_parent = node->parent;
        tree_transplant(tree, node, node->right);
        if (x)
            x_parent = x->parent;
    } else if (!node->right) {
        x = node->left;
        x_parent = node->parent;
        tree_transplant(tree, node, node->left);
        if (x)
            x_parent = x->parent;
    } else {
        y = tree_min(node->right);
        y_original_color = y->color;
        x = y->right;
        if (y->parent == node) {
            x_parent = y;
            if (x)
                x->parent = y;
        } else {
            x_parent = y->parent;
            tree_transplant(tree, y, y->right);
            y->right = node->right;
            y->right->parent = y;
        }
        tree_transplant(tree, node, y);
        y->left = node->left;
        y->left->parent = y;
        y->color = node->color;
    }

    if (tree->count > 0)
        tree->count--;
    if (tree->weight_sum >= node->weight)
        tree->weight_sum -= node->weight;
    else
        tree->weight_sum = 0;

    if (y_original_color == SCHED_TREE_BLACK)
        delete_fixup(tree, x, x_parent);

    /* Recompute the augmentation along the affected path. Pulling up from the
     * replacement node (or its parent when the replacement is NULL) covers
     * every subtree whose membership changed, including rotation endpoints.
     */
    if (x)
        tree_pull_up(x);
    else if (x_parent)
        tree_pull_up(x_parent);
    else if (tree->root)
        tree_pull_up(tree->root);

    node->left = node->right = node->parent = NULL;
    node->color = SCHED_TREE_BLACK;
}

sched_tree_node_t *sched_tree_first(const sched_tree_t *tree)
{
    if (!tree)
        return NULL;
    return tree_min(tree->root);
}

bool sched_tree_has_eligible(const sched_tree_t *tree, uint64_t eligible_time)
{
    sched_tree_node_t *first = sched_tree_first(tree);
    return first && first->key_time <= eligible_time;
}

sched_tree_node_t *sched_tree_pick_eligible(const sched_tree_t *tree,
                                            uint64_t eligible_time)
{
    if (!tree || !tree->root)
        return NULL;

    sched_tree_node_t *front = tree_min(tree->root);
    if (!front || front->key_time > eligible_time)
        return NULL;

    /* Descend the tree, keeping the eligible node with the earliest finish on
     * the path and the left subtree with the earliest finish. This is the
     * augmented search described by Zircon's find_earliest_eligible_thread.
     */
    sched_tree_node_t *node = tree->root;
    sched_tree_node_t *path = NULL;
    sched_tree_node_t *subtree = NULL;

    while (node) {
        if (node->key_time <= eligible_time) {
            if (!path || path->finish > node->finish)
                path = node;

            if (node->left) {
                if (!subtree || subtree->min_finish > node->left->min_finish)
                    subtree = node->left;
            }
            node = node->right;
        } else {
            node = node->left;
        }
    }

    if (!subtree)
        return path;

    if (path && subtree->min_finish >= path->finish)
        return path;

    uint64_t target = subtree->min_finish;
    node = subtree;
    while (node) {
        if (node->finish == target)
            return node;
        if (node->left && node->left->min_finish == target)
            node = node->left;
        else if (node->right && node->right->min_finish == target)
            node = node->right;
        else
            break;
    }
    return NULL;
}

/* Validation */

static bool validate_subtree(const sched_tree_node_t *n,
                             const sched_tree_node_t *min,
                             const sched_tree_node_t *max,
                             int *black_height,
                             uint32_t *count,
                             uint64_t *weight_sum)
{
    if (!n) {
        *black_height = 1;
        return true;
    }

    if (min && node_cmp(n, min) <= 0)
        return false;
    if (max && node_cmp(n, max) >= 0)
        return false;
    if (is_red(n) && (is_red(n->left) || is_red(n->right)))
        return false;
    if (n->left && n->left->parent != n)
        return false;
    if (n->right && n->right->parent != n)
        return false;

    uint64_t expect_finish = n->finish;
    uint32_t expect_weight = n->weight;
    if (n->left) {
        if (n->left->min_finish < expect_finish)
            expect_finish = n->left->min_finish;
        if (n->left->min_weight < expect_weight)
            expect_weight = n->left->min_weight;
    }
    if (n->right) {
        if (n->right->min_finish < expect_finish)
            expect_finish = n->right->min_finish;
        if (n->right->min_weight < expect_weight)
            expect_weight = n->right->min_weight;
    }
    if (n->min_finish != expect_finish || n->min_weight != expect_weight)
        return false;

    (*count)++;
    *weight_sum += n->weight;

    int lh = 0, rh = 0;
    if (!validate_subtree(n->left, min, n, &lh, count, weight_sum))
        return false;
    if (!validate_subtree(n->right, n, max, &rh, count, weight_sum))
        return false;
    if (lh != rh)
        return false;
    *black_height = lh + (is_red(n) ? 0 : 1);
    return true;
}

bool sched_tree_validate(const sched_tree_t *tree)
{
    if (!tree)
        return false;
    if (!tree->root)
        return tree->count == 0 && tree->weight_sum == 0;
    if (tree->root->parent || is_red(tree->root))
        return false;

    int bh = 0;
    uint32_t count = 0;
    uint64_t weight_sum = 0;
    if (!validate_subtree(tree->root, NULL, NULL, &bh, &count, &weight_sum))
        return false;
    return count == tree->count && weight_sum == tree->weight_sum;
}
