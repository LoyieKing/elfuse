/*
 * Linux futex emulation
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hash table of wait queues keyed by guest virtual address. Supports
 * FUTEX_WAIT, FUTEX_WAKE, FUTEX_WAIT_BITSET, FUTEX_WAKE_BITSET, FUTEX_REQUEUE,
 * FUTEX_CMP_REQUEUE, FUTEX_WAKE_OP, and PI futexes (FUTEX_LOCK_PI,
 * FUTEX_UNLOCK_PI, FUTEX_TRYLOCK_PI, FUTEX_WAIT_REQUEUE_PI,
 * FUTEX_CMP_REQUEUE_PI). Each waiter has its own condition variable for precise
 * wakeup.
 *
 * This header deliberately does not include runtime/thread.h: thread.h embeds
 * futex_pi_task_t, so the dependency runs the other way. Public entry points
 * spell the task type as struct thread_entry and take a pointer; thread_entry_t
 * is the same type.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "core/guest.h"
#include "runtime/sched/sched.h"

struct thread_entry;

/* Per-task PI bookkeeping, embedded in struct thread_entry and zeroed on slot
 * allocation (all-zero is the empty state). Every field is protected by the
 * futex module's PI mutex, never by the task lock.
 *
 * locks PI locks this task owns that currently have waiters. The owner of
 *            a lock inherits the maximum effective key of the waiters on those
 *            locks.
 * blocked_on This task's own PI waiter record while it is blocked acquiring a
 *            PI lock. The chain blocked_on -> lock -> owner is the basis for
 *            cycle detection and transitive donation.
 * base_key Last sampled base (unboosted) scheduler key. The scheduler exposes
 *            only the effective key, so a task that is already boosted is
 *            cleared once to sample the base; a base attribute change
 *            invalidates this cache.
 * applied_key The PI override last published to the scheduler, so a
 *            recomputation that changes nothing does not requeue the task.
 */
struct futex_pi_lock;
struct futex_waiter;

typedef struct futex_pi_task {
    struct futex_pi_lock *locks;
    struct futex_waiter *blocked_on;
    sched_pi_key_t base_key;
    sched_pi_key_t applied_key;
    bool base_valid;
    bool applied;
} futex_pi_task_t;

/* Initialize the futex subsystem. Call once at startup. */
void futex_init(void);

/* Interrupt blocking futex waits without requesting process exit. Used when
 * thread lifecycle events should wake waiters with EINTR.
 */
void futex_interrupt_request(void);
void futex_interrupt_clear(void);
int futex_interrupt_consume(void);

/* Tell @t that a signal it can take was queued, and complete its parked futex
 * wait with EINTR or the operation's post-requeue result. The kick is
 * remembered, so one that lands before @t parks is answered when it does.
 */
void futex_kick(struct thread_entry *t);

/* Main futex syscall entry point. op: futex operation (FUTEX_WAIT, FUTEX_WAKE,
 * etc.) uaddr: guest virtual address of the futex word val: expected value
 * (WAIT) or max wakeups (WAKE) timeout_gva: guest pointer to timespec (or 0 for
 * no timeout) uaddr2: second futex address (for REQUEUE/CMP_REQUEUE/WAKE_OP)
 * val3: bitset (for WAIT_BITSET/WAKE_BITSET)
 * Returns 0 on success, negative Linux errno on failure.
 */
int64_t sys_futex(guest_t *g,
                  uint64_t uaddr,
                  int op,
                  uint32_t val,
                  uint64_t timeout_gva,
                  uint64_t uaddr2,
                  uint32_t val3);

/* Wake up to 1 waiter at uaddr. Used by thread exit for CLONE_CHILD_CLEARTID
 * cleanup.
 *
 * Returns number of waiters woken.
 */
int futex_wake_one(guest_t *g, uint64_t uaddr);

/* futex_waitv (SYS 449): batch wait on multiple futex addresses. clockid
 * selects the timeout clock (Linux CLOCK_REALTIME=0 or CLOCK_MONOTONIC=1);
 * ignored when timeout_gva==0.
 * Returns the index of the woken futex, or negative errno.
 */
int64_t sys_futex_waitv(guest_t *g,
                        uint64_t waiters_gva,
                        uint32_t nr_futexes,
                        uint32_t flags,
                        uint64_t timeout_gva,
                        int clockid);

/* Walk the robust futex list on thread exit and set FUTEX_OWNER_DIED on each
 * held lock. Wakes one waiter per lock so a new owner can acquire it and see
 * EOWNERDEAD.
 */
void robust_list_walk(guest_t *g, struct thread_entry *t);

/* Non-robust PI owner exit: mark OWNER_DIED on every PI lock this task still
 * owns with waiters, hand the lock to the highest-priority waiter, and drop the
 * task's PI state. Called while @t is still active so owner records remain
 * valid.
 */
void futex_pi_owner_exit(guest_t *g, struct thread_entry *t);

/* Drop all PI bookkeeping owned by @t. Called after futex_pi_owner_exit and
 * before the task slot may be recycled; frees lock and waiter records that
 * still refer to @t and releases task references held for PI state.
 */
void futex_pi_task_release(struct thread_entry *t);

/* Recompute the effective priority @t inherits after its own base attributes
 * changed. Called by the scheduler after a successful attribute update.
 */
void futex_pi_task_priority_changed(struct thread_entry *t);

/* Exec/de_thread teardown: retire @t's futex park synchronously after the task
 * has been claimed DEAD and will never remount. Covers FUTEX_WAIT, PI waits,
 * and futex_waitv groups. Does not enqueue the dead task; safe when no park is
 * active.
 */
void futex_task_cancel_wait(struct thread_entry *t);

/* Async park (pool unmount): deadline / signal completion for a thread that
 * returned SYSCALL_PARKED from FUTEX_WAIT / WAIT_BITSET.
 */
void futex_park_on_deadline(struct thread_entry *t);
void futex_park_on_interrupt(struct thread_entry *t);
