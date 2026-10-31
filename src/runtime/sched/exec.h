/*
 * Task execution/resume protocol
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * State written by the owner vCPU worker, by a syscall handler, or by a waker
 * on an arbitrary thread, and consumed by the outer execution loop. The
 * scheduler never interprets these values: it only queues the task.
 */

#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/* What the owner worker must do before entering the guest after a mount.
 *
 * PLAIN restore the saved context and enter. This covers a first
 *                mount, a plain yield/preemption, and a ptrace/group-stop
 *                resumption whose interrupted tail needs no syscall work.
 * SYSCALL_TAIL the task was stopped after a completed syscall dispatch but
 *                before its return tail ran; finish that tail exactly once.
 * HVC10_TAIL the task was stopped inside the shim's HVC #10 BRK handler,
 *                where the saved SAVE_GPRS frame is still live and its tail
 *                reloads X8 from it; republish the tracer's architectural X8
 *                and enter.  No syscall work is owed.
 * RESULT a parked continuation completed with a result: inject X0 and
 *                finish the return tail.
 * REISSUE a parked continuation must re-dispatch its SVC and finish the
 *                return tail (IO retry, restartable wait, wait4 re-check).
 */
enum exec_resume {
    EXEC_RESUME_PLAIN = 0,
    EXEC_RESUME_SYSCALL_TAIL,
    EXEC_RESUME_RESULT,
    EXEC_RESUME_REISSUE,
    EXEC_RESUME_HVC10_TAIL,
};

/* park_resume argument for exec_park_current(): what the task should do when
 * the parked stop is released. A driver waiting for an event uses REISSUE when
 * its syscall must re-run; a stopped task itself uses PLAIN or SYSCALL_TAIL.
 */
enum exec_park_resume {
    EXEC_PARK_RESUME_PLAIN = 0,
    EXEC_PARK_RESUME_SYSCALL_TAIL,
};

/* Park publication. The owner worker arms a park and publishes it; a waker on
 * any thread may complete it; the owner consumes the completion on remount.
 * Every field reached through these macros is _Atomic in thread_entry, so the
 * explicit orderings live here instead of being spelled at each call site:
 *
 *   - An arm stores the fields describing the wait (kind, result direction,
 *     deadline, waiter) and publishes park_active with release.  A waker that
 *     acquires park_active observes every one of them.
 *   - A completion stores park_result first and park_result_pending with
 *     release.  The owner acquires park_result_pending before reading the
 *     result.
 *
 * park_restart_forbid and async_futex_requeue_pi_restart are the two
 * classification bits a waker writes and the owner consumes; both have their
 * own macros below and are never touched directly.
 */
#define exec_park_kind_load(t) \
    atomic_load_explicit(&(t)->park_kind, memory_order_acquire)
#define exec_park_kind_store(t, v) \
    atomic_store_explicit(&(t)->park_kind, (v), memory_order_release)
#define exec_park_active_load(t) \
    atomic_load_explicit(&(t)->park_active, memory_order_acquire)
#define exec_park_active_store(t, v) \
    atomic_store_explicit(&(t)->park_active, (v), memory_order_release)
#define exec_park_result_pending_load(t) \
    atomic_load_explicit(&(t)->park_result_pending, memory_order_acquire)
#define exec_park_result_pending_store(t, v) \
    atomic_store_explicit(&(t)->park_result_pending, (v), memory_order_release)
#define exec_park_reissue_load(t) \
    atomic_load_explicit(&(t)->park_reissue, memory_order_acquire)
#define exec_park_reissue_store(t, v) \
    atomic_store_explicit(&(t)->park_reissue, (v), memory_order_release)
#define exec_park_result_load(t) \
    atomic_load_explicit(&(t)->park_result, memory_order_acquire)
#define exec_park_result_store(t, v) \
    atomic_store_explicit(&(t)->park_result, (v), memory_order_release)
#define exec_park_deadline_ns_load(t) \
    atomic_load_explicit(&(t)->wait_deadline_ns, memory_order_acquire)
#define exec_park_deadline_ns_store(t, v) \
    atomic_store_explicit(&(t)->wait_deadline_ns, (v), memory_order_release)
#define exec_park_waiter_load(t) \
    atomic_load_explicit(&(t)->async_futex_waiter, memory_order_acquire)
#define exec_park_waiter_store(t, v) \
    atomic_store_explicit(&(t)->async_futex_waiter, (v), memory_order_release)

/* FUTEX_WAIT_REQUEUE_PI's forced restart (Linux ERESTARTNOINTR). A waker
 * publishes it together with an EINTR park result; the owner consumes it on
 * remount and must not let signal delivery cancel that rewind.
 */
#define exec_park_requeue_pi_load(t)                           \
    atomic_load_explicit(&(t)->async_futex_requeue_pi_restart, \
                         memory_order_acquire)
#define exec_park_requeue_pi_set(t, v)                               \
    atomic_store_explicit(&(t)->async_futex_requeue_pi_restart, (v), \
                          memory_order_release)
#define exec_park_requeue_pi_take(t)                                      \
    atomic_exchange_explicit(&(t)->async_futex_requeue_pi_restart, false, \
                             memory_order_acq_rel)

/* Task-owned stop/wake classification, written by wakers on any thread and
 * consumed by proc_resume_task() on the owner worker. False means the parked
 * syscall result is delivered exactly as published.
 */
#define exec_restart_forbid_load(t) \
    atomic_load_explicit(&(t)->park_restart_forbid, memory_order_acquire)
#define exec_restart_forbid_set(t, v) \
    atomic_store_explicit(&(t)->park_restart_forbid, (v), memory_order_release)
#define exec_restart_forbid_take(t)                            \
    atomic_exchange_explicit(&(t)->park_restart_forbid, false, \
                             memory_order_acq_rel)
