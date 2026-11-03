/*
 * Per-thread state for Linux threading support
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Thread table with _Thread_local fast path for current thread access.
 * Protected by a mutex since thread creation/destruction is infrequent relative
 * to per-syscall access (which uses the lock-free TLS pointer).
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"

#include "runtime/thread.h"
#include "runtime/sched/sched.h"
#include "runtime/sched/vcpu_pool.h"
#include "debug/log.h"
#include "core/guest.h" /* guest_t (shim_data_base/ipa_base), BLOCK_2MIB */
#include "core/shim-globals.h" /* SHIM_GLOBALS_SIZE: SP_EL1 pool floor */
#include "hvutil.h"            /* vcpu_get_gpr, vcpu_get_sysreg */
#include "runtime/futex.h"     /* futex_interrupt_request */

#include "syscall/exec.h"
#include "syscall/proc.h" /* proc_exit_group_requested */
#include "syscall/io.h"
#include "syscall/mem.h"
#include "syscall/proc-pidfd.h"
#include "syscall/mqueue.h"
#include "syscall/sysvipc.h"
#include "syscall/fuse.h"
#include "syscall/wakeup-pipe.h" /* wakeup_pipe_signal */

/* From syscall/signal.h, included here directly to avoid pulling in the full
 * signal header (macOS defines sa_handler as a macro that conflicts with the
 * linux_sigaction_t field name).
 */
#define LINUX_SS_DISABLE 2

static void thread_ptrace_init(thread_entry_t *t);
static int thread_add_deferred_unmap_locked(thread_entry_t *t,
                                            uint64_t start,
                                            uint64_t end);
static int thread_can_add_deferred_unmap_locked(thread_entry_t *t,
                                                uint64_t start,
                                                uint64_t end);

/* Top of the EL1 exception stack region (one 4KiB slot per thread). The shim
 * data block sits at high IPA, computed at guest_init time and stored in
 * g->shim_data_base; the top of the EL1 stacks is the next 2MiB boundary above
 * that. Caller must hold a guest_t reference.
 */
static inline uint64_t sp_el1_top(const guest_t *g)
{
    return g->ipa_base + g->shim_data_base + BLOCK_2MIB;
}

/* Thread table: array of stable heap entries. Pointers never move once
 * published, so lock-free scanners may walk thread_slots[0..capacity). Capacity
 * grows under thread_lock up to SP_EL1_SLOT_MAX (IPA pool).
 */

/* Residual shim_data IPA above the globals cache, in 4KiB SP_EL1 slots. Align
 * the globals end up to a page so stacks never overlap the cache.
 */
#define SP_EL1_GLOBALS_END                                      \
    (((uint64_t) SHIM_GLOBALS_SIZE + (SP_EL1_SLOT_BYTES - 1)) & \
     ~((uint64_t) SP_EL1_SLOT_BYTES - 1))
#define SP_EL1_SLOT_MAX \
    ((int) ((BLOCK_2MIB - SP_EL1_GLOBALS_END) / SP_EL1_SLOT_BYTES))
#define SP_EL1_BITMAP_WORDS ((SP_EL1_SLOT_MAX + 63) / 64)

/* Seed capacity; grows by doubling until SP_EL1_SLOT_MAX. */
#define THREAD_TABLE_INITIAL_CAP 64

static thread_entry_t *thread_slots[SP_EL1_SLOT_MAX];
static _Atomic int thread_capacity = 0; /* published slots in thread_slots[] */
static thread_entry_t *main_thread_entry = NULL;
/* Ordering: see the lock-ordering block in syscall/internal.h. */
static pthread_mutex_t thread_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic int active_thread_count = 0;
static uint64_t departed_user_ns; /* Protected by thread_lock. */
static uint64_t departed_sys_ns;

/* Atomic idle gate; counters remain protected by thread_lock. */
static _Atomic bool fork_quiesce_active;
static int fork_quiesced_count = 0; /* Siblings blocked on barrier */
static int fork_target_count = 0;   /* Number of siblings to quiesce */
static pthread_cond_t fork_cond = PTHREAD_COND_INITIALIZER;

/* Signalled when a deferred stack-unmap transaction clears. Declared here
 * rather than beside its users because thread_wake_exit_waiters, earlier in the
 * file, has to broadcast it too.
 */
static pthread_cond_t deferred_stack_unmap_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t fork_all_quiesced_cond = PTHREAD_COND_INITIALIZER;

/* Signalled when a quiesce window closes, so an execve teardown can wait for
 * one already open instead of tearing siblings out of it.
 */
static pthread_cond_t fork_window_closed_cond = PTHREAD_COND_INITIALIZER;

/* Defined with the rest of the execve teardown state further down; declared
 * here because thread_quiesce_siblings, above it, refuses to arm while a
 * teardown is running.
 */
static _Atomic bool exec_de_thread_active;

/* Iterate every published slot. Single for-loop so break/continue work
 * (thread_alloc relies on break). Capacity is acquire-loaded so a lock-free
 * walker never races past a pointer that grow has not yet published.
 */
#define THREAD_FOR_EACH(t)                                                   \
    for (thread_entry_t **_thp = thread_slots,                               \
                        **_the = thread_slots +                              \
                                 atomic_load_explicit(&thread_capacity,      \
                                                      memory_order_acquire), \
                        *t = (_thp < _the ? *_thp : NULL);                   \
         _thp < _the; t = (++_thp < _the ? *_thp : NULL))

/* Iterate active slots. Caller must hold thread_lock; the lock already orders
 * these reads against the release-stores of active, so a relaxed atomic load
 * suffices. It is used (rather than a plain read) only to keep every access to
 * active uniformly atomic -- no mixed atomic-write / plain-read on one object.
 */
#define THREAD_FOR_EACH_ACTIVE(t) \
    THREAD_FOR_EACH (t)           \
        if (atomic_load_explicit(&t->active, memory_order_relaxed))

/* Iterate active slots without holding thread_lock. Uses an acquire load on the
 * active flag so the lock-free observers in thread_tid_alive() and
 * thread_signal_deliverable() see a consistent transition.
 */
#define THREAD_FOR_EACH_ACTIVE_RELAXED(t) \
    THREAD_FOR_EACH (t)                   \
        if (atomic_load_explicit(&t->active, memory_order_acquire))

/* Bitmap tracking allocated SP_EL1 slots. Bit N set = slot N in use. Sized for
 * SP_EL1_SLOT_MAX (shim_data residual), not a fixed 64. Slot 0 is the main
 * thread (top of shim data region); each subsequent slot is 4KiB below.
 */
static uint64_t sp_el1_allocated[SP_EL1_BITMAP_WORDS];

static inline void sp_el1_slot_mark(int slot)
{
    sp_el1_allocated[slot / 64] |= BIT64(slot % 64);
}

static inline void sp_el1_slot_clear(int slot)
{
    sp_el1_allocated[slot / 64] &= ~BIT64(slot % 64);
}

/* Find lowest free SP_EL1 slot, or -1 if the IPA pool is full. */
static int sp_el1_find_free_slot(void)
{
    for (int w = 0; w < SP_EL1_BITMAP_WORDS; w++) {
        uint64_t free = ~sp_el1_allocated[w];
        if (w == SP_EL1_BITMAP_WORDS - 1) {
            int rem = SP_EL1_SLOT_MAX - w * 64;
            if (rem < 64)
                free &= bit_mask64_low((unsigned) rem);
        }
        if (free != 0)
            return w * 64 + bit_ctz64(free);
    }
    return -1;
}

/* Ensure thread_slots[0..n) exist. Caller holds thread_lock.
 *
 * Returns 0 or -1.
 */
static int thread_table_ensure_capacity_locked(int n)
{
    if (n < 0 || n > SP_EL1_SLOT_MAX)
        return -1;
    int cap = atomic_load_explicit(&thread_capacity, memory_order_relaxed);
    while (cap < n) {
        thread_entry_t *e = calloc(1, sizeof(*e));
        if (!e) {
            log_error("thread: calloc thread_entry failed (cap=%d)", cap);
            return -1;
        }
        e->sp_el1_slot = -1;
        thread_slots[cap] = e;
        cap++;
        atomic_store_explicit(&thread_capacity, cap, memory_order_release);
    }
    return 0;
}

/* Grow by doubling (or to need) when the existing range has no free slot. */
static int thread_table_grow_locked(void)
{
    int cap = atomic_load_explicit(&thread_capacity, memory_order_relaxed);
    if (cap >= SP_EL1_SLOT_MAX)
        return -1;
    int want = cap == 0 ? THREAD_TABLE_INITIAL_CAP : cap * 2;
    if (want > SP_EL1_SLOT_MAX)
        want = SP_EL1_SLOT_MAX;
    if (want <= cap)
        want = cap + 1;
    return thread_table_ensure_capacity_locked(want);
}

/* Per-thread pointer to the current thread's entry. Set once when a host
 * pthread starts running a guest vCPU. Syscall handlers read this without
 * locking since it is thread-local and never changes after init.
 */
_Thread_local thread_entry_t *current_thread = NULL;

/* Public API */

void thread_init(void)
{
    pthread_mutex_lock(&thread_lock);
    int cap = atomic_load_explicit(&thread_capacity, memory_order_relaxed);
    for (int i = 0; i < cap; i++) {
        free(thread_slots[i]);
        thread_slots[i] = NULL;
    }
    atomic_store_explicit(&thread_capacity, 0, memory_order_relaxed);
    main_thread_entry = NULL;
    memset(sp_el1_allocated, 0, sizeof(sp_el1_allocated));
    atomic_store_explicit(&active_thread_count, 0, memory_order_relaxed);
    departed_user_ns = 0;
    departed_sys_ns = 0;
    current_thread = NULL;
    if (thread_table_ensure_capacity_locked(THREAD_TABLE_INITIAL_CAP) < 0)
        log_error("thread: initial table alloc failed");
    pthread_mutex_unlock(&thread_lock);

    /* Fair scheduler + ncpu-sized physical slot table. Safe to re-init: both
     * are idempotent / replace prior bookkeeping without touching HVF handles.
     */
    sched_init();
    (void) vcpu_pool_init();
}

void thread_register_main(const guest_t *g,
                          hv_vcpu_t vcpu,
                          hv_vcpu_exit_t *vexit,
                          int64_t tid,
                          uint64_t sp_el1)
{
    pthread_mutex_lock(&thread_lock);

    if (thread_table_ensure_capacity_locked(1) < 0) {
        pthread_mutex_unlock(&thread_lock);
        log_fatal("thread: cannot allocate main thread entry");
        return;
    }
    thread_entry_t *t = thread_slots[0];
    main_thread_entry = t;
    atomic_store_explicit(&t->guest_tid, tid, memory_order_relaxed);
    guest_ctx_save(vcpu, &t->guest_ctx);
    (void) vexit;
    t->clear_child_tid = 0;
    t->sp_el1 = sp_el1;
    uint64_t top = sp_el1_top(g);
    uint64_t distance = top >= sp_el1 ? top - sp_el1 : UINT64_MAX;
    if (distance >= (uint64_t) SP_EL1_SLOT_MAX * SP_EL1_SLOT_BYTES) {
        pthread_mutex_unlock(&thread_lock);
        log_fatal("thread: invalid bootstrap EL1 stack");
        abort();
    }
    int stack_slot = (int) (distance / SP_EL1_SLOT_BYTES);
    t->sp_el1_slot = stack_slot;
    t->sp_el1 = top - (uint64_t) stack_slot * SP_EL1_SLOT_BYTES;
    t->altstack_flags = LINUX_SS_DISABLE;
    t->on_altstack = false;
    thread_ptrace_init(t);

    /* Release-store so a lock-free scanner that acquire-loads active == 1 sees
     * this slot's initialized fields (see thread_pending_union,
     * thread_tid_alive).
     */
    atomic_store_explicit(&t->active, 1, memory_order_release);

    /* The fork child can inherit a nonzero exception-stack slot. */
    memset(sp_el1_allocated, 0, sizeof(sp_el1_allocated));
    sp_el1_slot_mark(stack_slot);
    atomic_store_explicit(&active_thread_count, 1, memory_order_relaxed);

    pthread_mutex_unlock(&thread_lock);

    /* Set TLS pointer for the main thread */
    current_thread = t;
    sched_attach_thread(t);
}

/* Where thread_slot_clear starts its first memset: just past the one word
 * inside tpending that a lock-free scan reads.
 */
#define THREAD_SLOT_CLEAR_START           \
    (offsetof(thread_entry_t, tpending) + \
     sizeof(((thread_entry_t *) 0)->tpending.pending))

/* Each lock-free-scanned field has to sit wholly below that point, or the
 * memset would plain-write something a scan can be loading. Assert the property
 * each field actually needs rather than a chain of orderings, so inserting a
 * field in the middle of the group cannot quietly weaken it.
 */
#define THREAD_SLOT_KEPT(field)                   \
    (offsetof(thread_entry_t, field) +            \
         sizeof(((thread_entry_t *) 0)->field) <= \
     THREAD_SLOT_CLEAR_START)

_Static_assert(THREAD_SLOT_KEPT(active), "active is cleared by the memset");
_Static_assert(THREAD_SLOT_KEPT(blocked), "blocked is cleared by the memset");
_Static_assert(THREAD_SLOT_KEPT(guest_tid),
               "guest_tid is cleared by the memset");
_Static_assert(THREAD_SLOT_KEPT(tpending.pending),
               "tpending.pending is cleared by the memset");
_Static_assert(THREAD_SLOT_KEPT(in_syscall),
               "in_syscall is cleared by the memset");
_Static_assert(THREAD_SLOT_KEPT(futex_kick),
               "futex_kick is cleared by the memset");

/* Clear a slot that thread_alloc is about to hand to a new thread.
 *
 * A whole-struct memset cannot be used. The scans that walk the table lock-free
 * each load active and then a payload field with no lock in between, so one of
 * them can still be reading this slot after it went inactive and while the
 * recycle runs. Plain-writing any field they read is a data race, so the memset
 * skips them all: five are stored atomically here, and the futex park fields
 * are left as the last owner cleared them (runtime/thread.h).
 */
static void thread_slot_clear(thread_entry_t *t)
{
    atomic_store_explicit(&t->active, 0, memory_order_relaxed);
    atomic_store_explicit(&t->blocked, 0, memory_order_relaxed);
    atomic_store_explicit(&t->guest_tid, 0, memory_order_relaxed);
    pending_store(&t->tpending.pending, 0);
    atomic_store_explicit(&t->in_syscall, 0, memory_order_relaxed);

    /* Everything past the scanned fields is lock-private: one span covers the
     * rest of tpending and the whole tail, padding included.
     */
    memset((unsigned char *) t + THREAD_SLOT_CLEAR_START, 0,
           sizeof(*t) - THREAD_SLOT_CLEAR_START);
}

thread_entry_t *thread_alloc(int64_t tid,
                             uint64_t stack_start,
                             uint64_t stack_end,
                             const thread_vm_clone_t *vm_clone)
{
    thread_entry_t *result = NULL;

    pthread_mutex_lock(&thread_lock);
rescan:
    THREAD_FOR_EACH (t) {
        if (atomic_load_explicit(&t->active, memory_order_relaxed) ||
            t->references != 0 || t == main_thread_entry)
            continue;

        /* Skip slots where a tracer is still inside pthread_cond_wait on
         * ptrace_cond. Memset+reinit while a waiter holds a reference is UB.
         */
        if (t->ptrace_conds_inited && t->ptrace_waiters > 0)
            continue;

        if (t->ptrace_conds_inited) {
            pthread_cond_destroy(&t->ptrace_cond);
            pthread_cond_destroy(&t->resume_cond);
        }

        /* References prevent reuse; generation rejects stale notifications. */
        uint64_t next_generation = t->generation + 1;
        thread_slot_clear(t);
        t->generation = next_generation;
        t->sp_el1_slot = -1; /* No SP_EL1 yet; thread_alloc_sp_el1 fills this */
        t->connect_inflight_fd = -1;
        t->nl_restart_fd = -1;
        /* Not in one; syscall_dispatch fills this */
        atomic_store_explicit(&t->in_syscall, -1, memory_order_relaxed);
        atomic_store_explicit(&t->guest_tid, tid, memory_order_relaxed);
        if (stack_start < stack_end) {
            t->stack_map_start = stack_start;
            t->stack_map_end = stack_end;
        }
        t->altstack_flags = LINUX_SS_DISABLE;
        thread_ptrace_init(t);

        /* Set with the rest of the slot, so a reader that holds thread_lock
         * never finds this child active and taken for a thread.
         */
        if (vm_clone) {
            t->is_vm_clone = true;
            t->parent_tid = vm_clone->parent_tid;
            t->exit_signal = vm_clone->exit_signal;
        }

        /* Release-store last so a lock-free scanner that observes active == 1
         * also sees the zeroed tpending / guest_tid set above.
         */
        atomic_store_explicit(&t->active, 1, memory_order_release);
        atomic_fetch_add_explicit(&active_thread_count, 1,
                                  memory_order_relaxed);
        result = t;
        break;
    }
    if (!result) {
        /* No reusable slot in the published range; grow the table. */
        if (thread_table_grow_locked() == 0)
            goto rescan;
        log_error("thread: table full or OOM (cap=%d max=%d)",
                  atomic_load_explicit(&thread_capacity, memory_order_relaxed),
                  SP_EL1_SLOT_MAX);
    }
    pthread_mutex_unlock(&thread_lock);

    /* Caller attaches: sched_attach_thread (bootstrap main before pool adopt)
     * or sched_enqueue_thread (CLONE_THREAD / CLONE_VM task onto the vCPU
     * worker pool).
     */
    return result;
}

/* Free an SP_EL1 slot for reuse. Must be called with thread_lock held. Reads
 * the slot index recorded at allocation time and clears the bit.
 */
static void thread_free_sp_el1_locked(thread_entry_t *t)
{
    int slot = t->sp_el1_slot;
    if (RANGE_CHECK(slot, 0, SP_EL1_SLOT_MAX))
        sp_el1_slot_clear(slot);
    t->sp_el1 = 0;
    t->sp_el1_slot = -1;
}

static void thread_ptrace_cleanup_locked(thread_entry_t *t)
{
    if (!t->ptrace_conds_inited ||
        atomic_load_explicit(&t->active, memory_order_relaxed) ||
        t->ptrace_waiters != 0)
        return;

    pthread_cond_destroy(&t->ptrace_cond);
    pthread_cond_destroy(&t->resume_cond);
    t->ptrace_conds_inited = false;
    t->ptrace_cleanup_pending = false;
}


void thread_fork_release_counted_locked(thread_entry_t *t)
{
    /* Caller holds thread_lock. If a fork snapshot counted this slot but it is
     * exiting or failing bring-up before it could reach
     * thread_fork_barrier_check, hand its count back so thread_quiesce_siblings
     * is not stalled the full timeout waiting for a thread that will never
     * arrive. Guarded by fork_counted so a slot created after the barrier armed
     * (never counted) does not over-decrement. No-op when no barrier is armed.
     */
    if (atomic_load_explicit(&fork_quiesce_active, memory_order_relaxed) &&
        t->fork_counted) {
        t->fork_counted = false;
        fork_target_count--;
        if (fork_quiesced_count >= fork_target_count)
            pthread_cond_signal(&fork_all_quiesced_cond);
    }
}

void thread_deactivate(thread_entry_t *t)
{
    if (!t)
        return;

    /* Leave the fair run queue / weight sum before the slot can be recycled. */
    sched_detach_thread(t);

    /* Before thread_lock, which ranks after sig_lock, and before the slot can
     * be handed to a new thread that would inherit the claims by address.
     */
    signal_wait_cancel(t);
    signal_release_claims(t);
    futex_pi_task_release(t);
    uint64_t runtime_user_ns, runtime_sys_ns;
    sched_thread_cputime_split_ns(t, &runtime_user_ns, &runtime_sys_ns);

    pthread_mutex_lock(&thread_lock);

    /* If this is a VM-clone child, mark it as exited and wake the tracer/parent
     * so wait4 can collect the exit status. Must happen BEFORE destroying the
     * condvars, since broadcasting a destroyed condvar is undefined behavior.
     * Guard against double-deactivation: if already inactive, skip.
     */
    if (!atomic_load_explicit(&t->active, memory_order_relaxed)) {
        pthread_mutex_unlock(&thread_lock);
        return;
    }
    if (!t->is_vm_clone) {
        departed_user_ns += runtime_user_ns;
        departed_sys_ns += runtime_sys_ns;
    }

    if (t->is_vm_clone) {
        t->vm_exited = true;
        pthread_cond_broadcast(&t->ptrace_cond);
    }

    /* Free SP_EL1 slot so it can be reused by future threads */
    thread_free_sp_el1_locked(t);

    /* Publish the completed guest accesses before readers observe exit. */
    atomic_store_explicit(&t->active, 0, memory_order_release);
    atomic_fetch_sub_explicit(&active_thread_count, 1, memory_order_relaxed);

    thread_fork_release_counted_locked(t);

    /* Destroy condvars once no waiters still reference them. A tracer woken by
     * the broadcast above may still be re-acquiring thread_lock.
     */
    t->ptrace_cleanup_pending = true;
    thread_ptrace_cleanup_locked(t);

    pthread_mutex_unlock(&thread_lock);

    /* The slot is now inactive, so thread_pending_union() excludes it.
     * Recompute the global pending hint so any thread-directed signal left
     * unconsumed in this thread's private set stops pinning the
     * identity-syscall fast path off for the surviving threads. Done outside
     * thread_lock to honor sig_lock (4) before thread_lock (5).
     */
    signal_refresh_pending_hint();
}

void thread_exit_task(thread_entry_t *t, guest_t *g, int wait_status)
{
    if (!t || !g)
        return;
    pthread_mutex_lock(&thread_lock);
    if (t->exit_cleanup_claimed ||
        !atomic_load_explicit(&t->active, memory_order_relaxed)) {
        pthread_mutex_unlock(&thread_lock);
        return;
    }
    t->exit_cleanup_claimed = true;
    pthread_mutex_unlock(&thread_lock);
    signal_wait_cancel(t);
    futex_task_cancel_wait(t);
    io_task_cancel_wait(t);
    mqueue_task_cancel_wait(t);
    sysvipc_task_cancel_wait(t);
    fuse_task_cancel_wait(t);
    if (t->vfork_wait_fd_plus1) {
        close(t->vfork_wait_fd_plus1 - 1);
        t->vfork_wait_fd_plus1 = 0;
    }
    if (t->robust_list_head)
        robust_list_walk(g, t);
    futex_pi_owner_exit(g, t);
    futex_pi_task_release(t);
    mem_cleanup_deferred_stack_unmaps(g, t);
    if (t->clear_child_tid) {
        uint32_t zero = 0;
        if (guest_write_small(g, t->clear_child_tid, &zero, sizeof(zero)) == 0)
            futex_wake_one(g, t->clear_child_tid);
        t->clear_child_tid = 0;
    }
    int64_t tid = thread_tid(t);
    if (t->is_vm_clone) {
        pthread_mutex_lock(&thread_lock);
        t->vm_exited = true;
        t->vm_exit_status = wait_status;
        int64_t parent = t->parent_tid;
        pthread_cond_broadcast(&t->ptrace_cond);
        pthread_mutex_unlock(&thread_lock);
        sched_detach_thread(t);
        proc_pidfd_notify_exit(tid);
        thread_entry_t *waiter = thread_acquire_tid(parent);
        if (waiter) {
            (void) sched_park_try_complete_reissue(waiter);
            thread_release(waiter);
        }
        return;
    }
    thread_deactivate(t);
    bool last = thread_active_count() == thread_count_active_vm_clones();
    if (tid != proc_get_pid() || last) {
        proc_thread_exit(tid, wait_status);
        proc_pidfd_notify_exit_code(tid, wait_status);
    }
    if (last) {
        if (!proc_exit_group_requested()) {
            int term = wait_status & 0x7f;
            int code =
                term && term != 0x7f ? 128 + term : (wait_status >> 8) & 0xff;
            proc_request_exit_group_status(code, wait_status);
        }
        sched_request_shutdown();
        thread_wake_all_blocked();
    }
}

thread_entry_t *thread_find(int64_t tid)
{
    thread_entry_t *result = NULL;

    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t) {
        if (thread_tid(t) == tid) {
            result = t;
            break;
        }
    }
    pthread_mutex_unlock(&thread_lock);

    return result;
}

thread_entry_t *thread_acquire_tid(int64_t tid)
{
    thread_entry_t *result = NULL;
    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t) {
        if (thread_tid(t) == tid) {
            t->references++;
            result = t;
            break;
        }
    }
    pthread_mutex_unlock(&thread_lock);
    return result;
}

void thread_release(thread_entry_t *t)
{
    if (!t)
        return;
    pthread_mutex_lock(&thread_lock);
    if (t->references != 0)
        t->references--;
    pthread_mutex_unlock(&thread_lock);
}

thread_entry_t *thread_find_relaxed(int64_t tid)
{
    THREAD_FOR_EACH_ACTIVE_RELAXED (t) {
        if (thread_tid(t) == tid)
            return t;
    }
    return NULL;
}

thread_entry_t *thread_find_locked(int64_t tid)
{
    THREAD_FOR_EACH_ACTIVE (t) {
        if (thread_tid(t) == tid)
            return t;
    }
    return NULL;
}

uint64_t thread_pending_union(void)
{
    /* Lock-free active scan; sig_lock (held by the caller) already serializes
     * every tpending write, so reads here are stable. A slot mid-(de)activation
     * only ever contributes extra bits, which the caller treats as a harmless
     * false positive in the pending hint.
     */
    uint64_t u = 0;
    THREAD_FOR_EACH_ACTIVE_RELAXED (t)
        u |= pending_load(&t->tpending.pending);
    return u;
}


void thread_process_cputime_split_ns(uint64_t *user_ns, uint64_t *sys_ns)
{
    pthread_mutex_lock(&thread_lock);
    uint64_t user = departed_user_ns;
    uint64_t system = departed_sys_ns;
    THREAD_FOR_EACH_ACTIVE (t) {
        if (t->is_vm_clone)
            continue;
        uint64_t task_user, task_system;
        sched_thread_cputime_split_ns(t, &task_user, &task_system);
        user += task_user;
        system += task_system;
    }
    pthread_mutex_unlock(&thread_lock);
    *user_ns = user;
    *sys_ns = system;
}

uint64_t thread_process_cputime_ns(void)
{
    uint64_t user, system;
    thread_process_cputime_split_ns(&user, &system);
    return user + system;
}

int64_t thread_find_running_tid(void)
{
    THREAD_FOR_EACH_ACTIVE_RELAXED (t) {
        if (t->is_vm_clone)
            continue;
        if (!sched_task_is_running(t))
            continue;
        int64_t tid = atomic_load_explicit(&t->guest_tid, memory_order_relaxed);
        if (tid)
            return tid;
    }
    return 0;
}

bool thread_tid_alive(int64_t tid)
{
    /* Lock-free scan: active transitions 1->0 exactly once (in
     * thread_deactivate under thread_lock), and guest_tid is set at allocation
     * and never changes until the slot is reused (after active=0). A stale read
     * of active=1 for a thread being deactivated is benign; the caller retries
     * on the next poll iteration (100ms later).
     */
    THREAD_FOR_EACH_ACTIVE_RELAXED (t)
        if (thread_tid(t) == tid)
            return true;
    return false;
}

bool thread_tid_in_group(int64_t tid)
{
    bool found = false;
    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH (t) {
        if (atomic_load_explicit(&t->active, memory_order_relaxed) &&
            thread_tid(t) == tid && !t->is_vm_clone) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&thread_lock);
    return found;
}

int thread_active_count(void)
{
    return atomic_load_explicit(&active_thread_count, memory_order_relaxed);
}

int thread_table_capacity(void)
{
    return atomic_load_explicit(&thread_capacity, memory_order_acquire);
}

int thread_is_single_active(void)
{
    return atomic_load_explicit(&active_thread_count, memory_order_relaxed) ==
           1;
}

int thread_count_active_vm_clones(void)
{
    int count = 0;

    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t)
        if (t->is_vm_clone && !t->vm_exited)
            count++;
    pthread_mutex_unlock(&thread_lock);

    return count;
}

uint64_t thread_alloc_sp_el1(const guest_t *g, thread_entry_t *t)
{
    uint64_t sp = 0;

    pthread_mutex_lock(&thread_lock);

    int slot = sp_el1_find_free_slot();
    if (slot < 0) {
        log_error("thread: SP_EL1 IPA pool exhausted (%d slots)",
                  SP_EL1_SLOT_MAX);
    } else {
        /* Main thread's SP_EL1 sits at the top of the shim data block. Each
         * subsequent thread is one slot below.
         */
        uint64_t top = sp_el1_top(g);
        sp = top - (uint64_t) slot * SP_EL1_SLOT_BYTES;
        sp_el1_slot_mark(slot);
        t->sp_el1 = sp;
        t->sp_el1_slot = slot;
    }

    pthread_mutex_unlock(&thread_lock);

    return sp;
}

void thread_sp_el1_region(const guest_t *g, uint64_t *lo, uint64_t *hi)
{
    /* Derived from what thread_alloc_sp_el1 hands out: slot 0 at the top, slot
     * SP_EL1_SLOT_MAX-1 the lowest. Everything under that is the shim-globals
     * cache (and page-aligned pad).
     */
    uint64_t top = sp_el1_top(g);

    *hi = top;
    *lo = top - (uint64_t) SP_EL1_SLOT_MAX * SP_EL1_SLOT_BYTES;
}

void thread_for_each(void (*fn)(thread_entry_t *t, void *ctx), void *ctx)
{
    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t)
        fn(t, ctx);
    pthread_mutex_unlock(&thread_lock);
}

void thread_for_each_ref(void (*fn)(thread_entry_t *t, void *ctx), void *ctx)
{
    thread_entry_t *snapshot[SP_EL1_SLOT_MAX];
    int count = 0;
    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t) {
        t->references++;
        snapshot[count++] = t;
    }
    pthread_mutex_unlock(&thread_lock);
    for (int i = 0; i < count; i++) {
        fn(snapshot[i], ctx);
        thread_release(snapshot[i]);
    }
}

bool thread_ptrace_interrupt_pending_locked(void)
{
    THREAD_FOR_EACH_ACTIVE (t) {
        /* A vm-clone that has exited keeps its slot until a wait reaps it, and
         * carries whatever it was owed to the grave: nothing will consume it.
         * Counting one holds ATTN_BIT_PTRACE up for the life of the process and
         * sends every fast path down the slow lane for a stop that can never be
         * taken. execve reaches here past its own guard, which counts only
         * clones that have not exited.
         */
        if (t->is_vm_clone && t->vm_exited)
            continue;
        if (t->ptrace_interrupt_pending)
            return true;
    }
    return false;
}


void thread_interrupt_all(void)
{
    vcpu_pool_kick_all_mounted();
}

bool thread_signal_deliverable(uint64_t sigbit)
{
    /* Lock-free scan: a thread's blocked field is written under sig_lock (lock
     * order 4) by its owner, and once by the parent that clones it before the
     * child's pthread exists. This reads it without either lock, so every
     * writer publishes with an atomic store. A stale read is benign: worst case
     * is a harmless spurious interrupt after reading blocked=0 concurrently
     * with a transition to blocked=1, or a delayed delivery corrected by the
     * next signal_pending() check.
     */
    THREAD_FOR_EACH_ACTIVE_RELAXED (t) {
        uint64_t mask = thread_blocked_load(t);
        if (sigbit & ~mask)
            return true;
    }
    return false;
}

void thread_kick_futex_waiters(uint64_t shared_pending)
{
    /* Lock-free scan, on the same terms as thread_signal_deliverable above. A
     * stale blocked or pending read costs a kick the thread answers by parking
     * again, or misses one its own polling quantum still covers. The caller is
     * skipped: it tests its own pending signals on the way out.
     */
    THREAD_FOR_EACH_ACTIVE_RELAXED (t) {
        uint64_t pending = pending_load(&t->tpending.pending) | shared_pending;
        if (t != current_thread && (pending & ~thread_blocked_load(t))) {
            futex_kick(t);
            sched_park_on_signal(t);
        }
    }
}

/* Fork quiesce. */

bool thread_quiesce_siblings(void)
{
    int targets = 0;

    pthread_mutex_lock(&thread_lock);

    /* A concurrent forker must acknowledge the current window before waiting;
     * otherwise its owner waits for this task while this task waits to fork.
     */
    while (atomic_load_explicit(&fork_quiesce_active, memory_order_relaxed)) {
        thread_fork_release_counted_locked(current_thread);
        pthread_cond_wait(&fork_window_closed_cond, &thread_lock);
    }

    /* Refuse while an execve teardown is reaping. The caller is one of the
     * threads being reaped, and a window armed now would park its siblings in a
     * barrier that only the caller can release, which it will not do because it
     * is about to leave the guest itself. Refusing keeps the teardown and the
     * quiesce windows from overlapping at all, which is what lets the barrier
     * below block unconditionally: a sibling parked there is never one this
     * teardown is waiting for.
     *
     * Read under thread_lock, and thread_exec_de_thread publishes it under the
     * same lock after draining any window already open, so the two orderings
     * are the only ones possible: either this arms first and the teardown waits
     * for it, or the teardown publishes first and this refuses.
     */
    if (atomic_load_explicit(&exec_de_thread_active, memory_order_acquire)) {
        pthread_mutex_unlock(&thread_lock);
        return false;
    }

    bool service_pending = false;
    THREAD_FOR_EACH_ACTIVE (t) {
        if (t != current_thread && t->fuse_service) {
            service_pending = true;
            break;
        }
    }
    if (service_pending) {
        pthread_mutex_unlock(&thread_lock);
        return false;
    }
    /* Freeze dispatch before counting tasks that still execute guest code. */
    sched_domain_freeze(true);
    THREAD_FOR_EACH_ACTIVE (t) {
        if (t == current_thread || !sched_task_is_running(t))
            continue;
        t->fork_counted = true;
        targets++;
    }
    fork_quiesced_count = 0;
    fork_target_count = targets;

    if (targets == 0) {
        atomic_store_explicit(&fork_quiesce_active, true, memory_order_release);
        pthread_mutex_unlock(&thread_lock);
        return true;
    }

    /* Arm the barrier */
    atomic_store_explicit(&fork_quiesce_active, true, memory_order_release);

    vcpu_pool_kick_all_mounted();

    pthread_mutex_unlock(&thread_lock);

    /* A failed freeze must not authorize a snapshot of executing memory. */
    pthread_mutex_lock(&thread_lock);
    if (fork_quiesced_count < fork_target_count) {
        struct timespec deadline;

        /* Mounted memory handlers can be draining a backing pause. Keep a
         * finite bound without treating a host scheduling delay as fork
         * failure.
         */
        timespec_deadline_in_ms(&deadline, 2000);
        while (fork_quiesced_count < fork_target_count) {
            int rc = pthread_cond_timedwait(&fork_all_quiesced_cond,
                                            &thread_lock, &deadline);
            if (rc == ETIMEDOUT) {
                atomic_store_explicit(&fork_quiesce_active, false,
                                      memory_order_release);
                THREAD_FOR_EACH (t)
                    t->fork_counted = false;
                pthread_cond_broadcast(&fork_cond);
                pthread_cond_broadcast(&fork_window_closed_cond);
                pthread_mutex_unlock(&thread_lock);
                sched_domain_freeze(false);
                return false;
            }
        }
    }
    pthread_mutex_unlock(&thread_lock);

    return true;
}

void thread_resume_siblings(void)
{
    pthread_mutex_lock(&thread_lock);
    atomic_store_explicit(&fork_quiesce_active, false, memory_order_release);
    sched_domain_freeze(false);
    fork_quiesced_count = 0;
    fork_target_count = 0;

    /* Clear any fork_counted still set on siblings that never reached the
     * barrier (blocked in a host syscall and released by the timeout) so the
     * next barrier generation starts from a clean slate.
     */
    THREAD_FOR_EACH (t)
        t->fork_counted = false;
    pthread_cond_broadcast(&fork_cond);

    /* An execve teardown parked in thread_exec_de_thread is waiting for exactly
     * this.
     */
    pthread_cond_broadcast(&fork_window_closed_cond);
    pthread_mutex_unlock(&thread_lock);
}

bool thread_fork_barrier_check(void)
{
    if (!atomic_load_explicit(&fork_quiesce_active, memory_order_acquire))
        return false;
    pthread_mutex_lock(&thread_lock);
    if (!atomic_load_explicit(&fork_quiesce_active, memory_order_relaxed)) {
        pthread_mutex_unlock(&thread_lock);
        return false;
    }

    /* Only a thread that thread_quiesce_siblings counted contributes to the
     * quiesced tally, and only once. A thread created after the barrier armed
     * (fork_counted == false) still blocks below so it cannot run guest code
     * during the snapshot, but must not inflate fork_quiesced_count past
     * fork_target_count and let the forker proceed before a real sibling has
     * stopped.
     */
    if (current_thread && current_thread->fork_counted) {
        current_thread->fork_counted = false;
        if (++fork_quiesced_count >= fork_target_count)
            pthread_cond_signal(&fork_all_quiesced_cond);
    }

    /* Block until the window closes. An execve teardown deliberately does not
     * break this wait: the whole point of the barrier is that no other thread
     * mutates guest memory while the forker copies it, and a sibling released
     * here would run its exit path, which writes clear_child_tid, walks the
     * robust list and unmaps its stack. The child would receive a torn image.
     *
     * Unlike Linux, where fork() takes a copy-on-write snapshot that later
     * sibling writes cannot reach, the copy here is not atomic against a
     * running thread, so the quiet is load-bearing rather than advisory.
     *
     * Nothing deadlocks behind that, because a teardown and a window never
     * overlap. thread_exec_de_thread drains a window already open before it
     * publishes the teardown, and thread_quiesce_siblings refuses to arm a new
     * one once it has. Both sides of that handshake run under thread_lock, so
     * the thread that releases this barrier is never one the teardown is
     * waiting on. exit_group is still honored: that is process death, and no
     * snapshot outlives it.
     */
    while (atomic_load_explicit(&fork_quiesce_active, memory_order_relaxed) &&
           !proc_exit_group_requested()) {
        if (!thread_exec_stop_requested()) {
            pthread_cond_wait(&fork_cond, &thread_lock);
            continue;
        }

        struct timespec deadline;
        timespec_deadline_in_ms(&deadline, 200);
        if (pthread_cond_timedwait(&fork_cond, &thread_lock, &deadline) ==
            ETIMEDOUT)
            break;
    }

    pthread_mutex_unlock(&thread_lock);
    return true;
}

static void thread_wake_execution_waiters(void)
{
    wakeup_pipe_signal();
    thread_interrupt_all();
    thread_wake_exit_waiters();
}

void thread_wake_all_blocked(void)
{
    /* Teardown: every thread really is leaving, so the futex interrupt on top
     * of the wakes above is an EINTR each of them has to see.
     */
    futex_interrupt_request();
    THREAD_FOR_EACH_ACTIVE_RELAXED (t) {
        futex_kick(t);
        sched_park_on_signal(t);
    }
    thread_wake_execution_waiters();
}

void thread_wake_exit_waiters(void)
{
    pthread_mutex_lock(&thread_lock);

    /* Fork barrier: siblings parked in thread_fork_barrier_check. Only
     * exit_group releases them, since an execve teardown waits for the window
     * to close rather than breaking it; the broadcast is what makes them
     * re-check on process death.
     */
    pthread_cond_broadcast(&fork_cond);

    /* Deferred stack-unmap transactions: a thread waiting for another one's
     * transaction to clear parks on this condvar, which nothing else wakes.
     * Without the broadcast it sleeps through an execve teardown and is then
     * counted as a thread that would not leave.
     */
    pthread_cond_broadcast(&deferred_stack_unmap_cond);

    /* Ptrace parks: tracers blocked in thread_ptrace_wait (ptrace_cond) and
     * tracees blocked in thread_ptrace_stop (resume_cond). Scan every slot with
     * live condvars, not just active ones: a tracer may still be parked on a
     * slot whose thread was deactivated. ptrace_conds_inited only transitions
     * under thread_lock with ptrace_waiters == 0, so broadcasting here never
     * touches a destroyed condvar.
     */
    THREAD_FOR_EACH (t) {
        if (!t->ptrace_conds_inited)
            continue;
        pthread_cond_broadcast(&t->ptrace_cond);
        pthread_cond_broadcast(&t->resume_cond);
    }

    pthread_mutex_unlock(&thread_lock);
}

/* execve de_thread. */


bool thread_exec_de_thread_active(void)
{
    return atomic_load_explicit(&exec_de_thread_active, memory_order_acquire);
}

int thread_stop_requested_for(const thread_entry_t *t)
{
    if (!t)
        return 0;
    if (proc_exit_group_requested())
        return 1;
    if (atomic_load_explicit(&exec_de_thread_active, memory_order_acquire) &&
        t != main_thread_entry && !t->is_vm_clone)
        return 1;
    return 0;
}

int thread_exec_stop_requested(void)
{
    /* The flag first, so the common case (no execve in flight) never reaches
     * current_thread: on Darwin every _Thread_local read goes through the TLV
     * descriptor thunk, which is an indirect call, not a register read.
     */
    if (!atomic_load_explicit(&exec_de_thread_active, memory_order_acquire))
        return 0;

    /* No table entry (the preemption thread, the GDB stub, the rosettad
     * bridge): runs no guest code and is nobody's sibling. The leader is the
     * thread running the teardown. And a CLONE_VM child is a distinct task with
     * its own tgid, which Linux execve leaves alone: reaping it would publish a
     * bogus exit(0) to the parent's wait4 and let its exit path request a
     * process-wide exit_group in the middle of the exec.
     */
    return current_thread && !thread_current_is_leader() &&
           !current_thread->is_vm_clone;
}


void thread_note_syscall(int nr)
{
    if (current_thread)
        atomic_store_explicit(&current_thread->in_syscall, nr,
                              memory_order_relaxed);
}

int thread_stop_requested(void)
{
    return thread_exec_stop_requested() || proc_exit_group_requested();
}


/* Whether an execve teardown will reap this slot: not the caller, not the main
 * thread's (slot 0 is never torn down; it owns process teardown), and not a
 * CLONE_VM child (a separate task that execve leaves alone). Counting every
 * active thread instead would wait, and then report, on threads that were never
 * going to leave. Caller must hold thread_lock.
 */
static bool thread_is_joinable_sibling(const thread_entry_t *t)
{
    return t != current_thread && t != main_thread_entry && !t->is_vm_clone;
}

static int thread_count_joinable_siblings(void)
{
    int n = 0;

    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t) {
        if (thread_is_joinable_sibling(t))
            n++;
    }
    pthread_mutex_unlock(&thread_lock);

    return n;
}

bool thread_current_is_leader(void)
{
    return current_thread == main_thread_entry;
}

bool thread_leader_is_active(void)
{
    pthread_mutex_lock(&thread_lock);
    thread_entry_t *m = main_thread_entry;
    bool ok = m && atomic_load_explicit(&m->active, memory_order_acquire);
    pthread_mutex_unlock(&thread_lock);
    return ok;
}

void thread_promote_current_to_leader(void)
{
    if (!current_thread)
        return;
    pthread_mutex_lock(&thread_lock);
    main_thread_entry = current_thread;
    pthread_mutex_unlock(&thread_lock);
}

void thread_commit_exec_identity(void)
{
    if (!current_thread)
        return;
    pthread_mutex_lock(&thread_lock);
    atomic_store_explicit(&current_thread->guest_tid, proc_get_pid(),
                          memory_order_release);
    main_thread_entry = current_thread;
    pthread_mutex_unlock(&thread_lock);
}

thread_entry_t *thread_get_main(void)
{
    return main_thread_entry;
}

static void thread_reap_exec_unmounted(guest_t *guest)
{
    thread_entry_t *tasks[SP_EL1_SLOT_MAX];
    int count = 0;
    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t) {
        if (thread_is_joinable_sibling(t) && !t->exit_cleanup_claimed) {
            t->references++;
            tasks[count++] = t;
        }
    }
    pthread_mutex_unlock(&thread_lock);
    for (int i = 0; i < count; i++) {
        if (sched_task_claim_stopped(tasks[i]))
            thread_exit_task(tasks[i], guest, 0);
        thread_release(tasks[i]);
    }
}

/* Milliseconds on CLOCK_MONOTONIC since @since. Only the de_thread wait needs
 * it, which measures how long its siblings took rather than when they left.
 */
static int64_t thread_elapsed_ms(const struct timespec *since)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t) (now.tv_sec - since->tv_sec) * 1000 +
           (now.tv_nsec - since->tv_nsec) / 1000000;
}

int thread_exec_de_thread(void)
{
    if (!current_thread)
        return 0;

    /* execve tears down an in-process tracer with the old thread group. */
    pthread_mutex_lock(&thread_lock);
    current_thread->ptraced = false;
    current_thread->tracer_tid = 0;
    current_thread->ptrace_interrupt_pending = false;
    pthread_mutex_unlock(&thread_lock);

    if (thread_count_joinable_siblings() == 0)
        return 0;

    pthread_mutex_lock(&thread_lock);
    while (atomic_load_explicit(&fork_quiesce_active, memory_order_relaxed))
        pthread_cond_wait(&fork_window_closed_cond, &thread_lock);
    atomic_store_explicit(&exec_de_thread_active, true, memory_order_release);
    pthread_mutex_unlock(&thread_lock);

    /* Running siblings exit at a safe point; unmounted tasks need no CPU. */
    thread_wake_all_blocked();
    guest_t *guest = vcpu_pool_guest();
    thread_reap_exec_unmounted(guest);

    /* wakeup_pipe_drain takes every queued byte, so a sibling that reaches
     * poll() after another one drained sits out its own 200 ms recheck no
     * matter how many bytes the wake wrote. Re-poke while they wind down, which
     * costs a threaded execve milliseconds instead of a poll quantum per parked
     * sibling (measured: 38 s to 2.5 s over 200 threaded execs).
     *
     * One wall-clock ceiling bounds the wait, and nothing else does. Departures
     * look like a liveness signal and are not one: once a single sibling is
     * left there are none left to observe, so a stall interval only ever
     * measures that last sibling's own latency, which is the fixed bound it was
     * meant to replace. Sized honestly it would have to cover the slowest
     * re-check quantum a parked sibling owes (200 ms, in the io wait)
     * multiplied by how far behind schedule the host is running, and that
     * multiplier is not a property this code can know: CI runs the sanitizer
     * lanes of several workflows on one machine, where a 1000 ms stall interval
     * gave up on a sibling sitting in mmap and sent an otherwise healthy execve
     * to the post-PNR fatal exit.
     *
     * Spending the whole budget here rather than splitting it with the join
     * below is what the re-poke is for: this loop kicks the wake set every
     * iteration, and the join only polls. Time moved from here to there buys a
     * parked sibling nothing.
     *
     * Wall-clock, because the sleep is a floor: an oversubscribed host
     * stretches each iteration well past its 1 ms, so a bound counted in
     * iterations would run for minutes and blow the caller's timeout instead of
     * reaching the diagnosed exit.
     */
    enum { DE_THREAD_CEILING_MS = 10000 };
    struct timespec started;
    clock_gettime(CLOCK_MONOTONIC, &started);

    int remaining = thread_count_joinable_siblings();
    int64_t elapsed_ms = 0, progress_ms = 0;

    while (remaining > 0) {
        /* The whole wake set, not just the pipe: a sibling in a tight compute
         * loop is reachable only by hv_vcpus_exit, and one kick that lands
         * between two hv_vcpu_run calls is lost. Re-issuing costs nothing here
         * and removes the dependence on a single kick landing.
         */
        thread_wake_all_blocked();
        thread_reap_exec_unmounted(guest);
        usleep(1000);

        int now = thread_count_joinable_siblings();
        elapsed_ms = thread_elapsed_ms(&started);
        if (now < remaining) {
            remaining = now;
            progress_ms = elapsed_ms;
        }
        if (elapsed_ms >= DE_THREAD_CEILING_MS)
            break;
    }

    /* Name who is still here before the bounded join runs, so a teardown that
     * ends fatally says which thread held it up rather than only how many did.
     * The timings go with it: a report that spent its whole budget with
     * siblings leaving throughout is a slow host, and one whose last departure
     * is the start of the wait is a sibling no wake reaches, which are
     * different bugs.
     */
    if (remaining > 0) {
        log_warn(
            "execve: %d sibling(s) still in the guest after %lld ms, last "
            "departure at %lld ms",
            remaining, (long long) elapsed_ms, (long long) progress_ms);
        pthread_mutex_lock(&thread_lock);
        THREAD_FOR_EACH_ACTIVE (t) {
            if (!thread_is_joinable_sibling(t))
                continue;
            int32_t nr =
                atomic_load_explicit(&t->in_syscall, memory_order_relaxed);
            if (nr < 0)
                log_warn(
                    "execve: tid=%lld has not left the guest yet, "
                    "running guest code",
                    (long long) thread_tid(t));
            else
                log_warn(
                    "execve: tid=%lld has not left the guest yet, "
                    "in syscall %d",
                    (long long) thread_tid(t), nr);
        }
        pthread_mutex_unlock(&thread_lock);
    }

    int left = thread_count_joinable_siblings();

    /* Cleared last. A straggler that wakes after this reads false and resumes,
     * which is only safe because the caller treats a non-zero return as fatal.
     */
    atomic_store_explicit(&exec_de_thread_active, false, memory_order_release);

    return left;
}

void thread_reset_for_exec(void)
{
    if (!current_thread)
        return;

    /* Linux begin_new_exec() drops both: the robust list and clear_child_tid
     * are addresses in the image that just went away. Carrying them across the
     * reset makes this thread's eventual exit walk a list, and write a zero
     * word plus a futex wake, at whatever the new image happens to have put
     * there. Nothing is marked FUTEX_OWNER_DIED on the way out because no
     * thread survives that could observe it.
     */
    current_thread->robust_list_head = 0;
    current_thread->clear_child_tid = 0;

    /* rseq goes the same way, as rseq_execve does. Left registered, the address
     * belongs to the old image while the new one cannot register its own:
     * sc_rseq answers EBUSY for a thread that already has one, and the
     * preemption and signal paths would abort against the stale critical
     * section.
     */
    current_thread->rseq_gva = 0;
    current_thread->rseq_len = 0;
    current_thread->rseq_signature = 0;
    current_thread->sigreturn_cookie_depth = 0;
    signal_task_reset(current_thread);
    atomic_store_explicit(&current_thread->park_rem_pending, false,
                          memory_order_relaxed);
    current_thread->io_continue_bytes = 0;
    current_thread->sysv_waited = false;
    current_thread->syscall_restart = (task_syscall_restart_t) {0};
    current_thread->nl_restart_deadline_ms = 0;
    current_thread->nl_restart_fd = -1;
    atomic_store_explicit(&current_thread->park_restart_forbid, false,
                          memory_order_relaxed);
}

/* Ptrace helpers. */

pthread_mutex_t *thread_get_lock(void)
{
    return &thread_lock;
}

int thread_collect_and_defer_stack_ranges(
    uint64_t start,
    uint64_t end,
    thread_deferred_stack_unmap_txn_t *txns,
    int max_ranges)
{
    int nranges = 0;

    if (start >= end || !txns || max_ranges <= 0)
        return 0;

    pthread_mutex_lock(&thread_lock);
retry:
    nranges = 0;

    /* Pass 1: enumerate every thread whose live stack overlaps [start, end) and
     * verify each one can record a new deferred-unmap entry. If the
     * caller-provided buffer is too small or any thread is at its
     * deferred-unmap cap, refuse the whole operation so pass 2 never has to
     * handle a partial commit.
     */
    THREAD_FOR_EACH_ACTIVE (t) {
        uint64_t rs = t->stack_map_start;
        uint64_t re = t->stack_map_end;

        if (rs >= re || re <= start || rs >= end)
            continue;
        if (t->deferred_stack_unmap_busy > 0) {
            /* Give up rather than wait when this thread is leaving the guest.
             * The caller reports the failure to its guest, which never reads it
             * because the run loop winds the thread down first, and an execve
             * teardown that waited here instead would count this thread as one
             * that refused to leave.
             */
            if (thread_stop_requested()) {
                pthread_mutex_unlock(&thread_lock);
                return -1;
            }
            pthread_cond_wait(&deferred_stack_unmap_cond, &thread_lock);
            goto retry;
        }
        if (nranges >= max_ranges) {
            pthread_mutex_unlock(&thread_lock);
            return -1;
        }
        uint64_t ds = (rs > start) ? rs : start;
        uint64_t de = (re < end) ? re : end;
        if (thread_can_add_deferred_unmap_locked(t, ds, de) < 0) {
            pthread_mutex_unlock(&thread_lock);
            return -1;
        }

        txns[nranges].thread = t;
        txns[nranges].guest_tid = thread_tid(t);
        txns[nranges].start = ds;
        txns[nranges].end = de;
        txns[nranges].deferred_count = t->deferred_stack_unmap_count;
        for (int j = 0; j < t->deferred_stack_unmap_count; j++) {
            txns[nranges].deferred_starts[j] =
                t->deferred_stack_unmap_starts[j];
            txns[nranges].deferred_ends[j] = t->deferred_stack_unmap_ends[j];
        }
        nranges++;
    }

    /* Pass 2: commit. Both passes iterate the table in the same order under the
     * same lock, so the active set seen here matches pass 1.
     */
    for (int i = 0; i < nranges; i++) {
        (void) thread_add_deferred_unmap_locked(txns[i].thread, txns[i].start,
                                                txns[i].end);
        txns[i].thread->deferred_stack_unmap_busy++;
    }
    pthread_mutex_unlock(&thread_lock);

    return nranges;
}

void thread_finish_deferred_stack_ranges(
    const thread_deferred_stack_unmap_txn_t *txns,
    int nranges)
{
    bool wake = false;

    if (!txns || nranges <= 0)
        return;

    pthread_mutex_lock(&thread_lock);
    for (int i = 0; i < nranges; i++) {
        thread_entry_t *t = txns[i].thread;

        if (!t || !atomic_load_explicit(&t->active, memory_order_relaxed) ||
            thread_tid(t) != txns[i].guest_tid ||
            t->deferred_stack_unmap_busy <= 0)
            continue;
        t->deferred_stack_unmap_busy--;
        wake = true;
    }
    if (wake)
        pthread_cond_broadcast(&deferred_stack_unmap_cond);
    pthread_mutex_unlock(&thread_lock);
}

void thread_rollback_deferred_stack_ranges(
    const thread_deferred_stack_unmap_txn_t *txns,
    int nranges)
{
    bool wake = false;

    if (!txns || nranges <= 0)
        return;

    pthread_mutex_lock(&thread_lock);
    for (int i = 0; i < nranges; i++) {
        thread_entry_t *t = txns[i].thread;

        if (!t || !atomic_load_explicit(&t->active, memory_order_relaxed) ||
            thread_tid(t) != txns[i].guest_tid)
            continue;
        t->deferred_stack_unmap_count = txns[i].deferred_count;
        for (int j = 0; j < txns[i].deferred_count; j++) {
            t->deferred_stack_unmap_starts[j] = txns[i].deferred_starts[j];
            t->deferred_stack_unmap_ends[j] = txns[i].deferred_ends[j];
        }
        if (t->deferred_stack_unmap_busy > 0) {
            t->deferred_stack_unmap_busy--;
            wake = true;
        }
    }
    if (wake)
        pthread_cond_broadcast(&deferred_stack_unmap_cond);
    pthread_mutex_unlock(&thread_lock);
}

int thread_prepare_deferred_stack_unmaps_for_cleanup(thread_entry_t *t,
                                                     uint64_t *starts,
                                                     uint64_t *ends,
                                                     int max_ranges)
{
    int nranges = 0;

    if (!t || !starts || !ends || max_ranges <= 0)
        return 0;

    pthread_mutex_lock(&thread_lock);
    while (t->deferred_stack_unmap_busy > 0)
        pthread_cond_wait(&deferred_stack_unmap_cond, &thread_lock);
    t->stack_map_start = 0;
    t->stack_map_end = 0;
    nranges = t->deferred_stack_unmap_count;
    if (nranges > max_ranges)
        nranges = max_ranges;
    for (int i = 0; i < nranges; i++) {
        starts[i] = t->deferred_stack_unmap_starts[i];
        ends[i] = t->deferred_stack_unmap_ends[i];
    }
    pthread_mutex_unlock(&thread_lock);

    return nranges;
}

int thread_drop_deferred_stack_unmap(thread_entry_t *t,
                                     uint64_t start,
                                     uint64_t end)
{
    int removed = 0;

    if (!t || start >= end)
        return 0;

    pthread_mutex_lock(&thread_lock);
    int n = t->deferred_stack_unmap_count;
    for (int i = 0; i < n; i++) {
        if (t->deferred_stack_unmap_starts[i] != start ||
            t->deferred_stack_unmap_ends[i] != end)
            continue;
        n--;
        t->deferred_stack_unmap_starts[i] = t->deferred_stack_unmap_starts[n];
        t->deferred_stack_unmap_ends[i] = t->deferred_stack_unmap_ends[n];
        t->deferred_stack_unmap_count = n;
        removed = 1;
        break;
    }
    pthread_mutex_unlock(&thread_lock);

    return removed;
}

static int thread_add_deferred_unmap_locked(thread_entry_t *t,
                                            uint64_t start,
                                            uint64_t end)
{
    if (!t || start >= end)
        return 0;

    /* Absorb every existing slot that overlaps or is adjacent to [start, end),
     * expanding the candidate as needed. Compact the array in place by pulling
     * the live tail into each absorbed slot.
     */
    int n = t->deferred_stack_unmap_count;
    int i = 0;
    while (i < n) {
        uint64_t rs = t->deferred_stack_unmap_starts[i];
        uint64_t re = t->deferred_stack_unmap_ends[i];

        if (end < rs || start > re) {
            i++;
            continue;
        }
        if (rs < start)
            start = rs;
        if (re > end)
            end = re;
        n--;
        t->deferred_stack_unmap_starts[i] = t->deferred_stack_unmap_starts[n];
        t->deferred_stack_unmap_ends[i] = t->deferred_stack_unmap_ends[n];
    }

    if (n >= MAX_DEFERRED_STACK_UNMAPS) {
        t->deferred_stack_unmap_count = n;
        return -1;
    }

    t->deferred_stack_unmap_starts[n] = start;
    t->deferred_stack_unmap_ends[n] = end;
    t->deferred_stack_unmap_count = n + 1;
    return 0;
}

static int thread_can_add_deferred_unmap_locked(thread_entry_t *t,
                                                uint64_t start,
                                                uint64_t end)
{
    if (!t || start >= end)
        return 0;

    for (int i = 0; i < t->deferred_stack_unmap_count; i++) {
        uint64_t rs = t->deferred_stack_unmap_starts[i];
        uint64_t re = t->deferred_stack_unmap_ends[i];

        if (end < rs || start > re)
            continue;
        return 0;
    }

    return (t->deferred_stack_unmap_count < MAX_DEFERRED_STACK_UNMAPS) ? 0 : -1;
}

static void thread_ptrace_init(thread_entry_t *t)
{
    t->ptraced = false;
    t->tracer_tid = 0;
    t->ptrace_stopped = false;
    t->ptrace_stop_sig = 0;
    t->ptrace_cont_sig = 0;
    t->ptrace_regs_dirty = false;
    t->is_vm_clone = false;
    t->parent_tid = 0;
    t->exit_signal = 0;
    t->vm_exited = false;
    t->vm_exit_status = 0;
    memset(&t->ptrace_regs, 0, sizeof(t->ptrace_regs));
    pthread_cond_init(&t->ptrace_cond, NULL);
    pthread_cond_init(&t->resume_cond, NULL);
    t->ptrace_conds_inited = true;
    t->ptrace_waiters = 0;
    t->ptrace_cleanup_pending = false;
}

int thread_ptrace_stop(thread_entry_t *t, int sig)
{
    hv_vcpu_t vcpu;
    if (!vcpu_pool_current_vcpu(&vcpu))
        return -LINUX_EIO;
    pthread_mutex_lock(&thread_lock);
    vcpu_snapshot_gprs(vcpu, t->ptrace_regs.regs);
    t->ptrace_regs.sp = vcpu_get_sysreg(vcpu, HV_SYS_REG_SP_EL0);

    /* Which PC and PSTATE the tracer sees depends on where the stop landed. At
     * EL0 the live PC/CPSR are the architectural state and ELR_EL1/ SPSR_EL1
     * are stale from the ERET that entered it. Inside the shim the opposite
     * holds: the vCPU runs at EL1 and ELR_EL1/SPSR_EL1 name the EL0 context it
     * is about to ERET to. An interrupt can stop a task at either place; the
     * EL1 windows converge on HVC #5/#13, an EL0 task stops where the kick
     * found it.
     */
    uint64_t cpsr = vcpu_get_reg(vcpu, HV_REG_CPSR);
    if ((cpsr & 0xfULL) == 0) {
        t->ptrace_regs.pc = vcpu_get_reg(vcpu, HV_REG_PC);
        t->ptrace_regs.pstate = cpsr;
    } else {
        t->ptrace_regs.pc = vcpu_get_sysreg(vcpu, HV_SYS_REG_ELR_EL1);
        t->ptrace_regs.pstate = vcpu_get_sysreg(vcpu, HV_SYS_REG_SPSR_EL1);
    }
    t->ptrace_stopped = true;
    t->ptrace_stop_sig = sig;
    t->ptrace_cont_sig = 0;
    t->ptrace_regs_dirty = false;
    exec_park_current(PARK_KIND_STOP, EXEC_PARK_RESUME_PLAIN);
    int64_t tracer_tid = t->tracer_tid;
    sched_task_set_trace_stopped(t, true);
    pthread_cond_broadcast(&t->ptrace_cond);
    pthread_mutex_unlock(&thread_lock);
    thread_entry_t *tracer = thread_acquire_tid(tracer_tid);
    if (tracer) {
        (void) sched_park_try_complete_reissue(tracer);
        thread_release(tracer);
    }
    return 0;
}

void thread_ptrace_cont(thread_entry_t *t, int sig)
{
    pthread_mutex_lock(&thread_lock);
    t->ptrace_cont_sig = sig;
    t->ptrace_stopped = false;
    pthread_mutex_unlock(&thread_lock);
    sched_task_set_trace_stopped(t, false);
    sched_wake_stop(t);
}

void thread_ptrace_apply_resume(thread_entry_t *t, hv_vcpu_t vcpu)
{
    pthread_mutex_lock(&thread_lock);
    if (t->ptrace_regs_dirty) {
        vcpu_restore_gprs(vcpu, t->ptrace_regs.regs);
        vcpu_set_sysreg(vcpu, HV_SYS_REG_SP_EL0, t->ptrace_regs.sp);
        vcpu_set_sysreg(vcpu, HV_SYS_REG_ELR_EL1, t->ptrace_regs.pc);
        vcpu_set_sysreg(vcpu, HV_SYS_REG_SPSR_EL1, t->ptrace_regs.pstate);

        /* An EL0 task resumes from PC/CPSR and never consults the ELR writes
         * above; a shim tail runs at EL1 and resumes through ELR_EL1, so its
         * live PC/CPSR must stay the shim's. Same split gdbstub-reg makes when
         * the stop it applies landed at EL0.
         */
        uint64_t cpsr = vcpu_get_reg(vcpu, HV_REG_CPSR);
        if ((cpsr & 0xfULL) == 0) {
            vcpu_set_reg(vcpu, HV_REG_PC, t->ptrace_regs.pc);
            vcpu_set_reg(vcpu, HV_REG_CPSR,
                         (uint64_t) (uint32_t) t->ptrace_regs.pstate);
        }
        t->ptrace_regs_dirty = false;
    }
    int sig = t->ptrace_cont_sig;
    t->ptrace_cont_sig = 0;
    pthread_mutex_unlock(&thread_lock);
    if (sig > 0)
        (void) signal_queue_thread(thread_tid(t), sig);
}

bool thread_ptrace_stop_requested(thread_entry_t *t)
{
    pthread_mutex_lock(&thread_lock);
    bool requested =
        t && t->ptrace_interrupt_pending && t->ptraced && !t->ptrace_stopped;
    pthread_mutex_unlock(&thread_lock);
    return requested;
}

/* True when t is a waitable child of the given tracer, optionally narrowed by
 * pid (>0 = exact TID, <=0 = any). Caller holds thread_lock.
 */
static bool thread_matches_tracer_child(const thread_entry_t *t,
                                        int64_t tracer_tid,
                                        int pid)
{
    if (!atomic_load_explicit(&t->active, memory_order_relaxed))
        return false;
    bool is_child = (t->ptraced && t->tracer_tid == tracer_tid) ||
                    (t->is_vm_clone && t->parent_tid == tracer_tid);
    if (!is_child)
        return false;
    if (pid > 0 && thread_tid(t) != pid)
        return false;
    return true;
}

int64_t thread_ptrace_wait(int64_t tracer_tid,
                           int pid,
                           int *out_status,
                           int options)
{
    int wnohang = (options & 1); /* WNOHANG = 1 on Linux */

    pthread_mutex_lock(&thread_lock);

    for (;;) {
        /* exit_group or execve teardown: the stop/exit notifications that would
         * signal ptrace_cond stop arriving once workers are being torn down.
         *
         * Return 0 ("no matching children") so the caller falls through and its
         * blocking paths re-check proc_exit_group_requested.
         */
        if (thread_stop_requested()) {
            pthread_mutex_unlock(&thread_lock);
            return 0;
        }

        bool found_any = false; /* Any waitable children at all? */

        THREAD_FOR_EACH (t) {
            if (!thread_matches_tracer_child(t, tracer_tid, pid))
                continue;

            found_any = true;

            /* Ptrace-stopped: report stop signal in wait status. */
            if (t->ptrace_stopped) {
                int64_t tid = thread_tid(t);
                if (out_status)
                    *out_status = (t->ptrace_stop_sig << 8) | 0x7F;
                pthread_mutex_unlock(&thread_lock);
                return tid;
            }

            /* VM-clone child exited: reap and deactivate. */
            if (t->vm_exited) {
                int64_t tid = thread_tid(t);
                if (out_status)
                    *out_status = t->vm_exit_status;

                /* Destroy condvars after the last waiter returns from
                 * pthread_cond_wait().
                 */
                thread_free_sp_el1_locked(t);
                atomic_store_explicit(&t->active, 0, memory_order_release);
                atomic_fetch_sub_explicit(&active_thread_count, 1,
                                          memory_order_relaxed);
                t->ptrace_cleanup_pending = true;
                thread_ptrace_cleanup_locked(t);
                pthread_mutex_unlock(&thread_lock);

                /* Slot is now inactive; drop any unconsumed thread-directed
                 * pending bits from the global hint (same rationale as
                 * thread_deactivate). Outside thread_lock to honor sig_lock (4)
                 * before thread_lock (5).
                 */
                signal_refresh_pending_hint();
                return tid;
            }
        }

        if (!found_any) {
            pthread_mutex_unlock(&thread_lock);
            return 0; /* No matching children; let caller fall through */
        }

        if (wnohang) {
            pthread_mutex_unlock(&thread_lock);
            return 0;
        }

        pthread_mutex_unlock(&thread_lock);
        return io_park_unmount(-1, 0, 1);
    }
}
