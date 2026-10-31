/*
 * Linux futex emulation
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hash table of wait queues keyed by guest virtual address. Each bucket has its
 * own mutex for fine-grained locking. Waiters are singly-linked lists with
 * per-waiter condition variables for precise wakeup.
 *
 * Atomicity: The critical FUTEX_WAIT race (guest writes futex word after the
 * current read but before the waiter sleeps) is prevented by holding the bucket
 * lock across the word-read + enqueue + cond_wait sequence. FUTEX_WAKE also
 * acquires the same bucket lock, so a wake cannot slip between the read and the
 * wait.
 *
 * Timeout: FUTEX_WAIT with a non-NULL timeout uses pthread_cond_timedwait with
 * an absolute deadline. FUTEX_WAIT_BITSET always uses absolute time.
 */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <sys/time.h>

#include "utils.h"

#include "core/host-sigbus.h"
#include "core/shim-globals.h"
#include "runtime/futex.h"
#include "runtime/thread.h"
#include "runtime/sched/sched.h"
#include "runtime/sched/exec.h"

#include "syscall/linux-wire.h"
#include "syscall/proc.h"
#include "syscall/signal.h"

#include "debug/log.h"
#include "proved/futexhash.h"
#include "proved/futexop.h"
#include "proved/futexpi.h"
#include "proved/futexreq.h"
#include "proved/futexwaitv.h"
#include "proved/futexwakeop.h"
#include "proved/timespec.h"

/* Interrupt flag: when set, futex_wait returns -EINTR. Raised only by teardown
 * through thread_wake_all_blocked, so every blocked wait can observe that the
 * process is tearing down without a full exit_group.
 */
static _Atomic int futex_interrupt_requested = 0;

/* Futex operations (from Linux uapi). */
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_REQUEUE 3
#define FUTEX_CMP_REQUEUE 4
#define FUTEX_WAKE_OP 5
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12

/* Strips the FUTEX_PRIVATE_FLAG (0x80) and FUTEX_CLOCK_REALTIME bits so the
 * dispatch switch sees only the base operation. Emulation doesn't differentiate
 * private vs shared futexes (single-process guest).
 */
#define FUTEX_CMD_MASK 0x7F

/* Linux uapi: selected timeout uses CLOCK_REALTIME instead of MONOTONIC. Only
 * WAIT_BITSET / WAIT_REQUEUE_PI (and LOCK_PI2, unimplemented) accept it;
 * LOCK_PI historically uses realtime without this bit and returns -ENOSYS if
 * the flag is set (ks-futex_wait_timeout global.lock_pi).
 */
#define FUTEX_CLOCK_REALTIME 0x100
/* Unlock + clear list_op_pending in one futex op (newer Linux uapi). */
#define FUTEX_ROBUST_UNLOCK 512
#define FUTEX_ROBUST_LIST32 1024

/* core/shim.S futex_wait_fast decodes the same three values as immediates,
 * because assembly cannot see these defines. That leaves the shim serving a
 * shape the host would decode differently if one ever changes, with nothing to
 * catch it: test-shim-futex-stats.sh only asserts the counters move. Pin them
 * the way shim-globals.c pins the urandom literals it shares with the shim.
 */
_Static_assert(FUTEX_CMD_MASK == 0x7F,
               "core/shim.S futex_wait_fast hardcodes and w15, w14, #0x7f");
_Static_assert(FUTEX_WAIT == 0,
               "core/shim.S futex_wait_fast hardcodes cmp w15, #0");
_Static_assert(FUTEX_WAIT_BITSET == 9,
               "core/shim.S futex_wait_fast hardcodes cmp w15, #9");
_Static_assert(FUTEX_WAKE == 1,
               "core/shim.S futex_wait_fast hardcodes cmp w15, #1");
_Static_assert(FUTEX_WAKE_BITSET == 10,
               "core/shim.S futex_wait_fast hardcodes cmp w15, #10");

#define FUTEX_BITSET_MATCH_ANY 0xFFFFFFFFU

/* The PI word's three fields and the edits made to them are proved/futexpi.h,
 * which carries the layout and Linux's own constants.
 */

/* The wait quantum is capped at 100 ms so proc_exit_group_requested() and
 * futex_interrupt_consume() get noticed promptly without a process-wide
 * broadcast channel. EINTR is only returned when an actual deliverable signal
 * is queued for this thread (confirmed under sig_lock via signal_pending(), not
 * the atomic hint, so that rt_sigprocmask masking the queued signal cannot
 * leave a stale-true edge behind), or when a guest itimer expires under the
 * poll loop's signal_check_timer poke. Earlier revisions returned -EINTR after
 * one unconditional second of waiting to unblock shutdown-stalled
 * multi-threaded runtimes, but that broke POSIX sem_wait callers that do not
 * retry on EINTR (e.g. foot's render worker).
 */
#define FUTEX_POLL_QUANTUM_NS (100ULL * 1000 * 1000)

/* Hash table.
 *
 * Sized for wakers, not waiters. Concurrent waiters are memory/IPA-limited
 * rather than capped at 64, so 64 buckets would already keep the chains short;
 * what makes the table too narrow is that futex_wake takes the bucket lock even
 * when nothing is queued in the chain. Two threads waking unrelated futexes
 * therefore serialize whenever their addresses collide, which at 64 buckets is
 * often enough to cost more than the wake itself: eight threads each waking
 * their own private futex measured 801 ns per wake, worse than the same test at
 * four threads.
 *
 * At 1024, paired with the multiply-shift hash below, the collapse is gone (316
 * ns per wake against 801, and eight threads now beat four). Width alone was
 * not enough: the old shift-xor hash kept page-strided futexes in two buckets
 * at any width, so both had to change. Not widened further: iSH runs 4096, but
 * with a 64-thread ceiling the residual collision rate is already negligible
 * and the table is a fixed allocation: 64 KiB of mutexes at this size, inside
 * 128 KiB of BSS once padded. The whole table went from 5 KiB to 128 KiB, which
 * also costs about 25 us of extra futex_init per launch and per fork child
 * (1024 mutex inits plus first touch), under 0.1 percent of a fork.
 */

#define FUTEX_BUCKETS 1024u

/* How many times a census violation has to reproduce before it is believed. See
 * the contract assert in futex_wake for why one reading cannot decide. Five,
 * because the observed transients cleared on the first re-read every time and
 * the cost is paid only on a reading that already looks wrong.
 */
#define FUTEX_CENSUS_RECHECKS 5

/* The shim's wake fast path recomputes this bucket index in assembly, so both
 * the table size and the multiplier are pinned here. A divergence would send
 * the shim to the wrong count, and a wrong count that reads zero is a lost
 * wakeup rather than a slow path.
 */
_Static_assert(FUTEX_BUCKETS == SHIM_FUTEX_BUCKETS,
               "core/shim.S futex_wake_fast hardcodes and x15, x15, #1023");
_Static_assert((FUTEX_BUCKETS & (FUTEX_BUCKETS - 1)) == 0,
               "the shim masks instead of dividing, so this must be a power "
               "of two");
_Static_assert(FUTEX_HASH_MULT == 0x9E3779B97F4A7C15ULL,
               "core/shim.S futex_wake_fast builds this constant with movz "
               "and three movk");

/* Per-waiter node: one heap record per parked wait. */
struct futex_pi_lock;
struct futex_waitv_group;

typedef struct futex_waiter {
    uint64_t uaddr;            /* Guest VA being waited on */
    uint32_t bitset;           /* For WAIT_BITSET matching */
    pthread_cond_t cond;       /* Signalled by WAKE to unblock this waiter */
    _Atomic int woken;         /* Set to 1 by WAKE before signalling */
    struct futex_waiter *next; /* Next waiter in same bucket */


    /* Which bucket this waiter's published count was charged to. Normally the
     * bucket its uaddr hashes to, but FUTEX_REQUEUE moves a parked waiter to
     * another address, and the publication has to move with it: a count left on
     * the old bucket would let the shim answer a wake on the new address with
     * zero while this waiter is still parked. Requeue rewrites this field under
     * both bucket locks, and the wait path drops whatever it finds here rather
     * than what it charged on entry.
     */
    unsigned pub_bucket;

    /* Whether this waiter's owner drops the charge named by pub_bucket rather
     * than the bucket it charged on entry. futex_wait_inner and sys_futex_waitv
     * do. A LOCK_PI waiter does not: its wrapper drops the entry bucket on
     * every non-parked return, while a WAIT_REQUEUE_PI waiter starts with the
     * charge following it and drops that flag when CMP_REQUEUE_PI moves it.
     * Requeue reads this to decide whether moving the charge is safe.
     */
    bool pub_follows;

    /* Index of the bucket whose chain holds this waiter. A wake takes only the
     * lock of the bucket it finds the waiter in, so the owner has to sleep, and
     * test woken, under that same lock or the two are not ordered. Requeue
     * stores this under both bucket locks when it moves the waiter and signals
     * cond, and the owner loads it to learn which lock to hold. PI requeue
     * moves a WAIT_REQUEUE_PI waiter the same way.
     */
    _Atomic unsigned home;

    /* Non-NULL when the waiter was armed for pool async park (heap-allocated).
     * Wake/timeout/signal completes via sched_park_try_complete instead of
     * pthread_cond_wait on the worker.
     */
    thread_entry_t *async_owner;

    /* FUTEX_WAIT_REQUEUE_PI: waiter starts on uaddr and may be moved onto the
     * PI futex at requeue_pi_uaddr by FUTEX_CMP_REQUEUE_PI. waiter_tid is the
     * guest TID used for PI lock handoff (unlock_pi / cmp_requeue_pi).
     */
    bool requeue_pi;
    uint64_t requeue_pi_uaddr;
    uint32_t waiter_tid;

    /* PI state. pi_state is non-NULL while this waiter is queued on a PI lock's
     * waiter list; pi_task is the blocked task and holds a thread reference
     * from link until unlink (or until a handoff transfers that reference to
     * the lock record). All three are protected by the module's PI mutex, never
     * by the bucket lock. is_pi is LOCK_PI membership and is fixed at enqueue;
     * requeue_pi is WAIT_REQUEUE_PI membership and lets the cancel path choose
     * the PI lock before the waiter can be moved.
     */
    bool is_pi;
    bool pi_lock_pi;
    struct thread_entry *pi_task;
    struct futex_pi_lock *pi_state;
    struct futex_waiter *pi_next;
    uint64_t pi_seq;

    /* futex_waitv: the shared registration this waiter belongs to. Every node
     * in the set points at one group, whose single completion retires all of
     * them.
     */
    struct futex_waitv_group *waitv_group;
    int waitv_index;
} futex_waiter_t;

/* futex_waitv publishes its group in t->async_futex_waiter with the low bit
 * set, so every completion path can tell a group from a single waiter without
 * dereferencing a pointer that a racing completion may have freed. Groups are
 * malloc-aligned, so bit 0 is free.
 */
#define FUTEX_WAITV_TAG ((uintptr_t) 1)

static inline void *futex_waitv_tag(struct futex_waitv_group *g)
{
    return (void *) ((uintptr_t) g | FUTEX_WAITV_TAG);
}

static inline bool futex_async_is_waitv(const void *p)
{
    return ((uintptr_t) p & FUTEX_WAITV_TAG) != 0;
}

static inline struct futex_waitv_group *futex_async_waitv_group(const void *p)
{
    return (struct futex_waitv_group *) ((uintptr_t) p & ~FUTEX_WAITV_TAG);
}

/* Module-wide lifetime lock for futex wait records.
 *
 * A path that reads t->async_futex_waiter and then dereferences the record
 * needs more than a generation check: the generation proves the park is still
 * the one it woke, not that the record has not been freed since the load. Every
 * wake that completes a park frees the record off the bucket lock, so a reader
 * that took the pointer first would be dereferencing a returned allocation; the
 * re-check under the bucket cannot protect the earlier field reads. This lock
 * makes the load, the first dereference and the free one critical section:
 *
 *   - every reader of the published token holds it from the load through the
 *     last field it reads, and re-checks the token under the bucket lock
 *     before unlinking or completing the park;
 *   - every free of a waiter or a waitv group that could have been published
 *     holds it, after the publication was cleared (under the bucket lock that
 *     carries the claim, or here for a completion). A free without it is the
 *     race this exists to prevent. Records that were never published (a failed
 *     enqueue, or the wait-set early return before its tag store) are freed by
 *     the constructor under the bucket it already holds; no other thread can
 *     have named them.
 *
 * futex_waitv's group retirement used to carry its own mutex for the same
 * reason; it is this lock now, so single waiters, group members and tagged
 * group tokens all retire under one rule.
 *
 * Lock order: futex_lifetime_mutex -> futex_pi_mutex -> bucket locks, and above
 * sched_lock where a completion is published. It is never taken while holding a
 * bucket, futex_pi_mutex, sched_lock, thread_lock or sig_lock: the sync wait
 * paths claim under the bucket and acquire it only after dropping it, and a
 * signal claim (sig_lock) runs before it. Nothing below it takes it again, so a
 * completion that runs sched_dispatch under it cannot recurse.
 */
static pthread_mutex_t futex_lifetime_mutex = PTHREAD_MUTEX_INITIALIZER;



/* One bucket in the hash table. Protected by its own mutex, placed in the
 * lock-ordering block of src/syscall/internal.h (index-ordered when two are
 * acquired). Padded to a cache line. The struct is 72 bytes and this host's
 * line is 128, so unpadded neighbours share a line and two futexes the hash
 * correctly separated still contend on it. Measured with eight threads each
 * taking its own adjacent bucket: 16-18 ns per lock unpadded against 5-8 ns
 * padded, a 2-4x share of exactly the contention the 64-to-1024 widening was
 * made to remove. The padding itself costs BSS only, 73728 bytes to 131072 at
 * this bucket count; the table's total is above FUTEX_BUCKETS.
 */
typedef struct {
    pthread_mutex_t lock;
    futex_waiter_t *head; /* Linked list of waiters hashing to this bucket */
} __attribute__((aligned(128))) futex_bucket_t;

static futex_bucket_t buckets[FUTEX_BUCKETS];

/* Hash a guest VA to a bucket index.
 *
 * The mixing and its bound are futex_bucket_index in proved/futexhash.h, which
 * carries the postcondition that makes buckets[idx] in-range for any address a
 * guest can name. That mattered enough to prove: the index selects an element
 * of a fixed array on a hot path.
 *
 * The form it replaced, ((uaddr >> 2) ^ (uaddr >> 14)), aliased badly on
 * exactly the strides real allocators produce. Futexes laid out one per
 * cache-line pair, per slab slot, or per page differ by a power of two, and a
 * shift-xor of a power-of-two stride leaves the low index bits constant. Eight
 * futexes 256 bytes apart landed in one bucket of 64; eight a page apart landed
 * in two buckets, and stayed in two however wide the table grew, so widening
 * relocated the collapse rather than fixing it and the hash had to change with
 * it.
 */
static inline unsigned futex_hash(uint64_t uaddr)
{
    return futex_bucket_index(uaddr, FUTEX_BUCKETS);
}

/* Linux requires a futex word to be naturally aligned, and every op checks this
 * before the address reaches a bucket. Stated as a contract because without one
 * a widened or narrowed mask breaks no obligation: the proof would pass on a
 * body it never constrained, and the mutation gate would have nothing to
 * reject.
 *
 * The ensures is in the bit domain rather than the more readable "uaddr % 4 ==
 * 0" because the prover times out bridging modulo and bitmask on a 64-bit
 * value. Measured at the 30s budget, and a fresh cache does not help.
 */
/*@
  assigns \nothing;
  ensures \result <==> (uaddr & 0x3) == 0;
 */
static inline bool futex_uaddr_is_aligned(uint64_t uaddr)
{
    return (uaddr & 0x3) == 0;
}


/* Signal kick. A thread parked in FUTEX_WAIT or FUTEX_WAIT_BITSET watches
 * neither the wakeup pipe nor its condition variable, so futex_kick is what
 * tells it a signal was queued. The polling quantum stays, for teardown.
 *
 * The kicker sets futex_kick and then looks for a park; the thread publishes
 * its park and then tests futex_kick before it sleeps. All of it is seq_cst, so
 * at least one of the two sees the other. The park is signalled under the mutex
 * it published, which closes the window between its test and its sleep. A
 * waiter FUTEX_REQUEUE moved publishes again under its new bucket's lock.
 */
static bool futex_kick_consume(void)
{
    thread_entry_t *t = current_thread;
    return t && atomic_exchange_explicit(&t->futex_kick, 0,
                                         memory_order_seq_cst) != 0;
}

/* Signal kick. A parked futex waiter is an async park: the kick is remembered
 * and the parked task is completed with EINTR. The flag covers a kick that
 * lands before the task publishes its park.
 */
void futex_kick(thread_entry_t *t)
{
    atomic_store_explicit(&t->futex_kick, 1, memory_order_seq_cst);
    futex_park_on_interrupt(t);
}

/* Unlink a waiter from its bucket's singly-linked list. Caller must hold
 * b->lock. Silently returns if the waiter is not in the list (already unlinked
 * by a wake/requeue).
 */
static void bucket_unlink_locked(futex_bucket_t *b, const futex_waiter_t *w)
{
    for (futex_waiter_t **pp = &b->head; *pp; pp = &(*pp)->next) {
        if (*pp == w) {
            *pp = w->next;
            return;
        }
    }
}

/* Trade @b->lock, which the caller holds, for the lock of the bucket @w is
 * queued in or was woken from, and return that bucket. home cannot change under
 * the lock it names, since moving the waiter out takes that lock, so once this
 * returns a wake has either finished with @w or not found it yet.
 */
static futex_bucket_t *futex_waiter_follow(futex_bucket_t *b,
                                           const futex_waiter_t *w)
{
    for (;;) {
        futex_bucket_t *home =
            &buckets[atomic_load_explicit(&w->home, memory_order_acquire)];
        if (home == b)
            return b;
        pthread_mutex_unlock(&b->lock);
        pthread_mutex_lock(&home->lock);
        b = home;
    }
}

/* Whether any waiter on @uaddr is queued in @b. Caller must hold b->lock. */
static bool bucket_has_uaddr_locked(const futex_bucket_t *b, uint64_t uaddr)
{
    for (const futex_waiter_t *w = b->head; w; w = w->next) {
        if (w->uaddr == uaddr)
            return true;
    }
    return false;
}


/* Claim a heap async waiter for a pre-unmount teardown. Caller holds the bucket
 * lock and has published async_futex_waiter = waiter. Clearing
 * async_futex_waiter here is the ownership claim: futex_async_cancel rechecks
 * it under the same lock and must not finish_bookkeeping a pointer we free
 * after unlock.
 *
 * Returns true when this caller owns the free; the wait wrapper still drops the
 * shim charge on a non-PARKED return.
 */
static bool futex_async_claim_pre_unmount_locked(thread_entry_t *self,
                                                 futex_waiter_t *waiter)
{
    if (!self || exec_park_waiter_load(self) != waiter)
        return false;
    exec_park_waiter_store(self, NULL);
    exec_park_result_pending_store(self, false);
    exec_park_kind_store(self, PARK_KIND_NONE);
    exec_park_active_store(self, false);
    self->async_futex_timed = false;
    self->park_guest = NULL;
    return true;
}

/* Caller has already cleared the publication and must not hold the bucket it
 * held for the claim: futex_lifetime_mutex is outer to the bucket locks, and
 * the free is the half of the claim that has to wait for a reader which loaded
 * the token before the clear.
 */
static void futex_async_free_claimed(futex_waiter_t *waiter)
{
    pthread_mutex_lock(&futex_lifetime_mutex);
    pthread_cond_destroy(&waiter->cond);
    free(waiter);
    pthread_mutex_unlock(&futex_lifetime_mutex);
}

static void futex_pi_forget_waiter(futex_waiter_t *w);
static void futex_waitv_note_wake(futex_waiter_t *w);
static void futex_waitv_flush_locked(thread_entry_t *t,
                                     struct futex_waitv_group *g);
static bool futex_waitv_cancel_locked(thread_entry_t *t,
                                      struct futex_waitv_group *g,
                                      int64_t result);
static void futex_async_cancel(thread_entry_t *t, int64_t result);

/* Free the async waiter that was woken/cancelled. @w must be the waiter
 * snapshotted BEFORE sched_park_try_complete*: that call enqueues the thread,
 * which may remount on another slot and publish a new async_futex_waiter (e.g.
 * pthread_join's FUTEX_WAIT) before we reach free(). Freeing via a re-read of
 * t->async_futex_waiter then destroys the live join waiter while it is still
 * linked, so CLEARTID wake misses it and stress_owner_exits hangs.
 *
 * Caller holds futex_lifetime_mutex. That lock is what keeps a reader which
 * loaded the token just before the publication was cleared from dereferencing
 * the record after this free, so it is required, not just asserted.
 */
static void futex_async_finish_bookkeeping_locked(thread_entry_t *t,
                                                  futex_waiter_t *w,
                                                  guest_t *g)
{
    if (!t)
        return;

    /* Prefer the waiter's pub_bucket: FUTEX_REQUEUE rewrites it when it moves
     * the charge. t->async_futex_pub_bucket is only the entry charge and would
     * wrap the vacated bucket if used after a requeue (test-futex-requeue-
     * account).
     */
    unsigned pub = w ? w->pub_bucket : t->async_futex_pub_bucket;

    if (exec_park_waiter_load(t) == w) {
        exec_park_waiter_store(t, NULL);
        t->park_guest = NULL;
        t->async_futex_pub_bucket = 0;
        t->async_futex_timed = false;
    }

    /* If remount already published a different waiter, leave thread fields
     * alone and still free @w / drop its bucket charge below. Snapshot @g was
     * taken from the park that owned @w (caller must snapshot before
     * try_complete when racing remount is possible; flush/cancel do).
     */

    if (w) {
        /* A wake that did not hand the lock off leaves the waiter on the PI
         * record. Do not free or leak that link.
         */
        futex_pi_forget_waiter(w);
        pthread_cond_destroy(&w->cond);
        free(w);
    }
    if (g)
        shim_globals_futex_waiters_add(g, pub, -1);
}

/* Deferred async park completes: wake holds the bucket lock, and
 * sched_park_try_complete takes sched_lock, so owners are queued and flushed
 * once the bucket is released. Each entry is flushed under
 * futex_lifetime_mutex: the token was snapshotted when the wake unlinked the
 * waiter, and completion frees the record, so the load, the seq re-check and
 * the free have to share a lock with every other reader of that token. Growable
 * TLS queue: a single wake may complete many async parks; dropping one would
 * lose a wakeup. Starts small and doubles as needed.
 */
typedef struct {
    thread_entry_t *owner;
    void *async; /* The wait token this wake was raised for */
    uint64_t park_seq;

    /* Fields snapshotted under the bucket lock, while @w was still linked: the
     * owner may return early and free the waiter before this entry is flushed,
     * so the retry decision must not dereference it.
     */
    uint64_t uaddr;
    uint64_t requeue_pi_uaddr;
    uint64_t waiter_tid;
    guest_t *park_guest;
    bool pi_lock_pi;
    bool requeue_pi;
} futex_async_wake_t;

static _Thread_local futex_async_wake_t *futex_async_wake_q;
static _Thread_local int futex_async_wake_n;
static _Thread_local int futex_async_wake_cap;

static void futex_async_wake_queue(futex_waiter_t *w)
{
    thread_entry_t *owner = w ? w->async_owner : NULL;
    if (!owner)
        return;
    if (futex_async_wake_n >= futex_async_wake_cap) {
        int ncap = futex_async_wake_cap ? futex_async_wake_cap * 2 : 16;
        futex_async_wake_t *nq =
            realloc(futex_async_wake_q, (size_t) ncap * sizeof(*nq));
        if (!nq) {
            log_error("futex: async wake queue OOM");
            return;
        }
        futex_async_wake_q = nq;
        futex_async_wake_cap = ncap;
    }
    futex_async_wake_t *e = &futex_async_wake_q[futex_async_wake_n++];
    e->owner = owner;
    e->async = w->waitv_group ? futex_waitv_tag(w->waitv_group) : (void *) w;
    e->park_seq = sched_park_seq(owner);
    e->uaddr = w->uaddr;
    e->requeue_pi_uaddr = w->requeue_pi_uaddr;
    e->waiter_tid = w->waiter_tid;
    e->park_guest = owner->park_guest;
    e->pi_lock_pi = w->pi_lock_pi;
    e->requeue_pi = w->requeue_pi;
}

static bool futex_word_load(const uint32_t *word, uint32_t *out);

static void futex_async_wake_flush(void)
{
    int n = futex_async_wake_n;
    futex_async_wake_n = 0;
    for (int i = 0; i < n; i++) {
        futex_async_wake_t *e = &futex_async_wake_q[i];
        thread_entry_t *owner = e->owner;

        /* A LOCK_PI waiter may only complete with 0 when the waker already
         * handed it the word; otherwise re-dispatch the SVC and retry the
         * acquisition. WAIT_REQUEUE_PI woken before CMP_REQUEUE_PI moved it is
         * also re-dispatched; after requeue it must own the PI word.
         *
         * The completion only acts on the wait this wake was raised for: the
         * token and generation must still be the task's current park, so an
         * owner that already returned early and armed a new wait is not
         * completed by this stale queue entry.
         */
        pthread_mutex_lock(&futex_lifetime_mutex);
        void *async = exec_park_waiter_load(owner);
        if (!async || async != e->async ||
            sched_park_seq(owner) != e->park_seq) {
            pthread_mutex_unlock(&futex_lifetime_mutex);
            continue;
        }
        if (futex_async_is_waitv(async)) {
            futex_waitv_flush_locked(owner, futex_async_waitv_group(async));
            pthread_mutex_unlock(&futex_lifetime_mutex);
            continue;
        }
        futex_waiter_t *w = (futex_waiter_t *) async;
        bool need_retry = false;
        if (e->requeue_pi && e->uaddr != e->requeue_pi_uaddr)
            need_retry = true;
        if (!need_retry && (e->pi_lock_pi || e->requeue_pi)) {
            uint32_t *word = e->park_guest ? (uint32_t *) guest_ptr_w(
                                                 e->park_guest, e->uaddr)
                                           : NULL;
            uint32_t cur = 0;
            if (!word || !futex_word_load(word, &cur) ||
                futex_pi_owner_tid(cur) != e->waiter_tid)
                need_retry = true;
        }
        bool ok = need_retry ? sched_park_try_complete_reissue_seq(
                                   owner, PARK_KIND_FUTEX, e->park_seq)
                             : sched_park_try_complete_seq(
                                   owner, PARK_KIND_FUTEX, e->park_seq, 0);
        if (ok)
            futex_async_finish_bookkeeping_locked(owner, w, e->park_guest);
        pthread_mutex_unlock(&futex_lifetime_mutex);
    }
}

/* Unlink the waiter at *pp from its bucket list and wake it. The bucket lock
 * must be held. Unlinking before the store/signal keeps a woken waiter from
 * observing itself still queued; the release store pairs with the waiter's
 * acquire load of woken. On return *pp points at the next entry, so a scanning
 * loop should re-test *pp without advancing pp.
 */
static void futex_wake_waiter_locked(futex_waiter_t **pp)
{
    futex_waiter_t *w = *pp;
    *pp = w->next; /* unlink before signaling */
    atomic_store_explicit(&w->woken, 1, memory_order_release);
    pthread_cond_signal(&w->cond);

    if (w->waitv_group)
        futex_waitv_note_wake(w);
    if (w->async_owner)
        futex_async_wake_queue(w);
}

/* Wake the first waiter queued on @uaddr, whichever op parked it. The bucket
 * lock must be held. FUTEX_WAKE refuses a PI waiter, so the two callers that
 * have to reach one, FUTEX_UNLOCK_PI and the robust walk, come here instead.
 */
static void futex_wake_first_locked(futex_bucket_t *b, uint64_t uaddr)
{
    for (futex_waiter_t **pp = &b->head; *pp; pp = &(*pp)->next) {
        if ((*pp)->uaddr == uaddr) {
            futex_wake_waiter_locked(pp);
            return;
        }
    }
}

/* Guarded access to a guest futex word.
 *
 * A futex word can sit in a MAP_SHARED file mapping, which elfuse backs with a
 * live host overlay. Once anything truncates that file the page is gone, and
 * these atomics run from host user mode, so an unguarded access kills elfuse
 * instead of reporting an error. Both helpers return false on that fault; every
 * caller turns it into EFAULT the same way it handles an unresolvable uaddr.
 *
 * The jump lands inside these helpers, so a caller holding a bucket lock still
 * reaches its own unlock path.
 */
static bool futex_word_load(const uint32_t *word, uint32_t *out)
{
    bool faulted;
    HOST_SIGBUS_GUARD(
        faulted, *out = atomic_load_explicit((const _Atomic uint32_t *) word,
                                             memory_order_seq_cst));
    return !faulted;
}

/* The compare every waiting futex operation makes before it commits to
 * blocking. The guest reads the word, decides it should sleep, and calls futex
 * with the value it saw; between those two the value may have moved and a wake
 * may already have been sent, so this re-reads it and refuses to sleep when it
 * no longer matches. Skipping that turns a wake that arrived a moment early
 * into a wait nothing will ever satisfy.
 *
 * Returns 0 when the caller should block, -LINUX_EAGAIN when the word moved,
 * -LINUX_EFAULT when uaddr does not resolve or the load faults.
 *
 * Three callers share this: futex_wait, futex_requeue's CMP_REQUEUE, and
 * futex_waitv. What differs between them is which bucket locks are held on an
 * error return, so each keeps its own unlock ladder rather than this taking
 * one.
 *
 * futex_wait_fast in core/shim.S is a fourth implementation, in EL1 assembly,
 * answering the -LINUX_EAGAIN case without the HVC round trip. It bails to the
 * host for every input this function would answer differently, so a change to
 * the outcomes or their order here needs the same change there.
 */
static int64_t futex_should_block(const guest_t *g,
                                  uint64_t uaddr,
                                  uint32_t expected)
{
    uint32_t *word = (uint32_t *) guest_ptr(g, uaddr);
    if (!word)
        return -LINUX_EFAULT;

    uint32_t current;
    if (!futex_word_load(word, &current))
        return -LINUX_EFAULT;
    return current != expected ? -LINUX_EAGAIN : 0;
}

/* Iterations to re-read the futex word before handing the thread to the host
 * scheduler. Re-derived after the SIGBUS guard was hoisted out of the loop: the
 * first sweep ran one _setjmp per read, so its counts measured that rather than
 * the spin, and the same wall-clock spin now takes many more iterations.
 *
 * Re-swept with the guard hoisted, contended handoff: 256 gives 29.3 us (about
 * what an unspun build gives), 1024 gives 26.6 us, 4096 gives 8.3 us, 16384
 * gives 9.3 us. The knee is 4096 and past it the extra spinning costs more than
 * the park it avoids. The old constant of 256 is in that table as a warning:
 * under the per-read guard it measured a 4x win, and it buys nothing now.
 */
#define FUTEX_SPIN_ITERS 4096

/* Spin briefly waiting for the word to move, returning true if it did.
 *
 * What this catches is not the wake, it is the waker's store, which every
 * correct futex user issues before FUTEX_WAKE. Parking costs a park and an
 * unpark through the host scheduler; a handoff that completes inside the spin
 * pays neither, which is worth 4x on a two-thread handoff.
 *
 * Measured not to cost what spinning usually costs. Against an unspun build it
 * is faster under oversubscription rather than slower (2x oversubscribed 1565
 * to 1131 ms, 4x 2390 to 1787 ms), and thread-churn is unchanged (0.87x, p=0.40
 * over nine paired runs). yield is a hint rather than a hold, and the
 * park/unpark pair it avoids costs more than the spin.
 *
 * A fault here is not this function's to report: it stops spinning and lets the
 * caller's own guarded load produce the EFAULT it would have produced anyway.
 */
static bool futex_spin_word_moved(const uint32_t *word, uint32_t expected)
{
    /* volatile because a SIGBUS longjmps out of the block below, which leaves
     * any non-volatile local modified inside it indeterminate.
     */
    volatile bool moved = false;
    bool faulted;

    /* The guard is armed once around the whole loop rather than per read.
     * futex_word_load arms it per call, and arming is a thread-local lookup
     * plus a _setjmp, so spinning through it would make the loop's duration a
     * function of that macro's cost rather than of FUTEX_SPIN_ITERS.
     */
    HOST_SIGBUS_GUARD(faulted, {
        for (int i = 0; i < FUTEX_SPIN_ITERS; i++) {
            /* Relaxed: this only detects that the word moved. Every consumer of
             * that fact re-reads it under the bucket mutex or through
             * futex_word_load, both of which carry their own ordering. Worth 9
             * percent of the spin.
             */
            uint32_t seen = atomic_load_explicit(
                (const _Atomic uint32_t *) word, memory_order_relaxed);
            if (seen != expected) {
                moved = true;
                break;
            }
            __asm__ __volatile__("yield" ::: "memory");
        }
    });

    /* A fault just ends the spin. Reporting it is the caller's own guarded
     * load's job, which runs next and produces the EFAULT it would have anyway.
     */
    return !faulted && moved;
}

/* swapped may be NULL where the caller retries regardless of who won the race.
 */
static bool futex_word_cas(uint32_t *word,
                           uint32_t *expected,
                           uint32_t desired,
                           bool *swapped)
{
    bool faulted, won;
    HOST_SIGBUS_GUARD(faulted, won = atomic_compare_exchange_strong_explicit(
                                   (_Atomic uint32_t *) word, expected, desired,
                                   memory_order_seq_cst, memory_order_seq_cst));
    if (faulted)
        return false;
    if (swapped)
        *swapped = won;
    return true;
}

/* Best-effort clear of FUTEX_WAITERS on a PI word whose last waiter gave up.
 * The caller is already returning a terminal status, so a fault here only means
 * the bit stays set on a page nobody can reach anyway.
 */
static void futex_clear_waiters_bit(uint32_t *word)
{
    for (;;) {
        uint32_t v;
        bool cleared;
        if (!futex_word_load(word, &v))
            return;
        if (!futex_pi_has_waiters(v))
            return;
        if (!futex_word_cas(word, &v, futex_pi_clear_waiters(v), &cleared))
            return;
        if (cleared)
            return;
    }
}

/* PI futex core */

/* One PI lock word that has at least one blocked waiter. The owner reference
 * keeps the task slot alive while this record names it; the record is linked on
 * owner->futex_pi.locks so an exiting owner finds every lock it must hand off.
 */
typedef struct futex_pi_lock {
    uint64_t uaddr;
    thread_entry_t *owner;
    futex_waiter_t *waiters;
    struct futex_pi_lock *next;
} futex_pi_lock_t;

/* Serializes all PI state and is outer to every bucket lock a PI path takes.
 * Plain futex paths never acquire it; they only test the immutable is_pi and
 * requeue_pi flags of queued waiters.
 */
static pthread_mutex_t futex_pi_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t futex_pi_next_seq = 1;

/* @a outranks @b. The scheduler owns the exact policy/weight/deadline order. */
static bool futex_pi_key_gt(const sched_pi_key_t *a, const sched_pi_key_t *b)
{
    return sched_pi_key_cmp(a, b) < 0;
}

/* Sample the base (unboosted) selection key. The scheduler exposes the
 * effective key, so an already boosted task is deboosted once; a base attribute
 * change invalidates the cache and the hook recomputes. This is the only point
 * where base and effective attributes are separated, and it keeps futex from
 * reading scheduler state without the scheduler lock.
 */
static void futex_pi_base_key_locked(thread_entry_t *t, sched_pi_key_t *out)
{
    if (t->futex_pi.base_valid) {
        *out = t->futex_pi.base_key;
        return;
    }
    if (t->futex_pi.applied) {
        sched_task_pi_clear_priority(t);
        t->futex_pi.applied = false;
    }
    if (!sched_task_pi_key(t, &t->futex_pi.base_key)) {
        memset(out, 0, sizeof(*out));
        out->class_rank = SCHED_CLASS_FAIR;
        out->policy = SCHED_POLICY_OTHER;
        return;
    }
    t->futex_pi.base_valid = true;
    *out = t->futex_pi.base_key;
}

/* Publish @want as @t's effective override, or clear it when its base already
 * outranks every waiter. The cached applied key avoids requeueing a task whose
 * inherited maximum did not move.
 */
static void futex_pi_apply_locked(thread_entry_t *t,
                                  const sched_pi_key_t *want,
                                  const sched_pi_key_t *base)
{
    bool boost = futex_pi_key_gt(want, base);
    if (boost) {
        if (!t->futex_pi.applied ||
            sched_pi_key_cmp(&t->futex_pi.applied_key, want) != 0) {
            int rc;
            if (want->class_rank == SCHED_CLASS_DEADLINE)
                rc = sched_task_pi_set_deadline(t, want->deadline_ns, 0, 0);
            else
                rc =
                    sched_task_pi_set_priority(t, want->policy, want->priority);
            if (rc == 0) {
                t->futex_pi.applied = true;
                t->futex_pi.applied_key = *want;
            }
        }
    } else if (t->futex_pi.applied) {
        sched_task_pi_clear_priority(t);
        t->futex_pi.applied = false;
        memset(&t->futex_pi.applied_key, 0, sizeof(t->futex_pi.applied_key));
    }
}

/* Effective key for @t: its base or the strongest waiter on any lock it owns. A
 * waiter's own effective key already includes what it inherited from locks it
 * owns, so one pass is enough.
 */
static void futex_pi_compute_locked(thread_entry_t *t,
                                    sched_pi_key_t *want,
                                    sched_pi_key_t *base)
{
    futex_pi_base_key_locked(t, base);
    *want = *base;
    for (futex_pi_lock_t *st = t->futex_pi.locks; st; st = st->next) {
        for (futex_waiter_t *w = st->waiters; w; w = w->pi_next) {
            sched_pi_key_t wp;
            if (!sched_task_pi_key(w->pi_task, &wp))
                continue;
            if (futex_pi_key_gt(&wp, want))
                *want = wp;
        }
    }
}

/* Recompute @t, then walk the chain of locks it is blocked on. Each task in the
 * chain is a donor to the next lock's owner, so a change at the bottom has to
 * reach the top. Cycle checks at enqueue make this bounded; the hop cap only
 * protects against a corrupted chain.
 */
static void futex_pi_propagate_locked(thread_entry_t *t)
{
    for (int hops = 0; t && hops < 64; hops++) {
        sched_pi_key_t want, base;
        futex_pi_compute_locked(t, &want, &base);
        futex_pi_apply_locked(t, &want, &base);
        futex_waiter_t *bw = t->futex_pi.blocked_on;
        if (!bw || !bw->pi_state)
            break;
        t = bw->pi_state->owner;
    }
}

/* Would @self waiting on @st's lock close a cycle? Walk the owner chain: owner
 * of this lock, the lock that owner is blocked on, and so on.
 */
static bool futex_pi_cycle_locked(futex_pi_lock_t *st, thread_entry_t *self)
{
    thread_entry_t *o = st->owner;
    for (int hops = 0; o && hops < 64; hops++) {
        if (o == self)
            return true;
        futex_waiter_t *bw = o->futex_pi.blocked_on;
        if (!bw || !bw->pi_state)
            return false;
        o = bw->pi_state->owner;
    }
    return o != NULL;
}

static futex_pi_lock_t *futex_pi_find_locked(thread_entry_t *owner,
                                             uint64_t uaddr)
{
    for (futex_pi_lock_t *st = owner->futex_pi.locks; st; st = st->next) {
        if (st->uaddr == uaddr)
            return st;
    }
    return NULL;
}

static void futex_pi_owner_list_remove_locked(thread_entry_t *owner,
                                              futex_pi_lock_t *st)
{
    futex_pi_lock_t **pp = &owner->futex_pi.locks;
    while (*pp && *pp != st)
        pp = &(*pp)->next;
    if (*pp) {
        *pp = st->next;
        st->next = NULL;
    }
}

/* Create the lock record and link it on its owner. Takes a task reference for
 * the owner field; free or handoff releases it.
 */
static futex_pi_lock_t *futex_pi_create_locked(thread_entry_t *owner,
                                               uint64_t uaddr)
{
    futex_pi_lock_t *st = calloc(1, sizeof(*st));
    if (!st)
        return NULL;
    st->owner = thread_acquire_tid(thread_tid(owner));
    if (!st->owner) {
        free(st);
        return NULL;
    }
    st->uaddr = uaddr;
    st->next = owner->futex_pi.locks;
    owner->futex_pi.locks = st;
    return st;
}

static void futex_pi_free_locked(futex_pi_lock_t *st)
{
    thread_entry_t *owner = st->owner;
    if (owner)
        futex_pi_owner_list_remove_locked(owner, st);
    st->owner = NULL;
    free(st);
    if (owner)
        thread_release(owner);
}

/* Remove @w from its lock's waiter list and drop its task reference. The lock
 * record itself is left alone so a handoff can transfer it.
 */
static void futex_pi_detach_waiter_locked(futex_waiter_t *w)
{
    futex_pi_lock_t *st = w->pi_state;
    if (!st)
        return;
    futex_waiter_t **pp = &st->waiters;
    while (*pp && *pp != w)
        pp = &(*pp)->pi_next;
    if (*pp)
        *pp = w->pi_next;
    w->pi_next = NULL;
    w->pi_state = NULL;

    thread_entry_t *task = w->pi_task;
    w->pi_task = NULL;
    if (task) {
        if (task->futex_pi.blocked_on == w)
            task->futex_pi.blocked_on = NULL;
        thread_release(task);
    }
}

/* Detach every waiter from @st without freeing the waiter records (their park
 * or syscall path owns the memory). Used only when teardown cannot hand the
 * lock off.
 */
static void futex_pi_drop_waiters_locked(futex_pi_lock_t *st)
{
    while (st->waiters) {
        futex_waiter_t *w = st->waiters;
        st->waiters = w->pi_next;
        w->pi_next = NULL;
        w->pi_state = NULL;
        thread_entry_t *task = w->pi_task;
        w->pi_task = NULL;
        if (task && task->futex_pi.blocked_on == w)
            task->futex_pi.blocked_on = NULL;
        if (task)
            thread_release(task);
    }
}

/* An owner-record created for a failed enqueue must not stay linked with no
 * waiters; it would keep an owner reference and hide a later recreate.
 */
static void futex_pi_release_empty_locked(futex_pi_lock_t *st)
{
    if (st && !st->waiters)
        futex_pi_free_locked(st);
}

/* Normal removal (wake, timeout, signal, kill): after the waiter leaves, the
 * owner may lose its inherited priority and the empty lock record is freed.
 * Propagate before freeing so the owner reference in the record keeps the task
 * slot valid across the scheduler call.
 */
static void futex_pi_unlink_waiter_locked(futex_waiter_t *w)
{
    futex_pi_lock_t *st = w->pi_state;
    if (!st)
        return;
    futex_pi_detach_waiter_locked(w);
    thread_entry_t *owner = st->owner;
    if (owner)
        futex_pi_propagate_locked(owner);
    if (!st->waiters)
        futex_pi_free_locked(st);
}

/* Last-resort detach before a waiter record is freed. Normal wake/cancel paths
 * unlink under the PI mutex themselves; this catches a completion that raced
 * them and must not leave a dangling pointer in a lock record.
 */
static void futex_pi_forget_waiter(futex_waiter_t *w)
{
    if (!w || (!w->pi_state && !w->pi_task))
        return;
    pthread_mutex_lock(&futex_pi_mutex);
    if (w->pi_state) {
        futex_pi_unlink_waiter_locked(w);
    } else if (w->pi_task) {
        thread_entry_t *task = w->pi_task;
        w->pi_task = NULL;
        if (task->futex_pi.blocked_on == w)
            task->futex_pi.blocked_on = NULL;
        thread_release(task);
    }
    pthread_mutex_unlock(&futex_pi_mutex);
}

/* Highest effective priority waiter, FIFO among equals. */
static futex_waiter_t *futex_pi_top_locked(futex_pi_lock_t *st)
{
    futex_waiter_t *best = NULL;
    sched_pi_key_t best_key = {0};
    bool best_keyed = false;
    for (futex_waiter_t *w = st->waiters; w; w = w->pi_next) {
        sched_pi_key_t wp;
        bool keyed = sched_task_pi_key(w->pi_task, &wp);
        if (!best) {
            best = w;
            best_key = wp;
            best_keyed = keyed;
            continue;
        }
        if (keyed && (!best_keyed || futex_pi_key_gt(&wp, &best_key) ||
                      (sched_pi_key_cmp(&wp, &best_key) == 0 &&
                       w->pi_seq < best->pi_seq))) {
            best = w;
            best_key = wp;
            best_keyed = true;
        } else if (!keyed && !best_keyed && w->pi_seq < best->pi_seq) {
            best = w;
            best_key = wp;
        }
    }
    return best;
}

/* Give @st's lock to its top waiter: the waiter leaves the queue, the lock
 * record (and its owner reference) moves to the waiter's task, and the old
 * owner is recomputed. The caller owns the bucket lock and updates the guest
 * word before waking the returned waiter.
 */
static futex_waiter_t *futex_pi_handoff_locked(futex_pi_lock_t *st)
{
    futex_waiter_t *top = futex_pi_top_locked(st);
    if (!top)
        return NULL;
    futex_waiter_t **pp = &st->waiters;
    while (*pp && *pp != top)
        pp = &(*pp)->pi_next;
    if (*pp)
        *pp = top->pi_next;
    top->pi_next = NULL;
    top->pi_state = NULL;

    thread_entry_t *nw = top->pi_task;
    /* The waiter's task reference becomes the lock record's owner reference. */
    top->pi_task = NULL;
    if (!nw)
        return NULL;
    if (nw->futex_pi.blocked_on == top)
        nw->futex_pi.blocked_on = NULL;

    thread_entry_t *old = st->owner;
    if (old) {
        futex_pi_owner_list_remove_locked(old, st);
        st->owner = NULL;
        thread_release(old);
    }
    st->owner = nw;
    st->next = nw->futex_pi.locks;
    nw->futex_pi.locks = st;

    if (old)
        futex_pi_propagate_locked(old);
    futex_pi_propagate_locked(nw);
    return top;
}

/* Queue @w on @st and start donating @self's effective priority to the owner.
 * Returns -EDEADLK for a chain that closes, -ESRCH when @self's slot is gone.
 */
static int futex_pi_link_locked(futex_pi_lock_t *st,
                                futex_waiter_t *w,
                                thread_entry_t *self)
{
    if (futex_pi_cycle_locked(st, self))
        return -LINUX_EDEADLK;
    thread_entry_t *ref = thread_acquire_tid(thread_tid(self));
    if (!ref)
        return -LINUX_ESRCH;
    if (w->pi_state)
        futex_pi_unlink_waiter_locked(w);
    w->pi_task = ref;
    w->pi_seq = futex_pi_next_seq++;
    w->pi_state = st;
    w->pi_next = st->waiters;
    st->waiters = w;
    self->futex_pi.blocked_on = w;
    futex_pi_propagate_locked(st->owner);
    return 0;
}

static futex_pi_lock_t *futex_pi_owner_state_locked(thread_entry_t *owner,
                                                    uint64_t uaddr)
{
    futex_pi_lock_t *st = futex_pi_find_locked(owner, uaddr);
    if (!st)
        st = futex_pi_create_locked(owner, uaddr);
    return st;
}

/* A word can become unowned before the last owner's exit path runs (the robust
 * walk clears the TID). If waiters are already queued, their lock record still
 * names the old owner; the task that takes the word over must adopt it so the
 * remaining waiters donate to the real owner.
 */
static futex_pi_lock_t *futex_pi_state_for_uaddr_locked(futex_bucket_t *b,
                                                        uint64_t uaddr)
{
    for (futex_waiter_t *w = b->head; w; w = w->next) {
        if (w->uaddr == uaddr && w->pi_state)
            return w->pi_state;
    }
    return NULL;
}

static bool futex_pi_adopt_lock_locked(futex_pi_lock_t *st,
                                       thread_entry_t *self)
{
    if (!st || !self)
        return false;
    if (st->owner == self)
        return true;
    thread_entry_t *ref = thread_acquire_tid(thread_tid(self));
    if (!ref)
        return false;
    thread_entry_t *old = st->owner;
    if (old) {
        futex_pi_owner_list_remove_locked(old, st);
        st->owner = NULL;
        thread_release(old);
    }
    st->owner = ref;
    st->next = self->futex_pi.locks;
    self->futex_pi.locks = st;
    futex_pi_propagate_locked(self);
    return true;
}

/* Wake one specific waiter under @b's lock. PI handoff removes the waiter from
 * the PI state first but leaves it linked in the bucket until here.
 */
static void futex_wake_waiter_ptr_locked(futex_bucket_t *b, futex_waiter_t *w)
{
    for (futex_waiter_t **pp = &b->head; *pp; pp = &(*pp)->next) {
        if (*pp == w) {
            futex_wake_waiter_locked(pp);
            return;
        }
    }
}

/* Overwrite a PI word from a handoff. A CAS loop because a guest may still
 * rewrite a word it shares; a fault leaves the word as the waker found it.
 */
static bool futex_pi_word_store_locked(uint32_t *word, uint32_t want)
{
    for (;;) {
        uint32_t cur;
        bool done;
        if (!futex_word_load(word, &cur) ||
            !futex_word_cas(word, &cur, want, &done))
            return false;
        if (done)
            return true;
    }
}

/* Set FUTEX_WAITERS on a PI word unless already set. Caller holds the bucket
 * lock; a word that moves is retried by the owner-side paths.
 */
static void futex_pi_ensure_waiters_locked(uint32_t *word)
{
    for (;;) {
        uint32_t cur;
        bool done;
        if (!futex_word_load(word, &cur))
            return;
        if (futex_pi_has_waiters(cur))
            return;
        if (!futex_word_cas(word, &cur, futex_pi_set_waiters(cur), &done))
            return;
        if (done)
            return;
    }
}

/* Owner exit: for every lock record this task still owns with waiters, mark the
 * word OWNER_DIED and hand it to the highest-priority waiter. A word with no PI
 * waiters is left alone: Linux recovers it only through the robust list, and a
 * later LOCK_PI on a dead TID reports ESRCH.
 */
void futex_pi_owner_exit(guest_t *g, thread_entry_t *t)
{
    if (!t)
        return;

    bool woke = false;
    pthread_mutex_lock(&futex_pi_mutex);
    while (t->futex_pi.locks) {
        futex_pi_lock_t *st = t->futex_pi.locks;
        uint64_t uaddr = st->uaddr;
        uint32_t *word = g ? (uint32_t *) guest_ptr_w(g, uaddr) : NULL;
        futex_bucket_t *b = &buckets[futex_hash(uaddr)];

        pthread_mutex_lock(&b->lock);
        futex_waiter_t *top = futex_pi_top_locked(st);
        if (!top) {
            futex_pi_drop_waiters_locked(st);
            futex_pi_free_locked(st);
            pthread_mutex_unlock(&b->lock);
            continue;
        }

        uint32_t next_tid = top->waiter_tid;
        futex_pi_handoff_locked(st);
        bool more = st->waiters != NULL;
        if (word) {
            uint32_t want = next_tid | FUTEX_PI_OWNER_DIED;
            if (more)
                want = futex_pi_set_waiters(want);
            (void) futex_pi_word_store_locked(word, want);
        }
        futex_wake_waiter_ptr_locked(b, top);
        woke = true;
        pthread_mutex_unlock(&b->lock);
    }
    pthread_mutex_unlock(&futex_pi_mutex);
    if (woke)
        futex_async_wake_flush();
}

/* Drop every PI record that names @t, idempotently. Called from task teardown
 * before the slot may be recycled. Waiter memory belongs to the park or syscall
 * path and is never freed here.
 */
void futex_pi_task_release(thread_entry_t *t)
{
    if (!t)
        return;

    pthread_mutex_lock(&futex_pi_mutex);
    while (t->futex_pi.blocked_on) {
        futex_waiter_t *w = t->futex_pi.blocked_on;
        if (w->pi_state)
            futex_pi_unlink_waiter_locked(w);
        else
            t->futex_pi.blocked_on = NULL;
    }
    while (t->futex_pi.locks) {
        futex_pi_lock_t *st = t->futex_pi.locks;
        futex_pi_drop_waiters_locked(st);
        futex_pi_free_locked(st);
    }
    memset(&t->futex_pi.base_key, 0, sizeof(t->futex_pi.base_key));
    memset(&t->futex_pi.applied_key, 0, sizeof(t->futex_pi.applied_key));
    t->futex_pi.base_valid = false;
    t->futex_pi.applied = false;
    pthread_mutex_unlock(&futex_pi_mutex);
}

/* Base attributes changed: refresh this task's own effective maximum and, if it
 * is blocked on a lock, the priority its owner inherits from it.
 */
void futex_pi_task_priority_changed(thread_entry_t *t)
{
    if (!t)
        return;

    pthread_mutex_lock(&futex_pi_mutex);
    sched_pi_key_t want, base;
    /* The task's own base may have moved, so the cached sample is stale. */
    t->futex_pi.base_valid = false;
    futex_pi_compute_locked(t, &want, &base);
    futex_pi_apply_locked(t, &want, &base);
    futex_waiter_t *bw = t->futex_pi.blocked_on;
    if (bw && bw->pi_state && bw->pi_state->owner)
        futex_pi_propagate_locked(bw->pi_state->owner);
    pthread_mutex_unlock(&futex_pi_mutex);
}

/* Public API */

void futex_init(void)
{
    for (unsigned i = 0; i < FUTEX_BUCKETS; i++) {
        pthread_mutex_init(&buckets[i].lock, NULL);
        buckets[i].head = NULL;
    }

    /* Base attribute changes on any task in this domain must refresh the
     * priority its lock owners inherit from it.
     */
    sched_set_priority_changed_hook(futex_pi_task_priority_changed);
}

void futex_interrupt_request(void)
{
    atomic_store_explicit(&futex_interrupt_requested, 1, memory_order_release);
}

void futex_interrupt_clear(void)
{
    atomic_store_explicit(&futex_interrupt_requested, 0, memory_order_relaxed);
}

/* Test-and-clear: returns 1 if the interrupt request was pending and atomically
 * clears it, 0 otherwise. The interrupt is a one-shot edge, set by the teardown
 * paths through thread_wake_all_blocked. Teardown state marks every thread as
 * leaving; the atomic interrupt itself is consumed by only one waiter. Without
 * the clear, the flag stays set and every subsequent epoll_pwait, ppoll, futex
 * wait, etc. spins on EINTR until execve clears it -- in foot's case it never
 * does, and the spinning main thread eventually faults in a code path the guest
 * never expects to reach.
 *
 * forkipc.c set it too, on the last clone-thread exit, for a SIGCHLD that
 * clone(2) does not send. That is gone; only a process actually tearing down
 * fabricates an EINTR now.
 */
int futex_interrupt_consume(void)
{
    int expected = 1;
    return atomic_compare_exchange_strong_explicit(
        &futex_interrupt_requested, &expected, 0, memory_order_acquire,
        memory_order_relaxed);
}

/* Cap on guest-supplied tv_sec. The cap exists purely so the int64_t / time_t
 * arithmetic in the deadline conversion (now.tv_sec + delta_sec, where
 * delta_sec = lts.tv_sec - mono.tv_sec) cannot overflow even for adversarial
 * inputs. INT64_MAX / 4 leaves four-way headroom for any pairwise sum or
 * difference and still allows absolute CLOCK_REALTIME deadlines billions of
 * years into the future, which comfortably covers the year-2038/2106 envelope.
 * Linux saturates at KTIME_MAX (INT64_MAX ns ~ 292 years) on conversion to
 * ktime_t; this code stays in struct timespec so it does not need that
 * conversion, only the cap.
 */
#define FUTEX_TIMESPEC_SEC_MAX (INT64_MAX / 4)

/*@ requires \valid_read(lts);
    assigns \nothing;
    ensures \result != 0 <==> (0 <= lts->tv_sec <= FUTEX_TIMESPEC_SEC_MAX &&
                               0 <= lts->tv_nsec < TIMESPEC_NSEC_PER_SEC);
 */
static int linux_timespec_is_valid(const linux_timespec_t *lts)
{
    /* timespec_valid_capped is the proved statement of what Linux accepts on
     * the sleep and wait paths, plus the seconds ceiling this file needs, both
     * inside one <==> the provers check (verify-timespec). Restating either
     * here would be a second copy free to drift from it.
     */
    return timespec_valid_capped(lts->tv_sec, lts->tv_nsec,
                                 FUTEX_TIMESPEC_SEC_MAX);
}

/* Convert a Linux guest timespec to an absolute struct timespec deadline. For
 * FUTEX_WAIT (relative timeout), adds the duration to the current time. For
 * FUTEX_WAIT_BITSET (absolute timeout), uses the value directly.
 * Returns 0 on success, -1 if the guest pointer is invalid, -2 if the guest
 * timespec is malformed.
 */
static int futex_make_deadline(guest_t *g,
                               uint64_t timeout_gva,
                               int is_absolute,
                               struct timespec *out)
{
    linux_timespec_t lts;
    if (guest_read_small(g, timeout_gva, &lts, sizeof(lts)) < 0)
        return -1;
    if (!linux_timespec_is_valid(&lts))
        return -2;

    if (is_absolute) {
        out->tv_sec = (time_t) lts.tv_sec;
        out->tv_nsec = (long) lts.tv_nsec;
    } else {
        /* Relative: add to current CLOCK_REALTIME (pthread_cond_timedwait uses
         * CLOCK_REALTIME by default on macOS)
         */
        struct timeval now;
        gettimeofday(&now, NULL);
        out->tv_sec = now.tv_sec + (time_t) lts.tv_sec;
        out->tv_nsec = (long) now.tv_usec * 1000 + (long) lts.tv_nsec;
        timespec_normalize(out);
    }
    return 0;
}

/* Relative wait quantum until an absolute CLOCK_REALTIME deadline, capped at
 * cap_ns.
 *
 * Returns 0 once the deadline has elapsed, so the caller surfaces ETIMEDOUT
 * without re-arming.
 *
 * This subtracted the two tv_sec fields directly, which was undefined for
 * inputs the guest can name: linux_timespec_is_valid accepts tv_sec up to
 * FUTEX_TIMESPEC_SEC_MAX (INT64_MAX / 4) and the absolute-deadline path
 * forwards it unchanged, so the subtraction was safe only because the other
 * operand came from the clock. Frama-C could not discharge those five
 * signed-overflow obligations at any timeout.
 *
 * now_out hands the caller the clock reading the remainder was measured
 * against. futex_quantum_deadline needs it: building an absolute target from a
 * second reading would place that target one clock read past the guest's
 * deadline rather than on it.
 *
 * timespec_to_ns_sat is total and its proved postcondition puts both operands
 * in [0, INT64_MAX], so the subtraction below is total by construction. Using
 * it rather than a futex-local saturating helper also keeps one answer in the
 * tree to "what is this guest timespec in nanoseconds": proved/timespec.h names
 * futex as a caller, and a second convention would differ on inputs neither
 * caller can produce, which is the same provenance argument this replaces.
 */
/*@ requires \valid_read(deadline);
    requires now_out == \null || \valid(now_out);
    requires 0 <= deadline->tv_sec;
    requires 0 <= deadline->tv_nsec < TIMESPEC_NSEC_PER_SEC;
    ensures 0 <= \result <= cap_ns;
    assigns *now_out, __fc_time;
    behavior reports_now:
      assumes now_out != \null;
      assigns *now_out, __fc_time;
      ensures 0 <= *now_out <= INT64_MAX;
    behavior discards_now:
      assumes now_out == \null;
      assigns __fc_time;
    complete behaviors;
    disjoint behaviors;
 */
static uint64_t futex_remaining_ns(const struct timespec *deadline,
                                   uint64_t cap_ns,
                                   int64_t *now_out)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    int64_t deadline_ns =
        timespec_to_ns_sat(deadline->tv_sec, deadline->tv_nsec);
    int64_t now_ns = timespec_to_ns_sat(now.tv_sec, now.tv_nsec);
    if (now_out)
        *now_out = now_ns;
    if (deadline_ns <= now_ns)
        return 0;

    uint64_t rem = (uint64_t) (deadline_ns - now_ns);
    return rem < cap_ns ? rem : cap_ns;
}


/* FUTEX_WAIT / FUTEX_WAIT_BITSET: atomically check word == val, then sleep. */
static int64_t futex_wait_inner(unsigned *pub_bucket_out,
                                guest_t *g,
                                uint64_t uaddr,
                                uint32_t expected,
                                uint64_t timeout_gva,
                                uint32_t bitset,
                                int is_absolute)
{
    if (bitset == 0)
        return -LINUX_EINVAL;
    if (!futex_uaddr_is_aligned(uaddr))
        return -LINUX_EINVAL;

    unsigned idx = futex_hash(uaddr);
    futex_bucket_t *b = &buckets[idx];

    /* Build deadline before locking (avoid holding lock during syscall) */
    bool has_timeout = (timeout_gva != 0);
    struct timespec deadline;
    if (has_timeout) {
        int rc = futex_make_deadline(g, timeout_gva, is_absolute, &deadline);
        if (rc == -1)
            return -LINUX_EFAULT;
        if (rc == -2)
            return -LINUX_EINVAL;
    }

    /* Spin before the lock, not under it: holding the bucket lock while
     * spinning would block the very waker being waited for. FUTEX_WAIT_BITSET
     * arrives here, which is what glibc's pthread_cond_timedwait issues, so
     * without this the path a threaded glibc guest actually takes gets no
     * benefit. Returning EAGAIN without enqueueing is what Linux does whenever
     * the word does not match at the check.
     *
     * Skipped when the guest's deadline has already passed. A caller using
     * sem_timedwait or pthread_mutex_timedlock with a past deadline as a
     * non-blocking probe would otherwise pay the whole spin to be told
     * ETIMEDOUT, which the wait below reaches anyway (measured 4788 ns per call
     * against 1756 with this guard). The clock read this costs on the timed
     * path is one that path makes regardless; an untimed wait short-circuits
     * before it.
     */
    if (!has_timeout ||
        futex_remaining_ns(&deadline, FUTEX_POLL_QUANTUM_NS, NULL) > 0) {
        const uint32_t *spin_word = (const uint32_t *) guest_ptr(g, uaddr);
        if (spin_word && futex_spin_word_moved(spin_word, expected))
            return -LINUX_EAGAIN;
    }

    pthread_mutex_lock(&b->lock);

    /* Read the futex word while holding the bucket lock, so the enqueue below
     * is ordered against a concurrent wake. A mismatch returns EAGAIN and never
     * enqueues.
     */
    int64_t block = futex_should_block(g, uaddr, expected);
    if (block != 0) {
        pthread_mutex_unlock(&b->lock);
        return block;
    }

    thread_entry_t *self = current_thread;
    if (!self) {
        pthread_mutex_unlock(&b->lock);
        return -LINUX_ESRCH;
    }

    {
        futex_waiter_t *waiter = calloc(1, sizeof(*waiter));
        if (!waiter) {
            pthread_mutex_unlock(&b->lock);
            return -LINUX_ENOMEM;
        }
        waiter->uaddr = uaddr;
        waiter->bitset = bitset;
        atomic_store_explicit(&waiter->woken, 0, memory_order_relaxed);
        waiter->next = b->head;
        waiter->pub_bucket = idx;
        waiter->pub_follows = true;
        atomic_store_explicit(&waiter->home, idx, memory_order_relaxed);
        waiter->async_owner = self;
        pthread_cond_init(&waiter->cond, NULL);
        b->head = waiter;

        exec_park_kind_store(self, PARK_KIND_FUTEX);
        exec_park_result_pending_store(self, true);
        exec_park_reissue_store(self, false);
        self->async_futex_pub_bucket = idx;
        self->async_futex_relative = has_timeout && !is_absolute;
        self->async_futex_timed = has_timeout;
        self->park_guest = g;

        /* Publish the generation and the waiter, then the park itself with
         * release so a waker that matches the generation observes every field
         * above.
         */
        exec_park_deadline_ns_store(self, 0);
        (void) sched_park_seq_next(self);
        exec_park_waiter_store(self, waiter);
        exec_park_active_store(self, true);
        if (pub_bucket_out)
            *pub_bucket_out = idx;

        /* sched_arm_wait_deadline is CLOCK_MONOTONIC (slice timer). The guest
         * deadline above is CLOCK_REALTIME (Linux futex ABI / the sync
         * pthread_cond_timedwait path). Convert by remaining duration so a past
         * deadline becomes an immediate ETIMEDOUT rather than a wait on a
         * REALTIME absolute against MONOTONIC now (which never fires).
         *
         * Infinite waits arm FUTEX_POLL_QUANTUM_NS so exit_group / stop / a
         * late signal claim can be observed without an uncapped park (same
         * bound as the sync cond wait quantum). The deadline handler re-arms
         * rather than completing with a spurious 0: glibc/PI tests expect a
         * bare FUTEX_WAIT to block until a real wake or EINTR/ETIMEDOUT.
         */
        if (has_timeout) {
            struct timespec now_rt, now_mono;
            if (clock_gettime(CLOCK_REALTIME, &now_rt) != 0 ||
                clock_gettime(CLOCK_MONOTONIC, &now_mono) != 0) {
                bucket_unlink_locked(b, waiter);
                bool ours = futex_async_claim_pre_unmount_locked(self, waiter);
                pthread_mutex_unlock(&b->lock);
                if (ours)
                    futex_async_free_claimed(waiter);
                return -LINUX_EINTR;
            }
            int64_t dl_ns =
                timespec_to_ns_sat(deadline.tv_sec, deadline.tv_nsec);
            int64_t rt_now_ns =
                timespec_to_ns_sat(now_rt.tv_sec, now_rt.tv_nsec);
            if (dl_ns <= rt_now_ns) {
                /* Already expired: mirror the sync path's quantum check and
                 * never unmount for a wait that cannot block.
                 */
                bucket_unlink_locked(b, waiter);
                bool ours = futex_async_claim_pre_unmount_locked(self, waiter);
                pthread_mutex_unlock(&b->lock);
                if (ours)
                    futex_async_free_claimed(waiter);
                return -LINUX_ETIMEDOUT;
            }
            uint64_t mono_now = (uint64_t) now_mono.tv_sec * 1000000000ULL +
                                (uint64_t) now_mono.tv_nsec;
            uint64_t rem = (uint64_t) (dl_ns - rt_now_ns);
            sched_arm_wait_deadline(self, mono_now + rem);
        } else {
            struct timespec now_mono;
            if (clock_gettime(CLOCK_MONOTONIC, &now_mono) == 0) {
                uint64_t mono_now = (uint64_t) now_mono.tv_sec * 1000000000ULL +
                                    (uint64_t) now_mono.tv_nsec;
                sched_arm_wait_deadline(self, mono_now + FUTEX_POLL_QUANTUM_NS);
            } else {
                sched_disarm_wait_deadline(self);
            }
        }

        /* A kick that arrived before we published is consumed here without any
         * other lock. The signal claim must happen outside the bucket lock:
         * futex_kick is called under sig_lock, and claiming demands sig_lock,
         * so doing it here would invert the bucket and signal lock order.
         */
        bool kicked = futex_kick_consume();
        pthread_mutex_unlock(&b->lock);

        if (kicked) {
            bool teardown =
                proc_exit_group_requested() || thread_stop_requested();
            bool claimed = teardown;
            if (!claimed && signal_pending())
                claimed = signal_claim_interruption();

            /* One arbiter for wake vs abort: futex_async_cancel re-locks the
             * bucket, checks woken, and either retires the waiter or leaves the
             * waker's completed result alone. Do not touch the waiter after
             * this call. Returning PARKED is still correct when the park was
             * completed early: the execution loop sees park_active == false and
             * publishes READY with the stored result.
             */
            if (claimed)
                futex_async_cancel(self, -LINUX_EINTR);
        }
        return SYSCALL_PARKED;
    }
}

/* FUTEX_WAKE / FUTEX_WAKE_BITSET: wake up to val waiters at uaddr. Woken
 * waiters are unlinked from the bucket list so subsequent operations do not
 * count them as still-sleeping entries.
 *
 * Plain FUTEX_WAIT enqueues with implicit FUTEX_BITSET_MATCH_ANY, which matches
 * every legal FUTEX_WAKE_BITSET mask (mask must be non-zero by Linux contract),
 * so those waiters remain valid wake targets. Publish this bucket's waiter
 * count around the whole wait.
 *
 * The increment has to land before the wait reads the futex word, which it does
 * here because every read futex_wait_inner makes is inside the call. A wrapper
 * rather than an increment threaded through the body: the body has eight
 * returns, and one that missed the drop would leave the bucket looking occupied
 * forever, quietly costing the shim's wake fast path rather than failing
 * anything.
 */
static int64_t futex_wait(guest_t *g,
                          uint64_t uaddr,
                          uint32_t expected,
                          uint64_t timeout_gva,
                          uint32_t bitset,
                          int is_absolute)
{
    unsigned idx = futex_hash(uaddr);
    unsigned pub = idx;

    shim_globals_futex_waiters_add(g, idx, +1);
    int64_t rc = futex_wait_inner(&pub, g, uaddr, expected, timeout_gva, bitset,
                                  is_absolute);
    if (rc == SYSCALL_PARKED)
        return SYSCALL_PARKED; /* charge dropped when the park completes */
    shim_globals_futex_waiters_add(g, pub, -1);
    return rc;
}

/* Whether a plain wake would meet a PI waiter among the first budget entries it
 * would touch at uaddr. A PI waiter stays tied to its entry bucket while it
 * retries and is not woken by a plain wake, so Linux answers EINVAL from inside
 * futex_wake() and futex_wake_op(); this decides before anything is woken, the
 * way futex_requeue decides, so a refused call leaves the chain as it found it.
 *
 * The budget is what bounds the walk, because a waiter Linux never reaches
 * cannot refuse the call: its loops stop once nr_wake entries are woken.
 */
static bool futex_pi_waiter_within(const futex_bucket_t *b,
                                   uint64_t uaddr,
                                   uint32_t bitset,
                                   uint32_t budget)
{
    for (const futex_waiter_t *w = b->head; w && budget != 0; w = w->next) {
        if (w->uaddr != uaddr || (w->bitset & bitset) == 0)
            continue;

        /* A LOCK_PI waiter or a WAIT_REQUEUE_PI waiter cannot be reached by a
         * plain FUTEX_WAKE; Linux reports EINVAL.
         */
        if (!w->pub_follows || w->requeue_pi)
            return true;
        budget--;
    }
    return false;
}

static int64_t futex_wake(const guest_t *g,
                          uint64_t uaddr,
                          uint32_t val,
                          uint32_t bitset)
{
    if (bitset == 0)
        return -LINUX_EINVAL;
    if (!futex_uaddr_is_aligned(uaddr))
        return -LINUX_EINVAL;

    unsigned idx = futex_hash(uaddr);
    futex_bucket_t *b = &buckets[idx];
    int woken = 0;

    pthread_mutex_lock(&b->lock);

#ifdef ELFUSE_CONTRACT_ASSERT
    /* The published count may never understate what is parked on this bucket.
     * An understatement is what the shim's wake fast path reads as "nobody
     * here", so it is the one error that loses a wakeup rather than costing a
     * round trip. Checked here because this is the one place that holds the
     * bucket lock and can see both numbers at once; the fast path itself is
     * assembly and out of reach.
     */
    {
        /* Re-read before believing a violation, because a single reading of
         * this cannot tell one from a transient.
         *
         * The chain is stable here, under the bucket lock, but the published
         * count is not: a waiter charges it before it takes this lock and drops
         * the charge after releasing it.
         *
         * A real one is a charge that is missing rather than in flight, so it
         * does not go away when looked at again. Requiring the violation to
         * hold across re-reads is what separates the two. Measured before this
         * was added: test-signal-in-shim reported pub=0 against parked=1 on
         * every run and it survived 0 of 5 re-reads every time, on four
         * workloads including the contended benchmark. That was a false alarm
         * being read as a lost wakeup.
         */
        unsigned parked = 0;
        for (const futex_waiter_t *q = b->head; q; q = q->next)
            parked++;
        if (shim_globals_futex_waiters_get(g, idx) < parked) {
            int persisted = 0;
            for (int retry = 0; retry < FUTEX_CENSUS_RECHECKS; retry++) {
                unsigned again = 0;
                for (const futex_waiter_t *q = b->head; q; q = q->next)
                    again++;
                if (shim_globals_futex_waiters_get(g, idx) < again)
                    persisted++;
            }
            if (persisted == FUTEX_CENSUS_RECHECKS)
                abort();
        }
    }
#endif

    if (futex_pi_waiter_within(b, uaddr, bitset, val)) {
        pthread_mutex_unlock(&b->lock);
        return -LINUX_EINVAL;
    }

    futex_waiter_t **pp = &b->head;
    while (*pp && (uint32_t) woken < val) {
        futex_waiter_t *w = *pp;
        if (w->uaddr == uaddr && (w->bitset & bitset) != 0) {
            futex_wake_waiter_locked(pp);
            woken++;
        } else {
            pp = &w->next;
        }
    }

    pthread_mutex_unlock(&b->lock);
    futex_async_wake_flush();

    return woken;
}

/* FUTEX_REQUEUE / FUTEX_CMP_REQUEUE: wake val waiters at uaddr, then move up to
 * val2 remaining waiters from uaddr to uaddr2.
 *
 * CMP_REQUEUE additionally checks *uaddr == val3 before proceeding; returns
 * -EAGAIN if the comparison fails (stale wakeup avoidance).
 *
 * Musl uses FUTEX_REQUEUE (not CMP) in pthread_cond_timedwait.c for efficient
 * condition variable broadcast, avoiding thundering herd by moving waiters
 * directly to the mutex futex instead of waking them all.
 *
 * Lock ordering: always acquire lower-indexed bucket first to avoid deadlock
 * when source and destination hash to different buckets.
 */
static int64_t futex_requeue(guest_t *g,
                             uint64_t uaddr,
                             uint32_t wake_count,
                             uint32_t requeue_count,
                             uint64_t uaddr2,
                             int do_cmp,
                             uint32_t expected)
{
    /* Linux refuses these before taking either key; proved/futexreq.h carries
     * why the sign is only visible as the top bit here.
     */
    if (!futex_requeue_counts_valid(wake_count, requeue_count))
        return -LINUX_EINVAL;

    if (!futex_uaddr_is_aligned(uaddr) || !futex_uaddr_is_aligned(uaddr2))
        return -LINUX_EINVAL;

    unsigned idx_src = futex_hash(uaddr);
    unsigned idx_dst = futex_hash(uaddr2);
    futex_bucket_t *b_src = &buckets[idx_src];
    futex_bucket_t *b_dst = &buckets[idx_dst];

    /* Lock both buckets in consistent order (lower index first) */
    if (idx_src == idx_dst) {
        pthread_mutex_lock(&b_src->lock);
    } else if (idx_src < idx_dst) {
        pthread_mutex_lock(&b_src->lock);
        pthread_mutex_lock(&b_dst->lock);
    } else {
        pthread_mutex_lock(&b_dst->lock);
        pthread_mutex_lock(&b_src->lock);
    }

    /* CMP_REQUEUE: atomically verify *uaddr == expected */
    if (do_cmp) {
        int64_t block = futex_should_block(g, uaddr, expected);
        if (block != 0) {
            if (idx_src != idx_dst)
                pthread_mutex_unlock(&b_dst->lock);
            pthread_mutex_unlock(&b_src->lock);
            return block;
        }
    }

    /* A PI waiter stays tied to its entry bucket while it retries, and
     * FUTEX_REQUEUE has no PI-aware form here, so reject one before anything
     * moves. Every waiter the call could touch is checked, wake candidates
     * included, matching where requeue.c makes the same decision. The budget is
     * summed in 64 bits: both halves are guest-supplied and wake-all passes
     * INT_MAX.
     */
    uint64_t checked = futex_requeue_budget(wake_count, requeue_count);
    for (futex_waiter_t *w = b_src->head; w && checked != 0; w = w->next) {
        if (w->uaddr != uaddr)
            continue;

        /* The same PI rejection as futex_wake: a WAIT_REQUEUE_PI waiter is not
         * movable by a plain requeue.
         */
        if (!w->pub_follows || w->requeue_pi) {
            if (idx_src != idx_dst)
                pthread_mutex_unlock(&b_dst->lock);
            pthread_mutex_unlock(&b_src->lock);
            return -LINUX_EINVAL;
        }
        checked--;
    }

    int woken = 0, requeued = 0;

    /* Walk source bucket: wake up to wake_count, requeue up to requeue_count */
    futex_waiter_t **pp = &b_src->head;
    while (*pp) {
        futex_waiter_t *w = *pp;
        if (w->uaddr != uaddr) {
            pp = &w->next;
            continue;
        }

        if ((uint32_t) woken < wake_count) {
            /* Wake this waiter: unlink from source, then signal */
            futex_wake_waiter_locked(pp);
            woken++;
            /* Leave pp unchanged because *pp is already the next node */
        } else if ((uint32_t) requeued < requeue_count) {
            if (idx_src == idx_dst) {
                /* Same bucket: only the key changes. Linux's requeue_futex()
                 * takes this path too (hb1 == hb2), rewriting q->key without
                 * moving the entry. Unlinking and relinking here would put w
                 * right back at *pp, so pp would never advance past it.
                 */
                w->uaddr = uaddr2;
                pp = &w->next;
            } else {
                /* Requeue: remove from source, add to destination */
                *pp = w->next;

                /* Credit the destination before debiting the source, so the
                 * shim never sees this waiter charged to no bucket. Both halves
                 * sit under pub_follows: a waiter carrying no charge of its own
                 * must not gain one here, which is how a charge outlived its
                 * waiter.
                 */
                if (w->pub_follows) {
                    shim_globals_futex_waiters_add(g, idx_dst, +1);
                    shim_globals_futex_waiters_add(g, w->pub_bucket, -1);
                    w->pub_bucket = idx_dst;
                }
                w->uaddr = uaddr2;
                w->next = b_dst->head;
                b_dst->head = w;

                /* The owner sleeps under the source lock, and a wake at uaddr2
                 * takes the destination's. Send it to re-park there.
                 */
                atomic_store_explicit(&w->home, idx_dst, memory_order_release);
                pthread_cond_signal(&w->cond);
            }
            requeued++;
        } else {
            break; /* Both limits reached */
        }
    }

    /* Unlock in reverse order */
    if (idx_src == idx_dst) {
        pthread_mutex_unlock(&b_src->lock);
    } else if (idx_src < idx_dst) {
        pthread_mutex_unlock(&b_dst->lock);
        pthread_mutex_unlock(&b_src->lock);
    } else {
        pthread_mutex_unlock(&b_src->lock);
        pthread_mutex_unlock(&b_dst->lock);
    }
    futex_async_wake_flush();

    return (int64_t) woken + requeued;
}

/* FUTEX_WAKE_OP: atomically modify *uaddr2, wake val waiters at uaddr, then
 * conditionally wake val2 waiters at uaddr2 based on the old value.
 *
 * The op argument encodes: operation on *uaddr2 and comparison predicate. Used
 * by glibc's pthread_cond_signal; musl does NOT use this, but futex emulation
 * implements it for compatibility with glibc-linked binaries.
 *
 * val3 encodes both the operation and comparison:
 *   bits 28-31: op code (SET=0, ADD=1, OR=2, ANDN=3, XOR=4)
 *   bits 24-27: cmp code (EQ=0, NE=1, LT=2, LE=3, GT=4, GE=5)
 *   bits 12-23: op arg
 *   bits  0-11: cmp arg
 */
static int64_t futex_wake_op(guest_t *g,
                             uint64_t uaddr,
                             uint32_t val,
                             uint64_t uaddr2,
                             uint32_t val2,
                             uint32_t val3)
{
    if (!futex_uaddr_is_aligned(uaddr) || !futex_uaddr_is_aligned(uaddr2))
        return -LINUX_EINVAL;

    /* Decode operation and comparison from val3. Bits 31-28: operation (bit 31
     * = OPARG_SHIFT flag, bits 30-28 = op) Bits 27-24: comparison operator Bits
     * 23-12: op_arg (operand for modify, 12-bit signed) Bits 11-0: cmp_arg
     * (operand for compare, 12-bit signed) Both op_arg and cmp_arg are
     * sign-extended from 12 bits to match the Linux kernel's sign_extend32() in
     * futex_atomic_op_inuser().
     *
     * Decoded before the buckets are locked, so an operand this rejects returns
     * without an unlock path of its own.
     */
    unsigned wake_op = (val3 >> 28) & 0xF;
    unsigned wake_cmp = (val3 >> 24) & 0xF;
    int32_t op_arg = futex_op_sign_extend12(val3 >> 12);
    int32_t cmp_arg = futex_op_sign_extend12(val3);

    /* The modify operand is applied to a uint32_t word, and every op below is
     * modular, so the sign-extended value is carried as its two's complement
     * bits. Only cmp_arg stays signed, because the comparisons are signed.
     */
    uint32_t op_val = (uint32_t) op_arg;

    /* FUTEX_OP_OPARG_SHIFT (bit 3 of wake_op): interpret op_arg as 1<<op_arg.
     * Linux masks an operand outside 0..31 to its low five bits and warns,
     * rather than rejecting it, so an out-of-range operand still names a shift
     * and the call proceeds. The bound is what removes the undefined behavior:
     * a negative operand reaching the shift is the fault, and the mask fixes
     * it. Linux commit 30d6e0a4190d is the same change.
     */
    if (wake_op & 8)
        op_val = 1U << futex_op_shift_arg_mask(op_arg);
    wake_op &= 7; /* Actual operation is bits 0-2 */

    /* An op Linux does not implement stops here, before the modify and before
     * any wake. proved/futexwakeop.h carries both gates.
     */
    if (!futex_wake_op_supported(wake_op))
        return -LINUX_ENOSYS;

    unsigned idx1 = futex_hash(uaddr);
    unsigned idx2 = futex_hash(uaddr2);
    futex_bucket_t *b1 = &buckets[idx1];
    futex_bucket_t *b2 = &buckets[idx2];

    /* Lock ordering */
    if (idx1 == idx2) {
        pthread_mutex_lock(&b1->lock);
    } else if (idx1 < idx2) {
        pthread_mutex_lock(&b1->lock);
        pthread_mutex_lock(&b2->lock);
    } else {
        pthread_mutex_lock(&b2->lock);
        pthread_mutex_lock(&b1->lock);
    }

    /* Atomically modify *uaddr2 */
    uint32_t *word2 = (uint32_t *) guest_ptr_w(g, uaddr2);
    if (!word2) {
        if (idx1 != idx2)
            pthread_mutex_unlock(&b2->lock);
        pthread_mutex_unlock(&b1->lock);
        return -LINUX_EFAULT;
    }

    /* Atomic read-modify-write on *uaddr2 using CAS loop. Matches Linux
     * kernel's futex_atomic_op_inuser() semantics: the modification must be
     * atomic w.r.t. concurrent guest stores.
     */
    uint32_t old_val, new_val;
    bool swapped = false, ok;
    do {
        ok = futex_word_load(word2, &old_val);
        if (!ok)
            break;
        new_val = futex_wake_op_apply(old_val, wake_op, op_val);
        ok = futex_word_cas(word2, &old_val, new_val, &swapped);
    } while (ok && !swapped);

    if (!ok) {
        if (idx1 != idx2)
            pthread_mutex_unlock(&b2->lock);
        pthread_mutex_unlock(&b1->lock);
        return -LINUX_EFAULT;
    }

    /* A comparison Linux does not implement stops here: the modify above has
     * already landed, and neither wake runs.
     */
    if (!futex_wake_cmp_supported(wake_cmp)) {
        if (idx1 != idx2)
            pthread_mutex_unlock(&b2->lock);
        pthread_mutex_unlock(&b1->lock);
        return -LINUX_ENOSYS;
    }

    /* Signed comparison on the word as it was before the modify. Evaluated here
     * because the test below has to know whether the second wake runs at all: a
     * walk the comparison never reaches cannot refuse the call.
     */
    int cond_met = futex_wake_op_cmp((int32_t) old_val, wake_cmp, cmp_arg);

    /* Neither wake reaches a PI waiter. Both walks are tested before either one
     * wakes anybody, so a refused call leaves both chains as it found them. The
     * modify above stays: Linux applies it before its own walks reach the
     * waiter that answers EINVAL.
     */
    if (futex_pi_waiter_within(b1, uaddr, FUTEX_BITSET_MATCH_ANY, val) ||
        (cond_met &&
         futex_pi_waiter_within(b2, uaddr2, FUTEX_BITSET_MATCH_ANY, val2))) {
        if (idx1 != idx2)
            pthread_mutex_unlock(&b2->lock);
        pthread_mutex_unlock(&b1->lock);
        return -LINUX_EINVAL;
    }

    /* Wake up to val waiters at uaddr (unlink woken entries) */
    int woken1 = 0;
    futex_waiter_t **pp1 = &b1->head;
    while (*pp1 && (uint32_t) woken1 < val) {
        futex_waiter_t *w = *pp1;
        if (w->uaddr == uaddr) {
            futex_wake_waiter_locked(pp1);
            woken1++;
        } else {
            pp1 = &w->next;
        }
    }

    /* Conditionally wake up to val2 waiters at uaddr2 (unlink woken) */
    int woken2 = 0;
    if (cond_met) {
        futex_waiter_t **pp2 = &b2->head;
        while (*pp2 && (uint32_t) woken2 < val2) {
            futex_waiter_t *w2 = *pp2;
            if (w2->uaddr == uaddr2) {
                futex_wake_waiter_locked(pp2);
                woken2++;
            } else {
                pp2 = &w2->next;
            }
        }
    }

    /* Unlock reverse order */
    if (idx1 == idx2) {
        pthread_mutex_unlock(&b1->lock);
    } else if (idx1 < idx2) {
        pthread_mutex_unlock(&b2->lock);
        pthread_mutex_unlock(&b1->lock);
    } else {
        pthread_mutex_unlock(&b1->lock);
        pthread_mutex_unlock(&b2->lock);
    }
    futex_async_wake_flush();

    return (int64_t) woken1 + woken2;
}

/* PI futexes use the futex word itself as an atomic lock:
 *   bits 0-29 owner TID, bit 30 FUTEX_OWNER_DIED, bit 31 FUTEX_WAITERS.
 * The implementation below keeps that word as the guest-visible state and
 * maintains the local PI records used for priority donation.
 */

/* FUTEX_LOCK_PI: Block until the lock at uaddr can be acquired.
 *
 * The PI futex word stores the owner TID in bits 0-29 and a WAITERS flag in bit
 * 31. The kernel emulation sets FUTEX_WAITERS when a thread blocks, so the
 * current owner knows to call FUTEX_UNLOCK_PI instead of releasing the word
 * with the uncontended userspace CAS(TID->0) path.
 *
 * Flow: try CAS(0->TID). If held by another thread, set WAITERS bit via CAS,
 * then block. On wakeup, retry acquisition. FUTEX_LOCK_PI: Block until the lock
 * at uaddr can be acquired.
 *
 * The PI futex word stores the owner TID in bits 0-29 and a WAITERS flag in bit
 * 31. The kernel emulation sets FUTEX_WAITERS when a thread blocks, so the
 * current owner knows to call FUTEX_UNLOCK_PI instead of releasing the word
 * with the uncontended userspace CAS(TID->0) path.
 *
 * A blocked waiter is a heap record linked both into the address bucket and
 * into the owning task's PI lock record. While it waits it donates its
 * effective scheduling key to the owner; the chain continues through any lock
 * the owner is itself blocked on, with a cycle check before enqueue.
 */
static int64_t futex_lock_pi_inner(guest_t *g,
                                   uint64_t uaddr,
                                   uint64_t timeout_gva)
{
    if (!futex_uaddr_is_aligned(uaddr))
        return -LINUX_EINVAL;

    uint32_t *word = (uint32_t *) guest_ptr_w(g, uaddr);
    if (!word)
        return -LINUX_EFAULT;

    thread_entry_t *self = current_thread;
    if (!self)
        return -LINUX_ESRCH;
    uint32_t tid = (uint32_t) thread_tid(self);

    /* LOCK_PI timeouts are absolute CLOCK_REALTIME. */
    bool has_timeout = timeout_gva != 0;
    struct timespec deadline;
    if (has_timeout) {
        int rc =
            futex_make_deadline(g, timeout_gva, /*is_absolute=*/1, &deadline);
        if (rc == -1)
            return -LINUX_EFAULT;
        if (rc == -2)
            return -LINUX_EINVAL;
    }

    unsigned idx = futex_hash(uaddr);
    futex_bucket_t *b = &buckets[idx];

    for (;;) {
        /* Uncontended acquisition: the word is exactly 0. */
        uint32_t expected = 0;
        bool acquired;
        if (!futex_word_cas(word, &expected, tid, &acquired))
            return -LINUX_EFAULT;
        if (acquired)
            return 0;
        if (futex_pi_owner_tid(expected) == tid)
            return -LINUX_EDEADLK;

        pthread_mutex_lock(&futex_pi_mutex);
        pthread_mutex_lock(&b->lock);

        uint32_t cur;
        if (!futex_word_load(word, &cur)) {
            pthread_mutex_unlock(&b->lock);
            pthread_mutex_unlock(&futex_pi_mutex);
            return -LINUX_EFAULT;
        }
        if (futex_pi_owner_tid(cur) == tid) {
            pthread_mutex_unlock(&b->lock);
            pthread_mutex_unlock(&futex_pi_mutex);
            return -LINUX_EDEADLK;
        }
        if (futex_pi_unowned(cur)) {
            /* No TID but WAITERS and/or OWNER_DIED: a release handoff or a
             * robust death left the word for the next locker. Take it over and
             * adopt any waiters' lock record.
             */
            uint32_t want = tid | (cur & FUTEX_PI_OWNER_DIED);
            if (bucket_has_uaddr_locked(b, uaddr))
                want = futex_pi_set_waiters(want);
            bool taken;
            if (!futex_word_cas(word, &cur, want, &taken)) {
                pthread_mutex_unlock(&b->lock);
                pthread_mutex_unlock(&futex_pi_mutex);
                return -LINUX_EFAULT;
            }
            if (taken) {
                futex_pi_lock_t *st = futex_pi_state_for_uaddr_locked(b, uaddr);
                if (st)
                    (void) futex_pi_adopt_lock_locked(st, self);
                pthread_mutex_unlock(&b->lock);
                pthread_mutex_unlock(&futex_pi_mutex);
                return 0;
            }
            pthread_mutex_unlock(&b->lock);
            pthread_mutex_unlock(&futex_pi_mutex);
            continue;
        }

        uint32_t owner_tid = futex_pi_owner_tid(cur);
        if (!thread_tid_alive((int64_t) owner_tid)) {
            /* Non-robust owner exit with no waiter: Linux keeps the dead TID in
             * the word and reports ESRCH.
             */
            pthread_mutex_unlock(&b->lock);
            pthread_mutex_unlock(&futex_pi_mutex);
            return -LINUX_ESRCH;
        }
        thread_entry_t *owner = thread_acquire_tid((int64_t) owner_tid);
        if (!owner) {
            pthread_mutex_unlock(&b->lock);
            pthread_mutex_unlock(&futex_pi_mutex);
            return -LINUX_ESRCH;
        }

        /* Set WAITERS under the bucket lock before enqueueing. The owner's
         * guest-side CAS then fails and its release reaches UNLOCK_PI, which
         * takes this same bucket lock.
         */
        if (!futex_pi_has_waiters(cur)) {
            bool marked;
            if (!futex_word_cas(word, &cur, futex_pi_set_waiters(cur),
                                &marked)) {
                thread_release(owner);
                pthread_mutex_unlock(&b->lock);
                pthread_mutex_unlock(&futex_pi_mutex);
                return -LINUX_EFAULT;
            }
            if (!marked) {
                thread_release(owner);
                pthread_mutex_unlock(&b->lock);
                pthread_mutex_unlock(&futex_pi_mutex);
                continue;
            }
        }

        futex_pi_lock_t *st = futex_pi_owner_state_locked(owner, uaddr);
        thread_release(owner);
        if (!st) {
            pthread_mutex_unlock(&b->lock);
            pthread_mutex_unlock(&futex_pi_mutex);
            return -LINUX_ENOMEM;
        }
        if (futex_pi_cycle_locked(st, self)) {
            futex_pi_release_empty_locked(st);
            pthread_mutex_unlock(&b->lock);
            pthread_mutex_unlock(&futex_pi_mutex);
            return -LINUX_EDEADLK;
        }

        futex_waiter_t *waiter = calloc(1, sizeof(*waiter));
        if (!waiter) {
            futex_pi_release_empty_locked(st);
            pthread_mutex_unlock(&b->lock);
            pthread_mutex_unlock(&futex_pi_mutex);
            return -LINUX_ENOMEM;
        }
        waiter->uaddr = uaddr;
        waiter->bitset = FUTEX_BITSET_MATCH_ANY;
        atomic_store_explicit(&waiter->woken, 0, memory_order_relaxed);
        waiter->next = b->head;
        waiter->pub_bucket = idx;
        waiter->pub_follows = false;
        waiter->waiter_tid = tid;
        waiter->is_pi = true;
        waiter->pi_lock_pi = true;
        atomic_store_explicit(&waiter->home, idx, memory_order_relaxed);
        waiter->async_owner = self;
        pthread_cond_init(&waiter->cond, NULL);
        b->head = waiter;

        int lrc = futex_pi_link_locked(st, waiter, self);
        if (lrc != 0) {
            b->head = waiter->next;
            pthread_cond_destroy(&waiter->cond);
            free(waiter);
            futex_pi_release_empty_locked(st);
            pthread_mutex_unlock(&b->lock);
            pthread_mutex_unlock(&futex_pi_mutex);
            return lrc;
        }

        exec_park_kind_store(self, PARK_KIND_FUTEX);
        exec_park_result_pending_store(self, false); /* wake/timeout reissue */
        exec_park_reissue_store(self, false);
        self->async_futex_pub_bucket = idx;
        self->async_futex_relative = false;
        self->async_futex_timed = has_timeout;
        self->park_guest = g;
        exec_park_deadline_ns_store(self, 0);
        (void) sched_park_seq_next(self);
        exec_park_waiter_store(self, waiter);
        exec_park_active_store(self, true);

        int64_t fail = 0;
        if (has_timeout) {
            struct timespec now_rt, now_mono;
            if (clock_gettime(CLOCK_REALTIME, &now_rt) != 0 ||
                clock_gettime(CLOCK_MONOTONIC, &now_mono) != 0) {
                fail = -LINUX_EINTR;
            } else {
                int64_t dl_ns =
                    timespec_to_ns_sat(deadline.tv_sec, deadline.tv_nsec);
                int64_t rt_now_ns =
                    timespec_to_ns_sat(now_rt.tv_sec, now_rt.tv_nsec);
                if (dl_ns <= rt_now_ns) {
                    fail = -LINUX_ETIMEDOUT;
                } else {
                    uint64_t mono_now =
                        (uint64_t) now_mono.tv_sec * 1000000000ULL +
                        (uint64_t) now_mono.tv_nsec;
                    sched_arm_wait_deadline(
                        self, mono_now + (uint64_t) (dl_ns - rt_now_ns));
                }
            }
        } else {
            struct timespec now_mono;
            if (clock_gettime(CLOCK_MONOTONIC, &now_mono) == 0) {
                uint64_t mono_now = (uint64_t) now_mono.tv_sec * 1000000000ULL +
                                    (uint64_t) now_mono.tv_nsec;
                sched_arm_wait_deadline(self, mono_now + FUTEX_POLL_QUANTUM_NS);
            }
        }

        bool kicked = fail == 0 && futex_kick_consume();
        if (fail != 0) {
            if (fail == -LINUX_ETIMEDOUT && !bucket_has_uaddr_locked(b, uaddr))
                futex_clear_waiters_bit(word);
            bool ours = futex_async_claim_pre_unmount_locked(self, waiter);
            bucket_unlink_locked(b, waiter);
            futex_pi_unlink_waiter_locked(waiter);
            pthread_mutex_unlock(&b->lock);
            pthread_mutex_unlock(&futex_pi_mutex);
            if (ours) {
                sched_disarm_wait_deadline(self);
                futex_async_free_claimed(waiter);
            }
            return fail;
        }

        pthread_mutex_unlock(&b->lock);
        pthread_mutex_unlock(&futex_pi_mutex);
        if (kicked) {
            bool teardown =
                proc_exit_group_requested() || thread_stop_requested();
            bool claimed = teardown;
            if (!claimed && signal_pending())
                claimed = signal_claim_interruption();
            if (claimed)
                futex_async_cancel(self, -LINUX_EINTR);
        }
        return SYSCALL_PARKED;
    }
}

static int64_t futex_lock_pi(guest_t *g, uint64_t uaddr, uint64_t timeout_gva)
{
    unsigned idx = futex_hash(uaddr);

    shim_globals_futex_waiters_add(g, idx, +1);
    int64_t rc = futex_lock_pi_inner(g, uaddr, timeout_gva);
    if (rc == SYSCALL_PARKED)
        return SYSCALL_PARKED; /* charge dropped when the park completes */
    shim_globals_futex_waiters_add(g, idx, -1);
    return rc;
}

/* FUTEX_TRYLOCK_PI: non-blocking acquisition. The fast CAS handles a free word;
 * a word with OWNER_DIED and/or WAITERS but no TID is taken over exactly like
 * LOCK_PI, adopting any queued waiters. A live owner yields EAGAIN and a dead
 * owner without a robust mark yields ESRCH.
 */
static int64_t futex_trylock_pi(guest_t *g, uint64_t uaddr)
{
    if (!futex_uaddr_is_aligned(uaddr))
        return -LINUX_EINVAL;

    uint32_t *word = (uint32_t *) guest_ptr_w(g, uaddr);
    if (!word)
        return -LINUX_EFAULT;

    thread_entry_t *self = current_thread;
    if (!self)
        return -LINUX_ESRCH;
    uint32_t tid = (uint32_t) thread_tid(self);

    for (;;) {
        uint32_t expected = 0;
        bool acquired;
        if (!futex_word_cas(word, &expected, tid, &acquired))
            return -LINUX_EFAULT;
        if (acquired)
            return 0;

        pthread_mutex_lock(&futex_pi_mutex);
        futex_bucket_t *b = &buckets[futex_hash(uaddr)];
        pthread_mutex_lock(&b->lock);

        uint32_t cur;
        if (!futex_word_load(word, &cur)) {
            pthread_mutex_unlock(&b->lock);
            pthread_mutex_unlock(&futex_pi_mutex);
            return -LINUX_EFAULT;
        }
        if (futex_pi_unowned(cur)) {
            uint32_t want = tid | (cur & FUTEX_PI_OWNER_DIED);
            if (bucket_has_uaddr_locked(b, uaddr))
                want = futex_pi_set_waiters(want);
            bool taken;
            if (!futex_word_cas(word, &cur, want, &taken)) {
                pthread_mutex_unlock(&b->lock);
                pthread_mutex_unlock(&futex_pi_mutex);
                return -LINUX_EFAULT;
            }
            if (taken) {
                futex_pi_lock_t *st = futex_pi_state_for_uaddr_locked(b, uaddr);
                if (st)
                    (void) futex_pi_adopt_lock_locked(st, self);
                pthread_mutex_unlock(&b->lock);
                pthread_mutex_unlock(&futex_pi_mutex);
                return 0;
            }
            pthread_mutex_unlock(&b->lock);
            pthread_mutex_unlock(&futex_pi_mutex);
            continue;
        }
        if (futex_pi_owner_tid(cur) == tid) {
            pthread_mutex_unlock(&b->lock);
            pthread_mutex_unlock(&futex_pi_mutex);
            return -LINUX_EAGAIN;
        }
        if (!thread_tid_alive((int64_t) futex_pi_owner_tid(cur))) {
            pthread_mutex_unlock(&b->lock);
            pthread_mutex_unlock(&futex_pi_mutex);
            return -LINUX_ESRCH;
        }
        pthread_mutex_unlock(&b->lock);
        pthread_mutex_unlock(&futex_pi_mutex);
        return -LINUX_EAGAIN;
    }
}

/* FUTEX_UNLOCK_PI: Release the PI lock at uaddr and wake one waiter.
 *
 * Called by the lock owner when FUTEX_WAITERS is set (slow unlock path). Wake
 * one blocked waiter so it can retry acquisition, and release the word to
 * FUTEX_WAITERS while another stays queued, to 0 otherwise.
 */
static int64_t futex_unlock_pi(guest_t *g, uint64_t uaddr)
{
    thread_entry_t *self = current_thread;
    if (!self)
        return -LINUX_EPERM;
    uint32_t tid = (uint32_t) thread_tid(self);

    /* Linux futex_unlock_pi() reads the word and rejects a non-owner with
     * -EPERM *before* it validates alignment (get_user + owner check run ahead
     * of get_futex_key, whose -EINVAL is never reached), so releasing a lock
     * you do not own returns -EPERM even for an unaligned uaddr. Match that
     * ordering. The word may be unaligned here, so read it with
     * guest_read_small (boundary-safe, and avoids the aligned-atomic-load fault
     * an unaligned atomic load would take on the arm64 host).
     */
    uint32_t cur;
    if (guest_read_small(g, uaddr, &cur, sizeof(cur)) != 0)
        return -LINUX_EFAULT;
    if (futex_pi_owner_tid(cur) != tid)
        return -LINUX_EPERM;

    /* Only the owner reaches here, and an owned PI lock is always aligned
     * (LOCK_PI/TRYLOCK_PI reject an unaligned uaddr up front). Validate before
     * the atomic release path below, which requires a 4-byte-aligned word.
     */
    if (!futex_uaddr_is_aligned(uaddr))
        return -LINUX_EINVAL;

    uint32_t *word = (uint32_t *) guest_ptr_w(g, uaddr);
    if (!word)
        return -LINUX_EFAULT;

    futex_bucket_t *b = &buckets[futex_hash(uaddr)];
    pthread_mutex_lock(&futex_pi_mutex);
    pthread_mutex_lock(&b->lock);

    uint32_t released;
    futex_pi_lock_t *st = futex_pi_find_locked(self, uaddr);
    if (st && st->waiters) {
        /* Hand the lock to the highest effective key, FIFO among equals. The
         * async completion for that waiter sees its TID in the word and returns
         * 0 without re-executing LOCK_PI. The remaining waiters stay linked and
         * donate to the new owner.
         */
        futex_waiter_t *top = futex_pi_top_locked(st);
        uint32_t next_tid = top->waiter_tid;
        futex_pi_handoff_locked(st);
        released = next_tid;
        if (st->waiters)
            released = futex_pi_set_waiters(released);
        futex_wake_waiter_ptr_locked(b, top);
    } else {
        if (st)
            futex_pi_free_locked(st);

        /* A plain futex waiter on the same word is not a PI owner handoff; keep
         * WAITERS so its own FUTEX_WAKE can still reach it.
         */
        released = bucket_has_uaddr_locked(b, uaddr) ? FUTEX_PI_WAITERS : 0;
    }

    if (!futex_pi_word_store_locked(word, released)) {
        pthread_mutex_unlock(&b->lock);
        pthread_mutex_unlock(&futex_pi_mutex);
        futex_async_wake_flush();
        return -LINUX_EFAULT;
    }
    pthread_mutex_unlock(&b->lock);
    pthread_mutex_unlock(&futex_pi_mutex);
    futex_async_wake_flush();
    return 0;
}

/* Shared cancel path for async futex parks: unlink if still queued, then
 * complete with @result. Caller holds futex_lifetime_mutex, so @w stays alive
 * from the token load through the completion and the free, and the generation
 * is re-checked under it: a park that completed and remounted while this path
 * waited for the lock cannot be cancelled with the older result.
 */
static void futex_async_cancel_seq_locked(thread_entry_t *t,
                                          int64_t result,
                                          uint64_t seq)
{
    if (!t || !exec_park_active_load(t) ||
        exec_park_kind_load(t) != PARK_KIND_FUTEX)
        return;
    uint64_t cur = sched_park_seq(t);

    /* Every futex completion runs under this lock, so an unchanged seq here
     * means no completion ran since the caller read it and the token still
     * names the wait the caller meant to cancel.
     */
    if (seq != 0 && cur != seq)
        return;
    if (cur == 0)
        return;
    seq = cur;

    void *async = exec_park_waiter_load(t);
    if (!async)
        return;
    if (futex_async_is_waitv(async)) {
        (void) futex_waitv_cancel_locked(t, futex_async_waitv_group(async),
                                         result);
        return;
    }
    futex_waiter_t *w = (futex_waiter_t *) async;

    /* PI waiters have state under the PI mutex; take it before the bucket so a
     * concurrent unlock/owner-death handoff cannot detach the waiter between
     * the bucket unlink and the donation removal. The flags are immutable, so
     * they select the lock without reading PI state.
     */
    bool pi_waiter = w->is_pi || w->requeue_pi;
    if (pi_waiter)
        pthread_mutex_lock(&futex_pi_mutex);

    unsigned home = atomic_load_explicit(&w->home, memory_order_acquire);
    futex_bucket_t *b = &buckets[home];
    pthread_mutex_lock(&b->lock);

    /* Pre-unmount early-kick claims by clearing async_futex_waiter under this
     * lock before it frees. Without the recheck we would follow/free a pointer
     * that path already handed to libmalloc.
     */
    if (exec_park_waiter_load(t) != w) {
        pthread_mutex_unlock(&b->lock);
        if (pi_waiter)
            pthread_mutex_unlock(&futex_pi_mutex);
        return;
    }
    b = futex_waiter_follow(b, w);

    /* woken is the claim under the bucket lock: a wake that counted this waiter
     * has already unlinked it and queued a complete(0). Completing here with
     * ETIMEDOUT/EINTR would win that race and leave the guest reporting an
     * error for a wake that returned 1 (test-futex-requeue-race timeout-vs-wake
     * / signal-vs-wake). Mirror the sync wait path: if woken, the wake owns the
     * result.
     */
    bool was_woken = atomic_load_explicit(&w->woken, memory_order_acquire);
    if (!was_woken) {
        bucket_unlink_locked(b, w);
        if (pi_waiter)
            futex_pi_unlink_waiter_locked(w);
    }
    atomic_store_explicit(&w->woken, 1, memory_order_release);
    pthread_mutex_unlock(&b->lock);
    if (pi_waiter)
        pthread_mutex_unlock(&futex_pi_mutex);

    if (was_woken)
        return;

    /* This may run on a waker or timer thread. A relative FUTEX_WAIT timeout
     * must not be restarted after EINTR, but syscall_restart_forbid() is
     * worker-local: it would corrupt the waker's state instead of the parked
     * task's. Publish the decision on the task and let its resume tail apply
     * it.
     */
    if (result == -LINUX_EINTR && t->async_futex_relative)
        exec_restart_forbid_set(t, true);

    futex_waiter_t *w_done = w;
    guest_t *g_done = t->park_guest;
    if (sched_park_try_complete_seq(t, PARK_KIND_FUTEX, seq, result))
        futex_async_finish_bookkeeping_locked(t, w_done, g_done);
}

static void futex_async_cancel_seq(thread_entry_t *t,
                                   int64_t result,
                                   uint64_t seq)
{
    if (!t)
        return;
    pthread_mutex_lock(&futex_lifetime_mutex);
    futex_async_cancel_seq_locked(t, result, seq);
    pthread_mutex_unlock(&futex_lifetime_mutex);
}

static void futex_async_cancel(thread_entry_t *t, int64_t result)
{
    futex_async_cancel_seq(t, result, 0);
}

/* Exec/de_thread teardown: the task is already claimed DEAD and will never
 * remount, so retire its futex wait synchronously. This routes single waiters,
 * PI waiters, and futex_waitv groups through the same unlink/charge-drop path
 * as a signal cancel. sched_park_try_complete only publishes the parked result
 * and must not enqueue a DEAD task; there is no remount to consume it.
 */
void futex_task_cancel_wait(thread_entry_t *t)
{
    futex_async_cancel(t, -LINUX_EINTR);
}



/* WAIT_REQUEUE_PI signal result under the waiter bucket lock. Before
 * CMP_REQUEUE_PI: EINTR + async_futex_requeue_pi_restart (SVC restart). After
 * requeue onto the PI word: EWOULDBLOCK (Linux returns -EWOULDBLOCK). Teardown
 * always yields EINTR with no restart.
 *
 * Caller holds futex_lifetime_mutex. @w is dereferenced before its bucket lock
 * is taken, and its home is read to select that lock, so the token has to be
 * pinned from the load: a generation check after the lock is too late.
 */
static int64_t futex_requeue_pi_signal_result_locked(thread_entry_t *t,
                                                     bool teardown,
                                                     uint64_t seq)
{
    if (!t || !exec_park_active_load(t) ||
        exec_park_kind_load(t) != PARK_KIND_FUTEX)
        return -LINUX_EINTR;
    if (seq != 0 && sched_park_seq(t) != seq)
        return -LINUX_EINTR;
    void *async = exec_park_waiter_load(t);
    if (teardown || !async || futex_async_is_waitv(async))
        return -LINUX_EINTR;
    futex_waiter_t *w = (futex_waiter_t *) async;
    if (!w->requeue_pi)
        return -LINUX_EINTR;

    unsigned home = atomic_load_explicit(&w->home, memory_order_acquire);
    futex_bucket_t *b = &buckets[home];
    pthread_mutex_lock(&b->lock);
    int64_t result = -LINUX_EINTR;
    bool want_restart = false;
    if (exec_park_waiter_load(t) == w) {
        b = futex_waiter_follow(b, w);
        if (w->uaddr == w->requeue_pi_uaddr) {
            result = -LINUX_EAGAIN; /* EWOULDBLOCK */
        } else {
            want_restart = true;
        }
    }
    pthread_mutex_unlock(&b->lock);

    if (want_restart) {
        futex_async_cancel_seq_locked(t, -LINUX_EINTR, seq);
        if (exec_park_result_pending_load(t) &&
            exec_park_result_load(t) == -LINUX_EINTR)
            exec_park_requeue_pi_set(t, true);
        else
            exec_park_requeue_pi_set(t, false);
        return 0; /* already cancelled */
    }
    return result;
}

void futex_park_on_deadline(thread_entry_t *t)
{
    if (!t || !exec_park_active_load(t) ||
        exec_park_kind_load(t) != PARK_KIND_FUTEX)
        return;
    uint64_t seq = sched_park_seq(t);
    uint64_t deadline = exec_park_deadline_ns_load(t);
    if (seq == 0 || deadline == 0 || deadline > sched_now_ns())
        return;
    if (!t->async_futex_timed) {
        /* Infinite-wait poll quantum: mirror the sync no-timeout loop. Teardown
         * or a claimable waking signal completes with -EINTR; otherwise re-arm
         * and stay parked. Do not inject a spurious 0: callers that do not
         * retry (PI wait, requeue-race timeout rounds) would observe a wake
         * nobody sent.
         *
         * The signal claim runs before futex_lifetime_mutex: it takes sig_lock,
         * and claiming while holding the lifetime lock would put sig_lock under
         * it for no reason and stall every retirement behind a signal delivery.
         */
        bool teardown = thread_stop_requested_for(t);
        if (teardown || signal_claim_interruption_for(t)) {
            pthread_mutex_lock(&futex_lifetime_mutex);
            int64_t result =
                futex_requeue_pi_signal_result_locked(t, teardown, seq);
            if (result != 0)
                futex_async_cancel_seq_locked(t, result, seq);
            pthread_mutex_unlock(&futex_lifetime_mutex);
            return;
        }

        /* LOCK_PI: each quantum re-check the word like the sync path. Unowned
         * or a dead TID: mark OWNER_DIED and reissue so acquisition retries
         * without waiting for an unlock that will never come.
         *
         * The token, and every field read below, sit inside the lifetime lock:
         * the waker that completes this park frees the record, and it may not
         * do so between the load and these reads.
         */
        pthread_mutex_lock(&futex_lifetime_mutex);

        /* A completion that ran before this lock was acquired may already have
         * retired the park and let the owner arm a new one; the new park has
         * its own deadline, and the token may even reuse the old address.
         */
        if (!exec_park_active_load(t) ||
            exec_park_kind_load(t) != PARK_KIND_FUTEX ||
            sched_park_seq(t) != seq) {
            pthread_mutex_unlock(&futex_lifetime_mutex);
            return;
        }
        void *async = exec_park_waiter_load(t);
        futex_waiter_t *w = (!async || futex_async_is_waitv(async))
                                ? NULL
                                : (futex_waiter_t *) async;
        if (w && w->waiter_tid != 0 && !w->requeue_pi && t->park_guest) {
            guest_t *g = t->park_guest;
            uint32_t *word = (uint32_t *) guest_ptr_w(g, w->uaddr);
            uint32_t check = 0;
            if (word && futex_word_load(word, &check)) {
                bool retry = false;
                if (futex_pi_unowned(check)) {
                    retry = true;
                } else if (!thread_tid_alive(
                               (int64_t) futex_pi_owner_tid(check))) {
                    uint32_t died = futex_pi_mark_owner_died(check);
                    bool marked = false;
                    (void) futex_word_cas(word, &check, died, &marked);
                    retry = true;
                }
                if (retry) {
                    unsigned home =
                        atomic_load_explicit(&w->home, memory_order_acquire);
                    futex_bucket_t *b = &buckets[home];
                    if (w->is_pi)
                        pthread_mutex_lock(&futex_pi_mutex);
                    pthread_mutex_lock(&b->lock);
                    if (exec_park_waiter_load(t) == w) {
                        b = futex_waiter_follow(b, w);
                        bool woken = atomic_load_explicit(&w->woken,
                                                          memory_order_acquire);
                        if (!woken) {
                            bucket_unlink_locked(b, w);
                            if (w->is_pi)
                                futex_pi_unlink_waiter_locked(w);
                        }
                        atomic_store_explicit(&w->woken, 1,
                                              memory_order_release);
                        pthread_mutex_unlock(&b->lock);
                        if (w->is_pi)
                            pthread_mutex_unlock(&futex_pi_mutex);
                        guest_t *g_done = t->park_guest;
                        if (!woken && sched_park_try_complete_reissue_seq(
                                          t, PARK_KIND_FUTEX, seq)) {
                            futex_async_finish_bookkeeping_locked(t, w, g_done);
                        }
                        pthread_mutex_unlock(&futex_lifetime_mutex);
                        return;
                    }
                    pthread_mutex_unlock(&b->lock);
                    if (w->is_pi)
                        pthread_mutex_unlock(&futex_pi_mutex);
                }
            }
        }
        pthread_mutex_unlock(&futex_lifetime_mutex);

        struct timespec now_mono;
        if (clock_gettime(CLOCK_MONOTONIC, &now_mono) == 0) {
            uint64_t mono_now = (uint64_t) now_mono.tv_sec * 1000000000ULL +
                                (uint64_t) now_mono.tv_nsec;
            if (exec_park_active_load(t) &&
                exec_park_kind_load(t) == PARK_KIND_FUTEX &&
                sched_park_seq(t) == seq)
                sched_arm_wait_deadline(t, mono_now + FUTEX_POLL_QUANTUM_NS);
        }
        return;
    }
    futex_async_cancel_seq(t, -LINUX_ETIMEDOUT, seq);
}

void futex_park_on_interrupt(thread_entry_t *t)
{
    if (!t || !exec_park_active_load(t) ||
        exec_park_kind_load(t) != PARK_KIND_FUTEX)
        return;
    uint64_t seq = sched_park_seq(t);
    if (seq == 0)
        return;

    /* Waker thread: teardown must be evaluated for @t, not current_thread. The
     * claim takes sig_lock, so it stays outside futex_lifetime_mutex.
     */
    bool teardown = thread_stop_requested_for(t);
    if (!teardown && !signal_claim_interruption_for(t))
        return;
    pthread_mutex_lock(&futex_lifetime_mutex);
    int64_t result = futex_requeue_pi_signal_result_locked(t, teardown, seq);
    if (result != 0)
        futex_async_cancel_seq_locked(t, result, seq);
    pthread_mutex_unlock(&futex_lifetime_mutex);
}


/* FUTEX_WAIT_REQUEUE_PI: wait on @uaddr, prepared to be moved onto the PI futex
 * at @uaddr2 by FUTEX_CMP_REQUEUE_PI. On success the caller owns the PI lock at
 * uaddr2 (word holds its TID).
 */
static int64_t futex_wait_requeue_pi(guest_t *g,
                                     uint64_t uaddr,
                                     uint32_t expected,
                                     uint64_t uaddr2,
                                     uint64_t timeout_gva)
{
    if (!futex_uaddr_is_aligned(uaddr) || !futex_uaddr_is_aligned(uaddr2))
        return -LINUX_EINVAL;
    if (uaddr == uaddr2)
        return -LINUX_EINVAL;

    uint32_t tid = current_thread ? (uint32_t) thread_tid(current_thread)
                                  : (uint32_t) proc_get_pid();

    unsigned idx = futex_hash(uaddr);
    futex_bucket_t *b = &buckets[idx];

    bool has_timeout = (timeout_gva != 0);
    struct timespec deadline;
    if (has_timeout) {
        /* WAIT_REQUEUE_PI timeouts are absolute CLOCK_REALTIME, like LOCK_PI.
         */
        int rc =
            futex_make_deadline(g, timeout_gva, /*is_absolute=*/1, &deadline);
        if (rc == -1)
            return -LINUX_EFAULT;
        if (rc == -2)
            return -LINUX_EINVAL;
    }

    if (!has_timeout ||
        futex_remaining_ns(&deadline, FUTEX_POLL_QUANTUM_NS, NULL) > 0) {
        const uint32_t *spin_word = (const uint32_t *) guest_ptr(g, uaddr);
        if (spin_word && futex_spin_word_moved(spin_word, expected))
            return -LINUX_EAGAIN;
    }

    pthread_mutex_lock(&b->lock);
    int64_t block = futex_should_block(g, uaddr, expected);
    if (block != 0) {
        pthread_mutex_unlock(&b->lock);
        return block;
    }

    thread_entry_t *self = current_thread;
    if (!self) {
        pthread_mutex_unlock(&b->lock);
        return -LINUX_ESRCH;
    }

    {
        futex_waiter_t *waiter = calloc(1, sizeof(*waiter));
        if (!waiter) {
            pthread_mutex_unlock(&b->lock);
            return -LINUX_ENOMEM;
        }
        waiter->uaddr = uaddr;
        waiter->bitset = FUTEX_BITSET_MATCH_ANY;
        atomic_store_explicit(&waiter->woken, 0, memory_order_relaxed);
        waiter->next = b->head;
        waiter->pub_bucket = idx;
        waiter->pub_follows = true;
        atomic_store_explicit(&waiter->home, idx, memory_order_relaxed);
        waiter->async_owner = self;
        waiter->requeue_pi = true;
        waiter->requeue_pi_uaddr = uaddr2;
        waiter->waiter_tid = tid;
        pthread_cond_init(&waiter->cond, NULL);
        b->head = waiter;

        exec_park_kind_store(self, PARK_KIND_FUTEX);
        exec_park_result_pending_store(self, true);
        exec_park_reissue_store(self, false);
        self->async_futex_pub_bucket = idx;
        self->async_futex_relative = false;
        self->async_futex_timed = has_timeout;
        self->park_guest = g;
        exec_park_deadline_ns_store(self, 0);
        (void) sched_park_seq_next(self);
        exec_park_waiter_store(self, waiter);
        exec_park_active_store(self, true);

        if (has_timeout) {
            struct timespec now_rt, now_mono;
            if (clock_gettime(CLOCK_REALTIME, &now_rt) != 0 ||
                clock_gettime(CLOCK_MONOTONIC, &now_mono) != 0) {
                bucket_unlink_locked(b, waiter);
                bool ours = futex_async_claim_pre_unmount_locked(self, waiter);
                pthread_mutex_unlock(&b->lock);
                if (ours)
                    futex_async_free_claimed(waiter);
                return -LINUX_EINTR;
            }
            int64_t dl_ns =
                timespec_to_ns_sat(deadline.tv_sec, deadline.tv_nsec);
            int64_t rt_now_ns =
                timespec_to_ns_sat(now_rt.tv_sec, now_rt.tv_nsec);
            if (dl_ns <= rt_now_ns) {
                bucket_unlink_locked(b, waiter);
                bool ours = futex_async_claim_pre_unmount_locked(self, waiter);
                pthread_mutex_unlock(&b->lock);
                if (ours)
                    futex_async_free_claimed(waiter);
                return -LINUX_ETIMEDOUT;
            }
            uint64_t mono_now = (uint64_t) now_mono.tv_sec * 1000000000ULL +
                                (uint64_t) now_mono.tv_nsec;
            sched_arm_wait_deadline(self,
                                    mono_now + (uint64_t) (dl_ns - rt_now_ns));
        } else {
            struct timespec now_mono;
            if (clock_gettime(CLOCK_MONOTONIC, &now_mono) == 0) {
                uint64_t mono_now = (uint64_t) now_mono.tv_sec * 1000000000ULL +
                                    (uint64_t) now_mono.tv_nsec;
                sched_arm_wait_deadline(self, mono_now + FUTEX_POLL_QUANTUM_NS);
            }
        }

        bool kicked = futex_kick_consume();
        shim_globals_futex_waiters_add(g, idx, +1);
        pthread_mutex_unlock(&b->lock);

        if (kicked) {
            bool teardown =
                proc_exit_group_requested() || thread_stop_requested();
            bool claimed = teardown;
            if (!claimed && signal_pending())
                claimed = signal_claim_interruption();
            if (claimed) {
                uint64_t seq = sched_park_seq(self);
                pthread_mutex_lock(&futex_lifetime_mutex);
                int64_t result =
                    futex_requeue_pi_signal_result_locked(self, teardown, seq);
                if (result != 0)
                    futex_async_cancel_seq_locked(self, result, seq);
                pthread_mutex_unlock(&futex_lifetime_mutex);
            }
        }
        return SYSCALL_PARKED;
    }
}

/* FUTEX_CMP_REQUEUE_PI: compare *uaddr == expected, wake one WAIT_REQUEUE_PI
 * waiter (handing it the PI lock at uaddr2 when free), requeue the rest onto
 * uaddr2 as PI waiters. nr_wake must be 1. Plain (non-requeue_pi) waiters on
 * uaddr yield -EINVAL (ks-futex_requeue_pi_mismatched_ops).
 */
static int64_t futex_cmp_requeue_pi(guest_t *g,
                                    uint64_t uaddr,
                                    uint32_t wake_count,
                                    uint32_t requeue_count,
                                    uint64_t uaddr2,
                                    uint32_t expected)
{
    if (wake_count != 1)
        return -LINUX_EINVAL;
    if (!futex_uaddr_is_aligned(uaddr) || !futex_uaddr_is_aligned(uaddr2))
        return -LINUX_EINVAL;
    if (uaddr == uaddr2)
        return -LINUX_EINVAL;
    if (!futex_requeue_counts_valid(wake_count, requeue_count))
        return -LINUX_EINVAL;

    unsigned idx_src = futex_hash(uaddr);
    unsigned idx_dst = futex_hash(uaddr2);
    futex_bucket_t *b_src = &buckets[idx_src];
    futex_bucket_t *b_dst = &buckets[idx_dst];

    pthread_mutex_lock(&futex_pi_mutex);
    if (idx_src == idx_dst) {
        pthread_mutex_lock(&b_src->lock);
    } else if (idx_src < idx_dst) {
        pthread_mutex_lock(&b_src->lock);
        pthread_mutex_lock(&b_dst->lock);
    } else {
        pthread_mutex_lock(&b_dst->lock);
        pthread_mutex_lock(&b_src->lock);
    }

    int64_t rc = 0;
    futex_waiter_t *first = NULL;
    futex_waiter_t **first_pp = NULL;
    futex_pi_lock_t *st = NULL;
    thread_entry_t *new_owner = NULL;
    bool handed = false;
    int woken = 0;
    int requeued = 0;

    rc = futex_should_block(g, uaddr, expected);
    if (rc != 0)
        goto out;

    /* Mismatch detection: any waiter on uaddr that is not WAIT_REQUEUE_PI
     * targeting uaddr2 is EINVAL.
     */
    for (futex_waiter_t *w = b_src->head; w; w = w->next) {
        if (w->uaddr != uaddr)
            continue;
        if (!w->requeue_pi || w->requeue_pi_uaddr != uaddr2) {
            rc = -LINUX_EINVAL;
            goto out;
        }
    }

    uint32_t *pi_word = (uint32_t *) guest_ptr_w(g, uaddr2);
    if (!pi_word) {
        rc = -LINUX_EFAULT;
        goto out;
    }

    for (first_pp = &b_src->head; *first_pp; first_pp = &(*first_pp)->next) {
        if ((*first_pp)->uaddr == uaddr) {
            first = *first_pp;
            break;
        }
    }
    if (!first) {
        rc = 0;
        goto out;
    }
    if (!first->async_owner) {
        rc = -LINUX_ESRCH;
        goto out;
    }

    /* Decide who owns uaddr2 and whether the first waiter can take it now. */
    uint32_t cur;
    if (!futex_word_load(pi_word, &cur)) {
        rc = -LINUX_EFAULT;
        goto out;
    }
    uint32_t owner_tid = futex_pi_owner_tid(cur);
    if (owner_tid == 0) {
        uint32_t want = first->waiter_tid | (cur & FUTEX_PI_OWNER_DIED);
        if (requeue_count != 0)
            want = futex_pi_set_waiters(want);
        bool taken;
        if (!futex_word_cas(pi_word, &cur, want, &taken)) {
            rc = -LINUX_EFAULT;
            goto out;
        }
        if (taken) {
            handed = true;
            new_owner = first->async_owner;
            if (!new_owner) {
                rc = -LINUX_EINVAL;
                goto out;
            }
        }
    }
    if (!handed) {
        if (owner_tid == 0) {
            /* The word changed under us; ask the guest to retry. */
            rc = -LINUX_EAGAIN;
            goto out;
        }
        thread_entry_t *owner = thread_acquire_tid((int64_t) owner_tid);
        if (!owner) {
            rc = -LINUX_ESRCH;
            goto out;
        }
        st = futex_pi_owner_state_locked(owner, uaddr2);
        thread_release(owner);
        if (!st) {
            rc = -LINUX_ENOMEM;
            goto out;
        }
    }

    /* First waiter: move to uaddr2's bucket, then either wake it as the new
     * owner or link it as a PI waiter behind the live owner.
     */
    if (idx_src == idx_dst) {
        first->uaddr = uaddr2;
        first->pub_follows = false;
    } else {
        *first_pp = first->next;
        if (first->pub_follows) {
            shim_globals_futex_waiters_add(g, idx_dst, +1);
            shim_globals_futex_waiters_add(g, first->pub_bucket, -1);
            first->pub_bucket = idx_dst;
        }
        first->uaddr = uaddr2;
        first->pub_follows = false;
        first->next = b_dst->head;
        b_dst->head = first;
        atomic_store_explicit(&first->home, idx_dst, memory_order_release);
    }

    if (handed) {
        futex_wake_waiter_ptr_locked(b_dst, first);
        woken = 1;
    } else {
        int lrc;
        first->is_pi = true;
        first->pi_lock_pi = false;
        lrc = futex_pi_link_locked(st, first, first->async_owner);
        if (lrc != 0) {
            rc = lrc;
            goto out;
        }
        woken = 1;
        futex_pi_ensure_waiters_locked(pi_word);
    }

    /* Up to requeue_count further waiters stay blocked on the PI word. */
    while ((uint32_t) requeued < requeue_count) {
        futex_waiter_t **pp = &b_src->head;
        futex_waiter_t *w = NULL;
        while (*pp) {
            if ((*pp)->uaddr == uaddr) {
                w = *pp;
                break;
            }
            pp = &(*pp)->next;
        }
        if (!w)
            break;
        if (!w->async_owner) {
            rc = -LINUX_ESRCH;
            goto out;
        }

        if (idx_src == idx_dst) {
            w->uaddr = uaddr2;
            w->pub_follows = false;
        } else {
            *pp = w->next;
            if (w->pub_follows) {
                shim_globals_futex_waiters_add(g, idx_dst, +1);
                shim_globals_futex_waiters_add(g, w->pub_bucket, -1);
                w->pub_bucket = idx_dst;
            }
            w->uaddr = uaddr2;
            w->pub_follows = false;
            w->next = b_dst->head;
            b_dst->head = w;
            atomic_store_explicit(&w->home, idx_dst, memory_order_release);
        }

        if (!st) {
            st = futex_pi_owner_state_locked(new_owner, uaddr2);
            if (!st) {
                rc = -LINUX_ENOMEM;
                goto out;
            }
        }
        w->is_pi = true;
        w->pi_lock_pi = false;
        int lrc = futex_pi_link_locked(st, w, w->async_owner);
        if (lrc != 0) {
            rc = lrc;
            goto out;
        }
        futex_pi_ensure_waiters_locked(pi_word);
        requeued++;
    }

    /* If the first waiter became owner, publish WAITERS based on the waiters
     * that actually remain.
     */
    if (handed) {
        uint32_t now;
        if (futex_word_load(pi_word, &now) &&
            futex_pi_owner_tid(now) == first->waiter_tid) {
            uint32_t want = first->waiter_tid | (now & FUTEX_PI_OWNER_DIED);
            if (bucket_has_uaddr_locked(b_dst, uaddr2))
                want = futex_pi_set_waiters(want);
            (void) futex_pi_word_store_locked(pi_word, want);
        }
    }

    rc = (int64_t) woken + requeued;

out:
    if (rc < 0)
        futex_pi_release_empty_locked(st);
    if (idx_src == idx_dst) {
        pthread_mutex_unlock(&b_src->lock);
    } else if (idx_src < idx_dst) {
        pthread_mutex_unlock(&b_dst->lock);
        pthread_mutex_unlock(&b_src->lock);
    } else {
        pthread_mutex_unlock(&b_src->lock);
        pthread_mutex_unlock(&b_dst->lock);
    }
    pthread_mutex_unlock(&futex_pi_mutex);
    futex_async_wake_flush();
    return rc;
}


/* Syscall entry point. */

/* FUTEX_ROBUST_UNLOCK: clear the futex word, clear *list_op_pending (uaddr2),
 * and wake waiters. Used by glibc-style robust unlock helpers and exercised by
 * ks-robust_list futex_op.*test_futex_robust_unlock. LIST32 clears only the low
 * 32 bits of the pending pointer (compat layout).
 */
static int64_t futex_robust_unlock(guest_t *g,
                                   uint64_t uaddr,
                                   int cmd,
                                   uint32_t val,
                                   uint64_t pending_gva,
                                   uint32_t val3,
                                   bool list32)
{
    if (!futex_uaddr_is_aligned(uaddr))
        return -LINUX_EINVAL;

    uint32_t *word = (uint32_t *) guest_ptr_w(g, uaddr);
    if (!word)
        return -LINUX_EFAULT;

    uint32_t cur;
    if (!futex_word_load(word, &cur))
        return -LINUX_EFAULT;
    /* Owner check: val carries the expected TID (test passes gettid()). */
    if (futex_pi_owner_tid(cur) != futex_pi_owner_tid(val))
        return -LINUX_EPERM;

    /* Clear the word under the bucket lock so a concurrent waiter enqueue
     * cannot miss the wake after observing a non-zero owner.
     */
    futex_bucket_t *b = &buckets[futex_hash(uaddr)];
    pthread_mutex_lock(&b->lock);
    for (;;) {
        if (!futex_word_load(word, &cur)) {
            pthread_mutex_unlock(&b->lock);
            return -LINUX_EFAULT;
        }
        if (futex_pi_owner_tid(cur) != futex_pi_owner_tid(val)) {
            pthread_mutex_unlock(&b->lock);
            return -LINUX_EPERM;
        }
        bool done = false;
        if (!futex_word_cas(word, &cur, 0, &done)) {
            pthread_mutex_unlock(&b->lock);
            return -LINUX_EFAULT;
        }
        if (done)
            break;
    }

    int64_t woke = 0;
    if (cmd == FUTEX_WAKE || cmd == FUTEX_WAKE_BITSET ||
        cmd == FUTEX_UNLOCK_PI) {
        uint32_t bitset =
            (cmd == FUTEX_WAKE_BITSET) ? val3 : FUTEX_BITSET_MATCH_ANY;

        /* Wake all matching waiters for WAKE/BITSET; UNLOCK_PI wakes one. The
         * kselftest uses an uncontended word (expects 0).
         */
        int nr = (cmd == FUTEX_UNLOCK_PI) ? 1 : 0x7fffffff;
        for (int i = 0; i < nr; i++) {
            futex_waiter_t *w = NULL;
            for (futex_waiter_t *it = b->head; it; it = it->next) {
                if (it->uaddr != uaddr)
                    continue;
                if (cmd == FUTEX_WAKE_BITSET && (it->bitset & bitset) == 0)
                    continue;
                w = it;
                break;
            }
            if (!w)
                break;
            bucket_unlink_locked(b, w);
            atomic_store_explicit(&w->woken, 1, memory_order_release);
            if (w->async_owner)
                futex_async_wake_queue(w);
            else
                pthread_cond_signal(&w->cond);
            woke++;
        }
    }
    pthread_mutex_unlock(&b->lock);
    futex_async_wake_flush();

    if (pending_gva) {
        if (list32) {
            uint32_t zero32 = 0;
            if (guest_write_small(g, pending_gva, &zero32, sizeof(zero32)) < 0)
                return -LINUX_EFAULT;
        } else {
            uint64_t zero64 = 0;
            if (guest_write_small(g, pending_gva, &zero64, sizeof(zero64)) < 0)
                return -LINUX_EFAULT;
        }
    }

    return woke;
}

int64_t sys_futex(guest_t *g,
                  uint64_t uaddr,
                  int op,
                  uint32_t val,
                  uint64_t timeout_gva,
                  uint64_t uaddr2,
                  uint32_t val3)
{
    int cmd = op & FUTEX_CMD_MASK;

    /* Match Linux do_futex(): FLAGS_CLOCKRT is only valid for WAIT_BITSET and
     * WAIT_REQUEUE_PI (LOCK_PI2 not implemented). Plain LOCK_PI must not park
     * forever when the test probes the unsupported flag with a NULL timeout.
     */
    if ((op & FUTEX_CLOCK_REALTIME) && cmd != FUTEX_WAIT_BITSET &&
        cmd != FUTEX_WAIT_REQUEUE_PI)
        return -LINUX_ENOSYS;

    if (op & FUTEX_ROBUST_UNLOCK) {
        if (cmd != FUTEX_WAKE && cmd != FUTEX_WAKE_BITSET &&
            cmd != FUTEX_UNLOCK_PI)
            return -LINUX_ENOSYS;
        return futex_robust_unlock(g, uaddr, cmd, val, uaddr2, val3,
                                   (op & FUTEX_ROBUST_LIST32) != 0);
    }

    switch (cmd) {
    case FUTEX_WAIT:
        /* On the bucket, like FUTEX_WAIT_BITSET. Darwin's
         * os_sync_wait_on_address would park it with no bucket lock, but the
         * only way to reach a thread parked there is to wake its address, which
         * it cannot tell from a FUTEX_WAKE. Ending the wait for a queued signal
         * that way reports EINTR for a wake that counted the waiter, or 0 for a
         * signal it could not claim. waiter.woken is what tells them apart.
         */
        return futex_wait(g, uaddr, val, timeout_gva, FUTEX_BITSET_MATCH_ANY,
                          /*is_absolute=*/0);

    case FUTEX_WAKE:
        return futex_wake(g, uaddr, val, FUTEX_BITSET_MATCH_ANY);

    case FUTEX_REQUEUE:
        /* For REQUEUE, the timeout arg is repurposed as val2 (requeue count) */
        return futex_requeue(g, uaddr, val, (uint32_t) timeout_gva, uaddr2,
                             /*do_cmp=*/0, 0);

    case FUTEX_CMP_REQUEUE:
        /* Same repurposing of timeout -> val2, plus compare against val3 */
        return futex_requeue(g, uaddr, val, (uint32_t) timeout_gva, uaddr2,
                             /*do_cmp=*/1, val3);

    case FUTEX_WAKE_OP:
        /* timeout arg repurposed as val2 (wake count for uaddr2) */
        return futex_wake_op(g, uaddr, val, uaddr2, (uint32_t) timeout_gva,
                             val3);

    case FUTEX_WAIT_BITSET:
        return futex_wait(g, uaddr, val, timeout_gva, val3, /*is_absolute=*/1);

    case FUTEX_WAKE_BITSET:
        return futex_wake(g, uaddr, val, val3);

    case FUTEX_LOCK_PI:
        return futex_lock_pi(g, uaddr, timeout_gva);

    case FUTEX_UNLOCK_PI:
        return futex_unlock_pi(g, uaddr);

    case FUTEX_TRYLOCK_PI:
        return futex_trylock_pi(g, uaddr);

    case FUTEX_WAIT_REQUEUE_PI:
        /* val3 unused; uaddr2 is the PI futex; timeout is absolute REALTIME. */
        return futex_wait_requeue_pi(g, uaddr, val, uaddr2, timeout_gva);

    case FUTEX_CMP_REQUEUE_PI:
        /* timeout arg -> val2 (requeue count); val3 -> expected compare. */
        return futex_cmp_requeue_pi(g, uaddr, val, (uint32_t) timeout_gva,
                                    uaddr2, val3);

    default:
        /* Unimplemented futex operation.
         * Return ENOSYS so musl knows to fall back.
         */
        return -LINUX_ENOSYS;
    }
}

int futex_wake_one(guest_t *g, uint64_t uaddr)
{
    return (int) futex_wake(g, uaddr, 1, FUTEX_BITSET_MATCH_ANY);
}

/* futex_waitv (SYS 449): batch futex wait on multiple addresses.
 *
 * Blocks until any one of the specified futexes is woken, or a timeout expires.
 * Returns the 0-based index of the woken futex, or negative errno.
 *
 * Linux struct futex_waitv layout (24 bytes per element):
 *   uint64_t val, uaddr, uint32_t flags, __reserved
 */
#define FUTEX_WAITV_MAX 128 /* Linux limit */

#define FUTEX2_SIZE_U32 0x02
#define FUTEX2_SIZE_MASK 0x03
#define FUTEX2_PRIVATE 0x80
#define FUTEX2_VALID_FLAGS (FUTEX2_SIZE_MASK | FUTEX2_PRIVATE)

typedef struct {
    uint64_t val, uaddr;
    uint32_t flags, __reserved;
} linux_futex_waitv_t;

_Static_assert(sizeof(linux_futex_waitv_t) == 24,
               "futex_waitv element must be 24 bytes");

/* One wait registration for a whole futex_waitv set. Each element is an
 * ordinary bucket waiter; all of them point back here, and the first wake (or
 * timeout/signal/teardown) publishes one result and retires the whole set. The
 * group and its element array are freed only under futex_lifetime_mutex, after
 * the tagged publication is cleared, so a completion path that loaded the tag
 * can dereference the group for as long as it holds that lock.
 */
typedef struct futex_waitv_group {
    thread_entry_t *owner;
    uint64_t park_seq; /* Generation of the park that published this group */
    uint32_t n;
    futex_waiter_t *waiters;
    _Atomic int result; /* index, or negative errno; INT_MIN = unset */
    _Atomic int completed;
} futex_waitv_group_t;

/* Group retirement takes futex_lifetime_mutex, the same lock that protects a
 * single waiter: a reader that loaded the tagged token and a retirement that
 * frees the group have to serialize, because the tag is only a pointer with a
 * bit set and a freed group can be reallocated to a different one. Wakers only
 * publish a result under their bucket lock; they never free, and retirement
 * locks each element's bucket before unlinking it or freeing the group, so a
 * waker still holding an element's bucket keeps the group alive.
 */
#define FUTEX_WAITV_RESULT_UNSET INT_MIN

/* Linux clockid values accepted by futex_waitv. */
#define LINUX_CLOCK_REALTIME 0
#define LINUX_CLOCK_MONOTONIC 1

/* Called by the waker while it still holds the bucket lock. The first wake
 * publishes its index; later wakes leave it alone.
 */
static void futex_waitv_note_wake(futex_waiter_t *w)
{
    futex_waitv_group_t *grp = w->waitv_group;
    if (!grp)
        return;
    int expected = FUTEX_WAITV_RESULT_UNSET;
    (void) atomic_compare_exchange_strong_explicit(
        &grp->result, &expected, w->waitv_index, memory_order_release,
        memory_order_relaxed);
}

/* Retire @grp if it is still the task's published wait. Caller holds
 * futex_lifetime_mutex. Unlinks every element, drops charges, and frees the
 * group; returns false when another path already retired it.
 */
static bool futex_waitv_retire_locked(thread_entry_t *t,
                                      futex_waitv_group_t *grp,
                                      int64_t fallback,
                                      int64_t *out)
{
    if (!t || !grp || exec_park_waiter_load(t) != futex_waitv_tag(grp) ||
        sched_park_seq(t) != grp->park_seq)
        return false;
    if (atomic_exchange_explicit(&grp->completed, 1, memory_order_acq_rel))
        return false;

    int published = atomic_load_explicit(&grp->result, memory_order_acquire);
    int64_t result =
        published != FUTEX_WAITV_RESULT_UNSET ? published : fallback;
    if (result == FUTEX_WAITV_RESULT_UNSET)
        result = -LINUX_EAGAIN;

    guest_t *g_snap = t->park_guest;
    unsigned pubs[FUTEX_WAITV_MAX];

    for (uint32_t i = 0; i < grp->n; i++) {
        futex_waiter_t *w = &grp->waiters[i];
        futex_bucket_t *b =
            &buckets[atomic_load_explicit(&w->home, memory_order_acquire)];
        pthread_mutex_lock(&b->lock);
        b = futex_waiter_follow(b, w);
        if (!atomic_load_explicit(&w->woken, memory_order_acquire))
            bucket_unlink_locked(b, w);
        atomic_store_explicit(&w->woken, 1, memory_order_release);
        pubs[i] = w->pub_bucket;
        pthread_mutex_unlock(&b->lock);
    }

    for (uint32_t i = 0; i < grp->n; i++) {
        pthread_cond_destroy(&grp->waiters[i].cond);
        if (g_snap)
            shim_globals_futex_waiters_add(g_snap, pubs[i], -1);
    }

    exec_park_waiter_store(t, NULL);
    t->park_guest = NULL;
    t->async_futex_pub_bucket = 0;
    t->async_futex_timed = false;
    free(grp->waiters);
    free(grp);
    if (out)
        *out = result;
    return true;
}

/* Complete or abandon a waitv park. @complete publishes the syscall result
 * through the scheduler; an abandon is a pre-unmount signal return and must
 * leave no park state behind. Caller holds futex_lifetime_mutex: the tagged
 * load, the whole-set unlink and the free share the lock with every reader that
 * loaded the tag, so a retired group cannot be dereferenced by a late flush.
 */
static bool futex_waitv_finish_locked(thread_entry_t *t,
                                      futex_waitv_group_t *grp,
                                      int64_t fallback,
                                      bool complete,
                                      int64_t *out)
{
    int64_t result = fallback;
    bool valid = t && grp && exec_park_waiter_load(t) == futex_waitv_tag(grp);
    uint64_t seq = valid ? grp->park_seq : 0;
    bool ok = valid && futex_waitv_retire_locked(t, grp, fallback, &result);
    if (!ok)
        return false;
    if (!complete) {
        exec_park_result_pending_store(t, false);
        exec_park_reissue_store(t, false);
        exec_park_kind_store(t, PARK_KIND_NONE);
        exec_park_active_store(t, false);
        sched_disarm_wait_deadline(t);
    } else {
        (void) sched_park_try_complete_seq(t, PARK_KIND_FUTEX, seq, result);
    }
    if (out)
        *out = result;
    return true;
}

/* Owner-side entry, used by sys_futex_waitv after it drops the wait-set bucket
 * locks.
 */
static bool futex_waitv_finish(thread_entry_t *t,
                               futex_waitv_group_t *grp,
                               int64_t fallback,
                               bool complete,
                               int64_t *out)
{
    pthread_mutex_lock(&futex_lifetime_mutex);
    bool ok = futex_waitv_finish_locked(t, grp, fallback, complete, out);
    pthread_mutex_unlock(&futex_lifetime_mutex);
    return ok;
}

static void futex_waitv_flush_locked(thread_entry_t *t,
                                     struct futex_waitv_group *grp)
{
    (void) futex_waitv_finish_locked(t, grp, FUTEX_WAITV_RESULT_UNSET, true,
                                     NULL);
}

static bool futex_waitv_cancel_locked(thread_entry_t *t,
                                      struct futex_waitv_group *grp,
                                      int64_t result)
{
    return futex_waitv_finish_locked(t, grp, result, true, NULL);
}



/* The distinct buckets the wait set covers, ascending. The locks below are
 * taken in this order and released in reverse, so both properties of the answer
 * are load-bearing: proved/futexwaitv.h carries them.
 *
 * nr_futexes is bounded by FUTEX_WAITV_MAX before the call, which is what keeps
 * nbuckets below the array length at every insert.
 */
static int waitv_collect_buckets(const linux_futex_waitv_t *elts,
                                 uint32_t nr_futexes,
                                 unsigned bucket_ids[FUTEX_WAITV_MAX])
{
    unsigned nbuckets = 0;

    for (uint32_t i = 0; i < nr_futexes; i++)
        nbuckets = futex_bucket_insert(bucket_ids, nbuckets, FUTEX_WAITV_MAX,
                                       futex_hash(elts[i].uaddr));

    return (int) nbuckets;
}

int64_t sys_futex_waitv(guest_t *g,
                        uint64_t waiters_gva,
                        uint32_t nr_futexes,
                        uint32_t flags,
                        uint64_t timeout_gva,
                        int clockid)
{
    /* Validation order matches Linux do_futex_waitv(). */
    if (flags != 0)
        return -LINUX_EINVAL;
    if (nr_futexes == 0 || nr_futexes > FUTEX_WAITV_MAX || waiters_gva == 0)
        return -LINUX_EINVAL;

    bool has_timeout = (timeout_gva != 0);
    if (has_timeout && clockid != LINUX_CLOCK_REALTIME &&
        clockid != LINUX_CLOCK_MONOTONIC)
        return -LINUX_EINVAL;

    uint64_t mono_deadline = 0;
    if (has_timeout) {
        linux_timespec_t lts;
        if (guest_read_small(g, timeout_gva, &lts, sizeof(lts)) < 0)
            return -LINUX_EFAULT;
        if (!linux_timespec_is_valid(&lts))
            return -LINUX_EINVAL;

        uint64_t deadline_ns =
            (uint64_t) lts.tv_sec * 1000000000ULL + (uint64_t) lts.tv_nsec;
        struct timespec mono;
        if (clock_gettime(CLOCK_MONOTONIC, &mono) != 0)
            return -LINUX_EINVAL;
        uint64_t now =
            (uint64_t) mono.tv_sec * 1000000000ULL + (uint64_t) mono.tv_nsec;
        if (clockid == LINUX_CLOCK_MONOTONIC) {
            mono_deadline = deadline_ns;
        } else {
            struct timespec rt;
            if (clock_gettime(CLOCK_REALTIME, &rt) != 0)
                return -LINUX_EINVAL;
            uint64_t rt_now =
                (uint64_t) rt.tv_sec * 1000000000ULL + (uint64_t) rt.tv_nsec;
            if (deadline_ns <= rt_now)
                return -LINUX_ETIMEDOUT;
            mono_deadline = now + (deadline_ns - rt_now);
        }
        if (mono_deadline <= now)
            return -LINUX_ETIMEDOUT;
    }

    linux_futex_waitv_t elts[FUTEX_WAITV_MAX];
    size_t sz = nr_futexes * sizeof(linux_futex_waitv_t);
    if (guest_read_small(g, waiters_gva, elts, sz) < 0)
        return -LINUX_EFAULT;

    for (uint32_t i = 0; i < nr_futexes; i++) {
        if (elts[i].__reserved != 0 || (elts[i].flags & ~FUTEX2_VALID_FLAGS))
            return -LINUX_EINVAL;
        if ((elts[i].flags & FUTEX2_SIZE_MASK) != FUTEX2_SIZE_U32)
            return -LINUX_EINVAL;
        if (!futex_uaddr_is_aligned(elts[i].uaddr))
            return -LINUX_EINVAL;
    }

    thread_entry_t *self = current_thread;
    if (!self)
        return -LINUX_ESRCH;

    futex_waitv_group_t *grp = calloc(1, sizeof(*grp));
    futex_waiter_t *waiters = calloc(nr_futexes, sizeof(*waiters));
    if (!grp || !waiters) {
        free(grp);
        free(waiters);
        return -LINUX_ENOMEM;
    }
    atomic_init(&grp->result, FUTEX_WAITV_RESULT_UNSET);
    atomic_init(&grp->completed, 0);
    grp->owner = self;
    grp->n = nr_futexes;
    grp->waiters = waiters;

    unsigned bucket_ids[FUTEX_WAITV_MAX];
    int nbuckets = waitv_collect_buckets(elts, nr_futexes, bucket_ids);
    unsigned entry_bucket[FUTEX_WAITV_MAX];
    int enqueued = 0;

    /* Publish one charge per element before the word checks; the shim's wake
     * fast path reads these counts without a bucket lock.
     */
    for (uint32_t i = 0; i < nr_futexes; i++) {
        entry_bucket[i] = futex_hash(elts[i].uaddr);
        shim_globals_futex_waiters_add(g, entry_bucket[i], +1);
    }

    for (int i = 0; i < nbuckets; i++)
        pthread_mutex_lock(&buckets[bucket_ids[i]].lock);

    int64_t result_err = 0;
    for (uint32_t i = 0; i < nr_futexes; i++) {
        uint64_t uaddr = elts[i].uaddr;
        unsigned idx = entry_bucket[i];
        futex_bucket_t *b = &buckets[idx];

        int64_t block = futex_should_block(g, uaddr, (uint32_t) elts[i].val);
        if (block != 0) {
            result_err = block;
            goto unlock_early;
        }

        futex_waiter_t *w = &waiters[i];
        w->uaddr = uaddr;
        w->bitset = FUTEX_BITSET_MATCH_ANY;
        atomic_store_explicit(&w->woken, 0, memory_order_relaxed);
        w->next = b->head;
        w->pub_bucket = idx;
        w->pub_follows = true;
        w->async_owner = self;
        w->waitv_group = grp;
        w->waitv_index = (int) i;
        atomic_store_explicit(&w->home, idx, memory_order_relaxed);
        pthread_cond_init(&w->cond, NULL);
        b->head = w;
        enqueued++;
    }

    exec_park_kind_store(self, PARK_KIND_FUTEX);
    exec_park_result_pending_store(self, true);
    exec_park_reissue_store(self, false);
    self->async_futex_pub_bucket = 0;
    self->async_futex_relative = false;
    self->async_futex_timed = has_timeout;
    self->park_guest = g;
    exec_park_deadline_ns_store(self, 0);
    grp->park_seq = sched_park_seq_next(self);
    exec_park_waiter_store(self, futex_waitv_tag(grp));
    exec_park_active_store(self, true);

    if (has_timeout) {
        sched_arm_wait_deadline(self, mono_deadline);
    } else {
        struct timespec mono;
        if (clock_gettime(CLOCK_MONOTONIC, &mono) == 0) {
            uint64_t now = (uint64_t) mono.tv_sec * 1000000000ULL +
                           (uint64_t) mono.tv_nsec;
            sched_arm_wait_deadline(self, now + FUTEX_POLL_QUANTUM_NS);
        }
    }

    for (int i = nbuckets - 1; i >= 0; i--)
        pthread_mutex_unlock(&buckets[bucket_ids[i]].lock);

    /* A waker or the wait timer can retire the whole set as soon as the bucket
     * locks drop. Read only the pointer and the task's result until the tag
     * proves the group is still ours.
     */
    if (exec_park_waiter_load(self) != futex_waitv_tag(grp)) {
        if (!exec_park_active_load(self)) {
            int64_t r = exec_park_result_load(self);
            exec_park_result_pending_store(self, false);
            return r;
        }
        return SYSCALL_PARKED;
    }
    if (futex_kick_consume() || signal_pending()) {
        bool teardown = proc_exit_group_requested() || thread_stop_requested();
        if (teardown || signal_claim_interruption()) {
            int64_t out = -LINUX_EINTR;
            if (futex_waitv_finish(self, grp, -LINUX_EINTR, false, &out))
                return out;
            if (!exec_park_active_load(self)) {
                int64_t r = exec_park_result_load(self);
                exec_park_result_pending_store(self, false);
                return r;
            }
        }
    }
    return SYSCALL_PARKED;

unlock_early:
    /* All distinct bucket locks are still held, so every waiter this call
     * enqueued is stable and can be unlinked in place.
     */
    for (int i = 0; i < enqueued; i++) {
        futex_waiter_t *w = &waiters[i];
        unsigned home = atomic_load_explicit(&w->home, memory_order_relaxed);
        bucket_unlink_locked(&buckets[home], w);
        pthread_cond_destroy(&w->cond);
    }
    for (int i = nbuckets - 1; i >= 0; i--)
        pthread_mutex_unlock(&buckets[bucket_ids[i]].lock);

    for (uint32_t i = 0; i < nr_futexes; i++)
        shim_globals_futex_waiters_add(
            g, (int) i < enqueued ? waiters[i].pub_bucket : entry_bucket[i],
            -1);
    free(waiters);
    free(grp);
    return result_err;
}

/* Robust futex list walk. */

/* Linux robust_list_head layout:
 *   struct robust_list_head {
 *       struct robust_list *list;       offset 0: pointer to first entry
 *       long futex_offset;              offset 8: offset from entry to futex
 *       word struct robust_list *list_op_pending; offset 16: in-progress lock
 *   };
 *
 * Each entry in the list:
 *   struct robust_list {
 *       struct robust_list *next;       pointer to next (or back to head)
 *   };
 *
 * The futex word is at (entry_addr + futex_offset). The list is circular:
 * list->next... eventually points back to &head->list.
 */

#define ROBUST_LIST_LIMIT 2048 /* safety bound against corrupted lists */

/* Bit 0 of every robust list pointer (the entries, their next fields, and
 * list_op_pending) marks a PI mutex, as fetch_robust_entry reads it on Linux.
 * glibc sets it on each PI robust mutex it enqueues, so an untagged walk sees
 * an odd futex address, skips it as unaligned, and the next locker finds a dead
 * TID and gets ESRCH rather than EOWNERDEAD.
 */
#define ROBUST_ENTRY_PI 1ULL

/* Whether @t still has PI waiters on @uaddr. The robust walk must not wake one
 * itself in that case: futex_pi_owner_exit runs next and has to move the lock
 * record to the highest-priority waiter before the word is published.
 */
static bool futex_pi_state_has_waiters(thread_entry_t *t, uint64_t uaddr)
{
    bool found = false;
    pthread_mutex_lock(&futex_pi_mutex);
    for (futex_pi_lock_t *st = t->futex_pi.locks; st; st = st->next) {
        if (st->uaddr == uaddr && st->waiters) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&futex_pi_mutex);
    return found;
}

/* Wake one waiter on a word the robust walk just marked FUTEX_OWNER_DIED. PI
 * waiters are left to futex_pi_owner_exit.
 */
static void futex_wake_owner_died(guest_t *g, thread_entry_t *t, uint64_t uaddr)
{
    if (futex_pi_state_has_waiters(t, uaddr))
        return;
    futex_bucket_t *b = &buckets[futex_hash(uaddr)];
    pthread_mutex_lock(&b->lock);
    futex_wake_first_locked(b, uaddr);
    pthread_mutex_unlock(&b->lock);
    futex_async_wake_flush();
}

void robust_list_walk(guest_t *g, thread_entry_t *t)
{
    uint64_t head_gva = t->robust_list_head;
    if (head_gva == 0)
        return;

    /* Read robust_list_head: { list, futex_offset, list_op_pending } */
    uint64_t head[3];
    if (guest_read_small(g, head_gva, head, sizeof(head)) < 0)
        return;

    uint64_t list_ptr = head[0] & ~ROBUST_ENTRY_PI; /* first entry */
    int64_t futex_offset = (int64_t) head[1];
    uint64_t pending = head[2] & ~ROBUST_ENTRY_PI; /* list_op_pending */

    /* The head of the list is at &head->list (which is head_gva itself). Walk
     * entries until the walk loops back to the head pointer.
     */
    uint64_t head_entry = head_gva; /* address of head->list field */
    int count = 0;

    while (list_ptr != head_entry && count < ROBUST_LIST_LIMIT) {
        /* The futex word is at list_ptr + futex_offset. Use unsigned add to
         * avoid signed overflow UB; skip entries where the result wraps past
         * the guest address space.
         */
        uint64_t futex_gva;
        if (futex_offset >= 0)
            futex_gva = list_ptr + (uint64_t) futex_offset;
        else
            futex_gva = list_ptr - (uint64_t) (-futex_offset);

        /* Canonical user-VA range check (bits 47:0). Anything with bit 63 set
         * is kernel-VA territory and is never a valid futex address. The
         * previous primary-buffer-only check (futex_gva < ipa_base +
         * guest_size) silently dropped rosetta's high-VA futexes; the
         * subsequent guest_read_small / guest_write_small calls do the actual
         * mapping check via the page-table walker.
         */
        if (futex_gva > 0x0000FFFFFFFFFFFFULL ||
            !futex_uaddr_is_aligned(futex_gva)) {
            /* Out of range or unaligned: skip. Linux's unaligned_p() rejects
             * these; emulating the same avoids partial cross-page writes
             * leaving the futex word corrupted while the wake is suppressed.
             */
            uint64_t next;
            if (guest_read_small(g, list_ptr, &next, sizeof(next)) < 0)
                break;
            list_ptr = next & ~ROBUST_ENTRY_PI;
            count++;
            continue;
        }

        /* Read the futex word */
        uint32_t futex_val;
        if (guest_read_small(g, futex_gva, &futex_val, sizeof(futex_val)) ==
            0) {
            /* Only act if this thread owns the lock */
            uint32_t owner = futex_pi_owner_tid(futex_val);
            if (owner == (uint32_t) thread_tid(t)) {
                /* Set FUTEX_OWNER_DIED and clear TID */
                uint32_t new_val = futex_pi_mark_owner_died(futex_val);
                if (guest_write_small(g, futex_gva, &new_val, sizeof(new_val)) <
                    0)
                    log_debug(
                        "futex: robust list OWNER_DIED write to 0x%llx "
                        "failed; waiters on this lock may hang",
                        (unsigned long long) futex_gva);
                else
                    futex_wake_owner_died(g, t, futex_gva);
            }
        }

        /* Read next pointer */
        uint64_t next;
        if (guest_read_small(g, list_ptr, &next, sizeof(next)) < 0)
            break;
        list_ptr = next & ~ROBUST_ENTRY_PI;
        count++;
    }

    /* Handle pending operation (lock that was being acquired when the thread
     * died)
     */
    if (pending && pending != head_entry) {
        uint64_t futex_gva;
        if (futex_offset >= 0)
            futex_gva = pending + (uint64_t) futex_offset;
        else
            futex_gva = pending - (uint64_t) (-futex_offset);

        /* Canonical user-VA + alignment only; guest_read_small below is the
         * actual reachability test, so rosetta high-VA robust futexes are not
         * silently skipped (was: futex_gva >= ipa_base + guest_size).
         */
        if (futex_gva > 0x0000FFFFFFFFFFFFULL ||
            !futex_uaddr_is_aligned(futex_gva))
            return;
        uint32_t futex_val;
        if (guest_read_small(g, futex_gva, &futex_val, sizeof(futex_val)) ==
            0) {
            uint32_t owner = futex_pi_owner_tid(futex_val);
            if (owner == (uint32_t) thread_tid(t)) {
                uint32_t new_val = futex_pi_mark_owner_died(futex_val);
                if (guest_write_small(g, futex_gva, &new_val, sizeof(new_val)) <
                    0)
                    log_debug(
                        "futex: robust list pending OWNER_DIED write to "
                        "0x%llx failed; waiters on this lock may hang",
                        (unsigned long long) futex_gva);
                else
                    futex_wake_owner_died(g, t, futex_gva);
            }
        }
    }
}
