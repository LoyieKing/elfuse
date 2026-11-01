/*
 * Physical vCPU slot pool
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A slot is one logical CPU and, once started, one owner pthread with one HVF
 * vCPU. The owner is the only thread that creates registers or runs the vCPU;
 * kickers only publish a latch and call hv_vcpus_exit while the slot's handle
 * mutex pins the handle against destruction.
 *
 * Workers are created lazily from scheduler demand. Slot 0 is the caller that
 * adopts the bootstrap vCPU; a single-task VM never creates another worker.
 */

#include "runtime/sched/vcpu_pool.h"

#include "runtime/sched/exec.h"
#include "runtime/sched/guest_ctx.h"
#include "runtime/sched/sched.h"
#include "runtime/sched/fair.h"
#include "runtime/thread.h"
#include "runtime/futex.h"

#include "core/shim-globals.h"
#include "hvutil.h"
#include "syscall/linux-wire.h"
#include "syscall/mem.h"
#include "syscall/proc.h"
#include "syscall/abi.h"

#include "syscall/proc-pidfd.h"
#include "syscall/signal.h"
#include "syscall/wakeup-pipe.h"

typedef struct vcpu_pool_config {
    guest_t *guest;
    bool verbose;
    uint64_t vbar;
    uint64_t mair;
    uint64_t tcr;
    uint64_t ttbr0;
    uint64_t ttbr1;
    uint64_t sctlr;
    uint64_t cpacr;
} vcpu_pool_config_t;

#include "debug/log.h"

#include <mach/mach.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
    SLOT_FREE = 0,
    SLOT_STARTING,
    SLOT_RUNNING,
    SLOT_STOPPED,
};

struct vcpu_slot {
    int index;

    /* Owner pthread and its HVF handle. handle_lock serializes publication,
     * kick-side hv_vcpus_exit, and destruction. Only the owner creates, uses
     * for register access, or destroys @vcpu; kickers never dereference it
     * outside the lock.
     */
    pthread_t owner;
    bool owner_is_caller; /* slot 0: the bootstrap/fork-child pthread */
    pthread_mutex_t handle_lock;
    hv_vcpu_t vcpu;
    hv_vcpu_exit_t *vexit;
    bool vcpu_live;

    /* pool_cfg generation this owner programmed into @vcpu. Only the owner
     * writes it: a mismatch with pool_cfg_gen means execve published a new
     * TTBR0/TCR/TTBR1 and this vCPU owes the update before its next guest
     * entry.
     */
    uint64_t applied_cfg_gen;

    /* Worker lifecycle, protected by pool_lock (except owner/current). */
    bool worker_joinable; /* pthread_create succeeded; stop must join it */
    pthread_t worker;
    int state;
    bool in_use;

    /* Set by any kicker before hv_vcpus_exit; consumed only by the owner's
     * tick. Never cleared by arming or disarming a slice.
     */
    _Atomic bool kick_pending;

    /* Published by the owner while run_one_task owns this slot. A guest barrier
     * waits only for slots that can currently execute guest code; a parked task
     * re-runs the SYNC_CORE trampoline before its next entry.
     */
    _Atomic bool in_exec;

    /* Host-fence and guest SYNC_CORE generations this owner has executed. The
     * guest generation is published only by the shim trampoline after IC
     * IALLU/DSB/ISB, never by a host-only ISB.
     */
    _Atomic uint64_t barrier_fence_ack;
    _Atomic uint64_t barrier_sync_ack;

    /* SYNC_CORE generation currently being executed through the trampoline; HVC
     * #14 acknowledges exactly this value.
     */
    _Atomic uint64_t barrier_inflight;
    guest_thread_ctx_t
        barrier_context; /* Owner-only interrupted EL0/EL1 state. */

    /* Owner-only mount state. */
    struct thread_entry *_Atomic current;
    bool slice_armed;


    /* Owner CPU-time baseline for the live-execution query, and the last
     * settled sample reported to the scheduler.
     */
    _Atomic uint64_t cpu_account_base_ns;
    _Atomic bool accounting_guest;
    _Atomic uint64_t accounting_seq;
    /* Absolute CLOCK_MONOTONIC slice deadline; protected by slice_lock. */
    uint64_t slice_deadline_ns;

    /* Cached Mach thread port for CPU-time sampling (owner only). */
    _Atomic mach_port_t cpu_port;
};



/* Set by the owner tick when it takes the task off involuntarily (slice,
 * affinity migration, scheduler request). Consumed by publish_leave() as
 * SCHED_PUT_PREEMPTED so RT tasks go back at their priority head.
 */
static _Thread_local bool leave_preempted;

/* The worker pthread that is currently mounting a task. Only the owner reads or
 * writes it; accessors use it instead of task-carried HVF fields.
 */
static _Thread_local struct vcpu_slot *owner_slot;

static struct vcpu_slot *slots;
static int slot_count;
static int slots_in_use;
static pthread_mutex_t pool_lock = PTHREAD_MUTEX_INITIALIZER;
static bool pool_ready;
static bool pool_running;
static bool pool_stopping;
static guest_t *pool_guest;
static bool pool_verbose;
static bool pool_cfg_valid;
static vcpu_pool_config_t pool_cfg;

/* Bumped by execve whenever the image's translation regime changes. Writers
 * hold pool_lock; the mount fast path takes one acquire load.
 */
static _Atomic uint64_t pool_cfg_gen;
static bool slot0_is_caller;

/* Workers idle through sched_worker_wait(): Core owns the block/ready protocol,
 * including freeze and shutdown.
 */

static void slot_kick(struct vcpu_slot *slot);

/* Per-VM guest barriers
 *
 * A request publishes a generation and kicks every owner that can execute guest
 * code. Each owner executes the requested barrier at its next safe point and
 * acknowledges; the requester returns only after every such owner acknowledged
 * or stopped executing guest code. SYNC_CORE is acknowledged only by the shim
 * trampoline, after the guest has executed IC IALLU/DSB/ISB on that vCPU; a
 * host-only ISB is not sufficient for an I-cache invalidation that is local to
 * each PE.
 */
#define POOL_BARRIER_SYNC_CORE (1ULL << 63)
#define POOL_BARRIER_GEN_MASK (~POOL_BARRIER_SYNC_CORE)

static pthread_mutex_t barrier_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t barrier_cond = PTHREAD_COND_INITIALIZER;
static _Atomic uint64_t barrier_request;
static uint64_t barrier_seq; /* protected by barrier_lock */

/* EL1h with D/A/I/F masked; the owner restores the saved context at HVC #14. */
#define POOL_CPSR_EL1H_DAIF 0x3c5ULL

static void barrier_signal(void)
{
    pthread_mutex_lock(&barrier_lock);
    pthread_cond_broadcast(&barrier_cond);
    pthread_mutex_unlock(&barrier_lock);
}

/* Guest VA of the sync-core trampoline: vector slot 0x600 (the AArch64-only
 * guest never vectors through the AArch32 synchronous slot) inside the 2 KiB
 * vector table the shim is entered through.
 */
static uint64_t slot_sync_core_entry(hv_vcpu_t vcpu)
{
    return vcpu_get_sysreg(vcpu, HV_SYS_REG_VBAR_EL1) + 0x600;
}

/* Redirect the owner's paused vCPU into the trampoline. Saving the complete
 * context preserves live ELR/SPSR even when execution was interrupted in EL1.
 */
static bool slot_start_sync_core(struct vcpu_slot *slot, guest_t *g)
{
    /* Owner-thread code: the slot handle is this thread's private state; the
     * public bool-out accessor is for callers outside a mount.
     */
    hv_vcpu_t vcpu = slot->vcpu;
    if (!slot->vcpu_live)
        return false;

    uint64_t gen =
        atomic_load_explicit(&barrier_request, memory_order_acquire) &
        POOL_BARRIER_GEN_MASK;
    if (gen == 0)
        return false;

    guest_ctx_save(vcpu, &slot->barrier_context);
    hv_vcpu_set_reg(vcpu, HV_REG_PC, slot_sync_core_entry(vcpu));
    hv_vcpu_set_reg(vcpu, HV_REG_CPSR, POOL_CPSR_EL1H_DAIF);
    atomic_store_explicit(&slot->barrier_inflight, gen, memory_order_release);
    return true;
}

/* Execute the host half of a plain expedited barrier on this owner. A host ISB
 * serializes this core around the fence; SYNC_CORE takes the guest trampoline
 * instead.
 */
static void slot_host_barrier_ack(struct vcpu_slot *slot, uint64_t gen)
{
    atomic_thread_fence(memory_order_seq_cst);
    __asm__ __volatile__("isb" ::: "memory");
    atomic_store_explicit(&slot->barrier_fence_ack, gen, memory_order_release);
    barrier_signal();
}

/* Run whatever barrier the owner owes before it may execute guest code.
 * Returns true when the caller must not enter the guest in this iteration: the
 * vCPU now points at the sync-core trampoline instead.
 */
static bool slot_barrier_before_guest(struct vcpu_slot *slot, guest_t *g)
{
    if (atomic_load_explicit(&slot->barrier_inflight, memory_order_acquire))
        return true;
    uint64_t req = atomic_load_explicit(&barrier_request, memory_order_acquire);
    if (req == 0)
        return false;
    uint64_t gen = req & POOL_BARRIER_GEN_MASK;
    if (gen == 0)
        return false;

    if (req & POOL_BARRIER_SYNC_CORE) {
        uint64_t ack =
            atomic_load_explicit(&slot->barrier_sync_ack, memory_order_acquire);
        if (ack >= gen)
            return false;
        return slot_start_sync_core(slot, g);
    }

    uint64_t ack =
        atomic_load_explicit(&slot->barrier_fence_ack, memory_order_acquire);
    if (ack < gen)
        slot_host_barrier_ack(slot, gen);
    return false;
}

/* Owner leave path: a plain barrier must still be executed for a generation
 * that arrived while this task was mounted, even if the task now parks.
 * SYNC_CORE is deliberately not acknowledged here: the lag stays visible and
 * the next mount runs the trampoline before its first guest instruction.
 */
static void slot_barrier_leave(struct vcpu_slot *slot)
{
    uint64_t req = atomic_load_explicit(&barrier_request, memory_order_acquire);
    if (req == 0 || (req & POOL_BARRIER_SYNC_CORE))
        return;
    uint64_t gen = req & POOL_BARRIER_GEN_MASK;
    if (gen == 0)
        return;
    uint64_t ack =
        atomic_load_explicit(&slot->barrier_fence_ack, memory_order_acquire);
    if (ack < gen)
        slot_host_barrier_ack(slot, gen);
}

bool vcpu_pool_barrier_ack_current(void)
{
    struct vcpu_slot *slot = owner_slot;
    if (!slot)
        return false;
    uint64_t gen =
        atomic_load_explicit(&slot->barrier_inflight, memory_order_acquire);
    if (gen == 0)
        return false;

    /* HVC changes ELR/SPSR even when the interrupted PC was already in EL1.
     * Restore the entire saved context instead of ERET through that live tail.
     */
    guest_ctx_restore(slot->vcpu, &slot->barrier_context, NULL, 0);
    atomic_store_explicit(&slot->barrier_sync_ack, gen, memory_order_release);
    atomic_store_explicit(&slot->barrier_fence_ack, gen, memory_order_release);
    atomic_store_explicit(&slot->barrier_inflight, 0, memory_order_release);
    barrier_signal();
    return true;
}

static bool barrier_slot_outstanding(const struct vcpu_slot *slot,
                                     uint64_t req,
                                     const struct vcpu_slot *self)
{
    if (slot == self)
        return false; /* the caller's own CPU syncs before its next entry */
    if (!atomic_load_explicit(&slot->in_exec, memory_order_acquire))
        return false;
    uint64_t gen = req & POOL_BARRIER_GEN_MASK;
    uint64_t ack = (req & POOL_BARRIER_SYNC_CORE)
                       ? atomic_load_explicit(&slot->barrier_sync_ack,
                                              memory_order_acquire)
                       : atomic_load_explicit(&slot->barrier_fence_ack,
                                              memory_order_acquire);
    return ack < gen;
}

int vcpu_pool_membarrier(bool sync_core)
{
    uint64_t req;
    struct vcpu_slot *self = owner_slot;

    pthread_mutex_lock(&pool_lock);
    bool running = pool_running && slots && slot_count > 0;
    pthread_mutex_unlock(&pool_lock);
    if (!running)
        return 0;

    pthread_mutex_lock(&barrier_lock);
    barrier_seq++;
    req = barrier_seq | (sync_core ? POOL_BARRIER_SYNC_CORE : 0);
    atomic_store_explicit(&barrier_request, req, memory_order_release);
    pthread_mutex_unlock(&barrier_lock);

    for (int i = 0; i < slot_count; i++) {
        struct vcpu_slot *slot = &slots[i];
        if (slot == self)
            continue;
        if (atomic_load_explicit(&slot->in_exec, memory_order_acquire))
            slot_kick(slot);
    }

    pthread_mutex_lock(&barrier_lock);
    while (!sched_shutdown_requested() && !proc_exit_group_requested()) {
        bool outstanding = false;
        for (int i = 0; i < slot_count; i++) {
            if (barrier_slot_outstanding(&slots[i], req, self)) {
                outstanding = true;
                slot_kick(&slots[i]);
            }
        }
        if (!outstanding)
            break;
        struct timespec rel = {.tv_sec = 0, .tv_nsec = 5000000L};
        (void) pthread_cond_timedwait_relative_np(&barrier_cond, &barrier_lock,
                                                  &rel);
    }
    pthread_mutex_unlock(&barrier_lock);

    /* Pairs with the ack stores: the caller's operations before the request
     * happen-before every acknowledged owner's following guest execution.
     */
    atomic_thread_fence(memory_order_seq_cst);
    return 0;
}

/* Fair timeslice cut-off timer. Separate from the SIGALRM watchdog
 * (proc_preempt_init): ITIMER_REAL is process-wide and already claimed.
 */
static pthread_t slice_thread;
static bool slice_thread_started;
static bool slice_shutdown;
static pthread_mutex_t slice_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t slice_cond = PTHREAD_COND_INITIALIZER;

static uint64_t slice_mono_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

/* Owner CPU-time sampling */

static void slot_cpu_port_init(struct vcpu_slot *slot)
{
    if (atomic_load_explicit(&slot->cpu_port, memory_order_relaxed) ==
        MACH_PORT_NULL)
        atomic_store_explicit(&slot->cpu_port, mach_thread_self(),
                              memory_order_release);
}

static uint64_t slot_cpu_ns(struct vcpu_slot *slot)
{
    /* The public owner clock avoids a Mach message on every phase boundary.
     * Remote readers still need the cached port; both clocks sum user/system
     * CPU time, excluding time descheduled or blocked on the host.
     */
    if (slot == owner_slot)
        return clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID);
    mach_port_t port =
        atomic_load_explicit(&slot->cpu_port, memory_order_acquire);
    if (port == MACH_PORT_NULL)
        return 0;
    thread_basic_info_data_t info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    kern_return_t kr =
        thread_info(port, THREAD_BASIC_INFO, (thread_info_t) &info, &count);
    if (kr != KERN_SUCCESS)
        return 0;
    return (uint64_t) info.user_time.seconds * 1000000000ULL +
           (uint64_t) info.user_time.microseconds * 1000ULL +
           (uint64_t) info.system_time.seconds * 1000000000ULL +
           (uint64_t) info.system_time.microseconds * 1000ULL;
}

/* Mach permits CPU-time sampling of another worker without HVF register access.
 */
static uint64_t pool_live_phase_ns(const struct thread_entry *t, bool guest)
{
    int cpu = sched_thread_cpu(t);
    if (!t || !slots || cpu < 0 || cpu >= slot_count)
        return 0;
    struct vcpu_slot *slot = &slots[cpu];
    uint64_t seq =
        atomic_load_explicit(&slot->accounting_seq, memory_order_acquire);
    if ((seq & 1) ||
        atomic_load_explicit(&slot->current, memory_order_acquire) != t ||
        atomic_load_explicit(&slot->accounting_guest, memory_order_acquire) !=
            guest)
        return 0;
    uint64_t base =
        atomic_load_explicit(&slot->cpu_account_base_ns, memory_order_acquire);
    uint64_t now = slot_cpu_ns(slot);
    if (atomic_load_explicit(&slot->accounting_seq, memory_order_acquire) !=
            seq ||
        atomic_load_explicit(&slot->current, memory_order_acquire) != t)
        return 0;
    return now > base ? now - base : 0;
}

static uint64_t pool_live_exec_ns(const struct thread_entry *t)
{
    return pool_live_phase_ns(t, true);
}

static uint64_t pool_live_service_ns(const struct thread_entry *t)
{
    return pool_live_phase_ns(t, false);
}

void vcpu_pool_account_phase(bool entering_guest)
{
    if (!owner_slot || !current_thread)
        return;
    atomic_fetch_add_explicit(&owner_slot->accounting_seq, 1,
                              memory_order_acq_rel);
    uint64_t now = slot_cpu_ns(owner_slot);
    uint64_t base = atomic_load_explicit(&owner_slot->cpu_account_base_ns,
                                         memory_order_acquire);
    if (now > base) {
        if (atomic_load_explicit(&owner_slot->accounting_guest,
                                 memory_order_relaxed))
            sched_account_cpu_ns(current_thread, now - base);
        else
            sched_account_service_ns(current_thread, now - base);
    }
    atomic_store_explicit(&owner_slot->cpu_account_base_ns, now,
                          memory_order_release);
    atomic_store_explicit(&owner_slot->accounting_guest, entering_guest,
                          memory_order_release);
    atomic_fetch_add_explicit(&owner_slot->accounting_seq, 1,
                              memory_order_release);
}

/* SCHED_DEADLINE overrun: Linux delivers SIGXCPU to the task. Called by the
 * scheduler without its lock held; thread-directed queueing is lifetime-safe.
 */
static void pool_dl_overrun(struct thread_entry *t)
{
    if (t)
        (void) signal_queue_thread(thread_tid(t), LINUX_SIGXCPU);
}

static const sched_host_ops_t pool_host_ops = {
    .wake_cpu = vcpu_pool_wake_cpu,
    .kick_cpu = vcpu_pool_kick_cpu,
    .kick_all = vcpu_pool_kick_all_mounted,
    .wake_timer = vcpu_pool_wake_timer,
    .dl_overrun = pool_dl_overrun,
    .live_exec_ns = pool_live_exec_ns,
    .live_service_ns = pool_live_service_ns,
};

/* Kick / handle publication */

static struct vcpu_slot *slot_of(int cpu)
{
    if (!slots || cpu < 0 || cpu >= slot_count)
        return NULL;
    return &slots[cpu];
}

static void slot_kick(struct vcpu_slot *slot)
{
    if (!slot)
        return;

    /* Publish the reason before the HVF call: the owner may already be between
     * its tick and hv_vcpu_run, and the canceled exit it takes must still be
     * accounted for.
     */
    atomic_store_explicit(&slot->kick_pending, true, memory_order_release);
    pthread_mutex_lock(&slot->handle_lock);
    if (slot->vcpu_live)
        hv_vcpus_exit(&slot->vcpu, 1);
    pthread_mutex_unlock(&slot->handle_lock);
}

void vcpu_pool_kick_cpu(int cpu)
{
    slot_kick(slot_of(cpu));
}


void vcpu_pool_kick_all_mounted(void)
{
    if (!slots || slot_count <= 0)
        return;
    for (int i = 0; i < slot_count; i++) {
        struct vcpu_slot *slot = &slots[i];
        if (!slot->vcpu_live)
            continue;
        pthread_mutex_lock(&slot->handle_lock);
        if (slot->vcpu_live)
            hv_vcpus_exit(&slot->vcpu, 1);
        pthread_mutex_unlock(&slot->handle_lock);
    }
}

/* Slice / wait timer */

static void slot_arm_slice(struct vcpu_slot *slot)
{
    if (!slot)
        return;
    uint64_t slice = sched_timeslice_ns(current_thread);
    if (slice == 0)
        slice = SCHED_DEFAULT_FAIR_PERIOD_NS;
    uint64_t now = slice_mono_ns();
    pthread_mutex_lock(&slice_lock);
    slot->slice_deadline_ns = now + slice;
    slot->slice_armed = true;
    pthread_cond_signal(&slice_cond);
    pthread_mutex_unlock(&slice_lock);
}

static void slot_disarm_slice(struct vcpu_slot *slot)
{
    if (!slot)
        return;
    pthread_mutex_lock(&slice_lock);
    slot->slice_deadline_ns = 0;
    slot->slice_armed = false;
    pthread_cond_signal(&slice_cond);
    pthread_mutex_unlock(&slice_lock);
}

void vcpu_pool_wake_timer(void)
{
    pthread_mutex_lock(&slice_lock);
    pthread_cond_signal(&slice_cond);
    pthread_mutex_unlock(&slice_lock);
}

void vcpu_pool_kick_wait_timer(void)
{
    vcpu_pool_wake_timer();
}

void vcpu_pool_refresh_mmu_template(uint64_t ttbr0,
                                    uint64_t ttbr1,
                                    uint64_t tcr)
{
    pthread_mutex_lock(&pool_lock);
    if (!pool_ready || !pool_cfg_valid || !pool_running) {
        pthread_mutex_unlock(&pool_lock);
        return;
    }
    pool_cfg.ttbr0 = ttbr0;
    pool_cfg.ttbr1 = ttbr1;
    pool_cfg.tcr = tcr;
    uint64_t gen =
        atomic_load_explicit(&pool_cfg_gen, memory_order_relaxed) + 1;
    atomic_store_explicit(&pool_cfg_gen, gen, memory_order_release);
    pthread_mutex_unlock(&pool_lock);

    log_debug(
        "vcpu_pool: translation regime gen %llu ttbr0=0x%llx "
        "ttbr1=0x%llx tcr=0x%llx",
        (unsigned long long) gen, (unsigned long long) ttbr0,
        (unsigned long long) ttbr1, (unsigned long long) tcr);
}

static void slice_fire_slot(struct vcpu_slot *slot)
{
    /* Clear the deadline first so this slice does not fire twice. The kick
     * latch is a separate flag and is deliberately not touched here.
     */
    slot->slice_deadline_ns = 0;
    slot->slice_armed = false;
    bool has_ready = sched_cpu_has_ready(slot->index);

    /* Always latch a tick: solo runners still need CPU-clock / itimer
     * accounting, and the owner decides whether to switch.
     */
    if (!has_ready) {
        /* Solo runner: keep the metronome alive so a later enqueue is seen
         * within one more period instead of waiting for a wake that only a
         * started worker would receive.
         */
        uint64_t slice = SCHED_DEFAULT_FAIR_PERIOD_NS;
        thread_entry_t *current =
            atomic_load_explicit(&slot->current, memory_order_acquire);
        if (current)
            slice = sched_timeslice_ns(current);
        if (slice == 0)
            slice = SCHED_DEFAULT_FAIR_PERIOD_NS;
        slot->slice_deadline_ns = slice_mono_ns() + slice;
        slot->slice_armed = true;
    }
    slot_kick(slot);
}


static void *slice_timer_main(void *arg)
{
    (void) arg;
    pthread_mutex_lock(&slice_lock);
    for (;;) {
        if (slice_shutdown) {
            pthread_mutex_unlock(&slice_lock);
            return NULL;
        }

        uint64_t now = slice_mono_ns();
        uint64_t nearest = UINT64_MAX;
        for (int i = 0; i < slot_count; i++) {
            uint64_t d = slots[i].slice_deadline_ns;
            if (d != 0 && d < nearest)
                nearest = d;
        }
        pthread_mutex_unlock(&slice_lock);

        /* Fair/RT/DL timers belong to the scheduler. Its run_timers path
         * requests kicks for CPUs that must be rescheduled.
         */
        uint64_t sched_d = sched_next_timer_ns();
        if (sched_d != 0 && sched_d < nearest)
            nearest = sched_d;

        /* Async park (futex/sleep/IO) deadlines. */
        uint64_t park_d = sched_next_wait_deadline_ns();
        if (park_d != 0 && park_d < nearest)
            nearest = park_d;

        /* Wall timers (ITIMER_REAL / POSIX): wake parks near expiry. */
        uint64_t timer_d = signal_next_wall_timer_deadline_ns();
        if (timer_d != 0 && timer_d < nearest)
            nearest = timer_d;
        pthread_mutex_lock(&slice_lock);
        if (slice_shutdown)
            continue;

        if (nearest == UINT64_MAX) {
            pthread_cond_wait(&slice_cond, &slice_lock);
            continue;
        }

        if (now < nearest) {
            uint64_t wait_ns = nearest - now;
            struct timespec rel = {
                .tv_sec = (time_t) (wait_ns / 1000000000ULL),
                .tv_nsec = (long) (wait_ns % 1000000000ULL),
            };
            (void) pthread_cond_timedwait_relative_np(&slice_cond, &slice_lock,
                                                      &rel);
            continue;
        }

        now = slice_mono_ns();
        for (int i = 0; i < slot_count; i++) {
            uint64_t d = slots[i].slice_deadline_ns;
            if (d != 0 && d <= now)
                slice_fire_slot(&slots[i]);
        }

        /* Timers must not run under slice_lock: they take scheduler/futex locks
         * and call the host kick ops. Drop, fire, re-acquire.
         */
        pthread_mutex_unlock(&slice_lock);
        (void) sched_run_timers(now);
        sched_fire_expired_waits(now);

        /* wait4/waitid park on their own driver, which the scheduler does not
         * dispatch: fire their poll deadlines here. A completed park enters the
         * scheduler READY queue, which wakes an idle sched_worker_wait().
         */
        proc_wait_fire_expired(now);
        signal_deliver_expired_wall_timers_quiet();
        pthread_mutex_lock(&slice_lock);
    }
}

static int slice_timer_start(void)
{
    pthread_mutex_lock(&slice_lock);
    if (slice_thread_started) {
        slice_shutdown = false;
        pthread_mutex_unlock(&slice_lock);
        return 0;
    }
    slice_shutdown = false;
    int err = pthread_create(&slice_thread, NULL, slice_timer_main, NULL);
    if (err != 0) {
        pthread_mutex_unlock(&slice_lock);
        log_error("vcpu_pool: slice timer pthread_create failed: %s",
                  strerror(err));
        return -1;
    }
    slice_thread_started = true;
    pthread_mutex_unlock(&slice_lock);
    return 0;
}

static void slice_timer_stop(void)
{
    pthread_mutex_lock(&slice_lock);
    if (!slice_thread_started) {
        pthread_mutex_unlock(&slice_lock);
        return;
    }
    slice_shutdown = true;
    if (slots) {
        for (int i = 0; i < slot_count; i++)
            slots[i].slice_deadline_ns = 0;
    }
    pthread_cond_broadcast(&slice_cond);
    pthread_mutex_unlock(&slice_lock);
    (void) pthread_join(slice_thread, NULL);
    pthread_mutex_lock(&slice_lock);
    slice_thread_started = false;
    slice_shutdown = false;
    pthread_mutex_unlock(&slice_lock);
}

/* Worker tick */

/* Called by the run loop before each guest entry on the owning worker. It only
 * reports scheduling pressure; the outer loop owns every switch.
 */
static int pool_run_tick(guest_t *g, void *opaque)
{
    struct vcpu_slot *slot = (struct vcpu_slot *) opaque;
    if (!slot)
        return VCPU_TICK_CONTINUE;

    /* A published guest barrier runs before any guest instruction of this
     * iteration. SYNC_CORE redirects the vCPU through the shim trampoline,
     * which executes the guest-side IC/DSB/ISB and acknowledges at HVC #14;
     * this iteration must enter the vCPU so that trampoline runs.
     */
    if (slot_barrier_before_guest(slot, g))
        return VCPU_TICK_CONTINUE;

    /* de_thread: a non-leader must leave before the next guest entry even when
     * no kick is pending.
     */
    if (thread_exec_de_thread_active() && current_thread &&
        !thread_current_is_leader())
        return VCPU_TICK_EXIT_ZERO;

    if (!atomic_exchange_explicit(&slot->kick_pending, false,
                                  memory_order_acq_rel))
        return VCPU_TICK_CONTINUE;

    /* A slice/kick is also the only host-side clock for CPU timers while a
     * compute-bound guest never leaves EL0.
     */
    signal_check_timer();

    /* Group stop / SIGCONT-driven stop / traced stop requested from another
     * thread: this is the execution safe point. Consume it once, arm a STOP
     * park, and let the outer loop save the context and publish BLOCKED.
     */
    if (current_thread && !exec_park_active_load(current_thread)) {
        unsigned reasons = 0;
        if (sched_take_stop_request(current_thread, &reasons)) {
            exec_park_kind_store(current_thread, PARK_KIND_STOP);
            exec_park_result_pending_store(current_thread, false);
            exec_park_reissue_store(current_thread, false);
            exec_park_deadline_ns_store(current_thread, 0);
            current_thread->exec_resume = EXEC_RESUME_PLAIN;
            exec_park_active_store(current_thread, true);
            return VCPU_TICK_PARK;
        }
    }

    /* Affinity/fair/RR/DL decisions and their kicks are scheduler-owned; the
     * tick only decides that this mount must end at a safe point.
     */
    if (sched_resched_requested()) {
        leave_preempted = true;
        return VCPU_TICK_RESCHED;
    }

    /* No other runnable task: stay mounted and keep the slice metronome. */
    slot_arm_slice(slot);
    return VCPU_TICK_CONTINUE;
}
/* Task exit cleanup */

/* A never-run task drained at teardown owns no mount, so only the task's
 * process-visible exit bookkeeping remains. thread.c owns that policy.
 */
static void drain_one_ready(thread_entry_t *t, void *arg)
{
    if (!t)
        return;
    log_debug("vcpu_pool: draining never-run tid=%lld",
              (long long) thread_tid(t));
    thread_exit_task(t, (guest_t *) arg, 0);
}

static void drain_stopped_task(thread_entry_t *t, void *arg)
{
    if (sched_task_claim_stopped(t))
        thread_exit_task(t, (guest_t *) arg, 0);
}

/* Task exit cleanup is thread.c's policy (robust list, CLEARTID, pidfd,
 * thread-group state, shutdown). The execution layer only unmounts and
 * publishes DEAD.
 */

/* Mount / execution loop */

/* The address-space half of the per-vCPU template. VBAR/MAIR/CPACR/SCTLR/
 * CNTKCTL are creation constants, so a vCPU that already ran only ever owes
 * these three after execve. Rewriting SCTLR on a vCPU that already ran is the
 * case the cold-boot note warns about, so the refresh keeps to the trio.
 */
static int slot_program_addr_space(struct vcpu_slot *slot,
                                   const vcpu_pool_config_t *cfg)
{
    hv_return_t r =
        hv_vcpu_set_sys_reg(slot->vcpu, HV_SYS_REG_TTBR0_EL1, cfg->ttbr0);
    if (r == HV_SUCCESS)
        r = hv_vcpu_set_sys_reg(slot->vcpu, HV_SYS_REG_TCR_EL1, cfg->tcr);
    if (r == HV_SUCCESS)
        r = hv_vcpu_set_sys_reg(slot->vcpu, HV_SYS_REG_TTBR1_EL1, cfg->ttbr1);
    if (r != HV_SUCCESS) {
        log_error("vcpu_pool slot %d: address-space update failed: %d",
                  slot->index, (int) r);
        return -1;
    }
    return 0;
}

/* Pick up an address space execve published after this worker was created. A
 * worker started after the execve already reads the new template in
 * configure_slot_vcpu; this is for slots that already had a vCPU. The one
 * acquire load keeps the common mount free of pool_lock.
 */
static void slot_refresh_addr_space(struct vcpu_slot *slot)
{
    uint64_t gen = atomic_load_explicit(&pool_cfg_gen, memory_order_acquire);
    if (gen == slot->applied_cfg_gen)
        return;

    vcpu_pool_config_t cfg;
    bool valid;
    pthread_mutex_lock(&pool_lock);
    cfg = pool_cfg;
    valid = pool_cfg_valid;
    gen = atomic_load_explicit(&pool_cfg_gen, memory_order_relaxed);
    pthread_mutex_unlock(&pool_lock);

    if (!valid || gen == slot->applied_cfg_gen)
        return;
    if (slot_program_addr_space(slot, &cfg) == 0)
        slot->applied_cfg_gen = gen;
}

/* Run one task on @slot until it must leave the CPU. The complete return tail
 * has already run (or the task is explicitly parked); save the architectural
 * state, report actual CPU time, and clear the mount. The caller publishes the
 * next scheduler state.
 */
static proc_leave_t run_one_task(struct vcpu_slot *slot,
                                 thread_entry_t *t,
                                 guest_t *g,
                                 bool verbose,
                                 int timeout_sec,
                                 int *exit_code,
                                 int *wait_status)
{
    hv_vcpu_t vcpu = slot->vcpu;
    owner_slot = slot;

    atomic_store_explicit(&slot->current, t, memory_order_release);
    current_thread = t;
    atomic_store_explicit(&slot->in_exec, true, memory_order_release);

    if (!t->guest_ctx.valid) {
        log_error("vcpu_pool: tid=%lld has no guest_ctx",
                  (long long) thread_tid(t));
        atomic_store_explicit(&slot->in_exec, false, memory_order_release);
        barrier_signal();
        owner_slot = NULL;
        atomic_store_explicit(&slot->current, NULL, memory_order_release);
        current_thread = NULL;
        return PROC_LEAVE_EXIT;
    }

    slot_refresh_addr_space(slot);
    guest_ctx_restore(vcpu, &t->guest_ctx, g, thread_tid(t));

    /* Match rseq/getcpu to this physical slot. */
    if (t->rseq_gva != 0)
        rseq_set_cpu_ids(g, t, (uint32_t) slot->index, 0);

    /* A tracer may have rewritten registers while the task was stopped, and a
     * CONT may have queued an injection signal. Apply on the owner before any
     * resume work reads the register set.
     */
    thread_ptrace_apply_resume(t, vcpu);

    uint64_t cpu_start = slot_cpu_ns(slot);
    atomic_store_explicit(&slot->cpu_account_base_ns, cpu_start,
                          memory_order_release);
    atomic_store_explicit(&slot->accounting_guest, false, memory_order_release);
    proc_leave_t leave;

    /* A completed park (including a wake that raced the handler's return), a
     * parked stop, or a deferred syscall tail all need the resume path.
     * park_result_pending must be part of the test: a waker can complete a park
     * before the handler returns SYSCALL_PARKED, leaving park_active clear with
     * the result still owed.
     */
    if (t->ptrace_interrupt_pending || exec_park_active_load(t) ||
        exec_park_reissue_load(t) || exec_park_result_pending_load(t) ||
        t->exec_resume != EXEC_RESUME_PLAIN) {
        t->watchdog_progress_ns = sched_now_ns();
        leave = proc_resume_task(vcpu, g, verbose, exit_code);
    } else {
        leave = PROC_LEAVE_CONTINUE;
    }

    /* The resume path runs host work (SVC re-dispatch, sleep timespec fixup,
     * signal-frame writes). Its CPU time is syscall service, never guest
     * execution, and a block inside it accrues no CPU time at all.
     */
    vcpu_pool_account_phase(false);

    if (leave == PROC_LEAVE_CONTINUE && current_thread) {
        /* A stop requested after the last safe point but before this guest
         * entry must still park; the tick cannot see it before the first
         * hv_vcpu_run of the mount.
         */
        unsigned stop_reasons = 0;
        if (!exec_park_active_load(current_thread) &&
            sched_take_stop_request(current_thread, &stop_reasons)) {
            exec_park_kind_store(current_thread, PARK_KIND_STOP);
            exec_park_result_pending_store(current_thread, false);
            exec_park_reissue_store(current_thread, false);
            exec_park_deadline_ns_store(current_thread, 0);
            current_thread->exec_resume = EXEC_RESUME_PLAIN;
            exec_park_active_store(current_thread, true);
            leave = PROC_LEAVE_PARK;
            *wait_status = signal_linux_wait_status_for_exit(*exit_code);
        }
    }

    if (leave == PROC_LEAVE_CONTINUE) {
        if (t->ptrace_interrupt_pending)
            hv_vcpus_exit(&vcpu, 1);

        thread_fork_barrier_check();

        log_debug("vcpu_pool: slot %d running tid=%lld", slot->index,
                  (long long) thread_tid(t));

        slot_arm_slice(slot);
        vcpu_run_hooks_t hooks = {
            .tick = pool_run_tick,
            .opaque = slot,
        };
        leave = proc_run_task(vcpu, slot->vexit, g, verbose, timeout_sec,
                              &hooks, exit_code, wait_status);
        slot_disarm_slice(slot);
    } else if (leave != PROC_LEAVE_PARK) {
        *wait_status = signal_linux_wait_status_for_exit(*exit_code);
    }

    if (leave != PROC_LEAVE_EXIT)
        guest_ctx_save(vcpu, &t->guest_ctx);

    vcpu_pool_account_phase(false);

    /* A plain barrier that arrived while mounted still owes this owner a fence.
     * SYNC_CORE does not ack here: the lag stays and the next mount runs the
     * guest trampoline before its first instruction.
     */
    slot_barrier_leave(slot);
    atomic_store_explicit(&slot->in_exec, false, memory_order_release);
    barrier_signal();

    owner_slot = NULL;
    atomic_store_explicit(&slot->current, NULL, memory_order_release);
    current_thread = NULL;
    return leave;
}

/* Publish the scheduler state of a task that just left the CPU. Called after
 * the mount and architecture are settled, never before.
 */
static void publish_leave(thread_entry_t *t, proc_leave_t leave)
{
    bool preempted = leave_preempted;
    leave_preempted = false;
    pthread_mutex_t *lock = thread_get_lock();
    pthread_mutex_lock(lock);

    switch (leave) {
    case PROC_LEAVE_PARK:
        sched_put_current(t, SCHED_PUT_BLOCKED);
        break;
    case PROC_LEAVE_EXIT:
        sched_put_current(t, SCHED_PUT_DEAD);
        break;
    case PROC_LEAVE_RESCHED:
        sched_put_current(t, preempted ? SCHED_PUT_PREEMPTED : SCHED_PUT_READY);
        break;
    default:
        sched_put_current(t, SCHED_PUT_READY);
        break;
    }
    thread_fork_release_counted_locked(t);
    pthread_mutex_unlock(lock);
}


static int pool_worker_loop(struct vcpu_slot *slot, int timeout_sec)
{
    guest_t *g = pool_guest;
    bool verbose = pool_verbose;
    int last_exit = 0;

    while (!sched_shutdown_requested() && !proc_exit_group_requested()) {
        thread_entry_t *t = sched_worker_pick(slot->index);
        if (!t) {
            /* A CPU with nothing runnable is idle, not done: Core blocks here
             * until work, a timer-completed park, freeze, or shutdown. A NULL
             * pick must never unwind the VM while a task is parked.
             */
            if (sched_shutdown_requested() || proc_exit_group_requested() ||
                thread_active_count() == 0)
                break;
            sched_worker_wait(slot->index);
            continue;
        }

        if (sched_shutdown_requested() || proc_exit_group_requested()) {
            thread_exit_task(t, g, 0);
            if (proc_exit_group_requested())
                last_exit = proc_exit_group_code();
            break;
        }

        int exit_code = 0;
        int wait_status = 0;
        proc_leave_t leave = run_one_task(slot, t, g, verbose, timeout_sec,
                                          &exit_code, &wait_status);

        publish_leave(t, leave);

        if (leave == PROC_LEAVE_EXIT)
            thread_exit_task(t, g, wait_status);
        if (proc_exit_group_requested())
            last_exit = proc_exit_group_code();
        if (thread_active_count() == 0)
            break;
    }
    return last_exit;
}

/* Worker bring-up / lazy start */

static int configure_slot_vcpu(struct vcpu_slot *slot)
{
    hv_vcpu_t vcpu;
    hv_vcpu_exit_t *vexit;

    /* Copy a consistent (config, generation) pair: execve publishes a new
     * translation regime under the same lock while workers may be starting.
     */
    vcpu_pool_config_t cfg;
    uint64_t cfg_gen;
    pthread_mutex_lock(&pool_lock);
    cfg = pool_cfg;
    cfg_gen = atomic_load_explicit(&pool_cfg_gen, memory_order_relaxed);
    pthread_mutex_unlock(&pool_lock);

    hv_return_t r = hv_vcpu_create(&vcpu, &vexit, NULL);
    if (r != HV_SUCCESS) {
        log_error("vcpu_pool slot %d: hv_vcpu_create failed: %d", slot->index,
                  (int) r);
        return -1;
    }

#define POOL_HV(call)                                                         \
    do {                                                                      \
        hv_return_t _r = (call);                                              \
        if (_r != HV_SUCCESS) {                                               \
            log_error("vcpu_pool slot %d: %s failed: %d", slot->index, #call, \
                      (int) _r);                                              \
            hv_vcpu_destroy(vcpu);                                            \
            return -1;                                                        \
        }                                                                     \
    } while (0)

    POOL_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, cfg.vbar));
    POOL_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1, cfg.mair));
    POOL_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, cfg.tcr));
    POOL_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, cfg.ttbr0));
    POOL_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR1_EL1, cfg.ttbr1));
    POOL_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, cfg.cpacr));
    POOL_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTKCTL_EL1,
                                CNTKCTL_EL1_EL0_TIMER_EN));
    POOL_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, cfg.sctlr));
#undef POOL_HV

    slot->owner = pthread_self();
    atomic_store_explicit(&slot->cpu_port, MACH_PORT_NULL,
                          memory_order_relaxed);
    slot_cpu_port_init(slot);

    pthread_mutex_lock(&slot->handle_lock);
    slot->vcpu = vcpu;
    slot->vexit = vexit;
    slot->vcpu_live = true;
    bool kick = atomic_load_explicit(&slot->kick_pending, memory_order_acquire);
    pthread_mutex_unlock(&slot->handle_lock);

    slot->applied_cfg_gen = cfg_gen;

    /* A wake that raced publication latched kick_pending but had no handle to
     * kick; honor it now.
     */
    if (kick)
        hv_vcpus_exit(&vcpu, 1);
    return 0;
}

static void slot_destroy_vcpu_owner(struct vcpu_slot *slot)
{
    if (!slot)
        return;
    if (!pthread_equal(slot->owner, pthread_self())) {
        log_error("vcpu_pool slot %d: hv_vcpu_destroy off the owner pthread",
                  slot->index);
        return;
    }
    hv_vcpu_t vcpu = 0;
    bool had = false;
    pthread_mutex_lock(&slot->handle_lock);
    if (slot->vcpu_live) {
        vcpu = slot->vcpu;
        slot->vcpu_live = false;
        slot->vcpu = 0;
        slot->vexit = NULL;
        had = true;
    }
    pthread_mutex_unlock(&slot->handle_lock);
    if (had)
        hv_vcpu_destroy(vcpu);
    mach_port_t port = atomic_exchange_explicit(&slot->cpu_port, MACH_PORT_NULL,
                                                memory_order_acq_rel);
    if (port != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), port);
    atomic_store_explicit(&slot->current, NULL, memory_order_release);
}

static void *pool_worker_main(void *arg)
{
    struct vcpu_slot *slot = (struct vcpu_slot *) arg;

    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    if (!pool_cfg_valid || configure_slot_vcpu(slot) != 0) {
        log_error("vcpu_pool: worker %d failed to create vCPU", slot->index);
        pthread_mutex_lock(&pool_lock);
        slot->state = SLOT_STOPPED;
        pthread_mutex_unlock(&pool_lock);
        return NULL;
    }

    pthread_mutex_lock(&pool_lock);
    slot->state = SLOT_RUNNING;
    pthread_mutex_unlock(&pool_lock);

    log_debug("vcpu_pool: worker %d ready", slot->index);
    (void) pool_worker_loop(slot, 0);

    slot_destroy_vcpu_owner(slot);

    pthread_mutex_lock(&pool_lock);
    slot->state = SLOT_STOPPED;
    slot->in_use = false;
    if (slots_in_use > 0)
        slots_in_use--;
    pthread_mutex_unlock(&pool_lock);
    log_debug("vcpu_pool: worker %d stopped", slot->index);
    return NULL;
}

void vcpu_pool_wake_cpu(int cpu)
{
    struct vcpu_slot *slot = slot_of(cpu);
    if (!slot)
        return;

    bool spawn = false;
    pthread_mutex_lock(&pool_lock);
    if (!pool_ready || !pool_running || pool_stopping) {
        pthread_mutex_unlock(&pool_lock);
        return;
    }
    if (slot->state == SLOT_FREE) {
        slot->state = SLOT_STARTING;
        slot->in_use = true;
        slots_in_use++;
        spawn = true;
        int err = pthread_create(&slot->worker, NULL, pool_worker_main, slot);
        if (err == 0)
            slot->worker_joinable = true;
        if (err != 0) {
            log_error("vcpu_pool: pthread_create slot %d failed: %s", cpu,
                      strerror(err));
            slot->state = SLOT_FREE;
            slot->in_use = false;
            if (slots_in_use > 0)
                slots_in_use--;
            spawn = false;
        }
    }
    pthread_mutex_unlock(&pool_lock);

    if (spawn) {
        log_debug("vcpu_pool: spawned worker %d on demand", cpu);
        return;
    }
}

/* Public bring-up / teardown */

int vcpu_pool_init(void)
{
    pthread_mutex_lock(&pool_lock);
    if (pool_ready) {
        pthread_mutex_unlock(&pool_lock);
        return 0;
    }
    int n = sched_domain_ncpu();
    if (n < 1)
        n = 1;
    struct vcpu_slot *table = calloc((size_t) n, sizeof(*table));
    if (!table) {
        pthread_mutex_unlock(&pool_lock);
        return -1;
    }
    for (int i = 0; i < n; i++) {
        table[i].index = i;
        table[i].state = SLOT_FREE;
        pthread_mutex_init(&table[i].handle_lock, NULL);
    }
    slots = table;
    slot_count = n;
    slots_in_use = 0;
    pool_running = false;
    pool_stopping = false;
    pool_ready = true;
    pthread_mutex_unlock(&pool_lock);
    sched_set_host_ops(&pool_host_ops);
    return 0;
}

void vcpu_pool_shutdown(void)
{
    vcpu_pool_stop();
    pthread_mutex_lock(&pool_lock);
    struct vcpu_slot *table = slots;
    int n = slot_count;
    slots = NULL;
    slot_count = 0;
    slots_in_use = 0;
    pool_ready = false;
    pool_guest = NULL;
    pool_cfg_valid = false;
    pthread_mutex_unlock(&pool_lock);
    if (table) {
        for (int i = 0; i < n; i++)
            pthread_mutex_destroy(&table[i].handle_lock);
        free(table);
    }
}

int vcpu_pool_slot_count(void)
{
    if (!pool_ready)
        (void) vcpu_pool_init();
    return slot_count;
}

static void pool_cfg_from_vcpu(guest_t *g,
                               hv_vcpu_t vcpu,
                               bool verbose,
                               vcpu_pool_config_t *cfg)
{
    /* Bootstrap leaves SCTLR.M=0 so the shim _start enables the MMU; workers
     * must enter guest code with the MMU already on.
     */
    uint64_t sctlr = vcpu_get_sysreg(vcpu, HV_SYS_REG_SCTLR_EL1);
    if ((sctlr & SCTLR_M) == 0) {
        sctlr = SCTLR_RES1 | SCTLR_M | SCTLR_C | SCTLR_I | SCTLR_DZE |
                SCTLR_UCT | SCTLR_UCI;
    }

    *cfg = (vcpu_pool_config_t) {
        .guest = g,
        .verbose = verbose,
        .vbar = vcpu_get_sysreg(vcpu, HV_SYS_REG_VBAR_EL1),
        .mair = vcpu_get_sysreg(vcpu, HV_SYS_REG_MAIR_EL1),
        .tcr = vcpu_get_sysreg(vcpu, HV_SYS_REG_TCR_EL1),
        .ttbr0 = vcpu_get_sysreg(vcpu, HV_SYS_REG_TTBR0_EL1),
        .ttbr1 = vcpu_get_sysreg(vcpu, HV_SYS_REG_TTBR1_EL1),
        .sctlr = sctlr,
        .cpacr = vcpu_get_sysreg(vcpu, HV_SYS_REG_CPACR_EL1),
    };
}

int vcpu_pool_start_with_main(guest_t *g,
                              hv_vcpu_t vcpu,
                              hv_vcpu_exit_t *vexit,
                              bool verbose)
{
    if (!g || !vexit)
        return -1;
    if (!pool_ready && vcpu_pool_init() != 0)
        return -1;

    thread_entry_t *main_t = thread_get_main();
    if (!main_t) {
        log_error("vcpu_pool_start_with_main: main thread not registered");
        return -1;
    }

    pthread_mutex_lock(&pool_lock);
    if (pool_running) {
        pthread_mutex_unlock(&pool_lock);
        return 0;
    }
    pool_cfg_from_vcpu(g, vcpu, verbose, &pool_cfg);
    pool_cfg_valid = true;
    pool_guest = g;
    pool_verbose = verbose;
    pool_stopping = false;
    slot0_is_caller = true;

    struct vcpu_slot *slot0 = &slots[0];
    slot0->state = SLOT_RUNNING;
    slot0->in_use = true;
    slot0->owner = pthread_self();
    slot0->owner_is_caller = true;
    atomic_store_explicit(&slot0->current, NULL, memory_order_relaxed);
    slot0->vcpu = vcpu;
    slot0->vexit = vexit;
    slot0->vcpu_live = true;
    atomic_store_explicit(&slot0->cpu_port, MACH_PORT_NULL,
                          memory_order_relaxed);
    atomic_store_explicit(&slot0->kick_pending, false, memory_order_relaxed);
    slot0->slice_deadline_ns = 0;
    atomic_store_explicit(&slot0->in_exec, false, memory_order_release);
    atomic_store_explicit(&slot0->barrier_fence_ack, 0, memory_order_relaxed);
    atomic_store_explicit(&slot0->barrier_sync_ack, 0, memory_order_relaxed);
    atomic_store_explicit(&slot0->barrier_inflight, 0, memory_order_relaxed);
    barrier_seq = 0;
    atomic_store_explicit(&barrier_request, 0, memory_order_release);
    slots_in_use++;
    pool_running = true;

    slot0->applied_cfg_gen =
        atomic_load_explicit(&pool_cfg_gen, memory_order_relaxed);

    sched_clear_shutdown();
    pthread_mutex_unlock(&pool_lock);

    slot_cpu_port_init(slot0);

    /* thread_register_main already attached the task RUNNING on CPU 0; the
     * scheduler owns placement from here.
     */
    main_t->exec_resume = EXEC_RESUME_PLAIN;

    /* Snapshot live bootstrap regs so yield/preempt/park can remount. */
    guest_ctx_save(vcpu, &main_t->guest_ctx);

    atomic_store_explicit(&slot0->current, main_t, memory_order_release);
    current_thread = main_t;
    owner_slot = slot0;

    /* Guest owns g->vcpu until adopted; the pool now owns it. */
    g->vcpu = 0;
    g->vcpu_valid = false;

    if (slice_timer_start() != 0) {
        vcpu_pool_stop();
        return -1;
    }

    log_debug("vcpu_pool: main tid=%lld adopted on slot 0; other CPUs lazy",
              (long long) thread_tid(main_t));
    return 0;
}

int vcpu_pool_run_main(int timeout_sec)
{
    if (!pool_running || !slot0_is_caller || !slots) {
        log_error("vcpu_pool_run_main: pool not started with main");
        return 1;
    }

    guest_t *g = pool_guest;
    bool verbose = pool_verbose;
    struct vcpu_slot *slot = &slots[0];
    thread_entry_t *main_t =
        atomic_load_explicit(&slot->current, memory_order_acquire);
    int last_exit = 0;

    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    if (main_t && slot->vcpu_live) {
        int exit_code = 0;
        int wait_status = 0;
        proc_leave_t leave = run_one_task(slot, main_t, g, verbose, timeout_sec,
                                          &exit_code, &wait_status);
        publish_leave(main_t, leave);
        if (leave == PROC_LEAVE_EXIT)
            thread_exit_task(main_t, g, wait_status);
        if (proc_exit_group_requested())
            last_exit = proc_exit_group_code();
        else if (leave == PROC_LEAVE_EXIT)
            last_exit = exit_code;
    }

    if (!sched_shutdown_requested() && !proc_exit_group_requested() &&
        thread_active_count() > 0)
        last_exit = pool_worker_loop(slot, timeout_sec);
    if (proc_exit_group_requested())
        last_exit = proc_exit_group_code();

    slot_destroy_vcpu_owner(slot);
    log_debug("vcpu_pool: slot 0 (main) stopped, exit=%d", last_exit);
    return last_exit;
}

void vcpu_pool_stop(void)
{
    pthread_mutex_lock(&pool_lock);
    if (!pool_running) {
        pthread_mutex_unlock(&pool_lock);
        return;
    }
    pool_stopping = true;
    pthread_mutex_unlock(&pool_lock);

    /* Kick mounted guests so their loops observe teardown, and wake parks
     * before draining: a completed park must not be stranded READY after the
     * workers have left.
     */
    if (!proc_exit_group_requested())
        proc_request_exit_group(0);
    thread_interrupt_all();
    thread_wake_all_blocked();

    sched_request_shutdown();
    sched_worker_kick(-1);
    sched_drain_ready(drain_one_ready, pool_guest);

    /* Stop issuing timeslice kicks before joining workers. */
    slice_timer_stop();

    /* Wake any worker blocked inside hv_vcpu_run one last time. */
    vcpu_pool_kick_all_mounted();
    pthread_mutex_lock(&pool_lock);

    for (int i = 0; i < slot_count; i++) {
        struct vcpu_slot *slot = &slots[i];
        if (slot->owner_is_caller) {
            /* Slot 0 is the caller; it may already have destroyed its handle in
             * run_main. If bring-up failed before the loop, destroy here.
             */
            if (pthread_equal(slot->owner, pthread_self()))
                slot_destroy_vcpu_owner(slot);
            slot->state = SLOT_STOPPED;
            continue;
        }
        if (!slot->worker_joinable)
            continue;
        pthread_t thr = slot->worker;
        slot->worker_joinable = false;
        pthread_mutex_unlock(&pool_lock);
        (void) pthread_join(thr, NULL);
        pthread_mutex_lock(&pool_lock);
        slot->state = SLOT_STOPPED;
    }

    /* Adopted bootstrap: the pool owned g->vcpu. Clear the guest copy so a
     * later launch_destroy_guest cannot destroy it twice.
     */
    if (pool_guest) {
        pool_guest->vcpu = 0;
        pool_guest->vcpu_valid = false;
    }
    pthread_mutex_unlock(&pool_lock);
    thread_for_each_ref(drain_stopped_task, pool_guest);
    log_debug("vcpu_pool: stopped");
}

/* Accessors */

guest_t *vcpu_pool_guest(void)
{
    return pool_guest;
}

bool vcpu_pool_running(void)
{
    pthread_mutex_lock(&pool_lock);
    bool r = pool_running;
    pthread_mutex_unlock(&pool_lock);
    return r;
}

bool vcpu_pool_current_vcpu(hv_vcpu_t *out)
{
    if (!out || !owner_slot ||
        !atomic_load_explicit(&owner_slot->current, memory_order_acquire) ||
        !owner_slot->vcpu_live)
        return false;
    *out = owner_slot->vcpu;
    return true;
}

bool vcpu_pool_current_vexit(hv_vcpu_exit_t **out)
{
    if (!out || !owner_slot ||
        !atomic_load_explicit(&owner_slot->current, memory_order_acquire) ||
        !owner_slot->vcpu_live)
        return false;
    *out = owner_slot->vexit;
    return true;
}
int vcpu_pool_current_cpu(void)
{
    return owner_slot ? owner_slot->index : -1;
}

int vcpu_pool_cpu_of(const struct thread_entry *t)
{
    if (!t)
        return 0;
    return sched_thread_cpu(t);
}
