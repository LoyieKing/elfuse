/*
 * Per-VM guest scheduler
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * One scheduling domain per VM (host process), with logical CPUs 0..N-1. The
 * scheduler core owns run state, per-CPU fair/deadline/RT run queues, per-CPU
 * virtual time and shared fair period, runtime accounting, scheduling
 * attributes and effective (priority-inherited) selection.
 *
 * The core never touches an HVF handle, guest registers, or a worker's
 * architectural save area. Execution backends (runtime/sched/vcpu_pool.c) save
 * state, call sched_put_current(), call sched_worker_pick(), and restore the
 * returned task. Handler-side yield and affinity changes only request a
 * reschedule; the execution loop performs the switch at a switch-safe point.
 *
 * Fair scheduling mechanics are derived from the pinned Zircon reference (see
 * fair.h). Linux policies, admission and PI overlay are implemented against the
 * Linux sched(7), sched_setattr(2) and sched-deadline references named in
 * docs/scheduler.md.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#include "runtime/sched/fair.h"

struct thread_entry;

/* Linux scheduling policies, in guest ABI numbering. */
enum {
    SCHED_POLICY_OTHER = 0,
    SCHED_POLICY_FIFO = 1,
    SCHED_POLICY_RR = 2,
    SCHED_POLICY_BATCH = 3,
    SCHED_POLICY_IDLE = 5,
    SCHED_POLICY_DEADLINE = 6,
};

/* SCHED_FLAG_* guest ABI values. The core implements RESET_ON_FORK, RECLAIM
 * (GRUB bandwidth reclaim), DL_OVERRUN (host notification callback),
 * KEEP_POLICY and KEEP_PARAMS. UTIL_CLAMP_MIN/MAX only influence frequency and
 * capacity selection, which this backend does not provide; a request that sets
 * either returns SCHED_ERR_EOPNOTSUPP rather than pretending to apply it.
 */
#define SCHED_FLAG_RESET_ON_FORK 0x01U
#define SCHED_FLAG_RECLAIM 0x02U
#define SCHED_FLAG_DL_OVERRUN 0x04U
#define SCHED_FLAG_KEEP_POLICY 0x08U
#define SCHED_FLAG_KEEP_PARAMS 0x10U
#define SCHED_FLAG_UTIL_CLAMP_MIN 0x20U
#define SCHED_FLAG_UTIL_CLAMP_MAX 0x40U
#define SCHED_FLAG_UTIL_CLAMP \
    (SCHED_FLAG_UTIL_CLAMP_MIN | SCHED_FLAG_UTIL_CLAMP_MAX)
#define SCHED_FLAG_SUPPORTED                                                 \
    (SCHED_FLAG_RESET_ON_FORK | SCHED_FLAG_RECLAIM | SCHED_FLAG_DL_OVERRUN | \
     SCHED_FLAG_KEEP_POLICY | SCHED_FLAG_KEEP_PARAMS)

/* Linux errno values returned by scheduler entry points. They are guest ABI
 * values, not the host libc's errno numbering.
 */
#define SCHED_ERR_EINVAL 22
#define SCHED_ERR_EBUSY 16
#define SCHED_ERR_EOPNOTSUPP 95
#define SCHED_ERR_EAGAIN 11

/* Independent stop reasons. SIGCONT clears GROUP; PTRACE_CONT clears PTRACE. */
#define SCHED_STOP_PTRACE 0x1U
#define SCHED_STOP_GROUP 0x2U
#define SCHED_STOP_ALL (SCHED_STOP_PTRACE | SCHED_STOP_GROUP)

/* Linux priority, nice and quantum bounds. */
#define SCHED_RT_PRIO_MIN 1
#define SCHED_RT_PRIO_MAX 99
#define SCHED_NICE_MIN (-20)
#define SCHED_NICE_MAX 19

/* Linux default RR quantum (sched_rr_timeslice, 100 ms). */
#define SCHED_RR_QUANTUM_NS 100000000ULL

/* Deadline bandwidth fixed point: one logical CPU is 100% = 1 << 20. */
#define SCHED_DL_BW_ONE (1ULL << 20)

/* Per-CPU RT bandwidth, matching the Linux defaults. */
#define SCHED_RT_PERIOD_NS 1000000000ULL
#define SCHED_RT_RUNTIME_NS 950000000ULL

/* Linux CPU_SETSIZE. Affinity is carried as a byte array and sized by the
 * configured domain, never by a uint64_t.
 */
#define SCHED_MAX_CPUS 1024
#define SCHED_CPUSET_BYTES (SCHED_MAX_CPUS / 8)

/* Run state. NEW is the initial state before the task is made runnable. */
enum {
    SCHED_STATE_NEW = 0,
    SCHED_STATE_READY,
    SCHED_STATE_RUNNING,
    SCHED_STATE_BLOCKED,
    SCHED_STATE_DEAD,
};

/* Park kinds for a task that has unmounted on a blocking operation. The park
 * state itself belongs to the wait registration; the scheduler uses the kind
 * only to dispatch timeout and signal callbacks.
 */
enum {
    PARK_KIND_NONE = 0,
    PARK_KIND_FUTEX,
    PARK_KIND_SLEEP,
    PARK_KIND_IO,
    PARK_KIND_MQUEUE,
    PARK_KIND_STOP, /* ptrace/group stop: plain resume, no X0 injection */
    PARK_KIND_WAIT, /* wait driver re-check: reissue, no X0 injection */
    PARK_KIND_IPC,  /* SysV IPC wait: timeout reissues, signal gives EINTR */
    PARK_KIND_SERVICE,
};
/* Selection class. Lower value = lower precedence in Linux order. */
enum {
    SCHED_CLASS_FAIR = 0,
    SCHED_CLASS_RT = 1,
    SCHED_CLASS_DEADLINE = 2,
    SCHED_CLASS_NONE = -1,
};

/* How the execution loop is leaving the current task. */
typedef enum sched_put_disposition {
    /* Yield: requeue with retained budget; an RT task goes to the tail of its
     * priority list. A wake that raced a block leaves the task READY.
     */
    SCHED_PUT_READY = 0,

    /* Involuntary preemption, slice expiry or affinity migration: same as
     * READY, except that an RT task is requeued at the head of its priority
     * list (Linux put_prev_task_rt).
     */
    SCHED_PUT_PREEMPTED,
    /* Park/stop: BLOCKED unless a wake completed before the put. */
    SCHED_PUT_BLOCKED,
    /* Exit or detach: remove from every queue and mark DEAD. */
    SCHED_PUT_DEAD,
} sched_put_disposition_t;

/* Base user attributes, in canonical Linux units. This is the state
 * sched_getattr reports and sched_setattr replaces.
 */
typedef struct sched_task_attrs {
    int policy;           /* SCHED_POLICY_* */
    int nice;             /* -20..19 (fair), retained for RT/DL */
    unsigned rt_priority; /* 1..99 for FIFO/RR, 0 otherwise */
    unsigned flags;       /* SCHED_FLAG_* */
    uint64_t runtime;     /* fair custom slice (0 = default) or DL runtime */
    uint64_t deadline;    /* DL relative deadline, 0 otherwise */
    uint64_t period;      /* DL period, 0 means == deadline */
} sched_task_attrs_t;

/* Effective selection key used for local PI ordering and handoff. */
typedef struct sched_pi_key {
    int class_rank;       /* SCHED_CLASS_* */
    int policy;           /* SCHED_POLICY_* */
    int priority;         /* RT 1..99 or fair nice; 0 for DEADLINE */
    uint32_t weight;      /* fair weight, 0 for non-fair */
    uint64_t deadline_ns; /* absolute deadline for DEADLINE, else 0 */
} sched_pi_key_t;

/* Per-task scheduling state. thread.h embeds exactly one of these per task as
 * `sched_task_state_t sched;` and no longer carries flat scheduler fields. All
 * fields are guarded by the scheduler lock except the read-only-natured
 * accounting snapshot consumed through sched_thread_cputime_ns().
 */
typedef struct sched_task_state {
    /* Run state. */
    int state;              /* SCHED_STATE_* */
    int queued_class;       /* SCHED_CLASS_* while on a run queue, else NONE */
    int queued_cpu;         /* CPU whose run queue holds this task, else -1 */
    int current_cpu;        /* CPU executing this task, else -1 */
    int placement_cpu;      /* sticky CPU placement preference, else -1 */
    bool on_rq;             /* linked in a CPU run queue */
    bool attrs_initialized; /* base attrs and affinity are valid */
    bool wake_pending;      /* unblock raced while RUNNING: publish READY */
    bool block_requested; /* handler asked to block at the next switch point */
    bool resched_requested; /* handler asked to reschedule at a safe point */
    bool yield_requested;
    _Atomic uint32_t stop_reasons; /* SCHED_STOP_* */
    bool stop_requested;           /* safe-point stop park requested */
    bool stop_blocked;             /* removed by a stop, not by its wait */
    uint64_t stop_started_ns;

    /* Base (user) attributes. */
    int32_t policy;                /* SCHED_POLICY_* */
    int32_t nice;                  /* -20..19 */
    uint32_t rt_priority;          /* 1..99 for FIFO/RR */
    uint32_t flags;                /* SCHED_FLAG_* accepted subset */
    uint64_t fair_slice_custom_ns; /* fair se.slice; 0 means default */
    uint64_t dl_runtime_ns;
    uint64_t dl_deadline_ns; /* relative */
    uint64_t dl_period_ns;

    /* Effective (selection) attributes: base, or the PI override while
     * pi_boosted. Selection queues and queries read these.
     */
    int32_t eff_policy;
    int32_t eff_nice;
    uint32_t eff_rt_priority;
    uint32_t eff_weight;
    uint64_t eff_dl_abs_deadline_ns;
    uint64_t eff_dl_runtime_left_ns;
    uint64_t eff_dl_period_ns;
    bool pi_boosted;

    /* Stored PI boost, kept separate from base attributes so a base change can
     * re-evaluate which profile outranks which.
     */
    int32_t boost_policy;
    int32_t boost_prio;
    uint64_t boost_dl_abs_deadline_ns;
    uint64_t boost_dl_runtime_left_ns;
    uint64_t boost_dl_period_ns;

    /* Fair activation (CPU virtual nanoseconds). */
    uint64_t fair_start_ns;
    uint64_t fair_finish_ns;
    uint64_t fair_slice_ns;
    uint64_t fair_used_ns;
    int fair_cpu; /* CPU virtual timeline that fair_* values are in */

    /* RT run state. */
    uint64_t rr_remaining_ns; /* retained RR quantum, actual ns */
    int run_class;            /* class at the last pick, -1 when not running */

    /* Deadline run state (base profile). */
    uint64_t dl_runtime_left_ns;
    uint64_t dl_abs_deadline_ns;
    uint32_t dl_bw_q20;       /* runtime/period in SCHED_DL_BW_ONE units */
    bool dl_admitted;         /* base reservation counted in domain admission */
    bool dl_bw_counted;       /* bandwidth included in dl_running_bw */
    bool dl_overrun_reported; /* SIGXCPU notification already emitted */
    bool dl_throttled;
    bool dl_yielded;
    bool dl_non_contending; /* blocked but bandwidth not yet reclaimed */
    uint64_t dl_inactive_deadline_ns; /* 0-lag time */
    int dl_bw_cpu; /* CPU whose DL bandwidth counters include us */

    /* Run-queue linkage: one tree node (fair or deadline) or the RT list. */
    sched_tree_node_t node;
    struct thread_entry *rt_next;
    struct thread_entry *rt_prev;

    /* Domain list of admitted base deadline tasks, used by replenishment and
     * zero-lag timers without touching the global thread table.
     */
    struct thread_entry *dl_prev;
    struct thread_entry *dl_next;

    /* Runtime accounting, in actual executed nanoseconds. */
    uint64_t runtime_ns;      /* total charged runtime */
    uint64_t runtime_user_ns; /* guest execution */
    uint64_t runtime_sys_ns;  /* host syscall service */
    uint64_t run_start_ns;    /* host mono ns at pick (live cputime) */

    /* CPU affinity: bit i permits logical CPU i. Bits outside the domain are
     * always clear. All-zero is never stored.
     */
    uint8_t affinity[SCHED_CPUSET_BYTES];
} sched_task_state_t;

/* Host services the execution backend registers. NULL entries are permitted for
 * host unit tests; the core then simply does not wake or kick.
 */
typedef struct sched_host_ops {
    void (*wake_cpu)(int cpu); /* make a worker runnable on @cpu */
    void (*kick_cpu)(int cpu); /* force @cpu out of guest execution */
    void (*kick_all)(void);    /* force every mounted CPU out */
    void (*wake_timer)(void);  /* recompute the host timer deadline */
    /* Deliver SIGXCPU for a SCHED_FLAG_DL_OVERRUN task whose runtime was
     * exhausted. Called without the scheduler lock held, from any thread.
     */
    void (*dl_overrun)(struct thread_entry *t);

    /* Live guest-execution nanoseconds not yet settled through
     * sched_account_cpu_ns() for a RUNNING task. Called without the scheduler
     * lock held (the callback may take it for its slot lookup); must be safe
     * under sig_lock -> thread_lock iteration.
     */
    uint64_t (*live_exec_ns)(const struct thread_entry *t);

    /* Live host syscall-service nanoseconds not yet settled through
     * sched_account_service_ns() for a RUNNING task. Same call contract as
     * live_exec_ns(). Both samples feed budget-expiry decisions, because
     * service time is charged to the same runtime budgets.
     */
    uint64_t (*live_service_ns)(const struct thread_entry *t);
} sched_host_ops_t;

void sched_set_host_ops(const sched_host_ops_t *ops);

/* Domain lifecycle and clocks */

/* Initialize the domain from the host CPU count. Idempotent. */
void sched_init(void);

/* Initialize (or re-initialize before any task is attached) a domain with @ncpu
 * logical CPUs; 0 means sched_host_ncpu().
 *
 * Returns 0 or -EINVAL.
 */
int sched_domain_init(int ncpu);

int sched_host_ncpu(void);
int sched_domain_ncpu(void);

/* CLOCK_MONOTONIC nanoseconds, the scheduler's wall timeline. */
uint64_t sched_now_ns(void);

/* Task lifecycle and execution protocol */

/* Bind a freshly created bootstrap task to the calling CPU as RUNNING. */
void sched_attach_thread(struct thread_entry *t);

/* Make a NEW or BLOCKED task READY on an affinity-legal CPU and wake that CPU's
 * worker. Safe from any thread.
 */
void sched_enqueue_thread(struct thread_entry *t);

/* Remove a task from every queue and mark it DEAD. Called before the slot is
 * recycled; runtime totals are retained in the task until detach completes.
 */
void sched_detach_thread(struct thread_entry *t);

/* Atomically claim a non-running task for destruction. READY/BLOCKED/NEW are
 * dequeued and marked DEAD (returns true); a RUNNING task is left alone
 * (returns false). DEAD returns true. Wakers never enqueue a DEAD task, so the
 * caller can perform exit cleanup outside scheduler and thread locks.
 */
bool sched_task_claim_stopped(struct thread_entry *t);

/* Wake a BLOCKED task. If it is still RUNNING (completion before block), the
 * put publishes READY instead of BLOCKED.
 */
void sched_unblock(struct thread_entry *t);

/* Handler-side request: block the calling task at the next switch point. */
void sched_block_current(void);

/* Resume a task parked with PARK_KIND_STOP once no stop reason remains.
 * Publishes READY without touching the park result or reissuing an SVC.
 */
void sched_wake_stop(struct thread_entry *t);


/* Job-control and ptrace stop state. READY tasks are dequeued; RUNNING tasks
 * receive a safe-point reschedule request and are not requeued. The reasons are
 * independent: SIGCONT clears only GROUP and PTRACE_CONT only PTRACE. A task
 * with any reason set is never READY or RUNNING. A blocked wait is not
 * dequeued; it resumes through its wait completion and the stop check at
 * enqueue time.
 */
void sched_task_set_group_stopped(struct thread_entry *t, bool stopped);
void sched_task_set_trace_stopped(struct thread_entry *t, bool stopped);
bool sched_task_group_stopped(const struct thread_entry *t);
bool sched_task_trace_stopped(const struct thread_entry *t);

void sched_stop_task(struct thread_entry *t, unsigned reasons);
void sched_resume_task(struct thread_entry *t, unsigned reasons);

/* Execution safe point: consume a RUNNING stop request exactly once. The caller
 * saves architectural state and publishes SCHED_PUT_BLOCKED with park_kind
 * PARK_KIND_STOP.
 */
bool sched_take_stop_request(struct thread_entry *t, unsigned *reasons);

/* Lock-free current reason bits (procfs T state / SIGCONT suppression). */
unsigned sched_task_stop_reasons(const struct thread_entry *t);

/* Run-state snapshot safe to call while the caller holds thread_lock or
 * sig_lock. Never calls back into the thread table.
 */
int sched_task_run_state(const struct thread_entry *t);
bool sched_task_is_running(const struct thread_entry *t);

/* Execution backend: publish the current task after its architectural state has
 * been saved. Accounting for the interval must already have been reported with
 * sched_account_cpu_ns(). Never performs a context switch.
 */
void sched_put_current(struct thread_entry *t, sched_put_disposition_t how);

/* Execution backend: select and mark RUNNING the next task for @cpu.
 *
 * Returns NULL when the CPU has no runnable task. The caller restores the
 * returned task's architectural state; if it equals the task just put, no
 * switch is needed.
 */
struct thread_entry *sched_worker_pick(int cpu);

/* Execution backend: block until @cpu (or any CPU when negative) has a queued
 * task, or until freeze/shutdown.
 *
 * Returns immediately when work is already available. Use this instead of
 * unwinding the worker when every task is blocked.
 */
void sched_worker_wait(int cpu);

/* Report actual executed nanoseconds for @t (HVF exec time or an equivalent
 * owner-thread CPU delta). Called before sched_put_current().
 */
void sched_account_cpu_ns(struct thread_entry *t, uint64_t ns);

/* Report host syscall-service nanoseconds for @t. Service is execution too: it
 * is charged to the task and group CPU clocks and consumes the same fair/RT/DL
 * scheduling budget as guest execution.
 */
void sched_account_service_ns(struct thread_entry *t, uint64_t ns);

/* Reschedule requests */

/* Request scheduling after the calling task's own return path completes. Never
 * switches context from a handler.
 */
void sched_yield_current(void);
void sched_request_resched(struct thread_entry *t);
bool sched_resched_requested(void);
bool sched_take_resched(struct thread_entry *t);

/* CPU queries, timers, worker control */

int sched_thread_cpu(const struct thread_entry *t);
bool sched_cpu_has_ready(int cpu);
int sched_ready_count(void);
uint64_t sched_cpu_weight_sum(int cpu);

/* Current fair time slice of @t in actual nanoseconds (0 for FIFO/DL, which
 * have no fair quantum). Used by the worker to arm a preemption timer.
 */
uint64_t sched_timeslice_ns(const struct thread_entry *t);

/* Earliest absolute CLOCK_MONOTONIC time at which the scheduler needs a timer
 * event: fair slice expiry, RR quantum expiry, deadline replenishment or RT
 * bandwidth replenishment. 0 when no timer is needed.
 */
uint64_t sched_next_timer_ns(void);

/* Process timer events at @now_ns and request kicks for CPUs whose current task
 * must be rescheduled.
 *
 * Returns the number of CPUs kicked.
 */
int sched_run_timers(uint64_t now_ns);

void sched_worker_kick(int cpu);
void sched_request_shutdown(void);
void sched_clear_shutdown(void);
bool sched_shutdown_requested(void);

/* Fork snapshot gate. While frozen, a worker with no current task must not pick
 * one; a task that is already RUNNING (the forking caller) continues so it can
 * scan and kick siblings. Freezing does not take thread_lock and does not stop
 * already-running siblings; the caller sets freeze before scanning and calling
 * kick_all. Unfreezing wakes every CPU.
 */
void sched_domain_freeze(bool frozen);
bool sched_domain_frozen(void);

/* Detach every READY task (pool teardown). The callback runs without the
 * scheduler lock held.
 */
void sched_drain_ready(void (*on_thread)(struct thread_entry *t, void *arg),
                       void *arg);

/* Scheduling attributes and affinity */

/* Read the base attributes used by sched_getattr/legacy queries. */
void sched_task_get_attr(const struct thread_entry *t, sched_task_attrs_t *out);

/* Apply Linux-validated base attributes to @t (current or remote task in the
 * same domain). Handles KEEP_POLICY/KEEP_PARAMS, validates class parameters and
 * DL admission, rebuilds effective selection state, requeues READY tasks and
 * requests a reschedule on the affected CPU.
 *
 * Returns 0, -EINVAL for an unsupported policy/flag/parameter, or -EBUSY when
 * deadline admission fails. Never switches context and never touches HVF state.
 */
int sched_task_set_attr(struct thread_entry *t, const sched_task_attrs_t *a);

/* setpriority path: change nice (and the fair weight) for a fair task. */
int sched_task_set_nice(struct thread_entry *t, int nice);

/* Fork/clone attribute inheritance, including RESET_ON_FORK. Copies base
 * attributes and affinity only; the child still starts in SCHED_STATE_NEW.
 */
int sched_task_inherit_attr(const struct thread_entry *parent,
                            struct thread_entry *child);

/* Base and effective external priority: FIFO/RR 1..99, fair nice -20..19,
 * DEADLINE reports priority 0 and its deadline is available through
 * sched_task_pi_key().
 *
 * Return false for a NULL or detached task.
 */
bool sched_task_base_priority(const struct thread_entry *t,
                              int *policy,
                              int *prio);
bool sched_task_effective_priority(const struct thread_entry *t,
                                   int *policy,
                                   int *prio);

/* Interval reported by sched_rr_get_interval. RR returns the configured quantum
 * (not the remaining budget); FIFO and DEADLINE return 0; fair policies return
 * the configured fair slice (nonzero).
 */
uint64_t sched_task_rr_interval_ns(const struct thread_entry *t);

/* Number of bytes in a guest affinity mask for this domain (>= 8). */
size_t sched_affinity_cpuset_bytes(void);

/* Fill @buf with the domain's default affinity mask.
 *
 * Returns bytes written, or -1 on bad arguments.
 */
int sched_affinity_default_mask(uint8_t *buf, size_t len);

/* Copy @t's affinity mask.
 *
 * Returns bytes written; -EINVAL when @len is smaller than
 * sched_affinity_cpuset_bytes().
 */
int sched_task_get_affinity(const struct thread_entry *t,
                            uint8_t *buf,
                            size_t len);

/* Replace @t's affinity mask. The mask must intersect the domain. A READY task
 * is requeued if its CPU is no longer permitted; a RUNNING task receives a
 * reschedule request.
 *
 * Returns 0 or -EINVAL. Never switches.
 */
int sched_task_set_affinity(struct thread_entry *t,
                            const uint8_t *mask,
                            size_t len);

/* Local priority inheritance */

/* Effective RT/fair priority override. policy may be OTHER/BATCH/IDLE (prio is
 * nice) or FIFO/RR (prio 1..99).
 *
 * Returns 0 or -EINVAL. Reorders a READY task, preempts its CPU when the new
 * effective key outranks the current task, and never mutates base attributes.
 * Safe from any thread; the core never calls back into futex while holding the
 * scheduler lock.
 */
int sched_task_pi_set_priority(struct thread_entry *t, int policy, int prio);

/* Effective DEADLINE override for local deadline PI. @abs_deadline_ns is the
 * inherited absolute CLOCK_MONOTONIC deadline; @runtime_ns is the remaining
 * runtime (0 means the waiter's full runtime is unavailable, so the boost runs
 * without throttling), @period_ns is the inherited period.
 */
int sched_task_pi_set_deadline(struct thread_entry *t,
                               uint64_t abs_deadline_ns,
                               uint64_t runtime_ns,
                               uint64_t period_ns);

/* Drop the PI override and restore the base profile. */
void sched_task_pi_clear_priority(struct thread_entry *t);

/* Effective ordering key for PI comparison/handoff. */
bool sched_task_pi_key(const struct thread_entry *t, sched_pi_key_t *out);

/* Negative when @a outranks @b (earlier selection), positive when @b outranks
 * @a, zero when equal.
 */
int sched_pi_key_cmp(const sched_pi_key_t *a, const sched_pi_key_t *b);

/* Register the PI subsystem's base-attribute-change notification. The core
 * invokes it after committing sched_task_set_attr()/sched_task_set_nice() and
 * after releasing the scheduler lock.
 */
void sched_set_priority_changed_hook(void (*fn)(struct thread_entry *t));

/* Park / wait timer integration
 *
 * The execution backend owns unmounting and guest register injection. These
 * entry points only update scheduler run state and the task's wait deadline;
 * the park-kind callbacks live in the waiting syscall's module.
 */

bool sched_park_try_complete(struct thread_entry *t, int64_t result);
bool sched_park_try_complete_reissue(struct thread_entry *t);

/* A park's generation distinguishes one wait on a task from the next. An arm
 * path writes its kind-specific fields, takes a new generation with
 * sched_park_seq_next(), and only then sets park_active; the value is nonzero
 * and never reused, and its release ordering publishes those fields to any
 * waker that observes the matching generation.
 */
uint64_t sched_park_seq_next(struct thread_entry *t);

/* Latest park generation assigned to @t (0 before the first arm). Snapshot
 * only: callers must also check the task's live park state.
 */
uint64_t sched_park_seq(const struct thread_entry *t);

/* Generation-checked completions: they act only while @t is still parked in
 * @kind with generation @seq. A waker that was raised for an earlier wait can
 * therefore never complete a later one on the same task, which a task pointer
 * alone cannot distinguish. An unmatched call changes no state and returns
 * false.
 */
bool sched_park_try_complete_seq(struct thread_entry *t,
                                 int kind,
                                 uint64_t seq,
                                 int64_t result);
bool sched_park_try_complete_reissue_seq(struct thread_entry *t,
                                         int kind,
                                         uint64_t seq);
void sched_park_on_signal(struct thread_entry *t);
void sched_arm_wait_deadline(struct thread_entry *t, uint64_t abs_ns);
void sched_disarm_wait_deadline(struct thread_entry *t);
uint64_t sched_next_wait_deadline_ns(void);
void sched_fire_expired_waits(uint64_t now_ns);
void sched_kick_wait_timer(void);
void sched_wake_parked_for_pending_signal(void);

/* CPU clocks */

/* Task CPU time in nanoseconds: settled runtime plus the unsettled live guest
 * and service deltas reported by the host's live_exec_ns / live_service_ns
 * callbacks. Wall time while the task is not executing is never substituted.
 * Safe from any thread; does not call back into the thread table and does not
 * call the live callbacks under the scheduler lock.
 */
uint64_t sched_thread_cputime_ns(const struct thread_entry *t);

/* Split task CPU time into guest execution and host syscall service. The live
 * guest delta is attributed to user time and the live service delta to system
 * time. Wall time is never included.
 */
void sched_thread_cputime_split_ns(const struct thread_entry *t,
                                   uint64_t *user_ns,
                                   uint64_t *sys_ns);

/* Process CPU time split for the calling thread group, including the runtime of
 * departed members (owned by thread.c).
 */
void sched_process_cputime_split_ns(uint64_t *user_ns, uint64_t *sys_ns);

/* Process CPU time for the calling thread group. */
uint64_t sched_process_cputime_ns(void);
