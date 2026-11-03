/*
 * Guest kernel-task table (Linux threading support)
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Each guest user thread (main, CLONE_THREAD, CLONE_VM) is a schedulable kernel
 * task (`thread_entry` / `kernel_task_t`). Tasks are NOT HVF vCPUs: the fair
 * scheduler mounts READY tasks onto a fixed ncpu-sized vCPU worker pool
 * (runtime/sched/vcpu_pool.h) with register save/restore (`guest_ctx`).
 * Blocking parks unmount so another READY task can run on that slot. A
 * _Thread_local pointer provides O(1) access from any syscall handler.
 *
 * SP_EL1 allocation: each task gets a 4KiB EL1 exception stack carved from the
 * shim data region (g->shim_data_base + 2MiB). Task 0 (main) gets the top, task
 * N gets offset -(N * 4096). Slot count is bounded only by the residual IPA
 * above the shim-globals cache (see thread.c), not by a uint64_t bitset or a
 * fixed MAX_THREADS.
 */

#pragma once

#include <Hypervisor/Hypervisor.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

#include "core/guest.h"         /* guest_t (for thread_alloc_sp_el1) */
#include "syscall/linux-wire.h" /* linux_user_pt_regs_t */
#include "syscall/signal.h" /* signal_pending_t (per-thread directed signals) */
#include "runtime/sched/guest_ctx.h"
#include "runtime/futex.h"
#include "runtime/sched/sched.h"

/* Concurrent kernel tasks are not hard-capped at a fixed 64.
 *
 * The table grows with host memory (calloc failure -> clone EAGAIN). Each task
 * still needs a 4KiB SP_EL1 slot carved from the shim_data IPA block above the
 * shim-globals cache; exhausting that pool returns ENOMEM. Physical HVF vCPUs
 * stay bound to sched_host_ncpu() worker slots; creating many CLONE_THREAD
 * tasks does not create one vCPU each.
 *
 * Callers that need a snapshot buffer size should use thread_table_capacity()
 * (or thread_active_count()) rather than a compile-time MAX_THREADS.
 */

/* One EL1 exception stack per thread. Named because the region these slots
 * occupy is a bound as well as an allocation: the host writes into a live shim
 * frame on that stack, and anything below the lowest slot is the shim-globals
 * cache rather than stack.
 */
#define SP_EL1_SLOT_BYTES 4096
#define MAX_DEFERRED_STACK_UNMAPS 8

/* Restart witnesses span guest entries and follow the migrating task. */
typedef struct task_syscall_restart {
    bool armed;
    bool restarted;
    bool forbidden;
    uint64_t elr_rewound;
    uint64_t elr_after_svc;
    uint64_t nr;
    int64_t result;
} task_syscall_restart_t;

/* Per-task state. One entry per guest user thread (main + clones). This is
 * elfuse's kernel task: the fair scheduler's schedulable entity. Tagged (struct
 * thread_entry) so signal.h can forward-declare it for the thread-directed
 * signal API without an include cycle.
 */
typedef struct thread_entry {
    /* Read without thread_lock. Four scans walk the table lock-free
     * (thread_pending_union, thread_tid_alive, thread_signal_deliverable,
     * thread_kick_futex_waiters): each loads active, then one or two of
     * blocked, guest_tid, and tpending.pending, with nothing in between. A
     * scanner that saw active as 1 just before this slot went inactive can
     * still be loading one of those when thread_alloc recycles the slot, so
     * none of them may be plain-written there. They are grouped here, cleared
     * with atomic stores, and deliberately excluded from the memset that clears
     * the rest. Keep them ahead of the rest of the struct; thread.c asserts
     * that each one sits below where its memset starts.
     */
    _Atomic int active; /* Non-zero while thread is running. Stays int (not
                         * bool) because lock-free paths in thread.c use
                         * atomic_load_explicit on it; the 32-bit width keeps
                         * the access pattern predictable across architectures.
                         */
    _Atomic uint64_t
        blocked; /* Per-thread signal mask (POSIX requires each thread to
                  * have its own). Initialized to the parent's mask on
                  * clone, modified via rt_sigprocmask.
                  */
    _Atomic int64_t guest_tid; /* Linux TID (unique per thread) */

    /* The Linux syscall this thread is inside, or -1 between calls. Written
     * around the handler call in syscall_dispatch and read only by the execve
     * teardown, which otherwise reports a sibling that would not leave by tid
     * alone and leaves the wait it is parked in to be guessed. Sits in this
     * group so the one memset below it stays one memset.
     */
    _Atomic int32_t in_syscall;

    _Atomic uint32_t futex_kick; /* A kick not answered yet */

    /* Thread-directed pending signals (Linux task->pending). tgkill/tkill and
     * pthread_kill queue here so only this thread consumes them. Written and
     * read under the signal module's sig_lock; do not touch without it. Only
     * the leading pending bitmask is scanned lock-free, so the recycle clear
     * stores that one atomically and memsets the rest of this struct.
     */
    signal_pending_t tpending;

    uint64_t clear_child_tid; /* GVA for CLONE_CHILD_CLEARTID (0=none) */
    uint64_t sp_el1;          /* Per-thread EL1 stack top (IPA) */
    int sp_el1_slot;          /* Slot index in sp_el1_allocated (-1 = none).
                               * Stored at alloc time so the free path does
                               * not need to recompute (top - sp) / 4096; the
                               * shim data block is now at high IPA and only
                               * known via guest_t.
                               */
    uint64_t generation;      /* Slot identity; protected by thread_lock. */
    unsigned references; /* Held under thread_lock; prevents slot recycling. */
    bool exit_cleanup_claimed;

    /* Per-thread signal mask lives at the top of the struct; see the lock-free
     * group there. saved_blocked is touched only under sig_lock by the owning
     * thread, so it stays here with the rest of the signal state.
     */
    uint64_t saved_blocked; /* Original mask saved by sigsuspend */
    bool saved_blocked_valid;

    /* Per-thread alternate signal stack (Linux sigaltstack is per-thread).
     * Fields mirror linux_stack_t layout for easy copy.
     */
    uint64_t altstack_sp;   /* Alternate signal stack pointer */
    int32_t altstack_flags; /* SS_DISABLE / 0 */
    uint64_t altstack_size; /* Alternate signal stack size */
    bool on_altstack;       /* True if currently delivering on altstack */

    /* Robust futex list head (GVA). When non-zero, thread exit walks the list
     * and sets FUTEX_OWNER_DIED on each lock word.
     */
    uint64_t robust_list_head;

    futex_pi_task_t futex_pi;

    /* rseq (restartable sequences) per-thread registration state. When rseq_gva
     * != 0, the thread has a registered struct rseq. Signal delivery and
     * preemption must abort active critical sections.
     */
    uint64_t rseq_gva;       /* Guest VA of struct rseq (0 = not registered) */
    uint32_t rseq_len;       /* Length from registration */
    uint32_t rseq_signature; /* Abort signature from registration */

    /* Fork-quiesce barrier accounting. Set by thread_quiesce_siblings for each
     * sibling it counted into fork_target_count; cleared when the thread either
     * reaches thread_fork_barrier_check (contributing to fork_quiesced_count)
     * or deactivates first (decrementing fork_target_count so the forker is not
     * stalled). Guards both sides so a thread created after the barrier armed
     * neither inflates nor deflates the tally. Written under thread_lock.
     */
    bool fork_counted;

    /* ptrace state. Used by two-process JIT architectures: the tracer attaches
     * via PTRACE_SEIZE, then uses BRK-triggered SIGTRAP + wait4 to discover
     * untranslated code on-demand. The tracee snapshots its own vCPU registers
     * before stopping and applies any tracer-written changes on resume,
     * avoiding cross-thread HVF register access (which may not be supported).
     */
    bool ptraced;                /* True if being traced */
    int64_t tracer_tid;          /* TID of tracing thread */
    bool ptrace_stopped;         /* True when in ptrace-stop */
    int ptrace_stop_sig;         /* Signal that caused the stop */
    pthread_cond_t ptrace_cond;  /* Tracee stopped -> tracer wakes */
    pthread_cond_t resume_cond;  /* Tracer CONT -> tracee wakes */
    bool ptrace_conds_inited;    /* Condvars initialized for this slot */
    int ptrace_waiters;          /* Tracers currently blocked on ptrace_cond */
    bool ptrace_cleanup_pending; /* Destroy condvars after last waiter leaves */
    int ptrace_cont_sig;         /* Signal to inject on resume (0=none) */
    bool ptrace_interrupt_pending;    /* A ptrace-stop is owed to this thread.
                                       * Set by every PTRACE_INTERRUPT, not only
                                       * the bring-up race it started as: the
                                       * kick alone is not enough, because it can
                                       * land while the vCPU is at EL1 in the
                                       * shim, where the live registers are shim
                                       * scratch and a stop would show the tracer
                                       * those instead of the guest's. Consumed
                                       * in the HVC #5 epilogue, which then
                                       * either stops in place or routes the
                                       * stop through HVC #13, or by the
                                       * canceled-exit handler once it has
                                       * established EL0. A vCPU
                                       * still in bring-up (!vcpu_valid) cannot
                                       * be kicked at all and self-kicks at
                                       * publish. Under thread_lock.
                                       */
    linux_user_pt_regs_t ptrace_regs; /* snapshot for cross-thread access */
    bool ptrace_regs_dirty;           /* Tracer modified registers */

    /* GDB stub state. Per-thread stop state for the GDB remote stub. When GDB
     * requests a stop (breakpoint, Ctrl+C, step), the thread records its stop
     * reason here so the stub can report it to GDB.
     *
     * Register access: HVF requires vCPU register reads/writes on the owning
     * thread. When stopped, the vCPU thread snapshots registers into
     * gdb_reg_snapshot; the GDB handler thread reads/writes that buffer. On
     * resume, dirty changes are applied back to the vCPU.
     */
    uint8_t gdb_reg_snapshot[788]; /* Register snapshot for GDB
                                    * Layout: 31xGPR(8) + SP(8) + PC(8)
                                    * + CPSR(4) + 32xV(16) + FPSR(4) + FPCR(4)
                                    */
    bool gdb_regs_dirty;           /* GDB handler modified snapshot */

    /* VM-clone child state. For clone(CLONE_VM) without CLONE_THREAD: shares
     * guest memory but has a separate TID, is waitable via wait4, and can be
     * ptraced. Used by clone(CLONE_VM) two-process architecture.
     */
    bool is_vm_clone;   /* Waitable via wait4 */
    int64_t parent_tid; /* Parent TID for wait4 matching */
    int exit_signal;    /* Signal on exit (usually SIGCHLD) */
    bool vm_exited;     /* Child has exited */
    int vm_exit_status; /* Wait-format exit status */

    sched_task_state_t sched;

    guest_thread_ctx_t guest_ctx;

    /* Signal frames outlive a worker mount and migrate with the task. */
    uint64_t sigreturn_cookies[16];
    unsigned sigreturn_cookie_depth;
    bool sig_fault_valid;
    int32_t sig_fault_code;
    uint64_t sig_fault_addr;
    uint64_t sig_fault_esr;
    int termination_wait_status;
    bool sigreturn_x8_valid;
    bool ptrace_stop_armed;
    uint64_t sigreturn_x8_elr;
    uint64_t sigreturn_x8_value;
    int64_t nl_restart_deadline_ms;
    int nl_restart_fd;
    task_syscall_restart_t syscall_restart;
    _Atomic bool park_restart_forbid;
    int exec_resume;
    /* Notification fd plus one; zero means no vfork continuation. */
    int vfork_wait_fd_plus1;
    int64_t vfork_child_pid;
    int vfork_child_host_pid;
    uint64_t watchdog_progress_ns;
    uint64_t io_continue_bytes;
    struct io_stream_cont *io_stream_cont;
    void *fuse_service;
    bool sysv_waited;

    /* Synchronous signal wait registration and saved request, under sig_lock.
     */
    struct thread_entry *sigwait_prev, *sigwait_next;
    bool sigwait_registered, sigwait_continuation, sigwait_interrupted;
    uint64_t sigwait_mask, sigwait_info_gva, sigwait_deadline_ns;

    /* Async park (pool unmount). Futex wait / nanosleep return SYSCALL_PARKED
     * instead of pthread_cond_wait on the worker. Waker, deadline, or signal
     * completes the park and READY-enqueues; remount injects X0 then resumes
     * the HVC #5 shim epilogue path. IO waits (PARK_KIND_IO) remount with
     * park_reissue so the SVC is dispatched again instead of injecting X0.
     */
    _Atomic int park_kind;
    _Atomic uint64_t park_seq;
    _Atomic bool park_active;
    _Atomic bool park_result_pending;
    _Atomic bool park_reissue;
    _Atomic int64_t park_result;
    _Atomic uint64_t wait_deadline_ns;
    void *_Atomic async_futex_waiter;
    unsigned async_futex_pub_bucket;
    bool async_futex_relative; /* Plain FUTEX_WAIT: forbid restart on EINTR */
    bool async_futex_timed;    /* Guest supplied a timeout (vs infinite) */
    /* FUTEX_WAIT_REQUEUE_PI: signal before CMP_REQUEUE_PI must restart the SVC
     * (Linux ERESTARTNOINTR) even without SA_RESTART. Remount/epilogue rewind
     * ELR to the SVC and skip injecting EINTR so the handler's rt_sigreturn
     * re-enters the wait. After requeue, park completes with EWOULDBLOCK
     * instead (see futex_park_on_interrupt).
     */
    _Atomic bool async_futex_requeue_pi_restart;
    guest_t *park_guest; /* Guest for charge drop / rem write */
    uint64_t sleep_rem_gva;
    bool sleep_write_rem;
    int64_t sleep_requested_ns;
    int64_t sleep_start_ns;
    uint64_t park_rem_gva;
    int64_t park_rem_ns;
    _Atomic bool park_rem_pending;
    int io_park_fd; /* Host fd for PARK_KIND_IO poll, or -1 */
    short io_park_events;
    uint64_t io_park_deadline_ns; /* Guest wait end (0 = infinite) */
    /* Host fd SoftNS is driving through connect_nonblock_wait, or -1. Survives
     * PARK_KIND_IO park_reissue so a remounted connect that sees EISCONN
     * (connection landed while parked) can return 0 instead of leaking the host
     * errno. Cleared when connect returns a final result to the guest. A
     * genuine second connect after success finds this cleared and still reports
     * EISCONN (tests/test-socket.c).
     */
    int connect_inflight_fd;

    /* Absolute poll_now_ms() end for an in-flight ppoll/pselect/epoll wait.
     * Survives park_reissue remounts so a guest timeout is not reset each
     * quantum. 0 = unset. Cleared when the syscall returns to the guest
     * (including injected -EINTR via sched_park_try_complete).
     */
    int64_t io_syscall_deadline_ms;

    /* Guest stack range supplied by clone3(stack, stack_size). elfuse uses this
     * to avoid tearing down a still-active child stack when another thread
     * munmaps the backing range before the child is done with its bootstrap
     * stack.
     */
    uint64_t stack_map_start;
    uint64_t stack_map_end;
    uint64_t deferred_stack_unmap_starts[MAX_DEFERRED_STACK_UNMAPS];
    uint64_t deferred_stack_unmap_ends[MAX_DEFERRED_STACK_UNMAPS];
    int deferred_stack_unmap_count;
    int deferred_stack_unmap_busy;
} thread_entry_t;

/* Explicit alias: a guest user thread is a kernel task, not a vCPU. */
typedef thread_entry_t kernel_task_t;

/* The one definition of how the lock-free-scanned signal mask is accessed.
 * Writers are the owning thread under sig_lock, plus the parent that clones a
 * child before its pthread exists; readers are the lock-free scans. Going
 * through these keeps the memory order in one place, so a new writer cannot
 * plain-store the field by omission.
 */
static inline void thread_blocked_store(thread_entry_t *t, uint64_t mask)
{
    atomic_store_explicit(&t->blocked, mask, memory_order_release);
}

static inline uint64_t thread_blocked_load(const thread_entry_t *t)
{
    return atomic_load_explicit(&t->blocked, memory_order_acquire);
}

/* The same treatment for the TID, which the lock-free scans in thread_tid_alive
 * and the /proc walkers read while thread_alloc is writing a recycled slot.
 * Relaxed is the whole requirement: the field is a value, not a gate on
 * anything else, and every caller that needs the slot's other fields reaches
 * them through the active flag's release-acquire pair.
 */
static inline int64_t thread_tid(const thread_entry_t *t)
{
    return atomic_load_explicit(&t->guest_tid, memory_order_relaxed);
}

typedef struct {
    thread_entry_t *thread;
    int64_t guest_tid;
    uint64_t start;
    uint64_t end;
    uint64_t deferred_starts[MAX_DEFERRED_STACK_UNMAPS];
    uint64_t deferred_ends[MAX_DEFERRED_STACK_UNMAPS];
    int deferred_count;
} thread_deferred_stack_unmap_txn_t;

/* Current thread pointer, set once per host pthread at thread start. All
 * syscall handlers can access per-thread state through this.
 */
extern _Thread_local thread_entry_t *current_thread;

/* Initialize the thread table. Call once before any thread operations. */
void thread_init(void);

/* Register the main thread (thread 0). Called from main.c after the initial
 * vCPU is created. Sets current_thread for the main thread.
 */
void thread_register_main(const guest_t *g,
                          hv_vcpu_t vcpu,
                          hv_vcpu_exit_t *vexit,
                          int64_t tid,
                          uint64_t sp_el1);

/* What a clone(CLONE_VM) child without CLONE_THREAD records about itself. */
typedef struct {
    int64_t parent_tid;
    int exit_signal;
} thread_vm_clone_t;

/* Allocate a new thread table slot for the given TID, a VM-clone child when
 * @vm_clone is set and a thread of the caller's group when it is NULL.
 * Returns a new task, or NULL if storage cannot be allocated. The caller
 * initializes its guest context and SP_EL1 before enqueueing it.
 */
thread_entry_t *thread_alloc(int64_t tid,
                             uint64_t stack_start,
                             uint64_t stack_end,
                             const thread_vm_clone_t *vm_clone);

/* Mark a thread as inactive and release its table slot. */
void thread_deactivate(thread_entry_t *t);
void thread_exit_task(thread_entry_t *t, guest_t *g, int wait_status);


/* Find a thread by guest TID. Returns NULL if not found. */
thread_entry_t *thread_find(int64_t tid);

/* Find a thread by guest TID with thread_lock already held by the caller.
 * Returns a pointer that stays valid only while the caller keeps thread_lock.
 * Used by the signal module to resolve a tgkill target and enqueue into its
 * private pending set atomically against slot reuse. Acquire sig_lock (4)
 * before thread_lock (5) per the documented lock order.
 */
thread_entry_t *thread_find_locked(int64_t tid);

/* Lock-free TID lookup. Safe while the caller holds sig_lock (which serializes
 * tpending writes); a racing deactivate may return a stale pointer only until
 * active clears, so callers must treat a missing/inactive slot as "gone".
 */
thread_entry_t *thread_find_relaxed(int64_t tid);

/* Lock-free check: is there an active thread with this TID?
 * Returns true if found. Safe to call without holding any lock (used from
 * futex_lock_pi to avoid lock order inversion with bucket locks). May return a
 * stale true if the thread is being deactivated concurrently; callers must
 * tolerate this.
 */
bool thread_tid_alive(int64_t tid);

/* Hold storage identity until release, including after task exit. */
thread_entry_t *thread_acquire_tid(int64_t tid);
void thread_release(thread_entry_t *t);

/* Is there an active thread with this TID that is not a VM-clone child? Takes
 * thread_lock, because is_vm_clone is one of the fields thread_alloc clears
 * with a plain memset.
 */
bool thread_tid_in_group(int64_t tid);

/* Count currently active threads. */
int thread_active_count(void);

/* Current thread-table capacity (initialized slots, including inactive). Grows
 * as clone needs more entries; use for host-side snapshot buffers.
 */
int thread_table_capacity(void);

/* OR of every active thread's private pending bitmask (thread-directed
 * signals). The signal module folds this into its global "maybe pending" hint.
 * Caller must hold sig_lock so the tpending fields are stable; the active-slot
 * scan itself takes no lock and tolerates a racing (de)activation as a harmless
 * superset.
 */
uint64_t thread_pending_union(void);

/* Active and departed thread-group CPU time; locks thread then scheduler. */
uint64_t thread_process_cputime_ns(void);
void thread_process_cputime_split_ns(uint64_t *user_ns, uint64_t *sys_ns);

/* Lock-free: first active non-vm_clone thread in SCHED_STATE_RUNNING, or 0. */
int64_t thread_find_running_tid(void);

/* Fast path: return non-zero when exactly one guest thread is active. */
int thread_is_single_active(void);

/* Allocate a per-thread SP_EL1 stack and record both the IPA and the slot index
 * into t. Thread N gets the Nth SP_EL1_SLOT_BYTES slot counting down from the
 * top of the shim data block (g->shim_data_base + 2MiB). The shim block lives
 * at high IPA computed by guest_init, so callers must pass g; the slot index is
 * stored in t->sp_el1_slot so the free path (which is reached from teardown
 * contexts that lack g) can clear the bitmask directly.
 * Returns the SP_EL1 IPA, or 0 on IPA-pool exhaustion (ENOMEM to clone).
 */
uint64_t thread_alloc_sp_el1(const guest_t *g, thread_entry_t *t);

/* The IPA range the slots above are carved from: *lo is the bottom of the
 * lowest slot, *hi one past the top of the highest, so a live SP_EL1 is in
 * [*lo, *hi).
 *
 * The shim data block holds two unrelated things. These slots sit at the top of
 * it, and the shim-globals cache -- identity slots, urandom ring, attention
 * bitmask -- starts at the bottom. A host that validates an SP_EL1 against the
 * whole block therefore accepts addresses that name cache and not stack, and
 * writing a shim frame at one of those corrupts the cache instead of reporting
 * the bad SP_EL1. Callers that write through an SP_EL1 bound it with this.
 */
void thread_sp_el1_region(const guest_t *g, uint64_t *lo, uint64_t *hi);

/* Iterate over all active threads, calling fn(entry, ctx) for each. Holds the
 * thread table lock during iteration.
 */
void thread_for_each(void (*fn)(thread_entry_t *t, void *ctx), void *ctx);
void thread_commit_exec_identity(void);
void thread_for_each_ref(void (*fn)(thread_entry_t *t, void *ctx), void *ctx);

/* True when a tracee that can still consume one owes a PTRACE_INTERRUPT stop.
 * An exited vm-clone is not one of those. Caller holds thread_lock.
 */
bool thread_ptrace_interrupt_pending_locked(void);

/* Count running VM-clone children for exec teardown checks. */
int thread_count_active_vm_clones(void);


/* Interrupt all active vCPUs by calling hv_vcpus_exit(). Used for signal
 * preemption: when a signal is queued while a vCPU is running in a tight loop
 * (no syscalls), this forces it to break out of hv_vcpu_run so the signal can
 * be delivered.
 */
void thread_interrupt_all(void);

/* Wake every thread parked anywhere it cannot see a teardown flag: futex
 * waiters, poll/epoll/read parks on the wakeup pipe, vCPUs inside hv_vcpu_run,
 * and the internal condvars. The four wakes are always needed together, so
 * exit_group teardown (launch_destroy_guest, main's run-loop exit) and execve
 * de_thread share this rather than each keeping its own list. Callers that mean
 * process teardown must set the exit-group flag first, per
 * thread_wake_exit_waiters below.
 */
void thread_wake_all_blocked(void);


/* Wake workers parked on internal condvars (fork barrier, ptrace stop/wait) so
 * exit_group teardown reaches them within a bounded time. hv_vcpus_exit only
 * interrupts threads inside hv_vcpu_run, and the wakeup pipe / futex interrupt
 * only cover guest syscall waits; a thread parked on fork_cond, ptrace_cond, or
 * resume_cond would otherwise sleep past the join cap in thread_join_workers
 * and still be live when guest memory is unmapped. Callers must set the
 * exit-group flag (proc_request_exit_group) BEFORE calling this so woken
 * waiters observe it when they re-check.
 */
void thread_wake_exit_waiters(void);

/* Check if any active thread has sigbit unblocked in its signal mask. Uses
 * relaxed reads on per-thread blocked fields; false positives (stale blocked=0)
 * cause a harmless spurious interrupt; false negatives (stale blocked=1) are
 * corrected by rt_sigprocmask re-checking pending signals after unblock. Does
 * NOT acquire thread_lock.
 */
bool thread_signal_deliverable(uint64_t sigbit);

/* Kick every other thread that has a pending signal it does not block, so one
 * parked in a futex wait re-checks now rather than when its polling quantum
 * ends. @shared_pending is the process-directed pending set. Lock-free scan;
 * safe from any thread.
 */
void thread_kick_futex_waiters(uint64_t shared_pending);

/* Fork quiesce helpers. */

/* Freeze dispatch and wait for mounted siblings to finish admitted host work.
 * Concurrent forkers join the active window before claiming their own. Caller
 * holds neither thread_lock nor mmap_lock. A successful window stays owned
 * until thread_resume_siblings; teardown, a pending FUSE service or a failed
 * freeze returns false with no window to release.
 */
bool thread_quiesce_siblings(void);

/* Resume sibling vCPUs after fork snapshot is complete. Clears the quiesce flag
 * and broadcasts the fork condvar.
 */
void thread_resume_siblings(void);

/* Owner-side gate before guest entry and host dispatch. A counted sibling
 * acknowledges once and waits until the snapshot window closes. No locks needed
 * by another task's admitted host work may be held at this gate.
 */
bool thread_fork_barrier_check(void);

/* Hand a counted sibling's slot back to an armed fork barrier when it exits or
 * fails bring-up before reaching thread_fork_barrier_check. Caller must hold
 * the thread lock (thread_get_lock()). No-op if no barrier is armed or the slot
 * was not counted. thread_deactivate calls this; paths that keep a failed slot
 * active for wait4 (vm-clone bring-up failure) must call it explicitly.
 */
void thread_fork_release_counted_locked(thread_entry_t *t);

/* execve de_thread helpers. */

/* True when an execve on another thread is tearing this one down. Callers that
 * already tested proc_exit_group_requested use this; everything else wants
 * thread_stop_requested below.
 */
int thread_exec_stop_requested(void);

/* True while thread_exec_de_thread holds the process in teardown. Unlike
 * thread_exec_stop_requested(), this does not require current_thread to be a
 * non-leader sibling; pool workers use it between mounts (current_thread NULL)
 * to refuse remounting READY tasks during de_thread.
 */
bool thread_exec_de_thread_active(void);

/* Like thread_stop_requested(), but for an arbitrary guest task @t. Park
 * interrupt/deadline callbacks run on the wake/timer thread (current_thread is
 * the waker, not @t); they must use this rather than thread_stop_requested().
 */
int thread_stop_requested_for(const thread_entry_t *t);


/* True when the calling thread must leave guest execution: a process-wide
 * exit_group was requested, or an execve is tearing this thread down. Every
 * blocking wait in a guest syscall re-checks this and returns EINTR so the run
 * loop can wind the thread down; a thread that only polled the exit-group flag
 * would keep the exec'ing thread parked in thread_exec_de_thread until the join
 * cap expired.
 */
int thread_stop_requested(void);

/* Record the syscall this thread is entering, or -1 on the way out. Relaxed:
 * the only reader is a diagnostic on a path that is already failing, and
 * ordering it against every syscall would cost the whole guest to sharpen one
 * log line.
 */
void thread_note_syscall(int nr);


/* The current task owns process teardown and survives an active exec. */
bool thread_current_is_leader(void);

/* True when the registered leader entry is still an active guest thread. After
 * SYS_exit of the leader with siblings remaining, this is false and a
 * non-leader execve must promote itself rather than hand off to a dead leader.
 */
bool thread_leader_is_active(void);

/* Make the calling thread the SoftNS leader (main_thread_entry). Used when the
 * original leader has already exited and a remaining thread must own process
 * teardown / run execve in place.
 */
void thread_promote_current_to_leader(void);

/* Thread-group leader entry (bootstrap / fork-child main). NULL before
 * thread_register_main.
 */
thread_entry_t *thread_get_main(void);

/* Drop the exec'ing thread's robust list and clear_child_tid, as Linux
 * begin_new_exec() does: both name addresses in the image that just went away.
 * Call from sys_execve after guest_reset.
 */
void thread_reset_for_exec(void);

/* Destroy every sibling guest thread on behalf of an execve, Linux de_thread().
 * Call from the exec'ing thread at the point of no return, BEFORE guest_reset:
 * siblings wind down against the old image, so their CLEARTID and robust-list
 * writes still land on the memory their guest expects.
 *
 * Returns the number of siblings still live, which is 0 unless one outlived the
 * bounded join. A non-zero return means guest memory MUST NOT be reset: that
 * thread still holds registers into the old image and would resume into the
 * zeroed one. The caller is past the point of no return, so its only safe
 * response is a diagnosed fatal exit.
 */
int thread_exec_de_thread(void);

/* Ptrace helpers. */

/* Snapshot and publish a stop; the outer loop releases the CPU worker. */
int thread_ptrace_stop(thread_entry_t *t, int sig);

/* Tracer: resume a stopped tracee with optional signal injection. */
void thread_ptrace_cont(thread_entry_t *t, int sig);
void thread_ptrace_apply_resume(thread_entry_t *t, hv_vcpu_t vcpu);
bool thread_ptrace_stop_requested(thread_entry_t *t);

/* Tracer: wait for a ptraced or vm-clone child to stop or exit.
 * Returns child TID on success, 0 on WNOHANG with none ready, or negative Linux
 * errno. Writes wait-format status to *out_status.
 */
int64_t thread_ptrace_wait(int64_t tracer_tid,
                           int pid,
                           int *out_status,
                           int options);

/* Get the thread table mutex (needed for ptrace wait blocking). */
/*@
  ensures \valid(\result);
  assigns \nothing;
 */
pthread_mutex_t *thread_get_lock(void);

/* Snapshot every active guest stack range overlapping [start, end), then record
 * a deferred-unmap entry on each one. While the transaction is live, cleanup of
 * the affected thread's deferred stack entries will block so a later rollback
 * cannot race with thread exit. On success, txns[0..nranges) contains both the
 * overlapping ranges and the pre-update deferred-unmap state needed for
 * rollback.
 * Returns the number of overlapping stack ranges, or -1 if the caller's buffer
 * is too small or any thread's deferred-unmap budget is exhausted.
 */
int thread_collect_and_defer_stack_ranges(
    uint64_t start,
    uint64_t end,
    thread_deferred_stack_unmap_txn_t *txns,
    int max_ranges);

/* Release the in-flight marker set by thread_collect_and_defer_stack_ranges()
 * after the caller has successfully completed the non-deferred munmap work.
 */
void thread_finish_deferred_stack_ranges(
    const thread_deferred_stack_unmap_txn_t *txns,
    int nranges);

/* Restore the deferred-unmap state previously captured by
 * thread_collect_and_defer_stack_ranges(), then release the in-flight marker.
 */
void thread_rollback_deferred_stack_ranges(
    const thread_deferred_stack_unmap_txn_t *txns,
    int nranges);

/* For thread exit cleanup: wait for any in-flight deferred-stack munmap
 * transaction affecting this thread to finish, then clear the live stack map
 * and snapshot the current deferred unmaps.
 *
 * Returns the number of entries copied (capped at max_ranges).
 */
int thread_prepare_deferred_stack_unmaps_for_cleanup(thread_entry_t *t,
                                                     uint64_t *starts,
                                                     uint64_t *ends,
                                                     int max_ranges);

/* Drop a single completed deferred unmap entry by exact [start, end) match.
 * Returns 1 if removed, 0 if no matching entry was found.
 */
int thread_drop_deferred_stack_unmap(thread_entry_t *t,
                                     uint64_t start,
                                     uint64_t end);
