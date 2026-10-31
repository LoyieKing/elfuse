/*
 * Time and timer syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Clock, nanosleep, gettimeofday, and interval timer operations. All functions
 * are called from syscall_dispatch() in syscall/syscall.c.
 */

#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>

#include "utils.h"

#include "core/vdso.h"
#include "runtime/thread.h" /* current_thread, guest_tid */
#include "runtime/sched/sched.h"
#include "runtime/sched/vcpu_pool.h"
#include "runtime/sched/exec.h" /* exec_restart_forbid_set */

#include "proved/timespec.h"

#include "syscall/linux-wire.h"
#include "syscall/internal.h"
#include "syscall/proc.h" /* proc_exit_group_requested, proc_get_pid */
#include "syscall/signal.h"
#include "syscall/time.h"
#include "syscall/wakeup-pipe.h"

/* Linux TIMER_ABSTIME (not defined on all macOS SDK versions) */
#ifndef TIMER_ABSTIME
#define TIMER_ABSTIME 1
#endif

/* Clock ID translation. The CPU clock encoding lives in time.h so signal.c
 * decodes the same IDs the same way.
 */

#define SLEEP_CHUNK_NS 100000000LL /* 100ms */

_Static_assert(sizeof(struct timespec) == sizeof(linux_timespec_t),
               "host and guest timespec must match on LP64");
_Static_assert(sizeof(struct timeval) == sizeof(linux_timeval_t),
               "host and guest timeval must match on LP64");

_Static_assert(NSEC_PER_SEC == TIMESPEC_NSEC_PER_SEC,
               "the proved conversions must use this tree's nanosecond scale");

bool linux_timespec_valid(const linux_timespec_t *ts)
{
    return timespec_valid(ts->tv_sec, ts->tv_nsec) != 0;
}

int64_t linux_timespec_to_ns_sat(const linux_timespec_t *ts)
{
    return timespec_to_ns_sat(ts->tv_sec, ts->tv_nsec);
}

static int64_t host_timespec_to_ns_sat(const struct timespec *ts)
{
    linux_timespec_t lts = {
        .tv_sec = ts->tv_sec,
        .tv_nsec = ts->tv_nsec,
    };
    return linux_timespec_to_ns_sat(&lts);
}

static struct timespec ns_to_host_timespec(int64_t ns)
{
    if (ns < 0)
        ns = 0;
    return (struct timespec) {
        .tv_sec = ns / NSEC_PER_SEC,
        .tv_nsec = ns % NSEC_PER_SEC,
    };
}

/* Linux aarch64 sigevent. Thread notification fields are unsupported. */
typedef struct {
    uint64_t value;
    int32_t signum, notify;
    int32_t tid; /* sigev_notify_thread_id when SIGEV_THREAD_ID */
    int32_t reserved[11];
} linux_sigevent_t;

_Static_assert(sizeof(linux_sigevent_t) == 64,
               "Linux sigevent must be 64 bytes");

int64_t sys_timer_create(guest_t *g,
                         int clockid,
                         uint64_t event_gva,
                         uint64_t id_gva)
{
    linux_sigevent_t event = {
        .signum = LINUX_SIGALRM,
        .notify = LINUX_SIGEV_SIGNAL,
    };
    if (event_gva && guest_read(g, event_gva, &event, sizeof(event)) < 0)
        return -LINUX_EFAULT;
    int32_t id =
        signal_posix_timer_create(clockid, event.notify, event.signum,
                                  event.value, event.tid, event_gva == 0);
    if (id < 0)
        return id;
    if (guest_write_small(g, id_gva, &id, sizeof(id)) < 0) {
        signal_posix_timer_delete(id);
        return -LINUX_EFAULT;
    }
    return 0;
}

int64_t sys_timer_gettime(guest_t *g, int id, uint64_t value_gva)
{
    linux_itimerspec_t value;
    int ret = signal_posix_timer_get(id, &value);
    if (ret < 0)
        return ret;
    if (guest_write(g, value_gva, &value, sizeof(value)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

int64_t sys_timer_settime(guest_t *g,
                          int id,
                          int flags,
                          uint64_t value_gva,
                          uint64_t old_gva)
{
    linux_itimerspec_t value, old;
    if (guest_read(g, value_gva, &value, sizeof(value)) < 0)
        return -LINUX_EFAULT;
    if (!timespec_valid(value.it_value_sec, value.it_value_nsec) ||
        !timespec_valid(value.it_interval_sec, value.it_interval_nsec))
        return -LINUX_EINVAL;
    int ret = signal_posix_timer_set(id, flags, &value, &old);
    if (ret < 0)
        return ret;
    if (old_gva && guest_write(g, old_gva, &old, sizeof(old)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

static int write_remaining_sleep(guest_t *g,
                                 uint64_t rem_gva,
                                 int64_t remaining_ns)
{
    if (!rem_gva)
        return 0;

    if (remaining_ns < 0)
        remaining_ns = 0;

    struct timespec rem = ns_to_host_timespec(remaining_ns);
    return guest_write_small(g, rem_gva, &rem, sizeof(rem));
}

/* Waker-side: record the remaining interval on the task. The guest write is
 * deferred to the owner worker (sleep_park_apply_pending), because the waker
 * may be the slice-timer thread and a guest write there races fork snapshot.
 */
static void sleep_record_remaining(thread_entry_t *t,
                                   uint64_t rem_gva,
                                   int64_t remaining_ns)
{
    if (!t || !rem_gva)
        return;
    t->park_rem_gva = rem_gva;
    t->park_rem_ns = remaining_ns < 0 ? 0 : remaining_ns;
    atomic_store_explicit(&t->park_rem_pending, true, memory_order_release);
}

int sleep_park_apply_pending(thread_entry_t *t, guest_t *g)
{
    if (!t || !atomic_load_explicit(&t->park_rem_pending, memory_order_acquire))
        return 0;
    atomic_store_explicit(&t->park_rem_pending, false, memory_order_relaxed);
    uint64_t rem_gva = t->park_rem_gva;
    int64_t remaining_ns = t->park_rem_ns;
    t->park_rem_gva = 0;
    t->park_rem_ns = 0;
    if (!rem_gva || !g)
        return 0;
    return write_remaining_sleep(g, rem_gva, remaining_ns) < 0 ? -LINUX_EFAULT
                                                               : 0;
}

static int64_t interruptible_sleep_ns(guest_t *g,
                                      int64_t remaining_ns,
                                      uint64_t rem_gva,
                                      bool write_rem)
{
    int64_t requested_ns = remaining_ns;

    /* Pool-managed: unmount instead of wakeup_wait_ns on the worker. */
    thread_entry_t *self = current_thread;
    if (self && remaining_ns > 0) {
        struct timespec start;
        if (clock_gettime(CLOCK_MONOTONIC, &start) < 0)
            return linux_errno();
        uint64_t start_ns =
            (uint64_t) start.tv_sec * 1000000000ULL + (uint64_t) start.tv_nsec;
        exec_park_kind_store(self, PARK_KIND_SLEEP);
        exec_park_result_pending_store(self, true);
        exec_park_reissue_store(self, false);
        self->park_guest = g;
        self->sleep_rem_gva = rem_gva;
        self->sleep_write_rem = write_rem;
        self->sleep_requested_ns = requested_ns;
        self->sleep_start_ns = (int64_t) start_ns;
        atomic_store_explicit(&self->park_rem_pending, false,
                              memory_order_relaxed);
        self->park_rem_gva = 0;
        self->park_rem_ns = 0;

        /* Publish the park last: every payload above is visible to a waker that
         * acquires park_active.
         */
        exec_park_deadline_ns_store(self, 0);
        (void) sched_park_seq_next(self);
        exec_park_active_store(self, true);
        /* Arm a quantum, not the full remaining interval. Quiet ITIMER_REAL
         * (slice-timer thread) cannot attention_raise; sleep parks must poll
         * for pending SIGALRM the way IO parks do, or clock_nanosleep would run
         * to the deadline and return 0 with rem untouched (ks-nanosleep).
         */
        {
            uint64_t abs_dl = start_ns + (uint64_t) remaining_ns;
            uint64_t wake = start_ns + (uint64_t) SLEEP_CHUNK_NS;
            if (wake > abs_dl)
                wake = abs_dl;
            {
                uint64_t td = signal_next_wall_timer_deadline_ns();
                if (td != 0 && td < wake)
                    wake = td;
            }
            sched_arm_wait_deadline(self, wake);
        }

        if (signal_pending() || proc_exit_group_requested() ||
            thread_stop_requested()) {
            exec_park_result_pending_store(self, false);
            exec_park_kind_store(self, PARK_KIND_NONE);
            self->park_guest = NULL;
            exec_park_active_store(self, false);
            sched_disarm_wait_deadline(self);
            if (write_rem &&
                write_remaining_sleep(g, rem_gva, remaining_ns) < 0)
                return -LINUX_EFAULT;
            syscall_restart_forbid();
            return -LINUX_EINTR;
        }
        return SYSCALL_PARKED;
    }

    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) < 0)
        return linux_errno();

    int64_t elapsed_ns = 0;

    while (remaining_ns > 0) {
        /* Read the wake counter before testing the predicate, not after. A wake
         * that lands in between then moves the counter and wakeup_wait_ns
         * returns without parking, instead of broadcasting to a thread that has
         * not arrived yet and being lost.
         */
        uint64_t counter = wakeup_counter();

        /* A signal and an exit_group/execve teardown end the sleep on the wake
         * that reports them. Teardown is tested before a signal is claimed,
         * because a reaped thread would take a claimed process-directed signal
         * with it.
         */

        bool stop = thread_stop_requested();
        if (stop || signal_claim_interruption()) {
            /* Only once part of a relative interval is spent, because the
             * restart re-runs the original request rather than the remainder.
             * This check also runs before the first chunk, where nothing is
             * spent and a restart costs the guest nothing, so forbidding there
             * would manufacture the EINTR no signal explains. An absolute
             * deadline (write_rem false, TIMER_ABSTIME) re-derives the same
             * instant and stays restartable throughout.
             */
            if (write_rem && remaining_ns != requested_ns)
                syscall_restart_forbid();
            if (write_rem &&
                write_remaining_sleep(g, rem_gva, remaining_ns) < 0)
                return -LINUX_EFAULT;
            return -LINUX_EINTR;
        }

        /* Bound the host wait so a teardown or signal that arrives without
         * ringing the wakeup pipe is still observed. A wake cuts the park
         * short, so this bounds the check cadence, not what the sleep waits on.
         */
        int64_t chunk_ns =
            remaining_ns < SLEEP_CHUNK_NS ? remaining_ns : SLEEP_CHUNK_NS;
        wakeup_wait_ns(chunk_ns, counter);

        /* Charge the time that actually passed. The wake is process-wide, so
         * the park also returns early on another thread's, and a condition
         * variable may return spuriously. Neither the chunk nor the request is
         * a safe measure of what was spent.
         */
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
            return linux_errno();
        elapsed_ns =
            host_timespec_to_ns_sat(&now) - host_timespec_to_ns_sat(&start);
        remaining_ns = requested_ns - elapsed_ns;
    }

    return 0;
}

/* Translate Linux wall-clock IDs to macOS. Linux: REALTIME=0, MONOTONIC=1,
 * MONOTONIC_RAW=4 macOS: REALTIME=0, MONOTONIC_RAW=4, MONOTONIC=6.
 *
 * CPU clocks are not translated here: linux_cpuclock_decode() and
 * guest_cpu_clock_ns() serve them from the scheduler ledger, including the
 * dynamic negative IDs.
 */
static int translate_clockid(int linux_clockid)
{
    switch (linux_clockid) {
    case 0:
        return CLOCK_REALTIME;
    case 1:
        return CLOCK_MONOTONIC;
    case 2:
        return CLOCK_PROCESS_CPUTIME_ID;
    case 3:
        return CLOCK_THREAD_CPUTIME_ID;
    case 4:
        return CLOCK_MONOTONIC_RAW;
    case 5:
        return CLOCK_REALTIME; /* CLOCK_REALTIME_COARSE */
    case 6:
        return CLOCK_MONOTONIC; /* CLOCK_MONOTONIC_COARSE */
    case 7:
        /* CLOCK_BOOTTIME includes suspend time on Linux; macOS exposes no
         * suspend-aware equivalent, so use monotonic time.
         */
        return CLOCK_MONOTONIC;
    case 11: /* CLOCK_TAI: no host TAI; track as realtime (leap-smear absent).
              */
        return CLOCK_REALTIME;
    default:
        /* Includes every dynamic CPU clock ID; those are decoded by
         * linux_cpuclock_decode() before this translation is reached.
         */
        return -1;
    }
}

/* Linux itimerval type. */

/* Linux struct itimerval (same layout as macOS on LP64) */
typedef struct {
    linux_timeval_t it_interval, it_value;
} linux_itimerval_t;

/* Time/timer syscall handlers. */

#define LINUX_COARSE_CLOCK_RES_NS 1000000

/* Static 2/3 and dynamic negative IDs are all CPU clocks; see time.h for the
 * encoding. Reserved type bits are rejected here, target validation is the
 * caller's.
 */
bool linux_cpuclock_decode(int clockid,
                           int *type,
                           bool *per_thread,
                           int32_t *target)
{
    if (clockid == 2 || clockid == 3) {
        *type = LINUX_CPUCLOCK_SCHED;
        *per_thread = clockid == 3;
        *target = 0;
        return true;
    }
    if (clockid >= 0)
        return false;
    int which = clockid & 3;
    if (which == 3)
        return false; /* Reserved type bits in a dynamic clock id. */
    *type = which;
    *per_thread = (clockid & LINUX_CPUCLOCK_PERTHREAD_MASK) != 0;
    *target = LINUX_CPUCLOCK_PID(clockid);
    return true;
}

/* CPU time for one clock class. VIRT counts guest execution only; PROF and
 * SCHED count guest execution plus host syscall service. Wall time is never
 * substituted: this is the same ledger the scheduler charges and POSIX CPU
 * timers read.
 */
static uint64_t cpuclock_value_ns(int type, uint64_t user_ns, uint64_t sys_ns)
{
    return type == LINUX_CPUCLOCK_VIRT ? user_ns : user_ns + sys_ns;
}

/* Returns 1 and stores the value for a CPU clock, 0 when @clockid is not a CPU
 * clock, or a negative guest errno.
 */
static int guest_cpu_clock_ns(int clockid, uint64_t *value)
{
    int type;
    bool per_thread;
    int32_t target;
    if (!linux_cpuclock_decode(clockid, &type, &per_thread, &target))
        return 0;

    uint64_t user_ns, sys_ns;
    if (!per_thread) {
        /* The domain holds one Linux thread group plus CLONE_VM processes.
         * Process clocks name this VM's process (0 = self).
         */
        if (target != 0 && target != (int32_t) proc_get_pid())
            return -LINUX_EINVAL;
        thread_process_cputime_split_ns(&user_ns, &sys_ns);
        *value = cpuclock_value_ns(type, user_ns, sys_ns);
        return 1;
    }

    if (target == 0 && current_thread)
        target = (int32_t) thread_tid(current_thread);
    if (target == 0)
        return -LINUX_EINVAL;
    thread_entry_t *task = thread_acquire_tid(target);
    if (!task)
        return -LINUX_EINVAL;

    /* Per-thread clocks name a task in this thread group; a CLONE_VM child is a
     * different process with its own ledger.
     */
    if (task->is_vm_clone) {
        thread_release(task);
        return -LINUX_EINVAL;
    }
    sched_thread_cputime_split_ns(task, &user_ns, &sys_ns);
    thread_release(task);
    *value = cpuclock_value_ns(type, user_ns, sys_ns);
    return 1;
}

static bool linux_clock_getres_fixed(int clockid, linux_timespec_t *ts)
{
    switch (clockid) {
    case 0:  /* CLOCK_REALTIME */
    case 1:  /* CLOCK_MONOTONIC */
    case 4:  /* CLOCK_MONOTONIC_RAW */
    case 7:  /* CLOCK_BOOTTIME */
    case 11: /* CLOCK_TAI */
        *ts = (linux_timespec_t) {.tv_sec = 0, .tv_nsec = 1};
        return true;
    case 5: /* CLOCK_REALTIME_COARSE */
    case 6: /* CLOCK_MONOTONIC_COARSE */
        *ts = (linux_timespec_t) {.tv_sec = 0,
                                  .tv_nsec = LINUX_COARSE_CLOCK_RES_NS};
        return true;
    default:
        return false;
    }
}

int64_t sys_clock_getres(guest_t *g, int clockid, uint64_t tp_gva)
{
    uint64_t cpu_ns;
    int cpu_clock = guest_cpu_clock_ns(clockid, &cpu_ns);
    if (cpu_clock < 0)
        return cpu_clock;
    if (cpu_clock > 0) {
        /* Linux reports a 1 ns resolution for every CPU clock regardless of the
         * host timer granularity, since the value is charged accounting.
         */
        linux_timespec_t ts = {.tv_sec = 0, .tv_nsec = 1};
        if (tp_gva && guest_write_small(g, tp_gva, &ts, sizeof(ts)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }
    int mac_clockid = translate_clockid(clockid);
    if (mac_clockid < 0)
        return -LINUX_EINVAL;

    /* Linux permits NULL here as a clock-id validation query. */
    if (!tp_gva)
        return 0;

    linux_timespec_t ts;
    if (!linux_clock_getres_fixed(clockid, &ts)) {
        struct timespec host_ts;
        if (clock_getres(mac_clockid, &host_ts) < 0)
            return linux_errno();
        ts = (linux_timespec_t) {
            .tv_sec = host_ts.tv_sec,
            .tv_nsec = host_ts.tv_nsec,
        };
    }

    if (guest_write_small(g, tp_gva, &ts, sizeof(ts)) < 0)
        return -LINUX_EFAULT;

    return 0;
}

int64_t sys_clock_gettime(guest_t *g, int clockid, uint64_t tp_gva)
{
    uint64_t cpu_ns;
    int cpu_clock = guest_cpu_clock_ns(clockid, &cpu_ns);
    if (cpu_clock < 0)
        return cpu_clock;
    if (cpu_clock > 0) {
        linux_timespec_t ts = {
            .tv_sec = (int64_t) (cpu_ns / 1000000000ULL),
            .tv_nsec = (int64_t) (cpu_ns % 1000000000ULL),
        };
        return guest_write_small(g, tp_gva, &ts, sizeof(ts)) < 0 ? -LINUX_EFAULT
                                                                 : 0;
    }
    int mac_clockid = translate_clockid(clockid);
    if (mac_clockid < 0)
        return -LINUX_EINVAL;

    /* When the trap came from the __kernel_clock_gettime vDSO svc_fallback, the
     * trampoline parked the guest's CNTVCT_EL0 read in X9 before SVC, and
     * ELR_EL1 holds SVC_PC + 4. Use X9 to seed (or refresh) the vvar anchor so
     * subsequent calls hit the fast path. Reject any other trap: X9 would then
     * be arbitrary guest state and seeding from it would poison the anchor.
     *
     * Order matters: read X9 first, then sample host wall clocks back-to-back,
     * then write the guest result and seed. Sampling host clocks before
     * checking X9 would bake a permanent positive bias into the anchor from the
     * HVF round-trip in the seeding gate.
     */
    hv_vcpu_t vcpu = 0;
    bool from_trampoline = (clockid == 0 /* CLOCK_REALTIME */ ||
                            clockid == 1 /* CLOCK_MONOTONIC */) &&
                           current_thread && vcpu_pool_current_vcpu(&vcpu);

    uint64_t guest_cntvct = 0;
    if (from_trampoline) {
        uint64_t elr = 0;
        if (hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &elr) != HV_SUCCESS ||
            elr != vdso_clock_gettime_svc_pc() + 4 ||
            hv_vcpu_get_reg(vcpu, HV_REG_X9, &guest_cntvct) != HV_SUCCESS ||
            guest_cntvct == 0)
            from_trampoline = false;
    }

    struct timespec ts;
    if (clock_gettime(mac_clockid, &ts) < 0)
        return linux_errno();

    /* Sample the OTHER clockid back-to-back so both anchor pairs reflect
     * roughly the same host moment. If the second clock_gettime fails
     * (defensive; unreachable on macOS), skip seeding rather than fail the
     * user's request.
     */
    struct timespec ts_other;
    bool can_seed = false;
    if (from_trampoline) {
        int other_mac = (clockid == 1) ? CLOCK_REALTIME : CLOCK_MONOTONIC;
        if (clock_gettime(other_mac, &ts_other) == 0)
            can_seed = true;
    }

    if (guest_write_small(g, tp_gva, &ts, sizeof(ts)) < 0)
        return -LINUX_EFAULT;

    if (can_seed) {
        const struct timespec *ts_mono = (clockid == 1) ? &ts : &ts_other;
        const struct timespec *ts_real = (clockid == 0) ? &ts : &ts_other;

        /* Publish when the vvar is unseeded, has aged out, or has drifted
         * relative to the freshly-sampled REALTIME (catches macOS NTP steps).
         */
        if (!vdso_anchor_is_seeded(g) ||
            vdso_anchor_age_exceeded(g, guest_cntvct) ||
            vdso_realtime_drift_exceeded(g, guest_cntvct, ts_real->tv_sec,
                                         ts_real->tv_nsec))
            vdso_seed_anchor(g, guest_cntvct, ts_mono->tv_sec, ts_mono->tv_nsec,
                             ts_real->tv_sec, ts_real->tv_nsec);
    }

    return 0;
}

/* Interruptible nanosleep: break long sleeps into 100ms chunks so exit_group
 * and pending signals can be checked periodically. Without this, a thread
 * blocked in a multi-second nanosleep cannot be interrupted by exit_group
 * because hv_vcpus_exit only breaks hv_vcpu_run, not host-side blocking
 * syscalls.
 */
int64_t sys_nanosleep(guest_t *g, uint64_t req_gva, uint64_t rem_gva)
{
    linux_timespec_t lreq;
    if (guest_read_small(g, req_gva, &lreq, sizeof(lreq)) < 0)
        return -LINUX_EFAULT;

    if (!linux_timespec_valid(&lreq))
        return -LINUX_EINVAL;

    return interruptible_sleep_ns(g, linux_timespec_to_ns_sat(&lreq), rem_gva,
                                  true);
}

int64_t sys_clock_nanosleep(guest_t *g,
                            int clockid,
                            int flags,
                            uint64_t req_gva,
                            uint64_t rem_gva)
{
    linux_timespec_t lreq;
    if (guest_read_small(g, req_gva, &lreq, sizeof(lreq)) < 0)
        return -LINUX_EFAULT;

    if (flags & ~TIMER_ABSTIME)
        return -LINUX_EINVAL;

    /* Linux's hrtimer_nanosleep_clockid validates the timespec via
     * timespec64_valid_strict() (kernel/time/hrtimer.c) before deciding whether
     * the absolute deadline has expired. Negative tv_sec is rejected with
     * EINVAL even when TIMER_ABSTIME is set, not silently treated as 'already
     * expired'. Reject negative tv_sec unconditionally so both relative and
     * absolute callers match the kernel contract.
     */
    if (!linux_timespec_valid(&lreq))
        return -LINUX_EINVAL;

    /* A POSIX CPU clock measures consumed CPU time, so it has no wait
     * operation. Linux rejects it here even though timer_create accepts the
     * same clock IDs.
     */
    int cpu_type;
    bool cpu_per_thread;
    int32_t cpu_target;
    if (linux_cpuclock_decode(clockid, &cpu_type, &cpu_per_thread, &cpu_target))
        return -LINUX_EINVAL;


    int mac_clockid = translate_clockid(clockid);
    if (mac_clockid < 0)
        return -LINUX_EINVAL;

    int64_t remaining_ns;

    if (flags & TIMER_ABSTIME) {
        struct timespec now;
        if (clock_gettime(mac_clockid, &now) < 0)
            return linux_errno();

        int64_t target_ns = linux_timespec_to_ns_sat(&lreq);
        int64_t now_ns = host_timespec_to_ns_sat(&now);
        int64_t delta_ns = target_ns - now_ns;
        if (delta_ns <= 0)
            return 0; /* Already past */
        remaining_ns = delta_ns;
    } else {
        remaining_ns = linux_timespec_to_ns_sat(&lreq);
    }

    return interruptible_sleep_ns(g, remaining_ns, rem_gva,
                                  (flags & TIMER_ABSTIME) == 0);
}

int64_t sys_gettimeofday(guest_t *g, uint64_t tv_gva, uint64_t tz_gva)
{
    thread_entry_t *self = current_thread;
    hv_vcpu_t vcpu = 0;
    bool from_trampoline = self != NULL && vcpu_pool_current_vcpu(&vcpu);
    uint64_t guest_cntvct = 0;
    if (from_trampoline) {
        uint64_t elr = 0;
        if (hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &elr) != HV_SUCCESS ||
            elr != vdso_gettimeofday_svc_pc() + 4 ||
            hv_vcpu_get_reg(vcpu, HV_REG_X9, &guest_cntvct) != HV_SUCCESS ||
            guest_cntvct == 0)
            from_trampoline = false;
    }

    struct timeval tv;
    if (gettimeofday(&tv, NULL) < 0)
        return linux_errno();

    struct timespec ts_mono;
    struct timespec ts_real;
    bool can_seed = false;
    if (from_trampoline && clock_gettime(CLOCK_MONOTONIC, &ts_mono) == 0 &&
        clock_gettime(CLOCK_REALTIME, &ts_real) == 0)
        can_seed = true;

    linux_timeval_t ltv = {
        .tv_sec = tv.tv_sec,
        .tv_usec = tv.tv_usec,
    };
    if (tv_gva && guest_write_small(g, tv_gva, &ltv, sizeof(ltv)) < 0)
        return -LINUX_EFAULT;

    /* tz is obsolete on Linux but the kernel still zeroes a non-null pointer
     * (struct timezone has two int32 fields, 8 bytes total). Matching the vDSO
     * fast path's STR XZR, [tz] here keeps SVC and fast-path callers
     * observationally identical.
     */
    if (tz_gva) {
        const uint64_t tz_zero = 0;
        if (guest_write_small(g, tz_gva, &tz_zero, sizeof(tz_zero)) < 0)
            return -LINUX_EFAULT;
    }

    if (can_seed && (!vdso_anchor_is_seeded(g) ||
                     vdso_anchor_age_exceeded(g, guest_cntvct) ||
                     vdso_realtime_drift_exceeded(
                         g, guest_cntvct, ts_real.tv_sec, ts_real.tv_nsec)))
        vdso_seed_anchor(g, guest_cntvct, ts_mono.tv_sec, ts_mono.tv_nsec,
                         ts_real.tv_sec, ts_real.tv_nsec);

    return 0;
}

/* Linux struct tms: four clock_t fields (long on LP64) counting USER_HZ ticks.
 */
typedef struct {
    int64_t tms_utime;
    int64_t tms_stime;
    int64_t tms_cutime;
    int64_t tms_cstime;
} linux_tms_t;

/* Kernel USER_HZ, the unit of clock_t values returned by times(). Must match
 * the AT_CLKTCK auxv entry in core/stack.c: libc divides these raw tick counts
 * by sysconf(_SC_CLK_TCK), so a mismatch silently rescales every value.
 */
#define LINUX_USER_HZ 100

/* The scheduler ledger and the proc-layer child accumulator both count
 * nanoseconds; times() reports USER_HZ ticks.
 */
static int64_t usec_to_clock_ticks(uint64_t usec)
{
    return (int64_t) (usec / (1000000ULL / LINUX_USER_HZ));
}

static int64_t ns_to_clock_ticks(uint64_t ns)
{
    return (int64_t) (ns / (NSEC_PER_SEC / LINUX_USER_HZ));
}

int64_t sys_times(guest_t *g, uint64_t buf_gva)
{
    /* Linux permits a NULL buffer: only the return value (elapsed ticks) is
     * wanted. Self time is the guest-thread-group ledger the scheduler also
     * feeds the CPU clocks and POSIX CPU timers, including runtime retained for
     * departed members. cutime/cstime come from the proc-layer accumulator fed
     * at each guest-child reap, not from RUSAGE_CHILDREN: the emulator also
     * waits on helper subprocesses (rosettad translate, sysroot tooling) whose
     * CPU would otherwise masquerade as guest child time.
     */
    if (buf_gva) {
        uint64_t utime_ns, stime_ns;
        thread_process_cputime_split_ns(&utime_ns, &stime_ns);

        uint64_t cutime_us, cstime_us;
        proc_children_cpu_us(&cutime_us, &cstime_us);

        linux_tms_t tms = {
            .tms_utime = ns_to_clock_ticks(utime_ns),
            .tms_stime = ns_to_clock_ticks(stime_ns),
            .tms_cutime = usec_to_clock_ticks(cutime_us),
            .tms_cstime = usec_to_clock_ticks(cstime_us),
        };
        if (guest_write_small(g, buf_gva, &tms, sizeof(tms)) < 0)
            return -LINUX_EFAULT;
    }

    /* Linux returns jiffies-since-boot converted to clock_t ticks; POSIX only
     * requires an arbitrary-but-fixed reference point, so host CLOCK_MONOTONIC
     * satisfies callers that difference successive returns.
     */
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return linux_errno();
    return (int64_t) ts.tv_sec * LINUX_USER_HZ +
           ts.tv_nsec / (NSEC_PER_SEC / LINUX_USER_HZ);
}

int64_t sys_setitimer(guest_t *g, int which, uint64_t new_gva, uint64_t old_gva)
{
    /* Linux reads new_gva before dispatching on which, so an invalid pointer
     * takes precedence over an invalid which value (EFAULT > EINVAL).
     */
    linux_itimerval_t lnew;
    bool has_new = false;
    if (new_gva) {
        if (guest_read_small(g, new_gva, &lnew, sizeof(lnew)) < 0)
            return -LINUX_EFAULT;

        /* Linux rejects tv_usec outside [0, 999999] AND negative tv_sec for
         * both value and interval. Accepting a negative tv_sec would cast
         * through (long) below and arm an expired timer instead of returning
         * EINVAL, diverging from the kernel contract.
         */
        if (!RANGE_CHECK(lnew.it_value.tv_usec, 0, 1000000) ||
            !RANGE_CHECK(lnew.it_interval.tv_usec, 0, 1000000) ||
            (int64_t) lnew.it_value.tv_sec < 0 ||
            (int64_t) lnew.it_interval.tv_sec < 0)
            return -LINUX_EINVAL;
        has_new = true;
    }

    if (which != 0 && which != 1 && which != 2)
        return -LINUX_EINVAL;

    struct timeval val = {0}, itv = {0};
    if (has_new) {
        val = (struct timeval) {.tv_sec = (long) lnew.it_value.tv_sec,
                                .tv_usec = (int) lnew.it_value.tv_usec};
        itv = (struct timeval) {.tv_sec = (long) lnew.it_interval.tv_sec,
                                .tv_usec = (int) lnew.it_interval.tv_usec};
    }

    struct timeval old_val = {0}, old_itv = {0};
    struct timeval *new_val_p = has_new ? &val : NULL;
    struct timeval *new_itv_p = has_new ? &itv : NULL;
    struct timeval *old_val_p = old_gva ? &old_val : NULL;
    struct timeval *old_itv_p = old_gva ? &old_itv : NULL;

    /* ITIMER_REAL is emulated internally because macOS shares alarm() and
     * setitimer(ITIMER_REAL) as the same underlying timer, and elfuse needs
     * that timer for its execution watchdog. ITIMER_VIRTUAL/PROF must also be
     * emulated since SIGVTALRM/SIGPROF would otherwise hit the host process.
     */
    if (which == 0)
        signal_set_itimer(new_val_p, new_itv_p, old_val_p, old_itv_p);
    else
        signal_set_itimer_virt(which, new_val_p, new_itv_p, old_val_p,
                               old_itv_p);

    if (old_gva) {
        linux_itimerval_t lold = {
            .it_interval = {.tv_sec = old_itv.tv_sec,
                            .tv_usec = old_itv.tv_usec},
            .it_value = {.tv_sec = old_val.tv_sec, .tv_usec = old_val.tv_usec},
        };
        if (guest_write_small(g, old_gva, &lold, sizeof(lold)) < 0)
            return -LINUX_EFAULT;
    }
    return 0;
}

int64_t sys_getitimer(guest_t *g, int which, uint64_t val_gva)
{
    /* ITIMER_REAL/VIRTUAL/PROF are all emulated internally (see sys_setitimer
     * comment).
     */
    struct timeval val = {0}, itv = {0};
    if (which == 0)
        signal_get_itimer(&val, &itv);
    else if (which == 1 || which == 2)
        signal_get_itimer_virt(which, &val, &itv);
    else
        return -LINUX_EINVAL;

    linux_itimerval_t lval = {
        .it_interval = {.tv_sec = itv.tv_sec, .tv_usec = itv.tv_usec},
        .it_value = {.tv_sec = val.tv_sec, .tv_usec = val.tv_usec},
    };
    if (guest_write_small(g, val_gva, &lval, sizeof(lval)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

void sleep_park_on_deadline(thread_entry_t *t)
{
    if (!t || !exec_park_active_load(t) ||
        exec_park_kind_load(t) != PARK_KIND_SLEEP)
        return;
    uint64_t seq = sched_park_seq(t);
    if (seq == 0)
        return;

    /* Mirror io_park_on_deadline: materialize ITIMER_REAL into pending SIGALRM
     * with the quiet variant (this runs on the slice-timer thread). Then claim
     * or re-arm a quantum until the absolute sleep end.
     */
    signal_check_timer_real_quiet();

    bool teardown = thread_stop_requested_for(t);
    if (teardown || signal_claim_interruption_for_ex(t, false)) {
        /* Claim already consumed the waking signal; do not call
         * sleep_park_on_interrupt (it would claim again and stay parked).
         */
        uint64_t rem_gva = t->sleep_rem_gva;
        bool write_rem = t->sleep_write_rem;
        int64_t requested = t->sleep_requested_ns;
        int64_t start_ns = t->sleep_start_ns;

        struct timespec now;
        int64_t remaining = 0;
        if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
            int64_t now_ns =
                (int64_t) now.tv_sec * 1000000000LL + (int64_t) now.tv_nsec;
            remaining = requested - (now_ns - start_ns);
            if (remaining < 0)
                remaining = 0;
        }

        /* Slice-timer context: record the remainder for the owner to write.
         * Writing guest memory here would race a fork snapshot.
         */
        if (write_rem)
            sleep_record_remaining(t, rem_gva, remaining);

        /* This runs on the slice-timer thread, whose current_thread is not the
         * sleeper. Record the opt-out on the target task;
         * syscall_restart_forbid would write the waker's TLS and leave the
         * sleeper restartable.
         */
        exec_restart_forbid_set(t, true);
        sched_park_try_complete_seq(t, PARK_KIND_SLEEP, seq, -LINUX_EINTR);
        return;
    }

    struct timespec now_ts;
    if (clock_gettime(CLOCK_MONOTONIC, &now_ts) < 0) {
        sched_park_try_complete_seq(t, PARK_KIND_SLEEP, seq, 0);
        return;
    }
    uint64_t now =
        (uint64_t) now_ts.tv_sec * 1000000000ULL + (uint64_t) now_ts.tv_nsec;
    uint64_t abs_dl =
        (uint64_t) t->sleep_start_ns + (uint64_t) t->sleep_requested_ns;
    if (now >= abs_dl) {
        sched_park_try_complete_seq(t, PARK_KIND_SLEEP, seq, 0);
        return;
    }

    uint64_t wake = now + (uint64_t) SLEEP_CHUNK_NS;
    if (wake > abs_dl)
        wake = abs_dl;
    {
        uint64_t td = signal_next_wall_timer_deadline_ns();
        if (td != 0 && td < wake)
            wake = td;
    }
    if (exec_park_active_load(t) && exec_park_kind_load(t) == PARK_KIND_SLEEP &&
        sched_park_seq(t) == seq)
        sched_arm_wait_deadline(t, wake);
}

void sleep_park_on_interrupt(thread_entry_t *t)
{
    if (!t || !exec_park_active_load(t) ||
        exec_park_kind_load(t) != PARK_KIND_SLEEP)
        return;
    uint64_t seq = sched_park_seq(t);
    if (seq == 0)
        return;

    /* Linux complete_signal() interrupts one thread for a process-directed
     * signal. A host wake may reach every parked sleeper; only the thread that
     * claims the waking signal may leave with -EINTR. Others stay parked
     * (re-park) until their deadline or a later claimable wake. Teardown still
     * forces completion without a claim. Waker thread: use for(t), not
     * thread_stop_requested().
     */
    bool teardown = thread_stop_requested_for(t);
    if (!teardown && !signal_claim_interruption_for(t))
        return;

    uint64_t rem_gva = t->sleep_rem_gva;
    bool write_rem = t->sleep_write_rem;
    int64_t requested = t->sleep_requested_ns;
    int64_t start_ns = t->sleep_start_ns;

    struct timespec now;
    int64_t remaining = 0;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        int64_t now_ns =
            (int64_t) now.tv_sec * 1000000000LL + (int64_t) now.tv_nsec;
        remaining = requested - (now_ns - start_ns);
        if (remaining < 0)
            remaining = 0;
    }

    /* Waker context: record, do not write guest memory (fork snapshot). */
    if (write_rem)
        sleep_record_remaining(t, rem_gva, remaining);

    /* Waker context: the opt-out belongs to @t, never to this thread's TLS. */
    exec_restart_forbid_set(t, true);
    sched_park_try_complete_seq(t, PARK_KIND_SLEEP, seq, -LINUX_EINTR);
}


/* Linux aarch64 struct timex (uapi/linux/timex.h). Soft-accept queries. */
typedef struct {
    unsigned int modes;
    long offset;
    long freq;
    long maxerror;
    long esterror;
    int status;
    long constant;
    long precision;
    long tolerance;
    linux_timeval_t time;
    long tick;
    long ppsfreq;
    long jitter;
    int shift;
    long stabil;
    long jitcnt;
    long calcnt;
    long errcnt;
    long stbcnt;
    int tai;
    int pad[11];
} linux_timex_t;

#define LINUX_TIME_OK 0
#define LINUX_ADJ_OFFSET 0x0001
#define LINUX_ADJ_FREQUENCY 0x0002
#define LINUX_ADJ_MAXERROR 0x0004
#define LINUX_ADJ_ESTERROR 0x0008
#define LINUX_ADJ_STATUS 0x0010
#define LINUX_ADJ_TIMECONST 0x0020
#define LINUX_ADJ_TAI 0x0080
#define LINUX_ADJ_SETOFFSET 0x0100
#define LINUX_ADJ_MICRO 0x1000
#define LINUX_ADJ_NANO 0x2000
#define LINUX_ADJ_TICK 0x4000

/* Modes that would change the host clock; SoftNS refuses them. */
#define LINUX_ADJ_SETTERS                                      \
    (LINUX_ADJ_OFFSET | LINUX_ADJ_FREQUENCY | LINUX_ADJ_TICK | \
     LINUX_ADJ_SETOFFSET | LINUX_ADJ_TAI | LINUX_ADJ_STATUS |  \
     LINUX_ADJ_TIMECONST | LINUX_ADJ_MAXERROR | LINUX_ADJ_ESTERROR)

static int64_t adjtimex_fill(guest_t *g, uint64_t tx_gva)
{
    linux_timex_t tx;
    if (!tx_gva || guest_read(g, tx_gva, &tx, sizeof(tx)) < 0)
        return -LINUX_EFAULT;
    if (tx.modes & LINUX_ADJ_SETTERS)
        return -LINUX_EPERM;

    struct timeval tv;
    if (gettimeofday(&tv, NULL) < 0)
        return linux_errno();

    /* Soft-accept: report an undisciplined 100 Hz clock (matches CLK_TCK=100
     * glibc default). freq=0 and tick=10000 keep raw_skew's ppm math at 0.
     */
    tx.offset = 0;
    tx.freq = 0;
    tx.maxerror = 0;
    tx.esterror = 0;
    tx.status = 0;
    tx.constant = 0;
    tx.precision = 1;
    tx.tolerance = 0;
    tx.time.tv_sec = (int64_t) tv.tv_sec;
    tx.time.tv_usec = (int64_t) tv.tv_usec;
    tx.tick = 10000; /* usec per tick at 100 Hz */
    tx.ppsfreq = 0;
    tx.jitter = 0;
    tx.shift = 0;
    tx.stabil = 0;
    tx.jitcnt = 0;
    tx.calcnt = 0;
    tx.errcnt = 0;
    tx.stbcnt = 0;
    tx.tai = 0;
    if (guest_write(g, tx_gva, &tx, sizeof(tx)) < 0)
        return -LINUX_EFAULT;
    return LINUX_TIME_OK;
}

int64_t sys_adjtimex(guest_t *g, uint64_t tx_gva)
{
    return adjtimex_fill(g, tx_gva);
}

int64_t sys_clock_adjtime(guest_t *g, int clockid, uint64_t tx_gva)
{
    /* Soft-accept only REALTIME / REALTIME_ALARM-class clocks; others EINVAL.
     */
    if (clockid != 0 && clockid != 5 && clockid != 8 /* REALTIME_ALARM */)
        return -LINUX_EINVAL;
    return adjtimex_fill(g, tx_gva);
}
