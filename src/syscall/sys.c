/*
 * System info and identity syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Uname, getrandom, getcwd, sched_getaffinity, getgroups, getrusage, sysinfo,
 * and prlimit64. All functions are called from syscall_dispatch() in
 * syscall/syscall.c.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/random.h>
#include <stdlib.h>
#include <mach/mach.h>

#include "utils.h"

#include "proved/slice.h"

#include "core/shim-globals.h"
#include "runtime/thread.h"
#include "runtime/sched/sched.h"
#include "syscall/linux-wire.h"
#include "syscall/internal.h"
#include "syscall/proc.h"
#include "syscall/proc-pidfd.h"
#include "syscall/signal.h"
#include "syscall/sys.h"

/* System info syscall handlers. */

static pthread_once_t groups_once = PTHREAD_ONCE_INIT;
static uint32_t cached_linux_groups[64];
static int cached_ngroups = -1;
static const linux_utsname_t cached_uname = {
    .sysname = "Linux",
    .nodename = "elfuse",
    .release = GUEST_KERNEL_RELEASE,
    .version = GUEST_KERNEL_VERSION,
    .machine = "aarch64",
    .domainname = "(none)",
};

/* Physical memory to report when sysctl(HW_MEMSIZE) fails. Reporting zero is
 * not an option: a guest computing used = total - free - cached against a zero
 * total wraps, which is the failure sys_guest_ram_bytes() exists to prevent.
 * The figure is one captured from a 4 GiB VZ VM, so the fallback describes a
 * machine that plausibly exists.
 */
#define GUEST_RAM_FALLBACK_BYTES 4094595072ULL

/* sysinfo cache.
 *
 * Process-scoped by intent: the cache mirrors the host's view (totalram from
 * sysctl(HW_MEMSIZE), free pages from host_statistics64, getloadavg). Even if
 * multiple guest_t instances ever coexist in one process they share the same
 * host stats, so a single rwlock-protected cache refreshed at most once per
 * second is the right shape. Deliberately not moved into guest_t.
 */
static pthread_once_t sysinfo_once = PTHREAD_ONCE_INIT;
static pthread_rwlock_t sysinfo_lock = PTHREAD_RWLOCK_INITIALIZER;
static time_t cached_boottime_sec = 0;
static uint64_t cached_totalram = 0;
static uint64_t cached_page_size = 0;
static mach_port_t cached_host_port = MACH_PORT_NULL;
static time_t cached_sysinfo_sec = -1;
static linux_sysinfo_t cached_sysinfo;

/* The full-size assertion lives with write_rusage_to_guest() in proc.c; this
 * offset check guards the fast memcpy translation done there.
 */
_Static_assert(offsetof(struct rusage, ru_maxrss) ==
                   offsetof(linux_rusage_t, ru_maxrss),
               "ru_maxrss offset must stay aligned for fast translation");

static void groups_init_cached_linux_groups(void)
{
    gid_t groups[64];
    int ngroups = getgroups(64, groups);
    if (ngroups < 0)
        return;

    for (int i = 0; i < ngroups; i++)
        cached_linux_groups[i] = (uint32_t) groups[i];
    cached_ngroups = ngroups;
}

static void sysinfo_init_cached_host_state(void)
{
    struct timeval boottime;
    size_t bt_len = sizeof(boottime);
    int mib_bt[2] = {CTL_KERN, KERN_BOOTTIME};
    if (sysctl(mib_bt, 2, &boottime, &bt_len, NULL, 0) == 0)
        cached_boottime_sec = boottime.tv_sec;

    uint64_t memsize = 0;
    size_t ms_len = sizeof(memsize);
    int mib_mem[2] = {CTL_HW, HW_MEMSIZE};
    if (sysctl(mib_mem, 2, &memsize, &ms_len, NULL, 0) != 0 || memsize == 0)
        memsize = GUEST_RAM_FALLBACK_BYTES;
    cached_totalram = memsize;

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size > 0)
        cached_page_size = (uint64_t) page_size;

    cached_host_port = mach_host_self();
}

static void sysinfo_refresh_cached_locked(time_t now_sec)
{
    memset(&cached_sysinfo, 0, sizeof(cached_sysinfo));
    cached_sysinfo.totalram = cached_totalram;
    cached_sysinfo.mem_unit = 1;
    cached_sysinfo.procs = 1; /* Single-process model */

    if (cached_boottime_sec != 0)
        cached_sysinfo.uptime = now_sec - cached_boottime_sec;

    /* Free RAM from vm_statistics64, held below the total unconditionally so
     * that every reader of the pair -- here and /proc/meminfo -- can subtract
     * one from the other without checking.
     */
    vm_statistics64_data_t vmstat = {0};
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    if (cached_host_port != MACH_PORT_NULL &&
        host_statistics64(cached_host_port, HOST_VM_INFO64,
                          (host_info64_t) &vmstat, &count) == KERN_SUCCESS) {
        uint64_t free_bytes = (uint64_t) vmstat.free_count * cached_page_size;
        cached_sysinfo.freeram =
            free_bytes > cached_totalram ? cached_totalram : free_bytes;
    }

    /* Load averages (x 65536 for fixed-point). */
    double loadavg[3];
    if (getloadavg(loadavg, 3) == 3) {
        cached_sysinfo.loads[0] = (uint64_t) (loadavg[0] * 65536.0);
        cached_sysinfo.loads[1] = (uint64_t) (loadavg[1] * 65536.0);
        cached_sysinfo.loads[2] = (uint64_t) (loadavg[2] * 65536.0);
    }

    cached_sysinfo_sec = now_sec;
}

/* Copy out the cached sysinfo, refreshing it first if it has aged past a
 * second. Every guest-visible memory figure comes through here, so that a guest
 * reading two surfaces back to back reads one snapshot rather than two samples.
 */
static void sysinfo_snapshot(linux_sysinfo_t *out)
{
    pthread_once(&sysinfo_once, sysinfo_init_cached_host_state);
    time_t now_sec = time(NULL);

    if (thread_is_single_active()) {
        if (cached_sysinfo_sec != now_sec)
            sysinfo_refresh_cached_locked(now_sec);
        *out = cached_sysinfo;
        return;
    }

    pthread_rwlock_rdlock(&sysinfo_lock);
    if (cached_sysinfo_sec == now_sec) {
        *out = cached_sysinfo;
        pthread_rwlock_unlock(&sysinfo_lock);
        return;
    }
    pthread_rwlock_unlock(&sysinfo_lock);

    pthread_rwlock_wrlock(&sysinfo_lock);
    if (cached_sysinfo_sec != now_sec)
        sysinfo_refresh_cached_locked(now_sec);
    *out = cached_sysinfo;
    pthread_rwlock_unlock(&sysinfo_lock);
}

uint64_t sys_guest_ram_bytes(void)
{
    pthread_once(&sysinfo_once, sysinfo_init_cached_host_state);
    return cached_totalram;
}

uint64_t sys_guest_ram_free(void)
{
    linux_sysinfo_t si;
    sysinfo_snapshot(&si);
    return si.freeram; /* mem_unit is 1, so freeram is already bytes */
}

static int get_cached_linux_groups(void)
{
    if (thread_is_single_active()) {
        if (cached_ngroups >= 0)
            return cached_ngroups;
        groups_init_cached_linux_groups();
        return cached_ngroups;
    }

    pthread_once(&groups_once, groups_init_cached_linux_groups);
    return cached_ngroups;
}

int64_t sys_uname(guest_t *g, uint64_t buf_gva)
{
    if (guest_write_small(g, buf_gva, &cached_uname, sizeof(cached_uname)) < 0)
        return -LINUX_EFAULT;

    return 0;
}

/* Linux getrandom(2) flags. arc4random_buf is always non-blocking and always
 * seeded, so GRND_NONBLOCK / GRND_RANDOM / GRND_INSECURE all collapse to the
 * same behavior here. Unknown flag bits must still return EINVAL per kernel
 * behavior (kernel/random.c rejects flags & ~SUPPORTED_FLAGS) so callers do not
 * silently fossilize wrong assumptions about the elfuse implementation.
 */
#define LINUX_GRND_NONBLOCK 0x0001
#define LINUX_GRND_RANDOM 0x0002
#define LINUX_GRND_INSECURE 0x0004
#define LINUX_GRND_SUPPORTED_MASK \
    (LINUX_GRND_NONBLOCK | LINUX_GRND_RANDOM | LINUX_GRND_INSECURE)

int64_t sys_getrandom(guest_t *g,
                      uint64_t buf_gva,
                      uint64_t buflen,
                      unsigned int flags)
{
    if (flags & ~LINUX_GRND_SUPPORTED_MASK)
        return -LINUX_EINVAL;
    if ((flags & (LINUX_GRND_RANDOM | LINUX_GRND_INSECURE)) ==
        (LINUX_GRND_RANDOM | LINUX_GRND_INSECURE))
        return -LINUX_EINVAL;
    if (buflen == 0)
        return 0;
    if (buf_gva > UINT64_MAX - buflen)
        return -LINUX_EFAULT;

    /* arc4random_buf takes a libc lock, so it cannot be handed a guest pointer:
     * see the lock rule on HOST_SIGBUS_GUARD. Stage, then let guest_write do
     * the copy inside the pad.
     */
    uint8_t stage[512];
    uint64_t offset = 0, chunk;
    while (slice_clamp(buflen, offset, sizeof(stage), &chunk)) {
        arc4random_buf(stage, (size_t) chunk);
        if (guest_write(g, buf_gva + offset, stage, (size_t) chunk) < 0)
            return -LINUX_EFAULT;
        offset += chunk;
    }

    shim_globals_refill_urandom_ring(g);
    return (int64_t) buflen;
}

int64_t sys_getcwd(guest_t *g, uint64_t buf_gva, uint64_t size)
{
    proc_cwd_view_t view;
    if (proc_acquire_cwd_view(&view) < 0)
        return linux_errno();

    size_t write_len = view.len + 1;
    if (write_len > size) {
        proc_release_cwd_view(&view);
        return -LINUX_ERANGE;
    }

    int rc = guest_write_small(g, buf_gva, view.path, write_len);
    proc_release_cwd_view(&view);
    if (rc < 0)
        return -LINUX_EFAULT;

    return (int64_t) write_len;
}

int64_t sys_getcpu(guest_t *g,
                   uint64_t cpu_gva,
                   uint64_t node_gva,
                   uint64_t cache_gva)
{
    (void) cache_gva;

    /* CPU index matches the fair-scheduler pool slot (and rseq cpu_id). Single
     * NUMA node 0. The obsolete third cache argument is ignored.
     */
    uint32_t cpu = (uint32_t) sched_thread_cpu(current_thread);
    uint32_t node = 0;
    if (cpu_gva && guest_write_small(g, cpu_gva, &cpu, sizeof(cpu)) < 0)
        return -LINUX_EFAULT;
    if (node_gva && guest_write_small(g, node_gva, &node, sizeof(node)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* Linux scheduling ABI
 *
 * The kernel ABI is per-task: the pid argument names a TID, and pid 0 means the
 * calling task. All state lives in the task's embedded sched_task_state_t and
 * is read/written only through runtime/sched (sched_task_*). Queries read the
 * same base attributes the selector uses; the execution backend consumes
 * reschedule requests after the syscall return path.
 *
 * Task-directed control of a fork backend uses the pidfd scheduler RPC; unknown
 * TIDs return ESRCH. Group/user priority sweeps stay within the calling VM's
 * scheduling domain.
 */

static bool sched_policy_is_fair(int policy)
{
    return policy == LINUX_SCHED_NORMAL || policy == LINUX_SCHED_BATCH;
}

static bool sched_policy_is_rt(int policy)
{
    return policy == LINUX_SCHED_FIFO || policy == LINUX_SCHED_RR;
}

static bool sched_policy_is_dl(int policy)
{
    return policy == LINUX_SCHED_DEADLINE;
}

static bool sched_policy_supported(int policy)
{
    return sched_policy_is_fair(policy) || sched_policy_is_rt(policy) ||
           sched_policy_is_dl(policy) || policy == LINUX_SCHED_IDLE;
}

/* RLIMIT_NICE expresses permission as 20 - nice (1..40). CAP_SYS_NICE is
 * modeled by euid 0, matching the rest of elfuse's privilege checks.
 */
static bool sched_nice_reduction_allowed(int nice)
{
    return (uint64_t) (20 - nice) <= sys_rlimit_cur(LINUX_RLIMIT_NICE);
}

/* Linux __checkparam_dl: runtime >= 1<<DL_SCALE (1024 ns), deadline nonzero,
 * runtime <= deadline <= period (period 0 means deadline), and the effective
 * period inside the sysctl range 100 us .. 4 s.
 */
static bool sched_dl_params_valid(const sched_task_attrs_t *a)
{
    if (a->deadline == 0 || a->runtime < 1024)
        return false;
    if (a->runtime > a->deadline)
        return false;
    if ((a->deadline | a->period) >> 63)
        return false;
    uint64_t period = a->period ? a->period : a->deadline;
    if (a->deadline > period)
        return false;
    return period >= 100000ULL && period <= 4000000000ULL;
}

/* Look up the task named by a Linux scheduler pid argument. pid 0 is the
 * caller. A nonzero result is reference-held and must be thread_release()d.
 */
static thread_entry_t *sched_lookup(int pid)
{
    if (pid == 0)
        return current_thread;
    return thread_acquire_tid(pid);
}

/* Read sched_attr from the guest with Linux 6.18 size negotiation:
 * - size 0 means SCHED_ATTR_SIZE_VER0 (48);
 * - size outside [48, PAGE_SIZE] writes the required 56 and returns E2BIG;
 * - a nonzero tail beyond 56 is E2BIG with the same writeback;
 * - a short struct zero-fills the unavailable tail;
 * - nice is clamped to [-20, 19].
 */
static int64_t sched_attr_from_guest(guest_t *g,
                                     uint64_t attr_gva,
                                     linux_sched_attr_t *out)
{
    uint32_t size;
    if (guest_read_small(g, attr_gva, &size, sizeof(size)) < 0)
        return -LINUX_EFAULT;
    if (size == 0)
        size = LINUX_SCHED_ATTR_SIZE_VER0;
    if (size < LINUX_SCHED_ATTR_SIZE_VER0 ||
        size > (uint32_t) GUEST_PAGE_SIZE) {
        uint32_t required = LINUX_SCHED_ATTR_SIZE_VER1;
        (void) guest_write_small(g, attr_gva, &required, sizeof(required));
        return -LINUX_E2BIG;
    }

    memset(out, 0, sizeof(*out));
    size_t head = size < sizeof(*out) ? size : sizeof(*out);
    if (guest_read_small(g, attr_gva, out, head) < 0)
        return -LINUX_EFAULT;

    if (size > sizeof(*out)) {
        uint8_t chunk[64];
        for (uint64_t off = sizeof(*out); off < size;) {
            size_t n = size - off < sizeof(chunk) ? (size_t) (size - off)
                                                  : sizeof(chunk);
            if (guest_read_small(g, attr_gva + off, chunk, n) < 0)
                return -LINUX_EFAULT;
            for (size_t i = 0; i < n; i++) {
                if (chunk[i] != 0) {
                    uint32_t required = LINUX_SCHED_ATTR_SIZE_VER1;
                    (void) guest_write_small(g, attr_gva, &required,
                                             sizeof(required));
                    return -LINUX_E2BIG;
                }
            }
            off += n;
        }
    }

    /* SCHED_FLAG_UTIL_CLAMP needs VER1 fields. */
    if ((out->sched_flags & LINUX_SCHED_FLAG_UTIL_CLAMP) &&
        size < LINUX_SCHED_ATTR_SIZE_VER1)
        return -LINUX_EINVAL;

    if (out->sched_nice < SCHED_NICE_MIN)
        out->sched_nice = SCHED_NICE_MIN;
    if (out->sched_nice > SCHED_NICE_MAX)
        out->sched_nice = SCHED_NICE_MAX;
    return 0;
}

static void sched_attr_from_wire(const linux_sched_attr_t *w,
                                 sched_task_attrs_t *a)
{
    a->policy = (int) w->sched_policy;
    a->nice = w->sched_nice;
    a->rt_priority = w->sched_priority;
    a->flags = (unsigned) w->sched_flags;
    a->runtime = w->sched_runtime;
    a->deadline = w->sched_deadline;
    a->period = w->sched_period;
}

/* Fill the wire struct from the base attributes. For non-DEADLINE classes Linux
 * reports zero priority for fair tasks, zero nice for RT/DEADLINE, and only the
 * fields that class uses. Fair tasks also report their current slice
 * (se.slice), which the core derives when no custom slice is stored.
 */
static void sched_attr_to_wire(const sched_task_attrs_t *a,
                               uint64_t rr_interval_ns,
                               linux_sched_attr_t *w)
{
    memset(w, 0, sizeof(*w));
    w->size = LINUX_SCHED_ATTR_SIZE_VER1;
    w->sched_policy = (uint32_t) a->policy;

    /* KEEP_POLICY/KEEP_PARAMS are request modifiers; Linux reports only the
     * persistent flags. RECLAIM/DL_OVERRUN are DEADLINE flags.
     */
    w->sched_flags = a->flags & LINUX_SCHED_FLAG_RESET_ON_FORK;
    if (sched_policy_is_dl(a->policy))
        w->sched_flags |=
            a->flags & (LINUX_SCHED_FLAG_RECLAIM | LINUX_SCHED_FLAG_DL_OVERRUN);
    if (sched_policy_is_rt(a->policy)) {
        w->sched_priority = a->rt_priority;
    } else if (sched_policy_is_dl(a->policy)) {
        w->sched_runtime = a->runtime;
        w->sched_deadline = a->deadline;
        w->sched_period = a->period;
    } else {
        w->sched_nice = a->nice;
        w->sched_runtime = a->runtime ? a->runtime : rr_interval_ns;
    }
}

/* Linux permission rules from user_check_sched_setscheduler. Structural
 * validation runs first in sched_apply_attr; this function only decides whether
 * the transition needs CAP_SYS_NICE.
 */
static bool sched_transition_needs_cap(const sched_task_attrs_t *cur,
                                       const sched_task_attrs_t *eff)
{
    if (sched_policy_is_fair(eff->policy) && eff->nice < cur->nice &&
        !sched_nice_reduction_allowed(eff->nice))
        return true;

    if (sched_policy_is_rt(eff->policy)) {
        uint64_t rlim = sys_rlimit_cur(LINUX_RLIMIT_RTPRIO);
        if (eff->policy != cur->policy && rlim == 0)
            return true;
        if (eff->rt_priority > cur->rt_priority &&
            (uint64_t) eff->rt_priority > rlim)
            return true;
    }

    /* Unprivileged tasks cannot enter or change SCHED_DEADLINE. */
    if (sched_policy_is_dl(eff->policy))
        return true;

    /* Linux treats SCHED_IDLE as nice 20: leaving it needs RLIMIT_NICE. */
    if (cur->policy == LINUX_SCHED_IDLE && eff->policy != LINUX_SCHED_IDLE &&
        !sched_nice_reduction_allowed(cur->nice))
        return true;

    /* Normal users cannot clear RESET_ON_FORK. */
    if ((cur->flags & LINUX_SCHED_FLAG_RESET_ON_FORK) &&
        !(eff->flags & LINUX_SCHED_FLAG_RESET_ON_FORK))
        return true;

    return false;
}

/* Apply one request after Linux structural validation and permissions.
 * KEEP_POLICY / KEEP_PARAMS are resolved twice: here for permission checks and
 * by the core for the committed transition. The core owns admission (EBUSY) and
 * requeue/migration requests; this never switches context.
 */
static int64_t sched_apply_attr_with_cap(thread_entry_t *t,
                                         sched_task_attrs_t *req,
                                         bool cap)
{
    sched_task_attrs_t cur;
    sched_task_get_attr(t, &cur);

    sched_task_attrs_t eff = *req;
    if (req->flags & LINUX_SCHED_FLAG_KEEP_PARAMS) {
        eff.nice = cur.nice;
        eff.rt_priority = cur.rt_priority;
        eff.runtime = cur.runtime;
        eff.deadline = cur.deadline;
        eff.period = cur.period;
    }
    if (req->flags & LINUX_SCHED_FLAG_KEEP_POLICY) {
        eff.policy = cur.policy;
        eff.flags = (eff.flags & ~LINUX_SCHED_FLAG_RESET_ON_FORK) |
                    (cur.flags & LINUX_SCHED_FLAG_RESET_ON_FORK);
        req->flags = eff.flags;
        req->policy = -1;
    }

    /* Known flag namespace: RESET_ON_FORK, RECLAIM, DL_OVERRUN, KEEP_POLICY and
     * KEEP_PARAMS are implemented by the core; UTIL_CLAMP needs capacity
     * selection this backend does not provide (reported after the permission
     * checks, like a kernel built without CONFIG_UCLAMP_TASK); every other bit
     * is invalid, including the kernel-internal SUGOV flag.
     */
    if (req->flags & ~(LINUX_SCHED_FLAG_ALL | LINUX_SCHED_FLAG_SUGOV))
        return -LINUX_EINVAL;
    if (req->flags & LINUX_SCHED_FLAG_SUGOV)
        return -LINUX_EINVAL;

    if (!sched_policy_supported(eff.policy))
        return -LINUX_EINVAL;
    if (eff.rt_priority > SCHED_RT_PRIO_MAX)
        return -LINUX_EINVAL;
    if (sched_policy_is_dl(eff.policy)) {
        if (!sched_dl_params_valid(&eff))
            return -LINUX_EINVAL;
    } else {
        if (sched_policy_is_rt(eff.policy) != (eff.rt_priority != 0))
            return -LINUX_EINVAL;
        req->deadline = 0;
        req->period = 0;

        /* Linux 6.12+ accepts sched_runtime as a fair custom slice; the core
         * clamps it to [100 us, 100 ms]. For RT it is ignored.
         */
        if (!sched_policy_is_fair(eff.policy))
            req->runtime = 0;
    }

    if (sched_transition_needs_cap(&cur, &eff) && !cap)
        return -LINUX_EPERM;

    if (eff.flags & LINUX_SCHED_FLAG_UTIL_CLAMP)
        return -LINUX_EOPNOTSUPP;

    return sched_task_set_attr(t, req);
}

/* Linux sets one task's nice. A reduction (new nice < current nice) needs
 * RLIMIT_NICE (20 - nice <= rlim) or CAP_SYS_NICE; failure is EACCES, not
 * EPERM. The caller's error accumulator starts at -ESRCH and a success clears
 * it only in that state, so a later failure overrides an earlier success.
 */
static int64_t prio_set_one(thread_entry_t *t, int nice, int64_t error)
{
    sched_task_attrs_t a;
    sched_task_get_attr(t, &a);
    if (nice < a.nice && !proc_has_cap_sys_nice() &&
        (uint64_t) (20 - nice) > sys_rlimit_cur(LINUX_RLIMIT_NICE))
        return -LINUX_EACCES;

    int rc = sched_task_set_nice(t, nice);
    if (rc == -LINUX_EINVAL) {
        /* sched_task_set_nice is the fair-weight path. RT/DEADLINE tasks still
         * carry a Linux nice value; store it without changing class parameters
         * or re-admitting the task.
         */
        a.nice = nice;
        rc = sched_task_set_attr(t, &a);
    }
    if (rc < 0)
        return rc;
    return error == -LINUX_ESRCH ? 0 : error;
}

typedef struct prio_tid_snapshot {
    int64_t *tids;
    int count;
    int cap;
} prio_tid_snapshot_t;

static void prio_collect_tid(thread_entry_t *t, void *ctx)
{
    prio_tid_snapshot_t *s = ctx;
    int64_t tid = thread_tid(t);
    if (tid == 0 || s->count >= s->cap)
        return;
    s->tids[s->count++] = tid;
}

/* Snapshot local TIDs without calling scheduler code under thread_lock.
 * Returns the count, or -1 when the snapshot cannot be allocated.
 */
static int prio_snapshot_local(int64_t **out)
{
    *out = NULL;
    int cap = thread_table_capacity();
    if (cap <= 0)
        return 0;
    int64_t *tids = malloc((size_t) cap * sizeof(*tids));
    if (!tids)
        return -1;
    prio_tid_snapshot_t s = {.tids = tids, .count = 0, .cap = cap};
    thread_for_each(prio_collect_tid, &s);
    *out = tids;
    return s.count;
}

static bool prio_group_matches(int who)
{
    int64_t target = who ? (int64_t) who : proc_get_pgid();
    return target == proc_get_pgid();
}

static bool prio_user_matches(int who)
{
    /* PRIO_USER 0 means the caller's real UID, not its effective UID. */
    uint32_t target = who ? (uint32_t) who : proc_get_uid();
    return who >= 0 && target == proc_get_uid();
}

int64_t proc_sys_setpriority(int which, int who, int prio)
{
    if (which < LINUX_PRIO_PROCESS || which > LINUX_PRIO_USER)
        return -LINUX_EINVAL;
    if (prio < -20)
        prio = -20;
    if (prio > 19)
        prio = 19;

    int64_t error = -LINUX_ESRCH;
    if (which == LINUX_PRIO_PROCESS) {
        thread_entry_t *t =
            who ? thread_acquire_tid((int64_t) who) : current_thread;
        if (!t) {
            /* Another fork backend: control-plane RPC, not a local lie. */
            if (who == 0)
                return -LINUX_ESRCH;
            return pidfd_sched_set_nice((int64_t) who, prio, proc_get_euid());
        }
        error = prio_set_one(t, prio, error);
        if (who)
            thread_release(t);
        return error;
    }

    bool matches = which == LINUX_PRIO_PGRP ? prio_group_matches(who)
                                            : prio_user_matches(who);
    if (!matches)
        return -LINUX_ESRCH;

    int64_t *tids;
    int count = prio_snapshot_local(&tids);
    if (count < 0)
        return -LINUX_ENOMEM;
    for (int i = 0; i < count; i++) {
        thread_entry_t *t = thread_acquire_tid(tids[i]);
        if (!t)
            continue;
        error = prio_set_one(t, prio, error);
        thread_release(t);
    }
    free(tids);
    return error;
}

int64_t proc_sys_getpriority(int which, int who)
{
    if (which < LINUX_PRIO_PROCESS || which > LINUX_PRIO_USER)
        return -LINUX_EINVAL;

    if (which == LINUX_PRIO_PROCESS) {
        thread_entry_t *t =
            who ? thread_acquire_tid((int64_t) who) : current_thread;
        if (!t) {
            if (who == 0)
                return -LINUX_ESRCH;
            pidfd_sched_state_t st;
            int64_t rc = pidfd_sched_query((int64_t) who, &st);
            if (rc < 0)
                return rc;
            return 20 - st.attrs.nice;
        }
        sched_task_attrs_t a;
        sched_task_get_attr(t, &a);
        if (who)
            thread_release(t);
        return 20 - a.nice;
    }

    bool matches = which == LINUX_PRIO_PGRP ? prio_group_matches(who)
                                            : prio_user_matches(who);
    if (!matches)
        return -LINUX_ESRCH;

    int64_t *tids;
    int count = prio_snapshot_local(&tids);
    if (count < 0)
        return -LINUX_ENOMEM;

    /* Linux starts at -ESRCH and replaces it with the maximum nice_to_rlimit
     * value seen. No local member (for example, only remote fork backends in
     * the group) stays -ESRCH instead of inventing a value.
     */
    int64_t ret = -LINUX_ESRCH;
    for (int i = 0; i < count; i++) {
        thread_entry_t *t = thread_acquire_tid(tids[i]);
        if (!t)
            continue;
        sched_task_attrs_t a;
        sched_task_get_attr(t, &a);
        int64_t niceval = 20 - a.nice;
        if (niceval > ret)
            ret = niceval;
        thread_release(t);
    }
    free(tids);
    return ret;
}

static int64_t sched_apply_attr(thread_entry_t *t, sched_task_attrs_t *req)
{
    return sched_apply_attr_with_cap(t, req, proc_has_cap_sys_nice());
}

/* Remote backend control-plane entry points (called by proc-pidfd.c on the
 * target process). Same owner check as Linux: caller euid must equal target
 * euid or uid, or the caller has the modeled CAP_SYS_NICE (euid 0).
 */
static bool sched_remote_owner_ok(uint32_t requester_euid)
{
    return requester_euid == 0 || requester_euid == proc_get_euid() ||
           requester_euid == proc_get_uid();
}

int64_t sys_sched_remote_query(int64_t tid,
                               sched_task_attrs_t *attrs,
                               uint32_t *uid,
                               uint32_t *euid,
                               uint64_t *rr_interval_ns,
                               uint64_t *rlimit_nice,
                               uint64_t *rlimit_rtprio)
{
    if (!attrs || !uid || !euid || !rr_interval_ns || !rlimit_nice ||
        !rlimit_rtprio)
        return -LINUX_EINVAL;
    thread_entry_t *t = sched_lookup((int) tid);
    if (!t)
        return -LINUX_ESRCH;
    sched_task_get_attr(t, attrs);
    *rr_interval_ns = sched_task_rr_interval_ns(t);
    thread_release(t);
    *uid = proc_get_uid();
    *euid = proc_get_euid();
    *rlimit_nice = sys_rlimit_cur(LINUX_RLIMIT_NICE);
    *rlimit_rtprio = sys_rlimit_cur(LINUX_RLIMIT_RTPRIO);
    return 0;
}

int64_t sys_sched_remote_set_attr(int64_t tid,
                                  const sched_task_attrs_t *req,
                                  uint32_t requester_euid)
{
    thread_entry_t *t = sched_lookup((int) tid);
    if (!t)
        return -LINUX_ESRCH;
    if (!sched_remote_owner_ok(requester_euid)) {
        thread_release(t);
        return -LINUX_EPERM;
    }
    sched_task_attrs_t copy = *req;
    int64_t rc = sched_apply_attr_with_cap(t, &copy, requester_euid == 0);
    thread_release(t);
    return rc;
}

int64_t sys_sched_remote_set_nice(int64_t tid,
                                  int nice,
                                  uint32_t requester_euid)
{
    thread_entry_t *t = sched_lookup((int) tid);
    if (!t)
        return -LINUX_ESRCH;
    if (!sched_remote_owner_ok(requester_euid)) {
        thread_release(t);
        return -LINUX_EPERM;
    }
    if (nice < SCHED_NICE_MIN)
        nice = SCHED_NICE_MIN;
    if (nice > SCHED_NICE_MAX)
        nice = SCHED_NICE_MAX;
    sched_task_attrs_t a;
    sched_task_get_attr(t, &a);
    if (nice < a.nice && requester_euid != 0 &&
        (uint64_t) (20 - nice) > sys_rlimit_cur(LINUX_RLIMIT_NICE)) {
        thread_release(t);
        return -LINUX_EACCES;
    }
    int rc = sched_task_set_nice(t, nice);
    thread_release(t);
    return rc;
}

int64_t sys_sched_remote_get_affinity(int64_t tid, uint8_t *buf, size_t len)
{
    thread_entry_t *t = sched_lookup((int) tid);
    if (!t)
        return -LINUX_ESRCH;
    int rc = sched_task_get_affinity(t, buf, len);
    thread_release(t);
    return rc;
}

int64_t sys_sched_remote_set_affinity(int64_t tid,
                                      const uint8_t *mask,
                                      size_t len,
                                      uint32_t requester_euid)
{
    thread_entry_t *t = sched_lookup((int) tid);
    if (!t)
        return -LINUX_ESRCH;
    if (!sched_remote_owner_ok(requester_euid)) {
        thread_release(t);
        return -LINUX_EPERM;
    }
    int rc = sched_task_set_affinity(t, mask, len);
    thread_release(t);
    return rc;
}

int64_t sys_sched_getscheduler(int pid)
{
    if (pid < 0)
        return -LINUX_EINVAL;
    thread_entry_t *t = sched_lookup(pid);
    sched_task_attrs_t a;
    if (!t) {
        pidfd_sched_state_t st;
        int64_t rc = pidfd_sched_query(pid, &st);
        if (rc < 0)
            return rc;
        a = st.attrs;
    } else {
        sched_task_get_attr(t, &a);
        if (pid != 0)
            thread_release(t);
    }
    int64_t ret = a.policy;
    if (a.flags & LINUX_SCHED_FLAG_RESET_ON_FORK)
        ret |= LINUX_SCHED_RESET_ON_FORK;
    return ret;
}

int64_t sys_sched_getparam(guest_t *g, int pid, uint64_t param_gva)
{
    if (pid < 0 || param_gva == 0)
        return -LINUX_EINVAL;
    thread_entry_t *t = sched_lookup(pid);
    sched_task_attrs_t a;
    if (!t) {
        pidfd_sched_state_t st;
        int64_t rc = pidfd_sched_query(pid, &st);
        if (rc < 0)
            return rc;
        a = st.attrs;
    } else {
        sched_task_get_attr(t, &a);
        if (pid != 0)
            thread_release(t);
    }
    linux_sched_param_t param = {0};
    if (sched_policy_is_rt(a.policy))
        param.sched_priority = (int32_t) a.rt_priority;
    if (guest_write_small(g, param_gva, &param, sizeof(param)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

int64_t sys_sched_setscheduler(guest_t *g,
                               int pid,
                               int policy,
                               uint64_t param_gva)
{
    if (policy < 0)
        return -LINUX_EINVAL;
    if (pid < 0 || param_gva == 0)
        return -LINUX_EINVAL;

    linux_sched_param_t param;
    if (guest_read_small(g, param_gva, &param, sizeof(param)) < 0)
        return -LINUX_EFAULT;

    thread_entry_t *t = sched_lookup(pid);
    sched_task_attrs_t cur;
    if (!t) {
        pidfd_sched_state_t st;
        int64_t rc = pidfd_sched_query(pid, &st);
        if (rc < 0)
            return rc;
        cur = st.attrs;
    } else {
        sched_task_get_attr(t, &cur);
    }
    sched_task_attrs_t req = {
        .policy = policy & ~LINUX_SCHED_RESET_ON_FORK,
        .nice = cur.nice,
        .rt_priority = (unsigned) param.sched_priority,
        .runtime = cur.runtime,
        .flags = (policy & LINUX_SCHED_RESET_ON_FORK)
                     ? LINUX_SCHED_FLAG_RESET_ON_FORK
                     : 0,
    };
    int64_t ret = t ? sched_apply_attr(t, &req)
                    : pidfd_sched_set_attr(pid, &req, proc_get_euid());
    if (t && pid != 0)
        thread_release(t);
    return ret;
}

int64_t sys_sched_setparam(guest_t *g, int pid, uint64_t param_gva)
{
    if (pid < 0 || param_gva == 0)
        return -LINUX_EINVAL;

    linux_sched_param_t param;
    if (guest_read_small(g, param_gva, &param, sizeof(param)) < 0)
        return -LINUX_EFAULT;

    thread_entry_t *t = sched_lookup(pid);
    sched_task_attrs_t cur;
    if (!t) {
        pidfd_sched_state_t st;
        int64_t rc = pidfd_sched_query(pid, &st);
        if (rc < 0)
            return rc;
        cur = st.attrs;
    } else {
        sched_task_get_attr(t, &cur);
    }
    sched_task_attrs_t req = {
        .policy = cur.policy,
        .nice = cur.nice,
        .rt_priority = (unsigned) param.sched_priority,
        .runtime = cur.runtime,
        .flags = cur.flags & LINUX_SCHED_FLAG_RESET_ON_FORK,
    };
    int64_t ret = t ? sched_apply_attr(t, &req)
                    : pidfd_sched_set_attr(pid, &req, proc_get_euid());
    if (t && pid != 0)
        thread_release(t);
    return ret;
}

int64_t sys_sched_setattr(guest_t *g,
                          int pid,
                          uint64_t attr_gva,
                          unsigned int flags)
{
    if (attr_gva == 0 || pid < 0 || flags != 0)
        return -LINUX_EINVAL;

    linux_sched_attr_t wire;
    int64_t ret = sched_attr_from_guest(g, attr_gva, &wire);
    if (ret < 0)
        return ret;
    if ((int32_t) wire.sched_policy < 0)
        return -LINUX_EINVAL;

    thread_entry_t *t = sched_lookup(pid);
    bool high_flags = (wire.sched_flags >> 32) != 0;
    if (!t) {
        /* The RPC carries 32 flag bits; a high bit cannot be forwarded. A
         * successful query first preserves Linux's ESRCH-before-EINVAL order
         * for an unknown target.
         */
        if (high_flags) {
            pidfd_sched_state_t st;
            int64_t rc = pidfd_sched_query(pid, &st);
            return rc < 0 ? rc : -LINUX_EINVAL;
        }
        sched_task_attrs_t req;
        sched_attr_from_wire(&wire, &req);
        return pidfd_sched_set_attr(pid, &req, proc_get_euid());
    }

    /* A high flag is an unknown flag and must not be truncated into success. */
    if (high_flags) {
        if (pid != 0)
            thread_release(t);
        return -LINUX_EINVAL;
    }

    sched_task_attrs_t req;
    sched_attr_from_wire(&wire, &req);
    ret = sched_apply_attr(t, &req);
    if (pid != 0)
        thread_release(t);
    return ret;
}

int64_t sys_sched_getattr(guest_t *g,
                          int pid,
                          uint64_t attr_gva,
                          unsigned int size,
                          unsigned int flags)
{
    if (attr_gva == 0 || pid < 0 || flags != 0 ||
        size < LINUX_SCHED_ATTR_SIZE_VER0 || size > (unsigned) GUEST_PAGE_SIZE)
        return -LINUX_EINVAL;

    thread_entry_t *t = sched_lookup(pid);
    sched_task_attrs_t a;
    uint64_t rr_interval_ns;
    if (!t) {
        pidfd_sched_state_t st;
        int64_t rc = pidfd_sched_query(pid, &st);
        if (rc < 0)
            return rc;
        a = st.attrs;
        rr_interval_ns = st.rr_interval_ns;
    } else {
        sched_task_get_attr(t, &a);
        rr_interval_ns = sched_task_rr_interval_ns(t);
        if (pid != 0)
            thread_release(t);
    }
    linux_sched_attr_t wire;
    sched_attr_to_wire(&a, rr_interval_ns, &wire);
    wire.size =
        size < LINUX_SCHED_ATTR_SIZE_VER1 ? size : LINUX_SCHED_ATTR_SIZE_VER1;
    if (guest_write_small(g, attr_gva, &wire, wire.size) < 0)
        return -LINUX_EFAULT;
    return 0;
}

int64_t sys_sched_get_priority_min(int policy)
{
    switch (policy) {
    case LINUX_SCHED_DEADLINE:
    case LINUX_SCHED_NORMAL:
    case LINUX_SCHED_BATCH:
    case LINUX_SCHED_IDLE:
    case LINUX_SCHED_EXT:
        return 0;
    case LINUX_SCHED_FIFO:
    case LINUX_SCHED_RR:
        return SCHED_RT_PRIO_MIN;
    default:
        return -LINUX_EINVAL;
    }
}

int64_t sys_sched_get_priority_max(int policy)
{
    switch (policy) {
    case LINUX_SCHED_DEADLINE:
    case LINUX_SCHED_NORMAL:
    case LINUX_SCHED_BATCH:
    case LINUX_SCHED_IDLE:
    case LINUX_SCHED_EXT:
        return 0;
    case LINUX_SCHED_FIFO:
    case LINUX_SCHED_RR:
        return SCHED_RT_PRIO_MAX;
    default:
        return -LINUX_EINVAL;
    }
}

int64_t sys_sched_rr_get_interval(guest_t *g, int pid, uint64_t ts_gva)
{
    if (pid < 0)
        return -LINUX_EINVAL;
    thread_entry_t *t = sched_lookup(pid);
    uint64_t slice;
    if (!t) {
        pidfd_sched_state_t st;
        int64_t rc = pidfd_sched_query(pid, &st);
        if (rc < 0)
            return rc;
        slice = st.rr_interval_ns;
    } else {
        slice = sched_task_rr_interval_ns(t);
        if (pid != 0)
            thread_release(t);
    }
    if (ts_gva == 0)
        return -LINUX_EFAULT;

    linux_timespec_t ts = {
        .tv_sec = (int64_t) (slice / 1000000000ULL),
        .tv_nsec = (int64_t) (slice % 1000000000ULL),
    };
    if (guest_write_small(g, ts_gva, &ts, sizeof(ts)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

int64_t sys_sched_getaffinity(guest_t *g,
                              int pid,
                              uint64_t size,
                              uint64_t mask_gva)
{
    if (pid < 0)
        return -LINUX_EINVAL;
    size_t cpuset_bytes = sched_affinity_cpuset_bytes();
    if (size < cpuset_bytes || (size & (sizeof(uint64_t) - 1)) != 0)
        return -LINUX_EINVAL;

    thread_entry_t *t = sched_lookup(pid);
    uint8_t mask[SCHED_CPUSET_BYTES];
    int n;
    if (!t) {
        pidfd_sched_state_t st;
        int64_t rc = pidfd_sched_query(pid, &st);
        if (rc < 0)
            return rc;
        n = (int) st.mask_len;
        if (n < 0 || (size_t) n > sizeof(mask))
            return -LINUX_EIO;
        memcpy(mask, st.mask, (size_t) n);
    } else {
        n = sched_task_get_affinity(t, mask, cpuset_bytes);
        if (pid != 0)
            thread_release(t);
        if (n < 0)
            return -LINUX_EINVAL;
    }

    size_t copy_n = (size_t) n < (size_t) size ? (size_t) n : (size_t) size;
    if (guest_write_small(g, mask_gva, mask, copy_n) < 0)
        return -LINUX_EFAULT;
    return (int64_t) copy_n;
}

int64_t sys_sched_setaffinity(guest_t *g,
                              int pid,
                              uint64_t size,
                              uint64_t mask_gva)
{
    if (pid < 0)
        return -LINUX_EINVAL;

    /* Linux get_user_cpu_mask copies min(len, cpumask_size) bytes and pads an
     * undersized mask with zeros; the empty result then fails EINVAL below.
     */
    uint8_t mask[SCHED_CPUSET_BYTES];
    memset(mask, 0, sizeof(mask));
    size_t cpuset_bytes = sched_affinity_cpuset_bytes();
    size_t copy = size < cpuset_bytes ? (size_t) size : cpuset_bytes;
    if (copy != 0 && guest_read_small(g, mask_gva, mask, copy) < 0)
        return -LINUX_EFAULT;

    thread_entry_t *t = sched_lookup(pid);
    if (!t)
        return pidfd_sched_set_affinity(pid, mask, cpuset_bytes,
                                        proc_get_euid());
    int ret = sched_task_set_affinity(t, mask, cpuset_bytes);
    if (pid != 0)
        thread_release(t);
    return ret;
}

int64_t sys_getgroups(guest_t *g, int size, uint64_t list_gva)
{
    if (proc_fakeroot_enabled() && proc_get_euid() == 0) {
        if (size == 0)
            return 1;
        uint32_t zero_group = 0;
        if (guest_write_small(g, list_gva, &zero_group, sizeof(zero_group)) < 0)
            return -LINUX_EFAULT;
        return 1;
    }

    int ngroups = get_cached_linux_groups();
    if (ngroups < 0)
        return linux_errno();

    if (size == 0)
        return ngroups;
    if (size < ngroups)
        return -LINUX_EINVAL;

    size_t bytes = (size_t) ngroups * sizeof(cached_linux_groups[0]);
    if (guest_write_small(g, list_gva, cached_linux_groups, bytes) < 0)
        return -LINUX_EFAULT;

    return ngroups;
}

#define LINUX_NGROUPS_MAX 65536

int64_t sys_setgroups(guest_t *g, int size, uint64_t list_gva)
{
    if (proc_get_euid() != 0 && !proc_fakeroot_enabled())
        return -LINUX_EPERM;
    if (size < 0 || size > LINUX_NGROUPS_MAX)
        return -LINUX_EINVAL;
    if (size > 0) {
        size_t bytes = (size_t) size * sizeof(uint32_t);
        uint32_t *groups = malloc(bytes);
        if (!groups)
            return -LINUX_ENOMEM;
        int ret = guest_read(g, list_gva, groups, bytes);
        free(groups);
        if (ret < 0)
            return -LINUX_EFAULT;
    }
    return 0;
}

int64_t sys_getrusage(guest_t *g, int who, uint64_t usage_gva)
{
    /* Linux RUSAGE_SELF=0, RUSAGE_CHILDREN=-1, RUSAGE_THREAD=1. macOS has the
     * same values. Reject unknown values early.
     */
    if (who != 0 && who != -1 && who != 1)
        return -LINUX_EINVAL;

    /* Event counters and max RSS come from the host, but the CPU fields are the
     * guest scheduling ledger: host worker/helper threads must never appear in
     * them, and CPU time of departed guest threads must remain.
     */
    struct rusage mac_usage;
    if (getrusage(who, &mac_usage) < 0)
        return linux_errno();

    uint64_t user_ns = 0, sys_ns = 0;
    if (who == 1) {
        sched_thread_cputime_split_ns(current_thread, &user_ns, &sys_ns);
    } else if (who == 0) {
        sched_process_cputime_split_ns(&user_ns, &sys_ns);
    } else {
        uint64_t utime_us = 0, stime_us = 0;
        proc_children_cpu_us(&utime_us, &stime_us);
        user_ns = utime_us * 1000ULL;
        sys_ns = stime_us * 1000ULL;
    }
    mac_usage.ru_utime.tv_sec = (time_t) (user_ns / 1000000000ULL);
    mac_usage.ru_utime.tv_usec =
        (suseconds_t) ((user_ns % 1000000000ULL) / 1000ULL);
    mac_usage.ru_stime.tv_sec = (time_t) (sys_ns / 1000000000ULL);
    mac_usage.ru_stime.tv_usec =
        (suseconds_t) ((sys_ns % 1000000000ULL) / 1000ULL);

    if (write_rusage_to_guest(g, usage_gva, &mac_usage) < 0)
        return -LINUX_EFAULT;

    return 0;
}

int64_t sys_sysinfo(guest_t *g, uint64_t info_gva)
{
    linux_sysinfo_t si;
    sysinfo_snapshot(&si);
    if (guest_write_small(g, info_gva, &si, sizeof(si)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* Resource limits. */

/* Linux RLIMIT_* numbers to the macOS ones, for seeding the guest table from
 * the host. The numbering differs: Linux RLIMIT_NPROC=6 vs macOS
 * RLIMIT_NPROC=7.
 */
static int translate_rlimit_resource(int linux_res)
{
    switch (linux_res) {
    case LINUX_RLIMIT_CPU:
        return RLIMIT_CPU;
    case LINUX_RLIMIT_FSIZE:
        return RLIMIT_FSIZE;
    case LINUX_RLIMIT_DATA:
        return RLIMIT_DATA;
    case LINUX_RLIMIT_STACK:
        return RLIMIT_STACK;
    case LINUX_RLIMIT_CORE:
        return RLIMIT_CORE;
    case LINUX_RLIMIT_NPROC:
        return RLIMIT_NPROC; /* Linux 6 -> macOS 7 */
    case LINUX_RLIMIT_NOFILE:
        return RLIMIT_NOFILE; /* Linux 7 -> macOS 8 */
    case LINUX_RLIMIT_MEMLOCK:
        return RLIMIT_MEMLOCK; /* Linux 8 -> macOS 6 */
    case LINUX_RLIMIT_AS:
        return RLIMIT_AS;
    default:
        /* RSS too: macOS defines RLIMIT_RSS as RLIMIT_AS, so a host value would
         * be the address-space limit.
         */
        return -1;
    }
}

/* MAXSSIZ on arm64 macOS: 64 MiB less one 16 KiB page. */
#define HOST_STACK_HARD_CAP (64ULL * 1024 * 1024 - 16 * 1024)

/* _STK_LIM, the stack limit Linux starts a process with. macOS starts one at a
 * 16 KiB page less.
 */
#define LINUX_STACK_DEFAULT (8ULL * 1024 * 1024)
#define HOST_STACK_DEFAULT (LINUX_STACK_DEFAULT - 16 * 1024)

static linux_rlimit64_t translate_host_rlimit(int resource, struct rlimit rl)
{
    linux_rlimit64_t lim = {0};

    lim.rlim_cur =
        (rl.rlim_cur == RLIM_INFINITY) ? LINUX_RLIM_INFINITY : rl.rlim_cur;
    lim.rlim_max =
        (rl.rlim_max == RLIM_INFINITY) ? LINUX_RLIM_INFINITY : rl.rlim_max;

    /* The macOS default stack limit reads as the Linux one. A limit the user
     * set, and a default the hard limit has no room to round, pass through.
     */
    if (resource == LINUX_RLIMIT_STACK && lim.rlim_cur == HOST_STACK_DEFAULT &&
        lim.rlim_max >= LINUX_STACK_DEFAULT)
        lim.rlim_cur = LINUX_STACK_DEFAULT;

    /* macOS also caps the hard stack limit, at MAXSSIZ, where Linux starts a
     * process with it unlimited. The cap is about host thread stacks and bounds
     * nothing in the guest, so a host that sits at it reads as unlimited; one
     * whose user lowered it keeps the lower value.
     */
    if (resource == LINUX_RLIMIT_STACK && lim.rlim_max >= HOST_STACK_HARD_CAP)
        lim.rlim_max = LINUX_RLIM_INFINITY;

    return lim;
}

/* Guest rlimit table.
 *
 * prlimit64 reads and writes these slots and never calls host setrlimit, so a
 * guest limit cannot constrain elfuse itself, and RSS keeps a slot of its own
 * although macOS defines RLIMIT_RSS as RLIMIT_AS.
 *
 * rlimit_lock serializes the threads that write the table. A site that enforces
 * a limit loads one soft value through sys_rlimit_cur and takes no lock.
 */
typedef struct {
    struct {
        _Atomic uint64_t cur, max;
    } slot[LINUX_RLIMIT_COUNT];
} rlimit_table_t;

static pthread_mutex_t rlimit_lock = PTHREAD_MUTEX_INITIALIZER;

/* NOFILE starts at the table size because a fork child installs its inherited
 * descriptors before sys_rlimit_restore runs.
 */
static rlimit_table_t rlimit_private = {
    .slot = {[LINUX_RLIMIT_NOFILE] = {FD_TABLE_SIZE, FD_TABLE_SIZE}},
};

/* Relaxed on both sides: writers hold rlimit_lock, and the lock-free reader in
 * sys_rlimit_cur wants one word with nothing published behind it.
 */
static linux_rlimit64_t rlimit_slot_load(const rlimit_table_t *t, int resource)
{
    return (linux_rlimit64_t) {
        .rlim_cur =
            atomic_load_explicit(&t->slot[resource].cur, memory_order_relaxed),
        .rlim_max =
            atomic_load_explicit(&t->slot[resource].max, memory_order_relaxed),
    };
}

static void rlimit_slot_store(rlimit_table_t *t,
                              int resource,
                              linux_rlimit64_t lim)
{
    atomic_store_explicit(&t->slot[resource].cur, lim.rlim_cur,
                          memory_order_relaxed);
    atomic_store_explicit(&t->slot[resource].max, lim.rlim_max,
                          memory_order_relaxed);
}

/* Test hook, off unless ELFUSE_HOST_RLIMIT_CHECK is set: record every host
 * limit of this process and fail its exit when one has moved. Only elfuse can
 * read its own limits, and a guest limit that reached host setrlimit shows
 * nowhere else. tests/test-rlimit-unchanged-host drives it.
 */
#define HOST_RLIMIT_CHECK_EXIT 86

static struct rlimit host_rlimit_start[RLIM_NLIMITS];

static void host_rlimit_check(void)
{
    for (int r = 0; r < RLIM_NLIMITS; r++) {
        struct rlimit now;
        if (getrlimit(r, &now) < 0 ||
            (now.rlim_cur == host_rlimit_start[r].rlim_cur &&
             now.rlim_max == host_rlimit_start[r].rlim_max))
            continue;
        fprintf(stderr,
                "elfuse: host rlimit %d moved during the guest run: "
                "%llu/%llu -> %llu/%llu\n",
                r, (unsigned long long) host_rlimit_start[r].rlim_cur,
                (unsigned long long) host_rlimit_start[r].rlim_max,
                (unsigned long long) now.rlim_cur,
                (unsigned long long) now.rlim_max);
        _exit(HOST_RLIMIT_CHECK_EXIT);
    }
}

static void host_rlimit_check_arm(void)
{
    if (!getenv("ELFUSE_HOST_RLIMIT_CHECK"))
        return;
    for (int r = 0; r < RLIM_NLIMITS; r++)
        getrlimit(r, &host_rlimit_start[r]);
    atexit(host_rlimit_check);
}

static bool rlimit_pair_valid(int resource, linux_rlimit64_t lim)
{
    if (lim.rlim_cur > lim.rlim_max)
        return false;
    return resource != LINUX_RLIMIT_NOFILE || lim.rlim_max <= FD_TABLE_SIZE;
}

/* What Linux gives the resources macOS has no counterpart for: INIT_RLIMITS
 * (include/asm-generic/resource.h) for all but SIGPENDING, which fork_init
 * (kernel/fork.c) sets to the same value as NPROC.
 */
static linux_rlimit64_t rlimit_linux_default(int resource,
                                             linux_rlimit64_t nproc)
{
    switch (resource) {
    case LINUX_RLIMIT_SIGPENDING:
        return nproc;
    case LINUX_RLIMIT_MSGQUEUE:
        return (linux_rlimit64_t) {819200, 819200};
    case LINUX_RLIMIT_NICE:
    case LINUX_RLIMIT_RTPRIO:
        return (linux_rlimit64_t) {0, 0};
    default:
        return (linux_rlimit64_t) {LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY};
    }
}

void sys_rlimit_init(void)
{
    linux_rlimit64_t nproc = {LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY};

    pthread_mutex_lock(&rlimit_lock);
    for (int r = 0; r < LINUX_RLIMIT_COUNT; r++) {
        linux_rlimit64_t lim;
        struct rlimit rl;
        int host_res = translate_rlimit_resource(r);

        /* The host NOFILE limit is elfuse's own capacity (main.c); the guest
         * gets the size of its fd table.
         */
        if (r == LINUX_RLIMIT_NOFILE)
            lim = (linux_rlimit64_t) {FD_TABLE_SIZE, FD_TABLE_SIZE};
        else if (host_res >= 0 && getrlimit(host_res, &rl) == 0)
            lim = translate_host_rlimit(r, rl);
        else
            lim = rlimit_linux_default(r, nproc);
        if (r == LINUX_RLIMIT_NPROC)
            nproc = lim;
        rlimit_slot_store(&rlimit_private, r, lim);
    }
    pthread_mutex_unlock(&rlimit_lock);

    /* The guest's RLIMIT_FSIZE is enforced from the table just seeded, so the
     * host soft limit only stands in the way of a guest that raises its own:
     * lift it to the host hard limit. A guest that raises past the hard limit
     * still meets the host's, which the ignored SIGXFSZ (main.c) turns into
     * EFBIG. This runs before the check below records the host limits, which
     * stay fixed from here on.
     */
    struct rlimit fsz;
    if (getrlimit(RLIMIT_FSIZE, &fsz) == 0 && fsz.rlim_cur < fsz.rlim_max) {
        fsz.rlim_cur = fsz.rlim_max;
        (void) setrlimit(RLIMIT_FSIZE, &fsz);
    }
    host_rlimit_check_arm();
}

uint64_t sys_rlimit_cur(int resource)
{
    return atomic_load_explicit(&rlimit_private.slot[resource].cur,
                                memory_order_relaxed);
}

void sys_rlimit_send_xfsz(void)
{
    if (!current_thread ||
        !signal_queue_thread(thread_tid(current_thread), LINUX_SIGXFSZ))
        signal_queue(LINUX_SIGXFSZ);
}

void sys_rlimit_snapshot(linux_rlimit64_t out[LINUX_RLIMIT_COUNT])
{
    pthread_mutex_lock(&rlimit_lock);
    for (int r = 0; r < LINUX_RLIMIT_COUNT; r++)
        out[r] = rlimit_slot_load(&rlimit_private, r);
    pthread_mutex_unlock(&rlimit_lock);
}

bool sys_rlimit_table_valid(const linux_rlimit64_t in[LINUX_RLIMIT_COUNT])
{
    for (int r = 0; r < LINUX_RLIMIT_COUNT; r++)
        if (!rlimit_pair_valid(r, in[r]))
            return false;
    return true;
}

void sys_rlimit_restore(const linux_rlimit64_t in[LINUX_RLIMIT_COUNT])
{
    pthread_mutex_lock(&rlimit_lock);
    for (int r = 0; r < LINUX_RLIMIT_COUNT; r++)
        rlimit_slot_store(&rlimit_private, r, in[r]);
    pthread_mutex_unlock(&rlimit_lock);
    host_rlimit_check_arm();
}

/* Read the slot into @old_lim and, when @new_lim is set, replace it under the
 * rules of do_prlimit (Linux kernel/sys.c). The caller holds rlimit_lock.
 *
 * Returns 0 or a positive Linux errno.
 */
static int rlimit_exchange(rlimit_table_t *t,
                           int resource,
                           const linux_rlimit64_t *new_lim,
                           linux_rlimit64_t *old_lim)
{
    *old_lim = rlimit_slot_load(t, resource);
    if (!new_lim)
        return 0;
    if (new_lim->rlim_cur > new_lim->rlim_max)
        return LINUX_EINVAL;

    /* Raising a hard limit takes CAP_SYS_RESOURCE. The NOFILE ceiling is the
     * size of the guest fd table, where Linux uses nr_open.
     */
    if (new_lim->rlim_max > old_lim->rlim_max && proc_get_euid() != 0)
        return LINUX_EPERM;
    if (resource == LINUX_RLIMIT_NOFILE && new_lim->rlim_max > FD_TABLE_SIZE)
        return LINUX_EPERM;

    rlimit_slot_store(t, resource, *new_lim);
    return 0;
}

int64_t sys_prlimit64(guest_t *g,
                      int pid,
                      int resource,
                      uint64_t new_gva,
                      uint64_t old_gva)
{
    if (!RANGE_CHECK(resource, 0, LINUX_RLIMIT_COUNT))
        return -LINUX_EINVAL;

    linux_rlimit64_t new_lim, old_lim;
    if (new_gva != 0 &&
        guest_read_small(g, new_gva, &new_lim, sizeof(new_lim)) < 0)
        return -LINUX_EFAULT;
    const linux_rlimit64_t *set = new_gva ? &new_lim : NULL;

    /* find_task_by_vpid takes any thread id, and limits belong to the thread
     * group, so a tid of this process names this process. A VM-clone child is a
     * process of its own whose table is not reachable from here, like any other
     * pid, so it is ESRCH unless it names itself.
     */
    if (pid != 0 && pid != proc_get_pid() &&
        !(current_thread && pid == thread_tid(current_thread)) &&
        !(pid > 0 && thread_tid_in_group(pid)))
        return -LINUX_ESRCH;

    pthread_mutex_lock(&rlimit_lock);
    int err = rlimit_exchange(&rlimit_private, resource, set, &old_lim);
    pthread_mutex_unlock(&rlimit_lock);
    if (err)
        return -err;

    /* As in Linux, a new limit stays applied when the old one cannot be written
     * back.
     */
    if (old_gva != 0 &&
        guest_write_small(g, old_gva, &old_lim, sizeof(old_lim)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* Format /proc/self/limits content into buf.
 * Returns bytes written (excluding NUL) or -1 on error.
 */
int sys_format_limits(char *buf, size_t bufsz)
{
    /* Names, units and order of lnames in Linux fs/proc/base.c, indexed by
     * resource number.
     */
    static const struct {
        const char *name, *units;
    } rows[LINUX_RLIMIT_COUNT] = {
        [LINUX_RLIMIT_CPU] = {"Max cpu time", "seconds"},
        [LINUX_RLIMIT_FSIZE] = {"Max file size", "bytes"},
        [LINUX_RLIMIT_DATA] = {"Max data size", "bytes"},
        [LINUX_RLIMIT_STACK] = {"Max stack size", "bytes"},
        [LINUX_RLIMIT_CORE] = {"Max core file size", "bytes"},
        [LINUX_RLIMIT_RSS] = {"Max resident set", "bytes"},
        [LINUX_RLIMIT_NPROC] = {"Max processes", "processes"},
        [LINUX_RLIMIT_NOFILE] = {"Max open files", "files"},
        [LINUX_RLIMIT_MEMLOCK] = {"Max locked memory", "bytes"},
        [LINUX_RLIMIT_AS] = {"Max address space", "bytes"},
        [LINUX_RLIMIT_LOCKS] = {"Max file locks", "locks"},
        [LINUX_RLIMIT_SIGPENDING] = {"Max pending signals", "signals"},
        [LINUX_RLIMIT_MSGQUEUE] = {"Max msgqueue size", "bytes"},
        [LINUX_RLIMIT_NICE] = {"Max nice priority", ""},
        [LINUX_RLIMIT_RTPRIO] = {"Max realtime priority", ""},
        [LINUX_RLIMIT_RTTIME] = {"Max realtime timeout", "us"},
    };

    /* One snapshot, so every row is from the same instant of the table. */
    linux_rlimit64_t limits[LINUX_RLIMIT_COUNT];
    sys_rlimit_snapshot(limits);

    int off = snprintf(buf, bufsz, "%-26s%-21s%-21s%-10s\n", "Limit",
                       "Soft Limit", "Hard Limit", "Units");
    if (off < 0)
        return -1;
    if ((size_t) off >= bufsz)
        return (int) bufsz - 1;

    for (int i = 0; i < LINUX_RLIMIT_COUNT; i++) {
        char soft[24], hard[24];
        linux_rlimit64_t lim = limits[i];

        if (lim.rlim_cur == LINUX_RLIM_INFINITY)
            snprintf(soft, sizeof(soft), "unlimited");
        else
            snprintf(soft, sizeof(soft), "%llu",
                     (unsigned long long) lim.rlim_cur);
        if (lim.rlim_max == LINUX_RLIM_INFINITY)
            snprintf(hard, sizeof(hard), "unlimited");
        else
            snprintf(hard, sizeof(hard), "%llu",
                     (unsigned long long) lim.rlim_max);

        if ((size_t) off >= bufsz)
            break;
        int n = snprintf(buf + off, bufsz - off, "%-26s%-21s%-21s%-10s\n",
                         rows[i].name, soft, hard, rows[i].units);
        if (n < 0)
            return -1;
        off += n;
        if ((size_t) off >= bufsz) {
            off = (int) bufsz - 1;
            break;
        }
    }

    return off;
}
