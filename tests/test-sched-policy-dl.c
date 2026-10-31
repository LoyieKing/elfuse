/* Same-VM DEADLINE and affinity-migration behavior; see tests/scheduler. */
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "raw-syscall.h"
#include "test-harness.h"

#ifndef __NR_sched_setattr
#define __NR_sched_setattr 314
#endif
#ifndef __NR_getcpu
#define __NR_getcpu 309
#endif
#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif

#define SEC 1000000000ULL
#define MS 1000000ULL
#define CPUSZ 128
#define SKIP 77

int passes, fails;
static int cpus[2], ncpu, gerr;

struct sched_attr_wire {
    uint32_t size, policy;
    uint64_t flags;
    int32_t nice;
    uint32_t priority;
    uint64_t runtime, deadline, period;
    uint32_t util_min, util_max;
};
_Static_assert(sizeof(struct sched_attr_wire) == 56, "sched_attr size");

static uint64_t clk(clockid_t id)
{
    struct timespec ts;
    return clock_gettime(id, &ts) == 0
               ? (uint64_t) ts.tv_sec * SEC + (uint64_t) ts.tv_nsec
               : 0;
}
static uint64_t mono(void)
{
    return clk(CLOCK_MONOTONIC);
}
static uint64_t selfcpu(void)
{
    return clk(CLOCK_THREAD_CPUTIME_ID);
}

/* Linux dynamic per-thread clock: (~tid << 3) | CPUCLOCK_SCHED |
 * CPUCLOCK_PERTHREAD_MASK.
 */
static clockid_t tclock(pid_t tid)
{
    return (clockid_t) (((~(uint64_t) (uint32_t) tid) << 3) | 6);
}
static uint64_t remotecpu(pid_t tid)
{
    return clk(tclock(tid));
}

static int setdl(uint64_t runtime, uint64_t deadline, uint64_t period)
{
    struct sched_attr_wire a;
    memset(&a, 0, sizeof(a));
    a.size = sizeof(a);
    a.policy = SCHED_DEADLINE;
    a.runtime = runtime;
    a.deadline = deadline;
    a.period = period;
    return (int) raw_syscall3(__NR_sched_setattr, 0, (long) &a, 0);
}
static int pin(pid_t tid, int cpu)
{
    unsigned char m[CPUSZ];
    memset(m, 0, sizeof(m));
    m[cpu / 8] = (unsigned char) (1u << (cpu % 8));
    return (int) raw_syscall3(__NR_sched_setaffinity, (long) tid, sizeof(m),
                              (long) m);
}
static int getmask(pid_t tid, unsigned char *m)
{
    memset(m, 0, CPUSZ);
    return (int) raw_syscall3(__NR_sched_getaffinity, (long) tid, CPUSZ,
                              (long) m);
}
static int cpunow(void)
{
    uint32_t c = 0;
    return raw_syscall3(__NR_getcpu, (long) &c, 0, 0) == 0 ? (int) c : -1;
}
static int allowed(void)
{
    unsigned char m[CPUSZ];
    if (getmask(0, m) < 0)
        return -1;
    ncpu = 0;
    for (int i = 0; i < CPUSZ * 8 && ncpu < 2; i++)
        if (m[i / 8] & (unsigned char) (1u << (i % 8)))
            cpus[ncpu++] = i;
    return ncpu;
}
static void note(int rc)
{
    int z = 0;
    if (rc)
        (void) atomic_compare_exchange_strong(&gerr, &z, rc);
}
static int verdict(void)
{
    if (!gerr)
        return 0;
    if (gerr == -EPERM) {
        printf("SKIP: CAP_SYS_NICE unavailable\n");
        return SKIP;
    }
    printf("  setup failed: %s\n", strerror(-gerr));
    fails++;
    return 1;
}
static void wake(_Atomic int *p)
{
    (void) raw_futex_wake((int *) p, 1 << 30);
}
static void setw(_Atomic int *p, int v)
{
    atomic_store_explicit(p, v, memory_order_release);
    wake(p);
}
static void waitw(_Atomic int *p, int v, int ms)
{
    uint64_t end = mono() + (uint64_t) ms * MS;
    while (atomic_load_explicit(p, memory_order_acquire) != v && mono() < end) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * MS};
        int seen = atomic_load_explicit(p, memory_order_relaxed);
        (void) raw_syscall6(__NR_futex, (long) p,
                            FUTEX_WAIT | FUTEX_PRIVATE_FLAG, seen, (long) &ts,
                            0, 0);
    }
}
static int waitge(_Atomic int *p, int v, int ms)
{
    uint64_t end = mono() + (uint64_t) ms * MS;
    while (atomic_load_explicit(p, memory_order_acquire) < v) {
        if (mono() >= end)
            return -1;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 2 * MS};
        nanosleep(&ts, NULL);
    }
    return 0;
}
static int spawn(pthread_t *t, void *(*f)(void *), void *a)
{
    if (pthread_create(t, NULL, f, a))
        return -1;
    pthread_detach(*t);
    return 0;
}

/* deadline-throttle */
static _Atomic int dt_ready, dt_done, dt_gaps;
static _Atomic uint64_t dt_burst, dt_min, dt_max;
static void *dt_thr(void *arg)
{
    (void) arg;
    int rc = pin(0, cpus[0]);
    if (!rc)
        rc = setdl(20 * MS, 200 * MS, 200 * MS);
    note(rc);
    atomic_store_explicit(&dt_ready, 1, memory_order_release);
    wake(&dt_ready);
    if (rc) {
        atomic_store(&dt_done, 1);
        return NULL;
    }
    uint64_t start = mono(), prev = start, first = 0, min = ~0ULL, max = 0;
    int gaps = 0;
    while (mono() < start + 1200 * MS) {
        volatile uint64_t acc = 0;
        for (int i = 0; i < 4096; i++)
            acc += (uint64_t) i;
        (void) acc;
        uint64_t now = mono(), gap = now - prev;
        if (gap >= 100 * MS) {
            if (!gaps)
                first = prev;
            if (gap < min)
                min = gap;
            if (gap > max)
                max = gap;
            if (++gaps >= 2)
                break;
        }
        prev = now;
    }
    atomic_store(&dt_gaps, gaps);
    atomic_store(&dt_burst, first ? first - start : 0);
    atomic_store(&dt_min, gaps ? min : 0);
    atomic_store(&dt_max, max);
    atomic_store(&dt_done, 1);
    return NULL;
}
static int sc_throttle(void)
{
    pthread_t t;
    if (spawn(&t, dt_thr, NULL) || waitge(&dt_ready, 1, 1000)) {
        TEST("pthread_create deadline task");
        FAIL("worker start failed");
        return 1;
    }
    int v = verdict();
    if (v)
        return v;
    if (waitge(&dt_done, 1, 2500)) {
        TEST("deadline throttle");
        FAIL("deadline task hung");
        return 1;
    }
    TEST("solo deadline runtime throttle");
    if (dt_gaps >= 2 && dt_burst >= 5 * MS && dt_burst <= 150 * MS &&
        dt_min >= 100 * MS && dt_max <= 400 * MS)
        PASS();
    else {
        printf("  gaps=%d burst=%llu min=%llu max=%llu us\n", (int) dt_gaps,
               (unsigned long long) (dt_burst / 1000),
               (unsigned long long) (dt_min / 1000),
               (unsigned long long) (dt_max / 1000));
        FAIL("deadline throttling/replenishment bounds not met");
    }
    return 0;
}

/* deadline-yield */
static _Atomic int dy_ready, dy_done, dy_rc;
static _Atomic uint64_t dy_delay;
static void *dy_thr(void *arg)
{
    (void) arg;
    int rc = pin(0, cpus[0]);
    if (!rc)
        rc = setdl(100 * MS, 300 * MS, 300 * MS);
    note(rc);
    atomic_store_explicit(&dy_ready, 1, memory_order_release);
    wake(&dy_ready);
    if (rc) {
        atomic_store(&dy_done, 1);
        return NULL;
    }
    volatile uint64_t acc = 0;
    for (int i = 0; i < 100000; i++)
        acc += (uint64_t) i;
    (void) acc;
    uint64_t before = mono();
    long yr = raw_syscall0(__NR_sched_yield);
    uint64_t after = mono();
    atomic_store(&dy_rc, (int) yr);
    atomic_store(&dy_delay, after - before);
    atomic_store(&dy_done, 1);
    return NULL;
}
static int sc_yield(void)
{
    pthread_t t;
    if (spawn(&t, dy_thr, NULL) || waitge(&dy_ready, 1, 1000)) {
        TEST("pthread_create deadline yielder");
        FAIL("worker start failed");
        return 1;
    }
    int v = verdict();
    if (v)
        return v;
    if (waitge(&dy_done, 1, 2000)) {
        TEST("deadline yield");
        FAIL("yield did not return");
        return 1;
    }
    TEST("deadline yield waits for replenishment");
    if (dy_rc == 0 && dy_delay >= 150 * MS && dy_delay <= 600 * MS)
        PASS();
    else {
        printf("  rc=%d delay=%llu us\n", dy_rc,
               (unsigned long long) (dy_delay / 1000));
        FAIL("yield did not discard runtime until replenishment");
    }
    return 0;
}

/* affinity-migrate */
static _Atomic int am_ready, am_migrated, am_done, am_bad, am_release, am_tid;
static _Atomic int am_seen;
static _Atomic uint64_t am_at, am_after, am_spin;
static void *am_thr(void *arg)
{
    (void) arg;
    int rc = pin(0, cpus[0]);
    note(rc);
    atomic_store(&am_tid, (int) raw_syscall0(__NR_gettid));
    atomic_store_explicit(&am_ready, 1, memory_order_release);
    wake(&am_ready);
    if (rc)
        return NULL;
    uint64_t end = mono() + 1500 * MS;
    while (mono() < end && cpunow() != cpus[1])
        ;
    if (cpunow() != cpus[1]) {
        atomic_store(&am_bad, 1);
        atomic_store(&am_done, 1);
        return NULL;
    }
    atomic_store(&am_at, selfcpu());
    atomic_store(&am_seen, cpunow());
    setw(&am_migrated, 1);
    uint64_t s = mono();
    while (mono() - s < 150 * MS) {
        volatile uint64_t acc = 0;
        for (int i = 0; i < 4096; i++)
            acc += (uint64_t) i;
        (void) acc;
    }
    atomic_store(&am_spin, mono() - s);
    atomic_store(&am_after, selfcpu());
    atomic_store(&am_done, 1);
    waitw(&am_release, 1, 2000);
    return NULL;
}
static int sc_migrate(void)
{
    if (ncpu < 2) {
        printf("SKIP: migration needs two allowed CPUs\n");
        return SKIP;
    }
    pthread_t t;
    if (spawn(&t, am_thr, NULL) || waitge(&am_ready, 1, 1000)) {
        TEST("pthread_create migrating task");
        FAIL("worker start failed");
        return 1;
    }
    int v = verdict();
    if (v)
        return v;
    pid_t tid = (pid_t) am_tid;
    uint64_t before = 0, end = mono() + 1000 * MS;
    while (mono() < end) {
        before = remotecpu(tid);
        if (before >= 20 * MS)
            break;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 2 * MS};
        nanosleep(&ts, NULL);
    }
    TEST("source CPU ledger advances");
    if (before < 20 * MS) {
        FAIL("thread CPU clock did not advance before migration");
        setw(&am_release, 1);
        return 1;
    }
    PASS();
    if (pin(tid, cpus[1]) || waitge(&am_migrated, 1, 1500) || am_bad) {
        TEST("remote setaffinity migrates runner");
        FAIL("task did not move to the target CPU");
        setw(&am_release, 1);
        return 1;
    }
    unsigned char m[CPUSZ];
    int mask_ok = getmask(tid, m) > 0;
    for (int i = 0; i < CPUSZ * 8; i++) {
        int set = (m[i / 8] & (unsigned char) (1u << (i % 8))) != 0;
        if (set != (i == cpus[1]))
            mask_ok = 0;
    }
    TEST("migration visible to getaffinity/getcpu");
    if (mask_ok && am_seen == cpus[1])
        PASS();
    else
        FAIL("migrated task does not report the target CPU");
    if (waitge(&am_done, 1, 2000)) {
        TEST("migrated task runs on target");
        FAIL("post-migration window did not finish");
        setw(&am_release, 1);
        return 1;
    }
    uint64_t after = remotecpu(tid),
             own = am_after > am_at ? am_after - am_at : 0;
    uint64_t rem = after > before ? after - before : 0;
    TEST("CPU-time ledger survives migration");
    if (am_at >= 20 * MS && own >= am_spin / 3 &&
        own <= am_spin * 2 + 50 * MS && rem >= am_spin / 3 &&
        rem <= am_spin + 200 * MS)
        PASS();
    else {
        printf("  at=%llu own=%llu rem=%llu spin=%llu us\n",
               (unsigned long long) (am_at / 1000),
               (unsigned long long) (own / 1000),
               (unsigned long long) (rem / 1000),
               (unsigned long long) (am_spin / 1000));
        FAIL("thread CPU time lost or doubled across migration");
    }
    setw(&am_release, 1);
    return 0;
}

static const struct {
    const char *name;
    int (*run)(void);
} scenarios[] = {
    {"deadline-throttle", sc_throttle},
    {"deadline-yield", sc_yield},
    {"affinity-migrate", sc_migrate},
};

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && !strcmp(argv[1], "--list")) {
        for (unsigned i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++)
            printf("%s\n", scenarios[i].name);
        return 0;
    }
    if (argc != 2) {
        fprintf(stderr, "usage: %s <scenario|--list>\n", argv[0]);
        return 2;
    }
    if (allowed() < 1) {
        printf("SKIP: no allowed CPU\n");
        return SKIP;
    }
    for (unsigned i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++) {
        if (strcmp(argv[1], scenarios[i].name))
            continue;
        printf("test-sched-policy-dl: %s\n", scenarios[i].name);
        int rc = scenarios[i].run();
        if (rc == SKIP)
            return SKIP;
        SUMMARY(scenarios[i].name);
        return fails ? 1 : rc;
    }
    fprintf(stderr, "error: unknown scenario: %s\n", argv[1]);
    return 2;
}
