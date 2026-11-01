/* Same-VM RT ordering behavior; cases and prerequisites in tests/scheduler. */
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

#define SEC 1000000000ULL
#define MS 1000000ULL
#define CPUSZ 128
#define SKIP 77

int passes, fails;
static int cpus[2], ncpu, gerr;

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
static int setpol(int policy, int prio)
{
    int p = prio;
    return (int) raw_syscall3(__NR_sched_setscheduler, 0, policy, (long) &p);
}
static int pin(int cpu)
{
    unsigned char m[CPUSZ];
    memset(m, 0, sizeof(m));
    m[cpu / 8] = (unsigned char) (1u << (cpu % 8));
    return (int) raw_syscall3(__NR_sched_setaffinity, 0, sizeof(m), (long) m);
}
static int allowed(void)
{
    unsigned char m[CPUSZ];
    memset(m, 0, sizeof(m));
    if (raw_syscall3(__NR_sched_getaffinity, 0, sizeof(m), (long) m) < 0)
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
        printf("SKIP: RT scheduling privilege unavailable\n");
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
        if (seen == v)
            continue;
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
static int rt_ready(int policy, int prio, _Atomic int *ready)
{
    int rc = pin(cpus[0]);
    if (!rc)
        rc = setpol(policy, prio);
    note(rc);
    atomic_fetch_add_explicit(ready, 1, memory_order_release);
    wake(ready);
    return rc;
}

/* rr-rotation */
static _Atomic int rr_ready, rr_go, rr_saw[2];
static _Atomic unsigned long rr_n[2];
static void *rr_rot(void *arg)
{
    int i = (int) (intptr_t) arg;
    if (rt_ready(SCHED_RR, 50, &rr_ready)) {
        atomic_store(&rr_saw[i], -1);
        return NULL;
    }
    waitw(&rr_go, 1, 3000);
    uint64_t end = mono() + 400 * MS;
    int seen = 0;
    while (mono() < end) {
        atomic_fetch_add_explicit(&rr_n[i], 1, memory_order_relaxed);
        if (atomic_load_explicit(&rr_n[1 - i], memory_order_relaxed)) {
            seen = 1;
            break;
        }
    }
    atomic_store(&rr_saw[i], seen);
    return NULL;
}
static int sc_rotate(void)
{
    pthread_t a, b;
    if (spawn(&a, rr_rot, (void *) 0) || spawn(&b, rr_rot, (void *) 1) ||
        waitge(&rr_ready, 2, 3000)) {
        TEST("pthread_create RR peers");
        FAIL("worker start failed");
        return 1;
    }
    int v = verdict();
    if (v)
        return v;
    setw(&rr_go, 1);
    (void) waitge(&rr_saw[0], 1, 2000);
    (void) waitge(&rr_saw[1], 1, 2000);
    TEST("equal-priority RR peers rotate");
    if (rr_saw[0] == 1 && rr_saw[1] == 1)
        PASS();
    else
        FAIL("RR peer starved: quantum did not rotate");
    return 0;
}

/* rr-preempt-quantum */
static _Atomic int q_ready, q_ago, q_bgo, q_hgo, q_hblock;
static _Atomic int q_phase, q_first, q_hran, q_acnt;
static _Atomic int q_adone, q_bdone, q_hdone, q_to;
static void *q_a(void *arg)
{
    (void) arg;
    if (rt_ready(SCHED_RR, 50, &q_ready)) {
        atomic_store(&q_adone, 1);
        return NULL;
    }
    waitw(&q_ago, 1, 3000);
    for (int i = 0; i < 2000; i++)
        atomic_fetch_add(&q_acnt, 1);
    setw(&q_bgo, 1);
    for (int i = 0; i < 2000; i++)
        atomic_fetch_add(&q_acnt, 1);
    setw(&q_hgo, 1);
    uint64_t end = mono() + 400 * MS;
    while (mono() < end && atomic_load(&q_phase) != 2)
        atomic_fetch_add(&q_acnt, 1);
    if (atomic_load(&q_phase) == 2) {
        int z = 0;
        (void) atomic_compare_exchange_strong(&q_first, &z, 1);
    } else {
        atomic_store(&q_to, 1);
    }
    atomic_store(&q_adone, 1);
    return NULL;
}
static void *q_b(void *arg)
{
    (void) arg;
    if (rt_ready(SCHED_RR, 50, &q_ready)) {
        atomic_store(&q_bdone, 1);
        return NULL;
    }
    waitw(&q_bgo, 1, 3000);
    uint64_t end = mono() + 400 * MS;
    while (mono() < end && atomic_load(&q_phase) != 2)
        ;
    if (atomic_load(&q_phase) == 2) {
        int z = 0;
        (void) atomic_compare_exchange_strong(&q_first, &z, 2);
    } else {
        atomic_store(&q_to, 1);
    }
    atomic_store(&q_bdone, 1);
    return NULL;
}
static void *q_h(void *arg)
{
    (void) arg;
    if (rt_ready(SCHED_FIFO, 60, &q_ready)) {
        atomic_store(&q_hdone, 1);
        return NULL;
    }
    waitw(&q_hgo, 1, 3000);
    if (q_hgo) {
        atomic_store(&q_hran, 1);
        atomic_store_explicit(&q_phase, 2, memory_order_release);
        waitw(&q_hblock, 1, 3000);
    }
    atomic_store(&q_hdone, 1);
    return NULL;
}
static int sc_preempt(void)
{
    pthread_t a, b, h;
    if (spawn(&a, q_a, NULL) || spawn(&b, q_b, NULL) || spawn(&h, q_h, NULL) ||
        waitge(&q_ready, 3, 3000)) {
        TEST("pthread_create RR/FIFO tasks");
        FAIL("worker start failed");
        return 1;
    }
    int v = verdict();
    if (v)
        return v;
    setw(&q_ago, 1);
    (void) waitge(&q_first, 1, 2000);
    int first = q_first, hran = q_hran, to = q_to;
    setw(&q_hblock, 1);
    (void) waitge(&q_adone, 1, 1000);
    (void) waitge(&q_bdone, 1, 1000);
    (void) waitge(&q_hdone, 1, 1000);
    TEST("high-priority wake preserves RR head/quantum");
    if (hran == 1 && first == 1)
        PASS();
    else {
        printf("  hran=%d first=%d timeout=%d\n", hran, first, to);
        FAIL("preempted RR task lost its head position");
    }
    return 0;
}

/* fifo-yield-order */
static _Atomic int f_ready, f_ago, f_bgo, f_cgo, f_yielded;
static _Atomic int f_bran, f_cran, f_early, f_first, f_before, f_after, f_done;
static void *f_a(void *arg)
{
    (void) arg;
    if (rt_ready(SCHED_FIFO, 50, &f_ready))
        return NULL;
    waitw(&f_ago, 1, 3000);
    setw(&f_bgo, 1);
    uint64_t end = mono() + 2 * MS;
    while (mono() < end && !f_bran && !f_cran)
        ;
    setw(&f_cgo, 1);
    end = mono() + 2 * MS;
    while (mono() < end && !f_bran && !f_cran)
        ;
    atomic_store(&f_before, f_bran || f_cran);
    atomic_store(&f_yielded, 1);
    (void) raw_syscall0(__NR_sched_yield);
    atomic_store(&f_after, f_bran && f_cran);
    atomic_store_explicit(&f_done, 1, memory_order_release);
    return NULL;
}
static void *f_peer(void *arg)
{
    int id = (int) (intptr_t) arg;
    _Atomic int *gate = id == 1 ? &f_bgo : &f_cgo;
    if (rt_ready(SCHED_FIFO, 50, &f_ready))
        return NULL;
    while (!atomic_load_explicit(gate, memory_order_acquire))
        (void) raw_futex_wait((int *) gate, 0);
    if (id == 1)
        atomic_store(&f_bran, 1);
    else
        atomic_store(&f_cran, 1);
    if (!f_yielded)
        atomic_store(&f_early, 1);
    int z = 0;
    (void) atomic_compare_exchange_strong(&f_first, &z, id);
    return NULL;
}
static int sc_yield(void)
{
    pthread_t a, b, c;
    if (spawn(&a, f_a, NULL) || spawn(&b, f_peer, (void *) 1) ||
        spawn(&c, f_peer, (void *) 2) || waitge(&f_ready, 3, 3000)) {
        TEST("pthread_create FIFO peers");
        FAIL("worker start failed");
        return 1;
    }
    int v = verdict();
    if (v)
        return v;
    setw(&f_ago, 1);
    (void) waitge(&f_bran, 1, 1000);
    (void) waitge(&f_cran, 1, 1000);
    (void) waitge(&f_done, 1, 1000);
    TEST("FIFO wake tail and yield order");
    if (!f_before && f_after && !f_early && f_first == 1)
        PASS();
    else {
        printf("  before=%d after=%d early=%d first=%d\n", f_before, f_after,
               f_early, f_first);
        FAIL("FIFO wake/yield ordering differs from Linux");
    }
    return 0;
}

/* fifo-wake-preempt */
static _Atomic int w_ready, w_ago, w_hgo, w_hblock, w_hran, w_after;
static void *w_a(void *arg)
{
    (void) arg;
    if (rt_ready(SCHED_FIFO, 50, &w_ready))
        return NULL;
    waitw(&w_ago, 1, 3000);
    setw(&w_hgo, 1);
    uint64_t end = mono() + 150 * MS;
    while (mono() < end && !w_hran)
        ;
    atomic_store(&w_after, w_hran);
    return NULL;
}
static void *w_h(void *arg)
{
    (void) arg;
    if (rt_ready(SCHED_FIFO, 60, &w_ready))
        return NULL;
    waitw(&w_hgo, 1, 3000);
    if (w_hgo) {
        atomic_store(&w_hran, 1);
        waitw(&w_hblock, 1, 3000);
    }
    return NULL;
}
static int sc_wake(void)
{
    pthread_t a, h;
    if (spawn(&a, w_a, NULL) || spawn(&h, w_h, NULL) ||
        waitge(&w_ready, 2, 3000)) {
        TEST("pthread_create FIFO tasks");
        FAIL("worker start failed");
        return 1;
    }
    int v = verdict();
    if (v)
        return v;
    setw(&w_ago, 1);
    (void) waitge(&w_after, 1, 1000);
    setw(&w_hblock, 1);
    TEST("higher-priority FIFO wake preempts");
    if (w_hran && w_after)
        PASS();
    else
        FAIL("higher-priority wake did not preempt the runner");
    return 0;
}

static const struct {
    const char *name;
    int (*run)(void);
} scenarios[] = {
    {"rr-rotation", sc_rotate},
    {"rr-preempt-quantum", sc_preempt},
    {"fifo-yield-order", sc_yield},
    {"fifo-wake-preempt", sc_wake},
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
        printf("test-sched-policy-rt: %s\n", scenarios[i].name);
        int rc = scenarios[i].run();
        if (rc == SKIP)
            return SKIP;
        SUMMARY(scenarios[i].name);
        return fails ? 1 : rc;
    }
    fprintf(stderr, "error: unknown scenario: %s\n", argv[1]);
    return 2;
}
