/*
 * Linux task scheduler state: per-thread nice, signal-handler affinity changed
 * across rt_sigreturn, and process CPU time retained after a thread exits.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exit status: 0 pass, 1 fail, 77 prerequisite unavailable (skip).
 */

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "raw-syscall.h"
#include "test-harness.h"

#define SKIP_EXIT 77
#define NSEC_PER_SEC 1000000000ULL

static int passes;
static int fails;

static int skip(const char *why)
{
    printf("SKIP: %s\n", why);
    return SKIP_EXIT;
}

static int clock_ns(clockid_t id, unsigned long long *out)
{
    struct timespec ts;

    if (clock_gettime(id, &ts) != 0)
        return -1;
    *out = (unsigned long long) ts.tv_sec * NSEC_PER_SEC +
           (unsigned long long) ts.tv_nsec;
    return 0;
}

static int task_nice(pid_t tid, int *out)
{
    errno = 0;
    *out = getpriority(PRIO_PROCESS, (id_t) tid);
    return *out == -1 && errno != 0 ? -1 : 0;
}

static int affinity_count(const cpu_set_t *mask, int *first, int *second)
{
    int count = 0;

    *first = -1;
    *second = -1;
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, mask))
            continue;
        if (count == 0)
            *first = cpu;
        else if (count == 1)
            *second = cpu;
        count++;
    }
    return count;
}

static int affinity_is_only(const cpu_set_t *mask, int cpu)
{
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (!!CPU_ISSET(i, mask) != (i == cpu))
            return 0;
    }
    return 1;
}

static void affinity_set_one(cpu_set_t *mask, int cpu)
{
    CPU_ZERO(mask);
    CPU_SET(cpu, mask);
}

/* Return 0 with distinct values, -1 on error, 1 when nice is 19 and cannot be
 * lowered without CAP_SYS_NICE.
 */
static int nice_pair(int *parent_out, int *child_out)
{
    int start;

    if (task_nice(0, &start) != 0)
        return -1;
    if (start <= 17) {
        *parent_out = start + 1;
        *child_out = start + 2;
    } else if (start == 18 || setpriority(PRIO_PROCESS, 0, 18) == 0) {
        *parent_out = 18;
        *child_out = 19;
    } else {
        return 1;
    }
    if (*parent_out != start && setpriority(PRIO_PROCESS, 0, *parent_out))
        return -1;
    return 0;
}

struct nice_probe {
    pthread_barrier_t ready;
    pthread_barrier_t done;
    pid_t tid;
    int initial, initial_err, target, set_rc, set_err, final, final_err;
};

static void *nice_worker(void *arg)
{
    struct nice_probe *p = arg;

    p->tid = (pid_t) raw_syscall0(SYS_gettid);
    p->initial_err = task_nice(0, &p->initial) != 0 ? errno : 0;
    errno = 0;
    p->set_rc = setpriority(PRIO_PROCESS, 0, p->target);
    p->set_err = errno;
    pthread_barrier_wait(&p->ready);
    pthread_barrier_wait(&p->done);
    p->final_err = task_nice(0, &p->final) != 0 ? errno : 0;
    return NULL;
}

static int scenario_nice(void)
{
    struct nice_probe p;
    pthread_t thread;
    int parent_nice, child_nice, current, remote, rc;

    rc = nice_pair(&parent_nice, &child_nice);
    if (rc < 0) {
        TEST("prepare per-thread nice");
        FAIL("getpriority/setpriority");
        return 1;
    }
    if (rc > 0)
        return skip("nice is 19 and CAP_SYS_NICE is unavailable");
    if (parent_nice != 0) {
        TEST("raise caller nice");
        EXPECT_EQ(setpriority(PRIO_PROCESS, 0, parent_nice), 0,
                  "setpriority failed");
    }

    memset(&p, 0, sizeof(p));
    p.target = child_nice;
    pthread_barrier_init(&p.ready, NULL, 2);
    pthread_barrier_init(&p.done, NULL, 2);
    rc = pthread_create(&thread, NULL, nice_worker, &p);
    if (rc != 0) {
        TEST("create nice worker");
        FAIL("pthread_create");
        return 1;
    }
    pthread_barrier_wait(&p.ready);

    TEST("thread inherits creator nice");
    EXPECT_EQ(p.initial_err, 0, "getpriority failed in worker");
    EXPECT_EQ(p.initial, parent_nice, "nice was not inherited");
    TEST("worker raises its own nice");
    if (p.set_rc == 0) {
        PASS();
    } else {
        errno = p.set_err;
        FAIL("setpriority in worker");
    }
    TEST("creator nice is isolated");
    if (task_nice(0, &current) == 0)
        EXPECT_EQ(current, parent_nice, "worker nice leaked to creator");
    else
        FAIL("getpriority(caller)");
    TEST("remote getpriority(tid) sees thread nice");
    if (task_nice(p.tid, &remote) == 0)
        EXPECT_EQ(remote, child_nice, "remote TID saw wrong nice");
    else
        FAIL("getpriority(worker tid)");

    pthread_barrier_wait(&p.done);
    pthread_join(thread, NULL);
    TEST("worker keeps changed nice");
    EXPECT_EQ(p.final_err, 0, "getpriority failed after barrier");
    EXPECT_EQ(p.final, child_nice, "worker nice changed again");
    TEST("creator nice unchanged after join");
    if (task_nice(0, &current) == 0)
        EXPECT_EQ(current, parent_nice, "creator nice changed after join");
    else
        FAIL("getpriority(caller after join)");
    pthread_barrier_destroy(&p.ready);
    pthread_barrier_destroy(&p.done);
    return fails ? 1 : 0;
}

static volatile sig_atomic_t sig_count, sig_rc, sig_errno_value;
static volatile sig_atomic_t sig_handler_mask_ok;
static int sig_target_cpu;

/* Confirms from inside the handler that the new mask is installed, so the
 * post-return check proves rt_sigreturn preserved handler-written task state.
 */
static void affinity_handler(int signo)
{
    cpu_set_t mask, observed = {0};

    (void) signo;
    sig_count++;
    affinity_set_one(&mask, sig_target_cpu);
    sig_rc = (sig_atomic_t) raw_syscall3(SYS_sched_setaffinity, 0,
                                         (long) sizeof(mask), (long) &mask);
    sig_errno_value = (sig_atomic_t) (sig_rc < 0 ? -sig_rc : 0);
    sig_handler_mask_ok =
        raw_syscall3(SYS_sched_getaffinity, 0, (long) sizeof(observed),
                     (long) &observed) > 0 &&
        affinity_is_only(&observed, sig_target_cpu);
}

static int scenario_signal_affinity(void)
{
    cpu_set_t original, one, after;
    sigset_t initial_mask, after_mask;
    struct sigaction sa, old_sa;
    int cpu_a, cpu_b, ncpu, raise_rc = 0;
    volatile sig_atomic_t ticks = 0;
    volatile unsigned long acc = 0, expected = 0;
    char reason[128];

    if (sched_getaffinity(0, sizeof(original), &original) != 0) {
        TEST("read caller affinity");
        FAIL("sched_getaffinity");
        return 1;
    }
    ncpu = affinity_count(&original, &cpu_a, &cpu_b);
    if (ncpu < 2) {
        snprintf(reason, sizeof(reason),
                 "affinity mask has %d CPU(s); migration needs 2", ncpu);
        return skip(reason);
    }
    if (sigprocmask(SIG_SETMASK, NULL, &initial_mask) != 0) {
        TEST("read signal mask");
        FAIL("sigprocmask");
        return 1;
    }
    if (sigismember(&initial_mask, SIGUSR1))
        return skip("SIGUSR1 is blocked in the caller");

    affinity_set_one(&one, cpu_a);
    TEST("pin caller to first CPU");
    EXPECT_EQ(sched_setaffinity(0, sizeof(one), &one), 0,
              "sched_setaffinity failed");
    TEST("caller is on first CPU");
    if (sched_getaffinity(0, sizeof(after), &after) == 0)
        EXPECT_TRUE(affinity_is_only(&after, cpu_a), "mask is not first CPU");
    else
        FAIL("sched_getaffinity after pin");

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = affinity_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    TEST("install SIGUSR1 handler");
    EXPECT_EQ(sigaction(SIGUSR1, &sa, &old_sa), 0, "sigaction failed");

    sig_count = 0;
    sig_rc = -1;
    sig_errno_value = 0;
    sig_handler_mask_ok = 0;
    sig_target_cpu = cpu_b;
    for (int i = 0; i < 1000; i++) {
        acc = acc * 31u + (unsigned long) i;
        ticks++;
        if (i == 500)
            raise_rc = raise(SIGUSR1);
    }
    for (int i = 0; i < 1000; i++)
        expected = expected * 31u + (unsigned long) i;

    TEST("raise(SIGUSR1) delivered");
    EXPECT_EQ(raise_rc, 0, "raise failed");
    TEST("handler ran once and installed affinity");
    EXPECT_EQ(sig_count, 1, "handler did not run exactly once");
    if (sig_rc == 0) {
        PASS();
    } else {
        errno = sig_errno_value;
        FAIL("handler sched_setaffinity failed");
    }
    TEST("handler already observed new affinity");
    EXPECT_EQ(sig_handler_mask_ok, 1, "handler did not observe new mask");
    TEST("interrupted loop state intact");
    EXPECT_EQ(ticks, 1000, "loop state was corrupted");
    EXPECT_EQ(acc, expected, "interrupted local state was corrupted");
    TEST("rt_sigreturn restored signal mask");
    if (sigprocmask(SIG_SETMASK, NULL, &after_mask) == 0)
        EXPECT_TRUE(!sigismember(&after_mask, SIGUSR1),
                    "SIGUSR1 still blocked after handler");
    else
        FAIL("sigprocmask after handler");
    TEST("rt_sigreturn kept handler affinity");
    if (sched_getaffinity(0, sizeof(after), &after) == 0)
        EXPECT_TRUE(affinity_is_only(&after, cpu_b),
                    "affinity reverted across rt_sigreturn");
    else
        FAIL("sched_getaffinity after rt_sigreturn");
    TEST("remote query sees handler affinity");
    if (sched_getaffinity((pid_t) raw_syscall0(SYS_gettid), sizeof(after),
                          &after) == 0)
        EXPECT_TRUE(affinity_is_only(&after, cpu_b),
                    "remote TID saw old affinity");
    else
        FAIL("sched_getaffinity(remote tid)");

    (void) sched_setaffinity(0, sizeof(original), &original);
    (void) sigaction(SIGUSR1, &old_sa, NULL);
    return fails ? 1 : 0;
}

#define CPU_TARGET_NS (20ULL * 1000ULL * 1000ULL)
#define CPU_WALL_GUARD_NS (5ULL * 1000ULL * 1000ULL * 1000ULL)

struct cpu_probe {
    unsigned long long delta_ns;
    int err;
};

static void *cpu_worker(void *arg)
{
    struct cpu_probe *p = arg;
    unsigned long long start, end, wall_start, wall;
    volatile unsigned long long sink = 1;
    int done = 0;

    if (clock_ns(CLOCK_THREAD_CPUTIME_ID, &start) != 0 ||
        clock_ns(CLOCK_MONOTONIC, &wall_start) != 0) {
        p->err = errno;
        return NULL;
    }
    while (!done) {
        for (int i = 0; i < 20000; i++)
            sink = sink * 6364136223846793005ULL + 1442695040888963407ULL;
        if (clock_ns(CLOCK_THREAD_CPUTIME_ID, &end) != 0) {
            p->err = errno;
            return NULL;
        }
        done = end - start >= CPU_TARGET_NS;
        if (!done && clock_ns(CLOCK_MONOTONIC, &wall) == 0 &&
            wall - wall_start >= CPU_WALL_GUARD_NS)
            done = 1;
    }
    p->delta_ns = end - start;
    return NULL;
}

static int run_cpu_round(unsigned long long before,
                         unsigned long long *after_out)
{
    struct cpu_probe probe = {0};
    pthread_t thread;
    unsigned long long after;
    int rc = pthread_create(&thread, NULL, cpu_worker, &probe);

    if (rc != 0) {
        TEST("create CPU-clock worker");
        FAIL("pthread_create");
        return -1;
    }
    pthread_join(thread, NULL);
    if (clock_ns(CLOCK_PROCESS_CPUTIME_ID, &after) != 0) {
        TEST("read process CPU clock");
        FAIL("clock_gettime(CLOCK_PROCESS_CPUTIME_ID)");
        return -1;
    }
    printf("  worker CPU=%llu ns, process delta=%llu ns\n", probe.delta_ns,
           after >= before ? after - before : 0);
    TEST("worker thread CPU clock works");
    EXPECT_EQ(probe.err, 0, "thread CPU clock failed");
    TEST("exited thread CPU stays accounted");
    EXPECT_TRUE(probe.delta_ns > 0 && after >= before &&
                    after - before >= probe.delta_ns,
                "process CPU clock dropped the exited thread's time");
    *after_out = after;
    return 0;
}

static int scenario_process_cputime(void)
{
    unsigned long long p0, p1, p2, p3;

    if (clock_ns(CLOCK_PROCESS_CPUTIME_ID, &p0) != 0) {
        TEST("read initial process CPU clock");
        FAIL("clock_gettime(CLOCK_PROCESS_CPUTIME_ID)");
        return 1;
    }
    if (run_cpu_round(p0, &p1) != 0 || run_cpu_round(p1, &p2) != 0)
        return 1;
    TEST("process CPU clock monotonic over two exits");
    EXPECT_TRUE(p2 >= p1, "process CPU clock went backwards");
    TEST("final process CPU sample monotonic");
    if (clock_ns(CLOCK_PROCESS_CPUTIME_ID, &p3) == 0)
        EXPECT_TRUE(p3 >= p2, "process CPU clock went backwards");
    else
        FAIL("clock_gettime(final sample)");
    return fails ? 1 : 0;
}

static const struct scenario {
    const char *name;
    int (*run)(void);
} scenarios[] = {
    {"nice-inherit-isolate", scenario_nice},
    {"signal-affinity-migrate", scenario_signal_affinity},
    {"process-cputime-thread-exit", scenario_process_cputime},
};

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--list") == 0) {
        for (size_t i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++)
            printf("%s\n", scenarios[i].name);
        return 0;
    }
    for (int i = 0; i < (int) (sizeof(scenarios) / sizeof(scenarios[0])); i++) {
        int rc;

        if (argc != 2 || strcmp(argv[1], scenarios[i].name) != 0)
            continue;
        printf("test-sched-task-state: %s\n", scenarios[i].name);
        rc = scenarios[i].run();
        if (rc != SKIP_EXIT)
            SUMMARY(scenarios[i].name);
        return rc;
    }
    fprintf(stderr, "usage: %s --list | SCENARIO\n", argv[0]);
    return 2;
}
