/*
 * Linux scheduler policy ABI behaviour
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises sched_setparam (118), sched_setscheduler (119), sched_getscheduler
 * (120), sched_getparam (121), sched_get_priority_max/min (125/126),
 * sched_rr_get_interval (127), and setpriority/getpriority (140/141).
 *
 * The assertions are the Linux answers for an unprivileged task: BATCH and IDLE
 * are real policies, FIFO/RR changes need CAP_SYS_NICE or a non-zero
 * RLIMIT_RTPRIO, a nice reduction needs CAP_SYS_NICE or RLIMIT_NICE, and
 * structural errors (bad priority, bad pointer, job control) win before
 * permission errors. A case that succeeds because the test runner is privileged
 * verifies the resulting state instead of skipping.
 */

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"
#include "raw-syscall.h"

#ifndef __NR_setpriority
#define __NR_setpriority 140
#endif
#ifndef __NR_getpriority
#define __NR_getpriority 141
#endif
#ifndef __NR_sched_get_priority_max
#define __NR_sched_get_priority_max 125
#endif
#ifndef __NR_sched_get_priority_min
#define __NR_sched_get_priority_min 126
#endif
#ifndef __NR_sched_rr_get_interval
#define __NR_sched_rr_get_interval 127
#endif

#define LINUX_SCHED_DEADLINE 6
#define LINUX_SCHED_EXT 7
#define LINUX_SCHED_RESET_ON_FORK 0x40000000
#ifndef PRIO_PROCESS
#define PRIO_PROCESS 0
#endif
#ifndef PRIO_PGRP
#define PRIO_PGRP 1
#endif
#ifndef PRIO_USER
#define PRIO_USER 2
#endif
#ifndef SYS_gettid
#define SYS_gettid __NR_gettid
#endif

struct sched_param_compat {
    int sched_priority;
};

struct ts_compat {
    long tv_sec;
    long tv_nsec;
};

static int passes, fails;

static int have_cap_sys_nice(void)
{
    /* elfuse models CAP_SYS_NICE as euid 0; a real Linux root has it. */
    return geteuid() == 0;
}

static long rlimit_cur(int resource)
{
    struct rlimit rl;
    if (getrlimit(resource, &rl) != 0)
        return 0;
    if (rl.rlim_cur == RLIM_INFINITY)
        return 1L << 30;
    return (long) rl.rlim_cur;
}

static int can_lower_nice_to(int nice)
{
    return have_cap_sys_nice() || (20 - nice) <= rlimit_cur(RLIMIT_NICE);
}

static int can_switch_rt_class(int priority)
{
    long rtp = rlimit_cur(RLIMIT_RTPRIO);
    return have_cap_sys_nice() || (rtp != 0 && priority <= rtp);
}

static long get_nice(void)
{
    return raw_syscall2(__NR_getpriority, PRIO_PROCESS, 0);
}

static long set_nice(long nice)
{
    return raw_syscall3(__NR_setpriority, PRIO_PROCESS, 0, nice);
}

static long set_scheduler(long policy, int priority)
{
    struct sched_param_compat p = {.sched_priority = priority};
    return raw_syscall3(__NR_sched_setscheduler, 0, policy, (long) &p);
}

struct worker_result {
    long getscheduler_rc;
    long getparam_rc;
    int param_priority;
    long setscheduler_self_rc;
    long getaffinity_rc;
    long getpriority_rc;
    long tid;
};

static void restore_other_policy(void)
{
    long policy = raw_syscall1(__NR_sched_getscheduler, 0);
    if (policy == SCHED_FIFO || policy == SCHED_RR) {
        long rc = set_scheduler(SCHED_OTHER, 0);
        if (rc != 0)
            printf("  warn: could not restore OTHER from RT (%ld)\n", rc);
    }
}

struct reset_result {
    long set_rc;
    long observed;
    long clear_rc;
};

static void *reset_worker(void *arg)
{
    struct reset_result *r = arg;
    r->set_rc = set_scheduler(SCHED_OTHER | LINUX_SCHED_RESET_ON_FORK, 0);
    r->observed = raw_syscall1(__NR_sched_getscheduler, 0);
    if (r->set_rc == 0)
        r->clear_rc = set_scheduler(SCHED_OTHER, 0);
    return NULL;
}

static _Atomic int worker_go;

static void *worker_main(void *arg)
{
    struct worker_result *out = arg;
    out->tid = raw_syscall0(SYS_gettid);

    out->getscheduler_rc =
        raw_syscall1(__NR_sched_getscheduler, (long) out->tid);

    struct sched_param_compat p = {.sched_priority = 0xdead};
    out->getparam_rc =
        raw_syscall2(__NR_sched_getparam, (long) out->tid, (long) &p);
    out->param_priority = p.sched_priority;

    struct sched_param_compat zero = {.sched_priority = 0};
    out->setscheduler_self_rc = raw_syscall3(
        __NR_sched_setscheduler, (long) out->tid, SCHED_OTHER, (long) &zero);

    unsigned long mask = 0;
    out->getaffinity_rc = raw_syscall3(__NR_sched_getaffinity, (long) out->tid,
                                       sizeof(mask), (long) &mask);

    while (atomic_load_explicit(&worker_go, memory_order_acquire) == 0)
        ;
    out->getpriority_rc =
        raw_syscall2(__NR_getpriority, PRIO_PROCESS, (long) out->tid);
    return NULL;
}

int main(void)
{
    long base_priority = get_nice();
    if (base_priority <= 0) {
        printf("test-sched-policy: getpriority failed (%ld)\n", base_priority);
        return 1;
    }
    long base_nice = 20 - base_priority;

    printf("test-sched-policy: Linux scheduler policy ABI\n");

    TEST("getscheduler(0) reports a valid policy");
    long start_policy = raw_syscall1(__NR_sched_getscheduler, 0);
    EXPECT_TRUE(start_policy == SCHED_OTHER || start_policy == SCHED_BATCH ||
                    start_policy == SCHED_IDLE || start_policy == SCHED_FIFO ||
                    start_policy == SCHED_RR,
                "get scheduler returned an invalid policy");

    TEST("getscheduler(-1) == -EINVAL");
    EXPECT_RAW_ERRNO(raw_syscall1(__NR_sched_getscheduler, -1), -EINVAL,
                     "negative pid did not return EINVAL");

    TEST("getscheduler(unknown tid) == -ESRCH");
    EXPECT_RAW_ERRNO(raw_syscall1(__NR_sched_getscheduler, 999999), -ESRCH,
                     "unknown pid did not return ESRCH");

    TEST("getparam(NULL) == -EINVAL");
    EXPECT_RAW_ERRNO(raw_syscall2(__NR_sched_getparam, 0, 0), -EINVAL,
                     "NULL param pointer did not return EINVAL");

    TEST("getparam(bogus) == -EFAULT");
    EXPECT_RAW_ERRNO(raw_syscall2(__NR_sched_getparam, 0, (long) 0x1), -EFAULT,
                     "unmapped param did not return EFAULT");

    TEST("getparam(unknown tid, bogus) == -ESRCH");
    EXPECT_RAW_ERRNO(raw_syscall2(__NR_sched_getparam, 999999, (long) 0x1),
                     -ESRCH, "task lookup must precede output copy");

    TEST("setscheduler(OTHER, prio=0) == 0");
    EXPECT_EQ(set_scheduler(SCHED_OTHER, 0), 0,
              "SCHED_OTHER prio=0 was not accepted");

    TEST("setscheduler(OTHER, prio=1) == -EINVAL");
    EXPECT_RAW_ERRNO(set_scheduler(SCHED_OTHER, 1), -EINVAL,
                     "non-zero priority for SCHED_OTHER was accepted");

    TEST("setscheduler(garbage policy) == -EINVAL");
    EXPECT_RAW_ERRNO(set_scheduler(99, 0), -EINVAL,
                     "unknown policy did not return EINVAL");

    TEST("setscheduler(negative policy) == -EINVAL");
    EXPECT_RAW_ERRNO(set_scheduler(-1, 0), -EINVAL,
                     "negative policy did not return EINVAL");

    TEST("setscheduler(NULL param) == -EINVAL");
    EXPECT_RAW_ERRNO(raw_syscall3(__NR_sched_setscheduler, 0, SCHED_OTHER, 0),
                     -EINVAL, "NULL param pointer did not return EINVAL");

    TEST("setscheduler(bad pid, bogus param) == -EFAULT");
    EXPECT_RAW_ERRNO(
        raw_syscall3(__NR_sched_setscheduler, 999999, SCHED_OTHER, (long) 0x1),
        -EFAULT, "bad param pointer did not take precedence over ESRCH");

    TEST("setscheduler(unknown tid) == -ESRCH");
    {
        struct sched_param_compat p = {.sched_priority = 0};
        EXPECT_RAW_ERRNO(raw_syscall3(__NR_sched_setscheduler, 999999,
                                      SCHED_OTHER, (long) &p),
                         -ESRCH, "unknown pid did not return ESRCH");
    }

    TEST("setscheduler(BATCH, prio=0) == 0");
    EXPECT_EQ(set_scheduler(SCHED_BATCH, 0), 0,
              "SCHED_BATCH was rejected without state tracking");
    TEST("getscheduler reports BATCH");
    EXPECT_EQ(raw_syscall1(__NR_sched_getscheduler, 0), SCHED_BATCH,
              "SCHED_BATCH was not retained");
    TEST("getparam reports zero priority for BATCH");
    {
        struct sched_param_compat p = {.sched_priority = 0x5a5a};
        long rc = raw_syscall2(__NR_sched_getparam, 0, (long) &p);
        EXPECT_TRUE(rc == 0 && p.sched_priority == 0,
                    "BATCH reported a realtime priority");
    }
    TEST("BATCH restores to OTHER");
    EXPECT_EQ(set_scheduler(SCHED_OTHER, 0), 0,
              "could not return from SCHED_BATCH");

    TEST("setscheduler(FIFO, prio=0) == -EINVAL");
    EXPECT_RAW_ERRNO(set_scheduler(SCHED_FIFO, 0), -EINVAL,
                     "SCHED_FIFO prio=0 did not return EINVAL");
    TEST("setscheduler(FIFO, prio=100) == -EINVAL");
    EXPECT_RAW_ERRNO(set_scheduler(SCHED_FIFO, 100), -EINVAL,
                     "SCHED_FIFO prio=100 did not return EINVAL");

    TEST("FIFO transition follows CAP_SYS_NICE/RLIMIT_RTPRIO");
    {
        long rc = set_scheduler(SCHED_FIFO, 50);
        if (can_switch_rt_class(50)) {
            EXPECT_TRUE(rc == 0, "privileged FIFO transition failed");
            if (rc == 0) {
                TEST("FIFO policy and priority retained");
                struct sched_param_compat p = {.sched_priority = 0};
                long grc = raw_syscall2(__NR_sched_getparam, 0, (long) &p);
                EXPECT_TRUE(
                    raw_syscall1(__NR_sched_getscheduler, 0) == SCHED_FIFO &&
                        grc == 0 && p.sched_priority == 50,
                    "FIFO state was not retained");
                TEST("FIFO rr interval is zero");
                struct ts_compat ts = {.tv_sec = 7, .tv_nsec = 11};
                long rrc =
                    raw_syscall2(__NR_sched_rr_get_interval, 0, (long) &ts);
                EXPECT_TRUE(rrc == 0 && ts.tv_sec == 0 && ts.tv_nsec == 0,
                            "FIFO reported a round-robin quantum");
            }
        } else {
            EXPECT_RAW_ERRNO(rc, -EPERM,
                             "unprivileged FIFO transition was not EPERM");
        }
        restore_other_policy();
    }

    TEST("setscheduler(RR, prio=50) follows permissions");
    {
        long rc = set_scheduler(SCHED_RR, 50);
        if (can_switch_rt_class(50)) {
            EXPECT_TRUE(rc == 0, "privileged RR transition failed");
            if (rc == 0) {
                TEST("RR rr interval is nonzero");
                struct ts_compat ts = {.tv_sec = 7, .tv_nsec = 11};
                long rrc =
                    raw_syscall2(__NR_sched_rr_get_interval, 0, (long) &ts);
                EXPECT_TRUE(rrc == 0 && ts.tv_sec >= 0 && ts.tv_nsec >= 0 &&
                                ts.tv_nsec < 1000000000L &&
                                (ts.tv_sec != 0 || ts.tv_nsec != 0),
                            "RR reported no round-robin quantum");
            }
        } else {
            EXPECT_RAW_ERRNO(rc, -EPERM,
                             "unprivileged RR transition was not EPERM");
        }
        restore_other_policy();
    }

    TEST("setscheduler(DEADLINE) == -EINVAL");
    EXPECT_RAW_ERRNO(set_scheduler(LINUX_SCHED_DEADLINE, 0), -EINVAL,
                     "SCHED_DEADLINE legacy syscall did not return EINVAL");

    TEST("RESET_ON_FORK is per-task, reported and privilege-cleared");
    {
        pthread_t worker;
        struct reset_result r = {0};
        if (pthread_create(&worker, NULL, reset_worker, &r) != 0) {
            FAIL("pthread_create(reset_worker) failed");
        } else {
            pthread_join(worker, NULL);
            EXPECT_EQ(r.set_rc, 0, "SCHED_RESET_ON_FORK flag was not accepted");
            if (r.set_rc == 0) {
                EXPECT_EQ(r.observed, SCHED_OTHER | LINUX_SCHED_RESET_ON_FORK,
                          "RESET_ON_FORK was not reported");
                if (have_cap_sys_nice())
                    EXPECT_EQ(r.clear_rc, 0,
                              "privileged RESET_ON_FORK clear failed");
                else
                    EXPECT_RAW_ERRNO(
                        r.clear_rc, -EPERM,
                        "unprivileged RESET_ON_FORK clear succeeded");
            }
        }
    }

    TEST("setparam(prio=0) == 0 for OTHER");
    {
        struct sched_param_compat p = {.sched_priority = 0};
        EXPECT_EQ(raw_syscall2(__NR_sched_setparam, 0, (long) &p), 0,
                  "setparam(prio=0) was rejected");
    }

    TEST("setparam(prio=1) == -EINVAL for OTHER");
    {
        struct sched_param_compat p = {.sched_priority = 1};
        EXPECT_RAW_ERRNO(raw_syscall2(__NR_sched_setparam, 0, (long) &p),
                         -EINVAL, "setparam(prio=1) was accepted");
    }

    TEST("setparam(NULL) == -EINVAL");
    EXPECT_RAW_ERRNO(raw_syscall2(__NR_sched_setparam, 0, 0), -EINVAL,
                     "NULL setparam pointer did not return EINVAL");

    TEST("setparam(bad pid, bogus) == -EFAULT");
    EXPECT_RAW_ERRNO(raw_syscall2(__NR_sched_setparam, 999999, (long) 0x1),
                     -EFAULT, "bad setparam pointer did not return EFAULT");

    TEST("get_priority_min/max per policy");
    {
        int ok =
            raw_syscall1(__NR_sched_get_priority_min, SCHED_OTHER) == 0 &&
            raw_syscall1(__NR_sched_get_priority_max, SCHED_OTHER) == 0 &&
            raw_syscall1(__NR_sched_get_priority_min, SCHED_BATCH) == 0 &&
            raw_syscall1(__NR_sched_get_priority_max, SCHED_BATCH) == 0 &&
            raw_syscall1(__NR_sched_get_priority_min, SCHED_IDLE) == 0 &&
            raw_syscall1(__NR_sched_get_priority_max, SCHED_IDLE) == 0 &&
            raw_syscall1(__NR_sched_get_priority_min, LINUX_SCHED_DEADLINE) ==
                0 &&
            raw_syscall1(__NR_sched_get_priority_max, LINUX_SCHED_DEADLINE) ==
                0 &&
            raw_syscall1(__NR_sched_get_priority_min, LINUX_SCHED_EXT) == 0 &&
            raw_syscall1(__NR_sched_get_priority_max, LINUX_SCHED_EXT) == 0 &&
            raw_syscall1(__NR_sched_get_priority_min, SCHED_FIFO) == 1 &&
            raw_syscall1(__NR_sched_get_priority_max, SCHED_FIFO) == 99 &&
            raw_syscall1(__NR_sched_get_priority_min, SCHED_RR) == 1 &&
            raw_syscall1(__NR_sched_get_priority_max, SCHED_RR) == 99;
        EXPECT_TRUE(ok, "priority range does not match Linux");
    }
    TEST("get_priority_min/max(garbage) == -EINVAL");
    EXPECT_TRUE(raw_syscall1(__NR_sched_get_priority_min, 42) == -EINVAL &&
                    raw_syscall1(__NR_sched_get_priority_max, 42) == -EINVAL,
                "unknown policy range did not return EINVAL");

    TEST("rr_get_interval(0) writes a sane fair slice");
    {
        struct ts_compat ts = {.tv_sec = 7, .tv_nsec = 11};
        long rc = raw_syscall2(__NR_sched_rr_get_interval, 0, (long) &ts);
        EXPECT_TRUE(rc == 0 && ts.tv_sec == 0 && ts.tv_nsec >= 0 &&
                        ts.tv_nsec < 1000000000L,
                    "rr_get_interval did not write a sane slice");
    }
    TEST("rr_get_interval(NULL) == -EFAULT");
    EXPECT_RAW_ERRNO(raw_syscall2(__NR_sched_rr_get_interval, 0, 0), -EFAULT,
                     "NULL ts pointer did not return EFAULT");
    TEST("rr_get_interval(unknown tid) == -ESRCH");
    {
        struct ts_compat ts = {0};
        EXPECT_RAW_ERRNO(
            raw_syscall2(__NR_sched_rr_get_interval, 999999, (long) &ts),
            -ESRCH, "unknown tid did not return ESRCH");
    }

    /* Per-task nice: the worker was created before the main thread's nice
     * change, so it keeps the inherited value. Linux task nice is per-task.
     */
    {
        pthread_t worker;
        struct worker_result r;
        memset(&r, 0, sizeof(r));
        atomic_store(&worker_go, 0);
        if (pthread_create(&worker, NULL, worker_main, &r) != 0) {
            TEST("pthread_create(worker)");
            FAIL("pthread_create failed");
        } else {
            atomic_store_explicit(&worker_go, 1, memory_order_release);
            pthread_join(worker, NULL);

            TEST("worker getscheduler(gettid()) is its own task");
            EXPECT_EQ(r.getscheduler_rc, SCHED_OTHER,
                      "worker did not see its own SCHED_OTHER");

            TEST("worker getparam(gettid()) zeroes priority");
            EXPECT_TRUE(r.getparam_rc == 0 && r.param_priority == 0,
                        "worker getparam mismatch");

            TEST("worker setscheduler(gettid(), OTHER, 0) == 0");
            EXPECT_EQ(r.setscheduler_self_rc, 0,
                      "worker self-setscheduler rejected");

            TEST("worker getaffinity(gettid()) succeeds");
            EXPECT_TRUE(r.getaffinity_rc > 0, "worker getaffinity failed");

            TEST("worker getpriority(gettid()) sees inherited nice");
            EXPECT_EQ(r.getpriority_rc, base_priority,
                      "worker did not inherit the task nice");
        }
    }

    TEST("getpriority(PRIO_PROCESS, 0) matches task nice");
    {
        long observed = get_nice();
        EXPECT_TRUE(observed == base_priority,
                    "getpriority does not report 20-nice");
    }

    TEST("getpriority(-1 which) == -EINVAL");
    EXPECT_RAW_ERRNO(raw_syscall2(__NR_getpriority, -1, 0), -EINVAL,
                     "negative which did not return EINVAL");
    TEST("setpriority(-1 which) == -EINVAL");
    EXPECT_RAW_ERRNO(raw_syscall3(__NR_setpriority, 3, 0, 0), -EINVAL,
                     "out-of-range which did not return EINVAL");
    TEST("getpriority(unknown tid) == -ESRCH");
    EXPECT_RAW_ERRNO(raw_syscall2(__NR_getpriority, PRIO_PROCESS, 999999),
                     -ESRCH, "unknown tid did not return ESRCH");
    TEST("setpriority(unknown tid) == -ESRCH");
    EXPECT_RAW_ERRNO(raw_syscall3(__NR_setpriority, PRIO_PROCESS, 999999, 0),
                     -ESRCH, "unknown tid setpriority did not return ESRCH");

    TEST("setpriority(PRIO_PGRP, 0) applies to the process group");
    {
        long rc = raw_syscall3(__NR_setpriority, PRIO_PGRP, 0, base_nice);
        EXPECT_EQ(rc, 0, "group setpriority failed");
        TEST("getpriority(PRIO_PGRP, 0) reports the group");
        long observed = raw_syscall2(__NR_getpriority, PRIO_PGRP, 0);

        /* Other members of the group/user can legitimately have a lower nice
         * and therefore a larger return value; Linux reports the maximum.
         */
        EXPECT_TRUE(observed >= base_priority && observed <= 40,
                    "group getpriority is outside the Linux range");
    }

    TEST("setpriority(PRIO_USER, 0) applies to the user");
    {
        long rc = raw_syscall3(__NR_setpriority, PRIO_USER, 0, base_nice);
        EXPECT_EQ(rc, 0, "user setpriority failed");
        TEST("getpriority(PRIO_USER, 0) reports the user");
        long observed = raw_syscall2(__NR_getpriority, PRIO_USER, 0);
        EXPECT_TRUE(observed >= base_priority && observed <= 40,
                    "user getpriority is outside the Linux range");
    }

    TEST("setpriority(PRIO_PGRP, dead group) == -ESRCH");
    EXPECT_RAW_ERRNO(raw_syscall3(__NR_setpriority, PRIO_PGRP, 999999, 0),
                     -ESRCH, "dead group did not return ESRCH");
    TEST("setpriority(PRIO_USER, unused uid) == -ESRCH");
    EXPECT_RAW_ERRNO(raw_syscall3(__NR_setpriority, PRIO_USER, 123456, 0),
                     -ESRCH, "unused uid did not return ESRCH");

    TEST("nice reduction follows CAP_SYS_NICE/RLIMIT_NICE");
    if (base_nice > -20) {
        long target = base_nice - 1;
        long rc = set_nice(target);
        if (can_lower_nice_to((int) target)) {
            EXPECT_EQ(rc, 0, "permitted nice reduction failed");
            if (rc == 0)
                EXPECT_EQ(get_nice(), 20 - target,
                          "nice reduction was not retained");
            (void) set_nice(base_nice);
        } else {
            EXPECT_RAW_ERRNO(
                rc, -EACCES,
                "unpermitted nice reduction did not return EACCES");
        }
    } else {
        PASS();
    }

    TEST("nice raise always allowed");
    if (base_nice < 19) {
        long target = base_nice + 1;
        long rc = set_nice(target);
        EXPECT_EQ(rc, 0, "raising nice failed");
        if (rc == 0)
            EXPECT_EQ(get_nice(), 20 - target, "raised nice was not retained");
    } else {
        PASS();
    }

    /* IDLE last: leaving it needs CAP_SYS_NICE or RLIMIT_NICE by design. */
    TEST("setscheduler(IDLE, prio=0) == 0");
    {
        long rc = set_scheduler(SCHED_IDLE, 0);
        EXPECT_EQ(rc, 0, "SCHED_IDLE was rejected without state tracking");
        if (rc == 0) {
            TEST("getscheduler reports IDLE");
            EXPECT_EQ(raw_syscall1(__NR_sched_getscheduler, 0), SCHED_IDLE,
                      "SCHED_IDLE was not retained");

            TEST("leaving IDLE follows CAP_SYS_NICE/RLIMIT_NICE");
            long other = set_scheduler(SCHED_OTHER, 0);
            long allow =
                have_cap_sys_nice() || get_nice() <= rlimit_cur(RLIMIT_NICE);
            if (allow)
                EXPECT_EQ(other, 0, "permitted IDLE exit failed");
            else
                EXPECT_RAW_ERRNO(other, -EPERM,
                                 "unprivileged IDLE exit was not EPERM");
        }
    }

    SUMMARY("test-sched-policy");
    return fails == 0 ? 0 : 1;
}
