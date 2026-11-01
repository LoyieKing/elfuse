/*
 * rt_sigtimedwait: park, selection, metadata and deadline semantics
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A signal waiter and producer share one allowed CPU. The producer must run
 * before releasing the signal waiter, so a host-blocking syscall cannot pass.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

/* <sys/syscall.h> normally supplies these. Keep the fallbacks architectural
 * rather than one number shared by every ABI.
 */
#ifndef SYS_rt_sigtimedwait
#if defined(__aarch64__)
#define SYS_rt_sigtimedwait 137
#elif defined(__x86_64__)
#define SYS_rt_sigtimedwait 128
#else
#error "test-sigtimedwait needs SYS_rt_sigtimedwait for this architecture"
#endif
#endif

#ifndef SYS_rt_tgsigqueueinfo
#if defined(__aarch64__)
#define SYS_rt_tgsigqueueinfo 240
#elif defined(__x86_64__)
#define SYS_rt_tgsigqueueinfo 297
#else
#error "test-sigtimedwait needs SYS_rt_tgsigqueueinfo for this architecture"
#endif
#endif

int passes = 0, fails = 0;

#define NS_PER_MS 1000000LL
#define EAGAIN_TIMEOUT_MS 120
#define EINTR_TIMEOUT_MS 600
#define EINTR_SEND_MS 40
#define IGNORED_TIMEOUT_MS 300
#define IGNORED_SEND_MS 100
#define TWO_WAITER_TIMEOUT_MS 500
#define RACE_ITERATIONS 200

static sigset_t test_mask;

static int64_t now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t) t.tv_sec * 1000000000LL + t.tv_nsec;
}

static void sleep_ms(long milliseconds)
{
    struct timespec t = {milliseconds / 1000,
                         (milliseconds % 1000) * NS_PER_MS};
    while (nanosleep(&t, &t) != 0 && errno == EINTR)
        ;
}

static struct timespec ms_to_timespec(long milliseconds)
{
    struct timespec t = {milliseconds / 1000,
                         (milliseconds % 1000) * NS_PER_MS};
    return t;
}

static bool wait_flag(const _Atomic bool *flag, long milliseconds)
{
    int64_t deadline = now_ns() + (int64_t) milliseconds * NS_PER_MS;
    while (!atomic_load_explicit(flag, memory_order_acquire)) {
        if (now_ns() >= deadline)
            return false;
        sleep_ms(1);
    }
    return true;
}

static sigset_t signal_set_of(int signum)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signum);
    return set;
}

/* Exact consumer-visible metadata for a queued (SI_QUEUE) signal. */
static bool queued_info_matches(const siginfo_t *info, int signum, int payload)
{
    return info->si_signo == signum && info->si_code == SI_QUEUE &&
           info->si_pid == getpid() && info->si_uid == getuid() &&
           info->si_value.sival_int == payload;
}

/* Remove a signal this test left pending, so the next case starts clean. */
static void drain_signal(int signum)
{
    sigset_t set = signal_set_of(signum);
    struct timespec zero = {0, 0};
    for (int i = 0; i < 8; i++) {
        if (sigtimedwait(&set, NULL, &zero) != signum)
            break;
    }
}

/* The starvation case: one sigwait consumer and one producer on one CPU. */

static _Atomic bool waiter_armed;
static _Atomic bool producer_ran;
static sigset_t sigwait_set;
static int sigwait_result;

static void *starve_waiter(void *unused)
{
    (void) unused;
    atomic_store_explicit(&waiter_armed, true, memory_order_release);
    int signo = 0;
    sigwait_result = sigwait(&sigwait_set, &signo) == 0 ? signo : -1;
    return NULL;
}

static void *starve_producer(void *unused)
{
    (void) unused;
    atomic_store_explicit(&producer_ran, true, memory_order_release);
    return NULL;
}

static void test_worker_progress(void)
{
    TEST("sigwait releases the waiter's logical CPU");

    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
        FAIL("sched_getaffinity");
        return;
    }

    int cpus[CPU_SETSIZE];
    int cpu_count = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (CPU_ISSET(cpu, &allowed))
            cpus[cpu_count++] = cpu;
    }
    if (cpu_count == 0) {
        FAIL("affinity mask allows no CPU");
        return;
    }

    int controller_cpu = cpus[0];
    int worker_cpu = cpu_count > 1 ? cpus[1] : cpus[0];

    cpu_set_t pin;
    CPU_ZERO(&pin);
    CPU_SET(controller_cpu, &pin);
    if (sched_setaffinity(0, sizeof(pin), &pin) != 0) {
        FAIL("pin controller");
        return;
    }

    pthread_attr_t attr;
    int err = pthread_attr_init(&attr);
    if (err != 0) {
        errno = err;
        FAIL("pthread_attr_init");
        goto restore_affinity;
    }

    CPU_ZERO(&pin);
    CPU_SET(worker_cpu, &pin);
    err = pthread_attr_setaffinity_np(&attr, sizeof(pin), &pin);
    if (err != 0) {
        errno = err;
        FAIL("pin waiter and producer");
        goto destroy_attr;
    }

    sigemptyset(&sigwait_set);
    sigaddset(&sigwait_set, SIGUSR1);

    sigset_t saved_mask;
    if (pthread_sigmask(SIG_BLOCK, &sigwait_set, &saved_mask) != 0) {
        FAIL("block SIGUSR1");
        goto destroy_attr;
    }

    atomic_store_explicit(&waiter_armed, false, memory_order_relaxed);
    atomic_store_explicit(&producer_ran, false, memory_order_relaxed);
    sigwait_result = 0;

    bool waiter_created = false, producer_created = false;
    bool progressed = false, setup_ok = true;
    pthread_t waiter, producer;

    err = pthread_create(&waiter, &attr, starve_waiter, NULL);
    if (err != 0) {
        errno = err;
        FAIL("create waiter");
        setup_ok = false;
    } else {
        waiter_created = true;
        if (!wait_flag(&waiter_armed, 2000)) {
            FAIL("waiter never entered sigwait");
            setup_ok = false;
        } else {
            /* Let the waiter settle in the syscall before the producer is
             * created: the old host-worker release only showed up here.
             */
            sleep_ms(20);
            err = pthread_create(&producer, &attr, starve_producer, NULL);
            if (err != 0) {
                errno = err;
                FAIL("create producer");
                setup_ok = false;
            } else {
                producer_created = true;
                progressed = wait_flag(&producer_ran, 500);
                if (!progressed) {
                    FAIL("producer could not run while sigwait was parked");
                    setup_ok = false;
                }
            }
        }
    }

    if (waiter_created) {
        int kill_err = pthread_kill(waiter, SIGUSR1);

        /* A process-directed instance reaches the same waiter if the directed
         * send failed, so join cannot hang on a broken cleanup path.
         */
        if (kill_err != 0)
            (void) kill(getpid(), SIGUSR1);
        pthread_join(waiter, NULL);
    }
    if (producer_created)
        pthread_join(producer, NULL);

    if (setup_ok) {
        EXPECT_TRUE(sigwait_result == SIGUSR1,
                    "sigwait did not consume the released signal");
    }

    pthread_sigmask(SIG_SETMASK, &saved_mask, NULL);
destroy_attr:
    pthread_attr_destroy(&attr);
restore_affinity:
    sched_setaffinity(0, sizeof(allowed), &allowed);
}

/* A finite timeout must report EAGAIN and consume the whole duration. */

static void test_timeouts(void)
{
    int sig = SIGRTMIN + 1;
    drain_signal(sig);
    sigset_t set = signal_set_of(sig);
    siginfo_t info;
    struct timespec zero = {0, 0};

    int64_t start = now_ns();
    errno = 0;
    int rc = sigtimedwait(&set, &info, &zero);
    int error = errno;
    int64_t elapsed = now_ns() - start;
    errno = error;
    TEST("zero timeout with no signal reports EAGAIN");
    EXPECT_TRUE(rc == -1 && error == EAGAIN, "zero timeout accepted");

    TEST("zero timeout polls without blocking");
    EXPECT_TRUE(elapsed < 100 * NS_PER_MS, "zero timeout blocked");

    struct timespec timeout = ms_to_timespec(EAGAIN_TIMEOUT_MS);
    start = now_ns();
    errno = 0;
    rc = sigtimedwait(&set, &info, &timeout);
    error = errno;
    elapsed = now_ns() - start;
    errno = error;
    TEST("finite timeout with no signal reports EAGAIN");
    EXPECT_TRUE(rc == -1 && error == EAGAIN, "finite timeout accepted");

    TEST("finite timeout waits out its deadline");
    EXPECT_TRUE(elapsed >= (EAGAIN_TIMEOUT_MS - 10) * NS_PER_MS &&
                    elapsed < 1000 * NS_PER_MS,
                "timeout returned early or never expired");
}

/* A signal already pending at entry is consumed by the zero-timeout poll. */

static void test_pending_metadata(void)
{
    int sig = SIGUSR1;
    drain_signal(sig);

    if (kill(getpid(), sig) != 0) {
        TEST("zero timeout consumes an already pending signal");
        FAIL("kill");
        return;
    }

    sigset_t set = signal_set_of(sig);
    struct timespec zero = {0, 0};
    siginfo_t info;
    memset(&info, 0, sizeof(info));

    int64_t start = now_ns();
    int rc = sigtimedwait(&set, &info, &zero);
    int64_t elapsed = now_ns() - start;

    TEST("zero timeout consumes an already pending signal");
    EXPECT_TRUE(rc == sig, "pending process signal was not selected");

    TEST("process-directed signal keeps its sender metadata");
    EXPECT_TRUE(info.si_signo == sig && info.si_code == SI_USER &&
                    info.si_pid == getpid() && info.si_uid == getuid(),
                "siginfo lost signo/code/pid/uid");

    TEST("a pending signal makes the zero-timeout call immediate");
    EXPECT_TRUE(elapsed < 100 * NS_PER_MS, "pending poll blocked");
}

static void test_thread_directed_pending(void)
{
    int sig = SIGUSR1;
    drain_signal(sig);

    int err = pthread_kill(pthread_self(), sig);
    if (err != 0) {
        TEST("thread-directed pending signal is selected");
        errno = err;
        FAIL("pthread_kill");
        return;
    }

    sigset_t set = signal_set_of(sig);
    struct timespec zero = {0, 0};
    siginfo_t info;
    memset(&info, 0, sizeof(info));

    int rc = sigtimedwait(&set, &info, &zero);

    TEST("thread-directed pending signal is selected");
    EXPECT_TRUE(rc == sig, "private signal was not selected");

    TEST("thread-directed siginfo keeps sender identity");
    EXPECT_TRUE(info.si_signo == sig && info.si_pid == getpid() &&
                    info.si_uid == getuid(),
                "siginfo lost signo/pid/uid");
}

struct finite_wait_result {
    int rc;
    int err;
    siginfo_t info;
};

struct finite_wait_job {
    sigset_t set;
    long timeout_ms;
    _Atomic int *started;
    struct finite_wait_result *out;
};

static void *finite_waiter(void *arg)
{
    struct finite_wait_job *job = arg;
    atomic_fetch_add_explicit(job->started, 1, memory_order_acq_rel);
    struct timespec timeout = ms_to_timespec(job->timeout_ms);
    errno = 0;
    int rc = sigtimedwait(&job->set, &job->out->info, &timeout);
    job->out->err = errno;
    job->out->rc = rc;
    return NULL;
}

/* A shared signal is consumed once. Linux may interrupt the losing waiter if
 * both were woken before one dequeued the signal; a directed signal can only
 * satisfy its target.
 */
static void run_two_waiter_case(bool directed)
{
    int sig = SIGUSR1;
    drain_signal(sig);

    TEST(directed ? "thread-directed wake reaches only its waiter"
                  : "one shared signal satisfies one waiter");

    sigset_t set = signal_set_of(sig);
    _Atomic int started = 0;
    struct finite_wait_result results[2];
    memset(results, 0, sizeof(results));
    struct finite_wait_job jobs[2] = {
        {.set = set,
         .timeout_ms = TWO_WAITER_TIMEOUT_MS,
         .started = &started,
         .out = &results[0]},
        {.set = set,
         .timeout_ms = TWO_WAITER_TIMEOUT_MS,
         .started = &started,
         .out = &results[1]},
    };
    pthread_t waiters[2];
    bool created[2] = {false, false};
    bool setup_ok = true;

    for (int i = 0; i < 2; i++) {
        int err = pthread_create(&waiters[i], NULL, finite_waiter, &jobs[i]);
        if (err != 0) {
            errno = err;
            FAIL("create finite waiter");
            setup_ok = false;
            break;
        }
        created[i] = true;
    }

    if (setup_ok) {
        int64_t deadline = now_ns() + 2000 * NS_PER_MS;
        while (atomic_load_explicit(&started, memory_order_acquire) < 2 &&
               now_ns() < deadline) {
            sleep_ms(1);
        }
        if (atomic_load_explicit(&started, memory_order_acquire) < 2) {
            FAIL("a finite waiter did not start");
            setup_ok = false;
        } else {
            sleep_ms(50);
            if (directed) {
                int err = pthread_kill(waiters[0], sig);
                if (err != 0) {
                    errno = err;
                    FAIL("pthread_kill directed waiter");
                    setup_ok = false;
                }
            } else if (kill(getpid(), sig) != 0) {
                FAIL("kill shared waiter");
                setup_ok = false;
            }
        }
    }

    for (int i = 0; i < 2; i++) {
        if (created[i])
            pthread_join(waiters[i], NULL);
    }
    drain_signal(sig);

    if (!setup_ok)
        return;

    if (directed) {
        EXPECT_TRUE(results[0].rc == sig && results[1].rc == -1 &&
                        results[1].err == EAGAIN,
                    "directed signal left its target or hit the sibling");
    } else {
        int winners = (results[0].rc == sig) + (results[1].rc == sig);
        int losers = (results[0].rc == -1 &&
                      (results[0].err == EAGAIN || results[0].err == EINTR)) +
                     (results[1].rc == -1 &&
                      (results[1].err == EAGAIN || results[1].err == EINTR));
        EXPECT_TRUE(winners == 1 && losers == 1,
                    "shared signal was not consumed exactly once");
    }
}

static void test_two_waiters(void)
{
    run_two_waiter_case(false);
    run_two_waiter_case(true);
}

/* Matching private and shared RT instances are both queued. Linux drains
 * task->pending before signal->shared_pending, and the payload of whichever
 * instance is drained must reach the caller unchanged.
 */

static void test_rt_payload_precedence(void)
{
    int sig = SIGRTMIN;
    drain_signal(sig);

    union sigval shared_value = {.sival_int = 0x1111};
    if (sigqueue(getpid(), sig, shared_value) != 0) {
        TEST("private RT signal is dequeued before shared");
        FAIL("sigqueue shared");
        return;
    }

    siginfo_t queued;
    memset(&queued, 0, sizeof(queued));
    queued.si_signo = sig;
    queued.si_code = SI_QUEUE;
    queued.si_pid = getpid();
    queued.si_uid = getuid();
    queued.si_value.sival_int = 0x2222;

    pid_t pid = getpid();
    pid_t tid = (pid_t) syscall(SYS_gettid);
    long queued_rc = syscall(SYS_rt_tgsigqueueinfo, (long) pid, (long) tid,
                             (long) sig, &queued);
    if (queued_rc != 0) {
        TEST("private RT signal is dequeued before shared");
        FAIL("rt_tgsigqueueinfo private");
        return;
    }

    sigset_t set = signal_set_of(sig);
    struct timespec zero = {0, 0};
    siginfo_t info;

    memset(&info, 0, sizeof(info));
    int first = sigtimedwait(&set, &info, &zero);
    TEST("private RT signal is dequeued before shared");
    EXPECT_TRUE(first == sig && queued_info_matches(&info, sig, 0x2222),
                "private payload lost or shared signal won");

    memset(&info, 0, sizeof(info));
    int second = sigtimedwait(&set, &info, &zero);
    TEST("shared RT payload survives the private instance");
    EXPECT_TRUE(second == sig && queued_info_matches(&info, sig, 0x1111),
                "shared payload lost");

    errno = 0;
    int third = sigtimedwait(&set, &info, &zero);
    int error = errno;
    errno = error;
    TEST("both matching RT instances were consumed");
    EXPECT_TRUE(third == -1 && error == EAGAIN,
                "an RT instance is still pending");
}

/* A signal number's RT queue is FIFO. Each instance must keep its own payload
 * and sender metadata through sigtimedwait.
 */
static void test_rt_fifo_payload(void)
{
    int sig = SIGRTMIN + 1;
    drain_signal(sig);

    const int payloads[] = {0x51, 0x52, 0x53};
    for (unsigned i = 0; i < sizeof(payloads) / sizeof(payloads[0]); i++) {
        union sigval value = {.sival_int = payloads[i]};
        if (sigqueue(getpid(), sig, value) != 0) {
            TEST("queued RT payloads dequeue in FIFO order");
            FAIL("sigqueue");
            return;
        }
    }

    sigset_t set = signal_set_of(sig);
    struct timespec zero = {0, 0};
    TEST("queued RT payloads dequeue in FIFO order");
    for (unsigned i = 0; i < sizeof(payloads) / sizeof(payloads[0]); i++) {
        siginfo_t info;
        memset(&info, 0, sizeof(info));
        int rc = sigtimedwait(&set, &info, &zero);
        EXPECT_TRUE(rc == sig && queued_info_matches(&info, sig, payloads[i]),
                    "payload order or metadata lost");
    }

    errno = 0;
    int rc = sigtimedwait(&set, NULL, &zero);
    int error = errno;
    errno = error;
    TEST("FIFO test consumed every RT instance");
    EXPECT_TRUE(rc == -1 && error == EAGAIN, "an RT instance is still pending");
}

/* An unrelated handled signal ends the wait with EINTR. Linux does not restart
 * rt_sigtimedwait even when the handler asked for SA_RESTART.
 */

static volatile sig_atomic_t handled_hits;
static volatile sig_atomic_t handled_in_call;
static volatile sig_atomic_t wait_in_call;

static void on_usr2(int sig)
{
    (void) sig;
    handled_hits++;
    if (wait_in_call)
        handled_in_call++;
}

struct send_job {
    pthread_t target;
    int signo;
    int delay_ms;
    _Atomic bool *go;
    int rc;
};

static void *send_after_go(void *arg)
{
    struct send_job *job = arg;
    int64_t deadline = now_ns() + 5000000000LL;
    while (!atomic_load_explicit(job->go, memory_order_acquire)) {
        if (now_ns() >= deadline) {
            job->rc = -1;
            return NULL;
        }
        sched_yield();
    }
    sleep_ms(job->delay_ms);
    job->rc = pthread_kill(job->target, job->signo);
    return NULL;
}

static void test_handled_signal_eintr(void)
{
    int sig = SIGUSR2;
    drain_signal(sig);

    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_usr2;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(sig, &sa, &old) != 0) {
        TEST("SA_RESTART handler interrupts sigtimedwait");
        FAIL("sigaction");
        return;
    }

    sigset_t unblock = signal_set_of(sig);
    if (pthread_sigmask(SIG_UNBLOCK, &unblock, NULL) != 0) {
        TEST("SA_RESTART handler interrupts sigtimedwait");
        FAIL("unblock SIGUSR2");
        goto restore_action;
    }

    sigset_t wait_set = signal_set_of(SIGUSR1);
    drain_signal(SIGUSR1);

    bool reported = false, raced = true;
    for (int attempt = 0; attempt < 3 && !reported; attempt++) {
        handled_hits = 0;
        handled_in_call = 0;

        _Atomic bool go = false;
        struct send_job job = {
            .target = pthread_self(),
            .signo = sig,
            .delay_ms = EINTR_SEND_MS,
            .go = &go,
            .rc = -1,
        };
        pthread_t sender;
        int err = pthread_create(&sender, NULL, send_after_go, &job);
        if (err != 0) {
            TEST("SA_RESTART handler interrupts sigtimedwait");
            errno = err;
            FAIL("create sender");
            raced = false;
            break;
        }

        int64_t start = now_ns();
        atomic_store_explicit(&go, true, memory_order_release);
        wait_in_call = 1;

        struct timespec timeout = ms_to_timespec(EINTR_TIMEOUT_MS);
        errno = 0;
        int rc = sigtimedwait(&wait_set, NULL, &timeout);
        int error = errno;
        int64_t elapsed = now_ns() - start;
        wait_in_call = 0;

        pthread_join(sender, NULL);
        if (job.rc != 0) {
            TEST("SA_RESTART handler interrupts sigtimedwait");
            errno = job.rc;
            FAIL("sender pthread_kill");
            raced = false;
            break;
        }

        if (rc == -1 && error == EINTR) {
            TEST("SA_RESTART handler interrupts sigtimedwait");
            EXPECT_TRUE(handled_hits == 1, "handler ran zero or twice");

            TEST("EINTR is reported before the timeout");
            EXPECT_TRUE(elapsed < (EINTR_TIMEOUT_MS / 2) * NS_PER_MS,
                        "the wait was restarted to its deadline");
            reported = true;
        } else if (rc == -1 && error == EAGAIN && handled_in_call > 0) {
            TEST("SA_RESTART handler interrupts sigtimedwait");
            EXPECT_TRUE(false,
                        "SA_RESTART restarted the wait instead of EINTR");
            reported = true;
        } else if (rc == -1 && error == EAGAIN && handled_hits > 0) {
            /* The handler ran before the syscall was entered. This is the
             * wake-before-block race the test must tolerate, not a result.
             */
        } else {
            TEST("SA_RESTART handler interrupts sigtimedwait");
            errno = error;
            FAIL("sigtimedwait did not report EINTR");
            raced = false;
            break;
        }
    }

    if (raced && !reported) {
        TEST("SA_RESTART handler interrupts sigtimedwait");
        FAIL("sender always raced ahead of the wait");
    }

    pthread_sigmask(SIG_BLOCK, &unblock, NULL);
restore_action:
    sigaction(sig, &old, NULL);
    drain_signal(sig);
}

/* An unrelated ignored signal must neither end the wait nor restart its
 * timeout. Sending it while the waiter is parked makes the second half a
 * deadline check: resetting the relative timeout would expire one full
 * IGNORED_TIMEOUT_MS after the ignored wakeup.
 */

static void test_ignored_signal_deadline(void)
{
    int sig = SIGRTMIN + 2;
    drain_signal(sig);

    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    if (sigaction(sig, &sa, &old) != 0) {
        TEST("ignored unrelated signal does not end the wait");
        FAIL("sigaction");
        return;
    }

    sigset_t unblock = signal_set_of(sig);
    if (pthread_sigmask(SIG_UNBLOCK, &unblock, NULL) != 0) {
        TEST("ignored unrelated signal does not end the wait");
        FAIL("unblock ignored signal");
        goto restore_action;
    }

    sigset_t wait_set = signal_set_of(SIGUSR1);
    drain_signal(SIGUSR1);

    _Atomic bool go = false;
    struct send_job job = {
        .target = pthread_self(),
        .signo = sig,
        .delay_ms = IGNORED_SEND_MS,
        .go = &go,
        .rc = -1,
    };
    pthread_t sender;
    int err = pthread_create(&sender, NULL, send_after_go, &job);
    if (err != 0) {
        TEST("ignored unrelated signal does not end the wait");
        errno = err;
        FAIL("create sender");
        goto reblock;
    }

    int64_t start = now_ns();
    atomic_store_explicit(&go, true, memory_order_release);

    struct timespec timeout = ms_to_timespec(IGNORED_TIMEOUT_MS);
    errno = 0;
    int rc = sigtimedwait(&wait_set, NULL, &timeout);
    int error = errno;
    int64_t elapsed = now_ns() - start;

    pthread_join(sender, NULL);
    errno = error;
    TEST("ignored unrelated signal does not end the wait");
    EXPECT_TRUE(job.rc == 0 && rc == -1 && error == EAGAIN,
                "ignored signal returned early or was reported as EINTR");

    TEST("ignored signal does not reset the finite deadline");
    EXPECT_TRUE(elapsed >= (IGNORED_TIMEOUT_MS - 30) * NS_PER_MS &&
                    elapsed <= (IGNORED_TIMEOUT_MS + 60) * NS_PER_MS,
                "deadline restarted after the ignored signal");

reblock:
    pthread_sigmask(SIG_BLOCK, &unblock, NULL);
restore_action:
    sigaction(sig, &old, NULL);
    drain_signal(sig);
}

/* A matching signal posted just before the waiter parks must never be lost. The
 * sender sleeps between sends so the waiter actually parks on most iterations
 * instead of always consuming a pre-existing pending instance.
 */

struct spam_job {
    pthread_t target;
    _Atomic bool run;
    _Atomic bool started;
};

static void *spam_usr1(void *arg)
{
    struct spam_job *job = arg;
    atomic_store_explicit(&job->started, true, memory_order_release);
    while (atomic_load_explicit(&job->run, memory_order_acquire)) {
        (void) pthread_kill(job->target, SIGUSR1);
        sleep_ms(1);
    }
    return NULL;
}

static void test_wake_before_block(void)
{
    int sig = SIGUSR1;
    drain_signal(sig);

    struct spam_job job = {
        .target = pthread_self(),
        .run = true,
        .started = false,
    };
    pthread_t sender;
    if (pthread_create(&sender, NULL, spam_usr1, &job) != 0) {
        TEST("signal posted around the park is never lost");
        FAIL("create sender");
        return;
    }
    if (!wait_flag(&job.started, 2000)) {
        atomic_store_explicit(&job.run, false, memory_order_release);
        pthread_join(sender, NULL);
        TEST("signal posted around the park is never lost");
        FAIL("sender never started");
        return;
    }

    sigset_t set = signal_set_of(sig);
    int completed = 0;
    for (int i = 0; i < RACE_ITERATIONS; i++) {
        struct timespec timeout = ms_to_timespec(1000);
        if (sigtimedwait(&set, NULL, &timeout) != sig)
            break;
        completed++;
    }

    atomic_store_explicit(&job.run, false, memory_order_release);
    pthread_join(sender, NULL);
    drain_signal(sig);

    TEST("signal posted around the park is never lost");
    EXPECT_TRUE(completed == RACE_ITERATIONS,
                "a matching wake was lost or the deadline expired");
}

/* exit_group and exec must cancel a sibling parked in an indefinite
 * sigtimedwait even though the thread that owns the syscall never returns. Both
 * run in a forked child so a lost cancellation shows up as a bad child status
 * instead of wedging the harness.
 */

#define EXEC_MARKER "exec-sigwait-child"
#define CHILD_TIMEOUT_MS 5000

static const char *exec_path;
static _Atomic bool child_waiter_started;

static void *child_parked_waiter(void *unused)
{
    (void) unused;
    sigset_t set = signal_set_of(SIGUSR1);
    atomic_store_explicit(&child_waiter_started, true, memory_order_release);
    sigtimedwait(&set, NULL, NULL);
    return NULL;
}

/* Returns 0 once the sibling is parked, or a child exit status describing the
 * setup failure.
 */
static int park_child_sibling(void)
{
    atomic_store_explicit(&child_waiter_started, false, memory_order_relaxed);
    pthread_t waiter;
    int err = pthread_create(&waiter, NULL, child_parked_waiter, NULL);
    if (err != 0)
        return 3;
    if (!wait_flag(&child_waiter_started, 2000))
        return 4;
    sleep_ms(50);
    return 0;
}

static bool wait_child(pid_t pid, int timeout_ms, int *status)
{
    int64_t deadline = now_ns() + (int64_t) timeout_ms * NS_PER_MS;
    for (;;) {
        pid_t reaped = waitpid(pid, status, WNOHANG);
        if (reaped == pid)
            return true;
        if (reaped < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (now_ns() >= deadline) {
            (void) kill(pid, SIGKILL);
            for (int i = 0; i < 100; i++) {
                pid_t reaped = waitpid(pid, status, WNOHANG);
                if (reaped == pid || reaped < 0)
                    break;
                sleep_ms(10);
            }
            return false;
        }
        sleep_ms(10);
    }
}

static void test_cancel_parked_waiter(void)
{
    int status = 0;
    TEST("exit_group cancels a parked sigtimedwait sibling");
    pid_t child = fork();
    if (child == 0) {
        int rc = park_child_sibling();
        if (rc != 0)
            _exit(rc);
        _exit(0);
    }
    bool exited = child > 0 && wait_child(child, CHILD_TIMEOUT_MS, &status);
    EXPECT_TRUE(exited && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "exit_group left the parked sibling behind");

    TEST("exec cancels a parked sigtimedwait sibling");
    child = fork();
    if (child == 0) {
        int rc = park_child_sibling();
        if (rc != 0)
            _exit(rc);

        extern char **environ;
        char *args[] = {(char *) exec_path, (char *) EXEC_MARKER, NULL};
        execve(exec_path, args, environ);
        _exit(5);
    }
    exited = child > 0 && wait_child(child, CHILD_TIMEOUT_MS, &status);
    EXPECT_TRUE(exited && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "exec left the parked sibling behind or failed");
}

/* The post-exec image queues and consumes a signal: that walks the waiter list
 * which the sibling must have left at exec time.
 */
static int exec_marker_main(void)
{
    int sig = SIGUSR1;
    sigset_t set = signal_set_of(sig);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0)
        return 6;
    if (kill(getpid(), sig) != 0)
        return 7;

    siginfo_t info;
    memset(&info, 0, sizeof(info));
    struct timespec zero = {0, 0};
    int rc = sigtimedwait(&set, &info, &zero);
    if (rc != sig || info.si_signo != sig)
        return 8;
    return 0;
}

/* Kernel ABI validation. The libc wrapper always supplies a valid sigsetsize,
 * so these use the raw syscall.
 */
static void test_invalid_arguments(void)
{
    uint64_t set_word = 1ULL << (SIGUSR1 - 1);
    siginfo_t info;
    struct timespec zero = {0, 0};

    TEST("invalid sigsetsize is rejected");
    EXPECT_ERRNO(syscall(SYS_rt_sigtimedwait, &set_word, &info, &zero, 4),
                 EINVAL, "bad sigsetsize accepted");

    TEST("unreadable wait set is rejected");
    EXPECT_ERRNO(
        syscall(SYS_rt_sigtimedwait, (void *) (uintptr_t) 1, &info, &zero, 8),
        EFAULT, "bad set pointer accepted");

    TEST("unreadable timeout is rejected");
    EXPECT_ERRNO(syscall(SYS_rt_sigtimedwait, &set_word, &info,
                         (void *) (uintptr_t) 1, 8),
                 EFAULT, "bad timeout pointer accepted");

    struct timespec bad_nsec = {.tv_sec = 0, .tv_nsec = 1000000000L};
    TEST("out-of-range timeout nanoseconds is rejected");
    EXPECT_ERRNO(syscall(SYS_rt_sigtimedwait, &set_word, &info, &bad_nsec, 8),
                 EINVAL, "tv_nsec == 1s accepted");

    struct timespec bad_sec = {.tv_sec = -1, .tv_nsec = 0};
    TEST("negative timeout is rejected");
    EXPECT_ERRNO(syscall(SYS_rt_sigtimedwait, &set_word, &info, &bad_sec, 8),
                 EINVAL, "negative timeout accepted");
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], EXEC_MARKER) == 0)
        return exec_marker_main();

    exec_path = argv[0];
    sigemptyset(&test_mask);
    sigaddset(&test_mask, SIGUSR1);
    sigaddset(&test_mask, SIGUSR2);
    sigaddset(&test_mask, SIGRTMIN);
    sigaddset(&test_mask, SIGRTMIN + 1);
    sigaddset(&test_mask, SIGRTMIN + 2);

    sigset_t original_mask;
    if (pthread_sigmask(SIG_BLOCK, &test_mask, &original_mask) != 0) {
        fprintf(stderr, "test-sigtimedwait: cannot block test signals\n");
        return 2;
    }

    test_worker_progress();
    test_timeouts();
    test_pending_metadata();
    test_thread_directed_pending();
    test_two_waiters();
    test_rt_payload_precedence();
    test_rt_fifo_payload();
    test_handled_signal_eintr();
    test_ignored_signal_deadline();
    test_wake_before_block();
    test_cancel_parked_waiter();
    test_invalid_arguments();

    pthread_sigmask(SIG_SETMASK, &original_mask, NULL);
    SUMMARY("test-sigtimedwait");
    return fails != 0;
}
