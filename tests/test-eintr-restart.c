/*
 * Linux restart classification across a signal: ERESTARTSYS vs never-restart
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A blocking read is Linux's ERESTARTSYS shape: a handler with SA_RESTART makes
 * the kernel re-execute the call with the guest's original arguments, so the
 * reader stays blocked and later completes with the bytes that arrive. The poll
 * family is the opposite rule (signal(7)): poll, ppoll, select, pselect,
 * epoll_wait and epoll_pwait are never restarted, with or without SA_RESTART
 * and with or without a timeout, and always report EINTR.
 *
 * The read half also moves the task between CPUs while it is blocked. A restart
 * keeps its state on the task, not on the worker that armed it, so a remount on
 * another vCPU must resume the syscall with the same original arguments. The
 * reader pins itself to CPU A, the main thread retargets it to CPU B while it
 * is parked, and the byte is only written afterwards: the restarted read must
 * complete on B, and the handler must have run once.
 *
 * Both assertions are real Linux behaviour, so this test belongs to the
 * cross-checkable matrix rather than the elfuse-internal manifest.
 *
 * Syscalls exercised: pipe2(59), read(63), poll(7), rt_sigaction(134),
 *                     tgkill(131), sched_setaffinity(122),
 *                     sched_getaffinity(123), getcpu(168), nanosleep(101)
 */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

static volatile sig_atomic_t handler_hits;

static void on_usr1(int sig)
{
    (void) sig;
    handler_hits++;
}

static void sleep_ms(long ms)
{
    struct timespec ts = {.tv_sec = ms / 1000,
                          .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static pid_t self_tid(void)
{
    return (pid_t) syscall(SYS_gettid);
}

static int current_cpu(void)
{
    unsigned cpu = 0;
    if (syscall(SYS_getcpu, &cpu, NULL, NULL) < 0)
        return -1;
    return (int) cpu;
}

static int pin_to_cpu(pid_t tid, int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return (int) syscall(SYS_sched_setaffinity, tid, sizeof(set), &set);
}

/* CPUs this process may run on, in ascending order. Returns the count. */
static int allowed_cpus(int *out, int max)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof(set), &set) != 0)
        return 0;
    int n = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE && n < max; cpu++) {
        if (CPU_ISSET(cpu, &set))
            out[n++] = cpu;
    }
    return n;
}

/* read with SA_RESTART, restarted across a CPU migration */

struct read_case {
    int fd;
    int pin_cpu;
    pid_t tid;
    int cpu_before;
    int cpu_after;
    volatile int ready;
    volatile int done;
    ssize_t ret;
    int err;
    char byte;
};

static void *read_thread(void *arg)
{
    struct read_case *c = arg;
    c->tid = self_tid();
    if (c->pin_cpu >= 0) {
        if (pin_to_cpu(0, c->pin_cpu) != 0)
            FAIL("sched_setaffinity(self) failed");
        sched_yield();
    }
    c->cpu_before = current_cpu();
    c->ready = 1;
    errno = 0;
    c->ret = read(c->fd, &c->byte, 1);
    c->err = errno;
    c->cpu_after = current_cpu();
    c->done = 1;
    return NULL;
}

/* Wait up to @ms for *flag to become non-zero. */
static int wait_flag(volatile int *flag, long ms)
{
    for (long i = 0; i < ms; i++) {
        if (*flag)
            return 1;
        sleep_ms(1);
    }
    return *flag != 0;
}

static void test_read_sa_restart(void)
{
    int cpus[CPU_SETSIZE];
    int ncpu = allowed_cpus(cpus, CPU_SETSIZE);
    int migrate = ncpu >= 2;

    TEST("read SA_RESTART + migration");

    int pfd[2];
    if (pipe(pfd) != 0) {
        FAIL("pipe failed");
        printf("\n");
        return;
    }

    struct read_case c;
    memset(&c, 0, sizeof(c));
    c.fd = pfd[0];
    c.pin_cpu = migrate ? cpus[0] : -1;
    c.cpu_before = -1;
    c.cpu_after = -1;

    pthread_t th;
    if (pthread_create(&th, NULL, read_thread, &c) != 0) {
        FAIL("pthread_create failed");
        close(pfd[0]);
        close(pfd[1]);
        printf("\n");
        return;
    }

    /* The reader pins itself to the first allowed CPU before publishing ready;
     * give the remount a moment, then read where it landed.
     */
    (void) wait_flag(&c.ready, 1000);
    sleep_ms(20);

    /* Retarget the parked reader to a different CPU. It is not runnable, so the
     * affinity only takes effect on the wake this signal causes.
     */
    int target = -1;
    if (migrate) {
        int before = c.cpu_before;
        for (int i = 0; i < ncpu; i++) {
            if (cpus[i] != before) {
                target = cpus[i];
                break;
            }
        }
        if (target < 0)
            migrate = 0;
        else if (pin_to_cpu(c.tid, target) != 0) {
            FAIL("sched_setaffinity(target) failed");
            migrate = 0;
        }
    }

    sig_atomic_t hits_before = handler_hits;
    pthread_kill(th, SIGUSR1);

    /* A restarted read is still blocked: the signal ran a handler whose
     * SA_RESTART re-entered the syscall instead of reporting EINTR.
     */
    sleep_ms(100);
    EXPECT_TRUE(!c.done, "read stayed blocked across the signal");

    if (write(pfd[1], "R", 1) != 1)
        FAIL("write to pipe failed");

    pthread_join(th, NULL);

    printf("[cpu %d -> %d] ", c.cpu_before, c.cpu_after);
    EXPECT_EQ(c.ret, 1, "restarted read returned 1 byte");
    EXPECT_TRUE(c.ret != 1 || c.byte == 'R', "restarted read returned 'R'");
    EXPECT_TRUE(handler_hits > hits_before, "handler ran");
    if (migrate)
        EXPECT_EQ(c.cpu_after, target, "task resumed on the retargeted CPU");
    else
        printf("(migration skipped: need two CPUs) ");

    close(pfd[0]);
    close(pfd[1]);
    printf("\n");
}

/* poll family: never restarted, finite or infinite */

struct poll_case {
    int fd;
    int timeout_ms;
    pid_t tid;
    volatile int ready;
    volatile int done;
    int ret;
    int err;
};

static void *poll_thread(void *arg)
{
    struct poll_case *c = arg;
    struct pollfd p = {.fd = c->fd, .events = POLLIN};
    c->tid = self_tid();
    c->ready = 1;
    errno = 0;
    c->ret = poll(&p, 1, c->timeout_ms);
    c->err = errno;
    c->done = 1;
    return NULL;
}

static void run_poll_case(int timeout_ms, const char *label)
{
    char name[64];
    snprintf(name, sizeof(name), "poll %s never restarts", label);

    TEST(name);

    int pfd[2];
    if (pipe(pfd) != 0) {
        FAIL("pipe failed");
        printf("\n");
        return;
    }

    struct poll_case c;
    memset(&c, 0, sizeof(c));
    c.fd = pfd[0];
    c.timeout_ms = timeout_ms;

    pthread_t th;
    if (pthread_create(&th, NULL, poll_thread, &c) != 0) {
        FAIL("pthread_create failed");
        close(pfd[0]);
        close(pfd[1]);
        printf("\n");
        return;
    }

    (void) wait_flag(&c.ready, 1000);
    sleep_ms(50);
    EXPECT_TRUE(!c.done, "poll did not return before the signal");

    sig_atomic_t hits_before = handler_hits;
    pthread_kill(th, SIGUSR1);

    /* EINTR should arrive promptly. If the wait was wrongly restarted it is
     * still blocked, so unblock it with data and record the failure rather than
     * hanging the suite.
     */
    if (!wait_flag(&c.done, 500)) {
        (void) write(pfd[1], "P", 1);
        (void) wait_flag(&c.done, 2000);
    }
    pthread_join(th, NULL);

    EXPECT_TRUE(c.ret == -1 && c.err == EINTR,
                "poll reported EINTR for the SA_RESTART signal");
    EXPECT_TRUE(handler_hits > hits_before, "handler ran");

    /* The EINTR must not have consumed the data: a fresh call sees it. */
    if (write(pfd[1], "P", 1) != 1) {
        FAIL("write to pipe failed");
    } else {
        struct pollfd p = {.fd = pfd[0], .events = POLLIN};
        EXPECT_EQ(poll(&p, 1, 1000), 1, "fresh poll sees the byte");
    }

    close(pfd[0]);
    close(pfd[1]);
    printf("\n");
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_usr1;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        printf("sigaction failed\n");
        return 1;
    }

    test_read_sa_restart();
    run_poll_case(1500, "finite");
    run_poll_case(-1, "infinite");

    SUMMARY("test-eintr-restart");
    return fails == 0 ? 0 : 1;
}
