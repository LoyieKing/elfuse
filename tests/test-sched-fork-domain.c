/*
 * Linux fork-domain scheduler state: attribute inheritance with a remote
 * child-TID query, and SCHED_FIFO exclusion across forked processes.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pipes synchronize both sides; both sides arm alarm(2). Exit: 0 pass, 1 fail,
 * 77 prerequisite unavailable (skip).
 */

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

#define SKIP_EXIT 77
#define ALARM_SEC 30
#define CHILD_ALARM_SEC 25
#define NSEC_PER_SEC 1000000000ULL

static int passes;
static int fails;

static int skip(const char *why)
{
    printf("SKIP: %s\n", why);
    return SKIP_EXIT;
}

static int nice_get(pid_t task, int *out)
{
    errno = 0;
    *out = getpriority(PRIO_PROCESS, (id_t) task);
    return *out == -1 && errno != 0 ? -1 : 0;
}

static int state_get(pid_t task, int *nice, int *policy, cpu_set_t *mask)
{
    int pol = sched_getscheduler(task);

    if (pol < 0 || nice_get(task, nice) != 0)
        return -1;
    *policy = pol;
    return sched_getaffinity(task, sizeof(*mask), mask);
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

static int affinity_set_one(int cpu)
{
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    return sched_setaffinity(0, sizeof(mask), &mask);
}

static volatile sig_atomic_t alarm_child;

static void alarm_handler(int signo)
{
    (void) signo;
    if (alarm_child > 0)
        (void) kill((pid_t) alarm_child, SIGKILL);
    _exit(1);
}

static void arm(pid_t child, int seconds)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    (void) sigaction(SIGALRM, &sa, NULL);
    alarm_child = (sig_atomic_t) child;
    alarm(seconds);
}

struct state_msg {
    int failed;
    int nice;
    int policy;
    cpu_set_t mask;
};

static int send_msg(int fd, const struct state_msg *msg)
{
    ssize_t n;

    do {
        n = write(fd, msg, sizeof(*msg));
    } while (n < 0 && errno == EINTR);
    return n == (ssize_t) sizeof(*msg) ? 0 : -1;
}

static int recv_msg(int fd, struct state_msg *msg)
{
    size_t off = 0;

    while (off < sizeof(*msg)) {
        ssize_t n = read(fd, (char *) msg + off, sizeof(*msg) - off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        off += (size_t) n;
    }
    return 0;
}

static void kill_and_reap(pid_t pid)
{
    int status;

    (void) kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
}

static int reap_ok(pid_t pid)
{
    int status;

    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static void child_inherit(int out_fd,
                          int ack_fd,
                          int child_nice,
                          int change_nice,
                          int cpu_b)
{
    struct state_msg msg;
    struct sched_param sp = {0};
    char ack;

    alarm_child = 0;
    alarm(CHILD_ALARM_SEC);
    memset(&msg, 0, sizeof(msg));
    if (state_get(0, &msg.nice, &msg.policy, &msg.mask) != 0)
        msg.failed = 1;
    if (send_msg(out_fd, &msg) != 0)
        _exit(10);
    if (msg.failed)
        _exit(1);
    if (change_nice && setpriority(PRIO_PROCESS, 0, child_nice) != 0)
        msg.failed = 1;
    if (!msg.failed && sched_setscheduler(0, SCHED_IDLE, &sp) != 0)
        msg.failed = 1;
    if (!msg.failed && cpu_b >= 0 && affinity_set_one(cpu_b) != 0)
        msg.failed = 1;
    memset(&msg, 0, sizeof(msg));
    if (state_get(0, &msg.nice, &msg.policy, &msg.mask) != 0)
        msg.failed = 1;
    if (send_msg(out_fd, &msg) != 0)
        _exit(11);
    if (read(ack_fd, &ack, 1) != 1)
        _exit(12);
    _exit(msg.failed ? 1 : 0);
}

static int scenario_fork_inherit(void)
{
    struct state_msg first, second;
    struct sched_param sp = {0};
    cpu_set_t mask;
    int cpu_a, cpu_b, ncpu, start, parent_nice, child_nice, changes;
    int nice_now, policy_now;
    int to_parent[2] = {-1, -1}, ack_pipe[2] = {-1, -1};
    pid_t child = -1;
    char ack = 'x';
    int reaped = 0, status = 1;

    arm(0, ALARM_SEC);
    if (sched_getaffinity(0, sizeof(mask), &mask) != 0) {
        FAIL("sched_getaffinity");
        goto out;
    }
    ncpu = affinity_count(&mask, &cpu_a, &cpu_b);
    if (ncpu < 1) {
        FAIL("empty affinity mask");
        goto out;
    }
    if (nice_get(0, &start) != 0) {
        FAIL("getpriority");
        goto out;
    }
    if (start == 19) {
        parent_nice = child_nice = 19;
        changes = 0;
    } else if (start == 18) {
        parent_nice = 18;
        child_nice = 19;
        changes = 1;
    } else {
        parent_nice = start + 1;
        child_nice = start + 2;
        changes = 1;
    }
    if (parent_nice != start &&
        setpriority(PRIO_PROCESS, 0, parent_nice) != 0) {
        FAIL("setpriority(parent)");
        goto out;
    }
    if (sched_setscheduler(0, SCHED_BATCH, &sp) != 0) {
        FAIL("sched_setscheduler(SCHED_BATCH)");
        goto out;
    }
    if (affinity_set_one(cpu_a) != 0) {
        FAIL("sched_setaffinity");
        goto out;
    }
    if (pipe(to_parent) != 0 || pipe(ack_pipe) != 0) {
        FAIL("pipe");
        goto out;
    }
    child = fork();
    if (child < 0) {
        FAIL("fork");
        goto out;
    }
    if (child == 0) {
        close(to_parent[0]);
        close(ack_pipe[1]);
        child_inherit(to_parent[1], ack_pipe[0], child_nice, changes, cpu_b);
        _exit(1);
    }
    close(to_parent[1]);
    to_parent[1] = -1;
    close(ack_pipe[0]);
    ack_pipe[0] = -1;
    arm(child, ALARM_SEC);

    if (recv_msg(to_parent[0], &first) != 0) {
        FAIL("read inherited state");
        goto out;
    }
    EXPECT_TRUE(!first.failed, "child could not capture its state");
    EXPECT_EQ(first.nice, parent_nice, "nice was not inherited");
    EXPECT_EQ(first.policy, SCHED_BATCH, "policy was not inherited");
    EXPECT_TRUE(affinity_is_only(&first.mask, cpu_a),
                "affinity was not inherited");

    if (recv_msg(to_parent[0], &second) != 0) {
        FAIL("read changed state");
        goto out;
    }
    EXPECT_TRUE(!second.failed, "child could not change its state");
    EXPECT_EQ(second.nice, child_nice, "child nice is wrong");
    EXPECT_EQ(second.policy, SCHED_IDLE, "child policy is wrong");
    EXPECT_TRUE(affinity_is_only(&second.mask, cpu_b >= 0 ? cpu_b : cpu_a),
                "child affinity is wrong");

    if (state_get(child, &nice_now, &policy_now, &mask) != 0) {
        FAIL("remote changed state");
    } else {
        EXPECT_EQ(nice_now, child_nice, "remote nice is wrong");
        EXPECT_EQ(policy_now, SCHED_IDLE, "remote policy is wrong");
        EXPECT_TRUE(affinity_is_only(&mask, cpu_b >= 0 ? cpu_b : cpu_a),
                    "remote affinity is wrong");
    }
    if (state_get(0, &nice_now, &policy_now, &mask) != 0) {
        FAIL("parent state query");
    } else {
        EXPECT_EQ(nice_now, parent_nice, "parent nice changed");
        EXPECT_EQ(policy_now, SCHED_BATCH, "parent policy changed");
        EXPECT_TRUE(affinity_is_only(&mask, cpu_a), "parent affinity changed");
    }

    if (write(ack_pipe[1], &ack, 1) != 1) {
        FAIL("release child");
        goto out;
    }
    reaped = 1;
    TEST("fork child exited cleanly");
    if (reap_ok(child) == 0) {
        PASS();
    } else {
        printf("FAIL: child exit status was not 0\n");
        fails++;
    }
    status = fails ? 1 : 0;

out:
    if (child > 0 && !reaped)
        kill_and_reap(child);
    for (int i = 0; i < 2; i++) {
        if (to_parent[i] >= 0)
            close(to_parent[i]);
        if (ack_pipe[i] >= 0)
            close(ack_pipe[i]);
    }
    return status;
}

#define RT_SPIN_NS (150ULL * 1000ULL * 1000ULL)

static void child_rt(int ready_fd, int start_fd, int done_fd, int cpu)
{
    char byte;

    alarm_child = 0;
    alarm(CHILD_ALARM_SEC);
    if (affinity_set_one(cpu) != 0)
        _exit(1);
    if (write(ready_fd, "R", 1) != 1)
        _exit(1);
    if (read(start_fd, &byte, 1) != 1)
        _exit(1);
    if (write(done_fd, "D", 1) != 1)
        _exit(1);
    _exit(0);
}

static int scenario_rt_excludes(void)
{
    struct sched_param rt = {0}, other = {0};
    cpu_set_t mask;
    int cpu_a, cpu_b;
    int ready[2] = {-1, -1}, start[2] = {-1, -1}, done[2] = {-1, -1};
    pid_t child = -1;
    char byte;
    unsigned long long t0, now_ns;
    struct timespec ts0;
    int during = 0, saw_done = 0, eof = 0;
    int reaped = 0, status = 1;

    arm(0, ALARM_SEC);
    if (sched_getaffinity(0, sizeof(mask), &mask) != 0) {
        FAIL("sched_getaffinity");
        goto out;
    }
    if (affinity_count(&mask, &cpu_a, &cpu_b) < 1) {
        FAIL("empty affinity mask");
        goto out;
    }
    if (affinity_set_one(cpu_a) != 0) {
        FAIL("pin RT parent");
        goto out;
    }
    if (pipe(ready) != 0 || pipe(start) != 0 || pipe(done) != 0) {
        FAIL("pipe");
        goto out;
    }
    child = fork();
    if (child < 0) {
        FAIL("fork");
        goto out;
    }
    if (child == 0) {
        close(ready[0]);
        close(start[1]);
        close(done[0]);
        child_rt(ready[1], start[0], done[1], cpu_a);
        _exit(1);
    }
    close(ready[1]);
    ready[1] = -1;
    close(start[0]);
    start[0] = -1;
    close(done[1]);
    done[1] = -1;
    arm(child, ALARM_SEC);

    if (read(ready[0], &byte, 1) != 1 || byte != 'R') {
        FAIL("child ready handshake");
        goto out;
    }

    /* The capability check happens here, before the RT window. A missing
     * CAP_SYS_NICE/RLIMIT_RTPRIO is an explicit skip, never a pass.
     */
    rt.sched_priority = 1;
    if (sched_setscheduler(0, SCHED_FIFO, &rt) != 0) {
        if (errno == EPERM) {
            status = skip("SCHED_FIFO needs CAP_SYS_NICE or RLIMIT_RTPRIO");
            goto out;
        }
        FAIL("enter SCHED_FIFO");
        goto out;
    }
    EXPECT_EQ(sched_getscheduler(0), SCHED_FIFO, "FIFO policy not active");

    if (fcntl(done[0], F_SETFL, O_NONBLOCK) != 0) {
        FAIL("fcntl(done, O_NONBLOCK)");
        goto out;
    }
    if (write(start[1], "S", 1) != 1 ||
        clock_gettime(CLOCK_MONOTONIC, &ts0) != 0) {
        FAIL("start RT child");
        goto out;
    }
    t0 = (unsigned long long) ts0.tv_sec * NSEC_PER_SEC + ts0.tv_nsec;
    for (;;) {
        struct timespec now;
        ssize_t n = read(done[0], &byte, 1);

        if (n == 1) {
            during = 1;
            saw_done = byte == 'D';
            break;
        }
        if (n == 0) {
            eof = 1;
            break;
        }
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
            errno != EINTR) {
            FAIL("read RT progress pipe");
            goto out;
        }
        for (volatile unsigned long spin = 0; spin < 1000; spin++)
            ;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            FAIL("clock_gettime(CLOCK_MONOTONIC)");
            goto out;
        }
        now_ns = (unsigned long long) now.tv_sec * NSEC_PER_SEC + now.tv_nsec;
        if (now_ns - t0 >= RT_SPIN_NS)
            break;
    }

    if (sched_setscheduler(0, SCHED_OTHER, &other) != 0) {
        FAIL("drop SCHED_FIFO");
        goto out;
    }
    (void) fcntl(done[0], F_SETFL, 0);
    if (!saw_done) {
        ssize_t n;

        do {
            n = read(done[0], &byte, 1);
        } while (n < 0 && errno == EINTR);
        if (n == 1 && byte == 'D')
            saw_done = 1;
    }
    if (eof || !saw_done) {
        FAIL("child completion handshake");
        goto out;
    }
    reaped = 1;
    TEST("RT child exited cleanly");
    if (reap_ok(child) == 0) {
        PASS();
    } else {
        printf("FAIL: child exit status was not 0\n");
        fails++;
    }
    EXPECT_EQ(during, 0, "SCHED_OTHER child ran while FIFO parent spun");
    status = fails ? 1 : 0;

out:
    if (child > 0 && !reaped)
        kill_and_reap(child);
    for (int i = 0; i < 2; i++) {
        if (ready[i] >= 0)
            close(ready[i]);
        if (start[i] >= 0)
            close(start[i]);
        if (done[i] >= 0)
            close(done[i]);
    }
    return status;
}

static const struct scenario {
    const char *name;
    int (*run)(void);
} scenarios[] = {
    {"fork-inherit-isolate", scenario_fork_inherit},
    {"rt-fifo-excludes-fork", scenario_rt_excludes},
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
        printf("test-sched-fork-domain: %s\n", scenarios[i].name);
        rc = scenarios[i].run();
        if (rc != SKIP_EXIT)
            SUMMARY(scenarios[i].name);
        return rc;
    }
    fprintf(stderr, "usage: %s --list | SCENARIO\n", argv[0]);
    return 2;
}
