/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/timex.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int main(void)
{
    int passes = 0, fails = 0;
    struct timex before, after;
    memset(&before, 0, sizeof(before));
    memset(&after, 0, sizeof(after));
    long a = syscall(SYS_adjtimex, &before);
    long b = syscall(SYS_clock_adjtime, CLOCK_REALTIME, &after);
    TEST("clock adjustment query agrees");
    EXPECT_TRUE(a >= 0 && b >= 0 && before.tick == after.tick &&
                    before.freq == after.freq && before.tick > 0,
                "clock query failed or returned inconsistent state");
    TEST("clock adjustment query validates pointer");
    EXPECT_ERRNO(syscall(SYS_adjtimex, (void *) 1), EFAULT,
                 "adjtimex invalid pointer accepted");
    TEST("unsupported namespace creation fails");
    EXPECT_ERRNO(unshare(CLONE_NEWNS), EPERM,
                 "namespace request unexpectedly succeeded");
    TEST("namespace switch cannot fabricate success");
    long result = setns(-1, 0);
    EXPECT_TRUE(result == -1 && (errno == EBADF || errno == EPERM),
                "setns invalid descriptor fabricated success");
    SUMMARY("test-sched-capabilities");
    return fails != 0;
}
