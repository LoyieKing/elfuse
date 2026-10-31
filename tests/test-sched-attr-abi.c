/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"

struct sched_attr_wire {
    uint32_t size;
    uint32_t policy;
    uint64_t flags;
    int32_t nice;
    uint32_t priority;
    uint64_t runtime;
    uint64_t deadline;
    uint64_t period;
    uint32_t util_min;
    uint32_t util_max;
};

_Static_assert(sizeof(struct sched_attr_wire) == 56, "sched_attr ABI size");

int main(void)
{
    int passes = 0, fails = 0;
    struct sched_attr_wire original = {0};
    long rc = syscall(SYS_sched_getattr, 0, &original, sizeof(original), 0);

    TEST("sched_getattr available");
    EXPECT_EQ(rc, 0, "sched_getattr failed");
    if (rc != 0) {
        SUMMARY("test-sched-attr-abi");
        return 1;
    }

    TEST("legacy policy agrees with attr");
    EXPECT_EQ(sched_getscheduler(0),
              original.policy | ((original.flags & 1) ? 0x40000000U : 0),
              "legacy and extended policy disagree");

    struct {
        unsigned char prefix[48];
        uint64_t guard;
    } short_attr;
    memset(&short_attr, 0xa5, sizeof(short_attr));
    rc = syscall(SYS_sched_getattr, 0, &short_attr, sizeof(short_attr.prefix),
                 0);
    TEST("48-byte getattr preserves tail");
    EXPECT_TRUE(rc == 0 && short_attr.guard == UINT64_C(0xa5a5a5a5a5a5a5a5),
                "getattr overwrote bytes beyond requested size");

    struct sched_attr_wire small = {0};
    small.size = 47;
    TEST("short setattr rejects size");
    EXPECT_ERRNO(syscall(SYS_sched_setattr, 0, &small, 0), E2BIG,
                 "short sched_attr accepted");

    struct {
        struct sched_attr_wire attr;
        uint64_t extension;
    } oversized = {.attr = original, .extension = 1};
    oversized.attr.size = sizeof(oversized);
    TEST("nonzero unknown extension rejected");
    EXPECT_ERRNO(syscall(SYS_sched_setattr, 0, &oversized, 0), E2BIG,
                 "nonzero unknown sched_attr field accepted");
    TEST("E2BIG reports required attr size");
    EXPECT_EQ(oversized.attr.size, original.size,
              "E2BIG did not return kernel structure size");

    struct sched_attr_wire invalid = original;
    invalid.size = sizeof(invalid);
    invalid.flags |= UINT64_C(1) << 63;
    TEST("unknown scheduler flag rejected");
    EXPECT_ERRNO(syscall(SYS_sched_setattr, 0, &invalid, 0), EINVAL,
                 "unknown scheduler flag accepted");

    TEST("getattr syscall flags rejected");
    EXPECT_ERRNO(syscall(SYS_sched_getattr, 0, &small, sizeof(small), 1),
                 EINVAL, "nonzero getattr syscall flags accepted");

    if (original.policy == SCHED_OTHER) {
        struct sched_attr_wire requested = original;
        requested.size = sizeof(requested);
        requested.nice = original.nice < 19 ? original.nice + 1 : 19;
        rc = syscall(SYS_sched_setattr, 0, &requested, 0);
        TEST("fair attr changes real nice");
        struct sched_attr_wire observed = {0};
        long get_rc =
            syscall(SYS_sched_getattr, 0, &observed, sizeof(observed), 0);
        EXPECT_TRUE(rc == 0 && get_rc == 0 && observed.nice == requested.nice &&
                        observed.policy == SCHED_OTHER &&
                        observed.priority == 0,
                    "setattr did not update fair task attributes");
    } else {
        printf("SKIP fair nice mutation: caller policy=%u\n", original.policy);
    }

    SUMMARY("test-sched-attr-abi");
    return fails != 0;
}
