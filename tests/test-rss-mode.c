/*
 * /proc residency reporting under each --rss mode.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The exact walk classifies every guest page, so a touched mapping raises VmRSS
 * and discarding it lowers VmRSS again. The approximate mode reads the host
 * task's resident size, so the same transitions must still move in the same
 * direction, which is what a guest's memory monitoring observes. Neither mode
 * may report a value above VmSize or below zero.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

static bool read_status(unsigned long long *vm_size_kb,
                        unsigned long long *rss_kb)
{
    char buf[4096];
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0)
        return false;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return false;
    buf[n] = '\0';

    const char *size = strstr(buf, "VmSize:");
    const char *rss = strstr(buf, "VmRSS:");
    if (!size || !rss)
        return false;
    *vm_size_kb = strtoull(size + 7, NULL, 10);
    *rss_kb = strtoull(rss + 6, NULL, 10);
    return true;
}

int main(void)
{
    const size_t span = 128u * 1024u * 1024u;

    unsigned long long idle_size = 0, idle_rss = 0;
    TEST("status reports VmSize and VmRSS");
    EXPECT_TRUE(read_status(&idle_size, &idle_rss) && idle_size > 0,
                "status unreadable or VmSize missing");

    TEST("VmRSS never exceeds VmSize before touching memory");
    EXPECT_TRUE(idle_rss <= idle_size, "VmRSS above VmSize");

    unsigned char *p = mmap(NULL, span, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        SUMMARY("test-rss-mode");
        return 1;
    }

    unsigned long long reserved_size = 0, reserved_rss = 0;
    TEST("reserving without touching leaves VmSize ahead of VmRSS");
    EXPECT_TRUE(read_status(&reserved_size, &reserved_rss) &&
                    reserved_size >= idle_size + span / 1024 &&
                    reserved_rss <= reserved_size,
                "reservation did not raise VmSize or raised RSS past it");

    for (size_t i = 0; i < span; i += 4096)
        p[i] = 1;

    unsigned long long touched_size = 0, touched_rss = 0;
    TEST("touching every page raises VmRSS");
    EXPECT_TRUE(read_status(&touched_size, &touched_rss) &&
                    touched_rss > reserved_rss && touched_rss <= touched_size,
                "VmRSS did not grow with touched pages");

    TEST("VmRSS grew by roughly the touched span");
    {
        unsigned long long growth = touched_rss - reserved_rss;
        unsigned long long want = span / 1024;

        /* The approximate mode reads host residency, so it also counts what
         * elfuse touched outside the guest. Keep the band wide enough for that
         * constant and narrow enough to catch a lost or doubled span.
         */
        unsigned long long slack = want / 4;
        unsigned long long diff = growth > want ? growth - want : want - growth;
        EXPECT_TRUE(diff <= slack, "VmRSS growth is not near the touched span");
    }

    if (madvise(p, span, MADV_DONTNEED) != 0) {
        FAIL("madvise MADV_DONTNEED");
    } else {
        unsigned long long after_size = 0, after_rss = 0;
        TEST("discarding the range lowers VmRSS");
        EXPECT_TRUE(read_status(&after_size, &after_rss) &&
                        after_rss < touched_rss && after_rss <= after_size,
                    "VmRSS did not fall after discard");
    }

    munmap(p, span);

    unsigned long long final_size = 0, final_rss = 0;
    TEST("unmapping lowers VmSize again");
    EXPECT_TRUE(read_status(&final_size, &final_rss) &&
                    final_size < touched_size && final_rss <= final_size,
                "VmSize did not fall after unmap");

    SUMMARY("test-rss-mode");
    return fails == 0 ? 0 : 1;
}
