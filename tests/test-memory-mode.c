/*
 * Guest byte semantics under the host memory mode
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The runtime memory mode changes how anonymous memory is backed, not what the
 * guest reads. These cases run unchanged under --memory-mode=lazy and eager:
 * fresh anonymous bytes read zero, MAP_FIXED replacement drops the old bytes,
 * MADV_DONTNEED zeroes exactly its range even when live neighbours share the
 * 16KiB host page, repeated discard and remap reuse does not leak stale pages,
 * PROT_NONE does not hide a discard, fork copies stay private even while the
 * parent churns its allocator, anonymous shared bytes survive one side's unmap,
 * and the policy carries through a real exec of this image.
 *
 * Syscalls exercised: mmap(222), munmap(215), madvise(233), mprotect(226),
 *                     clone(220), execve(221), wait4(260), pipe2(59),
 *                     read(63), write(64)
 */

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0x4000
#endif

/* A macOS host page holds four 4KiB guest pages, so a discard of one guest page
 * must not disturb the other three. A 4KiB Linux host makes the same window
 * three separate pages and the assertions still hold.
 */
#define HOST_BLOCK ((size_t) 16384)
#define BLOCK_2MIB ((size_t) 2 * 1024 * 1024)

int passes = 0, fails = 0;

static size_t page_size;
extern char **environ;

static unsigned char pattern(size_t offset)
{
    return (unsigned char) (0x40 + ((offset * 37u) % 0x3fu));
}

static void fill_pattern(unsigned char *p, size_t len)
{
    for (size_t i = 0; i < len; i++)
        p[i] = pattern(i);
}

static bool all_zero(const unsigned char *p, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (p[i] != 0)
            return false;
    }
    return true;
}

static bool all_value(const unsigned char *p, size_t len, unsigned char value)
{
    for (size_t i = 0; i < len; i++) {
        if (p[i] != value)
            return false;
    }
    return true;
}

/* Volatile stores keep the explicit page touch ordered against the probe read
 * that follows; a plain memset may sink past it, since faulting is outside the
 * C abstract machine.
 */
static void fill_value(unsigned char *p, size_t len, unsigned char value)
{
    volatile unsigned char *vp = p;
    for (size_t i = 0; i < len; i++)
        vp[i] = value;
}

/* True when every byte is pattern(i), except the zero_off/zero_len window,
 * which must read zero. This is what catches a discard that zeroes a host page
 * rather than the guest range.
 */
static bool range_matches(const unsigned char *p,
                          size_t len,
                          size_t zero_off,
                          size_t zero_len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char want = pattern(i);
        if (zero_len != 0 && i >= zero_off && i < zero_off + zero_len)
            want = 0;
        if (p[i] != want)
            return false;
    }
    return true;
}

/* Pattern check on a subrange of a mapping filled from offset zero. */
static bool range_matches_from(const unsigned char *p, size_t start, size_t len)
{
    for (size_t i = start; i < start + len; i++) {
        if (p[i] != pattern(i))
            return false;
    }
    return true;
}

static unsigned char *map_anon(size_t len, int flags)
{
    void *p =
        mmap(NULL, len, PROT_READ | PROT_WRITE, flags | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

static bool remap_fixed(unsigned char *at, size_t len)
{
    void *p = mmap(at, len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p == MAP_FAILED)
        return false;
    if (p != at) {
        munmap(p, len);
        return false;
    }
    return true;
}

/* First 16KiB-aligned address inside p with room for three guest pages. */
static unsigned char *host_block(unsigned char *p, size_t len)
{
    uintptr_t start =
        ((uintptr_t) p + HOST_BLOCK - 1) & ~(uintptr_t) (HOST_BLOCK - 1);
    if (start + 3 * page_size > (uintptr_t) p + len)
        return NULL;
    return (unsigned char *) start;
}

static void test_zero_fill(void)
{
    size_t len = 3 * page_size;
    unsigned char *p;

    TEST("fresh anonymous mapping is zero");
    p = map_anon(len, MAP_PRIVATE);
    if (!p) {
        FAIL("mmap");
        return;
    }
    bool ok = all_zero(p, len);
    EXPECT_TRUE(ok, "fresh anonymous bytes were not zero");

    /* Fill the reused range first: a reset that only forgets metadata, rather
     * than replacing the physical backing, leaves these bytes visible.
     */
    if (ok) {
        fill_pattern(p, len);

        TEST("MAP_FIXED anonymous remap is zero");
        ok = remap_fixed(p, len) && all_zero(p, len);
        EXPECT_TRUE(ok, "MAP_FIXED reuse kept stale bytes");
    }
    if (ok) {
        fill_pattern(p, len);

        TEST("MAP_FIXED subrange keeps neighbours");
        ok = remap_fixed(p + page_size, page_size) &&
             range_matches(p, len, page_size, page_size);
        EXPECT_TRUE(ok, "MAP_FIXED subrange lost a neighbouring page");
    }

    if (ok) {
        fill_pattern(p, len);

        TEST("MAP_FIXED regrant over PROT_NONE zeroes");
        ok = mprotect(p + page_size, page_size, PROT_NONE) == 0;
        ok = ok && remap_fixed(p + page_size, page_size);
        ok = ok && range_matches(p, len, page_size, page_size);
        EXPECT_TRUE(ok, "PROT_NONE regrant kept dirty bytes");
    }
    munmap(p, len);

    TEST("anonymous mmap after unmap is zero");
    p = map_anon(len, MAP_PRIVATE);
    if (!p)
        FAIL("mmap");
    else {
        EXPECT_TRUE(all_zero(p, len), "reused address kept stale bytes");
        munmap(p, len);
    }
}

/* MAP_NORESERVE defers physical backing by 2MiB block. A fault on one page
 * materializes backing, and touching another page of the block must not reset
 * bytes already written. The aligned window puts a, b, and c in one block.
 */
static void test_noreserve_preserved(void)
{
    size_t len = 3 * BLOCK_2MIB + HOST_BLOCK;
    unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    volatile unsigned char *probe;
    unsigned char seen;
    bool ok;

    TEST("NORESERVE adjacent page keeps bytes");
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    uintptr_t base =
        ((uintptr_t) p + BLOCK_2MIB - 1) & ~(uintptr_t) (BLOCK_2MIB - 1);
    if (base + 3 * page_size > (uintptr_t) p + len) {
        FAIL("no 2MiB-aligned window");
        munmap(p, len);
        return;
    }

    unsigned char *a = (unsigned char *) base;
    unsigned char *b = a + page_size;
    unsigned char *c = b + page_size;
    fill_value(a, page_size, 0xA5);

    probe = b;
    seen = probe[page_size / 2];
    (void) seen;
    ok = all_value(a, page_size, 0xA5) && all_zero(b, page_size);

    fill_value(b, page_size, 0x5A);
    probe = c;
    seen = probe[page_size / 2];
    (void) seen;
    ok = ok && all_value(a, page_size, 0xA5) && all_value(b, page_size, 0x5A) &&
         all_zero(c, page_size);
    EXPECT_TRUE(ok, "a later page fault reset a written page");

    munmap(p, len);
}

/* Repeat a full discard, unmap, and fixed remap at the same address. A lazy
 * reset that leaks a host page or forgets one shows up as stale bytes on a
 * later round, not only on the first allocation.
 */
#define REUSE_ROUNDS 16

static void test_alloc_discard_reuse(void)
{
    size_t len = 4 * HOST_BLOCK + page_size;
    unsigned char *slot = map_anon(len, MAP_PRIVATE);
    bool ok = slot != NULL;

    TEST("repeated allocate/discard/reuse is zero");
    if (!ok) {
        FAIL("mmap");
        return;
    }
    munmap(slot, len);

    for (int round = 0; round < REUSE_ROUNDS && ok; round++) {
        ok = remap_fixed(slot, len);
        if (!ok)
            break;
        fill_pattern(slot, len);
        ok = madvise(slot, len, MADV_DONTNEED) == 0 && all_zero(slot, len);
        if (!ok) {
            munmap(slot, len);
            break;
        }
        fill_pattern(slot, len);
        ok = munmap(slot, len) == 0;
    }
    EXPECT_TRUE(ok, "stale bytes survived allocate/discard/reuse");
}

/* Discard the guest page at @index inside one 16KiB host block. Indexes 1 to 3
 * place the discarded page after a live neighbour, so a round-down or round-up
 * of the host page shows up as a corrupted neighbour.
 */
static void test_partial_discard(unsigned index)
{
    size_t len = 4 * HOST_BLOCK;
    char label[48];
    unsigned char *p = map_anon(len, MAP_PRIVATE);

    snprintf(label, sizeof(label), "DONTNEED 4K in 16K (offset %uK)",
             index * 4);
    TEST(label);
    if (!p) {
        FAIL("mmap");
        return;
    }
    unsigned char *block = host_block(p, len);
    if (!block) {
        FAIL("no 16KiB-aligned window");
        munmap(p, len);
        return;
    }

    fill_pattern(p, len);
    size_t off = (size_t) (block - p) + index * page_size;
    bool ok = madvise(block + index * page_size, page_size, MADV_DONTNEED) == 0;
    if (!ok)
        FAIL("madvise");
    else
        EXPECT_TRUE(range_matches(p, len, off, page_size),
                    "discard zeroed a neighbour or kept the page");

    munmap(p, len);
}

static void test_prot_none_discard(void)
{
    size_t len = 3 * page_size;
    unsigned char *p = map_anon(len, MAP_PRIVATE);
    bool ok;

    TEST("DONTNEED through PROT_NONE zeroes");
    if (!p) {
        FAIL("mmap");
        return;
    }
    fill_pattern(p, len);
    ok = mprotect(p + page_size, page_size, PROT_NONE) == 0;
    ok = ok && madvise(p + page_size, page_size, MADV_DONTNEED) == 0;
    ok = ok && mprotect(p + page_size, page_size, PROT_READ | PROT_WRITE) == 0;
    if (!ok)
        FAIL("PROT_NONE round trip");
    else
        EXPECT_TRUE(range_matches(p, len, page_size, page_size),
                    "PROT_NONE discard lost data or kept the page");
    munmap(p, len);

    TEST("PROT_NONE whole-range DONTNEED");
    p = map_anon(len, MAP_PRIVATE);
    if (!p) {
        FAIL("mmap");
        return;
    }
    fill_pattern(p, len);
    ok = mprotect(p, len, PROT_NONE) == 0;
    ok = ok && madvise(p, len, MADV_DONTNEED) == 0;
    ok = ok && mprotect(p, len, PROT_READ | PROT_WRITE) == 0;
    if (!ok)
        FAIL("PROT_NONE round trip");
    else
        EXPECT_TRUE(all_zero(p, len), "range not zeroed after restore");
    munmap(p, len);
}

/* The child dirties its private page, discards it, and rewrites it. Its report
 * bits record inherited bytes, zero fill, rewrite and fresh allocation.
 */
static void fork_discard_child(unsigned char *p, int report_fd)
{
    unsigned char report = 0;
    ssize_t n;

    if (!range_matches(p, page_size, 0, 0))
        report |= 1;
    p[0] = 0xC1;
    p[page_size - 1] = 0xC3;
    if (madvise(p, page_size, MADV_DONTNEED) != 0 || !all_zero(p, page_size))
        report |= 2;
    p[page_size / 2] = 0xC2;
    if (p[page_size / 2] != 0xC2)
        report |= 4;

    unsigned char *fresh = map_anon(page_size, MAP_PRIVATE);
    if (!fresh)
        report |= 8;
    else {
        if (!all_zero(fresh, page_size))
            report |= 8;
        munmap(fresh, page_size);
    }

    do {
        n = write(report_fd, &report, 1);
    } while (n < 0 && errno == EINTR);
    close(report_fd);
    _exit(n == 1 ? 0 : 1);
}

static void test_fork_discard(void)
{
    unsigned char *p = map_anon(page_size, MAP_PRIVATE);
    int report_pipe[2];
    unsigned char report = 0xff;
    int status = 0;
    ssize_t n = 0;
    bool reaped = false;
    pid_t child;

    TEST("fork child sees the parent dirty page");
    if (!p) {
        FAIL("mmap");
        return;
    }
    fill_pattern(p, page_size);
    if (pipe(report_pipe) != 0) {
        FAIL("pipe");
        munmap(p, page_size);
        return;
    }

    child = fork();
    if (child == 0) {
        close(report_pipe[0]);
        fork_discard_child(p, report_pipe[1]);
    }
    close(report_pipe[1]);
    if (child < 0) {
        FAIL("fork");
    } else {
        do {
            n = read(report_pipe[0], &report, 1);
        } while (n < 0 && errno == EINTR);
        reaped = waitpid(child, &status, 0) == child;
        EXPECT_TRUE(reaped && n == 1 && (report & 1) == 0,
                    "child did not see the parent's bytes");
    }
    close(report_pipe[0]);

    TEST("fork DONTNEED keeps parent bytes");
    if (child < 0) {
        FAIL("fork");
    } else {
        bool ok = reaped && n == 1 && (report & 2) == 0 &&
                  range_matches(p, page_size, 0, 0);
        EXPECT_TRUE(ok, "child discard changed the parent page");
    }

    TEST("fork child anon mmap is zero");
    if (child < 0) {
        FAIL("fork");
    } else {
        EXPECT_TRUE(reaped && n == 1 && (report & 8) == 0,
                    "child fresh mapping was not zero");
    }

    munmap(p, page_size);
}

/* A full 16KiB discard takes the lazy reset's unmap and remap path, not the
 * sub-host-page memset fallback. The child's copy must be the only one
 * replaced, and the untouched 16KiB half must keep the parent's bytes.
 */
static void fork_aligned_child(unsigned char *map, size_t len, size_t off)
{
    unsigned char *block = map + off;

    if (!range_matches_from(map, off, HOST_BLOCK))
        _exit(10);
    if (madvise(block, HOST_BLOCK, MADV_DONTNEED) != 0)
        _exit(11);
    if (!all_zero(block, HOST_BLOCK))
        _exit(12);
    if (off != 0 && !range_matches_from(map, 0, off))
        _exit(13);
    if (off + HOST_BLOCK < len &&
        !range_matches_from(map, off + HOST_BLOCK, len - off - HOST_BLOCK))
        _exit(14);
    memset(block, 0xC5, HOST_BLOCK);
    if (!all_value(block, HOST_BLOCK, 0xC5))
        _exit(15);
    _exit(0);
}

static void test_fork_aligned_discard(void)
{
    size_t len = 2 * HOST_BLOCK;
    unsigned char *p = map_anon(len, MAP_PRIVATE);
    int status = 0;
    pid_t child;

    TEST("fork aligned 16KiB DONTNEED isolated");
    if (!p) {
        FAIL("mmap");
        return;
    }
    fill_pattern(p, len);
    uintptr_t aligned =
        ((uintptr_t) p + HOST_BLOCK - 1) & ~(uintptr_t) (HOST_BLOCK - 1);
    if (aligned + HOST_BLOCK > (uintptr_t) p + len) {
        FAIL("no 16KiB-aligned window");
        munmap(p, len);
        return;
    }

    unsigned char *block = (unsigned char *) aligned;
    size_t off = (size_t) (block - p);
    child = fork();
    if (child == 0)
        fork_aligned_child(p, len, off);
    if (child < 0) {
        FAIL("fork");
    } else {
        bool ok = waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                  WEXITSTATUS(status) == 0 && range_matches_from(p, 0, len);
        EXPECT_TRUE(ok, "child discard changed the parent or a neighbour");
    }

    munmap(p, len);
}

#define FORK_CHURN_ROUNDS 16

/* The child waits until the parent has churned its allocator, then checks the
 * page it inherited. A child that shared the parent's backing instead of
 * snapshotting it sees the churn.
 */
static void fork_churn_child(unsigned char *p,
                             size_t len,
                             int sync_fd,
                             int report_fd)
{
    unsigned char token = 0;
    unsigned char report = 0;
    ssize_t n;

    do {
        n = read(sync_fd, &token, 1);
    } while (n < 0 && errno == EINTR);
    if (n == 1 && range_matches(p, len, 0, 0))
        report = 1;
    do {
        n = write(report_fd, &report, 1);
    } while (n < 0 && errno == EINTR);
    close(sync_fd);
    close(report_fd);
    _exit(n == 1 ? 0 : 1);
}

static void test_fork_parent_churn(void)
{
    size_t len = 2 * page_size;
    size_t churn_len = 4 * HOST_BLOCK + page_size;
    unsigned char *p = map_anon(len, MAP_PRIVATE);
    int sync_pipe[2];
    int report_pipe[2];
    unsigned char token = 0x5A;
    unsigned char report = 0;
    int status = 0;
    ssize_t n = 0;
    bool churn_ok;
    bool reaped = false;
    pid_t child;

    TEST("fork child keeps old dirty page across parent churn");
    if (!p) {
        FAIL("mmap");
        return;
    }
    fill_pattern(p, len);
    if (pipe(sync_pipe) != 0) {
        FAIL("pipe");
        munmap(p, len);
        return;
    }
    if (pipe(report_pipe) != 0) {
        FAIL("pipe");
        close(sync_pipe[0]);
        close(sync_pipe[1]);
        munmap(p, len);
        return;
    }

    child = fork();
    if (child == 0) {
        close(sync_pipe[1]);
        close(report_pipe[0]);
        fork_churn_child(p, len, sync_pipe[0], report_pipe[1]);
    }
    close(sync_pipe[0]);
    close(report_pipe[1]);
    if (child < 0) {
        close(sync_pipe[1]);
        close(report_pipe[0]);
        FAIL("fork");
        munmap(p, len);
        return;
    }

    /* Reuse one fixed address so every round replaces the same backing. */
    churn_ok = true;
    unsigned char *slot = map_anon(churn_len, MAP_PRIVATE);
    if (!slot)
        churn_ok = false;
    else
        churn_ok = munmap(slot, churn_len) == 0;
    for (int round = 0; round < FORK_CHURN_ROUNDS && churn_ok; round++) {
        churn_ok = remap_fixed(slot, churn_len);
        if (!churn_ok)
            break;
        fill_pattern(slot, churn_len);
        churn_ok = madvise(slot, churn_len, MADV_DONTNEED) == 0 &&
                   all_zero(slot, churn_len);
        if (!churn_ok) {
            munmap(slot, churn_len);
            break;
        }
        fill_value(slot, page_size, (unsigned char) (0x30 + round));
        churn_ok = munmap(slot, churn_len) == 0;
    }

    do {
        n = write(sync_pipe[1], &token, 1);
    } while (n < 0 && errno == EINTR);
    close(sync_pipe[1]);
    ssize_t report_n;
    do {
        report_n = read(report_pipe[0], &report, 1);
    } while (report_n < 0 && errno == EINTR);
    close(report_pipe[0]);
    reaped = waitpid(child, &status, 0) == child;
    EXPECT_TRUE(churn_ok && reaped && report_n == 1 && report == 1,
                "child lost the inherited dirty page");

    TEST("parent dirty page survives its own churn");
    EXPECT_TRUE(churn_ok && range_matches(p, len, 0, 0),
                "parent churn reset an unrelated dirty page");

    munmap(p, len);
}

/* Write from the child, drop the child's mapping, then let the parent read the
 * bytes back through its own mapping of the same anonymous shared object.
 */
static void shared_unmap_child(unsigned char *p, size_t len)
{
    if (!range_matches(p, len, 0, 0))
        _exit(10);
    p[page_size] = 0xE1;
    p[2 * page_size] = 0xE2;
    if (munmap(p, len) != 0)
        _exit(11);
    _exit(0);
}

static void shared_verify_child(unsigned char *p, int report_fd)
{
    unsigned char ok =
        p[0] == 0xF0 && p[page_size] == 0xE1 && p[2 * page_size] == 0xE2;
    ssize_t n;

    do {
        n = write(report_fd, &ok, 1);
    } while (n < 0 && errno == EINTR);
    close(report_fd);
    _exit(n == 1 ? 0 : 1);
}

static void test_shared_fork_unmap(void)
{
    size_t len = 3 * page_size;
    unsigned char *p = map_anon(len, MAP_SHARED);
    int report_pipe[2];
    unsigned char seen = 0;
    int status = 0;
    bool reaped = false;
    pid_t child;

    TEST("anon shared writes survive child unmap");
    if (!p) {
        FAIL("mmap");
        return;
    }
    fill_pattern(p, len);

    child = fork();
    if (child == 0)
        shared_unmap_child(p, len);
    if (child < 0) {
        FAIL("fork");
    } else {
        reaped = waitpid(child, &status, 0) == child;
        bool ok = reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                  p[page_size] == 0xE1 && p[2 * page_size] == 0xE2 &&
                  p[0] == pattern(0) &&
                  p[page_size + 1] == pattern(page_size + 1);
        EXPECT_TRUE(ok, "child write or unmap lost the shared bytes");
    }

    if (child < 0) {
        munmap(p, len);
        return;
    }

    TEST("anon shared parent write crosses fork");
    p[0] = 0xF0;
    if (pipe(report_pipe) != 0) {
        FAIL("pipe");
        munmap(p, len);
        return;
    }
    child = fork();
    if (child == 0) {
        close(report_pipe[0]);
        shared_verify_child(p, report_pipe[1]);
    }
    close(report_pipe[1]);
    if (child < 0) {
        FAIL("fork");
    } else {
        ssize_t n;
        do {
            n = read(report_pipe[0], &seen, 1);
        } while (n < 0 && errno == EINTR);
        reaped = waitpid(child, &status, 0) == child;
        EXPECT_TRUE(reaped && n == 1 && seen == 1 && WIFEXITED(status) &&
                        WEXITSTATUS(status) == 0,
                    "child did not see the parent's shared write");
    }
    close(report_pipe[0]);
    munmap(p, len);
}

#define CHURN_THREADS 2
#define CHURN_ITERS 64
#define CHURN_LEN ((size_t) 4 * 1024 * 1024)

/* ready/go is the start barrier: each worker publishes readiness, then spins
 * until the parent releases both, so neither starts the churn alone.
 */

typedef struct {
    int eintr;
    int failures;
    int first_errno;
} churn_result_t;

static _Atomic int churn_ready;
static _Atomic int churn_go;

static void churn_record(churn_result_t *result, int err)
{
    result->failures++;
    if (err == EINTR)
        result->eintr++;
    if (result->first_errno == 0)
        result->first_errno = err;
}

/* Both threads map, discard, and unmap the same large range. A reset that waits
 * for the sibling while holding mmap_lock meets a sibling waiting for that lock
 * and reports EINTR after the quiesce timeout.
 */
static void *churn_thread(void *opaque)
{
    churn_result_t *result = opaque;

    atomic_fetch_add_explicit(&churn_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&churn_go, memory_order_acquire))
        sched_yield();

    for (int i = 0; i < CHURN_ITERS; i++) {
        unsigned char *p = mmap(NULL, CHURN_LEN, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            churn_record(result, errno);
            break;
        }
        p[0] = (unsigned char) (0x30 + i);
        p[CHURN_LEN - page_size] = (unsigned char) (0x40 + i);
        if (madvise(p, CHURN_LEN, MADV_DONTNEED) != 0)
            churn_record(result, errno);
        if (munmap(p, CHURN_LEN) != 0)
            churn_record(result, errno);
    }
    return NULL;
}

static void test_threaded_reset(void)
{
    pthread_t threads[CHURN_THREADS];
    churn_result_t results[CHURN_THREADS] = {{0}};
    int created = 0;

    TEST("two threads reset without EINTR");
    atomic_store_explicit(&churn_ready, 0, memory_order_relaxed);
    atomic_store_explicit(&churn_go, 0, memory_order_relaxed);
    for (int i = 0; i < CHURN_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, churn_thread, &results[i]) != 0)
            break;
        created++;
    }
    if (created == CHURN_THREADS) {
        while (atomic_load_explicit(&churn_ready, memory_order_acquire) <
               CHURN_THREADS)
            sched_yield();
    }
    atomic_store_explicit(&churn_go, 1, memory_order_release);
    for (int i = 0; i < created; i++)
        pthread_join(threads[i], NULL);

    bool ok = created == CHURN_THREADS;
    int first_errno = 0;
    for (int i = 0; i < created; i++) {
        ok = ok && results[i].eintr == 0 && results[i].failures == 0;
        if (first_errno == 0)
            first_errno = results[i].first_errno;
    }
    errno = first_errno;
    EXPECT_TRUE(ok, "concurrent reset returned EINTR or another errno");
}

/* Repeat reset-sensitive byte semantics after a real execve. Host residency
 * measurements separately check which policy the replacement image uses.
 */
static int after_exec(void)
{
    printf("test-memory-mode: after execve\n");
    test_zero_fill();
    test_alloc_discard_reuse();
    test_partial_discard(1);
    test_prot_none_discard();
    SUMMARY("test-memory-mode (exec)");
    return fails > 0 ? 1 : 0;
}

int main(int argc, char **argv)
{
    long host_page = sysconf(_SC_PAGESIZE);

    if (host_page <= 0) {
        printf("test-memory-mode: cannot read the guest page size\n");
        return 1;
    }
    page_size = (size_t) host_page;
    if (page_size != 4096) {
        printf("test-memory-mode: SKIP: guest page size %zu, need 4096\n",
               page_size);
        return 0;
    }

    if (argc >= 2 && strcmp(argv[1], "after-exec") == 0)
        return after_exec();

    printf("test-memory-mode: anonymous memory semantics\n");
    test_zero_fill();
    test_noreserve_preserved();
    test_alloc_discard_reuse();
    test_partial_discard(1);
    test_partial_discard(2);
    test_partial_discard(3);
    test_prot_none_discard();
    test_fork_discard();
    test_fork_aligned_discard();
    test_fork_parent_churn();
    test_shared_fork_unmap();
    test_threaded_reset();

    if (fails > 0) {
        SUMMARY("test-memory-mode");
        return 1;
    }

    printf("test-memory-mode: execve self\n");
    fflush(stdout);
    fflush(stderr);
    char *next[] = {argv[0], (char *) "after-exec", NULL};
    execve(argv[0], next, environ);
    printf("test-memory-mode: execve self: %s\n", strerror(errno));
    fails++;
    SUMMARY("test-memory-mode");
    return 1;
}
