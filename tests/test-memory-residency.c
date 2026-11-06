/*
 * Host page residency reported through mincore
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A 64 KiB anonymous mapping aligned to the 16 KiB host page reports the real
 * backing state, not the mapped VA range: untouched pages are not resident,
 * written pages are, and a fully covered MADV_DONTNEED drops them again. On
 * Apple Silicon one host page covers four guest pages, so aligning the range
 * keeps a partial host-page edge out of the discard. The same assertions hold
 * on a 4 KiB Linux host.
 *
 * The memory mode this checks is lazy, where a reset releases backing. Eager
 * mode zeroes in place and intentionally keeps the pages resident, so the
 * Makefile target runs this binary with --memory-mode=lazy.
 *
 * Syscalls exercised: mmap(222), munmap(215), madvise(233), mprotect(226),
 *                     mincore(232)
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif

#define HOST_BLOCK ((size_t) 16384)
#define WINDOW_LEN ((size_t) 64 * 1024)
#define WINDOW_PAGES (WINDOW_LEN / 4096)

int passes = 0, fails = 0;

static size_t page_size;

/* Volatile stores keep the explicit page touch ordered before the mincore
 * probe; a plain memset may sink past it, since faulting is outside the C
 * abstract machine.
 */
static void touch_pages(unsigned char *p, size_t len)
{
    volatile unsigned char *vp = p;

    for (size_t i = 0; i < len; i++)
        vp[i] = (unsigned char) (0x40 + (i & 0x3f));
}

static bool touch_matches(const unsigned char *p, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (p[i] != (unsigned char) (0x40 + (i & 0x3f)))
            return false;
    }
    return true;
}

/* Exact 64 KiB window starting on a 16 KiB boundary. The surrounding head and
 * tail are discarded so the window is the whole mapping, which lets the hole
 * case unmap one page without leaving unrelated bytes in range.
 */
static unsigned char *aligned_window(void)
{
    size_t len = WINDOW_LEN + HOST_BLOCK;
    unsigned char *base = mmap(NULL, len, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uintptr_t aligned;
    size_t head, tail;

    if (base == MAP_FAILED)
        return NULL;
    aligned =
        ((uintptr_t) base + HOST_BLOCK - 1) & ~(uintptr_t) (HOST_BLOCK - 1);
    if (aligned + WINDOW_LEN > (uintptr_t) base + len) {
        munmap(base, len);
        return NULL;
    }
    head = (size_t) (aligned - (uintptr_t) base);
    tail = len - head - WINDOW_LEN;
    if (head != 0 && munmap(base, head) != 0) {
        munmap(base, len);
        return NULL;
    }
    if (tail != 0 &&
        munmap((unsigned char *) aligned + WINDOW_LEN, tail) != 0) {
        munmap((unsigned char *) aligned, WINDOW_LEN);
        return NULL;
    }
    return (unsigned char *) aligned;
}

/* True when mincore succeeds and every guest page's residency bit is @want. The
 * high bits are undefined by mincore(2), so only the LSB is read.
 */
static bool residency_is(unsigned char *p, size_t len, int want)
{
    unsigned char vec[WINDOW_PAGES];
    long rc;

    memset(vec, 0xff, sizeof(vec));
    rc = syscall(SYS_mincore, p, len, vec);
    if (rc != 0)
        return false;
    for (size_t i = 0; i < WINDOW_PAGES; i++) {
        if ((vec[i] & 1) != want)
            return false;
    }
    return true;
}

/* The whole point of the lazy policy: the host has released the backing, so the
 * pages are absent before the first touch and absent again after a full
 * discard. A mapped-region approximation would report them resident both times.
 */
static void test_fresh_fill_discard(void)
{
    unsigned char *p = aligned_window();
    bool ok;

    TEST("fresh anonymous pages are not resident");
    if (!p) {
        FAIL("mmap");
        return;
    }
    if (madvise(p, WINDOW_LEN, MADV_NOHUGEPAGE) != 0) {
        FAIL("MADV_NOHUGEPAGE");
        munmap(p, WINDOW_LEN);
        return;
    }
    ok = residency_is(p, WINDOW_LEN, 0);
    EXPECT_TRUE(ok, "untouched pages reported resident");

    TEST("written anonymous pages are resident");
    touch_pages(p, WINDOW_LEN);
    ok = residency_is(p, WINDOW_LEN, 1);
    EXPECT_TRUE(ok, "written pages reported nonresident");

    TEST("full DONTNEED drops the pages");
    ok = madvise(p, WINDOW_LEN, MADV_DONTNEED) == 0 &&
         residency_is(p, WINDOW_LEN, 0);
    EXPECT_TRUE(ok, "discarded pages reported resident");

    munmap(p, WINDOW_LEN);
}

static void test_free_reclaim(bool require_reclaim)
{
    unsigned char *p = aligned_window();

    TEST("MADV_FREE preserves neighboring guest pages");
    if (!p) {
        FAIL("mmap");
        return;
    }
    touch_pages(p, WINDOW_LEN);
    if (madvise(p + page_size, WINDOW_LEN - 2 * page_size, MADV_FREE) != 0) {
        FAIL("MADV_FREE");
        munmap(p, WINDOW_LEN);
        return;
    }
    if (require_reclaim) {
        unsigned char vec[WINDOW_PAGES];
        bool released = mincore(p, WINDOW_LEN, vec) == 0;
        for (size_t i = HOST_BLOCK / page_size;
             released && i < (WINDOW_LEN - HOST_BLOCK) / page_size; i++) {
            if (vec[i] & 1)
                released = false;
        }
        EXPECT_TRUE(released, "MADV_FREE retained complete host pages");
        TEST("MADV_FREE keeps partial host-page neighbors");
    }
    bool intact = true;
    for (size_t i = 0; i < WINDOW_LEN; i++) {
        unsigned char old = (unsigned char) (0x40 + (i & 0x3f));
        bool discarded = i >= page_size && i < WINDOW_LEN - page_size;
        if (p[i] != old && !(discarded && p[i] == 0)) {
            intact = false;
            break;
        }
    }
    EXPECT_TRUE(intact, "MADV_FREE corrupted retained or discarded bytes");

    TEST("writes after full-page MADV_FREE persist");
    touch_pages(p, WINDOW_LEN);
    EXPECT_TRUE(touch_matches(p, WINDOW_LEN), "write after discard was lost");
    munmap(p, WINDOW_LEN);
}

/* Revoking permission does not discard the backing. The guest still owns the
 * bytes, and mincore keeps reporting them until a reset runs.
 */
static void test_prot_none_keeps_pages(void)
{
    unsigned char *p = aligned_window();

    TEST("PROT_NONE keeps written pages resident");
    if (!p) {
        FAIL("mmap");
        return;
    }
    if (madvise(p, WINDOW_LEN, MADV_NOHUGEPAGE) != 0) {
        FAIL("MADV_NOHUGEPAGE");
        munmap(p, WINDOW_LEN);
        return;
    }
    touch_pages(p, WINDOW_LEN);
    if (mprotect(p, WINDOW_LEN, PROT_NONE) != 0) {
        FAIL("mprotect PROT_NONE");
        munmap(p, WINDOW_LEN);
        return;
    }
    if (!residency_is(p, WINDOW_LEN, 1)) {
        FAIL("PROT_NONE reported nonresident");
        mprotect(p, WINDOW_LEN, PROT_READ | PROT_WRITE);
        munmap(p, WINDOW_LEN);
        return;
    }
    PASS();

    TEST("PROT_NONE regrant keeps the bytes");
    if (mprotect(p, WINDOW_LEN, PROT_READ | PROT_WRITE) != 0) {
        FAIL("mprotect regrant");
        munmap(p, WINDOW_LEN);
        return;
    }
    EXPECT_TRUE(touch_matches(p, WINDOW_LEN),
                "PROT_NONE round trip lost written bytes");

    munmap(p, WINDOW_LEN);
}

/* Linux reports ENOMEM for any range containing an unmapped page, even when the
 * rest is mapped and resident.
 */
static void test_hole_reports_enomem(void)
{
    const size_t hole = 5 * 4096;
    unsigned char *p = aligned_window();
    unsigned char vec[WINDOW_PAGES];
    long rc;

    TEST("unmapped hole reports ENOMEM");
    if (!p) {
        FAIL("mmap");
        return;
    }
    touch_pages(p, WINDOW_LEN);
    if (munmap(p + hole, page_size) != 0) {
        FAIL("hole munmap");
        munmap(p, WINDOW_LEN);
        return;
    }
    errno = 0;
    rc = syscall(SYS_mincore, p, WINDOW_LEN, vec);
    EXPECT_TRUE(rc == -1 && errno == ENOMEM, "hole did not report ENOMEM");

    munmap(p, hole);
    munmap(p + hole + page_size, WINDOW_LEN - hole - page_size);
}

/* The vector is a guest buffer like any other. A write into an unmapped guest
 * address is EFAULT, and that takes precedence over the mapping checks.
 */
static void test_invalid_vec_reports_efault(void)
{
    unsigned char *p = aligned_window();
    long rc;

    TEST("unwritable vector reports EFAULT");
    if (!p) {
        FAIL("mmap");
        return;
    }
    errno = 0;
    rc = syscall(SYS_mincore, p, WINDOW_LEN, (unsigned char *) 1);
    EXPECT_TRUE(rc == -1 && errno == EFAULT, "invalid vector was accepted");

    TEST("unaligned address reports EINVAL");
    errno = 0;
    rc = syscall(SYS_mincore, p + 1, page_size, (unsigned char *) 1);
    EXPECT_TRUE(rc == -1 && errno == EINVAL, "unaligned address was accepted");

    munmap(p, WINDOW_LEN);
}

int main(int argc, char **argv)
{
    long host_page = sysconf(_SC_PAGESIZE);

    if (host_page <= 0) {
        printf("test-memory-residency: cannot read the guest page size\n");
        return 1;
    }
    page_size = (size_t) host_page;
    if (page_size != 4096) {
        printf("test-memory-residency: SKIP: guest page size %zu, need 4096\n",
               page_size);
        return 0;
    }

    printf("test-memory-residency: mincore over a 16 KiB aligned window\n");
    test_fresh_fill_discard();
    test_free_reclaim(argc == 2 && !strcmp(argv[1], "--free-reclaim"));
    test_prot_none_keeps_pages();
    test_hole_reports_enomem();
    test_invalid_vec_reports_efault();

    SUMMARY("test-memory-residency");
    return fails > 0 ? 1 : 0;
}
