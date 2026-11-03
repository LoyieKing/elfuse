/*
 * Low-address mmap hint regression test
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Verifies that non-fixed anonymous mmap() honors a free low address hint such
 * as 0x400000. box64 uses this pattern to reserve the ET_EXEC image window for
 * static x86-64 binaries.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

int passes = 0, fails = 0;

static void *reserve_free_low_hint(size_t len)
{
    static const uintptr_t candidates[] = {
        0x00400000ULL, 0x00800000ULL, 0x01000000ULL,
        0x02000000ULL, 0x04000000ULL, 0x06000000ULL,
    };

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        void *hint = (void *) candidates[i];
        void *p =
            mmap(hint, len, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (p == MAP_FAILED) {
            if (errno == EEXIST || errno == EINVAL)
                continue;
            return MAP_FAILED;
        }
        return p;
    }

    errno = ENOMEM;
    return MAP_FAILED;
}

static void test_low_hint_exact(void)
{
    TEST("mmap low hint preserves ET_EXEC-style address");

    size_t len = 0x21000;
    void *hint = reserve_free_low_hint(len);
    if (hint == MAP_FAILED) {
        FAIL("no free low hint candidate");
        return;
    }
    munmap(hint, len);

    void *p = mmap(hint, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    EXPECT_TRUE((uintptr_t) p == (uintptr_t) hint,
                "low mmap hint should be honored when range is free");
    munmap(p, len);
}

static void test_shared_file_hint_falls_back_from_2m_alignment(void)
{
    TEST("MAP_SHARED file hint falls back from 2MiB alignment");

    const size_t page = (size_t) sysconf(_SC_PAGESIZE);

    void *base = reserve_free_low_hint(0x20000 + page);
    void *anchor = base == MAP_FAILED ? MAP_FAILED : (char *) base + 0x20000;
    if (anchor == MAP_FAILED) {
        FAIL("anchor mmap failed");
        return;
    }

    uintptr_t anchor_addr = (uintptr_t) anchor;
    munmap(base, 0x20000);
    uintptr_t hint_addr = anchor_addr - 0x10000;

    char path[] = "/tmp/elfuse-mmap-hint-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        munmap(anchor, page);
        FAIL("mkstemp failed");
        return;
    }
    unlink(path);

    if (ftruncate(fd, (off_t) page) < 0) {
        close(fd);
        munmap(anchor, page);
        FAIL("ftruncate failed");
        return;
    }

    void *hint = (void *) hint_addr;
    void *p = mmap(hint, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        close(fd);
        munmap(anchor, page);
        FAIL("shared file mmap failed");
        return;
    }

    EXPECT_TRUE((uintptr_t) p == hint_addr,
                "shared file mmap should honor host-page-aligned hint");

    munmap(p, page);
    close(fd);
    munmap(anchor, page);
}

static void test_guest_page_hint(void)
{
    const size_t len = 8 * 4096;
    void *base = reserve_free_low_hint(len);
    if (base == MAP_FAILED) {
        TEST("4KiB hint setup");
        FAIL("no free range");
        return;
    }
    munmap(base, len);
    void *hint = (char *) base + 2 * 4096;
    TEST("4KiB-aligned anonymous hint stays exact");
    void *p = mmap(hint, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    EXPECT_TRUE(p == hint, "hint rounded to host page");
    if (p != MAP_FAILED)
        munmap(p, 4096);

    TEST("4KiB-aligned executable hint stays exact");
    p = mmap(hint, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1,
             0);
    EXPECT_TRUE(p == hint, "executable mmap ignored free hint");
    if (p != MAP_FAILED)
        munmap(p, 4096);
}

static void test_shared_hint_coherence(void)
{
    const size_t len = 4 * 4096;
    void *base = reserve_free_low_hint(2 * len);
    char path[] = "/tmp/elfuse-shared-hint-XXXXXX";
    int fd = mkstemp(path);
    TEST("shared aliases stay coherent with 4KiB hint");
    if (base == MAP_FAILED || fd < 0) {
        FAIL("setup shared hint");
        if (base != MAP_FAILED)
            munmap(base, 2 * len);
        if (fd >= 0) {
            close(fd);
            unlink(path);
        }
        return;
    }
    unlink(path);
    munmap(base, 2 * len);
    if (ftruncate(fd, len) < 0) {
        FAIL("ftruncate");
        close(fd);
        return;
    }
    volatile unsigned char *p = mmap((char *) base + 2 * 4096, len,
                                     PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    volatile unsigned char *alias =
        mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    bool ok = (void *) p != MAP_FAILED && (void *) alias != MAP_FAILED;
    if (ok) {
        p[0] = 0xe7;
        ok = alias[0] == 0xe7;
        alias[4096] = 0xd3;
        ok = ok && p[4096] == 0xd3;
    }
    EXPECT_TRUE(ok, "address hint turned shared backing into a snapshot");
    if ((void *) p != MAP_FAILED)
        munmap((void *) p, len);
    if ((void *) alias != MAP_FAILED)
        munmap((void *) alias, len);
    close(fd);
}

static void test_shared_overlay_preserves_neighbor(bool fixed)
{
    const size_t page = 4096;
    const size_t span = 4 * page;
    const size_t length = 3 * page;
    unsigned char *base = reserve_free_low_hint(2 * span);
    char path[] = "/tmp/elfuse-overlay-neighbor-XXXXXX";
    int fd = mkstemp(path);
    unsigned char *neighbor = MAP_FAILED;
    void *mapped = MAP_FAILED;
    TEST(fixed ? "fixed short shared overlay setup"
               : "short shared overlay hint setup");
    if (base == MAP_FAILED || fd < 0) {
        FAIL("reserve or mkstemp failed");
        goto out;
    }
    unlink(path);
    if (ftruncate(fd, (off_t) span) != 0) {
        FAIL("ftruncate failed");
        goto out;
    }
    neighbor = mmap(base + length, page, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (neighbor == MAP_FAILED) {
        FAIL("neighbor mmap failed");
        goto out;
    }
    memset(neighbor, 0xa5, page);
    if (munmap(base, length) != 0) {
        FAIL("opening preceding gap failed");
        goto out;
    }
    mapped = mmap(base, length, PROT_READ | PROT_WRITE,
                  MAP_SHARED | (fixed ? MAP_FIXED : 0), fd, 0);
    bool rejected = fixed && mapped == MAP_FAILED && errno == ENOMEM;
    if (mapped == MAP_FAILED && !rejected) {
        FAIL("shared mmap failed");
        goto out;
    }
    PASS();
    struct utsname uts;
    if (!fixed && uname(&uts) == 0 && !strcmp(uts.nodename, "elfuse")) {
        TEST(
            "short shared overlay skips a gap with an occupied host-page tail");
        EXPECT_TRUE(mapped != base, "overlay allocation reused a short gap");
    }
    TEST(fixed ? "fixed shared overlay preserves live neighbor"
               : "shared overlay preserves live neighbor");
    bool intact = true;
    for (size_t i = 0; i < page; i++)
        intact &= neighbor[i] == 0xa5;
    EXPECT_TRUE(intact, "overlay replaced neighboring guest-page bytes");
    if (mapped != MAP_FAILED) {
        volatile unsigned char *bytes = mapped;
        bytes[0] = 0x6b;
        unsigned char stored = 0;
        TEST("short shared overlay keeps live file backing");
        EXPECT_TRUE(pread(fd, &stored, 1, 0) == 1 && stored == 0x6b,
                    "shared mapping became a private snapshot");
        munmap(mapped, length);
    }
    mapped = MAP_FAILED;
    TEST(fixed ? "fixed shared overlay teardown preserves neighbor"
               : "shared overlay teardown preserves neighbor");
    intact = true;
    for (size_t i = 0; i < page; i++)
        intact &= neighbor[i] == 0xa5;
    EXPECT_TRUE(intact, "overlay teardown zeroed neighboring guest-page bytes");
out:
    if (mapped != MAP_FAILED)
        munmap(mapped, length);
    if (base != MAP_FAILED)
        munmap(base, 2 * span);
    if (fd >= 0) {
        close(fd);
        unlink(path);
    }
}

static void test_varying_size_churn(void)
{
    TEST("varying-size mmap churn retains bounded live coverage");
    const size_t unit = 2 * 1024 * 1024 + 16384;
    void *live[2] = {NULL, NULL};
    size_t lengths[2] = {0, 0};
    bool ok = true;
    size_t iteration;
    for (iteration = 0; iteration < 16384; iteration++) {
        size_t slot = iteration % 2;
        size_t length = iteration % 4 == 3 ? 2 * unit : unit;
        unsigned char *p = mmap(NULL, length, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            ok = false;
            break;
        }
        p[0] = (unsigned char) iteration;
        p[length - 1] = (unsigned char) (iteration + 1);
        if (mprotect(p, 4096, PROT_READ) != 0 ||
            mprotect(p, 4096, PROT_READ | PROT_WRITE) != 0 ||
            p[0] != (unsigned char) iteration ||
            p[length - 1] != (unsigned char) (iteration + 1)) {
            munmap(p, length);
            ok = false;
            break;
        }
        if (live[slot] && munmap(live[slot], lengths[slot]) != 0) {
            munmap(p, length);
            ok = false;
            break;
        }
        live[slot] = p;
        lengths[slot] = length;
    }
    for (size_t slot = 0; slot < 2; slot++) {
        if (live[slot] && munmap(live[slot], lengths[slot]) != 0)
            ok = false;
    }
    if (!ok)
        printf("mmap churn stopped at iteration %zu: errno=%d\n", iteration,
               errno);
    EXPECT_TRUE(ok, "bounded live mappings exhausted page tables");
}

int main(void)
{
    test_low_hint_exact();
    test_shared_file_hint_falls_back_from_2m_alignment();
    test_guest_page_hint();
    test_shared_hint_coherence();
    test_shared_overlay_preserves_neighbor(false);
    test_shared_overlay_preserves_neighbor(true);
    test_varying_size_churn();
    SUMMARY("test-mmap-hint");
    return fails ? 1 : 0;
}
