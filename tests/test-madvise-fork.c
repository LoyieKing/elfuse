/*
 * madvise fork inheritance tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Actual child reads must fault with SEGV_MAPERR, so metadata-only exclusion
 * cannot pass while copied page tables still expose the memory.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;
static size_t page;

static unsigned char pattern(int index)
{
    return (unsigned char) (0x41 + index);
}

static void fill_values(unsigned char *p, int pages)
{
    for (int i = 0; i < pages; i++)
        p[(size_t) i * page] = pattern(i);
}

static bool values_intact(const unsigned char *p, int pages)
{
    for (int i = 0; i < pages; i++) {
        if (p[(size_t) i * page] != pattern(i))
            return false;
    }
    return true;
}

static bool seed_file(int fd, int pages)
{
    for (int i = 0; i < pages; i++) {
        unsigned char value = pattern(i);
        if (pwrite(fd, &value, 1, (off_t) i * (off_t) page) != 1)
            return false;
    }
    return true;
}

static bool file_byte(int fd, int index, unsigned char expected)
{
    unsigned char got;
    if (pread(fd, &got, 1, (off_t) index * (off_t) page) != 1)
        return false;
    return got == expected;
}

/* The fault probes below record siginfo and resume at the sigsetjmp that armed
 * the probe, instead of returning to the faulting load.
 */
static sigjmp_buf fault_env;
static volatile sig_atomic_t fault_code;
static volatile uintptr_t fault_seen;
static volatile uintptr_t fault_expected;

static void fault_handler(int sig, siginfo_t *info, void *context)
{
    (void) sig;
    (void) context;
    fault_code = info ? info->si_code : 0;
    fault_seen = info ? (uintptr_t) info->si_addr : 0;
    siglongjmp(fault_env, 1);
}

static bool read_byte(unsigned char *addr, unsigned char *value)
{
    if (sigsetjmp(fault_env, 1) == 0) {
        *value = *(volatile unsigned char *) addr;
        return true;
    }
    return false;
}

static bool fault_map_err(unsigned char *addr)
{
    fault_code = 0;
    fault_seen = 0;
    fault_expected = (uintptr_t) addr;
    if (sigsetjmp(fault_env, 1) == 0) {
        (void) *(volatile unsigned char *) addr;
        return false;
    }
    return fault_code == SEGV_MAPERR && fault_seen == fault_expected;
}

/* Run in the fork child: pages selected by mask must read back their pattern;
 * every other page must be absent with SIGSEGV/SEGV_MAPERR.
 *
 * Returns 0 or a non-zero exit status that names the first failing page.
 */
static int child_verify(unsigned char *p, unsigned mask, int pages)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0)
        return 90;

    for (int i = 0; i < pages; i++) {
        unsigned char *addr = p + (size_t) i * page;
        if (((mask >> i) & 1U) != 0) {
            unsigned char value;
            if (!read_byte(addr, &value) || value != pattern(i))
                return 40 + i;
        } else if (!fault_map_err(addr)) {
            return 20 + i;
        }
    }
    return 0;
}

static bool child_layout(unsigned char *p, unsigned mask, int pages)
{
    pid_t child = fork();
    if (child == 0)
        _exit(child_verify(p, mask, pages));
    if (child < 0)
        return false;
    int status;
    return waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0;
}

static bool smaps_dontfork(const void *address, bool expected)
{
    FILE *file = fopen("/proc/self/smaps", "r");
    if (!file)
        return false;
    char line[512];
    bool selected = false, matched = false;
    while (fgets(line, sizeof(line), file)) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2)
            selected =
                (uintptr_t) address >= start && (uintptr_t) address < end;
        else if (selected && !strncmp(line, "VmFlags:", 8)) {
            bool found = false;
            for (char *flag = strtok(line + 8, " \t\n"); flag;
                 flag = strtok(NULL, " \t\n"))
                found |= !strcmp(flag, "dc");
            matched = found == expected;
            break;
        }
    }
    fclose(file);
    return matched;
}

static void test_private_subrange(void)
{
    TEST("private subrange survives mprotect split");

    unsigned char *p = mmap(NULL, 5 * page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    fill_values(p, 5);

    bool ok = madvise(p + page, 3 * page, MADV_DONTFORK) == 0;
    if (ok)
        ok = mprotect(p + page, page, PROT_READ) == 0;
    if (ok)
        ok = child_layout(p, 0x11, 5);
    ok = ok && values_intact(p, 5);
    EXPECT_TRUE(ok,
                "excluded page inherited, parent data changed, or split lost "
                "the flag");

    munmap(p, 5 * page);
}

static void test_shared_backing(void)
{
    TEST("shared file exclusion keeps backing");

    char path[] = "/tmp/elfuse-dontfork-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }
    unlink(path);
    if (ftruncate(fd, (off_t) (5 * page)) != 0 || !seed_file(fd, 5)) {
        FAIL("seed file");
        close(fd);
        return;
    }

    unsigned char *p =
        mmap(NULL, 5 * page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        close(fd);
        return;
    }

    bool ok = values_intact(p, 5);
    if (ok)
        ok = madvise(p + page, 2 * page, MADV_DONTFORK) == 0;
    if (ok)
        ok = child_layout(p, 0x19, 5);
    ok = ok && values_intact(p, 5);
    for (int i = 0; ok && i < 5; i++)
        ok = file_byte(fd, i, pattern(i));

    if (ok) {
        p[page] = 0x99;
        ok = msync(p + page, page, MS_SYNC) == 0 && file_byte(fd, 1, 0x99);
    }
    if (ok)
        ok = file_byte(fd, 2, pattern(2));
    EXPECT_TRUE(ok,
                "excluded shared pages disturbed the backing file or parent "
                "mapping");

    munmap(p, 5 * page);
    close(fd);
}

static void test_dofork_partial(void)
{
    TEST("DOFORK restores partial then full range");

    unsigned char *p = mmap(NULL, 4 * page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    fill_values(p, 4);

    bool ok = madvise(p, 4 * page, MADV_DONTFORK) == 0;
    if (ok)
        ok = smaps_dontfork(p, true);
    if (ok)
        ok = madvise(p + page, 2 * page, MADV_DOFORK) == 0;
    if (ok)
        ok = child_layout(p, 0x6, 4);
    ok = ok && values_intact(p, 4);
    if (ok)
        ok = madvise(p + 3 * page, page, MADV_DOFORK) == 0 &&
             child_layout(p, 0xE, 4);
    if (ok)
        ok = madvise(p, 4 * page, MADV_DOFORK) == 0 && child_layout(p, 0xF, 4);
    if (ok)
        ok = smaps_dontfork(p, false);
    ok = ok && values_intact(p, 4);
    EXPECT_TRUE(ok, "DOFORK restored the wrong subrange");

    munmap(p, 4 * page);
}

static void test_advice_edges(void)
{
    TEST("unaligned and zero-length advice");

    unsigned char *p = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    fill_values(p, 2);

    errno = 0;
    bool ok = madvise(p + 1, page, MADV_DONTFORK) == -1 && errno == EINVAL;
    if (ok)
        ok = madvise(p, 0, MADV_DONTFORK) == 0;
    if (ok)
        ok = child_layout(p, 0x3, 2);
    if (ok)
        ok = madvise(p, page, MADV_DONTFORK) == 0;
    if (ok)
        ok = madvise(p, 0, MADV_DOFORK) == 0;
    if (ok)
        ok = child_layout(p, 0x2, 2);
    ok = ok && values_intact(p, 2);
    EXPECT_TRUE(ok, "unaligned or zero-length advice diverged from Linux");

    munmap(p, 2 * page);
}

static void test_mremap_move(void)
{
    TEST("DONTFORK follows mremap move");

    unsigned char *p = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *target =
        mmap(NULL, 4 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED || target == MAP_FAILED) {
        FAIL("mmap");
        if (p != MAP_FAILED)
            munmap(p, 2 * page);
        if (target != MAP_FAILED)
            munmap(target, 4 * page);
        return;
    }
    fill_values(p, 2);

    bool ok = madvise(p, 2 * page, MADV_DONTFORK) == 0;
    void *moved = MAP_FAILED;
    if (ok)
        moved = mremap(p, 2 * page, 4 * page, MREMAP_MAYMOVE | MREMAP_FIXED,
                       target);
    if (moved != MAP_FAILED) {
        unsigned char *q = moved;
        ok = moved == target;
        if (ok)
            ok = child_layout(q, 0, 4);
        ok = ok && q[0] == pattern(0) && q[page] == pattern(1);
        munmap(moved, 4 * page);
        if (moved != target)
            munmap(target, 4 * page);
    } else {
        ok = false;
        munmap(p, 2 * page);
        munmap(target, 4 * page);
    }
    EXPECT_TRUE(ok, "moved mapping lost exclusion or data");
}

static void test_mremap_grow(void)
{
    TEST("DONTFORK survives mremap in-place growth");

    unsigned char *arena =
        mmap(NULL, 4 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    if (munmap(arena, 4 * page) != 0) {
        FAIL("munmap");
        return;
    }

    unsigned char *p = mmap(arena, 2 * page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p != arena) {
        FAIL("fixed mmap");
        if (p != MAP_FAILED)
            munmap(p, 2 * page);
        return;
    }
    fill_values(p, 2);

    bool ok = madvise(p, 2 * page, MADV_DONTFORK) == 0;
    void *grown = MAP_FAILED;
    if (ok)
        grown = mremap(p, 2 * page, 4 * page, 0);
    if (grown == p) {
        ok = child_layout(p, 0, 4);
        ok = ok && p[0] == pattern(0) && p[page] == pattern(1);
        munmap(p, 4 * page);
    } else {
        ok = false;
        if (grown != MAP_FAILED)
            munmap(grown, 4 * page);
        else
            munmap(p, 2 * page);
    }
    EXPECT_TRUE(ok, "in-place growth dropped exclusion or moved the mapping");
}

static void test_repeated_nested(void)
{
    TEST("exclusion persists across repeated and nested fork");

    unsigned char *p = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    fill_values(p, 2);

    bool ok = madvise(p, page, MADV_DONTFORK) == 0;
    if (ok)
        ok = child_layout(p, 0x2, 2) && child_layout(p, 0x2, 2);
    if (ok) {
        pid_t child = fork();
        if (child == 0)
            _exit(child_layout(p, 0x2, 2) ? 0 : 1);
        int status = 0;
        ok = child > 0 && waitpid(child, &status, 0) == child &&
             WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    ok = ok && values_intact(p, 2);
    EXPECT_TRUE(ok, "a later or nested fork re-inherited the excluded page");

    munmap(p, 2 * page);
}

static void test_remap_fresh(void)
{
    TEST("fresh mapping after munmap is inheritable");

    unsigned char *p = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    fill_values(p, 2);

    bool ok = madvise(p, 2 * page, MADV_DONTFORK) == 0;
    if (munmap(p, 2 * page) != 0)
        ok = false;

    unsigned char *q = MAP_FAILED;
    if (ok)
        q = mmap(p, 2 * page, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (ok)
        ok = q == p;
    if (ok) {
        fill_values(q, 2);
        ok = child_layout(q, 0x3, 2) && values_intact(q, 2);
    }
    if (q != MAP_FAILED)
        munmap(q, 2 * page);
    EXPECT_TRUE(ok, "address reuse inherited stale DONTFORK");
}

static void test_fixed_fresh(void)
{
    TEST("exact fixed replacement clears fork advice");
    unsigned char *p = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    bool ok = madvise(p, 2 * page, MADV_DONTFORK) == 0 &&
              madvise(p, 2 * page, MADV_WIPEONFORK) == 0;
    unsigned char *q = ok ? mmap(p, 2 * page, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)
                          : MAP_FAILED;
    ok = ok && q == p;
    if (ok) {
        fill_values(q, 2);
        ok = child_layout(q, 0x3, 2) && values_intact(q, 2);
    }
    ok = munmap(p, 2 * page) == 0 && ok;
    EXPECT_TRUE(ok, "replacement omitted or wiped fresh child bytes");
}

static int shared_child(void *arg)
{
    unsigned char *p = arg;
    if (*p != pattern(0))
        return 1;
    *p = 0x55;
    return 0;
}

static void test_shared_vm(void)
{
    TEST("CLONE_VM retains DONTFORK mapping");

    unsigned char *p = mmap(NULL, page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED || stack == MAP_FAILED) {
        FAIL("mmap");
        if (p != MAP_FAILED)
            munmap(p, page);
        if (stack != MAP_FAILED)
            munmap(stack, 65536);
        return;
    }
    *p = pattern(0);

    bool ok = madvise(p, page, MADV_DONTFORK) == 0;
    int status = 0;
    pid_t child = -1;
    if (ok)
        child =
            clone(shared_child, (char *) stack + 65536, CLONE_VM | SIGCHLD, p);
    ok = child > 0 && waitpid(child, &status, 0) == child &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 && *p == 0x55;
    EXPECT_TRUE(ok, "shared address space lost the excluded mapping");

    munmap(p, page);
    munmap(stack, 65536);
}

static void test_hole_partial(void)
{
    TEST("hole returns ENOMEM, fragments still updated");

    unsigned char *p = mmap(NULL, 3 * page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    fill_values(p, 3);
    if (munmap(p + page, page) != 0) {
        FAIL("munmap");
        munmap(p, 3 * page);
        return;
    }

    errno = 0;
    int result = madvise(p, 3 * page, MADV_DONTFORK);
    bool ok = result == -1 && errno == ENOMEM;
    if (ok)
        ok = child_layout(p, 0, 3);
    ok = ok && p[0] == pattern(0) && p[2 * page] == pattern(2);
    EXPECT_TRUE(ok, "hole return or partial update differs from Linux");

    munmap(p, page);
    munmap(p + 2 * page, page);
}

static bool wipe_contents(const unsigned char *p, unsigned keep, int pages)
{
    for (int i = 0; i < pages; i++) {
        unsigned char expected = (keep & (1U << i)) ? pattern(i) : 0;
        for (size_t j = 0; j < page; j++) {
            if (p[(size_t) i * page + j] != expected)
                return false;
        }
    }
    return true;
}

static bool wipe_child(unsigned char *p, unsigned keep, int pages, bool nested)
{
    pid_t child = fork();
    if (child == 0) {
        if (!wipe_contents(p, keep, pages))
            _exit(1);
        if (nested) {
            for (int i = 0; i < pages; i++)
                memset(p + (size_t) i * page, pattern(i), page);
            if (!wipe_child(p, keep, pages, false) ||
                !wipe_contents(p, (1U << pages) - 1, pages))
                _exit(2);
        }
        _exit(0);
    }
    int status;
    return child > 0 && waitpid(child, &status, 0) == child &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void test_wipe_subrange(void)
{
    TEST("WIPEONFORK partial KEEPONFORK and nested inheritance");
    unsigned char *p = mmap(NULL, 4 * page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    for (int i = 0; i < 4; i++)
        memset(p + (size_t) i * page, pattern(i), page);
    bool ok = madvise(p + page, 3 * page, MADV_WIPEONFORK) == 0 &&
              madvise(p + 2 * page, page, MADV_KEEPONFORK) == 0 &&
              madvise(p + page, page, MADV_DONTFORK) == 0 &&
              madvise(p + page, page, MADV_DOFORK) == 0 &&
              mprotect(p + page, page, PROT_READ) == 0 &&
              wipe_child(p, 0x5, 4, false) && wipe_contents(p, 0xf, 4) &&
              mprotect(p + page, page, PROT_READ | PROT_WRITE) == 0 &&
              wipe_child(p, 0x5, 4, true) && wipe_child(p, 0x5, 4, false) &&
              wipe_contents(p, 0xf, 4);
    EXPECT_TRUE(ok, "wipe lost across splits/forks or changed parent bytes");
    munmap(p, 4 * page);
}

static void test_wipe_mremap(void)
{
    TEST("WIPEONFORK follows mremap move and growth");
    unsigned char *p = mmap(NULL, page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *target =
        mmap(NULL, 3 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED || target == MAP_FAILED) {
        FAIL("mmap");
        if (p != MAP_FAILED)
            munmap(p, page);
        if (target != MAP_FAILED)
            munmap(target, 3 * page);
        return;
    }
    bool ok = madvise(p, page, MADV_WIPEONFORK) == 0;
    void *moved = MAP_FAILED;
    if (ok)
        moved =
            mremap(p, page, 3 * page, MREMAP_MAYMOVE | MREMAP_FIXED, target);
    if (moved != MAP_FAILED) {
        unsigned char *q = moved;
        for (int i = 0; i < 3; i++)
            memset(q + (size_t) i * page, pattern(i), page);
        ok = moved == target && wipe_child(q, 0, 3, true) &&
             wipe_contents(q, 7, 3);
        munmap(q, 3 * page);
    } else {
        ok = false;
        munmap(p, page);
        munmap(target, 3 * page);
    }
    EXPECT_TRUE(ok, "mremap lost wipe inheritance");
}

static void test_wipe_shared_vm(void)
{
    TEST("CLONE_VM retains WIPEONFORK bytes");
    unsigned char *p = mmap(NULL, page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED || stack == MAP_FAILED) {
        FAIL("mmap");
        if (p != MAP_FAILED)
            munmap(p, page);
        if (stack != MAP_FAILED)
            munmap(stack, 65536);
        return;
    }
    *p = pattern(0);
    bool ok = madvise(p, page, MADV_WIPEONFORK) == 0;
    pid_t child = -1;
    if (ok)
        child =
            clone(shared_child, (char *) stack + 65536, CLONE_VM | SIGCHLD, p);
    int status;
    ok = child > 0 && waitpid(child, &status, 0) == child &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 && *p == 0x55;
    EXPECT_TRUE(ok, "CLONE_VM incorrectly wiped shared address space");
    munmap(p, page);
    munmap(stack, 65536);
}

static void test_wipe_invalid(void)
{
    TEST("WIPEONFORK rejects shared/file mappings and reports holes");
    FILE *file = tmpfile();
    if (!file || ftruncate(fileno(file), (off_t) page) != 0) {
        FAIL("tmpfile");
        if (file)
            fclose(file);
        return;
    }
    unsigned char *p = mmap(NULL, 3 * page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *shared = mmap(NULL, page, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    void *backed =
        mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(file), 0);
    bool ok = p != MAP_FAILED && shared != MAP_FAILED && backed != MAP_FAILED;
    if (ok) {
        errno = 0;
        ok = madvise(shared, page, MADV_WIPEONFORK) == -1 && errno == EINVAL;
        errno = 0;
        ok = ok && madvise(backed, page, MADV_WIPEONFORK) == -1 &&
             errno == EINVAL;
        ok = ok && madvise(shared, page, MADV_KEEPONFORK) == 0 &&
             madvise(backed, page, MADV_KEEPONFORK) == 0;
        memset(p, pattern(0), page);
        memset(p + 2 * page, pattern(2), page);
        ok = ok && munmap(p + page, page) == 0;
        errno = 0;
        ok = ok && madvise(p, 3 * page, MADV_WIPEONFORK) == -1 &&
             errno == ENOMEM;
        pid_t child = ok ? fork() : -1;
        if (child == 0)
            _exit(wipe_contents(p, 0, 1) && wipe_contents(p + 2 * page, 0, 1)
                      ? 0
                      : 1);
        int status;
        ok = child > 0 && waitpid(child, &status, 0) == child &&
             WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
             p[0] == pattern(0) && p[2 * page] == pattern(2);
    }
    EXPECT_TRUE(ok,
                "mapping validation or partial hole update differs from Linux");
    if (p != MAP_FAILED)
        munmap(p, 3 * page);
    if (shared != MAP_FAILED)
        munmap(shared, page);
    if (backed != MAP_FAILED)
        munmap(backed, page);
    fclose(file);
}

int main(void)
{
    page = (size_t) sysconf(_SC_PAGESIZE);
    test_private_subrange();
    test_shared_backing();
    test_dofork_partial();
    test_advice_edges();
    test_mremap_move();
    test_mremap_grow();
    test_repeated_nested();
    test_remap_fresh();
    test_fixed_fresh();
    test_shared_vm();
    test_hole_partial();
    test_wipe_subrange();
    test_wipe_mremap();
    test_wipe_shared_vm();
    test_wipe_invalid();
    SUMMARY("test-madvise-fork");
    return fails != 0;
}
