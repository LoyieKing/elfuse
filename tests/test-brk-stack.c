/*
 * brk growth must stop at its neighbors
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The heap is premapped to the mmap RX region and a grow re-maps what it
 * crosses, with the heap at 16 MiB and the stack at [120 MiB, 128 MiB). sys_brk
 * used to accept any break below guest_size, so nothing faulted on the way to
 * stop it: a grow extended page tables over whatever sat above the heap and
 * zeroed it. The symptom is a SIGSEGV or a libc "free(): invalid pointer" abort
 * in whatever ran next, well away from the allocation that caused it (issue
 * #320).
 *
 * Four neighbor shapes are covered: a mapping in the gap above the heap, one
 * starting exactly on the break, a heap chunk the guest mremapped above it, and
 * the heap grown in place across it. The last two keep the "[heap]" name. Then
 * the stack: g->stack_base is where a grow stops there, and it is the same
 * address the "[stack-guard]" record starts at, so a last check unmaps that
 * record to show the bound is the address and not the record. Linux refuses a
 * break that would run into the next mapping, so every check below passes on a
 * real kernel too.
 *
 * Calls brk(2) directly rather than through sbrk(3): musl's sbrk answers ENOMEM
 * for any non-zero increment without issuing the syscall, which would make this
 * pass without testing anything.
 *
 * Syscalls exercised: brk(214), mmap(222), mremap(216)
 */

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;
static int skips;

#define CANARY_BYTE 0x5a
#define GROW_STEP (1u << 20)

/* Past the 128 MiB elfuse stack top, measured from wherever the break starts.
 */
#define GROW_TOTAL (192u << 20)

/* Keep a buffer the optimizer cannot reason about. Without this, gcc at the -O2
 * these tests build with folds every check below into its constant and drops
 * the allocation, so the check passes having tested nothing.
 */
#define KEEP(p) __asm__ volatile("" ::"r"(p) : "memory")

/* Give up on a check, restoring what it had already changed. A rollback that
 * fails is a failure, not a skip: the checks after it would run against state
 * this one left behind.
 */
static void give_up(const char *name, const char *why, int restored)
{
    printf("  %-30s SKIP (%s)\n", name, why);
    skips++;
    if (!restored) {
        TEST("rollback after a skip");
        FAIL("a skipped check left the heap or a mapping behind");
    }
}

/* A check that could not build its shape. Only one of these is ever expected,
 * and only on a real kernel: there is no "[stack-guard]" line to unmap there.
 * Every other way a shape fails to build means something the check relies on
 * stopped working, and the runner matches on "0 failed", so a skip would retire
 * the check without saying so. Fail instead.
 */
static void cannot_build(const char *name, const char *why, int restored)
{
    TEST(name);
    FAIL(why);
    if (!restored) {
        TEST("rollback after a failure");
        FAIL("the check left the heap or a mapping behind");
    }
}

static unsigned long guest_brk(unsigned long addr)
{
    return (unsigned long) syscall(SYS_brk, addr);
}

/* Grow the break one step at a time, touching each step the kernel actually
 * grants. brk(2) reports refusal by returning a break below the request.
 * Returns how far the break moved and stores where it ended up.
 */
static size_t grow_break(unsigned long *final_brk)
{
    unsigned long start = guest_brk(0), cur = start;

    while (cur - start < GROW_TOTAL) {
        unsigned long want = cur + GROW_STEP;
        unsigned long got = guest_brk(want);
        if (got < want)
            break;
        /* Touch both ends: a break the kernel granted must be writable. */
        volatile unsigned char *b = (volatile unsigned char *) cur;
        b[0] = 0xa5;
        b[GROW_STEP - 1] = 0xa5;
        cur = got;
    }

    *final_brk = cur;
    return cur - start;
}

/* Where the stack region begins, or 0 if /proc/self/maps names no stack.
 *
 * elfuse publishes a "[stack-guard]" page below "[stack]" and that guard page
 * is the boundary the break must respect, so prefer it where it exists. Linux
 * has only "[stack]", one page further up, which is why the fallback is not an
 * error. Plain strstr would not tell them apart: "[stack]" is a prefix of
 * "[stack-guard]".
 */
static unsigned long stack_map_start(void)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return 0;

    char line[512];
    unsigned long stack = 0, guard = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "[stack-guard]")) {
            guard = strtoul(line, NULL, 16);
            continue;
        }
        const char *tag = strstr(line, "[stack]");
        if (tag && (tag[7] == '\n' || tag[7] == '\0'))
            stack = strtoul(line, NULL, 16);
    }
    fclose(f);
    return guard ? guard : stack;
}

/* A mapping above the heap is a neighbor the break has to stop at, the same way
 * the stack is. Placed by hint rather than MAP_FIXED so a kernel that already
 * has something there is skipped instead of overwritten.
 *
 * With adjacent set, the break is first raised to meet the mapping, so the
 * mapping starts exactly on it. That is the boundary a limit computed from "the
 * first region starting strictly above the break" gets wrong.
 */
static void test_neighbor(const char *name, int adjacent)
{
    unsigned long len = 2u << 20;
    unsigned long hint = (guest_brk(0) + 2 * len) & ~(len - 1);

    if (adjacent && guest_brk(hint) != hint) {
        cannot_build(name, "break would not reach the mapping", 1);
        return;
    }

    unsigned char *p = mmap((void *) hint, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED || (unsigned long) p != hint) {
        int restored = p == MAP_FAILED || munmap(p, len) == 0;
        cannot_build(name, "hint not honored", restored);
        return;
    }
    memset(p, 0x77, len);

    TEST(name);
    unsigned long got = guest_brk(hint + len);
    int intact = p[0] == 0x77 && p[len - 1] == 0x77;
    EXPECT_TRUE(got <= hint && intact, "brk grew over a neighboring mapping");

    /* Same reason the straddler is put back: a neighbor left in place blocks
     * the growth the later checks depend on.
     */
    TEST("neighbor unmaps");
    EXPECT_EQ(munmap(p, len), 0, "neighbor left mapped above the break");
}

/* Extent of the "[stack-guard]" line.
 *
 * Returns 0 where there is none, which is every real kernel, and doubles as the
 * marker that tells elfuse from Linux. The length comes from the line rather
 * than a constant, so a wider guard is unmapped whole instead of split, which
 * would leave the check passing while testing nothing.
 */
static unsigned long guard_map_start(unsigned long *len)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return 0;

    char line[512];
    unsigned long start = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, "[stack-guard]"))
            continue;
        char *dash = NULL;
        start = strtoul(line, &dash, 16);
        if (len)
            *len = (*dash == '-') ? strtoul(dash + 1, NULL, 16) - start : 0;
        break;
    }
    fclose(f);
    return start;
}

/* g->stack_base and the "[stack-guard]" record name the same address, so every
 * check above passes whichever of the two is doing the work. Unmapping the
 * record settles it: the grow must still be refused with nothing in the table
 * to refuse it.
 */
static void test_stack_floor(void)
{
    const char *name = "floor holds without the record";
    unsigned long len = 0, guard = guard_map_start(&len);

    if (!guard || !len) {
        give_up(name, "no [stack-guard] line", 1);
        return;
    }
    TEST("stack guard unmaps");
    EXPECT_EQ(munmap((void *) guard, len), 0, "guard would not unmap");

    TEST(name);
    EXPECT_TRUE(guest_brk(guard + len - 1) <= guard,
                "brk grew into the stack guard once its record was gone");
}

/* The heap grown in place past the break, which leaves a record straddling it
 * that is still named "[heap]" on elfuse. A limit that exempts that name grows
 * straight through the guest's own live mapping.
 */
static void test_straddling_heap(void)
{
    const char *name = "break stops at a straddler";
    unsigned long len = 64u << 10, grown = 1u << 20;
    unsigned long src = guest_brk(0), base = src + len;

    if (guest_brk(base) != base) {
        cannot_build(name, "break would not grow", 1);
        return;
    }

    unsigned char *p = mremap((void *) src, len, grown, 0);
    if (p == MAP_FAILED || (unsigned long) p != src) {
        cannot_build(name, "in-place mremap declined", guest_brk(src) <= src);
        return;
    }
    memset(p, 0x77, grown);

    TEST(name);
    unsigned long got = guest_brk(src + grown + (2u << 20));
    size_t bad = 0;
    for (unsigned long i = 0; i < grown; i++) {
        if (p[i] != 0x77)
            bad++;
    }
    EXPECT_TRUE(got <= base && bad == 0, "brk grew over the straddling heap");

    /* Shrink it back so the checks below start from an ordinary heap. A failure
     * here would leave the break blocked where it stands, and every later check
     * would then pass by never reaching what it is aimed at.
     */
    TEST("straddler shrinks back");
    EXPECT_TRUE(mremap(p, grown, len, 0) == p,
                "heap left grown past the break");
}

/* A heap chunk the guest moved above the break is a neighbor too. mremap keeps
 * the source region's name, so on elfuse it is still called "[heap]", and a
 * limit that skips that name by itself grows straight through it.
 */
static void test_moved_heap_neighbor(void)
{
    const char *name = "break stops at a moved chunk";
    unsigned long len = 64u << 10;
    unsigned long src = guest_brk(0);

    if (guest_brk(src + 2 * len) != src + 2 * len) {
        cannot_build(name, "break would not grow", 1);
        return;
    }

    unsigned long dest = (src + (4u << 20)) & ~(unsigned long) ((2u << 20) - 1);
    unsigned char *p = mremap((void *) src, len, len,
                              MREMAP_MAYMOVE | MREMAP_FIXED, (void *) dest);
    if (p == MAP_FAILED || (unsigned long) p != dest) {
        cannot_build(name, "mremap declined the move", guest_brk(src) <= src);
        return;
    }
    memset(p, 0x77, len);

    TEST(name);
    unsigned long got = guest_brk(dest + 2 * len);
    int intact = p[0] == 0x77 && p[len - 1] == 0x77;
    EXPECT_TRUE(got <= dest && intact, "brk grew over a moved heap chunk");

    /* Put it back. Leaving the hole would hand the checks below a heap libc
     * still believes is contiguous, and leaving the chunk above the break would
     * block the growth they measure.
     */
    TEST("moved chunk moves back");
    EXPECT_TRUE(mremap(p, len, len, MREMAP_MAYMOVE | MREMAP_FIXED,
                       (void *) src) == (void *) src,
                "heap chunk left above the break");
}

static void str_trim_copy(char *dst, const char *src, size_t n)
{
    size_t i = 0;
    while (i + 1 < n && src[i] && src[i] != '\n') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

/* Hex at p, stopping at the first character that is not a hex digit. Not
 * strtoul: the child in test_maps_do_not_overlap has unmapped the base of its
 * heap, and glibc's strtoul reaches locale tables that live there.
 */
static unsigned long parse_hex(const char *p, const char **end)
{
    unsigned long v = 0;

    for (;; p++) {
        int c = (unsigned char) *p, d;
        if (c >= '0' && c <= '9')
            d = c - '0';
        else if (c >= 'a' && c <= 'f')
            d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            d = c - 'A' + 10;
        else
            break;
        v = v * 16 + (unsigned long) d;
    }
    if (end)
        *end = p;
    return v;
}

/* Read /proc/self/maps without libc allocation, so a caller that has just
 * unmapped the base of its own heap can still read it.
 */
static ssize_t read_maps(char *buf, size_t n)
{
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0)
        return -1;

    size_t got = 0;
    while (got + 1 < n) {
        ssize_t r = read(fd, buf + got, n - 1 - got);
        if (r <= 0)
            break;
        got += (size_t) r;
    }
    close(fd);
    buf[got] = '\0';
    return (ssize_t) got;
}

/* Count lines in a maps dump that start below the previous line's end. */
static int count_overlaps(const char *maps, char *worst, size_t worst_n)
{
    unsigned long prev_hi = 0;
    int overlaps = 0;

    for (const char *p = maps; *p;) {
        const char *dash = NULL;
        unsigned long lo = parse_hex(p, &dash);
        if (*dash == '-') {
            unsigned long hi = parse_hex(dash + 1, NULL);
            if (lo < prev_hi && !overlaps++ && worst)
                str_trim_copy(worst, p, worst_n);
            if (hi > prev_hi)
                prev_hi = hi;
        }
        const char *nl = strchr(p, '\n');
        if (!nl)
            break;
        p = nl + 1;
    }
    return overlaps;
}

/* Unmap the base of the heap, grow the break past it, and report whether the
 * tracker published an overlap. Runs in a child: the heap base is where libc
 * keeps its first chunk header, so nothing after this can allocate. That is
 * also why it is the one shape no real libc reaches on its own, and why it
 * needs its own process to be reachable at all.
 */
static int base_hole_overlaps(void)
{
    static char maps[64 * 1024];

    if (read_maps(maps, sizeof(maps)) < 0)
        return -1;

    unsigned long heap_start = 0;
    for (const char *p = maps; *p;) {
        const char *nl = strchr(p, '\n');
        const char *tag = strstr(p, "[heap]");
        if (tag && (!nl || tag < nl)) {
            heap_start = parse_hex(p, NULL);
            break;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    if (!heap_start)
        return -1;

    if (munmap((void *) heap_start, 4096) != 0)
        return -1;
    unsigned long want = guest_brk(0) + (4u << 20);
    if (guest_brk(want) < want)
        return -1;
    if (read_maps(maps, sizeof(maps)) < 0)
        return -1;
    return count_overlaps(maps, NULL, 0);
}

/* No two mappings may overlap. Linux never publishes that, and two paths in
 * sys_brk did: a grow widening the piece at the heap base over the pieces above
 * it, and the fallback add inserting a span from the heap base on top of them.
 * Checking it directly catches the whole class, where each of the checks above
 * only catches the symptom it was written for. No two mappings may overlap,
 * right now. Every check has to call this while the shape it built is still
 * standing: the defects here publish their overlap only for as long as the heap
 * is fragmented, and a heap shrunk back to one piece reports clean whether or
 * not it was ever wrong.
 */
static void expect_no_overlap(const char *name)
{
    static char maps[64 * 1024];
    char worst[256] = {0};

    if (read_maps(maps, sizeof(maps)) < 0) {
        cannot_build(name, "no /proc/self/maps", 1);
        return;
    }

    TEST(name);
    int overlaps = count_overlaps(maps, worst, sizeof(worst));
    if (overlaps)
        printf("[%d, first: %s] ", overlaps, worst);
    EXPECT_EQ(overlaps, 0, "/proc/self/maps published overlapping lines");
}

/* A hole in the heap, a grow past it, then a shrink back into it. The grow used
 * to widen the piece at the heap base straight over the pieces above it, and
 * the overlapping records that left could not be trimmed by the shrink; what
 * survived looked like a mapping straddling the break, so every later grow was
 * refused. Linux grows again here, so this check reads the same on both.
 */
static void test_hole_shrink_regrow(void)
{
    const char *name = "heap regrows past a hole";
    unsigned long M = 1u << 20;
    unsigned long base = guest_brk(0);

    /* Grow, punch two holes, grow past them, then shrink back to between the
     * pieces. Every step is checked: any one the kernel declines leaves the
     * shape unbuilt, and the check below would then pass on nothing more than
     * an ordinary grow and shrink. Two holes, because with one there is nothing
     * left above the new break to strand.
     */
    int built = guest_brk(base + 8 * M) == base + 8 * M &&
                munmap((void *) (base + M), 64u << 10) == 0 &&
                munmap((void *) (base + 3 * M), 64u << 10) == 0 &&
                guest_brk(base + 16 * M) == base + 16 * M &&
                guest_brk(base + 9 * M) == base + 9 * M;
    if (!built) {
        cannot_build(name, "heap would not take the shape",
                     guest_brk(base) <= base);
        return;
    }

    TEST(name);
    unsigned long want = base + 13 * M;
    EXPECT_TRUE(guest_brk(want) >= want, "brk refused a grow after a hole");

    expect_no_overlap("no overlap while a hole is live");

    TEST("heap shrinks back");
    EXPECT_TRUE(guest_brk(base) <= base, "heap left grown past its start");
}


static sigjmp_buf fault_jmp;
static volatile sig_atomic_t faulted;

static void fault_handler(int sig)
{
    (void) sig;
    faulted = 1;
    siglongjmp(fault_jmp, 1);
}

/* Does storing to addr fault? The tracker's own account of a mapping is not
 * evidence about it; this is.
 */
static int write_faults(volatile unsigned char *addr)
{
    struct sigaction sa, old_segv, old_bus;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fault_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);

    faulted = 0;
    if (sigsetjmp(fault_jmp, 1) == 0)
        *addr = 0x41;

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);
    return faulted;
}

static void test_maps_do_not_overlap(void)
{
    expect_no_overlap("no overlap on a settled heap");

    /* The one shape that reaches sys_brk's fallback add, in a child because it
     * costs the heap base.
     */
    pid_t pid = fork();
    if (pid < 0) {
        cannot_build("base hole leaves no overlap", "fork failed", 1);
        return;
    }
    if (pid == 0) {
        /* 2 means the child could not build the shape, which is a skip and not
         * a finding. 1 means it built it and saw the overlap.
         */
        int n = base_hole_overlaps();
        _exit(n < 0 ? 2 : (n ? 1 : 0));
    }

    int st = 0;
    if (waitpid(pid, &st, 0) != pid) {
        cannot_build("base hole leaves no overlap", "wait failed", 1);
        return;
    }
    if (WIFEXITED(st) && WEXITSTATUS(st) == 2) {
        cannot_build("base hole leaves no overlap", "child could not build it",
                     1);
        return;
    }

    TEST("base hole leaves no overlap");
    EXPECT_TRUE(WIFEXITED(st) && WEXITSTATUS(st) == 0,
                "a grow after unmapping the heap base published an overlap");
}

/* Permission field of the /proc/self/maps line covering addr, or NULL. */
static const char *map_perms_at(unsigned long addr, char out[8])
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return NULL;

    char line[512];
    const char *found = NULL;
    while (fgets(line, sizeof(line), f)) {
        char *dash = NULL;
        unsigned long lo = strtoul(line, &dash, 16);
        if (*dash != '-')
            continue;
        unsigned long hi = strtoul(dash + 1, &dash, 16);
        if (addr < lo || addr >= hi)
            continue;
        while (*dash == ' ')
            dash++;
        for (int i = 0; i < 4 && dash[i] && dash[i] != ' '; i++)
            out[i] = dash[i];
        out[4] = '\0';
        found = out;
        break;
    }
    fclose(f);
    return found;
}

/* Pages a grow exposes are writable, whatever the piece below them says.
 *
 * The record a grow extends is chosen by where it ends, so a guest that seals
 * the top of its heap with mprotect and then grows had the new pages absorbed
 * into the sealed record. The tracker then disagreed with the page tables, and
 * the next mprotect over those pages took its same-prot fast path and did no
 * work: the seal read as applied while the pages stayed writable.
 */
static void test_grow_past_a_seal(void)
{
    const char *name = "grown pages are writable";
    unsigned long M = 1u << 20;
    unsigned long base = (guest_brk(0) + 0xfff) & ~0xfffUL;

    int built = guest_brk(base + 2 * M) == base + 2 * M &&
                mprotect((void *) (base + M), M, PROT_READ | PROT_EXEC) == 0 &&
                guest_brk(base + 3 * M) == base + 3 * M;
    if (!built) {
        cannot_build(name, "heap would not take the shape",
                     guest_brk(base) <= base);
        return;
    }

    TEST(name);
    char perms[8] = {0};
    const char *got = map_perms_at(base + 2 * M, perms);
    EXPECT_TRUE(got && got[1] == 'w',
                "brk reported the pages it grew as unwritable");

    /* The report is not the guarantee. What the defect cost was a seal that did
     * no page-table work, so seal the grown pages and make the hardware answer.
     * PROT_READ | PROT_EXEC, not PROT_READ: mprotect_same_prot_fast_path_safe
     * refuses read-only outright, so a read-only seal always does the PTE work
     * and would pass with the defect fully present.
     */
    TEST("grown pages take a later seal");
    int took =
        mprotect((void *) (base + 2 * M), M, PROT_READ | PROT_EXEC) == 0 &&
        write_faults((volatile unsigned char *) (base + 2 * M));
    EXPECT_TRUE(took, "a seal over the grown pages left them writable");

    expect_no_overlap("no overlap while a seal is live");

    TEST("seal check cleans up");
    int clean =
        mprotect((void *) (base + 2 * M), M, PROT_READ | PROT_WRITE) == 0 &&
        mprotect((void *) (base + M), M, PROT_READ | PROT_WRITE) == 0 &&
        guest_brk(base) <= base;
    EXPECT_TRUE(clean, "the seal check left the heap sealed or grown");
}

static int guarded_maps_match(unsigned char *base, size_t count)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return 0;
    unsigned long cursor = (unsigned long) base;
    unsigned long limit = cursor + count * 8192;
    char line[512];
    int ok = 1;
    while (cursor < limit && fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        char prot[8];
        if (sscanf(line, "%lx-%lx %7s", &start, &end, prot) != 3 ||
            end <= cursor)
            continue;
        if (start > cursor) {
            ok = 0;
            break;
        }
        unsigned long stop = end < limit ? end : limit;
        for (; cursor < stop; cursor += 4096) {
            int data = ((cursor - (unsigned long) base) / 4096) % 2 == 0;
            if (prot[0] != (data ? 'r' : '-') ||
                prot[1] != (data ? 'w' : '-') || prot[2] != '-')
                ok = 0;
        }
    }
    fclose(f);
    return ok && cursor == limit;
}

static void test_vma_growth(void)
{
    const size_t count = 5000, page = 4096, span = count * 2 * page;
    unsigned char *base =
        mmap(NULL, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST("guarded mappings retain permissions beyond 4096 VMAs");
    if (base == MAP_FAILED) {
        FAIL("cannot reserve guarded mapping");
        return;
    }
    int ok = 1;
    for (size_t i = 0; i < count; i++) {
        if (mprotect(base + i * 2 * page, page, PROT_READ | PROT_WRITE)) {
            ok = 0;
            break;
        }
        *(uint64_t *) (base + i * 2 * page) = i;
    }
    EXPECT_TRUE(ok && guarded_maps_match(base, count),
                "maps lost guarded-page coverage or permissions");
    if (!ok) {
        munmap(base, span);
        return;
    }

    TEST("a late protection split updates hardware and maps");
    unsigned char *late = base + (count - 1) * 2 * page;
    char prot[8];
    ok = mprotect(late, page, PROT_READ | PROT_EXEC) == 0;
    const char *got = map_perms_at((unsigned long) late, prot);
    EXPECT_TRUE(ok && got && got[0] == 'r' && got[1] == '-' && got[2] == 'x' &&
                    write_faults(late),
                "late seal was lost by the region tracker or PTEs");
    ok = mprotect(late, page, PROT_READ | PROT_WRITE) == 0;

    TEST("fork preserves a large guarded VMA table and private data");
    pid_t pid = ok ? fork() : -1;
    if (pid == 0) {
        int valid = guarded_maps_match(base, count);
        for (size_t i = 0; i < count; i++) {
            if (*(uint64_t *) (base + i * 2 * page) != i)
                valid = 0;
        }
        *(uint64_t *) late = 0xfeed;
        _exit(valid ? 0 : 1);
    }
    int status = 0;
    ok = pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0 && *(uint64_t *) late == count - 1;
    EXPECT_TRUE(ok, "fork truncated the VMA table or shared private bytes");

    TEST("fixed replacement preserves neighboring guarded pages");
    unsigned char *replaced = base + (count - 2) * 2 * page;
    void *p = mmap(replaced, page, PROT_READ | PROT_WRITE,
                   MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    EXPECT_TRUE(p == replaced && *(uint64_t *) replaced == 0 &&
                    *(uint64_t *) late == count - 1 &&
                    guarded_maps_match(base, count),
                "fixed replacement lost metadata or neighboring data");

    TEST("interior unmap retains both sides after VMA growth");
    unsigned char *island = mmap(NULL, 3 * page, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ok = island != MAP_FAILED;
    if (ok) {
        island[0] = 0x12;
        island[2 * page] = 0x34;
        ok = munmap(island + page, page) == 0 && island[0] == 0x12 &&
             island[2 * page] == 0x34 && write_faults(island + page);
        got = map_perms_at((unsigned long) island + 2 * page, prot);
        ok = ok && got && got[1] == 'w';
        munmap(island, 3 * page);
    }
    EXPECT_TRUE(ok, "interior unmap dropped a live tail or exposed the hole");
    TEST("guarded VMA cleanup");
    EXPECT_EQ(munmap(base, span), 0, "guarded mapping cleanup failed");
}

/* A fixed replacement is one remove range, so these are the single-interval
 * cases of the removal count: the endpoint forms below decide how many records
 * survive and how large the rollback snapshot has to be. The islands stay small
 * and are reserved at runtime; the 5000-VMA shape above is already the
 * expensive part of this binary.
 */
#define REPLACE_PAGE 4096u

/* On Apple Silicon the host page is 16 KiB. A replacement that is not aligned
 * to it takes the pread copy path instead of the file-overlay path, so align
 * the islands and use 16 KiB replacement ranges where the overlay is under
 * test. On a 4 KiB host the same alignment is merely stronger.
 */
#define REPLACE_ALIGN (16u * 1024)

/* One mapping at a runtime-chosen address, aligned so the fixed replacements
 * below can reach the file-overlay path. The prefix and tail of the reservation
 * are unmapped, so the kept range is one record.
 */
static unsigned char *replacement_island(size_t pages)
{
    size_t len = pages * REPLACE_PAGE;
    unsigned char *raw = mmap(NULL, len + REPLACE_ALIGN, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED)
        return MAP_FAILED;

    unsigned char *base =
        (unsigned char *) (((uintptr_t) raw + REPLACE_ALIGN - 1) &
                           ~(uintptr_t) (REPLACE_ALIGN - 1));
    size_t prefix = (size_t) (base - raw);
    size_t tail = (size_t) (raw + len + REPLACE_ALIGN - (base + len));
    if ((prefix && munmap(raw, prefix) != 0) ||
        (tail && munmap(base + len, tail) != 0)) {
        munmap(base, len);
        return MAP_FAILED;
    }
    return base;
}

/* Per-page marker. A boundary that moves by even one page is visible. */
static void marker_fill(unsigned char *p, size_t pages, unsigned char seed)
{
    for (size_t i = 0; i < pages; i++)
        memset(p + i * REPLACE_PAGE, (unsigned char) (seed + i), REPLACE_PAGE);
}

static int marker_holds(const unsigned char *p,
                        size_t pages,
                        unsigned char seed)
{
    for (size_t i = 0; i < pages; i++) {
        unsigned char want = (unsigned char) (seed + i);
        for (size_t j = 0; j < REPLACE_PAGE; j++) {
            if (p[i * REPLACE_PAGE + j] != want)
                return 0;
        }
    }
    return 1;
}

static int bytes_hold(const unsigned char *p, size_t n, unsigned char want)
{
    for (size_t i = 0; i < n; i++) {
        if (p[i] != want)
            return 0;
    }
    return 1;
}

static int map_prot_is(unsigned long addr, char r, char w, char x)
{
    char perms[8];
    const char *got = map_perms_at(addr, perms);
    return got && got[0] == r && got[1] == w && got[2] == x;
}

/* The replacement is strictly inside one record: the tracker has to split at
 * both endpoints, and the snapshot it keeps for rollback covers one record, not
 * the three pieces the two splits create. Both survivors are older bytes.
 */
static void test_fixed_inside_mapping(void)
{
    const size_t pages = 8;
    unsigned char *base = replacement_island(pages);
    TEST("fixed replacement keeps both sides of one mapping");
    if (base == MAP_FAILED) {
        FAIL("cannot reserve replacement island");
        return;
    }

    marker_fill(base, pages, 0x31);
    unsigned char *mid = base + 3 * REPLACE_PAGE;
    void *got = mmap(mid, 2 * REPLACE_PAGE, PROT_READ | PROT_WRITE,
                     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int ok = got == mid && bytes_hold(mid, 2 * REPLACE_PAGE, 0);
    if (ok) {
        memset(mid, 0x7c, REPLACE_PAGE);
        ok = bytes_hold(mid, REPLACE_PAGE, 0x7c) &&
             bytes_hold(mid + REPLACE_PAGE, REPLACE_PAGE, 0);
    }
    ok = ok && marker_holds(base, 3, 0x31) &&
         marker_holds(base + 5 * REPLACE_PAGE, 3, 0x36) &&
         map_prot_is((unsigned long) base, 'r', 'w', '-') &&
         map_prot_is((unsigned long) mid, 'r', 'w', '-') &&
         map_prot_is((unsigned long) base + 7 * REPLACE_PAGE, 'r', 'w', '-');
    int clean = munmap(base, pages * REPLACE_PAGE) == 0;
    EXPECT_TRUE(ok && clean, "replacement lost a side or its bytes");
}

/* The range starts inside one record and ends inside another with different
 * protection. The snapshots must cover both, and the surviving right half must
 * stay executable/read-only rather than inherit the replacement's RW.
 */
static void test_fixed_across_protections(void)
{
    const size_t pages = 8;
    unsigned char *base = replacement_island(pages);
    TEST("fixed replacement spans differently protected records");
    if (base == MAP_FAILED) {
        FAIL("cannot reserve replacement island");
        return;
    }

    marker_fill(base, pages, 0x41);
    unsigned char *mid = base + 2 * REPLACE_PAGE;
    int ok = mprotect(base + 4 * REPLACE_PAGE, 4 * REPLACE_PAGE,
                      PROT_READ | PROT_EXEC) == 0;
    void *got = ok ? mmap(mid, 4 * REPLACE_PAGE, PROT_READ | PROT_WRITE,
                          MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
                   : MAP_FAILED;
    ok = ok && got == mid && bytes_hold(mid, 4 * REPLACE_PAGE, 0) &&
         marker_holds(base, 2, 0x41) &&
         marker_holds(base + 6 * REPLACE_PAGE, 2, 0x47) &&
         map_prot_is((unsigned long) base, 'r', 'w', '-') &&
         map_prot_is((unsigned long) mid, 'r', 'w', '-') &&
         map_prot_is((unsigned long) base + 6 * REPLACE_PAGE, 'r', '-', 'x') &&
         write_faults(base + 7 * REPLACE_PAGE);
    int clean = munmap(base, pages * REPLACE_PAGE) == 0;
    EXPECT_TRUE(ok && clean, "a protected survivor was trimmed or rewritable");
}

/* No overlap at all: the snapshot bound has nothing to capture and the removal
 * has nothing to remove. Neighbors on both sides of the hole must be intact.
 */
static void test_fixed_into_hole(void)
{
    const size_t pages = 8;
    unsigned char *base = replacement_island(pages);
    TEST("fixed replacement fills a hole between neighbors");
    if (base == MAP_FAILED) {
        FAIL("cannot reserve replacement island");
        return;
    }

    marker_fill(base, pages, 0x51);
    unsigned char *hole = base + 3 * REPLACE_PAGE;
    int ok = munmap(hole, 2 * REPLACE_PAGE) == 0 && write_faults(hole);
    void *got = ok ? mmap(hole, 2 * REPLACE_PAGE, PROT_READ | PROT_WRITE,
                          MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
                   : MAP_FAILED;
    ok = ok && got == hole && bytes_hold(hole, 2 * REPLACE_PAGE, 0) &&
         marker_holds(base, 3, 0x51) &&
         marker_holds(base + 5 * REPLACE_PAGE, 3, 0x56) &&
         map_prot_is((unsigned long) base, 'r', 'w', '-') &&
         map_prot_is((unsigned long) base + 7 * REPLACE_PAGE, 'r', 'w', '-');
    int clean = munmap(base, pages * REPLACE_PAGE) == 0;
    EXPECT_TRUE(ok && clean, "a hole replacement moved a neighbor boundary");
}

/* Endpoints land exactly on record boundaries on both sides. Nothing beyond the
 * replaced record may be removed or renamed, even though no split is needed to
 * express the range.
 */
static void test_fixed_exact_record(void)
{
    const size_t pages = 8;
    unsigned char *base = replacement_island(pages);
    TEST("fixed replacement of one whole record keeps its neighbors");
    if (base == MAP_FAILED) {
        FAIL("cannot reserve replacement island");
        return;
    }

    marker_fill(base, pages, 0x61);
    unsigned char *record = base + 2 * REPLACE_PAGE;
    int ok = mprotect(record, 2 * REPLACE_PAGE, PROT_READ) == 0 &&
             write_faults(record) &&
             map_prot_is((unsigned long) record, 'r', '-', '-');
    void *got = ok ? mmap(record, 2 * REPLACE_PAGE, PROT_READ | PROT_WRITE,
                          MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
                   : MAP_FAILED;
    ok = ok && got == record && bytes_hold(record, 2 * REPLACE_PAGE, 0) &&
         marker_holds(base, 2, 0x61) &&
         marker_holds(base + 4 * REPLACE_PAGE, 4, 0x65) &&
         map_prot_is((unsigned long) record, 'r', 'w', '-') &&
         map_prot_is((unsigned long) base, 'r', 'w', '-') &&
         map_prot_is((unsigned long) base + 7 * REPLACE_PAGE, 'r', 'w', '-');
    int clean = munmap(base, pages * REPLACE_PAGE) == 0;
    EXPECT_TRUE(ok && clean, "an exact-boundary replacement ate a neighbor");
}

/* A fixed replacement that fails after the old record was removed must put the
 * bytes, the protection, and the maps entry back. mmap of /dev/null fails with
 * ENODEV on real Linux and on the host, after the tracker has already removed
 * the replaced record, so it exercises the restore path rather than an early
 * argument check.
 */
static void test_fixed_failure_rollback(void)
{
    const size_t pages = 12;
    unsigned char *base = replacement_island(pages);
    TEST("failed fixed replacement restores the replaced record");
    if (base == MAP_FAILED) {
        FAIL("cannot reserve replacement island");
        return;
    }

    marker_fill(base, pages, 0xa1);
    unsigned char *record = base + 4 * REPLACE_PAGE;
    int fd = open("/dev/null", O_RDWR);
    int ok = fd >= 0 &&
             mprotect(record, 4 * REPLACE_PAGE, PROT_READ | PROT_EXEC) == 0 &&
             write_faults(record) &&
             map_prot_is((unsigned long) record, 'r', '-', 'x');
    errno = 0;
    void *got = ok ? mmap(record, 4 * REPLACE_PAGE, PROT_READ | PROT_WRITE,
                          MAP_FIXED | MAP_SHARED, fd, 0)
                   : MAP_FAILED;
    int failed = ok && got == MAP_FAILED && errno == ENODEV;
    ok = failed && marker_holds(base, pages, 0xa1) &&
         map_prot_is((unsigned long) record, 'r', '-', 'x') &&
         map_prot_is((unsigned long) base, 'r', 'w', '-') &&
         map_prot_is((unsigned long) base + 11 * REPLACE_PAGE, 'r', 'w', '-') &&
         write_faults(record);
    if (fd >= 0)
        close(fd);
    int clean = munmap(base, pages * REPLACE_PAGE) == 0;
    EXPECT_TRUE(ok && clean, "failed replacement changed bytes or permissions");
}

/* The failed range is interior to one record, so the rollback has to rejoin two
 * RX survivors around it rather than leave a hole or an RW strip.
 */
static void test_fixed_failure_inside(void)
{
    const size_t pages = 12;
    unsigned char *base = replacement_island(pages);
    TEST("failed replacement inside a record restores both sides");
    if (base == MAP_FAILED) {
        FAIL("cannot reserve replacement island");
        return;
    }

    marker_fill(base, pages, 0xb1);
    unsigned char *record = base + 4 * REPLACE_PAGE;
    int fd = open("/dev/null", O_RDWR);
    int ok = fd >= 0 &&
             mprotect(base, pages * REPLACE_PAGE, PROT_READ | PROT_EXEC) == 0 &&
             write_faults(record);
    errno = 0;
    void *got = ok ? mmap(record, 4 * REPLACE_PAGE, PROT_READ | PROT_WRITE,
                          MAP_FIXED | MAP_SHARED, fd, 0)
                   : MAP_FAILED;
    int failed = ok && got == MAP_FAILED && errno == ENODEV;
    ok = failed && marker_holds(base, pages, 0xb1) &&
         map_prot_is((unsigned long) base, 'r', '-', 'x') &&
         map_prot_is((unsigned long) record, 'r', '-', 'x') &&
         map_prot_is((unsigned long) base + 11 * REPLACE_PAGE, 'r', '-', 'x') &&
         write_faults(record);
    if (fd >= 0)
        close(fd);
    int clean = munmap(base, pages * REPLACE_PAGE) == 0;
    EXPECT_TRUE(ok && clean, "failed interior replacement lost a side");
}

/* A failing replacement into an unmapped range installs nothing: the hole stays
 * a hole and neither neighbor's bytes or permissions move.
 */
static void test_fixed_failure_in_hole(void)
{
    const size_t pages = 12;
    unsigned char *base = replacement_island(pages);
    TEST("failed replacement in a hole leaves it unmapped");
    if (base == MAP_FAILED) {
        FAIL("cannot reserve replacement island");
        return;
    }

    marker_fill(base, pages, 0xc1);
    unsigned char *hole = base + 4 * REPLACE_PAGE;
    int fd = open("/dev/null", O_RDWR);
    int ok =
        fd >= 0 && munmap(hole, 4 * REPLACE_PAGE) == 0 && write_faults(hole);
    errno = 0;
    void *got = ok ? mmap(hole, 4 * REPLACE_PAGE, PROT_READ | PROT_WRITE,
                          MAP_FIXED | MAP_SHARED, fd, 0)
                   : MAP_FAILED;
    int failed = ok && got == MAP_FAILED && errno == ENODEV;
    ok = failed && write_faults(hole) && marker_holds(base, 4, 0xc1) &&
         marker_holds(base + 8 * REPLACE_PAGE, 4, 0xc9) &&
         map_prot_is((unsigned long) base, 'r', 'w', '-') &&
         map_prot_is((unsigned long) base + 11 * REPLACE_PAGE, 'r', 'w', '-');
    if (fd >= 0)
        close(fd);
    int clean = munmap(base, pages * REPLACE_PAGE) == 0;
    EXPECT_TRUE(ok && clean, "failed hole replacement moved a boundary");
}

static void test_fixed_replacement(void)
{
    test_fixed_inside_mapping();
    test_fixed_across_protections();
    test_fixed_into_hole();
    test_fixed_exact_record();
    test_fixed_failure_rollback();
    test_fixed_failure_inside();
    test_fixed_failure_in_hole();
}

int main(void)
{
    printf("brk neighbor tests\n\n");

    test_straddling_heap();
    test_neighbor("break stops at a gap neighbor", 0);
    test_neighbor("break stops at an adjacent neighbor", 1);
    test_moved_heap_neighbor();
    test_hole_shrink_regrow();
    test_grow_past_a_seal();
    test_maps_do_not_overlap();
    test_vma_growth();
    test_fixed_replacement();

    /* A local array is the cheapest witness that main's own frame survived the
     * growth: sys_brk zeroed it in place when it overran. The barrier is what
     * makes it a witness at all. Nothing else in this function can alias the
     * array, so at the -O2 these tests build with, gcc folds the comparison
     * below to zero and allocates no frame for it: measured, no 0x5a and no
     * stack adjustment in main until the barrier went in.
     */
    unsigned char canary[8192];
    memset(canary, CANARY_BYTE, sizeof(canary));
    KEEP(canary);

    unsigned long final_brk = 0;
    size_t grown = grow_break(&final_brk);

    TEST("brk grows at all");
    EXPECT_TRUE(grown > 0, "the break never moved, nothing was tested");

    TEST("stack survives brk growth");
    size_t bad = 0;
    for (size_t i = 0; i < sizeof(canary); i++) {
        if (canary[i] != CANARY_BYTE)
            bad++;
    }
    EXPECT_EQ(bad, 0, "stack clobbered by brk");

    TEST("break stops below the stack mapping");
    unsigned long stack_start = stack_map_start();
    EXPECT_TRUE(stack_start != 0 && final_brk < stack_start,
                "no stack line in /proc/self/maps, or the break ran into it");

    /* Whether the break stopped short or ran the whole way, allocation has to
     * keep working afterwards: libc falls back to mmap once brk refuses.
     */
    TEST("malloc works past the break limit");

    /* 1 MiB, which is above glibc's 128 KiB mmap threshold and so still proves
     * the fallback. The 64 MiB this used to allocate spent 22 ms of a 216 ms
     * test memsetting pages to read three bytes back.
     */
    size_t big = 1u << 20;
    unsigned char *p = malloc(big);
    if (!p) {
        FAIL("malloc after brk limit");
    } else {
        memset(p, 0x3c, big);
        KEEP(p);
        int ok = p[0] == 0x3c && p[big / 2] == 0x3c && p[big - 1] == 0x3c;
        free(p);
        EXPECT_TRUE(ok, "large allocation did not hold its contents");
    }

    /* Last, because it unmaps the guard page for good. */
    test_stack_floor();

    printf("\n  brk moved %zu MiB, ended at 0x%lx, %d skipped\n", grown >> 20,
           final_brk, skips);

    SUMMARY("test-brk-stack");
    return fails ? 1 : 0;
}
