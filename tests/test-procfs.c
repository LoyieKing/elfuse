/*
 * /proc/self/* completeness tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests:
 *   1. /proc/self/auxv returns valid auxv with AT_PAGESZ=4096
 *   2. /proc/self/environ contains at least one entry
 *   3. /proc/self/cmdline is non-empty
 *   4. /proc/self/maps contains [heap] and [stack], every offset is
 *      page-aligned, the lines add up to VmSize, and [vdso] is listed
 *   5. /proc/self/status contains correct PID
 *
 * Syscalls: openat(56), read(63), close(57), getpid(172)
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "test-harness.h"
#include "test-util.h"

int passes = 0, fails = 0;

#define AT_NULL 0
#define AT_PAGESZ 6

static bool parse_proc_stat_field_u64(const char *buf,
                                      int target,
                                      uint64_t *out)
{
    if (target < 4)
        return false;

    const char *p = strrchr(buf, ')');
    if (!p)
        return false;
    p++;

    int field = 3;
    while (*p == ' ')
        p++;
    while (*p != '\0' && field <= target) {
        char *endp;
        if (field == 3) {
            if (*p == '\0' || p[1] != ' ')
                return false;
            endp = (char *) p + 1;
        } else {
            unsigned long long val = strtoull(p, &endp, 10);
            if (endp == p)
                return false;
            if (field == target) {
                *out = (uint64_t) val;
                return true;
            }
        }
        p = endp;
        while (*p == ' ')
            p++;
        field++;
    }
    return false;
}

/* Walk the maps text in @buf: add each line's size to @total, leaving out the
 * elfuse runtime records ([shim], [shim-data]) a Linux process does not have,
 * and report whether every file offset is page-aligned.
 */
static bool maps_walk(char *buf, uint64_t *total)
{
    bool aligned = true;
    *total = 0;
    for (char *line = buf; *line;) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        char *p;
        uint64_t lo = strtoull(line, &p, 16);
        if (*p == '-') {
            uint64_t hi = strtoull(p + 1, &p, 16);
            uint64_t off = strtoull(p + 6, NULL, 16); /* past " rwxp " */
            if (!strstr(line, "[shim"))
                *total += hi - lo;
            aligned &= (off & 0xfff) == 0;
        }
        if (!nl)
            break;
        *nl = '\n';
        line = nl + 1;
    }
    return aligned;
}

static bool parse_stack_range(const char *buf, uint64_t *start, uint64_t *end)
{
    const char *line = buf;
    while ((line = strstr(line, "[stack]")) != NULL) {
        const char *begin = line;
        while (begin > buf && begin[-1] != '\n')
            begin--;

        unsigned long long lo, hi;
        if (sscanf(begin, "%llx-%llx", &lo, &hi) == 2) {
            *start = (uint64_t) lo;
            *end = (uint64_t) hi;
            return true;
        }
        line += 7;
    }
    return false;
}

static bool read_stack_range(uint64_t *start, uint64_t *end)
{
    char mapsbuf[65536];
    ssize_t maps_n =
        raw_read_file_nul("/proc/self/maps", mapsbuf, sizeof(mapsbuf));
    return maps_n > 0 && parse_stack_range(mapsbuf, start, end);
}

static bool read_stat_field(const char *path, int field, uint64_t *value)
{
    char statbuf[1024];
    ssize_t stat_n = raw_read_file_nul(path, statbuf, sizeof(statbuf));
    return stat_n > 0 && parse_proc_stat_field_u64(statbuf, field, value);
}

static bool read_start_stack(const char *path, uint64_t *start_stack)
{
    return read_stat_field(path, 28, start_stack);
}

static bool start_stack_is_recorded(uint64_t start_stack, uint64_t stack_end)
{
    return start_stack != stack_end - 16;
}

static int child_write_start_stack(int fd)
{
    uint64_t start_stack = 0;
    if (!read_start_stack("/proc/self/stat", &start_stack))
        return 1;
    if (write_fd_all(fd, &start_stack, sizeof(start_stack)) < 0)
        return 2;
    return 0;
}

static bool read_rss(uint64_t *stat_rss, uint64_t *status_rss)
{
    char buf[1024];
    if (!read_stat_field("/proc/self/stat", 24, stat_rss))
        return false;
    *stat_rss *= 4096;
    ssize_t n = raw_read_file_nul("/proc/self/status", buf, sizeof(buf));
    char *rss = n > 0 ? strstr(buf, "VmRSS:") : NULL;
    if (!rss)
        return false;
    *status_rss = strtoull(rss + 6, NULL, 10) * 1024;
    return true;
}

static bool rss_near(uint64_t actual, uint64_t expected)
{
    uint64_t difference =
        actual > expected ? actual - expected : expected - actual;

    /* Linux batches RSS updates; unrelated libc pages can fault between reads.
     */
    return difference <= 2 * 1024 * 1024;
}

static void test_rss_changes(void)
{
    TEST("procfs: RSS excludes holes and refreshes after discard and unmap");
    const size_t span = 32 * 1024 * 1024;
    unsigned char *base = mmap(NULL, 4 * span, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    /* Each island covers complete host pages; the tail remains untouched. */
    bool ok = munmap(base + span, span) == 0;
    uint64_t before_stat = 0, before_status = 0, stat_rss = 0, status_rss = 0;
    ok = ok && read_rss(&before_stat, &before_status);
    for (size_t i = 0; i < span; i += 4096) {
        base[i] = 1;
        base[2 * span + i] = 2;
    }
    ok = ok && mprotect(base, span, PROT_NONE) == 0 &&
         read_rss(&stat_rss, &status_rss) &&
         rss_near(stat_rss, before_stat + 2 * span) &&
         rss_near(status_rss, before_status + 2 * span);
    ok = ok && madvise(base, span, MADV_DONTNEED) == 0 &&
         read_rss(&stat_rss, &status_rss) &&
         rss_near(stat_rss, before_stat + span) &&
         rss_near(status_rss, before_status + span);
    ok = ok && munmap(base + 2 * span, span) == 0 &&
         read_rss(&stat_rss, &status_rss) && rss_near(stat_rss, before_stat) &&
         rss_near(status_rss, before_status);
    if (!ok)
        printf("RSS before=%llu/%llu final=%llu/%llu errno=%d\n",
               (unsigned long long) before_stat,
               (unsigned long long) before_status,
               (unsigned long long) stat_rss, (unsigned long long) status_rss,
               errno);
    EXPECT_TRUE(ok,
                "RSS included holes or retained discarded/unmapped backing");
    munmap(base, 4 * span);
}

static void test_rss_aliases(void)
{
    TEST("procfs: RSS counts each shared alias");
    const size_t span = 16 * 1024 * 1024;
    FILE *file = tmpfile();
    if (!file) {
        FAIL("tmpfile");
        return;
    }
    bool ok = ftruncate(fileno(file), (off_t) span) == 0;
    uint64_t before_stat = 0, before_status = 0, stat_rss = 0, status_rss = 0;
    ok = ok && read_rss(&before_stat, &before_status);
    unsigned char *first =
        mmap(NULL, span, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(file), 0);
    unsigned char *second =
        mmap(NULL, span, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(file), 0);
    ok = ok && first != MAP_FAILED && second != MAP_FAILED;
    if (ok) {
        for (size_t i = 0; i < span; i += 4096) {
            first[i] = 1;
            second[i] = 2;
        }
        ok = read_rss(&stat_rss, &status_rss) &&
             rss_near(stat_rss, before_stat + 2 * span) &&
             rss_near(status_rss, before_status + 2 * span);
    }
    EXPECT_TRUE(ok, "RSS lost an aliased VMA contribution");
    if (first != MAP_FAILED)
        munmap(first, span);
    if (second != MAP_FAILED)
        munmap(second, span);
    fclose(file);
}

static void test_rss_subpage_holes(void)
{
    TEST("procfs: RSS excludes guest holes within resident host pages");
    const size_t span = 32 * 1024 * 1024;
    unsigned char *base = mmap(NULL, span + 16384, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    unsigned char *p =
        (unsigned char *) (((uintptr_t) base + 16383) & ~(uintptr_t) 16383);
    uint64_t before_stat = 0, before_status = 0, stat_rss = 0, status_rss = 0;
    bool ok = read_rss(&before_stat, &before_status);
    for (size_t i = 0; i < span; i += 4096)
        p[i] = 1;
    /* A 4 KiB guest hole keeps its 16 KiB host backing for live neighbors. */
    for (size_t i = 0; i < span; i += 16384) {
        if (munmap(p + i + 8192, 4096) < 0)
            ok = false;
    }
    ok = ok && read_rss(&stat_rss, &status_rss) &&
         rss_near(stat_rss, before_stat + span * 3 / 4) &&
         rss_near(status_rss, before_status + span * 3 / 4);
    EXPECT_TRUE(ok, "RSS counted unmapped slices of resident host regions");
    munmap(base, span + 16384);
}

static bool maps_name_at(const void *address, const char *name)
{
    char buf[65536];
    if (raw_read_file_nul("/proc/self/maps", buf, sizeof(buf)) <= 0)
        return false;
    for (char *line = buf; *line;) {
        char *next = strchr(line, '\n');
        if (next)
            *next = '\0';
        unsigned long long lo, hi;
        if (sscanf(line, "%llx-%llx", &lo, &hi) == 2 &&
            (uintptr_t) address >= lo && (uintptr_t) address < hi)
            return strstr(line, name) != NULL;
        if (!next)
            break;
        line = next + 1;
    }
    return false;
}

static void test_maps_split_names(void)
{
    TEST("procfs: split file names follow rename and fixed replacement");
    const size_t span = 65536;
    char first[] = "/tmp/elfuse-maps-first-XXXXXX";
    char second[] = "/tmp/elfuse-maps-second-XXXXXX";
    char renamed[sizeof(first) + 8];
    int fd = mkstemp(first), other = mkstemp(second);
    unsigned char *p = MAP_FAILED;
    bool ok = fd >= 0 && other >= 0 && ftruncate(fd, (off_t) (3 * span)) == 0 &&
              ftruncate(other, (off_t) span) == 0;
    snprintf(renamed, sizeof(renamed), "%s-moved", first);
    if (ok)
        p = mmap(NULL, 3 * span, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    ok = ok && p != MAP_FAILED && mprotect(p + span, span, PROT_READ) == 0;
    if (fd >= 0)
        close(fd);
    const char *first_name = strrchr(first, '/') + 1;
    const char *moved_name = strrchr(renamed, '/') + 1;
    const char *other_name = strrchr(second, '/') + 1;
    ok = ok && maps_name_at(p, first_name) &&
         maps_name_at(p + span, first_name) &&
         maps_name_at(p + 2 * span, first_name) &&
         rename(first, renamed) == 0 && maps_name_at(p, moved_name) &&
         maps_name_at(p + span, moved_name) &&
         maps_name_at(p + 2 * span, moved_name);
    ok = ok &&
         mmap(p + span, span, PROT_READ, MAP_PRIVATE | MAP_FIXED, other, 0) ==
             p + span &&
         maps_name_at(p, moved_name) && maps_name_at(p + span, other_name) &&
         maps_name_at(p + 2 * span, moved_name);
    EXPECT_TRUE(ok, "maps retained a stale name or confused neighboring files");
    if (p != MAP_FAILED)
        munmap(p, 3 * span);
    if (other >= 0)
        close(other);
    unlink(first);
    unlink(renamed);
    unlink(second);
}

int main(void)
{
    char buf[4096] __attribute__((aligned(8)));
    ssize_t n;

    TEST("procfs: /proc/self/auxv readable");
    {
        n = raw_read_file_nul("/proc/self/auxv", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else if (n > 0) {
            PASS();
        } else {
            FAIL("empty auxv");
        }
    }

    TEST("procfs: auxv contains AT_PAGESZ=4096");
    {
        n = raw_read_file_nul("/proc/self/auxv", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else {
            bool found = false;
            uint64_t *p = (uint64_t *) buf;
            for (ssize_t i = 0; i + 1 < n / 8; i += 2) {
                if (p[i] == AT_PAGESZ && p[i + 1] == 4096) {
                    found = true;
                    break;
                }
                if (p[i] == AT_NULL)
                    break;
            }
            EXPECT_TRUE(found, "AT_PAGESZ not found");
        }
    }

    TEST("procfs: /proc/self/environ readable");
    {
        n = raw_read_file_nul("/proc/self/environ", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else if (n > 0) {
            PASS();
        } else {
            FAIL("empty environ");
        }
    }

    TEST("procfs: /proc/self/cmdline non-empty");
    {
        n = raw_read_file_nul("/proc/self/cmdline", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else if (n > 0) {
            PASS();
        } else {
            FAIL("empty cmdline");
        }
    }

    TEST("procfs: /proc/self/maps contains [stack] and [heap]");
    {
        n = raw_read_file_nul("/proc/self/maps", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else {
            if (n > 0) {
                if (strstr(buf, "[stack]") && strstr(buf, "[heap]"))
                    PASS();
                else
                    FAIL("stack or heap not found in maps");
            } else {
                FAIL("empty maps");
            }
        }
    }

    TEST("procfs: maps offsets page-aligned, lines add up to VmSize");
    {
        static char mapsbuf[65536];
        uint64_t maps_total = 0;
        n = raw_read_file_nul("/proc/self/maps", mapsbuf, sizeof(mapsbuf));
        bool aligned = n > 0 && maps_walk(mapsbuf, &maps_total);
        n = raw_read_file_nul("/proc/self/status", buf, sizeof(buf));
        char *vm = n > 0 ? strstr(buf, "VmSize:") : NULL;
        uint64_t vm_kb = vm ? strtoull(vm + 7, NULL, 10) : 0;
        if (aligned && vm_kb * 1024 == maps_total) {
            PASS();
        } else {
            printf("FAIL: aligned %d, VmSize %llu kB, maps %llu kB\n", aligned,
                   (unsigned long long) vm_kb,
                   (unsigned long long) (maps_total / 1024));
            fails++;
        }
    }

    TEST("procfs: stat vsize is VmSize, VmRSS within it");
    {
        n = raw_read_file_nul("/proc/self/status", buf, sizeof(buf));
        char *vm = n > 0 ? strstr(buf, "VmSize:") : NULL;
        char *rss = n > 0 ? strstr(buf, "VmRSS:") : NULL;
        uint64_t vm_kb = vm ? strtoull(vm + 7, NULL, 10) : 0;
        uint64_t rss_kb = rss ? strtoull(rss + 6, NULL, 10) : 0;
        uint64_t vsize = 0;
        bool have_vsize = read_stat_field("/proc/self/stat", 23, &vsize);
        if (have_vsize && vm_kb && vsize == vm_kb * 1024 && rss_kb <= vm_kb) {
            PASS();
        } else {
            printf("FAIL: VmSize %llu kB, VmRSS %llu kB, vsize %llu kB\n",
                   (unsigned long long) vm_kb, (unsigned long long) rss_kb,
                   (unsigned long long) (vsize / 1024));
            fails++;
        }
    }

    TEST("procfs: /proc/self/maps lists [vdso]");
    n = raw_read_file_nul("/proc/self/maps", buf, sizeof(buf));
    EXPECT_TRUE(n > 0 && strstr(buf, "[vdso]"), "no [vdso] line");

    TEST("procfs: /proc/self/status has correct PID");
    {
        long pid = raw_getpid();
        n = raw_read_file_nul("/proc/self/status", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else {
            if (n > 0) {
                /* Check Pid: field */
                bool found = false;
                for (ssize_t i = 0; i < n - 5; i++) {
                    if (buf[i] == 'P' && buf[i + 1] == 'i' &&
                        buf[i + 2] == 'd' && buf[i + 3] == ':') {
                        /* Parse the PID value */
                        ssize_t j = i + 4;
                        while (j < n && (buf[j] == ' ' || buf[j] == '\t'))
                            j++;
                        long parsed_pid = 0;
                        while (j < n && buf[j] >= '0' && buf[j] <= '9')
                            parsed_pid = parsed_pid * 10 + (buf[j++] - '0');
                        if (parsed_pid == pid)
                            found = true;
                        break;
                    }
                }
                EXPECT_TRUE(found, "PID mismatch in status");
            } else {
                FAIL("empty status");
            }
        }
    }

    TEST("procfs: stat startstack is in [stack]");
    {
        uint64_t start_stack = 0, stack_start = 0, stack_end = 0;
        bool ok = read_start_stack("/proc/self/stat", &start_stack) &&
                  read_stack_range(&stack_start, &stack_end) &&
                  start_stack >= stack_start && start_stack < stack_end;
        EXPECT_TRUE(ok, "startstack not inside [stack]");
    }

    TEST("procfs: task stat startstack is in [stack]");
    {
        char path[128];
        snprintf(path, sizeof(path), "/proc/self/task/%ld/stat",
                 (long) raw_getpid());
        uint64_t start_stack = 0, stack_start = 0, stack_end = 0;
        bool ok = read_start_stack(path, &start_stack) &&
                  read_stack_range(&stack_start, &stack_end) &&
                  start_stack >= stack_start && start_stack < stack_end;
        EXPECT_TRUE(ok, "task startstack not inside [stack]");
    }

    TEST("procfs: stat startstack is recorded SP");
    {
        uint64_t start_stack = 0, stack_start = 0, stack_end = 0;
        bool ok = read_start_stack("/proc/self/stat", &start_stack) &&
                  read_stack_range(&stack_start, &stack_end) &&
                  start_stack >= stack_start && start_stack < stack_end &&
                  start_stack_is_recorded(start_stack, stack_end);
        EXPECT_TRUE(ok, "startstack used fallback value");
    }

    TEST("procfs: fork preserves stat startstack");
    {
        int pipefd[2];
        uint64_t parent_start = 0, child_start = 0;
        uint64_t stack_start = 0, stack_end = 0;
        bool ok = read_start_stack("/proc/self/stat", &parent_start) &&
                  read_stack_range(&stack_start, &stack_end) &&
                  start_stack_is_recorded(parent_start, stack_end) &&
                  pipe(pipefd) == 0;
        if (!ok) {
            EXPECT_TRUE(false, "fork startstack setup failed");
        } else {
            pid_t pid = fork();
            if (pid == 0) {
                close(pipefd[0]);
                int rc = child_write_start_stack(pipefd[1]);
                close(pipefd[1]);
                _exit(rc);
            }
            close(pipefd[1]);
            ssize_t nread = read(pipefd[0], &child_start, sizeof(child_start));
            close(pipefd[0]);
            int status = 0;
            if (pid < 0 || waitpid(pid, &status, 0) < 0)
                ok = false;
            else
                ok = nread == (ssize_t) sizeof(child_start) &&
                     WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                     child_start == parent_start &&
                     start_stack_is_recorded(child_start, stack_end);
            EXPECT_TRUE(ok, "fork child startstack mismatch");
        }
    }

    test_rss_changes();
    test_rss_aliases();
    test_rss_subpage_holes();
    test_maps_split_names();

    SUMMARY("test-procfs");
    return fails > 0 ? 1 : 0;
}
