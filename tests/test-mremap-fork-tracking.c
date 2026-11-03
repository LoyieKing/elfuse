/*
 * elfuse-internal mremap fork-tracking tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * These cases exercise elfuse's inherited-at-fork region bookkeeping, not a
 * portable Linux ABI contract. Do not add this binary to test-matrix.sh: Linux
 * can merge the adjacent file mappings below, and extends MAP_SHARED mappings
 * directly from the backing file rather than creating elfuse's child-private
 * tracking tail.
 */

#include <errno.h>
#include <fcntl.h>
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

#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif
#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif

static bool set_program_break(uintptr_t address)
{
    return brk((void *) address) == 0 && sbrk(0) == (void *) address;
}

static ssize_t read_file_nul(const char *path, char *buf, size_t bufsz)
{
    if (bufsz == 0) {
        errno = EINVAL;
        return -1;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    ssize_t total = 0;
    while ((size_t) total < bufsz - 1) {
        ssize_t n = read(fd, buf + total, bufsz - 1 - (size_t) total);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            int saved_errno = errno;
            (void) close(fd);
            errno = saved_errno;
            return -1;
        }
        if (n == 0)
            break;
        total += n;
    }
    buf[total] = '\0';
    (void) close(fd);
    return total;
}

static void *reserve_then_map_fixed(size_t reserve_length,
                                    size_t mapping_length,
                                    int prot,
                                    int flags,
                                    int fd,
                                    off_t offset)
{
    void *base = mmap(NULL, reserve_length, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return MAP_FAILED;
    if (munmap(base, reserve_length) != 0) {
        int saved_errno = errno;
        (void) munmap(base, reserve_length);
        errno = saved_errno;
        return MAP_FAILED;
    }
    return mmap(base, mapping_length, prot, flags | MAP_FIXED, fd, offset);
}

static bool parse_maps_hex(const char **cursor,
                           const char *end,
                           char delimiter,
                           uintptr_t *value)
{
    const char *start = *cursor;
    uintptr_t parsed = 0;
    while (*cursor < end && **cursor != delimiter) {
        unsigned int digit;
        char c = **cursor;
        if (c >= '0' && c <= '9')
            digit = (unsigned int) (c - '0');
        else if (c >= 'a' && c <= 'f')
            digit = (unsigned int) (c - 'a' + 10);
        else
            return false;
        parsed = parsed * 16 + digit;
        (*cursor)++;
    }
    if (*cursor == start || *cursor >= end)
        return false;
    *value = parsed;
    return true;
}

static bool mapping_is_rw_private(uintptr_t address)
{
    char maps[64 * 1024];
    ssize_t length = read_file_nul("/proc/self/maps", maps, sizeof(maps));
    if (length <= 0)
        return false;

    const char *cursor = maps;
    const char *end = maps + length;
    while (cursor < end) {
        uintptr_t start = 0, limit = 0;
        if (!parse_maps_hex(&cursor, end, '-', &start))
            return false;
        cursor++;
        if (!parse_maps_hex(&cursor, end, ' ', &limit))
            return false;
        cursor++;
        if (cursor + 4 > end)
            return false;
        if (start <= address && address < limit) {
            return cursor[0] == 'r' && cursor[1] == 'w' && cursor[2] == '-' &&
                   cursor[3] == 'p';
        }
        while (cursor < end && *cursor != '\n')
            cursor++;
        if (cursor < end)
            cursor++;
    }
    return false;
}


static void test_postfork_adjacent_anon_rejected(void)
{
    TEST("mremap rejects unrelated post-fork tail");

    const size_t span = 64 * 1024;
    void *first = reserve_then_map_fixed(2 * span, span, PROT_READ | PROT_WRITE,
                                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (first == MAP_FAILED) {
        FAIL("inherited anonymous mmap failed");
        return;
    }
    void *base = first;

    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork failed");
        munmap(first, span);
        return;
    }
    if (pid == 0) {
        void *second = mmap((char *) base + span, span, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (second != (char *) base + span)
            _exit(30);

        errno = 0;
        void *shrunk = mremap(base, 2 * span, span, 0);
        if (shrunk == MAP_FAILED && errno == EFAULT)
            _exit(0);
        _exit(31);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) >= 0 && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0)
        PASS();
    else
        FAIL("mremap accepted unrelated post-fork mapping");

    munmap(first, span);
}

static void test_postfork_repeated_allocations_keep_lineage(void)
{
    TEST("repeated post-fork allocations never alias inherited VMA IDs");

    const size_t span = 64 * 1024;
    const int attempts = 256;
    void *first = reserve_then_map_fixed(2 * span, span, PROT_READ | PROT_WRITE,
                                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (first == MAP_FAILED) {
        FAIL("inherited anonymous mmap failed");
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork failed");
        munmap(first, span);
        return;
    }
    if (pid == 0) {
        for (int i = 0; i < attempts; i++) {
            void *tail =
                mmap((char *) first + span, span, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (tail != (char *) first + span)
                _exit(90);

            /* If child allocation reused the inherited source's vma_id,
             * find_mremap_source would incorrectly accept the adjacent pair. A
             * reseeded allocator keeps the logical lineages distinct.
             */
            errno = 0;
            void *same = mremap(first, 2 * span, 2 * span, 0);
            if (same != MAP_FAILED || errno != EFAULT)
                _exit(91);
            if (munmap(tail, span) != 0)
                _exit(92);
        }
        _exit(0);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) >= 0 && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0)
        PASS();
    else
        FAIL("post-fork VMA IDs collided during repeated allocation");
    munmap(first, span);
}

static void test_adjacent_file_vmas_rejected(void)
{
    TEST("mremap rejects adjacent independent file VMAs");

    const size_t span = 64 * 1024;
    char tmpl[] = "/tmp/elfuse-mremap-adjacent-XXXXXX";
    int fd1 = mkstemp(tmpl);
    if (fd1 < 0) {
        FAIL("mkstemp failed");
        return;
    }
    int fd2 = open(tmpl, O_RDWR);
    unlink(tmpl);
    if (fd2 < 0 || ftruncate(fd1, (off_t) (2 * span)) != 0) {
        FAIL("file setup failed");
        if (fd2 >= 0)
            close(fd2);
        close(fd1);
        return;
    }

    void *first = reserve_then_map_fixed(2 * span, span, PROT_READ | PROT_WRITE,
                                         MAP_SHARED, fd1, 0);
    void *base = first;
    if (first == MAP_FAILED) {
        FAIL("address reservation or first file mmap failed");
        close(fd2);
        close(fd1);
        return;
    }
    void *second = mmap((char *) base + span, span, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_FIXED, fd2, (off_t) span);
    if (first != base || second != (char *) base + span) {
        FAIL("adjacent file mmap failed");
        if (first == base)
            munmap(first, span);
        if (second == (char *) base + span)
            munmap(second, span);
        close(fd2);
        close(fd1);
        return;
    }

    errno = 0;
    void *q = mremap(base, 2 * span, 2 * span, 0);
    if (q == MAP_FAILED && errno == EFAULT)
        PASS();
    else
        FAIL("mremap accepted two independent tracker records");

    munmap(first, span);
    munmap(second, span);
    close(fd2);
    close(fd1);
}

static void test_misaligned_shared_mremap_writeback(void)
{
    TEST("misaligned MAP_SHARED mremap writes back after move");

    const size_t page = 4096;
    const size_t span = 64 * 1024;
    char tmpl[] = "/tmp/elfuse-mremap-misaligned-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        FAIL("mkstemp failed");
        return;
    }
    unlink(tmpl);
    if (ftruncate(fd, (off_t) (2 * span)) != 0) {
        FAIL("file setup failed");
        close(fd);
        return;
    }

    /* Deliberately place the source one host page into its reservation. This
     * keeps the guest mapping page-aligned while making it non-2MiB-aligned, so
     * the MAP_SHARED overlay/mremap path exercises a split HVF segment.
     */
    size_t reservation_length = 2 * span + page;
    void *reservation = mmap(NULL, reservation_length, PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED ||
        munmap(reservation, reservation_length) != 0) {
        FAIL("source reservation failed");
        if (reservation != MAP_FAILED)
            (void) munmap(reservation, reservation_length);
        close(fd);
        return;
    }
    char *source_address = (char *) reservation + page;
    char *source = mmap(source_address, span, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_FIXED, fd, 0);
    if (source == MAP_FAILED || source != source_address) {
        FAIL("misaligned MAP_SHARED mmap failed");
        close(fd);
        return;
    }
    source[0] = 'A';
    source[page + 7] = 'B';

    /* Block in-place growth so mremap must move the mapping and leave the
     * destination on the snapshot-style shared-writeback path.
     */
    void *blocker = mmap(source + span, span, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (blocker != source + span) {
        FAIL("mremap blocker mmap failed");
        munmap(source, span);
        close(fd);
        return;
    }

    char *moved = mremap(source, span, 2 * span, MREMAP_MAYMOVE);
    if (moved == MAP_FAILED || moved == source) {
        FAIL("misaligned MAP_SHARED mremap did not move");
        if (moved != MAP_FAILED)
            munmap(moved, 2 * span);
        else
            munmap(source, span);
        munmap(blocker, span);
        close(fd);
        return;
    }
    if (moved[0] != 'A' || moved[page + 7] != 'B') {
        FAIL("mremap move corrupted source bytes");
        munmap(moved, 2 * span);
        munmap(blocker, span);
        close(fd);
        return;
    }

    moved[page + 7] = 'C';
    moved[span + 19] = 'D';
    errno = 0;
    int sync_result = msync(moved, 2 * span, MS_SYNC);
    int sync_errno = errno;
    unsigned char first = 0, extension = 0;
    bool writeback_ok = sync_result == 0 &&
                        pread(fd, &first, 1, (off_t) (page + 7)) == 1 &&
                        pread(fd, &extension, 1, (off_t) (span + 19)) == 1 &&
                        first == 'C' && extension == 'D';
    if (writeback_ok)
        PASS();
    else {
        errno = sync_errno;
        FAIL("mremap destination did not write back MAP_SHARED bytes");
    }

    munmap(moved, 2 * span);
    munmap(blocker, span);
    close(fd);
}

/* Force the snapshot-style MAP_SHARED path by placing a guest-page mapping one
 * page into an otherwise unused reservation. Apple hosts use larger host pages
 * than the guest's 4 KiB pages, so this address cannot receive a live file
 * overlay.
 */
static void *map_misaligned_shared_fixed(size_t length,
                                         int prot,
                                         int fd,
                                         off_t offset,
                                         void **reservation_out)
{
    const size_t page = 4096;
    *reservation_out = NULL;

    void *reservation = mmap(NULL, length + page, PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED)
        return MAP_FAILED;

    void *address = (char *) reservation + page;
    if (munmap(reservation, length + page) != 0) {
        /* Keep ownership visible to the caller when the reservation cannot be
         * released. Returning MAP_FAILED alone would make the live mapping
         * indistinguishable from an allocation that never happened.
         */
        *reservation_out = reservation;
        return MAP_FAILED;
    }
    return mmap(address, length, prot, MAP_SHARED | MAP_FIXED, fd, offset);
}

static void test_readonly_shared_mremap_does_not_flush_alias(void)
{
    TEST("read-only MAP_SHARED mremap does not flush writable alias");

    const size_t page = 4096;
    const size_t span = 64 * 1024;
    char tmpl[] = "/tmp/elfuse-mremap-readonly-alias-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        FAIL("mkstemp failed");
        return;
    }
    unlink(tmpl);
    if (ftruncate(fd, (off_t) (2 * span)) != 0 || pwrite(fd, "F", 1, 0) != 1) {
        FAIL("file setup failed");
        close(fd);
        return;
    }

    void *writer_reservation = NULL;
    void *source_reservation = NULL;
    char *writer = map_misaligned_shared_fixed(span, PROT_READ | PROT_WRITE, fd,
                                               0, &writer_reservation);
    char *source = map_misaligned_shared_fixed(span, PROT_READ, fd, 0,
                                               &source_reservation);
    if (writer == MAP_FAILED || source == MAP_FAILED) {
        FAIL("snapshot MAP_SHARED mappings failed");
        if (writer != MAP_FAILED)
            munmap(writer, span);
        if (source != MAP_FAILED)
            munmap(source, span);
        if (writer_reservation != NULL)
            munmap(writer_reservation, span + page);
        if (source_reservation != NULL)
            munmap(source_reservation, span + page);
        close(fd);
        return;
    }
    writer[0] = 'W';

    void *blocker = mmap(source + span, span, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (blocker != source + span) {
        FAIL("mremap blocker mmap failed");
        munmap(writer, span);
        munmap(source, span);
        close(fd);
        return;
    }

    char *moved = mremap(source, span, 2 * span, MREMAP_MAYMOVE);
    unsigned char file_byte = 0;
    bool unchanged = moved != MAP_FAILED && moved != source &&
                     pread(fd, &file_byte, 1, 0) == 1 && file_byte == 'F';
    if (unchanged)
        PASS();
    else
        FAIL("read-only source mremap flushed writable alias");

    if (moved != MAP_FAILED)
        munmap(moved, 2 * span);
    else
        munmap(source, span);
    munmap(writer, span);
    munmap(blocker, span);
    close(fd);
}

static void test_file_backed_fork_split_move(void)
{
    TEST("MAP_SHARED file: mremap across fork-split source");

    const size_t span = 64 * 1024;
    char tmpl[] = "/tmp/elfuse-cf-mremap-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }
    unlink(tmpl);
    if (ftruncate(fd, (off_t) (4 * span)) != 0 || pwrite(fd, "F", 1, 0) != 1 ||
        pwrite(fd, "X", 1, (off_t) span) != 1) {
        FAIL("file setup");
        close(fd);
        return;
    }

    char *p = reserve_then_map_fixed(4 * span, span, PROT_READ | PROT_WRITE,
                                     MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("file mmap");
        close(fd);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork");
        munmap(p, span);
        close(fd);
        return;
    }

    if (pid == 0) {
        char *grown = mremap(p, span, 2 * span, 0);
        if (grown != p)
            _exit(40);
        if (grown[0] != 'F' || grown[span] != 0)
            _exit(41);

        void *blocker = mmap(grown + 2 * span, span, PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (blocker != grown + 2 * span)
            _exit(42);

        /* A second fork marks both tracker records inherited. Their stable
         * logical-VMA lineage must still allow the grandchild to mremap the
         * complete source.
         */
        pid_t grandchild = fork();
        if (grandchild < 0)
            _exit(43);
        if (grandchild == 0) {
            char *moved = mremap(grown, 2 * span, 3 * span, MREMAP_MAYMOVE);
            if (moved == MAP_FAILED)
                _exit(44);
            if (moved == grown)
                _exit(45);
            if (moved[0] != 'F' || moved[span] != 0 || moved[2 * span] != 0)
                _exit(46);

            munmap(moved, 3 * span);
            munmap(blocker, span);
            _exit(0);
        }

        int grandchild_status = 0;
        if (waitpid(grandchild, &grandchild_status, 0) < 0 ||
            !WIFEXITED(grandchild_status))
            _exit(47);
        if (WEXITSTATUS(grandchild_status) != 0)
            _exit(WEXITSTATUS(grandchild_status));
        munmap(grown, 2 * span);
        munmap(blocker, span);
        _exit(0);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        FAIL("waitpid");
    } else if (!WIFEXITED(status)) {
        FAIL("child terminated abnormally");
    } else if (WEXITSTATUS(status) != 0) {
        char buf[80];
        snprintf(buf, sizeof(buf), "child mremap failed at step %d",
                 WEXITSTATUS(status));
        FAIL(buf);
    } else {
        PASS();
    }

    munmap(p, span);
    close(fd);
}

static void test_file_backed_mprotect_fragments_move(void)
{
    TEST("MAP_SHARED file: mremap across restored mprotect fragments");

    const size_t span = 64 * 1024;
    const size_t old_size = 3 * span;
    const size_t new_size = 4 * span;
    char tmpl[] = "/tmp/elfuse-mremap-fragments-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        FAIL("mkstemp failed");
        return;
    }
    unlink(tmpl);
    if (ftruncate(fd, (off_t) new_size) != 0) {
        FAIL("file setup failed");
        close(fd);
        return;
    }

    char *p = reserve_then_map_fixed(5 * span, old_size, PROT_READ | PROT_WRITE,
                                     MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("file mmap failed");
        close(fd);
        return;
    }
    p[0] = 'A';
    p[span] = 'B';
    p[2 * span] = 'C';

    if (mprotect(p + span, span, PROT_READ) != 0 ||
        mprotect(p + span, span, PROT_READ | PROT_WRITE) != 0) {
        FAIL("mprotect split and restore failed");
        munmap(p, old_size);
        close(fd);
        return;
    }

    void *blocker = mmap(p + old_size, span, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (blocker != p + old_size) {
        FAIL("move blocker mmap failed");
        munmap(p, old_size);
        close(fd);
        return;
    }

    char *moved = mremap(p, old_size, new_size, MREMAP_MAYMOVE);
    if (moved == MAP_FAILED || moved == p || moved[0] != 'A' ||
        moved[span] != 'B' || moved[2 * span] != 'C' || moved[3 * span] != 0) {
        FAIL("fragmented logical VMA did not move intact");
        if (moved == MAP_FAILED)
            munmap(p, old_size);
        else
            munmap(moved, new_size);
    } else {
        moved[3 * span] = 'D';
        PASS();
        munmap(moved, new_size);
    }

    munmap(blocker, span);
    close(fd);
}

static void test_file_backed_fixed_move_from_same_vma(void)
{
    TEST("MAP_SHARED file: fixed subrange move keeps source fd live");

    const size_t span = 64 * 1024;
    char tmpl[] = "/tmp/elfuse-mremap-fixed-source-fd-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        FAIL("mkstemp failed");
        return;
    }
    unlink(tmpl);
    if (ftruncate(fd, (off_t) (3 * span)) != 0) {
        FAIL("file setup failed");
        close(fd);
        return;
    }

    char *p = reserve_then_map_fixed(4 * span, 3 * span, PROT_READ | PROT_WRITE,
                                     MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("file mmap failed");
        close(fd);
        return;
    }
    p[0] = 'D';
    p[span] = 'M';
    p[2 * span] = 'S';

    char *moved =
        mremap(p + 2 * span, span, span, MREMAP_MAYMOVE | MREMAP_FIXED, p);
    if (moved != p || moved[0] != 'S' || moved[span] != 'M')
        FAIL("fixed subrange move lost its source backing fd");
    else
        PASS();

    munmap(p, 3 * span);
    close(fd);
}

static void test_file_backed_mremap_emfile_atomic(void)
{
    TEST("MAP_SHARED fork growth: mremap EMFILE preserves source");

    const size_t span = 64 * 1024;
    const size_t page_size = 4096;
    const int fill_limit = 4096;
    char tmpl[] = "/tmp/elfuse-mremap-emfile-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        FAIL("mkstemp failed");
        return;
    }
    unlink(tmpl);
    if (ftruncate(fd, (off_t) (4 * span)) != 0) {
        FAIL("file setup failed");
        close(fd);
        return;
    }

    char *p = reserve_then_map_fixed(4 * span, span, PROT_READ | PROT_WRITE,
                                     MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("file mmap failed");
        close(fd);
        return;
    }
    p[0] = 'I';

    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork failed");
        munmap(p, span);
        close(fd);
        return;
    }
    if (pid == 0) {
        const size_t filler_reservation_size =
            (size_t) fill_limit * 2 * page_size;
        char *grown = mremap(p, span, 2 * span, 0);
        if (grown != p)
            _exit(60);
        grown[span] = 'T';
        grown[2 * span - 1] = 'Z';

        void *blocker = mmap(grown + 2 * span, span, PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (blocker != grown + 2 * span)
            _exit(61);

        char *fixed_probe =
            reserve_then_map_fixed(4 * span, 3 * span, PROT_READ | PROT_WRITE,
                                   MAP_SHARED, fd, (off_t) span);
        if (fixed_probe == MAP_FAILED)
            _exit(72);
        fixed_probe[0] = 'D';
        fixed_probe[2 * span] = 'S';

        int last_dup = -1;
        for (;;) {
            int duplicated = dup(fd);
            if (duplicated < 0)
                break;
            last_dup = duplicated;
        }
        if (errno != EMFILE || last_dup < 0)
            _exit(62);

        /* Keep one guest slot available for the /proc/self/maps proof below.
         * The close also releases one host descriptor; the file-backed filler
         * loop consumes it again before finding the actual host/table limit.
         */
        if (close(last_dup) != 0)
            _exit(69);

        void *filler_base = mmap(NULL, filler_reservation_size, PROT_NONE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (filler_base == MAP_FAILED ||
            munmap(filler_base, filler_reservation_size) != 0)
            _exit(70);

        void *last_filler = MAP_FAILED;
        int filler_count = 0;
        for (; filler_count < fill_limit; filler_count++) {
            void *filler = mmap(
                (char *) filler_base + (size_t) filler_count * 2 * page_size,
                page_size, PROT_NONE, MAP_PRIVATE | MAP_FIXED, fd, 0);
            if (filler == MAP_FAILED)
                break;
            last_filler = filler;
        }
        if (filler_count == 0 || filler_count == fill_limit || errno != ENOMEM)
            _exit(63);

        int exhausted_probe = dup(fd);
        if (exhausted_probe >= 0) {
            close(exhausted_probe);
            _exit(77);
        }
        if (errno != EMFILE)
            _exit(77);

        /* The first failed filler proves no host descriptor remains. Freeing
         * one owned tracker fd lets mremap's prefix dup succeed and forces the
         * second, tail-owned dup to hit EMFILE.
         */
        if (munmap(last_filler, page_size) != 0)
            _exit(64);


        errno = 0;
        char *moved = mremap(grown, 2 * span, 3 * span, MREMAP_MAYMOVE);
        if (moved != MAP_FAILED || errno != ENOMEM)
            _exit(65);

        volatile char *source = grown;
        if (source[0] != 'I' || source[span] != 'T' ||
            source[2 * span - 1] != 'Z')
            _exit(66);
        if (mprotect(grown, 2 * span, PROT_READ) != 0 || source[0] != 'I' ||
            source[span] != 'T' ||
            mprotect(grown, 2 * span, PROT_READ | PROT_WRITE) != 0)
            _exit(67);
        source[1] = 'J';
        source[span + 1] = 'U';
        if (source[1] != 'J' || source[span + 1] != 'U')
            _exit(68);

        /* Exactly one host descriptor is free again. A fixed subrange move
         * consumes it for target tracking, then must fail atomically when the
         * source-boundary snapshot cannot duplicate its backing fd.
         */
        errno = 0;
        char *fixed = mremap(fixed_probe + 2 * span, span, span,
                             MREMAP_MAYMOVE | MREMAP_FIXED, fixed_probe);
        if (fixed != MAP_FAILED || errno != ENOMEM || fixed_probe[0] != 'D' ||
            fixed_probe[2 * span] != 'S')
            _exit(73);

        /* Release guest dup slots and filler tracker descriptors, then retry. A
         * failed split that published backing_fd=-1 would make this retry fail
         * even though descriptor capacity is now available.
         */
        for (int guest_fd = 0; guest_fd < 4096; guest_fd++) {
            if (guest_fd != fd)
                (void) close(guest_fd);
        }
        if (munmap(filler_base, filler_reservation_size) != 0)
            _exit(74);

        fixed = mremap(fixed_probe + 2 * span, span, span,
                       MREMAP_MAYMOVE | MREMAP_FIXED, fixed_probe);
        if (fixed != fixed_probe || fixed[0] != 'S')
            _exit(75);
        _exit(0);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        FAIL("waitpid failed");
    } else if (!WIFEXITED(status)) {
        FAIL("EMFILE child terminated abnormally");
    } else if (WEXITSTATUS(status) == 77) {
        FAIL("filler did not establish descriptor exhaustion");
    } else if (WEXITSTATUS(status) != 0) {
        char buf[80];
        snprintf(buf, sizeof(buf), "EMFILE child failed at step %d",
                 WEXITSTATUS(status));
        FAIL(buf);
    } else {
        PASS();
    }

    munmap(p, span);
    close(fd);
}

static void test_heap_tail_mprotect_then_grow(void)
{
    TEST("brk growth does not reuse protected heap tail");

    const uintptr_t page_size = 4096;
    void *current_break = sbrk(0);
    if (current_break == (void *) -1) {
        FAIL("read parent brk failed");
        return;
    }
    uintptr_t original = (uintptr_t) current_break;
    uintptr_t inherited_end =
        (original + page_size - 1) / page_size * page_size + page_size;
    if (!set_program_break(inherited_end)) {
        FAIL("parent brk growth failed");
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork failed");
        (void) set_program_break(original);
        return;
    }
    if (pid == 0) {
        uintptr_t protected_end = inherited_end + page_size;
        uintptr_t final_end = protected_end + page_size;
        if (!set_program_break(protected_end))
            _exit(50);
        if (mprotect((void *) inherited_end, page_size, PROT_READ) != 0)
            _exit(51);
        if (!set_program_break(final_end))
            _exit(52);

        if (!mapping_is_rw_private(protected_end))
            _exit(54);

        if (!set_program_break(protected_end))
            _exit(55);
        if (!set_program_break(final_end))
            _exit(56);
        if (!mapping_is_rw_private(protected_end))
            _exit(57);
        _exit(0);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) >= 0 && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0)
        PASS();
    else
        FAIL("new brk page inherited stale tail protection");

    (void) set_program_break(original);
}


int main(void)
{
    printf("test-mremap-fork-tracking: elfuse mremap tracker tests\n");

    test_postfork_adjacent_anon_rejected();
    test_postfork_repeated_allocations_keep_lineage();
    test_adjacent_file_vmas_rejected();
    test_misaligned_shared_mremap_writeback();
    test_readonly_shared_mremap_does_not_flush_alias();
    test_file_backed_fork_split_move();
    test_file_backed_mprotect_fragments_move();
    test_file_backed_fixed_move_from_same_vma();
    test_file_backed_mremap_emfile_atomic();
    test_heap_tail_mprotect_then_grow();

    SUMMARY("test-mremap-fork-tracking");
    return fails > 0 ? 1 : 0;
}
