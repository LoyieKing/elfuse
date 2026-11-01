/*
 * File-backed MAP_PRIVATE semantics
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A private file mapping opened through a read-only descriptor is writable,
 * because the writes never reach the file. MADV_DONTNEED restores the file
 * bytes for the discarded page only, fork keeps the dirty private view on both
 * sides after the original file changes, PROT_NONE does not discard it, and an
 * EOF tail inside the last file page reads zero.
 *
 * Removing a middle page, mremap shrink and grow/move, and a mapping created
 * PROT_NONE before regrant keep the same private bytes.
 *
 * A mapping used as a syscall buffer before its first guest touch must resolve
 * the same file bytes, and PROT_NONE must report EFAULT for such a buffer until
 * mprotect regrants access. An untouched private mapping stays independently
 * valid in each side after fork, and a 64 MiB private mapping of a fresh sparse
 * file reports every page absent through mincore.
 *
 * The edge shape uses a 4 KiB file offset and a length that is not a 16 KiB
 * multiple; the aligned shape uses offset zero and 64 KiB. ELF segment
 * replacement also covers whole pages past EOF, which must retain SIGBUS
 * delivery while neighbouring private bytes survive.
 *
 * Syscalls exercised: openat, mkstemp, read64, write64, ftruncate, pread64,
 *                     pwrite64, mmap, munmap, madvise, mprotect, mremap,
 *                     mincore, clone, wait4
 */

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif
#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif

#define UNTOUCHED_MAP_LEN ((size_t) 64 * 1024 * 1024)
#define UNTOUCHED_MAP_PAGES 16384
#define UNTOUCHED_BLOCK ((size_t) 2 * 1024 * 1024)

#include "test-harness.h"

int passes = 0, fails = 0;

static size_t page_size;

typedef struct {
    size_t off;
    size_t len;
    const char *name;
} map_shape_t;

static unsigned char seed_byte(size_t offset)
{
    return (unsigned char) (0x40 + ((offset * 37u) % 0x3fu));
}

static unsigned char dirty_byte(size_t offset)
{
    return (unsigned char) (0x80 + (offset & 0x3fu));
}

static unsigned char io_byte(size_t offset)
{
    return (unsigned char) (0xa5 ^ (offset * 131u));
}

static bool write_all_at(int fd, const void *buf, size_t len, off_t offset)
{
    const unsigned char *src = buf;
    size_t done = 0;

    while (done < len) {
        ssize_t n = pwrite(fd, src + done, len - done, offset + (off_t) done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (n == 0)
            return false;
        done += (size_t) n;
    }
    return true;
}

static bool read_all_at(int fd, void *buf, size_t len, off_t offset)
{
    unsigned char *dst = buf;
    size_t done = 0;

    while (done < len) {
        ssize_t n = pread(fd, dst + done, len - done, offset + (off_t) done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (n == 0)
            return false;
        done += (size_t) n;
    }
    return true;
}

/* Open the file read-only for the mapping and read-write for the checks that
 * the mapping did not change it. The path is unlinked once both descriptors
 * exist.
 */
static bool make_seed_file(size_t len, int *ro_out, int *rw_out)
{
    char path[] = "/tmp/elfuse-mmap-private-XXXXXX";
    unsigned char buf[4096];
    int rw = mkstemp(path);
    int ro;
    size_t off = 0;

    if (rw < 0)
        return false;
    ro = open(path, O_RDONLY);
    if (ro < 0) {
        close(rw);
        unlink(path);
        return false;
    }
    unlink(path);

    while (off < len) {
        size_t chunk = len - off < sizeof(buf) ? len - off : sizeof(buf);
        for (size_t i = 0; i < chunk; i++)
            buf[i] = seed_byte(off + i);
        if (!write_all_at(rw, buf, chunk, (off_t) off)) {
            close(ro);
            close(rw);
            return false;
        }
        off += chunk;
    }
    *ro_out = ro;
    *rw_out = rw;
    return true;
}

static bool overwrite_file(int fd, size_t len, unsigned char value)
{
    unsigned char buf[4096];
    size_t off = 0;

    memset(buf, value, sizeof(buf));
    while (off < len) {
        size_t chunk = len - off < sizeof(buf) ? len - off : sizeof(buf);
        if (!write_all_at(fd, buf, chunk, (off_t) off))
            return false;
        off += chunk;
    }
    return true;
}

static bool all_zero(const unsigned char *p, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (p[i] != 0)
            return false;
    }
    return true;
}

/* Volatile stores keep the private write before the file and alias probes that
 * follow; a plain store may be reordered across the unmapped file check.
 */
static void fill_dirty(unsigned char *p, size_t len)
{
    volatile unsigned char *vp = p;

    for (size_t i = 0; i < len; i++)
        vp[i] = dirty_byte(i);
}

static bool matches_dirty_from(const unsigned char *p, size_t start, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (p[i] != dirty_byte(start + i))
            return false;
    }
    return true;
}

static bool matches_dirty(const unsigned char *p, size_t len)
{
    return matches_dirty_from(p, 0, len);
}

/* File bytes expected at @file_off, compared against a mapping filled from that
 * file offset.
 */
static bool matches_seed(const unsigned char *p, size_t file_off, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (p[i] != seed_byte(file_off + i))
            return false;
    }
    return true;
}

static bool file_matches_seed(int fd, size_t len)
{
    unsigned char buf[4096];
    size_t off = 0;

    while (off < len) {
        size_t chunk = len - off < sizeof(buf) ? len - off : sizeof(buf);
        if (!read_all_at(fd, buf, chunk, (off_t) off) ||
            !matches_seed(buf, off, chunk))
            return false;
        off += chunk;
    }
    return true;
}

/* A regular file for the syscall-buffer cases, unlinked so the test leaves no
 * path behind.
 */
static int make_temp_fd(void)
{
    char path[] = "/tmp/elfuse-mmap-private-XXXXXX";
    int fd = mkstemp(path);

    if (fd >= 0)
        (void) unlink(path);
    return fd;
}

static bool make_pattern_file(size_t len,
                              unsigned char (*byte)(size_t),
                              int *out)
{
    unsigned char buf[4096];
    int fd = make_temp_fd();
    size_t off = 0;

    if (fd < 0)
        return false;
    while (off < len) {
        size_t chunk = len - off < sizeof(buf) ? len - off : sizeof(buf);

        for (size_t i = 0; i < chunk; i++)
            buf[i] = byte(off + i);
        if (!write_all_at(fd, buf, chunk, (off_t) off)) {
            close(fd);
            return false;
        }
        off += chunk;
    }
    *out = fd;
    return true;
}

static bool write_pattern_at(int fd,
                             size_t off,
                             size_t len,
                             unsigned char (*byte)(size_t))
{
    unsigned char buf[4096];
    size_t done = 0;

    while (done < len) {
        size_t chunk = len - done < sizeof(buf) ? len - done : sizeof(buf);

        for (size_t i = 0; i < chunk; i++)
            buf[i] = byte(off + done + i);
        if (!write_all_at(fd, buf, chunk, (off_t) (off + done)))
            return false;
        done += chunk;
    }
    return true;
}

/* write()/read() with the mapping itself as the guest buffer. Each call is a
 * real syscall, so the host-I/O path has to resolve a deferred file PTE rather
 * than relying on an earlier guest load.
 */
static bool write_all_from(int fd, const void *buf, size_t len)
{
    const unsigned char *src = buf;
    size_t done = 0;

    while (done < len) {
        ssize_t n = write(fd, src + done, len - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (n == 0)
            return false;
        done += (size_t) n;
    }
    return true;
}

static bool read_all_into(int fd, void *buf, size_t len)
{
    unsigned char *dst = buf;
    size_t done = 0;

    while (done < len) {
        ssize_t n = read(fd, dst + done, len - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (n == 0)
            return false;
        done += (size_t) n;
    }
    return true;
}

static bool fd_matches_from(int fd,
                            size_t fd_off,
                            size_t len,
                            unsigned char (*byte)(size_t),
                            size_t pattern_off)
{
    unsigned char buf[4096];
    size_t done = 0;

    while (done < len) {
        size_t chunk = len - done < sizeof(buf) ? len - done : sizeof(buf);

        if (!read_all_at(fd, buf, chunk, (off_t) (fd_off + done)))
            return false;
        for (size_t i = 0; i < chunk; i++) {
            if (buf[i] != byte(pattern_off + done + i))
                return false;
        }
        done += chunk;
    }
    return true;
}

static bool fd_matches_seed_from(int fd,
                                 size_t fd_off,
                                 size_t file_off,
                                 size_t len)
{
    return fd_matches_from(fd, fd_off, len, seed_byte, file_off);
}

static bool fd_matches_io(int fd, size_t fd_off, size_t len)
{
    return fd_matches_from(fd, fd_off, len, io_byte, 0);
}

static bool fd_all_zero_from(int fd, size_t fd_off, size_t len)
{
    unsigned char buf[4096];
    size_t done = 0;

    while (done < len) {
        size_t chunk = len - done < sizeof(buf) ? len - done : sizeof(buf);

        if (!read_all_at(fd, buf, chunk, (off_t) (fd_off + done)) ||
            !all_zero(buf, chunk))
            return false;
        done += chunk;
    }
    return true;
}

static bool matches_io(const unsigned char *p, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (p[i] != io_byte(i))
            return false;
    }
    return true;
}

static void edge_shape(map_shape_t *shape)
{
    shape->off = page_size;
    shape->len = 4 * page_size + 123;
    shape->name = "4K offset";
}

static void aligned_shape(map_shape_t *shape)
{
    shape->off = 0;
    shape->len = 16 * page_size;
    shape->name = "aligned";
}

static void make_label(char *label,
                       size_t cap,
                       const char *what,
                       const map_shape_t *shape)
{
    snprintf(label, cap, "%s (%s)", what, shape->name);
}

/* A read-only descriptor supports MAP_PRIVATE with PROT_WRITE, and the dirty
 * bytes stay in the mapping. A shared alias and a fresh pread see the original
 * file bytes.
 */
static void test_private_write_is_private(const map_shape_t *shape)
{
    size_t file_len = 16 * page_size;
    char label[80];
    int ro = -1, rw = -1;
    unsigned char *p;
    unsigned char *alias;
    bool ok;

    make_label(label, sizeof(label), "private write stays in mapping", shape);
    TEST(label);
    if (!make_seed_file(file_len, &ro, &rw)) {
        FAIL("seed file");
        return;
    }
    p = mmap(NULL, shape->len, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro,
             (off_t) shape->off);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(ro);
        close(rw);
        return;
    }
    ok = matches_seed(p, shape->off, shape->len);
    EXPECT_TRUE(ok, "private mapping did not hold the file bytes");

    alias = mmap(NULL, file_len, PROT_READ, MAP_SHARED, rw, 0);
    if (alias == MAP_FAILED) {
        FAIL("mmap shared alias");
        munmap(p, shape->len);
        close(ro);
        close(rw);
        return;
    }
    fill_dirty(p, shape->len);
    ok = matches_dirty(p, shape->len) && matches_seed(alias, 0, file_len) &&
         file_matches_seed(rw, file_len);
    EXPECT_TRUE(ok, "private write reached the file or the shared alias");

    munmap(alias, file_len);
    munmap(p, shape->len);
    close(ro);
    close(rw);
}

/* Discard one guest page in the middle of dirty neighbours. The page must
 * return to the file image and the neighbours must keep their private bytes.
 */
static void test_dontneed_restores_file_page(const map_shape_t *shape)
{
    size_t file_len = 16 * page_size;
    size_t discard = page_size;
    char label[80];
    int ro = -1, rw = -1;
    unsigned char *p;
    bool ok;

    make_label(label, sizeof(label), "4K DONTNEED restores file page", shape);
    TEST(label);
    if (!make_seed_file(file_len, &ro, &rw)) {
        FAIL("seed file");
        return;
    }
    p = mmap(NULL, shape->len, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro,
             (off_t) shape->off);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(ro);
        close(rw);
        return;
    }
    fill_dirty(p, shape->len);
    if (madvise(p + discard, page_size, MADV_DONTNEED) != 0) {
        FAIL("madvise DONTNEED");
        munmap(p, shape->len);
        close(ro);
        close(rw);
        return;
    }
    ok = matches_seed(p + discard, shape->off + discard, page_size) &&
         matches_dirty(p, discard) &&
         matches_dirty_from(p + discard + page_size, discard + page_size,
                            shape->len - discard - page_size) &&
         file_matches_seed(rw, file_len);
    EXPECT_TRUE(ok, "discard lost a neighbour or kept the private page");

    munmap(p, shape->len);
    close(ro);
    close(rw);
}

/* Removing one dirty guest page from the middle of a larger private file
 * mapping must not disturb bytes in the same 16 KiB host page on either side.
 */
static void test_munmap_middle_preserves(const map_shape_t *shape)
{
    size_t file_len = 16 * page_size;
    size_t hole = (shape->len / 2) & ~(page_size - 1);
    char label[80];
    int ro = -1, rw = -1;
    unsigned char *p;
    bool ok;

    if (hole == 0 || hole + page_size > shape->len)
        hole = page_size;
    if (hole % (16 * 1024) == 0)
        hole += page_size;
    if (hole + page_size > shape->len)
        hole = page_size;

    make_label(label, sizeof(label), "munmap middle 4K keeps neighbours",
               shape);
    TEST(label);
    if (!make_seed_file(file_len, &ro, &rw)) {
        FAIL("seed file");
        return;
    }
    p = mmap(NULL, shape->len, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro,
             (off_t) shape->off);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(ro);
        close(rw);
        return;
    }
    fill_dirty(p, shape->len);
    if (munmap(p + hole, page_size) != 0) {
        FAIL("munmap middle");
        munmap(p, shape->len);
        close(ro);
        close(rw);
        return;
    }
    ok = matches_dirty(p, hole) &&
         matches_dirty_from(p + hole + page_size, hole + page_size,
                            shape->len - hole - page_size) &&
         file_matches_seed(rw, file_len);
    EXPECT_TRUE(ok, "unmap changed a neighbour or the file");

    munmap(p, hole);
    munmap(p + hole + page_size, shape->len - hole - page_size);
    close(ro);
    close(rw);
}

/* A mapping that starts PROT_NONE still has to expose the file bytes once it is
 * made readable, including the aligned range that elfuse maps directly.
 */
static void test_initial_prot_none_seeded(const map_shape_t *shape)
{
    size_t file_len = 16 * page_size;
    char label[80];
    int ro = -1, rw = -1;
    unsigned char *p;
    bool ok;

    make_label(label, sizeof(label), "PROT_NONE mmap regrant is seeded", shape);
    TEST(label);
    if (!make_seed_file(file_len, &ro, &rw)) {
        FAIL("seed file");
        return;
    }
    p = mmap(NULL, shape->len, PROT_NONE, MAP_PRIVATE, ro, (off_t) shape->off);
    if (p == MAP_FAILED) {
        FAIL("mmap PROT_NONE");
        close(ro);
        close(rw);
        return;
    }
    ok = mprotect(p, shape->len, PROT_READ | PROT_WRITE) == 0 &&
         matches_seed(p, shape->off, shape->len);
    EXPECT_TRUE(ok, "regrant exposed zero or stale bytes");

    munmap(p, shape->len);
    close(ro);
    close(rw);
}

/* Shrinking keeps the dirty prefix. Growing with a forced move keeps that
 * prefix on the new range, so the copy cannot come from the file instead.
 */
static void test_mremap_keeps_data(void)
{
    size_t len = 16 * page_size;
    size_t shrink = 8 * page_size;
    int ro = -1, rw = -1;
    unsigned char *p;
    unsigned char *reserve;
    void *q;
    void *r;

    TEST("mremap shrink keeps dirty private prefix");
    if (!make_seed_file(len, &ro, &rw)) {
        FAIL("seed file");
        return;
    }
    p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(ro);
        close(rw);
        return;
    }
    fill_dirty(p, len);

    /* Keep a free destination for the forced move below. */
    reserve = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reserve == MAP_FAILED) {
        FAIL("reserve");
        munmap(p, len);
        close(ro);
        close(rw);
        return;
    }
    munmap(reserve, len);

    q = mremap(p, len, shrink, 0);
    if (q == MAP_FAILED) {
        FAIL("mremap shrink");
        munmap(p, len);
        close(ro);
        close(rw);
        return;
    }
    EXPECT_TRUE(matches_dirty(q, shrink),
                "shrink lost the dirty private prefix");

    TEST("mremap grow/move keeps dirty private data");
    r = mremap(q, shrink, len, MREMAP_MAYMOVE | MREMAP_FIXED, reserve);
    if (r == MAP_FAILED) {
        FAIL("mremap move");
        munmap(q, shrink);
        close(ro);
        close(rw);
        return;
    }
    EXPECT_TRUE(matches_dirty(r, shrink), "move lost the dirty private prefix");

    munmap(r, len);
    close(ro);
    close(rw);
}

static void private_fork_child(unsigned char *p,
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
    if (n == 1 && matches_dirty(p, len))
        report = 1;
    do {
        n = write(report_fd, &report, 1);
    } while (n < 0 && errno == EINTR);
    close(sync_fd);
    close(report_fd);
    _exit(n == 1 ? 0 : 1);
}

/* The parent overwrites the original file after fork. Both private views keep
 * the bytes they dirtied before the fork.
 */
static void test_fork_private_view(const map_shape_t *shape)
{
    size_t file_len = 16 * page_size;
    char label[80];
    int ro = -1, rw = -1;
    int sync_pipe[2];
    int report_pipe[2];
    unsigned char *p;
    unsigned char token = 0x5A;
    unsigned char report = 0;
    int status = 0;
    ssize_t n = 0;
    ssize_t report_n = 0;
    bool overwritten;
    bool reaped;
    pid_t child;

    make_label(label, sizeof(label), "fork keeps dirty private view", shape);
    TEST(label);
    if (!make_seed_file(file_len, &ro, &rw)) {
        FAIL("seed file");
        return;
    }
    p = mmap(NULL, shape->len, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro,
             (off_t) shape->off);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(ro);
        close(rw);
        return;
    }
    fill_dirty(p, shape->len);
    if (pipe(sync_pipe) != 0) {
        FAIL("pipe");
        munmap(p, shape->len);
        close(ro);
        close(rw);
        return;
    }
    if (pipe(report_pipe) != 0) {
        FAIL("pipe");
        close(sync_pipe[0]);
        close(sync_pipe[1]);
        munmap(p, shape->len);
        close(ro);
        close(rw);
        return;
    }

    child = fork();
    if (child == 0) {
        close(sync_pipe[1]);
        close(report_pipe[0]);
        private_fork_child(p, shape->len, sync_pipe[0], report_pipe[1]);
    }
    close(sync_pipe[0]);
    close(report_pipe[1]);
    if (child < 0) {
        close(sync_pipe[1]);
        close(report_pipe[0]);
        FAIL("fork");
        munmap(p, shape->len);
        close(ro);
        close(rw);
        return;
    }

    overwritten = overwrite_file(rw, file_len, 0x5A);
    do {
        n = write(sync_pipe[1], &token, 1);
    } while (n < 0 && errno == EINTR);
    close(sync_pipe[1]);
    do {
        report_n = read(report_pipe[0], &report, 1);
    } while (report_n < 0 && errno == EINTR);
    close(report_pipe[0]);
    reaped = waitpid(child, &status, 0) == child;
    EXPECT_TRUE(overwritten && n == 1 && reaped && report_n == 1 && report == 1,
                "child lost its private view after the file changed");

    TEST("parent keeps dirty private file view");
    EXPECT_TRUE(overwritten && matches_dirty(p, shape->len),
                "parent private view changed with the file");

    munmap(p, shape->len);
    close(ro);
    close(rw);
}

/* Permission revocation does not discard file-backed private bytes. */
static void test_prot_none_regrant(const map_shape_t *shape)
{
    size_t file_len = 16 * page_size;
    char label[80];
    int ro = -1, rw = -1;
    unsigned char *p;
    bool ok;

    make_label(label, sizeof(label), "PROT_NONE regrant keeps bytes", shape);
    TEST(label);
    if (!make_seed_file(file_len, &ro, &rw)) {
        FAIL("seed file");
        return;
    }
    p = mmap(NULL, shape->len, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro,
             (off_t) shape->off);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(ro);
        close(rw);
        return;
    }
    fill_dirty(p, shape->len);
    ok = mprotect(p, shape->len, PROT_NONE) == 0 &&
         mprotect(p, shape->len, PROT_READ | PROT_WRITE) == 0;
    ok = ok && matches_dirty(p, shape->len) && file_matches_seed(rw, file_len);
    EXPECT_TRUE(ok, "PROT_NONE round trip lost private bytes");

    munmap(p, shape->len);
    close(ro);
    close(rw);
}

/* The bytes between EOF and the end of its last file page read zero. A whole
 * page past EOF is not touched, because that faults and the fault path is not
 * part of this test.
 */
static void test_eof_tail_zero(const map_shape_t *shape)
{
    size_t full_pages = shape->off == 0 ? 4 : 1;
    size_t file_len = shape->off + full_pages * page_size + 123;
    char label[80];
    int ro = -1, rw = -1;
    unsigned char *p;
    bool ok;

    make_label(label, sizeof(label), "EOF tail inside last page is zero",
               shape);
    TEST(label);
    if (!make_seed_file(file_len, &ro, &rw)) {
        FAIL("seed file");
        return;
    }
    p = mmap(NULL, shape->len, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro,
             (off_t) shape->off);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(ro);
        close(rw);
        return;
    }
    ok = matches_seed(p, shape->off, full_pages * page_size) &&
         matches_seed(p + full_pages * page_size,
                      shape->off + full_pages * page_size, 123) &&
         all_zero(p + full_pages * page_size + 123, page_size - 123);
    EXPECT_TRUE(ok, "EOF tail kept stale or private bytes");

    munmap(p, shape->len);
    close(ro);
    close(rw);
}

/* A fresh private mapping is a syscall buffer before it is a guest buffer.
 * write() must copy out the file image with no prior guest load, and read()
 * must deposit its bytes without consulting the file again. The descriptor is
 * read-only, so both prove MAP_PRIVATE supplies PROT_WRITE.
 */
static void test_untouched_mapping_io(const map_shape_t *shape)
{
    size_t file_len = 16 * page_size;
    char label[80];
    int ro = -1, rw = -1, src = -1, sink = -1;
    unsigned char *p;
    bool ok;

    make_label(label, sizeof(label), "write from untouched mapping", shape);
    TEST(label);
    if (!make_seed_file(file_len, &ro, &rw)) {
        FAIL("seed file");
        return;
    }
    if (!make_pattern_file(shape->len, io_byte, &src)) {
        FAIL("source file");
        close(ro);
        close(rw);
        return;
    }
    sink = make_temp_fd();
    if (sink < 0) {
        FAIL("sink file");
        close(src);
        close(ro);
        close(rw);
        return;
    }
    p = mmap(NULL, shape->len, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro,
             (off_t) shape->off);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(sink);
        close(src);
        close(ro);
        close(rw);
        return;
    }
    ok = write_all_from(sink, p, shape->len) &&
         fd_matches_seed_from(sink, 0, shape->off, shape->len) &&
         file_matches_seed(rw, file_len);
    EXPECT_TRUE(ok, "write() saw zero or private bytes before the first touch");
    munmap(p, shape->len);

    make_label(label, sizeof(label), "read into untouched mapping", shape);
    TEST(label);
    p = mmap(NULL, shape->len, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro,
             (off_t) shape->off);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(sink);
        close(src);
        close(ro);
        close(rw);
        return;
    }
    ok = read_all_into(src, p, shape->len) && matches_io(p, shape->len) &&
         fd_matches_io(src, 0, shape->len) && file_matches_seed(rw, file_len);
    EXPECT_TRUE(ok, "read() did not land in the untouched private mapping");

    munmap(p, shape->len);
    close(sink);
    close(src);
    close(ro);
    close(rw);
}

/* The bytes between EOF and the end of the file's last page are zero when the
 * same mapping is consumed by write() before any guest load. A whole page past
 * EOF is not mapped, because that faults on Linux.
 */
static void test_eof_tail_io(const map_shape_t *shape)
{
    size_t file_len = shape->off + 123;
    size_t map_len = page_size;
    char label[80];
    int ro = -1, rw = -1, sink = -1;
    unsigned char *p;
    bool ok;

    make_label(label, sizeof(label), "EOF tail feeds write()", shape);
    TEST(label);
    if (!make_seed_file(file_len, &ro, &rw)) {
        FAIL("seed file");
        return;
    }
    sink = make_temp_fd();
    if (sink < 0) {
        FAIL("sink file");
        close(ro);
        close(rw);
        return;
    }
    p = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro,
             (off_t) shape->off);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(sink);
        close(ro);
        close(rw);
        return;
    }
    ok = write_all_from(sink, p, map_len) &&
         fd_matches_seed_from(sink, 0, shape->off, 123) &&
         fd_all_zero_from(sink, 123, map_len - 123) &&
         file_matches_seed(rw, file_len);
    EXPECT_TRUE(ok, "EOF tail was not zero through write()");

    munmap(p, map_len);
    close(sink);
    close(ro);
    close(rw);
}

/* The child inherits a private file mapping that nobody has touched yet. Its
 * first access must still see the file image, its dirty pages must stay its
 * own, and the parent's untouched view must stay the file image after the child
 * has rewritten every byte.
 */
static void private_fork_untouched_child(unsigned char *p,
                                         size_t len,
                                         size_t file_off,
                                         int report_fd)
{
    unsigned char report = 0;
    ssize_t n;

    if (matches_seed(p, file_off, len))
        report = 1;
    fill_dirty(p, len);
    if (matches_dirty(p, len))
        report |= 2;
    do {
        n = write(report_fd, &report, 1);
    } while (n < 0 && errno == EINTR);
    close(report_fd);
    _exit(n == 1 && report == 3 ? 0 : 1);
}

static void test_fork_untouched_private(const map_shape_t *shape)
{
    size_t file_len = 16 * page_size;
    char label[80];
    int ro = -1, rw = -1;
    int report_pipe[2];
    unsigned char *p;
    unsigned char report = 0;
    int status = 0;
    ssize_t report_n = 0;
    bool reaped;
    bool ok;
    pid_t child;

    if (!make_seed_file(file_len, &ro, &rw)) {
        FAIL("seed file");
        return;
    }
    p = mmap(NULL, shape->len, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro,
             (off_t) shape->off);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(ro);
        close(rw);
        return;
    }
    if (pipe(report_pipe) != 0) {
        FAIL("pipe");
        munmap(p, shape->len);
        close(ro);
        close(rw);
        return;
    }

    child = fork();
    if (child == 0) {
        close(report_pipe[0]);
        private_fork_untouched_child(p, shape->len, shape->off, report_pipe[1]);
    }
    close(report_pipe[1]);
    if (child < 0) {
        close(report_pipe[0]);
        FAIL("fork");
        munmap(p, shape->len);
        close(ro);
        close(rw);
        return;
    }

    do {
        report_n = read(report_pipe[0], &report, 1);
    } while (report_n < 0 && errno == EINTR);
    close(report_pipe[0]);
    reaped = waitpid(child, &status, 0) == child;

    make_label(label, sizeof(label), "child sees untouched private file view",
               shape);
    TEST(label);
    EXPECT_TRUE(reaped && report_n == 1 && (report & 1) != 0,
                "child did not see the file image in the untouched mapping");

    make_label(label, sizeof(label), "child dirty view stays private", shape);
    TEST(label);
    EXPECT_TRUE(reaped && report_n == 1 && (report & 2) != 0,
                "child rewrite was not stable in its own private view");

    make_label(label, sizeof(label), "parent untouched mapping ignores child",
               shape);
    TEST(label);
    ok = matches_seed(p, shape->off, shape->len) &&
         file_matches_seed(rw, file_len);
    EXPECT_TRUE(ok, "child private write leaked into the parent mapping");

    make_label(label, sizeof(label), "parent write private after child fork",
               shape);
    TEST(label);
    fill_dirty(p, shape->len);
    ok = matches_dirty(p, shape->len) && file_matches_seed(rw, file_len);
    EXPECT_TRUE(ok, "parent private write reached the file");

    munmap(p, shape->len);
    close(ro);
    close(rw);
}

/* A PROT_NONE mapping is not a usable syscall buffer on Linux. Both directions
 * must return EFAULT before any byte is transferred, and mprotect must make the
 * file image and private writes usable again.
 */
static void test_prot_none_io_efault(const map_shape_t *shape)
{
    size_t file_len = 16 * page_size;
    char label[80];
    int ro = -1, rw = -1, src = -1, sink = -1;
    unsigned char *p;
    ssize_t n;
    bool ok;

    if (!make_seed_file(file_len, &ro, &rw)) {
        FAIL("seed file");
        return;
    }
    if (!make_pattern_file(shape->len, io_byte, &src)) {
        FAIL("source file");
        close(ro);
        close(rw);
        return;
    }
    sink = make_temp_fd();
    if (sink < 0) {
        FAIL("sink file");
        close(src);
        close(ro);
        close(rw);
        return;
    }
    p = mmap(NULL, shape->len, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro,
             (off_t) shape->off);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(sink);
        close(src);
        close(ro);
        close(rw);
        return;
    }
    if (mprotect(p, shape->len, PROT_NONE) != 0) {
        FAIL("mprotect PROT_NONE");
        munmap(p, shape->len);
        close(sink);
        close(src);
        close(ro);
        close(rw);
        return;
    }

    make_label(label, sizeof(label), "read into PROT_NONE mapping faults",
               shape);
    TEST(label);
    errno = 0;
    n = read(src, p, shape->len);
    EXPECT_TRUE(n == -1 && errno == EFAULT,
                "read() into PROT_NONE did not return EFAULT");

    make_label(label, sizeof(label), "write from PROT_NONE mapping faults",
               shape);
    TEST(label);
    errno = 0;
    n = write(sink, p, shape->len);
    EXPECT_TRUE(n == -1 && errno == EFAULT,
                "write() from PROT_NONE did not return EFAULT");

    make_label(label, sizeof(label), "PROT_NONE regrant accepts write()",
               shape);
    TEST(label);
    ok = mprotect(p, shape->len, PROT_READ | PROT_WRITE) == 0 &&
         write_all_from(sink, p, shape->len) &&
         fd_matches_seed_from(sink, 0, shape->off, shape->len) &&
         file_matches_seed(rw, file_len);
    EXPECT_TRUE(ok, "regranted mapping did not feed write()");

    make_label(label, sizeof(label), "PROT_NONE regrant accepts read()", shape);
    TEST(label);
    ok = read_all_into(src, p, shape->len) && matches_io(p, shape->len) &&
         fd_matches_io(src, 0, shape->len) && file_matches_seed(rw, file_len);
    EXPECT_TRUE(ok, "regranted mapping did not receive read()");

    munmap(p, shape->len);
    close(sink);
    close(src);
    close(ro);
    close(rw);
}

/* A fresh sparse file has no page-cache pages, so a private 64 MiB mapping that
 * nobody has touched must report every guest page absent. This measures the
 * backing state rather than the mapped VA range.
 */
static void test_untouched_file_mapping_absent(void)
{
    char path[] = "/tmp/elfuse-mmap-private-XXXXXX";
    unsigned char vec[UNTOUCHED_MAP_PAGES];
    unsigned char *p;
    long rc;
    bool ok;
    int fd = mkstemp(path);

    TEST("64MiB untouched sparse file mapping is absent");
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }
    unlink(path);
    if (ftruncate(fd, (off_t) UNTOUCHED_MAP_LEN) != 0) {
        FAIL("ftruncate");
        close(fd);
        return;
    }
    p = mmap(NULL, UNTOUCHED_MAP_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd,
             0);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(fd);
        return;
    }
    memset(vec, 0xff, sizeof(vec));
    errno = 0;
    rc = syscall(SYS_mincore, p, UNTOUCHED_MAP_LEN, vec);
    ok = rc == 0;
    for (size_t i = 0; ok && i < UNTOUCHED_MAP_PAGES; i++) {
        if ((vec[i] & 1) != 0)
            ok = false;
    }
    EXPECT_TRUE(ok, "untouched file mapping reported resident pages");

    munmap(p, UNTOUCHED_MAP_LEN);
    close(fd);
}

/* A large untouched file mapping must also work as a syscall buffer. Revoking
 * access with PROT_NONE rejects both directions until mprotect regrants it.
 */
static void test_untouched_large_mapping_io(void)
{
    char path[] = "/tmp/elfuse-mmap-private-XXXXXX";
    int fd = -1, src = -1, sink = -1;
    unsigned char *p;
    ssize_t n;
    bool ok;

    TEST("64MiB untouched mapping feeds write()");
    fd = mkstemp(path);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }
    unlink(path);
    ok = ftruncate(fd, (off_t) UNTOUCHED_MAP_LEN) == 0 &&
         write_pattern_at(fd, 0, UNTOUCHED_BLOCK, io_byte);
    if (!ok) {
        FAIL("large data file");
        close(fd);
        return;
    }
    if (!make_pattern_file(UNTOUCHED_BLOCK, io_byte, &src)) {
        FAIL("source file");
        close(fd);
        return;
    }
    sink = make_temp_fd();
    if (sink < 0) {
        FAIL("sink file");
        close(src);
        close(fd);
        return;
    }
    p = mmap(NULL, UNTOUCHED_MAP_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd,
             0);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(sink);
        close(src);
        close(fd);
        return;
    }
    ok = write_all_from(sink, p, UNTOUCHED_BLOCK) &&
         fd_matches_from(sink, 0, UNTOUCHED_BLOCK, io_byte, 0) &&
         fd_matches_from(fd, 0, UNTOUCHED_BLOCK, io_byte, 0);
    EXPECT_TRUE(ok, "write() did not resolve the untouched 2MiB block");
    munmap(p, UNTOUCHED_MAP_LEN);

    TEST("64MiB untouched mapping receives read()");
    p = mmap(NULL, UNTOUCHED_MAP_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd,
             0);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(sink);
        close(src);
        close(fd);
        return;
    }
    ok = read_all_into(src, p + UNTOUCHED_MAP_LEN / 2, UNTOUCHED_BLOCK) &&
         matches_io(p + UNTOUCHED_MAP_LEN / 2, UNTOUCHED_BLOCK) &&
         fd_matches_from(fd, 0, UNTOUCHED_BLOCK, io_byte, 0);
    EXPECT_TRUE(ok, "read() did not resolve the untouched 2MiB block");
    munmap(p, UNTOUCHED_MAP_LEN);

    TEST("64MiB PROT_NONE mapping rejects IO");
    p = mmap(NULL, UNTOUCHED_MAP_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd,
             0);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(sink);
        close(src);
        close(fd);
        return;
    }
    if (mprotect(p, UNTOUCHED_MAP_LEN, PROT_NONE) != 0) {
        FAIL("mprotect PROT_NONE");
        munmap(p, UNTOUCHED_MAP_LEN);
        close(sink);
        close(src);
        close(fd);
        return;
    }
    ok = lseek(src, 0, SEEK_SET) == 0 && lseek(sink, 0, SEEK_SET) == 0;
    errno = 0;
    n = read(src, p, page_size);
    ok = ok && n == -1 && errno == EFAULT;
    errno = 0;
    n = write(sink, p, page_size);
    ok = ok && n == -1 && errno == EFAULT;
    EXPECT_TRUE(ok, "large PROT_NONE mapping accepted kernel IO");

    TEST("64MiB PROT_NONE regrant accepts IO");
    ok = mprotect(p, UNTOUCHED_MAP_LEN, PROT_READ | PROT_WRITE) == 0 &&
         write_all_from(sink, p, page_size) &&
         fd_matches_from(sink, 0, page_size, io_byte, 0) &&
         read_all_into(src, p + UNTOUCHED_MAP_LEN / 2, page_size) &&
         matches_io(p + UNTOUCHED_MAP_LEN / 2, page_size) &&
         fd_matches_from(fd, 0, page_size, io_byte, 0);
    EXPECT_TRUE(ok, "regranted 64MiB mapping rejected kernel IO");

    munmap(p, UNTOUCHED_MAP_LEN);
    close(sink);
    close(src);
    close(fd);
}

static sigjmp_buf eof_recover;
static volatile sig_atomic_t eof_signal;
static volatile sig_atomic_t eof_code;

static void eof_handler(int sig, siginfo_t *info, void *context)
{
    (void) context;
    eof_signal = sig;
    eof_code = info->si_code;
    siglongjmp(eof_recover, 1);
}

/* ELF loaders reserve the entire DSO before replacing a data segment whose
 * virtual address differs from its file offset by a segment-alignment gap.
 */
static void test_elf_segment_replacement(void)
{
    const size_t file_len = 4 * page_size + 123;
    const size_t map_len = 12 * page_size;
    struct sigaction action = {.sa_sigaction = eof_handler,
                               .sa_flags = SA_SIGINFO};
    struct sigaction old_bus, old_segv;
    int ro = -1, rw = -1;
    unsigned char *p;

    TEST("ELF data segment replaces past EOF");
    if (!make_seed_file(file_len, &ro, &rw)) {
        FAIL("seed file");
        return;
    }
    p = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        goto close_files;
    }
    p[0] = 0xe7;
    unsigned char *data =
        mmap(p + 9 * page_size, 2 * page_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_FIXED, ro, 3 * page_size);
    EXPECT_TRUE(data == p + 9 * page_size &&
                    matches_seed(data, 3 * page_size, page_size + 123) &&
                    all_zero(data + page_size + 123, page_size - 123) &&
                    p[0] == 0xe7 && file_matches_seed(rw, file_len),
                "ELF segment bytes or private neighbour lost");

    sigemptyset(&action.sa_mask);
    sigaction(SIGBUS, &action, &old_bus);
    sigaction(SIGSEGV, &action, &old_segv);
    TEST("unreplaced EOF page remains SIGBUS");
    eof_signal = 0;
    eof_code = 0;
    if (sigsetjmp(eof_recover, 1) == 0) {
        volatile unsigned char value = p[8 * page_size];
        (void) value;
    }
    EXPECT_TRUE(eof_signal == SIGBUS && eof_code == BUS_ADRERR,
                "EOF page lost SIGBUS semantics");
    TEST("EOF page stays faulting after mprotect");
    bool protected =
        mprotect(p + 8 * page_size, page_size, PROT_NONE) == 0 &&
        mprotect(p + 8 * page_size, page_size, PROT_READ | PROT_WRITE) == 0;
    eof_signal = 0;
    eof_code = 0;
    if (protected && sigsetjmp(eof_recover, 1) == 0) {
        volatile unsigned char value = p[8 * page_size];
        (void) value;
    }
    EXPECT_TRUE(protected && eof_signal == SIGBUS && eof_code == BUS_ADRERR,
                "mprotect exposed an EOF page");

    TEST("ELF replacement preserves dirty EOF tail");
    p[4 * page_size + 100] = 0xd3;
    p[4 * page_size + 200] = 0xd4;
    data = mmap(p + 5 * page_size, 2 * page_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_FIXED, ro, 3 * page_size);
    EXPECT_TRUE(data == p + 5 * page_size &&
                    matches_seed(data, 3 * page_size, page_size + 123) &&
                    all_zero(data + page_size + 123, page_size - 123) &&
                    p[4 * page_size + 100] == 0xd3 &&
                    p[4 * page_size + 200] == 0xd4 &&
                    file_matches_seed(rw, file_len),
                "ELF replacement lost a dirty neighbouring page");
    TEST("trailing EOF page remains SIGBUS");
    eof_signal = 0;
    eof_code = 0;
    if (sigsetjmp(eof_recover, 1) == 0) {
        volatile unsigned char value = p[7 * page_size];
        (void) value;
    }
    EXPECT_TRUE(eof_signal == SIGBUS && eof_code == BUS_ADRERR,
                "trailing EOF page became accessible");
    sigaction(SIGBUS, &old_bus, NULL);
    sigaction(SIGSEGV, &old_segv, NULL);
    munmap(p, map_len);
close_files:
    close(ro);
    close(rw);
}

/* Untouched EOF pages are valid VMA coverage, but have no backing to copy into
 * a fork snapshot. Dirty bytes in the last file page still belong to the child.
 */
static void test_fork_eof_mapping(void)
{
    const size_t file_len = 4 * page_size + 123;
    const size_t map_len = 12 * page_size;
    int ro = -1, rw = -1, status = 0;
    struct sigaction action = {.sa_sigaction = eof_handler,
                               .sa_flags = SA_SIGINFO};
    struct sigaction old_bus, old_segv;

    TEST("fork preserves private file EOF");
    if (!make_seed_file(file_len, &ro, &rw)) {
        FAIL("seed file");
        return;
    }
    unsigned char *p =
        mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap private");
        close(ro);
        close(rw);
        return;
    }
    p[0] = 0xe7;
    p[4 * page_size + 200] = 0xd4;
    sigemptyset(&action.sa_mask);
    sigaction(SIGBUS, &action, &old_bus);
    sigaction(SIGSEGV, &action, &old_segv);
    pid_t child = fork();
    if (child == 0) {
        if (p[0] != 0xe7 || p[4 * page_size + 200] != 0xd4 ||
            !matches_seed(p + page_size, page_size, 3 * page_size + 123))
            _exit(2);
        eof_signal = 0;
        eof_code = 0;
        if (sigsetjmp(eof_recover, 1) == 0) {
            volatile unsigned char value = p[8 * page_size];
            (void) value;
        }
        if (eof_signal != SIGBUS || eof_code != BUS_ADRERR)
            _exit(3);
        p[0] = 0xa1;
        _exit(0);
    }
    bool ok = child > 0 && waitpid(child, &status, 0) == child &&
              WIFEXITED(status) && WEXITSTATUS(status) == 0 && p[0] == 0xe7 &&
              p[4 * page_size + 200] == 0xd4 && file_matches_seed(rw, file_len);
    EXPECT_TRUE(ok, "fork lost private bytes or EOF fault");
    sigaction(SIGBUS, &old_bus, NULL);
    sigaction(SIGSEGV, &old_segv, NULL);
    munmap(p, map_len);
    close(ro);
    close(rw);
}

int main(void)
{
    long host_page = sysconf(_SC_PAGESIZE);
    map_shape_t shapes[2];

    if (host_page <= 0) {
        printf("test-mmap-private: cannot read the guest page size\n");
        return 1;
    }
    page_size = (size_t) host_page;
    if (page_size != 4096) {
        printf("test-mmap-private: SKIP: guest page size %zu, need 4096\n",
               page_size);
        return 0;
    }

    edge_shape(&shapes[0]);
    aligned_shape(&shapes[1]);
    printf("test-mmap-private: private file mapping semantics\n");
    for (int i = 0; i < 2; i++) {
        test_private_write_is_private(&shapes[i]);
        test_untouched_mapping_io(&shapes[i]);
        test_dontneed_restores_file_page(&shapes[i]);
        test_munmap_middle_preserves(&shapes[i]);
        test_initial_prot_none_seeded(&shapes[i]);
        test_prot_none_io_efault(&shapes[i]);
        test_fork_private_view(&shapes[i]);
        test_fork_untouched_private(&shapes[i]);
        test_prot_none_regrant(&shapes[i]);
        test_eof_tail_zero(&shapes[i]);
        test_eof_tail_io(&shapes[i]);
    }
    test_untouched_file_mapping_absent();
    test_untouched_large_mapping_io();
    test_fork_eof_mapping();
    test_elf_segment_replacement();
    test_mremap_keeps_data();

    SUMMARY("test-mmap-private");
    return fails > 0 ? 1 : 0;
}
