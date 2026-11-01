/*
 * Read-only MAP_SHARED file overlay tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Regression lock-in for the file-overlay path in src/syscall/mem.c.
 *
 * A MAP_SHARED, PROT_READ mapping of a file opened O_RDONLY is extremely common
 * -- the JVM maps its ~135 MiB lib/modules image this way, and so do loaders
 * that map read-only data segments. The original overlay code always mmap'd the
 * host page PROT_READ|PROT_WRITE and mapped the HVF segment RWX, which fails
 * twice for a read-only fd: the host mmap returns EACCES (writable mapping of
 * an O_RDONLY fd) and, even forced to PROT_READ, hv_vm_map then fails because a
 * MAP_SHARED-of-O_RDONLY region has macOS max_protection=READ.
 *
 * Syscalls exercised: openat, ftruncate/pwrite, mmap, munmap, pread64
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* Several guest pages so the overlay spans more than one host page and the
 * containing 2 MiB segment is split and remapped over a realistic range. 768
 * pages (3 MiB) crosses a 2 MiB boundary so hvf_segment_split's multi-block
 * path is exercised, matching how JVM's ~135 MiB lib/modules image crosses many
 * segments.
 */
#define NPAGES 768
#define PGSZ ((size_t) 4096)
#define FILE_LEN (NPAGES * PGSZ)

/* Distinct byte per 4 KiB page so a partial or misaligned overlay is caught. */
static unsigned char page_marker(int page)
{
    return (unsigned char) (0x40 + (page % 64));
}

/* Create a file seeded with a per-page marker pattern, then close it.
 *
 * Returns the path in @out (caller-sized buffer).
 *
 * Returns 0 on success, -1 on error.
 */
static int make_seed_file(char *out, size_t out_sz)
{
    snprintf(out, out_sz, "/tmp/elfuse-mmap-ro-XXXXXX");
    int fd = mkstemp(out);
    if (fd < 0)
        return -1;
    for (int p = 0; p < NPAGES; p++) {
        unsigned char buf[PGSZ];
        memset(buf, page_marker(p), sizeof(buf));
        off_t foff = (off_t) p * (off_t) PGSZ;
        if (pwrite(fd, buf, sizeof(buf), foff) != (ssize_t) sizeof(buf)) {
            close(fd);
            unlink(out);
            return -1;
        }
    }
    close(fd);
    return 0;
}

/* The headline case: O_RDONLY fd + MAP_SHARED + PROT_READ must map and expose
 * the full file contents. This is exactly the JVM lib/modules pattern.
 */
static void test_rdonly_shared_read(const char *path)
{
    TEST("MAP_SHARED PROT_READ on O_RDONLY fd maps");

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        FAIL("open O_RDONLY failed");
        return;
    }

    unsigned char *p = mmap(NULL, FILE_LEN, PROT_READ, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap MAP_SHARED PROT_READ failed");
        close(fd);
        return;
    }

    bool ok = true;
    for (int pg = 0; pg < NPAGES && ok; pg++) {
        unsigned char want = page_marker(pg);
        for (int off = 0; off < PGSZ; off += 512) {
            if (p[pg * PGSZ + off] != want) {
                ok = false;
                break;
            }
        }
    }
    if (ok)
        PASS();
    else
        FAIL("mapped contents did not match file across pages");

    munmap(p, FILE_LEN);
    close(fd);
}

/* The same content must be readable back-to-back through a fresh mapping, and a
 * second concurrent read-only mapping of the same fd must also work.
 */
static void test_rdonly_shared_second_mapping(const char *path)
{
    TEST("second MAP_SHARED PROT_READ mapping maps");

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        FAIL("open O_RDONLY failed");
        return;
    }

    unsigned char *a = mmap(NULL, FILE_LEN, PROT_READ, MAP_SHARED, fd, 0);
    unsigned char *b = mmap(NULL, FILE_LEN, PROT_READ, MAP_SHARED, fd, 0);
    if (a == MAP_FAILED || b == MAP_FAILED) {
        FAIL("one of two MAP_SHARED PROT_READ mappings failed");
        if (a != MAP_FAILED)
            munmap(a, FILE_LEN);
        if (b != MAP_FAILED)
            munmap(b, FILE_LEN);
        close(fd);
        return;
    }

    if (a[0] == page_marker(0) && b[0] == page_marker(0) &&
        a[(NPAGES - 1) * PGSZ] == page_marker(NPAGES - 1) &&
        b[(NPAGES - 1) * PGSZ] == page_marker(NPAGES - 1))
        PASS();
    else
        FAIL("two concurrent read-only mappings disagree with file");

    munmap(a, FILE_LEN);
    munmap(b, FILE_LEN);
    close(fd);
}

/* A read-only mapping must stay read-only: requesting PROT_WRITE | MAP_SHARED
 * on an O_RDONLY fd is EACCES on Linux, and elfuse must surface the same errno
 * rather than silently succeeding (which the MAP_PRIVATE backing must not do).
 */
static void test_rdonly_shared_write_rejected(const char *path)
{
    TEST("MAP_SHARED PROT_WRITE on O_RDONLY fd is EACCES");

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        FAIL("open O_RDONLY failed");
        return;
    }

    void *p = mmap(NULL, FILE_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED && errno == EACCES) {
        PASS();
    } else {
        FAIL("writable shared mapping of O_RDONLY fd was not rejected");
        if (p != MAP_FAILED)
            munmap(p, FILE_LEN);
    }
    close(fd);
}

/* A read-only mapping taken from a writable (O_RDWR) fd must also work; this
 * exercises the MAP_SHARED-PROT_READ-on-writable-fd branch (max_protection RWX
 * so the segment maps without dropping to MAP_PRIVATE).
 */
static void test_rdwr_fd_readonly_mapping(const char *path)
{
    TEST("MAP_SHARED PROT_READ on O_RDWR fd maps");

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        FAIL("open O_RDWR failed");
        return;
    }

    unsigned char *p = mmap(NULL, FILE_LEN, PROT_READ, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap MAP_SHARED PROT_READ on O_RDWR fd failed");
        close(fd);
        return;
    }

    if (p[0] == page_marker(0) &&
        p[(NPAGES - 1) * PGSZ] == page_marker(NPAGES - 1))
        PASS();
    else
        FAIL("read-only mapping of O_RDWR fd did not match file");

    munmap(p, FILE_LEN);
    close(fd);
}

/* A read-only mapping's max_protection must stay READ: mprotect must not be
 * able to upgrade it to PROT_WRITE after the fact. Linux remembers max_prot
 * from the O_RDONLY fd at mmap time and rejects the upgrade with EACCES.
 */
static void test_rdonly_mprotect_write_rejected(const char *path)
{
    TEST("mprotect PROT_WRITE on read-only MAP_SHARED mapping is EACCES");

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        FAIL("open O_RDONLY failed");
        return;
    }

    unsigned char *p = mmap(NULL, FILE_LEN, PROT_READ, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap MAP_SHARED PROT_READ failed");
        close(fd);
        return;
    }

    int rc = mprotect(p, FILE_LEN, PROT_READ | PROT_WRITE);
    if (rc == -1 && errno == EACCES)
        PASS();
    else
        FAIL("mprotect PROT_WRITE upgrade was not rejected");

    munmap(p, FILE_LEN);
    close(fd);
}

static void test_rdonly_shared_fixed(const char *path)
{
    const size_t len = 8 * PGSZ;
    unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int fd = open(path, O_RDONLY);
    if (p == MAP_FAILED || fd < 0) {
        FAIL("setup fixed mapping");
        if (p != MAP_FAILED)
            munmap(p, len);
        if (fd >= 0)
            close(fd);
        return;
    }
    p[0] = 0xe7;
    TEST("fixed shared write on read-only fd preserves old bytes");
    EXPECT_ERRNO(
        mmap(p, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0),
        EACCES, "writable mapping accepted read-only backing");
    EXPECT_TRUE(p[0] == 0xe7, "failed fixed mmap destroyed original bytes");
    TEST("fixed read-only shared mapping keeps bytes");
    unsigned char *mapped =
        mmap(p, len, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0);
    EXPECT_TRUE(
        mapped == p && p[0] == page_marker(0) && p[7 * PGSZ] == page_marker(7),
        "fixed read-only file mapping failed");
    TEST("fixed read-only shared rejects write regrant");
    EXPECT_ERRNO(mprotect(p, len, PROT_READ | PROT_WRITE), EACCES,
                 "write regrant accepted read-only backing");
    munmap(p, len);
    close(fd);
}

int main(void)
{
    printf("test-mmap-shared-ro: read-only MAP_SHARED file overlay tests\n\n");

    char path[64];
    if (make_seed_file(path, sizeof(path)) != 0) {
        printf("  %-30s FAIL: could not create seed file (errno=%d)\n", "setup",
               errno);
        return 1;
    }

    test_rdonly_shared_read(path);
    test_rdonly_shared_second_mapping(path);
    test_rdonly_shared_write_rejected(path);
    test_rdwr_fd_readonly_mapping(path);
    test_rdonly_mprotect_write_rejected(path);
    test_rdonly_shared_fixed(path);

    unlink(path);

    SUMMARY("test-mmap-shared-ro");
    return fails ? 1 : 0;
}
