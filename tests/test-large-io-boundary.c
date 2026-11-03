/*
 * large I/O across guest page-table boundaries
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: read/write buffers crossing 2MiB L2 blocks and split L3 tables.
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

#define BLOCK_2MIB (2UL * 1024 * 1024)
#define MAP_SIZE (6UL * 1024 * 1024)
#define IO_OFFSET 12345UL
#define IO_SIZE (3UL * 1024 * 1024)

static unsigned char *next_2mb_boundary(unsigned char *p)
{
    uintptr_t addr = (uintptr_t) p;
    addr = (addr + BLOCK_2MIB - 1) & ~(uintptr_t) (BLOCK_2MIB - 1);
    return (unsigned char *) addr;
}

static int fill_file(int fd, const unsigned char *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t ret = write(fd, buf + done, len - done);
        if (ret <= 0)
            return -1;
        done += (size_t) ret;
    }
    return 0;
}

static int verify_pattern(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char want = (unsigned char) (i * 131U + 17U);
        if (buf[i] != want)
            return -1;
    }
    return 0;
}

/* Verify a repeating 4KiB seed pattern across a large buffer. The seed is:
 * seed[i] = (i * 131 + 17) for i in [0, 4096).
 */
static int verify_repeating_seed(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char want = (unsigned char) ((i % 4096) * 131U + 17U);
        if (buf[i] != want)
            return -1;
    }
    return 0;
}

static void test_large_write(void)
{
    TEST("write crosses 2MiB boundary");

    unsigned char *map = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    unsigned char *buf = next_2mb_boundary(map) + IO_OFFSET;
    for (size_t i = 0; i < IO_SIZE; i++)
        buf[i] = (unsigned char) (i * 131U + 17U);

    char path[] = "/tmp/elfuse-large-write-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        munmap(map, MAP_SIZE);
        FAIL("mkstemp failed");
        return;
    }
    unlink(path);

    ssize_t ret = write(fd, buf, IO_SIZE);
    int ok = (ret == (ssize_t) IO_SIZE);
    if (ok && lseek(fd, 0, SEEK_SET) != 0)
        ok = 0;

    /* Read back the entire write and verify all bytes, including those spanning
     * the 2MiB page table boundary.
     */
    unsigned char *readback = mmap(NULL, IO_SIZE, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ok && readback != MAP_FAILED) {
        ssize_t nr = read(fd, readback, IO_SIZE);
        if (nr != (ssize_t) IO_SIZE)
            ok = 0;
        if (ok && verify_pattern(readback, IO_SIZE) != 0)
            ok = 0;
        munmap(readback, IO_SIZE);
    } else {
        ok = 0;
    }

    close(fd);
    munmap(map, MAP_SIZE);

    EXPECT_TRUE(ok, "write returned short count or corrupted data");
}

static void test_large_read_from_split_block(void)
{
    TEST("read crosses split block");

    unsigned char *map = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    /* Force the first 2MiB block to remain split into L3 pages while ending
     * with RW permissions, then read across the L3-to-L2 boundary.
     */
    unsigned char *block = next_2mb_boundary(map);
    unsigned char *buf = block + IO_OFFSET;
    void *page = block + BLOCK_2MIB / 2;
    if (mprotect(page, 4096, PROT_READ) != 0 ||
        mprotect(page, 4096, PROT_READ | PROT_WRITE) != 0) {
        munmap(map, MAP_SIZE);
        FAIL("mprotect failed");
        return;
    }

    char path[] = "/tmp/elfuse-large-read-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        munmap(map, MAP_SIZE);
        FAIL("mkstemp failed");
        return;
    }
    unlink(path);

    unsigned char seed[4096];
    for (size_t i = 0; i < sizeof(seed); i++)
        seed[i] = (unsigned char) (i * 131U + 17U);

    bool ok = true;
    for (size_t done = 0; done < IO_SIZE; done += sizeof(seed)) {
        if (fill_file(fd, seed, sizeof(seed)) != 0) {
            ok = false;
            break;
        }
    }
    if (ok && lseek(fd, 0, SEEK_SET) != 0)
        ok = false;

    if (ok) {
        ssize_t ret = read(fd, buf, IO_SIZE);
        ok = (ret == (ssize_t) IO_SIZE);
    }

    /* Verify the entire read buffer, including the 2MiB boundary crossing where
     * L3-to-L2 page table transitions happen.
     */
    if (ok && verify_repeating_seed(buf, IO_SIZE) != 0)
        ok = false;

    close(fd);
    munmap(map, MAP_SIZE);

    EXPECT_TRUE(ok, "read returned short count or corrupted data");
}

static void test_urandom_read_crosses_boundary(void)
{
    TEST("/dev/urandom partial read at mapping boundary");

    size_t page = (size_t) sysconf(_SC_PAGESIZE);
    unsigned char *map = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }
    if (munmap(map + page, page) != 0) {
        munmap(map, page);
        FAIL("munmap guard failed");
        return;
    }

    memset(map, 0, page);

    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        munmap(map, page);
        FAIL("open failed");
        return;
    }

    ssize_t ret = read(fd, map, page * 2);
    close(fd);

    bool any_nonzero = false;
    for (size_t i = 0; i < page; i++) {
        if (map[i] != 0) {
            any_nonzero = true;
            break;
        }
    }

    munmap(map, page);
    EXPECT_TRUE(ret == (ssize_t) page && any_nonzero,
                "urandom read did not preserve partial boundary result");
}

static void test_urandom_small_read_crosses_boundary(void)
{
    TEST("/dev/urandom small read at mapping boundary");

    size_t page = (size_t) sysconf(_SC_PAGESIZE);
    unsigned char *map = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }
    if (munmap(map + page, page) != 0) {
        munmap(map, page);
        FAIL("munmap guard failed");
        return;
    }

    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        munmap(map, page);
        FAIL("open failed");
        return;
    }

    ssize_t ret = read(fd, map + page - 1, 2);
    close(fd);

    munmap(map, page);
    EXPECT_TRUE(ret == 1,
                "urandom small boundary read did not fall back safely");
}

static void test_revalidated_io_span(void)
{
    TEST("cached I/O span observes interior permission and mapping changes");
    const size_t page = (size_t) sysconf(_SC_PAGESIZE);
    unsigned char *map = mmap(NULL, 3 * page, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int fd = open("/dev/zero", O_RDONLY);
    if (map == MAP_FAILED || fd < 0) {
        if (map != MAP_FAILED)
            munmap(map, 3 * page);
        if (fd >= 0)
            close(fd);
        FAIL("setup failed");
        return;
    }
    bool ok = read(fd, map, 3 * page) == (ssize_t) (3 * page);
    ok = ok && mprotect(map + page, page, PROT_READ) == 0;
    ok = ok && read(fd, map, 3 * page) == (ssize_t) page;
    ok = ok && mprotect(map + page, page, PROT_READ | PROT_WRITE) == 0;
    ok = ok && read(fd, map, 3 * page) == (ssize_t) (3 * page);
    ok = ok && munmap(map + page, page) == 0;
    ok = ok && read(fd, map, 3 * page) == (ssize_t) page;
    close(fd);
    munmap(map, 3 * page);
    EXPECT_TRUE(ok,
                "I/O span retained revoked permissions or an unmapped page");
}

int main(void)
{
    printf("large I/O boundary tests\n\n");

    test_large_write();
    test_large_read_from_split_block();
    test_urandom_read_crosses_boundary();
    test_urandom_small_read_crosses_boundary();
    test_revalidated_io_span();

    SUMMARY("test-large-io-boundary");
    return fails ? 1 : 0;
}
