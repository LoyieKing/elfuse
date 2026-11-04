/*
 * test-futex-shared-alias.c -- two MAP_SHARED mappings of one object.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FUTEX_WAIT on one mapping and FUTEX_WAKE on another must meet when both name
 * the same backing object and the same file offset. A wake that only hashes the
 * raw guest address answers 0 and leaves the waiter parked.
 *
 * The same object at a different offset, a different object, and a private
 * mapping of the same bytes must not meet. Every assertion is plain Linux futex
 * ABI, with the private flag left clear so the shared key is used.
 */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <linux/futex.h>
#include <sys/mman.h>

#include "raw-syscall.h"
#include "test-harness.h"

int passes = 0, fails = 0;

#ifndef SYS_memfd_create
#define SYS_memfd_create 279
#endif
#define LINUX_ETIMEDOUT 110

#define PAGE 4096
#define WAKE_TRIES 100000

static long futex_wait(uint32_t *word,
                       uint32_t expect,
                       const struct timespec *ts)
{
    return raw_syscall6(__NR_futex, (long) word, FUTEX_WAIT, expect, (long) ts,
                        0, 0);
}

static long futex_wake(uint32_t *word, int n)
{
    return raw_syscall6(__NR_futex, (long) word, FUTEX_WAKE, n, 0, 0, 0);
}

static int make_memfd(const char *name, size_t len)
{
    int fd = (int) syscall(SYS_memfd_create, name, 0);
    if (fd < 0)
        return -1;
    if (ftruncate(fd, (off_t) len) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

typedef struct {
    uint32_t *word;
    _Atomic int ready;
    long rc;
} wait_arg_t;

static void *wait_thread(void *arg)
{
    wait_arg_t *a = arg;
    struct timespec ts = {2, 0};
    atomic_store_explicit(&a->ready, 1, memory_order_release);
    a->rc = futex_wait(a->word, 0, &ts);
    return NULL;
}

/* Keep the word at the expected value until the wake has met the waiter. Then
 * store through the alias to check shared memory independently. A ready
 * handshake alone does not prove FUTEX_WAIT has enqueued the waiter.
 */
static int wake_alias(uint32_t *wait_word,
                      uint32_t *store_word,
                      uint32_t *wake_word,
                      long *wait_rc,
                      long *wake_rc)
{
    atomic_store_explicit((_Atomic uint32_t *) wait_word, 0,
                          memory_order_relaxed);
    wait_arg_t arg;
    atomic_init(&arg.ready, 0);
    arg.word = wait_word;
    arg.rc = -1;
    pthread_t th;
    if (pthread_create(&th, NULL, wait_thread, &arg) != 0)
        return -1;
    while (atomic_load_explicit(&arg.ready, memory_order_acquire) == 0)
        ;
    long woke = 0;
    for (int i = 0; i < WAKE_TRIES; i++) {
        woke = futex_wake(wake_word, 1);
        if (woke != 0)
            break;
    }
    atomic_store_explicit((_Atomic uint32_t *) store_word, 1,
                          memory_order_release);
    *wake_rc = woke;
    if (pthread_join(th, NULL) != 0)
        return -1;
    *wait_rc = arg.rc;
    return 0;
}

static void test_same_object_alias(void)
{
    TEST("shared alias of one memfd wakes");
    int fd = make_memfd("alias", PAGE);
    if (fd < 0) {
        FAIL("memfd_create");
        return;
    }
    uint32_t *a = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    uint32_t *b = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (a == MAP_FAILED || b == MAP_FAILED || a == b) {
        FAIL("mmap alias");
        close(fd);
        return;
    }
    long wait_rc = -1, wake_rc = -1;
    if (wake_alias(a, b, b, &wait_rc, &wake_rc) < 0) {
        FAIL("pthread");
    } else if (wake_rc == 1 && wait_rc == 0 && a[0] == 1) {
        PASS();
    } else {
        printf("FAIL: wake=%ld wait=%ld value=%u\n", wake_rc, wait_rc, a[0]);
        fails++;
    }
    munmap(a, PAGE);
    munmap(b, PAGE);
    close(fd);
}

static void test_offset_isolation(void)
{
    TEST("different offsets of one file stay apart");
    int fd = make_memfd("offsets", PAGE * 2);
    if (fd < 0) {
        FAIL("memfd_create");
        return;
    }
    uint32_t *lo = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    uint32_t *hi =
        mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, PAGE);
    if (lo == MAP_FAILED || hi == MAP_FAILED) {
        FAIL("mmap offsets");
        close(fd);
        return;
    }
    long wait_rc = -1, wake_rc = -1;
    if (wake_alias(lo, hi, hi, &wait_rc, &wake_rc) < 0) {
        FAIL("pthread");
    } else if (wake_rc == 0 && wait_rc == -LINUX_ETIMEDOUT && lo[0] == 0) {
        PASS();
    } else {
        printf("FAIL: wake=%ld wait=%ld value=%u\n", wake_rc, wait_rc, lo[0]);
        fails++;
    }
    munmap(lo, PAGE);
    munmap(hi, PAGE);
    close(fd);
}

static void test_different_file(void)
{
    TEST("two memfds do not share a queue");
    int fd_a = make_memfd("file-a", PAGE);
    int fd_b = make_memfd("file-b", PAGE);
    if (fd_a < 0 || fd_b < 0) {
        FAIL("memfd_create");
        if (fd_a >= 0)
            close(fd_a);
        if (fd_b >= 0)
            close(fd_b);
        return;
    }
    uint32_t *a = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd_a, 0);
    uint32_t *b = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd_b, 0);
    if (a == MAP_FAILED || b == MAP_FAILED) {
        FAIL("mmap files");
        close(fd_a);
        close(fd_b);
        return;
    }
    long wait_rc = -1, wake_rc = -1;
    if (wake_alias(a, b, b, &wait_rc, &wake_rc) < 0) {
        FAIL("pthread");
    } else if (wake_rc == 0 && wait_rc == -LINUX_ETIMEDOUT) {
        PASS();
    } else {
        printf("FAIL: wake=%ld wait=%ld\n", wake_rc, wait_rc);
        fails++;
    }
    munmap(a, PAGE);
    munmap(b, PAGE);
    close(fd_a);
    close(fd_b);
}

static void test_private_stays_private(void)
{
    TEST("private mapping is not the shared alias");
    int fd = make_memfd("private", PAGE);
    if (fd < 0) {
        FAIL("memfd_create");
        return;
    }
    uint32_t *shared =
        mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    uint32_t *priv =
        mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (shared == MAP_FAILED || priv == MAP_FAILED) {
        FAIL("mmap private");
        close(fd);
        return;
    }
    long wait_rc = -1, wake_rc = -1;
    if (wake_alias(shared, priv, priv, &wait_rc, &wake_rc) < 0) {
        FAIL("pthread");
    } else if (wake_rc == 0 && wait_rc == -LINUX_ETIMEDOUT && shared[0] == 0) {
        PASS();
    } else {
        printf("FAIL: wake=%ld wait=%ld value=%u\n", wake_rc, wait_rc,
               shared[0]);
        fails++;
    }
    munmap(shared, PAGE);
    munmap(priv, PAGE);
    close(fd);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_same_object_alias();
    test_offset_isolation();
    test_different_file();
    test_private_stays_private();
    SUMMARY("test-futex-shared-alias");
    return fails > 0 ? 1 : 0;
}
