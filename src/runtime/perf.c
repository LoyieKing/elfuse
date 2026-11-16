/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Operation and byte increments are separate relaxed atomics; a sample may
 * observe the operation before its transferred bytes.
 */

#include <stdatomic.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "runtime/perf.h"
#include "runtime/thread.h"
#include "runtime/sched/sched.h"

_Atomic bool g_perf_enabled;

static _Atomic bool perf_fork_child;
static _Atomic uint64_t perf_epoch_ns;

typedef struct {
    _Atomic uint64_t disk_read_ops;
    _Atomic uint64_t disk_write_ops;
    _Atomic uint64_t disk_read_bytes;
    _Atomic uint64_t disk_write_bytes;
    _Atomic uint64_t network_read_ops;
    _Atomic uint64_t network_write_ops;
    _Atomic uint64_t network_read_bytes;
    _Atomic uint64_t network_write_bytes;
} perf_io_t;

static perf_io_t perf_io;

static uint64_t perf_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

void perf_enable(void)
{
    uint64_t zero = 0;
    uint64_t now = perf_now_ns();

    /* The first caller names the incarnation. A later call (the HUD started
     * twice) keeps the earlier stamp, so the generation does not drift.
     */
    (void) atomic_compare_exchange_strong_explicit(
        &perf_epoch_ns, &zero, now, memory_order_relaxed, memory_order_relaxed);
    atomic_store_explicit(&g_perf_enabled, true, memory_order_release);
}

void perf_mark_fork_child(void)
{
    atomic_store_explicit(&perf_fork_child, true, memory_order_relaxed);
}

bool perf_is_fork_child(void)
{
    return atomic_load_explicit(&perf_fork_child, memory_order_relaxed);
}

void perf_generation(char *out, size_t cap)
{
    uint64_t epoch = atomic_load_explicit(&perf_epoch_ns, memory_order_relaxed);

    if (cap == 0)
        return;
    if (epoch == 0) {
        epoch = perf_now_ns();
        atomic_store_explicit(&perf_epoch_ns, epoch, memory_order_relaxed);
    }
    (void) snprintf(out, cap, "%d-%llu", (int) getpid(),
                    (unsigned long long) epoch);
}

void perf_count(int io_class, bool is_read, uint64_t ops, uint64_t bytes)
{
    if (ops == 0)
        return;
    switch (io_class) {
    case PERF_IO_DISK:
        if (is_read) {
            atomic_fetch_add_explicit(&perf_io.disk_read_ops, ops,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&perf_io.disk_read_bytes, bytes,
                                      memory_order_relaxed);
        } else {
            atomic_fetch_add_explicit(&perf_io.disk_write_ops, ops,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&perf_io.disk_write_bytes, bytes,
                                      memory_order_relaxed);
        }
        break;
    case PERF_IO_NET_STREAM:
    case PERF_IO_NET_DGRAM:
        if (is_read) {
            atomic_fetch_add_explicit(&perf_io.network_read_ops, ops,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&perf_io.network_read_bytes, bytes,
                                      memory_order_relaxed);
        } else {
            atomic_fetch_add_explicit(&perf_io.network_write_ops, ops,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&perf_io.network_write_bytes, bytes,
                                      memory_order_relaxed);
        }
        break;
    default:
        break;
    }
}

perf_snapshot_t perf_sample(void)
{
    perf_snapshot_t s;

    /* Both thread counts are snapshots taken at slightly different instants. A
     * task that exits between them can leave active above total for one sample;
     * the reader is charting, not auditing.
     */
    s.threads_total = (uint64_t) thread_active_count();
    s.threads_active = (uint64_t) sched_active_count();
    s.disk_read_ops =
        atomic_load_explicit(&perf_io.disk_read_ops, memory_order_relaxed);
    s.disk_write_ops =
        atomic_load_explicit(&perf_io.disk_write_ops, memory_order_relaxed);
    s.disk_read_bytes =
        atomic_load_explicit(&perf_io.disk_read_bytes, memory_order_relaxed);
    s.disk_write_bytes =
        atomic_load_explicit(&perf_io.disk_write_bytes, memory_order_relaxed);
    s.network_read_ops =
        atomic_load_explicit(&perf_io.network_read_ops, memory_order_relaxed);
    s.network_write_ops =
        atomic_load_explicit(&perf_io.network_write_ops, memory_order_relaxed);
    s.network_read_bytes =
        atomic_load_explicit(&perf_io.network_read_bytes, memory_order_relaxed);
    s.network_write_bytes = atomic_load_explicit(&perf_io.network_write_bytes,
                                                 memory_order_relaxed);
    return s;
}
