/*
 * Guest performance counters for the HUD snapshot
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Per-process counters the HUD publisher samples every tick: live guest tasks,
 * runnable ones, and the host syscalls that moved bytes for a regular file or
 * an INET socket. Increments are gated on g_perf_enabled, so an elfuse started
 * without ELFUSE_HUD_STATS pays one relaxed load per counted syscall and
 * nothing at install time.
 *
 * The snapshot file layout below is also parsed by scripts/developer.py, which
 * mirrors the offsets by hand. Change both together.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

/* I/O class recorded on a guest fd when it is installed. Only these reach the
 * counters: a pipe, a TTY, a AF_UNIX socket, an abstract-namespace socket, a
 * netlink socket, a device, and every synthetic fd type are excluded because
 * they are IPC or not a file transfer.
 */
enum {
    PERF_IO_NONE = 0,
    PERF_IO_DISK,       /* regular file, including memfd backing */
    PERF_IO_NET_STREAM, /* AF_INET/AF_INET6 SOCK_STREAM or SOCK_SEQPACKET */
    PERF_IO_NET_DGRAM,  /* AF_INET/AF_INET6 SOCK_DGRAM */
};

typedef struct {
    uint64_t threads_total;
    uint64_t threads_active;
    uint64_t disk_read_ops;
    uint64_t disk_write_ops;
    uint64_t disk_read_bytes;
    uint64_t disk_write_bytes;
    uint64_t network_read_ops;
    uint64_t network_write_ops;
    uint64_t network_read_bytes;
    uint64_t network_write_bytes;
} perf_snapshot_t;

/* Mirror of the HUD file extension read by scripts/developer.py. The first 224
 * bytes of the file stay the CPU snapshot of vcpu_pool.c; everything below
 * starts at HUD_EXT_OFFSET.
 */
#define HUD_EXT_MAGIC 0x48555831u /* "HUX1" */
#define HUD_EXT_VERSION 2u
#define HUD_SNAP_BYTES 224u
#define HUD_EXT_OFFSET HUD_SNAP_BYTES
#define HUD_MAX_PROC 16
#define HUD_GENERATION_BYTES 48
#define HUD_SLOT_STALE_NS 5000000000ull

/* Set in hud_ext_header_t.flags when a process could not claim a row, so a
 * reader can report the snapshot as incomplete instead of showing the rows that
 * did fit. Written by any participant, never cleared while the file exists: a
 * process that never appeared cannot be inferred from its absence.
 */
#define HUD_EXT_FLAG_PROC_FULL 0x1u

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t slot_count;
    uint32_t slot_size;
    uint64_t sample_ns; /* CLOCK_MONOTONIC, root publisher's last tick */
    uint64_t wall_ns;   /* CLOCK_REALTIME taken with sample_ns */
    uint32_t flags;     /* HUD_EXT_FLAG_* */
    uint32_t reserved;
} hud_ext_header_t;

typedef struct {
    /* Seqlock shared with the reader: odd while the payload is being written,
     * even when stable. 32-bit and lock-free, so the statement holds across the
     * MAP_SHARED writers in this process and in its fork children.
     */
    uint32_t seq;
    uint32_t pad;
    uint64_t sample_ns;
    uint64_t threads_total;
    uint64_t threads_active;
    uint64_t disk_read_ops;
    uint64_t disk_write_ops;
    uint64_t disk_read_bytes;
    uint64_t disk_write_bytes;
    uint64_t network_read_ops;
    uint64_t network_write_ops;
    uint64_t network_read_bytes;
    uint64_t network_write_bytes;
    uint64_t guest_pid; /* guest namespace pid, informational */
    char generation[HUD_GENERATION_BYTES];
} hud_proc_slot_t;

#define HUD_SLOT_OFFSET (HUD_EXT_OFFSET + sizeof(hud_ext_header_t))
#define HUD_FILE_BYTES \
    (HUD_SLOT_OFFSET + (size_t) HUD_MAX_PROC * sizeof(hud_proc_slot_t))

_Static_assert(sizeof(hud_ext_header_t) == 40, "HUD extension header size");
_Static_assert(offsetof(hud_proc_slot_t, sample_ns) == 8,
               "HUD slot sample offset");
_Static_assert(offsetof(hud_proc_slot_t, generation) == 104,
               "HUD slot generation offset");
_Static_assert(sizeof(hud_proc_slot_t) == 152, "HUD slot size");
_Static_assert(ATOMIC_INT_LOCK_FREE == 2 &&
                   sizeof(_Atomic uint32_t) == sizeof(uint32_t) &&
                   _Alignof(_Atomic uint32_t) == _Alignof(uint32_t),
               "HUD sequence words must be layout-compatible and lock-free");

/* One relaxed load per counted syscall while instrumentation is off. */
extern _Atomic bool g_perf_enabled;

static inline bool perf_enabled(void)
{
    return atomic_load_explicit(&g_perf_enabled, memory_order_relaxed);
}

/* Turn accounting on. Called from the HUD publisher, which is the only reader
 * of these counters. The process start time is captured here, on first enable,
 * and names its snapshot generation.
 */
void perf_enable(void);

/* True when this process is an elfuse --fork-child instance. Its HUD role is to
 * publish a slot into the parent's snapshot, never the CPU prefix.
 */
void perf_mark_fork_child(void);
bool perf_is_fork_child(void);

/* Fills @out with "<hostpid>-<start_ns>" for this incarnation: the host pid
 * plus the start time captured by perf_enable, so a reused pid gets a fresh
 * generation.
 */
void perf_generation(char *out, size_t cap);

/* Account one completed syscall that moved @bytes. @ops is the number of
 * syscalls (1) or messages (sendmmsg/recvmmsg). A zero-byte datagram is an
 * operation with no bytes; a zero-byte stream or file transfer is not.
 */
void perf_count(int io_class, bool is_read, uint64_t ops, uint64_t bytes);

/* Consistency snapshot of every counter plus the live thread counts. */
perf_snapshot_t perf_sample(void);
