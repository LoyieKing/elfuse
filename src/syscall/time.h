/*
 * Time and timer syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Clock, nanosleep, gettimeofday, and interval timer operations. Translates
 * Linux clock IDs to macOS wall clocks; CPU clocks are served from the
 * scheduler ledger, and interval timers are emulated internally.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "core/guest.h"
#include "syscall/linux-wire.h"

/* Linux dynamic CPU clock IDs (kernel/time/posix-cpu-timers.c):
 *
 *   clockid = ((~(pid)) << 3) | type | (perthread ? 4 : 0)
 *
 * type is PROF=0 (user+system), VIRT=1 (user only) or SCHED=2 (total runtime).
 * pid 0 means the calling task/process. The three static IDs
 * CLOCK_PROCESS_CPUTIME_ID (2) and CLOCK_THREAD_CPUTIME_ID (3) name SCHED.
 *
 * Linux encodes the dynamic-pid clock as ((~pid) << 3) | type. Decoding is
 * ~clockid >> 3, but >> on a signed negative value is implementation-defined.
 */
#define LINUX_CPUCLOCK_PERTHREAD_MASK 4
#define LINUX_CPUCLOCK_PROF 0
#define LINUX_CPUCLOCK_VIRT 1
#define LINUX_CPUCLOCK_SCHED 2
#define LINUX_CPUCLOCK_PID(clk) ((int32_t) (~(unsigned int) (clk)) >> 3)

/* Decode a Linux CPU clock ID.
 *
 * Returns false for wall clocks and for a dynamic ID whose reserved type bits
 * are set. A dynamic ID whose target names a task outside this VM's thread
 * group is still decoded here; callers validate the target in their own domain.
 */
bool linux_cpuclock_decode(int clockid,
                           int *type,
                           bool *per_thread,
                           int32_t *target);

/* Return true when a guest-supplied timespec is well-formed: non-negative
 * seconds and a nanosecond field in [0, NSEC_PER_SEC). Mirrors the kernel
 * hrtimer validation shared by the timeout-bearing syscalls.
 */
bool linux_timespec_valid(const linux_timespec_t *ts);

/* Convert a validated guest timespec to a nanosecond count, saturating to
 * INT64_MAX on overflow rather than wrapping. A negative tv_sec yields 0.
 */
int64_t linux_timespec_to_ns_sat(const linux_timespec_t *ts);

/* Time/timer syscall handlers. */

int64_t sys_clock_getres(guest_t *g, int clockid, uint64_t tp_gva);
int64_t sys_clock_gettime(guest_t *g, int clockid, uint64_t tp_gva);
int64_t sys_nanosleep(guest_t *g, uint64_t req_gva, uint64_t rem_gva);
int64_t sys_clock_nanosleep(guest_t *g,
                            int clockid,
                            int flags,
                            uint64_t req_gva,
                            uint64_t rem_gva);
int64_t sys_gettimeofday(guest_t *g, uint64_t tv_gva, uint64_t tz_gva);
int64_t sys_times(guest_t *g, uint64_t buf_gva);
int64_t sys_setitimer(guest_t *g,
                      int which,
                      uint64_t new_gva,
                      uint64_t old_gva);
int64_t sys_getitimer(guest_t *g, int which, uint64_t val_gva);
int64_t sys_timer_create(guest_t *g,
                         int clockid,
                         uint64_t event_gva,
                         uint64_t id_gva);
int64_t sys_timer_gettime(guest_t *g, int id, uint64_t value_gva);
int64_t sys_timer_settime(guest_t *g,
                          int id,
                          int flags,
                          uint64_t value_gva,
                          uint64_t old_gva);

struct thread_entry;

/* Async park (pool unmount) completion for nanosleep / clock_nanosleep. */
void sleep_park_on_deadline(struct thread_entry *t);
void sleep_park_on_interrupt(struct thread_entry *t);

/* Owner-worker hook: perform the guest write of a remaining sleep interval that
 * an async park completion recorded on the task. Wakers and the slice timer
 * never write guest memory (fork snapshot serializes guest mutations).
 * Returns 0, or -LINUX_EFAULT when the guest pointer is invalid; the caller
 * then publishes EFAULT in place of the park result. Consumes the pending
 * write.
 */
int sleep_park_apply_pending(struct thread_entry *t, guest_t *g);

/* Soft-accept adjtimex / clock_adjtime: report a stable (freq=0, tick=10000)
 * clock state so skew kselftests can compare MONOTONIC vs MONOTONIC_RAW. Modes
 * that would change the host clock are rejected with EPERM.
 */
int64_t sys_adjtimex(guest_t *g, uint64_t tx_gva);
int64_t sys_clock_adjtime(guest_t *g, int clockid, uint64_t tx_gva);
