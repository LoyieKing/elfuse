/*
 * pidfd helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "core/guest.h"
#include "runtime/sched/sched.h"

void pidfd_init(void);

/* Create a pidfd on @target_pid. @host_pid is the host process to watch for its
 * exit, or <= 0 when the target lives in this host process and so cannot be
 * watched (the caller itself, or a CLONE_VM child).
 */
int pidfd_create(guest_t *g, int64_t target_pid, pid_t host_pid);

/* Hold the registry entry for the description ofd_id across a dup, so a sibling
 * closing the source before the alias is published cannot retire it. pidfd_pin
 * returns false when no entry names ofd_id any more; every true return is
 * balanced by pidfd_unpin once the alias is published or abandoned. Neither may
 * be called with fd_lock held.
 */
bool pidfd_pin(uint64_t ofd_id);
void pidfd_unpin(uint64_t ofd_id);

/* What a fork child needs to rebuild one inherited pidfd description. */
typedef struct {
    int64_t target_pid; /* -1 when no registry entry names the description */
    int32_t host_pid;   /* the host process to watch, 0 for none */
    /* Nonzero once the write end is closed: the exit was reported, or the
     * monitor could not be armed, so the target may still be alive.
     */
    int32_t exited;
} pidfd_fork_state_t;

/* Caller holds fd_lock, which keeps the description named by ofd_id live. */
void pidfd_fork_snapshot_locked(uint64_t ofd_id, pidfd_fork_state_t *out);

/* Fork child: rebuild the pidfd at guest_fd with its own pipe, registry entry
 * and monitor. Further aliases of the same description dup the slot this
 * returns, so they share the entry.
 *
 * Returns guest_fd or a negative Linux errno.
 */
int pidfd_fork_restore(int guest_fd, const pidfd_fork_state_t *state);

void proc_pidfd_notify_exit(int64_t exited_pid);
void proc_pidfd_notify_exit_code(int64_t exited_pid, int status);
void proc_pidfd_notify_reaped(int64_t guest_pid, int status);
int64_t proc_pidfd_lookup_pid(int guest_fd);
bool proc_pidfd_is_nonblock(int guest_fd);
int64_t sys_pidfd_open(guest_t *g, int64_t pid, unsigned int flags);
int64_t sys_pidfd_send_signal(guest_t *g,
                              int pidfd,
                              int sig,
                              uint64_t info_gva,
                              unsigned int flags);

/* Snapshot Pid/NSpid for /proc/self/fdinfo on a pidfd.
 *
 * Returns true when @fd is a live pidfd; *pid_out is the target guest pid or -1
 * if it has exited.
 */
bool pidfd_fdinfo_snapshot(int guest_fd, int64_t *pid_out, bool *newpid_ns_out);

/* PIDFD_GET_INFO ioctl. */
int64_t pidfd_ioctl_get_info(guest_t *g, int guest_fd, uint64_t arg_gva);

int64_t sys_pidfd_getfd(guest_t *g,
                        int pidfd,
                        int targetfd,
                        unsigned int flags);

/* Drain pending cross-process pidfd_getfd requests for this host process.
 * Invoked from the guest-signal drain (SIGUSR2 / vCPU loop).
 */
void pidfd_getfd_drain(void);

/* Cross-process scheduling control
 *
 * Scheduler attributes are VM-local, so a fork backend is a different
 * scheduling domain. Attribute queries and updates for a task in another
 * backend use the same private inbox + SIGUSR2 + AF_UNIX reply transport as
 * pidfd_getfd, but carry no fd. This is a control-plane operation: it never
 * places the target on a run queue and never grants cross-VM capacity or
 * ordering.
 *
 * TIDs resolve through the fork-family thread map. Requests identify both the
 * owning thread group and the target task. Group/user priority sweeps remain
 * local to one VM; remote task-directed controls do not unify schedulers.
 */
#define PIDFD_SCHED_RPC_MAGIC 0x53434844U /* "SCHD" */

enum pidfd_sched_op {
    PIDFD_SCHED_OP_QUERY = 1,
    PIDFD_SCHED_OP_SET_ATTR = 2,
    PIDFD_SCHED_OP_SET_NICE = 3,
    PIDFD_SCHED_OP_SET_AFFINITY = 4,
};

typedef struct pidfd_sched_state {
    uint32_t magic;
    int32_t rc; /* 0, or negative Linux errno */
    sched_task_attrs_t attrs;
    uint32_t uid;
    uint32_t euid;
    uint32_t mask_len;
    uint64_t rr_interval_ns;
    uint64_t rlimit_nice;
    uint64_t rlimit_rtprio;
    uint8_t mask[SCHED_CPUSET_BYTES];
} pidfd_sched_state_t;

/* Query a task in another backend. Fills @out on success (rc 0). */
int64_t pidfd_sched_query(int64_t target_tid, pidfd_sched_state_t *out);
int64_t pidfd_sched_set_attr(int64_t target_tid,
                             const sched_task_attrs_t *attrs,
                             uint32_t requester_euid);
int64_t pidfd_sched_set_nice(int64_t target_tid,
                             int nice,
                             uint32_t requester_euid);
int64_t pidfd_sched_set_affinity(int64_t target_tid,
                                 const uint8_t *mask,
                                 size_t mask_len,
                                 uint32_t requester_euid);
