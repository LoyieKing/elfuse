/*
 * System V IPC syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * shmget, shmat, shmdt, shmctl, semget, semop, semctl, msgget, msgsnd, msgrcv,
 * msgctl. Translates Linux SysV IPC calls to macOS equivalents. shmat copies
 * data between host shm and guest memory (HVF cannot map host shm directly into
 * guest address space).
 */

#pragma once

#include <stdint.h>
#include "core/guest.h"

/* Shared memory handlers. */

int64_t sys_shmget(guest_t *g, int32_t key, uint64_t size, int shmflg);
int64_t sys_shmat(guest_t *g, int shmid, uint64_t shmaddr_gva, int shmflg);
int64_t sys_shmdt(guest_t *g, uint64_t shmaddr_gva);
int64_t sys_shmctl(guest_t *g, int shmid, int cmd, uint64_t buf_gva);

/* Semaphore handlers. */

int64_t sys_semget(guest_t *g, int32_t key, int nsems, int semflg);
int64_t sys_semop(guest_t *g, int semid, uint64_t sops_gva, unsigned nsops);
int64_t sys_semctl(guest_t *g, int semid, int semnum, int cmd, uint64_t arg);

/* Message queue handlers. */

int64_t sys_msgget(guest_t *g, int32_t key, int msgflg);
int64_t sys_msgsnd(guest_t *g,
                   int msqid,
                   uint64_t msgp_gva,
                   uint64_t msgsz,
                   int msgflg);
int64_t sys_msgrcv(guest_t *g,
                   int msqid,
                   uint64_t msgp_gva,
                   uint64_t msgsz,
                   int64_t msgtyp,
                   int msgflg);
int64_t sys_msgctl(guest_t *g, int msqid, int cmd, uint64_t buf_gva);

/* Drop guest SysV SHM shadows and IPC_RMID host segments we tracked. */

struct thread_entry;

/* Park callbacks for PARK_KIND_IPC. A local mutation reissues the parked probe
 * immediately; the deadline callback reissues a periodic re-check for a sibling
 * host process, and a signal completes -EINTR (semop/msgsnd/msgrcv are not
 * restartable).
 */
void sysvipc_park_on_deadline(struct thread_entry *t);
void sysvipc_park_on_interrupt(struct thread_entry *t);
/* Task-exit teardown: retire a PARK_KIND_IPC park and its waiter count. */
void sysvipc_task_cancel_wait(struct thread_entry *t);
void sysvipc_reset(void);
