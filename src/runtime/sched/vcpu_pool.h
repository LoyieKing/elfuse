/*
 * Physical vCPU / CPU worker pool
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * One VM owns logical CPUs 0..N-1. Each started CPU is a worker pthread that
 * owns exactly one HVF vCPU handle and all register access for it. Tasks do not
 * own handles: the scheduler queues them, and the worker that mounts a task
 * uses its own handle.
 *
 * Workers start lazily from runnable demand: slot 0 is the bootstrap (or
 * fork-child) pthread and the only started CPU until a second runnable task
 * needs a CPU. The scheduler calls vcpu_pool_wake_cpu() after publishing a
 * READY task; the pool either spawns that CPU's worker or kicks it awake.
 *
 * All task switches happen in the worker's outer execution loop, after the
 * complete syscall return tail of the outgoing task. Syscall handlers never
 * switch context; they publish a park/reschedule request that this loop
 * consumes.
 */

#pragma once

#include <Hypervisor/Hypervisor.h>
#include <stdbool.h>
#include <stdint.h>

#include "core/guest.h"

struct thread_entry;
struct vcpu_slot;

/* Allocate the (initially stopped) slot table sized to sched_host_ncpu().
 * Idempotent. No worker or HVF vCPU is created here.
 */
int vcpu_pool_init(void);

/* Tear down bookkeeping after workers have stopped. */
void vcpu_pool_shutdown(void);

int vcpu_pool_slot_count(void);

/* Adopt the calling thread's bootstrap (or fork-child) vCPU as logical CPU 0
 * and mark main_task mounted there. Only slot 0 is started: every other CPU
 * worker is created on demand by vcpu_pool_wake_cpu(). Physical HVF vCPUs
 * therefore equal started workers, never the task count. Call before GDB sync /
 * run. Idempotent while the pool is already running.
 */
int vcpu_pool_start_with_main(guest_t *g,
                              hv_vcpu_t vcpu,
                              hv_vcpu_exit_t *vexit,
                              bool verbose);

/* Run the CPU-0 worker loop on the calling thread after start_with_main.
 * Returns the process exit code when the guest stops.
 */
int vcpu_pool_run_main(int timeout_sec);

/* Stop workers: publish shutdown, kick every owner, join started worker
 * pthreads, and let the caller (the slot-0 owner) destroy the adopted handle.
 * Idempotent. Must be called by the slot-0 owner pthread.
 */
void vcpu_pool_stop(void);

/* The running guest / pool state (NULL / false before start). */
guest_t *vcpu_pool_guest(void);
bool vcpu_pool_running(void);

/* Scheduler -> execution: a task became READY on logical CPU @cpu. Start that
 * CPU's worker if it has none, otherwise kick the mounted task so the READY
 * task is considered without waiting for a full fair timeslice. Safe from any
 * thread, with or without the scheduler lock.
 */
void vcpu_pool_wake_cpu(int cpu);

/* Kick a started CPU's vCPU out of hv_vcpu_run. The kick latch is set before
 * the HVF call and is never cleared by slice re-arming: a kick that lands
 * between the tick's latch exchange and the next guest entry still forces a new
 * exit.
 */
void vcpu_pool_kick_cpu(int cpu);


/* hv_vcpus_exit every CPU whose owner has published a live handle. Handle
 * copies and destruction share one mutex, so a handle passed to HVF here is
 * never concurrently destroyed.
 */
void vcpu_pool_kick_all_mounted(void);

/* Per-VM expedited barrier. Publishes a generation, kicks every owner that can
 * execute guest code, and returns only after each such owner executed the
 * barrier and acknowledged (or stopped executing). Plain commands execute a
 * host full fence + ISB on each owner. @sync_core additionally requires the
 * guest shim trampoline (IC IALLU + DSB ISH + ISB executed by the vCPU) on
 * every target; an owner that is not mounted re-runs it before its next guest
 * instruction. Safe from a syscall handler on its owner; returns 0 when the
 * pool is not running or teardown starts.
 */
int vcpu_pool_membarrier(bool sync_core);

/* Stop guest entry while private backing is replaced. Host syscall handlers may
 * keep running; their host VAs remain stable. Caller holds mmap_lock and pairs
 * every pause with resume, including failures.
 */
void vcpu_pool_memory_pause(void);
void vcpu_pool_memory_resume(void);

/* Owner-side acknowledgement for the shim's HVC #14 trampoline tail.
 *
 * Returns false when no SYNC_CORE generation is in flight, which the HVC
 * handler reports as a shim/host protocol violation.
 */
bool vcpu_pool_barrier_ack_current(void);

/* Recompute the slice/wait-timer wakeup (deadline armed or disarmed, wall timer
 * changed). Safe from any thread.
 */
void vcpu_pool_wake_timer(void);
void vcpu_pool_kick_wait_timer(void);

/* Publish the EL0 translation regime of the image an execve just built.
 * @ttbr0/@ttbr1/@tcr are the values the entering vCPU is about to run with. A
 * worker created later reads them at bring-up; a worker that already has a vCPU
 * applies them before its next guest entry. The execve _start protocol
 * broadcasts TLBI VMALLE1IS before the new image can create another task, so no
 * guest code runs on a stale translation. Safe from any thread; no-op before
 * the pool starts.
 */
void vcpu_pool_refresh_mmu_template(uint64_t ttbr0,
                                    uint64_t ttbr1,
                                    uint64_t tcr);

/* Owner-thread-only accessors for the vCPU the calling worker is executing on.
 * The bool is the validity signal: hv_vcpu_t value 0 is a legal handle, so it
 * must never be used as "none". Outside a mounted guest execution both
 * accessors return false and leave the output untouched.
 */
bool vcpu_pool_current_vcpu(hv_vcpu_t *out);
bool vcpu_pool_current_vexit(hv_vcpu_exit_t **out);
int vcpu_pool_current_cpu(void);
void vcpu_pool_account_phase(bool entering_guest);

/* Current logical CPU of @t if it is RUNNING on this pool, else its scheduler
 * home. Task lookup is scheduler-owned; this is only for diagnostics.
 */
int vcpu_pool_cpu_of(const struct thread_entry *t);
