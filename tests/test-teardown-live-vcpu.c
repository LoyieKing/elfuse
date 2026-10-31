/*
 * Teardown must never cross-thread-destroy a live or bring-up worker vCPU
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * HVF vCPUs are thread-affine: only the creating thread may run or destroy a
 * vCPU. When the process tears down (main thread exit_group -> guest_destroy)
 * while worker threads still own live vCPUs, the teardown path must not call
 * hv_vcpu_destroy on a worker's vCPU from the main thread, nor hv_vm_destroy /
 * munmap the guest slab while a worker vCPU is still live. Doing either frees a
 * kernel vCPU object out from under its owning thread and faults the host
 * kernel (near-null dereference of the freed, poisoned vCPU struct).
 *
 * Two windows are exercised, each ending in exit_group(42):
 *
 *   spin:    a batch of workers spins on sched_yield, so every worker is inside
 *            hv_vcpu_run (a live vCPU) when the main thread calls exit_group.
 *            Teardown scans the thread table with those vCPUs still owned by
 *            their threads.
 *
 *   bringup: a burst of workers is cloned and the main thread calls exit_group
 *            immediately, so some workers are still mid-bring-up -- the slot is
 *            active but the vCPU handle has not been published yet -- when the
 *            teardown scan runs. Such a worker is about to create and enter its
 *            own vCPU, so teardown must treat it as live and defer, not skip
 * it.
 *
 * A clean exit with code 42 means teardown neither destroyed a foreign vCPU nor
 * tore the VM down under one. A crash, a host fault, or a hang (turned into a
 * timeout failure by the driver) means the teardown race is back.
 *
 * Syscalls: clone(220), nanosleep(101), sched_yield(124), exit_group(94)
 */

#include <string.h>

#include "raw-syscall.h"

#define CLONE_THREAD_FLAGS \
    (0x00010000 | 0x00000100 | 0x00000200 | 0x00000800 | 0x00200000)

#define EXIT_CODE 42

/* Modest concurrency: every worker here runs forever, so they are all alive at
 * teardown alongside the main thread. (Logical threads are no longer capped at
 * 64; this test is about teardown with live vCPUs, not the table ceiling.)
 */
#define WORKERS 40
#define STACK_SIZE 16384

static char worker_stacks[WORKERS][STACK_SIZE] __attribute__((aligned(16)));

static void msleep(long ms)
{
    struct {
        long tv_sec, tv_nsec;
    } ts = {ms / 1000, (ms % 1000) * 1000000L};
    raw_syscall4(101, (long) &ts, 0, 0, 0); /* nanosleep */
}

/* Never returns: keeps the worker inside hv_vcpu_run (or at a run-loop
 * preemption point) so its vCPU is live for the whole teardown window.
 */
static int spin_fn(void)
{
    for (;;)
        raw_syscall0(124); /* sched_yield */
    return 0;
}

/* Clone one CLONE_THREAD worker running spin_fn on the given stack.
 *
 * Returns the clone result (>0 tid in the parent, <0 on failure); the child
 * never returns.
 */
static long spawn_spinner(int i)
{
    char *stack_top = worker_stacks[i] + STACK_SIZE;
    long ret = raw_syscall5(220, CLONE_THREAD_FLAGS, (long) stack_top, 0, 0, 0);
    if (ret == 0) {
        spin_fn();
        raw_syscall1(93, 0); /* exit (unreached) */
    }
    return ret;
}

/* spin: bring every worker fully up (running a live vCPU), then exit_group. */
static int scenario_spin(void)
{
    for (int i = 0; i < WORKERS; i++) {
        if (spawn_spinner(i) < 0)
            break; /* out of thread slots; the rest still exercise teardown */
    }

    /* Let the workers reach the spin loop so their vCPUs are live, not still in
     * bring-up, when teardown runs.
     */
    msleep(100);
    raw_syscall1(94, EXIT_CODE); /* exit_group */
    return 1;                    /* unreached */
}

/* bringup: clone a burst and exit_group immediately, so teardown races workers
 * that are still creating/publishing their vCPUs.
 */
static int scenario_bringup(void)
{
    for (int i = 0; i < WORKERS; i++) {
        if (spawn_spinner(i) < 0)
            break;
    }
    raw_syscall1(94, EXIT_CODE); /* exit_group with bring-up in flight */
    return 1;                    /* unreached */
}

int main(int argc, char **argv)
{
    int rc;

    if (argc < 2) {
        static const char usage[] =
            "usage: test-teardown-live-vcpu spin|bringup\n";
        raw_syscall3(64, 2, (long) usage, sizeof(usage) - 1); /* write */
        return 2;
    }

    if (!strcmp(argv[1], "spin"))
        rc = scenario_spin();
    else if (!strcmp(argv[1], "bringup"))
        rc = scenario_bringup();
    else
        rc = 2;

    /* Scenarios normally never return: exit_group(42) ends the process. A
     * return means setup failed; surface it as a visible wrong exit code.
     */
    raw_syscall1(94, rc);
    return rc;
}
