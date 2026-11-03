/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * End a backing pause after fork has counted its waiting owner. Exercise the
 * real owner entry and fork gate without creating a VM or executing HVF.
 */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "runtime/forkipc.h"
#include "runtime/sched/vcpu_pool.h"
#include "runtime/thread.h"
#include "syscall/abi.h"
#include "syscall/proc.h"
#include "test-harness.h"

static int observed_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
#define pthread_cond_wait observed_cond_wait
#include "../src/runtime/sched/vcpu_pool.c"
#undef pthread_cond_wait

static int observed_posix_spawn(pid_t *pid,
                                const char *path,
                                const posix_spawn_file_actions_t *actions,
                                const posix_spawnattr_t *attr,
                                char *const argv[],
                                char *const envp[]);
#define posix_spawn observed_posix_spawn
#include "../src/runtime/forkipc.c"
#undef posix_spawn

static int passes, fails;
static pthread_mutex_t test_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t test_cond = PTHREAD_COND_INITIALIZER;
static bool backing_wait, fork_returned, release_fork;
static bool fork_ok;
static unsigned spawn_calls;
static _Atomic bool entry_returned;
static thread_entry_t *forker, *sibling;

static int observed_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    if (cond == &memory_cond && owner_slot == &slots[1]) {
        pthread_mutex_lock(&test_lock);
        backing_wait = true;
        pthread_cond_broadcast(&test_cond);
        pthread_mutex_unlock(&test_lock);
    }
    return pthread_cond_wait(cond, mutex);
}

static int observed_posix_spawn(pid_t *pid,
                                const char *path,
                                const posix_spawn_file_actions_t *actions,
                                const posix_spawnattr_t *attr,
                                char *const argv[],
                                char *const envp[])
{
    spawn_calls++;
    return posix_spawn(pid, path, actions, attr, argv, envp);
}

static void *enter_guest(void *arg)
{
    (void) arg;
    current_thread = sibling;
    owner_slot = &slots[1];
    vcpu_pool_account_phase(true);
    atomic_store_explicit(&entry_returned, true, memory_order_release);
    vcpu_pool_account_phase(false);
    thread_fork_barrier_check();
    owner_slot = NULL;
    current_thread = NULL;
    return NULL;
}

static void *freeze_guest(void *arg)
{
    (void) arg;
    current_thread = forker;
    bool ok = thread_quiesce_siblings();
    pthread_mutex_lock(&test_lock);
    fork_ok = ok;
    fork_returned = true;
    pthread_cond_broadcast(&test_cond);
    while (!release_fork)
        pthread_cond_wait(&test_cond, &test_lock);
    pthread_mutex_unlock(&test_lock);
    if (ok)
        thread_resume_siblings();
    current_thread = NULL;
    return NULL;
}

static void test_pause_then_fork(void)
{
    pthread_t owner, freezer;
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000L};

    TEST("backing wait rejoins armed fork");
    vcpu_pool_memory_pause();
    if (pthread_create(&owner, NULL, enter_guest, NULL) != 0) {
        vcpu_pool_memory_resume();
        FAIL("owner pthread_create");
        return;
    }
    pthread_mutex_lock(&test_lock);
    while (!backing_wait)
        pthread_cond_wait(&test_cond, &test_lock);
    pthread_mutex_unlock(&test_lock);
    if (pthread_create(&freezer, NULL, freeze_guest, NULL) != 0) {
        vcpu_pool_memory_resume();
        pthread_join(owner, NULL);
        FAIL("forker pthread_create");
        return;
    }

    while (!sched_domain_frozen())
        nanosleep(&delay, NULL);
    /* The fork scan and target publication finish under thread_lock. */
    pthread_mutex_t *lock = thread_get_lock();
    pthread_mutex_lock(lock);
    bool counted = sibling->fork_counted;
    pthread_mutex_unlock(lock);
    vcpu_pool_memory_resume();

    pthread_mutex_lock(&test_lock);
    while (!fork_returned)
        pthread_cond_wait(&test_cond, &test_lock);
    bool quiet =
        fork_ok && counted &&
        !atomic_load_explicit(&entry_returned, memory_order_acquire) &&
        !atomic_load_explicit(&slots[1].memory_guest, memory_order_seq_cst);
    release_fork = true;
    pthread_cond_broadcast(&test_cond);
    pthread_mutex_unlock(&test_lock);
    pthread_join(freezer, NULL);
    pthread_join(owner, NULL);
    EXPECT_TRUE(quiet, "owner crossed guest entry or fork timed out");
    TEST("fork release restores guest entry");
    EXPECT_TRUE(atomic_load_explicit(&entry_returned, memory_order_acquire) &&
                    !sched_domain_frozen(),
                "owner stayed parked after the snapshot window");
}

static void test_failed_fork(void)
{
    guest_t guest = {0};
    current_thread = forker;
    sibling->fuse_service = &guest;
    TEST("failed quiesce creates no child");
    bool ok = true;
    for (int i = 0; i < 8; i++) {
        int64_t rc =
            sys_clone(0, &guest, LINUX_SIGCHLD, 0, 0, 0, 0, 0, 0, 0, false);
        int status;
        errno = 0;
        pid_t child = waitpid(-1, &status, WNOHANG);
        ok &= rc == -LINUX_EAGAIN && child == -1 && errno == ECHILD &&
              !sched_domain_frozen() && spawn_calls == 0;
    }
    sibling->fuse_service = NULL;
    EXPECT_TRUE(ok, "failed clone escaped a child or retained its freeze");
    TEST("failed fork leaves gate reusable");
    pthread_mutex_t *lock = thread_get_lock();
    pthread_mutex_lock(lock);
    sched_put_current(sibling, SCHED_PUT_BLOCKED);
    pthread_mutex_unlock(lock);
    bool frozen = thread_quiesce_siblings();
    if (frozen)
        thread_resume_siblings();
    EXPECT_TRUE(frozen && !sched_domain_frozen(),
                "failed clone left a fork window owned");
}

int main(int argc, char **argv)
{
    /* A pre-fix sys_clone spawns this binary. Preserve the real EOF diagnostic.
     */
    for (int i = 1; i + 1 < argc; i++)
        if (strcmp(argv[i], "--fork-child") == 0)
            return fork_child_main(atoi(argv[i + 1]), -1, false, 0);
    alarm(15);
    log_init();
    if (sched_domain_init(2) != 0 || sched_domain_ncpu() < 2)
        return 77;
    proc_init();
    sched_set_host_ops(NULL);
    forker = thread_alloc(1, 0, 0, NULL);
    sibling = thread_alloc(2, 0, 0, NULL);
    if (!forker || !sibling)
        return 1;
    sched_task_inherit_attr(NULL, forker);
    sched_task_inherit_attr(forker, sibling);
    forker->sched.placement_cpu = 0;
    sibling->sched.placement_cpu = 1;
    sched_attach_thread(forker);
    sched_attach_thread(sibling);
    test_pause_then_fork();
    test_failed_fork();
    SUMMARY("test-fork-quiesce-host");
    return fails != 0;
}
