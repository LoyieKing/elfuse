/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test-harness.h"

static int passes, fails;
static int ready_pipe[2];
static int release_pipe[2];
static char child_stack[65536] __attribute__((aligned(16)));
static int vfork_ok;
static int signal_pipe[2];
static _Atomic bool child_released;
static _Atomic bool signal_too_early;
static _Atomic uint64_t *shared_words;
static _Atomic uint64_t *unfaulted_word;
static bool sibling_observed;
static bool private_vfork;
static bool kill_child;

static int coherence_child(void *unused)
{
    (void) unused;
    atomic_store_explicit(&shared_words[0], 23, memory_order_release);
    atomic_store_explicit(unfaulted_word, 79, memory_order_release);
    char byte = 1;
    if (write(ready_pipe[1], &byte, 1) != 1 ||
        read(release_pipe[0], &byte, 1) != 1)
        _exit(2);
    if (kill_child) {
        kill(getpid(), SIGKILL);
        _exit(4);
    }
    bool saw_sibling =
        atomic_load_explicit(&shared_words[512], memory_order_acquire) == 47;
    _exit(saw_sibling != private_vfork ? 0 : 3);
}

static void *coherence_sibling(void *unused)
{
    (void) unused;
    char byte;
    if (read(ready_pipe[0], &byte, 1) != 1)
        return NULL;
    sibling_observed =
        atomic_load_explicit(&shared_words[0], memory_order_acquire) ==
            (private_vfork ? 11 : 23) &&
        atomic_load_explicit(unfaulted_word, memory_order_acquire) ==
            (private_vfork ? 0 : 79);
    atomic_store_explicit(&shared_words[512], 47, memory_order_release);
    atomic_store_explicit(&shared_words[1024], 61, memory_order_release);
    (void) write(release_pipe[1], &byte, 1);
    return NULL;
}

static void test_coherence(bool private, bool killed)
{
    TEST(private  ? "VFORK without VM keeps child stores private"
         : killed ? "vfork signal death preserves shared stores"
                  : "vfork shares live and unfaulted pages with sibling");
    void *mapping = mmap(NULL, 131072, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        FAIL("cannot allocate coherence pages");
        return;
    }
    shared_words = (_Atomic uint64_t *) (((uintptr_t) mapping + 16383) &
                                         ~(uintptr_t) 16383);
    unfaulted_word = shared_words + 4096;
    atomic_store_explicit(&shared_words[0], 11, memory_order_relaxed);
    atomic_store_explicit(&shared_words[512], 19, memory_order_relaxed);
    atomic_store_explicit(&shared_words[1024], 29, memory_order_relaxed);
    private_vfork = private;
    kill_child = killed;
    sibling_observed = false;
    pthread_t sibling;
    if (pipe(ready_pipe) != 0 || pipe(release_pipe) != 0 ||
        pthread_create(&sibling, NULL, coherence_sibling, NULL) != 0) {
        FAIL("cannot start coherence sibling");
        return;
    }
    pid_t child = clone(coherence_child, child_stack + sizeof(child_stack),
                        CLONE_VFORK | SIGCHLD | (private ? 0 : CLONE_VM), NULL);
    int status = 0;
    bool waited = child > 0 && waitpid(child, &status, 0) == child;
    pthread_join(sibling, NULL);
    bool child_ok = killed ? WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL
                           : WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (waited && child_ok && sibling_observed &&
        atomic_load_explicit(&shared_words[0], memory_order_acquire) ==
            (private ? 11 : 23) &&
        atomic_load_explicit(&shared_words[512], memory_order_acquire) == 47 &&
        atomic_load_explicit(&shared_words[1024], memory_order_acquire) == 61 &&
        atomic_load_explicit(unfaulted_word, memory_order_acquire) ==
            (private ? 0 : 79))
        PASS();
    else
        FAIL("child visibility or sibling bytes changed");
    close(ready_pipe[0]);
    close(ready_pipe[1]);
    close(release_pipe[0]);
    close(release_pipe[1]);
    munmap(mapping, 131072);
}

static void signal_handler(int signum)
{
    (void) signum;
    if (!atomic_load_explicit(&child_released, memory_order_acquire))
        atomic_store_explicit(&signal_too_early, true, memory_order_relaxed);
    char byte = 1;
    (void) write(signal_pipe[1], &byte, 1);
}

static int child_main(void *unused)
{
    (void) unused;
    char ready = 1;
    if (write(ready_pipe[1], &ready, 1) != 1)
        _exit(2);
    char release;
    if (read(release_pipe[0], &release, 1) != 1)
        _exit(3);
    _exit(7);
}

static void *vfork_thread(void *unused)
{
    (void) unused;
    pid_t child = clone(child_main, child_stack + sizeof(child_stack),
                        CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    int status = 0;
    vfork_ok = child > 0 && waitpid(child, &status, 0) == child &&
               WIFEXITED(status) && WEXITSTATUS(status) == 7;
    return NULL;
}

int main(void)
{
    alarm(30);
    struct sigaction action = {.sa_handler = signal_handler};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) != 0 || pipe(signal_pipe) != 0)
        return 1;
    TEST("fork succeeds while a sibling waits for its vfork child");
    pthread_t thread;
    if (pipe(ready_pipe) != 0 || pipe(release_pipe) != 0 ||
        pthread_create(&thread, NULL, vfork_thread, NULL) != 0) {
        FAIL("cannot start vfork caller");
        return 1;
    }
    char ready;
    if (read(ready_pipe[0], &ready, 1) != 1) {
        FAIL("vfork child did not start");
        return 1;
    }
    if (pthread_kill(thread, SIGUSR1) != 0)
        FAIL("cannot signal vfork caller");
    pid_t child = fork();
    if (child == 0)
        _exit(0);
    int status = 0;
    if (child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0)
        PASS();
    else
        FAIL("sibling fork failed");
    atomic_store_explicit(&child_released, true, memory_order_release);
    ready = 1;
    if (write(release_pipe[1], &ready, 1) != 1)
        FAIL("cannot release vfork child");
    pthread_join(thread, NULL);
    TEST("vfork defers a signal until child release");
    if (read(signal_pipe[0], &ready, 1) == 1 &&
        !atomic_load_explicit(&signal_too_early, memory_order_relaxed))
        PASS();
    else
        FAIL("vfork delivered signal before child release");
    TEST("vfork resumes once and leaves the child waitable");
    if (vfork_ok)
        PASS();
    else
        FAIL("vfork child status lost");
    close(ready_pipe[0]);
    close(ready_pipe[1]);
    close(release_pipe[0]);
    close(release_pipe[1]);
    close(signal_pipe[0]);
    close(signal_pipe[1]);
    test_coherence(false, false);
    test_coherence(false, true);
    test_coherence(true, false);
    SUMMARY("test-vfork-sibling");
    return fails != 0;
}
