/*
 * Multi-threaded synchronous-fault delivery test
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Regression lock-in for synchronous fault (SIGSEGV) delivery in a
 * multi-threaded guest. Faults were routed through the process-wide pending
 * bitmask (signal_queue + signal_deliver), so a fault raised by one vCPU thread
 * could be dequeued and delivered by another: the other thread had no
 * thread-local fault info, so the kernel-visible siginfo became si_code=SI_USER
 * with no si_addr instead of SEGV_MAPERR. A JVM treats such a SIGSEGV as a
 * fatal external signal rather than a recoverable implicit null check, so javac
 * crashed. Two threads faulting at once also collapsed into a single bitmask
 * bit, dropping one fault entirely.
 *
 * Each thread repeatedly takes a recoverable SIGSEGV (read from a known bad
 * address) and the handler asserts the siginfo is the correct synchronous-fault
 * shape. Under the bug, a fault delivered to the wrong thread is seen either as
 * SI_USER or on a thread with no armed recovery point, which this test flags.
 *
 * Also locks in Linux force_sig_info_to_task() semantics for unhandleable
 * faults: a synchronous SIGSEGV whose disposition is SIG_IGN, or which is
 * blocked, resets to SIG_DFL + unblocked and terminates the process. Without
 * the reset, SIG_IGN resumes at the faulting PC and re-faults forever, and a
 * blocked fault either stalls the same way or runs a handler the guest asked to
 * block. Each case runs in a forked child that must die by SIGSEGV.
 *
 * Syscalls exercised: rt_sigaction, rt_sigprocmask, clone (pthreads), fork,
 * wait4, the fault delivery path.
 */

#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define NTHREADS 4
#define NFAULTS 4000

/* The bad address every thread reads. Page zero is never mapped, so the read
 * faults with a translation fault -> SEGV_MAPERR and si_addr == FAULT_ADDR.
 */
#define FAULT_ADDR ((volatile int *) (uintptr_t) 0x8)

static _Thread_local sigjmp_buf recover;
static _Thread_local volatile int armed;

/* Set by the handler when it observes a malformed delivery. async-signal-safe
 * stores to sig_atomic_t/int flags only.
 */
static volatile sig_atomic_t bad_si_code = 0;
static volatile sig_atomic_t bad_si_addr = 0;
static volatile sig_atomic_t unarmed_delivery = 0;

static void segv_handler(int sig, siginfo_t *info, void *uc)
{
    (void) sig;
    (void) uc;

    /* A synchronous fault must report a fault si_code (SEGV_MAPERR for an
     * unmapped address), never SI_USER (0), which is what a stolen/cross-thread
     * delivery produced.
     */
    if (info->si_code != SEGV_MAPERR && info->si_code != SEGV_ACCERR)
        bad_si_code = 1;
    if (info->si_addr != (void *) FAULT_ADDR)
        bad_si_addr = 1;
    if (!armed) {
        /* Delivered to a thread that is not currently faulting: the fault was
         * misrouted. Cannot recover (no jmp target), so fail and exit.
         */
        unarmed_delivery = 1;
        _exit(2);
    }
    siglongjmp(recover, 1);
}

static void *fault_loop(void *arg)
{
    (void) arg;
    for (int i = 0; i < NFAULTS; i++) {
        armed = 1;
        if (sigsetjmp(recover, 1) == 0) {
            /* Trigger the fault. volatile so the read is not optimized away. */
            volatile int v = *FAULT_ADDR;
            (void) v;
        }
        armed = 0;
    }
    return NULL;
}

/* Fork a child that faults under the disposition installed by `setup` and
 * return its wait status.
 *
 * Returns -1 on fork/waitpid failure, -2 if the child had to be killed: a
 * re-fault-forever regression spins the child on the faulting PC without
 * reaching a signal poll point, so no in-child alarm can interrupt it -- the
 * parent must bound the wait and kill.
 */
#define CHILD_WAIT_MS 8000

static int fault_child_status(void (*setup)(void))
{
    pid_t pid = fork();
    if (pid == 0) {
        setup();
        volatile int v = *FAULT_ADDR;
        (void) v;
        _exit(0); /* Reached only if the fault did not fire at all */
    }
    if (pid < 0)
        return -1;
    int status = 0;
    for (int waited = 0; waited < CHILD_WAIT_MS; waited += 50) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid)
            return status;
        if (r < 0)
            return -1;
        usleep(50 * 1000);
    }
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    return -2;
}

/* elfuse fork children report signal deaths as exit(128+signum); accept the
 * native WIFSIGNALED form too.
 */
static int died_by(int status, int sig)
{
    if (WIFSIGNALED(status) && WTERMSIG(status) == sig)
        return 1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 128 + sig;
}

static void setup_ign(void)
{
    signal(SIGSEGV, SIG_IGN);
}

static void blocked_handler(int sig, siginfo_t *info, void *uc)
{
    (void) sig;
    (void) info;
    (void) uc;

    /* Must never run: SIGSEGV was blocked when the fault hit, so Linux
     * force_sig semantics reset to SIG_DFL and terminate instead.
     */
    _exit(3);
}

static void setup_blocked(void)
{
    struct sigaction sa;
    sa.sa_sigaction = blocked_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGSEGV);
    sigprocmask(SIG_BLOCK, &set, NULL);
}

#ifdef __aarch64__
#define MIGRATION_THREADS 16
#define MIGRATION_FAULTS 30000
static _Atomic bool migration_start;
static _Atomic unsigned migration_errors;
static _Thread_local unsigned migration_faults;
static _Thread_local uintptr_t migration_address;

static void migration_handler(int sig, siginfo_t *info, void *context)
{
    ucontext_t *uc = context;
    if (sig != SIGSEGV || info->si_code != SEGV_MAPERR ||
        info->si_addr != (void *) migration_address ||
        uc->uc_mcontext.regs[8] != 0x12345678)
        atomic_fetch_add_explicit(&migration_errors, 1, memory_order_relaxed);
    migration_faults++;
    uc->uc_mcontext.pc += 4;
}

static void *migration_worker(void *arg)
{
    migration_address = (uintptr_t) arg;
    while (!atomic_load_explicit(&migration_start, memory_order_acquire))
        ;
    for (unsigned i = 0; i < MIGRATION_FAULTS; i++) {
        register uint64_t x0 __asm__("x0") = migration_address;
        register uint64_t x8 __asm__("x8") = 0x12345678;
        __asm__ __volatile__("ldr xzr, [x0]" : "+r"(x0), "+r"(x8) : : "memory");
        if (x0 != migration_address || x8 != 0x12345678)
            atomic_fetch_add_explicit(&migration_errors, 1,
                                      memory_order_relaxed);
        syscall(SYS_getppid);
    }
    if (migration_faults != MIGRATION_FAULTS)
        atomic_fetch_add_explicit(&migration_errors, 1, memory_order_relaxed);
    return NULL;
}

static bool migration_check(void)
{
    struct sigaction sa = {.sa_sigaction = migration_handler,
                           .sa_flags = SA_SIGINFO};
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0)
        return false;
    pthread_t threads[MIGRATION_THREADS];
    int spawned = 0;
    for (; spawned < MIGRATION_THREADS; spawned++)
        if (pthread_create(&threads[spawned], NULL, migration_worker,
                           (void *) (uintptr_t) (8 + spawned * 8)) != 0)
            break;
    atomic_store_explicit(&migration_start, true, memory_order_release);
    bool ok = spawned == MIGRATION_THREADS;
    for (int i = 0; i < spawned; i++)
        ok &= pthread_join(threads[i], NULL) == 0;
    return ok &&
           atomic_load_explicit(&migration_errors, memory_order_relaxed) == 0;
}
#endif

int main(void)
{
    printf("test-fault-signal-mt: multi-threaded SIGSEGV delivery\n\n");

    /* Forced-fault disposition cases run first, in forked children, before this
     * process installs its own SIGSEGV handler or spawns threads.
     */
    TEST("SIG_IGN'd synchronous SIGSEGV terminates");
    int status = fault_child_status(setup_ign);
    if (status == -2)
        FAIL("child re-faulted forever under SIG_IGN (killed)");
    else if (status < 0)
        FAIL("fork/waitpid failed");
    else if (died_by(status, SIGSEGV))
        PASS();
    else
        FAIL("child did not die by SIGSEGV");

    TEST("blocked synchronous SIGSEGV terminates, handler not run");
    status = fault_child_status(setup_blocked);
    if (status == -2)
        FAIL("child re-faulted forever with SIGSEGV blocked (killed)");
    else if (status < 0)
        FAIL("fork/waitpid failed");
    else if (died_by(status, SIGSEGV))
        PASS();
    else if (WIFEXITED(status) && WEXITSTATUS(status) == 3)
        FAIL("handler ran despite SIGSEGV being blocked");
    else
        FAIL("child did not die by SIGSEGV");

    struct sigaction sa;
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        printf("  %-34s FAIL: sigaction (errno=%d)\n", "setup", errno);
        return 1;
    }

    TEST("concurrent recoverable SIGSEGV faults");
    pthread_t th[NTHREADS];
    int spawned = 0;
    for (int i = 0; i < NTHREADS; i++) {
        if (pthread_create(&th[i], NULL, fault_loop, NULL) != 0)
            break;
        spawned++;
    }
    for (int i = 0; i < spawned; i++)
        pthread_join(th[i], NULL);

    if (spawned != NTHREADS)
        FAIL("could not spawn all threads");
    else if (bad_si_code)
        FAIL("fault delivered with si_code != SEGV_MAPERR/ACCERR (SI_USER?)");
    else if (bad_si_addr)
        FAIL("fault delivered with wrong si_addr");
    else if (unarmed_delivery)
        FAIL("fault delivered to a non-faulting thread");
    else
        PASS();

#ifdef __aarch64__
    TEST("migration preserves fault class, address and registers");
    EXPECT_TRUE(migration_check(), "fault became a syscall or changed address");
#endif

    SUMMARY("test-fault-signal-mt");
    return fails ? 1 : 0;
}
