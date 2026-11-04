/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "runtime/thread.h"
#include "test-harness.h"
#include "../src/debug/profile.c"

_Thread_local thread_entry_t *current_thread;
static int passes, fails;

int main(void)
{
    uint64_t parsed = 1000;
    TEST("disabled has no clock");
    errno = EDOM;
    EXPECT_TRUE(profile_now_ns() == 0 && errno == EDOM && tasks == NULL,
                "disabled path touched storage or errno");
    TEST("strict configuration range");
    setenv("ELFUSE_PROFILE_INTERVAL_MS", "99", 1);
    EXPECT_TRUE(!number("ELFUSE_PROFILE_INTERVAL_MS", &parsed, 100, 60000),
                "invalid interval accepted");
    TEST("strict configuration syntax");
    setenv("ELFUSE_PROFILE_INTERVAL_MS", "100x", 1);
    EXPECT_TRUE(!number("ELFUSE_PROFILE_INTERVAL_MS", &parsed, 100, 60000),
                "malformed interval accepted");

    char dir[] = "/private/tmp/elfuse-profile-test-XXXXXX";
    if (!mkdtemp(dir))
        return 1;
    char prefix[PATH_MAX], path[PATH_MAX];
    snprintf(prefix, sizeof(prefix), "%s/run", dir);
    snprintf(path, sizeof(path), "%s/run.%d.jsonl", dir, getpid());
    setenv("ELFUSE_PROFILE", prefix, 1);
    setenv("ELFUSE_PROFILE_INTERVAL_MS", "100", 1);
    setenv("ELFUSE_PROFILE_PC_MS", "10", 1);
    profile_init();
    profile_start_writer();
    profile_start_writer();
    TEST("enabled exporter");
    EXPECT_TRUE(profile_enabled(), "exporter initialization failed");
    thread_entry_t first = {0}, second = {0};
    atomic_store_explicit(&first.guest_tid, 17, memory_order_relaxed);
    first.generation = 1;
    profile_attach(&first);
    current_thread = &first;
    profile_mount(&first, 0);
    profile_syscall_begin(&first, SYS_read);
    profile_syscall_end(&first, 0, true);
    profile_mount(&first, 1);
    profile_syscall_begin(&first, SYS_read);
    profile_syscall_end(&first, 12, false);
    profile_call_t *c = &first.profile->calls[SYS_read % PROFILE_SYSCALLS];
    TEST("migration reissue logical call");
    EXPECT_TRUE(LOAD(&c->values[CALLS]) == 1 &&
                    LOAD(&c->values[ATTEMPTS]) == 2 &&
                    LOAD(&c->values[COMPLETED]) == 1 &&
                    LOAD(&c->values[IO_BYTES]) == 12,
                "reissue double counted or transfer lost");
    profile_syscall_begin(&first, SYS_futex);
    profile_syscall_end(&first, 0, true);
    exec_park_result_store(&first, -11);
    profile_syscall_resume(&first);
    TEST("parked result completion");
    EXPECT_TRUE(LOAD(&first.profile->calls[SYS_futex % PROFILE_SYSCALLS]
                          .values[ERRORS]) == 1 &&
                    LOAD(&first.profile->calls[SYS_futex % PROFILE_SYSCALLS]
                              .values[COMPLETED]) == 1,
                "parked return or errno missing");
    profile_state(&first, SCHED_STATE_READY, PARK_KIND_NONE, 100);
    profile_state(&first, SCHED_STATE_RUNNING, PARK_KIND_NONE, 200);
    profile_state(&first, SCHED_STATE_BLOCKED, PARK_KIND_SLEEP, 300);
    profile_state(&first, SCHED_STATE_READY, PARK_KIND_NONE, 500);
    TEST("ready versus sleep residence");
    EXPECT_TRUE(LOAD(&first.profile->wait_ns[0]) == 100 &&
                    LOAD(&first.profile->wait_ns[PARK_KIND_SLEEP + 1]) == 200,
                "wait categories merged");
    atomic_store_explicit(&second.guest_tid, 17, memory_order_relaxed);
    second.generation = 2;
    profile_attach(&second);
    TEST("TID reuse separate lifetime");
    EXPECT_TRUE(
        first.profile != second.profile && second.profile->generation == 2,
        "reused TID merged");
    profile_sample(&first, 4096, 8192, true, false);
    profile_exec(&first);
    profile_sample(&first, 4096, 8192, true, false);
    TEST("PC epoch identity");
    EXPECT_TRUE(first.profile->pc_used == 2, "exec PC epochs merged");
    profile_syscall_begin(&first, SYS_read);
    usleep(250000);
    FILE *live = fopen(path, "r");
    char line[8192];
    bool ended = false, open_span = false;
    if (live) {
        while (fgets(line, sizeof(line), live)) {
            ended |= strstr(line, "\"type\":\"snapshot_end\"") != NULL;
            open_span |= strstr(line, "\"open_nr\":63") != NULL;
        }
        fclose(live);
    }
    TEST("live snapshot and open span");
    EXPECT_TRUE(ended && open_span, "snapshot depends on guest exit");
    profile_syscall_end(&first, 0, false);
    finish();
    live = fopen(path, "r");
    bool final = false;
    if (live) {
        while (fgets(line, sizeof(line), live))
            final |= strstr(line, "\"final\":true") != NULL;
        fclose(live);
    }
    TEST("final snapshot");
    EXPECT_TRUE(final, "normal exit flush missing");
    TEST("bounded overflow");
    STORE(&profile_active, true);
    STORE(&task_count, PROFILE_TASKS);
    thread_entry_t excess = {0};
    profile_attach(&excess);
    EXPECT_TRUE(excess.profile == NULL && LOAD(&task_overflow) == 1,
                "task cap exceeded");
    STORE(&profile_active, false);
    unlink(path);
    rmdir(dir);
    SUMMARY("test-profile-host");
    return fails != 0;
}
