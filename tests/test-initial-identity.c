/*
 * Explicit initial guest PID/PPID behavior
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Usage: elfuse --pid N --ppid M test-initial-identity N M child-pid
 *
 * The no-argument form checks the unchanged PID 1 / PPID 0 default, whose
 * first child takes PID 2. The explicit form checks that every surface agrees
 * on the staged identity: the identity syscalls, the shim identity cache, the
 * main thread's TID, /proc, and the session/process group Linux derives from
 * it. fork must skip both reserved ids, and the child checks that execve
 * preserves the inherited identity.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "raw-syscall.h"
#include "test-harness.h"

int passes = 0, fails = 0;

#ifndef __NR_getpid
#define __NR_getpid 172
#endif
#ifndef __NR_getppid
#define __NR_getppid 173
#endif
#ifndef __NR_gettid
#define __NR_gettid 178
#endif
#ifndef __NR_getpgid
#define __NR_getpgid 155
#endif
#ifndef __NR_getsid
#define __NR_getsid 156
#endif
#ifndef __NR_setsid
#define __NR_setsid 157
#endif

static long parse_long(const char *text, const char *what)
{
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (text[0] == '\0' || *end != '\0') {
        fprintf(stderr, "test-initial-identity: bad %s: %s\n", what, text);
        exit(2);
    }
    return value;
}

static void expect_eq(long got, long want, const char *what)
{
    TEST(what);
    if (got != want) {
        printf("got %ld want %ld ", got, want);
        FAIL(what);
        return;
    }
    PASS();
}

static long status_field(const char *path, const char *key)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;

    char line[256];
    long value = -1;
    size_t key_len = strlen(key);
    while (fgets(line, sizeof(line), fp)) {
        if (!strncmp(line, key, key_len) && line[key_len] == ':') {
            value = strtol(line + key_len + 1, NULL, 10);
            break;
        }
    }
    fclose(fp);
    return value;
}

/* Field 1 is the PID before the parenthesized comm; fields 3 onward follow it.
 * A comm may contain spaces or parentheses, so the scan starts at the last
 * closing parenthesis.
 */
static long stat_field(const char *path, int target)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;

    char buf[1024];
    size_t len = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[len] = '\0';

    if (target == 1) {
        char *end = NULL;
        long value = strtol(buf, &end, 10);
        return end == buf ? -1 : value;
    }
    if (target < 4)
        return -1;

    char *p = strrchr(buf, ')');
    if (!p)
        return -1;
    p++;

    int field = 3;
    while (*p == ' ')
        p++;
    while (*p != '\0' && field <= target) {
        char *end = NULL;
        if (field == 3) {
            if (p[1] != ' ')
                return -1;
            end = p + 1;
        } else {
            long value = strtol(p, &end, 10);
            if (end == p)
                return -1;
            if (field == target)
                return value;
        }
        p = end;
        while (*p == ' ')
            p++;
        field++;
    }
    return -1;
}

static void verify_initial(long pid, long ppid)
{
    printf("init: pid=%ld ppid=%ld\n", pid, ppid);

    expect_eq(raw_syscall0(__NR_getpid), pid, "getpid");
    expect_eq(raw_syscall0(__NR_getppid), ppid, "getppid");
    expect_eq(raw_syscall0(__NR_gettid), pid, "main thread gettid");

    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/status", pid);
    expect_eq(status_field("/proc/self/status", "Pid"), pid, "self Pid");
    expect_eq(status_field("/proc/self/status", "PPid"), ppid, "self PPid");
    expect_eq(status_field("/proc/self/status", "Tgid"), pid, "self Tgid");
    expect_eq(status_field(path, "Pid"), pid, "numbered Pid");
    expect_eq(status_field(path, "PPid"), ppid, "numbered PPid");

    expect_eq(stat_field("/proc/self/stat", 1), pid, "stat pid");
    expect_eq(stat_field("/proc/self/stat", 4), ppid, "stat ppid");
    expect_eq(stat_field("/proc/self/stat", 5), pid, "stat pgrp");
    expect_eq(stat_field("/proc/self/stat", 6), pid, "stat session");

    expect_eq(raw_syscall1(__NR_getpgid, 0), pid, "getpgid(0)");
    expect_eq(raw_syscall1(__NR_getsid, 0), pid, "getsid(0)");

    /* The initial process is already a group leader, so setsid must refuse. */
    expect_eq(raw_syscall0(__NR_setsid), -1, "setsid EPERM");
}

/* A fork child inherits the initial process's session and process group. */
static void verify_child(long pid, long ppid, long pgid)
{
    printf("child: pid=%ld ppid=%ld pgid=%ld\n", pid, ppid, pgid);

    expect_eq(raw_syscall0(__NR_getpid), pid, "child getpid");
    expect_eq(raw_syscall0(__NR_getppid), ppid, "child getppid");
    expect_eq(raw_syscall0(__NR_gettid), pid, "child gettid");

    expect_eq(status_field("/proc/self/status", "Pid"), pid, "child Pid");
    expect_eq(status_field("/proc/self/status", "PPid"), ppid, "child PPid");
    expect_eq(status_field("/proc/self/status", "Tgid"), pid, "child Tgid");
    expect_eq(stat_field("/proc/self/stat", 1), pid, "child stat pid");
    expect_eq(stat_field("/proc/self/stat", 4), ppid, "child stat ppid");
    expect_eq(stat_field("/proc/self/stat", 5), pgid, "child stat pgrp");
    expect_eq(stat_field("/proc/self/stat", 6), pgid, "child stat session");

    expect_eq(raw_syscall1(__NR_getpgid, 0), pgid, "child getpgid(0)");
    expect_eq(raw_syscall1(__NR_getsid, 0), pgid, "child getsid(0)");
}

static int exec_mode(long pid, long ppid)
{
    printf("exec: pid=%ld ppid=%ld\n", pid, ppid);
    verify_child(pid, ppid, ppid);
    SUMMARY("test-initial-identity (exec)");
    return fails ? 1 : 0;
}

static void child_exec(long pid, long ppid)
{
    char pidbuf[24], ppidbuf[24];
    snprintf(pidbuf, sizeof(pidbuf), "%ld", pid);
    snprintf(ppidbuf, sizeof(ppidbuf), "%ld", ppid);

    char *args[] = {(char *) "/proc/self/exe", (char *) "exec", pidbuf, ppidbuf,
                    NULL};
    execv(args[0], args);
    _exit(127);
}

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "exec")) {
        if (argc != 4) {
            fprintf(stderr, "usage: %s exec <pid> <ppid>\n", argv[0]);
            return 2;
        }
        return exec_mode(parse_long(argv[2], "pid"),
                         parse_long(argv[3], "ppid"));
    }

    long want_pid = 1, want_ppid = 0, want_child = 2;
    if (argc == 4) {
        want_pid = parse_long(argv[1], "pid");
        want_ppid = parse_long(argv[2], "ppid");
        want_child = parse_long(argv[3], "first child pid");
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [<pid> <ppid> <first-child-pid>]\n",
                argv[0]);
        return 2;
    }

    printf("test-initial-identity: pid=%ld ppid=%ld child=%ld\n", want_pid,
           want_ppid, want_child);
    verify_initial(want_pid, want_ppid);
    if (fails)
        goto out;

    TEST("fork child pid skips pid and ppid");
    pid_t kid = fork();
    if (kid < 0) {
        FAIL("fork failed");
        goto out;
    }
    if (kid == 0) {
        long pid = raw_syscall0(__NR_getpid);
        long ppid = raw_syscall0(__NR_getppid);
        if (pid != want_child || ppid != want_pid) {
            fprintf(stderr,
                    "test-initial-identity: child %ld/%ld, want %ld/%ld\n", pid,
                    ppid, want_child, want_pid);
            _exit(1);
        }
        child_exec(pid, ppid);
    }
    if (kid != want_child) {
        printf("got %ld want %ld ", (long) kid, want_child);
        FAIL("child pid collides with the initial identity");
    } else {
        PASS();
    }

    TEST("fork+exec preserves the child identity");
    int status = 0;
    if (waitpid(kid, &status, 0) != kid) {
        FAIL("waitpid failed");
    } else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("status 0x%x ", status);
        FAIL("exec'd child identity mismatch");
    } else {
        PASS();
    }

out:
    SUMMARY("test-initial-identity");
    return fails ? 1 : 0;
}