/*
 * Test POSIX advisory record locking via fcntl(F_SETLK/F_GETLK/F_SETLKW)
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Regression coverage for the Linux<->macOS struct flock translation. The
 * l_type constants differ between the two ABIs (Linux F_RDLCK=0/F_WRLCK=1,
 * macOS F_RDLCK=1/F_WRLCK=3), so passing the guest value straight through to
 * the host made the very first lock SQLite takes (a shared F_RDLCK) fail with
 * EINVAL and surface as "disk I/O error". The byte offsets below mirror the
 * ones SQLite locks around its 1GiB "pending byte".
 */

#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

#define PENDING_BYTE 0x40000000L
#define RESERVED_BYTE (PENDING_BYTE + 1)
#define SHARED_FIRST (PENDING_BYTE + 2)
#define SHARED_SIZE 510
#define CHILD_LOCK_BYTE 100

static int set_lock(int fd, short type, off_t start, off_t len)
{
    struct flock fl = {
        .l_type = type,
        .l_whence = SEEK_SET,
        .l_start = start,
        .l_len = len,
    };
    return fcntl(fd, F_SETLK, &fl);
}

int main(void)
{
    int passes = 0, fails = 0;

    /* Unique per invocation: record locks are held per (process, inode), so a
     * fixed name shares one lock space with every concurrent run.
     */
    char path[] = "/tmp/elfuse-test-flock.XXXXXX";

    int fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }

    /* Shared read lock -- this is the call that regressed to EINVAL. */
    TEST("F_SETLK F_RDLCK (shared)");
    EXPECT_EQ(set_lock(fd, F_RDLCK, SHARED_FIRST, SHARED_SIZE), 0,
              "shared read lock rejected");

    /* Promote the pending byte to a write lock, then drop it. */
    TEST("F_SETLK F_WRLCK (pending)");
    EXPECT_EQ(set_lock(fd, F_WRLCK, PENDING_BYTE, 1), 0,
              "pending write lock rejected");

    TEST("F_SETLK F_WRLCK (reserved)");
    EXPECT_EQ(set_lock(fd, F_WRLCK, RESERVED_BYTE, 1), 0,
              "reserved write lock rejected");

    TEST("F_SETLK F_UNLCK (release shared)");
    EXPECT_EQ(set_lock(fd, F_UNLCK, SHARED_FIRST, SHARED_SIZE), 0,
              "unlock rejected");

    /* Blocking variant must take the same translation path. */
    TEST("F_SETLKW F_WRLCK");
    struct flock wfl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 16,
    };
    EXPECT_EQ(fcntl(fd, F_SETLKW, &wfl), 0, "F_SETLKW rejected");

    /* F_GETLK on a region this process already write-locks must report back a
     * Linux l_type. Linux reports F_UNLCK for locks held by the *same* owner,
     * so the only thing we can assert portably is that the type round-trips to
     * a valid Linux constant and the call succeeds.
     */
    TEST("F_GETLK round-trips l_type");
    struct flock gfl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 16,
    };
    int gr = fcntl(fd, F_GETLK, &gfl);
    EXPECT_TRUE(gr == 0 && (gfl.l_type == F_UNLCK || gfl.l_type == F_RDLCK ||
                            gfl.l_type == F_WRLCK),
                "F_GETLK returned an invalid l_type");

    /* F_GETLK must report the *guest* PID of a conflicting lock, not elfuse's
     * raw host PID -- guest code that treats l_pid as a real PID (e.g. a
     * kill(pid, 0) liveness check) would otherwise resolve a foreign host
     * process instead of the actual lock holder.
     */
    TEST("F_GETLK reports the guest PID of a conflicting child lock");
    int pfd[2];
    int pipe_ok = (pipe(pfd) == 0);
    EXPECT_TRUE(pipe_ok, "pipe() failed");
    if (pipe_ok) {
        pid_t child = fork();
        if (child == 0) {
            close(pfd[0]);
            int cfd = open(path, O_RDWR);
            if (cfd < 0 || set_lock(cfd, F_WRLCK, CHILD_LOCK_BYTE, 1) != 0) {
                _exit(1);
            }
            pid_t self = getpid();
            ssize_t n = write(pfd[1], &self, sizeof(self));
            if (n != (ssize_t) sizeof(self))
                _exit(1);
            sleep(5); /* Hold the lock until the parent has queried it. */
            _exit(0);
        }

        close(pfd[1]);
        pid_t child_pid = -1;
        ssize_t n = read(pfd[0], &child_pid, sizeof(child_pid));
        close(pfd[0]);

        struct flock cfl = {
            .l_type = F_WRLCK,
            .l_whence = SEEK_SET,
            .l_start = CHILD_LOCK_BYTE,
            .l_len = 1,
        };
        int cr = fcntl(fd, F_GETLK, &cfl);
        EXPECT_TRUE(n == (ssize_t) sizeof(child_pid) && cr == 0 &&
                        cfl.l_type == F_WRLCK && cfl.l_pid == child_pid,
                    "F_GETLK did not report the child's guest PID");

        if (child > 0) {
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
        }
    }

    TEST("F_SETLKW waits for release and acquires");
    int ready_pipe[2], go_pipe[2];
    if (pipe(ready_pipe) != 0 || pipe(go_pipe) != 0) {
        FAIL("pipe failed");
    } else {
        pid_t child = fork();
        if (child == 0) {
            close(ready_pipe[0]);
            close(go_pipe[1]);
            char go;
            if (set_lock(fd, F_WRLCK, CHILD_LOCK_BYTE, 1) != 0 ||
                write(ready_pipe[1], "x", 1) != 1 ||
                read(go_pipe[0], &go, 1) != 1)
                _exit(1);
            usleep(20000);
            if (set_lock(fd, F_UNLCK, CHILD_LOCK_BYTE, 1) != 0)
                _exit(2);
            _exit(0);
        }
        close(ready_pipe[1]);
        close(go_pipe[0]);
        char ready;
        bool ok = child > 0 && read(ready_pipe[0], &ready, 1) == 1;
        struct timespec before, after;
        struct flock requested = {.l_type = F_WRLCK,
                                  .l_whence = SEEK_SET,
                                  .l_start = CHILD_LOCK_BYTE,
                                  .l_len = 1};
        if (ok) {
            clock_gettime(CLOCK_MONOTONIC, &before);
            ok = write(go_pipe[1], "x", 1) == 1 &&
                 fcntl(fd, F_SETLKW, &requested) == 0;
            clock_gettime(CLOCK_MONOTONIC, &after);
            double elapsed = (after.tv_sec - before.tv_sec) +
                             (after.tv_nsec - before.tv_nsec) / 1e9;
            ok = ok && elapsed >= 0.015;
        }
        int status = -1;
        if (child > 0)
            waitpid(child, &status, 0);
        EXPECT_TRUE(ok && status == 0, "wait did not preserve lock ordering");
        close(ready_pipe[0]);
        close(go_pipe[1]);
    }

    close(fd);
    unlink(path);

    SUMMARY("test-flock");
    return fails == 0 ? 0 : 1;
}
