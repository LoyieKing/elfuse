/*
 * Runs the shared-futex assertions in two independent elfuse instances.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define ELFUSE_BIN "build/elfuse"
#define GUEST_NAME "test-futex-shared-vm"
#define RUN_TIMEOUT_SEC 90

/* Start one independent elfuse running @mode with @sock_fd as stdin and @out_fd
 * as stdout. The child closes every descriptor it inherited from the harness,
 * so neither instance holds the other's socket end or capture file.
 */
static pid_t spawn_guest(int sock_fd,
                         int other_sock_fd,
                         int out_fd,
                         int other_out_fd,
                         const char *guest,
                         const char *mode)
{
    pid_t pid = fork();

    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (dup2(sock_fd, STDIN_FILENO) < 0 || dup2(out_fd, STDOUT_FILENO) < 0)
            _exit(127);
        close(sock_fd);
        close(other_sock_fd);
        close(out_fd);
        close(other_out_fd);
        execl(ELFUSE_BIN, ELFUSE_BIN, guest, mode, (char *) NULL);
        _exit(127);
    }
    return pid;
}

static void dump_output(int fd, const char *mode)
{
    char buf[4096];
    ssize_t n;
    off_t off = 0;

    fprintf(stderr, "--- %s guest output ---\n", mode);
    while ((n = pread(fd, buf, sizeof(buf), off)) > 0) {
        fwrite(buf, 1, (size_t) n, stderr);
        off += n;
    }
    fprintf(stderr, "\n");
}


static const char *find_guest(void)
{
    static const char *const paths[] = {
        "build/" GUEST_NAME,
        "build/bin/" GUEST_NAME,
    };

    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (access(paths[i], R_OK) == 0)
            return paths[i];
    }
    return NULL;
}

int main(void)
{
    const char *guest;
    int sockets[2];
    char send_path[] = "/tmp/elfuse-futex-shared-vm-ab-XXXXXX";
    char recv_path[] = "/tmp/elfuse-futex-shared-vm-ba-XXXXXX";
    int send_out;
    int recv_out;
    pid_t owner;
    pid_t peer;
    int owner_status = -1;
    int peer_status = -1;
    bool spawned;

    printf("%s: one memfd's futex queue across independent elfuse instances\n",
           GUEST_NAME);

    guest = find_guest();
    if (access(ELFUSE_BIN, X_OK) != 0 || !guest) {
        FAIL("elfuse or the shared futex guest is not built");
        return 1;
    }
    alarm(RUN_TIMEOUT_SEC);

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        TEST("socketpair");
        FAIL("socketpair failed");
        SUMMARY("test-futex-shared-vm-host");
        return 1;
    }
    send_out = mkstemp(send_path);
    recv_out = mkstemp(recv_path);
    if (send_out < 0 || recv_out < 0) {
        TEST("capture files");
        FAIL("mkstemp failed");
        close(sockets[0]);
        close(sockets[1]);
        if (send_out >= 0)
            close(send_out);
        if (recv_out >= 0)
            close(recv_out);
        SUMMARY("test-futex-shared-vm-host");
        return 1;
    }
    unlink(send_path);
    unlink(recv_path);

    owner =
        spawn_guest(sockets[0], sockets[1], send_out, recv_out, guest, "peer0");
    peer =
        spawn_guest(sockets[1], sockets[0], recv_out, send_out, guest, "peer1");
    close(sockets[0]);
    close(sockets[1]);
    spawned = owner > 0 && peer > 0;

    if (owner > 0) {
        int status = 0;

        if (waitpid(owner, &status, 0) >= 0 && WIFEXITED(status))
            owner_status = WEXITSTATUS(status);
    }
    if (peer > 0) {
        int status = 0;

        if (waitpid(peer, &status, 0) >= 0 && WIFEXITED(status))
            peer_status = WEXITSTATUS(status);
    }

    TEST("the descriptor owner instance exits 0");
    if (!spawned)
        FAIL("fork failed");
    else if (owner_status != 0) {
        dump_output(send_out, "peer0");
        FAIL("the owner instance did not exit 0");
    } else
        PASS();

    TEST("the receiving instance exits 0");
    if (!spawned)
        FAIL("fork failed");
    else if (peer_status != 0) {
        dump_output(recv_out, "peer1");
        FAIL("the receiving instance did not exit 0");
    } else
        PASS();


    close(send_out);
    close(recv_out);
    SUMMARY("test-futex-shared-vm-host");
    return fails == 0 ? 0 : 1;
}
