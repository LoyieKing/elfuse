/*
 * A memfd keeps its name and seals across independent elfuse instances
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A memfd is an unlinked regular file on the host, so the descriptor alone
 * tells a second elfuse process nothing about its Linux identity. This launches
 * two top-level elfuse processes, connects their stdio with one socketpair, and
 * has the sender pass a memfd, an unlinked ordinary file, and a file whose host
 * name contains "memfd" over SCM_RIGHTS. The receiver checks the exact magic
 * link, the seal set, the ashmem size, shared bytes, and that neither ordinary
 * file gained an identity. The guest binary is tests/test-memfd-scm.c.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define ELFUSE_BIN "build/elfuse"

/* Start one independent elfuse running @mode with @sock_fd as stdin and @out_fd
 * as stdout. The child closes every descriptor it inherited from the harness so
 * neither instance holds the other's socket end or capture file.
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

int main(void)
{
    printf(
        "test-memfd-scm-host: memfd identity across independent elfuse "
        "instances\n");

    static const char *const guest_paths[] = {
        "build/test-memfd-scm",
        "build/bin/test-memfd-scm",
    };
    const char *guest = NULL;
    for (size_t i = 0; i < sizeof(guest_paths) / sizeof(guest_paths[0]); i++) {
        if (access(guest_paths[i], R_OK) == 0) {
            guest = guest_paths[i];
            break;
        }
    }
    if (access(ELFUSE_BIN, X_OK) != 0 || !guest) {
        FAIL("elfuse or memfd guest helper is not built");
        return 1;
    }
    alarm(60);

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        TEST("socketpair");
        FAIL("socketpair failed");
        SUMMARY("test-memfd-scm-host");
        return 1;
    }

    char send_path[] = "/tmp/elfuse-memfd-scm-sender-XXXXXX";
    char recv_path[] = "/tmp/elfuse-memfd-scm-receiver-XXXXXX";
    int send_out = mkstemp(send_path);
    int recv_out = mkstemp(recv_path);
    if (send_out < 0 || recv_out < 0) {
        TEST("capture files");
        FAIL("mkstemp failed");
        close(sockets[0]);
        close(sockets[1]);
        if (send_out >= 0)
            close(send_out);
        if (recv_out >= 0)
            close(recv_out);
        SUMMARY("test-memfd-scm-host");
        return 1;
    }
    unlink(send_path);
    unlink(recv_path);

    pid_t sender = spawn_guest(sockets[0], sockets[1], send_out, recv_out,
                               guest, "sender");
    pid_t receiver = spawn_guest(sockets[1], sockets[0], recv_out, send_out,
                                 guest, "receiver");
    close(sockets[0]);
    close(sockets[1]);

    int sender_status = -1;
    int receiver_status = -1;
    bool spawned = sender > 0 && receiver > 0;

    if (sender > 0) {
        int status = 0;
        if (waitpid(sender, &status, 0) >= 0 && WIFEXITED(status))
            sender_status = WEXITSTATUS(status);
    }
    if (receiver > 0) {
        int status = 0;
        if (waitpid(receiver, &status, 0) >= 0 && WIFEXITED(status))
            receiver_status = WEXITSTATUS(status);
    }

    TEST("sender instance exits 0");
    if (!spawned)
        FAIL("fork failed");
    else if (sender_status != 0) {
        dump_output(send_out, "sender");
        FAIL("sender instance did not exit 0");
    } else
        PASS();

    TEST("receiver instance exits 0");
    if (!spawned)
        FAIL("fork failed");
    else if (receiver_status != 0) {
        dump_output(recv_out, "receiver");
        FAIL("receiver instance did not exit 0");
    } else
        PASS();

    close(send_out);
    close(recv_out);
    SUMMARY("test-memfd-scm-host");
    return fails == 0 ? 0 : 1;
}
