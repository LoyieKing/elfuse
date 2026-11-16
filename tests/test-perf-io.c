/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The host test drives stdout markers and stdin bytes over pipes, which are
 * excluded from disk/network accounting. Its HUD deltas include file copies, a
 * zero-byte UDP message, and a runnable versus parked thread pair.
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char buf[4096];

static void sync_point(void)
{
    char byte;

    if (read(STDIN_FILENO, &byte, 1) != 1)
        _exit(2);
}

static void marker(const char *text)
{
    printf("PERF %s\n", text);
    fflush(stdout);
}

static void disk_phase(void)
{
    struct iovec iov[2];
    int fd = open("perf-io.dat", O_RDWR | O_CREAT | O_TRUNC, 0644);

    if (fd < 0) {
        perror("open perf-io.dat");
        _exit(3);
    }
    if (write(fd, buf, 1000) != 1000)
        _exit(4);
    if (pwrite(fd, buf, 200, 0) != 200)
        _exit(5);
    iov[0] = (struct iovec) {.iov_base = buf, .iov_len = 100};
    iov[1] = (struct iovec) {.iov_base = buf + 100, .iov_len = 150};
    if (writev(fd, iov, 2) != 250)
        _exit(6);
    iov[0] = (struct iovec) {.iov_base = buf, .iov_len = 40};
    iov[1] = (struct iovec) {.iov_base = buf + 40, .iov_len = 60};
    if (pwritev(fd, iov, 2, 100) != 100)
        _exit(7);

    if (lseek(fd, 0, SEEK_SET) != 0)
        _exit(8);
    if (read(fd, buf, 500) != 500)
        _exit(9);
    if (pread(fd, buf, 300, 10) != 300)
        _exit(10);
    iov[0] = (struct iovec) {.iov_base = buf, .iov_len = 200};
    iov[1] = (struct iovec) {.iov_base = buf + 200, .iov_len = 100};
    if (readv(fd, iov, 2) != 300)
        _exit(11);
    iov[0] = (struct iovec) {.iov_base = buf, .iov_len = 50};
    iov[1] = (struct iovec) {.iov_base = buf + 50, .iov_len = 25};
    if (preadv(fd, iov, 2, 0) != 75)
        _exit(12);
    close(fd);
}

/* sendfile, copy_file_range and splice over regular files. Each pair counts one
 * read on the file input and one write on the file output; the pipe end of a
 * splice is PERF_IO_NONE, so the two splice calls together add one file read
 * and one file write of 64 bytes.
 */
static void pair_phase(void)
{
    int in = open("perf-io.dat", O_RDONLY);
    int sent = open("perf-send.dat", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    int copied = open("perf-copy.dat", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    int spliced = open("perf-splice.dat", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    int pipefd[2];

    if (in < 0 || sent < 0 || copied < 0 || spliced < 0)
        _exit(36);
    if (sendfile(sent, in, NULL, 128) != 128)
        _exit(37);
    if (copy_file_range(in, NULL, copied, NULL, 96, 0) != 96)
        _exit(38);
    if (pipe(pipefd) != 0)
        _exit(39);
    if (splice(in, NULL, pipefd[1], NULL, 64, 0) != 64)
        _exit(40);
    if (splice(pipefd[0], NULL, spliced, NULL, 64, 0) != 64)
        _exit(41);
    close(pipefd[0]);
    close(pipefd[1]);
    close(spliced);
    close(copied);
    close(sent);
    close(in);
}

/* Loopback socket address after bind, so the peer dials the ephemeral port. */
static socklen_t bound_address(int fd, struct sockaddr_in *addr)
{
    socklen_t len = sizeof(*addr);

    memset(addr, 0, sizeof(*addr));
    if (getsockname(fd, (struct sockaddr *) addr, &len) != 0) {
        perror("getsockname");
        _exit(13);
    }
    return len;
}

static void tcp_phase(void)
{
    struct sockaddr_in addr;
    struct msghdr msg;
    struct iovec iov;
    socklen_t len;
    int listener;
    int client;
    int server;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *) &addr, sizeof(addr)) != 0 ||
        listen(listener, 1) != 0)
        _exit(14);
    len = bound_address(listener, &addr);
    client = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(client, (struct sockaddr *) &addr, len) != 0)
        _exit(15);
    server = accept(listener, NULL, NULL);

    /* write/read, send/recv, sendmsg/recvfrom: one byte each way per pair. */
    if (write(client, "x", 1) != 1 || read(server, buf, 1) != 1)
        _exit(16);
    if (send(client, buf, 32, 0) != 32 || recv(server, buf, 32, 0) != 32)
        _exit(17);
    memset(&msg, 0, sizeof(msg));
    iov = (struct iovec) {.iov_base = buf, .iov_len = 16};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (sendmsg(client, &msg, 0) != 16)
        _exit(18);
    if (recvfrom(server, buf, 16, 0, NULL, NULL) != 16)
        _exit(19);
    close(server);
    close(client);
    close(listener);
}

static void udp_phase(void)
{
    struct sockaddr_in addr;
    struct msghdr msg;
    struct iovec iov;
    socklen_t len;
    int server;
    int client;

    server = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(server, (struct sockaddr *) &addr, sizeof(addr)) != 0)
        _exit(20);
    len = bound_address(server, &addr);
    client = socket(AF_INET, SOCK_DGRAM, 0);
    if (connect(client, (struct sockaddr *) &addr, len) != 0)
        _exit(21);

    /* send/recv, sendto/recvfrom, sendmsg/recvmsg, then an empty datagram. */
    if (send(client, buf, 100, 0) != 100 ||
        recvfrom(server, buf, 100, 0, NULL, NULL) != 100)
        _exit(22);
    if (sendto(client, buf, 100, 0, NULL, 0) != 100 ||
        recv(server, buf, 100, 0) != 100)
        _exit(23);
    memset(&msg, 0, sizeof(msg));
    iov = (struct iovec) {.iov_base = buf, .iov_len = 64};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (sendmsg(client, &msg, 0) != 64)
        _exit(24);
    memset(&msg, 0, sizeof(msg));
    iov = (struct iovec) {.iov_base = buf, .iov_len = 64};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (recvmsg(server, &msg, 0) != 64)
        _exit(25);
    if (sendto(client, buf, 0, 0, NULL, 0) != 0)
        _exit(26);
    if (recv(server, buf, 100, 0) != 0)
        _exit(27);
    close(client);
    close(server);
}

/* Pipe and AF_UNIX traffic: IPC, not a disk or INET transfer. */
static void exclusion_phase(void)
{
    int pipefd[2];
    int pair[2];

    if (pipe(pipefd) != 0)
        _exit(28);
    if (write(pipefd[1], buf, 100) != 100 || read(pipefd[0], buf, 100) != 100)
        _exit(29);
    close(pipefd[0]);
    close(pipefd[1]);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
        _exit(30);
    if (send(pair[0], buf, 100, 0) != 100 || recv(pair[1], buf, 100, 0) != 100)
        _exit(31);
    close(pair[0]);
    close(pair[1]);
}

static void *parked_helper(void *arg)
{
    char byte;
    int fd = *(int *) arg;

    /* Blocks in the guest's pipe wait for the whole threads phase. */
    (void) read(fd, &byte, 1);
    return NULL;
}

static void threads_phase(void)
{
    volatile unsigned long spins = 0;
    struct timespec start;
    struct timespec now;
    pthread_t helper;
    int pipefd[2];

    if (pipe(pipefd) != 0)
        _exit(32);
    if (pthread_create(&helper, NULL, parked_helper, &pipefd[0]) != 0)
        _exit(33);
    marker("THREADS");
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
        _exit(34);
    do {
        spins++;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
            _exit(35);
    } while ((now.tv_sec - start.tv_sec) * 1000000000L +
                 (now.tv_nsec - start.tv_nsec) <
             3000000000L);
    marker("DONE");
    close(pipefd[1]);
    pthread_join(helper, NULL);
}

static void fork_phase(void)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int gate[2];
    int server = socket(AF_INET, SOCK_DGRAM, 0);
    int client = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (server < 0 || client < 0 ||
        bind(server, (struct sockaddr *) &addr, sizeof(addr)) != 0 ||
        getsockname(server, (struct sockaddr *) &addr, &len) != 0 ||
        connect(client, (struct sockaddr *) &addr, len) != 0 || pipe(gate) != 0)
        _exit(36);
    pid_t child = fork();
    if (child < 0)
        _exit(37);
    if (child == 0) {
        close(gate[1]);
        if (send(client, buf, 17, 0) != 17)
            _exit(38);
        marker("FORK");
        char byte;
        if (read(gate[0], &byte, 1) != 1)
            _exit(39);
        _exit(0);
    }
    close(gate[0]);
    if (recv(server, buf, 17, 0) != 17)
        _exit(40);
    sync_point();
    if (write(gate[1], buf, 1) != 1)
        _exit(41);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        _exit(42);
    close(gate[1]);
    close(server);
    close(client);
}

int main(void)
{
    memset(buf, 'x', sizeof(buf));
    marker("BASELINE");
    sync_point();

    disk_phase();
    pair_phase();
    tcp_phase();
    udp_phase();
    exclusion_phase();

    marker("WORKLOAD");
    sync_point();
    threads_phase();
    fork_phase();
    return 0;
}
