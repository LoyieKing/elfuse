/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes, fails;

static int connect_proxy(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, "/dev/socket/dnsproxyd", sizeof("/dev/socket/dnsproxyd"));
    if (connect(fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int receive_all(int fd, void *buffer, size_t bytes)
{
    uint8_t *out = buffer;
    while (bytes) {
        ssize_t n = read(fd, out, bytes);
        if (n <= 0)
            return -1;
        out += n;
        bytes -= (size_t) n;
    }
    return 0;
}

static int receive_word(int fd, uint32_t *value)
{
    uint32_t wire;
    if (receive_all(fd, &wire, sizeof(wire)) < 0)
        return -1;
    *value = ntohl(wire);
    return 0;
}

static int query_numeric(int fd)
{
    static const char query[] = "getaddrinfo 127.0.0.42 443 12 2 1 6 100";
    if (write(fd, query, sizeof(query)) != sizeof(query))
        return -1;
    char code[4];
    if (receive_all(fd, code, sizeof(code)) < 0 || memcmp(code, "222", 4))
        return -1;
    uint32_t present, flags, family, type, protocol, length;
    if (receive_word(fd, &present) || present != 1 || receive_word(fd, &flags) ||
        receive_word(fd, &family) || receive_word(fd, &type) || receive_word(fd, &protocol) ||
        receive_word(fd, &length) || family != AF_INET || type != SOCK_STREAM ||
        protocol != IPPROTO_TCP || length != sizeof(struct sockaddr_in))
        return -1;
    struct sockaddr_in address;
    if (receive_all(fd, &address, sizeof(address)) || address.sin_family != AF_INET ||
        address.sin_port != htons(443) || ntohl(address.sin_addr.s_addr) != 0x7f00002a)
        return -1;
    if (receive_word(fd, &length) || length > 1025)
        return -1;
    char name[1025];
    if (receive_all(fd, name, length) || receive_word(fd, &present) || present != 0)
        return -1;
    return 0;
}

int main(void)
{
    TEST("Android resolver numeric reply and hidden listener path");
    int fd = connect_proxy();
    if (fd < 0) {
        FAIL("connect Android resolver");
        SUMMARY("dns-proxy");
        return 1;
    }
    struct sockaddr_un peer;
    socklen_t size = sizeof(peer);
    EXPECT_EQ(getpeername(fd, (struct sockaddr *) &peer, &size), 0, "getpeername");
    EXPECT_TRUE(!strcmp(peer.sun_path, "/dev/socket/dnsproxyd"), "private listener path exposed");
    int alias = dup(fd);
    close(fd);
    EXPECT_TRUE(alias >= 0 && query_numeric(alias) == 0, "numeric address and port survive dup");
    if (alias >= 0)
        close(alias);

    TEST("fork shares connected resolver description");
    fd = connect_proxy();
    pid_t child = fork();
    if (child == 0) {
        int rc = query_numeric(fd);
        close(fd);
        _exit(rc ? 1 : 0);
    }
    close(fd);
    int status = 0;
    EXPECT_TRUE(child > 0 && waitpid(child, &status, 0) == child &&
                    WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "inherited resolver request failed");

    TEST("unknown netid and malformed query are rejected");
    fd = connect_proxy();
    static const char bad_net[] = "getaddrinfo 127.0.0.42 443 12 2 1 6 101";
    char code[4];
    EXPECT_TRUE(fd >= 0 && write(fd, bad_net, sizeof(bad_net)) == sizeof(bad_net) &&
                    receive_all(fd, code, sizeof(code)) == 0 && !memcmp(code, "401", 4),
                "unknown network accepted");
    close(fd);
    fd = connect_proxy();
    static const char bad_base64[] = "resnsend 100 0 A===junk";
    uint32_t error = 0;
    EXPECT_TRUE(fd >= 0 && write(fd, bad_base64, sizeof(bad_base64)) == sizeof(bad_base64) &&
                    receive_word(fd, &error) == 0 && (int32_t) error < 0,
                "malformed raw DNS query accepted");
    close(fd);
    SUMMARY("dns-proxy");
    return fails ? 1 : 0;
}
