/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "host-test-util.h"
#include "utils.h"

static const char requests[] = "$qAttached#8f$qAttached#8f";
static const char replies[] = "+$1#31+$1#31";
static int server_fd;
static int read_calls;
static int poll_calls;

static void require(bool ok, const char *detail)
{
    host_check(ok, "buffered session", detail);
    if (!ok)
        exit(EXIT_FAILURE);
}

static ssize_t batch_read(int fd, void *buf, size_t count)
{
    require(fd == server_fd && ++read_calls == 1,
            "only one transport read is needed");
    require(count >= sizeof(requests) - 1, "the read buffer fits both packets");

    /* Return both packets together even when the socket returns short reads. */
    size_t used = 0;
    while (used < sizeof(requests) - 1) {
        ssize_t n = read(fd, (char *) buf + used, sizeof(requests) - 1 - used);
        if (n < 0 && errno == EINTR)
            continue;
        require(n > 0, "the queued request bytes are readable");
        used += (size_t) n;
    }
    int queued = -1;
    require(ioctl(fd, FIONREAD, &queued) == 0 && queued == 0,
            "the socket is empty after the transport read");
    return (ssize_t) used;
}

static int session_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    require(count == 1 && fds[0].fd == server_fd && fds[0].events == POLLIN &&
                timeout == -1,
            "the session polls its client socket");
    poll_calls++;

    /* Keep real readiness results, but return immediately at an empty socket.
     */
    int ready = poll(fds, count, 0);
    require(
        poll_calls == 1 ? ready == 1 && fds[0].revents == POLLIN : ready == 0,
        "only the initial poll finds socket input");
    return ready;
}

/* Compile the real session and transport with only their I/O calls wrapped. */
#define read batch_read
#include "../src/debug/gdbstub-rsp.c"
#undef read
#define poll session_poll
#include "../src/debug/gdbstub.c"
#undef poll

/* No guest or vCPU operation belongs to a qAttached exchange. */
static _Noreturn void unexpected_call(const char *name)
{
    host_fail("unexpected dependency", name);
    exit(EXIT_FAILURE);
}

_Thread_local thread_entry_t *current_thread;

bool vcpu_pool_current_vcpu(hv_vcpu_t *out)
{
    (void) out;
    unexpected_call(__func__);
}

thread_entry_t *thread_find(int64_t tid)
{
    unexpected_call(__func__);
}

bool thread_tid_alive(int64_t tid)
{
    unexpected_call(__func__);
}

void thread_for_each(void (*fn)(thread_entry_t *t, void *ctx), void *ctx)
{
    unexpected_call(__func__);
}

void thread_interrupt_all(void)
{
    unexpected_call(__func__);
}

void sched_domain_debug_freeze(bool frozen)
{
    unexpected_call(__func__);
}

bool sched_task_is_running(const thread_entry_t *t)
{
    unexpected_call(__func__);
}

void thread_sp_el1_region(const guest_t *g, uint64_t *lo, uint64_t *hi)
{
    unexpected_call(__func__);
}

guest_t *vcpu_pool_guest(void)
{
    unexpected_call(__func__);
}

void signal_publish_shim_frame_gprs(hv_vcpu_t vcpu,
                                    const guest_t *g,
                                    const uint64_t gprs[31])
{
    unexpected_call(__func__);
}

void *guest_ptr_bound(const guest_t *g,
                      uint64_t gva,
                      uint64_t *avail,
                      int required_perms,
                      uint64_t len_limit)
{
    unexpected_call(__func__);
}

int guest_read(const guest_t *g, uint64_t gva, void *dst, size_t len)
{
    unexpected_call(__func__);
}

int guest_write(guest_t *g, uint64_t gva, const void *src, size_t len)
{
    unexpected_call(__func__);
}

void log_impl(int level, const char *file, int line, const char *fmt, ...)
{
    unexpected_call(__func__);
}

int main(void)
{
    int sockets[2];
    require(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "socketpair");
    server_fd = sockets[0];
    require(fcntl(server_fd, F_SETFL, O_NONBLOCK) == 0 &&
                fcntl(sockets[1], F_SETFL, O_NONBLOCK) == 0,
            "unexpected socket reads must not block");
    require(write_all(sockets[1], requests, sizeof(requests) - 1) == 0,
            "queue both requests before entering the session");

    gdb.client_fd = server_fd;
    gdb_client_session();

    require(read_calls == 1, "both requests use one transport read");
    require(poll_calls == 2, "poll only before input and after draining it");
    require(gdb.rsp_ctx == NULL, "the session clears its transport pointer");

    int queued = -1;
    require(ioctl(server_fd, FIONREAD, &queued) == 0 && queued == 0,
            "no further client input wakes the session");
    require(ioctl(sockets[1], FIONREAD, &queued) == 0 &&
                queued == sizeof(replies) - 1,
            "both replies arrived before further client input");
    char received[sizeof(replies) - 1];
    size_t used = 0;
    while (used < sizeof(received)) {
        ssize_t n = read(sockets[1], received + used, sizeof(received) - used);
        if (n < 0 && errno == EINTR)
            continue;
        require(n > 0, "read the queued replies");
        used += (size_t) n;
    }
    require(memcmp(received, replies, sizeof(received)) == 0,
            "both requests produce their ACK and checksummed reply");

    close(sockets[0]);
    close(sockets[1]);
    gdb.client_fd = -1;
    return host_summary("test-gdbstub-host");
}
