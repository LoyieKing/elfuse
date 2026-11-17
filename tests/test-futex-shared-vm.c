/*
 * SCM_RIGHTS shares one backing object between independent elfuse instances.
 * The default mode runs both peers under the reference Linux kernel.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <linux/futex.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "raw-syscall.h"
#include "test-harness.h"

int passes = 0, fails = 0;

#ifndef SYS_memfd_create
#define SYS_memfd_create 279
#endif

#define LINUX_EINTR 4
#define LINUX_EAGAIN 11
#define LINUX_EINVAL 22
#define LINUX_ETIMEDOUT 110

#define PAGE 4096
#define MAP_LEN (3 * PAGE)
#define NS_PER_MS 1000000LL

/* Futex words as byte offsets into the shared mapping. Each phase owns its own
 * words, so a wake in one phase cannot be read as another phase's answer.
 */
#define W_HANDOFF 0u
#define W_PAIR (4u * 8u)
#define W_BITSET (4u * 9u)
#define W_TIMED (4u * 10u)
#define W_PAST (4u * 11u)
#define W_ISO (4u * 12u)
#define W_SIGNAL (4u * 13u)
#define W_DEATH (4u * 14u)
#define W_OTHER_PAGE PAGE

#define ROUNDS 2
#define HANDOFF_WAIT_SEC 2
#define PAIR_WAIT_SEC 2
#define BITSET_WAIT_SEC 3
#define WAKE_TRIES 2000000
#define WAKE_DEADLINE_MS 2000
#define ARMED_DEADLINE_MS 2000
#define PEER_TIMEOUT_MS 20000
#define BITSET_MASK_A 0x1u
#define BITSET_MASK_B 0x2u
#define BITSET_MASK_NONE 0x4u
#define BITSET_PROBES 32
#define ISO_PROBES 8
#define ISO_WAIT_SEC 1
#define ISO_MIN_MS 200
#define TIMED_WAIT_MS 150
#define TIMED_MIN_MS 100
#define DEATH_WAIT_MS 300
#define DEATH_MIN_MS 200
#define SIGNAL_ATTEMPTS 3
#define SIGNAL_SETTLE_MS 200

#define MSG_ARMED 1
#define MSG_WAIT 2
#define MSG_SIGNAL_DONE 3

typedef struct {
    uint32_t cmd;
    int32_t arg;
} peer_msg_t;

static int64_t now_ns(clockid_t clock)
{
    struct timespec ts;

    if (clock_gettime(clock, &ts) != 0)
        return 0;
    return (int64_t) ts.tv_sec * 1000000000LL + (int64_t) ts.tv_nsec;
}

static void check(const char *what, bool ok, long detail)
{
    TEST(what);
    if (ok) {
        PASS();
        return;
    }
    printf("got %ld: ", detail);
    FAIL("unexpected shared futex result");
}

static long futex_op(uint32_t *word,
                     int op,
                     uint32_t val,
                     const struct timespec *timeout,
                     uint32_t bitset)
{
    return raw_syscall6(__NR_futex, (long) word, (long) op, (long) val,
                        (long) timeout, 0, (long) bitset);
}

static uint32_t *word_at(uint32_t *base, size_t offset)
{
    return (uint32_t *) ((uint8_t *) base + offset);
}

/* The futex word's layout is fixed by the guest ABI, so this cast is how the
 * tree states that a store to one is a shared store.
 */
static void word_reset(uint32_t *word)
{
    atomic_store_explicit((_Atomic uint32_t *) word, 0, memory_order_relaxed);
}

static bool write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;

    while (len > 0) {
        ssize_t n = write(fd, p, len);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (n == 0)
            return false;
        p += n;
        len -= (size_t) n;
    }
    return true;
}

/* Bounded on both ends: poll before each read, so a peer that died mid-message
 * costs one timeout instead of parking the lane.
 */
static bool read_all(int fd, void *buf, size_t len)
{
    char *p = buf;

    while (len > 0) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int prc;
        ssize_t n;

        do {
            prc = poll(&pfd, 1, PEER_TIMEOUT_MS);
        } while (prc < 0 && errno == EINTR);
        if (prc <= 0) {
            errno = prc == 0 ? ETIMEDOUT : errno;
            return false;
        }
        n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (n == 0) {
            errno = EPROTO; /* the peer is gone */
            return false;
        }
        p += n;
        len -= (size_t) n;
    }
    return true;
}

static bool peer_send(int sock, uint32_t cmd, int32_t arg)
{
    peer_msg_t msg = {.cmd = cmd, .arg = arg};

    return write_all(sock, &msg, sizeof(msg));
}

static bool peer_recv(int sock, uint32_t cmd, int32_t *arg)
{
    peer_msg_t msg;

    if (!read_all(sock, &msg, sizeof(msg)))
        return false;
    if (msg.cmd != cmd) {
        errno = EPROTO;
        return false;
    }
    if (arg)
        *arg = msg.arg;
    return true;
}

static int create_memfd(const char *name)
{
    int fd = (int) syscall(SYS_memfd_create, name, 0);

    if (fd < 0)
        return -1;
    if (ftruncate(fd, MAP_LEN) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool send_fd(int sock, int fd)
{
    union {
        char ctrl[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } ctrl;
    char payload = 'f';
    struct iovec iov = {.iov_base = &payload, .iov_len = 1};
    struct msghdr msg;
    struct cmsghdr *cmsg;

    memset(&ctrl, 0, sizeof(ctrl));
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.ctrl;
    msg.msg_controllen = sizeof(ctrl.ctrl);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

    return sendmsg(sock, &msg, 0) == 1;
}

static int recv_fd(int sock)
{
    union {
        char ctrl[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } ctrl;
    char payload = 0;
    struct iovec iov = {.iov_base = &payload, .iov_len = 1};
    struct msghdr msg;
    struct cmsghdr *cmsg;
    int fd = -1;

    memset(&ctrl, 0, sizeof(ctrl));
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.ctrl;
    msg.msg_controllen = sizeof(ctrl.ctrl);

    if (recvmsg(sock, &msg, 0) != 1)
        return -1;
    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len < CMSG_LEN(sizeof(int)))
        return -1;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
    return fd;
}

/* Zero means the peer has not enqueued yet or has nobody: the first non-zero
 * answer is what proves the enqueue, so no sleep stands in for it.
 */
static long wake_until_nonzero(uint32_t *word,
                               int op,
                               uint32_t val,
                               uint32_t bitset)
{
    int64_t deadline = now_ns(CLOCK_MONOTONIC) + WAKE_DEADLINE_MS * NS_PER_MS;

    for (int i = 0; i < WAKE_TRIES; i++) {
        long n = futex_op(word, op, val, NULL, bitset);

        if (n != 0)
            return n;
        if (now_ns(CLOCK_MONOTONIC) > deadline)
            break;
    }
    return 0;
}


typedef struct {
    uint32_t *word;
    int op;
    uint32_t bitset;
    int sec;
    _Atomic int armed;
    long rc;
} shared_wait_t;

/* FUTEX_WAIT takes a relative timeout and FUTEX_WAIT_BITSET an absolute one, so
 * the same thread body serves both. Every wait here has a deadline, which is
 * what keeps a lost wake a failed assertion instead of a hung lane.
 */
static void *shared_waiter(void *arg)
{
    shared_wait_t *w = arg;
    struct timespec timeout;

    if (w->op == FUTEX_WAIT) {
        timeout.tv_sec = w->sec;
        timeout.tv_nsec = 0;
    } else {
        clock_gettime(CLOCK_MONOTONIC, &timeout);
        timeout.tv_sec += w->sec;
    }
    atomic_store_explicit(&w->armed, 1, memory_order_release);
    w->rc = futex_op(w->word, w->op, 0, &timeout, w->bitset);
    return NULL;
}

static bool wait_armed(_Atomic int *armed)
{
    int64_t deadline = now_ns(CLOCK_MONOTONIC) + ARMED_DEADLINE_MS * NS_PER_MS;

    while (atomic_load_explicit(armed, memory_order_acquire) == 0) {
        if (now_ns(CLOCK_MONOTONIC) > deadline)
            return false;
    }
    return true;
}

static void on_signal(int sig)
{
    (void) sig;
}

/* A signal queued at a waiter parked on a shared word nobody wakes must end the
 * wait with EINTR. A signal taken before the syscall is answered by the task
 * loop instead, so the attempt is retried rather than reported as a wait that
 * ignored the signal.
 */
static bool signal_round(uint32_t *word)
{
    for (int attempt = 0; attempt < SIGNAL_ATTEMPTS; attempt++) {
        shared_wait_t w = {.word = word,
                           .op = FUTEX_WAIT,
                           .bitset = 0,
                           .sec = HANDOFF_WAIT_SEC,
                           .rc = 0};
        pthread_t th;
        struct timespec settle = {0, SIGNAL_SETTLE_MS * NS_PER_MS};

        word_reset(word);
        atomic_init(&w.armed, 0);
        if (pthread_create(&th, NULL, shared_waiter, &w) != 0)
            return false;
        if (!wait_armed(&w.armed)) {
            pthread_join(th, NULL);
            return false;
        }
        nanosleep(&settle, NULL);
        if (pthread_kill(th, SIGUSR1) != 0) {
            pthread_join(th, NULL);
            return false;
        }
        pthread_join(th, NULL);
        if (w.rc == -LINUX_EINTR)
            return true;
    }
    return false;
}

/* The two peers alternate who parks. Each round asserts three counts: the wake
 * that met the peer answered 1, the peer's wait answered 0, and a wake after
 * that answered 0. A wake answered before the peer enqueued counts 0 and is
 * simply retried.
 */
static void handoff_round(int self, int sock, uint32_t *base, int round)
{
    uint32_t *word = word_at(base, W_HANDOFF + 4u * (uint32_t) round);
    int32_t peer_rc = 0;
    long woken;

    if (self == round % 2) {
        struct timespec rel = {HANDOFF_WAIT_SEC, 0};
        long rc;

        word_reset(word);
        (void) peer_send(sock, MSG_ARMED, round);
        rc = futex_op(word, FUTEX_WAIT, 0, &rel, 0);
        (void) peer_send(sock, MSG_WAIT, (int32_t) rc);
        check("a shared wait answers its wake", rc == 0, rc);
        return;
    }

    if (!peer_recv(sock, MSG_ARMED, NULL)) {
        check("the peering wait is announced", false, -1);
        return;
    }
    woken = wake_until_nonzero(word, FUTEX_WAKE, 1, 0);
    check("a shared wake answers exactly one", woken == 1, woken);
    if (!peer_recv(sock, MSG_WAIT, &peer_rc)) {
        check("the peering wait reports its result", false, -1);
        return;
    }
    check("the woken peer returned from its wait", peer_rc == 0, peer_rc);
    check("a retired waiter answers zero",
          futex_op(word, FUTEX_WAKE, 1, NULL, 0) == 0, -1);
}

/* Two waiters in one process on one word, woken from the other process. The
 * total across calls must be exactly two and both waits must return 0: a third
 * count is a double count, fewer leaves a wait to time out.
 */
static void pair_waits(int sock, uint32_t *base)
{
    uint32_t *word = word_at(base, W_PAIR);
    shared_wait_t a = {.word = word,
                       .op = FUTEX_WAIT,
                       .bitset = 0,
                       .sec = PAIR_WAIT_SEC,
                       .rc = 0};
    shared_wait_t b = a;
    pthread_t th_a, th_b;

    word_reset(word);
    atomic_init(&a.armed, 0);
    atomic_init(&b.armed, 0);
    if (pthread_create(&th_a, NULL, shared_waiter, &a) != 0) {
        check("two shared waiters start", false, -1);
        (void) peer_send(sock, MSG_WAIT, 0);
        return;
    }
    if (pthread_create(&th_b, NULL, shared_waiter, &b) != 0) {
        check("two shared waiters start", false, -1);
        (void) peer_send(sock, MSG_WAIT, 0);
        pthread_join(th_a, NULL);
        return;
    }
    check("two shared waiters start",
          wait_armed(&a.armed) && wait_armed(&b.armed), -1);
    (void) peer_send(sock, MSG_ARMED, 2);
    pthread_join(th_a, NULL);
    pthread_join(th_b, NULL);
    (void) peer_send(sock, MSG_WAIT, a.rc == 0 && b.rc == 0 ? 1 : 0);
    check("both shared waits answer their wake", a.rc == 0 && b.rc == 0,
          a.rc == 0 ? b.rc : a.rc);
}

static void pair_waking(int sock, uint32_t *base)
{
    uint32_t *word = word_at(base, W_PAIR);
    int64_t deadline = now_ns(CLOCK_MONOTONIC) + WAKE_DEADLINE_MS * NS_PER_MS;
    int32_t both_ok = 0;
    long total = 0;

    if (!peer_recv(sock, MSG_ARMED, NULL)) {
        check("two shared waiters are announced", false, -1);
        return;
    }
    while (total < 2 && now_ns(CLOCK_MONOTONIC) <= deadline) {
        long n = futex_op(word, FUTEX_WAKE, 1, NULL, 0);

        if (n < 0) {
            total = n;
            break;
        }
        total += n;
    }
    check("the peer's two waits are woken once each", total == 2, total);
    if (!peer_recv(sock, MSG_WAIT, &both_ok)) {
        check("the two waits report their results", false, -1);
        return;
    }
    check("both waiters of one word returned", both_ok == 1, both_ok);
    check("no waiter is left on the word",
          futex_op(word, FUTEX_WAKE, 2, NULL, 0) == 0, -1);
}

static void bitset_waits(int sock, uint32_t *base)
{
    uint32_t *word = word_at(base, W_BITSET);
    shared_wait_t a = {.word = word,
                       .op = FUTEX_WAIT_BITSET,
                       .bitset = BITSET_MASK_A,
                       .sec = BITSET_WAIT_SEC,
                       .rc = 0};
    shared_wait_t b = a;
    struct timespec future;
    pthread_t th_a, th_b;
    long rc;

    b.bitset = BITSET_MASK_B;
    word_reset(word);
    atomic_init(&a.armed, 0);
    atomic_init(&b.armed, 0);
    if (pthread_create(&th_a, NULL, shared_waiter, &a) != 0) {
        check("two bitset waiters start", false, -1);
        (void) peer_send(sock, MSG_WAIT, 0);
        return;
    }
    if (pthread_create(&th_b, NULL, shared_waiter, &b) != 0) {
        check("two bitset waiters start", false, -1);
        (void) peer_send(sock, MSG_WAIT, 0);
        pthread_join(th_a, NULL);
        return;
    }
    check("two bitset waiters start",
          wait_armed(&a.armed) && wait_armed(&b.armed), -1);
    (void) peer_send(sock, MSG_ARMED, 0);
    pthread_join(th_a, NULL);
    pthread_join(th_b, NULL);
    check("both bitset waiters answer their own mask", a.rc == 0 && b.rc == 0,
          a.rc == 0 ? b.rc : a.rc);

    /* A zero bitset is EINVAL, and a deadline in the future keeps the answer
     * about the mask rather than about an expired timeout.
     */
    clock_gettime(CLOCK_MONOTONIC, &future);
    future.tv_sec += 1;
    word_reset(word);
    rc = futex_op(word, FUTEX_WAIT_BITSET, 0, &future, 0);
    check("a zero bitset is rejected by a wait", rc == -LINUX_EINVAL, rc);
}

static void bitset_wakes(int sock, uint32_t *base)
{
    uint32_t *word = word_at(base, W_BITSET);
    bool unmatched_zero = true;
    long woken;
    long rc;

    if (!peer_recv(sock, MSG_ARMED, NULL)) {
        check("two bitset waiters are announced", false, -1);
        return;
    }
    woken = wake_until_nonzero(word, FUTEX_WAKE_BITSET, 1, BITSET_MASK_A);
    check("a bitset wake reaches only its mask", woken == 1, woken);

    /* The 0x2 waiter is the only one left and this mask selects neither, so
     * every probe must answer zero. A wake answering otherwise either ignored
     * the mask or counted a retired waiter, and the 0x2 handoff below would
     * then have nobody to reach.
     */
    for (int i = 0; i < BITSET_PROBES; i++) {
        if (futex_op(word, FUTEX_WAKE_BITSET, 1, NULL, BITSET_MASK_NONE) != 0)
            unmatched_zero = false;
    }
    check("an unmatched mask answers zero", unmatched_zero, -1);
    woken = wake_until_nonzero(word, FUTEX_WAKE_BITSET, 1, BITSET_MASK_B);
    check("the second bitset waiter is still queued", woken == 1, woken);
    check("both bitset waiters retired",
          futex_op(word, FUTEX_WAKE_BITSET, 1, NULL, BITSET_MASK_B) == 0, -1);

    rc = futex_op(word, FUTEX_WAKE_BITSET, 1, NULL, 0);
    check("a zero bitset is rejected by a wake", rc == -LINUX_EINVAL, rc);
}

static void timed_wait(int sock, uint32_t *base)
{
    uint32_t *word = word_at(base, W_TIMED);
    uint32_t *past_word = word_at(base, W_PAST);
    struct timespec rel = {0, TIMED_WAIT_MS * NS_PER_MS};
    struct timespec past;
    int64_t start = now_ns(CLOCK_MONOTONIC);
    int64_t elapsed;
    long rc;

    word_reset(word);
    word_reset(past_word);
    (void) peer_send(sock, MSG_ARMED, 0);
    rc = futex_op(word, FUTEX_WAIT, 0, &rel, 0);
    elapsed = (now_ns(CLOCK_MONOTONIC) - start) / NS_PER_MS;
    (void) peer_send(sock, MSG_WAIT, (int32_t) rc);
    check("a shared wait with no waker times out", rc == -LINUX_ETIMEDOUT, rc);
    check("the shared timeout really blocked", elapsed >= TIMED_MIN_MS,
          elapsed);

    clock_gettime(CLOCK_MONOTONIC, &past);
    past.tv_sec -= 1;
    rc = futex_op(past_word, FUTEX_WAIT_BITSET, 0, &past,
                  FUTEX_BITSET_MATCH_ANY);
    check("a past bitset deadline times out at once", rc == -LINUX_ETIMEDOUT,
          rc);
}

static void timed_peering(int sock, uint32_t *base)
{
    int32_t peer_rc = 0;

    if (!peer_recv(sock, MSG_ARMED, NULL)) {
        check("the timed wait is announced", false, -1);
        return;
    }
    if (!peer_recv(sock, MSG_WAIT, &peer_rc)) {
        check("the timed wait reports its result", false, -1);
        return;
    }
    check("the peer's own wait timed out", peer_rc == -LINUX_ETIMEDOUT,
          peer_rc);
    check("a timed-out waiter is gone",
          futex_op(word_at(base, W_TIMED), FUTEX_WAKE, 1, NULL, 0) == 0, -1);
}

static void isolation_wait(int sock, uint32_t *base)
{
    uint32_t *word = word_at(base, W_ISO);
    struct timespec rel = {ISO_WAIT_SEC, 0};
    int64_t start;
    int64_t elapsed;
    long rc;

    word_reset(word);
    (void) peer_send(sock, MSG_ARMED, 0);
    start = now_ns(CLOCK_MONOTONIC);
    rc = futex_op(word, FUTEX_WAIT, 0, &rel, 0);
    elapsed = (now_ns(CLOCK_MONOTONIC) - start) / NS_PER_MS;
    (void) peer_send(sock, MSG_WAIT, (int32_t) rc);
    check("no other identity meets the shared wait", rc == -LINUX_ETIMEDOUT,
          rc);
    check("the isolation window really blocked", elapsed >= ISO_MIN_MS,
          elapsed);
}

/* Wakes the peer issues while its own process holds a waiter on the same word:
 * one at another offset of the same file, one on a second memfd, and one
 * through a private mapping of the same file at the same offset. None may meet
 * the parked waiter, and the waiter must outlive every probe.
 */
static void isolation_probing(int sock, int mfd, uint32_t *base)
{
    uint32_t *word = word_at(base, W_ISO);
    int other_fd = create_memfd("futex-shared-vm-other");
    uint32_t *other = other_fd >= 0 ? mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                                           MAP_SHARED, other_fd, 0)
                                    : MAP_FAILED;
    uint32_t *priv = MAP_FAILED;
    bool offset_apart = true;
    bool object_apart = true;
    bool private_apart = true;
    int32_t peer_rc = 0;

    if (other != MAP_FAILED)
        priv = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE, mfd, 0);
    if (other == MAP_FAILED || priv == MAP_FAILED) {
        check("the isolation mappings exist", false, -1);
        goto out;
    }
    if (!peer_recv(sock, MSG_ARMED, NULL)) {
        check("the isolated wait is announced", false, -1);
        goto out;
    }
    for (int i = 0; i < ISO_PROBES; i++) {
        if (futex_op(word_at(base, W_OTHER_PAGE), FUTEX_WAKE, 1, NULL, 0) != 0)
            offset_apart = false;
        if (futex_op(word_at(other, 0), FUTEX_WAKE, 1, NULL, 0) != 0)
            object_apart = false;
        if (futex_op(word_at(priv, W_ISO), FUTEX_WAKE, 1, NULL, 0) != 0)
            private_apart = false;
    }
    check("another offset of the file stays apart", offset_apart, -1);
    check("another object stays apart", object_apart, -1);
    check("a private mapping stays apart", private_apart, -1);
    if (!peer_recv(sock, MSG_WAIT, &peer_rc)) {
        check("the isolated wait reports its result", false, -1);
        goto out;
    }
    check("the isolated wait outlived every probe", peer_rc == -LINUX_ETIMEDOUT,
          peer_rc);
    check("the isolated waiter is gone",
          futex_op(word, FUTEX_WAKE, 1, NULL, 0) == 0, -1);
out:
    if (other != MAP_FAILED)
        munmap(other, PAGE);
    if (priv != MAP_FAILED)
        munmap(priv, PAGE);
    if (other_fd >= 0)
        close(other_fd);
}

/* Block until the peer's end of the socket reports EOF, which is what its exit
 * looks like from here. Bounded, so a peer that hangs costs one timeout.
 */
static bool peer_gone(int sock)
{
    for (;;) {
        struct pollfd pfd = {.fd = sock, .events = POLLIN};
        char scratch[64];
        int prc;

        do {
            prc = poll(&pfd, 1, PEER_TIMEOUT_MS);
        } while (prc < 0 && errno == EINTR);
        if (prc <= 0)
            return false;
        if (read(sock, scratch, sizeof(scratch)) == 0)
            return true;
    }
}

/* The backing object outlives the process that created it, because this one
 * holds a descriptor. Waiting on it must still be an ordinary wait, and the
 * retired peer's exit must not have pre-completed the queue.
 */
static void death_wait(uint32_t *base, int sock)
{
    uint32_t *word = word_at(base, W_DEATH);
    struct timespec rel = {0, DEATH_WAIT_MS * NS_PER_MS};
    int64_t start;
    int64_t elapsed;
    long rc;

    check("the peer instance has exited", peer_gone(sock), -1);
    word_reset(word);
    start = now_ns(CLOCK_MONOTONIC);
    rc = futex_op(word, FUTEX_WAIT, 0, &rel, 0);
    elapsed = (now_ns(CLOCK_MONOTONIC) - start) / NS_PER_MS;
    check("the shared word outlives the peer that created it",
          rc == -LINUX_ETIMEDOUT, rc);
    check("that wait really blocked", elapsed >= DEATH_MIN_MS, elapsed);
    check("the peer's exit claimed no waiter",
          futex_op(word, FUTEX_WAKE, 1, NULL, 0) == 0, -1);
}

static void run_script(int self, int sock, int mfd)
{
    uint32_t *base =
        mmap(NULL, MAP_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);

    if (base == MAP_FAILED) {
        check("the shared file maps", false, -1);
        return;
    }
    check("the shared file maps", true, 0);

    if (self == 0) {
        uint32_t *changed = word_at(base, W_PAST);
        struct timespec rel = {1, 0};

        atomic_store_explicit((_Atomic uint32_t *) changed, 1,
                              memory_order_release);
        long rc = futex_op(changed, FUTEX_WAIT, 0, &rel, 0);
        check("a changed shared value rejects the wait", rc == -LINUX_EAGAIN,
              rc);
    }

    for (int round = 0; round < ROUNDS; round++)
        handoff_round(self, sock, base, round);

    if (self == 0)
        pair_waits(sock, base);
    else
        pair_waking(sock, base);

    if (self == 0)
        bitset_waits(sock, base);
    else
        bitset_wakes(sock, base);

    if (self == 0)
        timed_wait(sock, base);
    else
        timed_peering(sock, base);

    if (self == 0)
        isolation_wait(sock, base);
    else
        isolation_probing(sock, mfd, base);

    if (self == 0) {
        bool interrupted = signal_round(word_at(base, W_SIGNAL));

        check("a queued signal ends a shared wait", interrupted, -1);
        (void) peer_send(sock, MSG_SIGNAL_DONE, interrupted ? 1 : 0);
        munmap(base, MAP_LEN);
        close(mfd);
        return;
    }

    int32_t interrupted = 0;

    /* The peer's own report is what says its wait ended: probing first would
     * count a waiter still parked on the signal word.
     */
    if (!peer_recv(sock, MSG_SIGNAL_DONE, &interrupted))
        check("the interrupted wait is announced", false, -1);
    else
        check("an interrupted waiter leaves the queue",
              futex_op(word_at(base, W_SIGNAL), FUTEX_WAKE, 1, NULL, 0) == 0,
              -1);

    death_wait(base, sock);
    munmap(base, MAP_LEN);
    close(mfd);
}

static int peer_main(int self, int sock)
{
    char name[48];
    int mfd;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("test-futex-shared-vm peer%d: one memfd, two processes\n", self);

    if (self == 0) {
        struct sigaction sa;

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_signal;
        check("the signal handler installs", sigaction(SIGUSR1, &sa, NULL) == 0,
              -1);
        mfd = create_memfd("futex-shared-vm");
        check("the owner creates the shared memfd", mfd >= 0, mfd);
        if (mfd < 0)
            goto done;
        check("the shared descriptor transfers", send_fd(sock, mfd), -1);
    } else {
        mfd = recv_fd(sock);
        check("the shared descriptor arrives", mfd >= 0, mfd);
        if (mfd < 0)
            goto done;
    }

    run_script(self, sock, mfd);
done:
    snprintf(name, sizeof(name), "test-futex-shared-vm peer%d", self);
    SUMMARY(name);
    return fails == 0 ? 0 : 1;
}

/* Both peers in one process tree, which is how the reference kernel lane runs
 * this file. The elfuse lane runs the same peer code under two independent
 * elfuse instances, where the futex key has to cross a process boundary the
 * host does not share.
 */
static int both_main(void)
{
    int sockets[2];
    int child_status = -1;
    int self_status;
    pid_t pid;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        fprintf(stderr, "test-futex-shared-vm: socketpair failed\n");
        return 1;
    }
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "test-futex-shared-vm: fork failed\n");
        return 1;
    }
    if (pid == 0) {
        int rc;

        close(sockets[1]);
        rc = peer_main(0, sockets[0]);
        fflush(stdout);
        _exit(rc);
    }
    close(sockets[0]);
    self_status = peer_main(1, sockets[1]);
    close(sockets[1]);
    if (waitpid(pid, &child_status, 0) < 0)
        child_status = -1;
    printf("test-futex-shared-vm: peer0 exit %d, peer1 exit %d\n",
           WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1,
           self_status);
    return self_status == 0 && WIFEXITED(child_status) &&
                   WEXITSTATUS(child_status) == 0
               ? 0
               : 1;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "peer0"))
        return peer_main(0, STDIN_FILENO);
    if (argc > 1 && !strcmp(argv[1], "peer1"))
        return peer_main(1, STDIN_FILENO);
    if (argc == 1 || (argc > 1 && !strcmp(argv[1], "both")))
        return both_main();
    fprintf(stderr, "test-futex-shared-vm: expected peer0, peer1 or both\n");
    return 2;
}
