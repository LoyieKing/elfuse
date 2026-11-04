/*
 * test-futex-timed.c -- what a timed futex wait answers, and in what order.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux validates the timeout before it compares the word. The syscall entry
 * copies the timespec in (EFAULT if it cannot), checks it (EINVAL if tv_sec is
 * negative or tv_nsec is not under a second), and only then does futex_wait
 * read the word and answer EAGAIN for a value that moved. So a call with both a
 * malformed timeout and a moved word gets the timeout's error, not EAGAIN, and
 * a call with a valid but already-expired timeout still gets EAGAIN rather than
 * ETIMEDOUT when the word moved.
 *
 * The moved-word case can return at EL1 without reaching the host, so its fast
 * path must validate the timespec first and hand over anything it cannot check.
 * The tv_sec = 2^32 case covers the boundary between the narrower EL1 range and
 * the host range. Matching-word waits also check that future WAIT_BITSET and
 * WAIT_REQUEUE_PI deadlines use monotonic time unless CLOCK_REALTIME is set.
 *
 * Every assertion is plain Linux futex ABI, so the reference kernel adjudicates
 * this file unchanged.
 */

#include <errno.h>
#include <stdio.h>
#include <time.h>

#include <linux/futex.h>

#include "raw-syscall.h"
#include "test-harness.h"

int passes = 0, fails = 0;

#define WAIT_OP (FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#define BITSET_OP (FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG)

static long wait_to(int *word, int val, int op, const struct timespec *to)
{
    return raw_syscall6(__NR_futex, (long) word, op, val, (long) to, 0,
                        FUTEX_BITSET_MATCH_ANY);
}

static void check_future_deadline(int op, clockid_t clock)
{
    int word = 0, pi_word = 0;
    struct timespec deadline, before, after;
    clock_gettime(clock, &deadline);
    deadline.tv_nsec += 50000000;
    if (deadline.tv_nsec >= 1000000000) {
        deadline.tv_nsec -= 1000000000;
        deadline.tv_sec++;
    }
    clock_gettime(CLOCK_MONOTONIC, &before);
    long rc = raw_syscall6(__NR_futex, (long) &word, op, 0, (long) &deadline,
                           (long) &pi_word, FUTEX_BITSET_MATCH_ANY);
    clock_gettime(CLOCK_MONOTONIC, &after);
    long elapsed = (after.tv_sec - before.tv_sec) * 1000000000L +
                   after.tv_nsec - before.tv_nsec;
    EXPECT_TRUE(rc == -ETIMEDOUT && elapsed >= 40000000,
                "future deadline expired before its clock reached it");
}

int main(void)
{
    /* The word is 1 everywhere below and every wait expects 0, so the value has
     * always moved and any answer other than the timeout's own error would be
     * EAGAIN. That is what makes the ordering visible.
     */
    int word = 1;

    struct timespec zero = {0, 0};
    struct timespec neg_sec = {-1, 0};
    struct timespec big_nsec = {0, 1000000000L};
    struct timespec neg_nsec = {0, -1};

    /* Past the range elfuse's EL1 path will vouch for, inside the one the host
     * accepts. The answer has to be the same as for any other valid timeout.
     */
    struct timespec far = {(time_t) 1ULL << 32, 0};

    TEST("bad timeout pointer outranks moved word");
    EXPECT_RAW_ERRNO(wait_to(&word, 0, WAIT_OP, (struct timespec *) 0x1000),
                     -EFAULT, "expected EFAULT");

    TEST("negative tv_sec outranks moved word");
    EXPECT_RAW_ERRNO(wait_to(&word, 0, WAIT_OP, &neg_sec), -EINVAL,
                     "expected EINVAL");

    TEST("tv_nsec of a full second outranks moved word");
    EXPECT_RAW_ERRNO(wait_to(&word, 0, WAIT_OP, &big_nsec), -EINVAL,
                     "expected EINVAL");

    TEST("negative tv_nsec outranks moved word");
    EXPECT_RAW_ERRNO(wait_to(&word, 0, WAIT_OP, &neg_nsec), -EINVAL,
                     "expected EINVAL");

    TEST("moved word beats an expired relative timeout");
    EXPECT_RAW_ERRNO(wait_to(&word, 0, WAIT_OP, &zero), -EAGAIN,
                     "expected EAGAIN");

    TEST("moved word beats an expired absolute deadline");
    EXPECT_RAW_ERRNO(wait_to(&word, 0, BITSET_OP, &zero), -EAGAIN,
                     "expected EAGAIN");

    TEST("a far-future timeout answers like any other");
    EXPECT_RAW_ERRNO(wait_to(&word, 0, WAIT_OP, &far), -EAGAIN,
                     "expected EAGAIN");

    TEST("bitset waits validate the timeout too");
    EXPECT_RAW_ERRNO(wait_to(&word, 0, BITSET_OP, &big_nsec), -EINVAL,
                     "expected EINVAL");

    /* A zero bitset is EINVAL whatever the timeout says, and it is checked
     * before the value: this is the one case where something outranks the
     * timeout rather than the other way round.
     */
    TEST("zero bitset outranks a valid timeout");
    EXPECT_RAW_ERRNO(raw_syscall6(__NR_futex, (long) &word, BITSET_OP, 0,
                                  (long) &zero, 0, 0),
                     -EINVAL, "expected EINVAL");

    /* Matching word, expired deadline: nothing moved, so the timeout is what
     * answers. This is the case a fast path must not steal, since it has to
     * report the deadline rather than EAGAIN.
     */
    TEST("expired deadline times out when the word matches");
    EXPECT_RAW_ERRNO(wait_to(&word, 1, WAIT_OP, &zero), -ETIMEDOUT,
                     "expected ETIMEDOUT");

    TEST("expired absolute deadline times out when the word matches");
    EXPECT_RAW_ERRNO(wait_to(&word, 1, BITSET_OP, &zero), -ETIMEDOUT,
                     "expected ETIMEDOUT");

    /* An unaligned or tagged address is still the host's to reject, and the
     * timeout must not change that.
     */
    TEST("unaligned address with a timeout");
    EXPECT_RAW_ERRNO(wait_to((int *) ((char *) &word + 1), 0, WAIT_OP, &zero),
                     -EINVAL, "expected EINVAL");

    TEST("bitset default deadline uses monotonic time");
    check_future_deadline(BITSET_OP, CLOCK_MONOTONIC);
    TEST("bitset realtime deadline honors clock flag");
    check_future_deadline(BITSET_OP | FUTEX_CLOCK_REALTIME, CLOCK_REALTIME);
    TEST("requeue PI default deadline uses monotonic time");
    check_future_deadline(FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                          CLOCK_MONOTONIC);
    TEST("requeue PI realtime deadline honors clock flag");
    check_future_deadline(
        FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME,
        CLOCK_REALTIME);

    SUMMARY("test-futex-timed");
    return fails ? 1 : 0;
}
