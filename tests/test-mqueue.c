/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

struct send_ctx {
    mqd_t queue;
    int result;
};

static void *send_delayed(void *arg)
{
    struct send_ctx *ctx = arg;
    struct timespec delay = {.tv_nsec = 20000000};
    nanosleep(&delay, NULL);
    ctx->result = mq_send(ctx->queue, "wake", 5, 7);
    return NULL;
}

int main(void)
{
    int passes = 0, fails = 0;
    char name[64];
    snprintf(name, sizeof(name), "/elfuse-mqueue-%ld", (long) getpid());
    mq_unlink(name);
    struct mq_attr attr = {.mq_maxmsg = 2, .mq_msgsize = 32};
    mqd_t queue = mq_open(name, O_CREAT | O_EXCL | O_RDWR, 0600, &attr);
    TEST("create queue");
    EXPECT_TRUE(queue != (mqd_t) -1, "mq_open failed");
    if (queue == (mqd_t) -1)
        return 1;
    TEST("duplicate exclusive queue rejected");
    EXPECT_ERRNO(mq_open(name, O_CREAT | O_EXCL | O_RDWR, 0600, &attr), EEXIST,
                 "exclusive create replaced a queue");
    TEST("messages retain priority ordering");
    char buf[32];
    unsigned priority = 0;
    bool sent = mq_timedsend(queue, "low", 4, 1, NULL) == 0 &&
                mq_timedsend(queue, "high", 5, 9, NULL) == 0;
    ssize_t size = mq_timedreceive(queue, buf, sizeof(buf), &priority, NULL);
    EXPECT_TRUE(sent && size == 5 && priority == 9 && !memcmp(buf, "high", 5),
                "queue selected wrong priority or corrupted message");
    mq_receive(queue, buf, sizeof(buf), &priority);
    struct mq_attr old;
    attr.mq_flags = O_NONBLOCK;
    TEST("empty nonblocking queue returns EAGAIN");
    EXPECT_TRUE(mq_setattr(queue, &attr, &old) == 0 &&
                    mq_receive(queue, buf, sizeof(buf), NULL) == -1 &&
                    errno == EAGAIN,
                "nonblocking queue did not return EAGAIN");
    attr.mq_flags = 0;
    mq_setattr(queue, &attr, NULL);
    struct send_ctx ctx = {.queue = queue, .result = -1};
    pthread_t worker;
    int created = pthread_create(&worker, NULL, send_delayed, &ctx);
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;
    size = created == 0
               ? mq_timedreceive(queue, buf, sizeof(buf), &priority, &deadline)
               : -1;
    if (created == 0)
        pthread_join(worker, NULL);
    TEST("blocking receive releases worker CPU");
    EXPECT_TRUE(size == 5 && ctx.result == 0 && priority == 7 &&
                    !memcmp(buf, "wake", 5),
                "blocking queue receive lost wakeup");
    TEST("unlink retains open queue handle");
    EXPECT_TRUE(mq_unlink(name) == 0 && mq_send(queue, "live", 5, 0) == 0 &&
                    mq_receive(queue, buf, sizeof(buf), NULL) == 5 &&
                    !memcmp(buf, "live", 5),
                "unlink invalidated an open queue");
    TEST("notification withdrawal validates queue");
    EXPECT_EQ(mq_notify(queue, NULL), 0, "mq_notify withdrawal failed");
    mq_close(queue);
    mq_unlink(name);
    SUMMARY("test-mqueue");
    return fails != 0;
}
