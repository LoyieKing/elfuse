/*
 * POSIX message queues (minimal SoftNS)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Enough for timers/mqueue-lat: mq_open + empty-queue mq_timedreceive timeout
 * + mq_getsetattr/close/unlink. No notify, no cross-process sharing beyond the
 * SoftNS guest.
 */

#pragma once

#include <stdint.h>
#include "core/guest.h"

void mqueue_init(void);

int64_t sys_mq_open(guest_t *g,
                    uint64_t name_gva,
                    int oflag,
                    uint64_t mode,
                    uint64_t attr_gva);
int64_t sys_mq_unlink(guest_t *g, uint64_t name_gva);
int64_t sys_mq_timedsend(guest_t *g,
                         int mqdes,
                         uint64_t msg_gva,
                         uint64_t msg_len,
                         unsigned int msg_prio,
                         uint64_t abs_timeout_gva);
int64_t sys_mq_timedreceive(guest_t *g,
                            int mqdes,
                            uint64_t msg_gva,
                            uint64_t msg_len,
                            uint64_t msg_prio_gva,
                            uint64_t abs_timeout_gva);
int64_t sys_mq_notify(guest_t *g, int mqdes, uint64_t sevp_gva);
int64_t sys_mq_getsetattr(guest_t *g,
                          int mqdes,
                          uint64_t new_gva,
                          uint64_t old_gva);

struct thread_entry;
void mqueue_park_on_deadline(struct thread_entry *t);
void mqueue_park_on_interrupt(struct thread_entry *t);
/* Task-exit teardown: retire a PARK_KIND_MQUEUE park and its waiter count. */
void mqueue_task_cancel_wait(struct thread_entry *t);
