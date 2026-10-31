/*
 * POSIX message queues (minimal SoftNS)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * In-guest named queues with a small ring. Empty mq_timedreceive parks until
 * the absolute CLOCK_REALTIME timeout and returns -ETIMEDOUT, enough for
 * kselftest timers/mqueue-lat (100 receives x 100ms, 40ms slack).
 */

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"

#include "runtime/sched/sched.h"
#include "runtime/thread.h"
#include "runtime/sched/exec.h"

#include "syscall/internal.h"
#include "syscall/linux-wire.h"
#include "syscall/mqueue.h"
#include "syscall/proc.h"
#include "syscall/signal.h"
#include "syscall/time.h"

#define MQ_NAME_MAX 64
#define MQ_DEFAULT_MAXMSG 10
#define MQ_DEFAULT_MSGSIZE 8192
#define MQ_MAX_QUEUES 32
#define MQ_MAX_MSGSIZE 8192

typedef struct {
    char *data;
    unsigned int prio;
    uint64_t len;
} mq_msg_t;

typedef struct {
    bool used;
    bool unlinked;
    int refcnt;
    char name[MQ_NAME_MAX];
    long maxmsg;
    long msgsize;
    long flags; /* O_NONBLOCK bit mirrored */
    int head;
    int count;
    mq_msg_t *msgs; /* maxmsg entries */
} mq_queue_t;

typedef struct {
    mq_queue_t *q;
} mq_fd_state_t;

static pthread_mutex_t mq_lock = PTHREAD_MUTEX_INITIALIZER;
static mq_queue_t queues[MQ_MAX_QUEUES];
static mq_fd_state_t fd_state[FD_TABLE_SIZE];

/* Parked senders and receivers. The count gates the wake scan, so a transfer on
 * a queue nobody waits on does not walk the thread table.
 */
static _Atomic unsigned mqueue_waiters;

static void mqueue_wake_one(thread_entry_t *t, void *ctx)
{
    (void) ctx;
    if (!t || !exec_park_active_load(t) ||
        exec_park_kind_load(t) != PARK_KIND_MQUEUE)
        return;
    uint64_t seq = sched_park_seq(t);
    if (seq == 0)
        return;
    if (sched_park_try_complete_reissue_seq(t, PARK_KIND_MQUEUE, seq))
        atomic_fetch_sub_explicit(&mqueue_waiters, 1, memory_order_relaxed);
}

/* A queue changed state (message queued or dequeued): every parked operation
 * re-checks its own condition on the re-dispatched SVC.
 */
static void mqueue_wake_waiters(void)
{
    if (atomic_load_explicit(&mqueue_waiters, memory_order_relaxed) == 0)
        return;
    thread_for_each(mqueue_wake_one, NULL);
}

/* Arm a queue wait with mq_lock held, so an enqueue and its wake scan cannot
 * land between the caller's empty/full check and park_active.
 */
static int64_t mqueue_park_locked(thread_entry_t *self, uint64_t deadline_ns)
{
    if (!self)
        return -LINUX_EAGAIN;
    exec_park_kind_store(self, PARK_KIND_MQUEUE);
    exec_park_result_pending_store(self, true);
    exec_park_reissue_store(self, false);
    atomic_fetch_add_explicit(&mqueue_waiters, 1, memory_order_relaxed);
    exec_park_deadline_ns_store(self, 0);
    (void) sched_park_seq_next(self);
    exec_park_active_store(self, true);
    sched_arm_wait_deadline(self, deadline_ns);
    return SYSCALL_PARKED;
}

static void mqueue_close_fd(int guest_fd);

void mqueue_init(void)
{
    memset(queues, 0, sizeof(queues));
    memset(fd_state, 0, sizeof(fd_state));
    fd_register_cleanup(FD_MQUEUE, mqueue_close_fd);
}

static int read_mq_name(guest_t *g, uint64_t name_gva, char *out, size_t out_sz)
{
    if (!name_gva || out_sz < 3)
        return -LINUX_EFAULT;
    char raw[MQ_NAME_MAX];
    int n = guest_read_str(g, name_gva, raw, sizeof(raw));
    if (n == -2)
        return -LINUX_EFAULT;
    if (n < 0)
        return -LINUX_ENAMETOOLONG;
    if (n == 0 || raw[0] == '\0')
        return -LINUX_EINVAL;

    /* glibc strips the leading '/' before the syscall; the kernel mqueue fs
     * also stores the name without it. Accept both and normalize to "/name".
     */
    const char *body = raw[0] == '/' ? raw + 1 : raw;
    if (body[0] == '\0')
        return -LINUX_EINVAL; /* "/" alone is EACCES on Linux; treat as EINVAL
                               */
    if (strchr(body, '/'))
        return -LINUX_EINVAL;
    size_t blen = strlen(body);
    if (blen + 2 > out_sz)
        return -LINUX_ENAMETOOLONG;
    out[0] = '/';
    memcpy(out + 1, body, blen + 1);
    return 0;
}

static mq_queue_t *find_queue_locked(const char *name)
{
    for (int i = 0; i < MQ_MAX_QUEUES; i++) {
        if (queues[i].used && !queues[i].unlinked &&
            strcmp(queues[i].name, name) == 0)
            return &queues[i];
    }
    return NULL;
}

static mq_queue_t *alloc_queue_locked(const char *name,
                                      long maxmsg,
                                      long msgsize)
{
    for (int i = 0; i < MQ_MAX_QUEUES; i++) {
        if (queues[i].used)
            continue;
        mq_queue_t *q = &queues[i];
        memset(q, 0, sizeof(*q));
        strncpy(q->name, name, MQ_NAME_MAX - 1);
        q->maxmsg = maxmsg;
        q->msgsize = msgsize;
        q->msgs = calloc((size_t) maxmsg, sizeof(mq_msg_t));
        if (!q->msgs)
            return NULL;
        q->used = true;
        q->refcnt = 0;
        return q;
    }
    return NULL;
}

static void free_queue_locked(mq_queue_t *q)
{
    if (!q || !q->used)
        return;
    if (q->msgs) {
        for (long i = 0; i < q->maxmsg; i++)
            free(q->msgs[i].data);
        free(q->msgs);
    }
    memset(q, 0, sizeof(*q));
}

static void queue_decref_locked(mq_queue_t *q)
{
    if (!q)
        return;
    if (q->refcnt > 0)
        q->refcnt--;
    if (q->refcnt == 0 && q->unlinked)
        free_queue_locked(q);
}

static void mqueue_close_fd(int guest_fd)
{
    if (guest_fd < 0 || guest_fd >= FD_TABLE_SIZE)
        return;
    pthread_mutex_lock(&mq_lock);
    mq_queue_t *q = fd_state[guest_fd].q;
    fd_state[guest_fd].q = NULL;
    queue_decref_locked(q);
    pthread_mutex_unlock(&mq_lock);
    if (q)
        mqueue_wake_waiters();
}

int64_t sys_mq_open(guest_t *g,
                    uint64_t name_gva,
                    int oflag,
                    uint64_t mode,
                    uint64_t attr_gva)
{
    (void) mode;
    char name[MQ_NAME_MAX];
    int nerr = read_mq_name(g, name_gva, name, sizeof(name));
    if (nerr < 0)
        return nerr;

    long maxmsg = MQ_DEFAULT_MAXMSG;
    long msgsize = MQ_DEFAULT_MSGSIZE;
    if (attr_gva) {
        /* struct mq_attr: mq_flags, mq_maxmsg, mq_msgsize, mq_curmsgs */
        int64_t attr[4];
        if (guest_read(g, attr_gva, attr, sizeof(attr)) < 0)
            return -LINUX_EFAULT;
        if (attr[1] <= 0 || attr[2] <= 0)
            return -LINUX_EINVAL;
        if (attr[1] > MQ_DEFAULT_MAXMSG * 10 || attr[2] > MQ_MAX_MSGSIZE)
            return -LINUX_EINVAL;
        maxmsg = (long) attr[1];
        msgsize = (long) attr[2];
    }

    bool creat = (oflag & LINUX_O_CREAT) != 0;
    bool excl = (oflag & LINUX_O_EXCL) != 0;
    int acc = oflag & LINUX_O_ACCMODE;
    if (acc != LINUX_O_RDONLY && acc != LINUX_O_WRONLY && acc != LINUX_O_RDWR)
        return -LINUX_EINVAL;

    pthread_mutex_lock(&mq_lock);
    mq_queue_t *q = find_queue_locked(name);
    if (q) {
        if (creat && excl) {
            pthread_mutex_unlock(&mq_lock);
            return -LINUX_EEXIST;
        }
    } else {
        if (!creat) {
            pthread_mutex_unlock(&mq_lock);
            return -LINUX_ENOENT;
        }
        q = alloc_queue_locked(name, maxmsg, msgsize);
        if (!q) {
            pthread_mutex_unlock(&mq_lock);
            return -LINUX_EMFILE;
        }
    }

    /* Host pipe is only a pollable placeholder; mqueue I/O is synthetic. */
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        if (q->refcnt == 0 && creat)
            free_queue_locked(q);
        pthread_mutex_unlock(&mq_lock);
        return linux_errno();
    }
    close(pipefd[1]);
    int gfd = fd_alloc(FD_MQUEUE, pipefd[0], mqueue_close_fd);
    if (gfd < 0) {
        close(pipefd[0]);
        if (q->refcnt == 0 && creat)
            free_queue_locked(q);
        pthread_mutex_unlock(&mq_lock);
        return -LINUX_EMFILE;
    }
    q->refcnt++;
    fd_state[gfd].q = q;
    if (oflag & LINUX_O_NONBLOCK)
        q->flags |= LINUX_O_NONBLOCK;
    int publish = LINUX_O_RDONLY; /* mqd is always readable for getattr */
    if (oflag & LINUX_O_CLOEXEC)
        publish |= LINUX_O_CLOEXEC;
    if (oflag & LINUX_O_NONBLOCK)
        publish |= LINUX_O_NONBLOCK;
    fd_publish_linux_flags(gfd, publish);
    pthread_mutex_unlock(&mq_lock);
    return gfd;
}

int64_t sys_mq_unlink(guest_t *g, uint64_t name_gva)
{
    char name[MQ_NAME_MAX];
    int nerr = read_mq_name(g, name_gva, name, sizeof(name));
    if (nerr < 0)
        return nerr;
    pthread_mutex_lock(&mq_lock);
    mq_queue_t *q = find_queue_locked(name);
    if (!q) {
        pthread_mutex_unlock(&mq_lock);
        return -LINUX_ENOENT;
    }
    q->unlinked = true;
    bool freed = q->refcnt == 0;
    if (freed)
        free_queue_locked(q);
    pthread_mutex_unlock(&mq_lock);
    if (freed)
        mqueue_wake_waiters();
    return 0;
}

int64_t sys_mq_getsetattr(guest_t *g,
                          int mqdes,
                          uint64_t new_gva,
                          uint64_t old_gva)
{
    if (mqdes < 0 || mqdes >= FD_TABLE_SIZE)
        return -LINUX_EBADF;
    pthread_mutex_lock(&mq_lock);
    if (fd_table[mqdes].type != FD_MQUEUE || !fd_state[mqdes].q) {
        pthread_mutex_unlock(&mq_lock);
        return -LINUX_EBADF;
    }
    mq_queue_t *q = fd_state[mqdes].q;
    int64_t old[4] = {q->flags, q->maxmsg, q->msgsize, q->count};
    if (old_gva) {
        if (guest_write(g, old_gva, old, sizeof(old)) < 0) {
            pthread_mutex_unlock(&mq_lock);
            return -LINUX_EFAULT;
        }
    }
    if (new_gva) {
        int64_t nw[4];
        if (guest_read(g, new_gva, nw, sizeof(nw)) < 0) {
            pthread_mutex_unlock(&mq_lock);
            return -LINUX_EFAULT;
        }
        q->flags = (nw[0] & LINUX_O_NONBLOCK);
    }
    pthread_mutex_unlock(&mq_lock);
    return 0;
}

int64_t sys_mq_notify(guest_t *g, int mqdes, uint64_t sevp_gva)
{
    (void) g;
    (void) sevp_gva;
    if (mqdes < 0 || mqdes >= FD_TABLE_SIZE)
        return -LINUX_EBADF;
    /* Soft-accept: report success without arming notifications. */
    return 0;
}

static int64_t realtime_abs_to_mono_deadline_ns(const linux_timespec_t *abs_rt)
{
    struct timespec rt_now, mono_now;
    if (clock_gettime(CLOCK_REALTIME, &rt_now) < 0 ||
        clock_gettime(CLOCK_MONOTONIC, &mono_now) < 0)
        return -1;
    int64_t abs_ns = linux_timespec_to_ns_sat(abs_rt);
    int64_t rt_now_ns =
        (int64_t) rt_now.tv_sec * NSEC_PER_SEC + (int64_t) rt_now.tv_nsec;
    int64_t mono_now_ns =
        (int64_t) mono_now.tv_sec * NSEC_PER_SEC + (int64_t) mono_now.tv_nsec;
    int64_t delta = abs_ns - rt_now_ns;
    if (delta <= 0)
        return mono_now_ns;
    if (__builtin_add_overflow(mono_now_ns, delta, &mono_now_ns))
        return INT64_MAX;
    return mono_now_ns;
}

int64_t sys_mq_timedsend(guest_t *g,
                         int mqdes,
                         uint64_t msg_gva,
                         uint64_t msg_len,
                         unsigned int msg_prio,
                         uint64_t abs_timeout_gva)
{
    if (mqdes < 0 || mqdes >= FD_TABLE_SIZE)
        return -LINUX_EBADF;
    if (msg_len > MQ_MAX_MSGSIZE)
        return -LINUX_EMSGSIZE;

    linux_timespec_t abs_rt;
    bool have_timeout = abs_timeout_gva != 0;
    if (have_timeout) {
        if (guest_read(g, abs_timeout_gva, &abs_rt, sizeof(abs_rt)) < 0)
            return -LINUX_EFAULT;
        if (!linux_timespec_valid(&abs_rt))
            return -LINUX_EINVAL;
    }

    char *copy = NULL;
    if (msg_len) {
        copy = malloc((size_t) msg_len);
        if (!copy)
            return -LINUX_ENOMEM;
        if (guest_read(g, msg_gva, copy, (size_t) msg_len) < 0) {
            free(copy);
            return -LINUX_EFAULT;
        }
    }

    pthread_mutex_lock(&mq_lock);
    if (fd_table[mqdes].type != FD_MQUEUE || !fd_state[mqdes].q) {
        pthread_mutex_unlock(&mq_lock);
        free(copy);
        return -LINUX_EBADF;
    }
    mq_queue_t *q = fd_state[mqdes].q;
    if ((long) msg_len > q->msgsize) {
        pthread_mutex_unlock(&mq_lock);
        free(copy);
        return -LINUX_EMSGSIZE;
    }

    if (q->count >= q->maxmsg) {
        if (q->flags & LINUX_O_NONBLOCK) {
            pthread_mutex_unlock(&mq_lock);
            free(copy);
            return -LINUX_EAGAIN;
        }
        uint64_t deadline_ns = 0;
        if (have_timeout) {
            int64_t dl = realtime_abs_to_mono_deadline_ns(&abs_rt);
            if (dl < 0) {
                pthread_mutex_unlock(&mq_lock);
                free(copy);
                return -LINUX_EFAULT;
            }
            deadline_ns = (uint64_t) dl;
        }

        /* A queue wake reissues the SVC, which re-checks the queue; a signal or
         * the absolute deadline completes it in place.
         */
        syscall_restart_forbid();
        int64_t parked = mqueue_park_locked(current_thread, deadline_ns);
        pthread_mutex_unlock(&mq_lock);
        free(copy);
        return parked;
    }

    int idx = (q->head + q->count) % (int) q->maxmsg;
    q->msgs[idx].data = copy;
    q->msgs[idx].len = msg_len;
    q->msgs[idx].prio = msg_prio;
    q->count++;
    pthread_mutex_unlock(&mq_lock);
    mqueue_wake_waiters();
    return 0;
}

int64_t sys_mq_timedreceive(guest_t *g,
                            int mqdes,
                            uint64_t msg_gva,
                            uint64_t msg_len,
                            uint64_t msg_prio_gva,
                            uint64_t abs_timeout_gva)
{
    if (mqdes < 0 || mqdes >= FD_TABLE_SIZE)
        return -LINUX_EBADF;

    linux_timespec_t abs_rt;
    bool have_timeout = abs_timeout_gva != 0;
    if (have_timeout) {
        if (guest_read(g, abs_timeout_gva, &abs_rt, sizeof(abs_rt)) < 0)
            return -LINUX_EFAULT;
        if (!linux_timespec_valid(&abs_rt))
            return -LINUX_EINVAL;
    }

    pthread_mutex_lock(&mq_lock);
    if (fd_table[mqdes].type != FD_MQUEUE || !fd_state[mqdes].q) {
        pthread_mutex_unlock(&mq_lock);
        return -LINUX_EBADF;
    }
    mq_queue_t *q = fd_state[mqdes].q;
    if ((long) msg_len < q->msgsize) {
        pthread_mutex_unlock(&mq_lock);
        return -LINUX_EMSGSIZE;
    }

    if (q->count > 0) {
        int best = 0;
        for (int i = 1; i < q->count; i++) {
            int candidate = (q->head + i) % (int) q->maxmsg;
            int selected = (q->head + best) % (int) q->maxmsg;
            if (q->msgs[candidate].prio > q->msgs[selected].prio)
                best = i;
        }
        int idx = (q->head + best) % (int) q->maxmsg;
        mq_msg_t m = q->msgs[idx];
        for (int i = best; i + 1 < q->count; i++)
            q->msgs[(q->head + i) % (int) q->maxmsg] =
                q->msgs[(q->head + i + 1) % (int) q->maxmsg];
        q->msgs[(q->head + q->count - 1) % (int) q->maxmsg].data = NULL;
        q->count--;
        pthread_mutex_unlock(&mq_lock);
        mqueue_wake_waiters();
        if (m.len && guest_write(g, msg_gva, m.data, (size_t) m.len) < 0) {
            free(m.data);
            return -LINUX_EFAULT;
        }
        if (msg_prio_gva) {
            uint32_t p = m.prio;
            if (guest_write(g, msg_prio_gva, &p, sizeof(p)) < 0) {
                free(m.data);
                return -LINUX_EFAULT;
            }
        }
        free(m.data);
        return (int64_t) m.len;
    }

    if (q->flags & LINUX_O_NONBLOCK) {
        pthread_mutex_unlock(&mq_lock);
        return -LINUX_EAGAIN;
    }

    uint64_t deadline_ns = 0;
    if (have_timeout) {
        int64_t dl = realtime_abs_to_mono_deadline_ns(&abs_rt);
        if (dl < 0) {
            pthread_mutex_unlock(&mq_lock);
            return -LINUX_EINVAL;
        }
        deadline_ns = (uint64_t) dl;
    }

    /* A queue wake reissues the SVC, which re-checks the queue; a signal or the
     * absolute deadline completes it in place. The message copy-out stays in
     * the handler on the target, never in a timer callback.
     */
    syscall_restart_forbid();
    int64_t parked = mqueue_park_locked(current_thread, deadline_ns);
    pthread_mutex_unlock(&mq_lock);
    return parked;
}

void mqueue_park_on_deadline(thread_entry_t *t)
{
    if (!t || !exec_park_active_load(t) ||
        exec_park_kind_load(t) != PARK_KIND_MQUEUE)
        return;
    uint64_t seq = sched_park_seq(t);
    uint64_t deadline = exec_park_deadline_ns_load(t);
    if (seq == 0 || deadline == 0 || deadline > sched_now_ns())
        return;
    if (sched_park_try_complete_seq(t, PARK_KIND_MQUEUE, seq, -LINUX_ETIMEDOUT))
        atomic_fetch_sub_explicit(&mqueue_waiters, 1, memory_order_relaxed);
}

void mqueue_park_on_interrupt(thread_entry_t *t)
{
    if (!t || !exec_park_active_load(t) ||
        exec_park_kind_load(t) != PARK_KIND_MQUEUE)
        return;
    uint64_t seq = sched_park_seq(t);
    if (seq == 0)
        return;
    bool teardown = thread_stop_requested_for(t);
    if (!teardown && !signal_claim_interruption_for(t))
        return;
    if (!teardown)
        exec_restart_forbid_set(t, true);
    if (sched_park_try_complete_seq(t, PARK_KIND_MQUEUE, seq, -LINUX_EINTR))
        atomic_fetch_sub_explicit(&mqueue_waiters, 1, memory_order_relaxed);
}

/* Task death drops a parked receive/send: no wake or deadline will run for a
 * DEAD task, so the waiter count must be retired here or every future mqueue
 * mutation keeps scanning the thread table.
 */
void mqueue_task_cancel_wait(thread_entry_t *t)
{
    if (!t || !exec_park_active_load(t) ||
        exec_park_kind_load(t) != PARK_KIND_MQUEUE)
        return;
    uint64_t seq = sched_park_seq(t);
    if (seq == 0)
        return;
    if (sched_park_try_complete_seq(t, PARK_KIND_MQUEUE, seq, -LINUX_EINTR))
        atomic_fetch_sub_explicit(&mqueue_waiters, 1, memory_order_relaxed);
}
