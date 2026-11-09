/*
 * pidfd helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "runtime/procemu.h"
#include "utils.h"

#include "core/guest.h"
#include "syscall/fs.h"
#include "syscall/internal.h"
#include "syscall/linux-wire.h"
#include "syscall/net.h" /* absock_get_namespace_id */
#include "syscall/proc.h"
#include "syscall/sys.h"
#include "syscall/proc-pidfd.h"
#include "syscall/signal.h"
#include "runtime/thread.h"
#include "debug/log.h"

#define PIDFD_TABLE_SIZE 32

/* Linux uapi/linux/pidfd.h reserved pseudo-fds for pidfd_send_signal. */
#define PIDFD_SELF_THREAD (-10000)       /* current thread */
#define PIDFD_SELF_THREAD_GROUP (-10001) /* current thread-group leader */

/* An entry belongs to an open file description, not to a guest fd number:
 * dup(2) and F_DUPFD hand the alias the same ofd_id, and the target stays
 * watched until the last name for it closes. Keying by number made a dup report
 * the target exited (the original's close dropped the shared write end) and
 * answer EBADF to pidfd_send_signal and waitid(P_PIDFD).
 */
typedef struct {
    bool active;
    uint64_t ofd_id; /* reserved before the slot is published; never 0 */
    int64_t guest_pid;
    pid_t host_pid; /* what the monitor watches, carried to a fork child */
    int write_end;
    int pins;      /* creations and dups in flight, which no sweep may retire */
    uint64_t gen;  /* names this entry for the monitor thread */
    bool exited;   /* target has exited (zombie or reaped); poll readable */
    bool reaped;   /* wait consumed the zombie; GET_INFO EXIT semantics */
    int exit_code; /* Linux wait status */
    bool newpid_ns;   /* soft CLONE_NEWPID on the target */
    bool thread_mode; /* opened with PIDFD_THREAD */
    int64_t tgid;     /* thread-group id; equals guest_pid for process pidfds */
} pidfd_entry_t;

static pidfd_entry_t pidfd_table[PIDFD_TABLE_SIZE];
static uint64_t pidfd_next_gen;
static pthread_mutex_t pidfd_lock = PTHREAD_MUTEX_INITIALIZER;

static pidfd_entry_t *pidfd_find_free_entry(void)
{
    for (int i = 0; i < PIDFD_TABLE_SIZE; i++) {
        if (!pidfd_table[i].active)
            return &pidfd_table[i];
    }
    return NULL;
}

static pidfd_entry_t *pidfd_find_ofd_entry(uint64_t ofd_id)
{
    if (ofd_id == 0)
        return NULL;
    for (int i = 0; i < PIDFD_TABLE_SIZE; i++) {
        if (pidfd_table[i].active && pidfd_table[i].ofd_id == ofd_id)
            return &pidfd_table[i];
    }
    return NULL;
}

static pidfd_entry_t *pidfd_find_gen_entry(uint64_t gen)
{
    for (int i = 0; i < PIDFD_TABLE_SIZE; i++) {
        if (pidfd_table[i].active && pidfd_table[i].gen == gen)
            return &pidfd_table[i];
    }
    return NULL;
}

static void pidfd_cleanup(int guest_fd);

/* Caller holds pidfd_lock.
 *
 * Linux pidfd poll: exited-not-reaped reports POLLIN; reaped reports
 * POLLIN|POLLHUP. Keep the write end open across exit so the host pipe does not
 * report HUP until notify_reaped closes it.
 */
static void pidfd_signal_readable(pidfd_entry_t *entry)
{
    if (entry->write_end < 0)
        return;
    uint8_t byte = 0;
    (void) write(entry->write_end, &byte, 1);
}

static void pidfd_close_writer(pidfd_entry_t *entry)
{
    if (entry->write_end < 0)
        return;
    close(entry->write_end);
    entry->write_end = -1;
}

/* Fully complete (readable + hung up). Error paths and already-reaped installs.
 */
static void pidfd_complete_entry(pidfd_entry_t *entry)
{
    pidfd_signal_readable(entry);
    pidfd_close_writer(entry);
}

/* Complete one pidfd without touching others that watch the same target. */
static void pidfd_complete_one(uint64_t gen)
{
    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_gen_entry(gen);
    if (entry)
        pidfd_complete_entry(entry);
    pthread_mutex_unlock(&pidfd_lock);
}

/* Retire every unpinned entry no fd_table slot names any more. Caller holds
 * fd_lock and then pidfd_lock, so the set of live slots cannot change under the
 * scan. A close hook only learns the number it closed, which by then is already
 * FD_CLOSED, so asking the table is the one way to tell whether that was the
 * last alias.
 */
static void pidfd_sweep_locked(void)
{
    bool live[PIDFD_TABLE_SIZE] = {false};
    for (int fd = 0; fd < FD_TABLE_SIZE; fd++) {
        if (fd_table[fd].type != FD_PIDFD)
            continue;
        pidfd_entry_t *entry = pidfd_find_ofd_entry(fd_table[fd].ofd_id);
        if (entry)
            live[entry - pidfd_table] = true;
    }
    for (int i = 0; i < PIDFD_TABLE_SIZE; i++) {
        pidfd_entry_t *entry = &pidfd_table[i];
        if (!entry->active || entry->pins > 0 || live[i])
            continue;
        if (entry->write_end >= 0)
            close(entry->write_end);
        entry->write_end = -1;
        entry->active = false;
    }
}

static void pidfd_sweep(void)
{
    pthread_mutex_lock(&fd_lock);
    pthread_mutex_lock(&pidfd_lock);
    pidfd_sweep_locked();
    pthread_mutex_unlock(&pidfd_lock);
    pthread_mutex_unlock(&fd_lock);
}

bool pidfd_pin(uint64_t ofd_id)
{
    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_ofd_entry(ofd_id);
    if (entry)
        entry->pins++;
    pthread_mutex_unlock(&pidfd_lock);
    return entry != NULL;
}

void pidfd_unpin(uint64_t ofd_id)
{
    pthread_mutex_lock(&fd_lock);
    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_ofd_entry(ofd_id);
    if (entry)
        entry->pins--;
    pidfd_sweep_locked();
    pthread_mutex_unlock(&pidfd_lock);
    pthread_mutex_unlock(&fd_lock);
}

void pidfd_init(void)
{
    fd_register_cleanup(FD_PIDFD, pidfd_cleanup);
}

static void pidfd_cleanup(int guest_fd)
{
    (void) guest_fd;
    pidfd_sweep();
}

static void *pidfd_monitor_thread(void *arg)
{
    int64_t *ctx = (int64_t *) arg;
    int64_t gpid = ctx[0];
    pid_t hpid = (pid_t) ctx[1];
    uint64_t gen = (uint64_t) ctx[2];
    free(arg);

    if (kill(hpid, 0) < 0 && errno == ESRCH) {
        proc_pidfd_notify_exit(gpid);
        return NULL;
    }

    int kq = kqueue();
    if (kq < 0) {
        pidfd_complete_one(gen);
        return NULL;
    }

    struct kevent ev;
    EV_SET(&ev, hpid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);
    if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0) {
        /* ESRCH means the target exited before registration, which every pidfd
         * on it should see. Any other failure says nothing about the target, so
         * only this fd is completed.
         */
        bool gone = errno == ESRCH;
        close(kq);
        if (gone) {
            proc_pidfd_notify_exit(gpid);
        } else
            pidfd_complete_one(gen);
        return NULL;
    }

    struct kevent out;
    int n;
    do {
        n = kevent(kq, NULL, 0, &out, 1, NULL);
    } while (n < 0 && errno == EINTR);
    close(kq);

    if (n > 0 && out.filter == EVFILT_PROC) {
        proc_pidfd_notify_exit_code(gpid, (int) out.data);
    } else
        pidfd_complete_one(gen);

    return NULL;
}

static bool pidfd_start_monitor(int64_t target_pid,
                                pid_t host_pid,
                                uint64_t gen)
{
    int64_t *ctx = malloc(3 * sizeof(int64_t));
    if (!ctx)
        return false;
    ctx[0] = target_pid;
    ctx[1] = (int64_t) host_pid;
    ctx[2] = (int64_t) gen;

    bool ok = false;
    pthread_t thr;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) == 0) {
        ok = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0 &&
             pthread_create(&thr, &attr, pidfd_monitor_thread, ctx) == 0;
        pthread_attr_destroy(&attr);
    }
    if (!ok)
        free(ctx);
    return ok;
}

/* SoftNS publishes CLONE_THREAD exits into a shared thread map from inside the
 * child SoftNS process. Parent PIDFD_THREAD watchers never see that local
 * notify_exit(tid), so poll a map entry until the tid is marked exited (or the
 * SoftNS host vanishes) and then complete+reap the matching pidfd. Threads
 * killed by execve de_thread do not leave waitable zombies; treat map exit as
 * already reaped (POLLHUP).
 */
static void *pidfd_threadmap_monitor(void *arg)
{
    int64_t *ctx = (int64_t *) arg;
    int64_t tid = ctx[0];
    uint64_t gen = (uint64_t) ctx[1];
    free(arg);

    for (;;) {
        pid_t host = 0;
        bool exited = false;
        int status = 0;
        bool found = proc_thread_resolve(tid, &host, NULL, &exited, &status);
        if (found && exited) {
            proc_pidfd_notify_exit_code(tid, status);
            proc_pidfd_notify_reaped(tid, status);
            return NULL;
        }
        if (!found || host <= 0 || (kill(host, 0) < 0 && errno == ESRCH)) {
            /* SoftNS host gone without a map exit row: complete this fd alone
             * (process NOTE_EXIT fan-out may also have matched by tgid).
             */
            pidfd_complete_one(gen);
            return NULL;
        }

        /* Still live. Bounded sleep; kevent on the map file would be nicer but
         * flock writers do not produce reliable vnode notes across SoftNS.
         */
        usleep(5000);
    }
}

static bool pidfd_start_threadmap_monitor(int64_t tid, uint64_t gen)
{
    int64_t *ctx = malloc(2 * sizeof(int64_t));
    if (!ctx)
        return false;
    ctx[0] = tid;
    ctx[1] = (int64_t) gen;

    bool ok = false;
    pthread_t thr;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) == 0) {
        ok = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0 &&
             pthread_create(&thr, &attr, pidfd_threadmap_monitor, ctx) == 0;
        pthread_attr_destroy(&attr);
    }
    if (!ok)
        free(ctx);
    return ok;
}

/* fixed_fd >= 0 installs at that slot (the fork rebuild), otherwise at the
 * lowest free one. exited publishes the fd already complete.
 */
static int pidfd_install(int fixed_fd,
                         int64_t target_pid,
                         pid_t host_pid,
                         bool exited,
                         bool thread_mode,
                         int64_t tgid,
                         bool nonblock)
{
    int pfd[2];
    if (pipe(pfd) < 0)
        return -LINUX_EMFILE;
    if (fd_set_cloexec(pfd[0]) < 0 || fd_set_cloexec(pfd[1]) < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return linux_errno();
    }

    /* PIDFD_NONBLOCK: guest F_GETFL / waitid(P_PIDFD) see O_NONBLOCK. The
     * readiness pipe stays nonblocking on the host either way; the flag lives
     * in linux_flags for the waitid EAGAIN path and F_GETFL.
     */
    if (nonblock) {
        int fl = fcntl(pfd[0], F_GETFL);
        if (fl < 0 || fcntl(pfd[0], F_SETFL, fl | O_NONBLOCK) < 0) {
            close(pfd[0]);
            close(pfd[1]);
            return linux_errno();
        }
    }

    /* Register and bind before publishing: the slot is visible to every sibling
     * the moment the allocation returns, and a sibling that dups or closes it
     * must find the entry under the description it names. The description id is
     * reserved first so the entry carries it from the start; binding after the
     * publish left a window in which a dup made an alias the registry did not
     * know and a close then retired the entry under it. The pin keeps a close
     * sweep from retiring the entry before the slot exists.
     */
    uint64_t ofd_id = fd_reserve_ofd_id();
    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_free_entry();
    if (!entry) {
        pthread_mutex_unlock(&pidfd_lock);
        close(pfd[0]);
        close(pfd[1]);
        return -LINUX_EMFILE;
    }
    if (tgid <= 0)
        tgid = target_pid;
    *entry = (pidfd_entry_t) {
        .active = true,
        .guest_pid = target_pid,
        .host_pid = host_pid,
        .write_end = pfd[1],
        .pins = 1,
        .gen = ++pidfd_next_gen,
        .ofd_id = ofd_id,
        .exited = exited,
        .reaped = exited, /* fork-restore of an already-complete pidfd */
        .exit_code = 0,
        .newpid_ns = proc_child_in_newpid_ns(tgid),
        .thread_mode = thread_mode,
        .tgid = tgid,
    };
    uint64_t gen = entry->gen;
    bool skip_monitor = thread_mode && target_pid != tgid;
    if (exited)
        pidfd_complete_entry(entry);
    pthread_mutex_unlock(&pidfd_lock);

    /* An identity-only alias spec carries the reserved id onto the slot; a
     * pidfd's pipe cannot block, so the probe the alias path skips would have
     * decided nothing.
     */
    int guest_fl = LINUX_O_CLOEXEC | (nonblock ? LINUX_O_NONBLOCK : 0);
    fd_alias_spec_t spec = fd_alias_identity(ofd_id, guest_fl);
    int gfd = fixed_fd >= 0
                  ? fd_alloc_alias_at(&spec, fixed_fd, FD_PIDFD, pfd[0],
                                      pidfd_cleanup, NULL)
                  : fd_alloc_alias(&spec, FD_PIDFD, pfd[0], pidfd_cleanup);

    /* Drop the pin. If a sibling already closed every name for the description,
     * or the allocation failed, the sweep retires the entry with its write end.
     */
    pidfd_unpin(ofd_id);

    if (gfd < 0) {
        close(pfd[0]);
        return -LINUX_EMFILE;
    }

    /* host_pid <= 0 means the target lives inside this host process -- the
     * caller itself, or a CLONE_VM child, which holds a guest tid but no host
     * pid of its own. Neither can be watched from here, and neither has exited,
     * so the fd stays unreadable rather than being completed. Thread-specific
     * pidfds on a non-leader tid: SoftNS child notify_exit(tid) only updates
     * the child's table. Watch the shared thread map from here so the parent's
     * pipe becomes readable when that tid exits (exec de_thread, SYS_exit,
     * SIGKILL of the group after map publish, etc.).
     */
    if (exited)
        return gfd;
    if (skip_monitor) {
        if (!pidfd_start_threadmap_monitor(target_pid, gen))
            pidfd_complete_one(gen);
        return gfd;
    }
    if (host_pid <= 0)
        return gfd;

    /* Nothing will ever mark this fd readable without a monitor behind it, so
     * complete it rather than leave the guest polling forever. Only this fd:
     * other pidfds on the same live target keep their own monitors. A target
     * that has already exited needs no special case: the monitor thread finds
     * it gone and completes the fd the same way.
     */
    if (!pidfd_start_monitor(target_pid, host_pid, gen))
        pidfd_complete_one(gen);

    return gfd;
}

int pidfd_create(guest_t *g, int64_t target_pid, pid_t host_pid)
{
    (void) g;
    return pidfd_install(-1, target_pid, host_pid, false, false, target_pid,
                         false);
}

static int pidfd_create_flags(guest_t *g,
                              int64_t target_pid,
                              pid_t host_pid,
                              bool thread_mode,
                              int64_t tgid,
                              bool exited,
                              bool nonblock)
{
    (void) g;
    return pidfd_install(-1, target_pid, host_pid, exited, thread_mode, tgid,
                         nonblock);
}

void pidfd_fork_snapshot_locked(uint64_t ofd_id, pidfd_fork_state_t *out)
{
    *out = (pidfd_fork_state_t) {.target_pid = -1};
    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_ofd_entry(ofd_id);
    if (entry) {
        out->target_pid = entry->guest_pid;
        out->exited = entry->exited || entry->write_end < 0;

        /* A pidfd on this process could not be watched here, but the child is
         * another host process and can watch this one. A CLONE_VM target stays
         * unwatched: it has no host pid, and this process outliving it says
         * nothing about when it exits.
         */
        if (entry->guest_pid == proc_get_pid())
            out->host_pid = getpid();
        else
            out->host_pid = entry->host_pid > 0 ? entry->host_pid : 0;
    }
    pthread_mutex_unlock(&pidfd_lock);
}

int pidfd_fork_restore(int guest_fd, const pidfd_fork_state_t *state)
{
    if (state->target_pid <= 0)
        return -LINUX_EBADF;
    return pidfd_install(guest_fd, state->target_pid, state->host_pid,
                         state->exited != 0, false, state->target_pid, false);
}


void proc_pidfd_notify_exit_code(int64_t exited_pid, int status)
{
    status = proc_linux_wait_status(exited_pid, status);
    bool newpid = proc_child_in_newpid_ns(exited_pid);
    if (status == 0) {
        int looked = proc_child_exit_status(exited_pid);
        if (looked != 0)
            status = looked;
    }

    /* Match guest_pid == exited_pid, and also thread-mode pidfds whose tgid
     * matches. SoftNS runs guest threads inside one host process, so NOTE_EXIT
     * / process publish only names the TGID; PIDFD_THREAD watchers on sibling
     * tids live in the parent and never see the child's local notify_exit(tid).
     * Fanning out on process exit matches Linux once the group dissolves.
     */
    pthread_mutex_lock(&pidfd_lock);
    for (int i = 0; i < PIDFD_TABLE_SIZE; i++) {
        pidfd_entry_t *e = &pidfd_table[i];
        if (!e->active)
            continue;
        bool match = e->guest_pid == exited_pid;
        if (!match && e->thread_mode && e->tgid == exited_pid)
            match = true;
        if (!match)
            continue;
        e->exited = true;
        if (status != 0)
            e->exit_code = status;
        else if (e->exit_code == 0) {
            int looked = proc_child_exit_status(exited_pid);
            if (looked != 0)
                e->exit_code = looked;
        }
        e->newpid_ns = newpid || e->newpid_ns;
        pidfd_signal_readable(e);
    }
    pthread_mutex_unlock(&pidfd_lock);
}

void proc_pidfd_notify_exit(int64_t exited_pid)
{
    proc_pidfd_notify_exit_code(exited_pid, proc_child_exit_status(exited_pid));
}

void proc_pidfd_notify_reaped(int64_t guest_pid, int status)
{
    status = proc_linux_wait_status(guest_pid, status);
    if (status == 0) {
        int looked = proc_child_exit_status(guest_pid);
        if (looked != 0)
            status = looked;
    }
    pthread_mutex_lock(&pidfd_lock);
    for (int i = 0; i < PIDFD_TABLE_SIZE; i++) {
        pidfd_entry_t *e = &pidfd_table[i];
        if (!e->active)
            continue;
        bool match = e->guest_pid == guest_pid;
        if (!match && e->thread_mode && e->tgid == guest_pid)
            match = true;
        if (!match)
            continue;
        e->exited = true;
        e->reaped = true;
        if (status != 0)
            e->exit_code = status;
        pidfd_signal_readable(e);
        pidfd_close_writer(e);
    }
    pthread_mutex_unlock(&pidfd_lock);
}

/* Resolve a stamped /proc/self or /proc/<pid> directory to a guest pid. Linux
 * pidfd_send_signal / waitid(P_PIDFD) historically accepted these as pidfds
 * before pidfd_open existed.
 */
static int64_t pidfd_pid_from_proc_path(const char *path)
{
    if (!path || path[0] == '\0')
        return -1;
    if (!strcmp(path, "/proc/self"))
        return proc_get_pid();
    if (strncmp(path, "/proc/", 6) != 0)
        return -1;
    char *endp = NULL;
    long pid = strtol(path + 6, &endp, 10);
    if (endp == path + 6 || *endp != '\0' || pid <= 0)
        return -1;
    return (int64_t) pid;
}

int64_t proc_pidfd_lookup_pid(int guest_fd)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return -1;

    /* One window over the slot and the registry, so the type check and the
     * description it names come from the same open: a number closed and reused
     * in between cannot reach the old target.
     */
    int64_t pid = -1;
    pthread_mutex_lock(&fd_lock);
    if (fd_table[guest_fd].type == FD_PIDFD) {
        pthread_mutex_lock(&pidfd_lock);
        pidfd_entry_t *entry = pidfd_find_ofd_entry(fd_table[guest_fd].ofd_id);
        if (entry)
            pid = entry->guest_pid;
        pthread_mutex_unlock(&pidfd_lock);
    } else if (fd_table[guest_fd].type != FD_CLOSED) {
        /* /proc/self or /proc/<pid> directory opened via procemu. */
        pid = pidfd_pid_from_proc_path(fd_table[guest_fd].proc_path);
    }
    pthread_mutex_unlock(&fd_lock);
    return pid;
}

/* True when @guest_fd is a pidfd (or /proc pid dir) opened with O_NONBLOCK /
 * PIDFD_NONBLOCK. Used by waitid(P_PIDFD) to return EAGAIN instead of blocking.
 */
bool proc_pidfd_is_nonblock(int guest_fd)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return false;
    bool nb = false;
    pthread_mutex_lock(&fd_lock);
    if (fd_table[guest_fd].type != FD_CLOSED)
        nb = (fd_table[guest_fd].linux_flags & LINUX_O_NONBLOCK) != 0;
    pthread_mutex_unlock(&fd_lock);
    return nb;
}

int64_t sys_pidfd_open(guest_t *g, int64_t pid, unsigned int flags)
{
    /* PIDFD_THREAD = O_EXCL; PIDFD_NONBLOCK = O_NONBLOCK. */
    if (flags & ~((unsigned int) (LINUX_O_EXCL | LINUX_O_NONBLOCK)))
        return -LINUX_EINVAL;
    bool thread_mode = (flags & LINUX_O_EXCL) != 0;
    bool nonblock = (flags & LINUX_O_NONBLOCK) != 0;

    /* The kernel rejects a non-positive pid before it looks anything up. */
    if (pid <= 0)
        return -LINUX_EINVAL;

    /* Process (non-THREAD) open: TGID only. A bare thread tid fails with ENOENT
     * (Linux pidfd_create: pid exists as PIDTYPE_PID but not TGID).
     */
    if (!thread_mode) {
        if (pid == proc_get_pid())
            return pidfd_create_flags(g, pid, 0, false, pid, false, nonblock);
        pid_t host_pid = proc_resolve_guest_pid(pid);
        if (host_pid > 0)
            return pidfd_create_flags(g, pid, host_pid, false, pid, false,
                                      nonblock);
        if (proc_thread_resolve(pid, NULL, NULL, NULL, NULL) ||
            thread_tid_in_group(pid))
            return -LINUX_ENOENT;
        return -LINUX_ESRCH;
    }

    /* PIDFD_THREAD: TGID or a published CLONE_THREAD tid. */
    if (pid == proc_get_pid())
        return pidfd_create_flags(g, pid, 0, true, pid, false, nonblock);

    pid_t host_pid = proc_resolve_guest_pid(pid);
    if (host_pid > 0)
        return pidfd_create_flags(g, pid, host_pid, true, pid, false, nonblock);

    pid_t thr_host = 0;
    int64_t tgid = 0;
    bool exited = false;
    int status = 0;
    if (proc_thread_resolve(pid, &thr_host, &tgid, &exited, &status)) {
        int fd =
            pidfd_create_flags(g, pid, thr_host, true, tgid, exited, nonblock);
        if (fd >= 0 && exited)
            proc_pidfd_notify_exit_code(pid, status);
        return fd;
    }

    /* Local SoftNS: tid still in this process's thread table. */
    if (thread_tid_in_group(pid)) {
        return pidfd_create_flags(g, pid, 0, true, proc_get_pid(), false,
                                  nonblock);
    }

    return -LINUX_ESRCH;
}

int64_t sys_pidfd_send_signal(guest_t *g,
                              int pidfd,
                              int sig,
                              uint64_t info_gva,
                              unsigned int flags)
{
    (void) g;
    (void) info_gva;

    if (flags != 0)
        return -LINUX_EINVAL;

    if (sig < 0 || sig > 64)
        return -LINUX_EINVAL;

    /* Reserved negative "pidfds" name the caller itself. */
    if (pidfd == PIDFD_SELF_THREAD) {
        if (sig != 0) {
            int64_t tid =
                current_thread ? thread_tid(current_thread) : proc_get_pid();
            if (!signal_queue_thread(tid, sig))
                signal_queue(sig);
        }
        return 0;
    }
    if (pidfd == PIDFD_SELF_THREAD_GROUP) {
        if (sig != 0)
            signal_queue(sig);
        return 0;
    }

    /* Resolve the target under one lock window so a reaped FD_PIDFD cannot race
     * back to a live namespace host after wait (ks-pidfd_test exited_fail: open
     * /proc/<pid>, wait, pidfd_send_signal(..., 0) must return ESRCH even while
     * the SoftNS host is still briefly published).
     */
    int64_t pid = -1;
    bool is_pidfd = false;
    bool reaped = false;
    pid_t pidfd_host = 0;
    pthread_mutex_lock(&fd_lock);
    if (!RANGE_CHECK(pidfd, 0, FD_TABLE_SIZE) ||
        fd_table[pidfd].type == FD_CLOSED) {
        pthread_mutex_unlock(&fd_lock);
        return -LINUX_EBADF;
    }
    if (fd_table[pidfd].type == FD_PIDFD) {
        is_pidfd = true;
        pthread_mutex_lock(&pidfd_lock);
        pidfd_entry_t *entry = pidfd_find_ofd_entry(fd_table[pidfd].ofd_id);
        if (!entry) {
            pthread_mutex_unlock(&pidfd_lock);
            pthread_mutex_unlock(&fd_lock);
            return -LINUX_EBADF;
        }
        pid = entry->guest_pid;
        reaped = entry->reaped;
        pidfd_host = entry->host_pid;
        pthread_mutex_unlock(&pidfd_lock);
    } else {
        pid = pidfd_pid_from_proc_path(fd_table[pidfd].proc_path);
    }
    pthread_mutex_unlock(&fd_lock);

    if (pid < 0)
        return -LINUX_EBADF;

    if (is_pidfd && reaped)
        return -LINUX_ESRCH;

    if (pid == proc_get_pid()) {
        if (sig != 0)
            signal_queue(sig);
        return 0;
    }

    /* Thread-mode pidfd may name a sibling tid in this SoftNS process. */
    if (thread_tid_in_group(pid)) {
        if (sig != 0) {
            if (!signal_queue_thread(pid, sig))
                return -LINUX_ESRCH;
        }
        return 0;
    }

    /* Prefer the local process table (live or unreaped zombie). Do not fall
     * back to the namespace registry for /proc/<pid> directory fds: after wait
     * consumes the guest entry the SoftNS host can still answer kill(0). Real
     * FD_PIDFD peers keep their stamped host_pid / resolve path below.
     */
    pid_t host_pid = proc_guest_to_host_pid(pid);
    if (host_pid <= 0 && is_pidfd) {
        if (pidfd_host > 0)
            host_pid = pidfd_host;
        else
            host_pid = proc_resolve_guest_pid(pid);
    }
    if (host_pid > 0) {
        if (sig == 0) {
            if (kill(host_pid, 0) < 0)
                return -LINUX_ESRCH;
            return 0;
        }
        if (proc_send_guest_signal(host_pid, pid, sig) < 0)
            return linux_errno();
        return 0;
    }

    /* Cross-process thread map: signal the SoftNS host by tgid. */
    pid_t thr_host = 0;
    int64_t tgid = 0;
    if (proc_thread_resolve(pid, &thr_host, &tgid, NULL, NULL) &&
        thr_host > 0) {
        if (sig == 0) {
            if (kill(thr_host, 0) < 0)
                return -LINUX_ESRCH;
            return 0;
        }
        if (proc_send_guest_signal(thr_host, tgid > 0 ? tgid : pid, sig) < 0)
            return linux_errno();
        return 0;
    }

    return -LINUX_ESRCH;
}


/* Linux pidfd_info (uapi). VER0 is 64 bytes; later kernels added coredump
 * fields and supported_mask. Read/write the full current layout; older guests
 * that pass a shorter buffer only exchange the prefix they know.
 */
typedef struct {
    uint64_t mask;
    uint64_t cgroupid;
    uint32_t pid;
    uint32_t tgid;
    uint32_t ppid;
    uint32_t ruid;
    uint32_t rgid;
    uint32_t euid;
    uint32_t egid;
    uint32_t suid;
    uint32_t sgid;
    uint32_t fsuid;
    uint32_t fsgid;
    int32_t exit_code;
    uint32_t coredump_mask;
    uint32_t coredump_signal;
    uint32_t coredump_code;
    uint32_t __pad;
    uint64_t supported_mask;
} linux_pidfd_info_t;

#define PIDFD_INFO_PID (1ULL << 0)
#define PIDFD_INFO_CREDS (1ULL << 1)
#define PIDFD_INFO_CGROUPID (1ULL << 2)
#define PIDFD_INFO_EXIT (1ULL << 3)
#define PIDFD_INFO_COREDUMP (1ULL << 4)
#define PIDFD_INFO_SUPPORTED_MASK (1ULL << 5)
#define PIDFD_INFO_COREDUMP_SIGNAL (1ULL << 6)
#define PIDFD_INFO_COREDUMP_CODE (1ULL << 7)

#define PIDFD_INFO_ALL_SUPPORTED                                         \
    (PIDFD_INFO_PID | PIDFD_INFO_CREDS | PIDFD_INFO_CGROUPID |           \
     PIDFD_INFO_EXIT | PIDFD_INFO_COREDUMP | PIDFD_INFO_SUPPORTED_MASK | \
     PIDFD_INFO_COREDUMP_SIGNAL | PIDFD_INFO_COREDUMP_CODE)

bool pidfd_fdinfo_snapshot(int guest_fd, int64_t *pid_out, bool *newpid_ns_out)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE) || !pid_out)
        return false;
    if (newpid_ns_out)
        *newpid_ns_out = false;

    bool ok = false;
    pthread_mutex_lock(&fd_lock);
    if (fd_table[guest_fd].type == FD_PIDFD) {
        pthread_mutex_lock(&pidfd_lock);
        pidfd_entry_t *entry = pidfd_find_ofd_entry(fd_table[guest_fd].ofd_id);
        if (entry) {
            /* Reaped targets report Pid/NSpid as -1; zombies still show the pid
             * (task_struct remains until wait). Soft NEWPID keeps the nested
             * NSpid level until reap.
             */
            *pid_out = entry->reaped ? (int64_t) -1 : entry->guest_pid;
            if (newpid_ns_out)
                *newpid_ns_out = entry->newpid_ns && !entry->reaped;
            ok = true;
        }
        pthread_mutex_unlock(&pidfd_lock);
    }
    pthread_mutex_unlock(&fd_lock);
    return ok;
}

/* If a thread-mode pidfd's tid has exited in the shared map, complete+reap it
 * locally. Cheap; also the path GET_INFO takes when the map monitor has not yet
 * woken.
 */
static void pidfd_sync_threadmap_one(int64_t tid)
{
    if (tid <= 0)
        return;
    bool exited = false;
    int status = 0;
    if (!proc_thread_resolve(tid, NULL, NULL, &exited, &status) || !exited)
        return;
    proc_pidfd_notify_exit_code(tid, status);
    proc_pidfd_notify_reaped(tid, status);
}

int64_t pidfd_ioctl_get_info(guest_t *g, int guest_fd, uint64_t arg_gva)
{
    linux_pidfd_info_t info = {0};
    if (guest_read(g, arg_gva, &info, sizeof(info)) < 0)
        return -LINUX_EFAULT;

    int64_t target_pid = -1;
    int64_t target_tgid = -1;
    bool reaped = false;
    int exit_code = 0;
    bool found = false;

    pthread_mutex_lock(&fd_lock);
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE) ||
        fd_table[guest_fd].type != FD_PIDFD) {
        pthread_mutex_unlock(&fd_lock);
        return -LINUX_EBADF;
    }
    int64_t sync_tid = -1;
    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_ofd_entry(fd_table[guest_fd].ofd_id);
    if (entry) {
        found = true;
        target_pid = entry->guest_pid;
        target_tgid = entry->tgid > 0 ? entry->tgid : entry->guest_pid;
        reaped = entry->reaped;
        exit_code = entry->exit_code;
        if (entry->thread_mode && !entry->reaped)
            sync_tid = entry->guest_pid;
    }
    pthread_mutex_unlock(&pidfd_lock);
    pthread_mutex_unlock(&fd_lock);

    if (sync_tid > 0) {
        pidfd_sync_threadmap_one(sync_tid);
        /* Re-read after sync. */
        pthread_mutex_lock(&fd_lock);
        if (RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE) &&
            fd_table[guest_fd].type == FD_PIDFD) {
            pthread_mutex_lock(&pidfd_lock);
            entry = pidfd_find_ofd_entry(fd_table[guest_fd].ofd_id);
            if (entry) {
                target_pid = entry->guest_pid;
                target_tgid = entry->tgid > 0 ? entry->tgid : entry->guest_pid;
                reaped = entry->reaped;
                exit_code = entry->exit_code;
            } else {
                found = false;
            }
            pthread_mutex_unlock(&pidfd_lock);
        } else {
            found = false;
        }
        pthread_mutex_unlock(&fd_lock);
    }

    if (!found)
        return -LINUX_EBADF;

    /* Reaped + EXIT not requested: ESRCH. Zombie (exited, not reaped) still
     * answers CREDS queries.
     */
    if (reaped && !(info.mask & PIDFD_INFO_EXIT))
        return -LINUX_ESRCH;

    uint64_t out_mask = 0;
    linux_pidfd_info_t out = {0};

    if (!reaped) {
        /* Alive or zombie: PID + CREDS always. */
        out.pid = (uint32_t) target_pid;
        out.tgid = (uint32_t) target_tgid;
        out.ppid = (uint32_t) proc_get_ppid();
        out.ruid = proc_get_uid();
        out.rgid = proc_get_gid();
        out.euid = proc_get_euid();
        out.egid = proc_get_egid();
        out.suid = proc_get_suid();
        out.sgid = proc_get_sgid();
        out.fsuid = proc_get_euid();
        out.fsgid = proc_get_egid();
        out_mask |= PIDFD_INFO_PID | PIDFD_INFO_CREDS;

        out.cgroupid = 1;
        if (info.mask & PIDFD_INFO_CGROUPID)
            out_mask |= PIDFD_INFO_CGROUPID;

        /* Zombie: EXIT bit is NOT set even when requested; wait first. */
    } else {
        out.exit_code = exit_code;
        out_mask |= PIDFD_INFO_EXIT;
        if (info.mask & PIDFD_INFO_CGROUPID) {
            out.cgroupid = 1;
            out_mask |= PIDFD_INFO_CGROUPID;
        }
    }

    if (info.mask & PIDFD_INFO_SUPPORTED_MASK) {
        out.supported_mask = PIDFD_INFO_ALL_SUPPORTED;
        out_mask |= PIDFD_INFO_SUPPORTED_MASK;
    }

    if (info.mask & PIDFD_INFO_COREDUMP) {
        out.coredump_mask = 0;
        out_mask |= PIDFD_INFO_COREDUMP;
    }
    if (info.mask & PIDFD_INFO_COREDUMP_SIGNAL) {
        out.coredump_signal = 0;
        out_mask |= PIDFD_INFO_COREDUMP_SIGNAL;
    }
    if (info.mask & PIDFD_INFO_COREDUMP_CODE) {
        out.coredump_code = 0;
        out_mask |= PIDFD_INFO_COREDUMP_CODE;
    }

    out.mask = out_mask;
    if (guest_write(g, arg_gva, &out, sizeof(out)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* Cross-process pidfd_getfd: requester drops a line in the target's inbox and
 * rings SIGUSR2; the target's signal drain dups the host fd and ships it back
 * over a reply AF_UNIX socket via SCM_RIGHTS. Mirrors the guest-signal
 * transport layout (private temp file keyed by host pid).
 */
static bool getfd_inbox_path(char *out, size_t out_size, pid_t host_pid)
{
    char dir[PATH_MAX];
    size_t n = confstr(_CS_DARWIN_USER_TEMP_DIR, dir, sizeof(dir));
    if (n == 0 || n > sizeof(dir))
        return false;
    int len = snprintf(out, out_size, "%selfuse-getfd-%llu", dir,
                       (unsigned long long) host_pid);
    return len > 0 && (size_t) len < out_size;
}

static bool getfd_reply_path(char *out, size_t out_size)
{
    /* macOS sun_path is only 104 bytes; Darwin user temp dirs are long, so use
     * a short mkstemp path under /tmp and convert the file into a socket name.
     */
    if (out_size < 32)
        return false;
    snprintf(out, out_size, "/tmp/elfuse-gfr-XXXXXX");
    int tfd = mkstemp(out);
    if (tfd < 0)
        return false;
    close(tfd);
    unlink(out); /* name is ours for bind() until we unlink after accept */
    return true;
}

/* Send {err, optional SCM_RIGHTS fd} to a listening reply socket. */
static void getfd_reply(const char *reply_path, int err, int host_fd)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        return;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(reply_path) >= sizeof(addr.sun_path)) {
        close(sock);
        return;
    }
    memcpy(addr.sun_path, reply_path, strlen(reply_path) + 1);

    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(sock);
        return;
    }

    int32_t e = (int32_t) err;
    struct iovec iov = {.iov_base = &e, .iov_len = sizeof(e)};
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    if (err == 0 && host_fd >= 0) {
        memset(cmsgbuf, 0, sizeof(cmsgbuf));
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &host_fd, sizeof(int));
    }

    (void) sendmsg(sock, &msg, 0);
    close(sock);
}

/* Serve one getfd request against this process's fd table. */
static void getfd_serve_one(int target_fd, const char *reply_path)
{
    /* Linux pidfd_getfd requires PTRACE_MODE_ATTACH_REALCREDS. A non-dumpable
     * target refuses every caller that lacks CAP_SYS_PTRACE; we approximate by
     * always returning EPERM when dumpable is off (covers the kselftest path
     * that drops dumpable without needing credential matching).
     */
    if (!proc_get_dumpable()) {
        getfd_reply(reply_path, LINUX_EPERM, -1);
        return;
    }

    int host_dup = -1;
    int err = LINUX_EBADF;

    pthread_mutex_lock(&fd_lock);
    if (RANGE_CHECK(target_fd, 0, FD_TABLE_SIZE) &&
        fd_table[target_fd].type != FD_CLOSED &&
        fd_table[target_fd].host_fd >= 0) {
        proc_synthetic_disown(fd_table[target_fd].host_fd);
        host_dup = dup(fd_table[target_fd].host_fd);
        if (host_dup < 0)
            err =
                (errno == EMFILE || errno == ENFILE) ? LINUX_EMFILE : LINUX_EIO;
        else
            err = 0;
    }
    pthread_mutex_unlock(&fd_lock);

    getfd_reply(reply_path, err, host_dup);
    if (host_dup >= 0)
        close(host_dup);
}

/* Cross-process scheduler control RPC
 *
 * Same transport as pidfd_getfd (inbox line + SIGUSR2 + AF_UNIX reply), but the
 * reply is a fixed pidfd_sched_state_t rather than an SCM_RIGHTS fd. The
 * request line is:
 *
 *   S ns gpid tid op req_euid policy nice rtprio flags runtime deadline period
 * maskhex reply
 *
 * Only the registered guest PID of a backend is addressable; a non-leader
 * remote TID has no registry identity and is answered with -ESRCH by the
 * requester rather than being mapped to its leader.
 */
static bool sched_mask_to_hex(const uint8_t *mask,
                              size_t len,
                              char *out,
                              size_t out_size)
{
    static const char digits[] = "0123456789abcdef";
    if (!out || out_size < 2)
        return false;
    if (!mask || len == 0) {
        out[0] = '0';
        out[1] = '\0';
        return true;
    }
    if (len > SCHED_CPUSET_BYTES || out_size < len * 2 + 1)
        return false;
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = digits[mask[i] >> 4];
        out[i * 2 + 1] = digits[mask[i] & 0xf];
    }
    out[len * 2] = '\0';
    return true;
}

static int sched_mask_from_hex(const char *hex, uint8_t *out, size_t out_size)
{
    if (!hex || !out)
        return -LINUX_EINVAL;
    size_t n = strlen(hex);
    if (n == 1 && hex[0] == '0')
        return 0;
    if ((n & 1) != 0 || n / 2 > out_size)
        return -LINUX_EINVAL;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex[i * 2], lo = hex[i * 2 + 1];
        if (hi >= '0' && hi <= '9')
            hi -= '0';
        else if (hi >= 'a' && hi <= 'f')
            hi = hi - 'a' + 10;
        else
            return -LINUX_EINVAL;
        if (lo >= '0' && lo <= '9')
            lo -= '0';
        else if (lo >= 'a' && lo <= 'f')
            lo = lo - 'a' + 10;
        else
            return -LINUX_EINVAL;
        out[i] = (uint8_t) ((hi << 4) | lo);
    }
    return (int) (n / 2);
}

static void pidfd_sched_send_reply(const char *reply_path,
                                   const pidfd_sched_state_t *st)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        return;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(reply_path) >= sizeof(addr.sun_path)) {
        close(sock);
        return;
    }
    memcpy(addr.sun_path, reply_path, strlen(reply_path) + 1);
    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) == 0)
        (void) write_all(sock, st, sizeof(*st));
    close(sock);
}

/* Serve one scheduler request line addressed to this process.
 *
 * Returns true when the line was a scheduler request (including a malformed
 * one), so the caller does not try the getfd parser on it.
 */
static bool pidfd_sched_serve_line(char *line, uint64_t my_ns, int64_t my_gpid)
{
    if (line[0] != 'S' || line[1] != ' ')
        return false;

    char *save = NULL;
    char *tok[15];
    int ntok = 0;
    for (char *t = strtok_r(line, " ", &save); t && ntok < 15;
         t = strtok_r(NULL, " ", &save))
        tok[ntok++] = t;
    if (ntok != 15 || strcmp(tok[0], "S") != 0)
        return true;

    unsigned long long ns = strtoull(tok[1], NULL, 10);
    long long gpid = strtoll(tok[2], NULL, 10);
    long long tid = strtoll(tok[3], NULL, 10);
    unsigned op = (unsigned) strtoul(tok[4], NULL, 10);
    uint32_t req_euid = (uint32_t) strtoul(tok[5], NULL, 10);
    int policy = (int) strtol(tok[6], NULL, 10);
    int nice = (int) strtol(tok[7], NULL, 10);
    unsigned rtprio = (unsigned) strtoul(tok[8], NULL, 10);
    unsigned flags = (unsigned) strtoul(tok[9], NULL, 10);
    uint64_t runtime = strtoull(tok[10], NULL, 10);
    uint64_t deadline = strtoull(tok[11], NULL, 10);
    uint64_t period = strtoull(tok[12], NULL, 10);
    const char *maskhex = tok[13];
    const char *reply = tok[14];

    if (ns != my_ns || gpid != my_gpid || tid <= 0)
        return true;

    pidfd_sched_state_t st;
    memset(&st, 0, sizeof(st));
    st.magic = PIDFD_SCHED_RPC_MAGIC;
    int64_t rc = -LINUX_EINVAL;

    switch (op) {
    case PIDFD_SCHED_OP_QUERY: {
        rc = sys_sched_remote_query(tid, &st.attrs, &st.uid, &st.euid,
                                    &st.rr_interval_ns, &st.rlimit_nice,
                                    &st.rlimit_rtprio);
        if (rc == 0) {
            int m = (int) sys_sched_remote_get_affinity(tid, st.mask,
                                                        sizeof(st.mask));
            if (m < 0)
                rc = m;
            else
                st.mask_len = (uint32_t) m;
        }
        break;
    }
    case PIDFD_SCHED_OP_SET_ATTR: {
        sched_task_attrs_t a = {
            .policy = policy,
            .nice = nice,
            .rt_priority = rtprio,
            .flags = flags,
            .runtime = runtime,
            .deadline = deadline,
            .period = period,
        };
        rc = sys_sched_remote_set_attr(tid, &a, req_euid);
        break;
    }
    case PIDFD_SCHED_OP_SET_NICE:
        rc = sys_sched_remote_set_nice(tid, nice, req_euid);
        break;
    case PIDFD_SCHED_OP_SET_AFFINITY: {
        uint8_t mask[SCHED_CPUSET_BYTES];
        int mlen = sched_mask_from_hex(maskhex, mask, sizeof(mask));
        if (mlen < 0)
            rc = mlen;
        else
            rc = sys_sched_remote_set_affinity(tid, mask, (size_t) mlen,
                                               req_euid);
        break;
    }
    default:
        break;
    }
    st.rc = (int32_t) rc;
    pidfd_sched_send_reply(reply, &st);
    return true;
}

/* Send one scheduler request to @target_tid's backend and wait for the reply.
 * Returns 0 and fills @out for a successful query/apply, or a negative Linux
 * errno (including the target's own answer). @target_tid must be the registered
 * guest PID of that backend.
 */
static int64_t pidfd_sched_call(int64_t target_tid,
                                unsigned op,
                                uint32_t requester_euid,
                                const sched_task_attrs_t *attrs,
                                int nice,
                                const uint8_t *mask,
                                size_t mask_len,
                                pidfd_sched_state_t *out)
{
    pid_t host_pid = 0;
    int64_t tgid = 0;
    bool exited = false;
    if (proc_thread_resolve(target_tid, &host_pid, &tgid, &exited, NULL)) {
        if (exited)
            return -LINUX_ESRCH;
    } else {
        host_pid = proc_resolve_guest_pid(target_tid);
        tgid = target_tid;
    }
    if (host_pid <= 0 || tgid <= 0 || host_pid == getpid())
        return -LINUX_ESRCH;
    if (kill(host_pid, 0) != 0 && errno == ESRCH)
        return -LINUX_ESRCH;

    char reply_path[PATH_MAX];
    if (!getfd_reply_path(reply_path, sizeof(reply_path)))
        return -LINUX_EIO;
    unlink(reply_path);

    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        unlink(reply_path);
        return -LINUX_EIO;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, reply_path, strlen(reply_path) + 1);
    if (bind(listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
        listen(listen_fd, 1) < 0) {
        close(listen_fd);
        unlink(reply_path);
        return -LINUX_EIO;
    }

    char inbox[PATH_MAX];
    if (!getfd_inbox_path(inbox, sizeof(inbox), host_pid)) {
        close(listen_fd);
        unlink(reply_path);
        return -LINUX_EIO;
    }
    int ifd = open(
        inbox, O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (ifd < 0) {
        close(listen_fd);
        unlink(reply_path);
        return -LINUX_EIO;
    }

    char maskhex[SCHED_CPUSET_BYTES * 2 + 2];
    if (!sched_mask_to_hex(mask, mask_len, maskhex, sizeof(maskhex))) {
        close(ifd);
        close(listen_fd);
        unlink(reply_path);
        return -LINUX_EINVAL;
    }
    sched_task_attrs_t zero;
    memset(&zero, 0, sizeof(zero));
    if (!attrs)
        attrs = &zero;

    char line[PATH_MAX + 1024];
    int len = snprintf(
        line, sizeof(line),
        "S %llu %lld %lld %u %u %d %d %u %u %llu %llu %llu %s %s\n",
        (unsigned long long) absock_get_namespace_id(), (long long) tgid,
        (long long) target_tid, op, requester_euid, attrs->policy, attrs->nice,
        attrs->rt_priority, attrs->flags, (unsigned long long) attrs->runtime,
        (unsigned long long) attrs->deadline,
        (unsigned long long) attrs->period, maskhex, reply_path);
    if (len < 0 || (size_t) len >= sizeof(line) || flock(ifd, LOCK_EX) != 0 ||
        write_all(ifd, line, (size_t) len) < 0) {
        flock(ifd, LOCK_UN);
        close(ifd);
        close(listen_fd);
        unlink(reply_path);
        return -LINUX_EIO;
    }
    flock(ifd, LOCK_UN);
    close(ifd);

    if (kill(host_pid, SIGUSR2) != 0) {
        close(listen_fd);
        unlink(reply_path);
        return -LINUX_ESRCH;
    }

    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    (void) setsockopt(listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int conn = accept(listen_fd, NULL, NULL);
    close(listen_fd);
    unlink(reply_path);
    if (conn < 0)
        return -LINUX_EIO;

    pidfd_sched_state_t reply;
    ssize_t n = recv(conn, &reply, sizeof(reply), MSG_WAITALL);
    close(conn);
    if (n != (ssize_t) sizeof(reply) || reply.magic != PIDFD_SCHED_RPC_MAGIC)
        return -LINUX_EIO;
    if (out)
        *out = reply;
    return reply.rc;
}

int64_t pidfd_sched_query(int64_t target_tid, pidfd_sched_state_t *out)
{
    if (!out)
        return -LINUX_EINVAL;
    return pidfd_sched_call(target_tid, PIDFD_SCHED_OP_QUERY, proc_get_euid(),
                            NULL, 0, NULL, 0, out);
}

int64_t pidfd_sched_set_attr(int64_t target_tid,
                             const sched_task_attrs_t *attrs,
                             uint32_t requester_euid)
{
    if (!attrs)
        return -LINUX_EINVAL;
    return pidfd_sched_call(target_tid, PIDFD_SCHED_OP_SET_ATTR, requester_euid,
                            attrs, 0, NULL, 0, NULL);
}

int64_t pidfd_sched_set_nice(int64_t target_tid,
                             int nice,
                             uint32_t requester_euid)
{
    return pidfd_sched_call(target_tid, PIDFD_SCHED_OP_SET_NICE, requester_euid,
                            NULL, nice, NULL, 0, NULL);
}

int64_t pidfd_sched_set_affinity(int64_t target_tid,
                                 const uint8_t *mask,
                                 size_t mask_len,
                                 uint32_t requester_euid)
{
    if (!mask || mask_len > SCHED_CPUSET_BYTES)
        return -LINUX_EINVAL;
    return pidfd_sched_call(target_tid, PIDFD_SCHED_OP_SET_AFFINITY,
                            requester_euid, NULL, 0, mask, mask_len, NULL);
}

void pidfd_getfd_drain(void)
{
    char path[PATH_MAX];
    if (!getfd_inbox_path(path, sizeof(path), getpid()))
        return;

    int fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return;

    if (flock(fd, LOCK_EX) != 0) {
        close(fd);
        return;
    }

    /* Read the whole inbox, truncate, then serve. Serving after truncate means
     * a crashed serve cannot leave a stuck request that re-fires forever; the
     * requester times out and retries or fails.
     */
    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz < 0 || lseek(fd, 0, SEEK_SET) != 0) {
        flock(fd, LOCK_UN);
        close(fd);
        return;
    }

    char *buf = NULL;
    if (sz > 0) {
        if (sz > 1 << 20) /* refuse pathological inboxes */
            sz = 1 << 20;
        buf = malloc((size_t) sz + 1);
        if (!buf) {
            flock(fd, LOCK_UN);
            close(fd);
            return;
        }
        ssize_t n = read(fd, buf, (size_t) sz);
        if (n < 0)
            n = 0;
        buf[n] = '\0';
        (void) ftruncate(fd, 0);
    }
    flock(fd, LOCK_UN);
    close(fd);

    if (!buf)
        return;

    uint64_t my_ns = absock_get_namespace_id();
    int64_t my_gpid = proc_get_pid();

    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (pidfd_sched_serve_line(line, my_ns, my_gpid))
            continue;
        unsigned long long ns = 0;
        long long gpid = 0;
        int target_fd = -1;
        char reply[sizeof(((struct sockaddr_un *) 0)->sun_path)];
        reply[0] = '\0';
        /* ns gpid target_fd reply_path */
        if (sscanf(line, "%llu %lld %d %103s", &ns, &gpid, &target_fd, reply) !=
            4)
            continue;
        if (ns != my_ns || gpid != my_gpid)
            continue;
        getfd_serve_one(target_fd, reply);
    }
    free(buf);
}

/* Look up target guest pid, host pid, and exited flag under one lock window. */
static int pidfd_lookup_target(int guest_fd,
                               int64_t *guest_pid_out,
                               pid_t *host_pid_out,
                               bool *exited_out)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return -1;

    int ok = -1;
    pthread_mutex_lock(&fd_lock);
    if (fd_table[guest_fd].type == FD_PIDFD) {
        pthread_mutex_lock(&pidfd_lock);
        pidfd_entry_t *entry = pidfd_find_ofd_entry(fd_table[guest_fd].ofd_id);
        if (entry) {
            *guest_pid_out = entry->guest_pid;

            /* POLLIN (exited) precedes POLLHUP (writer closed / reaped). Linux
             * returns ESRCH from getfd once the task has exited, so trust the
             * exited bit rather than waiting for the writer close.
             */
            *exited_out = entry->exited || entry->write_end < 0;
            if (entry->guest_pid == proc_get_pid())
                *host_pid_out = getpid();
            else
                *host_pid_out = entry->host_pid > 0 ? entry->host_pid : 0;
            ok = 0;
        }
        pthread_mutex_unlock(&pidfd_lock);
    }
    pthread_mutex_unlock(&fd_lock);
    return ok;
}

static int64_t getfd_force_cloexec(int64_t fd)
{
    if (fd < 0)
        return fd;
    pthread_mutex_lock(&fd_lock);
    if (RANGE_CHECK((int) fd, 0, FD_TABLE_SIZE) &&
        fd_table[fd].type != FD_CLOSED)
        fd_table[fd].linux_flags |= LINUX_O_CLOEXEC;
    pthread_mutex_unlock(&fd_lock);
    return fd;
}

static int64_t getfd_cross_process(pid_t host_pid,
                                   int64_t guest_pid,
                                   int targetfd)
{
    if (host_pid <= 0)
        return -LINUX_ESRCH;

    char reply_path[PATH_MAX];
    if (!getfd_reply_path(reply_path, sizeof(reply_path)))
        return -LINUX_EIO;

    unlink(reply_path);

    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0)
        return -LINUX_EIO;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, reply_path, strlen(reply_path) + 1);

    if (bind(listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
        listen(listen_fd, 1) < 0) {
        close(listen_fd);
        unlink(reply_path);
        return -LINUX_EIO;
    }

    char inbox[PATH_MAX];
    if (!getfd_inbox_path(inbox, sizeof(inbox), host_pid)) {
        close(listen_fd);
        unlink(reply_path);
        return -LINUX_EIO;
    }

    int ifd = open(
        inbox, O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (ifd < 0) {
        close(listen_fd);
        unlink(reply_path);
        return -LINUX_EIO;
    }

    char line[PATH_MAX + 128];
    int len = snprintf(line, sizeof(line), "%llu %lld %d %s\n",
                       (unsigned long long) absock_get_namespace_id(),
                       (long long) guest_pid, targetfd, reply_path);
    if (len < 0 || (size_t) len >= sizeof(line)) {
        close(ifd);
        close(listen_fd);
        unlink(reply_path);
        return -LINUX_EIO;
    }

    if (flock(ifd, LOCK_EX) != 0 || write_all(ifd, line, (size_t) len) < 0) {
        flock(ifd, LOCK_UN);
        close(ifd);
        close(listen_fd);
        unlink(reply_path);
        return -LINUX_EIO;
    }
    flock(ifd, LOCK_UN);
    close(ifd);

    /* Ring the target's doorbell so its getfd drain runs. */
    if (kill(host_pid, SIGUSR2) != 0) {
        close(listen_fd);
        unlink(reply_path);
        return -LINUX_ESRCH;
    }

    /* Wait for the reply with a generous timeout so a wedged target cannot hang
     * the caller forever; kselftests expect prompt EPERM/EBADF/ESRCH.
     */
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    (void) setsockopt(listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int conn = accept(listen_fd, NULL, NULL);
    close(listen_fd);
    unlink(reply_path);
    if (conn < 0)
        return -LINUX_EIO;

    int32_t err = LINUX_EIO;
    int got_fd = -1;
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {.iov_base = &err, .iov_len = sizeof(err)};
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    ssize_t n = recvmsg(conn, &msg, 0);
    close(conn);
    if (n != (ssize_t) sizeof(err))
        return -LINUX_EIO;

    if (err == 0) {
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c;
             c = CMSG_NXTHDR(&msg, c)) {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
                c->cmsg_len >= CMSG_LEN(sizeof(int))) {
                memcpy(&got_fd, CMSG_DATA(c), sizeof(int));
                break;
            }
        }
        if (got_fd < 0)
            return -LINUX_EIO;

        /* Adopt like inbound SCM_RIGHTS: foreign description, CLOEXEC set
         * (pidfd_getfd always returns O_CLOEXEC).
         */
        int recv_fl = fcntl(got_fd, F_GETFL);
        fd_alias_spec_t spec =
            fd_alias_carried(true, recv_fl >= 0 && (recv_fl & O_NONBLOCK));
        int gfd = fd_alloc_alias(&spec, FD_REGULAR, got_fd, NULL);
        if (gfd < 0) {
            close(got_fd);
            return gfd < 0 ? gfd : -LINUX_EMFILE;
        }
        return getfd_force_cloexec(gfd);
    }

    /* Positive Linux errno from the target. */
    if (err > 0)
        return -err;
    return -LINUX_EIO;
}

int64_t sys_pidfd_getfd(guest_t *g, int pidfd, int targetfd, unsigned int flags)
{
    (void) g;

    if (flags != 0)
        return -LINUX_EINVAL;

    int64_t guest_pid = -1;
    pid_t host_pid = 0;
    bool exited = false;
    if (pidfd_lookup_target(pidfd, &guest_pid, &host_pid, &exited) < 0)
        return -LINUX_EBADF;

    /* Linux returns ESRCH once the task has exited (even if the pidfd itself is
     * still open and pollable). Matches no_strange_EBADF.
     */
    if (exited)
        return -LINUX_ESRCH;

    if (guest_pid == proc_get_pid()) {
        if (!RANGE_CHECK(targetfd, 0, FD_TABLE_SIZE))
            return -LINUX_EBADF;

        /* Same open-file table: dup, then force O_CLOEXEC as the man page
         * requires for pidfd_getfd.
         */
        int64_t fd = sys_dup(targetfd);
        return getfd_force_cloexec(fd);
    }

    return getfd_cross_process(host_pid, guest_pid, targetfd);
}
