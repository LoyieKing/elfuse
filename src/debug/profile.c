/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "debug/profile.h"
#include "runtime/thread.h"
#include "syscall/abi.h"
#include "runtime/sched/exec.h"
#include "dispatch.h"

#define PROFILE_TASKS 1024
#define PROFILE_SYSCALLS 64
#define PROFILE_BUCKETS 16
#define PROFILE_ERRORS 8
#define PROFILE_PCS 64
#define PROFILE_KINDS 11
/* Diagnostic storage limits; task churn never overwrites a prior lifetime. */

enum {
    CALLS,
    ATTEMPTS,
    COMPLETED,
    PARKS,
    ACTIVE_NS,
    ACTIVE_MAX_NS,
    LATENCY_NS,
    LATENCY_MAX_NS,
    ERRORS,
    ZERO_RETURNS,
    POSITIVE_RETURNS,
    IO_BYTES,
    CALL_FIELDS
};
enum {
    GUEST_CPU,
    SERVICE_CPU,
    GUEST_WALL,
    HOST_WALL,
    MOUNTS,
    PREEMPTS,
    WAKES,
    THREAD_FIELDS
};

typedef struct {
    _Atomic int nr_plus_one;
    _Atomic uint64_t values[CALL_FIELDS];
    _Atomic uint64_t hist[PROFILE_BUCKETS];
    _Atomic int error_nr[PROFILE_ERRORS];
    _Atomic uint64_t error_count[PROFILE_ERRORS];
    _Atomic uint64_t error_overflow;
    _Atomic int64_t last_return;
} profile_call_t;

typedef struct {
    _Atomic uint64_t count;
    uint64_t pc;
    uint64_t lr;
    bool rosetta;
    uint64_t epoch;
} profile_pc_t;

struct profile_task {
    _Atomic bool published;
    int64_t tid;
    uint64_t generation;
    _Atomic uint64_t values[THREAD_FIELDS];
    _Atomic uint64_t wait_ns[PROFILE_KINDS + 1];
    _Atomic int state;
    _Atomic int kind;
    _Atomic uint64_t state_start;
    _Atomic int worker;
    _Atomic uint64_t syscall_overflow;
    _Atomic uint64_t incomplete_calls;
    _Atomic uint64_t pc_overflow;
    _Atomic uint64_t pc_non_el0;
    _Atomic int open_nr;
    _Atomic uint64_t open_start;
    _Atomic uint64_t phase_live_start;
    _Atomic bool phase_live_guest;
    profile_call_t calls[PROFILE_SYSCALLS];
    profile_pc_t pcs[PROFILE_PCS];
    /* Owner-only fields follow the task across mount migration. */
    profile_call_t *call;
    profile_call_t *last_call;
    uint64_t logical_start;
    uint64_t attempt_start;
    uint64_t phase_start;
    uint64_t pc_deadline;
    bool guest_phase;
    unsigned pc_used;
};

_Atomic bool profile_active;
static struct profile_task *tasks;
static _Atomic unsigned task_count;
static _Atomic uint64_t task_overflow;
static _Atomic uint64_t clock_errors;
static _Atomic uint64_t epoch;
static _Atomic bool image_rosetta;
typedef struct {
    _Atomic uint64_t calls;
    _Atomic uint64_t ns;
    _Atomic uint64_t max_ns;
    _Atomic uint64_t failed;
    _Atomic uint64_t owner;
    _Atomic uint64_t remote;
    _Atomic uint64_t owner_ns;
    _Atomic uint64_t remote_ns;
} profile_account_t;
_Static_assert(sizeof(profile_account_t) == 64, "accounting cache line");
static profile_account_t accounting[SCHED_MAX_CPUS + 1];
static FILE *stream;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static pthread_once_t writer_once = PTHREAD_ONCE_INIT;
static pthread_t writer;
static pthread_mutex_t writer_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t writer_cond = PTHREAD_COND_INITIALIZER;
static bool stopping;
static uint64_t interval_ms = 1000;
static uint64_t pc_interval_ns;
static uint64_t snapshot_seq;
static uint64_t start_ns;

static const char *const names[512] = {
#define _(name, handler, extra) [name] = #name,
    SYSCALL_TABLE_ENTRIES(_)
#undef _
};
_Static_assert(SC_MAX_SYSCALL_NUM < 512, "profile syscall name table");
_Static_assert(PARK_KIND_SIGNAL + 1 == PROFILE_KINDS, "profile park kinds");

#define LOAD(p) atomic_load_explicit((p), memory_order_relaxed)
#define ADD(p, n) atomic_fetch_add_explicit((p), (n), memory_order_relaxed)
#define STORE(p, n) atomic_store_explicit((p), (n), memory_order_relaxed)

static void maximum(_Atomic uint64_t *p, uint64_t value)
{
    uint64_t previous = LOAD(p);
    while (value > previous && !atomic_compare_exchange_weak_explicit(
                                   p, &previous, value, memory_order_relaxed,
                                   memory_order_relaxed)) {
    }
}

uint64_t profile_now_ns(void)
{
    if (!profile_enabled())
        return 0;
    int saved_errno = errno;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        ADD(&clock_errors, 1);
        errno = saved_errno;
        return 0;
    }
    errno = saved_errno;
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static uint64_t elapsed(uint64_t start, uint64_t end)
{
    return start && end >= start ? end - start : 0;
}

static unsigned bucket(uint64_t ns)
{
    uint64_t us = ns / 1000;
    unsigned b = 0;
    while (us > 1 && b < PROFILE_BUCKETS - 1) {
        us >>= 1;
        b++;
    }
    return b;
}

static struct profile_task *task(struct thread_entry *t)
{
    return profile_enabled() && t ? t->profile : NULL;
}

void profile_attach(struct thread_entry *t)
{
    if (!profile_enabled() || !t || t->profile)
        return;
    unsigned n = LOAD(&task_count);
    while (n < PROFILE_TASKS &&
           !atomic_compare_exchange_weak_explicit(&task_count, &n, n + 1,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) {
    }
    if (n == PROFILE_TASKS) {
        ADD(&task_overflow, 1);
        return;
    }
    struct profile_task *p = &tasks[n];
    p->tid = thread_tid(t);
    p->generation = t->generation;
    STORE(&p->worker, -1);
    STORE(&p->state, SCHED_STATE_NEW);
    STORE(&p->state_start, profile_now_ns());
    t->profile = p;
    STORE(&p->open_nr, -1);
    /* The exporter acquires publication before reading immutable identity. */
    atomic_store_explicit(&p->published, true, memory_order_release);
}

void profile_state(struct thread_entry *t, int state, int kind, uint64_t now)
{
    struct profile_task *p = task(t);
    if (!p)
        return;
    int old = LOAD(&p->state);
    if (old == state)
        return;
    uint64_t delta = elapsed(LOAD(&p->state_start), now);
    if (old == SCHED_STATE_READY)
        ADD(&p->wait_ns[0], delta);
    else if (old == SCHED_STATE_BLOCKED) {
        int k = LOAD(&p->kind);
        if (k >= 0 && k < PROFILE_KINDS)
            ADD(&p->wait_ns[k + 1], delta);
    }
    STORE(&p->kind, kind);
    STORE(&p->state_start, now);
    STORE(&p->state, state);
    if (state == SCHED_STATE_DEAD) {
        int open =
            atomic_exchange_explicit(&p->open_nr, -1, memory_order_relaxed);
        if (open >= 0)
            ADD(&p->incomplete_calls, 1);
    }
}

void profile_wake(struct thread_entry *t)
{
    struct profile_task *p = task(t);
    if (p)
        ADD(&p->values[WAKES], 1);
}

void profile_mount(struct thread_entry *t, int worker)
{
    struct profile_task *p = task(t);
    if (!p)
        return;
    STORE(&p->worker, worker);
    ADD(&p->values[MOUNTS], 1);
    p->phase_start = profile_now_ns();
    p->guest_phase = false;
    STORE(&p->phase_live_start, p->phase_start);
    STORE(&p->phase_live_guest, false);
}

void profile_preempt(struct thread_entry *t)
{
    struct profile_task *p = task(t);
    if (p)
        ADD(&p->values[PREEMPTS], 1);
}

void profile_phase(struct thread_entry *t, bool guest)
{
    struct profile_task *p = task(t);
    if (!p)
        return;
    uint64_t now = profile_now_ns();
    ADD(&p->values[p->guest_phase ? GUEST_WALL : HOST_WALL],
        elapsed(p->phase_start, now));
    p->phase_start = now;
    p->guest_phase = guest;
    STORE(&p->phase_live_start, now);
    STORE(&p->phase_live_guest, guest);
}

void profile_cpu(struct thread_entry *t, uint64_t guest, uint64_t service)
{
    struct profile_task *p = task(t);
    if (!p)
        return;
    ADD(&p->values[GUEST_CPU], guest);
    ADD(&p->values[SERVICE_CPU], service);
}

void profile_accounting(uint64_t start, bool success, int slot, bool owner)
{
    if (!start)
        return;
    uint64_t ns = elapsed(start, profile_now_ns());
    int index =
        owner && slot >= 0 && slot < SCHED_MAX_CPUS ? slot : SCHED_MAX_CPUS;
    profile_account_t *a = &accounting[index];
    ADD(&a->calls, 1);
    ADD(&a->ns, ns);
    maximum(&a->max_ns, ns);
    if (!success)
        ADD(&a->failed, 1);
    if (owner) {
        ADD(&a->owner, 1);
        ADD(&a->owner_ns, ns);
    } else {
        ADD(&a->remote, 1);
        ADD(&a->remote_ns, ns);
    }
}

void profile_syscall_begin(struct thread_entry *t, int nr)
{
    struct profile_task *p = task(t);
    if (!p)
        return;
    if (nr < 0 || nr == INT_MAX) {
        ADD(&p->syscall_overflow, 1);
        return;
    }
    uint64_t now = profile_now_ns();
    if (p->call && LOAD(&p->call->nr_plus_one) != nr + 1) {
        ADD(&p->incomplete_calls, 1);
        p->call = NULL;
    }
    if (!p->call) {
        if (p->last_call && LOAD(&p->last_call->nr_plus_one) == nr + 1)
            p->call = p->last_call;
        for (unsigned probe = 0; !p->call && probe < PROFILE_SYSCALLS;
             probe++) {
            unsigned i = ((unsigned) nr + probe) % PROFILE_SYSCALLS;
            int key = LOAD(&p->calls[i].nr_plus_one);
            if (key == nr + 1 || key == 0) {
                if (key == 0)
                    STORE(&p->calls[i].nr_plus_one, nr + 1);
                p->call = &p->calls[i];
                break;
            }
        }
        if (!p->call) {
            ADD(&p->syscall_overflow, 1);
            return;
        }
        p->last_call = p->call;
        p->logical_start = now;
        STORE(&p->open_nr, nr);
        STORE(&p->open_start, now);
        ADD(&p->call->values[CALLS], 1);
    }
    p->attempt_start = now;
    ADD(&p->call->values[ATTEMPTS], 1);
}

static bool io_bytes(int nr)
{
    return nr == SYS_read || nr == SYS_write || nr == SYS_readv ||
           nr == SYS_writev || nr == SYS_pread64 || nr == SYS_pwrite64 ||
           nr == SYS_preadv || nr == SYS_pwritev || nr == SYS_sendto ||
           nr == SYS_recvfrom || nr == SYS_sendmsg || nr == SYS_recvmsg ||
           nr == SYS_sendfile || nr == SYS_splice;
}

static void complete(struct profile_task *p, int64_t result, uint64_t now)
{
    profile_call_t *c = p->call;
    if (!c)
        return;
    uint64_t ns = elapsed(p->logical_start, now);
    ADD(&c->values[COMPLETED], 1);
    ADD(&c->values[LATENCY_NS], ns);
    maximum(&c->values[LATENCY_MAX_NS], ns);
    STORE(&c->last_return, result);
    if (result < 0 && result >= -4095) {
        ADD(&c->values[ERRORS], 1);
        unsigned i;
        for (i = 0; i < PROFILE_ERRORS; i++) {
            int key = LOAD(&c->error_nr[i]);
            if (key == -result || key == 0) {
                STORE(&c->error_nr[i], (int) -result);
                ADD(&c->error_count[i], 1);
                break;
            }
        }
        if (i == PROFILE_ERRORS)
            ADD(&c->error_overflow, 1);
    } else if (result == 0) {
        ADD(&c->values[ZERO_RETURNS], 1);
    } else if (result > 0) {
        ADD(&c->values[POSITIVE_RETURNS], 1);
        if (io_bytes(LOAD(&c->nr_plus_one) - 1))
            ADD(&c->values[IO_BYTES], (uint64_t) result);
    }
    p->call = NULL;
    STORE(&p->open_nr, -1);
    STORE(&p->open_start, 0);
}

void profile_syscall_end(struct thread_entry *t, int64_t result, bool parked)
{
    struct profile_task *p = task(t);
    if (!p || !p->call)
        return;
    uint64_t now = profile_now_ns();
    uint64_t ns = elapsed(p->attempt_start, now);
    ADD(&p->call->values[ACTIVE_NS], ns);
    maximum(&p->call->values[ACTIVE_MAX_NS], ns);
    ADD(&p->call->hist[bucket(ns)], 1);
    if (parked)
        ADD(&p->call->values[PARKS], 1);
    else
        complete(p, result, now);
}

void profile_syscall_resume(struct thread_entry *t)
{
    struct profile_task *p = task(t);
    if (p)
        complete(p, exec_park_result_load(t), profile_now_ns());
}

void profile_exec(struct thread_entry *t)
{
    if (!profile_enabled())
        return;
    ADD(&epoch, 1);
    struct profile_task *p = task(t);
    if (p)
        p->pc_deadline = 0;
}

void profile_image(bool rosetta)
{
    if (profile_enabled())
        STORE(&image_rosetta, rosetta);
}

bool profile_sample_due(struct thread_entry *t)
{
    struct profile_task *p = task(t);
    if (!p || !pc_interval_ns)
        return false;
    uint64_t now = profile_now_ns();
    if (!now || now < p->pc_deadline)
        return false;
    p->pc_deadline = now + pc_interval_ns;
    return true;
}

void profile_sample(struct thread_entry *t,
                    uint64_t pc,
                    uint64_t lr,
                    bool el0,
                    bool rosetta)
{
    struct profile_task *p = task(t);
    if (!p)
        return;
    if (!el0) {
        ADD(&p->pc_non_el0, 1);
        return;
    }
    for (unsigned i = 0; i < p->pc_used; i++) {
        if (p->pcs[i].pc == pc && p->pcs[i].lr == lr &&
            p->pcs[i].rosetta == rosetta && p->pcs[i].epoch == LOAD(&epoch)) {
            ADD(&p->pcs[i].count, 1);
            return;
        }
    }
    if (p->pc_used == PROFILE_PCS) {
        ADD(&p->pc_overflow, 1);
        return;
    }
    profile_pc_t *s = &p->pcs[p->pc_used++];
    s->pc = pc;
    s->lr = lr;
    s->rosetta = rosetta;
    s->epoch = LOAD(&epoch);
    /* Count publishes the immutable address pair to the exporter. */
    atomic_store_explicit(&s->count, 1, memory_order_release);
}

static void array(const _Atomic uint64_t *values, unsigned n)
{
    fputc('[', stream);
    for (unsigned i = 0; i < n; i++)
        fprintf(stream, "%s%" PRIu64, i ? "," : "", LOAD(&values[i]));
    fputc(']', stream);
}

static void snapshot(bool final)
{
    uint64_t now = profile_now_ns();
    uint64_t seq = ++snapshot_seq;
    uint64_t current_epoch = LOAD(&epoch);
    uint64_t calls = 0, ns = 0, max = 0, failed = 0, owner = 0, remote = 0;
    uint64_t owner_ns = 0, remote_ns = 0;
    for (unsigned i = 0; i <= SCHED_MAX_CPUS; i++) {
        calls += LOAD(&accounting[i].calls);
        ns += LOAD(&accounting[i].ns);
        uint64_t sample_max = LOAD(&accounting[i].max_ns);
        if (sample_max > max)
            max = sample_max;
        failed += LOAD(&accounting[i].failed);
        owner += LOAD(&accounting[i].owner);
        remote += LOAD(&accounting[i].remote);
        owner_ns += LOAD(&accounting[i].owner_ns);
        remote_ns += LOAD(&accounting[i].remote_ns);
    }
    fprintf(stream,
            "{\"v\":1,\"type\":\"snapshot\",\"seq\":%" PRIu64
            ",\"host_pid\":%d,\"mono_ns\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64
            ",\"epoch\":%" PRIu64
            ",\"rosetta\":%s,\"final\":%s,"
            "\"task_overflow\":%" PRIu64 ",\"clock_errors\":%" PRIu64
            ",\"cpu_sample\":{\"calls\":%" PRIu64 ",\"wall_ns\":%" PRIu64
            ",\"max_ns\":%" PRIu64 ",\"failed\":%" PRIu64
            ",\"owner_calls\":%" PRIu64 ",\"remote_calls\":%" PRIu64
            ",\"owner_ns\":%" PRIu64 ",\"remote_ns\":%" PRIu64 "}}\n",
            seq, getpid(), now, elapsed(start_ns, now), current_epoch,
            LOAD(&image_rosetta) ? "true" : "false", final ? "true" : "false",
            LOAD(&task_overflow), LOAD(&clock_errors), calls, ns, max, failed,
            owner, remote, owner_ns, remote_ns);
    unsigned count = LOAD(&task_count);
    if (count > PROFILE_TASKS)
        count = PROFILE_TASKS;
    for (unsigned n = 0; n < count; n++) {
        struct profile_task *p = &tasks[n];
        if (!atomic_load_explicit(&p->published, memory_order_acquire))
            continue;
        fprintf(stream,
                "{\"v\":1,\"type\":\"thread\",\"seq\":%" PRIu64
                ",\"task\":%u,\"tid\":%" PRId64 ",\"generation\":%" PRIu64
                ",\"worker\":%d,\"state\":%d,\"kind\":%d,\"state_start_ns\":"
                "%" PRIu64 ",\"values\":",
                seq, n, p->tid, p->generation, LOAD(&p->worker),
                LOAD(&p->state), LOAD(&p->kind), LOAD(&p->state_start));
        array(p->values, THREAD_FIELDS);
        fputs(",\"wait_ns\":", stream);
        array(p->wait_ns, PROFILE_KINDS + 1);
        fprintf(stream,
                ",\"open_nr\":%d,\"open_start_ns\":%" PRIu64
                ",\"phase_start_ns\":%" PRIu64 ",\"phase_guest\":%s",
                LOAD(&p->open_nr), LOAD(&p->open_start),
                LOAD(&p->phase_live_start),
                LOAD(&p->phase_live_guest) ? "true" : "false");
        fprintf(stream,
                ",\"syscall_overflow\":%" PRIu64
                ",\"incomplete_calls\":%" PRIu64 ",\"pc_overflow\":%" PRIu64
                ",\"pc_non_el0\":%" PRIu64 "}\n",
                LOAD(&p->syscall_overflow), LOAD(&p->incomplete_calls),
                LOAD(&p->pc_overflow), LOAD(&p->pc_non_el0));
        for (unsigned i = 0; i < PROFILE_SYSCALLS; i++) {
            profile_call_t *c = &p->calls[i];
            int nr = LOAD(&c->nr_plus_one) - 1;
            if (nr < 0)
                continue;
            const char *name = nr < 512 ? names[nr] : NULL;
            fprintf(stream,
                    "{\"v\":1,\"type\":\"syscall\",\"seq\":%" PRIu64
                    ",\"task\":%u,\"tid\":%" PRId64
                    ",\"nr\":%d,\"name\":\"%s\","
                    "\"values\":",
                    seq, n, p->tid, nr, name ? name : "unknown");
            array(c->values, CALL_FIELDS);
            fputs(",\"active_hist\":", stream);
            array(c->hist, PROFILE_BUCKETS);
            fprintf(stream, ",\"last_return\":%" PRId64 ",\"errno_counts\":{",
                    LOAD(&c->last_return));
            bool comma = false;
            for (unsigned e = 0; e < PROFILE_ERRORS; e++) {
                int error = LOAD(&c->error_nr[e]);
                if (!error)
                    continue;
                fprintf(stream, "%s\"%d\":%" PRIu64, comma ? "," : "", error,
                        LOAD(&c->error_count[e]));
                comma = true;
            }
            fprintf(stream, "},\"errno_overflow\":%" PRIu64 "}\n",
                    LOAD(&c->error_overflow));
        }
        for (unsigned i = 0; i < PROFILE_PCS; i++) {
            profile_pc_t *s = &p->pcs[i];
            uint64_t hits =
                atomic_load_explicit(&s->count, memory_order_acquire);
            if (hits)
                fprintf(stream,
                        "{\"v\":1,\"type\":\"pc\",\"seq\":%" PRIu64
                        ",\"task\":%u,\"pc\":%" PRIu64 ",\"lr\":%" PRIu64
                        ",\"rosetta\":%s,\"epoch\":%" PRIu64
                        ",\"count\":%" PRIu64 "}\n",
                        seq, n, s->pc, s->lr, s->rosetta ? "true" : "false",
                        s->epoch, hits);
        }
    }
    fprintf(stream,
            "{\"v\":1,\"type\":\"snapshot_end\",\"seq\":%" PRIu64
            ",\"epoch\":%" PRIu64 "}\n",
            seq, LOAD(&epoch));
    if (fflush(stream) != 0 || ferror(stream)) {
        fprintf(stderr,
                "elfuse: profile output failed: %s; profiling disabled\n",
                strerror(errno));
        STORE(&profile_active, false);
    }
}

static void *export_main(void *unused)
{
    pthread_mutex_lock(&writer_lock);
    while (!stopping) {
        struct timespec delay = {
            .tv_sec = (time_t) (interval_ms / 1000),
            .tv_nsec = (long) (interval_ms % 1000) * 1000000,
        };
        pthread_cond_timedwait_relative_np(&writer_cond, &writer_lock, &delay);
        if (stopping)
            break;
        pthread_mutex_unlock(&writer_lock);
        snapshot(false);
        pthread_mutex_lock(&writer_lock);
        if (!profile_enabled())
            break;
    }
    pthread_mutex_unlock(&writer_lock);
    return NULL;
}

static void finish(void)
{
    if (!stream)
        return;
    pthread_mutex_lock(&writer_lock);
    stopping = true;
    pthread_cond_signal(&writer_cond);
    pthread_mutex_unlock(&writer_lock);
    pthread_join(writer, NULL);
    if (profile_enabled())
        snapshot(true);
    STORE(&profile_active, false);
    fclose(stream);
    stream = NULL;
    /* Storage survives late runtime hooks during process teardown. */
}

static bool number(const char *key, uint64_t *out, uint64_t min, uint64_t max)
{
    const char *s = getenv(key);
    if (!s)
        return true;
    if (!*s)
        return false;
    uint64_t value = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || value > max / 10)
            return false;
        value = value * 10 + (unsigned) (*s - '0');
        if (value > max)
            return false;
    }
    if (value < min)
        return false;
    *out = value;
    return true;
}

static void initialize(void)
{
    const char *prefix = getenv("ELFUSE_PROFILE");
    if (!prefix)
        return;
    uint64_t pc_ms = 0;
    if (prefix[0] != '/' || strlen(prefix) > PATH_MAX - 40 ||
        !number("ELFUSE_PROFILE_INTERVAL_MS", &interval_ms, 100, 60000) ||
        !number("ELFUSE_PROFILE_PC_MS", &pc_ms, 0, 60000)) {
        fputs(
            "elfuse: invalid profile configuration (absolute prefix; interval "
            "100..60000 ms; PC 0..60000 ms); profiling disabled\n",
            stderr);
        return;
    }
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s.%d.jsonl", prefix, getpid());
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        fprintf(stderr, "elfuse: profile open %s: %s; profiling disabled\n",
                path, strerror(errno));
        return;
    }
    stream = fdopen(fd, "w");
    tasks = calloc(PROFILE_TASKS, sizeof(*tasks));
    if (!stream || !tasks) {
        fputs(
            "elfuse: profile storage initialization failed; profiling "
            "disabled\n",
            stderr);
        if (stream)
            fclose(stream);
        else
            close(fd);
        free(tasks);
        tasks = NULL;
        return;
    }
    pc_interval_ns = pc_ms * 1000000;
    atomic_store_explicit(&profile_active, true, memory_order_release);
    start_ns = profile_now_ns();
    fprintf(
        stream,
        "{\"v\":1,\"type\":\"metadata\",\"host_pid\":%d,\"host_ppid\":%d,"
        "\"clock\":\"CLOCK_MONOTONIC\",\"units\":\"ns\",\"host_arch\":"
        "\"aarch64\","
        "\"cpu_sample_owner\":\"CLOCK_THREAD_CPUTIME_ID\","
        "\"cpu_sample_remote\":\"thread_info\","
        "\"task_capacity\":%d,\"syscalls_per_task\":%d,\"pc_per_task\":%d,"
        "\"interval_ms\":%" PRIu64 ",\"pc_interval_ns\":%" PRIu64
        ",\"storage_bytes\":%zu,\"thread_fields\":[\"guest_cpu_ns\",\"service_"
        "cpu_ns\","
        "\"guest_wall_ns\",\"host_wall_ns\",\"mounts\",\"preempts\",\"wakes\"],"
        "\"syscall_fields\":[\"calls\",\"attempts\",\"completed\",\"parks\","
        "\"active_ns\",\"active_max_ns\",\"latency_ns\",\"latency_max_ns\","
        "\"errors\",\"zero_returns\",\"positive_returns\",\"io_bytes\"],"
        "\"wait_fields\":[\"ready\",\"unknown\",\"futex\",\"sleep\",\"io\","
        "\"mqueue\",\"stop\",\"wait\",\"vfork\",\"ipc\",\"service\",\"signal\"]"
        "}\n",
        getpid(), getppid(), PROFILE_TASKS, PROFILE_SYSCALLS, PROFILE_PCS,
        interval_ms, pc_interval_ns,
        PROFILE_TASKS * sizeof(*tasks) + sizeof(accounting));
    if (fflush(stream) != 0 || ferror(stream)) {
        fprintf(stderr,
                "elfuse: profile output failed: %s; profiling disabled\n",
                strerror(errno));
        STORE(&profile_active, false);
        fclose(stream);
        stream = NULL;
    }
}

static void start_writer(void)
{
    if (!stream || !profile_enabled())
        return;
    int rc = pthread_create(&writer, NULL, export_main, NULL);
    if (rc != 0) {
        fprintf(stderr,
                "elfuse: profile exporter initialization failed: %s; profiling "
                "disabled\n",
                strerror(rc));
        STORE(&profile_active, false);
        fclose(stream);
        stream = NULL;
        return;
    }
    atexit(finish);
}

void profile_start_writer(void)
{
    pthread_once(&init_once, initialize);
    pthread_once(&writer_once, start_writer);
}

void profile_init(void)
{
    pthread_once(&init_once, initialize);
}
