/*
 * System V IPC syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * shmget, shmat, shmdt, shmctl, semget, semop, semctl, msgget, msgsnd, msgrcv,
 * msgctl. Forwards to macOS SysV IPC with structure translation.
 *
 * shmat limitation: HVF guest memory cannot directly map host shm segments.
 * Data is copied between host shm and guest memory on attach/detach. True
 * cross-process shared semantics require a more complex synchronization scheme.
 */

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

#include "utils.h"

#include "syscall/sysvipc.h"
#include "syscall/linux-wire.h"
#include "syscall/internal.h"
#include "syscall/io.h" /* io_retry_backoff, used by the stream paths */
#include "syscall/mem.h"
#include "syscall/proc.h"
#include "syscall/signal.h"
#include "runtime/thread.h"
#include "runtime/sched/sched.h"
#include "runtime/sched/exec.h"

/* Linux SysV IPC constants. */

/* IPC commands (same on Linux and macOS) */
#define LINUX_IPC_RMID 0
#define LINUX_IPC_SET 1
#define LINUX_IPC_STAT 2
#define LINUX_IPC_INFO 3

/* shm-specific Linux commands */
#define LINUX_SHM_INFO 14
#define LINUX_SHM_STAT 13
#define LINUX_SHM_LOCK 11
#define LINUX_SHM_UNLOCK 12

/* shm attach flags (same on Linux and macOS) */
#define LINUX_SHM_RDONLY 010000

/* Linux semctl commands (differ from macOS!) */
#define LINUX_GETVAL 12
#define LINUX_SETVAL 16
#define LINUX_GETALL 13
#define LINUX_SETALL 17
#define LINUX_GETPID 11
#define LINUX_GETNCNT 14
#define LINUX_GETZCNT 15
#define LINUX_SEM_INFO 19
#define LINUX_SEM_STAT 18

/* Linux ipc64_perm (aarch64 LP64). */
typedef struct {
    int32_t key;        /*  0 */
    uint32_t uid;       /*  4 */
    uint32_t gid;       /*  8 */
    uint32_t cuid;      /* 12 */
    uint32_t cgid;      /* 16 */
    uint32_t mode;      /* 20 */
    uint16_t seq;       /* 24 */
    uint16_t __pad2;    /* 26 */
    uint32_t __pad3;    /* 28 */
    uint64_t __unused1; /* 32 */
    uint64_t __unused2; /* 40 */
} linux_ipc64_perm_t;   /* 48 bytes */

/* Linux shmid_ds (aarch64 LP64). */
typedef struct {
    linux_ipc64_perm_t shm_perm; /*  0: 48 */
    uint64_t shm_segsz;          /* 48 */
    int64_t shm_atime;           /* 56 */
    int64_t shm_dtime;           /* 64 */
    int64_t shm_ctime;           /* 72 */
    int32_t shm_cpid;            /* 80 */
    int32_t shm_lpid;            /* 84 */
    uint64_t shm_nattch;         /* 88 */
    uint64_t __unused4;          /* 96 */
    uint64_t __unused5;          /* 104 */
} linux_shmid_ds_t;              /* 112 bytes */

/* Linux semid_ds (aarch64 LP64). */
typedef struct {
    linux_ipc64_perm_t sem_perm; /*  0: 48 */
    int64_t sem_otime;           /* 48 */
    int64_t sem_ctime;           /* 56 */
    uint64_t sem_nsems;          /* 64 */
    uint64_t __unused3;          /* 72 */
    uint64_t __unused4;          /* 80 */
} linux_semid_ds_t;              /* 88 bytes */

/* Linux struct sembuf (same layout on macOS) */
typedef struct {
    uint16_t sem_num;
    int16_t sem_op, sem_flg;
} linux_sembuf_t;

/* Linux msqid_ds (aarch64 LP64). */
typedef struct {
    linux_ipc64_perm_t msg_perm; /*  0: 48 */
    int64_t msg_stime;           /* 48 */
    int64_t msg_rtime;           /* 56 */
    int64_t msg_ctime;           /* 64 */
    uint64_t msg_cbytes;         /* 72 */
    uint64_t msg_qnum;           /* 80 */
    uint64_t msg_qbytes;         /* 88 */
    int32_t msg_lspid;           /* 96 */
    int32_t msg_lrpid;           /* 100 */
    uint64_t __unused4;          /* 104 */
    uint64_t __unused5;          /* 112 */
} linux_msqid_ds_t;              /* 120 bytes */

/* Linux IPC_NOWAIT (same value on both platforms) */
#define LINUX_IPC_NOWAIT 04000

/* Linux MSG_NOERROR flag (same on both platforms) */
#define LINUX_MSG_NOERROR 010000

/* Linux MSG_EXCEPT / MSG_COPY (Linux-specific extensions) */
#define LINUX_MSG_EXCEPT 020000
#define LINUX_MSG_COPY 040000

/* SysV SHM tracking.
 *
 * macOS caps per-process host shmat count at kern.sysv.shmseg (often 8). Linux
 * guests routinely attach dozens of IPC_PRIVATE segments (e.g. futex waitv
 * shared needs 30). Mirror each shmid in a malloc shadow and only touch host
 * SysV via short attach/copy/detach windows so the guest never holds more than
 * one host attach at a time.
 */

#define MAX_SHM_SEGMENTS 128
#define MAX_SHM_ATTACH 256

typedef struct {
    bool active;
    int shmid;
    void *shadow; /* malloc'd mirror of segment bytes */
    uint64_t size;
    int guest_nattach;
    bool removed; /* IPC_RMID; free shadow when guest_nattach hits 0 */
} shm_segment_t;

typedef struct {
    bool active;
    shm_segment_t *seg;
    uint64_t guest_gva;
    uint64_t size;
    bool rdonly;
} shm_attach_t;

static shm_segment_t shm_segments[MAX_SHM_SEGMENTS];
static shm_attach_t shm_table[MAX_SHM_ATTACH];
static pthread_mutex_t shm_lock = PTHREAD_MUTEX_INITIALIZER;

#define SHM_FOR_EACH(e) \
    for (shm_attach_t *e = shm_table; e < shm_table + MAX_SHM_ATTACH; e++)

#define SHM_SEG_FOR_EACH(s)                                                    \
    for (shm_segment_t *s = shm_segments; s < shm_segments + MAX_SHM_SEGMENTS; \
         s++)

/* Helper: macOS ipc_perm -> Linux ipc64_perm. */

static void mac_to_linux_ipc_perm(const struct ipc_perm *mac,
                                  linux_ipc64_perm_t *lin)
{
    memset(lin, 0, sizeof(*lin));
    lin->key = mac->_key;
    lin->uid = mac->uid;
    lin->gid = mac->gid;
    lin->cuid = mac->cuid;
    lin->cgid = mac->cgid;
    lin->mode = mac->mode;
    lin->seq = mac->_seq;
}

/* Helper: Linux ipc64_perm -> macOS ipc_perm. */

static void linux_to_mac_ipc_perm(const linux_ipc64_perm_t *lin,
                                  struct ipc_perm *mac)
{
    memset(mac, 0, sizeof(*mac));
    mac->_key = lin->key;
    mac->uid = (uid_t) lin->uid;
    mac->gid = (gid_t) lin->gid;
    mac->cuid = (uid_t) lin->cuid;
    mac->cgid = (gid_t) lin->cgid;
    mac->mode = (unsigned short) lin->mode;
    mac->_seq = (unsigned short) lin->seq;
}

/* Helper: translate Linux semctl cmd -> macOS. */

static int translate_semctl_cmd(int linux_cmd)
{
    switch (linux_cmd) {
    case LINUX_IPC_RMID:
        return IPC_RMID;
    case LINUX_IPC_SET:
        return IPC_SET;
    case LINUX_IPC_STAT:
        return IPC_STAT;
    case LINUX_GETVAL:
        return GETVAL;
    case LINUX_SETVAL:
        return SETVAL;
    case LINUX_GETALL:
        return GETALL;
    case LINUX_SETALL:
        return SETALL;
    case LINUX_GETPID:
        return GETPID;
    case LINUX_GETNCNT:
        return GETNCNT;
    case LINUX_GETZCNT:
        return GETZCNT;
    default:
        return -1;
    }
}

/* Shared memory. */

static shm_segment_t *shm_seg_lookup_locked(int shmid)
{
    SHM_SEG_FOR_EACH(s)
    {
        if (s->active && s->shmid == shmid)
            return s;
    }
    return NULL;
}

static void shm_seg_free_shadow_locked(shm_segment_t *seg)
{
    if (!seg || !seg->shadow)
        return;
    free(seg->shadow);
    seg->shadow = NULL;
}

static void shm_seg_drop_locked(shm_segment_t *seg)
{
    if (!seg)
        return;
    if (seg->guest_nattach > 0)
        return;
    if (seg->removed) {
        shm_seg_free_shadow_locked(seg);
        seg->active = false;
    }
}

/* Pull host SysV bytes into seg->shadow. Holds at most one host attach. */
static int shm_seg_pull_host(shm_segment_t *seg)
{
    void *host = shmat(seg->shmid, NULL, 0);
    if (host == (void *) -1)
        return -1;
    memcpy(seg->shadow, host, (size_t) seg->size);
    shmdt(host);
    return 0;
}

/* Push seg->shadow out to host SysV. Holds at most one host attach. */
static int shm_seg_push_host(shm_segment_t *seg)
{
    void *host = shmat(seg->shmid, NULL, 0);
    if (host == (void *) -1)
        return -1;
    memcpy(host, seg->shadow, (size_t) seg->size);
    shmdt(host);
    return 0;
}

int64_t sys_shmget(guest_t *g, int32_t key, uint64_t size, int shmflg)
{
    (void) g;

    /* IPC_CREAT, IPC_EXCL, IPC_PRIVATE, and permission bits are the same
     * numeric values on Linux and macOS. Pass through directly.
     */
    int id = shmget((key_t) key, (size_t) size, shmflg);
    if (id < 0)
        return linux_errno();
    return id;
}

int64_t sys_shmat(guest_t *g, int shmid, uint64_t shmaddr_gva, int shmflg)
{
    struct shmid_ds info;
    if (shmctl(shmid, IPC_STAT, &info) < 0)
        return linux_errno();

    size_t seg_size = info.shm_segsz;
    if (seg_size == 0)
        return -LINUX_EINVAL;

    bool rdonly = (shmflg & LINUX_SHM_RDONLY) != 0;
    (void) shmaddr_gva;

    pthread_mutex_lock(&shm_lock);
    shm_segment_t *seg = shm_seg_lookup_locked(shmid);
    if (!seg) {
        SHM_SEG_FOR_EACH(s)
        {
            if (!s->active) {
                seg = s;
                break;
            }
        }
        if (!seg) {
            pthread_mutex_unlock(&shm_lock);
            return -LINUX_ENOMEM;
        }
        void *shadow = malloc(seg_size);
        if (!shadow) {
            pthread_mutex_unlock(&shm_lock);
            return -LINUX_ENOMEM;
        }
        memset(shadow, 0, seg_size);
        seg->active = true;
        seg->shmid = shmid;
        seg->shadow = shadow;
        seg->size = seg_size;
        seg->guest_nattach = 0;
        seg->removed = false;

        /* Seed shadow from host (may already hold data from another process).
         */
        if (shm_seg_pull_host(seg) < 0) {
            int64_t err = linux_errno();
            shm_seg_free_shadow_locked(seg);
            seg->active = false;
            pthread_mutex_unlock(&shm_lock);
            return err;
        }
    } else if (seg->size != seg_size) {
        /* Host resized under us (unusual); reject. */
        pthread_mutex_unlock(&shm_lock);
        return -LINUX_EINVAL;
    }

    /* Snapshot for the guest copy while still holding the lock so a concurrent
     * shmdt writeback cannot tear the shadow mid-copy.
     */
    void *copy = malloc(seg_size);
    if (!copy) {
        pthread_mutex_unlock(&shm_lock);
        return -LINUX_ENOMEM;
    }
    memcpy(copy, seg->shadow, seg_size);
    pthread_mutex_unlock(&shm_lock);

    int64_t gva =
        sys_mmap_anon(g, 0, seg_size, LINUX_PROT_READ | LINUX_PROT_WRITE);
    if (gva < 0) {
        free(copy);
        return gva;
    }

    if (guest_write(g, (uint64_t) gva, copy, seg_size) < 0) {
        free(copy);
        return -LINUX_EFAULT;
    }
    free(copy);

    if (rdonly)
        sys_mprotect(g, (uint64_t) gva, PAGE_ALIGN_UP(seg_size),
                     LINUX_PROT_READ);

    pthread_mutex_lock(&shm_lock);

    /* seg pointer remains valid: segments are only cleared when nattach==0 and
     * removed, and we have not yet published an attach.
     */
    if (!seg->active) {
        pthread_mutex_unlock(&shm_lock);
        return -LINUX_EIDRM;
    }
    shm_attach_t *entry = NULL;
    SHM_FOR_EACH (e) {
        if (!e->active) {
            entry = e;
            break;
        }
    }
    if (!entry) {
        pthread_mutex_unlock(&shm_lock);
        return -LINUX_ENOMEM;
    }
    entry->active = true;
    entry->seg = seg;
    entry->guest_gva = (uint64_t) gva;
    entry->size = seg_size;
    entry->rdonly = rdonly;
    seg->guest_nattach++;
    pthread_mutex_unlock(&shm_lock);

    return gva;
}

int64_t sys_shmdt(guest_t *g, uint64_t shmaddr_gva)
{
    pthread_mutex_lock(&shm_lock);
    shm_attach_t *match = NULL;
    SHM_FOR_EACH (e) {
        if (e->active && e->guest_gva == shmaddr_gva) {
            match = e;
            break;
        }
    }
    if (!match) {
        pthread_mutex_unlock(&shm_lock);
        return -LINUX_EINVAL;
    }

    shm_attach_t entry = *match;
    shm_segment_t *seg = entry.seg;
    match->active = false;
    match->seg = NULL;

    if (!entry.rdonly && seg && seg->shadow) {
        /* Pull guest bytes into the shadow, then publish to host SysV so a
         * forked peer that shmget/shmat'd the same id sees the update.
         */
        guest_read(g, entry.guest_gva, seg->shadow, entry.size);
        (void) shm_seg_push_host(seg);
    }

    if (seg) {
        if (seg->guest_nattach > 0)
            seg->guest_nattach--;
        shm_seg_drop_locked(seg);
    }
    pthread_mutex_unlock(&shm_lock);
    return 0;
}

int64_t sys_shmctl(guest_t *g, int shmid, int cmd, uint64_t buf_gva)
{
    switch (cmd) {
    case LINUX_IPC_STAT: {
        struct shmid_ds mac_ds;
        if (shmctl(shmid, IPC_STAT, &mac_ds) < 0)
            return linux_errno();

        linux_shmid_ds_t lin_ds;
        memset(&lin_ds, 0, sizeof(lin_ds));
        mac_to_linux_ipc_perm(&mac_ds.shm_perm, &lin_ds.shm_perm);
        lin_ds.shm_segsz = mac_ds.shm_segsz;
        lin_ds.shm_atime = mac_ds.shm_atime;
        lin_ds.shm_dtime = mac_ds.shm_dtime;
        lin_ds.shm_ctime = mac_ds.shm_ctime;
        lin_ds.shm_cpid = mac_ds.shm_cpid;
        lin_ds.shm_lpid = mac_ds.shm_lpid;
        lin_ds.shm_nattch = mac_ds.shm_nattch;

        if (guest_write_small(g, buf_gva, &lin_ds, sizeof(lin_ds)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    case LINUX_IPC_SET: {
        linux_shmid_ds_t lin_ds;
        if (guest_read_small(g, buf_gva, &lin_ds, sizeof(lin_ds)) < 0)
            return -LINUX_EFAULT;

        struct shmid_ds mac_ds;
        memset(&mac_ds, 0, sizeof(mac_ds));

        /* Only uid, gid, mode are writable via IPC_SET */
        linux_to_mac_ipc_perm(&lin_ds.shm_perm, &mac_ds.shm_perm);

        if (shmctl(shmid, IPC_SET, &mac_ds) < 0)
            return linux_errno();
        return 0;
    }

    case LINUX_IPC_RMID: {
        if (shmctl(shmid, IPC_RMID, NULL) < 0)
            return linux_errno();

        /* Host segment is destroyed when the last local attach drops. Mark our
         * tracker so shm_seg_drop_locked frees the shadow.
         */
        pthread_mutex_lock(&shm_lock);
        shm_segment_t *seg = shm_seg_lookup_locked(shmid);
        if (seg) {
            seg->removed = true;
            shm_seg_drop_locked(seg);
        }
        pthread_mutex_unlock(&shm_lock);
        return 0;
    }

    case LINUX_IPC_INFO:
    case LINUX_SHM_INFO:
    case LINUX_SHM_STAT:
        /* IPC_INFO/SHM_INFO/SHM_STAT are Linux-specific and have no direct
         * macOS equivalent.
         *
         * Return EINVAL rather than ENOSYS to match what a
         * restricted-permission kernel would do.
         */
        return -LINUX_EINVAL;

    case LINUX_SHM_LOCK:
    case LINUX_SHM_UNLOCK:
        /* SHM_LOCK/UNLOCK: no-op, memory is always resident in HVF */
        return 0;

    default:
        return -LINUX_EINVAL;
    }
}

/* Semaphores. */

int64_t sys_semget(guest_t *g, int32_t key, int nsems, int semflg)
{
    (void) g;
    int id = semget((key_t) key, nsems, semflg);
    if (id < 0)
        return linux_errno();
    return id;
}

/* Entries a host GETALL can write or a host SETALL can read. The kernel walks
 * the set's own sem_nsems, an unsigned short in the macOS semid_ds, and not any
 * count the caller learned earlier: an IPC_STAT answer goes stale the moment
 * another process removes the set and a larger one takes its id. So every
 * buffer handed to the host is this size, and the IPC_STAT count only bounds
 * what crosses to or from the guest.
 */
#define SEM_HOST_MAX_NSEMS ((size_t) USHRT_MAX)

static unsigned short *sem_host_vals_alloc(void)
{
    return calloc(SEM_HOST_MAX_NSEMS, sizeof(unsigned short));
}

/* Semaphores in the set per IPC_STAT, or a negative Linux errno. */
static int sem_stat_nsems(int semid)
{
    struct semid_ds info;
    if (semctl(semid, 0, IPC_STAT, &info) < 0)
        return (int) linux_errno();
    if (info.sem_nsems == 0)
        return -LINUX_EINVAL;
    return (int) info.sem_nsems;
}

/* Outcomes of the walk below that are not an operation index. */
#define SEMOP_BLOCKER_NONE (-1)    /* Every operation could proceed */
#define SEMOP_BLOCKER_UNKNOWN (-2) /* The values could not be read */

/* Index of the operation that cannot proceed against the current values.
 *
 * This repeats the walk the kernel makes before it decides to block: a positive
 * operation always proceeds, a zero operation needs the value already at zero,
 * and a negative one needs enough units to take. Linux answers EAGAIN when the
 * operation it stopped on carries IPC_NOWAIT, and blocks otherwise, so which
 * one stopped it is the whole question.
 *
 * Returns SEMOP_BLOCKER_NONE when nothing blocked, and SEMOP_BLOCKER_UNKNOWN
 * when the values could not be read, which a set granting alter but not read
 * permission does while its operations still apply.
 *
 * The caller keeps waiting on either, rather than answering EAGAIN from a
 * result it cannot back up. That trade has a cost worth naming: a mixed set on
 * a set it may alter but not read never gets the refusal Linux would have given
 * it, and waits instead. Answering EAGAIN there would be inventing a refusal in
 * every other case the probe cannot read, which is the more common one.
 *
 * nsems is resolved once per semop by the caller, since a set cannot be
 * resized. The values are re-read on every pass, because those are what move.
 * vals is the caller's SEM_HOST_MAX_NSEMS scratch buffer, so a set replaced
 * under the same id cannot make the host write past it.
 *
 * They can move between this read and the failed semop it explains, so the
 * operation named here can differ from the one the host actually stopped on.
 * Usually that costs a retry: applying the set is still one atomic host call,
 * and the next pass re-reads. The case it gets wrong is a set whose true
 * blocker carries IPC_NOWAIT while a concurrent change makes a blocking
 * operation look like the blocker, where the caller waits and Linux would have
 * answered EAGAIN. It resolves as soon as one pass reads a consistent set.
 */
static int semop_first_blocker(int semid,
                               const struct sembuf *sops,
                               unsigned nsops,
                               int nsems,
                               unsigned short *vals)
{
    if (nsems <= 0 || semctl(semid, 0, GETALL, vals) < 0)
        return SEMOP_BLOCKER_UNKNOWN;

    /* Running value after each operation, so a later operation on the same
     * semaphore sees what the earlier ones left. Kept per operation rather than
     * per semaphore because nsops is at most 256 while a set can hold
     * SEM_HOST_MAX_NSEMS. Widened because a positive operation may carry the
     * running value past what a semaphore can hold, and the walk only needs the
     * comparisons to stay honest until it reaches the operation that stops it.
     */
    int after[256];
    for (unsigned i = 0; i < nsops; i++) {
        int num = sops[i].sem_num;
        if (num >= nsems) {
            /* Out of range: the host semop owns that error */
            return SEMOP_BLOCKER_UNKNOWN;
        }

        int cur = (int) vals[num];
        for (unsigned j = i; j-- > 0;) {
            if (sops[j].sem_num == sops[i].sem_num) {
                cur = after[j];
                break;
            }
        }

        int op = sops[i].sem_op;
        if (op == 0 && cur != 0)
            return (int) i;
        if (op < 0 && cur < -op)
            return (int) i;
        after[i] = cur + op;
    }

    return SEMOP_BLOCKER_NONE;
}

/* Blocking IPC probes
 *
 * A SysV operation is probed with IPC_NOWAIT because a blocking host call
 * cannot be reached by a guest signal or by teardown. When the probe refuses,
 * the task parks as PARK_KIND_IPC: a mutation in this process reissues every
 * parked probe, and a periodic deadline catches a mutation made by a forked
 * sibling process, which shares the host IPC object but not this registry. The
 * callbacks publish a result only; guest memory is written by the re-dispatched
 * handler on its own vCPU.
 */
#define SYSV_RECHECK_NS (10ULL * 1000 * 1000)

static _Atomic unsigned sysvipc_waiters;

static uint64_t sysvipc_mono_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static void sysvipc_wait_done(void)
{
    if (atomic_load_explicit(&sysvipc_waiters, memory_order_relaxed) > 0)
        atomic_fetch_sub_explicit(&sysvipc_waiters, 1, memory_order_relaxed);
}

static void sysvipc_wake_one(thread_entry_t *t, void *ctx)
{
    (void) ctx;
    if (!t || !exec_park_active_load(t) ||
        exec_park_kind_load(t) != PARK_KIND_IPC)
        return;
    uint64_t seq = sched_park_seq(t);
    if (seq == 0)
        return;
    if (sched_park_try_complete_reissue_seq(t, PARK_KIND_IPC, seq))
        sysvipc_wait_done();
}

/* Local mutation: every parked probe re-checks its set or queue. */
static void sysvipc_wake_waiters(void)
{
    if (atomic_load_explicit(&sysvipc_waiters, memory_order_relaxed) == 0)
        return;
    thread_for_each(sysvipc_wake_one, NULL);
}

static int64_t sysvipc_park(thread_entry_t *self)
{
    if (!self)
        return -LINUX_EAGAIN;
    exec_park_kind_store(self, PARK_KIND_IPC);
    exec_park_result_pending_store(self, false);
    exec_park_reissue_store(self, false);
    self->sysv_waited = true;
    atomic_fetch_add_explicit(&sysvipc_waiters, 1, memory_order_relaxed);
    exec_park_deadline_ns_store(self, 0);
    (void) sched_park_seq_next(self);
    exec_park_active_store(self, true);
    sched_arm_wait_deadline(self, sysvipc_mono_ns() + SYSV_RECHECK_NS);
    return SYSCALL_PARKED;
}

/* Consume the "this SVC already parked" witness at entry, so a re-dispatched
 * probe maps EINVAL to EIDRM and a fresh call starts clean.
 */
static bool sysvipc_take_waited(void)
{
    if (!current_thread)
        return false;
    bool waited = current_thread->sysv_waited;
    current_thread->sysv_waited = false;
    return waited;
}

void sysvipc_park_on_deadline(thread_entry_t *t)
{
    if (!t || !exec_park_active_load(t) ||
        exec_park_kind_load(t) != PARK_KIND_IPC)
        return;
    uint64_t seq = sched_park_seq(t);
    if (seq == 0)
        return;
    signal_check_timer_real_quiet();
    uint64_t deadline = exec_park_deadline_ns_load(t);
    if (deadline == 0 || deadline > sched_now_ns())
        return;
    bool teardown = thread_stop_requested_for(t);
    if (teardown || signal_claim_interruption_for_ex(t, false)) {
        if (sched_park_try_complete_seq(t, PARK_KIND_IPC, seq, -LINUX_EINTR))
            sysvipc_wait_done();
        return;
    }
    if (sched_park_try_complete_reissue_seq(t, PARK_KIND_IPC, seq))
        sysvipc_wait_done();
}

void sysvipc_park_on_interrupt(thread_entry_t *t)
{
    if (!t || !exec_park_active_load(t) ||
        exec_park_kind_load(t) != PARK_KIND_IPC)
        return;
    uint64_t seq = sched_park_seq(t);
    if (seq == 0)
        return;
    bool teardown = thread_stop_requested_for(t);
    if (!teardown && !signal_claim_interruption_for(t))
        return;
    if (sched_park_try_complete_seq(t, PARK_KIND_IPC, seq, -LINUX_EINTR))
        sysvipc_wait_done();
}

/* Task death drops a parked IPC probe: no wake or recheck deadline runs for a
 * DEAD task, so its waiter count must not stay in the scan gate.
 */
void sysvipc_task_cancel_wait(thread_entry_t *t)
{
    if (!t || !exec_park_active_load(t) ||
        exec_park_kind_load(t) != PARK_KIND_IPC)
        return;
    uint64_t seq = sched_park_seq(t);
    if (seq == 0)
        return;
    if (sched_park_try_complete_seq(t, PARK_KIND_IPC, seq, -LINUX_EINTR))
        sysvipc_wait_done();
}

/* Linux errno for a failed IPC_NOWAIT probe, from the host errno.
 *
 * An object this call has already waited on was valid then, so a stale id now
 * means IPC_RMID removed it under the wait, which Linux reports as EIDRM. The
 * host poll cannot tell, since it never sleeps inside the kernel where that
 * error is raised. Callers pass the parked witness, which is the same as having
 * waited at least once.
 */
static int64_t sysv_poll_errno(bool waited)
{
    return (waited && errno == EINVAL) ? -LINUX_EIDRM : linux_errno();
}

int64_t sys_semop(guest_t *g, int semid, uint64_t sops_gva, unsigned nsops)
{
    bool waited = sysvipc_take_waited();
    if (nsops == 0 || nsops > 256)
        return -LINUX_EINVAL;

    /* Linux and macOS struct sembuf are layout-compatible */
    struct sembuf sops[256];
    size_t len = nsops * sizeof(struct sembuf);

    if (guest_read(g, sops_gva, sops, len) < 0)
        return -LINUX_EFAULT;

    /* Every set polls, mixed or not. A blocking semop parks the vCPU thread in
     * a host call no teardown wake reaches, so nothing here may enter one, and
     * a set that mixes IPC_NOWAIT with blocking operations would otherwise have
     * to. The copy carries the flag on every operation so the host still
     * applies the set atomically or not at all; sops keeps the guest's own
     * flags, which is what decides whether a refusal is owed to the caller now.
     */
    struct sembuf poll_sops[256];
    bool any_nowait = false;
    for (unsigned i = 0; i < nsops; i++) {
        poll_sops[i] = sops[i];
        poll_sops[i].sem_flg |= IPC_NOWAIT;
        if (sops[i].sem_flg & IPC_NOWAIT)
            any_nowait = true;
    }

    /* Resolved on the first probe, which only a set carrying IPC_NOWAIT ever
     * makes, so an all-blocking set pays nothing for it.
     */
    int nsems = 0;
    unsigned short *vals = NULL;

    int64_t rc;
    for (;;) {
        if (semop(semid, poll_sops, nsops) == 0) {
            sysvipc_wake_waiters();
            rc = 0;
            break;
        }
        if (errno != EAGAIN) {
            rc = sysv_poll_errno(waited);
            break;
        }

        /* The set did not apply. Linux owes EAGAIN only when the operation that
         * stopped it is itself IPC_NOWAIT; when a blocking one stopped it the
         * caller waits, whatever flags the rest of the set carries.
         */
        if (any_nowait) {
            /* Read once per semop, not per pass: a set cannot be resized. A
             * negative errno sticks too, and the walk answers it as unknown.
             */
            if (nsems == 0)
                nsems = sem_stat_nsems(semid);

            /* No count, no walk: the blocker probe answers unknown without
             * touching the buffer, so do not allocate one for it.
             */
            if (nsems > 0 && !vals) {
                vals = sem_host_vals_alloc();
                if (!vals) {
                    /* Waiting on would turn an owed EAGAIN into a hang */
                    rc = -LINUX_ENOMEM;
                    break;
                }
            }
            int blocker = semop_first_blocker(semid, sops, nsops, nsems, vals);
            if (blocker >= 0 && (sops[blocker].sem_flg & IPC_NOWAIT)) {
                rc = -LINUX_EAGAIN;
                break;
            }
        }

        /* A blocking operation stopped the set. Park: a local change reissues
         * this probe, and the periodic recheck covers a forked sibling.
         */
        free(vals);
        syscall_restart_forbid();
        return sysvipc_park(current_thread);
    }
    free(vals);
    return rc;
}

int64_t sys_semctl(guest_t *g, int semid, int semnum, int cmd, uint64_t arg)
{
    switch (cmd) {
    case LINUX_IPC_RMID:
        if (semctl(semid, 0, IPC_RMID) < 0)
            return linux_errno();
        sysvipc_wake_waiters();
        return 0;

    case LINUX_GETVAL: {
        int val = semctl(semid, semnum, GETVAL);
        if (val < 0)
            return linux_errno();
        return val;
    }

    case LINUX_SETVAL: {
        /* arg is the value directly (union semun.val) */
        int val = (int) arg;
        if (semctl(semid, semnum, SETVAL, val) < 0)
            return linux_errno();
        sysvipc_wake_waiters();
        return 0;
    }

    case LINUX_GETALL: {
        /* arg is guest pointer to unsigned short array */
        int nsems = sem_stat_nsems(semid);
        if (nsems < 0)
            return nsems;

        size_t vals_len = (size_t) nsems * sizeof(unsigned short);
        unsigned short *vals = sem_host_vals_alloc();
        if (!vals)
            return -LINUX_ENOMEM;
        if (semctl(semid, 0, GETALL, vals) < 0) {
            int err = linux_errno();
            free(vals);
            return err;
        }

        if (guest_write(g, arg, vals, vals_len) < 0) {
            free(vals);
            return -LINUX_EFAULT;
        }
        free(vals);
        return 0;
    }

    case LINUX_SETALL: {
        int nsems = sem_stat_nsems(semid);
        if (nsems < 0)
            return nsems;

        size_t vals_len = (size_t) nsems * sizeof(unsigned short);
        unsigned short *vals = sem_host_vals_alloc();
        if (!vals)
            return -LINUX_ENOMEM;
        if (guest_read(g, arg, vals, vals_len) < 0) {
            free(vals);
            return -LINUX_EFAULT;
        }

        if (semctl(semid, 0, SETALL, vals) < 0)
            return free(vals), linux_errno();
        free(vals);
        sysvipc_wake_waiters();
        return 0;
    }

    case LINUX_IPC_STAT: {
        struct semid_ds mac_ds;
        if (semctl(semid, 0, IPC_STAT, &mac_ds) < 0)
            return linux_errno();

        linux_semid_ds_t lin_ds;
        memset(&lin_ds, 0, sizeof(lin_ds));
        mac_to_linux_ipc_perm(&mac_ds.sem_perm, &lin_ds.sem_perm);
        lin_ds.sem_otime = mac_ds.sem_otime;
        lin_ds.sem_ctime = mac_ds.sem_ctime;
        lin_ds.sem_nsems = mac_ds.sem_nsems;

        if (guest_write_small(g, arg, &lin_ds, sizeof(lin_ds)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    case LINUX_IPC_SET: {
        linux_semid_ds_t lin_ds;
        if (guest_read_small(g, arg, &lin_ds, sizeof(lin_ds)) < 0)
            return -LINUX_EFAULT;

        struct semid_ds mac_ds;
        memset(&mac_ds, 0, sizeof(mac_ds));
        linux_to_mac_ipc_perm(&lin_ds.sem_perm, &mac_ds.sem_perm);

        if (semctl(semid, 0, IPC_SET, &mac_ds) < 0)
            return linux_errno();
        sysvipc_wake_waiters();
        return 0;
    }

    case LINUX_GETPID:
    case LINUX_GETNCNT:
    case LINUX_GETZCNT: {
        int mac_cmd = translate_semctl_cmd(cmd);
        int val = semctl(semid, semnum, mac_cmd);
        if (val < 0)
            return linux_errno();
        return val;
    }

    case LINUX_IPC_INFO:
    case LINUX_SEM_INFO:
    case LINUX_SEM_STAT:
        return -LINUX_EINVAL;

    default:
        return -LINUX_EINVAL;
    }
}

/* Message queues. */

int64_t sys_msgget(guest_t *g, int32_t key, int msgflg)
{
    (void) g;
    int id = msgget((key_t) key, msgflg);
    if (id < 0)
        return linux_errno();
    return id;
}

/* Max message size for stack allocation; larger messages use malloc. */
#define MSG_STACK_THRESHOLD 4096

/* Ceiling on a guest-supplied msgsz, checked before the sizeof(long) + msgsz
 * total is formed so the addition cannot wrap. elfuse's own limit rather than a
 * Linux constant: Linux caps msgsz at the per-queue MSGMAX (8192 by default,
 * tunable through /proc/sys/kernel/msgmax, which elfuse does not emulate).
 */
#define MSG_SIZE_MAX 65536

int64_t sys_msgsnd(guest_t *g,
                   int msqid,
                   uint64_t msgp_gva,
                   uint64_t msgsz,
                   int msgflg)
{
    bool waited = sysvipc_take_waited();

    /* Linux msgsnd msgp layout: long mtype followed by msgsz bytes of message
     * text. Total read from guest = sizeof(long) + msgsz.
     */
    if (msgsz > MSG_SIZE_MAX)
        return -LINUX_EINVAL;

    size_t total = sizeof(long) + (size_t) msgsz;
    char stack_buf[MSG_STACK_THRESHOLD + sizeof(long)];
    char *heap = NULL;
    char *buf = stack_buf;
    if (total > sizeof(stack_buf)) {
        heap = malloc(total);
        if (!heap)
            return -LINUX_ENOMEM;
        buf = heap;
    }

    int64_t result;
    if (guest_read(g, msgp_gva, buf, total) < 0) {
        result = -LINUX_EFAULT;
        goto out;
    }

    /* The mtype field is a 64-bit long on aarch64-linux. macOS also uses long
     * (64-bit on arm64). Direct passthrough. Probed with IPC_NOWAIT for the
     * reason sys_semop gives: a refused probe queues nothing, so the retry is
     * the whole of the wait and parking repeats it.
     */
    for (;;) {
        if (msgsnd(msqid, buf, (size_t) msgsz, IPC_NOWAIT) == 0) {
            sysvipc_wake_waiters();
            result = 0;
            break;
        }
        if (errno != EAGAIN || (msgflg & LINUX_IPC_NOWAIT)) {
            result = sysv_poll_errno(waited);
            break;
        }
        free(heap);
        syscall_restart_forbid();
        return sysvipc_park(current_thread);
    }
out:
    free(heap);
    return result;
}

int64_t sys_msgrcv(guest_t *g,
                   int msqid,
                   uint64_t msgp_gva,
                   uint64_t msgsz,
                   int64_t msgtyp,
                   int msgflg)
{
    bool waited = sysvipc_take_waited();

    if (msgsz > MSG_SIZE_MAX)
        return -LINUX_EINVAL;

    /* MSG_EXCEPT and MSG_COPY are Linux-specific queue selection modes. macOS
     * cannot emulate either with a native msgrcv call.
     */
    if (msgflg & (LINUX_MSG_COPY | LINUX_MSG_EXCEPT))
        return -LINUX_ENOSYS;

    /* Every receive is an IPC_NOWAIT probe; the guest's own flag only decides
     * whether an empty queue is answered with ENOMSG or waited on below.
     */
    int flags = IPC_NOWAIT;
    if (msgflg & LINUX_MSG_NOERROR)
        flags |= MSG_NOERROR;

    size_t total = sizeof(long) + (size_t) msgsz;
    char stack_buf[MSG_STACK_THRESHOLD + sizeof(long)];
    char *heap = NULL;
    char *buf = stack_buf;
    if (total > sizeof(stack_buf)) {
        heap = malloc(total);
        if (!heap)
            return -LINUX_ENOMEM;
        buf = heap;
    }

    /* A failed probe dequeues nothing. */
    int64_t result;
    ssize_t ret;
    for (;;) {
        ret = msgrcv(msqid, buf, (size_t) msgsz, (long) msgtyp, flags);
        if (ret >= 0)
            break;
        if (errno != ENOMSG || (msgflg & LINUX_IPC_NOWAIT)) {
            result = sysv_poll_errno(waited);
            goto out;
        }
        free(heap);
        syscall_restart_forbid();
        return sysvipc_park(current_thread);
    }

    sysvipc_wake_waiters();

    /* Write back mtype + received bytes to guest */
    size_t write_len = sizeof(long) + (size_t) ret;
    if (guest_write(g, msgp_gva, buf, write_len) < 0)
        result = -LINUX_EFAULT;
    else
        result = ret;

out:
    free(heap);
    return result;
}

int64_t sys_msgctl(guest_t *g, int msqid, int cmd, uint64_t buf_gva)
{
    switch (cmd) {
    case LINUX_IPC_STAT: {
        struct msqid_ds mac_ds;
        if (msgctl(msqid, IPC_STAT, &mac_ds) < 0)
            return linux_errno();

        linux_msqid_ds_t lin_ds;
        memset(&lin_ds, 0, sizeof(lin_ds));
        mac_to_linux_ipc_perm(&mac_ds.msg_perm, &lin_ds.msg_perm);
        lin_ds.msg_stime = mac_ds.msg_stime;
        lin_ds.msg_rtime = mac_ds.msg_rtime;
        lin_ds.msg_ctime = mac_ds.msg_ctime;
        lin_ds.msg_cbytes = mac_ds.msg_cbytes;
        lin_ds.msg_qnum = mac_ds.msg_qnum;
        lin_ds.msg_qbytes = mac_ds.msg_qbytes;
        lin_ds.msg_lspid = mac_ds.msg_lspid;
        lin_ds.msg_lrpid = mac_ds.msg_lrpid;

        if (guest_write_small(g, buf_gva, &lin_ds, sizeof(lin_ds)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    case LINUX_IPC_SET: {
        linux_msqid_ds_t lin_ds;
        if (guest_read_small(g, buf_gva, &lin_ds, sizeof(lin_ds)) < 0)
            return -LINUX_EFAULT;

        struct msqid_ds mac_ds;
        memset(&mac_ds, 0, sizeof(mac_ds));
        linux_to_mac_ipc_perm(&lin_ds.msg_perm, &mac_ds.msg_perm);
        mac_ds.msg_qbytes = (msglen_t) lin_ds.msg_qbytes;

        if (msgctl(msqid, IPC_SET, &mac_ds) < 0)
            return linux_errno();
        sysvipc_wake_waiters();
        return 0;
    }

    case LINUX_IPC_RMID:
        if (msgctl(msqid, IPC_RMID, NULL) < 0)
            return linux_errno();
        sysvipc_wake_waiters();
        return 0;

    case LINUX_IPC_INFO:
    default:
        return -LINUX_EINVAL;
    }
}

void sysvipc_reset(void)
{
    pthread_mutex_lock(&shm_lock);
    SHM_FOR_EACH (e) {
        e->active = false;
        e->seg = NULL;
    }
    SHM_SEG_FOR_EACH(s)
    {
        if (!s->active)
            continue;
        int shmid = s->shmid;
        shm_seg_free_shadow_locked(s);
        s->guest_nattach = 0;
        s->removed = true;
        s->active = false;

        /* Best-effort: reclaim host IPC_PRIVATE leftovers so macOS shmmni
         * (often 32) does not exhaust across elfuse invocations.
         */
        (void) shmctl(shmid, IPC_RMID, NULL);
    }
    pthread_mutex_unlock(&shm_lock);
}
