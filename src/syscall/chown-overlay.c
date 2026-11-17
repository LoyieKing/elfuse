/*
 * Virtual chown overlay (fakeroot-style)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "linux-limits.h"

#include "runtime/fork-state.h"
#include "syscall/chown-overlay.h"
#include "syscall/proc.h"
#include "utils.h" /* create_private_dir */

/* Open-chained hash table on (dev, ino). The stat fast path has to stay cheap,
 * so an atomic entry counter lets chown_overlay_apply skip the lock entirely
 * when nothing has been recorded yet (the common case before any guest chown).
 * Once the table is non-empty, readers (apply, send) take the lock in shared
 * mode and writers (set, clear, recv) take it exclusively, so stat-heavy
 * workloads scale across vCPU threads instead of serializing on a global mutex.
 */
#define CHOWN_OVERLAY_BUCKETS 512u

/* Wire-format guardrail. 24 bytes per record (dev, ino, uid, gid), so the cap
 * bounds the recv-side allocation regardless of what the IPC stream claims. 1M
 * entries is far above any plausible package-installer workload (dpkg etc.) but
 * small enough that a corrupted count cannot allocate gigabytes.
 */
#define CHOWN_OVERLAY_MAX_ENTRIES (1u << 20)

typedef struct overlay_entry {
    struct overlay_entry *next;
    uint64_t dev;
    uint64_t ino;
    uint32_t uid;
    uint32_t gid;
} overlay_entry_t;

static overlay_entry_t *buckets[CHOWN_OVERLAY_BUCKETS];
static pthread_rwlock_t overlay_lock = PTHREAD_RWLOCK_INITIALIZER;
static _Atomic size_t entry_count = 0;

/* fnv-1a-style mix; (dev, ino) is unique per host file but ino values cluster
 * low so spread before masking.
 */
static unsigned int bucket_index(uint64_t dev, uint64_t ino)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    h = (h ^ dev) * 0x100000001b3ULL;
    h = (h ^ ino) * 0x100000001b3ULL;
    return (unsigned int) ((h ^ (h >> 32)) & (CHOWN_OVERLAY_BUCKETS - 1));
}

static overlay_entry_t *find_locked(uint64_t dev, uint64_t ino)
{
    unsigned int idx = bucket_index(dev, ino);
    for (overlay_entry_t *e = buckets[idx]; e; e = e->next) {
        if (e->dev == dev && e->ino == ino)
            return e;
    }
    return NULL;
}

static void remove_locked(uint64_t dev, uint64_t ino)
{
    unsigned int idx = bucket_index(dev, ino);
    overlay_entry_t **prev = &buckets[idx];
    for (overlay_entry_t *e = *prev; e; prev = &e->next, e = e->next) {
        if (e->dev == dev && e->ino == ino) {
            *prev = e->next;
            free(e);
            atomic_fetch_sub_explicit(&entry_count, 1, memory_order_release);
            break;
        }
    }
}

static void clear_all_locked(void)
{
    for (unsigned int i = 0; i < CHOWN_OVERLAY_BUCKETS; i++) {
        overlay_entry_t *e = buckets[i];
        while (e) {
            overlay_entry_t *next = e->next;
            free(e);
            e = next;
        }
        buckets[i] = NULL;
    }
    atomic_store_explicit(&entry_count, 0, memory_order_release);
}

int chown_overlay_set(uint64_t dev,
                      uint64_t ino,
                      uint32_t new_owner,
                      uint32_t new_group,
                      uint32_t cur_uid,
                      uint32_t cur_gid)
{
    int rc = 0;

    pthread_rwlock_wrlock(&overlay_lock);

    overlay_entry_t *e = find_locked(dev, ino);
    if (!e) {
        uint32_t next_uid = new_owner == (uint32_t) -1 ? cur_uid : new_owner;
        uint32_t next_gid = new_group == (uint32_t) -1 ? cur_gid : new_group;
        if (next_uid == cur_uid && next_gid == cur_gid)
            goto out;

        e = calloc(1, sizeof(*e));
        if (!e) {
            rc = -1;
            goto out;
        }
        e->dev = dev;
        e->ino = ino;

        /* Initialise with the sentinel (uint32_t)-1, meaning "no override
         * recorded for this field yet". The apply path skips sentinel fields,
         * so a partial chown that only touches one of uid/gid does not corrupt
         * the other field with a stale physical host value.
         */
        e->uid = (uint32_t) -1;
        e->gid = (uint32_t) -1;
        unsigned int idx = bucket_index(dev, ino);
        e->next = buckets[idx];
        buckets[idx] = e;
        atomic_fetch_add_explicit(&entry_count, 1, memory_order_release);
    }

    /* Linux chown semantic: -1 means "do not change this field". */
    if (new_owner != (uint32_t) -1)
        e->uid = new_owner;
    if (new_group != (uint32_t) -1)
        e->gid = new_group;

    /* A sentinel field means "keep whatever cur reports". Resolve before
     * comparing so the no-op check is evaluated in the guest-virtual ID space
     * on both sides.
     */
    uint32_t effective_uid = e->uid == (uint32_t) -1 ? cur_uid : e->uid;
    uint32_t effective_gid = e->gid == (uint32_t) -1 ? cur_gid : e->gid;
    if (effective_uid == cur_uid && effective_gid == cur_gid)
        remove_locked(dev, ino);

out:
    pthread_rwlock_unlock(&overlay_lock);
    return rc;
}

void chown_overlay_clear(uint64_t dev, uint64_t ino)
{
    /* Skipping the lock when the table is empty saves one rwlock op when no
     * overrides exist.
     */
    if (atomic_load_explicit(&entry_count, memory_order_acquire) == 0)
        return;

    pthread_rwlock_wrlock(&overlay_lock);

    remove_locked(dev, ino);

    pthread_rwlock_unlock(&overlay_lock);
}

void chown_overlay_apply(struct stat *st)
{
    if (atomic_load_explicit(&entry_count, memory_order_acquire) == 0)
        return;

    pthread_rwlock_rdlock(&overlay_lock);

    overlay_entry_t *e =
        find_locked((uint64_t) st->st_dev, (uint64_t) st->st_ino);
    if (e) {
        /* Skip sentinel fields: (uint32_t)-1 means "no override recorded" for
         * that field, so leave the host value untouched.
         */
        if (e->uid != (uint32_t) -1)
            st->st_uid = e->uid;
        if (e->gid != (uint32_t) -1)
            st->st_gid = e->gid;
    }

    pthread_rwlock_unlock(&overlay_lock);
}

bool chown_overlay_empty(void)
{
    return atomic_load_explicit(&entry_count, memory_order_acquire) == 0;
}

/* Wire format: uint32_t count, followed by count records of { uint64_t dev;
 * uint64_t ino; uint32_t uid; uint32_t gid; }. Matches the in-memory layout so
 * the child can install the table without an intermediate translation step.
 */
typedef struct {
    uint64_t dev;
    uint64_t ino;
    uint32_t uid;
    uint32_t gid;
} overlay_wire_t;

int chown_overlay_send(int ipc_sock)
{
    pthread_rwlock_rdlock(&overlay_lock);

    size_t n = atomic_load_explicit(&entry_count, memory_order_acquire);

    /* The cap is well above any realistic chown-heavy workload (dpkg). Hitting
     * it indicates a runaway table or a bug, not a legitimate parent; refuse to
     * truncate-on-success and fail the fork so the caller sees the problem.
     */
    if (n > CHOWN_OVERLAY_MAX_ENTRIES) {
        pthread_rwlock_unlock(&overlay_lock);
        return -1;
    }
    uint32_t count = (uint32_t) n;

    if (fork_ipc_write_all(ipc_sock, &count, sizeof(count)) < 0) {
        pthread_rwlock_unlock(&overlay_lock);
        return -1;
    }
    if (count == 0) {
        pthread_rwlock_unlock(&overlay_lock);
        return 0;
    }

    uint32_t emitted = 0;
    for (unsigned int i = 0; i < CHOWN_OVERLAY_BUCKETS; i++) {
        for (overlay_entry_t *e = buckets[i]; e; e = e->next) {
            overlay_wire_t w = {
                .dev = e->dev,
                .ino = e->ino,
                .uid = e->uid,
                .gid = e->gid,
            };
            if (fork_ipc_write_all(ipc_sock, &w, sizeof(w)) < 0) {
                pthread_rwlock_unlock(&overlay_lock);
                return -1;
            }
            emitted++;
        }
    }

    /* entry_count under the rwlock cannot drift; emitted must equal the count
     * we wrote.
     */
    int rc = (emitted == count) ? 0 : -1;
    pthread_rwlock_unlock(&overlay_lock);
    return rc;
}

int chown_overlay_recv(int ipc_sock)
{
    uint32_t count;
    if (fork_ipc_read_all(ipc_sock, &count, sizeof(count)) < 0)
        return -1;
    if (count > CHOWN_OVERLAY_MAX_ENTRIES)
        return -1;

    /* Read every record into a transient buffer before touching the live table.
     * Keeps the rwlock free for siblings during the blocking IO, and a partial
     * read just drops the buffer without leaving a half-built table behind.
     */
    overlay_wire_t *records = NULL;
    if (count > 0) {
        records = calloc(count, sizeof(*records));
        if (!records)
            return -1;
        if (fork_ipc_read_all(ipc_sock, records,
                              (size_t) count * sizeof(*records)) < 0) {
            free(records);
            return -1;
        }
    }

    pthread_rwlock_wrlock(&overlay_lock);
    clear_all_locked();

    for (uint32_t i = 0; i < count; i++) {
        overlay_entry_t *e = calloc(1, sizeof(*e));
        if (!e) {
            clear_all_locked();
            pthread_rwlock_unlock(&overlay_lock);
            free(records);
            return -1;
        }
        e->dev = records[i].dev;
        e->ino = records[i].ino;
        e->uid = records[i].uid;
        e->gid = records[i].gid;
        unsigned int idx = bucket_index(e->dev, e->ino);
        e->next = buckets[idx];
        buckets[idx] = e;
        atomic_fetch_add_explicit(&entry_count, 1, memory_order_release);
    }

    pthread_rwlock_unlock(&overlay_lock);
    free(records);
    return 0;
}


/* owner records shared by every elfuse process of one sysroot */

/* The canonical sysroot's private sibling holds its owner table. Keeping it
 * outside the guest tree prevents forged records and preserves ownership with
 * instance data across restart. The caller removes both when deleting a tree.
 */
#define OWNER_STORE_SIBLING "%s.elfuse-owner"
#define OWNER_STORE_MAGIC 0x4f574e53u /* 'OWNS' */
#define OWNER_STORE_VERSION 3u

/* Open addressing with linear probing and no deletion, so an insert lands in
 * the first empty slot of its probe run and a lookup may stop at the first
 * empty slot it meets. Every insert runs under the store lock, so one inode
 * owns exactly one slot; a full table refuses the record instead of dropping
 * it.
 */
#define OWNER_STORE_SLOTS 65536u

enum owner_slot_state {
    OWNER_SLOT_EMPTY = 0,
    OWNER_SLOT_FILLED = 1,
};

typedef struct {
    _Atomic uint32_t state;
    _Atomic uint64_t owner; /* uid in the high half, gid in the low half */
    uint64_t dev;
    uint64_t ino;
    uint64_t generation;
} owner_slot_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
} owner_store_header_t;

typedef struct {
    owner_store_header_t header;
    owner_slot_t slots[OWNER_STORE_SLOTS];
} owner_store_t;

_Static_assert(offsetof(owner_store_t, slots) == sizeof(owner_store_header_t),
               "the on-file header must map onto the header field");
_Static_assert(offsetof(owner_store_t, slots) % _Alignof(owner_slot_t) == 0,
               "the mapped slots must be naturally aligned");

/* One attach, during owner_store_init, decides everything a reader will ever
 * see: the mapping, whether it is writable, and the mode. They are atomic
 * because a reader reaches them without the writer's lock, and publishing the
 * mapping last is what lets a lock-free reader trust the other two.
 *
 * The attach creates the table, so a table that exists in this process exists
 * for every sibling that starts later: a reader never has to discover one that
 * appears underneath it.
 */
static _Atomic(owner_store_t *) owner_store;
static _Atomic bool owner_store_writable;
static _Atomic int owner_store_fd = -1;
static _Atomic chown_owner_mode_t owner_mode = CHOWN_OWNER_NO_STORE;
static pthread_once_t owner_store_once = PTHREAD_ONCE_INIT;

/* Serializes attach against itself and against a write's read-modify-write;
 * flock is what serializes this process against its siblings. Both are released
 * by the kernel, so a killed process cannot leave the table wedged. Readers
 * take neither, because the only word they read that changes is one atomic
 * owner.
 */
static pthread_mutex_t owner_store_lock = PTHREAD_MUTEX_INITIALIZER;

static int owner_store_fd_value(void)
{
    return atomic_load_explicit(&owner_store_fd, memory_order_acquire);
}

static bool owner_store_write_lock(void)
{
    pthread_mutex_lock(&owner_store_lock);
    int fd = owner_store_fd_value();
    if (fd < 0) {
        pthread_mutex_unlock(&owner_store_lock);
        return false;
    }
    while (flock(fd, LOCK_EX) < 0) {
        if (errno == EINTR)
            continue;
        pthread_mutex_unlock(&owner_store_lock);
        return false;
    }
    return true;
}

static void owner_store_write_unlock(void)
{
    int fd = owner_store_fd_value();
    if (fd >= 0)
        (void) flock(fd, LOCK_UN);
    pthread_mutex_unlock(&owner_store_lock);
}

static bool owner_store_prepare(int fd, bool writable)
{
    struct stat st;
    if (fstat(fd, &st) < 0)
        return false;
    bool blank = st.st_size == 0;
    if (!blank) {
        if (st.st_size != (off_t) sizeof(owner_store_t))
            return false;
        owner_store_header_t header;
        if (pread(fd, &header, sizeof(header), 0) != (ssize_t) sizeof(header))
            return false;
        if (header.magic == OWNER_STORE_MAGIC &&
            header.version == OWNER_STORE_VERSION)
            return true;

        /* A published table this tree did not write. Truncating it would SIGBUS
         * a process still mapping it, so leave it alone: removing the file is
         * what starts a fresh table. A zero magic is an interrupted creation,
         * which no process can have mapped yet.
         */
        if (header.magic != 0)
            return false;
        blank = true;
    }
    if (!writable)
        return false;
    if (blank && st.st_size != 0 && ftruncate(fd, 0) < 0)
        return false;
    if (ftruncate(fd, (off_t) sizeof(owner_store_t)) < 0)
        return false;
    owner_store_header_t header = {
        .magic = OWNER_STORE_MAGIC,
        .version = OWNER_STORE_VERSION,
    };
    return pwrite(fd, &header, sizeof(header), 0) == (ssize_t) sizeof(header);
}

/* One table per sysroot, in a private directory beside it, named by the format
 * version. The sysroot is realpath()ed first, so two spellings of one tree (a
 * symlink, a trailing slash, a '.' component) reach one table instead of two
 * that disagree; the canonical form is also what the table is named after, so
 * the table and the tree it describes cannot drift apart. Every slot is keyed
 * by inode identity, so a record cannot match a different file, and the version
 * in the file name starts a fresh table after a format change rather than
 * reading one it cannot interpret.
 *
 * The table is created by the one attach every process makes, so a tree this
 * run touches always has one and no reader can be looking for a table a sibling
 * has not made yet. It lives beside the tree, never inside it, so no guest path
 * names it.
 */
static bool owner_store_paths(char *out_file,
                              size_t out_file_size,
                              char *out_dir,
                              size_t out_dir_size,
                              const char *sysroot)
{
    char resolved[LINUX_PATH_MAX];
    if (!realpath(sysroot, resolved))
        return false;

    /* A sysroot at the host root would put the private directory inside the
     * guest namespace, where a guest could rewrite the owners it names.
     */
    if (!strcmp(resolved, "/"))
        return false;
    int dir_len =
        snprintf(out_dir, out_dir_size, OWNER_STORE_SIBLING, resolved);
    if (dir_len < 0 || (size_t) dir_len >= out_dir_size)
        return false;
    int len = snprintf(out_file, out_file_size, "%s/v%u", out_dir,
                       (unsigned) OWNER_STORE_VERSION);
    return len > 0 && (size_t) len < out_file_size;
}

/* @create is true for the one attach a process makes, which brings the private
 * directory and the table into being; no other caller passes it. An existing
 * table is opened read-write when this process may, so the mapping is writable
 * from the first stat rather than needing a re-attach later.
 *
 * A directory that cannot be created (a read-only parent) is not fatal: an
 * existing table is still opened read-only, and a write then reports that it
 * could not record.
 */
static int owner_store_open(char *path,
                            size_t path_size,
                            const char *dir,
                            bool create,
                            bool *writable)
{
    (void) path_size;
    *writable = false;

    /* A missing directory is made only for a caller that asked to create, so a
     * read of a tree with no table does not bring metadata into being. Failing
     * to make it is not fatal here: the read-only open below decides.
     */
    if (create)
        (void) create_private_dir(dir);

    int fd = -1;
    if (create) {
        /* O_NOFOLLOW refuses a symlink planted in the private directory, and
         * O_EXCL keeps a second creator from adopting whatever an earlier one
         * left.
         */
        fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  0600);
    }

    /* Either this call just created the table, or one already exists and this
     * process may write it; both want a writable descriptor.
     */
    if (fd < 0)
        fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
            st.st_uid == getuid() && (st.st_mode & (S_IRWXG | S_IRWXO)) == 0) {
            *writable = true;
            return fd;
        }
        close(fd);
    }

    /* Someone else's private directory, or a table this process may only read.
     */
    return open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
}

/* Maps the table for this process and reports the mode the attempt reached. A
 * caller that needs to record an owner passes @create, which is what brings the
 * private directory into being; everything else only ever reads.
 */
static chown_owner_mode_t owner_store_attach(bool create)
{
    char sysroot[LINUX_PATH_MAX];
    char path[LINUX_PATH_MAX];
    char dir[LINUX_PATH_MAX];
    if (!proc_sysroot_snapshot(sysroot, sizeof(sysroot)))
        return CHOWN_OWNER_NO_STORE;
    if (!owner_store_paths(path, sizeof(path), dir, sizeof(dir), sysroot))
        return CHOWN_OWNER_READ_ONLY;

    bool writable = false;
    int fd = owner_store_open(path, sizeof(path), dir, create, &writable);
    if (fd < 0)
        return CHOWN_OWNER_READ_ONLY;

    if (flock(fd, writable ? LOCK_EX : LOCK_SH) < 0) {
        close(fd);
        return CHOWN_OWNER_READ_ONLY;
    }
    bool ready = owner_store_prepare(fd, writable);
    flock(fd, LOCK_UN);
    if (!ready) {
        close(fd);
        return CHOWN_OWNER_READ_ONLY;
    }

    void *map =
        mmap(NULL, sizeof(owner_store_t),
             writable ? PROT_READ | PROT_WRITE : PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return CHOWN_OWNER_READ_ONLY;
    }
    atomic_store_explicit(&owner_store_fd, fd, memory_order_release);
    atomic_store_explicit(&owner_store_writable, writable,
                          memory_order_relaxed);
    atomic_store_explicit(&owner_store, map, memory_order_release);
    return writable ? CHOWN_OWNER_SHARED : CHOWN_OWNER_READ_ONLY;
}

/* One attach for the life of the process, made once, with creation. Every
 * process that can name the tree sees the same table from its first stat, so a
 * reader can never be stuck on a mapping taken before a sibling made the table:
 * there is no later table for it to miss.
 *
 * Creating it unconditionally is what makes that true. The alternative -- read
 * first, create on demand -- leaves a reader whose attach found nothing holding
 * a null mapping forever while another VM makes the table, and answering the
 * host uid in the meantime is exactly the leak this table exists to prevent.
 * The cost is one small file per sysroot, spent even when no owner is ever
 * recorded; a tree that must stay pristine is a fixture's cleanup to decide,
 * not a reason to under-report ownership at runtime.
 */
static void owner_store_init(void)
{
    atomic_store_explicit(&owner_mode, owner_store_attach(true),
                          memory_order_release);
}

chown_owner_mode_t chown_owner_mode(void)
{
    pthread_once(&owner_store_once, owner_store_init);
    return atomic_load_explicit(&owner_mode, memory_order_acquire);
}

static owner_store_t *owner_store_get(void)
{
    pthread_once(&owner_store_once, owner_store_init);
    return atomic_load_explicit(&owner_store, memory_order_acquire);
}

/* The table a write may record into. NULL means this run cannot record an owner
 * at all -- no sysroot, a mapping that failed, or a table only readable here --
 * which the caller reports rather than answering with the host uid. The gate is
 * the mapping's own property, so a write can never land on a PROT_READ mapping
 * and fault instead of failing closed.
 */
static owner_store_t *owner_store_get_for_write(void)
{
    owner_store_t *store = owner_store_get();
    if (!store)
        return NULL;
    if (!atomic_load_explicit(&owner_store_writable, memory_order_acquire))
        return NULL;
    return store;
}

static uint64_t owner_hash(uint64_t dev, uint64_t ino)
{
    uint64_t h = dev ^ (ino + 0x9e3779b97f4a7c15ULL + (dev << 6) + (dev >> 2));
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    return h ^ (h >> 33);
}

/* APFS birth time changes when an earlier mtime is set. st_gen is stable;
 * confirmed creation overwrites an old record when a filesystem reuses an id.
 */
static bool owner_slot_matches(const owner_slot_t *slot, const struct stat *st)
{
    return slot->dev == (uint64_t) st->st_dev &&
           slot->ino == (uint64_t) st->st_ino &&
           slot->generation == (uint64_t) st->st_gen;
}

/* Callers hold the store lock. */
static owner_slot_t *owner_slot_find(owner_store_t *store,
                                     const struct stat *st)
{
    uint64_t hash = owner_hash((uint64_t) st->st_dev, (uint64_t) st->st_ino);
    for (uint32_t probe = 0; probe < OWNER_STORE_SLOTS; probe++) {
        owner_slot_t *slot = &store->slots[(hash + probe) % OWNER_STORE_SLOTS];
        if (atomic_load_explicit(&slot->state, memory_order_acquire) ==
            OWNER_SLOT_EMPTY)
            return NULL;
        if (owner_slot_matches(slot, st))
            return slot;
    }
    return NULL;
}

/* Callers hold the store lock exclusively. Publishes a complete slot -- owner
 * included -- at the first empty position of the probe run, which is the only
 * slot a later lookup can reach for this inode, so an inode never owns two. The
 * owner is written before the state release publishes the slot, so a lock-free
 * reader that sees it filled also sees its owner rather than a transient zero.
 * NULL means the table has no room, which the caller reports rather than
 * dropping the record.
 */
static owner_slot_t *owner_slot_publish(owner_store_t *store,
                                        const struct stat *st,
                                        uint32_t uid,
                                        uint32_t gid)
{
    uint64_t hash = owner_hash((uint64_t) st->st_dev, (uint64_t) st->st_ino);
    for (uint32_t probe = 0; probe < OWNER_STORE_SLOTS; probe++) {
        owner_slot_t *slot = &store->slots[(hash + probe) % OWNER_STORE_SLOTS];
        if (atomic_load_explicit(&slot->state, memory_order_relaxed) !=
            OWNER_SLOT_EMPTY)
            continue;
        slot->dev = (uint64_t) st->st_dev;
        slot->ino = (uint64_t) st->st_ino;
        slot->generation = (uint64_t) st->st_gen;
        atomic_store_explicit(&slot->owner, ((uint64_t) uid << 32) | gid,
                              memory_order_relaxed);
        atomic_store_explicit(&slot->state, OWNER_SLOT_FILLED,
                              memory_order_release);
        return slot;
    }
    return NULL;
}

static void owner_slot_store(owner_slot_t *slot, uint32_t uid, uint32_t gid)
{
    atomic_store_explicit(&slot->owner, ((uint64_t) uid << 32) | gid,
                          memory_order_relaxed);
}

static void owner_slot_load(const owner_slot_t *slot,
                            uint32_t *uid,
                            uint32_t *gid)
{
    uint64_t packed = atomic_load_explicit(&slot->owner, memory_order_relaxed);
    *uid = (uint32_t) (packed >> 32);
    *gid = (uint32_t) packed;
}

/* Whether the host stat already reports the identity the guest wants, so no
 * record is needed to answer correctly. Compared against the stat rather than
 * against the host credentials: only the object in hand says what it reports.
 */
static bool owner_host_reports(const struct stat *host_st,
                               uint32_t uid,
                               uint32_t gid)
{
    return (uint32_t) host_st->st_uid == uid &&
           (uint32_t) host_st->st_gid == gid;
}

/* A reader needs no lock: the only word it reads that a writer can change is
 * the owner, which is one atomic store of a fully formed (uid, gid) pair, and a
 * slot becomes visible only after that word is set. Taking flock here would put
 * a kernel lock on every stat the guest performs.
 */
void chown_owner_apply(struct stat *st)
{
    if (chown_owner_mode() == CHOWN_OWNER_NO_STORE) {
        /* The host filesystem is shared, so the overlay is the only layer there
         * has ever been, and it stays authoritative exactly as before.
         */
        chown_overlay_apply(st);
        return;
    }

    /* The attach ran before any stat could reach here, and it publishes the
     * mapping last, so a non-NULL store is a mapped table. A NULL one means the
     * attach could not map it at all, in which case the host's own answer
     * stands -- the same answer a tree with no records gives.
     */
    owner_store_t *store =
        atomic_load_explicit(&owner_store, memory_order_acquire);
    if (!store)
        return;
    owner_slot_t *slot = owner_slot_find(store, st);
    if (!slot)
        return;
    uint32_t uid, gid;
    owner_slot_load(slot, &uid, &gid);
    st->st_uid = (uid_t) uid;
    st->st_gid = (gid_t) gid;
}

/* @claim says the caller just created the inode: an inode that already has a
 * record keeps it, and one the host already reports correctly needs none.
 * Returns false only when a record was required and could not be written, which
 * the caller must surface rather than report a success the next stat would
 * contradict.
 */
static bool owner_store_write(const struct stat *host_st,
                              uint32_t uid,
                              uint32_t gid,
                              bool claim)
{
    chown_owner_mode_t mode = chown_owner_mode();
    if (mode == CHOWN_OWNER_NO_STORE) {
        /* No sysroot is configured, so this run keeps the behaviour it had
         * before a shared table existed: a created object reports whatever the
         * host reports, and an explicit chown is the only thing that records an
         * owner, in the process-local overlay.
         */
        if (claim)
            return true;
        struct stat guest_st = *host_st;
        chown_overlay_apply(&guest_st);
        return chown_overlay_set((uint64_t) host_st->st_dev,
                                 (uint64_t) host_st->st_ino, uid, gid,
                                 guest_st.st_uid, guest_st.st_gid) == 0;
    }
    owner_store_t *store = owner_store_get_for_write();
    if (!store)
        return false;

    bool ok = true;
    if (!owner_store_write_lock())
        return false;
    owner_slot_t *slot = owner_slot_find(store, host_st);
    if (!slot) {
        if (!claim || !owner_host_reports(host_st, uid, gid)) {
            ok = owner_slot_publish(
                     store, host_st,
                     uid == (uint32_t) -1 ? (uint32_t) host_st->st_uid : uid,
                     gid == (uint32_t) -1 ? (uint32_t) host_st->st_gid : gid) !=
                 NULL;
        }
    } else if (claim) {
        owner_slot_store(slot, uid, gid);
    } else {
        /* Resolve the chown sentinels against the record as it stands, inside
         * the same critical section that writes the pair, so a concurrent
         * uid-only and gid-only chown cannot lose either field.
         */
        uint32_t cur_uid, cur_gid;
        owner_slot_load(slot, &cur_uid, &cur_gid);
        owner_slot_store(slot, uid == (uint32_t) -1 ? cur_uid : uid,
                         gid == (uint32_t) -1 ? cur_gid : gid);
    }
    /* Only the kernel's successful creation reaches the claim path. */
    owner_store_write_unlock();
    return ok;
}

bool chown_owner_claim(const struct stat *host_st, uint32_t uid, uint32_t gid)
{
    return owner_store_write(host_st, uid, gid, true);
}

bool chown_owner_claim_fd(int host_fd, uint32_t uid, uint32_t gid)
{
    struct stat st;
    if (fstat(host_fd, &st) < 0)
        return false;
    return chown_owner_claim(&st, uid, gid);
}

bool chown_owner_claim_at(int host_dirfd,
                          const char *host_path,
                          uint32_t uid,
                          uint32_t gid)
{
    struct stat st;
    if (fstatat(host_dirfd, host_path, &st, AT_SYMLINK_NOFOLLOW) < 0)
        return false;
    return chown_owner_claim(&st, uid, gid);
}

bool chown_owner_record(const struct stat *host_st, uint32_t uid, uint32_t gid)
{
    return owner_store_write(host_st, uid, gid, false);
}
