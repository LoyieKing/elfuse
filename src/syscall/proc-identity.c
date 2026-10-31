/*
 * Process identity and session state
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "syscall/linux-wire.h"
#include "syscall/internal.h"
#include "core/shim-globals.h"
#include "runtime/thread.h"
#include "syscall/proc-identity.h"
#include "syscall/proc.h"

static _Atomic int64_t guest_pid = 1, parent_pid = 0;
static _Atomic bool child_subreaper;
static _Atomic bool soft_newpid;
static _Atomic int dumpable = 1; /* Linux PR_SET/GET_DUMPABLE */
static _Atomic uint32_t emu_uid, emu_euid, emu_suid;
static _Atomic uint32_t emu_gid, emu_egid, emu_sgid;

static pthread_mutex_t session_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic int64_t guest_sid = 1, guest_pgid = 1;
static _Atomic int64_t guest_fg_pgrp = 1;
static _Atomic int32_t guest_has_ctty = 1;

static _Atomic bool fakeroot_enabled = false;

static _Atomic bool initial_ids_staged = false;
static _Atomic uint32_t initial_uid;
static _Atomic uint32_t initial_gid;

void proc_set_fakeroot_enabled(bool enabled)
{
    atomic_store_explicit(&fakeroot_enabled, enabled, memory_order_relaxed);
}

bool proc_fakeroot_enabled(void)
{
    return atomic_load_explicit(&fakeroot_enabled, memory_order_relaxed);
}

/* Written once during startup, before any guest code runs, and only read after
 * that. No lock: exec reads it from guest threads that all start later.
 */
static char fakeroot_exec_path[LINUX_PATH_MAX];

bool proc_set_fakeroot_exec_path(const char *path)
{
    size_t len = path ? strlen(path) : 0;
    if (len == 0 || path[0] != '/' || len >= sizeof(fakeroot_exec_path)) {
        fakeroot_exec_path[0] = '\0';
        return false;
    }
    memcpy(fakeroot_exec_path, path, len + 1);
    return true;
}

const char *proc_fakeroot_exec_path(void)
{
    return fakeroot_exec_path[0] ? fakeroot_exec_path : NULL;
}

void proc_set_initial_ids(uint32_t uid, uint32_t gid)
{
    /* Release on the staged flag publishes the two ids with it. The consumer in
     * proc_identity_init acquires through the same flag before reading them.
     */
    atomic_store_explicit(&initial_uid, uid, memory_order_relaxed);
    atomic_store_explicit(&initial_gid, gid, memory_order_relaxed);
    atomic_store_explicit(&initial_ids_staged, true, memory_order_release);
}

void proc_clear_initial_ids(void)
{
    atomic_store_explicit(&initial_ids_staged, false, memory_order_relaxed);
}

void proc_identity_init(void)
{
    guest_pid = 1;
    parent_pid = 0;
    child_subreaper = false;
    atomic_store_explicit(&dumpable, 1, memory_order_relaxed);

    uint32_t uid = (uint32_t) getuid();
    uint32_t euid = (uint32_t) geteuid();
    uint32_t gid = (uint32_t) getgid();
    uint32_t egid = (uint32_t) getegid();

    if (proc_fakeroot_enabled()) {
        uid = euid = 0;
        gid = egid = 0;
    }

    /* A staged --user wins over the defaults and over fakeroot; consumed here
     * so it applies to one bring-up only (contract in proc.h).
     */
    if (atomic_exchange_explicit(&initial_ids_staged, false,
                                 memory_order_acquire)) {
        uid = atomic_load_explicit(&initial_uid, memory_order_relaxed);
        gid = atomic_load_explicit(&initial_gid, memory_order_relaxed);
        euid = uid;
        egid = gid;
    }

    atomic_store_explicit(&emu_uid, uid, memory_order_relaxed);
    atomic_store_explicit(&emu_euid, euid, memory_order_relaxed);
    atomic_store_explicit(&emu_suid, euid, memory_order_relaxed);
    atomic_store_explicit(&emu_gid, gid, memory_order_relaxed);
    atomic_store_explicit(&emu_egid, egid, memory_order_relaxed);
    atomic_store_explicit(&emu_sgid, egid, memory_order_relaxed);
    guest_sid = 1;
    guest_pgid = 1;
    guest_fg_pgrp = 1;
    guest_has_ctty = 1;
}

int64_t proc_get_pid(void)
{
    return guest_pid;
}

int64_t proc_get_ppid(void)
{
    return parent_pid;
}

uint32_t proc_get_uid(void)
{
    return emu_uid;
}

uint32_t proc_get_euid(void)
{
    return emu_euid;
}

uint32_t proc_get_suid(void)
{
    return emu_suid;
}

uint32_t proc_get_gid(void)
{
    return emu_gid;
}

uint32_t proc_get_egid(void)
{
    return emu_egid;
}

uint32_t proc_get_sgid(void)
{
    return emu_sgid;
}

static bool uid_is_permitted(uint32_t val)
{
    if (emu_euid == 0 || proc_fakeroot_enabled())
        return true;
    return val == emu_uid || val == emu_euid || val == emu_suid;
}

static bool gid_is_permitted(uint32_t val)
{
    if (emu_euid == 0 || proc_fakeroot_enabled())
        return true;
    return val == emu_gid || val == emu_egid || val == emu_sgid;
}

int64_t proc_sys_setuid(uint32_t uid)
{
    if (!uid_is_permitted(uid))
        return -LINUX_EPERM;
    if (emu_euid == 0 || proc_fakeroot_enabled()) {
        emu_uid = uid;
        emu_euid = uid;
        emu_suid = uid;
    } else
        emu_euid = uid;
    return 0;
}

int64_t proc_sys_setgid(uint32_t gid)
{
    if (!gid_is_permitted(gid))
        return -LINUX_EPERM;
    if (emu_euid == 0 || proc_fakeroot_enabled()) {
        emu_gid = gid;
        emu_egid = gid;
        emu_sgid = gid;
    } else
        emu_egid = gid;
    return 0;
}

#define DEFINE_SETRE(suffix, real, eff, saved, perm_fn)                    \
    int64_t proc_sys_setre##suffix(uint32_t r, uint32_t e)                 \
    {                                                                      \
        uint32_t old_real = real;                                          \
        if (r != (uint32_t) -1 && r != real && r != eff &&                 \
            !(emu_euid == 0 || proc_fakeroot_enabled()))                   \
            return -LINUX_EPERM;                                           \
        if (e != (uint32_t) -1 && !perm_fn(e))                             \
            return -LINUX_EPERM;                                           \
        if (r != (uint32_t) -1)                                            \
            real = r;                                                      \
        if (e != (uint32_t) -1)                                            \
            eff = e;                                                       \
        /* Linux setreuid(2): saved-set-ID is updated to                   \
         * the new effective ID when the real ID is set                    \
         * (r != -1) OR when the new effective ID differs                  \
         * from the old real ID.  Both conditions use the                  \
         * *new* effective value (eff, which may be                        \
         * unchanged if e == -1).                                          \
         */                                                                \
        if (r != (uint32_t) -1 || (e != (uint32_t) -1 && eff != old_real)) \
            saved = eff;                                                   \
        return 0;                                                          \
    }

DEFINE_SETRE(uid, emu_uid, emu_euid, emu_suid, uid_is_permitted)
DEFINE_SETRE(gid, emu_gid, emu_egid, emu_sgid, gid_is_permitted)

#undef DEFINE_SETRE

#define DEFINE_SETRES(suffix, real, eff, saved, perm_fn)                \
    int64_t proc_sys_setres##suffix(uint32_t r, uint32_t e, uint32_t s) \
    {                                                                   \
        if (r != (uint32_t) -1 && !perm_fn(r))                          \
            return -LINUX_EPERM;                                        \
        if (e != (uint32_t) -1 && !perm_fn(e))                          \
            return -LINUX_EPERM;                                        \
        if (s != (uint32_t) -1 && !perm_fn(s))                          \
            return -LINUX_EPERM;                                        \
        if (r != (uint32_t) -1)                                         \
            real = r;                                                   \
        if (e != (uint32_t) -1)                                         \
            eff = e;                                                    \
        if (s != (uint32_t) -1)                                         \
            saved = s;                                                  \
        return 0;                                                       \
    }

DEFINE_SETRES(uid, emu_uid, emu_euid, emu_suid, uid_is_permitted)
DEFINE_SETRES(gid, emu_gid, emu_egid, emu_sgid, gid_is_permitted)

#undef DEFINE_SETRES

void proc_set_ids(uint32_t uid,
                  uint32_t euid,
                  uint32_t suid,
                  uint32_t gid,
                  uint32_t egid,
                  uint32_t sgid)
{
    emu_uid = uid;
    emu_euid = euid;
    emu_suid = suid;
    emu_gid = gid;
    emu_egid = egid;
    emu_sgid = sgid;
}


bool proc_has_cap_sys_nice(void)
{
    return proc_get_euid() == 0;
}

bool proc_pid_alive(int pid)
{
    if (pid == 0 || pid == (int) guest_pid)
        return true;
    return thread_tid_alive((int64_t) pid);
}


int64_t proc_get_sid(void)
{
    return guest_sid;
}

int64_t proc_get_pgid(void)
{
    return guest_pgid;
}

static void proc_publish_pgsid_locked(guest_t *g)
{
    shim_globals_publish_pgsid(g, guest_pgid, guest_sid);
}

void proc_publish_pgsid_snapshot(guest_t *g)
{
    pthread_mutex_lock(&session_lock);
    proc_publish_pgsid_locked(g);
    pthread_mutex_unlock(&session_lock);
}

int64_t proc_get_fg_pgrp(void)
{
    return guest_fg_pgrp;
}

int proc_get_ctty(void)
{
    return guest_has_ctty;
}

void proc_set_session(int64_t sid, int64_t pgid)
{
    guest_sid = sid;
    guest_pgid = pgid;
    guest_fg_pgrp = pgid;
}

void proc_set_pgid_from_registry(guest_t *g, int64_t pgid)
{
    pthread_mutex_lock(&session_lock);
    guest_pgid = pgid;
    proc_publish_pgsid_locked(g);
    pthread_mutex_unlock(&session_lock);
}

void proc_set_fg_pgrp(int64_t pgrp)
{
    guest_fg_pgrp = pgrp;
}

void proc_set_ctty(int has_ctty)
{
    guest_has_ctty = has_ctty;
}

int64_t proc_sys_setsid(guest_t *g)
{
    int64_t pid = guest_pid;

    pthread_mutex_lock(&session_lock);
    if (guest_pgid == pid) {
        pthread_mutex_unlock(&session_lock);
        return -LINUX_EPERM;
    }

    guest_sid = pid;
    guest_pgid = pid;
    guest_fg_pgrp = pid;
    guest_has_ctty = 0;
    proc_publish_pgsid_locked(g);
    pthread_mutex_unlock(&session_lock);
    return pid;
}

int64_t proc_sys_setpgid(guest_t *g, int64_t pid, int64_t pgid)
{
    int64_t self = guest_pid;

    if (pid == 0)
        pid = self;
    if (pgid == 0)
        pgid = pid;
    if (pid != self)
        return 0;

    pthread_mutex_lock(&session_lock);
    if (guest_sid == self && guest_pgid == self) {
        pthread_mutex_unlock(&session_lock);
        return -LINUX_EPERM;
    }

    guest_pgid = pgid;
    proc_publish_pgsid_locked(g);
    pthread_mutex_unlock(&session_lock);
    return 0;
}

int64_t proc_sys_getsid(int64_t pid)
{
    int64_t self = guest_pid;

    if (pid == 0 || pid == self)
        return guest_sid;
    return -LINUX_ESRCH;
}

void proc_set_identity(int64_t pid, int64_t ppid)
{
    guest_pid = pid;
    parent_pid = ppid;
}

void proc_set_soft_newpid(bool enabled)
{
    atomic_store_explicit(&soft_newpid, enabled, memory_order_relaxed);
}

bool proc_in_soft_newpid(void)
{
    return atomic_load_explicit(&soft_newpid, memory_order_relaxed);
}

void proc_set_ppid(int64_t ppid)
{
    parent_pid = ppid;
}

void proc_set_child_subreaper(bool enabled)
{
    child_subreaper = enabled;
}

bool proc_get_child_subreaper(void)
{
    return child_subreaper;
}

void proc_set_dumpable(int value)
{
    /* Linux: SUID_DUMP_DISABLE(0) or SUID_DUMP_USER(1). Other values get EINVAL
     * at the prctl layer; we store the clamped 0/1 here.
     */
    atomic_store_explicit(&dumpable, value ? 1 : 0, memory_order_relaxed);
}

int proc_get_dumpable(void)
{
    return atomic_load_explicit(&dumpable, memory_order_relaxed);
}
