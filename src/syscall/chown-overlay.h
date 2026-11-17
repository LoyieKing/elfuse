/*
 * Guest-visible file ownership
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * One table answers "who owns this inode" for the guest, shared by every elfuse
 * process that uses the same sysroot. A record is written when a syscall
 * creates an inode or the guest chowns one, and stat reports it, so a file
 * created by one process has one owner in every process. Files with no record
 * keep the host owner, and recording is skipped for an identity the host
 * already reports correctly.
 *
 * The table is a private directory beside the canonical sysroot
 * (<sysroot>.elfuse-owner/), so it is exactly as durable as the tree it
 * describes and is removed with that tree, never by clearing a global scratch
 * directory.
 *
 * While that table exists it is authoritative: the process-local chown overlay
 * below is not consulted, because a chown another process records later would
 * otherwise stay hidden behind this process's older entry. Without a table,
 * when there is no sysroot or the private file cannot be mapped, the overlay is
 * the only layer, and an owner it cannot express is a failure for the caller
 * rather than a silent fallback to the host uid.
 *
 * Both layers key on host inode identity, so an entry survives rename and
 * covers every hard link; the shared record also keys on birth time, so a
 * reused inode cannot inherit a previous file's owner.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

/* Record an intended owner/group for the (dev, ino) pair. owner/group of
 * (uint32_t)-1 means "leave that field unchanged" (Linux chown sentinel).
 * cur_uid/cur_gid supply the defaults for unchanged fields when no entry exists
 * yet (typically the host stat result for the same file). If the resulting
 * virtual owner matches cur_uid/cur_gid, the entry is removed.
 * Returns 0 on success, -1 if a fresh entry could not be allocated.
 */
int chown_overlay_set(uint64_t dev,
                      uint64_t ino,
                      uint32_t new_owner,
                      uint32_t new_group,
                      uint32_t cur_uid,
                      uint32_t cur_gid);

/* Drop any recorded override for (dev, ino). */
void chown_overlay_clear(uint64_t dev, uint64_t ino);

/* If (st->st_dev, st->st_ino) has a recorded override, substitute st->st_uid
 * and st->st_gid in place. Cheap atomic-load fast path when the table is empty.
 */
void chown_overlay_apply(struct stat *st);

/* True when no override is recorded. The close path reads it to decide whether
 * a host stat is worth taking: with an empty table there is no entry to drop.
 */
bool chown_overlay_empty(void);

/* Fork IPC: serialize the table to ipc_sock.
 *
 * Returns 0 on success, -1 on transport failure or when the live table exceeds
 * the in-build cap (refused rather than truncated, so the caller sees the
 * problem instead of inheriting a partial state).
 */
int chown_overlay_send(int ipc_sock);

/* Fork IPC: rebuild the table from ipc_sock.
 *
 * Returns 0 on success, -1 on transport failure, a record count above the
 * in-build cap (malformed wire), or allocation failure during install.
 */
int chown_overlay_recv(int ipc_sock);

/* The three states the store can be in, which decide what a caller may rely on.
 *
 * NO_STORE means this run was never meant to share owners: no sysroot is
 * configured, so there is no tree to share. The process-local chown overlay is
 * the whole answer there, exactly as it was before a shared table existed, and
 * an identity the host cannot express is not an error.
 *
 * READ_ONLY means a sysroot is configured but its table cannot be written here
 * (another user's private directory, no room, a mapping failure). Records other
 * processes wrote are still honoured; a caller that needs to add one is told so
 * and fails, rather than quietly answering with the host uid.
 *
 * SHARED is the normal case and is authoritative over the local overlay.
 */
typedef enum {
    CHOWN_OWNER_NO_STORE = 0,
    CHOWN_OWNER_READ_ONLY = 1,
    CHOWN_OWNER_SHARED = 2,
} chown_owner_mode_t;

chown_owner_mode_t chown_owner_mode(void);

/* If @st's inode has an owner record, substitute its uid/gid in place. Falls
 * back to the process-local overlay only in CHOWN_OWNER_NO_STORE mode, where
 * that overlay is authoritative.
 */
void chown_owner_apply(struct stat *st);

/* Record @uid/@gid as the owner of the inode @host_st describes, replacing an
 * earlier record and resolving the @uid/@gid sentinel ((uint32_t)-1) against
 * the record it replaces, in one critical section, so concurrent partial chowns
 * cannot lose each other's field.
 *
 * Returns false only when a record was required and could not be written, which
 * includes every case the local overlay could not express in NO_STORE mode, so
 * the caller's failure matches what the guest would see from an unanswered
 * chown.
 */
bool chown_owner_record(const struct stat *host_st, uint32_t uid, uint32_t gid);

/* Record the owner after a successful atomic creation. Reopening an existing
 * inode must not call this; a fresh creation replaces a stale record when the
 * filesystem reuses an inode number.
 */
bool chown_owner_claim(const struct stat *host_st, uint32_t uid, uint32_t gid);
bool chown_owner_claim_fd(int host_fd, uint32_t uid, uint32_t gid);
bool chown_owner_claim_at(int host_dirfd,
                          const char *host_path,
                          uint32_t uid,
                          uint32_t gid);
