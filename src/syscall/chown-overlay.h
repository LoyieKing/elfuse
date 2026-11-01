/*
 * Virtual chown overlay (fakeroot-style)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Records intended owner/group for files whose host chown returned EPERM
 * (rootless macOS cannot chown to arbitrary uids/gids) so a subsequent
 * stat/statx/fstat from the guest returns the value the program just "chowned"
 * to instead of the host's real owner.
 *
 * Keyed by host (st_dev, st_ino) so overrides survive rename and apply
 * uniformly to every hard link.
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
