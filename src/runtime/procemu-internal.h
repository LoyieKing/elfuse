/*
 * Interface between procemu.c and procemu-pty.c
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Not a public header. runtime/procemu.h is what the rest of the tree calls;
 * this carries only what the two halves of the /proc, /sys, /dev interceptor
 * need from each other after the pty side-table moved into its own file.
 *
 * It is deliberately short. If it grows, the split is in the wrong place.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

/* Provided by procemu.c, used by procemu-pty.c. */

/* Open a directory the interceptor synthesized, honoring the guest's open
 * flags. The pty code uses it for /dev/pts.
 */
int proc_open_dir_fd(const char *path, int linux_flags);

/* Record a scratch directory for removal at its last close or at exit. */
void proc_scratch_register(const char *dir);

/* Remove one lazily-created scratch directory. The pty code uses it to drop its
 * /dev/pts staging directory at teardown.
 */
void proc_scratch_remove_one(const char *dir);

/* Provided by procemu-pty.c, used by procemu.c.
 *
 * The proc_pty_* entry points are in runtime/procemu.h because callers outside
 * procemu use them too. The five below are internal to the interceptor: they
 * were static before the split and stay unexported beyond this pair of files.
 */

/* Parse the N out of "/dev/pts/N". False when the path is not a slave. */
bool pty_slave_num_from_path(const char *path, uint32_t *out);

/* Host path of a live Unix98 slave, or -1 when the pts number is unknown. */
int pty_lookup_slave_path(uint32_t linux_pts_num, char *out, size_t out_sz);

/* Open /dev/pts/N, /dev/pts, and /dev/ptmx respectively, with Linux open flags.
 * Each allocates or adopts the keepalive state the side-table needs.
 */
int pty_open_slave(uint32_t linux_pts_num, int linux_flags);
int pty_open_pts_dir(int linux_flags);
int pty_open_master(int linux_flags);
