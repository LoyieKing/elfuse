/*
 * /proc and /dev path emulation
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Intercepts openat and readlinkat for /proc, /dev, and other synthetic paths.
 * Returns host fds for synthetic content or -2 if not intercepted.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include "core/guest.h"

/* Sentinel return value: path was not intercepted, caller should fall through
 * to the real syscall.
 */
#define PROC_NOT_INTERCEPTED (-2)

/* Intercept openat for /proc and /dev paths. The guest_t pointer is needed to
 * generate /proc/self/maps and /proc/self/smaps from region data.
 * Returns a host fd on match (caller should fd_alloc it), -1 on error with
 * errno set, or PROC_NOT_INTERCEPTED if the path is not intercepted.
 */
int proc_intercept_open(const guest_t *g,
                        const char *path,
                        int linux_flags,
                        int mode);

/* Intercept readlinkat for /proc paths.
 * Returns the link length on match, -1 on error, or -2 if not intercepted (fall
 * through to real readlinkat).
 */
int proc_intercept_readlink(const char *path, char *buf, size_t bufsiz);

/* Intercept stat/fstatat for /proc paths.
 * Returns 0 if stat was synthesized (mac_st filled), or -2 if not intercepted
 * (fall through to real fstatat).
 *
 * `follow` selects stat() vs lstat() semantics for a synthetic symlink leaf.
 * The synthetic trees carry real symlinks (the USB `subsystem` links), and
 * Linux reports the target's identity for a following stat, so a caller that is
 * serving stat()/fstatat() without AT_SYMLINK_NOFOLLOW must pass true.
 * proc_intercept_stat keeps the nofollow spelling for callers that name a
 * specific object (an already-opened fd's stamp, a readlink probe).
 */
int proc_intercept_stat_at(const char *path, struct stat *mac_st, bool follow);
int proc_intercept_stat(const char *path, struct stat *mac_st);

/* True when PATH names a live Unix98 pty slave (/dev/pts/N whose master is
 * open), filling out with the same synthesized stat proc_intercept_stat would
 * return. Such a path has no host backing, so metadata operations on it must be
 * answered here rather than passed through to the host filesystem.
 *
 * Answering and stat'ing together keeps callers that need both from walking the
 * locked pty table twice, which would leave a window where the slave goes away
 * between the test and the stat. out may be NULL for a pure test.
 */
bool proc_pty_slave_stat(const char *path, struct stat *out);

/* Intercept writes to synthetic proc files that need stateful behavior.
 * Returns 1 if handled (with *written_out set), 0 if not intercepted, or -1 on
 * error with errno set.
 */
int proc_intercept_write(int guest_fd,
                         int host_fd,
                         const void *buf,
                         size_t count,
                         int64_t offset,
                         int use_pwrite,
                         ssize_t *written_out);

/* Intercept reads from synthetic proc files that must reflect shared state on
 * every read rather than the per-open temp-file snapshot.
 * Returns 1 if handled (with *read_out set), 0 if not intercepted, or -1 on
 * error with errno set.
 */
int proc_intercept_read(int guest_fd,
                        void *buf,
                        size_t count,
                        int64_t offset,
                        ssize_t *read_out);

/* Vector form of proc_intercept_read for readv/preadv. */
int proc_intercept_readv(int guest_fd,
                         const struct iovec *iov,
                         int iovcnt,
                         int64_t offset,
                         ssize_t *read_out);

/* Get the /dev/shm emulation directory path (creating it on first call). Used
 * by sys_unlinkat to rewrite /dev/shm/<name> paths.
 */
const char *proc_get_shm_dir(void);

/* Resolve a /dev/shm/<suffix> guest-path suffix to a host path inside the
 * per-UID /dev/shm emulation directory. Rejects empty, ".."-bearing, or
 * compound suffixes with errno = EACCES.
 *
 * Returns 0 on success and writes the full host path to host_path; returns -1
 * with errno set (EACCES on invalid suffix, ENAMETOOLONG on overflow, or as set
 * by shm_dir_path()).
 */
int proc_dev_shm_resolve(const char *guest_suffix,
                         char *host_path,
                         size_t host_path_sz);

/* A directory stream's last reference is closing @host_fd. When it names a
 * /proc listing scratch directory that no fork child shares, remove that
 * directory now instead of at exit. No-op for every other descriptor.
 */
void proc_scratch_note_closed_dir(int host_fd);

/* A fork is duplicating every guest descriptor into the child: the scratch
 * directories tracked so far stay until exit, since the child may still list
 * them through its inherited descriptors.
 */
void proc_scratch_note_fork(void);

/* Drop the keepalive slave fd paired with a /dev/ptmx master host fd. Called
 * from fd_cleanup_entry when the guest closes the master so the host kernel
 * eventually tears the tty down. Idempotent and safe to call on any host fd
 * (no-op when no keepalive is registered).
 */
void proc_pty_close_keepalive(int master_host_fd);

/* Record a slave fd the guest now holds, so the master knows it is not yet hung
 * up. Both guest-facing slave opens report through this: the /dev/pts/N
 * intercept and the TIOCGPTPEER ioctl.
 */
void proc_pty_note_guest_slave(int slave_host_fd, uint32_t linux_pts_num);

/* Drop a guest-held pty slave fd from the per-master accounting. Called for
 * every closing host fd and a no-op for anything that is not a tracked slave.
 */
void proc_pty_slave_fd_closed(int host_fd);

/* Drop a host fd from both pty side tables, master and slave.
 *
 * A host fd that goes away without becoming a guest fd has to leave both, and
 * which of the two it is registered in is not known at the call site. Calling
 * only one is silent: a leaked keepalive slave, or a phantom slave count that
 * suppresses the master's hangup for good. Every path that closes a host fd
 * outside fd_cleanup_entry wants this rather than either half.
 */
void proc_pty_forget_host_fd(int host_fd);

/* Count the pty slave fds a forked child inherited from its parent.
 *
 * The host-fd-to-pty mapping is per-process and does not cross the fork, so
 * without this an inherited slave is counted by nobody: the parent closes its
 * own copy, the count reaches zero while the child's shell still holds a live
 * slave, and the master reports a hangup as soon as the terminal starts. Call
 * from the fork child once its fd table and keepalives are both restored.
 */
void proc_pty_adopt_inherited_slaves(void);

/* Return this process's outstanding pty slave count at teardown.
 *
 * A guest that exits normally never closes its stdio -- the kernel does -- so
 * the slaves behind fds 0/1/2 never reach the per-fd close hook. Without this
 * the shared count keeps a departed shell's slaves forever and the master never
 * reports the hangup its terminal is waiting on. Call once from the process
 * cleanup path; idempotent.
 */
void proc_pty_release_process_slaves(void);

/* Count the slave fds a fork is about to duplicate into the child.
 *
 * Called in the parent while the guest is still inside clone, because the child
 * cannot do it for itself in time: a parent that closes its own copy the moment
 * fork returns -- openpty(3)-style terminal startup -- would otherwise drive
 * the count to zero before the child's init runs, and the master would report a
 * hangup with the shell alive.
 */
void proc_pty_fork_parent_note_inherited(void);

/* True when the guest has closed every slave fd it held for this master, the
 * state Linux reports as a hangup: poll gives POLLHUP, epoll gives EPOLLHUP,
 * and read gives EIO. elfuse's own keepalive slave stays open, so the host
 * cannot answer this.
 *
 * expect_generation is the fd generation the caller pinned when it resolved
 * guest_fd. The lookup re-resolves the guest fd, so without that witness a
 * close-and-reuse in the window would report the hangup against whatever file
 * now occupies the slot. Pass fd_current_generation(guest_fd) captured at
 * resolve time; a mismatch (including the 0 returned for a closed slot) reports
 * no hangup.
 */
bool proc_pty_master_hung_up(int guest_fd, uint64_t expect_generation);

/* Caller-locked variant of pty keepalive duplication. Brackets the host
 * fd_snapshot_and_dup and the keepalive mirror under one pty_keepalive_lock
 * window so a sibling close cannot run proc_pty_close_keepalive in the gap and
 * leave the alias without a keepalive entry. Caller must wrap the sequence with
 * proc_pty_lock_for_dup / proc_pty_unlock_for_dup.
 */
void proc_pty_lock_for_dup(void);
void proc_pty_unlock_for_dup(void);
void proc_pty_dup_keepalive_locked(int src_master_host_fd,
                                   int dst_master_host_fd);

/* Slave-side counterpart of proc_pty_dup_keepalive_locked: mirror a guest pty
 * slave onto the host fd a dup just produced.
 *
 * open() and the TIOCGPTPEER ioctl are the two paths that register a slave;
 * every further reference dup2 creates went uncounted. A terminal that dup2()s
 * its slave onto stdin/stdout/stderr and closes the original then drove the
 * count to zero with three live references left, and the master reported a
 * hangup while the shell was still running. Caller must hold the dup bracket
 * (proc_pty_lock_for_dup).
 */
void proc_pty_dup_guest_slave_locked(int src_slave_host_fd,
                                     int dst_slave_host_fd);

/* Return the captured Linux pts number for a host master fd, or UINT32_MAX when
 * no keepalive is registered. Lets sys_ioctl TIOCGPTN report the value
 * /dev/pts/N opens / stats round-trip through, instead of independently parsing
 * the macOS slave path and risking divergence with the open table.
 */
uint32_t proc_pty_master_pts_num(int master_host_fd);

/* Best-effort lazy registration for a /dev/ptmx master that elfuse did not open
 * itself (e.g. one received from a peer via SCM_RIGHTS). Takes a guest fd
 * because the canonical host fd would race with sibling close+reuse if passed
 * in directly: this helper snapshots fd_table[guest_fd].host_fd and its
 * generation, performs the slave open against a private dup, and only registers
 * the keepalive after re-verifying the slot still holds the original (host_fd,
 * generation).
 *
 * Returns the pts number on success, or UINT32_MAX if the fd is not a pty
 * master, the slot got closed/recycled mid-adoption, or the keepalive table is
 * full. Idempotent: if the master already has a keepalive entry, returns its
 * stored linux_pts_num.
 */
uint32_t proc_pty_master_adopt(int guest_fd);

/* Max bytes for a captured macOS slave path (e.g. "/dev/ttys004"). Lives in the
 * header so proc_pty_ipc_entry_t below and the in-memory keepalive table in
 * procemu.c share one source of truth; a divergence would silently corrupt the
 * fork-IPC wire format.
 */
#define PTY_SLAVE_PATH_MAX 64

/* Serialized form of a pty keepalive entry, used by fork-IPC. The slave host fd
 * travels separately via SCM_RIGHTS; this struct only carries the
 * lifetime-independent metadata that the child needs to re-register.
 */
typedef struct {
    int32_t master_host_fd;
    uint32_t linux_pts_num;
    char slave_path[PTY_SLAVE_PATH_MAX];
} proc_pty_ipc_entry_t;

/* Snapshot the current pty keepalive table into out_entries / out_slave_fds.
 * dup()s every slave fd under the keepalive lock so the snapshot stays valid
 * across the SCM_RIGHTS send even if the original master gets closed before the
 * IPC drains.
 *
 * Returns the number of live entries written (always <= max_entries); on
 * success the caller owns the duplicated slave fds and must close them after
 * the IPC send completes.
 */
int proc_pty_snapshot_keepalive(proc_pty_ipc_entry_t *out_entries,
                                int *out_slave_fds,
                                int max_entries);

/* Re-register a single keepalive in the child after a fork-IPC. master_host_fd
 * is the child-side host fd that just landed in fd_table (its number is
 * different from the parent's). Takes ownership of slave_host_fd. The slave
 * path is recorded so /dev/pts/N opens in the child resolve to the same macOS
 * tty the parent has been talking to.
 */
void proc_pty_restore_keepalive(int master_host_fd,
                                int slave_host_fd,
                                uint32_t linux_pts_num,
                                const char *slave_path);
