#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

#include "core/guest.h"

struct thread_entry;

void fuse_init(void);
void fuse_task_cancel_wait(struct thread_entry *t);

int64_t sys_mount(guest_t *g,
                  uint64_t source_gva,
                  uint64_t target_gva,
                  uint64_t fstype_gva,
                  unsigned long flags,
                  uint64_t data_gva);

int fuse_proc_open(int linux_flags);
int fuse_proc_stat(struct stat *st);

int64_t fuse_open_path(guest_t *g, const char *path, int linux_flags, int mode);
bool fuse_path_matches_mount(const char *path);

/* Returns the mount_id of the FUSE mount containing path, or -1 if path is not
 * inside any live or tombstoned FUSE mount. Distinct FUSE mounts have distinct
 * mount_ids; used by RESOLVE_NO_XDEV to detect cross-mount paths.
 */
int fuse_path_mount_id(const char *path);

/* Stat a FUSE-mounted path. at_flags carries the Linux AT_* mask from the
 * caller; only LINUX_AT_SYMLINK_NOFOLLOW is consulted today. When the daemon
 * returns S_IFLNK for the final component and the caller did not request
 * NOFOLLOW, the call surfaces -LINUX_ENOSYS because symlink target resolution
 * is not implemented yet. With NOFOLLOW the symlink's own attrs are returned
 * unchanged.
 */
int fuse_stat_path(const char *path, struct stat *st, int at_flags);
int fuse_access_path(const char *path, int mode, int flags);
int fuse_materialize_path(const char *path, char *out_path, size_t outsz);
int fuse_materialize_fd(int fd, char *out_path, size_t outsz);
int fuse_fstat_fd(int fd, struct stat *st);
int64_t fuse_getdents64(guest_t *g, int fd, uint64_t buf_gva, uint64_t count);
int64_t fuse_read_fd(guest_t *g, int fd, uint64_t buf_gva, uint64_t count);
int64_t fuse_pread_fd(guest_t *g,
                      int fd,
                      uint64_t buf_gva,
                      uint64_t count,
                      int64_t offset);
int64_t fuse_dev_read(int guest_fd,
                      guest_t *g,
                      uint64_t buf_gva,
                      uint64_t count);
int64_t fuse_dev_write(guest_t *g,
                       int guest_fd,
                       uint64_t buf_gva,
                       uint64_t count);

bool fuse_is_file_fd(int fd);
bool fuse_is_dir_fd(int fd);
bool fuse_fd_refuse_mmap(int fd);

/* Move the per-fd offset for a FUSE-backed regular file.
 *
 * Returns the new offset on success or a negative Linux errno. /dev/fuse
 * returns -ESPIPE (stream-like, no absolute position); FUSE-backed regular
 * files and directories are seekable.
 */
int64_t fuse_lseek_fd(int fd, int64_t offset, int whence);
int64_t fuse_fchdir(int fd);
int fuse_dup_fd(int src_fd,
                int min_guest_fd,
                int fixed_guest_fd,
                bool fixed_slot,
                int linux_flags);
int fuse_resolve_at_path(int dirfd, const char *path, char *out, size_t outsz);
int fuse_fd_mnt_id(int fd, int *mnt_id_out);
int fuse_append_mountinfo(char *buf, size_t bufsz, size_t *off);
int fuse_append_mounts(char *buf, size_t bufsz, size_t *off);
