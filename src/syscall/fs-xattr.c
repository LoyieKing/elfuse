/*
 * Extended attribute syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>

#include "core/guest.h"

#include "syscall/linux-wire.h"
#include "syscall/fs.h"
#include "syscall/internal.h"
#include "syscall/path.h"

/* macOS xattr API has extra position and options parameters vs Linux. Linux:
 * getxattr(path, name, value, size) macOS: getxattr(path, name, value, size,
 * position, options) The xattr shim passes position=0, options=0 for normal
 * operation, and options=XATTR_NOFOLLOW for lgetxattr/lsetxattr/etc.
 */

#define LINUX_XATTR_NAME_MAX 255
#define LINUX_XATTR_SIZE_MAX 65536
#define LINUX_XATTR_CREATE 1
#define LINUX_XATTR_REPLACE 2

static int xattr_translate_flags(int flags, int *opts)
{
    if ((flags & ~(LINUX_XATTR_CREATE | LINUX_XATTR_REPLACE)) != 0 ||
        flags == (LINUX_XATTR_CREATE | LINUX_XATTR_REPLACE))
        return -LINUX_EINVAL;

    if (flags & LINUX_XATTR_CREATE)
        *opts |= XATTR_CREATE;
    if (flags & LINUX_XATTR_REPLACE)
        *opts |= XATTR_REPLACE;
    return 0;
}

static int64_t xattr_alloc_buf(uint64_t size, void **buf)
{
    if (size > LINUX_XATTR_SIZE_MAX)
        return -LINUX_E2BIG;
    if (size == 0) {
        *buf = NULL;
        return 0;
    }

    *buf = malloc((size_t) size);
    return *buf ? 0 : -LINUX_ENOMEM;
}

/* The memfd marker is host metadata on an unlinked backing file. Exact-name
 * calls answer the way Linux answers an unknown xattr namespace, and the list
 * calls drop the name, so no guest entry point can see or change the identity.
 */
static bool xattr_name_reserved(const char *name)
{
    return strcmp(name, FD_MEMFD_XATTR_NAME) == 0;
}

/* Resolve a path-based xattr call and derive the macOS options flag.
 *
 * One choke point for two facts each entry point below would otherwise carry
 * for itself: a FUSE-backed path has no xattrs, and a shm redirect is never
 * followed whatever the caller asked. See dev_shm_resolve_path() in procemu.c
 * for the invariant, and path_translation_at_flags() for its *at form.
 *
 * Returns the macOS options flag with tx filled, or a negative Linux errno. The
 * flag is 0 or XATTR_NOFOLLOW, so the sign separates the two.
 */
static int xattr_resolve_path(const char *path,
                              int nofollow,
                              path_translation_t *tx)
{
    if (path_translate_at(LINUX_AT_FDCWD, path, path_tr_nofollow(nofollow),
                          tx) < 0)
        return linux_errno();
    int64_t fuse_rc = reject_unsupported_fuse_path_op(tx);
    if (fuse_rc != INT64_MIN)
        return (int) fuse_rc;

    return (nofollow || tx->is_dev_shm) ? XATTR_NOFOLLOW : 0;
}

static int64_t xattr_copy_out_result(guest_t *g,
                                     uint64_t dst_gva,
                                     void *buf,
                                     ssize_t ret)
{
    if (ret < 0)
        return linux_errno();
    if (guest_write(g, dst_gva, buf, (size_t) ret) < 0)
        return -LINUX_EFAULT;
    return ret;
}

/* Drop the reserved name from a host xattr list of @len bytes. Host and Linux
 * both spell a list as NUL-terminated names; an unterminated tail is ignored
 * rather than copied out.
 */
static size_t xattr_list_filter(char *list, size_t len)
{
    size_t in = 0;
    size_t out = 0;

    while (in < len) {
        size_t name_len = strnlen(list + in, len - in);
        size_t entry_len;

        if (name_len == len - in)
            break;
        entry_len = name_len + 1;
        if (!xattr_name_reserved(list + in)) {
            if (out != in)
                memcpy(list + out, list + in, entry_len);
            out += entry_len;
        }
        in += entry_len;
    }
    return out;
}

/* Fetch the full host list so the reserved name can be removed before the
 * caller's size decides success, then report or copy the filtered list. The
 * guest buffer ceiling bounds this fetch too: a larger aggregate could not be
 * copied out by the call that asked for it.
 */
static int64_t xattr_list_emit(guest_t *g,
                               const char *host_path,
                               int fd,
                               int opts,
                               uint64_t list_gva,
                               uint64_t size)
{
    ssize_t total = fd >= 0 ? flistxattr(fd, NULL, 0, 0)
                            : listxattr(host_path, NULL, 0, opts);
    if (total < 0)
        return linux_errno();
    if (total == 0)
        return 0;
    if (total > LINUX_XATTR_SIZE_MAX)
        return -LINUX_E2BIG;

    char *list = malloc((size_t) total);
    if (!list)
        return -LINUX_ENOMEM;
    ssize_t got = fd >= 0 ? flistxattr(fd, list, (size_t) total, 0)
                          : listxattr(host_path, list, (size_t) total, opts);
    if (got < 0) {
        int64_t err = linux_errno();
        free(list);
        return err;
    }
    size_t kept = xattr_list_filter(list, (size_t) (got > total ? total : got));
    if (size != 0 && kept > size) {
        free(list);
        return -LINUX_ERANGE;
    }
    int64_t result =
        size == 0 ? (int64_t) kept
                  : xattr_copy_out_result(g, list_gva, list, (ssize_t) kept);
    free(list);
    return result;
}

int64_t sys_getxattr(guest_t *g,
                     uint64_t path_gva,
                     uint64_t name_gva,
                     uint64_t value_gva,
                     uint64_t size,
                     int nofollow)
{
    char path[LINUX_PATH_MAX], name[LINUX_XATTR_NAME_MAX + 1];
    if (guest_read_str(g, path_gva, path, sizeof(path)) < 0)
        return -LINUX_EFAULT;
    if (guest_read_str(g, name_gva, name, sizeof(name)) < 0)
        return -LINUX_EFAULT;

    path_translation_t tx;
    int opts = xattr_resolve_path(path, nofollow, &tx);
    if (opts < 0)
        return opts;

    if (xattr_name_reserved(name))
        return -LINUX_EOPNOTSUPP;

    if (size == 0) {
        ssize_t ret = getxattr(tx.host_path, name, NULL, 0, 0, opts);
        return ret < 0 ? linux_errno() : ret;
    }

    void *buf;
    int64_t err = xattr_alloc_buf(size, &buf);
    if (err < 0)
        return err;

    ssize_t ret = getxattr(tx.host_path, name, buf, (size_t) size, 0, opts);
    int64_t result = xattr_copy_out_result(g, value_gva, buf, ret);
    free(buf);
    return result;
}

int64_t sys_setxattr(guest_t *g,
                     uint64_t path_gva,
                     uint64_t name_gva,
                     uint64_t value_gva,
                     uint64_t size,
                     int flags,
                     int nofollow)
{
    char path[LINUX_PATH_MAX], name[LINUX_XATTR_NAME_MAX + 1];
    if (guest_read_str(g, path_gva, path, sizeof(path)) < 0)
        return -LINUX_EFAULT;
    if (guest_read_str(g, name_gva, name, sizeof(name)) < 0)
        return -LINUX_EFAULT;

    path_translation_t tx;
    int opts = xattr_resolve_path(path, nofollow, &tx);
    if (opts < 0)
        return opts;

    if (xattr_name_reserved(name))
        return -LINUX_EOPNOTSUPP;
    int64_t err;

    void *buf;
    err = xattr_alloc_buf(size, &buf);
    if (err < 0)
        return err;
    if (size > 0 && guest_read(g, value_gva, buf, (size_t) size) < 0) {
        free(buf);
        return -LINUX_EFAULT;
    }

    err = xattr_translate_flags(flags, &opts);
    if (err < 0) {
        free(buf);
        return err;
    }

    int ret = setxattr(tx.host_path, name, buf, (size_t) size, 0, opts);
    free(buf);
    return ret < 0 ? linux_errno() : 0;
}

int64_t sys_listxattr(guest_t *g,
                      uint64_t path_gva,
                      uint64_t list_gva,
                      uint64_t size,
                      int nofollow)
{
    char path[LINUX_PATH_MAX];
    if (guest_read_str(g, path_gva, path, sizeof(path)) < 0)
        return -LINUX_EFAULT;

    path_translation_t tx;
    int opts = xattr_resolve_path(path, nofollow, &tx);
    if (opts < 0)
        return opts;

    return xattr_list_emit(g, tx.host_path, -1, opts, list_gva, size);
}

int64_t sys_removexattr(guest_t *g,
                        uint64_t path_gva,
                        uint64_t name_gva,
                        int nofollow)
{
    char path[LINUX_PATH_MAX], name[LINUX_XATTR_NAME_MAX + 1];
    if (guest_read_str(g, path_gva, path, sizeof(path)) < 0)
        return -LINUX_EFAULT;
    if (guest_read_str(g, name_gva, name, sizeof(name)) < 0)
        return -LINUX_EFAULT;

    path_translation_t tx;
    int opts = xattr_resolve_path(path, nofollow, &tx);
    if (opts < 0)
        return opts;

    if (xattr_name_reserved(name))
        return -LINUX_EOPNOTSUPP;
    int ret = removexattr(tx.host_path, name, opts);
    return ret < 0 ? linux_errno() : 0;
}

int64_t sys_fgetxattr(guest_t *g,
                      int fd,
                      uint64_t name_gva,
                      uint64_t value_gva,
                      uint64_t size)
{
    host_fd_ref_t host_ref;
    int64_t ref_err = host_fd_ref_open(fd, &host_ref);
    if (ref_err < 0)
        return ref_err;

    char name[LINUX_XATTR_NAME_MAX + 1];
    if (guest_read_str(g, name_gva, name, sizeof(name)) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    if (xattr_name_reserved(name)) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EOPNOTSUPP;
    }

    if (size == 0) {
        ssize_t ret = fgetxattr(host_ref.fd, name, NULL, 0, 0, 0);
        host_fd_ref_close(&host_ref);
        return ret < 0 ? linux_errno() : ret;
    }

    void *buf;
    int64_t err = xattr_alloc_buf(size, &buf);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }

    ssize_t ret = fgetxattr(host_ref.fd, name, buf, (size_t) size, 0, 0);
    int64_t result = xattr_copy_out_result(g, value_gva, buf, ret);
    free(buf);
    host_fd_ref_close(&host_ref);
    return result;
}

int64_t sys_fsetxattr(guest_t *g,
                      int fd,
                      uint64_t name_gva,
                      uint64_t value_gva,
                      uint64_t size,
                      int flags)
{
    host_fd_ref_t host_ref;

    /* Linux: fsetxattr on an O_PATH fd returns EBADF (the descriptor lacks the
     * write reference required by mnt_want_write_file).
     */
    int64_t err = host_fd_ref_open_io(fd, &host_ref);
    if (err < 0)
        return err;

    char name[LINUX_XATTR_NAME_MAX + 1];
    if (guest_read_str(g, name_gva, name, sizeof(name)) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    if (xattr_name_reserved(name)) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EOPNOTSUPP;
    }

    void *buf;
    err = xattr_alloc_buf(size, &buf);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }
    if (size > 0 && guest_read(g, value_gva, buf, (size_t) size) < 0) {
        free(buf);
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    int opts = 0;
    err = xattr_translate_flags(flags, &opts);
    if (err < 0) {
        free(buf);
        host_fd_ref_close(&host_ref);
        return err;
    }

    int ret = fsetxattr(host_ref.fd, name, buf, (size_t) size, 0, opts);
    int64_t result = ret < 0 ? linux_errno() : 0;
    free(buf);
    host_fd_ref_close(&host_ref);
    return result;
}

int64_t sys_flistxattr(guest_t *g, int fd, uint64_t list_gva, uint64_t size)
{
    host_fd_ref_t host_ref;
    int64_t ref_err = host_fd_ref_open(fd, &host_ref);
    if (ref_err < 0)
        return ref_err;

    int64_t result = xattr_list_emit(g, NULL, host_ref.fd, 0, list_gva, size);
    host_fd_ref_close(&host_ref);
    return result;
}

int64_t sys_fremovexattr(guest_t *g, int fd, uint64_t name_gva)
{
    host_fd_ref_t host_ref;

    /* Linux: fremovexattr on an O_PATH fd returns EBADF, same reason as
     * fsetxattr above.
     */
    int64_t err = host_fd_ref_open_io(fd, &host_ref);
    if (err < 0)
        return err;

    char name[LINUX_XATTR_NAME_MAX + 1];
    if (guest_read_str(g, name_gva, name, sizeof(name)) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    if (xattr_name_reserved(name)) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EOPNOTSUPP;
    }

    int ret = fremovexattr(host_ref.fd, name, 0);
    host_fd_ref_close(&host_ref);
    return ret < 0 ? linux_errno() : 0;
}
