/*
 * memfd F_SEAL_FUTURE_WRITE regression tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Existing shared mappings retain writes; future shared mappings and descriptor
 * writes honor F_SEAL_FUTURE_WRITE. Private mappings retain COW semantics.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef SYS_memfd_create
#define SYS_memfd_create 279
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif

#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif

#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE 0x0010
#endif

/* elfuse's guest page size, and the one this test binary runs with on a native
 * aarch64 kernel.
 */
#define PAGE_SZ 4096

int passes = 0, fails = 0;

static int create_memfd(void)
{
    return (int) syscall(SYS_memfd_create, "elfuse-future-write",
                         MFD_ALLOW_SEALING);
}

/* A one-page memfd holding 'O' at offset 0, sealed with F_SEAL_FUTURE_WRITE
 * through a duplicated descriptor, the way nativeDupAsReadOnly() does it.
 * Returns the writable descriptor and stores the sealed alias in *alias_out.
 */
static int sealed_memfd(int *alias_out)
{
    int fd = create_memfd();
    int alias = -1;

    if (fd < 0)
        return -1;
    if (ftruncate(fd, PAGE_SZ) != 0)
        goto fail;
    if (pwrite(fd, "O", 1, 0) != 1)
        goto fail;

    alias = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (alias < 0)
        goto fail;
    if (fcntl(alias, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) < 0) {
        close(alias);
        goto fail;
    }

    *alias_out = alias;
    return fd;

fail:
    close(fd);
    return -1;
}

/* The full ApplicationSharedMemory shape: the owner maps the region read-write
 * before the seal exists, then a duplicated descriptor seals it.
 * Returns 0 with *fd_out, *alias_out and *owner_out set.
 */
static int setup_owner_sealed(int *fd_out, int *alias_out, char **owner_out)
{
    int fd = create_memfd();
    int alias = -1;
    char *owner = MAP_FAILED;

    if (fd < 0)
        return -1;
    if (ftruncate(fd, PAGE_SZ) != 0)
        goto fail;
    if (pwrite(fd, "O", 1, 0) != 1)
        goto fail;

    owner = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (owner == MAP_FAILED)
        goto fail;

    alias = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (alias < 0)
        goto fail;
    if (fcntl(alias, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) < 0)
        goto fail;

    *fd_out = fd;
    *alias_out = alias;
    *owner_out = owner;
    return 0;

fail:
    if (alias >= 0)
        close(alias);
    if (owner != MAP_FAILED)
        munmap(owner, PAGE_SZ);
    close(fd);
    return -1;
}

/* The owner's pre-seal shared mapping must keep writing after the seal, and the
 * bytes must be visible to the file and to a read-only mapping of the sealed
 * descriptor.
 */
static void test_owner_mapping_writes_after_seal(void)
{
    TEST("owner mapping writes after seal");

    int fd = -1, alias = -1;
    char *owner = MAP_FAILED, *reader = MAP_FAILED;
    bool ok = false;

    if (setup_owner_sealed(&fd, &alias, &owner) != 0) {
        FAIL("setup failed");
        return;
    }

    owner[0] = 'A';
    char file_byte = 0;
    if (pread(fd, &file_byte, 1, 0) != 1 || file_byte != 'A') {
        FAIL("owner mapping write did not reach the file");
        goto out;
    }

    reader = mmap(NULL, PAGE_SZ, PROT_READ, MAP_SHARED, alias, 0);
    if (reader == MAP_FAILED) {
        FAIL("read-only shared mmap of the sealed fd failed");
        goto out;
    }
    if (reader[0] != 'A') {
        FAIL("read-only mapping did not observe the owner write");
        goto out;
    }

    owner[0] = 'B';
    if (reader[0] != 'B') {
        FAIL("owner mapping stopped writing after the seal");
        goto out;
    }
    ok = true;

out:
    if (reader != MAP_FAILED)
        munmap(reader, PAGE_SZ);
    munmap(owner, PAGE_SZ);
    close(alias);
    close(fd);
    if (ok)
        PASS();
}

/* A shared mapping made before the seal keeps VM_MAYWRITE: mprotect may drop
 * and restore PROT_WRITE, and the restored mapping still writes the file.
 */
static void test_pre_seal_mapping_keeps_maywrite(void)
{
    TEST("pre-seal mapping keeps VM_MAYWRITE");

    int fd = -1, alias = -1;
    char *owner = MAP_FAILED;
    bool ok = false;

    if (setup_owner_sealed(&fd, &alias, &owner) != 0) {
        FAIL("setup failed");
        return;
    }

    if (mprotect(owner, PAGE_SZ, PROT_READ) != 0) {
        FAIL("mprotect(PROT_READ) on the pre-seal mapping failed");
        goto out;
    }
    errno = 0;
    if (mprotect(owner, PAGE_SZ, PROT_READ | PROT_WRITE) != 0) {
        FAIL("mprotect restored PROT_WRITE after the seal");
        goto out;
    }

    owner[0] = 'C';
    char file_byte = 0;
    if (pread(fd, &file_byte, 1, 0) != 1 || file_byte != 'C') {
        FAIL("restored mapping did not write the file");
        goto out;
    }
    ok = true;

out:
    munmap(owner, PAGE_SZ);
    close(alias);
    close(fd);
    if (ok)
        PASS();
}

/* New shared writable mappings are refused for the whole file, whichever
 * descriptor of it is used.
 */
static void test_new_shared_writable_rejected(void)
{
    TEST("new shared writable mmap is EPERM");

    int fd = -1, alias = -1;
    void *via_alias, *via_owner;
    bool ok = false;

    fd = sealed_memfd(&alias);
    if (fd < 0) {
        FAIL("setup failed");
        return;
    }

    errno = 0;
    via_alias =
        mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, alias, 0);
    if (via_alias != MAP_FAILED || errno != EPERM) {
        FAIL("sealed alias accepted a shared writable mapping");
        if (via_alias != MAP_FAILED)
            munmap(via_alias, PAGE_SZ);
        goto out;
    }

    errno = 0;
    via_owner = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (via_owner != MAP_FAILED || errno != EPERM) {
        FAIL("sealed file accepted a shared writable mapping via its owner fd");
        if (via_owner != MAP_FAILED)
            munmap(via_owner, PAGE_SZ);
        goto out;
    }

    /* MAP_PRIVATE is still allowed, so the refusal is specific to MAP_SHARED
     * and not a blanket mmap failure.
     */
    void *priv =
        mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE, alias, 0);
    if (priv == MAP_FAILED) {
        FAIL("seal also refused a private mapping");
        goto out;
    }
    munmap(priv, PAGE_SZ);
    ok = true;

out:
    close(alias);
    close(fd);
    if (ok)
        PASS();
}

/* A read-only shared mapping made after the seal gets no VM_MAYWRITE, so
 * mprotect cannot add PROT_WRITE; the same applies to a shared PROT_NONE
 * mapping made after the seal.
 */
static void test_post_seal_shared_mapping_not_elevatable(void)
{
    TEST("post-seal shared mapping rejects mprotect write");

    int fd = -1, alias = -1;
    char *ro = MAP_FAILED, *none_map = MAP_FAILED;
    bool ok = false;

    fd = sealed_memfd(&alias);
    if (fd < 0) {
        FAIL("setup failed");
        return;
    }

    ro = mmap(NULL, PAGE_SZ, PROT_READ, MAP_SHARED, alias, 0);
    if (ro == MAP_FAILED) {
        FAIL("read-only shared mmap failed");
        goto out;
    }
    if (ro[0] != 'O') {
        FAIL("read-only mapping did not see the file contents");
        goto out;
    }

    errno = 0;
    if (mprotect(ro, PAGE_SZ, PROT_READ | PROT_WRITE) != -1 ||
        errno != EACCES) {
        FAIL("read-only mapping was elevated to writable");
        goto out;
    }
    /* Dropping protection is still allowed, and the mapping stays readable. */
    if (mprotect(ro, PAGE_SZ, PROT_READ) != 0 || ro[0] != 'O') {
        FAIL("read-only mapping stopped being usable");
        goto out;
    }

    none_map = mmap(NULL, PAGE_SZ, PROT_NONE, MAP_SHARED, alias, 0);
    if (none_map == MAP_FAILED) {
        FAIL("PROT_NONE shared mmap failed");
        goto out;
    }
    errno = 0;
    if (mprotect(none_map, PAGE_SZ, PROT_READ | PROT_WRITE) != -1 ||
        errno != EACCES) {
        FAIL("PROT_NONE shared mapping was elevated to writable");
        goto out;
    }
    ok = true;

out:
    if (none_map != MAP_FAILED)
        munmap(none_map, PAGE_SZ);
    if (ro != MAP_FAILED)
        munmap(ro, PAGE_SZ);
    close(alias);
    close(fd);
    if (ok)
        PASS();
}

/* MAP_PRIVATE stays COW-writable after the seal, including through mprotect,
 * and must not modify the file.
 */
static void test_private_mapping_stays_writable(void)
{
    TEST("private mapping stays COW-writable");

    int fd = -1, alias = -1;
    char *priv = MAP_FAILED;
    bool ok = false;

    fd = sealed_memfd(&alias);
    if (fd < 0) {
        FAIL("setup failed");
        return;
    }

    priv = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE, alias, 0);
    if (priv == MAP_FAILED) {
        FAIL("private writable mmap failed");
        goto out;
    }
    priv[0] = 'P';
    if (priv[0] != 'P') {
        FAIL("private mapping is not writable");
        goto out;
    }

    char file_byte = 0;
    if (pread(fd, &file_byte, 1, 0) != 1 || file_byte != 'O') {
        FAIL("private write reached the sealed file");
        goto out;
    }

    if (mprotect(priv, PAGE_SZ, PROT_READ) != 0 ||
        mprotect(priv, PAGE_SZ, PROT_READ | PROT_WRITE) != 0) {
        FAIL("mprotect on a private mapping failed");
        goto out;
    }
    priv[0] = 'Q';
    if (priv[0] != 'Q') {
        FAIL("private mapping lost write access after mprotect");
        goto out;
    }
    ok = true;

out:
    if (priv != MAP_FAILED)
        munmap(priv, PAGE_SZ);
    close(alias);
    close(fd);
    if (ok)
        PASS();
}

/* Every descriptor write path answers EPERM for either write seal, matching
 * shmem_write_begin; the owner fd is not exempt.
 */
static void test_descriptor_writes_rejected(void)
{
    TEST("descriptor writes are EPERM");

    int fd = -1, alias = -1;
    char byte = 'x';
    struct iovec iov = {.iov_base = &byte, .iov_len = 1};
    bool ok = false;

    fd = sealed_memfd(&alias);
    if (fd < 0) {
        FAIL("setup failed");
        return;
    }

    errno = 0;
    if (write(fd, &byte, 1) != -1 || errno != EPERM) {
        FAIL("write on the sealed owner fd succeeded");
        goto out;
    }
    errno = 0;
    if (write(alias, &byte, 1) != -1 || errno != EPERM) {
        FAIL("write on the sealed alias succeeded");
        goto out;
    }
    errno = 0;
    if (pwrite(fd, &byte, 1, 0) != -1 || errno != EPERM) {
        FAIL("pwrite on the sealed fd succeeded");
        goto out;
    }
    errno = 0;
    if (pwrite(alias, &byte, 1, 0) != -1 || errno != EPERM) {
        FAIL("pwrite on the sealed alias succeeded");
        goto out;
    }
    errno = 0;
    if (writev(fd, &iov, 1) != -1 || errno != EPERM) {
        FAIL("writev on the sealed fd succeeded");
        goto out;
    }
    errno = 0;
    if (pwritev(alias, &iov, 1, 0) != -1 || errno != EPERM) {
        FAIL("pwritev on the sealed alias succeeded");
        goto out;
    }
    ok = true;

out:
    close(alias);
    close(fd);
    if (ok)
        PASS();
}

/* Control: an unsealed memfd keeps both the descriptor write path and shared
 * writable mappings, so the refusals above come from the seal and not from
 * memfd handling in general.
 */
static void test_unsealed_memfd_still_writable(void)
{
    TEST("unsealed memfd stays writable");

    int fd = create_memfd();
    char *map = MAP_FAILED;
    bool ok = false;

    if (fd < 0) {
        FAIL("memfd_create failed");
        return;
    }
    if (ftruncate(fd, PAGE_SZ) != 0) {
        FAIL("ftruncate failed");
        goto out;
    }
    if (write(fd, "O", 1) != 1) {
        FAIL("write on an unsealed memfd failed");
        goto out;
    }

    map = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        FAIL("unsealed shared writable mmap failed");
        goto out;
    }
    map[0] = 'U';
    if (map[0] != 'U') {
        FAIL("unsealed shared mapping is not writable");
        goto out;
    }

    char file_byte = 0;
    if (pread(fd, &file_byte, 1, 0) != 1 || file_byte != 'U') {
        FAIL("unsealed shared write did not reach the file");
        goto out;
    }
    if (write(fd, "V", 1) != 1) {
        FAIL("write after mmap failed on an unsealed memfd");
        goto out;
    }
    ok = true;

out:
    if (map != MAP_FAILED)
        munmap(map, PAGE_SZ);
    close(fd);
    if (ok)
        PASS();
}

int main(void)
{
    printf("test-memfd-future-write: memfd F_SEAL_FUTURE_WRITE tests\n\n");

    test_owner_mapping_writes_after_seal();
    test_pre_seal_mapping_keeps_maywrite();
    test_new_shared_writable_rejected();
    test_post_seal_shared_mapping_not_elevatable();
    test_private_mapping_stays_writable();
    test_descriptor_writes_rejected();
    test_unsealed_memfd_still_writable();

    SUMMARY("test-memfd-future-write");
    return fails > 0 ? 1 : 0;
}
