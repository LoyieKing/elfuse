/*
 * /dev/shm path-syscall consistency tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Every path syscall must resolve /dev/shm/<name> to the same per-UID host
 * backing object that open() creates. The regression: LTP's setup_ipc
 * (lib/tst_test.c) does open(O_CREAT|O_EXCL) then chmod() on a /dev/shm path; a
 * split resolution turns the chmod into ENOENT and aborts every test.
 *
 * The containment half checks that no shm op follows a symlink planted at a
 * leaf: the backing store is a host directory, so a followed link escapes onto
 * the host. Each op class is driven against a symlink to a host victim, which
 * must come out untouched. stat reports the link itself (lstat), as escaping is
 * the alternative here.
 *
 * An alarm bounds the run so a regression that reintroduces a blocking open on
 * a FIFO leaf (see test_fifo_truncate_fast) fails instead of hanging CI.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* Linux tmpfs superblock magic, reported for /dev/shm and its leaves. */
#define TMPFS_MAGIC 0x01021994

/* Shm mount and leaf prefix; a leaf is SHM_DIR "name" via concatenation. */
#define SHM_ROOT "/dev/shm"
#define SHM_DIR SHM_ROOT "/"

static char shm_path[128];
static char shm_path2[128];
static char shm_link[128];
static char shm_evil[128];
static char shm_dir[128];
static char shm_fifo[128];
static char shm_exec[128];
static char victim_path[128];
static char fixture_suffix[16];
static char fixture_seed[] = "/tmp/elfuse-shm-seed-XXXXXX";

/* Guest PIDs restart from the same value in each independent elfuse process.
 * Reserve a host-unique suffix so concurrent runtime jobs cannot unlink or
 * replace one another's /dev/shm fixtures.
 */
static int name_fixtures(void)
{
    int fd = mkstemp(fixture_seed);
    if (fd < 0)
        return -1;
    close(fd);

    /* The seed stays until cleanup: mkstemp reserves a suffix only while the
     * file exists, and the fixtures below are named after it.
     */
    const char *suffix = strrchr(fixture_seed, '-');
    if (suffix == NULL || suffix[1] == '\0')
        return -1;
    snprintf(fixture_suffix, sizeof(fixture_suffix), "%s", suffix + 1);

    snprintf(shm_path, sizeof(shm_path), SHM_DIR "elfuse_paths_%s",
             fixture_suffix);
    snprintf(shm_path2, sizeof(shm_path2), SHM_DIR "elfuse_paths2_%s",
             fixture_suffix);
    snprintf(shm_link, sizeof(shm_link), SHM_DIR "elfuse_link_%s",
             fixture_suffix);
    snprintf(shm_evil, sizeof(shm_evil), SHM_DIR "elfuse_evil_%s",
             fixture_suffix);
    snprintf(shm_dir, sizeof(shm_dir), SHM_DIR "elfuse_dir_%s", fixture_suffix);
    snprintf(shm_fifo, sizeof(shm_fifo), SHM_DIR "elfuse_fifo_%s",
             fixture_suffix);
    snprintf(shm_exec, sizeof(shm_exec), SHM_DIR "elfuse_exec_%s",
             fixture_suffix);
    snprintf(victim_path, sizeof(victim_path), "/tmp/elfuse-shm-victim-%s",
             fixture_suffix);
    return 0;
}

static void cleanup_fixtures(void)
{
    unlink(shm_path);
    unlink(shm_path2);
    unlink(shm_link);
    unlink(shm_evil);
    unlink(shm_fifo);
    unlink(shm_exec);
    rmdir(shm_dir);
    unlink(victim_path);
}

/* Separate from cleanup_fixtures, which also runs once before the tests to
 * sweep fixtures a killed run left in the shm backing dir. Releasing the seed
 * there would free the suffix for another run to mint for the whole of this
 * one.
 */
static void release_fixture_seed(void)
{
    unlink(fixture_seed);
}

/* The exact LTP setup_ipc() sequence: create via open, adjust via chmod. */
static int test_open_then_chmod(void)
{
    TEST("open O_CREAT then chmod same path");
    int fd = open(shm_path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) {
        FAIL("open O_CREAT");
        return -1;
    }
    if (chmod(shm_path, 0666) != 0) {
        FAIL("chmod after open");
        close(fd);
        return -1;
    }
    struct stat fd_st, path_st;
    int ok = fstat(fd, &fd_st) == 0 && stat(shm_path, &path_st) == 0 &&
             fd_st.st_ino == path_st.st_ino && fd_st.st_dev == path_st.st_dev &&
             (path_st.st_mode & 0777) == 0666;
    close(fd);
    if (!ok) {
        FAIL("path stat disagrees with the fd the open created");
        return -1;
    }
    PASS();
    return 0;
}

static void test_metadata_ops_hit_same_object(void)
{
    TEST("chown/truncate/utimensat/access");
    if (chown(shm_path, (uid_t) -1, (gid_t) -1) != 0) {
        FAIL("chown");
        return;
    }
    if (truncate(shm_path, 4096) != 0) {
        FAIL("truncate");
        return;
    }
    struct stat st;
    if (stat(shm_path, &st) != 0 || st.st_size != 4096) {
        FAIL("truncate size not visible through path stat");
        return;
    }
    if (utimensat(AT_FDCWD, shm_path, NULL, 0) != 0) {
        FAIL("utimensat");
        return;
    }
    if (access(shm_path, R_OK | W_OK) != 0) {
        FAIL("access");
        return;
    }
    PASS();
}

/* xattr round-trips through the same backing object. A host fs that refuses
 * user xattrs (ENOTSUP) is a skip, not a failure.
 */
static void test_xattr_round_trip(void)
{
    TEST("xattr set/get on a shm path");
    static const char name[] = "user.elfuse_test";
    static const char val[] = "shmval";
    if (setxattr(shm_path, name, val, sizeof(val), 0) != 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP) {
            printf("SKIP (host xattr unsupported)\n");
            return;
        }
        FAIL("setxattr");
        return;
    }
    char buf[32];
    ssize_t n = getxattr(shm_path, name, buf, sizeof(buf));
    if (n != (ssize_t) sizeof(val) || memcmp(buf, val, sizeof(val)) != 0) {
        FAIL("getxattr mismatch");
        return;
    }
    (void) removexattr(shm_path, name);
    PASS();
}

static void test_statfs_reports_tmpfs(void)
{
    TEST("statfs on a shm leaf reports tmpfs");
    struct statfs sfs;
    if (statfs(shm_path, &sfs) != 0) {
        FAIL("statfs leaf");
        return;
    }
    if (sfs.f_type != TMPFS_MAGIC) {
        FAIL("shm leaf statfs f_type is not TMPFS_MAGIC");
        return;
    }
    if (sfs.f_namelen != 255) {
        FAIL("shm leaf statfs f_namelen is not 255");
        return;
    }
    PASS();
}

static void test_statfs_root_reports_tmpfs(void)
{
    TEST("statfs on /dev/shm reports tmpfs");
    struct statfs sfs;
    if (statfs(SHM_ROOT, &sfs) != 0) {
        FAIL("statfs /dev/shm");
        return;
    }
    if (sfs.f_type != TMPFS_MAGIC) {
        FAIL("/dev/shm statfs is not TMPFS_MAGIC");
        return;
    }

    /* A trailing slash names the same mount root (stat accepts it), so statfs
     * must answer identically rather than falling through to the host.
     */
    if (statfs(SHM_DIR, &sfs) != 0 || sfs.f_type != TMPFS_MAGIC) {
        FAIL("/dev/shm/ (trailing slash) statfs is not TMPFS_MAGIC");
        return;
    }
    PASS();
}

static void test_statfs_missing_leaf(void)
{
    TEST("statfs on an absent shm leaf is ENOENT");
    struct statfs sfs;
    errno = 0;
    EXPECT_TRUE(
        statfs(SHM_DIR "elfuse_absent_leaf", &sfs) == -1 && errno == ENOENT,
        "absent shm leaf did not report ENOENT");
}

static void test_rename_within_shm(void)
{
    TEST("rename within /dev/shm and back");
    if (rename(shm_path, shm_path2) != 0) {
        FAIL("rename away");
        return;
    }
    struct stat st;
    if (stat(shm_path, &st) == 0 || errno != ENOENT) {
        FAIL("old name still visible");
        rename(shm_path2, shm_path);
        return;
    }
    if (rename(shm_path2, shm_path) != 0) {
        FAIL("rename back");
        return;
    }
    EXPECT_TRUE(stat(shm_path, &st) == 0, "object lost across rename");
}

/* Data moved out of /dev/shm to a plain /tmp path must survive intact,
 * exercising a rename where only the source side is a shm redirect.
 */
static void test_rename_out_of_shm(void)
{
    TEST("rename /dev/shm leaf out to /tmp");
    int fd = open(shm_path2, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) {
        FAIL("create shm source");
        return;
    }
    if (write(fd, "payload", 7) != 7) {
        FAIL("write shm source");
        close(fd);
        return;
    }
    close(fd);
    if (rename(shm_path2, victim_path) != 0) {
        FAIL("rename shm->/tmp");
        return;
    }
    struct stat st;
    int ok = stat(victim_path, &st) == 0 && st.st_size == 7 &&
             stat(shm_path2, &st) == -1 && errno == ENOENT;
    unlink(victim_path);
    EXPECT_TRUE(ok, "payload did not move out of /dev/shm intact");
}

static void test_link_and_unlink(void)
{
    TEST("link then unlink second name");
    if (link(shm_path, shm_link) != 0) {
        FAIL("link");
        return;
    }
    struct stat a, b;
    int ok = stat(shm_path, &a) == 0 && stat(shm_link, &b) == 0 &&
             a.st_ino == b.st_ino;
    if (unlink(shm_link) != 0) {
        FAIL("unlink second name");
        return;
    }
    EXPECT_TRUE(ok, "hard link is a different object");
}

static void test_unlink_removes(void)
{
    TEST("unlink then stat is ENOENT");
    if (unlink(shm_path) != 0) {
        FAIL("unlink");
        return;
    }
    struct stat st;
    EXPECT_TRUE(stat(shm_path, &st) == -1 && errno == ENOENT,
                "object survived unlink");
}

/* chdir into a shm directory; getcwd must report the guest path, not the host
 * backing location.
 */
static void test_mkdir_chdir(void)
{
    TEST("mkdir + chdir into a shm directory");
    char cwd_before[256];
    if (!getcwd(cwd_before, sizeof(cwd_before))) {
        FAIL("getcwd before");
        return;
    }
    if (mkdir(shm_dir, 0700) != 0) {
        FAIL("mkdir shm dir");
        return;
    }
    if (chdir(shm_dir) != 0) {
        FAIL("chdir shm dir");
        return;
    }
    char cwd_after[256];
    int ok = getcwd(cwd_after, sizeof(cwd_after)) != NULL &&
             strcmp(cwd_after, shm_dir) == 0;
    /* Restore cwd before touching anything else. */
    if (chdir(cwd_before) != 0) {
        FAIL("chdir back");
        return;
    }
    if (rmdir(shm_dir) != 0) {
        FAIL("rmdir shm dir");
        return;
    }
    EXPECT_TRUE(ok, "getcwd leaked the host backing path");
}

/* truncate a FIFO leaf. Linux returns EINVAL immediately; the regression is an
 * O_WRONLY open blocking forever on the reader-less FIFO (caught by the alarm).
 */
static void test_fifo_truncate_fast(void)
{
    TEST("truncate on a shm FIFO fails fast, not blocks");
    if (mknod(shm_fifo, S_IFIFO | 0600, 0) != 0) {
        if (errno == EPERM || errno == ENOSYS) {
            printf("SKIP (mknod FIFO unsupported)\n");
            return;
        }
        FAIL("mknod FIFO");
        return;
    }
    errno = 0;
    int rc = truncate(shm_fifo, 0);
    int saved = errno;
    if (unlink(shm_fifo) != 0) {
        FAIL("unlink FIFO");
        return;
    }

    /* Accept EINVAL (Linux truncate-on-FIFO). The critical property is that the
     * call returned at all rather than hanging.
     */
    EXPECT_TRUE(rc == -1 && saved == EINVAL,
                "truncate on FIFO did not fail with EINVAL");
}

/* statfs on a FIFO leaf must answer from the backing dir synthetically and
 * never open the leaf (an open would risk blocking on the FIFO).
 */
static void test_statfs_fifo_no_block(void)
{
    TEST("statfs on a shm FIFO does not block");
    if (mknod(shm_fifo, S_IFIFO | 0600, 0) != 0) {
        if (errno == EPERM || errno == ENOSYS) {
            printf("SKIP (mknod FIFO unsupported)\n");
            return;
        }
        FAIL("mknod FIFO");
        return;
    }
    struct statfs sfs;
    int ok = statfs(shm_fifo, &sfs) == 0 && sfs.f_type == TMPFS_MAGIC;
    if (unlink(shm_fifo) != 0) {
        FAIL("unlink FIFO");
        return;
    }
    EXPECT_TRUE(ok, "statfs on FIFO leaf did not report tmpfs");
}

static int make_victim(void)
{
    int fd = open(victim_path, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd < 0)
        return -1;
    if (write(fd, "victim", 6) != 6) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int victim_unchanged(void)
{
    struct stat vic;
    if (stat(victim_path, &vic) != 0)
        return 0;
    return (vic.st_mode & 0777) == 0644 && vic.st_size == 6;
}

/* Create the host victim and plant a symlink to it at the shm leaf shm_evil.
 * Reports the failing step through FAIL; returns 0 on success, -1 otherwise.
 */
static int plant_symlink_victim(void)
{
    if (make_victim() != 0) {
        FAIL("create victim");
        return -1;
    }
    if (symlink(victim_path, shm_evil) != 0) {
        FAIL("symlink into /dev/shm");
        return -1;
    }
    return 0;
}

/* The central containment test: plant a symlink at a shm leaf pointing at a
 * host victim, then drive every op class that can reach the leaf. Each must
 * either fail or act on the link itself; none may reach the victim.
 */
static void test_symlink_leaf_is_not_followed(void)
{
    TEST("symlink leaf never reaches its target");
    if (plant_symlink_victim() != 0)
        return;

    /* Metadata ops: must not touch the victim. */
    (void) chmod(shm_evil, 0777);
    (void) chown(shm_evil, (uid_t) -1, (gid_t) -1);
    (void) truncate(shm_evil, 0);
    struct timeval past[2] = {{1, 0}, {1, 0}};
    (void) utimes(shm_evil, past);

    /* xattr through the symlink must not reach the victim either. */
    (void) setxattr(shm_evil, "user.elfuse_evil", "x", 1, 0);

    if (!victim_unchanged()) {
        FAIL("victim modified through the shm symlink");
        return;
    }

    /* stat reports the link (lstat semantics), not the target. */
    struct stat link_st;
    if (stat(shm_evil, &link_st) != 0 || !S_ISLNK(link_st.st_mode)) {
        FAIL("shm stat followed the symlink");
        return;
    }

    /* access() judges the link, and with a live target reports success on the
     * link's own reachability; the point is that it did not escape. Re-check
     * the victim afterwards.
     */
    (void) access(shm_evil, F_OK);
    if (!victim_unchanged()) {
        FAIL("access escaped through the shm symlink");
        return;
    }

    /* readlink is inherently nofollow and must return the raw target string. */
    char target[256];
    ssize_t n = readlink(shm_evil, target, sizeof(target) - 1);
    if (n < 0) {
        FAIL("readlink");
        return;
    }
    target[n] = '\0';
    if (strcmp(target, victim_path) != 0) {
        FAIL("readlink target mismatch");
        return;
    }

    /* open must refuse to follow the leaf. */
    errno = 0;
    if (open(shm_evil, O_RDWR) >= 0 || errno != ELOOP) {
        FAIL("open followed the shm symlink");
        return;
    }

    /* statfs must not follow onto the host filesystem. */
    struct statfs sfs;
    if (statfs(shm_evil, &sfs) == 0 && sfs.f_type != TMPFS_MAGIC) {
        FAIL("statfs followed the shm symlink onto the host");
        return;
    }

    if (unlink(shm_evil) != 0) {
        FAIL("unlink symlink");
        return;
    }
    if (unlink(victim_path) != 0) {
        FAIL("unlink victim");
        return;
    }
    PASS();
}

/* chdir must not follow a symlink-to-directory leaf out of the backing dir. */
static void test_symlink_dir_chdir_contained(void)
{
    TEST("chdir refuses a symlink-to-dir shm leaf");
    char cwd_before[256];
    if (!getcwd(cwd_before, sizeof(cwd_before))) {
        FAIL("getcwd");
        return;
    }
    /* Point the link at /tmp, a real host directory outside the backing dir. */
    if (symlink("/tmp", shm_evil) != 0) {
        FAIL("symlink to /tmp");
        return;
    }
    errno = 0;
    int rc = chdir(shm_evil);
    char cwd_after[256];
    int cwd_ok = getcwd(cwd_after, sizeof(cwd_after)) != NULL &&
                 strcmp(cwd_after, cwd_before) == 0;
    if (rc == 0)
        (void) chdir(cwd_before);
    if (unlink(shm_evil) != 0) {
        FAIL("unlink symlink");
        return;
    }

    /* Either the chdir failed (ELOOP/ENOTDIR), or if it somehow succeeded the
     * cwd must not have escaped; the strong assertion is that it failed.
     */
    EXPECT_TRUE(rc == -1 && cwd_ok, "chdir followed a symlink-to-dir shm leaf");
}

/* linkat of a symlink leaf hard-links the link itself, never its target. */
static void test_link_of_symlink_is_link_itself(void)
{
    TEST("link of a shm symlink links the link");
    if (plant_symlink_victim() != 0)
        return;
    int linked = linkat(AT_FDCWD, shm_evil, AT_FDCWD, shm_link, 0);
    int ok = 1;
    if (linked == 0) {
        struct stat st;
        /* New name must itself be a symlink (the link, not the file). */
        ok = lstat(shm_link, &st) == 0 && S_ISLNK(st.st_mode) &&
             victim_unchanged();
        (void) unlink(shm_link);
    } else {
        /* Some host filesystems reject hard-linking a symlink; that is also
         * contained. Just require the victim untouched.
         */
        ok = victim_unchanged();
    }
    (void) unlink(shm_evil);
    (void) unlink(victim_path);
    EXPECT_TRUE(ok, "link of a shm symlink reached its target");
}

/* rename of a symlink within /dev/shm moves the link, not its target. */
static void test_rename_symlink_within_shm(void)
{
    TEST("rename of a shm symlink moves the link");
    if (plant_symlink_victim() != 0)
        return;
    if (rename(shm_evil, shm_link) != 0) {
        FAIL("rename symlink");
        (void) unlink(shm_evil);
        (void) unlink(victim_path);
        return;
    }
    struct stat st;
    int ok =
        lstat(shm_link, &st) == 0 && S_ISLNK(st.st_mode) && victim_unchanged();
    (void) unlink(shm_link);
    (void) unlink(victim_path);
    EXPECT_TRUE(ok, "rename dereferenced the shm symlink");
}

/* A symlink renamed into /dev/shm from a plain path still cannot be followed,
 * covering the creation vector that bypasses sys_symlinkat.
 */
static void test_imported_symlink_contained(void)
{
    TEST("symlink renamed into shm stays contained");
    char tmp_link[128];
    snprintf(tmp_link, sizeof(tmp_link), "/tmp/elfuse-shm-implink-%s",
             fixture_suffix);
    if (make_victim() != 0) {
        FAIL("create victim");
        return;
    }
    if (symlink(victim_path, tmp_link) != 0) {
        FAIL("symlink at /tmp");
        (void) unlink(victim_path);
        return;
    }
    if (rename(tmp_link, shm_evil) != 0) {
        /* If the host refuses the cross-directory rename of a symlink, skip. */
        printf("SKIP (import rename unsupported)\n");
        (void) unlink(tmp_link);
        (void) unlink(victim_path);
        return;
    }
    (void) chmod(shm_evil, 0777);
    int ok = victim_unchanged();
    (void) unlink(shm_evil);
    (void) unlink(victim_path);
    EXPECT_TRUE(ok, "chmod followed an imported shm symlink");
}

/* execve of a symlink leaf pointing at a host binary must not run the target; a
 * real binary copied into /dev/shm must still run. Both are checked in a child
 * so a successful exec does not replace the test process.
 */
static void test_execve_symlink_contained(void)
{
    TEST("execve refuses a symlink shm leaf");
    if (symlink("/bin/true", shm_evil) != 0) {
        /* No host /bin/true visible; still assert the symlink+exec is refused
         * by pointing at a test-controlled victim path.
         */
        if (make_victim() != 0 || symlink(victim_path, shm_evil) != 0) {
            FAIL("prepare symlink");
            return;
        }
    }
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = {shm_evil, NULL};
        execv(shm_evil, argv);
        /* Reachable only if exec failed, which is the contained outcome. */
        _exit(42);
    }
    int status = 0;
    int refused = 0;
    if (pid > 0 && waitpid(pid, &status, 0) == pid)
        refused = WIFEXITED(status) && WEXITSTATUS(status) == 42;
    (void) unlink(shm_evil);
    (void) unlink(victim_path);
    EXPECT_TRUE(refused, "execve followed the shm symlink");
}

/* A real binary in /dev/shm must execute the same as anywhere else: the
 * redirect adds no barrier for legitimate files. elfuse's exec-permission model
 * independently rejects freshly-created guest binaries with EACCES regardless
 * of location, so an EACCES child is a skip, keeping this about the redirect
 * only. The child reports the execv errno as its exit code; success exits 7.
 */
static void test_execve_real_binary_runs(const char *self)
{
    TEST("execve of a real binary in /dev/shm runs");
    int in = open(self, O_RDONLY);
    if (in < 0) {
        printf("SKIP (cannot reopen self)\n");
        return;
    }
    int out = open(shm_exec, O_CREAT | O_EXCL | O_WRONLY, 0700);
    if (out < 0) {
        close(in);
        FAIL("create shm exec target");
        return;
    }
    char buf[65536];
    ssize_t r;
    int copy_ok = 1;
    while ((r = read(in, buf, sizeof(buf))) > 0) {
        if (write(out, buf, (size_t) r) != r) {
            copy_ok = 0;
            break;
        }
    }
    close(in);
    close(out);
    if (!copy_ok) {
        (void) unlink(shm_exec);
        FAIL("copy self into /dev/shm");
        return;
    }

    /* Explicit guest credentials may differ from the host file owner. */
    if (chmod(shm_exec, 0777) != 0) {
        (void) unlink(shm_exec);
        FAIL("chmod shm exec copy");
        return;
    }
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = {(char *) shm_exec, (char *) "--exec-sentinel", NULL};
        execv(shm_exec, argv);
        _exit(errno); /* report why exec failed to the parent */
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
        (void) unlink(shm_exec);
        FAIL("fork/wait for shm exec child");
        return;
    }
    (void) unlink(shm_exec);
    int code = WEXITSTATUS(status);
    if (code == 7) {
        PASS();
    } else if (code == EACCES) {
        printf("SKIP (elfuse exec-permission model rejects the copy)\n");
    } else {
        FAIL("real binary in /dev/shm failed for a shm-specific reason");
    }
}

static void test_flat_namespace_gate(void)
{
    TEST("nested and traversing names rejected");
    errno = 0;
    if (chmod(SHM_DIR "a/b", 0644) != -1 || errno != EACCES) {
        FAIL("nested name not rejected with EACCES");
        return;
    }
    errno = 0;
    if (chmod(SHM_DIR "..", 0644) != -1 || errno != EACCES) {
        FAIL("traversing name not rejected with EACCES");
        return;
    }
    PASS();
}

/* Flat names that merely contain ".." are valid shm names, the regression the
 * strstr("..") gate broke.
 */
static void test_dotdot_bearing_names_allowed(void)
{
    TEST("flat names containing .. are allowed");
    static const char *names[] = {"a..b", "..a", "a..", "..."};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char p[128];
        snprintf(p, sizeof(p), SHM_DIR "elfuse_%s_%s", fixture_suffix,
                 names[i]);
        int fd = open(p, O_CREAT | O_EXCL | O_RDWR, 0600);
        if (fd < 0) {
            FAIL("open dotdot-bearing name");
            return;
        }
        close(fd);
        if (chmod(p, 0640) != 0) {
            FAIL("chmod dotdot-bearing name");
            (void) unlink(p);
            return;
        }
        if (unlink(p) != 0) {
            FAIL("unlink dotdot-bearing name");
            return;
        }
    }
    PASS();
}

/* An over-long leaf name overflows the host backing path and must surface as
 * ENAMETOOLONG rather than a truncated resolution.
 */
static void test_oversized_name(void)
{
    TEST("oversized shm name is ENAMETOOLONG");
    char p[600];
    int off = snprintf(p, sizeof(p), SHM_DIR);
    memset(p + off, 'x', sizeof(p) - off - 1);
    p[sizeof(p) - 1] = '\0';
    errno = 0;
    EXPECT_TRUE(open(p, O_CREAT | O_RDWR, 0600) == -1 &&
                    (errno == ENAMETOOLONG || errno == EACCES),
                "oversized name was not rejected");
}

int main(int argc, char **argv)
{
    /* Re-exec sentinel used by test_execve_real_binary_runs. */
    if (argc >= 2 && strcmp(argv[1], "--exec-sentinel") == 0)
        return 7;

    /* Bound the run so a reintroduced blocking FIFO open cannot hang CI: an
     * unhandled SIGALRM ends the process. A true hang is unbounded, so this
     * still catches it while leaving headroom for a slow host.
     */
    alarm(120);

    printf("test-dev-shm-paths: /dev/shm path-syscall consistency\n");

    if (name_fixtures() < 0) {
        FAIL("reserve unique fixture suffix");
        release_fixture_seed();
        SUMMARY("test-dev-shm-paths");
        return 1;
    }
    cleanup_fixtures();

    if (test_open_then_chmod() == 0) {
        test_metadata_ops_hit_same_object();
        test_xattr_round_trip();
        test_statfs_reports_tmpfs();
        test_statfs_root_reports_tmpfs();
        test_statfs_missing_leaf();
        test_rename_within_shm();
        test_rename_out_of_shm();
        test_link_and_unlink();
        test_unlink_removes();
    }

    test_mkdir_chdir();
    test_fifo_truncate_fast();
    test_statfs_fifo_no_block();

    test_symlink_leaf_is_not_followed();
    test_symlink_dir_chdir_contained();
    test_link_of_symlink_is_link_itself();
    test_rename_symlink_within_shm();
    test_imported_symlink_contained();
    test_execve_symlink_contained();
    test_execve_real_binary_runs(argv[0]);

    test_flat_namespace_gate();
    test_dotdot_bearing_names_allowed();
    test_oversized_name();

    cleanup_fixtures();
    release_fixture_seed();

    SUMMARY("test-dev-shm-paths");
    return fails == 0 ? 0 : 1;
}
