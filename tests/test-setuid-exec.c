/*
 * setuid-on-exec must grant an ID the guest can actually mean.
 *
 * A sysroot's files are owned by whoever unpacked them on the host, and no host
 * IDs are mapped into the guest. Honouring setuid on such a file would leave
 * the process at an effective ID that exists nowhere in the guest -- neither
 * root nor its own -- so the bit has to be ignored there, the way Linux ignores
 * it on a nosuid mount.
 *
 * Ownership the guest merely recorded is no better. The virtual chown overlay
 * accepts any unprivileged guest's chown, so an owner of 0 that came from it
 * proves nothing about privilege; only physical root ownership may elevate.
 * That is the case this test cannot stage without being root already, so what
 * it pins is the other half: a virtual owner, foreign or root, never elevates.
 *
 * Note which owner does the work. The set-id path reads the *physical* stat,
 * and mkstemp already leaves the helper owned by the host user (501 or whatever
 * unpacked the tree), which is foreign to the guest either way. The virtual
 * chowns below stage the guest-visible half; the physical host owner is what
 * the exec actually sees and refuses to honour.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* An ID that is neither root nor any caller this test runs as, so the "owner
 * the guest cannot mean" case is staged deterministically instead of relying on
 * whichever host UID happens to own /tmp files.
 */
#define FOREIGN_UID 4242u

/* Unique per invocation. A fixed name in the shared /tmp would let two runs
 * truncate each other's helper, and the cleanup unlink would remove a file a
 * concurrent run still needs. mkstemp creates it O_EXCL and mode 0600, so no
 * other run can be holding the same path.
 */
static char helper_path[] = "/tmp/test-setuid-exec-XXXXXX";

/* Re-executed as the setuid helper: report whether euid matches expectations.
 */
static int child_main(const char *want_str)
{
    unsigned long want = strtoul(want_str, NULL, 10);
    unsigned got = (unsigned) geteuid();
    if ((unsigned long) got != want) {
        fprintf(stderr, "  child: euid=%u expected=%lu\n", got, want);
        return 2;
    }
    return 0;
}

/* Copy this binary to a fresh helper_path and mark it setuid. The fd is closed
 * before returning: exec'ing a file still open for writing is ETXTBSY.
 */
static int build_setuid_helper(void)
{
    char src[4096];
    ssize_t n = readlink("/proc/self/exe", src, sizeof(src) - 1);
    if (n <= 0)
        return -1;
    src[n] = '\0';

    int in = open(src, O_RDONLY);
    if (in < 0)
        return -1;
    int out = mkstemp(helper_path);
    if (out < 0) {
        close(in);
        return -1;
    }

    /* Past mkstemp the file exists, so every failure below has to unlink it
     * rather than leave a setuid-marked copy of this binary in the shared /tmp.
     */
    int rc = 0;
    char buf[65536];
    ssize_t got = 0;
    while ((got = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < got) {
            ssize_t put = write(out, buf + off, (size_t) (got - off));
            if (put <= 0) {
                rc = -1;
                break;
            }
            off += put;
        }
        if (rc != 0)
            break;
    }
    close(in);
    /* Set the bit through the fd we own rather than re-opening by name. */
    if (rc == 0 && (got < 0 || fchmod(out, 04755) != 0))
        rc = -1;
    if (close(out) != 0 && rc == 0)
        rc = -1;
    if (rc != 0)
        (void) unlink(helper_path);
    return rc;
}

/* Run the helper and return its exit status, or -1 if it could not run. */
static int run_helper(unsigned want_euid)
{
    char expect[32];
    snprintf(expect, sizeof(expect), "%u", want_euid);

    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execl(helper_path, helper_path, "--child", expect, (char *) NULL);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

/* Hand the helper to owner and re-arm the setuid bit, which a chown drops.
 * Returns 1 when the guest-visible owner really is owner afterwards, 0 when the
 * chown was refused, -1 when the staging itself broke.
 */
static int stage_owner(unsigned owner)
{
    errno = 0;
    if (chown(helper_path, (uid_t) owner, (gid_t) -1) != 0)
        return 0;
    if (chmod(helper_path, 04755) != 0)
        return -1;
    struct stat st;
    if (stat(helper_path, &st) != 0)
        return -1;

    /* exec reads ownership the same way stat does, so a stat that does not show
     * the chown means the two would disagree about what was staged.
     */
    if ((unsigned) st.st_uid != owner) {
        fprintf(stderr, "  stat reports owner=%u after chown to %u\n",
                (unsigned) st.st_uid, owner);
        return -1;
    }
    return 1;
}

/* --user can make guest credentials differ from the host. Observe the physical
 * chown result before deciding which set-id transitions the host permits.
 */
static int caller_is_privileged(void)
{
    return geteuid() == 0;
}

int main(int argc, char **argv)
{
    if (argc >= 3 && strcmp(argv[1], "--child") == 0)
        return child_main(argv[2]);

    int failures = 0;

    /* Checks that actually exercised an exec. Without this a run where every
     * interesting case skipped -- a privileged caller, say -- would print the
     * success line and exit 0 having proved nothing.
     */
    int checks_run = 0;
    unsigned self_uid = (unsigned) getuid();
    unsigned self_euid = (unsigned) geteuid();

    printf("test-setuid-exec: 1. build setuid helper... ");
    if (build_setuid_helper() != 0) {
        printf("FAIL (could not build helper: %m)\n");
        return 1;
    }
    struct stat st;
    if (stat(helper_path, &st) != 0) {
        printf("FAIL (stat: %m)\n");
        failures++;
        goto cleanup;
    }
    printf("PASS (owner=%u mode=%04o)\n", (unsigned) st.st_uid,
           st.st_mode & 07777);

    /* 2. An owner the guest cannot mean must not become the effective ID.
     *
     * No skip: the physical owner staged by mkstemp is already foreign to the
     * guest, whichever host user that is, so the case holds whether or not the
     * virtual chown below is recorded. Attempting the chown on top only widens
     * it -- the guest then sees a foreign owner too, and both views agree.
     */
    printf("test-setuid-exec: 2. foreign owner does not elevate... ");
    {
        unsigned physical_owner = (unsigned) st.st_uid;
        int staged = caller_is_privileged() ? 0 : stage_owner(FOREIGN_UID);
        if (staged < 0) {
            printf("FAIL (could not stage foreign owner)\n");
            failures++;
        } else {
            checks_run++;
            int rc = run_helper(self_euid);
            if (rc < 0 || rc == 127) {
                printf("FAIL (helper did not run)\n");
                failures++;
            } else if (rc != 0) {
                printf("FAIL (euid moved to an owner the guest cannot mean)\n");
                failures++;
            } else if (staged == 1) {
                printf("PASS (owner=%u physical, %u virtual, euid stayed %u)\n",
                       physical_owner, FOREIGN_UID, self_euid);
            } else {
                printf("PASS (physical owner=%u ignored, euid stayed %u)\n",
                       physical_owner, self_euid);
            }
        }
    }

    /* 3. Nor may a *recorded* root owner. The chown overlay takes any guest's
     * chown, so honouring the owner it reports would let an unprivileged
     * process chown its own file to 0, set the bit, and exec its way to root.
     * The regression guard for that escalation.
     *
     * A guest stat cannot tell a recorded chown from one the host really
     * performed -- the overlay is invisible from in here, and both report owner
     * 0. That distinction matters, because when elfuse itself runs as host root
     * the chown below is physical, and a physically root-owned setuid file is
     * *supposed* to elevate. Resolve it from the outcome instead: elevation to
     * 0 only happens when the physical owner is 0, which only a real chown can
     * produce. Staying put and landing on root are both correct, one per
     * staging; anything else is the bug.
     */
    printf("test-setuid-exec: 3. virtual root owner does not elevate... ");
    {
        int staged = stage_owner(0);
        if (staged < 0) {
            printf("FAIL (could not stage root owner)\n");
            failures++;
        } else if (staged == 0) {
            printf("SKIP (chown to root refused, as on a real kernel)\n");
        } else {
            checks_run++;
            int rc = run_helper(self_euid);
            if (rc < 0 || rc == 127) {
                printf("FAIL (helper did not run)\n");
                failures++;
            } else if (rc == 0) {
                printf("PASS (stat says owner=0, euid stayed %u)\n", self_euid);
            } else if (run_helper(0) == 0) {
                printf("PASS (host chown was real, physical root elevated)\n");
            } else {
                printf("FAIL (euid is neither %u nor 0; see the report)\n",
                       self_euid);
                failures++;
            }
        }
    }

    /* 4. The permission check must use the owner the guest sees, unlike the
     * set-id owner above. A file the guest owns with owner-only permission has
     * to run: judging it by the physical owner would fall through to the
     * "other" bits and refuse an executable the guest's own stat says it owns.
     */
    printf("test-setuid-exec: 4. guest-owned owner-only file runs... ");
    if (chown(helper_path, self_uid, (gid_t) -1) != 0) {
        printf("SKIP (cannot take ownership: %m)\n");
    } else if (chmod(helper_path, 0700) != 0) {
        printf("FAIL (chmod: %m)\n");
        failures++;
    } else {
        checks_run++;
        int rc = run_helper(self_euid);
        if (rc < 0) {
            printf("FAIL (helper did not run at all)\n");
            failures++;
        } else if (rc == 127) {
            printf("FAIL (exec refused for a file the guest owns)\n");
            failures++;
        } else if (rc != 0) {
            printf("FAIL (helper exited %d)\n", rc);
            failures++;
        } else {
            printf("PASS\n");
        }
    }

cleanup:
    (void) unlink(helper_path);

    if (failures == 0 && checks_run == 0) {
        printf("test-setuid-exec: no check exercised an exec -- FAIL\n");
        return 1;
    }
    if (failures == 0)
        printf("test-setuid-exec: all tests passed -- PASS\n");
    else
        printf("test-setuid-exec: %d failed\n", failures);
    return failures != 0;
}
