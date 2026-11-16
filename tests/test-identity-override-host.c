/*
 * Host-side unit test for ELFUSE_FAKEROOT environment overrides and the --user
 * and --pid/--ppid staging protocols.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The staging cases are regression guards for the proc_set_initial_ids and
 * proc_set_initial_identity contracts in proc.h. No launcher performs two
 * bring-ups in one host process, so a regression shows up as the wrong
 * uid/gid or pid/ppid below rather than as a launch failure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>

#include "syscall/proc.h"
#include "syscall/proc-identity.h"

/* Mock shim_globals_publish_pgsid to avoid linking the entire guest shim
 * subsystem
 */
void shim_globals_publish_pgsid(guest_t *g, int64_t pgid, int64_t sid);
void shim_globals_publish_pgsid(guest_t *g, int64_t pgid, int64_t sid)
{
    (void) g;
    (void) pgid;
    (void) sid;
}

int thread_tid_alive(int64_t tid);
int thread_tid_alive(int64_t tid)
{
    (void) tid;
    return 0;
}

/* The identity initializer republishes the peer identity; the process
 * registry that owns the record is not linked here.
 */
void proc_peer_identity_publish(void) {}

int main(void)
{
    /* Test 1: Fallback case (fakeroot disabled) */
    unsetenv("ELFUSE_FAKEROOT");
    proc_set_fakeroot_enabled(false);
    proc_identity_init();

    assert(proc_get_uid() == getuid());
    assert(proc_get_euid() == geteuid());
    assert(proc_get_suid() == geteuid());
    assert(proc_get_gid() == getgid());
    assert(proc_get_egid() == getegid());
    assert(proc_get_sgid() == getegid());
    assert(proc_fakeroot_enabled() == false);

    /* Test 2: Enable via API */
    proc_set_fakeroot_enabled(true);
    proc_identity_init();

    assert(proc_get_uid() == 0);
    assert(proc_get_euid() == 0);
    assert(proc_get_suid() == 0);
    assert(proc_get_gid() == 0);
    assert(proc_get_egid() == 0);
    assert(proc_get_sgid() == 0);
    assert(proc_fakeroot_enabled() == true);

    /* Test 3: Enable via Env Var (ELFUSE_FAKEROOT=1) */
    proc_set_fakeroot_enabled(false);
    setenv("ELFUSE_FAKEROOT", "1", 1);

    bool fakeroot = false;
    const char *fakeroot_env = getenv("ELFUSE_FAKEROOT");
    if (fakeroot_env && strcmp(fakeroot_env, "1") == 0)
        fakeroot = true;
    proc_set_fakeroot_enabled(fakeroot);
    proc_identity_init();

    assert(proc_get_uid() == 0);
    assert(proc_get_gid() == 0);
    assert(proc_fakeroot_enabled() == true);

    /* Test 4: Env Var other than 1 should not enable fakeroot */
    setenv("ELFUSE_FAKEROOT", "0", 1);
    fakeroot = false;
    fakeroot_env = getenv("ELFUSE_FAKEROOT");
    if (fakeroot_env && strcmp(fakeroot_env, "1") == 0)
        fakeroot = true;
    proc_set_fakeroot_enabled(fakeroot);
    proc_identity_init();
    assert(proc_get_uid() == getuid());
    assert(proc_get_gid() == getgid());
    assert(proc_fakeroot_enabled() == false);

    /* Test 5: consume-once. A leftover would leak one launch's --user into the
     * next launch of the same host process.
     */
    proc_set_fakeroot_enabled(false);
    proc_set_initial_ids(1234, 5678);
    proc_identity_init();
    assert(proc_get_uid() == 1234);
    assert(proc_get_euid() == 1234);
    assert(proc_get_suid() == 1234);
    assert(proc_get_gid() == 5678);
    assert(proc_get_egid() == 5678);
    assert(proc_get_sgid() == 5678);

    proc_identity_init();
    assert(proc_get_uid() == getuid());
    assert(proc_get_gid() == getgid());

    /* Test 6: the elfuse_launch fail path drops the staging
     * (proc_clear_initial_ids contract in proc.h).
     */
    proc_set_initial_ids(1234, 5678);
    proc_clear_initial_ids();
    proc_identity_init();
    assert(proc_get_uid() == getuid());
    assert(proc_get_euid() == geteuid());
    assert(proc_get_gid() == getgid());
    assert(proc_get_egid() == getegid());

    /* Test 7: --pid/--ppid staging. A staged identity also becomes the
     * process's session and process group, so getpid/getppid and the /proc
     * group view agree.
     */
    proc_set_fakeroot_enabled(false);
    proc_identity_init();
    assert(proc_get_pid() == 1);
    assert(proc_get_ppid() == 0);
    assert(proc_get_sid() == 1);
    assert(proc_get_pgid() == 1);

    assert(proc_set_initial_identity(4242, 4241));
    proc_identity_init();
    assert(proc_get_pid() == 4242);
    assert(proc_get_ppid() == 4241);
    assert(proc_get_sid() == 4242);
    assert(proc_get_pgid() == 4242);

    /* Consume-once, like --user. */
    proc_identity_init();
    assert(proc_get_pid() == 1);
    assert(proc_get_ppid() == 0);

    /* Test 8: the elfuse_launch fail path drops the staging. */
    assert(proc_set_initial_identity(4242, 4241));
    proc_clear_initial_identity();
    proc_identity_init();
    assert(proc_get_pid() == 1);
    assert(proc_get_ppid() == 0);

    /* Test 9: the CLI bounds. A rejected staging leaves the previous one
     * intact, and INT_MAX / a zero PPID are both valid.
     */
    assert(!proc_set_initial_identity(0, 0));
    assert(!proc_set_initial_identity(-1, 0));
    assert(!proc_set_initial_identity((int64_t) INT_MAX + 1, 0));
    assert(!proc_set_initial_identity(1, -1));
    assert(!proc_set_initial_identity(1, (int64_t) INT_MAX + 1));

    assert(proc_set_initial_identity(INT_MAX, 0));
    assert(!proc_set_initial_identity((int64_t) INT_MAX + 1, 0));
    proc_identity_init();
    assert(proc_get_pid() == INT_MAX);
    assert(proc_get_ppid() == 0);

    /* Test 10: the descendant allocator reserves the identity's PID and PPID.
     * Both candidates below are already assigned, so a first allocation must
     * skip to 4 (tests/test-initial-identity.c observes the fork result).
     */
    assert(proc_set_initial_identity(2, 3));
    proc_identity_init();
    assert(proc_pid_is_reserved(2));
    assert(proc_pid_is_reserved(3));
    assert(!proc_pid_is_reserved(4));
    assert(!proc_pid_is_reserved(0));
    assert(!proc_pid_is_reserved(-1));

    uid_t host_uid = getuid(), host_euid = geteuid();
    gid_t host_gid = getgid(), host_egid = getegid();
    proc_set_fakeroot_enabled(true);
    proc_identity_init();
    assert(proc_sys_setgid(5678) == 0);
    assert(proc_sys_setuid(1234) == 0);
    assert(proc_get_uid() == 1234 && proc_get_gid() == 5678);
    assert(getuid() == host_uid && geteuid() == host_euid);
    assert(getgid() == host_gid && getegid() == host_egid);
    proc_set_fakeroot_enabled(false);
    proc_identity_init();

    printf("test-identity-override-host: PASS\n");
    return 0;
}
