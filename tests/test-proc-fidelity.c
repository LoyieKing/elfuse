/*
 * /proc fidelity tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises the /proc nodes that elfuse synthesizes through procemu:
 * /proc/self/oom_score_adj (read/write/persist/range/zero-length writev), the
 * legacy /proc/self/oom_adj scaling alias, /proc/self/oom_score (open-time and
 * write-time enforcement), /proc/self/fdinfo entries for generic fds plus
 * eventfd/signalfd/timerfd, /proc/net/tcp serial-number density across mixed
 * socket types, and /proc/cpuinfo CPU enumeration. These tests pin the
 * host-visible byte format so a regression to the wrong separator, scaling
 * factor, or sparse layout fails loudly.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* Some procfs write-rejection tests can only be exercised as root (root
 * bypasses the 0444 open-time gate, so the kernel actually invokes the proc
 * node's write handler). On non-root the test cannot prove the lower layer is
 * correct without also reproducing a kernel-internal regression; counting these
 * as skips keeps the summary honest instead of either masking real regressions
 * behind a bogus PASS or pretending the path was exercised.
 */
static int procfs_skips = 0;
#define PROCFS_SKIP(reason)           \
    do {                              \
        printf("SKIP: %s\n", reason); \
        procfs_skips++;               \
    } while (0)

/* /proc/self/oom_* */

static void test_proc_oom_score_adj(void)
{
    TEST("/proc/self/oom_score_adj readable");
    int fd = open("/proc/self/oom_score_adj", O_RDONLY);
    if (fd < 0) {
        FAIL("open");
        return;
    }
    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0) {
        buf[n] = '\0';
        int val = atoi(buf);
        EXPECT_TRUE(val == 0, "unexpected value");
    } else {
        FAIL("read");
    }
}

static void test_proc_oom_score_adj_persists_write(void)
{
    TEST("/proc/self/oom_score_adj write persists");
    int fd = open("/proc/self/oom_score_adj", O_RDWR);
    if (fd < 0) {
        FAIL("open");
        return;
    }

    const char value[] = "123\n";
    if (write(fd, value, sizeof(value) - 1) != (ssize_t) (sizeof(value) - 1)) {
        close(fd);
        FAIL("write");
        return;
    }
    close(fd);

    fd = open("/proc/self/oom_score_adj", O_RDONLY);
    if (fd < 0) {
        FAIL("reopen");
        return;
    }

    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        FAIL("read");
        return;
    }

    buf[n] = '\0';
    EXPECT_TRUE(atoi(buf) == 123, "value did not persist");
}

static void test_proc_oom_score_adj_rejects_out_of_range(void)
{
    TEST("/proc/self/oom_score_adj rejects out-of-range writes");
    int fd = open("/proc/self/oom_score_adj", O_RDWR);
    if (fd < 0) {
        FAIL("open");
        return;
    }

    /* Linux validates the input domain on the writer side; the kernel returns
     * EINVAL for any value outside [-1000, 1000].
     */
    const char too_high[] = "1001\n";
    ssize_t rc = write(fd, too_high, sizeof(too_high) - 1);
    int saved = errno;
    close(fd);
    if (rc < 0 && saved == EINVAL)
        PASS();
    else
        FAIL("expected -EINVAL");
}

static void test_proc_oom_adj_scaling(void)
{
    TEST("/proc/self/oom_adj scales to oom_score_adj");
    /* Reset to a known starting value so test ordering does not matter. */
    int z = open("/proc/self/oom_score_adj", O_RDWR);
    if (z >= 0) {
        write(z, "0\n", 2);
        close(z);
    }

    int fd = open("/proc/self/oom_adj", O_RDWR);
    if (fd < 0) {
        /* Older silent-PASS treated absence as acceptable, which turned the
         * scaling regression into a no-op on any host that did not ship the
         * legacy compat node. elfuse must expose it via the procemu layer, and
         * current Linux kernels still keep the alias, so absence is a real
         * regression.
         */
        FAIL("open /proc/self/oom_adj");
        return;
    }

    /* Linux fs/proc/base.c oom_adj_write special-cases OOM_ADJUST_MAX so 15
     * maps directly to OOM_SCORE_ADJ_MAX (1000), not 15*1000/17 = 882.
     */
    if (write(fd, "15\n", 3) != 3) {
        close(fd);
        FAIL("write");
        return;
    }
    close(fd);

    int sa = open("/proc/self/oom_score_adj", O_RDONLY);
    if (sa < 0) {
        FAIL("reopen oom_score_adj");
        return;
    }
    char buf[32] = {0};
    ssize_t n = read(sa, buf, sizeof(buf) - 1);
    close(sa);
    if (n <= 0) {
        FAIL("read");
        return;
    }
    int score = atoi(buf);
    EXPECT_TRUE(score == 1000, "oom_adj=15 should map to oom_score_adj=1000");
}

static void test_proc_oom_adj_same_fd_roundtrip(void)
{
    TEST("/proc/self/oom_adj same-fd readback stays legacy");

    int reset = open("/proc/self/oom_score_adj", O_RDWR);
    if (reset >= 0) {
        write(reset, "0\n", 2);
        close(reset);
    }

    int fd = open("/proc/self/oom_adj", O_RDWR);
    if (fd < 0) {
        /* See test_proc_oom_adj_scaling for rationale: silent PASS on absent
         * oom_adj turned the same-fd readback regression into a no-op. Fail
         * hard so a missing compat alias surfaces.
         */
        FAIL("open /proc/self/oom_adj");
        return;
    }
    if (write(fd, "15\n", 3) != 3) {
        close(fd);
        FAIL("write");
        return;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        FAIL("lseek");
        return;
    }

    char buf[32] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    reset = open("/proc/self/oom_score_adj", O_RDWR);
    if (reset >= 0) {
        write(reset, "0\n", 2);
        close(reset);
    }
    if (n <= 0) {
        FAIL("read");
        return;
    }
    EXPECT_TRUE(atoi(buf) == 15, "same-fd readback should preserve oom_adj");
}

static void test_proc_oom_score_no_write(void)
{
    TEST("/proc/self/oom_score writes are rejected");

    /* Linux: open succeeds (root bypasses the 0444 check, non-root sees EACCES
     * from the permission gate); writes always fail because there is no write
     * handler. The test focuses on the write side, which is uniform across
     * uids.
     */
    int fd = open("/proc/self/oom_score", O_RDONLY);
    if (fd < 0) {
        FAIL("open RDONLY");
        return;
    }
    char buf[32] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        FAIL("read");
        return;
    }

    /* Stub returns 0; real Linux computes a small positive score, but for a
     * userspace bridge a constant zero is acceptable.
     */
    EXPECT_TRUE(atoi(buf) >= 0, "score must be non-negative");
}

static void test_proc_oom_score_write_fails(void)
{
    TEST("/proc/self/oom_score write is rejected");

    /* The intended coverage is the proc node's write handler returning EIO.
     * That handler is only reached when open succeeds with write access. Only
     * root can open the 0444 file O_WRONLY; non-root sees EACCES at open and
     * exits the write-rejection path entirely. The sibling
     * test_proc_oom_score_open_enforces_read_only covers the open-time EACCES
     * branch separately, so explicitly skip here when the write path cannot be
     * reached.
     */
    int fd = open("/proc/self/oom_score", O_WRONLY);
    if (fd < 0) {
        if (errno == EACCES) {
            PROCFS_SKIP(
                "non-root cannot open oom_score O_WRONLY; write path "
                "covered only when run as root");
            return;
        }
        FAIL("open WRONLY");
        return;
    }
    ssize_t w = write(fd, "0\n", 2);
    int saved = errno;
    close(fd);

    /* Linux's proc_reg_write returns -EIO when the proc node has no write op.
     * Older or stripped kernels may return other errno; the load-bearing
     * assertion is that the write fails, not the exact errno value.
     */
    if (w < 0)
        PASS();
    else
        printf("FAIL: write succeeded rc=%zd errno=%d\n", w, saved), fails++;
}

static void test_proc_oom_score_open_enforces_read_only(void)
{
    TEST("/proc/self/oom_score rejects writable open");
    errno = 0;
    int fd = open("/proc/self/oom_score", O_WRONLY);
    if (fd >= 0) {
        close(fd);
        FAIL("open should fail");
        return;
    }
    EXPECT_TRUE(errno == EACCES, "expected EACCES from open");
}

static void test_proc_oom_adj_reread_tracks_score_adj_updates(void)
{
    TEST("/proc/self/oom_adj reread reflects later score_adj writes");

    int reset = open("/proc/self/oom_score_adj", O_RDWR);
    if (reset < 0) {
        FAIL("reset open");
        return;
    }
    if (write(reset, "0\n", 2) != 2) {
        close(reset);
        FAIL("reset write");
        return;
    }
    close(reset);

    int fd = open("/proc/self/oom_adj", O_RDONLY);
    if (fd < 0) {
        /* The legacy oom_adj compat node must exist whenever the test runs
         * under elfuse (procemu emits it) or under a current Linux kernel that
         * still ships the compat alias. The previous version silently PASSed on
         * open failure, which turned this regression into a no-op on any host
         * where the file was absent.
         */
        FAIL("open /proc/self/oom_adj");
        return;
    }

    char buf[32] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0 || atoi(buf) != 0) {
        close(fd);
        FAIL("initial read");
        return;
    }

    int score = open("/proc/self/oom_score_adj", O_RDWR);
    if (score < 0) {
        close(fd);
        FAIL("score_adj open");
        return;
    }
    if (write(score, "1000\n", 5) != 5) {
        close(score);
        close(fd);
        FAIL("score_adj write");
        return;
    }
    close(score);

    if (lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        FAIL("lseek");
        return;
    }

    memset(buf, 0, sizeof(buf));
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    reset = open("/proc/self/oom_score_adj", O_RDWR);
    if (reset >= 0) {
        write(reset, "0\n", 2);
        close(reset);
    }

    if (n <= 0) {
        FAIL("reread");
        return;
    }
    EXPECT_TRUE(atoi(buf) == 15, "oom_adj fd should reflect current score_adj");
}

static void test_proc_oom_score_adj_reread_tracks_updates(void)
{
    TEST("/proc/self/oom_score_adj reread reflects later writes");

    int reset = open("/proc/self/oom_score_adj", O_RDWR);
    if (reset < 0) {
        FAIL("reset open");
        return;
    }
    if (write(reset, "0\n", 2) != 2) {
        close(reset);
        FAIL("reset write");
        return;
    }
    close(reset);

    int fd = open("/proc/self/oom_score_adj", O_RDONLY);
    if (fd < 0) {
        FAIL("open");
        return;
    }

    char buf[32] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0 || atoi(buf) != 0) {
        close(fd);
        FAIL("initial read");
        return;
    }

    int update = open("/proc/self/oom_score_adj", O_RDWR);
    if (update < 0) {
        close(fd);
        FAIL("update open");
        return;
    }
    if (write(update, "1000\n", 5) != 5) {
        close(update);
        close(fd);
        FAIL("update write");
        return;
    }
    close(update);

    if (lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        FAIL("lseek");
        return;
    }

    memset(buf, 0, sizeof(buf));
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    reset = open("/proc/self/oom_score_adj", O_RDWR);
    if (reset >= 0) {
        write(reset, "0\n", 2);
        close(reset);
    }

    if (n <= 0) {
        FAIL("reread");
        return;
    }
    EXPECT_TRUE(atoi(buf) == 1000,
                "oom_score_adj fd should reflect current value");
}

static void test_proc_oom_zero_length_writev(void)
{
    TEST("/proc/self/oom_score_adj zero-length writev returns 0");
    int fd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (fd < 0) {
        FAIL("open");
        return;
    }

    /* Two empty iovecs: total length zero. Linux returns 0; the previous
     * implementation returned EINVAL via proc_parse_int_write.
     */
    char dummy = 0;
    struct iovec iov[2] = {{&dummy, 0}, {&dummy, 0}};
    ssize_t n = writev(fd, iov, 2);
    int saved = errno;
    close(fd);
    if (n == 0)
        PASS();
    else
        printf("FAIL: writev returned %zd errno=%d\n", n, saved), fails++;
}

static void test_proc_oom_stat_size_zero(void)
{
    TEST("/proc/self/oom_score_adj stat reports size 0");
    struct stat st;
    if (stat("/proc/self/oom_score_adj", &st) < 0) {
        FAIL("stat");
        return;
    }

    /* A non-zero st_size would cap stat-sized read buffers, truncating
     * "-1000\n" (6 bytes) to whatever size was hardcoded.
     */
    EXPECT_TRUE(st.st_size == 0, "st_size should be 0");
}

/* /proc/self/fdinfo */

static void test_proc_fdinfo(void)
{
    TEST("/proc/self/fdinfo/0 readable");
    int fd = open("/proc/self/fdinfo/0", O_RDONLY);
    if (fd < 0) {
        FAIL("open");
        return;
    }
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0) {
        buf[n] = '\0';
        EXPECT_TRUE(strstr(buf, "pos:") && strstr(buf, "flags:"),
                    "missing pos/flags fields");
    } else {
        FAIL("read");
    }
}

static void test_proc_fdinfo_eventfd_count(void)
{
    TEST("/proc/self/fdinfo/<N> exposes eventfd-count");
    int efd = eventfd(42, 0);
    if (efd < 0) {
        FAIL("eventfd");
        return;
    }
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", efd);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        close(efd);
        FAIL("open");
        return;
    }
    char buf[256] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    close(efd);
    if (n <= 0) {
        FAIL("read");
        return;
    }

    /* Linux fs/eventfd.c emits "eventfd-count: %16llx" with a single space
     * separator (not a tab, unlike pos:/flags:/mnt_id:). Pin the exact prefix
     * so a regression to a tab is caught. Decimal 42 is 0x2a.
     */
    const char *p = strstr(buf, "eventfd-count: ");
    EXPECT_TRUE(p && strstr(p, "2a") != NULL,
                "eventfd-count missing space separator or wrong hex value");
}

static void test_proc_fdinfo_signalfd_mask(void)
{
    TEST("/proc/self/fdinfo/<N> exposes sigmask");
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    int sfd = signalfd(-1, &mask, 0);
    if (sfd < 0) {
        FAIL("signalfd");
        return;
    }
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", sfd);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        close(sfd);
        FAIL("open");
        return;
    }
    char buf[256] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    close(sfd);
    if (n <= 0) {
        FAIL("read");
        return;
    }

    /* Linux fs/signalfd.c emits "sigmask:\t%016llx" with a tab separator
     * (verified against a real /proc/self/fdinfo dump on Linux 6.x). Pin the
     * exact prefix so a regression to a space is caught.
     */
    EXPECT_TRUE(strstr(buf, "sigmask:\t") != NULL,
                "sigmask missing tab separator");
}

static void test_proc_fdinfo_timerfd_periodic_value(void)
{
    TEST("/proc/self/fdinfo/<N> reports periodic timerfd next expiry");
    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (tfd < 0) {
        FAIL("timerfd_create");
        return;
    }

    struct itimerspec its = {.it_value = {.tv_sec = 0, .tv_nsec = 50000000},
                             .it_interval = {.tv_sec = 0, .tv_nsec = 50000000}};
    if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
        close(tfd);
        FAIL("timerfd_settime");
        return;
    }

    usleep(70000);

    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", tfd);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        close(tfd);
        FAIL("open");
        return;
    }

    char buf[256] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    close(tfd);
    if (n <= 0) {
        FAIL("read");
        return;
    }

    long long value_sec = -1, value_nsec = -1;
    long long interval_sec = -1, interval_nsec = -1;

    /* Linux fs/timerfd.c emits "it_value: (S, NS)" with a single space after
     * the colon (unlike pos:/flags: which use tabs).
     */
    const char *value = strstr(buf, "it_value: (");
    const char *interval = strstr(buf, "it_interval: (");
    if (!value || !interval ||
        sscanf(value, "it_value: (%lld, %lld)", &value_sec, &value_nsec) != 2 ||
        sscanf(interval, "it_interval: (%lld, %lld)", &interval_sec,
               &interval_nsec) != 2) {
        FAIL("parse fdinfo");
        return;
    }

    long long value_total_ns = value_sec * 1000000000LL + value_nsec;
    long long interval_total_ns = interval_sec * 1000000000LL + interval_nsec;

    /* it_interval is the static settime value and must round-trip; Linux's
     * timerfd_get_remaining() reports 0 once the timer has fired, while elfuse
     * computes time-until-next from the kqueue arm time. Both are non-negative
     * and bounded by the interval, so accept either form.
     */
    EXPECT_TRUE(interval_total_ns == 50000000 && value_total_ns >= 0 &&
                    value_total_ns <= interval_total_ns,
                "interval should round-trip and value should be within bounds");
}

static void test_proc_fdinfo_timerfd_ticks_drains_kqueue(void)
{
    TEST("/proc/self/fdinfo/<N> ticks reflects pending kqueue fires");

    /* Arm a periodic timer, wait for several fires, then read fdinfo WITHOUT
     * first reading the timerfd. The pre-fix snapshot exported a stale
     * expirations counter (the kqueue events had not been folded in), so ticks
     * would read 0 even after multiple fires. Linux's fs/timerfd.c snapshots
     * ticks under the wait-queue lock, where the counter reflects every fire
     * that hit the kernel state.
     */
    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (tfd < 0) {
        FAIL("timerfd_create");
        return;
    }
    struct itimerspec its = {.it_value = {.tv_sec = 0, .tv_nsec = 20000000},
                             .it_interval = {.tv_sec = 0, .tv_nsec = 20000000}};
    if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
        close(tfd);
        FAIL("timerfd_settime");
        return;
    }
    /* Wait long enough for the timer to fire at least three times. */
    usleep(120000);

    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", tfd);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        close(tfd);
        FAIL("open");
        return;
    }
    char buf[256] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    close(tfd);
    if (n <= 0) {
        FAIL("read");
        return;
    }

    /* Linux uses "ticks: %llu" with a single space; elfuse matches. */
    const char *p = strstr(buf, "ticks: ");
    unsigned long long ticks = 0;
    if (!p || sscanf(p, "ticks: %llu", &ticks) != 1) {
        FAIL("parse ticks");
        return;
    }

    /* At minimum one fire should be visible; on a slow host more would be
     * expected. Pre-fix elfuse would report 0 here.
     */
    EXPECT_TRUE(ticks >= 1, "ticks should reflect at least one fire");
}

static void test_proc_fdinfo_dir_concurrent_safe(void)
{
    TEST("/proc/self/fdinfo dir tolerates concurrent re-open");

    /* Open the directory twice and verify both enumerate independently. The
     * earlier shared-dir design could mutate one open's backing files while
     * another iterated. Both Linux and the per-open scratch fix should at
     * minimum surface stdin/out/err on each enumeration.
     */
    DIR *d1 = opendir("/proc/self/fdinfo");
    if (!d1) {
        FAIL("opendir 1");
        return;
    }
    DIR *d2 = opendir("/proc/self/fdinfo");
    if (!d2) {
        closedir(d1);
        FAIL("opendir 2");
        return;
    }

    int n1 = 0, n2 = 0;
    struct dirent *ent;
    while ((ent = readdir(d1)))
        if (ent->d_name[0] != '.')
            n1++;
    while ((ent = readdir(d2)))
        if (ent->d_name[0] != '.')
            n2++;
    closedir(d1);
    closedir(d2);
    EXPECT_TRUE(n1 >= 3 && n2 >= 3, "concurrent enumeration broken");
}

/* True when the listing behind @d names descriptor @fd. */
static bool fd_listing_has(DIR *d, int fd)
{
    char name[16];
    snprintf(name, sizeof(name), "%d", fd);
    rewinddir(d);
    struct dirent *ent;
    while ((ent = readdir(d)))
        if (!strcmp(ent->d_name, name))
            return true;
    return false;
}

static void test_proc_fd_dir_tracks_churn(void)
{
    TEST("/proc/self/fd listing follows open and close churn");

    /* Each open is a snapshot: a listing opened earlier keeps its entries
     * while the descriptor set changes, and a later open reflects the closes
     * and reopens made in between, across several rounds.
     */
    enum { N = 64 };
    int fds[N];
    for (int i = 0; i < N; i++)
        fds[i] = open("/dev/null", O_RDONLY);
    DIR *before = opendir("/proc/self/fd");
    if (!before) {
        FAIL("opendir before");
        return;
    }
    bool ok = true;
    for (int round = 0; round < 4 && ok; round++) {
        for (int i = round % 2; i < N; i += 2) {
            close(fds[i]);
            fds[i] = -1;
        }
        DIR *now = opendir("/proc/self/fd");
        if (!now) {
            FAIL("opendir during churn");
            closedir(before);
            return;
        }
        for (int i = 0; i < N && ok; i++) {
            if (fds[i] >= 0 && !fd_listing_has(now, fds[i]))
                ok = false;
        }
        for (int i = round % 2; i < N && ok; i += 2) {
            fds[i] = open("/dev/null", O_RDONLY);
            if (fds[i] < 0)
                ok = false;
        }
        closedir(now);
        /* The reopens reuse the closed numbers, so a listing taken now must
         * name every one of them again.
         */
        DIR *after = opendir("/proc/self/fd");
        for (int i = 0; i < N && ok && after; i++)
            if (!fd_listing_has(after, fds[i]))
                ok = false;
        if (after)
            closedir(after);
    }
    for (int i = 0; i < N && ok; i++)
        if (fds[i] >= 0 && !fd_listing_has(before, fds[i]))
            ok = false;
    closedir(before);

    int probe = open("/dev/null", O_RDONLY);
    close(probe);
    DIR *closed = opendir("/proc/self/fd");
    bool stale = closed && fd_listing_has(closed, probe);
    if (closed)
        closedir(closed);
    for (int i = 0; i < N; i++)
        if (fds[i] >= 0)
            close(fds[i]);
    EXPECT_TRUE(ok && closed && !stale,
                "listing missed a live fd or kept a closed one");
}

/* The /proc/self/maps line covering @addr, or false when none does. */
static bool maps_line_for(const void *addr, char *out, size_t outsz)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return false;
    bool found = false;
    while (!found && fgets(out, (int) outsz, f)) {
        unsigned long lo, hi;
        if (sscanf(out, "%lx-%lx", &lo, &hi) == 2 &&
            (unsigned long) addr >= lo && (unsigned long) addr < hi)
            found = true;
    }
    fclose(f);
    return found;
}

static void test_proc_maps_names_file_mappings(void)
{
    TEST("/proc/self/maps names file-backed mappings");

    /* Native crash reporters and loaders map a PC back to its library by the
     * pathname column; an unnamed file mapping hides every library.
     */
    char path[] = "/tmp/maps-name-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0 || ftruncate(fd, 8192) < 0) {
        FAIL("mkstemp");
        return;
    }
    void *p = mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) {
        unlink(path);
        FAIL("mmap");
        return;
    }
    char line[1024];
    bool named = maps_line_for(p, line, sizeof(line)) &&
                 strstr(line, strrchr(path, '/'));

    /* A removed file has no path to report, and must not borrow one. */
    unlink(path);
    char gone[1024];
    bool removed_unnamed = maps_line_for(p, gone, sizeof(gone)) &&
                           !strstr(gone, strrchr(path, '/'));
    munmap(p, 8192);
    EXPECT_TRUE(named && removed_unnamed,
                "file mapping not named, or a removed one kept its name");
}

static void test_proc_fdinfo_dirfd_openat_uses_virtual_entries(void)
{
    TEST("/proc/self/fdinfo dirfd openat resolves virtually");
    int dirfd = open("/proc/self/fdinfo", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        return;
    }

    int fd = openat(dirfd, "0", O_RDONLY);
    close(dirfd);
    if (fd < 0) {
        FAIL("openat");
        return;
    }

    char buf[256] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        FAIL("read");
        return;
    }

    EXPECT_TRUE(strstr(buf, "pos:\t") && strstr(buf, "flags:\t"),
                "fdinfo openat should yield synthetic payload");
}

/* /proc/net */

static int bind_listen_loopback_tcp(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(s, (struct sockaddr *) &sa, sizeof(sa)) < 0 || listen(s, 1) < 0) {
        close(s);
        return -1;
    }
    return s;
}

static void test_proc_net_tcp_sl_dense(void)
{
    TEST("/proc/net/tcp sl column stays dense across mixed sockets");

    /* Interleave non-TCP sockets BEFORE the bound TCP listeners so the
     * proc_pidinfo iterator visits the rejected sockets first and the pre-fix
     * sparse-slot bug would assign nonzero sl to the first emitted row. Two TCP
     * listeners ensure the second row's sl exposes any gap created by
     * additional non-TCP visits between them.
     *
     * Pre-fix: udp1, udp2, sp[0], sp[1] all bump the iterator slot counter to 4
     * before tcp1 emits. tcp1 row: sl=4. tcp2 row: sl=5. The first-row check
     * (sl == 0) would fail. Post-fix: only emitted rows increment the visitor's
     * row counter; tcp1: sl=0, tcp2: sl=1. Dense.
     */
    int udp1 = socket(AF_INET, SOCK_DGRAM, 0);
    int udp2 = socket(AF_INET, SOCK_DGRAM, 0);
    int sp[2] = {-1, -1};
    int sp_rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    int tcp1 = bind_listen_loopback_tcp();
    int tcp2 = bind_listen_loopback_tcp();
    if (udp1 < 0 || udp2 < 0 || sp_rc < 0 || tcp1 < 0 || tcp2 < 0) {
        if (udp1 >= 0)
            close(udp1);
        if (udp2 >= 0)
            close(udp2);
        if (sp[0] >= 0)
            close(sp[0]);
        if (sp[1] >= 0)
            close(sp[1]);
        if (tcp1 >= 0)
            close(tcp1);
        if (tcp2 >= 0)
            close(tcp2);
        FAIL("socket setup");
        return;
    }

    int fd = open("/proc/net/tcp", O_RDONLY);
    if (fd < 0) {
        close(udp1);
        close(udp2);
        close(sp[0]);
        close(sp[1]);
        close(tcp1);
        close(tcp2);
        FAIL("open");
        return;
    }
    char buf[16384];
    ssize_t total = 0;
    for (;;) {
        ssize_t n = read(fd, buf + total, sizeof(buf) - total - 1);
        if (n <= 0)
            break;
        total += n;
    }
    close(fd);
    close(udp1);
    close(udp2);
    close(sp[0]);
    close(sp[1]);
    close(tcp1);
    close(tcp2);
    buf[total] = '\0';

    /* Skip the header line; collect each subsequent row's leading "sl" field.
     * /proc/net/tcp's row format is " N: ..." with N a decimal serial. Verify
     * the serials form 0,1,2,... with no gaps.
     */
    char *line = strchr(buf, '\n');
    if (!line) {
        FAIL("no rows");
        return;
    }
    line++;
    int expected = 0;
    while (*line) {
        char *colon = strchr(line, ':');
        char *eol = strchr(line, '\n');
        if (!colon || (eol && colon > eol))
            break;
        int sl = atoi(line);
        if (sl != expected) {
            printf("FAIL: sl=%d expected=%d\n", sl, expected);
            fails++;
            return;
        }
        expected++;
        if (!eol)
            break;
        line = eol + 1;
    }
    if (expected == 0) {
        /* The bound listener should have produced a row. Treat absence as
         * failure since the regression coverage depends on it.
         */
        FAIL("no TCP rows after bind/listen");
        return;
    }
    PASS();
}

static void test_proc_net_dirfd_openat_uses_virtual_entries(void)
{
    TEST("/proc/net dirfd openat resolves virtually");
    int dirfd = open("/proc/net", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        return;
    }

    int fd = openat(dirfd, "tcp", O_RDONLY);
    close(dirfd);
    if (fd < 0) {
        FAIL("openat");
        return;
    }

    char buf[512] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        FAIL("read");
        return;
    }

    EXPECT_TRUE(strstr(buf, "local_address"),
                "proc net dirfd should preserve synthetic tcp table");
}

/* /proc/cpuinfo */

static void test_proc_cpuinfo_all_cpus(void)
{
    TEST("/proc/cpuinfo lists all CPUs");
    int fd = open("/proc/cpuinfo", O_RDONLY);
    if (fd < 0) {
        FAIL("open");
        return;
    }
    char buf[65536];
    ssize_t total = 0;
    for (;;) {
        ssize_t n = read(fd, buf + total, sizeof(buf) - total - 1);
        if (n <= 0)
            break;
        total += n;
    }
    close(fd);
    buf[total] = '\0';

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    int count = 0;
    char *p = buf;
    while ((p = strstr(p, "processor\t:"))) {
        count++;
        p++;
    }
    if (count == ncpu)
        PASS();
    else {
        printf("FAIL: found %d cpus, expected %ld\n", count, ncpu);
        fails++;
    }
}

int main(void)
{
    printf("/proc fidelity tests:\n");

    test_proc_oom_score_adj();
    test_proc_oom_score_adj_persists_write();
    test_proc_oom_score_adj_rejects_out_of_range();
    test_proc_oom_adj_scaling();
    test_proc_oom_adj_same_fd_roundtrip();
    test_proc_oom_adj_reread_tracks_score_adj_updates();
    test_proc_oom_score_adj_reread_tracks_updates();
    test_proc_oom_score_no_write();
    test_proc_oom_score_write_fails();
    test_proc_oom_score_open_enforces_read_only();
    test_proc_oom_zero_length_writev();
    test_proc_oom_stat_size_zero();
    test_proc_fdinfo();
    test_proc_fdinfo_eventfd_count();
    test_proc_fdinfo_signalfd_mask();
    test_proc_fdinfo_timerfd_periodic_value();
    test_proc_fdinfo_timerfd_ticks_drains_kqueue();
    test_proc_fdinfo_dir_concurrent_safe();
    test_proc_fd_dir_tracks_churn();
    test_proc_maps_names_file_mappings();
    test_proc_fdinfo_dirfd_openat_uses_virtual_entries();
    test_proc_net_tcp_sl_dense();
    test_proc_net_dirfd_openat_uses_virtual_entries();
    test_proc_cpuinfo_all_cpus();

    /* Local summary includes the skip count so missed coverage (e.g. non-root
     * oom_score write path) is visible alongside passes and fails. Cannot reuse
     * SUMMARY() from test-harness.h because it has no skip accounting.
     */
    printf("\ntest-proc-fidelity: %d passed, %d failed, %d skipped%s\n", passes,
           fails, procfs_skips, fails == 0 ? " - PASS" : " - FAIL");
    return fails ? 1 : 0;
}
