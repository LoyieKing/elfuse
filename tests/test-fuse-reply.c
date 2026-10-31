/*
 * Reply matching and execve materialization against a hostile FUSE daemon.
 *
 * The daemon is a guest thread, so every reply it writes to /dev/fuse is
 * untrusted. Checks:
 *   1. A reply naming a request that is still queued (not yet read by the
 *      daemon) is refused with ENOENT, as Linux refuses a unique that is not on
 *      its processing list.
 *   2. A second reply to an already answered request is refused with ENOENT.
 *   3. The mount keeps serving requests after both refusals.
 *   4. execve of a FUSE-backed file whose daemon answers every FUSE_READ with
 *      more bytes than were asked for fails after one READ, instead of
 *      materializing an unbounded stream into a host temp file.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "linux-fuse.h"

/* A stand-in "executable" whose content is never valid ELF; only the number of
 * READs the materializer issues matters.
 */
static const char file_data[] = "not an elf, just bytes\n";
static const char file_name[] = "prog";

/* Upper bound on flood replies, so the unfixed tree terminates instead of
 * filling the host temp directory.
 */
#define FLOOD_READ_LIMIT 64

typedef struct {
    int fusefd;

    /* Every field below crosses between the main thread and the daemon thread,
     * so each is atomic: the stage flags publish the state around them.
     */
    _Atomic int failures;

    /* Stage 1: hold the first LOOKUP after arming and probe uniques ahead. */
    _Atomic int stall_lookup;
    _Atomic int stalled;
    _Atomic int release_stall;
    _Atomic uint64_t stalled_unique;

    /* Stage 2: answer the next LOOKUP twice. */
    _Atomic int dup_lookup;

    /* Stage 3: answer every READ with more than was asked for. */
    _Atomic int flood_read;
    _Atomic int flood_reads_seen;
} daemon_ctx_t;

static void fill_dir_attr(struct fuse_attr *attr)
{
    memset(attr, 0, sizeof(*attr));
    attr->ino = 1;
    attr->mode = S_IFDIR | 0755;
    attr->nlink = 2;
    attr->uid = getuid();
    attr->gid = getgid();
    attr->blksize = 4096;
}

static void fill_file_attr(struct fuse_attr *attr)
{
    memset(attr, 0, sizeof(*attr));
    attr->ino = 2;
    attr->mode = S_IFREG | 0755;
    attr->nlink = 1;
    attr->uid = getuid();
    attr->gid = getgid();
    attr->size = sizeof(file_data) - 1;
    attr->blocks = 1;
    attr->blksize = 4096;
}

/* Returns the write(2) result, with errno preserved on failure. */
static ssize_t send_reply(int fd,
                          uint64_t unique,
                          int32_t error,
                          const void *payload,
                          size_t len)
{
    static uint8_t buf[8192];
    struct fuse_out_header out = {
        .len = (uint32_t) (sizeof(out) + len),
        .error = error,
        .unique = unique,
    };
    memcpy(buf, &out, sizeof(out));
    if (len)
        memcpy(buf + sizeof(out), payload, len);
    return write(fd, buf, sizeof(out) + len);
}

static void reply_or_die(int fd,
                         uint64_t unique,
                         int32_t error,
                         const void *payload,
                         size_t len)
{
    if (send_reply(fd, unique, error, payload, len) !=
        (ssize_t) (sizeof(struct fuse_out_header) + len)) {
        perror("write(/dev/fuse)");
        exit(1);
    }
}

/* A reply the transport must refuse: anything but ENOENT is a failure. */
static void expect_refused(daemon_ctx_t *ctx, uint64_t unique, const char *why)
{
    struct fuse_entry_out out;
    memset(&out, 0, sizeof(out));
    out.nodeid = 2;
    fill_file_attr(&out.attr);
    errno = 0;
    ssize_t rc = send_reply(ctx->fusefd, unique, 0, &out, sizeof(out));
    if (rc >= 0 || errno != ENOENT) {
        fprintf(stderr, "%s: reply to unique %llu got rc=%zd errno=%d\n", why,
                (unsigned long long) unique, rc, errno);
        ctx->failures++;
    }
}

static void reply_lookup(daemon_ctx_t *ctx, const struct fuse_in_header *in)
{
    const char *name = (const char *) (in + 1);
    if (in->nodeid != FUSE_ROOT_ID || strcmp(name, file_name)) {
        reply_or_die(ctx->fusefd, in->unique, -ENOENT, NULL, 0);
        return;
    }
    struct fuse_entry_out out;
    memset(&out, 0, sizeof(out));
    out.nodeid = 2;
    fill_file_attr(&out.attr);
    reply_or_die(ctx->fusefd, in->unique, 0, &out, sizeof(out));
}

static void handle_lookup(daemon_ctx_t *ctx, const struct fuse_in_header *in)
{
    if (ctx->stall_lookup) {
        ctx->stall_lookup = 0;
        ctx->stalled_unique = in->unique;
        ctx->stalled = 1;
        while (!ctx->release_stall)
            usleep(1000);

        /* The second stat is queued now, under one of the next few uniques, and
         * no frame past this one has been read. Every one of them must be
         * refused: a queued request is not answerable yet, and the rest do not
         * exist.
         */
        for (uint64_t u = in->unique + 1; u <= in->unique + 4; u++)
            expect_refused(ctx, u, "reply before read");
        reply_lookup(ctx, in);
        return;
    }
    reply_lookup(ctx, in);
    if (ctx->dup_lookup) {
        ctx->dup_lookup = 0;
        expect_refused(ctx, in->unique, "duplicate reply");
    }
}

static void *daemon_main(void *arg)
{
    daemon_ctx_t *ctx = arg;
    static uint8_t buf[1 << 17];
    for (;;) {
        ssize_t nr = read(ctx->fusefd, buf, sizeof(buf));
        if (nr < 0) {
            if (errno == ENOTCONN || errno == EBADF)
                return NULL;
            perror("read(/dev/fuse)");
            exit(1);
        }

        struct fuse_in_header *in = (struct fuse_in_header *) buf;
        switch (in->opcode) {
        case FUSE_INIT: {
            struct fuse_init_out out = {
                .major = 7,
                .minor = 45,
                .max_readahead = 1024 * 1024,
                .max_write = 65536,
            };
            reply_or_die(ctx->fusefd, in->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_GETATTR: {
            struct fuse_attr_out out;
            memset(&out, 0, sizeof(out));
            if (in->nodeid == FUSE_ROOT_ID)
                fill_dir_attr(&out.attr);
            else
                fill_file_attr(&out.attr);
            reply_or_die(ctx->fusefd, in->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_LOOKUP:
            handle_lookup(ctx, in);
            break;
        case FUSE_OPEN: {
            struct fuse_open_out out = {.fh = 11};
            reply_or_die(ctx->fusefd, in->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_READ: {
            struct fuse_read_in *rin = (struct fuse_read_in *) (in + 1);
            if (ctx->flood_read) {
                static uint8_t flood[4096];
                memset(flood, 0xA5, sizeof(flood));
                size_t len = ctx->flood_reads_seen++ < FLOOD_READ_LIMIT
                                 ? sizeof(flood)
                                 : 0;
                reply_or_die(ctx->fusefd, in->unique, 0, flood, len);
                break;
            }
            size_t total = sizeof(file_data) - 1;
            size_t avail = rin->offset < total ? total - rin->offset : 0;
            if (avail > rin->size)
                avail = rin->size;
            reply_or_die(ctx->fusefd, in->unique, 0, file_data + rin->offset,
                         avail);
            break;
        }
        case FUSE_RELEASE:
            reply_or_die(ctx->fusefd, in->unique, 0, NULL, 0);
            break;
        case FUSE_FORGET:
        case FUSE_BATCH_FORGET:
        case FUSE_INTERRUPT:
            break;
        default:
            reply_or_die(ctx->fusefd, in->unique, -ENOSYS, NULL, 0);
            break;
        }
    }
}

static char file_path[256];

static void *stat_main(void *arg)
{
    struct stat st;
    *(int *) arg = stat(file_path, &st) == 0 ? 0 : errno;
    return NULL;
}

static void die(const char *msg)
{
    perror(msg);
    exit(1);
}

/* pthread_create reports its error as the return value, not errno. */
static void start_thread(pthread_t *th,
                         void *(*fn)(void *),
                         void *arg,
                         const char *what)
{
    int rc = pthread_create(th, NULL, fn, arg);
    if (rc != 0) {
        errno = rc;
        die(what);
    }
}

static void expect_file_readable(void)
{
    int fd = open(file_path, O_RDONLY);
    if (fd < 0)
        die("open(fuse file)");
    char buf[64];
    ssize_t nr = read(fd, buf, sizeof(buf));
    if (nr != (ssize_t) (sizeof(file_data) - 1) ||
        memcmp(buf, file_data, (size_t) nr) != 0) {
        fprintf(stderr, "unexpected FUSE read payload (nr=%zd)\n", nr);
        exit(1);
    }
    close(fd);
}

int main(void)
{
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) < 0)
        die("sched_getaffinity");
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, &allowed))
            continue;
        CPU_ZERO(&allowed);
        CPU_SET(cpu, &allowed);
        if (sched_setaffinity(0, sizeof(allowed), &allowed) < 0)
            die("sched_setaffinity");
        break;
    }
    char mount_dir[] = "/tmp/elfuse-fuse-reply.XXXXXX";
    if (!mkdtemp(mount_dir))
        die("mkdtemp");
    snprintf(file_path, sizeof(file_path), "%s/%s", mount_dir, file_name);

    int fusefd = open("/dev/fuse", O_RDWR);
    if (fusefd < 0)
        die("open(/dev/fuse)");

    daemon_ctx_t ctx = {.fusefd = fusefd};
    pthread_t daemon;
    start_thread(&daemon, daemon_main, &ctx, "pthread_create(daemon)");

    char opts[128];
    snprintf(opts, sizeof(opts), "fd=%d,rootmode=40000,user_id=%u,group_id=%u",
             fusefd, (unsigned) getuid(), (unsigned) getgid());
    if (syscall(SYS_mount, "elfuse-test", mount_dir, "fuse", 0, opts) < 0)
        die("mount(fuse)");

    /* Stage 1: one stat parked in the daemon, a second one queued behind it. */
    ctx.stall_lookup = 1;
    int first_rc = -1, second_rc = -1;
    pthread_t first, second;
    start_thread(&first, stat_main, &first_rc, "pthread_create(first stat)");
    for (int i = 0; i < 5000 && !ctx.stalled; i++)
        usleep(1000);
    if (!ctx.stalled) {
        fprintf(stderr, "daemon never saw the first LOOKUP\n");
        return 1;
    }
    errno = 0;
    if (fork() != -1 || errno != EAGAIN) {
        fprintf(stderr, "fork accepted an outstanding FUSE service job\n");
        return 1;
    }
    start_thread(&second, stat_main, &second_rc, "pthread_create(second stat)");
    struct pollfd pfd = {.fd = fusefd, .events = POLLIN};
    (void) poll(&pfd, 1, 2000);
    usleep(50000);
    ctx.release_stall = 1;
    pthread_join(first, NULL);
    pthread_join(second, NULL);
    if (first_rc != 0 || second_rc != 0) {
        fprintf(stderr, "stat under stalled daemon failed: %d %d\n", first_rc,
                second_rc);
        return 1;
    }

    /* Stage 2: a duplicate reply to an answered LOOKUP. */
    ctx.dup_lookup = 1;
    struct stat st;
    if (stat(file_path, &st) < 0)
        die("stat(dup reply)");
    expect_file_readable();

    /* Stage 3: execve through a daemon that over-answers every READ. The name
     * is relative to a cwd inside the mount, which is the spelling execve
     * routes through FUSE materialization.
     */
    if (chdir(mount_dir) < 0)
        die("chdir(mount)");
    ctx.flood_read = 1;
    char *argv[] = {(char *) file_name, NULL};
    char *envp[] = {NULL};
    errno = 0;
    if (execve(file_name, argv, envp) == 0)
        return 1;
    int exec_errno = errno;
    ctx.flood_read = 0;
    if (chdir("/") < 0)
        die("chdir(/)");
    if (ctx.flood_reads_seen != 1 || exec_errno != EIO) {
        fprintf(stderr,
                "execve materialization issued %d over-answered READs "
                "(errno=%d)\n",
                ctx.flood_reads_seen, exec_errno);
        ctx.failures++;
    }
    expect_file_readable();

    close(fusefd);
    pthread_join(daemon, NULL);
    rmdir(mount_dir);
    if (ctx.failures) {
        fprintf(stderr, "%d refusal check(s) failed\n", ctx.failures);
        return 1;
    }
    printf("test-fuse-reply: ok\n");
    return 0;
}
