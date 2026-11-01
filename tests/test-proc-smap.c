/*
 * Generic /proc/<pid>/smaps parser and accounting regression test.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

typedef struct {
    uintptr_t start;
    uintptr_t end;
    unsigned long long offset;
    char perms[5];
    unsigned long long size_kb;
    unsigned long long kernel_page_kb;
    unsigned long long mmu_page_kb;
    unsigned long long rss_kb;
    unsigned long long pss_kb;
    unsigned long long pss_dirty_kb;
    unsigned long long shared_dirty_kb;
    bool have_size;
    bool have_rss;
    bool have_pss;
    bool have_pss_dirty;
    bool have_shared_dirty;
    bool have_vmflags;
    bool vmflags_wr;
} smaps_vma_t;

static const char *const smaps_fields[] = {
    "Size:",          "KernelPageSize:", "MMUPageSize:",     "Rss:",
    "Pss:",           "Pss_Dirty:",      "Shared_Clean:",    "Shared_Dirty:",
    "Private_Clean:", "Private_Dirty:",  "Referenced:",      "Anonymous:",
    "KSM:",           "LazyFree:",       "AnonHugePages:",   "ShmemPmdMapped:",
    "FilePmdMapped:", "Shared_Hugetlb:", "Private_Hugetlb:", "Swap:",
    "SwapPss:",       "Locked:",         "THPeligible:",     "VmFlags:",
};

#define SMAPS_FIELD_COUNT (sizeof(smaps_fields) / sizeof(smaps_fields[0]))
#define SMAPS_KB_FIELD_COUNT 22

typedef struct {
    smaps_vma_t *vmas;
    size_t count;
} smaps_info_t;

static const char *skip_space(const char *p)
{
    while (*p && isspace((unsigned char) *p))
        p++;
    return p;
}

static bool parse_token(const char **cursor, char *token, size_t token_size)
{
    const char *p = skip_space(*cursor);
    const char *start = p;
    while (*p && !isspace((unsigned char) *p))
        p++;
    size_t len = (size_t) (p - start);
    if (len == 0 || len >= token_size)
        return false;
    memcpy(token, start, len);
    token[len] = '\0';
    *cursor = p;
    return true;
}

static bool parse_unsigned_token(const char *token,
                                 int base,
                                 unsigned long long *value)
{
    if (!token[0])
        return false;
    for (const unsigned char *p = (const unsigned char *) token; *p; p++) {
        if (base == 16 ? !isxdigit(*p) : !isdigit(*p))
            return false;
    }

    errno = 0;
    char *end = NULL;
    unsigned long long n = strtoull(token, &end, base);
    if (errno == ERANGE || end == token || *end != '\0')
        return false;
    *value = n;
    return true;
}

static bool parse_device_token(const char *token)
{
    const char *colon = strchr(token, ':');
    if (!colon || colon == token || colon[1] == '\0' || strchr(colon + 1, ':'))
        return false;

    char major[32], minor[32];
    size_t major_len = (size_t) (colon - token);
    if (major_len >= sizeof(major) || strlen(colon + 1) >= sizeof(minor))
        return false;
    memcpy(major, token, major_len);
    major[major_len] = '\0';
    strcpy(minor, colon + 1);

    unsigned long long value;
    return parse_unsigned_token(major, 16, &value) &&
           parse_unsigned_token(minor, 16, &value);
}

/* Parse the address/perms/offset/dev/inode part of a smaps header. The rest of
 * the line is an optional pathname and is intentionally left opaque.
 */
static bool parse_header(const char *line, smaps_vma_t *vma)
{
    const char *p = line;
    errno = 0;
    char *end = NULL;
    unsigned long long start = strtoull(p, &end, 16);
    if (errno == ERANGE || end == p || *end != '-')
        return false;
    p = end + 1;

    errno = 0;
    unsigned long long finish = strtoull(p, &end, 16);
    if (errno == ERANGE || end == p || start >= finish ||
        !isspace((unsigned char) *end))
        return false;
    if (start > UINTPTR_MAX || finish > UINTPTR_MAX)
        return false;
    p = end;

    char token[128];
    if (!parse_token(&p, token, sizeof(token)) || strlen(token) != 4)
        return false;
    for (size_t i = 0; i < 3; i++) {
        if (token[i] != 'r' && token[i] != 'w' && token[i] != 'x' &&
            token[i] != '-')
            return false;
    }
    if (token[3] != 'p' && token[3] != 's')
        return false;
    memcpy(vma->perms, token, sizeof(vma->perms));

    if (!parse_token(&p, token, sizeof(token)) ||
        !parse_unsigned_token(token, 16, &vma->offset))
        return false;
    if (!parse_token(&p, token, sizeof(token)) || !parse_device_token(token))
        return false;
    if (!parse_token(&p, token, sizeof(token)))
        return false;
    unsigned long long inode;
    if (!parse_unsigned_token(token, 10, &inode))
        return false;

    vma->start = (uintptr_t) start;
    vma->end = (uintptr_t) finish;
    vma->size_kb = 0;
    vma->kernel_page_kb = 0;
    vma->mmu_page_kb = 0;
    vma->rss_kb = 0;
    vma->pss_kb = 0;
    vma->pss_dirty_kb = 0;
    vma->shared_dirty_kb = 0;
    vma->have_size = false;
    vma->have_rss = false;
    vma->have_pss = false;
    vma->have_pss_dirty = false;
    vma->have_shared_dirty = false;
    vma->have_vmflags = false;
    vma->vmflags_wr = false;
    return true;
}

/* Parse a decimal field and optionally require a suffix after its number. Both
 * smaps field families share the same label/whitespace/overflow rules; only the
 * trailing unit differs ("kB" for the first group, none for the remaining
 * numeric fields).
 */
static bool parse_numeric_field(const char *line,
                                const char *label,
                                const char *suffix,
                                unsigned long long *value)
{
    size_t label_len = strlen(label);
    if (strncmp(line, label, label_len) != 0)
        return false;
    const char *p = skip_space(line + label_len);
    const char *start = p;
    while (isdigit((unsigned char) *p))
        p++;
    if (p == start)
        return false;
    char number[64];
    size_t number_len = (size_t) (p - start);
    if (number_len >= sizeof(number))
        return false;
    memcpy(number, start, number_len);
    number[number_len] = '\0';
    if (!parse_unsigned_token(number, 10, value))
        return false;
    p = skip_space(p);
    return suffix ? !strcmp(p, suffix) : *p == '\0';
}

static bool parse_vmflags(const char *line, bool *writable)
{
    const char *label = "VmFlags:";
    size_t label_len = strlen(label);
    if (strncmp(line, label, label_len) != 0)
        return false;

    const char *p = line + label_len;
    if (*p && !isspace((unsigned char) *p))
        return false;

    /* Keep the provider's stable spelling for an empty flag set: the Linux
     * field always has a separating space, even when no token follows.
     */
    if (!*p)
        return false;
    bool has_wr = false;
    while (*(p = skip_space(p))) {
        const char *start = p;
        while (*p && !isspace((unsigned char) *p)) {
            if (!isalpha((unsigned char) *p))
                return false;
            p++;
        }
        if (p == start)
            return false;
        if ((size_t) (p - start) == 2 && start[0] == 'w' && start[1] == 'r')
            has_wr = true;
    }

    /* A synthetic PROT_NONE VMA has no provable access flags and therefore may
     * legitimately emit an empty VmFlags field.
     */
    *writable = has_wr;
    return true;
}

static bool finish_vma(smaps_vma_t *vma, size_t field_index)
{
    return field_index == SMAPS_FIELD_COUNT && vma->have_size &&
           vma->have_rss && vma->have_pss && vma->have_pss_dirty &&
           vma->have_shared_dirty && vma->have_vmflags;
}

static bool append_vma(smaps_info_t *info, const smaps_vma_t *vma)
{
    smaps_vma_t *vmas =
        realloc(info->vmas, (info->count + 1) * sizeof(*info->vmas));
    if (!vmas)
        return false;
    vmas[info->count++] = *vma;
    info->vmas = vmas;
    return true;
}

static bool parse_smaps(char *buf, size_t len, smaps_info_t *info)
{
    memset(info, 0, sizeof(*info));
    if (len == 0 || buf[len - 1] != '\n')
        return false; /* catches a truncated final record */

    smaps_vma_t current;
    bool have_current = false;
    size_t field_index = 0;
    uintptr_t previous_end = 0;
    char *line = buf;
    while ((size_t) (line - buf) < len) {
        char *next = memchr(line, '\n', len - (size_t) (line - buf));
        if (!next)
            goto fail;
        *next = '\0';

        /* smaps records are contiguous: a blank line is not a field and is
         * rejected so malformed snapshots cannot hide an out-of-order VMA.
         */
        if (!*line) {
            goto fail;
        }

        smaps_vma_t header;
        if (parse_header(line, &header)) {
            if (have_current) {
                if (!finish_vma(&current, field_index) ||
                    !append_vma(info, &current))
                    goto fail;
            }
            if (info->count > 0 &&
                (header.start < previous_end ||
                 header.start <= info->vmas[info->count - 1].start))
                goto fail;
            current = header;
            have_current = true;
            field_index = 0;
            previous_end = header.end;
        } else {
            if (!have_current)
                goto fail;
            if (field_index >= SMAPS_FIELD_COUNT)
                goto fail;
            unsigned long long value;
            bool writable;
            if (field_index < SMAPS_KB_FIELD_COUNT &&
                parse_numeric_field(line, smaps_fields[field_index], "kB",
                                    &value)) {
                if (field_index == 0)
                    current.size_kb = value;
                if (field_index == 1)
                    current.kernel_page_kb = value;
                if (field_index == 2)
                    current.mmu_page_kb = value;
                if (field_index == 3)
                    current.rss_kb = value;
                if (field_index == 4)
                    current.pss_kb = value;
                if (field_index == 5)
                    current.pss_dirty_kb = value;
                if (field_index == 7)
                    current.shared_dirty_kb = value;
                if (field_index == 0)
                    current.have_size = true;
                if (field_index == 3)
                    current.have_rss = true;
                if (field_index == 4)
                    current.have_pss = true;
                if (field_index == 5)
                    current.have_pss_dirty = true;
                if (field_index == 7)
                    current.have_shared_dirty = true;
                field_index++;
            } else if (field_index >= SMAPS_KB_FIELD_COUNT &&
                       field_index < SMAPS_FIELD_COUNT - 1 &&
                       parse_numeric_field(line, smaps_fields[field_index],
                                           NULL, &value)) {
                field_index++;
            } else if (field_index == SMAPS_FIELD_COUNT - 1 &&
                       parse_vmflags(line, &writable)) {
                current.have_vmflags = true;
                current.vmflags_wr = writable;
                field_index++;
            } else {
                goto fail;
            }
        }
        line = next + 1;
    }

    if (!have_current || !finish_vma(&current, field_index) ||
        !append_vma(info, &current) || info->count == 0)
        goto fail;
    return true;

fail:
    free(info->vmas);
    memset(info, 0, sizeof(*info));
    return false;
}

static void free_smaps(smaps_info_t *info)
{
    free(info->vmas);
    memset(info, 0, sizeof(*info));
}

/* Read, parse, and release one smaps snapshot. The parser owns only its VMA
 * array, so the transient file buffer can be cleaned up in this single place on
 * both success and failure.
 */
static bool load_smaps(const char *path, smaps_info_t *info)
{
    FILE *file = fopen(path, "r");
    if (!file)
        return false;

    char *buf = NULL;
    size_t capacity = 0;
    ssize_t length = getdelim(&buf, &capacity, '\0', file);
    bool ok = length >= 0 && parse_smaps(buf, (size_t) length, info);
    free(buf);
    (void) fclose(file);
    return ok;
}

static const smaps_vma_t *find_vma(const smaps_info_t *info, uintptr_t address)
{
    for (size_t i = 0; i < info->count; i++) {
        if (info->vmas[i].start <= address && address < info->vmas[i].end)
            return &info->vmas[i];
    }
    return NULL;
}

static size_t count_vmas_in_range(const smaps_info_t *info,
                                  uintptr_t start,
                                  uintptr_t end)
{
    size_t count = 0;
    for (size_t i = 0; i < info->count; i++) {
        if (info->vmas[i].end > start && info->vmas[i].start < end)
            count++;
    }
    return count;
}

static bool validate_layout(const smaps_info_t *info,
                            uintptr_t target,
                            uintptr_t stress,
                            size_t page_size,
                            size_t stress_size)
{
    if (info->count <= 256)
        return false;

    const smaps_vma_t *first = find_vma(info, target);
    const smaps_vma_t *middle = find_vma(info, target + page_size);
    const smaps_vma_t *last = find_vma(info, target + 2 * page_size);
    unsigned long long page_kb = page_size / 1024;
    if (!first || !middle || !last || page_kb == 0)
        return false;

    if (first->start != target || first->end != target + page_size ||
        middle->start != target + page_size ||
        middle->end != target + 2 * page_size ||
        last->start != target + 2 * page_size ||
        last->end != target + 3 * page_size)
        return false;
    if (strcmp(first->perms, "rw-p") || strcmp(middle->perms, "r--p") ||
        strcmp(last->perms, "rw-p"))
        return false;
    if (first->size_kb != page_kb || middle->size_kb != page_kb ||
        last->size_kb != page_kb || !first->vmflags_wr || middle->vmflags_wr ||
        !last->vmflags_wr || first->kernel_page_kb != 4 ||
        first->mmu_page_kb != 4 || middle->kernel_page_kb != 4 ||
        middle->mmu_page_kb != 4 || last->kernel_page_kb != 4 ||
        last->mmu_page_kb != 4)
        return false;

    /* Every stress-map page has deliberately distinct permissions (with one
     * PROT_NONE probe), so each page must remain its own VMA. Requiring the
     * full count makes a short read or a producer cap observable instead of
     * merely checking that some blocks exceed 256.
     */
    size_t expected_stress_vmas = stress_size / page_size;
    if (expected_stress_vmas <= 256 ||
        count_vmas_in_range(info, stress, stress + stress_size) !=
            expected_stress_vmas)
        return false;
    for (size_t i = 0; i < expected_stress_vmas; i++) {
        const smaps_vma_t *page = find_vma(info, stress + i * page_size);
        if (!page || page->start != stress + i * page_size ||
            page->end != stress + (i + 1) * page_size)
            return false;
    }
    const smaps_vma_t *stress_none = find_vma(info, stress + 2 * page_size);
    if (!stress_none || strcmp(stress_none->perms, "---p") ||
        stress_none->vmflags_wr)
        return false;
    return true;
}

static bool read_exact(int fd, void *data, size_t len)
{
    char *p = data;
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, p + done, len - done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        done += (size_t) n;
    }
    return true;
}

static bool write_exact(int fd, const void *data, size_t len)
{
    const char *p = data;
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, p + done, len - done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        done += (size_t) n;
    }
    return true;
}

static int child_probe(uintptr_t target,
                       uintptr_t stress,
                       size_t page_size,
                       size_t stress_size)
{
    void *postfork = MAP_FAILED;
    uintptr_t target_end = target + 3 * page_size;
    uintptr_t stress_end = stress + stress_size;

#ifdef MAP_FIXED_NOREPLACE
    /* Keep the probe in a known gap so the synthetic smaps builder cannot merge
     * it with the target's final rw page or the stress fixture.
     */
    uintptr_t fixed_hint = 0x700000000000ULL;
    for (int attempt = 0; attempt < 32; attempt++) {
        void *candidate =
            mmap((void *) fixed_hint, page_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (candidate != MAP_FAILED) {
            uintptr_t p = (uintptr_t) candidate;
            if (p != target_end && p + page_size != target && p != stress_end &&
                p + page_size != stress) {
                postfork = candidate;
                break;
            }
            munmap(candidate, page_size);
        }
        fixed_hint += 16 * page_size;
    }
#endif

    if (postfork == MAP_FAILED) {
        uintptr_t hint = stress_end + 64 * page_size;
        for (int attempt = 0; attempt < 32; attempt++) {
            void *candidate =
                mmap((void *) hint, page_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (candidate == MAP_FAILED)
                break;
            uintptr_t p = (uintptr_t) candidate;
            if (p != target_end && p + page_size != target && p != stress_end &&
                p + page_size != stress) {
                postfork = candidate;
                break;
            }
            munmap(candidate, page_size);
            hint += 64 * page_size;
        }
    }
    if (postfork == MAP_FAILED)
        return 1;

    char pid_path[64];
    snprintf(pid_path, sizeof(pid_path), "/proc/%ld/smaps", (long) getpid());
    const char *paths[] = {"/proc/self/smaps", pid_path};

    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        smaps_info_t info;
        if (!load_smaps(paths[i], &info)) {
            munmap(postfork, page_size);
            return 1;
        }
        bool ok =
            validate_layout(&info, target, stress, page_size, stress_size);
        const smaps_vma_t *first = find_vma(&info, target);
        const smaps_vma_t *middle = find_vma(&info, target + page_size);
        const smaps_vma_t *last = find_vma(&info, target + 2 * page_size);
        const smaps_vma_t *stress_ro = find_vma(&info, stress);
        const smaps_vma_t *stress_rw = find_vma(&info, stress + page_size);
        const smaps_vma_t *stress_none =
            find_vma(&info, stress + 2 * page_size);
        const smaps_vma_t *postfork_vma = find_vma(&info, (uintptr_t) postfork);
        if (!ok || !first || !middle || !last || !stress_ro || !stress_rw ||
            !stress_none || !postfork_vma) {
            free_smaps(&info);
            munmap(postfork, page_size);
            return 1;
        }
        free_smaps(&info);
    }
    munmap(postfork, page_size);
    return 0;
}

int main(void)
{
    long page_size_long = sysconf(_SC_PAGESIZE);
    TEST("smaps page size and VMA fixture");
    if (page_size_long < 1024 || page_size_long % 1024 != 0) {
        FAIL("sysconf(_SC_PAGESIZE)");
        SUMMARY("test-proc-smap");
        return 1;
    }
    PASS();
    size_t page_size = (size_t) page_size_long;

    size_t target_size = 3 * page_size;
    char *target = mmap(NULL, target_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    size_t stress_pages = 320;
    size_t stress_size = stress_pages * page_size;
    char *stress = MAP_FAILED;
    bool fixture_ok = target != MAP_FAILED;
    if (fixture_ok)
        stress = mmap(NULL, stress_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    fixture_ok = fixture_ok && stress != MAP_FAILED;
    if (fixture_ok) {
        *(volatile unsigned char *) target = 0x5a; /* make one page dirty */
        fixture_ok = mprotect(target + page_size, page_size, PROT_READ) == 0;
    }
    if (fixture_ok) {
        /* Start with a read-only page so an allocator placing this mapping
         * immediately after target cannot merge target's final rw page into the
         * stress range. Alternating permissions keeps every stress page as a
         * distinct VMA while preserving the >256 completeness probe.
         */
        for (size_t i = 0; i < stress_pages; i += 2) {
            if (mprotect(stress + i * page_size, page_size, PROT_READ) < 0) {
                fixture_ok = false;
                break;
            }
        }

        /* Keep one page inaccessible so the parser and formatter exercise
         * PROT_NONE coverage and the required empty VmFlags spelling.
         */
        if (fixture_ok &&
            mprotect(stress + 2 * page_size, page_size, PROT_NONE) < 0)
            fixture_ok = false;
    }

    TEST("smaps headers, order, fields, and completeness");
    if (!fixture_ok) {
        FAIL("mmap/mprotect fixture");
    } else {
        char pid_path[64];
        snprintf(pid_path, sizeof(pid_path), "/proc/%ld/smaps",
                 (long) getpid());
        const char *paths[] = {"/proc/self/smaps", pid_path};
        bool ok = true;
        size_t expected_count = 0;
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
            smaps_info_t info;
            bool parsed = load_smaps(paths[i], &info);
            if (!parsed ||
                !validate_layout(&info, (uintptr_t) target, (uintptr_t) stress,
                                 page_size, stress_size)) {
                ok = false;
            } else if (i == 0) {
                expected_count = info.count;
            } else if (info.count != expected_count) {
                ok = false;
            }
            if (parsed)
                free_smaps(&info);
        }
        EXPECT_TRUE(ok, "smaps parser/layout/completeness");
    }

    TEST("fork smaps snapshot of inherited VMAs");
    if (!fixture_ok) {
        FAIL("fixture unavailable");
    } else {
        int pipefd[2] = {-1, -1};
        pid_t pid = pipe(pipefd) == 0 ? fork() : -1;
        if (pid < 0) {
            FAIL("pipe/fork");
            if (pipefd[0] >= 0)
                close(pipefd[0]);
            if (pipefd[1] >= 0)
                close(pipefd[1]);
        } else if (pid == 0) {
            close(pipefd[0]);
            int result = child_probe((uintptr_t) target, (uintptr_t) stress,
                                     page_size, stress_size);
            (void) write_exact(pipefd[1], &result, sizeof(result));
            close(pipefd[1]);
            _exit(result);
        } else {
            close(pipefd[1]);
            int result = 1;
            bool received = read_exact(pipefd[0], &result, sizeof(result));
            close(pipefd[0]);
            int status = 0;
            bool waited = waitpid(pid, &status, 0) == pid;
            EXPECT_TRUE(received && waited && result == 0 &&
                            WIFEXITED(status) && WEXITSTATUS(status) == 0,
                        "fork smaps VMA snapshot");
        }
    }

    if (stress != MAP_FAILED)
        munmap(stress, stress_size);
    if (target != MAP_FAILED)
        munmap(target, target_size);
    SUMMARY("test-proc-smap");
    return fails == 0 ? 0 : 1;
}
