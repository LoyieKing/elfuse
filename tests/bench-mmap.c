/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static int run(size_t pairs, size_t iterations)
{
    const size_t page = 4096;
    const size_t span = pairs * 2 * page;
    unsigned char *base =
        mmap(NULL, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return -1;
    for (size_t i = 0; i < pairs; i++) {
        if (mprotect(base + i * 2 * page, page, PROT_READ | PROT_WRITE)) {
            munmap(base, span);
            return -1;
        }
        *(uint64_t *) (base + i * 2 * page) = i;
    }
    const size_t positions[] = {0, pairs / 2, pairs - 1};
    const char *names[] = {"head", "middle", "tail"};
    for (size_t pos = 0; pos < 3; pos++) {
        unsigned char *target = base + positions[pos] * 2 * page;
        double samples[5];
        for (size_t sample = 0; sample < 5; sample++) {
            uint64_t start = now_ns();
            for (size_t i = 0; i < iterations; i++) {
                void *mapped =
                    mmap(target, page, PROT_READ | PROT_WRITE,
                         MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (mapped != target || *(uint64_t *) target != 0) {
                    fprintf(stderr,
                            "replacement address or zero-fill mismatch\n");
                    munmap(base, span);
                    return -1;
                }
                *(uint64_t *) target = positions[pos];
            }
            samples[sample] = (double) (now_ns() - start) / (double) iterations;
        }
        for (size_t i = 1; i < 5; i++) {
            double value = samples[i];
            size_t j = i;
            while (j > 0 && samples[j - 1] > value) {
                samples[j] = samples[j - 1];
                j--;
            }
            samples[j] = value;
        }
        printf("mmap-fixed pairs=%zu position=%s median_ns=%.1f\n", pairs,
               names[pos], samples[2]);
    }
    for (size_t i = 0; i < pairs; i++) {
        if (*(uint64_t *) (base + i * 2 * page) != i) {
            fprintf(stderr, "neighbor data mismatch at pair %zu\n", i);
            munmap(base, span);
            return -1;
        }
    }
    return munmap(base, span);
}

int main(int argc, char **argv)
{
    size_t iterations = 1000;
    if (argc > 2)
        return 2;
    if (argc == 2) {
        char *end;
        errno = 0;
        unsigned long value = strtoul(argv[1], &end, 10);
        if (errno || *end || value == 0 || value > 100000)
            return 2;
        iterations = value;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    return run(100, iterations) || run(5000, iterations) ? 1 : 0;
}
