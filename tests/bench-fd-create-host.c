/*
 * Native open/close baseline for the guest fd-create performance guardrail.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static int create_fd(void)
{
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0)
        return -1;
    return close(fd);
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    char *end;
    errno = 0;
    unsigned long iters = strtoul(argv[1], &end, 10);
    if (errno || *end || argv[1][0] == '-' || iters == 0)
        return 2;
    unsigned long warmup = iters / 20;
    if (warmup < 1000)
        warmup = 1000;
    if (warmup > iters)
        warmup = iters;
    for (unsigned long i = 0; i < warmup; i++) {
        if (create_fd() != 0) {
            perror("native fd-create warmup");
            return 1;
        }
    }

    double samples[3];
    for (unsigned run = 0; run < 3; run++) {
        uint64_t start = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
        for (unsigned long i = 0; i < iters; i++) {
            if (create_fd() != 0) {
                perror("native fd-create");
                return 1;
            }
        }
        samples[run] =
            (double) (clock_gettime_nsec_np(CLOCK_UPTIME_RAW) - start) /
            (double) iters;
    }
    for (unsigned i = 1; i < 3; i++) {
        double value = samples[i];
        unsigned j = i;
        while (j && samples[j - 1] > value) {
            samples[j] = samples[j - 1];
            j--;
        }
        samples[j] = value;
    }
    printf("fd-create %.1f ns/op\n", samples[1]);
    return 0;
}
