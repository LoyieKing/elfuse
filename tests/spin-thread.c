/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Fixture for test-vcpu-watchdog.sh. One task spins while its sibling blocks
 * with a pipe still open. A host timeout must terminate both tasks.
 */
#include <pthread.h>
#include <string.h>
#include <unistd.h>

static int pipe_fds[2];

static void *spin(void *unused)
{
    (void) unused;
    (void) write(STDOUT_FILENO, "worker spinning\n", 16);
    for (;;)
        __asm__ __volatile__("" ::: "memory");
    return NULL;
}

static void *block(void *unused)
{
    (void) unused;
    char byte;
    (void) read(pipe_fds[0], &byte, 1);
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t thread;
    if (pipe(pipe_fds) != 0)
        return 1;
    if (argc == 2 && strcmp(argv[1], "leader") == 0) {
        if (pthread_create(&thread, NULL, block, NULL) != 0)
            return 1;
        (void) spin(NULL);
    } else {
        if (pthread_create(&thread, NULL, spin, NULL) != 0)
            return 1;
        (void) block(NULL);
    }
    return 2;
}
