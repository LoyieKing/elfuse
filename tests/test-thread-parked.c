/*
 * Concurrent parked tasks retain private state through signals and slot reuse.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define PARKED 640

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready = PTHREAD_COND_INITIALIZER;
static pthread_cond_t release = PTHREAD_COND_INITIALIZER;
static int live;
static bool released;
static unsigned char values[PARKED];
static atomic_int correct;
static atomic_int signals;

static void on_usr1(int sig)
{
    (void) sig;
    atomic_fetch_add_explicit(&signals, 1, memory_order_relaxed);
}

static void *parked_fn(void *arg)
{
    int id = (int) (intptr_t) arg;
    unsigned char expected = (unsigned char) (id * 7);
    pthread_mutex_lock(&lock);
    live++;
    pthread_cond_signal(&ready);
    while (!released)
        pthread_cond_wait(&release, &lock);
    if (values[id] == expected)
        atomic_fetch_add_explicit(&correct, 1, memory_order_relaxed);
    pthread_mutex_unlock(&lock);
    return NULL;
}

static void park_wave(void)
{
    pthread_t threads[PARKED];
    int created = 0;
    int error = 0;
    pthread_mutex_lock(&lock);
    live = 0;
    released = false;
    memset(values, 0, sizeof(values));
    atomic_store_explicit(&correct, 0, memory_order_relaxed);
    atomic_store_explicit(&signals, 0, memory_order_relaxed);
    pthread_mutex_unlock(&lock);
    for (int i = 0; i < PARKED; i++) {
        error = pthread_create(&threads[i], NULL, parked_fn, (void *) (intptr_t) i);
        if (error != 0)
            break;
        created++;
    }
    pthread_mutex_lock(&lock);
    while (live != created)
        pthread_cond_wait(&ready, &lock);
    pthread_mutex_unlock(&lock);
    bool ok = created == PARKED;
    if (ok) {
        ok = pthread_kill(threads[0], SIGUSR1) == 0;
        for (int i = 0; i < 2000 &&
                        atomic_load_explicit(&signals, memory_order_relaxed) == 0; i++)
            usleep(1000);
        ok = ok && atomic_load_explicit(&signals, memory_order_relaxed) == 1;
    }
    pthread_mutex_lock(&lock);
    for (int i = 0; i < created; i++)
        values[i] = (unsigned char) (i * 7);
    released = true;
    pthread_cond_broadcast(&release);
    pthread_mutex_unlock(&lock);
    for (int i = 0; i < created; i++)
        if (pthread_join(threads[i], NULL) != 0)
            ok = false;
    if (!ok || atomic_load_explicit(&correct, memory_order_relaxed) != PARKED) {
        printf("(created=%d pthread_error=%d) ", created, error);
        FAIL("parked tasks lost capacity, signal or private state");
        return;
    }
    PASS();
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_usr1;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0)
        return 1;
    TEST("640 parked tasks preserve signal and private state");
    park_wave();
    TEST("640 task slots can be reused after exit");
    park_wave();
    SUMMARY("test-thread-parked");
    return fails ? 1 : 0;
}
