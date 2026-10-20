/*
 * completion.h - a one-shot "done" signal with a timeout, so the main thread can wait
 * for a callback that runs on another thread, and a way to tell threads apart.
 * Windows and POSIX versions.
 */
#ifndef COMPLETION_H
#define COMPLETION_H

#include <stdbool.h>

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef struct completion {
    SRWLOCK lock;
    CONDITION_VARIABLE cv;
    bool done;
} completion_t;

typedef DWORD thread_id_t;

static thread_id_t current_thread(void) { return GetCurrentThreadId(); }
static bool same_thread(thread_id_t a, thread_id_t b) { return a == b; }

static void completion_init(completion_t* c)
{
    InitializeSRWLock(&c->lock);
    InitializeConditionVariable(&c->cv);
    c->done = false;
}

static void completion_signal(completion_t* c)
{
    AcquireSRWLockExclusive(&c->lock);
    c->done = true;
    ReleaseSRWLockExclusive(&c->lock);
    WakeAllConditionVariable(&c->cv);
}

/* Returns true if signalled, false on timeout. */
static bool completion_wait(completion_t* c, unsigned timeout_ms)
{
    ULONGLONG deadline = GetTickCount64() + timeout_ms;
    AcquireSRWLockExclusive(&c->lock);
    while (!c->done) {
        ULONGLONG now = GetTickCount64();
        if (now >= deadline)
            break;
        SleepConditionVariableSRW(&c->cv, &c->lock, (DWORD)(deadline - now), 0);
    }
    bool done = c->done;
    ReleaseSRWLockExclusive(&c->lock);
    return done;
}

#else

#include <pthread.h>
#include <time.h>

typedef struct completion {
    pthread_mutex_t lock;
    pthread_cond_t cv;
    bool done;
} completion_t;

typedef pthread_t thread_id_t;

static thread_id_t current_thread(void) { return pthread_self(); }
static bool same_thread(thread_id_t a, thread_id_t b) { return pthread_equal(a, b) != 0; }

static void completion_init(completion_t* c)
{
    pthread_mutex_init(&c->lock, NULL);
    pthread_cond_init(&c->cv, NULL);
    c->done = false;
}

static void completion_signal(completion_t* c)
{
    pthread_mutex_lock(&c->lock);
    c->done = true;
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->lock);
}

/* Returns true if signalled, false on timeout. */
static bool completion_wait(completion_t* c, unsigned timeout_ms)
{
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&c->lock);
    int rc = 0;
    while (!c->done && rc == 0)
        rc = pthread_cond_timedwait(&c->cv, &c->lock, &deadline);
    bool done = c->done;
    pthread_mutex_unlock(&c->lock);
    return done;
}

#endif

#endif /* COMPLETION_H */
