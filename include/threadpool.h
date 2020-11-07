#ifndef _THREADPOOL_H
#define _THREADPOOL_H

#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>

typedef struct job_t {
    void *(*task)(void *);
    void *args;
    struct job_t *next;
} job_t;

typedef struct result_t {
    void *result;
    struct result_t *next;
} result_t;

typedef struct thread_pool_t {
    pthread_t   *worker_ids;
    int         worker_count;
    job_t       *jobs_head;
    job_t       *jobs_tail;
    sem_t       job_count;
    pthread_mutex_t job_lock;
} thread_pool_t;

job_t *thread_pool_get_job(thread_pool_t *pool);
bool thread_pool_put_job(thread_pool_t *pool, void *(*task)(void *), void *args);
bool thread_pool_init(thread_pool_t *pool, int worker_count);
void thread_pool_fini(thread_pool_t *pool);

#endif
