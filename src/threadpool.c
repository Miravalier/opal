#include <stdlib.h>
#include <threadpool.h>

// Static functions
static void *thread_pool_worker(thread_pool_t *pool)
{
    while (true) {
        // Wait for task and args
        job_t *job = thread_pool_get_job(pool);
        void *(*task)(void *) = job->task;
        void *args = job->args;
        free(job);
        // Perform task
        task(args);
    }
}


// Public functions
job_t *thread_pool_get_job(thread_pool_t *pool)
{
    // Wait for a job to post
    sem_wait(&pool->job_count);

    // Critical section, retrieve job
    pthread_mutex_lock(&pool->job_lock);
    job_t *job = pool->jobs_head;
    pool->jobs_head = job->next;
    if (pool->jobs_head == NULL) {
        pool->jobs_tail = NULL;
    }
    pthread_mutex_unlock(&pool->job_lock);

    return job;
}


bool thread_pool_put_job(thread_pool_t *pool, void *(*task)(void *), void *args)
{
    // Allocate job memory
    job_t *job = malloc(sizeof(job_t));
    if (job == NULL)
    {
        return false;
    }
    job->task = task;
    job->args = args;
    job->next = NULL;

    // Critical section, append job
    pthread_mutex_lock(&pool->job_lock);
    if (pool->jobs_head == NULL)
    {
        pool->jobs_head = job;
        pool->jobs_tail = job;
    }
    else
    {
        pool->jobs_tail->next = job;
        pool->jobs_tail = job;
    }
    pthread_mutex_unlock(&pool->job_lock);

    // Release the job
    sem_post(&pool->job_count);
    return true;
}


bool thread_pool_init(thread_pool_t *pool, int worker_count)
{
    // Allocate worker id memory
    pool->worker_ids = malloc(sizeof(pthread_t) * worker_count);
    if (pool->worker_ids == NULL) {
        return false;
    }
    pool->worker_count = worker_count;

    // Initialize linked list, semaphore, and mutex
    pool->jobs_head = NULL;
    pool->jobs_tail = NULL;

    if (sem_init(&pool->job_count, 0, 0) != 0) {
        free(pool->worker_ids);
        return false;
    }

    if (pthread_mutex_init(&pool->job_lock, NULL) != 0) {
        free(pool->worker_ids);
        sem_destroy(&pool->job_count);
        return false;
    }

    // Start threads
    for (int i=0; i < worker_count; i++) {
        if (pthread_create(pool->worker_ids + i, NULL, (void *(*) (void *))thread_pool_worker, pool) != 0)
        {
            // Pthread create failed
            for (int j=0; j < i; j++) {
                pthread_cancel(pool->worker_ids[j]);
            }
            free(pool->worker_ids);
            sem_destroy(&pool->job_count);
            pthread_mutex_destroy(&pool->job_lock);
            return false;
        }
        // Pthread create succeeded
        pthread_detach(pool->worker_ids[i]);
    }
    
    return true;
}


void thread_pool_fini(thread_pool_t *pool)
{
    // Kill threads
    for (int i=0; i < pool->worker_count; i++) {
        pthread_cancel(pool->worker_ids[i]);
    }
    // Free worker id memory
    free(pool->worker_ids);
    // Free semaphore and mutex
    sem_destroy(&pool->job_count);
    pthread_mutex_destroy(&pool->job_lock);
    // Free jobs
    for (job_t *job = pool->jobs_head; job != NULL;) {
        job_t *next = job->next;
        free(job);
        job = next;
    }
}
