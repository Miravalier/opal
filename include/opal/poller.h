#ifndef _OPAL_POLLER_H
#define _OPAL_POLLER_H

#include <sys/epoll.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_POLL_EVENTS 16

typedef struct poller_t {
    struct epoll_event events[MAX_POLL_EVENTS];
    int fd;
    int events_pending;
} poller_t;

bool poller_init(poller_t *poller);
bool poller_add(poller_t *poller, int fd, uint32_t events);
bool poller_add_ctx(poller_t *poller, int fd, uint32_t events, void *ctx);
bool poller_modify(poller_t *poller, int fd, uint32_t events);
bool poller_modify_ctx(poller_t *poller, int fd, uint32_t events, void *ctx);
bool poller_remove(poller_t *poller, int fd);
bool poller_wait(poller_t *poller, int *fd, int *events, int timeout);
bool poller_wait_ctx(poller_t *poller, void **ctx, int *events, int timeout);
void poller_fini(poller_t *poller);

#endif
