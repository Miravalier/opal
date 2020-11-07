#include <unistd.h>
#include "epoll_interface.h"


bool poller_init(poller_t *poller)
{
    poller->fd = epoll_create1(0);
    if (poller->fd == -1) {
        return false;
    }

    poller->events_pending = 0;

    return true;
}


bool poller_add(poller_t *poller, int fd, uint32_t events)
{
    struct epoll_event added_event = {
        .data = {
            .fd = fd
        },
        .events = events
    };
    return epoll_ctl(poller->fd, EPOLL_CTL_ADD, fd, &added_event) == 0;
}


bool poller_add_ctx(poller_t *poller, int fd, uint32_t events, void *ctx)
{
    struct epoll_event added_event = {
        .data = {
            .ptr = ctx
        },
        .events = events
    };
    return epoll_ctl(poller->fd, EPOLL_CTL_ADD, fd, &added_event) == 0;
}


bool poller_modify(poller_t *poller, int fd, uint32_t events)
{
    struct epoll_event modified_event = {
        .data = {
            .fd = fd
        },
        .events = events
    };
    return epoll_ctl(poller->fd, EPOLL_CTL_MOD, fd, &modified_event) == 0;
}


bool poller_modify_ctx(poller_t *poller, int fd, uint32_t events, void *ctx)
{
    struct epoll_event modified_event = {
        .data = {
            .ptr = ctx
        },
        .events = events
    };
    return epoll_ctl(poller->fd, EPOLL_CTL_MOD, fd, &modified_event) == 0;
}


bool poller_remove(poller_t *poller, int fd)
{
    static struct epoll_event delete_event = {0};
    return epoll_ctl(poller->fd, EPOLL_CTL_DEL, fd, &delete_event) == 0;
}


bool poller_wait(poller_t *poller, int *fd, int *events, int timeout)
{
    if (poller->events_pending == 0) {
        poller->events_pending = epoll_wait(poller->fd, poller->events, MAX_POLL_EVENTS, timeout);
        if (poller->events_pending <= 0) {
            return false;
        }
    }

    struct epoll_event event = poller->events[--poller->events_pending];
    *fd = event.data.fd;
    *events = event.events;

    return true;
}


bool poller_wait_ctx(poller_t *poller, void **ctx, int *events, int timeout)
{
    if (poller->events_pending == 0) {
        poller->events_pending = epoll_wait(poller->fd, poller->events, MAX_POLL_EVENTS, timeout);
        if (poller->events_pending <= 0) {
            return false;
        }
    }

    struct epoll_event event = poller->events[--poller->events_pending];
    *ctx = event.data.ptr;
    *events = event.events;

    return true;
}


void poller_fini(poller_t *poller)
{
    close(poller->fd);
}
