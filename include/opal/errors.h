#ifndef _OPAL_ERRORS_H
#define _OPAL_ERRORS_H

typedef opal_error_e {
    OPAL_SUCCESS = 0,
    MEMORY_ERROR = -1,
    ACCEPT_ERROR = -2,
    BIND_ERROR = -3,
    POLL_ERROR = -4,
    CONNECT_ERROR = -5,
    RESOLVE_ERROR = -6,
    FORMAT_ERROR = -7,
    SOCKET_ERROR = -8,
} opal_error_e;

#endif
