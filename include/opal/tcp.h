#ifndef _OPAL_TCP_H
#define _OPAL_TCP_H

#include <stdbool.h>


/** @return A bound TCP socket fd, or one of opal_error_e on error. */
int tcp_bind(const char *ip, uint16_t port, struct sockaddr *server_addr, socklen_t *server_addr_len);

bool tcp_write_all(int fd, const void *buffer, size_t bytes);

bool tcp_read_all(int fd, void *buffer, size_t bytes);


#endif
