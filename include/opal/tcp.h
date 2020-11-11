#ifndef _OPAL_TCP_H
#define _OPAL_TCP_H

#include <stdbool.h>
#include <stdbool.h>
#include <netinet/in.h>

/** @return A bound connected socket fd, or one of opal_error_e on error (a negative number). */
int tcp_connect(const char *host, const char *service);

/** @return A bound TCP socket fd, or one of opal_error_e on error (a negative number). */
int tcp_bind(const char *ip, uint16_t port, struct sockaddr *server_addr, socklen_t *server_addr_len);

/** @return An accepted TCP socket fd, or one of opal_error_e on error (a negative number). */
int tcp_accept(int bound_fd, char **address, uint16_t *port);

/** @return True on success, false on socket error. */
bool tcp_write_all(int fd, const void *buffer, size_t bytes);

/** @return True on success, false on socket error. */
bool tcp_read_all(int fd, void *buffer, size_t bytes);


#endif
