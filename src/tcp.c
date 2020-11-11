#include <stdbool.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include "opal/tcp.h"
#include "opal/error.h"
#include "opal/debug.h"


/* Public Functions */
bool tcp_read_all(int fd, void *buffer, size_t bytes)
{
    size_t bytes_recved = 0;
    while (bytes_recved < bytes)
    {
        ssize_t last_recv = read(fd, (uint8_t*)buffer + bytes_recved, bytes - bytes_recved);
        if (last_recv <= 0)
        {
            return false;
        }
        bytes_recved += (size_t)last_recv;
    }
    return true;
}


bool tcp_write_all(int fd, const void *buffer, size_t bytes)
{
    size_t bytes_sent = 0;
    while (bytes_sent < bytes)
    {
        ssize_t last_sent = write(fd, (const uint8_t*)buffer + bytes_sent, bytes - bytes_sent);
        if (last_sent <= 0)
        {
            return false;
        }
        bytes_sent += (size_t)last_sent;
    }
    return true;
}


int tcp_connect(const char *host, const char *service)
{
    int fd = -1;
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM
    };
    struct addrinfo *results;

    // Perform host lookup
    int gai_status = getaddrinfo(host, service, &hints, &results);
    if (gai_status != 0)
    {
        opal_error("failed to resolve %s/%s: %s", host, service, gai_strerror(gai_status));
        return RESOLVE_ERROR;
    }
    if (results == NULL)
    {
        opal_error("failed to resolve %s/%s: no results", host, service);
        return RESOLVE_ERROR;
    }

    // Try all results until one connects
    for (struct addrinfo *result = results; result != NULL; result = result->ai_next) {
        // Try to open a socket with this result
        fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (fd == -1) {
            continue;
        }
        // Try to connect to this result
        if (connect(fd, result->ai_addr, result->ai_addrlen) != 0)
        {
            close(fd);
            fd = -1;
            continue;
        }
        // If neither operation failed, this socket is connected
        break;
    }

    // If all sockets failed to connect
    if (fd == -1)
    {
        opal_error("connection failed to %s/%s", host, service);
        return CONNECT_ERROR;
    }
    return fd;
}


int tcp_bind(const char *ip, uint16_t port, struct sockaddr *addr, socklen_t *addr_len)
{
    struct sockaddr_storage unused_addr;
    socklen_t unused_addr_len;
    if (addr == NULL)
    {
        addr = (struct sockaddr *)&unused_addr;
    }
    if (addr_len == NULL)
    {
        addr_len = &unused_addr_len;
    }

    struct sockaddr_in *in_addr = (struct sockaddr_in*)addr;
    struct sockaddr_in6 *in6_addr = (struct sockaddr_in6*)addr;

    int server_fd = -1;

    // Try to parse as IPv4
    in_addr->sin_family = AF_INET;
    in_addr->sin_port = htons(port);
    *addr_len = sizeof (struct sockaddr_in);
    if (inet_pton(AF_INET, ip, &addr->sin.sin_addr.s_addr) == 1)
    {
        goto BIND;
    }

    // Try to parse as IPv6
    in6_addr->sin6_family = AF_INET6;
    in6_addr->sin6_port = htons(port);
    *addr_len = sizeof (struct sockaddr_in6);
    if (inet_pton(AF_INET6, ip, &addr->sin6.sin6_addr) == 1)
    {
        goto BIND;
    }

    // If neither IPv4 nor IPv6, invalid IP
    opal_error("invalid IP address format");
    return FORMAT_ERROR;

BIND:
    // Create socket
    server_fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd == -1)
    {
        opal_error("socket allocation failed");
        return SOCKET_ERROR;
    }

    // Bind
    if (bind(server_fd, addr, *addr_len) != 0)
    {
        close(server_fd);
        opal_strerror("failed to bind to %s:%u", ip, port);
        return BIND_ERROR;
    }

    // Listen
    (void) listen(server_fd, 8);

    return server_fd;
}
