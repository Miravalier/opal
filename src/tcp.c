#include <stdbool.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "opal/tcp.h"
#include "opal/error.h"
#include "opal/debug.h"


/* Public Functions */
int tcp_accept(int bound_fd, char **address, uint16_t *port)
{
    struct sockaddr_storage addr_storage;
    socklen_t addr_len = sizeof addr_storage;
    struct sockaddr *addr = (struct sockaddr *)&addr_storage;
    struct sockaddr_in *in_addr = (struct sockaddr_in *)&addr_storage;
    struct sockaddr_in6 *in6_addr = (struct sockaddr_in6 *)&addr_storage;

    // Get connected fd
    int fd = accept(bound_fd, addr, &addr_len);
    if (fd == -1)
    {
        return ACCEPT_ERROR;
    }

    // Get remote address
    if (address != NULL)
    {
        *address = NULL;

        char *ip_string = malloc(INET6_ADDRSTRLEN);
        if (ip_string == NULL)
        {
            opal_debug_error("out of memory during tcp accept");
            close(fd);
            return MEMORY_ERROR;
        }

        if (addr->sa_family == AF_INET)
        {
            if (inet_ntop(addr->sa_family, &in_addr->sin_addr.s_addr, ip_string, INET_ADDRSTRLEN) == NULL)
            {
                close(fd);
                free(ip_string);
                return FORMAT_ERROR;
            }
        }
        else if (addr->sa_family == AF_INET6)
        {
            if (inet_ntop(addr->sa_family, &in6_addr->sin6_addr, ip_string, INET6_ADDRSTRLEN) == NULL)
            {
                close(fd);
                free(ip_string);
                return FORMAT_ERROR;
            }
        }
        else
        {
            close(fd);
            free(ip_string);
            return FORMAT_ERROR;
        }

        *address = ip_string;
    }

    // Get remote port
    if (port != NULL)
    {
        *port = 0;
        if (addr->sa_family == AF_INET)
        {
            *port = ntohs(in_addr->sin_port);
        }
        else if (addr->sa_family == AF_INET6)
        {
            *port = ntohs(in6_addr->sin6_port);
        }
        else
        {
            close(fd);
            return FORMAT_ERROR;
        }
    }

    return fd;
}


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
        .ai_socktype = SOCK_STREAM
    };
    struct addrinfo *results;

    // Perform host lookup
    int gai_status = getaddrinfo(host, service, &hints, &results);
    if (gai_status != 0)
    {
        opal_debug_error("failed to resolve %s/%s: %s", host, service, gai_strerror(gai_status));
        return RESOLVE_ERROR;
    }
    if (results == NULL)
    {
        opal_debug_error("failed to resolve %s/%s: no results", host, service);
        return RESOLVE_ERROR;
    }

    // Try all results until one connects
    for (struct addrinfo *result = results; result != NULL; result = result->ai_next) {
        // Try to open a socket with this result
        fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (fd == -1) {
            opal_debug_strerror("socket failed");
            continue;
        }
        // Try to connect to this result
        if (connect(fd, result->ai_addr, result->ai_addrlen) != 0)
        {
            opal_debug_strerror("connect failed");
            close(fd);
            fd = -1;
            continue;
        }
        break;
    }

    freeaddrinfo(results);

    // If all sockets failed to connect
    if (fd == -1)
    {
        opal_debug_error("connection failed to %s/%s", host, service);
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
    if (inet_pton(AF_INET, ip, &in_addr->sin_addr.s_addr) == 1)
    {
        goto BIND;
    }

    // Try to parse as IPv6
    in6_addr->sin6_family = AF_INET6;
    in6_addr->sin6_port = htons(port);
    *addr_len = sizeof (struct sockaddr_in6);
    if (inet_pton(AF_INET6, ip, &in6_addr->sin6_addr) == 1)
    {
        goto BIND;
    }

    // If neither IPv4 nor IPv6, invalid IP
    opal_debug_error("invalid IP address format");
    return FORMAT_ERROR;

BIND:
    // Create socket
    server_fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd == -1)
    {
        opal_debug_error("socket allocation failed");
        return SOCKET_ERROR;
    }

    // Bind
    if (bind(server_fd, addr, *addr_len) != 0)
    {
        close(server_fd);
        opal_debug_strerror("failed to bind to %s:%u", ip, port);
        return BIND_ERROR;
    }

    // Listen
    (void) listen(server_fd, 8);

    return server_fd;
}
