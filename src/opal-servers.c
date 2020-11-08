#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>

#include "opal/servers.h"
#include "opal/threadpool.h"
#include "opal/poller.h"
#include "opal/debug.h"

// Types
typedef union generic_addr_u {
    struct sockaddr     sa;
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;
} generic_addr_u;


typedef struct json_request_context_t {
    // Poll fields
    int         fd;
    char        *ip;
    uint16_t    port;
    int         events;

    // IO Fields
    uint8_t     *buffer;
    size_t      count;
    size_t      capacity;
    
    uint8_t     *excess_buffer;
    size_t      excess_count;
    size_t      excess_capacity;
} json_request_context_t;


// Function prototypes
static int bind_server_socket(const char *ip, uint16_t port, int *server_fd, generic_addr_u *server_addr, socklen_t *server_addr_len);
static int json_request_dispatcher(json_request_context_t *ctx, json_request_handler_f handler);
static size_t json_object_length(const char *data, size_t bytes);
static json_request_context_t *json_request_context_new(int fd, const char *ip, uint16_t port);
static void json_request_context_delete(json_request_context_t *ctx);



/* Static Functions */
static size_t json_object_length(const char *data, size_t bytes)
{
    // Skip prefixed whitespace
    while (bytes > 0 && isspace(*data)) {
        data++;
        bytes--;
    }
    // Short circuit if the data cannot be an object.
    if (bytes < 2 || *data != '{') return 0;

    // Keep track of braces, waiting for the brace count to reach zero.
    int depth = 0;
    for (size_t i=0; i < bytes; i++) {
        if (data[i] == '{') depth++;
        else if (data[i] == '}') depth--;
        
        // If the braces are matched at this point, return the length of the object up to here.
        if (depth == 0) {
            return i + 1;
        }
    }

    // If the end of the data is reached and the braces are mismatched, return 0.
    return 0;
}


static int json_request_dispatcher(json_request_context_t *ctx, json_request_handler_f handler)
{
    cJSON *request, *reply;

    // Initial connection
    if (ctx->events == 0) {
        return EPOLLIN;
    }
    // Ready to read
    else if (ctx->events & EPOLLIN) {
        // Resize buffer if necessary
        if (ctx->count + 4096 > ctx->capacity) {
            // Find new capacity
            do {
                ctx->capacity *= 2;
            } while (ctx->count + 4096 > ctx->capacity);
            // Reallocate the buffer
            uint8_t *buffer = realloc(ctx->buffer, ctx->capacity);
            if (buffer == NULL)
            {
                opal_puts("out of memory");
                return 0;
            }
            ctx->buffer = buffer;
        }
        // Read as many bytes as are available, up to 4096
        ssize_t bytes = read(ctx->fd, ctx->buffer + ctx->count, 4096);
        if (bytes <= 0) {
            opal_puts("read failed");
            return 0;
        }
        ctx->count += (size_t)bytes;

    CHECK_FOR_REQUESTS:
        // If the data cannot possibly be valid, close the connection
        if (ctx->count > 0 && ctx->buffer[0] != '{') {
            return 0;
        }
        
        // If the data in the buffer forms at least one complete JSON object, call the handler.
        size_t offset = json_object_length((char *)ctx->buffer, ctx->count);
        if (offset > 0) {
            // Create request and reply objects
            request = cJSON_ParseWithLength(ctx->buffer, offset);
            if (request == NULL) {
                return 0;
            }
            reply = cJSON_CreateObject();
            if (reply == NULL) {
                opal_puts("out of memory");
                cJSON_Delete(request);
                return 0;
            }
            // Call handler
            if (!handler(request, reply, ctx->ip, ctx->port)) {
                cJSON_Delete(request);
                cJSON_Delete(reply);
                return 0;
            }
            // Save excess bytes
            ctx->excess_buffer = ctx->buffer;
            ctx->excess_capacity = ctx->capacity;
            ctx->excess_count = ctx->count - offset;
            memmove(ctx->excess_buffer, ctx->excess_buffer + offset, ctx->excess_count);
            // Serialize reply to buffer
            ctx->buffer = (uint8_t *)cJSON_Print(reply);
            ctx->capacity = strlen((char *)ctx->buffer);
            ctx->count = 0;
            // Cleanup JSON objects
            cJSON_Delete(request);
            cJSON_Delete(reply);
            // Begin polling for write
            return EPOLLOUT;
        }
        // Otherwise read more bytes to get a complete JSON object
        else {
            return EPOLLIN;
        }
    }
    // Ready to write
    else if (ctx->events & EPOLLOUT) {
        // Write as many bytes as possible out of the reply
        ssize_t bytes = write(ctx->fd, ctx->buffer + ctx->count, ctx->capacity - ctx->count);
        if (bytes <= 0) {
            opal_puts("write failed");
            return 0;
        }
        ctx->count += (size_t) bytes;
        // If the reply is finished being sent, check for requests
        if (ctx->count == ctx->capacity) {
            free(ctx->buffer);
            ctx->buffer = ctx->excess_buffer;
            ctx->count = ctx->excess_count;
            ctx->capacity = ctx->excess_capacity;
            ctx->excess_buffer = NULL;
            ctx->excess_capacity = 0;
            ctx->excess_count = 0;
            goto CHECK_FOR_REQUESTS;
        }
        // Otherwise, continue waiting for an opportunity to send
        else {
            return EPOLLOUT;
        }
    }
    // Error condition on socket
    else {
        opal_puts("error condition on socket");
        return 0;
    }
}


static int bind_server_socket(const char *ip, uint16_t port, int *server_fd, generic_addr_u *server_addr, socklen_t *server_addr_len)
{
    // Try to parse as IPv4
    server_addr->sin.sin_family = AF_INET;
    server_addr->sin.sin_port = htons(port);
    *server_addr_len = sizeof (struct sockaddr_in);
    if (inet_pton(AF_INET, ip, &server_addr->sin.sin_addr.s_addr) == 1)
    {
        goto BIND;
    }

    // Try to parse as IPv6
    server_addr->sin6.sin6_family = AF_INET6;
    server_addr->sin6.sin6_port = htons(port);
    *server_addr_len = sizeof (struct sockaddr_in6);
    if (inet_pton(AF_INET6, ip, &server_addr->sin6.sin6_addr) == 1)
    {
        goto BIND;
    }

    // If neither IPv4 nor IPv6, invalid IP
    return INVALID_IP_ERROR;

BIND:
    // Create socket
    *server_fd = socket(server_addr->sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (*server_fd == -1)
    {
        return SOCKET_ALLOCATION_ERROR;
    }

    // Bind
    if (bind(*server_fd, (struct sockaddr *)server_addr, *server_addr_len) != 0)
    {
        close(*server_fd);
        opal_printf("failed to bind to %s:%u", ip, port);
        return BIND_ERROR;
    }
    listen(*server_fd, 8);

    return SERVE_SUCCESS;
}


static json_request_context_t *json_request_context_new(int fd, const char *ip, uint16_t port)
{
    json_request_context_t *ctx = malloc(sizeof(json_request_context_t));
    ctx->fd = fd;
    ctx->ip = strdup(ip);
    ctx->port = port;
    ctx->events = 0;
    ctx->buffer = malloc(4096);
    ctx->capacity = 4096;
    ctx->count = 0;
    ctx->excess_buffer = NULL;
    ctx->excess_capacity = 0;
    ctx->excess_count = 0;
    return ctx;
}


static void json_request_context_delete(json_request_context_t *ctx)
{
    free(ctx->ip);
    if (ctx->buffer != NULL) {
        free(ctx->buffer);
    }
    if (ctx->excess_buffer != NULL) {
        free(ctx->excess_buffer);
    }
    shutdown(ctx->fd, SHUT_RDWR);
    close(ctx->fd);
    free(ctx);
}


/* Public Functions */
int json_request_server(const char *ip, uint16_t port, json_request_handler_f handler)
{
    // Bind socket
    int server_fd;
    generic_addr_u server_addr;
    socklen_t server_addr_len;

    int status = bind_server_socket(ip, port, &server_fd, &server_addr, &server_addr_len);
    if (status != SERVE_SUCCESS)
    {
        return status;
    }

    // Set up poller
    json_request_context_t listen_context = {
        .fd = server_fd
    };
    poller_t poller;
    poller_init(&poller);
    poller_add_ctx(&poller, server_fd, EPOLLIN, &listen_context);

    // Poll
    while (true) {
        json_request_context_t *poll_ctx;
        int events;
        opal_puts("Polling ...");
        if (!poller_wait_ctx(&poller, (void **)&poll_ctx, &events, -1)) {
            break;
        }
        poll_ctx->events = events;

        // Server socket
        if (poll_ctx->fd == server_fd) {
            if (events & EPOLLIN == 0) {
                return POLL_ERROR;
            }

            // Get connection
            generic_addr_u connection_addr;
            socklen_t connection_addr_len = server_addr_len;
            int connection_fd = accept(server_fd, (struct sockaddr*)&connection_addr, &connection_addr_len);
            if (connection_fd == -1)
            {
                opal_puts("failed to accept");
                return ACCEPT_ERROR;
            }

            // Convert address to string
            char connection_addr_string[INET6_ADDRSTRLEN];
            uint16_t connection_port;
            if (server_addr.sa.sa_family == AF_INET)
            {
                inet_ntop(AF_INET, &connection_addr.sin.sin_addr, connection_addr_string, INET_ADDRSTRLEN);
                connection_port = ntohs(connection_addr.sin.sin_port);
            }
            else if (server_addr.sa.sa_family == AF_INET6)
            {
                inet_ntop(AF_INET6, &connection_addr.sin6.sin6_addr, connection_addr_string, INET6_ADDRSTRLEN);
                connection_port = ntohs(connection_addr.sin6.sin6_port);
            }
            else
            {
                close(connection_fd);
                close(server_fd);
                return INVALID_IP_ERROR;
            }

            // Create a poll context
            json_request_context_t *new_ctx = json_request_context_new(connection_fd, connection_addr_string, connection_port);

            // Call the dispatcher
            int event_mask = json_request_dispatcher(new_ctx, handler);
            if (event_mask == 0) {
                json_request_context_delete(new_ctx);
                continue;
            }

            // If the dispatcher returned a valid mask, add it to the poller
            poller_add_ctx(&poller, connection_fd, event_mask, new_ctx);
            opal_printf("New connection from %s:%u", new_ctx->ip, new_ctx->port);
        }
        else {
            // If events pop for a connected socket, call the dispatcher
            int event_mask = json_request_dispatcher(poll_ctx, handler);
            if (event_mask == 0) {
                poller_remove(&poller, poll_ctx->fd);
                opal_printf("Connection closed from %s:%u", poll_ctx->ip, poll_ctx->port);
                json_request_context_delete(poll_ctx);
            }
            else {
                poller_modify_ctx(&poller, poll_ctx->fd, event_mask, poll_ctx);
            }
        }
    }

    // Poll failed
    poller_fini(&poller);
    close(server_fd);
    return POLL_ERROR;
}
