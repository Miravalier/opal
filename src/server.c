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

#include "server.h"
#include "threadpool.h"
#include "epoll_interface.h"

// Types
typedef union generic_addr_u {
    struct sockaddr     sa;
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;
} generic_addr_u;

typedef struct thread_worker_args_t {
    connection_handler_f handler;
    int         fd;
    char        *ip;
    uint16_t    port;
} thread_worker_args_t;

typedef struct thread_pool_server_context_t {
    connection_handler_f handler;
    thread_pool_t pool;
} thread_pool_server_context_t;

typedef struct tcp_request_dispatcher_context_t {
    request_handler_f handler;
    
    uint8_t *buffer;
    size_t count;
    size_t capacity;
    
    size_t read_size;
} tcp_dispatcher_context_t;

typedef struct tcp_json_dispatcher_context_t {
    json_request_handler_f handler;

    uint8_t *buffer;
    size_t count;
    size_t capacity;
    
    size_t excess_count;
    uint8_t *excess_buffer;
    size_t excess_capacity;
} tcp_json_dispatcher_context_t;

typedef struct poll_context_t {
    int         fd;
    char        *ip;
    uint16_t    port;
} poll_context_t;

typedef void (*raw_handler_f)(void *context, int fd, const char *remote_address, uint16_t remote_port);

/** @return An event mask comprised of EPOLLIN, EPOLLOUT, both, or 0 to close the connection. */
typedef int (*poll_handler_f)(void *context, int events, int fd, const char *remote_address, uint16_t remote_port);


// Function prototypes
static int thread_starter(connection_handler_f handler, int fd, const char *ip, uint16_t port);
static void *thread_worker(thread_worker_args_t *args);
static int raw_serve(const char *ip, uint16_t port, raw_handler_f handler, void *context);
static int poll_serve(const char *ip, uint16_t port, poll_handler_f handler, void *context);
static int tcp_request_dispatcher(tcp_dispatcher_context_t *context, int events, int fd, const char *remote_address, uint16_t remote_port);
static int tcp_json_request_dispatcher(tcp_json_dispatcher_context_t *context, int events, int fd, const char *remote_address, uint16_t remote_port);
static size_t json_object_length(const char *data, size_t bytes);


/* Static Functions */
static size_t json_object_length(const char *data, size_t bytes)
{
    // Skip prefixed whitespace
    while (bytes > 0 && isspace(*data)) {
        data++;
        bytes--;
    }
    // Short circuit if the data cannot be an qobject.
    if (bytes < 2 || *data != '{') return 0;

    // Keep track of braces, waiting for the brace count to reach zero.
    int depth = 0;
    for (size_t i=0; i < bytes; i++) {
        if (data[i] == '{') depth++;
        else if (data[i] == '}') depth--;
        
        // If the braces are matched at this point, return the length of the object up to here.
        if (depth == 0) {
            return i;
        }
    }

    // If the end of the data is reached and the braces are mismatched, return 0.
    return 0;
}


static int tcp_request_dispatcher(tcp_dispatcher_context_t *context, int events, int fd, const char *remote_address, uint16_t remote_port)
{
    // Initial connection
    if (events == 0) {
        goto CALL_HANDLER;
    }
    // Ready to read
    else if (events & EPOLLIN) {
        // Resize buffer if necessary
        if (context->count + context->read_size > context->capacity) {
            // Find new capacity
            do {
                context->capacity *= 2;
            } while (context->count + context->read_size > context->capacity);
            // Reallocate the buffer
            uint8_t *buffer = realloc(context->buffer, context->capacity);
            if (buffer == NULL)
            {
                return 0;
            }
            context->buffer = buffer;
        }
        // Read as many bytes as are available, up to the number of bytes wanted
        ssize_t bytes = read(fd, context->buffer + context->count, context->read_size);
        if (bytes <= 0) {
            return 0;
        }
        context->count += (size_t)bytes;
        goto CALL_HANDLER;
    }
    // Ready to write
    else if (events & EPOLLOUT) {
        // Write as many bytes as possible out of the reply
        ssize_t bytes = write(fd, context->buffer + context->count, context->capacity - context->count);
        if (bytes <= 0) {
            return 0;
        }
        context->count += (size_t) bytes;
        // If the reply is finished being sent, call the handler
        if (context->count == context->capacity) {
            context->count = 0;
            goto CALL_HANDLER;
        }
        else {
            return EPOLLOUT;
        }
    }
    // Error condition on socket
    else {
        return 0;
    }

CALL_HANDLER:
    {
        uint8_t *reply = NULL;
        size_t reply_size = 0;
        int read_size = context->handler(context->buffer, context->count, &reply, &reply_size, remote_address, remote_port);
        // If the handler is ready to write, set EPOLLOUT
        if (read_size = 0) {
            free(context->buffer);
            context->buffer = reply;
            context->capacity = reply_size;
            context->count = 0;
            return EPOLLOUT;
        }
        // If an error has occured, close the connection
        else if (read_size < 0) {
            return 0;
        }
        // Otherwise, set read size and EPOLLIN
        else {
            context->read_size = read_size;
            return EPOLLIN;
        }
    }
}


static int tcp_json_request_dispatcher(tcp_json_dispatcher_context_t *context, int events, int fd, const char *remote_address, uint16_t remote_port)
{
    cJSON *request, *reply;

    // Initial connection
    if (events == 0) {
        return EPOLLIN;
    }
    // Ready to read
    else if (events & EPOLLIN) {
        // Resize buffer if necessary
        if (context->count + 4096 > context->capacity) {
            // Find new capacity
            do {
                context->capacity *= 2;
            } while (context->count + 4096 > context->capacity);
            // Reallocate the buffer
            uint8_t *buffer = realloc(context->buffer, context->capacity);
            if (buffer == NULL)
            {
                return 0;
            }
            context->buffer = buffer;
        }
        // Read as many bytes as are available, up to 4096
        ssize_t bytes = read(fd, context->buffer + context->count, 4096);
        if (bytes <= 0) {
            return 0;
        }
        context->count += (size_t)bytes;

    CHECK_FOR_REQUESTS:
        // If the data cannot possibly be valid, close the connection
        if (context->count > 0 && context->buffer[0] != '{') {
            return 0;
        }
        
        // If the data in the buffer forms at least one complete JSON object, call the handler.
        size_t offset = json_object_length((char *)context->buffer, context->count);
        if (offset > 0) {
            // Create request and reply objects
            request = cJSON_ParseWithLength(context->buffer, offset);
            if (request == NULL) {
                return 0;
            }
            reply = cJSON_CreateObject();
            if (reply == NULL) {
                cJSON_Delete(request);
                return 0;
            }
            // Call handler
            if (!context->handler(request, reply, remote_address, remote_port)) {
                cJSON_Delete(request);
                cJSON_Delete(reply);
                return 0;
            }
            // Save excess bytes
            context->excess_buffer = context->buffer;
            context->excess_capacity = context->capacity;
            context->excess_count = context->count - offset;
            memmove(context->excess_buffer, context->excess_buffer + offset, context->excess_count);
            // Serialize reply to buffer
            context->buffer = (uint8_t *)cJSON_Print(reply);
            context->capacity = strlen((char *)context->buffer);
            context->count = 0;
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
    else if (events & EPOLLOUT) {
        // Write as many bytes as possible out of the reply
        ssize_t bytes = write(fd, context->buffer + context->count, context->capacity - context->count);
        if (bytes <= 0) {
            return 0;
        }
        context->count += (size_t) bytes;
        // If the reply is finished being sent, check for requests
        if (context->count == context->capacity) {
            free(context->buffer);
            context->buffer = context->excess_buffer;
            context->count = context->excess_count;
            context->excess_capacity = context->excess_capacity;
            goto CHECK_FOR_REQUESTS;
        }
        // Otherwise, continue waiting for an opportunity to send
        else {
            return EPOLLOUT;
        }
    }
    // Error condition on socket
    else {
        return 0;
    }
}


static int thread_pool_assigner(thread_pool_server_context_t *context, int fd, const char *ip, uint16_t port)
{
    thread_worker_args_t *args = malloc(sizeof(thread_worker_args_t));
    if (args == NULL) {
        return MEMORY_ERROR;
    }

    args->handler = context->handler;
    args->fd = fd;
    args->ip = strdup(ip);
    args->port = port;

    if (!thread_pool_put_job(&context->pool, (void *(*)(void *))thread_worker, args)) {
        return MEMORY_ERROR;
    }
}

static int thread_starter(connection_handler_f handler, int fd, const char *ip, uint16_t port)
{
    thread_worker_args_t *args = malloc(sizeof(thread_worker_args_t));
    if (args == NULL) {
        return MEMORY_ERROR;
    }

    args->handler = handler;
    args->fd = fd;
    args->ip = strdup(ip);
    args->port = port;

    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, (void *(*) (void *))thread_worker, args) != 0)
    {
        free(args);
        return THREAD_ERROR;
    }
    pthread_detach(thread_id);

    return SERVE_SUCCESS;
}

static void *thread_worker(thread_worker_args_t *args)
{
    // Run handler
    args->handler(args->fd, args->ip, args->port);

    // Cleanup
    shutdown(args->fd, SHUT_RDWR);
    close(args->fd);
    free(args->ip);
    free(args);
    return NULL;
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
        return BIND_ERROR;
    }
    listen(*server_fd, 8);

    return SERVE_SUCCESS;
}


static int raw_serve(const char *ip, uint16_t port, raw_handler_f handler, void *context)
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

    // Handle connections
    while (true)
    {
        // Get connection
        generic_addr_u connection_addr;
        socklen_t connection_addr_len = server_addr_len;
        int connection_fd = accept(server_fd, (struct sockaddr*)&connection_addr, &connection_addr_len);
        if (connection_fd == -1)
        {
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

        // Run handler
        handler(context, connection_fd, connection_addr_string, connection_port);
    }

    // Unreachable
    close(server_fd);
    return SERVE_SUCCESS;
}


static int poll_serve(const char *ip, uint16_t port, poll_handler_f handler, void *context)
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
    poll_context_t listen_context = {
        .fd = server_fd
    };
    poller_t poller;
    poller_init(&poller);
    poller_add_ctx(&poller, server_fd, EPOLLIN, &listen_context);

    // Poll
    while (true) {
        poll_context_t *ctx;
        int events;
        if (!poller_wait_ctx(&poller, (void **)&ctx, &events, -1)) {
            break;
        }

        if (ctx->fd == server_fd) {
            // Listening socket
            if (events & EPOLLIN == 0) {
                return POLL_ERROR;
            }
            // Get connection
            generic_addr_u connection_addr;
            socklen_t connection_addr_len = server_addr_len;
            int connection_fd = accept(server_fd, (struct sockaddr*)&connection_addr, &connection_addr_len);
            if (connection_fd == -1)
            {
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

            // Call the handler
            int event_mask = handler(context, 0, connection_fd, connection_addr_string, connection_port);
            if (event_mask == 0) {
                shutdown(connection_fd, SHUT_RDWR);
                close(connection_fd);
                continue;
            }

            // If the handler returned a valid mask, add it to the poller
            poll_context_t *connection_ctx = malloc(sizeof(poll_context_t));
            connection_ctx->fd = connection_fd;
            connection_ctx->ip = strdup(connection_addr_string);
            connection_ctx->port = connection_port;
            poller_add_ctx(&poller, connection_fd, event_mask, connection_ctx);
        }
        else {
            // If events pop for a connected socket, call the handler
            int event_mask = handler(context, events, ctx->fd, ctx->ip, ctx->port);
            if (event_mask == 0) {
                shutdown(ctx->fd, SHUT_RDWR);
                close(ctx->fd);
                poller_remove(&poller, ctx->fd);
                free(ctx->ip);
                free(ctx);
            }
            else {
                poller_modify_ctx(&poller, ctx->fd, event_mask, ctx);
            }
        }
    }

    // Poll failed
    poller_fini(&poller);
    close(server_fd);
    return POLL_ERROR;
}


/* Public Functions */

int tcp_threaded_serve(const char *ip, uint16_t port, connection_handler_f handler)
{
    return raw_serve(ip, port, (raw_handler_f)thread_starter, (void*)handler);
}

int tcp_thread_pool_serve(const char *ip, uint16_t port, connection_handler_f handler, int worker_count)
{
    // Create context
    thread_pool_server_context_t context;
    context.handler = handler;
    if (!thread_pool_init(&context.pool, worker_count)) {
        return THREAD_ERROR;
    }

    // Serve clients
    int status = raw_serve(ip, port, (raw_handler_f)thread_pool_assigner, &context);

    // Cleanup
    thread_pool_fini(&context.pool);
    return status;
}


int tcp_request_serve(const char *ip, uint16_t port, request_handler_f handler)
{
    tcp_dispatcher_context_t context = {
        .handler = handler,
        .buffer = malloc(4096),
        .capacity = 4096,
        .count = 0
    };
    if (context.buffer == NULL) {
        return MEMORY_ERROR;
    }

    int status = poll_serve(ip, port, (poll_handler_f)tcp_request_dispatcher, &context);

    free(context.buffer);
    return status;
}


int tcp_json_request_serve(const char *ip, uint16_t port, json_request_handler_f handler)
{
    tcp_json_dispatcher_context_t context = {
        .handler = handler,
        .buffer = malloc(4096),
        .capacity = 4096,
        .count = 0
    };
    if (context.buffer == NULL) {
        return MEMORY_ERROR;
    }

    int status = poll_serve(ip, port, (poll_handler_f)tcp_json_request_dispatcher, &context);

    free(context.buffer);
    return status;
}
