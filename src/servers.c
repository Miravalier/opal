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
#include <cjson/cJSON.h>

#include "opal/tcp.h"
#include "opal/poller.h"
#include "opal/debug.h"
#include "opal/servers.h"
#include "opal/error.h"

// Types
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
static int json_request_dispatcher(json_request_context_t *ctx, json_request_handler_f handler);
static json_request_context_t *json_request_context_new(int fd, char *ip, uint16_t port);
static void json_request_context_delete(json_request_context_t *ctx);


/* Static Functions */
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
                opal_error("out of memory");
                return 0;
            }
            ctx->buffer = buffer;
        }
        // Read as many bytes as are available, up to 4096
        ssize_t bytes = read(ctx->fd, ctx->buffer + ctx->count, 4096);
        if (bytes <= 0) {
            opal_info("connection closed while reading");
            return 0;
        }
        ctx->count += (size_t)bytes;

    CHECK_FOR_REQUESTS:
        // If the buffer is empty, wait for data
        if (ctx->count == 0) {
            return EPOLLIN;
        }

        const char *parse_end;
        request = cJSON_ParseWithLengthOpts(ctx->buffer, ctx->count, &parse_end, false);
        uintptr_t offset = (uintptr_t)parse_end - (uintptr_t)ctx->buffer;

        // If the offset is before the end of the buffer, a syntax error is
        // present in the JSON.
        if (offset < ctx->count - 1) {
            opal_error("syntax error in JSON request");
            return 0;
        }
        // If the data in the buffer forms at least one complete JSON object, call the handler.
        if (request != NULL) {
            // Create reply object
            reply = cJSON_CreateObject();
            if (reply == NULL) {
                opal_error("out of memory");
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
            opal_info("connection closed while writing");
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
        opal_error("error condition on socket");
        return 0;
    }
}


/**
 * @param ip    Takes ownership of ip.
 */
static json_request_context_t *json_request_context_new(int fd, char *ip, uint16_t port)
{
    json_request_context_t *ctx = malloc(sizeof(json_request_context_t));
    ctx->fd = fd;
    ctx->ip = ip;
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
    int server_fd = tcp_bind(ip, port, NULL, NULL);
    if (server_fd < 0)
    {
        return server_fd;
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
            char *remote_address;
            uint16_t remote_port;
            int connection_fd = tcp_accept(server_fd, &remote_address, &remote_port);
            if (connection_fd < 0)
            {
                close(server_fd);
                opal_error("failed to accept");
                return connection_fd;
            }

            // Create a poll context
            json_request_context_t *new_ctx = json_request_context_new(connection_fd, remote_address, remote_port);
            if (new_ctx == NULL)
            {
                free(remote_address);
                return MEMORY_ERROR;
            }

            // Call the dispatcher
            int event_mask = json_request_dispatcher(new_ctx, handler);
            if (event_mask == 0) {
                json_request_context_delete(new_ctx);
                continue;
            }

            // If the dispatcher returned a valid mask, add it to the poller
            poller_add_ctx(&poller, connection_fd, event_mask, new_ctx);
            opal_info("New connection from %s:%u", new_ctx->ip, new_ctx->port);
        }
        else {
            // If events pop for a connected socket, call the dispatcher
            int event_mask = json_request_dispatcher(poll_ctx, handler);
            if (event_mask == 0) {
                poller_remove(&poller, poll_ctx->fd);
                opal_info("Connection closed from %s:%u", poll_ctx->ip, poll_ctx->port);
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
