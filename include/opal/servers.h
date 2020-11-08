#ifndef _OPAL_SERVERS_H
#define _OPAL_SERVERS_H

// Includes required for the below types and functions
#include <stdint.h>
#include <cjson/cJSON.h>

// Public types
typedef enum serve_error_e {
    SERVE_SUCCESS,
    INVALID_IP_ERROR,
    SOCKET_ALLOCATION_ERROR,
    BIND_ERROR,
    ACCEPT_ERROR,
    MEMORY_ERROR,
    THREAD_ERROR,
    POLL_ERROR
} serve_error_e;

/** Performs blocking reads and writes with the given fd. Not responsible for closing the fd. */
typedef void (*connection_handler_f)(int fd, const char *remote_address, uint16_t remote_port);

/**
 * Uses the two request input parameters (request and request_size) to formulate a reply, 
 * which is returned by two output parameters (reply and reply_size).
 * @return The number of bytes to try to read, 0 to send the reply, or -1 to close the connection.
 */
typedef int (*request_handler_f)(
        const uint8_t *request, size_t request_size,
        uint8_t **reply, size_t *reply_size,
        const char *remote_address, uint16_t remote_port);

/**
 * Uses the provided json object to formulate a json object reply.
 * @return True to send the reply or false to close the connection.
 */
typedef bool (*json_request_handler_f)(const cJSON *request, cJSON *reply, const char *remote_address, uint16_t remote_port);


// Public functions
/** Spins off a new thread for every incoming connection. */
int tcp_threaded_serve(const char *ip, uint16_t port, connection_handler_f handler);
/** Assigns incoming connections a worker from a thread pool. */
int tcp_thread_pool_serve(const char *ip, uint16_t port, connection_handler_f handler, int workers);
/** Polls on incoming connections in a single thread. Deals with byte frames. */
int tcp_request_serve(const char *ip, uint16_t port, request_handler_f handler);
/** Polls on incoming connections in a single thread. Deals with JSON objects. */
int tcp_json_request_serve(const char *ip, uint16_t port, json_request_handler_f handler);

#endif
