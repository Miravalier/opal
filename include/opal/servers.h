#ifndef _OPAL_SERVERS_H
#define _OPAL_SERVERS_H

// Includes required for the below types and functions
#include <stdbool.h>
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

/**
 * Uses the provided json object to formulate a json object reply.
 * @return True to send the reply or false to close the connection.
 */
typedef bool (*json_request_handler_f)(const cJSON *request, cJSON *reply, const char *remote_address, uint16_t remote_port);


// Public functions
/** Polls on incoming connections in a single thread. Deals with JSON objects. */
int json_request_server(const char *ip, uint16_t port, json_request_handler_f handler);

#endif
