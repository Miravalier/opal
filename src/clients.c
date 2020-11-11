#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <cjson/cJSON.h>

#include "opal/tcp.h"
#include "opal/clients.h"
#include "opal/debug.h"


cJSON *send_json_request(int fd, const cJSON *request)
{
    uint8_t *request_buffer = cJSON_Print(request);
    if (request_buffer == NULL)
    {
        return NULL;
    }

    // Send JSON request
    if (!tcp_write_all(fd, request_buffer, strlen(request_buffer)))
    {
        free(request_buffer);
        return NULL;
    }
    free(request_buffer);

    // Read JSON reply
    size_t reply_capacity = 4096;
    size_t reply_size = 0;
    uint8_t *reply_buffer = malloc(reply_capacity);
    if (reply_buffer == NULL)
    {
        opal_debug_error("out of memory during JSON request");
        return NULL;
    }

    while (true)
    {
        // Resize reply buffer if necessary
        if (reply_capacity < reply_size + 1024)
        {
            do {
                reply_capacity *= 2;
            } while (reply_capacity < reply_size + 1024);
            uint8_t *resized_reply_buffer = realloc(reply_buffer, reply_capacity);
            if (resized_reply_buffer == NULL)
            {
                opal_debug_error("out of memory during JSON request");
                free(reply_buffer);
                return NULL;
            }
            reply_buffer = resized_reply_buffer;
        }

        // Read as many bytes as fit in the buffer
        ssize_t last_read = read(fd, reply_buffer + reply_size, reply_capacity - reply_size);
        if (last_read <= 0)
        {
            opal_debug_strerror("read failed during json request");
            free(reply_buffer);
            return NULL;
        }
        reply_size += last_read;

        // Try to parse reply
        const char *parse_end;
        cJSON *reply = cJSON_ParseWithLengthOpts((char *)reply_buffer, reply_size, &parse_end, false);
        uintptr_t offset = (uintptr_t)parse_end - (uintptr_t)reply_buffer;
        if (reply_size - offset > 1)
        {
            opal_debug_error("syntax error in JSON reply");
            free(reply_buffer);
            return NULL;
        }
        // If a reply was received
        if (reply != NULL)
        {
            free(reply_buffer);
            return reply;
        }
    }
}
