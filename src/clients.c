#include <cjson/cJSON.h>

#include "opal/tcp.h"
#include "opal/clients.h"
#include "opal/debug.h"


cJSON *send_json_request(const char *host, const char *service, const cJSON *request)
{
    int fd = tcp_connect(host, service);
    if (fd == -1)
    {
        return NULL;
    }

    uint8_t *request_buffer = cJSON_Print(request);
    if (request_buffer == NULL)
    {
        close(fd);
        return NULL;
    }

    // Send JSON request
    if (!tcp_write_all(request_buffer, strlen(request_buffer)))
    {
        free(request_buffer);
        close(fd);
        return NULL;
    }
    free(request_buffer);

    // Read JSON reply
    while (true)
    {
        const char *parse_end;
        cJSON *reply = cJSON_ParseWithLengthOpts(reply_buffer, reply_size, &parse_end, false);
        uintptr_t offset = (uintptr_t)parse_end - (uintptr_t)reply_buffer;
        if (offset < reply_size - 1)
        {
            opal_error("syntax error in JSON reply");
            close(fd);
            return NULL;
        }
        // If a reply was received
        if (reply != NULL)
        {
            close(fd);
            return reply;
        }
    }
}
