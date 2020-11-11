#ifndef _OPAL_CLIENTS_H
#define _OPAL_CLIENTS_H

#include <cjson/cJSON.h>

/** The request object and the returned JSON reply object must be freed by the caller. */
cJSON *send_json_request(int fd, const cJSON *request);

#endif
