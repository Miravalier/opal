#ifndef _OPAL_DEBUG_H
#define _OPAL_DEBUG_H

#include <stdio.h>

#define SGR_YELLOW  "\x1B[33m"
#define SGR_CYAN    "\x1B[32m"
#define SGR_RESET   "\x1B[0m"

#define opal_puts(s)            printf(                         \
                                    SGR_YELLOW "%s" SGR_RESET   \
                                    ":"                         \
                                    SGR_CYAN "%d" SGR_RESET     \
                                    " %s\n",                    \
                                    __FILE__, __LINE__, s       \
                                )

#define opal_printf(fmt, ...)   printf(                                 \
                                    SGR_YELLOW "%s" SGR_RESET           \
                                    ":"                                 \
                                    SGR_CYAN "%d" SGR_RESET             \
                                    " " fmt "\n",                       \
                                    __FILE__, __LINE__, ##__VA_ARGS__   \
                                )

#endif
