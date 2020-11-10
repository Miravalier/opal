#ifndef _OPAL_DEBUG_H
#define _OPAL_DEBUG_H

#include <stdio.h>

#define SGR_RED     "\x1B[31m"
#define SGR_CYAN    "\x1B[32m"
#define SGR_YELLOW  "\x1B[33m"
#define SGR_GREEN   "\x1B[34m"
#define SGR_RESET   "\x1B[0m"

/* Debug versions */
#ifndef NDEBUG

#include <errno.h>

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

#define opal_error(fmt, ...)    opal_printf(                    \
                                    SGR_RED "error" SGR_RESET   \
                                    ": "                        \
                                    fmt, ##__VA_ARGS__          \
                                )

#define opal_success(fmt, ...)  opal_printf(                        \
                                    SGR_GREEN "success" SGR_RESET   \
                                    ": "                            \
                                    fmt, ##__VA_ARGS__              \
                                )

#define opal_debug(fmt, ...)    opal_printf(                    \
                                    "debug: "                   \
                                    fmt, ##__VA_ARGS__          \
                                )

#define opal_info(fmt, ...)     opal_printf(                        \
                                    SGR_YELLOW "info" SGR_RESET     \
                                    ": "                            \
                                    fmt, ##__VA_ARGS__              \
                                )

#define opal_strerror(fmt, ...) do {                                                    \
                                    char _opal_strerror_buffer[64] = "unknown error";   \
                                    (void)strerror_r(errno, _opal_strerror_buffer, 64); \
                                    opal_printf(                                        \
                                        SGR_RED "error" SGR_RESET                       \
                                        ": " fmt ", %s",                                \
                                        ##__VA_ARGS__,                                \
                                        _opal_strerror_buffer                           \
                                    );                                                  \
                                } while (0)

#else

/* Debug off versions */
#define opal_puts(s)            (void)s
#define opal_printf(fmt, ...)   (void)fmt
#define opal_error(fmt, ...)    (void)fmt
#define opal_success(fmt, ...)  (void)fmt
#define opal_info(fmt, ...)     (void)fmt
#define opal_debug(fmt, ...)    (void)fmt
#define opal_strerror(fmt, ...) (void)fmt

#endif // NDEBUG

#endif
