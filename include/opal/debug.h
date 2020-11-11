#ifndef _OPAL_DEBUG_H
#define _OPAL_DEBUG_H

#define SGR_RED     "\x1B[31m"
#define SGR_CYAN    "\x1B[32m"
#define SGR_YELLOW  "\x1B[33m"
#define SGR_GREEN   "\x1B[34m"
#define SGR_RESET   "\x1B[0m"

/* Ensure at least one debug macro is defined between NDEBUG and DEBUG */
#if !defined(NDEBUG) && !defined(DEBUG)
#define DEBUG
#endif

/* Ensure both debug macros are not defined */
#if defined(NDEBUG) && defined(DEBUG)
#error Both NDEBUG and DEBUG are defined.
#endif

/* Include stdio, errno, and string headers */
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* If no NDEBUG, print debug opal messages */
#ifndef NDEBUG

#define opal_debug_printf(fmt, ...)                 \
            printf(                                 \
                SGR_YELLOW "%s" SGR_RESET           \
                ":"                                 \
                SGR_CYAN "%d" SGR_RESET             \
                " " fmt "\n",                       \
                __FILE__, __LINE__, ##__VA_ARGS__   \
            )
#define opal_debug_strerror(fmt, ...)                               \
            do {                                                    \
                char _opal_strerror_buffer[64] = "unknown error";   \
                (void)strerror_r(errno, _opal_strerror_buffer, 64); \
                opal_debug_printf(                                  \
                    SGR_RED "error" SGR_RESET                       \
                    ": " fmt ", %s",                                \
                    ##__VA_ARGS__,                                  \
                    _opal_strerror_buffer                           \
                );                                                  \
            } while (0)
#define opal_printf(fmt, ...)                       \
            printf(                                 \
                SGR_YELLOW "%s" SGR_RESET           \
                ":"                                 \
                SGR_CYAN "%d" SGR_RESET             \
                " " fmt "\n",                       \
                __FILE__, __LINE__, ##__VA_ARGS__   \
            )

#else /* NDEBUG */
#define opal_debug_printf(fmt, ...)     (void)(fmt, ##__VA_ARGS__)
#define opal_debug_strerror(fmt, ...)   (void)(fmt, ##__VA_ARGS__)
#define opal_printf(fmt, ...)           printf(fmt "\n", ##__VA_ARGS__)
#endif /* NDEBUG */

#define opal_debug_error(fmt, ...)    opal_debug_printf(        \
                                    SGR_RED "error" SGR_RESET   \
                                    ": "                        \
                                    fmt, ##__VA_ARGS__          \
                                )

#define opal_debug_success(fmt, ...)  opal_debug_printf(            \
                                    SGR_GREEN "success" SGR_RESET   \
                                    ": "                            \
                                    fmt, ##__VA_ARGS__              \
                                )

#define opal_debug_info(fmt, ...)     opal_debug_printf(            \
                                    SGR_YELLOW "info" SGR_RESET     \
                                    ": "                            \
                                    fmt, ##__VA_ARGS__              \
                                )

#define opal_error(fmt, ...)    opal_printf(                    \
                                    SGR_RED "error" SGR_RESET   \
                                    ": "                        \
                                    fmt, ##__VA_ARGS__          \
                                )

#define opal_strerror(fmt, ...) do {                                                    \
                                    char _opal_strerror_buffer[64] = "unknown error";   \
                                    (void)strerror_r(errno, _opal_strerror_buffer, 64); \
                                    opal_printf(                                        \
                                        SGR_RED "error" SGR_RESET                       \
                                        ": " fmt ", %s",                                \
                                        ##__VA_ARGS__,                                  \
                                        _opal_strerror_buffer                           \
                                    );                                                  \
                                } while (0)

#define opal_success(fmt, ...)  opal_printf(                        \
                                    SGR_GREEN "success" SGR_RESET   \
                                    ": "                            \
                                    fmt, ##__VA_ARGS__              \
                                )

#define opal_info(fmt, ...)     opal_printf(                        \
                                    SGR_YELLOW "info" SGR_RESET     \
                                    ": "                            \
                                    fmt, ##__VA_ARGS__              \
                                )

#endif /* _OPAL_DEBUG_H */
