// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket.h>

// ################
// # rs_ret & Co. #

typedef enum {
    RS_OK = 0,

    // RS_CLOSE_PEER advises the calling function to initiate peer shutdown
    // because some condition ocurred that makes the called function want to
    // say goodbye to the peer.
    RS_CLOSE_PEER = -1,

    // A fatal error occurred. RS_FATAL will cause the RS process to exit
    // (across all apps and worker threads).
    RS_FATAL = -2,

    // All IO is performed in non-blocking modes. If continuing an operation
    // would cause an IO function to block, they instead return RS_AGAIN.
    // For TLS: returned on SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
    // For plain TCP: returned on EAGAIN, or if any unwritten bytes still remain
    RS_AGAIN = -3
} rs_ret;

// Return if the called child function was not successful, propagating its
// returned status code to the parent function.
#define RS_GUARD(call) do { \
    rs_ret ret = (call); \
    if (ret != RS_OK) { \
        return ret; \
    } \
} while (0)

// ################
// # RS_LOG & Co. #

// The only two variables with external linkage in rs:

// Used instead of setlogmask() in order to optimize out the overhead of calling
// syslog() and evaluating its arguments for each logging statement beyond the
// run-time-determined mask level (e.g., LOG_DEBUG).
extern int _rs_log_mask;
// Unique thread_local string such as "Worker #7: " or "App Foo: ".
// Its value is an empty "" during the early single-threaded startup phase.
extern thread_local char _rs_thread_id_str[];
#define RS_APP_NAME_MAX_STRLEN 32
#define RS_THREAD_ID_MAX_STRLEN \
    (RS_APP_NAME_MAX_STRLEN + RS_CONST_STRLEN(": "))

#define _RS_LOG(...) \
    RS_MACRIFY_LOG( \
        RS_256_3( \
            _RS_LOG_1, \
            _RS_LOG_2, \
            _RS_LOG_MORE, \
            __VA_ARGS__ \
        ), \
        __VA_ARGS__ \
    )

#define _RS_LOG_ERRNO(...) \
    RS_MACRIFY_LOG( \
        RS_256_3( \
            _RS_LOG_ERRNO_1, \
            _RS_LOG_ERRNO_2, \
            _RS_LOG_ERRNO_MORE, \
            __VA_ARGS__ \
        ), \
        __VA_ARGS__ \
    )

#define _RS_LOG_CHBUF(lvl, fmt, chbuf, ...) \
    RS_MACRIFY_LOG( \
        RS_256_2( \
            _RS_LOG_CHBUF_1, \
            _RS_LOG_CHBUF_MORE, \
            __VA_ARGS__ \
        ), \
        lvl, \
        fmt, \
        chbuf, \
        __VA_ARGS__ \
    )

#define _RS_SYSLOG(lvl, ...) do { \
    if ((lvl) & _rs_log_mask) { \
        syslog((lvl), "%s" __FILE__ ":%s():" RS_STRINGIFY(__LINE__) \
            __VA_ARGS__); \
    } \
} while (0)

#define _RS_LOG_1(lvl) \
    _RS_SYSLOG((lvl), , _rs_thread_id_str, __func__)
#define _RS_LOG_2(lvl, fmt) \
    _RS_SYSLOG((lvl), ": " fmt, _rs_thread_id_str, __func__)
#define _RS_LOG_MORE(lvl, fmt, ...) \
    _RS_SYSLOG((lvl), ": " fmt, _rs_thread_id_str, __func__, __VA_ARGS__)

#define _RS_LOG_ERRNO_1(lvl) \
    _RS_SYSLOG((lvl), ": %s", _rs_thread_id_str, __func__, strerror(errno))
#define _RS_LOG_ERRNO_2(lvl, fmt) \
    _RS_SYSLOG((lvl), ": " fmt ": %s", _rs_thread_id_str, __func__, \
        strerror(errno))
#define _RS_LOG_ERRNO_MORE(lvl, fmt, ...) \
    _RS_SYSLOG((lvl), ": " fmt ": %s", _rs_thread_id_str, __func__, \
        __VA_ARGS__, strerror(errno))

#define _RS_LOG_CHBUF_VLA(chbuf, size) \
    char str[(size) + 1]; \
    memcpy(str, chbuf, size); \
    str[size] = '\0' \

#define _RS_LOG_CHBUF_1(lvl, fmt, chbuf, size) do { \
    _RS_LOG_CHBUF_VLA(chbuf, size); \
    _RS_LOG_MORE((lvl), fmt ": %s", (str)); \
} while (0)

#define _RS_LOG_CHBUF_MORE(lvl, fmt, chbuf, size, ...) do { \
    _RS_LOG_CHBUF_VLA(chbuf, size); \
    _RS_LOG_MORE((lvl), fmt ": %s", __VA_ARGS__, (str)); \
} while (0)

// #################################
// # Heap allocation helper macros #

#define RS_CALLOC(pointer, elem_c) do { \
    if (pointer) { \
        RS_LOG(LOG_CRIT, "Pointer argument of RS_CALLOC(pointer, elem_c) " \
            "must be NULL."); \
        return RS_FATAL; \
    } \
    (pointer) = calloc((elem_c), sizeof(*(pointer))); \
    if (!(pointer)) { \
        RS_LOG(LOG_ALERT, "Failed to calloc()."); \
        return RS_FATAL; \
    } \
} while (0)

#define RS_CACHE_ALIGNED_CALLOC(pointer, elem_c) do { \
    if (pointer) { \
        RS_LOG(LOG_CRIT, "Pointer argument of " \
            "RS_CACHE_ALIGNED_CALLOC(pointer, elem_c) must be NULL."); \
        return RS_FATAL; \
    } \
    size_t alloc_size = (elem_c) * sizeof(*(pointer)); \
    (pointer) = aligned_alloc(RS_CACHELINE_SIZE, alloc_size); \
    if (!(pointer)) { \
        RS_LOG(LOG_ALERT, "Failed to aligned_alloc()."); \
        return RS_FATAL; \
    } \
    memset((pointer), 0, alloc_size); \
} while (0)

#define RS_REALLOC(pointer, elem_c) do { \
    if (!(pointer)) { \
        RS_LOG(LOG_CRIT, "Pointer argument of RS_REALLOC(pointer, " \
            "elem_c) must not be NULL."); \
        return RS_FATAL; \
    } \
    size_t type_size = sizeof(*(pointer)); \
    (pointer) = realloc((pointer), (elem_c) * type_size); \
    if (!(pointer)) { \
        RS_LOG(LOG_ALERT, "Failed to realloc()."); \
        return RS_FATAL; \
    } \
} while (0)

#define RS_FREE(pointer) do { \
    free(pointer); \
    (pointer) = NULL; \
} while (0)
