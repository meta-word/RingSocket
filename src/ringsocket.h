// SPDX-License-Identifier: MIT
// Copyright © 2021 MetaWord Inc
// Copyright © 2019-2021 William Budd

#pragma once

#include <ringsocket_helper.h>
// <ringsocket_variadic.h>           # Arity-based macro expansion helper macros
//   |
//   \---> <ringsocket_api.h>                            # RingSocket's core API
//                        |
// <ringsocket_conf.h> <--/   # Definition of struct rs_conf and its descendents
//   |
//   \---> <ringsocket_ring.h> # Single producer single consumer ring buffer API
//                         |
// <ringsocket_queue.h> <--/      # Ring buffer update queuing and thread waking
//   |
//   \--> <ringsocket_wsframe.h>   # RFC 6455 WebSocket frame protocol interface
//                           |
// <ringsocket_app.h> <------/    # Definition of RS_APP() and descendent macros
//   |            |
//   |            |
//   |            \--------------> [ Worker translation units: see rs_worker.h ]
//   |
//   |
//   \--> <ringsocket_helper.h> # Definitions of app helper functions (internal)
//                          |
//  [YOU ARE HERE]          |
//  <ringsocket.h> <--------/        # Definitions of app helper functions (API)
//    |
//    |
//    \-------------------------------> [ Any RingSocket app translation units ]

#ifdef __cplusplus
#include <string_view>
#include <type_traits>
#if __cplusplus >= 202002L
#include <span>
#endif
#endif

// #############################################################################
// # RingSocket app callback API helper functions ##############################

static inline uint64_t rs_get_client_id(
    rs_t const * rs
) {
    rs_guard_cb_kind(__func__, rs->cb, RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE);
    uint32_t u32tuple[] = {
        // Offset worker index by 1 to prevent ever returning an ID value of 0.
        rs->inbound_worker_i + 1,
        rs->inbound_peer_i
    };
    return *((uint64_t *) u32tuple);
}

static inline int rs_get_client_addr(
    rs_t const * rs,
    struct sockaddr_storage * addr
) {
    rs_guard_cb_kind(__func__, rs->cb, RS_CB_OPEN | RS_CB_READ);
    socklen_t size = (socklen_t) sizeof(struct sockaddr_storage);
    return getpeername(rs->inbound_socket_fd, (struct sockaddr *) addr, &size);
}

static inline uint64_t rs_get_endpoint_id(
    rs_t const * rs
) {
    rs_guard_cb_kind(__func__, rs->cb, RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE);
    return rs->inbound_endpoint_id;
}

static inline enum rs_data_kind rs_get_read_data_kind(
    rs_t const * rs
) {
    rs_guard_cb_kind(__func__, rs->cb, RS_CB_READ);
    return rs->read_data_kind;
}

static inline struct rs_conf const * rs_get_conf(
    rs_t const * rs
) {
    return rs->conf;
}

#ifndef __cplusplus
static inline void * rs_get_app_data(
    rs_t const * rs
) {
    return rs->app_data;
}
#endif

// #############################################################################
// # rs_w_*(): WebSocket message chunk writing functions for RingSocket apps ###

static inline void rs_w_p(
    rs_t * rs,
    void const * src,
    size_t size
) {
    rs_guard_cb_kind(__func__, rs->cb,
        RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER);
    RS_GUARD_APP(rs_check_app_wsize(rs, size));
    memcpy(rs->wbuf + rs->wbuf_i, src, size);
    rs->wbuf_i += size;
}

#ifdef __cplusplus
static inline void rs_w_str(
    rs_t * rs,
    std::string_view str
) {
    rs_w_p(rs, &str[0], str.size());
}
#else
static inline void rs_w_str(
    rs_t * rs,
    char const * str // Must be null-terminated
) {
    rs_w_p(rs, str, strlen(str));
}
#endif

static inline void rs_w_uint8(
    rs_t * rs,
    uint8_t u8
) {
    rs_guard_cb_kind(__func__, rs->cb,
        RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER);
    RS_GUARD_APP(rs_check_app_wsize(rs, 1));
    rs->wbuf[rs->wbuf_i++] = u8;
}

static inline void rs_w_uint16(
    rs_t * rs,
    uint16_t u16
) {
    rs_guard_cb_kind(__func__, rs->cb,
        RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER);
    RS_GUARD_APP(rs_check_app_wsize(rs, 2));
    *((uint16_t *) (rs->wbuf + rs->wbuf_i)) = u16;
    rs->wbuf_i += 2;
}

static inline void rs_w_uint32(
    rs_t * rs,
    uint32_t u32
) {
    rs_guard_cb_kind(__func__, rs->cb,
        RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER);
    RS_GUARD_APP(rs_check_app_wsize(rs, 4));
    *((uint32_t *) (rs->wbuf + rs->wbuf_i)) = u32;
    rs->wbuf_i += 4;
}

static inline void rs_w_uint64(
    rs_t * rs,
    uint64_t u64
) {
    rs_guard_cb_kind(__func__, rs->cb,
        RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER);
    RS_GUARD_APP(rs_check_app_wsize(rs, 8));
    *((uint64_t *) (rs->wbuf + rs->wbuf_i)) = u64;
    rs->wbuf_i += 8;
}

static inline void rs_w_uint16_hton(
    rs_t * rs,
    uint16_t u16
) {
    rs_w_uint16(rs, RS_HTON16(u16));
}

static inline void rs_w_uint32_hton(
    rs_t * rs,
    uint32_t u32
) {
    rs_w_uint32(rs, RS_HTON32(u32));
}

static inline void rs_w_uint64_hton(
    rs_t * rs,
    uint64_t u64
) {
    rs_w_uint64(rs, RS_HTON64(u64));
}

static inline void rs_w_int8(
    rs_t * rs,
    int8_t i8
) {
    rs_w_uint8(rs, i8);
}

static inline void rs_w_int16(
    rs_t * rs,
    int16_t i16
) {
    rs_w_uint16(rs, i16);
}

static inline void rs_w_int32(
    rs_t * rs,
    int32_t i32
) {
    rs_w_uint32(rs, i32);
}

static inline void rs_w_int64(
    rs_t * rs,
    int64_t i64
) {
    rs_w_uint64(rs, i64);
}

static inline void rs_w_int16_hton(
    rs_t * rs,
    int16_t i16
) {
    rs_w_uint16_hton(rs, i16);
}

static inline void rs_w_int32_hton(
    rs_t * rs,
    int32_t i32
) {
    rs_w_uint32_hton(rs, i32);
}

static inline void rs_w_int64_hton(
    rs_t * rs,
    int64_t i64
) {
    rs_w_uint64_hton(rs, i64);
}

#if __cplusplus >= 202002L
template<class T, std::size_t N>
static inline void rs_w_span(
    rs_t * rs,
    std::span<T const, N> span
) {
    rs_w_p(rs, &span[0], span.size_bytes());
}

template <typename T>
static inline void rs_w_span(
    rs_t * rs,
    T const & range
) {
    rs_w_span(rs, std::span(range));
}

template<class T, std::size_t N>
static inline void rs_w_span_hton(
    rs_t * rs,
    std::span<T const, N> span
) {
    static_assert(std::is_integral_v<T> &&
        (sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8),
        "rs_w_span_hton() only supports integer types of size 2, 4, or 8.");
    rs_guard_cb_kind(__func__, rs->cb,
        RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER);
    RS_GUARD_APP(rs_check_app_wsize(rs, span.size_bytes()));
    if constexpr (sizeof(T) == 2) {
        for (T const elem : span) {
            *((uint16_t *) (rs->wbuf + rs->wbuf_i)) = RS_HTON16(elem);
            rs->wbuf_i += 2;
        }
    } else if constexpr (sizeof(T) == 4) {
        for (T const elem : span) {
            *((uint32_t *) (rs->wbuf + rs->wbuf_i)) = RS_HTON32(elem);
            rs->wbuf_i += 4;
        }
    } else {
        for (T const elem : span) {
            *((uint64_t *) (rs->wbuf + rs->wbuf_i)) = RS_HTON64(elem);
            rs->wbuf_i += 8;
        }
    }
}

template<typename T>
static inline void rs_w_span_hton(
    rs_t * rs,
    T const & range
) {
    rs_w_span_hton(rs, std::span(range));
}
#endif

// #############################################################################
// # rs_to_*(): WebSocket message recipient setter functions for RS apps #######

static inline void rs_to_single(
    rs_t * rs,
    enum rs_data_kind data_kind,
    uint64_t client_id
) {
    uint32_t * u32 = (uint32_t *) &client_id;
    rs_send(rs, *u32 - 1, RS_OUTBOUND_SINGLE, u32 + 1, 1, data_kind);
    rs->wbuf_i = 0;
}

static inline void rs_to_multi(
    rs_t * rs,
    enum rs_data_kind data_kind,
    uint64_t const * client_ids,
    size_t client_c
) {
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        uint32_t cur_clients[client_c];
        size_t cur_client_c = 0;
        for (size_t j = 0; j < client_c; j++) {
            uint32_t * u32 = (uint32_t *) (client_ids + j);
            if (*u32++ - 1 != i) {
                continue;
            }
            for (size_t k = 0; k < cur_client_c; k++) {
                if (cur_clients[k] == *u32) {
                    RS_LOG(LOG_WARNING, "Ignoring duplicate client_id %" PRIu64
                        ": please fix your app code!", client_ids[j]);
                    goto next_client;
                }
            }
            cur_clients[cur_client_c++] = *u32;
            next_client:;
        }
        switch (cur_client_c) {
        case 0:
            continue;
        case 1:
            rs_send(rs, i, RS_OUTBOUND_SINGLE, cur_clients, 1, data_kind);
            continue;
        default:
            rs_send(rs, i, RS_OUTBOUND_ARRAY, cur_clients, cur_client_c,
                data_kind);
            continue;
        }
    }
    rs->wbuf_i = 0;
}

static inline void rs_to_cur(
    rs_t * rs,
    enum rs_data_kind data_kind
) {
    rs_guard_cb_kind(__func__, rs->cb, RS_CB_OPEN | RS_CB_READ);
    rs_send(rs, rs->inbound_worker_i, RS_OUTBOUND_SINGLE, &rs->inbound_peer_i,
        1, data_kind);
    rs->wbuf_i = 0;
}

static inline void rs_to_every(
    rs_t * rs,
    enum rs_data_kind data_kind
) {
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        rs_send(rs, i, RS_OUTBOUND_EVERY, NULL, 0, data_kind);
    }
    rs->wbuf_i = 0;
}

static inline void rs_to_every_except_single(
    rs_t * rs,
    enum rs_data_kind data_kind,
    uint64_t client_id
) {
    uint32_t * u32 = (uint32_t *) &client_id;
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        if (*u32 - 1 == i) {
            rs_send(rs, i, RS_OUTBOUND_EVERY_EXCEPT_SINGLE, u32 + 1, 1,
                data_kind);
        } else {
            rs_send(rs, i, RS_OUTBOUND_EVERY, NULL, 0, data_kind);
        }
    }
    rs->wbuf_i = 0;
}

static inline void rs_to_every_except_multi(
    rs_t * rs,
    enum rs_data_kind data_kind,
    uint64_t const * client_ids,
    size_t client_c
) {
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        uint32_t cur_clients[client_c];
        size_t cur_client_c = 0;
        for (size_t j = 0; j < client_c; j++) {
            uint32_t * u32 = (uint32_t *) (client_ids + j);
            if (*u32++ - 1 != i) {
                continue;
            }
            for (size_t k = 0; k < cur_client_c; k++) {
                if (cur_clients[k] == *u32) {
                    RS_LOG(LOG_WARNING, "Ignoring duplicate client_id %" PRIu64
                        ": please fix your app code!", client_ids[j]);
                    goto next_client;
                }
            }
            cur_clients[cur_client_c++] = *u32;
            next_client:;
        }
        switch (cur_client_c) {
        case 0:
            rs_send(rs, i, RS_OUTBOUND_EVERY, NULL, 0, data_kind);
            continue;
        case 1:
            rs_send(rs, i, RS_OUTBOUND_EVERY_EXCEPT_SINGLE, cur_clients, 1,
                data_kind);
            continue;
        default:
            rs_send(rs, i, RS_OUTBOUND_EVERY_EXCEPT_ARRAY, cur_clients,
                cur_client_c, data_kind);
            continue;
        }
    }
    rs->wbuf_i = 0;
}

static inline void rs_to_every_except_cur(
    rs_t * rs,
    enum rs_data_kind data_kind
) {
    rs_guard_cb_kind(__func__, rs->cb, RS_CB_OPEN | RS_CB_READ);
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        if (i == rs->inbound_worker_i) {
            rs_send(rs, i, RS_OUTBOUND_EVERY_EXCEPT_SINGLE, &rs->inbound_peer_i,
                1, data_kind);
        } else {
            rs_send(rs, i, RS_OUTBOUND_EVERY, NULL, 0, data_kind);
        }
    }
    rs->wbuf_i = 0;
}

// #############################################################################
// # rs_close() and rs_close_cur(): shut down a client WebSocket connection ####

static inline void rs_close(
    rs_t * rs,
    uint64_t client_id,
    unsigned ws_close_code
) {
    if (ws_close_code < 4000 || ws_close_code >= 4900) {
        RS_LOG(LOG_ERR, "rs_close() given an invalid WebSocket close code "
            "value: %d. As per RFC 6455, only private use values in the range "
            "4000 through 4899 are allowed to be used for app-defined "
            "purposes. (RingSocket reserves the range 4900 through 4999 for "
            "its own ends.) Changing close code to 4899.");
        ws_close_code = 4899;
    }
    uint32_t * u32 = (uint32_t *) &client_id;
    rs_close_peer(rs, *u32 - 1, u32[1], ws_close_code);
}

static inline void rs_close_cur(
    rs_t * rs,
    unsigned ws_close_code
) {
    rs_close(rs, rs_get_client_id(rs), ws_close_code);
}

// #############################################################################
// # rs_set_thread_id(): set the thread ID string prefix as used by RS_LOG() ###

#ifdef __cplusplus
static inline void rs_set_thread_id(
    std::string const & new_thread_id
) {
    snprintf(_rs_thread_id_str, sizeof(_rs_thread_id_str),
        "%s:", new_thread_id.c_str());
}
#else
static inline void rs_set_thread_id(
    char const * new_thread_id
) {
    snprintf(_rs_thread_id_str, sizeof(_rs_thread_id_str),
        "%s:", new_thread_id);
}
#endif

// #############################################################################
// # C++20/fmtlib-based "format string free" versions of RS_LOG() ##############

// With a full-featured C++20 compiler or fmtlib, instead of writing...
// RS_LOG(LOG_INFO, "Player %s has %u remaining lives.", username, live_c);
// ...you can write the same thing more concisely/elegantly as:
// RS_INFO("Player ", username, " has ", live_c, " remaining lives.");

// Hopefully GCC and Clang will finally implement std::format soon, but for the
// time being use the reference library instead: https://github.com/fmtlib/fmt

#ifdef __cplusplus

#ifdef __cpp_lib_format
#include <format>
#define RS_MAKE_FORMAT_ARGS std::make_format_args
#define RS_FORMAT_ARGS std::format_args
#define RS_VFORMAT std::vformat
#else
// This getting evaluated means the compiler doesn't support the std::format
// portion of C++20. Plan B: try to include the fmt library in header-only mode.
#define FMT_HEADER_ONLY
#include <fmt/format.h>
#define RS_MAKE_FORMAT_ARGS fmt::make_format_args
#define RS_FORMAT_ARGS fmt::format_args
#define RS_VFORMAT fmt::vformat
#endif

static inline void rs_log_vformat(
    int log_level,
    char const * function_name,
    std::string_view format,
    RS_FORMAT_ARGS args
) {
    try {
        auto formatted_str = RS_VFORMAT(format, args);
        _RS_LOG(log_level, "%s", _rs_thread_id_str, function_name,
            formatted_str.c_str());
    } catch (...) {
        RS_LOG(LOG_CRIT, "Internal rs_log_vformat() error.");
    }
}

template <typename ... Args>
static inline constexpr void rs_log_format(
    int log_level,
    char const * function_name,
    Args && ... args
) {
    // Create a C++20 std::format string of "{}" sequences. E.g., "{}{}{}".
    std::array<char, 2 * (sizeof ... (Args)) + 1> braces{};
    for (char * p{&braces[0]}, * const p_over{&braces[braces.size() - 1]};
        p < p_over;) {
        *p++ = '{';
        *p++ = '}';
    }
    rs_log_vformat(log_level, function_name, std::string_view{&braces[0]},
        RS_MAKE_FORMAT_ARGS(args...));
}

// Facilitate log level branch prediction to reduce function call overhead.
#define RS_DEBUG(...) do { if (LOG_DEBUG <= _rs_log_max) \
    RS_LOG_FORMAT(LOG_DEBUG, __VA_ARGS__); } while (0)
#define RS_INFO(...) do { if (LOG_INFO <= _rs_log_max) \
    RS_LOG_FORMAT(LOG_INFO, __VA_ARGS__); } while (0)
#define RS_NOTICE(...) do { if (LOG_NOTICE <= _rs_log_max) \
    RS_LOG_FORMAT(LOG_NOTICE, __VA_ARGS__); } while (0)
#define RS_WARNING(...) do { if (LOG_WARNING <= _rs_log_max) \
    RS_LOG_FORMAT(LOG_WARNING, __VA_ARGS__); } while (0)
#define RS_ERR(...) do { if (LOG_ERR <= _rs_log_max) \
    RS_LOG_FORMAT(LOG_ERR, __VA_ARGS__); } while (0)
#define RS_CRIT(...) do { if (LOG_CRIT <= _rs_log_max) \
    RS_LOG_FORMAT(LOG_CRIT, __VA_ARGS__); } while (0)
#define RS_ALERT(...) do { if (LOG_ALERT <= _rs_log_max) \
    RS_LOG_FORMAT(LOG_ALERT, __VA_ARGS__); } while (0)

// __LINE__ and __func__ need to be included prior to making a function call.
#define RS_LOG_FORMAT(lvl, ...) \
    rs_log_format(lvl, __func__, RS_STRINGIFY(__LINE__) ": ", __VA_ARGS__)

#endif // End of __cplusplus
