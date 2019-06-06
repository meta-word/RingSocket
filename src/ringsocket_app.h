// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket.h>

struct rs_app_args {
    struct rs_conf const * conf;
    // Worker_c length io_pair array to be allocated by the called app
    struct rs_thread_io_pairs * * app_io_pairs;
    struct rs_thread_sleep_state * app_sleep_state; // This app's sleep state
    struct rs_thread_sleep_state * * worker_sleep_states;
    int const * worker_eventfds;
    size_t app_i;
    int log_mask;
};

struct rs_inbound_msg_header {
    uint32_t peer_i;
    uint32_t socket_fd;
    uint16_t endpoint_id;
    uint8_t is_utf8;
    uint8_t kind; // enum rs_inbound_kind
};

enum rs_inbound_kind {
    RS_INBOUND_OPEN = 0,
    RS_INBOUND_READ = 1,
    RS_INBOUND_CLOSE = 2
};

enum rs_outbound_kind {
    RS_OUTBOUND_SINGLE = 0,
    RS_OUTBOUND_ARRAY = 1,
    RS_OUTBOUND_EVERY = 2,
    RS_OUTBOUND_EVERY_EXCEPT_SINGLE = 3,
    RS_OUTBOUND_EVERY_EXCEPT_ARRAY = 4
};

// All peer closures originating in an rs app use the 4xxx range exclusively:
// "Status codes in the range 4000-4999 are reserved for private use and thus
// can't be registered.  Such codes can be used by prior agreements between
// WebSocket applications.  The interpretation of these codes is undefined by
// this protocol." -- https://tools.ietf.org/html/rfc6455#section-7.4.2
enum rs_app_ws_close {
    // A callback received data of a size other than what its parameters require
    RS_APP_WS_CLOSE_WRONG_SIZE = 4900,
    // A callback expecting UTF-8 data received binary data, or vice versa
    RS_APP_WS_CLOSE_WRONG_DATA_TYPE = 4901,
    // RS_READ_SWITCH received a 1st byte not matching any of its case labels
    RS_APP_WS_CLOSE_UNKNOWN_READ_CASE = 4902
};

struct rs {
    struct rs_conf const * conf;
    uint8_t * * wbuf;
    struct rs_thread_io_pairs * io_pairs;
    struct rs_ring * outbound_rings;
    struct rs_ring_update_queue * ring_update_queue;
    struct rs_thread_sleep_state * worker_sleep_states;
    int const * worker_eventfds;
    size_t * wbuf_size;
    size_t wbuf_i;
    uint32_t src_peer_i;
    int socket_fd;
    uint16_t endpoint_id;
    uint16_t src_worker_thread_i;
};

#include <ringsocket_app_helper.h>

#define _RS_APP(init_macro, open_macro, read_macro, close_macro, \
    timer_macro) \
\
int _rs_log_mask = LOG_UPTO(LOG_WARNING); \
\
thread_local char _rs_thread_id_str[RS_THREAD_ID_MAX_STRLEN + 1] = {0}; \
\
rs_ret rs_app( \
    struct rs_app_args * app_args \
) { \
    struct rs_conf const * conf = app_args->conf; \
    \
    _rs_log_mask = app_args->log_mask; \
    sprintf(_rs_thread_id_str, "%s: ", conf->apps[app_args->app_i].name); \
    \
    struct rs_thread_sleep_state * app_sleep_state = \
        app_args->app_sleep_state; \
    struct rs_thread_sleep_state * * worker_sleep_states = \
        app_args->worker_sleep_states; \
    int const * worker_eventfds = app_args->worker_eventfds; \
    \
    struct rs_ring * outbound_rings = NULL; \
    uint8_t * inbound_readers = NULL; \
    struct rs_ring_update_queue ring_update_queue = {0}; \
    \
    if (!app_args->app_i) { /* The 1st app allocates worker sleep states */ \
        RS_CACHE_ALIGNED_CALLOC(*worker_sleep_states, conf->worker_c); \
    } \
    \
    RS_GUARD_APP(rs_init_rings( \
        conf, \
        conf->apps + app_args->app_i, \
        app_args->app_io_pairs, \
        &outbound_rings, \
        &inbound_readers, \
        &ring_update_queue \
    )); \
    /* Don't initialize wbuf yet, but do so instead during the 1st */ \
    /* rs_w_...() call, if any. This saves memory for apps that never */ \
    /* call rs_w_...() functions, and instead write/send everything */ \
    /* "in one go" with rs_send(). */ \
    uint8_t * wbuf = NULL; \
    size_t wbuf_size = conf->apps[app_args->app_i].wbuf_size; \
    \
    /* IO pairs must be dereferenced after calling rs_init_rings */ \
    struct rs_thread_io_pairs * io_pairs = *app_args->app_io_pairs; \
    \
    /* Prepend-pasting prevents (paramaterized) macro arguments from */ \
    /* getting expanded before this _RS_APP macro is expanded (i.e., */ \
    /* because RS_INIT isn't defined, whereas _RS_INIT is). */ \
    _##init_macro; /* Should expand through _RS_INIT */ \
    \
    /* todo: make this optional */ \
    uint64_t time_ms = {0}; /* overflows every 585 million years */ \
    RS_GUARD_APP(rs_get_time_in_milliseconds(&time_ms)); \
    \
    size_t idle_c = 0; \
    for (size_t worker_i = 0;; worker_i = ++worker_i % conf->worker_c) { \
        struct rs_thread_pair * pair = &io_pairs[worker_i].inbound; \
        uint8_t const * reader = inbound_readers + worker_i; \
        struct rs_ring_msg *ring_msg = rs_get_ring_msg(pair, reader); \
        if (!ring_msg) { \
            if (++idle_c == 3 * RS_MAX(4, conf->worker_c)) { \
                RS_GUARD_APP(rs_wait_for_worker(app_sleep_state, NULL)); \
                idle_c = 0; \
            } else if (idle_c == 2 * RS_MAX(4, conf->worker_c)) { \
                RS_ATOMIC_STORE_RELAXED(&app_sleep_state->is_asleep, true); \
                RS_GUARD_APP(rs_wait_for_worker(app_sleep_state, \
                    &(struct timespec){0})); \
                RS_GUARD_APP(rs_flush_ring_updates(&ring_update_queue, \
                    io_pairs, *worker_sleep_states, worker_eventfds, \
                    conf->worker_c)); \
            } \
            continue; \
        } \
        if (idle_c) { \
            /* Went to bed, but couln't fall asleep? Then get back to work! */ \
            RS_ATOMIC_STORE_RELAXED(&app_sleep_state->is_asleep, false); \
            idle_c = 0; \
        } \
        do { \
            struct rs_inbound_msg_header *header = \
                ((struct rs_inbound_msg_header *) ring_msg->msg); \
            reader = ring_msg->msg + sizeof(struct rs_inbound_msg_header); \
            uint8_t const * const over = ring_msg->msg + ring_msg->size; \
            struct rs n = { \
                .conf = conf, \
                .wbuf = &wbuf, \
                .wbuf_size = &wbuf_size, \
                .io_pairs = io_pairs, \
                .outbound_rings = outbound_rings, \
                .ring_update_queue = &ring_update_queue, \
                .worker_sleep_states = *worker_sleep_states, \
                .worker_eventfds = worker_eventfds, \
                .src_peer_i = header->peer_i, \
                .socket_fd = header->socket_fd, \
                .endpoint_id = header->endpoint_id, \
                .src_worker_thread_i = worker_i \
            }; \
            switch (header->kind) { \
            case RS_INBOUND_OPEN: \
                _##open_macro; /* Should expand through _RS_OPEN */ \
                break; \
            case RS_INBOUND_READ: \
                _##read_macro; /* Should expand through _RS_READ */ \
                break; \
            case RS_INBOUND_CLOSE: default: \
                _##close_macro; /* Should expand through _RS_CLOSE */ \
            } \
            next_inbound_message:; \
        } while ((ring_msg = rs_get_ring_msg(pair, reader))); \
        \
        uint64_t old_time_ms = time_ms; \
        RS_GUARD_APP(rs_get_time_in_milliseconds(&time_ms)); \
        if (time_ms != old_time_ms) { \
            _##timer_macro; /* Should expand through _RS_TIMER */ \
        } \
    } \
} \
\
extern inline rs_ret rs_init_rings( \
    struct rs_conf const * conf, \
    struct rs_app const * app, \
    struct rs_thread_io_pairs * * io_pairs, \
    struct rs_ring * * outbound_rings, \
    uint8_t * * inbound_readers, \
    struct rs_ring_update_queue * ring_update_queue \
); \
\
extern inline rs_ret rs_get_time_in_milliseconds( \
    uint64_t * time_ms \
); \
\
extern inline rs_ret rs_prepare_ring_write( \
    struct rs_thread_pair * pair, \
    struct rs_ring * ring, \
    uint32_t msg_size \
); \
\
extern inline struct rs_ring_msg * rs_get_ring_msg( \
    struct rs_thread_pair * pair, \
    uint8_t const * reader \
); \
\
extern inline rs_ret rs_wake_up_app( \
    struct rs_thread_sleep_state * app_sleep_state \
); \
\
extern inline rs_ret rs_wake_up_worker( \
    struct rs_thread_sleep_state * worker_sleep_state, \
    int worker_eventfd \
); \
\
extern inline rs_ret rs_wait_for_worker( \
    struct rs_thread_sleep_state * app_sleep_state, \
    struct timespec const * timeout \
); \
\
extern inline rs_ret rs_enqueue_ring_update( \
    struct rs_ring_update_queue * updates, \
    struct rs_thread_io_pairs * io_pairs, \
    struct rs_thread_sleep_state * worker_sleep_states, \
    int const * worker_eventfds, \
    uint8_t const * new_ring_position, \
    size_t worker_thread_i, \
    bool is_write \
); \
\
extern inline rs_ret rs_flush_ring_updates( \
    struct rs_ring_update_queue * updates, \
    struct rs_thread_io_pairs * io_pairs, \
    struct rs_thread_sleep_state * sleep_states, \
    int const * eventfds, \
    size_t dest_thread_c \
)

// todo: This should probably be replaced with something less dumb...
#define RS_APP_FATAL exit(EXIT_FAILURE)

#define RS_APP_CLOSE_PEER(ws_close_code) do { \
    struct rs_ring * ring = outbound_rings + worker_i; \
    RS_GUARD_APP(rs_prepare_ring_write(&io_pairs[worker_i].outbound, \
        ring, 5)); \
    *ring->writer++ = RS_OUTBOUND_SINGLE; \
    *ring->writer++ = 0x88; /* FIN_CLOSE */ \
    *ring->writer++ = 0x02; /* payload size == 2 */ \
    *((uint16_t *) ring->writer) = RS_HTON16(ws_close_code); \
    ring->writer += 2; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, ring->writer, worker_i, true)); \
} while (0)

#define RS_GUARD_APP(call) if ((call) != RS_OK) RS_APP_FATAL

#define RS_GUARD_APP_CB(call) do { \
    int ret = (call); \
    switch (ret) { \
    case -1: \
        RS_LOG(LOG_WARNING, \
            "Shutting down: callback returned -1 (fatal error)."); \
        RS_APP_FATAL; \
    case 0: \
        break; \
    default: \
        RS_LOG(LOG_ERR, "Shutting down: callback returned an invalid " \
            "value: %d. Valid values are -1 (fatal error) and 0 (success). ", \
            ret); \
        RS_APP_FATAL; \
    } \
} while (0)

#define RS_GUARD_APP_CB_PEER(call) do { \
    int ret = (call); \
    switch (ret) { \
    case -1: \
        RS_LOG(LOG_WARNING, \
            "Shutting down: read/open callback returned -1 (fatal error)."); \
        RS_APP_FATAL; \
    case 0: \
        break; \
    default: \
        if (ret < 4000 || ret > 4899) { \
            RS_LOG(LOG_ERR, "Shutting down: read/open callback returned an " \
                "invalid value: %d. Valid values are -1 (fatal error), " \
                "0 (success), and any value within the range 4000 through " \
                "4899 (private use WebSocket close codes).", ret); \
            RS_APP_FATAL; \
        } \
        RS_APP_CLOSE_PEER(ret); \
    } \
} while (0)

// This allows macro invocations such as RS_INIT_CB(RS_NONE) to be used
#define RS_NONE(_) RS_OK

#define _RS_INIT(init_cb) RS_GUARD_APP_CB(init_cb())
#define _RS_OPEN(open_cb) RS_GUARD_APP_CB_PEER(open_cb(n))
#define _RS_CLOSE(close_cb) RS_GUARD_APP_CB_PEER(close_cb(n))
#define _RS_TIMER(timer_cb) RS_GUARD_APP_CB(timer_cb(n))

#define _RS_READ_SWITCH(...) do { \
    RS_CHECK_SIZE(1); \
    switch (*reader++) { \
    RS_PREFIX_EACH(_, __VA_ARGS__); \
    default: \
        RS_APP_CLOSE_PEER(RS_APP_WS_CLOSE_UNKNOWN_READ_CASE); \
    } \
} while (0)

/*#define _RS_READ_SWITCH2(...) do { \
    RS_CHECK_SIZE(1); \
    switch (*reader++) { \
    RS_PREFIX_EACH(_, __VA_ARGS__); \
    default: \
        RS_APP_CLOSE_PEER(RS_APP_WS_CLOSE_UNKNOWN_READ_CASE); \
    } \
} while (0)*/

#define _RS_READ_CASE_BIN(cb_i, ...) case cb_i: { \
    _RS_READ_BIN(__VA_ARGS__); \
} \
break

#define _RS_READ_CASE_UTF8(cb_i, ...) case cb_i: { \
    _RS_READ_UTF8(__VA_ARGS__); \
} \
break

#define _RS_READ_BIN(...) do { \
    if (header->is_utf8) { \
        RS_READ_ABORT(RS_APP_WS_CLOSE_WRONG_DATA_TYPE); \
    } else { \
        RS_READ_PROCEED(__VA_ARGS__); \
    } \
} while (0)

#define _RS_READ_UTF8(...) do { \
    if (header->is_utf8) { \
        RS_READ_PROCEED(__VA_ARGS__); \
    } else { \
        RS_READ_ABORT(RS_APP_WS_CLOSE_WRONG_DATA_TYPE); \
    } \
} while (0)

#define RS_READ_PROCEED(...) RS_MACRIFY2(RS_256_16( \
    RS_A00, RS_A01, RS_A02, RS_A03, RS_A04, RS_A05, RS_A06, \
    RS_A07, RS_A08, RS_A09, RS_A10, RS_A11, RS_A12, RS_A13, \
    RS_A14, RS_A15, __VA_ARGS__), __VA_ARGS__)

#define RS_READ_ABORT(ws_close_code) do { \
    reader = over; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_APP_CLOSE_PEER(ws_close_code); \
    goto next_inbound_message; \
} while (0)

#define RS_A00(cb) do { \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n)); \
} while (0)
#define RS_A01(cb, a01) do { \
    _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v1 __##a01)); \
} while (0)
#define RS_A02(cb, a02, a01) do { \
    _02##a02; _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v2, v1 __##a01)); \
} while (0)
#define RS_A03(cb, a03, a02, a01) do { \
    _03##a03; _02##a02; _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v3, v2, v1 __##a01)); \
} while (0)
#define RS_A04(cb, a04, a03, a02, a01) do { \
    _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v4, v3, v2, v1 __##a01)); \
} while (0)
#define RS_A05(cb, a05, a04, a03, a02, a01) do { \
    _05##a05; _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v5, v4, v3, v2, v1 __##a01)); \
} while (0)
#define RS_A06(cb, a06, a05, a04, a03, a02, a01) do { \
    _06##a06; _05##a05; _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v6, v5, v4, v3, v2, v1 __##a01)); \
} while (0)
#define RS_A07(cb, a07, a06, a05, a04, a03, a02, a01) do { \
    _07##a07; _06##a06; _05##a05; _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v7, v6, v5, v4, v3, v2, v1 __##a01)); \
} while (0)
#define RS_A08(cb, a08, a07, a06, a05, a04, a03, a02, a01) do { \
    _08##a08; _07##a07; _06##a06; _05##a05; _04##a04; _03##a03; _02##a02; \
    _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v8, v7, v6, v5, v4, v3, v2, v1 __##a01)); \
} while (0)
#define RS_A09(cb, a09, a08, a07, a06, a05, a04, a03, a02, a01) do { \
    _09##a09; _08##a08; _07##a07; _06##a06; _05##a05; _04##a04; _03##a03; \
    _02##a02; _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v9, v8, v7, v6, v5, v4, v3, v2, v1 __##a01)); \
} while (0)
#define RS_A10(cb, a10, a09, a08, a07, a06, a05, a04, a03, a02, a01) do { \
    _10##a10; _09##a09; _08##a08; _07##a07; _06##a06; _05##a05; _04##a04; \
    _03##a03; _02##a02; _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v10, v9, v8, v7, v6, v5, v4, v3, v2, v1 \
        __##a01)); \
} while (0)
#define RS_A11(cb, a11, a10, a09, a08, a07, a06, a05, a04, a03, a02, \
    a01) do { \
    _11##a11; _10##a10; _09##a09; _08##a08; _07##a07; _06##a06; _05##a05; \
    _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v11, v10, v9, v8, v7, v6, v5, v4, v3, v2, v1 \
        __##a01)); \
} while (0)
#define RS_A12(cb, a12, a11, a10, a09, a08, a07, a06, a05, a04, a03, a02, \
    a01) do { \
    _12##a12; _11##a11; _10##a10; _09##a09; _08##a08; _07##a07; _06##a06; \
    _05##a05; _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v12, v11, v10, v9, v8, v7, v6, v5, v4, v3, \
        v2, v1 __##a01)); \
} while (0)
#define RS_A13(cb, a13, a12, a11, a10, a09, a08, a07, a06, a05, a04, a03, \
    a02, a01) do { \
    _13##a13, _12##a12; _11##a11; _10##a10; _09##a09; _08##a08; _07##a07; \
    _06##a06; _05##a05; _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v13, v12, v11, v10, v9, v8, v7, v6, v5, v4, \
        v3, v2, v1 __##a01)); \
} while (0)
#define RS_A14(cb, a14, a13, a12, a11, a10, a09, a08, a07, a06, a05, a04, \
    a03, a02, a01) do { \
    _14##a14, _13##a13, _12##a12; _11##a11; _10##a10; _09##a09; _08##a08; \
    _07##a07; _06##a06; _05##a05; _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v14, v13, v12, v11, v10, v9, v8, v7, v6, v5, \
        v4, v3 v2, v1 __##a01)); \
} while (0)
#define RS_A15(cb, a15, a14, a13, a12, a11, a10, a09, a08, a07, a06, a05, \
    a04, a03, a02, a01) do { \
    _15##a15, _14##a14, _13##a13, _12##a12; _11##a11; _10##a10; _09##a09; \
    _08##a08; _07##a07; _06##a06; _05##a05; _04##a04; _03##a03; _02##a02; \
    _01##a01; \
    RS_GUARD_APP(rs_enqueue_ring_update(&ring_update_queue, io_pairs, \
        *worker_sleep_states, worker_eventfds, reader, worker_i, false)); \
    RS_GUARD_APP_CB_PEER(cb(n, v15, v14, v13, v12, v11, v10, v9, v8, v7, v6, \
        v5, v4, v3, v2, v1 __##a01)); \
} while (0)

#define _15RS_NET(...) _RS_NET(15, __VA_ARGS__)
#define _14RS_NET(...) _RS_NET(14, __VA_ARGS__)
#define _13RS_NET(...) _RS_NET(13, __VA_ARGS__)
#define _12RS_NET(...) _RS_NET(12, __VA_ARGS__)
#define _11RS_NET(...) _RS_NET(11, __VA_ARGS__)
#define _10RS_NET(...) _RS_NET(10, __VA_ARGS__)
#define _09RS_NET(...) _RS_NET(9, __VA_ARGS__)
#define _08RS_NET(...) _RS_NET(8, __VA_ARGS__)
#define _07RS_NET(...) _RS_NET(7, __VA_ARGS__)
#define _06RS_NET(...) _RS_NET(6, __VA_ARGS__)
#define _05RS_NET(...) _RS_NET(5, __VA_ARGS__)
#define _04RS_NET(...) _RS_NET(4, __VA_ARGS__)
#define _03RS_NET(...) _RS_NET(3, __VA_ARGS__)
#define _02RS_NET(...) _RS_NET(2, __VA_ARGS__)
#define _01RS_NET(...) _RS_NET(1, __VA_ARGS__)

#define _15RS_NTOH(...) _RS_NTOH(15, __VA_ARGS__)
#define _14RS_NTOH(...) _RS_NTOH(14, __VA_ARGS__)
#define _13RS_NTOH(...) _RS_NTOH(13, __VA_ARGS__)
#define _12RS_NTOH(...) _RS_NTOH(12, __VA_ARGS__)
#define _11RS_NTOH(...) _RS_NTOH(11, __VA_ARGS__)
#define _10RS_NTOH(...) _RS_NTOH(10, __VA_ARGS__)
#define _09RS_NTOH(...) _RS_NTOH(9, __VA_ARGS__)
#define _08RS_NTOH(...) _RS_NTOH(8, __VA_ARGS__)
#define _07RS_NTOH(...) _RS_NTOH(7, __VA_ARGS__)
#define _06RS_NTOH(...) _RS_NTOH(6, __VA_ARGS__)
#define _05RS_NTOH(...) _RS_NTOH(5, __VA_ARGS__)
#define _04RS_NTOH(...) _RS_NTOH(4, __VA_ARGS__)
#define _03RS_NTOH(...) _RS_NTOH(3, __VA_ARGS__)
#define _02RS_NTOH(...) _RS_NTOH(2, __VA_ARGS__)
#define _01RS_NTOH(...) _RS_NTOH(1, __VA_ARGS__)

#define _RS_NET(name_i, ...) RS_MACRIFY3(RS_256_3(RS_NET_SINGLE, \
    RS_NET_STA, RS_NET_VLA, __VA_ARGS__), name_i, __VA_ARGS__)

#define _RS_NTOH(name_i, ...) RS_MACRIFY3(RS_256_3(RS_NTOH_SINGLE, \
    RS_NTOH_STA, RS_NTOH_VLA, __VA_ARGS__), name_i, __VA_ARGS__)

#define RS_READ_CHECK(size) do { \
    if (reader + (size) > over) { \
        RS_READ_ABORT(RS_APP_WS_CLOSE_WRONG_SIZE); \
    } \
} while (0)

// No "do while (0)" wrapping do to elem_c needing to remain in scope
#define RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c) \
    size_t elem_c = over - reader; \
    if (elem_c % sizeof(type)) { \
        RS_READ_ABORT(RS_APP_WS_CLOSE_WRONG_SIZE); \
    } \
    elem_c /= sizeof(type); \
    if (elem_c < (min_elem_c) || elem_c > (max_elem_c)) { \
        RS_READ_ABORT(RS_APP_WS_CLOSE_WRONG_SIZE); \
    } \
    do { ; } while (0)

// No "do while (0)" wrapping due to v##name_i needing to remain in scope
#define RS_NTOH_SINGLE(name_i, type) \
    RS_READ_CHECK(sizeof(type)); \
    type v##name_i = *((type *) reader); \
    reader += sizeof(type)

#define RS_NET_ARR(var, elem_c, type) \
do { \
    memcpy(var, reader, (elem_c) * sizeof(type)); \
    reader += (elem_c) * sizeof(type); \
} while (0)

// No "do while (0)" wrapping due to v##name_i[] needing to remain in scope
#define RS_NET_STA(name_i, type, elem_c) \
    RS_READ_CHECK(elem_c * sizeof(type)); \
    thread_local static type v##name_i[elem_c] = {0}; \
    RS_NET_ARR(v##name_i, elem_c, type)

// No "do while (0)" wrapping due to v1[] and elem_c needing to remain in scope
#define RS_NET_VLA(_, type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    type v1[elem_c]; /* VLA */ \
    RS_NET_ARR(v1, elem_c, type)

// No "do while (0)" wrapping due to v1[] and elem_c needing to remain in scope
#define _RS_NET_HEAP(_, type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    type * v1 = malloc(elem_c); \
    if (!v1) { \
        RS_LOG(LOG_ALERT, "Failed to malloc()."); \
        RS_APP_FATAL; \
    } \
    RS_NET_ARR(v1, elem_c, type)

#define RS_NTOH_ASSIGN(var, type) \
do { \
    switch (sizeof(type)) { \
    case 1: default: (var) = *((type *) reader); break; \
    case 2: (var) = *((type *) RS_R_NTOH16(reader)); break; \
    case 4: (var) = *((type *) RS_R_NTOH32(reader)); break; \
    case 8: (var) = *((type *) RS_R_NTOH64(reader)); break; \
    } \
    reader += sizeof(type); \
} while (0)

// No "do while (0)" wrapping due to v##name_i needing to remain in scope
#define RS_NTOH_SINGLE(name_i, type) \
    RS_READ_CHECK(sizeof(type)); \
    type v##name_i = 0; \
    RS_NTOH_ASSIGN(v##name_i, type)

// No "do while (0)" wrapping due to v##name_i[] needing to remain in scope
#define RS_NTOH_STA(name_i, type, elem_c) \
    RS_READ_CHECK(elem_c * sizeof(type)); \
    thread_local static type v##name_i[elem_c] = {0}; \
    for (size_t i = 0; i < elem_c; i++) { \
        RS_NTOH_ASSIGN(v##name_i[i], type); \
    } \
    do { ; } while (0)

// No "do while (0)" wrapping due to v1[] and elem_c needing to remain in scope
#define RS_NTOH_VLA(_, type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    type v1[elem_c]; /* VLA */ \
    for (size_t i = 0; i < elem_c; i++) { \
        RS_NTOH_ASSIGN(v1[i], type); \
    } \
    do { ; } while (0)

// No "do while (0)" wrapping due to v1[] and elem_c needing to remain in scope
#define _RS_NTOH_HEAP(_, type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    type * v1 = malloc(elem_c); \
    if (!v1) { \
        RS_LOG(LOG_ALERT, "Failed to malloc()."); \
        RS_APP_FATAL; \
    } \
    for (size_t i = 0; i < elem_c; i++) { \
        RS_NTOH_ASSIGN(v1[i], type); \
    } \
    do { ; } while (0)

// No "do while (0)" wrapping due to v1[] and elem_c needing to remain in scope
#define _RS_STR(_, type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    type v1[elem_c + 1]; /* VLA */ \
    RS_NET_ARR(v1, elem_c, type); \
    v1[elem_c] = '\0'

// No "do while (0)" wrapping due to v1[] and elem_c needing to remain in scope
#define _RS_STR_HEAP(_, type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    type * v1 = malloc(elem_c + 1); \
    if (!v1) { \
        RS_LOG(LOG_ALERT, "Failed to malloc()."); \
        RS_APP_FATAL; \
    } \
    RS_NET_ARR(v_heap, elem_c, type); \
    v1[elem_c] = '\0'

// Determine whether to include a final "elem_c" parameter in the calback call,
// depending on whether the corresponding "v1" parameter is a non-static array.
#define __RS_NET(...) \
    RS_MACRIFY3(RS_256_3( \
        RS_NO_ELEM_C_PARAM, RS_NO_ELEM_C_PARAM, RS_ELEM_C_PARAM, \
    __VA_ARGS__), _)
#define __RS_NTOH(...) \
    RS_MACRIFY3(RS_256_3( \
        RS_NO_ELEM_C_PARAM, RS_NO_ELEM_C_PARAM, RS_ELEM_C_PARAM, \
    __VA_ARGS__), _)
#define __RS_STR RS_ELEM_C_PARAM(_)
#define __RS_NET_HEAP RS_ELEM_C_PARAM(_)
#define __RS_NTOH_HEAP RS_ELEM_C_PARAM(_)
#define __RS_STR_HEAP RS_ELEM_C_PARAM(_)

#define RS_NO_ELEM_C_PARAM(_)
#define RS_ELEM_C_PARAM(_) , elem_c
