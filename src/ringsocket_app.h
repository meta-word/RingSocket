// SPDX-License-Identifier: MIT
// Copyright © 2021 MetaWord Inc
// Copyright © 2019-2021 William Budd

#pragma once

#include <ringsocket_wsframe.h>
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
//   [YOU ARE HERE]          |
// <ringsocket_app.h> <------/    # Definition of RS_APP() and descendent macros
//   |            |
//   |            |
//   |            \--------------> [ Worker translation units: see rs_worker.h ]
//   |
//   |
//   \--> <ringsocket_helper.h> # Definitions of app helper functions (internal)
//                          |
//  <ringsocket.h> <--------/        # Definitions of app helper functions (API)
//    |
//    |
//    \-------------------------------> [ Any RingSocket app translation units ]

// #############################################################################
// # Initial Arguments app threads receive when spawned ########################

#ifdef __cplusplus
#include <array>
#include <string>
#include <vector>
#endif

struct rs_app_args {
    struct rs_conf const * conf;
    // Worker_c length ring_pair array to be allocated by the called app
    struct rs_ring_pair * * ring_pairs;
    struct rs_sleep_state * sleep_state; // This app's sleep state
    struct rs_sleep_state * * worker_sleep_states;
    int const * worker_eventfds;
    size_t app_i;
    enum rs_log_facility log_facility;
    int log_max;
};

// #############################################################################
// # Inbound (i.e., worker --> app) ring buffer message format #################

// Every ring buffer message consists of an rs_consumer_msg struct instance
// (see ringsocket_ring.h), and in case of an inbound ring buffer its cons->msg
// member consists of the following rs_inbound_msg struct instance.

enum rs_inbound_kind {
    RS_INBOUND_OPEN = 0, // Implies an imsg->payload of 0 bytes.
    RS_INBOUND_READ = 1, // Implies an imsg->payload of 1 or more bytes.
    RS_INBOUND_CLOSE = 2 // Implies an imsg->payload of 0 bytes.
};

struct rs_inbound_msg {
    uint32_t peer_i;
    uint32_t socket_fd;
    uint16_t endpoint_id;
    uint8_t data_kind; // Enum rs_data_kind compressed into a single byte
    uint8_t inbound_kind; // Enum rs_inbound_kind compressed into a single byte
    uint8_t const payload[]; // Size: cons->size - sizeof(struct rs_inbound_msg)
};

// #############################################################################
// # Outbound (i.e., app --> worker) ring buffer message format ################

// Every message on an outbound ring buffer consists of an rs_consumer_msg
// struct instance (see ringsocket_ring.h), of which the cons->msg member starts
// with the following enum, packed into a single uint8_t:

enum rs_outbound_kind { // The outbound message format depends on the enum value
    RS_OUTBOUND_OPEN_ACK = 0, // uint8_t kind, uint32_t peer_i
    RS_OUTBOUND_SINGLE = 1, // uint8_t kind, uint32_t peer_i
    RS_OUTBOUND_ARRAY = 2, // uint8_t kind, uint32_t peer_c, uint32_t peer_i[]
    RS_OUTBOUND_EVERY = 3, // uint8_t kind
    RS_OUTBOUND_EVERY_EXCEPT_SINGLE = 4, // Same format as RS_OUTBOUND_SINGLE
    RS_OUTBOUND_EVERY_EXCEPT_ARRAY = 5 // Same format as RS_OUTBOUND_ARRAY
};

// Following the enum byte and any uint32_t peer_c/peer_i sequence; every
// outbound message ends with a full WebSocket message that will be sent as-is
// to every peer_i it's addressed to (see rs_send() in ringsocket_helper.h).
// This allows worker threads to treat the outbound ring buffers as read-only
// write buffers, because they never have to alter the contents of the messages
// they relay.
//
// For any outbound ring buffer WebSocket message arriving from an app, worker
// threads determine whether to keep or shut down the peer(s) it's addressed to
// simply by checking whether its WebSocket opcode is a RS_WS_OPC_FIN_CLOSE
// (See also the WebSocket definitions in ringsocket_api.h).

// When an incoming message fails to pass an internal check performed by the
// RS_APP() macro below (as stipulated by the arguments passed to said macro),
// it will place a WebSocket close message with one of the following WebSocket
// status codes on an outbound ring without calling any app callback function:
//
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
    RS_APP_WS_CLOSE_UNKNOWN_CASE = 4902
};
// In contrast, RingSocket prescribes that app callback functions may only
// trigger peer closures with a status code in the range 4000-4899.

// #############################################################################
// # Internal RingSocket app data ##############################################

enum rs_callback {
    RS_CB_INIT  = 0x01,
    RS_CB_OPEN  = 0x02,
    RS_CB_READ  = 0x04,
    RS_CB_CLOSE = 0x08,
    RS_CB_TIMER = 0x10
};

struct rs_app_cb_args { // AKA rs_t (typedef located in ringsocket_api.h)
#ifndef __cplusplus
    void * app_data;
#endif
    struct rs_conf const * conf;
    struct rs_ring_pair * * ring_pairs;
    struct rs_ring_producer * outbound_producers;
    struct rs_ring_queue * ring_queue;
    struct rs_sleep_state * worker_sleep_states;
    int const * worker_eventfds;
    uint8_t * wbuf;
    size_t wbuf_size;
    size_t wbuf_i;
    uint32_t inbound_peer_i;
    int inbound_socket_fd;
    unsigned cb; // unsigned version of enum rs_callback
    enum rs_data_kind read_data_kind;
    uint16_t inbound_endpoint_id;
    uint16_t inbound_worker_i;
};

struct rs_app_schedule {
    struct rs_sleep_state * sleep_state;
    struct rs_ring_consumer * inbound_consumers;
    uint64_t timestamp_microsec;
    uint64_t interval_microsec;
    uint64_t interval_microsec_min;
    uint64_t interval_microsec_incr;
    uint64_t interval_microsec_max;
};

// #############################################################################
// # Fatal app error handling ##################################################

// This should probably be replaced at some point with something less dumb.
#define RS_APP_FATAL exit(EXIT_FAILURE)

#define RS_GUARD_APP(call) if ((call) != RS_OK) RS_APP_FATAL

// #############################################################################
// # C++: casting of enum class values to int, based on operator+ ##############

// This template makes it less cumbersome to cast any custom enum class return
// value from C++ callback functions to int (without generating compiler
// complaints, or writing more boilerplate than a single + per invocation).

// Based on https://stackoverflow.com/a/42198760/765294 by user Pixelchemist.

#ifdef __cplusplus
template <typename T>
constexpr auto operator+(T e) noexcept
    -> std::enable_if_t<std::is_enum<T>::value, std::underlying_type_t<T>>
{
    return static_cast<std::underlying_type_t<T>>(e);
}
#endif

// #############################################################################
// # RS_APP() ##################################################################

// See the RS_LOG() section in ringsocket_api.h for explanation of RS_LOG_VARS.
#ifdef __cplusplus
// The slightly involved C++ version:
#define RS_APP(app_obj_type, open_macro, read_macro, close_macro, timer_macro) \
/* Templating app_obj_type as typename T allows more straightforward type */ \
/* referencing than when passing it through the macro invocation hierarchy. */ \
template <typename T> \
static rs_ret _ringsocket_app(struct rs_app_args * app_args) { \
    T app_obj; \
    RS_APP_BODY( \
        RS_INIT_NONE, open_macro, read_macro, close_macro, timer_macro); \
} \
/* Declare C linkage, instantiate <typename T>, and catch any exceptions. */ \
extern "C" rs_ret ringsocket_app(struct rs_app_args * app_args) { \
    /* Update RS_LOG_VARS below to match the values obtained in rs_conf.c */ \
    _rs_log_facility = app_args->log_facility; \
    _rs_log_max = app_args->log_max; \
    rs_set_thread_id(app_args->conf->apps[app_args->app_i].name); \
    try { \
        _ringsocket_app<app_obj_type>(app_args); \
    } catch (std::exception const & e) { \
        RS_LOG(LOG_CRIT, \
            "Shutting down: app threw an exception: %s", e.what()); \
    } catch (...) { \
        RS_LOG(LOG_CRIT, \
            "Shutting down: app threw an unrecognized exception."); \
    } \
    RS_APP_FATAL; \
} \
\
RS_LOG_VARS
#else
// The Plain C version:
#define RS_APP(init_macro, open_macro, read_macro, close_macro, timer_macro) \
rs_ret ringsocket_app(struct rs_app_args * app_args) { \
    /* Update RS_LOG_VARS below to match the values obtained in rs_conf.c */ \
    _rs_log_facility = app_args->log_facility; \
    _rs_log_max = app_args->log_max; \
    rs_set_thread_id(app_args->conf->apps[app_args->app_i].name); \
    RS_APP_BODY(init_macro, open_macro, read_macro, close_macro, timer_macro); \
} \
\
RS_LOG_VARS
#endif

#define RS_APP_BODY( \
    init_macro, open_macro, read_macro, close_macro, timer_macro) \
    struct rs_ring_queue _ring_queue = {0}; \
    struct rs_app_cb_args rs = {0}; \
    rs.cb = RS_CB_INIT; \
    rs.ring_queue = &_ring_queue; \
    /* All RS_APP() helper functions are located in ringsocket_helper.h. */ \
    RS_GUARD_APP(rs_init_app_cb_args(app_args, &rs)); \
    \
    /* Prepend-pasting prevents (paramaterized) macro arguments from */ \
    /* getting expanded before this _RS_APP macro is expanded (i.e., */ \
    /* because RS_INIT[_NONE] isn't defined, whereas _RS_INIT[_NONE] is). */ \
    \
    _##init_macro; /* Should expand _RS_INIT[_NONE] */ \
    \
    struct rs_app_schedule sched = { \
        .sleep_state = app_args->sleep_state \
    }; \
    RS_GUARD_APP(rs_get_consumers_from_producers(&rs, &sched)); \
    \
    /* See rs_init_app_cb_args() for why this assignment must occur here */ \
    rs.worker_sleep_states = *app_args->worker_sleep_states; \
    \
    _##timer_macro; /* Should expand _RS_TIMER_[NONE|SLEEP|WAKE] */ \
    \
    struct rs_inbound_msg * imsg = NULL; \
    size_t payload_size = 0; \
    while (rs_wait_for_inbound_msg(&rs, &sched, &imsg, &payload_size \
        _PARAMS_##timer_macro) == RS_OK) { \
        rs.inbound_peer_i = imsg->peer_i; \
        rs.inbound_socket_fd = imsg->socket_fd; \
        rs.inbound_endpoint_id = imsg->endpoint_id; \
        switch (imsg->inbound_kind) { \
        case RS_INBOUND_OPEN: \
            RS_ENQUEUE_APP_READ_UPDATE; \
            _##open_macro; /* Should expand _RS_OPEN[_NONE] */ \
            continue; \
        case RS_INBOUND_READ: \
            break; \
        case RS_INBOUND_CLOSE: default: \
            RS_ENQUEUE_APP_READ_UPDATE; \
            call_close_cb: \
            _##close_macro; /* Should expand _RS_CLOSE[_NONE] */ \
            continue; \
        } \
        rs.cb = RS_CB_READ; \
        rs.read_data_kind = (enum rs_data_kind) imsg->data_kind; \
        size_t payload_i = 0; \
        _##read_macro; /* Should expand _RS_READ_... */ \
    } \
    RS_APP_FATAL

// #############################################################################
// # RS_INIT() #################################################################

#ifndef __cplusplus
#define _RS_INIT(...) \
RS_MACRIFY_INIT( \
    RS_256_2( \
        _RS_INIT_WITHOUT_APP_DATA, \
        _RS_INIT_WITH_APP_DATA, \
        __VA_ARGS__ \
    ), \
    __VA_ARGS__ \
)

#define _RS_INIT_WITHOUT_APP_DATA(init_cb) \
    RS_GUARD_APP(rs_guard_init_cb(init_cb(&rs)))

#define _RS_INIT_WITH_APP_DATA(init_cb, app_data_byte_c) \
    /* Omit do {} while loop to keep app_data array in function scope */ \
    uint8_t app_data[app_data_byte_c] = {0}; \
    rs.app_data = app_data; \
    _RS_INIT_WITHOUT_APP_DATA(init_cb)
#endif

#define _RS_INIT_NONE

// #############################################################################
// # RS_TIMER_...() ############################################################

#define _RS_TIMER(timer_cb, \
    timer_interval_min, timer_interval_incr, timer_interval_max) \
do { \
    sched.interval_microsec_min = timer_interval_min; \
    sched.interval_microsec_incr = timer_interval_incr; \
    sched.interval_microsec_max = timer_interval_max; \
} while (0) \

#define _RS_TIMER_NONE

#ifdef __cplusplus
#define _PARAMS_RS_TIMER(timer_cb, ...) , &T::timer_cb, app_obj
#define _PARAMS_RS_TIMER_NONE , nullptr, app_obj
#else
#define _PARAMS_RS_TIMER(timer_cb, ...) , timer_cb
#define _PARAMS_RS_TIMER_NONE , NULL
#endif

// #############################################################################
// # RS_OPEN() #################################################################

#ifdef __cplusplus
#define _RS_OPEN(open_cb) _RS_OPEN_GENERIC(app_obj.open_cb)
#else
#define _RS_OPEN(open_cb) _RS_OPEN_GENERIC(open_cb)
#endif

#define _RS_OPEN_GENERIC(open_cb) \
do { \
    RS_GUARD_APP(rs_ack_peer_open(&rs)); \
    rs.cb = RS_CB_OPEN; \
    RS_GUARD_APP(rs_guard_cb(&rs, open_cb(&rs))); \
} while (0)

#define _RS_OPEN_NONE

// #############################################################################
// # RS_CLOSE() ################################################################

#ifdef __cplusplus
#define _RS_CLOSE(close_cb) _RS_CLOSE_GENERIC(app_obj.close_cb)
#else
#define _RS_CLOSE(close_cb) _RS_CLOSE_GENERIC(close_cb)
#endif

#define _RS_CLOSE_GENERIC(close_cb) \
do { \
    rs.cb = RS_CB_CLOSE; \
    RS_GUARD_APP(rs_guard_cb(&rs, close_cb(&rs))); \
} while (0)

#define _RS_CLOSE_NONE

// #############################################################################
// # RS_READ_...() #############################################################

#define _RS_READ_SWITCH(...) \
do { \
    RS_READ_CHECK(1); \
    switch (imsg->payload[payload_i++]) { \
    RS_PREFIX_EACH(_, __VA_ARGS__); \
    default: \
        RS_READ_ABORT(RS_APP_WS_CLOSE_UNKNOWN_CASE); \
    } \
} while (0)

#define _RS_CASE_BIN(cb_i, ...) \
    case +cb_i: \
        { \
            _RS_READ_BIN(__VA_ARGS__); \
        } \
        break

#define _RS_CASE_UTF8(cb_i, ...) \
    case +cb_i: \
        { \
            _RS_READ_UTF8(__VA_ARGS__); \
        } \
        break

#define _RS_CASE_ANY(cb_i, ...) \
    case +cb_i: \
        { \
            _RS_READ_ANY(__VA_ARGS__); \
        } \
        break

#define _RS_READ_BIN(...) \
do { \
    if (rs.read_data_kind == RS_UTF8) { \
        RS_READ_ABORT(RS_APP_WS_CLOSE_WRONG_DATA_TYPE); \
    } \
    _RS_READ_ANY(__VA_ARGS__); \
} while (0)

#define _RS_READ_UTF8(...) \
do { \
    if (rs.read_data_kind == RS_BIN) { \
        RS_READ_ABORT(RS_APP_WS_CLOSE_WRONG_DATA_TYPE); \
    } \
    _RS_READ_ANY(__VA_ARGS__); \
} while (0)

#ifdef __cplusplus
#define _RS_READ_ANY(...) \
    RS_MACRIFY_METHOD( \
        RS_256_2( \
            RS_READ_ANY_METHOD_WITHOUT_ARGS, \
            RS_READ_ANY_METHOD_WITH_ARGS, \
            __VA_ARGS__ \
        ), \
        __VA_ARGS__ \
    )

#define RS_READ_ANY_METHOD_WITHOUT_ARGS(read_cb) RS_A00(app_obj.read_cb)
#define RS_READ_ANY_METHOD_WITH_ARGS(read_cb, ...) \
    RS_READ_ANY_GENERIC(app_obj.read_cb, __VA_ARGS__)
#else
#define _RS_READ_ANY(...) RS_READ_ANY_GENERIC(__VA_ARGS__)
#endif

#define RS_READ_ANY_GENERIC(...) \
    RS_MACRIFY_ARGC( \
        RS_256_16( \
            RS_A00, RS_A01, RS_A02, RS_A03, \
            RS_A04, RS_A05, RS_A06, RS_A07, \
            RS_A08, RS_A09, RS_A10, RS_A11, \
            RS_A12, RS_A13, RS_A14, RS_A15, \
            __VA_ARGS__ \
        ), \
        __VA_ARGS__ \
    )

#define RS_ENQUEUE_APP_READ_UPDATE \
    RS_GUARD_APP(rs_enqueue_ring_update(rs.ring_queue, rs.ring_pairs, \
        rs.worker_sleep_states, rs.worker_eventfds, \
        (uint8_t *) sched.inbound_consumers[rs.inbound_worker_i].r, \
        rs.inbound_worker_i, false)) \

#define RS_READ_ABORT(ws_close_code) \
do { \
    RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_close_peer(&rs, rs.inbound_worker_i, rs.inbound_peer_i, \
        (ws_close_code))); \
    goto call_close_cb; \
} while (0)

#define RS_A00(cb) \
do { \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs))); \
} while (0)

#define RS_A01(cb, a01) \
do { \
    _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v1 __##a01))); \
} while (0)

#define RS_A02(cb, a02, a01) \
do { \
    _02##a02; _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v2, v1 __##a01))); \
} while (0)

#define RS_A03(cb, a03, a02, a01) \
do { \
    _03##a03; _02##a02; _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v3, v2, v1 __##a01))); \
} while (0)

#define RS_A04(cb, a04, a03, a02, a01) \
do { \
    _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v4, v3, v2, v1 __##a01))); \
} while (0)

#define RS_A05(cb, a05, a04, a03, a02, a01) \
do { \
    _05##a05; _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v5, v4, v3, v2, v1 __##a01))); \
} while (0)

#define RS_A06(cb, a06, a05, a04, a03, a02, a01) \
do { \
    _06##a06; _05##a05; _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v6, v5, v4, v3, v2, v1 __##a01))); \
} while (0)

#define RS_A07(cb, a07, a06, a05, a04, a03, a02, a01) \
do { \
    _07##a07; _06##a06; _05##a05; _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v7, v6, v5, v4, v3, v2, v1 \
        __##a01))); \
} while (0)

#define RS_A08(cb, a08, a07, a06, a05, a04, a03, a02, a01) \
do { \
    _08##a08; _07##a07; _06##a06; _05##a05; _04##a04; _03##a03; _02##a02; \
    _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v8, v7, v6, v5, v4, v3, v2, v1 \
        __##a01))); \
} while (0)

#define RS_A09(cb, a09, a08, a07, a06, a05, a04, a03, a02, a01) \
do { \
    _09##a09; _08##a08; _07##a07; _06##a06; _05##a05; _04##a04; _03##a03; \
    _02##a02; _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v9, v8, v7, v6, v5, v4, v3, v2, v1 \
        __##a01))); \
} while (0)

#define RS_A10(cb, a10, a09, a08, a07, a06, a05, a04, a03, a02, a01) \
do { \
    _10##a10; _09##a09; _08##a08; _07##a07; _06##a06; _05##a05; _04##a04; \
    _03##a03; _02##a02; _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v10, v9, v8, v7, v6, v5, v4, v3, v2, \
        v1 __##a01))); \
} while (0)

#define RS_A11(cb, a11, a10, a09, a08, a07, a06, a05, a04, a03, a02, a01) \
do { \
    _11##a11; _10##a10; _09##a09; _08##a08; _07##a07; _06##a06; _05##a05; \
    _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v11, v10, v9, v8, v7, v6, v5, v4, \
        v3, v2, v1 __##a01))); \
} while (0)

#define RS_A12(cb, a12, a11, a10, a09, a08, a07, a06, a05, a04, a03, a02, a01) \
do { \
    _12##a12; _11##a11; _10##a10; _09##a09; _08##a08; _07##a07; _06##a06; \
    _05##a05; _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v12, v11, v10, v9, v8, v7, v6, v5, \
        v4, v3, v2, v1 __##a01))); \
} while (0)

#define RS_A13(cb, a13, a12, a11, a10, a09, a08, a07, a06, a05, a04, a03, a02, \
    a01) \
do { \
    _13##a13, _12##a12; _11##a11; _10##a10; _09##a09; _08##a08; _07##a07; \
    _06##a06; _05##a05; _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v13, v12, v11, v10, v9, v8, v7, v6, \
        v5, v4, v3, v2, v1 __##a01))); \
} while (0)

#define RS_A14(cb, a14, a13, a12, a11, a10, a09, a08, a07, a06, a05, a04, a03, \
    a02, a01) \
do { \
    _14##a14, _13##a13, _12##a12; _11##a11; _10##a10; _09##a09; _08##a08; \
    _07##a07; _06##a06; _05##a05; _04##a04; _03##a03; _02##a02; _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v14, v13, v12, v11, v10, v9, v8, v7, \
        v6, v5, v4, v3 v2, v1 __##a01))); \
} while (0)

#define RS_A15(cb, a15, a14, a13, a12, a11, a10, a09, a08, a07, a06, a05, a04, \
    a03, a02, a01) \
do { \
    _15##a15, _14##a14, _13##a13, _12##a12; _11##a11; _10##a10; _09##a09; \
    _08##a08; _07##a07; _06##a06; _05##a05; _04##a04; _03##a03; _02##a02; \
    _01##a01; \
    RS_READ_CHECK_EXACT; RS_ENQUEUE_APP_READ_UPDATE; \
    RS_GUARD_APP(rs_guard_cb(&rs, cb(&rs, v15, v14, v13, v12, v11, v10, v9, \
        v8, v7, v6, v5, v4, v3, v2, v1 __##a01))); \
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

#define _RS_NET(name_i, ...) \
    RS_MACRIFY_TYPE( \
        RS_256_3( \
            RS_NET_SINGLE, \
            RS_NET_ARR, \
            RS_NET_ARR_MAX, \
            __VA_ARGS__ \
        ), \
        name_i, \
        __VA_ARGS__ \
    )

#define _RS_NTOH(name_i, ...) \
    RS_MACRIFY_TYPE( \
        RS_256_3( \
            RS_NTOH_SINGLE, \
            RS_NTOH_ARR, \
            RS_NTOH_ARR_MAX, \
            __VA_ARGS__ \
        ), \
        name_i, \
        __VA_ARGS__ \
    )

#define RS_READ_CHECK(size) \
do { \
    if (payload_i + (size) > payload_size) { \
        RS_READ_ABORT(RS_APP_WS_CLOSE_WRONG_SIZE); \
    } \
} while (0)

#define RS_READ_CHECK_EXACT \
do { \
    if (payload_i != payload_size) { \
        RS_READ_ABORT(RS_APP_WS_CLOSE_WRONG_SIZE); \
    } \
} while (0)

// Many of the macros below instantiate a variable that needs to remain in scope
// until the read callback function is called, hence they cannot be wrapped in a
// "do while (0)"

#define RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c) \
    size_t elem_c = payload_size - payload_i; \
    if (elem_c % sizeof(type)) { \
        RS_READ_ABORT(RS_APP_WS_CLOSE_WRONG_SIZE); \
    } \
    elem_c /= sizeof(type); \
    if (elem_c < (min_elem_c) || elem_c > (max_elem_c)) { \
        RS_READ_ABORT(RS_APP_WS_CLOSE_WRONG_SIZE); \
    } \
    do { ; } while (0)

#define RS_NET_SINGLE(name_i, type) \
    RS_READ_CHECK(sizeof(type)); \
    type v##name_i = *((type *) (imsg->payload + payload_i)); \
    payload_i += sizeof(type)

#define RS_NET_MEMCPY(var, elem_c, type) \
do { \
    memcpy(var, imsg->payload + payload_i, (elem_c) * sizeof(type)); \
    payload_i += (elem_c) * sizeof(type); \
} while (0)

#ifdef __cplusplus
#define RS_NET_ARR(name_i, type, elem_c) \
    RS_READ_CHECK(elem_c * sizeof(type)); \
    std::array<type, elem_c> v##name_i; \
    RS_NET_MEMCPY(&v##name_i[0], elem_c, type)
#else
#define RS_NET_ARR(name_i, type, elem_c) \
    RS_READ_CHECK(elem_c * sizeof(type)); \
    type v##name_i[elem_c] = {0}; \
    RS_NET_MEMCPY(v##name_i, elem_c, type)
#endif

#ifdef __cplusplus
#define RS_NET_ARR_MAX(name_i, type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    std::vector<type> v1(elem_c); \
    RS_NET_MEMCPY(&v1[0], elem_c, type)
#else
#define RS_NET_ARR_MAX(type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    type v1[max_elem_c] = {0}; \
    RS_NET_MEMCPY(v1, elem_c, type)

#define RS_NET_STA(type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    thread_local static type v1[max_elem_c] = {0}; \
    RS_NET_MEMCPY(v1, elem_c, type)

#define RS_NET_VLA(type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    type v1[elem_c]; /* VLA */ \
    RS_NET_MEMCPY(v1, elem_c, type)

#define RS_NET_HEAP(type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    type * v1 = malloc(elem_c); \
    if (!v1) { \
        RS_LOG(LOG_ALERT, "Failed to malloc()."); \
        RS_APP_FATAL; \
    } \
    RS_NET_MEMCPY(v1, elem_c, type)
#endif

#define RS_NTOH_ASSIGN(var, type) \
do { \
    switch (sizeof(type)) { \
    case 1: default: (var) = *((type *) (imsg->payload + payload_i)); break; \
    case 2: (var) = RS_R_NTOH16(imsg->payload + payload_i); break; \
    case 4: (var) = RS_R_NTOH32(imsg->payload + payload_i); break; \
    case 8: (var) = RS_R_NTOH64(imsg->payload + payload_i); break; \
    } \
    payload_i += sizeof(type); \
} while (0)

#define RS_NTOH_SINGLE(name_i, type) \
    RS_READ_CHECK(sizeof(type)); \
    type v##name_i = 0; \
    RS_NTOH_ASSIGN(v##name_i, type)

#ifdef __cplusplus
#define RS_NTOH_ARR(name_i, type, elem_c) \
    RS_READ_CHECK(elem_c * sizeof(type)); \
    std::array<type, elem_c> v##name_i; \
    for (auto && elem : v##name_i) { \
        RS_NTOH_ASSIGN(elem, type); \
    } \
    do { ; } while (0)
#else
#define RS_NTOH_ARR(name_i, type, elem_c) \
    RS_READ_CHECK(elem_c * sizeof(type)); \
    type v##name_i[elem_c] = {0}; \
    for (size_t i = 0; i < elem_c; i++) { \
        RS_NTOH_ASSIGN(v##name_i[i], type); \
    } \
    do { ; } while (0)
#endif

#ifdef __cplusplus
#define _01RS_NTOH_ARR_MAX(type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    std::vector<type> v1(elem_c); \
    for (auto && elem : v1) { \
        RS_NTOH_ASSIGN(elem, type); \
    } \
    do { ; } while (0)
#else
#define _01RS_NTOH_ARR_MAX(type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    type v1[max_elem_c] = {0}; \
    for (size_t i = 0; i < elem_c; i++) { \
        RS_NTOH_ASSIGN(v1[i], type); \
    } \
    do { ; } while (0)

#define _01RS_NTOH_STA(type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    thread_local static type v1[max_elem_c] = {0}; \
    for (size_t i = 0; i < elem_c; i++) { \
        RS_NTOH_ASSIGN(v1[i], type); \
    } \
    do { ; } while (0)

#define _01RS_NTOH_VLA(type, min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(type, min_elem_c, max_elem_c); \
    type v1[elem_c]; /* VLA */ \
    for (size_t i = 0; i < elem_c; i++) { \
        RS_NTOH_ASSIGN(v1[i], type); \
    } \
    do { ; } while (0)

#define _01RS_NTOH_HEAP(type, min_elem_c, max_elem_c) \
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
#endif

#ifdef __cplusplus
#define _01RS_STR(min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(char, min_elem_c, max_elem_c); \
    std::string v1(reinterpret_cast<char const *>(imsg->payload + payload_i), \
        elem_c); \
    payload_i + elem_c
#else
#define RS_STR(min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(char, min_elem_c, max_elem_c); \
    char v1[(max_elem_c) + 1] = {0}; \
    RS_NET_MEMCPY(v1, elem_c, char);

#define RS_STR_STA(min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(char, min_elem_c, max_elem_c); \
    thread_local static char v1[(max_elem_c) + 1] = {0}; \
    RS_NET_MEMCPY(v1, elem_c, char); \
    v1[elem_c] = '\0'

#define RS_STR_VLA(min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(char, min_elem_c, max_elem_c); \
    char v1[elem_c + 1]; /* VLA */ \
    RS_NET_MEMCPY(v1, elem_c, char); \
    v1[elem_c] = '\0'

#define RS_STR_HEAP(min_elem_c, max_elem_c) \
    RS_READ_CHECK_RANGE(char, min_elem_c, max_elem_c); \
    char * v1 = malloc(elem_c + 1); \
    if (!v1) { \
        RS_LOG(LOG_ALERT, "Failed to malloc()."); \
        RS_APP_FATAL; \
    } \
    RS_NET_MEMCPY(v1, elem_c, char); \
    v1[elem_c] = '\0'
#endif

// Determine whether to include a final "elem_c" parameter in the calback call,
// depending on whether the corresponding "v1" parameter has a variable length.

// These take a dummy empty parameter to allow their macro names to be specified
// without caused unwanted early substitution.
#define RS_WITHOUT_ELEM_C_PARAM()
#define RS_WITH_ELEM_C_PARAM() , elem_c

#ifdef __cplusplus
#define __RS_NET(...) RS_WITHOUT_ELEM_C_PARAM()
#define __RS_NTOH(...) RS_WITHOUT_ELEM_C_PARAM()
#else
#define __RS_NET(...) RS_MACRIFY_ELEMC( \
    RS_256_3( \
        RS_WITHOUT_ELEM_C_PARAM, \
        RS_WITHOUT_ELEM_C_PARAM, \
        RS_WITH_ELEM_C_PARAM, \
        __VA_ARGS__), \
    )
#define __RS_NTOH(...) __RS_NET(__VA_ARGS__)

#define __RS_NET_STA(...) RS_WITH_ELEM_C_PARAM()
#define __RS_NTOH_STA(...) RS_WITH_ELEM_C_PARAM()
#define __RS_NET_VLA(...) RS_WITH_ELEM_C_PARAM()
#define __RS_NTOH_VLA(...) RS_WITH_ELEM_C_PARAM()
#define __RS_NET_HEAP(...) RS_WITH_ELEM_C_PARAM()
#define __RS_NTOH_HEAP(...) RS_WITH_ELEM_C_PARAM()
#endif

#ifdef __cplusplus
#define __RS_STR(...) RS_WITHOUT_ELEM_C_PARAM()
#else
#define __RS_STR(...) RS_WITH_ELEM_C_PARAM()
#define __RS_STR_VLA(...) RS_WITH_ELEM_C_PARAM()
#define __RS_STR_HEAP(...) RS_WITH_ELEM_C_PARAM()
#endif
