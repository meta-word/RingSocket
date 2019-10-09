// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#define _POSIX_C_SOURCE 201112L // CLOCK_MONOTONIC_COARSE

#define RS_INCLUDE_QUEUE_FUNCTIONS // See ringsocket_queue.h
#define RS_INCLUDE_CONSUME_RING_MSG // See ringsocket_ring.h
#define RS_INCLUDE_PRODUCE_RING_MSG // See ringsocket_ring.h

// Due to their dependency relationships, all RingSocket system headers other
// than ringsocket_conf.h and ringsocket_variadic.h each include one other
// RingSocket system header, forming a chain in the following order:
//
// ----> <ringsocket.h>: RingSocket helper function API
#include <ringsocket_app.h> // Definition of RS_APP() and its descendent macros
//       <ringsocket_queue.h>: Struct rs_ring_queue and queuing/waking functions
//       <ringsocket_ring.h>: Single producer single consumer ring buffer API
//       <ringsocket_api.h>: Basic RingSocket API macros and typedefs
//       <ringsocket_variadic.h>: Arity-based macro expansion helper macros
//
// Their contents are therefore easier to understand when read in reverse order.

#include <inttypes.h> // PRI print format of stdint.h types
#include <time.h> // clock_gettime()

//##############################################################################
//## RingSocket helper function API ############################################

// All WebSocket message sending helper functions take this enum as a parameter
// to determine whether to send the message as binary data or as text data.
enum rs_data_kind {
 RS_BIN = 0, // Binary data
 RS_UTF8 = 1 // UTF-8 data (AKA Text data)
};

inline uint64_t rs_get_client_id(
    rs_t const * rs
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE); 
    return *((uint64_t *) (uint32_t []){
        // Offset worker index by 1 to prevent ever returning an ID value of 0.
        rs->inbound_worker_i + 1,
        rs->inbound_peer_i
    });
}

inline uint64_t rs_get_endpoint_id(
    rs_t const * rs
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE); 
    return rs->inbound_endpoint_id;
}

inline struct rs_conf const * rs_get_conf(
    rs_t const * rs
) {
    return rs->conf;
}

inline void * rs_get_app_data(
    rs_t const * rs
) {
    return rs->app_data;
}

inline void rs_w_p(
    rs_t * rs,
    void const * src,
    size_t size
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER); 
    RS_GUARD_APP(rs_check_app_wsize(rs, size));
    memcpy(rs->wbuf + rs->wbuf_i, src, size);
    rs->wbuf_i += size;
}

inline void rs_w_str(
    rs_t * rs,
    char const * str // Must be null-terminated
) {
    rs_w_p(rs, str, strlen(str));
}

inline void rs_w_uint8(
    rs_t * rs,
    uint8_t u8
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER); 
    RS_GUARD_APP(rs_check_app_wsize(rs, 1));
    rs->wbuf[rs->wbuf_i++] = u8;
}

inline void rs_w_uint16(
    rs_t * rs,
    uint16_t u16
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER); 
    RS_GUARD_APP(rs_check_app_wsize(rs, 2));
    *((uint16_t *) (rs->wbuf + rs->wbuf_i)) = u16;
    rs->wbuf_i += 2;
}

inline void rs_w_uint32(
    rs_t * rs,
    uint32_t u32
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER); 
    RS_GUARD_APP(rs_check_app_wsize(rs, 4));
    *((uint32_t *) (rs->wbuf + rs->wbuf_i)) = u32;
    rs->wbuf_i += 4;
}

inline void rs_w_uint64(
    rs_t * rs,
    uint32_t u64
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER); 
    RS_GUARD_APP(rs_check_app_wsize(rs, 8));
    *((uint64_t *) (rs->wbuf + rs->wbuf_i)) = u64;
    rs->wbuf_i += 8;
}

inline void rs_w_uint16_hton(
    rs_t * rs,
    uint16_t u16
) {
    rs_w_uint16(rs, RS_HTON16(u16));
}

inline void rs_w_uint32_hton(
    rs_t * rs,
    uint32_t u32
) {
    rs_w_uint32(rs, RS_HTON32(u32));
}

inline void rs_w_uint64_hton(
    rs_t * rs,
    uint64_t u64
) {
    rs_w_uint64(rs, RS_HTON64(u64));
}

inline void rs_w_int8(
    rs_t * rs,
    int8_t i8
) {
    rs_w_uint8(rs, i8);
}

inline void rs_w_int16(
    rs_t * rs,
    int16_t i16
) {
    rs_w_uint16(rs, i16);
}

inline void rs_w_int32(
    rs_t * rs,
    int32_t i32
) {
    rs_w_uint32(rs, i32);
}

inline void rs_w_int64(
    rs_t * rs,
    int64_t i64
) {
    rs_w_uint64(rs, i64);
}

inline void rs_w_int16_hton(
    rs_t * rs,
    int16_t i16
) {
    rs_w_uint16_hton(rs, i16);
}

inline void rs_w_int32_hton(
    rs_t * rs,
    int32_t i32
) {
    rs_w_uint32_hton(rs, i32);
}

inline void rs_w_int64_hton(
    rs_t * rs,
    int64_t i64
) {
    rs_w_uint64_hton(rs, i64);
}

inline void rs_to_single(
    rs_t * rs,
    enum rs_data_kind data_kind,
    uint64_t client_id
) {
    uint32_t * u32 = (uint32_t *) &client_id;
    rs_send(rs, *u32 - 1, RS_OUTBOUND_SINGLE, u32 + 1, 1, data_kind);
    rs->wbuf_i = 0;
}

inline void rs_to_multi(
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
            if (*u32++ - 1 == i) {
                cur_clients[cur_client_c++] = *u32;
            }
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

inline void rs_to_cur(
    rs_t * rs,
    enum rs_data_kind data_kind
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ); 
    rs_send(rs, rs->inbound_worker_i, RS_OUTBOUND_SINGLE,
        (uint32_t []){rs->inbound_peer_i}, 1, data_kind);
    rs->wbuf_i = 0;
}

inline void rs_to_every(
    rs_t * rs,
    enum rs_data_kind data_kind
) {
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        rs_send(rs, i, RS_OUTBOUND_EVERY, NULL, 0, data_kind);
    }
    rs->wbuf_i = 0;
}

inline void rs_to_every_except_single(
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

inline void rs_to_every_except_multi(
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
            if (*u32++ - 1 == i) {
                cur_clients[cur_client_c++] = *u32;
            }
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

inline void rs_to_every_except_cur(
    rs_t * rs,
    enum rs_data_kind data_kind
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ); 
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        if (i == rs->inbound_worker_i) {
            rs_send(rs, i, RS_OUTBOUND_EVERY_EXCEPT_SINGLE,
                (uint32_t []){rs->inbound_peer_i}, 1, data_kind);
        } else {
            rs_send(rs, i, RS_OUTBOUND_EVERY, NULL, 0, data_kind);
        }
    }
    rs->wbuf_i = 0;
}

//##############################################################################
//## Internal definitions (don't call these functions directly from app code) ##

inline rs_ret rs_check_app_wsize(
    rs_t * rs,
    size_t incr_size
) {
    if (!rs->wbuf) {
        RS_CALLOC(rs->wbuf, rs->wbuf_size);
    }
    if (rs->wbuf_i + incr_size >= rs->wbuf_size) {
        rs->wbuf_size = rs->conf->realloc_multiplier * (rs->wbuf_i + incr_size);
        RS_REALLOC(rs->wbuf, rs->wbuf_size);
    }
    return RS_OK;
}

inline void rs_send(
    rs_t * rs,
    size_t worker_i,
    enum rs_outbound_kind outbound_kind,
    uint32_t const * recipients,
    uint32_t recipient_c,
    enum rs_data_kind data_kind
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER); 
    size_t payload_size = rs->wbuf_i;
    if (payload_size > rs->conf->max_ws_msg_size) {
        RS_LOG(LOG_ERR, "Payload of size %zu exceeds the configured "
            "max_ws_msg_size %zu. Shutting down to avert further trouble...",
            payload_size, rs->conf->max_ws_msg_size);
        RS_APP_FATAL;
    }
    size_t msg_size =
        1 + // uint8_t outbound_kind
        4 * (recipient_c > 1) + // if (recipient_c > 1): uint32_t recipient_c
        4 * recipient_c + // uint32_t array of recipients (peer_i elements)
        2; // uint8_t WebSocket opcode + uint8_t WebSocket size indicator byte
    if (payload_size > UINT16_MAX) {
        msg_size += 8; // uint64_t WebSocket payload size (after '127' byte)
    } else if (payload_size > 125) {
        msg_size += 2; // uint16_t payload size (after '126' byte)
    }
    msg_size += payload_size;
    struct rs_ring_producer * prod = rs->outbound_producers + worker_i;
    RS_GUARD_APP(rs_produce_ring_msg(rs->conf,
        &rs->ring_pairs[worker_i].outbound_ring, prod, msg_size));
    *prod->w++ = (uint8_t) outbound_kind;
    if (recipient_c) {
        if (recipient_c > 1) {
            *((uint32_t *) prod->w) = recipient_c;
            prod->w += 4;
        }
        do {
            *((uint32_t *) prod->w) = *recipients++;
            prod->w += 4;
        } while (--recipient_c);
    }
    *prod->w++ = data_kind == RS_UTF8 ? RS_WS_OPC_FIN_TEXT : RS_WS_OPC_FIN_BIN;
    if (payload_size > UINT16_MAX) {
        *prod->w++ = 127;
        RS_W_HTON64(prod->w, payload_size);
        prod->w += 8;
    } else if (payload_size > 125) {
        *prod->w++ = 126;
        RS_W_HTON16(prod->w, payload_size);
        prod->w += 2;
    } else {
        *prod->w++ = payload_size;
    }
    if (rs->wbuf_i) {
        memcpy(prod->w, rs->wbuf, rs->wbuf_i);
        prod->w += rs->wbuf_i;
    }
    RS_GUARD_APP(rs_enqueue_ring_update(rs->ring_queue, rs->ring_pairs,
        rs->worker_sleep_states, rs->worker_eventfds, prod->w, worker_i, true));
}

inline rs_ret rs_init_outbound_producers(
    rs_t * rs
) {
    RS_CALLOC(rs->outbound_producers, rs->conf->worker_c);
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        struct rs_ring_producer * prod = rs->outbound_producers + i;
        prod->ring_size = rs->conf->outbound_ring_buf_size;
        RS_CACHE_ALIGNED_CALLOC(prod->ring, prod->ring_size);
        prod->w = prod->ring;
        RS_ATOMIC_STORE_RELAXED(&rs->ring_pairs[i].outbound_ring.w,
            (atomic_uintptr_t) prod->ring);
        RS_ATOMIC_STORE_RELAXED(&rs->ring_pairs[i].outbound_ring.r,
            (atomic_uintptr_t) prod->ring);
    }
    // Inbound ring producers are initialized by worker threads in
    // init_inbound_producers() of rs_to_app.c
    return RS_OK;
}

inline rs_ret rs_init_app_cb_args(
    struct rs_app_args * app_args,
    rs_t * rs
) {
    struct rs_conf const * conf = app_args->conf;
    struct rs_conf_app const * conf_app = conf->apps + app_args->app_i;
    rs->conf = conf;

    // Allocate all ring buffer pairs between this app and each worker
    RS_CACHE_ALIGNED_CALLOC(*app_args->ring_pairs, conf->worker_c);
    rs->ring_pairs = *app_args->ring_pairs;
 
    RS_GUARD(rs_init_outbound_producers(rs));
    
    // The 1st app allocates all worker sleep states (as per the reasons
    // mentioned in spawn_app_and_worker_threads()).
    if (!app_args->app_i) {
        RS_CACHE_ALIGNED_CALLOC(*app_args->worker_sleep_states, conf->worker_c);
    }
    rs->worker_sleep_states = *app_args->worker_sleep_states;
    rs->worker_eventfds = app_args->worker_eventfds;

    // Don't allocate rs->wbuf yet, but do so instead during the 1st rs_w_...()
    // call, if any. This saves memory for apps that never call rs_w_...()
    // functions, and instead write/send everything "in one go" with rs_w_to_...
    rs->wbuf_size = conf_app->wbuf_size;
    
    rs->ring_queue->size = conf_app->update_queue_size;
    RS_CALLOC(rs->ring_queue->queue, conf_app->update_queue_size);
    return RS_OK;
}

inline rs_ret rs_get_inbound_consumers_from_producers(
    rs_t const * rs,
    struct rs_ring_consumer * inbound_consumers
) {
    // Only run once during app initialization, so just do a bit of sleep
    // polling instead of bothering with something more fancy like a futex.
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        for (;;) {
            RS_CASTED_ATOMIC_LOAD_RELAXED(&rs->ring_pairs[i].inbound_ring.r,
                inbound_consumers[i].r, (uint8_t const *));
            if (inbound_consumers[i].r) {
                break;
            }
            thrd_sleep(&(struct timespec){ .tv_nsec = 1000000 }, NULL); // 1 ms
        }
    }
    return RS_OK;
}

inline rs_ret rs_get_cur_time_microsec(
    uint64_t * time_microsec
) {
    struct timespec ts = {0};
    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts) == -1) {
        RS_LOG_ERRNO(LOG_CRIT,
            "Unsuccessful clock_gettime(CLOCK_MONOTONIC_COARSE, &ts)");
        return RS_FATAL;
    }
    *time_microsec = 1000000 * ts.tv_sec + ts.tv_nsec / 1000;
    return RS_OK;
}

inline rs_ret rs_close_peer(
    rs_t * rs,
    uint16_t ws_close_code
) {
    struct rs_ring_producer * prod =
        rs->outbound_producers + rs->inbound_worker_i;
    RS_GUARD(rs_produce_ring_msg(rs->conf,
        &rs->ring_pairs[rs->inbound_worker_i].outbound_ring, prod, 9));
    *prod->w++ = RS_OUTBOUND_SINGLE;
    *((uint32_t *) prod->w) = rs->inbound_peer_i;
    prod->w += 4;
    *prod->w++ = RS_WS_OPC_FIN_CLOSE;
    *prod->w++ = 0x02; /* payload size == 2 */
    *((uint16_t *) prod->w) = RS_HTON16(ws_close_code);
    prod->w += 2;
    RS_GUARD(rs_enqueue_ring_update(rs->ring_queue, rs->ring_pairs,
        rs->worker_sleep_states, rs->worker_eventfds, prod->w,
        rs->inbound_worker_i, true));
    return RS_OK;
}

inline rs_ret rs_guard_cb(
    int ret
) {
    switch (ret) {
    case -1:
        RS_LOG(LOG_WARNING,
            "Shutting down: callback returned -1 (fatal error).");
        break;
    case 0:
        return RS_OK;
    default:
        RS_LOG(LOG_ERR, "Shutting down: callback returned an invalid value: "
            "%d. Valid values are -1 (fatal error) and 0 (success). ", ret);
    }
    return RS_FATAL;
}

inline rs_ret rs_guard_peer_cb(
    rs_t * rs,
    int ret
) {
    switch (ret) {
    case -1:
        RS_LOG(LOG_WARNING,
            "Shutting down: read/open callback returned -1 (fatal error).");
        return RS_FATAL;
    case 0:
        return RS_OK;
    default:
        if (ret >= 4000 && ret < 4900) {
            return rs_close_peer(rs, ret);
        }
    }
    RS_LOG(LOG_ERR, "Shutting down: read/open callback returned an invalid "
        "value: %d. Valid values are -1 (fatal error), 0 (success), and any "
        "value within the range 4000 through 4899 (private use WebSocket close "
        "codes).", ret);
    return RS_FATAL;
}

inline rs_ret rs_guard_timer_cb(
    int64_t ret,
    uint64_t *interval_microsec
) {
    switch (ret) {
    case -1:
        RS_LOG(LOG_WARNING,
            "Shutting down: timer callback returned -1 (fatal error).");
        return RS_FATAL;
    case 0:
        RS_LOG(LOG_NOTICE, "Timer callback returned 0, which means it will not "
            "be called again.");
        *interval_microsec = RS_TIME_INF;
        return RS_OK;
    default:
        if (ret > 0) {
            *interval_microsec = ret;
            return RS_OK;
        }
    }
    RS_LOG(LOG_ERR, "Shutting down: timer callback returned an invalid "
        "value: %" PRIu64 ". Valid values are -1 (fatal error), 0 (don't call "
        "the timer callback again), and any value greater than 0 (the number "
        "of microseconds after which the timer callback wishes to be called "
        "again).", ret);
    return RS_FATAL;
}
