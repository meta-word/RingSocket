// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket.h>

//##############################################################################
//## RingSocket helper API functions ###########################################

// All WebSocket message sending helper functions take this enum as a parameter
// to determine whether to send the message as binary data or as text data.
enum rs_data_kind {
 RS_BIN = 0, // Binary data
 RS_UTF8 = 1 // UTF-8 data (AKA Text data)
};

inline uint64_t rs_get_client_id(
    rs_t * rs
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE); 
    return *((uint64_t *) (uint32_t []){
        // Offset worker index by 1 to prevent ever returning an ID value of 0.
        rs->inbound_worker_i + 1,
        rs->inbound_peer_i
    });
}

inline uint64_t rs_get_endpoint_id(
    rs_t * rs
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE); 
    return rs->inbound_endpoint_id;
}

inline struct rs_conf const * rs_get_conf(
    rs_t * rs
) {
    return rs->conf;
}

inline void * rs_get_app_data(
    rs_t * rs
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

#define RS_GUARD_CB(allowed_cb_mask) \
do { \
    if (!(rs->cb & allowed_cb_mask)) { \
        RS_LOG(LOG_ERR, "%s must not be called from an RS_%s() " \
            "callback function: shutting down...", __func__, \
            (char *[]){"", /*0x01*/"INIT", /*0x02*/"OPEN", "", \
                /*0x04*/"READ...", "", "", "", /*0x08*/"CLOSE", "", "", "", \
                "", "", "", "", /*0x10*/"TIMER..."}[rs->cb]); \
        RS_APP_FATAL; \
    } \
} while (0)

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
    struct rs_ring * ring = rs->outbound_rings + worker_i;
    RS_GUARD_APP(rs_prepare_ring_write(&rs->io_pairs[worker_i].outbound,
        ring, msg_size));
    *ring->writer++ = (uint8_t) outbound_kind;
    if (recipient_c) {
        if (recipient_c > 1) {
            *((uint32_t *) ring->writer) = recipient_c;
            ring->writer += 4;
        }
        do {
            *((uint32_t *) ring->writer) = *recipients++;
            ring->writer += 4;
        } while (--recipient_c);
    }
    *ring->writer++ = data_kind == RS_UTF8 ?
        RS_WS_OPC_FIN_TEXT : RS_WS_OPC_FIN_BIN;
    if (payload_size > UINT16_MAX) {
        *ring->writer++ = 127;
        RS_W_HTON64(ring->writer, payload_size);
        ring->writer += 8;
    } else if (payload_size > 125) {
        *ring->writer++ = 126;
        RS_W_HTON16(ring->writer, payload_size);
        ring->writer += 2;
    } else {
        *ring->writer++ = payload_size;
    }
    if (rs->wbuf_i) {
        memcpy(ring->writer, rs->wbuf, rs->wbuf_i);
        ring->writer += rs->wbuf_i;
    }
    RS_GUARD_APP(rs_enqueue_ring_update(rs->ring_update_queue, rs->io_pairs,
        rs->worker_sleep_states, rs->worker_eventfds, ring->writer, worker_i,
        true));
}

inline rs_ret rs_init_outbound_rings(
    rs_t * rs
) {
    RS_CALLOC(rs->outbound_rings, rs->conf->worker_c);
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        struct rs_ring * ring = rs->outbound_rings + i;
        ring->buf_size = rs->conf->outbound_ring_buf_size;
        RS_CACHE_ALIGNED_CALLOC(ring->buf, ring->buf_size);
        ring->writer = ring->buf;
        ring->alloc_multiplier = rs->conf->realloc_multiplier;
        RS_ATOMIC_STORE_RELAXED(&rs->io_pairs[i].outbound.writer,
            (atomic_uintptr_t) ring->buf);
        RS_ATOMIC_STORE_RELAXED(&rs->io_pairs[i].outbound.reader,
            (atomic_uintptr_t) ring->buf);
    }
    // Inbound rings are initialized by worker threads
    // through init_inbound_rings() of rs_ring.c
    return RS_OK;
}

inline rs_ret rs_init_app_cb_args(
    struct rs_app_args * app_args,
    rs_t * rs
) {
    struct rs_conf const * conf = app_args->conf;
    struct rs_conf_app const * conf_app = conf->apps + app_args->app_i;
    rs->conf = conf;

    // Allocate all IO pairs between this app and each worker
    RS_CACHE_ALIGNED_CALLOC(*app_args->app_io_pairs, conf->worker_c);
    rs->io_pairs = *app_args->app_io_pairs;
 
    RS_GUARD(rs_init_outbound_rings(rs));
    
    // The 1st app allocates all worker sleep states (as per the reasons
    // mentioned in spawn_app_and_worker_threads()).
    if (!app_args->app_i) {
        RS_CACHE_ALIGNED_CALLOC(*app_args->worker_sleep_states, conf->worker_c);
    }
    rs->worker_sleep_states = *app_args->worker_sleep_states;
    rs->worker_eventfds = app_args->worker_eventfds;

    // Don't allocate rs->wbuf yet, but do so instead during the 1st rs_w_...()
    // call, if any. This saves memory for apps that never call rs_w_...()
    // functions, and instead write/send everything "in one go" with rs_send().
    rs->wbuf_size = conf_app->wbuf_size;
    
    rs->ring_update_queue->size = conf_app->update_queue_size;
    RS_CALLOC(rs->ring_update_queue->queue, conf_app->update_queue_size);
    return RS_OK;
}

inline rs_ret rs_get_readers_upon_inbound_rings_init(
    struct rs_app_cb_args const * rs,
    uint8_t const * * * inbound_readers
) {
    RS_CALLOC(*inbound_readers, rs->conf->worker_c);
    // Only run once during app initialization, so just do a bit of sleep
    // polling instead of bothering with something more fancy like a futex.
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        for (uint8_t * reader = NULL;;) {
            RS_ATOMIC_LOAD_RELAXED_CASTED(&rs->io_pairs[i].inbound.reader,
                reader, (uint8_t *));
            if (reader) {
                (*inbound_readers)[i] = reader;
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
    struct rs_ring * ring = rs->outbound_rings + rs->inbound_worker_i;
    RS_GUARD(rs_prepare_ring_write(
        &rs->io_pairs[rs->inbound_worker_i].outbound, ring, 9));
    *ring->writer++ = RS_OUTBOUND_SINGLE;
    *((uint32_t *) ring->writer) = rs->inbound_peer_i;
    ring->writer += 4;
    *ring->writer++ = RS_WS_OPC_FIN_CLOSE;
    *ring->writer++ = 0x02; /* payload size == 2 */
    *((uint16_t *) ring->writer) = RS_HTON16(ws_close_code);
    ring->writer += 2;
    RS_GUARD(rs_enqueue_ring_update(rs->ring_update_queue, rs->io_pairs,
        rs->worker_sleep_states, rs->worker_eventfds, ring->writer,
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

// See the comment at the bottom of RS_APP() in ringsocket_app.h for explanation
#define RS_INLINE_PROTOTYPES_APP \
extern inline uint64_t rs_get_client_id(rs_t *); \
extern inline uint64_t rs_get_endpoint_id(rs_t *); \
extern inline struct rs_conf const * rs_get_conf(rs_t *); \
extern inline void * rs_get_app_data(rs_t *); \
extern inline void rs_w_p(rs_t *, void const *, size_t); \
extern inline void rs_w_str(rs_t *, char const *); \
extern inline void rs_w_uint8(rs_t *, uint8_t); \
extern inline void rs_w_uint16(rs_t *, uint16_t); \
extern inline void rs_w_uint32(rs_t *, uint32_t); \
extern inline void rs_w_uint64(rs_t *, uint32_t); \
extern inline void rs_w_uint16_hton(rs_t *, uint16_t); \
extern inline void rs_w_uint32_hton(rs_t *, uint32_t); \
extern inline void rs_w_uint64_hton(rs_t *, uint64_t); \
extern inline void rs_w_int8(rs_t *, int8_t); \
extern inline void rs_w_int16(rs_t *, int16_t); \
extern inline void rs_w_int32(rs_t *, int32_t); \
extern inline void rs_w_int64(rs_t *, int64_t); \
extern inline void rs_w_int16_hton(rs_t *, int16_t); \
extern inline void rs_w_int32_hton(rs_t *, int32_t); \
extern inline void rs_w_int64_hton(rs_t *, int64_t); \
extern inline void rs_to_single(rs_t *, enum rs_data_kind, uint64_t); \
extern inline void rs_to_multi(rs_t *, enum rs_data_kind, uint64_t const *, \
    size_t); \
extern inline void rs_to_cur(rs_t *, enum rs_data_kind); \
extern inline void rs_to_every(rs_t *, enum rs_data_kind); \
extern inline void rs_to_every_except_single(rs_t *, enum rs_data_kind, \
    uint64_t); \
extern inline void rs_to_every_except_multi(rs_t *, enum rs_data_kind, \
    uint64_t const *, size_t); \
extern inline void rs_to_every_except_cur(rs_t *, enum rs_data_kind); \
\
extern inline rs_ret rs_check_app_wsize(rs_t *, size_t); \
extern inline void rs_send(rs_t *, size_t, enum rs_outbound_kind, \
    uint32_t const *, uint32_t, enum rs_data_kind); \
extern inline rs_ret rs_init_outbound_rings(rs_t *); \
extern inline rs_ret rs_init_app_cb_args(struct rs_app_args *, rs_t *); \
extern inline rs_ret rs_get_readers_upon_inbound_rings_init( \
    struct rs_app_cb_args const *, uint8_t const * * *); \
extern inline rs_ret rs_get_cur_time_microsec(uint64_t *); \
extern inline rs_ret rs_close_peer(rs_t *, uint16_t); \
extern inline rs_ret rs_guard_cb(int); \
extern inline rs_ret rs_guard_peer_cb(rs_t *, int); \
extern inline rs_ret rs_guard_timer_cb(int64_t, uint64_t *interval_microsec)
