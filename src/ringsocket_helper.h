// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#define _POSIX_C_SOURCE 201112L // CLOCK_MONOTONIC_COARSE

#define RS_INCLUDE_QUEUE_FUNCTIONS // Include function defs @ ringsocket_queue.h
#define RS_INCLUDE_CONSUME_RING_MSG // rs_consume_ring_msg() @ ringsocket_ring.h
#define RS_INCLUDE_PRODUCE_RING_MSG // rs_produce_ring_msg() @ ringsocket_ring.h

#include <ringsocket_app.h>
// <ringsocket_variadic.h>           # Arity-based macro expansion helper macros
//   |
//   \---> <ringsocket_api.h>   # RingSocket API other than app helper functions
//                        |
// <ringsocket_conf.h> <--/   # Definition of struct rs_conf and its descendents
//   |
//   \---> <ringsocket_ring.h> # Single producer single consumer ring buffer API
//                         |
// <ringsocket_queue.h> <--/      # Ring buffer update queuing and thread waking
//   |
//   \-----> <ringsocket_app.h>   # Definition of RS_APP() and descendent macros
//                          |
//    [YOU ARE HERE]        |
// <ringsocket_helper.h> <--/   # Definitions of app helper functions (internal)
//   |
//   \--> <ringsocket.h>             # Definitions of app helper functions (API)

#include <inttypes.h> // PRI print format of stdint.h types
#include <time.h> // clock_gettime()

// #############################################################################
// # Internal app helpers (don't call these functions directly from app code) ##

static rs_ret rs_check_app_wsize(
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

static void rs_send(
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
    RS_GUARD_APP(rs_produce_ring_msg(&rs->ring_pairs[worker_i].outbound_ring,
        prod, rs->conf->realloc_multiplier, msg_size));
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

static rs_ret rs_init_outbound_producers(
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

static rs_ret rs_init_app_cb_args(
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

static rs_ret rs_get_inbound_consumers_from_producers(
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

static rs_ret rs_get_cur_time_microsec(
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

static rs_ret rs_close_peer(
    rs_t * rs,
    uint16_t ws_close_code
) {
    struct rs_ring_producer * prod =
        rs->outbound_producers + rs->inbound_worker_i;
    RS_GUARD(rs_produce_ring_msg(
        &rs->ring_pairs[rs->inbound_worker_i].outbound_ring, prod,
        rs->conf->realloc_multiplier, 9));
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

static rs_ret rs_guard_cb(
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

static rs_ret rs_guard_peer_cb(
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

static rs_ret rs_guard_timer_cb(
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
