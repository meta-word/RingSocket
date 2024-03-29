// SPDX-License-Identifier: MIT
// Copyright © 2021 MetaWord Inc
// Copyright © 2019-2021 William Budd

#pragma once

#include <ringsocket_app.h>
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
//   |       [YOU ARE HERE]
//   \--> <ringsocket_helper.h> # Definitions of app helper functions (internal)
//                          |
//  <ringsocket.h> <--------/        # Definitions of app helper functions (API)
//    |
//    |
//    \-------------------------------> [ Any RingSocket app translation units ]

// #############################################################################
// # RingSocket app callback return value enums ################################

// The return value expected of all app callbacks except for the timer callback:
#ifdef __cplusplus
enum class rs_cb_ret {
#else
typedef enum {
#endif
    RS_CB_FATAL,
    RS_CB_OK
#ifdef __cplusplus
};
#else
} rs_cb_ret;
#endif

// The return value expected of the timer callback:
#ifdef __cplusplus
enum class rs_timer_ret {
#else
typedef enum {
#endif
    RS_TIMER_FATAL,
    RS_TIMER_MIN,  // Call me again after the configured mininum interval.
    RS_TIMER_HOLD, // Call me again with an interval unchanged from this time.
    RS_TIMER_INCR, // Add the configured increment to next call's interval.
    RS_TIMER_MAX,  // Call me again after the configured maximum interval.
    RS_TIMER_NEVER // Don't you dare ever calling me again.
#ifdef __cplusplus
};
#else
} rs_timer_ret;
#endif

// #############################################################################
// # Internal app callback helper functions (don't call these from app code) ###

static inline void rs_guard_cb_kind(
    char const * function_str,
    unsigned cb,
    unsigned allowed_cb_mask
) {
    if (!(cb & allowed_cb_mask)) {
        RS_LOG(LOG_ERR, "%s must not be called from an RS_%s() callback "
            "function: shutting down...", function_str,
            (char *[]){/* 0*/"",
                /* 1*/"INIT", /* 2*/"OPEN", /* 3*/"", /* 4*/"READ...",
                /* 5*/"",     /* 6*/"",     /* 7*/"", /* 8*/"CLOSE",
                /* 9*/"",     /*10*/"",     /*11*/"", /*12*/"",
                /*13*/"",     /*14*/"",     /*15*/"", /*16*/"TIMER..."
            }[RS_MIN(16, cb)]);
        RS_APP_FATAL;
    }
}

static inline rs_ret rs_check_app_wsize(
    rs_t * rs,
    size_t incr_size
) {
    if (!rs->wbuf) {
        RS_CASTED_CALLOC(rs->wbuf, uint8_t, rs->wbuf_size);
    }
    if (rs->wbuf_i + incr_size >= rs->wbuf_size) {
        rs->wbuf_size = rs->conf->realloc_multiplier * (rs->wbuf_i + incr_size);
        RS_CASTED_REALLOC(rs->wbuf, uint8_t, rs->wbuf_size);
    }
    return RS_OK;
}

static inline void rs_send(
    rs_t * rs,
    size_t worker_i,
    enum rs_outbound_kind outbound_kind,
    uint32_t const * recipients,
    uint32_t recipient_c,
    enum rs_data_kind data_kind
) {
    rs_guard_cb_kind(__func__, rs->cb,
        RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER);

    if (rs->wbuf_i > rs->conf->max_ws_msg_size) {
        RS_LOG(LOG_ERR, "Payload of size %zu exceeds the configured "
            "max_ws_msg_size %zu. Shutting down to avert further trouble...",
            rs->wbuf_i, rs->conf->max_ws_msg_size);
        RS_APP_FATAL;
    }

    size_t msg_size =
        1 + // uint8_t outbound_kind
        4 * (recipient_c > 1) + // if (recipient_c > 1): uint32_t recipient_c
        4 * recipient_c + // uint32_t array of recipients (peer_i elements)
        rs_get_wsframe_sc_size_from_payload_size(rs->wbuf_i);

    struct rs_ring_producer * prod = rs->outbound_producers + worker_i;
    RS_GUARD_APP(rs_produce_ring_msg(&rs->ring_pairs[worker_i]->outbound_ring,
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
    union rs_wsframe * frame = (union rs_wsframe *) prod->w;
    rs_clear_wsframe_bit_fields(frame);
    rs_set_wsframe_is_final(frame, true);
    rs_set_wsframe_opcode(frame, data_kind == RS_UTF8 ?
        RS_WSFRAME_OPC_TEXT : RS_WSFRAME_OPC_BIN);
    prod->w += rs_set_wsframe_sc_payload_and_get_frame_size(frame, rs->wbuf,
        rs->wbuf_i);

    RS_GUARD_APP(rs_enqueue_ring_update(rs->ring_queue, rs->ring_pairs,
        rs->worker_sleep_states, rs->worker_eventfds, prod->w, worker_i, true));
}

// #############################################################################
// # Internal RS_APP() helper functions ########################################

static inline rs_ret rs_init_outbound_producers(
    rs_t * rs
) {
    RS_CASTED_CALLOC(rs->outbound_producers, rs_ring_producer,
        rs->conf->worker_c);
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        struct rs_ring_producer * prod = rs->outbound_producers + i;
        prod->ring_size = rs->conf->outbound_ring_buf_size;
        RS_CASTED_CACHE_ALIGNED_CALLOC(prod->ring, uint8_t, prod->ring_size);
        prod->w = prod->ring;
#ifdef __cplusplus
        uintptr_t ring = reinterpret_cast<uintptr_t>(prod->ring);
#else
        atomic_uintptr_t ring = (atomic_uintptr_t) prod->ring;
#endif
        RS_ATOMIC_STORE_RELAXED(&rs->ring_pairs[i]->outbound_ring.w, ring);
        RS_ATOMIC_STORE_RELAXED(&rs->ring_pairs[i]->outbound_ring.r, ring);
    }
    // Inbound ring producers are initialized by worker threads in
    // init_inbound_producers() of rs_to_app.c
    return RS_OK;
}

static inline rs_ret rs_init_app_cb_args(
    struct rs_app_args * app_args,
    rs_t * rs
) {
    struct rs_conf const * conf = app_args->conf;
    struct rs_conf_app const * conf_app = conf->apps + app_args->app_i;
    rs->conf = conf;

    // Allocate all ring buffer pairs between this app and each worker
    RS_CASTED_CACHE_ALIGNED_CALLOC(*app_args->ring_pairs, rs_ring_pair,
        conf->worker_c);

    // *app_args->ring_pairs cannot be assigned directly to rs->ring_pairs,
    // because rs_enqueue_ring_update() and rs_flush_ring_updates() require one
    // extra layer of indirection to accomodate (and to be consistent with)
    // the format of worker threads' indirect ring pair arrays.
    RS_CASTED_CALLOC(rs->ring_pairs, rs_ring_pair *, conf->worker_c);
    for (size_t i = 0; i < conf->worker_c; i++) {
        rs->ring_pairs[i] = (*app_args->ring_pairs) + i;
    }
 
    RS_GUARD(rs_init_outbound_producers(rs));
    
    // The 1st app allocates all worker sleep states (as per the reasons
    // mentioned in spawn_app_and_worker_threads() in rs_main.c).
    if (!app_args->app_i) {
        RS_CASTED_CACHE_ALIGNED_CALLOC(*app_args->worker_sleep_states,
            rs_sleep_state, conf->worker_c);
    }
    // worker_sleep_states must not be assigned to rs->worker_sleep_states here;
    // because for apps other than the 1st, there is no guarantee yet that the
    // source array has been allocated already by the 1st app. Instead, do this
    // after rs_get_consumers_from_producers() has returned to ringsocket_app().
    
    rs->worker_eventfds = app_args->worker_eventfds;

    // Don't allocate rs->wbuf yet, but do so instead during the 1st rs_w_...()
    // call, if any. This saves memory for apps that never call rs_w_...()
    // functions, and instead write/send everything "in one go" with rs_w_to_...
    rs->wbuf_size = conf_app->wbuf_size;
    
    rs->ring_queue->size = conf_app->update_queue_size;
    RS_CASTED_CALLOC(rs->ring_queue->updates, rs_ring_update,
        conf_app->update_queue_size);
    return RS_OK;
}

static inline rs_ret rs_get_consumers_from_producers(
    rs_t * rs,
    struct rs_app_schedule * sched
) {
    // Among other things, the following 3 procedures have now been completed:
    // 1) outbound_ring.r has been initialized for all ring_pairs of this app.
    // 2) worker_sleep_states has been allocated (if this app's app_i == 0).
    // 3) The RS_INIT() app initialization callback function has returned RS_OK.
    //
    // That means now is the time to signal that fact to the startup thread
    // waiting in spawn_app_and_worker_threads() of rs_main.c, by setting this
    // app's thread sleep state to true: only once all app sleep states are true
    // will the startup thread deem it safe to start spawning worker threads.
    //
    // (Although this thread isn't actually going to sleep yet, this temporary
    // false positive is harmless, because the resultant worst case scenario is
    // merely that worker threads may syscall() a redundant FUTEX_WAKE_PRIVATE.)
    RS_ATOMIC_STORE_RELAXED(&sched->sleep_state->is_asleep, true);

    // In the same way that the startup thread waited for this app thread in
    // spawn_app_and_worker_threads(), this app thread should now wait for every
    // worker thread to initialize its paired inbound ring, and obtain the
    // corresponding "r" pointer.
    RS_CASTED_CALLOC(sched->inbound_consumers, rs_ring_consumer,
        rs->conf->worker_c);
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        for (;;) {
            // Simply wait for sched->inbound_consumers[i].r to become non-NULL,
            // which is safe because the ring_pairs array was zeroed in advance.
            RS_CASTED_ATOMIC_LOAD_RELAXED(&rs->ring_pairs[i]->inbound_ring.r,
                sched->inbound_consumers[i].r, (uint8_t const *));
            if (sched->inbound_consumers[i].r) {
                RS_LOG(LOG_DEBUG, "Received inbound_consumers[%zu].r: %p",
                    i, sched->inbound_consumers[i].r);
                break;
            }
            struct timespec timespec = { .tv_nsec = 1000000 };
            thrd_sleep(&timespec, NULL); // 1 ms
        }
    }
    // All inbound consumers are initialized now, which means all worker threads
    // have been spawned (and have completed their init_inbound_producers()),
    // which means sleep_state->is_asleep can be reset to false (until actual
    // sleep occurs in rs_wait_for_inbound_msg() below).
    RS_ATOMIC_STORE_RELAXED(&sched->sleep_state->is_asleep, false);
    return RS_OK;
}

#define RS_TIME_INFINITE UINT64_MAX
static inline rs_ret rs_wait_for_worker(
    struct rs_sleep_state * app_sleep_state,
    uint64_t timeout_microsec
) {
    struct timespec timespec = {
        .tv_sec = timeout_microsec / 1000000,
        .tv_nsec = 1000 * (timeout_microsec % 1000000)
    };
    struct timespec const * timeout = timeout_microsec == RS_TIME_INFINITE ?
        NULL : &timespec;
    if (syscall(SYS_futex, &app_sleep_state->is_asleep, FUTEX_WAIT_PRIVATE,
        true, timeout, NULL, 0) != -1 || errno == EAGAIN) {
        // May return immediately with errno == EAGAIN when a worker thread
        // already tried to wake this app thread up with rs_wake_up_app()
        // (which is possible because app_sleep_state->is_asleep was set to
        // true in advance of this function call). This is not a problem:
        // just try to do some more work.
        return RS_OK;
    }
    if (errno == ETIMEDOUT) {
        return RS_AGAIN; // Indicate that this function should be called again
        // to go back to sleep, because there was no worker thread activity.
    }
    RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful syscall(SYS_futex, &app_sleep_state->"
        "is_asleep, FUTEX_WAIT_PRIVATE, 1, timeout, NULL, 0)");
    return RS_FATAL;
}

static inline rs_ret rs_get_cur_time_microsec(
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

#ifdef __cplusplus
template<typename T>
#endif
static inline rs_ret rs_wait_for_inbound_msg(
    rs_t * rs,
    struct rs_app_schedule * sched,
    struct rs_inbound_msg * * imsg,
    size_t * payload_size,
#ifdef __cplusplus
    rs_timer_ret (T :: * timer_cb)(rs_t *),
    T & app_obj
#else
    rs_timer_ret (* timer_cb)(rs_t *)
#endif
) {
    size_t idle_c = 0;
    for (;;rs->inbound_worker_i++, rs->inbound_worker_i %= rs->conf->worker_c) {
        struct rs_ring_atomic * inbound_ring =
            &rs->ring_pairs[rs->inbound_worker_i]->inbound_ring;
        struct rs_ring_consumer * cons =
            sched->inbound_consumers + rs->inbound_worker_i;
        struct rs_consumer_msg * cmsg = rs_consume_ring_msg(inbound_ring, cons);
        if (cmsg) {
            *imsg = (struct rs_inbound_msg *) cmsg->msg;
            *payload_size = cmsg->size - sizeof(**imsg);
            // Reset the timer interval to its configured minimum, given that
            // this received message may be the start of some flurry of
            // activity. (This has no effect when timer_cb == NULL.)
            sched->interval_microsec = sched->interval_microsec_min;
            return RS_OK;
        }
        if (++idle_c == 2 * RS_MAX(4, rs->conf->worker_c)) {
            // Announce sleep prematurely in order to err on the side of caution
            // against deadlocking: in the likely event that this thread
            // actually goes to sleep soon, worker threads should become aware
            // of that fact no later than the moment sleep begins; and to
            // guarantee that in the face of memory reordering this leeway of
            // advance notice is necessary. The worst case scenario then merely
            // consists of workers potentially wasting a few clock cycles
            // calling FUTEX_WAKE on a still/already awake app during this
            // short window of time.
            RS_ATOMIC_STORE_RELAXED(&sched->sleep_state->is_asleep, true);
       
            // The 1st FUTEX_WAIT should timeout immediately to obtain an
            // opportunity to flush ring updates safely. I.e., the main purpose
            // of this call is to announce the remainder of ring buffer IO,
            // because doing so is made safe against CPU memory reordering
            // thanks to the presence of this syscall acting as a memory fence.
            // (And the purpose of said flushing is to not have unshared pending
            // IO left in the event that this thread does actually sleep soon.)
            switch (rs_wait_for_worker(sched->sleep_state, 0)) {
            case RS_OK: // Immediately awoken by a worker thread
                RS_ATOMIC_STORE_RELAXED(&sched->sleep_state->is_asleep, false);
                idle_c = 0;
                break;
            case RS_AGAIN: // Futex timed out as expected
                break;
            default:
                return RS_FATAL;
            }
            RS_GUARD(rs_flush_ring_updates(rs->ring_queue, rs->ring_pairs,
                rs->worker_sleep_states, rs->worker_eventfds,
                rs->conf->worker_c));
            continue;
        }
        if (idle_c < 4 * RS_MAX(4, rs->conf->worker_c)) {
            continue;
        }
        idle_c = 0;
        if (!timer_cb) {
            RS_LOG(LOG_DEBUG, "Going to sleep without setting a timeout...");
            RS_GUARD(rs_wait_for_worker(sched->sleep_state, RS_TIME_INFINITE));
            RS_ATOMIC_STORE_RELAXED(&sched->sleep_state->is_asleep, false);
            RS_LOG(LOG_DEBUG, "Awoken by a worker thread.");
            continue;
        }
        uint64_t timestamp_microsec = 0;
        RS_GUARD(rs_get_cur_time_microsec(&timestamp_microsec));
        if (timestamp_microsec <
            sched->timestamp_microsec + sched->interval_microsec) {
            switch (rs_wait_for_worker(sched->sleep_state,
                sched->timestamp_microsec + sched->interval_microsec -
                timestamp_microsec)) {
            case RS_OK: // A worker thread already woke this thread up.
                RS_LOG(LOG_DEBUG, "Awoken by a worker thread.");
                RS_ATOMIC_STORE_RELAXED(&sched->sleep_state->is_asleep, false);
                continue;
            case RS_AGAIN: // futex timed out: assume timing was accurate-ish
                //RS_LOG(LOG_DEBUG, "RS_TIMER_...(): Futex timed out after "
                //    "(supposedly) %f second(s)",
                //    .000001 * sched->interval_microsec);
                sched->timestamp_microsec += sched->interval_microsec;
                break;
            default:
                return RS_FATAL;
            }
        } else {
            sched->timestamp_microsec = timestamp_microsec;
        }
        RS_ATOMIC_STORE_RELAXED(&sched->sleep_state->is_asleep, false);

        rs->cb = RS_CB_TIMER;
#ifdef __cplusplus
        rs_timer_ret timer_ret = (app_obj.*timer_cb)(rs);
#else
        rs_timer_ret timer_ret = timer_cb(rs);
#endif

        switch (timer_ret) {
#ifdef __cplusplus
        case rs_timer_ret::RS_TIMER_FATAL:
#else
        case RS_TIMER_FATAL:
#endif
            RS_LOG(LOG_WARNING,
                "Shutting down: timer callback returned RS_TIMER_FATAL (-1).");
            return RS_FATAL;
#ifdef __cplusplus
        case rs_timer_ret::RS_TIMER_MIN:
#else
        case RS_TIMER_MIN:
#endif
            sched->interval_microsec = sched->interval_microsec_min;
            continue;
#ifdef __cplusplus
        case rs_timer_ret::RS_TIMER_HOLD:
#else
        case RS_TIMER_HOLD:
#endif
            continue;
 #ifdef __cplusplus
        case rs_timer_ret::RS_TIMER_INCR:
#else
        case RS_TIMER_INCR:
#endif
            sched->interval_microsec += sched->interval_microsec_incr;
            if (sched->interval_microsec <= sched->interval_microsec_max) {
                continue;
            } // fall through
#ifdef __cplusplus
        case rs_timer_ret::RS_TIMER_MAX:
#else
        case RS_TIMER_MAX:
#endif
            sched->interval_microsec = sched->interval_microsec_max;
            continue;
#ifdef __cplusplus
        case rs_timer_ret::RS_TIMER_NEVER:
#else
        case RS_TIMER_NEVER:
#endif
            RS_LOG(LOG_NOTICE, "Timer callback returned RS_TIMER_NEVER, "
                "which means it will not be called again.");
            timer_cb = NULL;
            continue;
        default:
            RS_LOG(LOG_ERR, "Shutting down: timer callback returned an "
                "invalid value: %" PRIu64, timer_ret);
            return RS_FATAL;
        }
    }
}

static inline rs_ret rs_ack_peer_open(
    rs_t * rs
) {
    struct rs_ring_producer * prod =
        rs->outbound_producers + rs->inbound_worker_i;
    RS_GUARD(rs_produce_ring_msg(
        &rs->ring_pairs[rs->inbound_worker_i]->outbound_ring, prod,
        rs->conf->realloc_multiplier, 5));
    *prod->w++ = RS_OUTBOUND_OPEN_ACK;
    *((uint32_t *) prod->w) = rs->inbound_peer_i;
    prod->w += 4;

    RS_GUARD(rs_enqueue_ring_update(rs->ring_queue, rs->ring_pairs,
        rs->worker_sleep_states, rs->worker_eventfds, prod->w,
        rs->inbound_worker_i, true));
    return RS_OK;
}

static inline rs_ret rs_close_peer(
    rs_t * rs,
    size_t worker_i,
    uint32_t recipient,
    uint16_t ws_close_code
) {
    struct rs_ring_producer * prod = rs->outbound_producers + worker_i;
    RS_GUARD(rs_produce_ring_msg(
        &rs->ring_pairs[rs->inbound_worker_i]->outbound_ring, prod,
        rs->conf->realloc_multiplier, 9));
    *prod->w++ = RS_OUTBOUND_SINGLE;
    *((uint32_t *) prod->w) = recipient;
    prod->w += 4;

    union rs_wsframe * frame = (union rs_wsframe *) prod->w;
    rs_clear_wsframe_bit_fields(frame);
    rs_set_wsframe_is_final(frame, true);
    rs_set_wsframe_opcode(frame, RS_WSFRAME_OPC_CLOSE);

    uint16_t net_bytes = 0;
    RS_W_HTON16(&net_bytes, ws_close_code);
    prod->w += rs_set_wsframe_sc_payload_and_get_frame_size(frame,
        &net_bytes, sizeof(net_bytes));
 
    RS_GUARD(rs_enqueue_ring_update(rs->ring_queue, rs->ring_pairs,
        rs->worker_sleep_states, rs->worker_eventfds, prod->w, worker_i, true));
    return RS_OK;
}

static inline rs_ret rs_guard_cb(
    rs_t * rs,
    rs_cb_ret cb_ret
) {
    switch (cb_ret) {
#ifdef __cplusplus
    case rs_cb_ret::RS_CB_FATAL:
#else
    case RS_CB_FATAL:
#endif
        RS_LOG(LOG_WARNING,
            "Shutting down: init callback returned RS_CB_FATAL.");
        break;
#ifdef __cplusplus
    case rs_cb_ret::RS_CB_OK:
#else
    case RS_CB_OK:
#endif
        return RS_OK;
    default:
        RS_LOG(LOG_ERR,
            "Shutting down: init callback returned an invalid value: %d. "
            "Recognized values are RS_CB_OK and RS_CB_FATAL.", cb_ret);
    }
    return RS_FATAL;
}
