// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include "rs_event.h" // handle_peer_events()
#include "rs_ring.h"
#include "rs_tcp.h" // write_tcp()
#include "rs_tls.h" // write_tls()
#include "rs_util.h" // move_left()

thread_local static struct rs_thread_io_pairs * * io_pairs = NULL;
thread_local static struct rs_ring * inbound_rings = NULL;
thread_local static uint8_t * * outbound_readers = NULL;
thread_local static struct rs_ring_update_queue ring_update_queue = {0};
thread_local static struct rs_thread_sleep_state * worker_sleep_state = NULL;
thread_local static struct rs_thread_sleep_state * app_sleep_states = NULL;

thread_local static struct rs_wref * wrefs = NULL;
thread_local static size_t wrefs_elem_c = 0;
thread_local static size_t newest_wref_i = 0;
thread_local static size_t oldest_wref_i = 0;
thread_local static size_t * oldest_wref_i_by_app = NULL;

static rs_ret set_worker_io_pairs(
    struct rs_thread_io_pairs * * all_io_pairs,
    size_t app_c,
    size_t worker_i
) {
    RS_CALLOC(io_pairs, app_c);
    // Each element of all_io_pairs is an array of IO pairs allocated by a
    // separate app. For each such array, the element with an index
    // corresponding to the worker index of this thread is the pointer to the IO
    // pair between that app and this worker, so copy only the elements at that
    // index to io_pairs.
    for (size_t i = 0; i < app_c; i++) {
        io_pairs[i] = all_io_pairs[i] + worker_i;
    }
    return RS_OK;
}

static rs_ret init_inbound_rings(
    struct rs_conf const * conf
) {
    RS_CALLOC(inbound_rings, conf->app_c);
    for (size_t i = 0; i < conf->app_c; i++) {
        struct rs_ring * ring = inbound_rings + i;
        ring->buf_size = conf->inbound_ring_buf_size;
        RS_CACHE_ALIGNED_CALLOC(ring->buf, ring->buf_size);
        ring->writer = ring->buf;
        ring->alloc_multiplier = conf->realloc_multiplier;
        RS_ATOMIC_STORE_RELAXED(&io_pairs[i]->inbound.writer,
            (atomic_uintptr_t) ring->buf);
        RS_ATOMIC_STORE_RELAXED(&io_pairs[i]->inbound.reader,
            (atomic_uintptr_t) ring->buf);
    }
    // Outbound rings are initialized by app threads through
    // rs_init_outbound_rings() of ringsocket_app_helper.h
    return RS_OK;
}

static rs_ret get_outbound_readers(
    size_t app_c
) {
    RS_CALLOC(outbound_readers, app_c);
    // Obtain the outbound rings' reader pointers as atomically stored by the
    // corresponding apps (and waited for in spawn_app_and_worker_threads()).
    for (size_t i = 0; i < app_c; i++) {
        RS_ATOMIC_LOAD_RELAXED_CASTED(&io_pairs[i]->outbound.reader,
            outbound_readers[i], (uint8_t *));
    }
    return RS_OK;
}

rs_ret init_worker_ring_state(
    struct rs_conf const * conf,
    struct rs_thread_io_pairs * * all_io_pairs,
    struct rs_thread_sleep_state * _app_sleep_states,
    struct rs_thread_sleep_state * _worker_sleep_state,
    size_t worker_i
) {
    RS_GUARD(set_worker_io_pairs(all_io_pairs, conf->app_c, worker_i));
    RS_GUARD(init_inbound_rings(conf));
    RS_GUARD(get_outbound_readers(conf->app_c));

    ring_update_queue.size = conf->update_queue_size;
    RS_CALLOC(ring_update_queue.queue, ring_update_queue.size);
    worker_sleep_state = _worker_sleep_state;
    app_sleep_states = _app_sleep_states;

    wrefs_elem_c = conf->wrefs_elem_c;
    RS_CALLOC(wrefs, wrefs_elem_c);
    RS_CALLOC(oldest_wref_i_by_app, conf->app_c);
    return RS_OK;
}

void announce_worker_sleep(
    void
) {
    RS_ATOMIC_STORE_RELAXED(&worker_sleep_state->is_asleep, true);
}

static rs_ret enqueue_ring_update(
    uint8_t * new_ring_position,
    size_t app_thread_i,
    bool is_write
) {
    return rs_enqueue_ring_update(&ring_update_queue, *io_pairs,
        app_sleep_states, NULL, new_ring_position, app_thread_i, is_write);
}

rs_ret flush_ring_updates(
    size_t app_c
) {
    return rs_flush_ring_updates(&ring_update_queue, *io_pairs,
        app_sleep_states, NULL, app_c);
}

static rs_ret send_msg_to_app(
    struct rs_conf const * conf,
    union rs_peer const * peer,
    uint32_t peer_i,
    uint8_t const * msg,
    uint32_t msg_size,
    enum rs_inbound_kind kind
) {
    struct rs_thread_pair * pair = &io_pairs[peer->app_i]->inbound;
    struct rs_ring * ring = inbound_rings + peer->app_i;
    struct rs_inbound_msg_header header = {
        .peer_i = peer_i,
        .socket_fd = peer->socket_fd,
        .endpoint_id = conf->apps[peer->app_i].endpoints[peer->endpoint_i]
            .endpoint_id,
        .is_utf8 = peer->ws.rmsg_is_utf8,
        .kind = kind
    };
    RS_GUARD(rs_prepare_ring_write(pair, ring, sizeof(header) + msg_size));
    memcpy(ring->writer, &header, sizeof(header));
    ring->writer += sizeof(header);
    if (msg_size) {
        memcpy(ring->writer, msg, msg_size);
        ring->writer += msg_size;
    }
    enqueue_ring_update(ring->writer, peer->app_i, true);
    return RS_OK;
}

rs_ret send_open_to_app(
    struct rs_conf const * conf,
    union rs_peer const * peer,
    uint32_t peer_i
) {
    return conf->apps[peer->app_i].wants_open_notification ?
        send_msg_to_app(conf, peer, peer_i, NULL, 0, RS_INBOUND_OPEN) : RS_OK;
}

rs_ret send_read_to_app(
    struct rs_conf const * conf,
    union rs_peer const * peer,
    uint32_t peer_i,
    uint8_t const * msg,
    uint32_t msg_size
) {
    return send_msg_to_app(conf, peer, peer_i, msg, msg_size,
        RS_INBOUND_READ);
}

rs_ret send_close_to_app(
    struct rs_conf const * conf,
    union rs_peer const * peer,
    uint32_t peer_i
) {
    return conf->apps[peer->app_i].wants_close_notification ?
        send_msg_to_app(conf, peer, peer_i, NULL, 0, RS_INBOUND_CLOSE) : RS_OK;
}

static rs_ret send_newest_wmsg(
    struct rs_conf const * conf,
    union rs_peer * peer,
    uint8_t const * msg,
    size_t msg_size
) {
    if (peer->layer != RS_LAYER_WEBSOCKET ||
        peer->mortality != RS_MORTALITY_LIVE) {
        return RS_OK;
    }
    if (peer->continuation != RS_CONT_NONE) {
        if (!peer->ws.wref_c++) {
            peer->ws.wref_i = newest_wref_i;
            wrefs[newest_wref_i].remaining_recipient_c++;
        }
        return RS_OK;
    }
    RS_LOG(LOG_DEBUG, "Sending %zu bytes outbound", msg_size);
    switch (peer->is_encrypted ?
        write_tls(peer, msg, msg_size) :
        write_tcp(peer, msg, msg_size)
    ) {
    case RS_OK:
        if (*msg == 0x88) { // Check if this msg was a WebSocket Close Message
            peer->mortality = RS_MORTALITY_SHUTDOWN_WRITE;
            // Call handle_peer_events() with MORTALITY_SHUTDOWN_WRITE (but
            // without any events) to try to perform any shutdown procedures
            // that can be done right away layer by layer until the occurence
            // of RS_AGAIN or completion.
            return handle_peer_events(conf, NULL, peer, 0, 0);
        }
        return RS_OK;
    case RS_AGAIN:
        peer->ws.wref_c = 1;
        peer->ws.wref_i = newest_wref_i;
        wrefs[newest_wref_i].remaining_recipient_c++;
        return RS_OK;
    case RS_CLOSE_PEER:
        peer->mortality = RS_MORTALITY_DEAD;
        return RS_OK;
    default:
        return RS_FATAL;
    }
}

rs_ret receive_from_app(
    struct rs_conf const * conf,
    union rs_peer * peers,
    size_t peers_elem_c
) {
    for (size_t app_i = 0; app_i < conf->app_c; app_i++) {
        struct rs_thread_pair * pair = &io_pairs[app_i]->outbound;
        uint8_t * reader = outbound_readers[app_i];
        struct rs_ring_msg *ring_msg = NULL;
        while ((ring_msg = rs_get_ring_msg(pair, reader))) {
            size_t head_size = 1;
            uint32_t peer_c = 0;
            uint32_t * peer_i = (uint32_t *) (ring_msg->msg + 1);
            switch (*ring_msg->msg) {
            case RS_OUTBOUND_SINGLE:
                RS_LOG(LOG_DEBUG, "Sending single outbound msg to peer_i: %u",
                    *peer_i);
                head_size += 4;
                RS_GUARD(send_newest_wmsg(conf, peers + *peer_i,
                    ring_msg->msg + head_size, ring_msg->size - head_size));
                break;
            case RS_OUTBOUND_ARRAY:
                peer_c = *peer_i++;
                head_size += 4 + 4 * peer_c;
                for (size_t i = 0; i < peer_c; i++) {
                    RS_GUARD(send_newest_wmsg(conf, peers + peer_i[i],
                    ring_msg->msg + head_size, ring_msg->size - head_size));
                }
                break;
            case RS_OUTBOUND_EVERY:
                for (size_t p_i = 0; p_i < peers_elem_c; p_i++) {
                    RS_GUARD(send_newest_wmsg(conf, peers + p_i,
                        ring_msg->msg + head_size, ring_msg->size - head_size));
                }
                break;
            case RS_OUTBOUND_EVERY_EXCEPT_SINGLE:
                head_size += 4;
                for (size_t p_i = 0; p_i < peers_elem_c; p_i++) {
                    if (p_i != *peer_i) {
                        RS_GUARD(send_newest_wmsg(conf, peers + p_i,
                            ring_msg->msg + head_size,
                            ring_msg->size - head_size));
                    }
                }
                break;
            case RS_OUTBOUND_EVERY_EXCEPT_ARRAY: default:
                peer_c = *peer_i++;
                head_size += 4 + 4 * peer_c;
                for (size_t p_i = 0; p_i < peers_elem_c; p_i++) {
                    for (size_t i = 0; peer_i[i] != p_i; i++) {
                        if (i == peer_c) {
                            RS_GUARD(send_newest_wmsg(conf, peers + p_i,
                                ring_msg->msg + head_size,
                                ring_msg->size - head_size));
                            break;
                        }
                    }
                }
            }
            outbound_readers[app_i] = reader =
                (uint8_t *) ring_msg->msg + ring_msg->size;
            if (wrefs[newest_wref_i].remaining_recipient_c) {
                wrefs[newest_wref_i].ring_msg = ring_msg;
                wrefs[newest_wref_i].head_size = head_size;
                wrefs[newest_wref_i++].app_i = app_i;
                newest_wref_i %= wrefs_elem_c;
                if (newest_wref_i == oldest_wref_i) {
                    size_t new_elem_c = conf->realloc_multiplier * wrefs_elem_c;
                    RS_REALLOC(wrefs, wrefs_elem_c);
                    size_t added_ref_c = new_elem_c - wrefs_elem_c;
                    if (added_ref_c > newest_wref_i) {
                        memcpy(wrefs + wrefs_elem_c, wrefs,    newest_wref_i);
                        newest_wref_i += wrefs_elem_c;
                        for (union rs_peer * p = peers;
                            p < peers + peers_elem_c; p++) {
                            if (p->ws.wref_c && p->ws.wref_i < newest_wref_i) {
                                p->ws.wref_i += wrefs_elem_c;
                            }
                        }
                    } else {
                        memcpy(wrefs + wrefs_elem_c, wrefs,    added_ref_c);
                        move_left(wrefs, added_ref_c, newest_wref_i);
                        newest_wref_i -= added_ref_c;
                        for (union rs_peer * p = peers;
                            p < peers + peers_elem_c; p++) {
                            if (p->ws.wref_c) {
                                if (p->ws.wref_i < added_ref_c) {
                                    p->ws.wref_i += wrefs_elem_c;
                                } else if (p->ws.wref_i <
                                    newest_wref_i) {
                                    p->ws.wref_i -= added_ref_c;
                                }
                            }
                        }
                    }
                    wrefs_elem_c = new_elem_c;
                }
            } else if (newest_wref_i == oldest_wref_i_by_app[app_i]) {
                enqueue_ring_update(reader, app_i, false);
            }
        }
    }
    return RS_OK;
}

static void get_next_pending_write_reference(
    uint32_t target_peer_i,
    struct rs_wref * * wref
) {
    for (;;) {
        if (++(*wref) >= wrefs + wrefs_elem_c) {
            *wref = wrefs;
        }
        if (!(*wref)->ring_msg) {
            continue;
        }
        uint8_t const * msg = (*wref)->ring_msg->msg;
        uint32_t const * peer_i = (uint32_t const *) (msg + 1);
        uint32_t peer_c = 0;
        switch (*msg) {
        case RS_OUTBOUND_SINGLE:
            if (*peer_i == target_peer_i) {
                return;
            }
            continue;
        case RS_OUTBOUND_ARRAY:
            peer_c = *peer_i++;
            for (size_t i = 0; i < peer_c; i++) {
                if (peer_i[i] == target_peer_i) {
                    return;
                }
            }
            continue;
        case RS_OUTBOUND_EVERY:
            return;
        case RS_OUTBOUND_EVERY_EXCEPT_SINGLE:
            if (*peer_i != target_peer_i) {
                return;
            }
            continue;
        case RS_OUTBOUND_EVERY_EXCEPT_ARRAY: default:
            peer_c = *peer_i++;
            for (size_t i = 0; *peer_i != target_peer_i; i++) {
                if (i == peer_c) {
                    return;
                }
            }
        }
    }
}

static void decrement_pending_write_reference_count(
    struct rs_wref * wref
) {
    size_t wref_i = wref - wrefs;
    if (--wref->remaining_recipient_c) {
        return;
    }
    size_t app_i = wref->app_i;
    memset(wref, 0, sizeof(struct rs_wref));
    if (wref_i != oldest_wref_i_by_app[app_i]) {
        return;
    }
    if (wref_i == newest_wref_i) {
        enqueue_ring_update(outbound_readers[app_i], app_i, false);
        return;
    }
    size_t next_oldest_wref_i = wref_i + 1;
    while (wrefs[next_oldest_wref_i].app_i != app_i ||
        !wrefs[next_oldest_wref_i].remaining_recipient_c) {
        next_oldest_wref_i++;
    }
    oldest_wref_i_by_app[app_i] = next_oldest_wref_i;
    if (oldest_wref_i == wref_i) {
        oldest_wref_i = next_oldest_wref_i;
    }
    enqueue_ring_update((uint8_t *) wrefs[next_oldest_wref_i].ring_msg, app_i,
        false);
}

rs_ret send_pending_write_references(
    struct rs_conf const * conf,
    union rs_peer * peer,
    uint32_t peer_i
) {
    if (!peer->ws.wref_c) {
        return RS_OK;
    }
    for (struct rs_wref * wref = wrefs + peer->ws.wref_i;;) {
        uint8_t const * ws = wref->ring_msg->msg + wref->head_size;
        switch (peer->is_encrypted ?
            write_tls(peer, ws, wref->ring_msg->size - wref->head_size) :
            write_tls(peer, ws, wref->ring_msg->size - wref->head_size)) {
        case RS_OK:
            if (*ws != 0x88) {
                break;
            }
            // This message was a WebSocket Close message.
            peer->mortality = RS_MORTALITY_SHUTDOWN_WRITE;
            // Set CONT_NONE to indicate that the ws close msg was already sent.
            peer->continuation = RS_CONT_NONE;
            peer->ws.wref_i = wref - wrefs;
            remove_pending_write_references(peer, peer_i);
            // Call handle_peer_events() with MORTALITY_SHUTDOWN_WRITE (but
            // without any events) to try to perform any shutdown procedures
            // that can be done right away layer by layer until the occurence
            // of RS_AGAIN or completion.
            return handle_peer_events(conf, NULL, peer, 0, 0);
        case RS_AGAIN:
            peer->ws.wref_i = wref - wrefs;
            return RS_AGAIN;
        case RS_CLOSE_PEER:
            peer->ws.wref_i = wref - wrefs;
            if (*ws != 0x88) {
                // Only notify the app of peer closure if the message the error
                // occurred on wasn't itself a close message sent by the app.
                send_close_to_app(conf, peer, peer_i);
            }
            return RS_CLOSE_PEER;
        default:
            return RS_FATAL;
        }
        decrement_pending_write_reference_count(wref);
        if (!--peer->ws.wref_c) {
            return RS_OK;
        }
        get_next_pending_write_reference(peer_i, &wref);
    }
}

void remove_pending_write_references(
    union rs_peer * peer,
    uint32_t peer_i
) {
    if (!peer->ws.wref_c) {
        return;
    }
    for (struct rs_wref * wref = wrefs + peer->ws.wref_i;;) {
        decrement_pending_write_reference_count(wref);
        if (!--peer->ws.wref_c) {
            return;
        }
        get_next_pending_write_reference(peer_i, &wref);
    }
}
