// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include "rs_event.h" // handle_peer_events()
#include "rs_from_app.h"
#include "rs_tcp.h" // write_tcp()
#include "rs_tls.h" // write_tls()
#include "rs_to_app.h" // send_close_to_app()
#include "rs_util.h" // move_left()

// "owref" is an abbreviation of "Outbound Write REFerence"

rs_ret get_outbound_readers(
    struct rs_worker * worker
) {
    RS_CALLOC(worker->outbound_readers, worker->conf->app_c);
    // Obtain the outbound rings' reader pointers as atomically stored by the
    // corresponding apps (and waited for in spawn_app_and_worker_threads()).
    for (size_t i = 0; i < worker->conf->app_c; i++) {
        RS_ATOMIC_LOAD_RELAXED_CASTED(&worker->io_pairs[i]->outbound.reader,
            worker->outbound_readers[i], (uint8_t *));
    }
    return RS_OK;
}

rs_ret init_owrefs(
    struct rs_worker * worker
) {
    // Set the initial owrefs_elem_c. This number may grow through reallocation.
    worker->owrefs_elem_c = worker->conf->owrefs_elem_c;
    RS_CALLOC(worker->owrefs, worker->owrefs_elem_c);
    RS_CALLOC(worker->oldest_owref_i_by_app, worker->conf->app_c);
    return RS_OK;
}

static rs_ret send_newest_ring_msg(
    struct rs_worker * worker,
    size_t * remaining_recipient_c,
    uint32_t peer_i,
    uint8_t const * msg,
    size_t msg_size
) {
    union rs_peer * peer = worker->peers + peer_i;
    if (peer->layer != RS_LAYER_WEBSOCKET ||
        peer->mortality != RS_MORTALITY_LIVE) {
        //RS_LOG(LOG_DEBUG, "Not sending newest %zu byte message from app to "
        //    "peer %" PRIu32 ", because it's not live on the WebSocket layer.",
        //    msg_size, peer_i);
        return RS_OK;
    }
    if (peer->continuation != RS_CONT_NONE) {
        if (peer->ws.owref_c == UINT8_MAX) {
            RS_LOG(LOG_WARNING, "More outbound write references are pending "
                "for peer %s than the maximum supported number of 255: "
                "shutting the peer down", get_peer_str(peer));
            goto close_peer;
        }
        if (!peer->ws.owref_c++) {
            peer->ws.owref_i = worker->newest_owref_i;
        }
        (*remaining_recipient_c)++;
        RS_LOG(LOG_DEBUG, "Not sending newest %zu byte message from app to "
            "peer %" PRIu32 " yet, because its continuation state is "
            "RS_CONT_%sING (resultant peer->ws.owref_c: %" PRIu8 ").",
            msg_size, peer_i, peer->continuation == RS_CONT_PARSING ?
            "PARS" : "SEND", peer->ws.owref_c);
        return RS_OK;
    }
    switch (peer->is_encrypted ?
        write_tls(peer, msg, msg_size) :
        write_tcp(peer, msg, msg_size)
    ) {
    case RS_OK:
        if (*msg == RS_WS_OPC_FIN_CLOSE) { // Check if msg is close notification
            RS_LOG(LOG_DEBUG, "Successfully sent newest %zu byte ws%s close "
                "message from app to peer %" PRIu32 ".", msg_size,
                peer->is_encrypted ? "s" : "", peer_i);
            peer->mortality = RS_MORTALITY_SHUTDOWN_WRITE;
            // Call handle_peer_events() with MORTALITY_SHUTDOWN_WRITE (but
            // without any events) to try to perform any shutdown procedures
            // that can be done right away layer by layer until the occurence
            // of RS_AGAIN or completion.
            return handle_peer_events(worker, peer_i, 0);
        }
        RS_LOG(LOG_DEBUG, "Successfully sent newest %zu byte ws%s %s message "
            "from app to peer %" PRIu32 ".", msg_size,
            peer->is_encrypted ? "s" : "",
            *msg == RS_WS_OPC_FIN_BIN ? "RS_BIN" : "RS_UTF8", peer_i);
        return RS_OK;
    case RS_AGAIN:
        RS_LOG(LOG_DEBUG, "Attempt to send newest %zu byte ws%s message from "
            "app to peer %" PRIu32 " was unsuccessfull due to RS_AGAIN.",
            msg_size, peer->is_encrypted ? "s" : "", peer_i);
        peer->continuation = RS_CONT_SENDING;
        peer->ws.owref_c = 1;
        peer->ws.owref_i = worker->newest_owref_i;
        (*remaining_recipient_c)++;
        return RS_OK;
    case RS_CLOSE_PEER:
        RS_LOG(LOG_WARNING, "Attempt to send newest %zu byte ws%s message from "
            "app to peer %" PRIu32 " was unsuccessfull due to RS_CLOSE_PEER.",
            msg_size, peer->is_encrypted ? "s" : "", peer_i);
        close_peer:
        if (*msg != RS_WS_OPC_FIN_CLOSE) {
            // Only notify the app of peer closure if the message the error
            // occurred on wasn't itself a close message sent by the app.
            RS_GUARD(send_close_to_app(worker, peer, peer_i));
        }
        peer->mortality = RS_MORTALITY_DEAD;
        // Call handle_peer_events() with MORTALITY_DEAD (but without any
        // events) to abort this peer and free up its resources, layer by layer.
        return handle_peer_events(worker, peer_i, 0);
    default:
        return RS_FATAL;
    }
}

static rs_ret reallocate_owrefs(
    struct rs_worker * worker
) {
    // Reallocate larger worker->owrefs array, and move data around as needed.
    size_t new_elem_c =
        worker->conf->realloc_multiplier * worker->owrefs_elem_c;
    RS_REALLOC(worker->owrefs, new_elem_c);
    RS_LOG(LOG_NOTICE, "Reallocated worker->owrefs with a "
        "worker->owrefs_elem_c increase from %zu to %zu.",
        worker->owrefs_elem_c, new_elem_c);
    size_t added_ref_c = new_elem_c - worker->owrefs_elem_c;
    if (added_ref_c > worker->newest_owref_i) {
        // added_ref_c is large enough to accomodate a "full de-wrap":
        // move the wrapped around owref elements at the start of the owrefs
        // array to the index equal to the array's old length.
        memcpy(worker->owrefs + worker->owrefs_elem_c, worker->owrefs,
            worker->newest_owref_i * sizeof(struct rs_owref));
        worker->newest_owref_i += worker->owrefs_elem_c;
        // Update every peer for which ws.owref_i corresponds to a moved index.
        for (union rs_peer * p = worker->peers;
            p <= worker->peers + worker->highest_peer_i; p++) {
            if (p->ws.owref_c && p->ws.owref_i < worker->newest_owref_i) {
                p->ws.owref_i += worker->owrefs_elem_c;
            }
        }
        RS_LOG(LOG_DEBUG, "Full owrefs dewrap completed.");
    } else {
        // added_ref_c is only large enough to accomodate a "partial de-wrap".
        memcpy(worker->owrefs + worker->owrefs_elem_c, worker->owrefs,
            added_ref_c * sizeof(struct rs_owref));
        // Move remaining elements to the start of the array to recreate the
        // "wrapping effect".
        move_left(worker->owrefs, added_ref_c, worker->newest_owref_i);
        worker->newest_owref_i -= added_ref_c;
        // Update every peer for which ws.owref_i corresponds to a moved index.
        for (union rs_peer * p = worker->peers;
            p <= worker->peers + worker->highest_peer_i; p++) {
            if (p->ws.owref_c) {
                if (p->ws.owref_i < added_ref_c) {
                    p->ws.owref_i += worker->owrefs_elem_c;
                } else if (p->ws.owref_i < worker->newest_owref_i) {
                    p->ws.owref_i -= added_ref_c;
                }
            }
        }
        RS_LOG(LOG_DEBUG, "Partial owrefs dewrap and wrap move completed.");
    }
    worker->owrefs_elem_c = new_elem_c;
    return RS_OK;
}

rs_ret receive_from_app(
    struct rs_worker * worker
) {
    for (size_t app_i = 0; app_i < worker->conf->app_c; app_i++) {
        struct rs_thread_pair * pair = &worker->io_pairs[app_i]->outbound;
        uint8_t * reader = worker->outbound_readers[app_i];
        struct rs_ring_msg * ring_msg = NULL;
        while ((ring_msg = rs_get_ring_msg(pair, reader))) {
            size_t remaining_recipient_c = 0;
            size_t head_size = 1;
            uint32_t peer_c = 0;
            uint32_t * peer_i = (uint32_t *) (ring_msg->msg + 1);
            switch (*ring_msg->msg) {
            case RS_OUTBOUND_SINGLE:
                head_size += 4;
                RS_GUARD(send_newest_ring_msg(worker, &remaining_recipient_c,
                    *peer_i, ring_msg->msg + head_size,
                    ring_msg->size - head_size));
                break;
            case RS_OUTBOUND_ARRAY:
                peer_c = *peer_i++;
                head_size += 4 + 4 * peer_c;
                for (size_t i = 0; i < peer_c; i++) {
                    RS_GUARD(send_newest_ring_msg(worker,
                        &remaining_recipient_c, peer_i[i],
                        ring_msg->msg + head_size, ring_msg->size - head_size));
                }
                break;
            case RS_OUTBOUND_EVERY:
                for (size_t p_i = 0; p_i <= worker->highest_peer_i; p_i++) {
                    RS_GUARD(send_newest_ring_msg(worker,
                        &remaining_recipient_c, p_i, ring_msg->msg + head_size,
                        ring_msg->size - head_size));
                }
                break;
            case RS_OUTBOUND_EVERY_EXCEPT_SINGLE:
                head_size += 4;
                for (size_t p_i = 0; p_i <= worker->highest_peer_i; p_i++) {
                    if (p_i != *peer_i) {
                        RS_GUARD(send_newest_ring_msg(worker,
                            &remaining_recipient_c, p_i,
                            ring_msg->msg + head_size,
                            ring_msg->size - head_size));
                    }
                }
                break;
            case RS_OUTBOUND_EVERY_EXCEPT_ARRAY: default:
                peer_c = *peer_i++;
                head_size += 4 + 4 * peer_c;
                for (size_t p_i = 0; p_i <= worker->highest_peer_i; p_i++) {
                    for (size_t i = 0; peer_i[i] != p_i; i++) {
                        if (i == peer_c) {
                            RS_GUARD(send_newest_ring_msg(worker,
                                &remaining_recipient_c, p_i,
                                ring_msg->msg + head_size,
                                ring_msg->size - head_size));
                            break;
                        }
                    }
                }
            }
            worker->outbound_readers[app_i] = reader =
                (uint8_t *) ring_msg->msg + ring_msg->size;
            if (remaining_recipient_c) {
                struct rs_owref * new = worker->owrefs + worker->newest_owref_i;
                RS_LOG(LOG_DEBUG, "worker->owrefs[%zu].ring_msg == %p, "
                    ".remaining_recipient_c == %" PRIu32 " , .head_size == %"
                    PRIu16 ", .app_i == %" PRIu16 ".", worker->newest_owref_i,
                    ring_msg, remaining_recipient_c, head_size, app_i);
                new->remaining_recipient_c = remaining_recipient_c;
                new->ring_msg = ring_msg;
                new->head_size = head_size;
                new->app_i = app_i;
                // Increment to get the next writable owref element,
                // but wrap around if needed.
                worker->newest_owref_i++;
                worker->newest_owref_i %= worker->owrefs_elem_c;
                for (size_t i = 0; i < worker->conf->app_c; i++) {
                    if (worker->oldest_owref_i_by_app[i] ==
                        worker->newest_owref_i) {
                        // The worker->owrefs array is full. (Traffic jam?)
                        reallocate_owrefs(worker);
                        break;
                    }
                }
            } else if (worker->newest_owref_i ==
                worker->oldest_owref_i_by_app[app_i]) {
                enqueue_ring_update(worker, reader, app_i, false);
                //RS_LOG(LOG_DEBUG, "Newest message from app %zu was "
                //    "immediately sent to all its peer recipients, and "
                //    "worker->newest_owref_i (%zu) == "
                //    "worker->oldest_owref_i_by_app[%zu] (%zu), so outbound "
                //    "ring update enqueued immediately.",
                //    app_i, worker->newest_owref_i,
                //    app_i, worker->newest_owref_i);
            } else {
                RS_LOG(LOG_DEBUG, "Newest message from app %zu was "
                    "immediately sent to all its peer recipients, but "
                    "worker->newest_owref_i (%zu) != "
                    "worker->oldest_owref_i_by_app[%zu] (%zu), so outbound "
                    "ring update cannot be enqueued yet due to pending older "
                    "owref(s).", app_i, worker->newest_owref_i,
                    app_i, worker->oldest_owref_i_by_app[app_i]);
                // Keep newest_owref(_i) unchanged to allow reuse on next msg
            }
        }
    }
    return RS_OK;
}

static size_t find_next_owref_for_peer(
    struct rs_worker * worker,
    uint32_t target_peer_i,
    size_t owref_i
) {
    for (;;) {
        owref_i++;
        owref_i %= worker->owrefs_elem_c;
        struct rs_owref * owref = worker->owrefs + owref_i;
        if (!owref->ring_msg) {
            RS_LOG(LOG_DEBUG, "Skipping owref_i %zu for peer_i %zu, because "
                "it's empty (which means it's already done, which also means "
                "this peer was not one of its recipients).", owref_i,
                target_peer_i);
            continue;
        }
        uint8_t const * msg = owref->ring_msg->msg;
        uint32_t const * peer_i = (uint32_t const *) (msg + 1);
        uint32_t peer_c = 0;
        switch (*msg) {
        case RS_OUTBOUND_SINGLE:
            if (*peer_i == target_peer_i) {
                RS_LOG(LOG_DEBUG, "Found next owref_i %zu for peer_i %zu, "
                    "with message header RS_OUTBOUND_SINGLE.", owref_i,
                    target_peer_i);
                return owref_i;
            }
            RS_LOG(LOG_DEBUG, "Skipping owref_i %zu for peer_i %zu, because "
                "it's only addressed to peer_i %zu.", owref_i, target_peer_i,
                *peer_i);
            continue;
        case RS_OUTBOUND_ARRAY:
            peer_c = *peer_i++;
            for (size_t i = 0; i < peer_c; i++) {
                if (peer_i[i] == target_peer_i) {
                    RS_LOG(LOG_DEBUG, "Found next owref_i %zu for peer_i %zu, "
                        "with message header RS_OUTBOUND_ARRAY.", owref_i,
                        target_peer_i);
                    return owref_i;
                }
            }
            RS_LOG(LOG_DEBUG, "Skipping owref_i %zu for peer_i %zu, because "
                "it's not mentioned in its array of recipients.", owref_i,
                target_peer_i);
            continue;
        case RS_OUTBOUND_EVERY:
            RS_LOG(LOG_DEBUG, "Found next owref_i %zu for peer_i %zu, with "
                "message header RS_OUTBOUND_EVERY.", owref_i, target_peer_i);
            return owref_i;
        case RS_OUTBOUND_EVERY_EXCEPT_SINGLE:
            if (*peer_i != target_peer_i) {
                RS_LOG(LOG_DEBUG, "Found next owref_i %zu for peer_i %zu, "
                    "with message header RS_EVERY_EXCEPT_SINGLE.", owref_i,
                    target_peer_i);
                return owref_i;
            }
            RS_LOG(LOG_DEBUG, "Skipping owref_i %zu for peer_i %zu, because "
                "it's the one black sheep that it excludes.", owref_i,
                target_peer_i);
            continue;
        case RS_OUTBOUND_EVERY_EXCEPT_ARRAY: default:
            peer_c = *peer_i++;
            for (size_t i = 0; *peer_i != target_peer_i; i++) {
                if (i == peer_c) {
                    RS_LOG(LOG_DEBUG, "Found next owref_i %zu for peer_i %zu, "
                        "with message header RS_OUTBOUND_EVERY_EXCEPT_ARRAY.",
                        owref_i, target_peer_i);
                    return owref_i;
                }
            }
            RS_LOG(LOG_DEBUG, "Skipping owref_i %zu for peer_i %zu, because "
                "it's mentioned in its array of excluded recipients.", owref_i,
                target_peer_i);
        }
    }
}

static void decrement_pending_owref_count(
    struct rs_worker * worker,
    size_t owref_i
) {
    struct rs_owref * owref = worker->owrefs + owref_i;
    if (--owref->remaining_recipient_c) {
        // One or more of this owref's recipients remain, so the owref itself
        // must remain too for now.
        return;
    }
    size_t app_i = owref->app_i;
    memset(owref, 0, sizeof(struct rs_owref));
    if (owref_i != worker->oldest_owref_i_by_app[app_i]) {
        // This owref is done, but an older one is still pending for this app,
        // so enqueue_ring_update() cannot be called yet.
        return;
    }
    do {
        owref_i++;
        owref_i %= worker->owrefs_elem_c;
        if (owref_i == worker->newest_owref_i) {
            // All owrefs for this app are done, so enqueue up to the reader.
            enqueue_ring_update(worker, worker->outbound_readers[app_i], app_i,
                false);
            worker->oldest_owref_i_by_app[app_i] = owref_i;
            RS_LOG(LOG_DEBUG, "Enqueued ring update for app_i %zu up to "
            "worker->outbound_readers[%zu]", app_i, app_i);
            return;
        }
    } while (!worker->owrefs[owref_i].remaining_recipient_c ||
        worker->owrefs[owref_i].app_i != app_i);
    // Enqueue up to the message pointed at by the owref with index owref_i
    // (because that message is this app's next message that has remaining
    // recipients, which therefore cannot be enqueued yet).
    enqueue_ring_update(worker, (uint8_t *) worker->owrefs[owref_i].ring_msg,
        app_i, false);
    worker->oldest_owref_i_by_app[app_i] = owref_i;
    RS_LOG(LOG_INFO, "Enqueued ring update for app_i %zu up to the message "
        "corresponding to owref_i: %zu", app_i, owref_i);
}

rs_ret send_pending_owrefs(
    struct rs_worker * worker,
    union rs_peer * peer,
    uint32_t peer_i
) {
    if (!peer->ws.owref_c) {
        return RS_OK;
    }
    for (;;) {
        struct rs_owref * owref = worker->owrefs + peer->ws.owref_i;
        uint8_t const * ws = owref->ring_msg->msg + owref->head_size;
        size_t ws_size = owref->ring_msg->size - owref->head_size;
        switch (peer->is_encrypted ?
            write_tls(peer, ws, ws_size) :
            write_tcp(peer, ws, ws_size)) {
        case RS_OK:
            if (*ws != RS_WS_OPC_FIN_CLOSE) {
                RS_LOG(LOG_DEBUG, "Successfully sent %zu byte ws%s %s owref "
                    "message to peer %" PRIu32 ".", ws_size,
                    peer->is_encrypted ? "s" : "",
                    *ws == RS_WS_OPC_FIN_BIN ? "RS_BIN" : "RS_UTF8", peer_i);
                break;
            }
            RS_LOG(LOG_DEBUG, "Successfully sent %zu byte ws%s close owref "
                "message to peer %" PRIu32 ".", ws_size,
                peer->is_encrypted ? "s" : "", peer_i);
            // This message was a WebSocket Close message.
            peer->mortality = RS_MORTALITY_SHUTDOWN_WRITE;
            // Set CONT_NONE to indicate that the ws close msg was already sent.
            peer->continuation = RS_CONT_NONE;
            remove_pending_owrefs(worker, peer, peer_i);
            // Call handle_peer_events() with MORTALITY_SHUTDOWN_WRITE (but
            // without any events) to try to perform any shutdown procedures
            // that can be done right away layer by layer until the occurence
            // of RS_AGAIN or completion.
            return handle_peer_events(worker, peer_i, 0);
        case RS_AGAIN:
            RS_LOG(LOG_DEBUG, "Attempt to send %zu byte ws%s owref message to "
                "peer %" PRIu32 " was unsuccessfull due to RS_AGAIN.",
                ws_size, peer->is_encrypted ? "s" : "", peer_i);
            return RS_AGAIN;
        case RS_CLOSE_PEER:
            RS_LOG(LOG_DEBUG, "Attempt to send %zu byte ws%s owref message to "
                "peer %" PRIu32 " was unsuccessfull due to RS_CLOSE_PEER.",
                ws_size, peer->is_encrypted ? "s" : "", peer_i);
            if (*ws != RS_WS_OPC_FIN_CLOSE) {
                // Only notify the app of peer closure if the message the error
                // occurred on wasn't itself a close message sent by the app.
                RS_GUARD(send_close_to_app(worker, peer, peer_i));
            }
            return RS_CLOSE_PEER;
        default:
            return RS_FATAL;
        }
        decrement_pending_owref_count(worker, peer->ws.owref_i);
        if (!--peer->ws.owref_c) {
            return RS_OK;
        }
        peer->ws.owref_i = find_next_owref_for_peer(worker, peer_i,
            peer->ws.owref_i);
    }
}

void remove_pending_owrefs(
    struct rs_worker * worker,
    union rs_peer * peer,
    uint32_t peer_i
) {
    if (!peer->ws.owref_c) {
        return;
    }
    for (size_t owref_i = peer->ws.owref_i;;) {
        decrement_pending_owref_count(worker, owref_i);
        if (!--peer->ws.owref_c) {
            return;
        }
        owref_i = find_next_owref_for_peer(worker, peer_i, owref_i);
    }
}
