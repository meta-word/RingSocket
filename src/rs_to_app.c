// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include "rs_to_app.h"

rs_ret init_inbound_rings(
    struct rs_worker * worker
) {
    RS_CALLOC(worker->inbound_rings, worker->conf->app_c);
    for (size_t i = 0; i < worker->conf->app_c; i++) {
        struct rs_ring * ring = worker->inbound_rings + i;
        ring->buf_size = worker->conf->inbound_ring_buf_size;
        RS_CACHE_ALIGNED_CALLOC(ring->buf, ring->buf_size);
        ring->writer = ring->buf;
        ring->alloc_multiplier = worker->conf->realloc_multiplier;
        RS_ATOMIC_STORE_RELAXED(&worker->io_pairs[i]->inbound.writer,
            (atomic_uintptr_t) ring->buf);
        RS_ATOMIC_STORE_RELAXED(&worker->io_pairs[i]->inbound.reader,
            (atomic_uintptr_t) ring->buf);
    }
    // Outbound rings are initialized by app threads through
    // rs_init_outbound_rings() of ringsocket_app_helper.h
    return RS_OK;
}

static rs_ret send_msg_to_app(
    struct rs_worker * worker,
    union rs_peer const * peer,
    uint32_t peer_i,
    uint8_t const * msg,
    uint32_t msg_size,
    enum rs_inbound_kind kind
) {
    struct rs_thread_pair * pair = &worker->io_pairs[peer->app_i]->inbound;
    struct rs_ring * ring = worker->inbound_rings + peer->app_i;
    struct rs_inbound_msg_header header = {
        .peer_i = peer_i,
        .socket_fd = peer->socket_fd,
        .endpoint_id = worker->conf->apps[peer->app_i]
            .endpoints[peer->endpoint_i].endpoint_id,
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
    enqueue_ring_update(worker, ring->writer, peer->app_i, true);
    return RS_OK;
}

rs_ret send_open_to_app(
    struct rs_worker * worker,
    union rs_peer const * peer,
    uint32_t peer_i
) {
    return worker->conf->apps[peer->app_i].wants_open_notification ?
        send_msg_to_app(worker, peer, peer_i, NULL, 0, RS_INBOUND_OPEN) : RS_OK;
}

rs_ret send_read_to_app(
    struct rs_worker * worker,
    union rs_peer const * peer,
    uint32_t peer_i,
    uint8_t const * msg,
    uint32_t msg_size
) {
    return send_msg_to_app(worker, peer, peer_i, msg, msg_size,
        RS_INBOUND_READ);
}

rs_ret send_close_to_app(
    struct rs_worker * worker,
    union rs_peer const * peer,
    uint32_t peer_i
) {
    return worker->conf->apps[peer->app_i].wants_close_notification ?
        send_msg_to_app(worker, peer, peer_i, NULL, 0, RS_INBOUND_CLOSE) :
        RS_OK;
}
