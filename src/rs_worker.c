// SPDX-License-Identifier: MIT
// Copyright © 2021 MetaWord Inc
// Copyright © 2019-2021 William Budd

#include "rs_worker.h"

#include "rs_event.h" // loop_over_events()
#include "rs_from_app.h" // get_outbound_readers(), init_owrefs()
#include "rs_hash.h" // init_hash_state()
#include "rs_slot.h" // init_slots()
#include "rs_tls.h" // create_tls_contexts()
#include "rs_to_app.h" // init_inbound_rings()

static rs_ret init_ring_update_queue(
    struct rs_worker * worker
) {
    worker->ring_queue.size = worker->conf->update_queue_size;
    RS_CALLOC(worker->ring_queue.updates, worker->ring_queue.size);
    return RS_OK;
}

static rs_ret init_peers_array(
    struct rs_worker * worker
) {
    // Verify the assumptions made to optimize union rs_peer for compactness.
    static_assert(sizeof(int) == 4, "sizeof(int) != 4. Some code might need to "
        "be written in a more portable manner after all. Please file a bug "
        "report mentioning your CPU model. ");
    static_assert(sizeof(union rs_peer) == 32, "sizeof(union rs_peer) is not "
        "the 32 bytes it was expected to be.");
    worker->peers_elem_c = worker->conf->fd_alloc_c / worker->conf->worker_c;
    RS_CALLOC(worker->peers, worker->peers_elem_c);
    RS_GUARD(init_slots(worker->peers_elem_c, &worker->peer_slots));
    return RS_OK;
}

static rs_ret init_rbuf(
    struct rs_worker * worker
) {
    RS_CALLOC(worker->rbuf, worker->conf->worker_rbuf_size);
    return RS_OK;
}

static rs_ret _work(
    struct rs_worker * worker
) {
    // Thread ID used as prefix by RS_LOG(): see ringsocket_api.h.
    sprintf(_rs_thread_id_str, "Worker#%zu:", worker->worker_i + 1);

    RS_GUARD(init_inbound_producers(worker)); // rs_to_app.c
    RS_GUARD(init_ring_update_queue(worker));
    RS_GUARD(init_peers_array(worker));
    RS_GUARD(init_rbuf(worker));
    RS_GUARD(init_hash_state(worker)); // rs_hash.c
    RS_GUARD(create_tls_contexts(worker)); // rs_tls.c
    RS_GUARD(get_outbound_consumers_from_producers(worker)); // rs_from_app.c
    RS_GUARD(init_owrefs(worker)); // rs_from_app.c

    return loop_over_events(worker); // rs_event.c
}

int work(
    struct rs_worker_args const * worker_args
) {
    // See rs_worker.h for the difference between rs_worker_args and rs_worker.
    struct rs_worker worker = {
        // Only instantialize const members here. The rest can be done later.

        // worker_args member copies
        .conf = worker_args->conf,
        .ring_pairs = worker_args->ring_pairs,
        .sleep_state = worker_args->sleep_state,
        .app_sleep_states = worker_args->app_sleep_states,
        .eventfd = worker_args->eventfd,
        .worker_i = worker_args->worker_i,

        // Defined in ringsocket_wsframe.h. Used by rs_websocket.c.
        .pong_response = {.is_final_with_opcode = 0x80 | RS_WSFRAME_OPC_PONG }
    };
    _work(&worker);
    // _work() only returns if something went wrong: call exit() instead of
    // returning thrd_error to make sure any other threads go down too.
    exit(EXIT_FAILURE);
}

rs_ret enqueue_ring_update(
    struct rs_worker * worker,
    uint8_t * new_ring_position,
    size_t app_thread_i,
    bool is_write
) {
    return rs_enqueue_ring_update(&worker->ring_queue, worker->ring_pairs,
        worker->app_sleep_states, NULL, new_ring_position, app_thread_i,
        is_write);
}

rs_ret flush_ring_updates(
    struct rs_worker * worker
) {
    return rs_flush_ring_updates(&worker->ring_queue, worker->ring_pairs,
        worker->app_sleep_states, NULL, worker->conf->app_c);
}
