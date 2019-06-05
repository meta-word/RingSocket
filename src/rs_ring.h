// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket.h>

rs_ret init_rings(
    struct rs_conf const * conf,
    struct rs_thread_io_pairs * * all_io_pairs,
    struct rs_thread_sleep_state * app_sleep_states,
    struct rs_thread_sleep_state * worker_sleep_state,
    size_t worker_i
);

void announce_worker_sleep(
    void
);

rs_ret flush_ring_updates(
    size_t app_c
);

rs_ret send_open_to_app(
    struct rs_conf const * conf,
    union rs_peer const * peer,
    uint32_t peer_i
);

rs_ret send_read_to_app(
    struct rs_conf const * conf,
    union rs_peer const * peer,
    uint32_t peer_i,
    uint8_t const * msg,
    uint32_t msg_size
);

rs_ret send_close_to_app(
    struct rs_conf const * conf,
    union rs_peer const * peer,
    uint32_t peer_i
);

rs_ret receive_from_app(
    struct rs_conf const * conf,
    union rs_peer * peers,
    size_t peers_elem_c
);

rs_ret send_pending_write_references(
    struct rs_conf const * conf,
    union rs_peer * peer,
    uint32_t peer_i
);

void remove_pending_write_references(
    union rs_peer * peer,
    uint32_t peer_i
);
