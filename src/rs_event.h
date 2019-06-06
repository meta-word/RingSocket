// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket.h>

struct rs_worker_args {
    struct rs_conf const * conf;
    // app_c length array of io_pair arrays allocated by each app respectively
    struct rs_thread_io_pairs * * all_io_pairs;
    // app_c length array of each app's sleep state
    struct rs_thread_sleep_state * app_sleep_states;
    struct rs_thread_sleep_state * worker_sleep_state;
    int worker_eventfd;
    size_t worker_i;
};

// Stored as the left half of epoll event .u64 data to indicate the contents
// of that .u64 data's right half.
enum rs_event_kind {
    RS_EVENT_PEER = 0,
    RS_EVENT_ENCRYPTED_LISTENFD = 1,
    RS_EVENT_UNENCRYPTED_LISTENFD = 2,
    RS_EVENT_EVENTFD = 3
};

rs_ret handle_peer_events(
    struct rs_conf const * conf,
    uint8_t * rbuf,
    union rs_peer * peer,
    uint32_t peer_i,
    uint32_t events
);

void set_shutdown_deadline(
    union rs_peer * peer,
    size_t wait_interval
);

int work(
    struct rs_worker_args * worker_args
);

