// SPDX-License-Identifier: MIT
// Copyright © 2021 MetaWord Inc
// Copyright © 2019-2021 William Budd

#pragma once

#include "rs_worker.h"

// Stored as the left half of epoll event .u64 data to indicate the contents
// of that .u64 data's right half.
enum rs_event_kind {
    RS_EVENT_PEER = 0,
    RS_EVENT_ENCRYPTED_LISTENFD = 1,
    RS_EVENT_UNENCRYPTED_LISTENFD = 2,
    RS_EVENT_EVENTFD = 3
};

rs_ret handle_peer_events(
    struct rs_worker * worker,
    uint32_t peer_i,
    uint32_t events
);

void set_shutdown_deadline(
    union rs_peer * peer,
    size_t wait_interval
);

rs_ret loop_over_events(
    struct rs_worker * worker
);
