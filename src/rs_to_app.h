// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include "rs_worker.h"

rs_ret init_inbound_producers(
    struct rs_worker * worker
);

rs_ret send_open_to_app(
    struct rs_worker * worker,
    union rs_peer const * peer,
    uint32_t peer_i
);

rs_ret send_read_to_app(
    struct rs_worker * worker,
    union rs_peer const * peer,
    uint32_t peer_i,
    uint8_t const * payload,
    uint32_t payload_size
);

rs_ret send_close_to_app(
    struct rs_worker * worker,
    union rs_peer const * peer,
    uint32_t peer_i
);
