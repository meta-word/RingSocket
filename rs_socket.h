// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include "ringsocket.h"

rs_ret bind_to_ports(
    struct rs_conf * conf
);

rs_ret init_peer_slots(
    size_t peer_slot_c
);

void free_peer_slot(
    int peer_i
);

rs_ret listen_to_sockets(
    struct rs_conf const * conf,
    size_t worker_i,
    int epoll_fd
);

rs_ret accept_sockets(
    union rs_peer * peers,
    int epoll_fd,
    int listen_fd,
    bool is_encrypted
);
