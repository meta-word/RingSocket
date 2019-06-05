// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket.h>

char * get_peer_str(
    union rs_peer * peer
);

char * get_epoll_events_str(
    uint32_t epoll_events
);

void move_left(
    void * dest,
    size_t offset,
    size_t size
);
