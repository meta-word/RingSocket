// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include "rs_worker.h"

void move_left(
    void * dst,
    size_t offset,
    size_t size
);

char * bin_to_log_buf(
    struct rs_worker * worker,
    void const * bin,
    size_t size
);

char * pointer_context_to_log_buf(
    struct rs_worker * worker,
    void const * pointer,
    void const * lower_bound,
    void const * upper_bound,
    size_t max_left_byte_c,
    size_t max_right_byte_c
);

char * get_peer_str(
    union rs_peer * peer
);

char * get_epoll_events_str(
    uint32_t epoll_events
);
