// SPDX-License-Identifier: MIT
// Copyright © 2021 MetaWord Inc
// Copyright © 2019-2021 William Budd

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

char * get_addr_str(
    union rs_peer const * peer
);

char * print_to_log_buf(
    struct rs_worker * worker,
    char * log_dst,
    char const * fmt,
    ...
);

char * get_peer_str(
    struct rs_worker * worker,
    union rs_peer const * peer
);

char * get_epoll_events_str(
    uint32_t epoll_events
);
