// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include "ringsocket.h"

rs_ret read_tcp(
    union rs_peer * peer,
    void * rbuf,
    size_t rbuf_size,
    size_t * rsize
);

rs_ret write_tcp(
    union rs_peer * peer,
    void const * wbuf,
    size_t wbuf_size
);

rs_ret write_bidirectional_tcp_shutdown(
    union rs_peer * peer
);

rs_ret handle_tcp_io(
    union rs_peer * peer,
    uint8_t * rbuf,
    size_t rbuf_size,
    int peer_i
);
