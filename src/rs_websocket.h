// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include "ringsocket.h"

rs_ret handle_ws_io(
    struct rs_conf const * conf,
    union rs_peer * peer,
    uint32_t peer_i,
    uint8_t * rbuf
);
