// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include "rs_worker.h"

rs_ret handle_ws_io(
    struct rs_worker * worker,
    union rs_peer * peer,
    uint32_t peer_i
);
