// SPDX-License-Identifier: MIT
// Copyright © 2021 MetaWord Inc
// Copyright © 2019-2021 William Budd

#pragma once

#include "rs_worker.h"

rs_ret handle_websocket_io(
    struct rs_worker * worker,
    union rs_peer * peer,
    uint32_t peer_i
);
