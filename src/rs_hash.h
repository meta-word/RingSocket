// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include "rs_worker.h"

rs_ret init_hash_state(
    struct rs_worker * worker
);

rs_ret get_websocket_key_hash(
    struct rs_worker * worker,
    char const * wskey_22str,
    char * dst_27str
);
