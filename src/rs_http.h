// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include "rs_worker.h"

rs_ret handle_http_io(
    struct rs_worker * worker,
    union rs_peer * peer
);
