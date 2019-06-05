// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket.h>

rs_ret handle_http_io(
    struct rs_conf const * conf,
    union rs_peer * peer,
    char * rbuf
);
