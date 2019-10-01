// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket.h>

// struct rs_conf is defined ringsocket_conf.h instead of here, because some of
// its members need to be accessed by ringsocket_app(_helpers).h.

rs_ret get_configuration(
    struct rs_conf * conf,
    char const * conf_path
);
