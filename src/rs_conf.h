// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket_api.h> // rs_ret
#include <ringsocket_conf.h> // struct rs_conf

// struct rs_conf is defined in ringsocket_conf.h instead of here, because of
// its shared usage with RingSocket apps.

rs_ret get_configuration(
    struct rs_conf * conf,
    char const * conf_path
);
