// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#define RS_EXCLUDE_APP_HELPER_HEADER
#include <ringsocket.h>

// struct rs_conf is defined in ringsocket_conf.h instead of here, because of
// its shared usage with RingSocket apps.

rs_ret get_configuration(
    struct rs_conf * conf,
    char const * conf_path
);
