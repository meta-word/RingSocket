// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket.h>

rs_ret get_configuration(
    struct rs_conf * conf,
    char const * conf_path
);
