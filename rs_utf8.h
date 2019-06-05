// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <stddef.h> // size_t

#define RS_IS_VALID_UTF8_FRAGMENT(utf8_state) ((utf8_state) != 1)
#define RS_IS_VALID_UTF8_MESSAGE(utf8_state) (!(utf8_state))

unsigned validate_utf8(
    void const * buf,
    size_t size,
    unsigned utf8_state
);
