// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket.h> // rs_ret

struct rs_slots {
    uint8_t * bytes; // Array in which each bit signifies availability of 1 slot
    uint8_t * byte_over; // If pointer >= byte_over: pointer is out of bounds
    size_t i; // The lowest slot index that _could_ be empty
};

rs_ret init_slots(
    size_t slot_c, // Elem_c of a constant-length arr requiring slot bookkeeping
    struct rs_slots * slots // The rs_slots struct to initialize
);

void free_slots(
    struct rs_slots * slots
);

rs_ret alloc_slot(
    struct rs_slots * slots,
    size_t * slot_i
);

void free_slot(
    struct rs_slots * slots,
    size_t slot_i
);
