// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include "rs_worker.h" // struct rs_slots, rs_ret

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
