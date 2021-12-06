// SPDX-License-Identifier: MIT
// Copyright © 2021 MetaWord Inc
// Copyright © 2019-2021 William Budd

#include "rs_slot.h"

// A simple utility to keep track of which array elements are available.
// Because availability of each element is stored as a single bit, using these
// functions can help reduce cache misses compared to directly checking the
// elements of the actual array in question, especially when elements are large.

// Currently only supports fixed-length arrays (lacks length updating function).

rs_ret init_slots(
    size_t slot_c, // Elem_c of a constant-length arr requiring slot bookkeeping
    struct rs_slots * slots // The rs_slots struct to initialize
) {
    size_t byte_c = (slot_c + 7) / 8;
    RS_CALLOC(slots->bytes, byte_c);
    slots->byte_over = slots->bytes + byte_c--;
    slots->i = 0;
    // Set any bits in the last byte that correspond to an index equal to or
    // greater than slot_c to 1, marking them as unavailable. (Doing so allows
    // alloc_slot() to only check bounds at each byte, rather than at each bit.)
    switch (slot_c % 8) {
    case 0:                               break; // 00000000
    case 1:  slots->bytes[byte_c] = 0xFE; break; // 11111110
    case 2:  slots->bytes[byte_c] = 0xFC; break; // 11111100
    case 3:  slots->bytes[byte_c] = 0xF8; break; // 11111000
    case 4:  slots->bytes[byte_c] = 0xF0; break; // 11110000
    case 5:  slots->bytes[byte_c] = 0xE0; break; // 11100000
    case 6:  slots->bytes[byte_c] = 0xC0; break; // 11000000
    default: slots->bytes[byte_c] = 0x80;        // 10000000
    }
    return RS_OK;
}

void free_slots(
    struct rs_slots * slots
) {
    RS_FREE(slots->bytes);
    memset(slots, 0, sizeof(struct rs_slots));
}

rs_ret alloc_slot(
    struct rs_slots * slots,
    size_t * slot_i
) {
    uint8_t * p = slots->bytes + slots->i / 8;
    switch (slots->i % 8) { // A Duff's device-like "Jump, Fall, and Roll" dance
        do {
            case 0:  if (!(*p & 0x01)) { goto ok; } slots->i++; // fall through
            case 1:  if (!(*p & 0x02)) { goto ok; } slots->i++; // fall through
            case 2:  if (!(*p & 0x04)) { goto ok; } slots->i++; // fall through
            case 3:  if (!(*p & 0x08)) { goto ok; } slots->i++; // fall through
            case 4:  if (!(*p & 0x10)) { goto ok; } slots->i++; // fall through
            case 5:  if (!(*p & 0x20)) { goto ok; } slots->i++; // fall through
            case 6:  if (!(*p & 0x40)) { goto ok; } slots->i++; // fall through
            default: if (!(*p & 0x80)) { goto ok; } slots->i++;
        } while (++p < slots->byte_over);
        return RS_AGAIN; // "Sorry, but we're full at the moment!"
    }
    ok:
    // Set the bit corresponding to slot_i to 1
    *p |= 1 << slots->i % 8;
    *slot_i = slots->i;
    return RS_OK;
}

void free_slot(
    struct rs_slots * slots,
    size_t slot_i
) {
    // Set the bit corresponding to slot_i to 0
    slots->bytes[slot_i / 8] &= ~(1 << slot_i % 8);
    // If slot_i is now the lowest available index, assign it to slots->i,
    // to mark the starting location from which alloc_slot() will search next.
    if (slot_i < slots->i) {
        slots->i = slot_i;
    }
}
