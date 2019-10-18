// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket_queue.h>
// <ringsocket_variadic.h>           # Arity-based macro expansion helper macros
//   |
//   \---> <ringsocket_api.h>                            # RingSocket's core API
//                        |
// <ringsocket_conf.h> <--/   # Definition of struct rs_conf and its descendents
//   |
//   \---> <ringsocket_ring.h> # Single producer single consumer ring buffer API
//                         |
// <ringsocket_queue.h> <--/      # Ring buffer update queuing and thread waking
//   |
//   |        [YOU ARE HERE]
//   \--> <ringsocket_wsframe.h>   # RFC 6455 WebSocket frame protocol interface
//                           |
// <ringsocket_app.h> <------/    # Definition of RS_APP() and descendent macros
//   |            |
//   |            |
//   |            \--------------> [ Worker translation units: see rs_worker.h ]
//   |
//   |
//   \--> <ringsocket_helper.h> # Definitions of app helper functions (internal)
//                          |
//  <ringsocket.h> <--------/        # Definitions of app helper functions (API)
//    |
//    |
//    \-------------------------------> [ Any RingSocket app translation units ]


// This header aims to provide a convenient interface to WebSocket's framing
// protocol as stipulated in RFC 6455. Having access to this in interface in a
// dedicated <ringsocket_*.h> system header is beneficial to RingSocket given
// that both workers and shared app objects need to read/write WebSocket frames.

// Defined in accordance to: https://tools.ietf.org/html/rfc6455#section-5.2

enum rs_wsframe_opcode {
    RS_WSFRAME_OPC_CONT  = 0x0,
    RS_WSFRAME_OPC_TEXT  = 0x1,
    RS_WSFRAME_OPC_BIN   = 0x2,
    RS_WSFRAME_OPC_CLOSE = 0x8,
    RS_WSFRAME_OPC_PING  = 0x9,
    RS_WSFRAME_OPC_PONG  = 0xA
};

// Sizes and the absence of padding of the structs/union below are verified with
// static_assert() in static_assert_wsframe_sizes() of rs_websocket.c.

// It's unfortunate that the order of bit field members isn't language-defined,
// because that would make these structs convenient even without the helper
// functions defined below.

// Client to server frame with a (size <= 125) payload
struct rs_wsframe_in_small {
    union { uint8_t is_final_x80; uint8_t reserved_x70; uint8_t opcode_x0F; };
    union { uint8_t is_masked_x80; uint8_t payload_size_x7F; };
    uint8_t mask_key[4];
    uint8_t payload[];
};

// Client to server frame with a (126 <= size <= UINT16_MAX) payload
struct rs_wsframe_in_medium {
    union { uint8_t is_final_x80; uint8_t reserved_x70; uint8_t opcode_x0F; };
    union { uint8_t is_masked_x80; uint8_t payload_size_x7F; };
    uint8_t payload_size[2]; // uint16_t would need __attribute__((packed))
    uint8_t mask_key[4];
    uint8_t payload[];
};

// Client to server frame with a (UINT16_MAX < size <= UINT64_MAX) payload
struct rs_wsframe_in_large {
    union { uint8_t is_final_x80; uint8_t reserved_x70; uint8_t opcode_x0F; };
    union { uint8_t is_masked_x80; uint8_t payload_size_x7F; };
    uint8_t payload_size[8]; // uint64_t would need __attribute__((packed))
    uint8_t mask_key[4];
    uint8_t payload[];
};

// Server to client frame with a (size <= 125) payload
struct rs_wsframe_out_small {
    union { uint8_t is_final_x80; uint8_t reserved_x70; uint8_t opcode_x0F; };
    union { uint8_t is_masked_x80; uint8_t payload_size_x7F; };
    uint8_t payload[];
};

// Client to server frame with a (126 <= size <= UINT16_MAX) payload
struct rs_wsframe_out_medium {
    union { uint8_t is_final_x80; uint8_t reserved_x70; uint8_t opcode_x0F; };
    union { uint8_t is_masked_x80; uint8_t payload_size_x7F; };
    uint8_t payload_size[2]; // uint16_t would be OK here, but not consistent...
    uint8_t payload[];
};

// Client to server frame with a (UINT16_MAX < size <= UINT64_MAX) payload
struct rs_wsframe_out_large {
    union { uint8_t is_final_x80; uint8_t reserved_x70; uint8_t opcode_x0F; };
    union { uint8_t is_masked_x80; uint8_t payload_size_x7F; };
    uint8_t payload_size[8]; // uint64_t would need __attribute__((packed))
    uint8_t payload[];
};

// This union is relatively useful, especially when parsing; because it doesn't
// require knowing the payload size in advance.
union rs_wsframe {
    // Anonymous C11 "shortcut" struct to members shared between every variant
    struct {
        union {
            uint8_t is_final_x80;
            uint8_t reserved_x70;
            uint8_t opcode_x0F;
        };
        union {
            uint8_t is_masked_x80;
            uint8_t payload_size_x7F;
        };
    };
    struct rs_wsframe_in_small in_small;
    struct rs_wsframe_in_medium in_medium;
    struct rs_wsframe_in_large in_large;
    struct rs_wsframe_out_small out_small;
    struct rs_wsframe_out_medium out_medium;
    struct rs_wsframe_out_large out_large;
};

// Special-purpose frame with pre-allocated payload buffer for struct rs_worker
struct rs_wsframe_out_pong {
    uint8_t const is_final_with_opcode;
    uint8_t payload_size; // .is_masked bit omitted because always zero here
    uint8_t payload[125]; // The maximum pong frame payload size is 125.
};

// #############################################################################
// # rs_[g|s]et_wsframe_...() helper functions #################################

static inline bool rs_get_wsframe_is_final(
    union rs_wsframe const * frame
) {
    return frame->is_final_x80 >> 7;
}

static inline void rs_set_wsframe_is_final(
    union rs_wsframe * frame,
    bool is_final
) {
    frame->is_final_x80 |= is_final << 7;
}


static inline unsigned rs_get_wsframe_opcode(
    union rs_wsframe const * frame
) {
    return frame->opcode_x0F & 0x0F;
}

static inline void rs_set_wsframe_opcode(
    union rs_wsframe * frame,
    uint8_t opcode
) {
    frame->opcode_x0F |= opcode;
}


static inline bool rs_get_wsframe_ismasked(
    union rs_wsframe const * frame
) {
    return frame->is_masked_x80 >> 7;
}

static inline bool rs_set_wsframe_is_masked(
    union rs_wsframe * frame,
    bool is_masked
) {
    return frame->is_masked_x80 |= is_masked << 7;
}


static inline uint64_t rs_get_wsframe_payload_size(
    union rs_wsframe const * frame
) {
    uint64_t payload_size = frame->payload_size_x7F & 0x7F;
    switch (payload_size) {
    default: return payload_size;
    // .in_medium.payload_size and .out_medium.payload_size are equivalent.
    case 126: return RS_R_NTOH16(frame->in_medium.payload_size);
    // .in_large.payload_size and .out_large.payload_size are equivalent.
    case 127: return RS_R_NTOH64(frame->in_large.payload_size);
    }
}

static inline void rs_set_wsframe_payload_size(
    union rs_wsframe * frame,
    uint64_t payload_size
) {
    if (payload_size <= 125) {
        frame->payload_size_x7F |= payload_size;
    } else if (payload_size <= UINT16_MAX) {
        frame->payload_size_x7F |= 126;
        // .in_medium.payload_size and .out_medium.payload_size are equivalent.
        RS_W_HTON16(frame->in_medium.payload_size, payload_size);
    } else {
        frame->payload_size_x7F |= 127;
        // .in_large.payload_size and .out_large.payload_size are equivalent.
        RS_W_HTON64(frame->in_large.payload_size, payload_size);
    }
}


static inline uint64_t rs_get_wsframe_out_size(
    union rs_wsframe const * frame
) {
    uint64_t payload_size = frame->payload_size_x7F & 0x7F;
    switch (payload_size) {
    default: return sizeof(frame->out_small) + payload_size;
    case 126: return sizeof(frame->out_medium) +
        RS_R_NTOH16(frame->out_medium.payload_size);
    case 127: return sizeof(frame->out_large) +
        RS_R_NTOH64(frame->out_large.payload_size);
    }
}

static inline uint64_t rs_get_wsframe_in_size(
    union rs_wsframe const * frame
) {
    // Size of "in" equals "out", except for the inclusion of 4 mask_key bytes.
    return rs_get_wsframe_out_size(frame) + 4;
}


static inline uint64_t rs_get_wsframe_out_size_from_payload_size(
    uint64_t payload_size
) {
    if (payload_size <= 125) {
        return sizeof(struct rs_wsframe_out_small) + payload_size;
    }
    return payload_size <= UINT16_MAX ?
        sizeof(struct rs_wsframe_out_medium) + payload_size :
        sizeof(struct rs_wsframe_out_large)  + payload_size;
}

static inline uint64_t rs_get_wsframe_in_size_from_payload_size(
    uint64_t payload_size
) {
    // Size of "in" equals "out", except for the inclusion of 4 mask_key bytes.
    return rs_get_wsframe_out_size_from_payload_size(payload_size) + 4;
}


static inline union rs_wsframe * rs_get_next_wsframe_in(
    union rs_wsframe const * frame
) {
    return (union rs_wsframe *)
        ((uint8_t *) frame + rs_get_wsframe_in_size(frame));
}


static inline uint64_t rs_get_wsframe_in_payload(
    union rs_wsframe const * frame,
    uint8_t * * payload
) {
    uint64_t payload_size = frame->payload_size_x7F & 0x7F;
    switch (payload_size) {
    default:
        *payload = frame->in_small.payload;
        break;
    case 126:
        payload_size = RS_R_NTOH16(frame->in_medium.payload_size);
        *payload = frame->in_medium.payload;
        break;
    case 127:
        payload_size = RS_R_NTOH64(frame->in_large.payload_size);
        *payload = frame->in_large.payload;
    }
    return payload_size;
}


static inline uint64_t rs_copy_wsframe_in_payload(
    union rs_wsframe const * frame,
    void * payload_dst
) {
    uint64_t payload_size = frame->payload_size_x7F & 0x7F;
    switch (payload_size) {
    default:
        memcpy(payload_dst, frame->in_small.payload, payload_size);
        break;
    case 126:
        payload_size = RS_R_NTOH16(frame->in_medium.payload_size);
        memcpy(payload_dst, frame->in_medium.payload, payload_size);
        break;
    case 127:
        payload_size = RS_R_NTOH64(frame->in_large.payload_size);
        memcpy(payload_dst, frame->in_large.payload, payload_size);
    }
    return payload_size;
}


static inline uint64_t rs_set_wsframe_out_payload_and_get_frame_size(
    union rs_wsframe * frame,
    void const * payload_src,
    uint64_t payload_size
) {
    if (payload_size <= 125) {
        frame->payload_size_x7F |= payload_size;
        memcpy(frame->out_small.payload, payload_src, payload_size);
        return sizeof(frame->out_small) + payload_size;
    }
    if (payload_size <= UINT16_MAX) {
        frame->payload_size_x7F |= 126;
        RS_W_HTON16(frame->out_medium.payload_size, payload_size);
        memcpy(frame->out_medium.payload, payload_src, payload_size);
        return sizeof(frame->out_medium) + payload_size;
    }
    frame->payload_size_x7F |= 127;
    RS_W_HTON64(frame->out_large.payload_size, payload_size);
    memcpy(frame->out_large.payload, payload_src, payload_size);
    return sizeof(frame->out_large) + payload_size;
}

static inline void rs_clear_wsframe_bit_fields(
    union rs_wsframe * frame
) {
    memset(frame, 0, 2);
}
