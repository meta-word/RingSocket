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
struct rs_wsframe_cs_small {
    union { uint8_t is_final_x80; uint8_t reserved_x70; uint8_t opcode_x0F; };
    union { uint8_t is_masked_x80; uint8_t payload_size_x7F; };
    uint8_t mask_key[4];
    uint8_t payload[];
};

// Client to server frame with a (126 <= size <= UINT16_MAX) payload
struct rs_wsframe_cs_medium {
    union { uint8_t is_final_x80; uint8_t reserved_x70; uint8_t opcode_x0F; };
    union { uint8_t is_masked_x80; uint8_t payload_size_x7F; };
    uint8_t payload_size[2]; // uint16_t would need __attribute__((packed))
    uint8_t mask_key[4];
    uint8_t payload[];
};

// Client to server frame with a (UINT16_MAX < size <= UINT64_MAX) payload
struct rs_wsframe_cs_large {
    union { uint8_t is_final_x80; uint8_t reserved_x70; uint8_t opcode_x0F; };
    union { uint8_t is_masked_x80; uint8_t payload_size_x7F; };
    uint8_t payload_size[8]; // uint64_t would need __attribute__((packed))
    uint8_t mask_key[4];
    uint8_t payload[];
};

// Server to client frame with a (size <= 125) payload
struct rs_wsframe_sc_small {
    union { uint8_t is_final_x80; uint8_t reserved_x70; uint8_t opcode_x0F; };
    union { uint8_t is_masked_x80; uint8_t payload_size_x7F; };
    uint8_t payload[];
};

// Client to server frame with a (126 <= size <= UINT16_MAX) payload
struct rs_wsframe_sc_medium {
    union { uint8_t is_final_x80; uint8_t reserved_x70; uint8_t opcode_x0F; };
    union { uint8_t is_masked_x80; uint8_t payload_size_x7F; };
    uint8_t payload_size[2]; // uint16_t would be OK here, but not consistent...
    uint8_t payload[];
};

// Client to server frame with a (UINT16_MAX < size <= UINT64_MAX) payload
struct rs_wsframe_sc_large {
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
    struct rs_wsframe_cs_small  cs_small;
    struct rs_wsframe_cs_medium cs_medium;
    struct rs_wsframe_cs_large  cs_large;
    struct rs_wsframe_sc_small  sc_small;
    struct rs_wsframe_sc_medium sc_medium;
    struct rs_wsframe_sc_large  sc_large;
};

// Special-purpose frame with pre-allocated payload buffer for struct rs_worker
struct rs_wsframe_sc_pong {
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


static inline enum rs_wsframe_opcode rs_get_wsframe_opcode(
    union rs_wsframe const * frame
) {
    return frame->opcode_x0F & 0x0F;
}

static inline void rs_set_wsframe_opcode(
    union rs_wsframe * frame,
    enum rs_wsframe_opcode opcode
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
    // .cs_medium.payload_size and .sc_medium.payload_size are equivalent.
    case 126: return RS_R_NTOH16(frame->cs_medium.payload_size);
    // .cs_large.payload_size and .sc_large.payload_size are equivalent.
    case 127: return RS_R_NTOH64(frame->cs_large.payload_size);
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
        // .cs_medium.payload_size and .sc_medium.payload_size are equivalent.
        RS_W_HTON16(frame->cs_medium.payload_size, payload_size);
    } else {
        frame->payload_size_x7F |= 127;
        // .cs_large.payload_size and .sc_large.payload_size are equivalent.
        RS_W_HTON64(frame->cs_large.payload_size, payload_size);
    }
}


static inline uint64_t rs_get_wsframe_sc_size(
    union rs_wsframe const * frame
) {
    uint64_t payload_size = frame->payload_size_x7F & 0x7F;
    switch (payload_size) {
    default: return sizeof(frame->sc_small) + payload_size;
    case 126: return sizeof(frame->sc_medium) +
        RS_R_NTOH16(frame->sc_medium.payload_size);
    case 127: return sizeof(frame->sc_large) +
        RS_R_NTOH64(frame->sc_large.payload_size);
    }
}

static inline uint64_t rs_get_wsframe_cs_size(
    union rs_wsframe const * frame
) {
    // Size of "cs" equals "sc", except for the inclusion of 4 mask_key bytes.
    return rs_get_wsframe_sc_size(frame) + 4;
}


static inline uint64_t rs_get_wsframe_sc_size_from_payload_size(
    uint64_t payload_size
) {
    if (payload_size <= 125) {
        return sizeof(struct rs_wsframe_sc_small) + payload_size;
    }
    return payload_size <= UINT16_MAX ?
        sizeof(struct rs_wsframe_sc_medium) + payload_size :
        sizeof(struct rs_wsframe_sc_large)  + payload_size;
}

static inline uint64_t rs_get_wsframe_cs_size_from_payload_size(
    uint64_t payload_size
) {
    // Size of "cs" equals "sc", except for the inclusion of 4 mask_key bytes.
    return rs_get_wsframe_sc_size_from_payload_size(payload_size) + 4;
}


static inline union rs_wsframe * rs_get_next_wsframe_cs(
    union rs_wsframe const * frame
) {
    return (union rs_wsframe *)
        ((uint8_t *) frame + rs_get_wsframe_cs_size(frame));
}


static inline uint64_t rs_get_wsframe_cs_payload(
    union rs_wsframe const * frame,
    uint8_t * * payload
) {
    uint64_t payload_size = frame->payload_size_x7F & 0x7F;
    switch (payload_size) {
    default:
        *payload = frame->cs_small.payload;
        break;
    case 126:
        payload_size = RS_R_NTOH16(frame->cs_medium.payload_size);
        *payload = frame->cs_medium.payload;
        break;
    case 127:
        payload_size = RS_R_NTOH64(frame->cs_large.payload_size);
        *payload = frame->cs_large.payload;
    }
    return payload_size;
}


static inline uint64_t rs_copy_wsframe_cs_payload(
    union rs_wsframe const * frame,
    void * payload_dst
) {
    uint64_t payload_size = frame->payload_size_x7F & 0x7F;
    switch (payload_size) {
    default:
        memcpy(payload_dst, frame->cs_small.payload, payload_size);
        break;
    case 126:
        payload_size = RS_R_NTOH16(frame->cs_medium.payload_size);
        memcpy(payload_dst, frame->cs_medium.payload, payload_size);
        break;
    case 127:
        payload_size = RS_R_NTOH64(frame->cs_large.payload_size);
        memcpy(payload_dst, frame->cs_large.payload, payload_size);
    }
    return payload_size;
}


static inline uint64_t rs_set_wsframe_sc_payload_and_get_frame_size(
    union rs_wsframe * frame,
    void const * payload_src,
    uint64_t payload_size
) {
    if (payload_size <= 125) {
        frame->payload_size_x7F |= payload_size;
        memcpy(frame->sc_small.payload, payload_src, payload_size);
        return sizeof(frame->sc_small) + payload_size;
    }
    if (payload_size <= UINT16_MAX) {
        frame->payload_size_x7F |= 126;
        RS_W_HTON16(frame->sc_medium.payload_size, payload_size);
        memcpy(frame->sc_medium.payload, payload_src, payload_size);
        return sizeof(frame->sc_medium) + payload_size;
    }
    frame->payload_size_x7F |= 127;
    RS_W_HTON64(frame->sc_large.payload_size, payload_size);
    memcpy(frame->sc_large.payload, payload_src, payload_size);
    return sizeof(frame->sc_large) + payload_size;
}

static inline void rs_clear_wsframe_bit_fields(
    union rs_wsframe * frame
) {
    memset(frame, 0, 2);
}

// #############################################################################
// # UTF-8 validator ###########################################################

// Included here because RFC 6455 mandates UTF-8 validation of all frame payload
// content of type text (RS_WSFRAME_OPC_TEXT). Having this in this header also
// has the benefit of allowing the compiler to do inlining optimization without
// needing to rely on LTO.

// Very basic implementation that should nonetheless result in decent bytecode:

enum rs_utf8_state {
    // The byte stream is in a valid UTF-8 state: ready to validate the next
    // codepoint (i.e., unicode character).
    RS_UTF8_OK = 0,

    // The 1st byte of a 2 byte codepoint was valid: awaiting the 2nd byte.
    RS_UTF8_2BYTE_I1 = 1,

    // There are 4 valid range sequences of 3 byte codepoints.
    // 2 more bytes are needed if at index 1 (I1), or 1 more if at index 2 (I2).
    RS_UTF8_3BYTE_1_I1 = 2, RS_UTF8_3BYTE_1_I2 = 3,
    RS_UTF8_3BYTE_2_I1 = 4, RS_UTF8_3BYTE_2_I2 = 5,
    RS_UTF8_3BYTE_3_I1 = 6, RS_UTF8_3BYTE_3_I2 = 7,
    RS_UTF8_3BYTE_4_I1 = 8, RS_UTF8_3BYTE_4_I2 = 9,

    // There are 3 valid range sequences of 4 byte codepoints.
    // 3 bytes await if index 1, 2 await if index 2, and 1 awaits if index 3.
    RS_UTF8_4BYTE_1_I1 = 10, RS_UTF8_4BYTE_1_I2 = 11, RS_UTF8_4BYTE_1_I3 = 12,
    RS_UTF8_4BYTE_2_I1 = 13, RS_UTF8_4BYTE_2_I2 = 14, RS_UTF8_4BYTE_2_I3 = 15,
    RS_UTF8_4BYTE_3_I1 = 16, RS_UTF8_4BYTE_3_I2 = 17, RS_UTF8_4BYTE_3_I3 = 18,

    // The byte stream contains invalid UTF-8 data, no matter what data follows.
    RS_UTF8_INVALID = 19
};

static inline enum rs_utf8_state rs_validate_utf8_byte(
    enum rs_utf8_state state,
    uint8_t b
) {
    switch (state) {
    case RS_UTF8_OK:
        switch (b) {
        default: // b < 0x80
            return RS_UTF8_OK;
        case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85:
        case 0x86: case 0x87: case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F: case 0x90: case 0x91:
        case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D:
        case 0x9E: case 0x9F: case 0xA0: case 0xA1: case 0xA2: case 0xA3:
        case 0xA4: case 0xA5: case 0xA6: case 0xA7: case 0xA8: case 0xA9:
        case 0xAA: case 0xAB: case 0xAC: case 0xAD: case 0xAE: case 0xAF:
        case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5:
        case 0xB6: case 0xB7: case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF: case 0xC0: case 0xC1:
            return RS_UTF8_INVALID;
        case 0xC2: case 0xC3: case 0xC4: case 0xC5: case 0xC6: case 0xC7:
        case 0xC8: case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD:
        case 0xCE: case 0xCF: case 0xD0: case 0xD1: case 0xD2: case 0xD3:
        case 0xD4: case 0xD5: case 0xD6: case 0xD7: case 0xD8: case 0xD9:
        case 0xDA: case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF:
            return RS_UTF8_2BYTE_I1;
        case 0xE0:
            return RS_UTF8_3BYTE_1_I1;
        case 0xE1: case 0xE2: case 0xE3: case 0xE4: case 0xE5: case 0xE6:
        case 0xE7: case 0xE8: case 0xE9: case 0xEA: case 0xEB: case 0xEC:
            return RS_UTF8_3BYTE_2_I1;
        case 0xED:
            return RS_UTF8_3BYTE_3_I1;
        case 0xEE: case 0xEF:
            return RS_UTF8_3BYTE_4_I1;
        case 0xF0:
            return RS_UTF8_4BYTE_1_I1;
        case 0xF1: case 0xF2: case 0xF3:
            return RS_UTF8_4BYTE_2_I1;
        case 0xF4:
            return RS_UTF8_4BYTE_3_I1;
        case 0xF5: case 0xF6: case 0xF7: case 0xF8: case 0xF9: case 0xFA:
        case 0xFB: case 0xFC: case 0xFD: case 0xFE: case 0xFF:
            return RS_UTF8_INVALID;
        }

    case RS_UTF8_2BYTE_I1:
        return b < 0x80 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_OK;

    case RS_UTF8_3BYTE_1_I1:
        return b < 0xA0 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_3BYTE_1_I2;
    case RS_UTF8_3BYTE_1_I2:
        return b < 0x80 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_OK;

    case RS_UTF8_3BYTE_2_I1:
        return b < 0x80 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_3BYTE_2_I2;
    case RS_UTF8_3BYTE_2_I2:
        return b < 0x80 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_OK;

    case RS_UTF8_3BYTE_3_I1:
        return b < 0x80 || b > 0x9F ? RS_UTF8_INVALID : RS_UTF8_3BYTE_3_I2;
    case RS_UTF8_3BYTE_3_I2:
        return b < 0x80 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_OK;

    case RS_UTF8_3BYTE_4_I1:
        return b < 0x80 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_3BYTE_4_I2;
    case RS_UTF8_3BYTE_4_I2:
        return b < 0x80 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_OK;

    case RS_UTF8_4BYTE_1_I1:
        return b < 0x90 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_4BYTE_1_I2;
    case RS_UTF8_4BYTE_1_I2:
        return b < 0x80 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_4BYTE_1_I3;
    case RS_UTF8_4BYTE_1_I3:
        return b < 0x80 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_OK;

    case RS_UTF8_4BYTE_2_I1:
        return b < 0x80 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_4BYTE_2_I2;
    case RS_UTF8_4BYTE_2_I2:
        return b < 0x80 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_4BYTE_2_I3;
    case RS_UTF8_4BYTE_2_I3:
        return b < 0x80 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_OK;

    case RS_UTF8_4BYTE_3_I1:
        return b < 0x80 || b > 0x8F ? RS_UTF8_INVALID : RS_UTF8_4BYTE_3_I2;
    case RS_UTF8_4BYTE_3_I2:
        return b < 0x80 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_4BYTE_3_I3;
    case RS_UTF8_4BYTE_3_I3:
        return b < 0x80 || b > 0xBF ? RS_UTF8_INVALID : RS_UTF8_OK;

    case RS_UTF8_INVALID: default:
        return RS_UTF8_INVALID;
    }
}
