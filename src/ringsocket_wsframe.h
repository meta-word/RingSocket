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
default:
/* 0x00 <= b <= 0x7F */ return RS_UTF8_OK;
case 0200:case 0201:case 0202:case 0203:case 0204:case 0205:case 0206:case 0207:
case 0210:case 0211:case 0212:case 0213:case 0214:case 0215:case 0216:case 0217:
case 0220:case 0221:case 0222:case 0223:case 0224:case 0225:case 0226:case 0227:
case 0230:case 0231:case 0232:case 0233:case 0234:case 0235:case 0236:case 0237:
case 0240:case 0241:case 0242:case 0243:case 0244:case 0245:case 0246:case 0247:
case 0250:case 0251:case 0252:case 0253:case 0254:case 0255:case 0256:case 0257:
case 0260:case 0261:case 0262:case 0263:case 0264:case 0265:case 0266:case 0267:
case 0270:case 0271:case 0272:case 0273:case 0274:case 0275:case 0276:case 0277:
/* 0x80 <= b <= 0xBF */ return RS_UTF8_INVALID;
case 0300:case 0301:case 0302:case 0303:case 0304:case 0305:case 0306:case 0307:
case 0310:case 0311:case 0312:case 0313:case 0314:case 0315:case 0316:case 0317:
case 0320:case 0321:case 0322:case 0323:case 0324:case 0325:case 0326:case 0327:
case 0330:case 0331:case 0332:case 0333:case 0334:case 0335:case 0336:case 0337:
/* 0xC0 <= b <= 0xDF */ return RS_UTF8_2BYTE_I1;
case 0340:
/* 0xE0 == b == 0xE0 */ return RS_UTF8_3BYTE_1_I1;
          case 0341:case 0342:case 0343:case 0344:case 0345:case 0346:case 0347:
case 0350:case 0351:case 0352:case 0353:case 0354:
/* 0xE1 <= b <= 0xEC */ return RS_UTF8_3BYTE_2_I1;
                                                  case 0355:
/* 0xED == b == 0xED */ return RS_UTF8_3BYTE_3_I1;
                                                            case 0356:case 0357:
/* 0xEE <= b <= 0xEF */ return RS_UTF8_3BYTE_4_I1;
case 0360:
/* 0xF0 == b == 0xF0 */ return RS_UTF8_4BYTE_1_I1;
          case 0361:case 0362:case 0363:
/* 0xF1 <= b <= 0xF3 */ return RS_UTF8_4BYTE_2_I1;
                                        case 0364:
/* 0xF4 == b == 0xF4 */ return RS_UTF8_4BYTE_3_I1;
                                                  case 0365:case 0366:case 0367:
case 0370:case 0371:case 0372:case 0373:case 0374:case 0375:case 0376:case 0377:
/* 0xF5 <= b <= 0xFF */ return RS_UTF8_INVALID;
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
