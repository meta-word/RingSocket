// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include "rs_event.h" // set_shutdown_deadline()
#include "rs_ring.h" // various functions
#include "rs_tcp.h" // read_tcp(), write_tcp()
#include "rs_tls.h" // read_tls(), write_tls()
#include "rs_utf8.h" // validate_utf8()
#include "rs_util.h" // get_peer_str(), move_left()
#include "rs_websocket.h"

enum ws_opc {
    RS_OPC_NFIN_CONT = 0x00,
    RS_OPC_NFIN_TEXT = 0x01,
    RS_OPC_NFIN_BIN  = 0x02,
    RS_OPC_FIN_CONT  = 0x80,
    RS_OPC_FIN_TEXT  = 0x81,
    RS_OPC_FIN_BIN   = 0x82,
    RS_OPC_FIN_CLOSE = 0x88,
    RS_OPC_FIN_PING  = 0x89,
    RS_OPC_FIN_PONG  = 0x8A
};

#define RS_IS_CONTROL_FRAME(opc) ((opc) >= RS_OPC_FIN_CLOSE)
#define RS_6BYTE_MIN_CLIENT_HEADER_SIZE 6
#define RS_14BYTE_MAX_CLIENT_HEADER_SIZE 14
#define RS_2BYTE_MIN_SERVER_HEADER_SIZE 2
#define RS_10BYTE_MAX_SERVER_HEADER_SIZE 10

enum ws_close_wmsg_i {
    RS_WS_CLOSE_EMPTY_REPLY = 0,
    RS_WS_CLOSE_ERROR_PROTOCOL = 1,
    RS_WS_CLOSE_ERROR_PAYLOAD = 2,
    RS_WS_CLOSE_ERROR_TOO_LARGE = 3
}; // enum to be assigned to peer->ws.close_wmsg_i as an index to this array:
static uint8_t const close_wmsgs[][4] = {
// FIN_CLOSE opcode (0x88) + payload size (0x0[02]) + two byte status code
    {0x88, 0x00, 0x00, 0x00}, // Empty close reply (only first 2 bytes used)
    {0x88, 0x02, 0x03, 0xEA}, // 1002: Protocol error
    {0x88, 0x02, 0x03, 0xEF}, // 1007: Invalid payload data (e.g., bad UTF-8)
    {0x88, 0x02, 0x03, 0xF1} // 1009: Message too large to process
};

static rs_ret write_ws_control_frame(
    union rs_peer * peer,
    uint8_t const * control_frame
) {
    // Because control frame payload size cannot be greater than 125, byte #2 of
    // a server-to-client control frame must contain the payload size as-is.
    // Reference: https://tools.ietf.org/html/rfc6455#section-5.5
    size_t wsize = 2 + control_frame[1];
    return peer->is_encrypted ?
        write_tls(peer, control_frame, wsize) :
        write_tcp(peer, control_frame, wsize);
}

static rs_ret read_ws(
    union rs_peer * peer,
    uint8_t * rbuf,
    size_t rbuf_size,
    size_t msg_size,
    size_t required_rsize,
    size_t * unparsed_rsize
) {
    // Keep read()ing until either required_rsize bytes are obtained or a read()
    // returns a response other than RS_OK.
    size_t old_rsize = msg_size + *unparsed_rsize;
    do {
        if (old_rsize > rbuf_size / 2) {
            RS_LOG(LOG_NOTICE, "Currently received a %zu byte WebSocket "
                "frame from %s after having received %zu WebSocket payload "
                "bytes in previous frame(s), the total of which is taking up "
                "more than half the size of the %zu byte read buffer. It's "
                "likely that either the read buffer is too small, or that the "
                "permitted WebSocket message size is too large.",
                *unparsed_rsize, get_peer_str(peer), msg_size,
                rbuf_size);
        }
        size_t new_rsize = 0;
        rs_ret ret = peer->is_encrypted ?
            read_tls(peer, rbuf + old_rsize, rbuf_size - old_rsize, &new_rsize):
            read_tcp(peer, rbuf + old_rsize, rbuf_size - old_rsize, &new_rsize);
        RS_LOG(LOG_DEBUG, "Read() %zu bytes", new_rsize);
        *unparsed_rsize += new_rsize;
        old_rsize += new_rsize;
        switch (ret) {
        case RS_OK:
            break;
        case RS_AGAIN:
            if (old_rsize) {
                if (peer->heap_buf) {
                    RS_REALLOC(peer->heap_buf, old_rsize);
                } else {
                    RS_CALLOC(peer->heap_buf, old_rsize);
                }
                memcpy(peer->heap_buf, rbuf, old_rsize);
                peer->ws.msg_rsize = msg_size;
                peer->ws.unparsed_rsize = *unparsed_rsize;
            }
            return RS_AGAIN;
        default:
            return ret;
        }
    } while (*unparsed_rsize < required_rsize);
    return RS_OK;
}

static void unmask_ws_payload(
    uint8_t * payload,
    size_t payload_size,
    size_t mask_i
) {
    uint8_t * const mask = payload - 4;
    for (; mask_i < payload_size; mask_i++) {
        payload[mask_i] ^= mask[mask_i % 4];
    }
}

// This function attempts to parse one whole WebSocket message. If RS_AGAIN
// occurs before it could do so (or because the write buffer was full while this
// function tried to write a control frame or close reason to the peer) it will
// update peer->ws state as needed and return RS_AGAIN, in the expectation that
// parse_ws_msg() will be called again later to resume parsing.
//
// If this function returns RS_OK, the caller may then access one complete
// continuous read WebSocket message pointed to by msg of size msg_size.
//
// If a WebSocket error occurs or a close frame is received, this function will
// attempt to write an appropriate close response. When/if that response was
// completely written out, this function will return RS_CLOSE_PEER; indicating
// to the caller that it should proceed with a bidirectional shutdown on the
// underlying TLS layer or TCP layer.
//
// Any WebSocket message can be fragmented across any number of WebSocket
// frames. Each time a non-final frame is parsed its payload (i.e., the  portion
// of the frame containing app data) will be moved to the start of rbuf,
// concatenated onto any payload fragments of previous frames already moved
// there. In the case of RS_AGAIN, any such accumulated message is copied to
// peer->rbuf along with any data of the current frame already received; and
// copied back to rbuf when this function is called again.
static rs_ret parse_ws_msg(
    union rs_peer * peer,
    uint8_t * rbuf, // The start of this threads whole rbuf
    size_t rbuf_size, // The constant length of this thread's whole rbuf
    size_t max_msg_size, // The maximum total WebSocket message size to accept
    uint8_t * * msg,
    size_t * msg_size
) {
    // Size of the part of the message already accumulated, if any.
    // Non-zero if at least one frame with a non-empty payload was parsed on a
    // previous call to this function.
    *msg_size = peer->ws.msg_rsize;

    // Total number of bytes of frame(s) not yet (completely) parsed.
    // At this point it must be less than the current frame size, but after
    // read()ing this size may include any number of continuation frames too.
    size_t unparsed_rsize = peer->ws.unparsed_rsize;

    if (peer->ws.heap_buf_contains_pong) {
        RS_GUARD(write_ws_control_frame(peer,
            peer->heap_buf + *msg_size + unparsed_rsize));
        // The pong frame has been written out. Altough it's actually still
        // stored in peer->heap_buf, being located behind any of its other data
        // means it can be safely ignored until the next realloc() or free()
        // gets rid of it.
        peer->ws.heap_buf_contains_pong = false;
    }

    if (*msg_size || unparsed_rsize) {
        // Some partial read data was previously stored. Copy it to the start of
        // rbuf, ahead of the upcoming read().
        memcpy(rbuf, peer->heap_buf, *msg_size + unparsed_rsize);
        // Don't free parser_rwbuf (yet), because it may needed (either as-is,
        // or realloc()ed) by a next call to this function in case of RS_AGAIN
    }

    // required_rsize = RS_6BYTE_MIN_CLIENT_HEADER_SIZE, which means no
    // parsing progress can be made until read_ws() reads in enough such that
    // unparsed_rsize >= required_rsize.
    RS_GUARD(read_ws(peer, rbuf, rbuf_size, *msg_size,
        RS_6BYTE_MIN_CLIENT_HEADER_SIZE, &unparsed_rsize));

    // Perhaps not the prettiest way to bail, but at least its fairly fool-proof
#define RS_WS_RETURN_CLOSE_MSG(close_msg_i) do { \
    *msg = NULL; \
    *msg_size = 0; \
    peer->mortality = RS_MORTALITY_SHUTDOWN_WRITE; \
    peer->ws.close_wmsg_i = (close_msg_i); \
    return RS_CLOSE_PEER; \
} while (0)

    for (;;) { // Each loop iteration corresponds to parsing of one whole frame.
        RS_LOG(LOG_DEBUG, "NEW FRAME: %s", get_peer_str(peer));
        // The start of the current frame
        uint8_t * frame = rbuf + *msg_size;
        enum ws_opc opcode = *frame;
        switch (opcode) {
        case RS_OPC_NFIN_CONT:
        case RS_OPC_FIN_CONT:
            if (!peer->ws.rmsg_is_fragmented) {
                // This frame's opcode should not have been MMWS_OPC_(N)FIN_CONT
                // because the last frame's opcode was a final OPC_FIN_*.
                RS_WS_RETURN_CLOSE_MSG(RS_WS_CLOSE_ERROR_PROTOCOL);
            }
            break;
        case RS_OPC_NFIN_TEXT:
        case RS_OPC_FIN_TEXT:
            if (peer->ws.rmsg_is_fragmented) {
                // This frame's opcode should have been the continuation kind
                // RS_OPC_(N)FIN_CONT, becuase the previous frame's opcode
                // was a non-final RS_OPC_NFIN_*.
                RS_WS_RETURN_CLOSE_MSG(RS_WS_CLOSE_ERROR_PROTOCOL);
            }
            // WebSocket test messages must be utf8-encoded.
            peer->ws.rmsg_is_utf8 = true;
            break;
        case RS_OPC_NFIN_BIN:
        case RS_OPC_FIN_BIN:
            if (peer->ws.rmsg_is_fragmented) {
                // This frame's opcode should have been the continuation kind
                // RS_OPC_(N)FIN_CONT, because the previous frame's opcode
                // was a non-final RS_OPC_NFIN_*.
                RS_WS_RETURN_CLOSE_MSG(RS_WS_CLOSE_ERROR_PROTOCOL);
            }
            peer->ws.rmsg_is_utf8 = false;
            break;
        default:
            // Handle the rest of the opcode checks after obtaining the payload.
            break;
        }
        size_t payload_size = frame[1];
        if (!(payload_size & 0x80)) { // Bail if the required masking bit is 0.
            RS_WS_RETURN_CLOSE_MSG(RS_WS_CLOSE_ERROR_PROTOCOL);
        }
        payload_size &= 0x7F; // Clear the masking bit to get the payload size.
        uint8_t *payload = NULL;
        if (payload_size <= 125) {
            payload = frame + 6;
        } else {
            if (RS_IS_CONTROL_FRAME(opcode)) {
                // Control frames must not have payloads in excess of 125 bytes.
                // Reference: https://tools.ietf.org/html/rfc6455#section-5.5
                RS_WS_RETURN_CLOSE_MSG(RS_WS_CLOSE_ERROR_PROTOCOL);
            }
            if (payload_size == 126) {
                payload_size = RS_R_NTOH16(frame + 2);
                payload = frame + 8;
            } else { 
                // Payload_size is guaranteed to hold the mnemonic val 127 here.
                if (unparsed_rsize < RS_14BYTE_MAX_CLIENT_HEADER_SIZE) {
                    RS_GUARD(read_ws(peer, rbuf, rbuf_size, *msg_size,
                        RS_14BYTE_MAX_CLIENT_HEADER_SIZE, &unparsed_rsize));
                }
                payload_size = RS_R_NTOH64(frame + 2);
                payload = frame + 14;
            }
        }
        RS_LOG(LOG_DEBUG, "payload_size: %zu", payload_size);
        if (*msg_size + payload_size > max_msg_size) {
            RS_WS_RETURN_CLOSE_MSG(RS_WS_CLOSE_ERROR_TOO_LARGE);
        }
        size_t header_size = payload - frame;
        size_t frame_size = header_size + payload_size;
        // Now that the dimensions of this frame are known, we're ready to
        // unmask the payload: https://tools.ietf.org/html/rfc6455#section-5.3
        //
        // However, there is a slight complication involved:
        // "When an endpoint is to interpret a byte stream as UTF-8 but finds
        // that the byte stream is not, in fact, a valid UTF-8 stream, that
        // endpoint MUST _Fail the WebSocket Connection_. This rule applies
        // both during the opening handshake and during subsequent data
        // exchange." -- https://tools.ietf.org/html/rfc6455#section-8.1
        //
        // Even though that quote (or the rest of RFC 6455) does not explicitly
        // mention how quickly a server must "find that the byte stream is not,
        // in fact, a valid UTF-8 stream", the Autobahn Testsuite expects 
        // "fail-fast" validation in order for server implementations to pass
        // all of its tests, essentially making such behavior a de facto
        // standard: https://github.com/crossbario/autobahn-testsuite/issues/1
        //
        // RS (which passes every Autobahn test) implements fail-fast as
        // follows: if RS_AGAIN occurs before the entire payload could be
        // read, it unmasks whatever amount of the message has already been
        // accumulated; and if it's supposed to hold UTF-8 (i.e., if the first
        // frame's opcode was RS_OPC_(N)FIN_TEXT), applies UTF-8 stream
        // validation to its contents prior to returning from this function.
        //
        // A consequence of this is that the current frame may contain payload
        // bytes from a previous call to this function (which were then stored
        // at peer->rbuf) that have already been unmasked and which must not
        // be "re-unmasked".
        //
        // mask_i marks the payload index of the first byte that has not yet
        // been unmasked. Any unparsed bytes that were stored in peer->rbuf in
        // excess of the current frame header size must be already unmasked
        // payload bytes -- hence the difference between the two equals mask_i.
        // Otherwise, unmask from the start of the current payload (mask_i = 0).
        size_t const mask_i = peer->ws.unparsed_rsize > header_size ?
            peer->ws.unparsed_rsize - header_size : 0;
        if (unparsed_rsize < frame_size) {
            // Not all payload bytes have arrived yet. Attempt to read() more
            // with frame_size as required_rsize.
            rs_ret ret = read_ws(peer, rbuf, rbuf_size, *msg_size, frame_size,
                &unparsed_rsize);
            switch (ret) {
            case RS_OK:
                break;
            case RS_AGAIN:
                // Unmask from mask_i and validate if UTF-8 as described above.
                // read_ws() having returned RS_AGAIN means the payload has
                // already been copied to peer->rbuf, so that's where the
                // unmasking needs to take place, starting from index mask_i.
                payload = peer->heap_buf + *msg_size + header_size;
                // Reduce payload size to only the payload part already read
                payload_size = unparsed_rsize - header_size;
                unmask_ws_payload(payload, payload_size, mask_i);
                if (peer->ws.rmsg_is_utf8) {
                    peer->ws.rmsg_utf8_state = validate_utf8(payload,
                        payload_size, peer->ws.rmsg_utf8_state);
                    if (!RS_IS_VALID_UTF8_FRAGMENT(
                        peer->ws.rmsg_utf8_state)) {
                        RS_WS_RETURN_CLOSE_MSG(RS_WS_CLOSE_ERROR_PAYLOAD);
                    }
                }
                return RS_AGAIN;
            default:
                return ret;
            }
        }
        unparsed_rsize -= frame_size;
        // This frame's whole payload was read. Unmask from mask_i and validate.
        unmask_ws_payload(payload, payload_size, mask_i);
        if (peer->ws.rmsg_is_utf8) {
            peer->ws.rmsg_utf8_state =
                validate_utf8(payload, payload_size, peer->ws.rmsg_utf8_state);
            if (!RS_IS_VALID_UTF8_MESSAGE(peer->ws.rmsg_utf8_state)) {
                RS_WS_RETURN_CLOSE_MSG(RS_WS_CLOSE_ERROR_PAYLOAD);
            }
        }
        // If this message is fragmented (i.e., this frame is a continuation of
        // a previous frame, or this frame is expected to be followed by a
        // continuation frame), move this frame's payload plus any remaining
        // unparsed bytes to the left by header_size, effectively
        // deleting/overwriting the current frame's header and concatenating
        // its payload onto any previous frames' payloads.
        switch (opcode) {
        case RS_OPC_NFIN_CONT:
            // Neither the first nor the last frame of this fragmented message
            break;
        case RS_OPC_FIN_CONT:
            // The last frame of a fragmented message
            move_left(frame, header_size, payload_size + unparsed_rsize);
            goto parse_success;
        case RS_OPC_NFIN_TEXT:
            // The first frame of a fragmented UTF-8 message
            // (Already set above: peer->ws.is_utf8 = true)
        case RS_OPC_NFIN_BIN:
            // The first frame of a fragmented binary message
            break;
        case RS_OPC_FIN_TEXT:
            // The only frame of an unfragmented UTF-8 message
            // (Already set above: peer->ws.is_utf8 = true)
        case RS_OPC_FIN_BIN:
            // The only frame of an unfragmented binary message
            *msg = payload;
            *msg_size = payload_size;
            parse_success:
            // Clean up per-msg peer state
            peer->ws.rmsg_is_fragmented = false;
            peer->ws.rmsg_utf8_state = 0;
            // ws.rmsg_is_utf8 must remain as-is
            peer->ws.msg_rsize = 0;
            peer->ws.unparsed_rsize = unparsed_rsize;
            if (peer->heap_buf) {
                // Free up any heap memory that was used to hold the current msg
                if (unparsed_rsize) {
                    RS_REALLOC(peer->heap_buf, unparsed_rsize);
                    RS_LOG(LOG_DEBUG, "%zu bytes remaining after chunked ws "
                        "msg was parsed.", unparsed_rsize);
                } else {
                    RS_FREE(peer->heap_buf);
                }
            }
            return RS_OK;
        case RS_OPC_FIN_CLOSE:
            RS_WS_RETURN_CLOSE_MSG(RS_WS_CLOSE_EMPTY_REPLY);
        case RS_OPC_FIN_PING:
            // https://tools.ietf.org/html/rfc6455#section-5.5.3 :
            // 'A Pong frame sent in response to a Ping frame must have
            // identical "Application data" as found in the message body
            // of the Ping frame being replied to.'
            // The fastest way to do so is to leave the ping payload in rbuf
            // (for now) and simply overwrite the last 2 bytes of the received
            // ping frame header with a pong response frame header and attempt
            // to write the pong directly from the rbuf.
            payload[-2] = RS_OPC_FIN_PONG;
            payload[-1] = payload_size;
            {
                rs_ret ret = write_ws_control_frame(peer, payload - 2);
                switch (ret) {
                case RS_OK:
                    break; // The next step is the same as that of the pong case
                case RS_AGAIN:
                    // This pong frame will be needed again for write
                    // resumption, so it will need to get its own storage until
                    // then: save it in peer->heap_buf, appending it to
                    // any partial *msg and/or remaining unparsed_rsize
                    if (peer->heap_buf) {
                        RS_REALLOC(peer->heap_buf,
                            *msg_size + unparsed_rsize + 2 + payload_size);
                    } else {
                        RS_CALLOC(peer->heap_buf,
                            *msg_size + unparsed_rsize + 2 + payload_size);
                    }
                    if (*msg_size) {
                        memcpy(peer->heap_buf, rbuf, *msg_size);
                    }
                    if (unparsed_rsize) {
                        memcpy(peer->heap_buf + *msg_size,
                            frame + frame_size, unparsed_rsize);
                    }
                    memcpy(peer->heap_buf + *msg_size + unparsed_rsize,
                        payload - 2, 2 + payload_size);
                    peer->ws.heap_buf_contains_pong = true;
                    return RS_AGAIN;
                default:
                    return ret;
                }
            } // fall through
        case RS_OPC_FIN_PONG: // Responding to a pong is not neccessary.
            // Pings and pongs are control frames that may appear anywhere
            // amidst message frames; so remove this control frame from rbuf by
            // moving the remaining unparsed read bytes left, and continue to
            // attempt parsing the next message frame.
            move_left(frame, frame_size, unparsed_rsize);
            continue;
        default:
            RS_WS_RETURN_CLOSE_MSG(RS_WS_CLOSE_ERROR_PROTOCOL);
        }
        peer->ws.rmsg_is_fragmented = true;
        move_left(frame, header_size, payload_size + unparsed_rsize);
        *msg = rbuf;
        *msg_size += payload_size;
    }
}

rs_ret handle_ws_io(
    struct rs_conf const * conf,
    union rs_peer * peer,
    uint32_t peer_i,
    uint8_t * rbuf
) {
    switch (peer->mortality) {
    case RS_MORTALITY_LIVE:
        break;
    case RS_MORTALITY_SHUTDOWN_WRITE:
        if (peer->continuation == RS_CONT_SENDING) {
            write_ws_close_msg:
            switch (write_ws_control_frame(peer,
                close_wmsgs[peer->ws.close_wmsg_i])) {
            case RS_OK:
                peer->continuation = RS_CONT_NONE;
                break;
            case RS_AGAIN:
                peer->continuation = RS_CONT_SENDING;
                return RS_OK;
            case RS_CLOSE_PEER:
                peer->mortality = RS_MORTALITY_DEAD;
                goto terminate_ws;
            case RS_FATAL: default:
                return RS_FATAL;
            }
        }
        set_shutdown_deadline(peer, conf->shutdown_wait_ws);
        // fall through
    default:
        terminate_ws:
        if (peer->heap_buf) {
            RS_FREE(peer->heap_buf);
        }
        peer->layer = peer->is_encrypted ? RS_LAYER_TLS : RS_LAYER_TCP;
        return RS_OK;
    }
    switch (peer->continuation) {
    case RS_CONT_PARSING:
        {
            uint8_t * msg = NULL;
            size_t msg_size = 0;
            switch (parse_ws_msg(peer, rbuf, conf->worker_rbuf_size,
                conf->max_ws_msg_size, &msg, &msg_size)) {
            case RS_OK:
                RS_LOG_CHBUF(LOG_DEBUG,
                    "Received a chunked WebSocket message from %s",
                    msg, msg_size, get_peer_str(peer));
                RS_GUARD(send_read_to_app(conf, peer, peer_i, msg, msg_size));
                break;
            case RS_AGAIN:
                return RS_OK;
            case RS_CLOSE_PEER:
                send_close_to_app(conf, peer, peer_i);
                remove_pending_write_references(peer, peer_i);
                if (peer->mortality == RS_MORTALITY_SHUTDOWN_WRITE) {
                    goto write_ws_close_msg;
                }
                peer->mortality = RS_MORTALITY_DEAD;
                goto terminate_ws;
            case RS_FATAL: default:
                return RS_FATAL;
            }
        }
        if (peer->ws.wref_c) {
            peer->continuation = RS_CONT_SENDING;
            // fall through
    case RS_CONT_SENDING:
            switch (send_pending_write_references(conf, peer, peer_i)) {
            case RS_OK:
                break;
            case RS_AGAIN:
                return RS_OK;
            case RS_CLOSE_PEER:
                remove_pending_write_references(peer, peer_i);
                peer->mortality = RS_MORTALITY_DEAD;
                goto terminate_ws;
            case RS_FATAL: default:
                return RS_FATAL;
            }
        }
        peer->continuation = RS_CONT_NONE;
        // fall through
    case RS_CONT_NONE: default:
        for (;;) {
            uint8_t * msg = NULL;
            size_t msg_size = 0;
            switch (parse_ws_msg(peer, rbuf, conf->worker_rbuf_size,
                conf->max_ws_msg_size, &msg, &msg_size)) {
            case RS_OK:
                RS_LOG_CHBUF(LOG_DEBUG, "Received a WebSocket message from %s",
                    msg, msg_size, get_peer_str(peer));
                RS_GUARD(send_read_to_app(conf, peer, peer_i, msg, msg_size));
                break;
            case RS_AGAIN:
                if (peer->ws.msg_rsize || peer->ws.unparsed_rsize) {
                    peer->continuation = RS_CONT_PARSING;
                }
                return RS_OK;
            case RS_CLOSE_PEER:
                send_close_to_app(conf, peer, peer_i);
                remove_pending_write_references(peer, peer_i);
                if (peer->mortality == RS_MORTALITY_SHUTDOWN_WRITE) {
                    goto write_ws_close_msg;
                }
                peer->mortality = RS_MORTALITY_DEAD;
                goto terminate_ws;
            case RS_FATAL: default:
                return RS_FATAL;
            }
        }
    }
}
