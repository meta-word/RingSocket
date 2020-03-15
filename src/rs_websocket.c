// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include "rs_event.h" // set_shutdown_deadline()
#include "rs_from_app.h" // send_pending_owrefs(), remove_pending_owrefs()
#include "rs_tcp.h" // read_tcp(), write_tcp()
#include "rs_tls.h" // read_tls(), write_tls()
#include "rs_to_app.h" // send_read_to_app(), send_close_to_app()
#include "rs_util.h" // move_left(), bin_to_log_buf(), get_addr_str()
#include "rs_websocket.h"

// enum rs_wsframe_opcode, union rs_wsframe and related structs and helper
// functions are defined in ringsocket_wsframe.h

static void static_assert_wsframe_sizes(
    union rs_wsframe * frame
) {
    static_assert(sizeof(frame->cs_small) == 6);
    static_assert(sizeof(frame->cs_medium) == 8);
    static_assert(sizeof(frame->cs_large) == 14);
    static_assert(sizeof(frame->sc_small) == 2);
    static_assert(sizeof(frame->sc_medium) == 4);
    static_assert(sizeof(frame->sc_large) == 10);
    static_assert(sizeof(*frame) == 14);
}

enum rs_wsframe_close {
    RS_WSFRAME_CLOSE_EMPTY_REPLY   = 0,
    RS_WSFRAME_CLOSE_ERR_PROTOCOL  = 1,
    RS_WSFRAME_CLOSE_ERR_PAYLOAD   = 2,
    RS_WSFRAME_CLOSE_ERR_TOO_LARGE = 3
}; // Assigned to peer->ws.close_frame, and used as an index to this array:
static uint8_t const close_frames[][4] = {
// FIN+CLOSE opcode (0x88) + payload size (0x02 or 0x00) + two byte status code
    {0x88, 0x00, 0x00, 0x00}, // Empty close reply (only first 2 bytes used)
    {0x88, 0x02, 0x03, 0xEA}, // 1002: Protocol error
    {0x88, 0x02, 0x03, 0xEF}, // 1007: Invalid payload data (e.g., bad UTF-8)
    {0x88, 0x02, 0x03, 0xF1}  // 1009: Message too large to process
};

struct rs_wsframe_parser {
    uint8_t * cur_read;
    uint8_t * next_read;
    union rs_wsframe * frame;
    uint8_t * payload;
    uint64_t payload_size;
    uint64_t data_size;
    enum rs_wsframe_close close_frame;
    enum rs_data_kind data_kind;
    enum rs_utf8_state utf8_state;

    // Unable to use data_size>0 instead, given that "empty" frames are allowed.
    bool is_continuation;

    // Unable to use pong_size>0 instead, given that "empty" pings are allowed.
    bool must_send_pong_response;
};

struct rs_wsframe_parser_storage {
    // rs_frame_parser's frame pointer can be stored as is, because all frames
    // are copied back to the same locations on worker->rbuf
    union rs_wsframe * frame;

    uint64_t next_read_i;
    uint64_t data_size;

    enum rs_utf8_state utf8_state;
    uint8_t data_kind;
    uint8_t is_continuation;
    uint8_t must_send_pong_response;
    uint8_t pong_payload_size;

    uint8_t frames[];
};

static rs_ret parse_websocket_frame_header(
    union rs_peer * peer,
    struct rs_wsframe_parser * wsp,
    size_t max_ws_msg_size
) {
    if (!rs_get_wsframe_ismasked(wsp->frame)) {
        RS_LOG(LOG_NOTICE, "Failing peer %s: received a WebSocket frame with "
            "an unset IS_MASKED bit.", get_addr_str(peer));
        wsp->close_frame = RS_WSFRAME_CLOSE_ERR_PROTOCOL;
        return RS_CLOSE_PEER;
    }
    if (wsp->frame->reserved_x70 & 0x70) {
        RS_LOG(LOG_NOTICE, "Failing peer %s: received a WebSocket frame with "
            "one or more reserved bits set.", get_addr_str(peer));
        wsp->close_frame = RS_WSFRAME_CLOSE_ERR_PROTOCOL;
        return RS_CLOSE_PEER;
    }
    switch (rs_get_wsframe_opcode(wsp->frame)) {
    case RS_WSFRAME_OPC_CONT:
        if (!wsp->is_continuation) {
            RS_LOG(LOG_NOTICE, "Failing peer %s: opcode value of the first "
                "frame of a WebSocket message is CONTINUATION despite not "
                "being a continuation.", get_addr_str(peer));
            wsp->close_frame = RS_WSFRAME_CLOSE_ERR_PROTOCOL;
            return RS_CLOSE_PEER;
        }
        break;
    case RS_WSFRAME_OPC_TEXT:
        if (wsp->is_continuation) {
            RS_LOG(LOG_NOTICE, "Failing peer %s: opcode value of a WebSocket "
                "message continuation frame is TEXT instead of the expected "
                "value CONTINUATION", get_addr_str(peer));
            wsp->close_frame = RS_WSFRAME_CLOSE_ERR_PROTOCOL;
            return RS_CLOSE_PEER;
        }
        wsp->data_kind = RS_UTF8;
        break;
    case RS_WSFRAME_OPC_BIN:
        if (wsp->is_continuation) {
            RS_LOG(LOG_NOTICE, "Failing peer %s: opcode value of a WebSocket "
                "message continuation frame is BINARY instead of the expected "
                "value CONTINUATION", get_addr_str(peer));
            wsp->close_frame = RS_WSFRAME_CLOSE_ERR_PROTOCOL;
            return RS_CLOSE_PEER;
        }
        wsp->data_kind = RS_BIN;
        break;
    case RS_WSFRAME_OPC_CLOSE:
        if (!rs_get_wsframe_is_final(wsp->frame)) {
            RS_LOG(LOG_NOTICE, "Failing peer %s: received a WebSocket CLOSE "
                "control frame with an unset IS_FINAL bit.",
                get_addr_str(peer));
            wsp->close_frame = RS_WSFRAME_CLOSE_ERR_PROTOCOL;
            return RS_CLOSE_PEER;
        }
        if (rs_get_wsframe_payload_size(wsp->frame) > 125) {
            RS_LOG(LOG_NOTICE, "Failing peer %s: received a WebSocket CLOSE "
                "control frame with a payload size value greater than the "
                "maximum control frame size of 125.", get_addr_str(peer));
            wsp->close_frame = RS_WSFRAME_CLOSE_ERR_PROTOCOL;
            return RS_CLOSE_PEER;
        }
        // Relevant https://tools.ietf.org/html/rfc6455#section-5.5.1 quote:
        //
        // > The Close frame MAY contain a body [...] If an endpoint receives a
        // > Close frame and did not previously send a Close frame, the endpoint
        // > MUST send a Close frame in response. When sending a Close frame in
        // > response, the endpoint typically echos the status code it received.
        //
        // RingSocket faithfully replies with a close frame, but does not echo
        // the status code received: completely ignoring the received body
        // (i.e., payload) and sending a body-less close response is a lot more
        // convenient, while still in accordance with the spec.
        wsp->close_frame = RS_WSFRAME_CLOSE_EMPTY_REPLY;
        return RS_CLOSE_PEER;
    case RS_WSFRAME_OPC_PING:
        if (!rs_get_wsframe_is_final(wsp->frame)) {
            RS_LOG(LOG_NOTICE, "Failing peer %s: received a WebSocket PING "
                "control frame with an unset IS_FINAL bit.",
                get_addr_str(peer));
            wsp->close_frame = RS_WSFRAME_CLOSE_ERR_PROTOCOL;
            return RS_CLOSE_PEER;
        }
        if (rs_get_wsframe_payload_size(wsp->frame) > 125) {
            RS_LOG(LOG_NOTICE, "Failing peer %s: received a WebSocket PING "
                "control frame with a payload size value greater than the "
                "maximum control frame size of 125.", get_addr_str(peer));
            wsp->close_frame = RS_WSFRAME_CLOSE_ERR_PROTOCOL;
            return RS_CLOSE_PEER;
        }
        // Relevant https://tools.ietf.org/html/rfc6455#section-5.5.2 quote:
        //
        // > Upon receipt of a Ping frame, an endpoint MUST send a Pong frame in
        // > response, unless it already received a Close frame.  It SHOULD
        // > respond with Pong frame as soon as is practical.
        //
        // "As soon as is practical" in this case means after read_websocket()
        // has returned RS_OK, which only happens after read_tls()/read_tcp()
        // has returned RS_AGAIN exactly afer a complete WebSocket message has
        // been parsed; which is due to constraints imposed by epoll() in
        // edge-triggered mode in combination with the constraints imposed by
        // non-blocking OpenSSL IO functions, that basically mean interleaving
        // reads and writes should be avoided.
        //
        // The response pong is generated at the bottom of
        // parse_websocket_frame(), because the ping frame payload which it must
        // echo is not unmasked here yet.
        wsp->payload = wsp->frame->cs_small.payload;
        wsp->payload_size = wsp->frame->payload_size_x7F & 0x7F;
        wsp->must_send_pong_response = true;
        return RS_OK;
    case RS_WSFRAME_OPC_PONG:
        if (!rs_get_wsframe_is_final(wsp->frame)) {
            RS_LOG(LOG_NOTICE, "Failing peer %s: received a WebSocket PONG "
                "control frame with an unset IS_FINAL bit.",
                get_addr_str(peer));
            wsp->close_frame = RS_WSFRAME_CLOSE_ERR_PROTOCOL;
            return RS_CLOSE_PEER;
        }
        if (rs_get_wsframe_payload_size(wsp->frame) > 125) {
            RS_LOG(LOG_NOTICE, "Failing peer %s: received a WebSocket PONG "
                "control frame with a payload size value greater than the "
                "maximum control frame size of 125.", get_addr_str(peer));
            wsp->close_frame = RS_WSFRAME_CLOSE_ERR_PROTOCOL;
            return RS_CLOSE_PEER;
        }
        // Relevant https://tools.ietf.org/html/rfc6455#section-5.5.3 quote:
        // > A Pong frame MAY be sent unsolicited.  This serves as a
        // > unidirectional heartbeat.  A response to an unsolicited Pong frame
        // > is not expected.
        //
        // Given that RingSocket never sends any pings, all pongs it receives
        // are by definition unsolicited, and can thus simply be ignored.
        wsp->payload = wsp->frame->cs_small.payload;
        wsp->payload_size = wsp->frame->payload_size_x7F & 0x7F;
        return RS_OK;
    default:
        wsp->close_frame = RS_WSFRAME_CLOSE_ERR_PROTOCOL;
        RS_LOG(LOG_NOTICE, "Failing peer %s: received a WebSocket message "
            "frame with an invalid opcode.", get_addr_str(peer));
        return RS_CLOSE_PEER;
    }
    //  rs_get_wsframe_cs_payload_and_payload_size() can't be used safely here
    //  because there is no guarantee that all header bytes are read yet.
    unsigned payload_byte = wsp->frame->payload_size_x7F & 0x7F;
    switch (payload_byte) {
    default:
        wsp->payload = wsp->frame->cs_small.payload;
        wsp->payload_size = payload_byte;
        break;
    case 126:
        if (wsp->next_read < wsp->frame->cs_medium.payload) {
            return RS_AGAIN;
        }
        wsp->payload = wsp->frame->cs_medium.payload;
        wsp->payload_size = RS_R_NTOH16(wsp->frame->cs_medium.payload_size);
        break;
    case 127:
        if (wsp->next_read < wsp->frame->cs_large.payload) {
            return RS_AGAIN;
        }
        wsp->payload = wsp->frame->cs_large.payload;
        wsp->payload_size = RS_R_NTOH64(wsp->frame->cs_large.payload_size);
        break;
    }
    if (wsp->data_size + wsp->payload_size > max_ws_msg_size) {
        RS_LOG(LOG_NOTICE, "Failing peer %s: total WebSocket message payload "
            "size of %zu exceeds the configured \"max_ws_msg_size\" value of "
            "%zu by %zu bytes.", get_addr_str(peer),
            wsp->data_size + wsp->payload_size, max_ws_msg_size,
            wsp->data_size + wsp->payload_size - max_ws_msg_size);
        wsp->close_frame = RS_WSFRAME_CLOSE_ERR_TOO_LARGE;
        return RS_CLOSE_PEER;
    }
    return RS_OK;
}

static rs_ret unmask_payload_and_validate_any_utf8(
    struct rs_wsframe_parser * wsp,
    size_t masked_size
) {
    uint8_t * mask_key = wsp->payload - 4;
    size_t mask_i =
        wsp->cur_read > wsp->payload ? wsp->cur_read - wsp->payload : 0;
    if (wsp->data_kind == RS_BIN) {
        for (; mask_i < masked_size; mask_i++) {
            wsp->payload[mask_i] ^= mask_key[mask_i % 4];
        }
    } else {
        for (; mask_i < masked_size; mask_i++) {
            wsp->payload[mask_i] ^= mask_key[mask_i % 4];
            if ((wsp->utf8_state = rs_validate_utf8_byte(wsp->utf8_state,
                wsp->payload[mask_i])) == RS_UTF8_INVALID) {
                wsp->close_frame = RS_WSFRAME_CLOSE_ERR_PAYLOAD;
                return RS_CLOSE_PEER;
            }
        }
    }
    return RS_OK;
}

static rs_ret parse_websocket_frame(
    struct rs_worker * worker,
    union rs_peer * peer,
    struct rs_wsframe_parser * wsp
) {
    if (wsp->cur_read < wsp->frame->cs_large.payload) {
        if (wsp->next_read < wsp->frame->cs_small.payload) {
            return RS_AGAIN;
        }
        RS_GUARD(parse_websocket_frame_header(peer, wsp,
            worker->conf->max_ws_msg_size));
        if (wsp->payload + wsp->payload_size >
            worker->rbuf + worker->conf->max_ws_frame_chain_size) {
            RS_LOG(LOG_NOTICE, "Failing peer %s: total size of all seen "
                "frames %zu in WebSocket message exceeds the configured "
                "\"max_ws_frame_chain_size\" value of %zu by %zu bytes.",
                get_addr_str(peer),
                wsp->payload + wsp->payload_size - worker->rbuf,
                worker->conf->max_ws_frame_chain_size,
                wsp->payload + wsp->payload_size -
                (worker->rbuf + worker->conf->max_ws_frame_chain_size));
            wsp->close_frame = RS_WSFRAME_CLOSE_ERR_TOO_LARGE;
            return RS_CLOSE_PEER;
        }
    }
    if (wsp->next_read < wsp->payload + wsp->payload_size) {
        RS_GUARD(unmask_payload_and_validate_any_utf8(wsp,
            wsp->next_read - wsp->payload));
        return RS_AGAIN;
    }
    RS_GUARD(unmask_payload_and_validate_any_utf8(wsp, wsp->payload_size));
    if (rs_get_wsframe_opcode(wsp->frame) == RS_WSFRAME_OPC_PING) {
        // Do this here because the Pong response frame must contain the Ping
        // frame's unmasked payload.
        //
        // Relevant https://tools.ietf.org/html/rfc6455#section-5.5.3 quote:
        // > If an endpoint receives a Ping frame and has not yet sent Pong
        // > frame(s) in response to previous Ping frame(s), the endpoint MAY
        // > elect to send a Pong frame for only the most recently processed
        // > Ping frame.
        //
        // RingSocket only sends "the most recently processed Ping frame" simply
        // by (over)writing worker->pong_response without checking whether any
        // older frame may have been previously copied to it from here.
        worker->pong_response.payload_size = wsp->payload_size;
        memcpy(worker->pong_response.payload, wsp->payload, wsp->payload_size);
    }
    return RS_OK;
}

static rs_ret parse_websocket(
    struct rs_worker * worker,
    union rs_peer * peer,
    uint32_t peer_i,
    struct rs_wsframe_parser * wsp
) {
    for (;;) {
        RS_GUARD(parse_websocket_frame(worker, peer, wsp));
        uint8_t * frame_incr = wsp->payload + wsp->payload_size;
        switch (rs_get_wsframe_opcode(wsp->frame)) {
        case RS_WSFRAME_OPC_PING:
        case RS_WSFRAME_OPC_PONG:
            if (frame_incr == wsp->next_read && !wsp->is_continuation) {
                return RS_OK;
            }
            wsp->frame = (union rs_wsframe *) frame_incr;
            continue;
        default:
            break;
        }
        wsp->data_size += wsp->payload_size;
        if (!rs_get_wsframe_is_final(wsp->frame)) {
            wsp->is_continuation = true;
            wsp->frame = (union rs_wsframe *) frame_incr;
            continue;
        }
        if (wsp->utf8_state != RS_UTF8_OK) {
            // https://tools.ietf.org/html/rfc6455#section-5.6 :
            //
            // > Note that a particular text frame might include a partial UTF-8
            // > sequence; however, the whole message MUST contain valid UTF-8.
            //
            // This check is also safe when kind == RS_BIN, because in that case
            // wsp.utf8_state remains zero.
            wsp->close_frame = RS_WSFRAME_CLOSE_ERR_PAYLOAD;
            return RS_CLOSE_PEER;
        }
        RS_GUARD(send_read_to_app(worker, peer, peer_i, wsp->data_size,
            wsp->data_kind));
        if (frame_incr == wsp->next_read) {
            return RS_OK;
        }
        size_t remaining_size = wsp->next_read - frame_incr;
        move_left(worker->rbuf, frame_incr - worker->rbuf, remaining_size);
        {
            bool must_send_pong_response = wsp->must_send_pong_response;
            memset(wsp, 0, sizeof(*wsp));
            wsp->must_send_pong_response = must_send_pong_response;
        }
        wsp->next_read = worker->rbuf + remaining_size;
        wsp->frame = (union rs_wsframe *) worker->rbuf;
    }
}

static rs_ret save_websocket_parse_state(
    struct rs_worker * worker,
    union rs_peer * peer,
    struct rs_wsframe_parser * wsp
) {
    size_t frames_size = wsp->next_read - worker->rbuf;
    size_t pong_payload_size = worker->pong_response.payload_size;
    // Primarily because of the flexible array member .frames, and secondarily
    // to avoid zero-ing overhead of large buffers, use "raw" malloc() instead
    // of the macros of ringsocket_api.h.
    peer->ws.storage =
        malloc(sizeof(*peer->ws.storage) + frames_size + pong_payload_size);
    if (!peer->ws.storage) {
        RS_LOG(LOG_ERR, "Unsuccessful malloc(%zu)",
            frames_size + pong_payload_size);
        return RS_CLOSE_PEER;
    }
    peer->ws.storage->frame = wsp->frame;
    peer->ws.storage->next_read_i = frames_size;
    peer->ws.storage->data_size = wsp->data_size;
    peer->ws.storage->data_kind = wsp->data_kind;
    peer->ws.storage->utf8_state = wsp->utf8_state;
    peer->ws.storage->is_continuation = wsp->is_continuation;
    peer->ws.storage->must_send_pong_response = wsp->must_send_pong_response;
    peer->ws.storage->pong_payload_size = pong_payload_size;

    memcpy(peer->ws.storage->frames, worker->rbuf, frames_size);

    if (pong_payload_size) {
        memcpy(peer->ws.storage->frames + frames_size,
            worker->pong_response.payload, pong_payload_size);
        worker->pong_response.payload_size = 0;
    }
    return RS_OK;
}

static void load_websocket_parse_state(
    struct rs_worker * worker,
    union rs_peer * peer,
    struct rs_wsframe_parser * wsp
) {
    memcpy(worker->rbuf, peer->ws.storage->frames,
        peer->ws.storage->next_read_i);

    if (peer->ws.storage->pong_payload_size) {
        memcpy(worker->pong_response.payload,
            peer->ws.storage->frames + peer->ws.storage->next_read_i,
            peer->ws.storage->pong_payload_size);
        worker->pong_response.payload_size =
            peer->ws.storage->pong_payload_size;
    }

    wsp->next_read = worker->rbuf + peer->ws.storage->next_read_i;
    wsp->frame = peer->ws.storage->frame;
    wsp->data_size = peer->ws.storage->data_size;
    wsp->data_kind = peer->ws.storage->data_kind;
    wsp->utf8_state = peer->ws.storage->utf8_state;
    wsp->is_continuation = peer->ws.storage->is_continuation;
    wsp->must_send_pong_response = peer->ws.storage->must_send_pong_response;

    RS_FREE(peer->ws.storage);
    
    if (wsp->next_read >= wsp->frame->cs_large.payload) {
        // parse_websocket_frame_header() must have already been called during
        // the previous iteration of parse_websocket_frame() (which resulted in
        // RS_AGAIN). However, to save space, struct wsframe_storage omits the
        // .payload and .payload_size of struct websocket_peer; so regenerate
        // them here with rs_get_wsframe_cs_payload().
        wsp->payload_size =
            rs_get_wsframe_cs_payload(wsp->frame, &wsp->payload);
    }
}

static rs_ret send_pong_response(
    struct rs_worker * worker,
    union rs_peer * peer,
    struct rs_wsframe_sc_small const * pong_response
) {
    return peer->is_encrypted ?
        write_tls(worker, peer, pong_response,
            sizeof(*pong_response) + pong_response->payload_size_x7F) :
        write_tcp(peer, pong_response,
            sizeof(*pong_response) + pong_response->payload_size_x7F);
}

static rs_ret send_pong_response_from_worker(
    struct rs_worker * worker,
    union rs_peer * peer
) {
    rs_ret ret = send_pong_response(worker, peer,
        (struct rs_wsframe_sc_small *) &worker->pong_response);
    if (ret != RS_AGAIN) {
        worker->pong_response.payload_size = 0;
        return ret;
    }
    size_t pong_size = sizeof(struct rs_wsframe_sc_small) +
        worker->pong_response.payload_size;
    worker->pong_response.payload_size = 0;
    // Because of the flexible array member .payload, use "raw" malloc() instead
    // of the macros of ringsocket_api.h.
    peer->ws.pong_response = malloc(pong_size);
    if (!peer->ws.pong_response) {
        RS_LOG(LOG_ERR, "Unsuccessful malloc(%zu)", pong_size);
        return RS_CLOSE_PEER;
    }
    memcpy(peer->ws.pong_response, &worker->pong_response, pong_size);
    return RS_OK;
}

static rs_ret read_websocket(
    struct rs_worker * worker,
    union rs_peer * peer,
    uint32_t peer_i
) {
    uint8_t * const rbuf_over = worker->rbuf + worker->conf->worker_rbuf_size;
    bool parse_is_incomplete = false;
    struct rs_wsframe_parser wsp = {
        .next_read = worker->rbuf,
        .frame = (union rs_wsframe *) worker->rbuf
    };
    static_assert_wsframe_sizes(wsp.frame);
    if (peer->ws.storage) {
        parse_is_incomplete = true;
        load_websocket_parse_state(worker, peer, &wsp);
    }
    for (;;) {
        size_t rsize = 0;
        switch (peer->is_encrypted ?
            read_tls(worker,
                peer, wsp.next_read, rbuf_over - wsp.next_read, &rsize) :
            read_tcp(
                peer, wsp.next_read, rbuf_over - wsp.next_read, &rsize)
        ) {
        case RS_OK:
            wsp.cur_read = wsp.next_read;
            wsp.next_read += rsize;
            switch (parse_websocket(worker, peer, peer_i, &wsp)) {
            case RS_OK:
                {
                    bool must_send_pong_response = wsp.must_send_pong_response;
                    memset(&wsp, 0, sizeof(wsp));
                    wsp.must_send_pong_response = must_send_pong_response;
                }
                wsp.next_read = worker->rbuf;
                wsp.frame = (union rs_wsframe *) worker->rbuf;
                parse_is_incomplete = false;
                continue;
            case RS_AGAIN:
                parse_is_incomplete = true;
                continue;
            case RS_CLOSE_PEER: default:
                peer->ws.close_frame = wsp.close_frame;
                peer->mortality = RS_MORTALITY_SHUTDOWN_WRITE;
                return RS_CLOSE_PEER;
            }
        case RS_AGAIN:
            if (parse_is_incomplete) {
                RS_LOG(LOG_DEBUG, "RS_AGAIN occurred while attempting to read "
                    "the remainder of a partially parsed WebSocket message: "
                    "calling save_websocket_parse_state()");
                RS_GUARD(save_websocket_parse_state(worker, peer, &wsp));
                return RS_AGAIN;
            }
            RS_LOG(LOG_DEBUG, "RS_AGAIN occurred after a WebSocket message was "
                    "fully parsed: ready now to handle any pending writes.");
            return wsp.must_send_pong_response ?
                send_pong_response_from_worker(worker, peer) : RS_OK;
        case RS_CLOSE_PEER:
            return RS_CLOSE_PEER;
        case RS_FATAL: default:
            return RS_FATAL;
        }
    }
}

static rs_ret write_websocket_control_frame(
    struct rs_worker * worker,
    union rs_peer * peer,
    struct rs_wsframe_sc_small * frame
) {
    size_t frame_size = sizeof(*frame) + frame->payload_size_x7F;
    RS_LOG(LOG_DEBUG, "Writing a WebSocket control frame to peer %s with a "
        "%zu byte payload: %s", get_addr_str(peer), frame->payload_size_x7F,
        bin_to_log_buf(worker, frame, frame_size));
    return peer->is_encrypted ? write_tls(worker, peer, frame, frame_size) :
                                        write_tcp(peer, frame, frame_size);
}

rs_ret handle_websocket_io(
    struct rs_worker * worker,
    union rs_peer * peer,
    uint32_t peer_i
) {
    switch (peer->mortality) {
    case RS_MORTALITY_LIVE:
        break;
    case RS_MORTALITY_SHUTDOWN_WRITE:
        if (peer->continuation == RS_CONT_SENDING) {
            write_ws_close_msg:
            switch (write_websocket_control_frame(worker, peer,
                (struct rs_wsframe_sc_small *)
                close_frames[RS_BOUNDS(0, peer->ws.close_frame, 3)])) {
            case RS_OK:
                peer->continuation = RS_CONT_NONE;
                break;
            case RS_AGAIN:
                return RS_OK;
            case RS_CLOSE_PEER:
                peer->mortality = RS_MORTALITY_DEAD;
                goto terminate_ws;
            case RS_FATAL: default:
                return RS_FATAL;
            }
        }
        set_shutdown_deadline(peer, worker->conf->shutdown_wait_ws);
        // Fall through
    default:
        terminate_ws:
        peer->layer = peer->is_encrypted ? RS_LAYER_TLS : RS_LAYER_TCP;
        return RS_OK;
    }
    switch (peer->continuation) {
        for (;;) {
    case RS_CONT_NONE: default:
            peer->continuation = RS_CONT_PARSING;
            // Fall through
    case RS_CONT_PARSING:
            switch (read_websocket(worker, peer, peer_i)) {
            case RS_OK:
                if (!peer->ws.owref_c) {
                    peer->continuation = RS_CONT_NONE;
                    return RS_OK;
                }
                break;
            case RS_AGAIN:
                return RS_OK;
            case RS_CLOSE_PEER:
                RS_GUARD(send_close_to_app(worker, peer, peer_i));
                remove_pending_owrefs(worker, peer, peer_i);
                if (peer->mortality == RS_MORTALITY_SHUTDOWN_WRITE) {
                    peer->continuation = RS_CONT_SENDING;
                    goto write_ws_close_msg;
                }
                peer->mortality = RS_MORTALITY_DEAD;
                goto terminate_ws;
            case RS_FATAL: default:
                return RS_FATAL;
            }
            peer->continuation = RS_CONT_SENDING;
            // Fall through
    case RS_CONT_SENDING:
            if (peer->ws.pong_response) {
                switch (send_pong_response(worker, peer,
                    peer->ws.pong_response)) {
                case RS_OK:
                    RS_FREE(peer->ws.pong_response);
                    break;
                case RS_AGAIN:
                    return RS_OK;
                case RS_CLOSE_PEER:
                    RS_GUARD(send_close_to_app(worker, peer, peer_i));
                    remove_pending_owrefs(worker, peer, peer_i);
                    peer->mortality = RS_MORTALITY_DEAD;
                    goto terminate_ws;
                case RS_FATAL: default:
                    return RS_FATAL;
                }
            }
            switch (send_pending_owrefs(worker, peer, peer_i)) {
            case RS_OK:
                continue; // Loopy zero-gravity fall through
            case RS_AGAIN:
                return RS_OK;
            case RS_CLOSE_PEER:
                remove_pending_owrefs(worker, peer, peer_i);
                peer->mortality = RS_MORTALITY_DEAD;
                goto terminate_ws;
            case RS_FATAL: default:
                return RS_FATAL;
            }
        }
    }
}
