// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket_helper.h>
// <ringsocket_variadic.h>           # Arity-based macro expansion helper macros
//   |
//   \---> <ringsocket_api.h>   # RingSocket API other than app helper functions
//                        |
// <ringsocket_conf.h> <--/   # Definition of struct rs_conf and its descendents
//   |
//   \---> <ringsocket_ring.h> # Single producer single consumer ring buffer API
//                         |
// <ringsocket_queue.h> <--/      # Ring buffer update queuing and thread waking
//   |
//   \-----> <ringsocket_app.h>   # Definition of RS_APP() and descendent macros
//                          |
// <ringsocket_helper.h> <--/   # Definitions of app helper functions (internal)
//   |
//   |    [YOU ARE HERE]
//   \--> <ringsocket.h>             # Definitions of app helper functions (API)

// #############################################################################
// # RingSocket app helpers ####################################################

static uint64_t rs_get_client_id(
    rs_t const * rs
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE); 
    return *((uint64_t *) (uint32_t []){
        // Offset worker index by 1 to prevent ever returning an ID value of 0.
        rs->inbound_worker_i + 1,
        rs->inbound_peer_i
    });
}

static uint64_t rs_get_endpoint_id(
    rs_t const * rs
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE); 
    return rs->inbound_endpoint_id;
}

static struct rs_conf const * rs_get_conf(
    rs_t const * rs
) {
    return rs->conf;
}

static void * rs_get_app_data(
    rs_t const * rs
) {
    return rs->app_data;
}

static void rs_w_p(
    rs_t * rs,
    void const * src,
    size_t size
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER); 
    RS_GUARD_APP(rs_check_app_wsize(rs, size));
    memcpy(rs->wbuf + rs->wbuf_i, src, size);
    rs->wbuf_i += size;
}

static void rs_w_str(
    rs_t * rs,
    char const * str // Must be null-terminated
) {
    rs_w_p(rs, str, strlen(str));
}

static void rs_w_uint8(
    rs_t * rs,
    uint8_t u8
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER); 
    RS_GUARD_APP(rs_check_app_wsize(rs, 1));
    rs->wbuf[rs->wbuf_i++] = u8;
}

static void rs_w_uint16(
    rs_t * rs,
    uint16_t u16
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER); 
    RS_GUARD_APP(rs_check_app_wsize(rs, 2));
    *((uint16_t *) (rs->wbuf + rs->wbuf_i)) = u16;
    rs->wbuf_i += 2;
}

static void rs_w_uint32(
    rs_t * rs,
    uint32_t u32
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER); 
    RS_GUARD_APP(rs_check_app_wsize(rs, 4));
    *((uint32_t *) (rs->wbuf + rs->wbuf_i)) = u32;
    rs->wbuf_i += 4;
}

static void rs_w_uint64(
    rs_t * rs,
    uint32_t u64
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ | RS_CB_CLOSE | RS_CB_TIMER); 
    RS_GUARD_APP(rs_check_app_wsize(rs, 8));
    *((uint64_t *) (rs->wbuf + rs->wbuf_i)) = u64;
    rs->wbuf_i += 8;
}

static void rs_w_uint16_hton(
    rs_t * rs,
    uint16_t u16
) {
    rs_w_uint16(rs, RS_HTON16(u16));
}

static void rs_w_uint32_hton(
    rs_t * rs,
    uint32_t u32
) {
    rs_w_uint32(rs, RS_HTON32(u32));
}

static void rs_w_uint64_hton(
    rs_t * rs,
    uint64_t u64
) {
    rs_w_uint64(rs, RS_HTON64(u64));
}

static void rs_w_int8(
    rs_t * rs,
    int8_t i8
) {
    rs_w_uint8(rs, i8);
}

static void rs_w_int16(
    rs_t * rs,
    int16_t i16
) {
    rs_w_uint16(rs, i16);
}

static void rs_w_int32(
    rs_t * rs,
    int32_t i32
) {
    rs_w_uint32(rs, i32);
}

static void rs_w_int64(
    rs_t * rs,
    int64_t i64
) {
    rs_w_uint64(rs, i64);
}

static void rs_w_int16_hton(
    rs_t * rs,
    int16_t i16
) {
    rs_w_uint16_hton(rs, i16);
}

static void rs_w_int32_hton(
    rs_t * rs,
    int32_t i32
) {
    rs_w_uint32_hton(rs, i32);
}

static void rs_w_int64_hton(
    rs_t * rs,
    int64_t i64
) {
    rs_w_uint64_hton(rs, i64);
}

static void rs_to_single(
    rs_t * rs,
    enum rs_data_kind data_kind,
    uint64_t client_id
) {
    uint32_t * u32 = (uint32_t *) &client_id;
    rs_send(rs, *u32 - 1, RS_OUTBOUND_SINGLE, u32 + 1, 1, data_kind);
    rs->wbuf_i = 0;
}

static void rs_to_multi(
    rs_t * rs,
    enum rs_data_kind data_kind,
    uint64_t const * client_ids,
    size_t client_c
) {
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        uint32_t cur_clients[client_c];
        size_t cur_client_c = 0;
        for (size_t j = 0; j < client_c; j++) {
            uint32_t * u32 = (uint32_t *) (client_ids + j);
            if (*u32++ - 1 == i) {
                cur_clients[cur_client_c++] = *u32;
            }
        }
        switch (cur_client_c) {
        case 0:
            continue;
        case 1:
            rs_send(rs, i, RS_OUTBOUND_SINGLE, cur_clients, 1, data_kind);
            continue;
        default:
            rs_send(rs, i, RS_OUTBOUND_ARRAY, cur_clients, cur_client_c,
                data_kind);
            continue;
        }
    }
    rs->wbuf_i = 0;
}

static void rs_to_cur(
    rs_t * rs,
    enum rs_data_kind data_kind
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ); 
    rs_send(rs, rs->inbound_worker_i, RS_OUTBOUND_SINGLE,
        (uint32_t []){rs->inbound_peer_i}, 1, data_kind);
    rs->wbuf_i = 0;
}

static void rs_to_every(
    rs_t * rs,
    enum rs_data_kind data_kind
) {
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        rs_send(rs, i, RS_OUTBOUND_EVERY, NULL, 0, data_kind);
    }
    rs->wbuf_i = 0;
}

static void rs_to_every_except_single(
    rs_t * rs,
    enum rs_data_kind data_kind,
    uint64_t client_id
) {
    uint32_t * u32 = (uint32_t *) &client_id;
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        if (*u32 - 1 == i) {
            rs_send(rs, i, RS_OUTBOUND_EVERY_EXCEPT_SINGLE, u32 + 1, 1,
                data_kind);
        } else {
            rs_send(rs, i, RS_OUTBOUND_EVERY, NULL, 0, data_kind);
        }
    }
    rs->wbuf_i = 0;
}

static void rs_to_every_except_multi(
    rs_t * rs,
    enum rs_data_kind data_kind,
    uint64_t const * client_ids,
    size_t client_c
) {
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        uint32_t cur_clients[client_c];
        size_t cur_client_c = 0;
        for (size_t j = 0; j < client_c; j++) {
            uint32_t * u32 = (uint32_t *) (client_ids + j);
            if (*u32++ - 1 == i) {
                cur_clients[cur_client_c++] = *u32;
            }
        }
        switch (cur_client_c) {
        case 0:
            rs_send(rs, i, RS_OUTBOUND_EVERY, NULL, 0, data_kind);
            continue;
        case 1:
            rs_send(rs, i, RS_OUTBOUND_EVERY_EXCEPT_SINGLE, cur_clients, 1,
                data_kind);
            continue;
        default:
            rs_send(rs, i, RS_OUTBOUND_EVERY_EXCEPT_ARRAY, cur_clients,
                cur_client_c, data_kind);
            continue;
        }
    }
    rs->wbuf_i = 0;
}

static void rs_to_every_except_cur(
    rs_t * rs,
    enum rs_data_kind data_kind
) {
    RS_GUARD_CB(RS_CB_OPEN | RS_CB_READ); 
    for (size_t i = 0; i < rs->conf->worker_c; i++) {
        if (i == rs->inbound_worker_i) {
            rs_send(rs, i, RS_OUTBOUND_EVERY_EXCEPT_SINGLE,
                (uint32_t []){rs->inbound_peer_i}, 1, data_kind);
        } else {
            rs_send(rs, i, RS_OUTBOUND_EVERY, NULL, 0, data_kind);
        }
    }
    rs->wbuf_i = 0;
}
