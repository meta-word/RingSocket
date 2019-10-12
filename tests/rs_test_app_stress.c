// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include <ringsocket.h>

#define RS_TEST_MAX_READ_MSG_BYTE_C 536870912 // 512 MB
#define RS_TEST_MAX_CLIENT_C 1000

typedef enum {
    RS_TEST_FATAL = -1,
    RS_TEST_OK = 0,
    RS_TEST_TOO_MANY_CLIENTS = 4000,
    RS_TEST_BAD_MSG = 4001
} rs_test_ret;

struct rs_stress {
    size_t max_msg_byte_c;
    size_t msg_byte_c;
    size_t client_c;
    int interval;
    uint64_t client_ids[RS_TEST_MAX_CLIENT_C];
};

static size_t randrange(
    size_t range
) { // Random "enough" for the purpose of this app
    return rand() / (RAND_MAX + 1.) * range;
}

static void randrange_twice( // 2 different choices
    size_t range,
    size_t * dst
) {
    dst[0] = randrange(range);
    dst[1] = randrange(range - 1);
    dst[1] += dst[1] >= dst[0];
}

static void randrange_thrice( // 3 different choices
    size_t range,
    size_t * dst
) {
    dst[0] = randrange(range);
    dst[1] = randrange(range - 1);
    dst[1] += dst[1] >= dst[0];
    dst[2] = randrange(range - 2);
    dst[2] += dst[2] >= dst[0];
    dst[2] += dst[2] >= dst[1];
}

static uint64_t get_nth_client_id( // 0th client == first client...........
    struct rs_stress * s,
    size_t n
) {
    for (uint64_t * cid = s->client_ids;
        cid < s->client_ids + RS_TEST_MAX_CLIENT_C; cid++) {
        if (*cid && !n--) {
            return *cid;
        }
    }
    return 0; // I.e., none
}

static void send_somewhere(
    rs_t * rs,
    struct rs_stress * s,
    bool cb_has_cur
) {
    switch (s->client_c) {
    case 1:
        switch (randrange(2 + cb_has_cur)) {
        case 0:
            rs_to_every(rs, RS_BIN);
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to_every()", s->msg_byte_c);
            break;
        case 1:
            rs_to_single(rs, RS_BIN, get_nth_client_id(s, 0));
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to_single()", s->msg_byte_c);
            break;
        case 2:
            rs_to_cur(rs, RS_BIN);
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to_cur()", s->msg_byte_c);
        }
        break;
    case 2:
        switch (randrange(6 + 2 * cb_has_cur)) {
        case 0:
            rs_to_every(rs, RS_BIN);
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to_every()", s->msg_byte_c);
            break;
        case 1:
            rs_to_single(rs, RS_BIN, get_nth_client_id(s, 0));
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to client #0", s->msg_byte_c);
            break;
        case 2:
            rs_to_single(rs, RS_BIN, get_nth_client_id(s, 1));
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to client #1", s->msg_byte_c);
            break;
        case 3:
            rs_to_multi(rs, RS_BIN, (uint64_t []){get_nth_client_id(s, 0),
                get_nth_client_id(s, 1)}, 2);
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to both clients",
                s->msg_byte_c);
            break;
        case 4:
            rs_to_every_except_single(rs, RS_BIN, get_nth_client_id(s, 0));
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to client !#0", s->msg_byte_c);
            break;
        case 5:
            rs_to_every_except_single(rs, RS_BIN, get_nth_client_id(s, 1));
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to client !#1", s->msg_byte_c);
            break;
        case 6:
            rs_to_cur(rs, RS_BIN);
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to_cur()", s->msg_byte_c);
            break;
        case 7:
            rs_to_every_except_cur(rs, RS_BIN);
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to_every_except_cur()",
                s->msg_byte_c);
        }
        break;
    default:
        switch (randrange(6 + 2 * cb_has_cur)) {
        case 0:
            rs_to_every(rs, RS_BIN);
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to_every()", s->msg_byte_c);
            break;
        case 1:
            rs_to_single(rs, RS_BIN,
                get_nth_client_id(s, randrange(s->client_c)));
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to_single()", s->msg_byte_c);
            break;
        case 2:
            {
                size_t r[2] = {0};
                randrange_twice(s->client_c, r);
                rs_to_multi(rs, RS_BIN, (uint64_t []){
                    get_nth_client_id(s, r[0]),
                    get_nth_client_id(s, r[1])}, 2);
                RS_LOG(LOG_DEBUG, "Sending %zu bytes to_every_multi() client "
                    "#%zu and #%zu", s->msg_byte_c, r[0], r[1]);
            }
            break;
        case 3:
            {
                size_t r[3] = {0};
                randrange_thrice(s->client_c, r);
                rs_to_multi(rs, RS_BIN, (uint64_t []){
                    get_nth_client_id(s, r[0]), get_nth_client_id(s, r[1]),
                    get_nth_client_id(s, r[2])}, 3);
                RS_LOG(LOG_DEBUG, "Sending %zu bytes to_every_multi() client "
                    "#%zu, #%zu and #%zu", s->msg_byte_c, r[0], r[1], r[2]);
            }
            break;
        case 4:
            rs_to_every_except_single(rs, RS_BIN,
                get_nth_client_id(s, randrange(s->client_c)));
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to_every_except_single()",
                s->msg_byte_c);
            break;
        case 5:
            {
                size_t r[2] = {0};
                randrange_twice(s->client_c, r);
                rs_to_every_except_multi(rs, RS_BIN, (uint64_t []){
                    get_nth_client_id(s, r[0]), get_nth_client_id(s, r[1])}, 2);
                RS_LOG(LOG_DEBUG, "Sending %zu bytes to_every_except() client "
                    "#%zu and #%zu", s->msg_byte_c, r[0], r[1]);
            }
            break;
        case 6:
            rs_to_cur(rs, RS_BIN);
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to_cur()", s->msg_byte_c);
            break;
        case 7:
            rs_to_every_except_cur(rs, RS_BIN);
            RS_LOG(LOG_DEBUG, "Sending %zu bytes to_every_except_cur()",
                s->msg_byte_c);
        }
    }
}

static void send_something(
    rs_t * rs,
    struct rs_stress * s,
    bool cb_has_cur
) {
    // Write a cheap dumb predictable sequence of data that should nonetheless
    // function as an okay-ish signal. In other words, in the event that bytes
    // in this stream become corrupt due to a bug, they are fairly likely to
    // be distinguishable from the expected sequence. (No, I can't be bothered
    // to include checksum integrity checks. Maybe some other day.)
    for (size_t i = 0; i < s->msg_byte_c; i++) {
        rs_w_uint8(rs, 255 - i % 256);
    }
    send_somewhere(rs, s, cb_has_cur);
}

rs_test_ret init_cb(
    rs_t * rs
) {
    struct rs_conf const * conf = rs_get_conf(rs);
    struct rs_stress * s = rs_get_app_data(rs);
    s->max_msg_byte_c = conf->max_ws_msg_size;
    s->msg_byte_c = s->max_msg_byte_c;
    s->interval = 10000000; // 10 seconds
    RS_LOG(LOG_DEBUG, "[init_cb] s->interval: %d, s->msg_byte_c: %zu, "
        "s->max_msg_byte_c: %zu",
        s->interval, s->msg_byte_c, s->max_msg_byte_c);
    // Feed some quasi-crappy seed to quasi-crappy rand().
    srand((unsigned) time(NULL));
    return RS_TEST_OK;
}

rs_test_ret open_cb(
    rs_t * rs
) {
    struct rs_stress * s = rs_get_app_data(rs);
    for (uint64_t * cid = s->client_ids;
        cid < s->client_ids + RS_TEST_MAX_CLIENT_C; cid++) {
        if (!*cid) {
            *cid = rs_get_client_id(rs);
            s->client_c++;
            RS_LOG(LOG_DEBUG, "s->client_c: %zu", s->client_c);
            return RS_TEST_OK;
        }
    }
    // Close client if too many test clients are already connected.
    return RS_TEST_TOO_MANY_CLIENTS;
}

rs_test_ret read_cb(
    rs_t * rs,
    uint8_t * msg,
    size_t msg_byte_c
) {
    (void) rs;
    for (size_t i = 0; i < msg_byte_c; i++) {
        if (msg[i] != 255 - i % 256) { // expect same as send_something() sends
            RS_LOG(LOG_ERR, "Received a message byte at index %zu with a value "
                "of " PRIu8 " instead of the expected value " PRIu8,
                i, msg[i], 255 - i % 256);
            return RS_TEST_BAD_MSG;
        }
    }
    RS_LOG(LOG_DEBUG, "Validated a %zu byte message from a client.",
        msg_byte_c);
    return RS_TEST_OK;
}

rs_test_ret close_cb(
    rs_t * rs
) {
    struct rs_stress * s = rs_get_app_data(rs);
    uint64_t client_id = rs_get_client_id(rs);
    for (uint64_t * cid = s->client_ids;
        cid < s->client_ids + RS_TEST_MAX_CLIENT_C; cid++) {
        if (*cid == client_id) {
            *cid = 0;
            s->client_c--;
            return RS_TEST_OK;
        }
    }
    RS_LOG(LOG_CRIT, "Close callback received unknown client ID.");
    return RS_TEST_FATAL;
}

rs_test_ret timer_cb(
    rs_t * rs
) {
    struct rs_stress * s = rs_get_app_data(rs);
    if (!s->client_c) {
        return s->interval;
    }
    send_something(rs, s, false);
    s->msg_byte_c = s->msg_byte_c > 200000 ? s->msg_byte_c - 200000 : 1;
    //if (s->msg_byte_c < s->max_msg_byte_c) {
    //    s->msg_byte_c++;
    //    return s->interval = RS_MAX(100000 /* 0.1 sec */, s->interval * 9 / 10);
    //}
    //// Give RingSocket some time to cool down and process accumulated owrefs.
    //s->msg_byte_c = 1;
    //return s->interval = 200000; // 0.2 sec

    //if (s->interval >= 20000000) {
    //    return s->interval = 100000;
    //}
    //return s->interval = s->interval < 99000 ? 20000000 : s->interval - 100;
    return s->interval;
}

RS_APP(
    RS_INIT(init_cb, sizeof(struct rs_stress)),
    RS_OPEN(open_cb),
    RS_READ_BIN(read_cb, RS_NET_STA(uint8_t, 0, RS_TEST_MAX_READ_MSG_BYTE_C)),
    RS_CLOSE(close_cb),
    RS_TIMER_WAKE(timer_cb, 1000000 /* 1 sec */)
);
