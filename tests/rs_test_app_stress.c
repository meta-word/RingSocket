// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include <ringsocket.h>

#define RS_TEST_MAX_READ_MSG_BYTE_C 536870912 // 512 MB
#define RS_TEST_MAX_CLIENT_C 1000
#define RS_TEST_INCR_MSG_BYTE_C(_cur_byte_c) (1.1 * ((_cur_byte_c) + 100))

typedef enum {
    RS_TEST_FATAL = -1,
    RS_TEST_OK = 0,
    RS_TEST_TOO_MANY_CLIENTS = 4000,
    RS_TEST_BAD_MSG = 4001
} rs_test_ret;

struct rs_stress {
    size_t max_msg_byte_c;
    size_t client_c;
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
            break;
        case 1:
            rs_to_single(rs, RS_BIN, get_nth_client_id(s, 0));
            break;
        case 2:
            rs_to_cur(rs, RS_BIN);
        }
        break;
    case 2:
        switch (randrange(6 + 2 * cb_has_cur)) {
        case 0:
            rs_to_every(rs, RS_BIN);
            break;
        case 1:
            rs_to_single(rs, RS_BIN, get_nth_client_id(s, 0));
            break;
        case 2:
            rs_to_single(rs, RS_BIN, get_nth_client_id(s, 1));
            break;
        case 3:
            rs_to_multi(rs, RS_BIN, (uint64_t []){get_nth_client_id(s, 0),
                get_nth_client_id(s, 1)}, 2);
            break;
        case 4:
            rs_to_every_except_single(rs, RS_BIN, get_nth_client_id(s, 0));
            break;
        case 5:
            rs_to_every_except_single(rs, RS_BIN, get_nth_client_id(s, 1));
            break;
        case 6:
            rs_to_cur(rs, RS_BIN);
            break;
        case 7:
            rs_to_every_except_cur(rs, RS_BIN);
        }
        break;
    default:
        switch (randrange(6 + 2 * cb_has_cur)) {
        case 0:
            rs_to_every(rs, RS_BIN);
            break;
        case 1:
            rs_to_single(rs, RS_BIN,
                get_nth_client_id(s, randrange(s->client_c)));
            break;
        case 2:
            {
                size_t r[2] = {0};
                randrange_twice(s->client_c, r);
                rs_to_multi(rs, RS_BIN, (uint64_t []){
                    get_nth_client_id(s, r[0]),
                    get_nth_client_id(s, r[1])}, 2);
            }
            break;
        case 3:
            {
                size_t r[3] = {0};
                randrange_thrice(s->client_c, r);
                rs_to_multi(rs, RS_BIN, (uint64_t []){
                    get_nth_client_id(s, r[0]), get_nth_client_id(s, r[1]),
                    get_nth_client_id(s, r[2])}, 3);
            }
            break;
        case 4:
            rs_to_every_except_single(rs, RS_BIN,
                get_nth_client_id(s, randrange(s->client_c)));
            break;
        case 5:
            {
                size_t r[2] = {0};
                randrange_twice(s->client_c, r);
                rs_to_every_except_multi(rs, RS_BIN, (uint64_t []){
                    get_nth_client_id(s, r[0]), get_nth_client_id(s, r[1])}, 2);
            }
            break;
        case 6:
            rs_to_cur(rs, RS_BIN);
            break;
        case 7:
            rs_to_every_except_cur(rs, RS_BIN);
        }
    }
}

static void send_something(
    rs_t * rs,
    struct rs_stress * s,
    bool cb_has_cur
) {
    thread_local static size_t byte_c = 1;
    // Write a cheap dumb predictable sequence of data that should nonetheless
    // function as an okay-ish signal. In other words, in the event that bytes
    // in this stream become corrupt due to a bug, they are fairly likely to
    // be distinguishable from the expected sequence. (No, I can't be bothered
    // to include checksum integrity checks. Maybe some other day.)
    for (size_t i = 0; i < byte_c; i++) {
        rs_w_uint8(rs, 255 - i % 256);
    }
    send_somewhere(rs, s, cb_has_cur);
    byte_c = RS_TEST_INCR_MSG_BYTE_C(byte_c);
    byte_c %= s->max_msg_byte_c;
}

rs_test_ret init_cb(
    rs_t * rs
) {
    struct rs_conf const * conf = rs_get_conf(rs);
    struct rs_stress * s = rs_get_app_data(rs);
    s->max_msg_byte_c = conf->max_ws_msg_size;
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
            return RS_TEST_OK;
        }
    }
    // Close client if too many test clients are already connected.
    return RS_TEST_TOO_MANY_CLIENTS;
}

int read_cb(
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
    RS_LOG(LOG_DEBUG,"Validated a %zu byte message from a client.");
    return RS_TEST_OK;
}

int close_cb(
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

int timer_cb(
    rs_t * rs
) {
    struct rs_stress * s = rs_get_app_data(rs);
    if (s->client_c) {
        send_something(rs, s, false);
    }
    return 1000000;
}

RS_APP(
    RS_INIT(init_cb, sizeof(struct rs_stress)),
    RS_OPEN(open_cb),
    RS_READ_BIN(read_cb, RS_NET_STA(uint8_t, 0, RS_TEST_MAX_READ_MSG_BYTE_C)),
    RS_CLOSE(close_cb),
    RS_TIMER_WAKE(timer_cb, 1000000)
);
