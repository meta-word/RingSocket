// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include <ringsocket.h>

#define RS_TEST_MAX_READ_MSG_BYTE_C 0x1000000 // 16 MB
#define RS_TEST_MAX_CLIENT_C 1000

typedef enum {
    RS_TEST_FATAL = -1,
    RS_TEST_OK = 0,
    RS_TEST_TOO_MANY_CLIENTS = 4000,
    RS_TEST_BAD_MSG = 4001
} rs_test_ret;

struct rs_stress {
    uint64_t max_content_size;
    uint64_t content_size;
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
    dst[2] += dst[2] == dst[0];
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
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_every()",
                s->content_size);
            rs_to_every(rs, RS_BIN);
            break;
        case 1:
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_single()",
                s->content_size);
            rs_to_single(rs, RS_BIN, get_nth_client_id(s, 0));
            break;
        case 2:
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_cur()", s->content_size);
            rs_to_cur(rs, RS_BIN);
        }
        break;
    case 2:
        switch (randrange(6 + 2 * cb_has_cur)) {
        case 0:
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_every()",
                s->content_size);
            rs_to_every(rs, RS_BIN);
            break;
        case 1:
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to client #0",
                s->content_size);
            rs_to_single(rs, RS_BIN, get_nth_client_id(s, 0));
            break;
        case 2:
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to client #1",
                s->content_size);
            rs_to_single(rs, RS_BIN, get_nth_client_id(s, 1));
            break;
        case 3:
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to both clients",
                s->content_size);
            rs_to_multi(rs, RS_BIN, (uint64_t []){get_nth_client_id(s, 0),
                get_nth_client_id(s, 1)}, 2);
            break;
        case 4:
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to client !#0",
                s->content_size);
            rs_to_every_except_single(rs, RS_BIN, get_nth_client_id(s, 0));
            break;
        case 5:
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to client !#1",
                s->content_size);
            rs_to_every_except_single(rs, RS_BIN, get_nth_client_id(s, 1));
            break;
        case 6:
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_cur()",
                s->content_size);
            rs_to_cur(rs, RS_BIN);
            break;
        case 7:
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_every_except_cur()",
                s->content_size);
            rs_to_every_except_cur(rs, RS_BIN);
        }
        break;
    default:
        switch (randrange(6 + 2 * cb_has_cur)) {
        case 0:
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_every()",
                s->content_size);
            rs_to_every(rs, RS_BIN);
            break;
        case 1:
            {
                size_t r = randrange(s->client_c);
                RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to client #%lu",
                    s->content_size, r);
                rs_to_single(rs, RS_BIN, get_nth_client_id(s, r));
            }
            break;
        case 2:
            {
                size_t r[2] = {0};
                randrange_twice(s->client_c, r);
                RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_multi() "
                    "client #%zu and #%zu", s->content_size, r[0], r[1]);
                rs_to_multi(rs, RS_BIN, (uint64_t []){
                    get_nth_client_id(s, r[0]),
                    get_nth_client_id(s, r[1])}, 2);
            }
            break;
        case 3:
            {
                size_t r[3] = {0};
                randrange_thrice(s->client_c, r);
                RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_multi() client "
                    "#%zu, #%zu and #%zu", s->content_size, r[0], r[1], r[2]);
                rs_to_multi(rs, RS_BIN, (uint64_t []){
                    get_nth_client_id(s, r[0]), get_nth_client_id(s, r[1]),
                    get_nth_client_id(s, r[2])}, 3);
            }
            break;
        case 4:
            {
                size_t r = randrange(s->client_c);
                RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_every_except() "
                    "client #%zu", s->content_size, r);
                rs_to_every_except_single(rs, RS_BIN, get_nth_client_id(s, r));
            }
            break;
        case 5:
            {
                size_t r[2] = {0};
                randrange_twice(s->client_c, r);
                RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_every_except() "
                    "client #%zu and #%zu", s->content_size, r[0], r[1]);
                rs_to_every_except_multi(rs, RS_BIN, (uint64_t []){
                    get_nth_client_id(s, r[0]), get_nth_client_id(s, r[1])}, 2);
            }
            break;
        case 6:
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_cur()", s->content_size);
            rs_to_cur(rs, RS_BIN);
            break;
        case 7:
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_every_except_cur()",
                s->content_size);
            rs_to_every_except_cur(rs, RS_BIN);
        }
    }
}

static void send_something(
    rs_t * rs,
    struct rs_stress * s,
    bool cb_has_cur
) {
    rs_w_uint64_hton(rs, s->content_size);
    // Write a cheap dumb predictable sequence of data that should nonetheless
    // function as an okay-ish signal. In other words, in the event that bytes
    // in this stream become corrupt due to a bug, they are fairly likely to
    // be distinguishable from the expected sequence. (No, I can't be bothered
    // to include checksum integrity checks. Maybe some other day.)
    for (size_t i = 0; i < s->content_size; i++) {
        rs_w_uint8(rs, 255 - i % 256);
    }
    send_somewhere(rs, s, cb_has_cur);
}

rs_test_ret remove_client_id(
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

rs_test_ret init_cb(
    rs_t * rs
) {
    struct rs_conf const * conf = rs_get_conf(rs);
    struct rs_stress * s = rs_get_app_data(rs);
    s->max_content_size = conf->max_ws_msg_size - sizeof(uint64_t);
    s->interval = 1000000; // 1 second
    RS_LOG(LOG_DEBUG, "[init_cb] s->interval: %d, s->max_content_size: %zu",
        s->interval, s->max_content_size);
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
    uint64_t declared_size,
    uint8_t * content,
    size_t content_size
) {
    (void) rs;
    if (declared_size != content_size) {
        RS_LOG(LOG_ERR, "Received a message with a declared content size of "
            "%zu despite its actual content size of %zu",
            declared_size, content_size);
        remove_client_id(rs);
        return RS_TEST_BAD_MSG;
    }
    for (size_t i = 0; i < content_size; i++) {
        if (content[i] != 255 - i % 256) { // expected to match send_something()
            RS_LOG(LOG_ERR, "Received a content byte at index %zu with a value "
                "of %" PRIu8 " instead of the expected value %" PRIu8,
                i, content[i], 255 - i % 256);
            remove_client_id(rs);
            return RS_TEST_BAD_MSG;
        }
    }
    RS_LOG(LOG_DEBUG, "Validated 8+%zu bytes of client-echoed content.",
        content_size);
    return RS_TEST_OK;
}

rs_test_ret close_cb(
    rs_t * rs
) {
    return remove_client_id(rs);
}

rs_test_ret timer_cb(
    rs_t * rs
) {
    struct rs_stress * s = rs_get_app_data(rs);
    if (s->client_c) {
        s->content_size = randrange(s->max_content_size / 10) + 1;
        send_something(rs, s, false);
    }
    return s->interval = RS_MAX(10000 /* 0.01 sec */, s->interval - 1000);
}

RS_APP(
    RS_INIT(init_cb, sizeof(struct rs_stress)),
    RS_OPEN(open_cb),
    RS_READ_BIN(read_cb, RS_NTOH(uint64_t),
        RS_NET_STA(uint8_t, 0, RS_TEST_MAX_READ_MSG_BYTE_C)),
    RS_CLOSE(close_cb),
    RS_TIMER_WAKE(timer_cb, 1000000 /* 1 sec */)
);
