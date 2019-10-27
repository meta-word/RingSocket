// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include "rs_event.h" // set_shutdown_deadline()
#include "rs_hash.h" // get_websocket_key_hash()
#include "rs_http.h"
#include "rs_tcp.h" // read_tcp(), write_tcp()
#include "rs_tls.h" // read_tls(), write_tls()
#include "rs_util.h" // get_addr_str()

enum http_error_index {
    RS_HTTP_BAD_REQUEST = 0,
    RS_HTTP_FORBIDDEN = 1,
    RS_HTTP_NOT_FOUND = 2,
    RS_HTTP_METHOD_NOT_ALLOWED = 3
}; // This enum is used by write_http_error_response() as index to this array:
static char const * http_errors[] = {
    "HTTP/1.1 400 \r\n\r\n",
    "HTTP/1.1 403 \r\n\r\n",
    "HTTP/1.1 404 \r\n\r\n",
    "HTTP/1.1 405 \r\n\r\n"
};

static rs_ret read_http(
    struct rs_worker * worker,
    union rs_peer * peer,
    size_t jump_distance,
    char * * unsaved_str,
    char * * ch,
    char * * ch_over,
    char * wskey
) {
    char * rbuf = (char *) worker->rbuf;
    // To read as much as possible in one go (and to stay in the same cache
    // area), the 1st byte of the upcoming new read will be placed at the start
    // of rbuf, or at that start plus an offset as required to accomodate
    // prefixing the new read with any unsaved_str.
    size_t unsaved_strlen = 0;
    if (*unsaved_str) {
        unsaved_strlen = *ch - *unsaved_str;
        if (*unsaved_str != rbuf) {
            memmove(rbuf, unsaved_str, unsaved_strlen);
            *unsaved_str = rbuf;
            *ch = rbuf + unsaved_strlen;
        }
    } else {
        *ch = rbuf;
    }
    size_t rsize = 0;
    rs_ret ret = peer->is_encrypted ?
        read_tls(worker, peer,
            *ch, worker->conf->worker_rbuf_size - unsaved_strlen, &rsize) :
        read_tcp(peer,
            *ch, worker->conf->worker_rbuf_size - unsaved_strlen, &rsize);
    *ch_over = *ch + rsize;
    //RS_LOG(LOG_DEBUG, "Read HTTP from peer %s: %.*s",
    //            get_addr_str(peer), (int) rsize, *ch);
    if (ret != RS_AGAIN) {
        return ret;
    }
    // Store parsing state in the peer union to allow resumption later on.
    peer->http.jump_distance = jump_distance;
    if (unsaved_strlen) {
        // peer->http.partial_strlen is an uint16_t, which should be plenty;
        // but even in the event of an overflow, the worst that could happen is
        // for the HTTP contents to be rejected and the peer to be disconnected
        // (due to the fact that unsigned types are guaranteed to wrap around on
        // overflow).
        peer->http.partial_strlen = unsaved_strlen;
        if (peer->http.char_buf == wskey) {
            RS_REALLOC(peer->http.char_buf, 22 + unsaved_strlen);
            memcpy(peer->http.char_buf + 22, unsaved_str, unsaved_strlen);
        } else if (wskey) {
            RS_CALLOC(peer->http.char_buf, 22 + unsaved_strlen);
            memcpy(peer->http.char_buf, wskey, 22);
            memcpy(peer->http.char_buf + 22, unsaved_str, unsaved_strlen);
        } else {
            RS_CALLOC(peer->http.char_buf, unsaved_strlen);
            memcpy(peer->http.char_buf, unsaved_str, unsaved_strlen);
        }
    } else if (wskey && wskey != peer->http.char_buf) {
        RS_CALLOC(peer->http.char_buf, 22);
        memcpy(peer->http.char_buf, wskey, 22);
    }
    return RS_AGAIN;
}

static rs_ret match_hostname(
    struct rs_conf const * conf,
    union rs_peer * peer,
    char * hostname, // not 0-terminated
    size_t hostname_strlen,
    bool url_was_parsed
) {
    // Attempt to find the 1st endpoint hostname match accross all apps and
    // endpoints at an index position equal to or greater than that of the
    // endpoint currently referenced by the peer. Depending on the boolean
    // states of url_was_parsed and peer->http.origin_was_parsed, any endpoint
    // other than the current endpoint that matches the hostname must also match
    // the url and/or origin respectively that the current endpoint references.
    struct rs_conf_app * app = conf->apps + peer->app_i;
    // The currently referenced endpoint
    struct rs_conf_endpoint * endpoint = app->endpoints + peer->endpoint_i;
    if (!strncmp(endpoint->hostname, hostname, hostname_strlen) &&
        endpoint->is_encrypted == peer->is_encrypted) {
        peer->http.hostname_was_parsed = true;
        return RS_OK;
    }
    char * url = endpoint->url;
    char * origin = endpoint->allowed_origin_c ?
        endpoint->allowed_origins[peer->http.origin_i] : NULL;
    // The current endpoint did not match the hostname. Try remaining candidates
    for (;;) {
        while (++endpoint < app->endpoints + app->endpoint_c) {
            if (!strncmp(endpoint->hostname, hostname, hostname_strlen) &&
                endpoint->is_encrypted == peer->is_encrypted &&
                !(url_was_parsed && strcmp(endpoint->url, url))) {
                if (!peer->http.origin_was_parsed) {
                    peer->app_i = app - conf->apps;
                    peer->endpoint_i = endpoint - app->endpoints;
                    peer->http.hostname_was_parsed = true;
                    return RS_OK;
                }
                for (size_t i = 0; i < endpoint->allowed_origin_c; i++) {
                    if (!strcmp(endpoint->allowed_origins[i], origin)) {
                        peer->app_i = app - conf->apps;
                        peer->endpoint_i = endpoint - app->endpoints;
                        peer->http.origin_i = i;
                        peer->http.hostname_was_parsed = true;
                        return RS_OK;
                    }
                }
            }
        }
        if (++app >= conf->apps + conf->app_c) {
            RS_LOG(LOG_NOTICE, "Failing peer %s: unrecognized hostname: %.*s",
                get_addr_str(peer), (int) hostname_strlen, hostname);
            return RS_CLOSE_PEER;
        }
        endpoint = app->endpoints;
    }
}

static rs_ret match_url(
    struct rs_conf const * conf,
    union rs_peer * peer,
    char * url, // not 0-terminated
    size_t url_strlen
) {
    // Attempt to find the 1st endpoint url match accross all apps and endpoints
    // at an index position equal to or greater than that of the endpoint
    // currently referenced by the peer. If peer->http.hostname_was_parsed is
    // true, any endpoint other than the current endpoint that matches the url
    // must also match the hostname the current endpoint references.
    struct rs_conf_app * app = conf->apps + peer->app_i;
    // The currently referenced endpoint
    struct rs_conf_endpoint * endpoint = app->endpoints + peer->endpoint_i;
    if (!strncmp(endpoint->url, url, url_strlen) &&
        endpoint->is_encrypted == peer->is_encrypted) {
        return RS_OK;
    }
    char * hostname = endpoint->hostname;
    // The current endpoint did not match the url. Try remaining candidates.
    for (;;) {
        while (++endpoint < app->endpoints + app->endpoint_c) {
            if (!strncmp(endpoint->url, url, url_strlen) &&
                endpoint->is_encrypted == peer->is_encrypted &&
                !(peer->http.hostname_was_parsed &&
                strcmp(endpoint->hostname, hostname))) {
                peer->app_i = app - conf->apps;
                peer->endpoint_i = endpoint - app->endpoints;
                return RS_OK;
            }
        }
        if (++app >= conf->apps + conf->app_c) {
            RS_LOG(LOG_NOTICE, "Failing peer %s: unrecognized url: %.*s",
                get_addr_str(peer), (int) url_strlen, url);
            return RS_CLOSE_PEER;
        }
        endpoint = app->endpoints;
    }
}

static bool match_origin(
    struct rs_conf const * conf,
    union rs_peer * peer,
    char * origin, // not 0-terminated
    size_t origin_strlen
) {
    // Attempt to find the 1st endpoint origin match accross all apps and
    // endpoints at an index position equal to or greater than that of the
    // endpoint currently referenced by the peer. Any endpoint other than the
    // current endpoint that matches the origin must also match the url the
    // current endpoint references; and if peer->hostname_was_parsed is true,
    // then the hostname as well.
    struct rs_conf_app * app = conf->apps + peer->app_i;
    // The currently referenced endpoint
    struct rs_conf_endpoint * endpoint = app->endpoints + peer->endpoint_i;
    if (endpoint->is_encrypted == peer->is_encrypted) {
        for (size_t i = 0; i < endpoint->allowed_origin_c; i++) {
            if (!strncmp(endpoint->allowed_origins[i], origin, origin_strlen)) {
                peer->http.origin_i = i;
                peer->http.origin_was_parsed = true;
                return RS_OK;
            }
        }
    }
    char * hostname = endpoint->hostname;
    char * url = endpoint->url;
    // The current endpoint did not match the origin. Try remaining candidates.
    for (;;) {
        while (++endpoint < app->endpoints + app->endpoint_c) {
            if (endpoint->is_encrypted == peer->is_encrypted &&
                !strcmp(endpoint->url, url) && 
                !(peer->http.hostname_was_parsed &&
                strcmp(endpoint->hostname, hostname))) {
                for (size_t i = 0; i < endpoint->allowed_origin_c; i++) {
                    if (!strcmp(endpoint->allowed_origins[i], origin)) {
                        peer->app_i = app - conf->apps;
                        peer->endpoint_i = endpoint - app->endpoints;
                        peer->http.origin_i = i;
                        peer->http.origin_was_parsed = true;
                        return RS_OK;
                    }
                }
            }
        }
        if (++app >= conf->apps + conf->app_c) {
            RS_LOG(LOG_NOTICE, "Failing peer %s: unrecognized origin: %.*s",
                get_addr_str(peer), (int) origin_strlen, origin);
            return RS_CLOSE_PEER;
        }
        endpoint = app->endpoints;
    }
}

// Completely re-entrant function: any attempt at parsing all the required HTTP
// data may end prematurely at any point when the end of the read buffer was
// reached and a subsequent attempt at reading more into that buffer returned
// EAGAIN. Parsing resumes at a later time when this function is called again.
//
// A naive way to make that happen would be to store incomplete HTTP sequence(s)
// in the peer union, concatenate any new read(s) to it, and just start parsing
// over again from the beginning of that byte array. This would be a wasteful
// use of memory though, given that only a tiny fraction of potentially valid
// HTTP is relevant to WebSocket HTTP Upgrade parsing. If reentrancy is instead
// guaranteed without storing the raw stream, the upper bound to the amount of
// state in need of storage becomes tiny (as evidenced by the rs_peer union).
//
// It might seem like the jump table required to accomplish that could be
// implemented a straightforward way in C with a switch statement where each
// case represents the location to jump to, accross which parsing flows normally
// from top to bottom, falling through each case, one by one. In other words, a
// giant Duff's Device. Unfortunately, it would then not be possible to use any
// nested switch statements within that outer jump switch.
//
// This function's actual implementation avoids that limitation through one
// level of (virtual) indirection: use a switch statement jump table to map to a
// corresponding goto statement, which will readily fly anywhere -- effectively
// implementing an ISO C-compliant variadic goto.
static rs_ret parse_http_upgrade_request(
    struct rs_worker * worker,
    union rs_peer * peer,
    char * * wskey
) {
    char * ch = (char *) worker->rbuf; // the character currently being parsed
    char * ch_over = ch; // pointer to the 1st out-of-read-bounds rbuf element
    // pointer to start of url/host/origin/wskey val str currently being parsed
    char * unsaved_str = NULL;
    // If the previous call to this function was broken off while in the middle
    // of parsing an unsaved_str, that partial string was stored in
    // peer->http.char_buf, and must now be copied to worker->rbuf as a prefix
    // to a new read().
    if (peer->http.partial_strlen) {
        if (peer->http.wskey_was_parsed) {
            *wskey = peer->http.char_buf;
            memcpy(worker->rbuf, peer->http.char_buf + 22,
                peer->http.partial_strlen);
        } else {
            memcpy(worker->rbuf, peer->http.char_buf,
                peer->http.partial_strlen);
            RS_FREE(peer->http.char_buf);
        }
        ch += peer->http.partial_strlen;
        ch_over = ch;
        unsaved_str = (char *) worker->rbuf;
        peer->http.partial_strlen = 0;
    }
    // The above-mentioned case<->goto label mapping jump table switch:
    // RS_MACRIFY_EACH inserts the RS_H_JUMP macro into this switch for each
    // distance number provided, 0 through 95; powered by rs_variadic.h.
    switch (peer->http.jump_distance) {
#define RS_H_JUMP(distance) case distance: goto RS_H_##distance
    RS_APPLY_EACH(RS_H_JUMP,   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11,
        12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
        66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83,
        84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95);
#undef RS_H_JUMP
    default:
        RS_LOG(LOG_CRIT, "Invalid peer->http.jump_distance: %" PRIu8 ". "
            "This shouldn't be possible.", peer->http.jump_distance);
        return RS_FATAL;
    }
    // RS_H_GETCH must be called whenever another char needs to be read.
#define RS_H_GETCH(jump_distance) do { \
    RS_H_##jump_distance: \
    if (++ch >= ch_over) { \
        RS_GUARD(read_http(worker, peer, jump_distance, &unsaved_str, &ch, \
            &ch_over, *wskey)); \
    } \
} while (0)
    // Often repeated parsing procedures are implemented as nice 'n ugly macros
#define RS_H_ERR(http_err_i) do { \
    peer->http.error_i = (http_err_i); \
    peer->mortality = RS_MORTALITY_SHUTDOWN_WRITE; \
    return RS_CLOSE_PEER; \
} while (0)
#define RS_H_CH(ascii) (*ch == (ascii))
#define RS_H_ICH(ascii) (*ch == (ascii) || *ch == (ascii) + 32) // takes upper
#define RS_H_IFNOT_CH_ERR(ascii, http_err_i) do { \
    if (!RS_H_CH(ascii)) { \
        RS_H_ERR(http_err_i); \
    } \
} while (0)
#define RS_H_IFNOT_ICH_ERR(ascii, http_err_i) do { /* ascii must be upper */ \
    if (!RS_H_ICH(ascii)) { \
        RS_H_ERR(http_err_i); \
    } \
} while (0)
#define RS_H_SKIP_OPTIONAL_WHITESPACE(uint8) do { \
    while (*ch == ' ' || *ch == '\t') { \
        RS_H_GETCH(uint8); \
    } \
} while (0)
#define RS_H_GETCH_AND_SKIP_OPTIONAL_WHITESPACE(uint8) do { \
    RS_H_GETCH(uint8); \
} while (*ch == ' ' || *ch == '\t')
    // Alright, let's actually start parsing some HTTP now...

    // RFC7230#section-3.1.1: request method is case-sensitive (uppercase)
    RS_H_GETCH(0); RS_H_IFNOT_CH_ERR('G', RS_HTTP_METHOD_NOT_ALLOWED);
    RS_H_GETCH(1); RS_H_IFNOT_CH_ERR('E', RS_HTTP_BAD_REQUEST);
    RS_H_GETCH(2); RS_H_IFNOT_CH_ERR('T', RS_HTTP_BAD_REQUEST);
    RS_H_GETCH(3); RS_H_IFNOT_CH_ERR(' ', RS_HTTP_BAD_REQUEST);
    RS_H_GETCH(4);
    if (*ch != '/') {
        // RFC7230#section-5.3.2: "To allow for transition to the absolute-form
        // for all requests in some future version of HTTP, a server MUST accept
        // the absolute-form in requests, even though HTTP/1.1 clients will only
        // send them in requests to proxies."

        // RFC3986#section-3.1: scheme names (e.g. "http") are case-insensitive
        switch (*ch) {
        case 'H': case 'h': // "http(s)://"
            RS_H_GETCH(5); RS_H_IFNOT_ICH_ERR('T', RS_HTTP_BAD_REQUEST);
            RS_H_GETCH(6); RS_H_IFNOT_ICH_ERR('T', RS_HTTP_BAD_REQUEST);
            RS_H_GETCH(7); RS_H_IFNOT_ICH_ERR('P', RS_HTTP_BAD_REQUEST);
            break;
        case 'W': case 'w': // "ws(s)://"
            RS_H_GETCH(8); RS_H_IFNOT_ICH_ERR('S', RS_HTTP_BAD_REQUEST);
            break;
        default:
            RS_H_ERR(RS_HTTP_BAD_REQUEST);
        }
        RS_H_GETCH(9);
        if (RS_H_ICH('S')) {
            if (!peer->is_encrypted) {
                RS_H_ERR(RS_HTTP_BAD_REQUEST);
            }
            RS_H_GETCH(10);
        } else if (peer->is_encrypted) {
            RS_H_ERR(RS_HTTP_BAD_REQUEST);
        }
        RS_H_IFNOT_CH_ERR(':', RS_HTTP_BAD_REQUEST);
        RS_H_GETCH(11); RS_H_IFNOT_CH_ERR('/', RS_HTTP_BAD_REQUEST);
        RS_H_GETCH(12); RS_H_IFNOT_CH_ERR('/', RS_HTTP_BAD_REQUEST);
        RS_H_GETCH(13); unsaved_str = ch;
        while (*ch != '/') {
            if (*ch == ' ') { // a top-level absolute-form URI
                if (match_hostname(worker->conf, peer, unsaved_str,
                    ch - unsaved_str, false) != RS_OK) {
                    RS_H_ERR(RS_HTTP_BAD_REQUEST);
                }
                unsaved_str = NULL;
                goto parse_http_version;
            }
            if (ch >= unsaved_str + worker->conf->hostname_max_strlen) {
                RS_H_ERR(RS_HTTP_BAD_REQUEST);
            }
            RS_H_GETCH(14);
        }
        if (match_hostname(worker->conf, peer, unsaved_str, ch - unsaved_str,
            false) != RS_OK) {
            RS_H_ERR(RS_HTTP_BAD_REQUEST);
        }
        unsaved_str = NULL;
    }
    RS_H_GETCH(15); unsaved_str = ch;
    while (*ch != ' ') {
        if (*ch == '?' || *ch == '#') {
            RS_H_ERR(RS_HTTP_NOT_FOUND);
        }
        RS_H_GETCH(16);
        if (ch > unsaved_str + worker->conf->url_max_strlen) {
            RS_LOG(LOG_NOTICE, "Failing peer %s: length of \"%.*s\" exceeds "
                "the longest configured url's size %zu by %zu byte(s)",
                get_addr_str(peer), (int) (ch - unsaved_str), unsaved_str,
                worker->conf->url_max_strlen,
                ch - unsaved_str - worker->conf->url_max_strlen);
            RS_H_ERR(RS_HTTP_NOT_FOUND);
        }
    }
    if (match_url(worker->conf, peer, unsaved_str, ch - unsaved_str) != RS_OK) {
        RS_H_ERR(RS_HTTP_NOT_FOUND);
    }
    unsaved_str = NULL;
    parse_http_version:
    RS_H_GETCH(17); RS_H_IFNOT_CH_ERR('H', RS_HTTP_BAD_REQUEST);
    RS_H_GETCH(18); RS_H_IFNOT_CH_ERR('T', RS_HTTP_BAD_REQUEST);
    RS_H_GETCH(19); RS_H_IFNOT_CH_ERR('T', RS_HTTP_BAD_REQUEST);
    RS_H_GETCH(20); RS_H_IFNOT_CH_ERR('P', RS_HTTP_BAD_REQUEST);
    RS_H_GETCH(21); RS_H_IFNOT_CH_ERR('/', RS_HTTP_BAD_REQUEST);
    RS_H_GETCH(22); RS_H_IFNOT_CH_ERR('1', RS_HTTP_BAD_REQUEST);
    RS_H_GETCH(23); RS_H_IFNOT_CH_ERR('.', RS_HTTP_BAD_REQUEST);
    RS_H_GETCH(24); RS_H_IFNOT_CH_ERR('1', RS_HTTP_BAD_REQUEST);
    RS_H_GETCH(25);
    parse_carriage_return:
    RS_H_IFNOT_CH_ERR('\r', RS_HTTP_BAD_REQUEST);
    parse_line_feed:
    RS_H_GETCH(26); RS_H_IFNOT_CH_ERR('\n', RS_HTTP_BAD_REQUEST);
    RS_H_GETCH(27); switch (*ch) {
    case '\r':
        RS_H_GETCH(28); RS_H_IFNOT_CH_ERR('\n', RS_HTTP_BAD_REQUEST);
        if (peer->http.hostname_was_parsed &&
            peer->http.upgrade_was_parsed &&
            peer->http.wskey_was_parsed &&
            peer->http.wsversion_was_parsed) {
            return RS_OK;
        }
        RS_H_ERR(RS_HTTP_BAD_REQUEST);
    // RFC7230#section-3.2: Field names are case-insensitive
    case 'C': case 'c':
        RS_H_GETCH(29); if (!RS_H_ICH('O')) break;
        RS_H_GETCH(30); if (!RS_H_ICH('N')) break;
        RS_H_GETCH(31); if (!RS_H_ICH('N')) break;
        RS_H_GETCH(32); if (!RS_H_ICH('E')) break;
        RS_H_GETCH(33); if (!RS_H_ICH('C')) break;
        RS_H_GETCH(34); if (!RS_H_ICH('T')) break;
        RS_H_GETCH(35); if (!RS_H_ICH('I')) break;
        RS_H_GETCH(36); if (!RS_H_ICH('O')) break;
        RS_H_GETCH(37); if (!RS_H_ICH('N')) break;
        RS_H_GETCH(38); if (!RS_H_CH(':')) break;
        // CONNECTION may include comma-separated values other than UPGRADE, so
        // skip of those with "skip_this_conn_value" and "parse_next_conn_value"
        parse_next_conn_value: RS_H_GETCH_AND_SKIP_OPTIONAL_WHITESPACE(39);
        if (!RS_H_ICH('U')) goto skip_this_conn_value;
        RS_H_GETCH(40); if (!RS_H_ICH('P')) goto skip_this_conn_value;
        RS_H_GETCH(41); if (!RS_H_ICH('G')) goto skip_this_conn_value;
        RS_H_GETCH(42); if (!RS_H_ICH('R')) goto skip_this_conn_value;
        RS_H_GETCH(43); if (!RS_H_ICH('A')) goto skip_this_conn_value;
        RS_H_GETCH(44); if (!RS_H_ICH('D')) goto skip_this_conn_value;
        RS_H_GETCH(45); if (!RS_H_ICH('E')) goto skip_this_conn_value;
        RS_H_GETCH_AND_SKIP_OPTIONAL_WHITESPACE(46);
        if (RS_H_CH('\r')) {
            peer->http.upgrade_was_parsed = true;
            goto parse_line_feed;
        }
        if (RS_H_CH(',')) {
            peer->http.upgrade_was_parsed = true;
            break;
        }
        skip_this_conn_value:
        if (RS_H_ICH(',')) goto parse_next_conn_value;
        if (RS_H_ICH('\r')) goto parse_line_feed;
        RS_H_GETCH(47);
        goto skip_this_conn_value;
    case 'H': case 'h':
        RS_H_GETCH(48); if (!RS_H_ICH('O')) break;
        RS_H_GETCH(49); if (!RS_H_ICH('S')) break;
        RS_H_GETCH(50); if (!RS_H_ICH('T')) break;
        RS_H_GETCH(51); if (!RS_H_ICH(':')) break;
        RS_H_GETCH_AND_SKIP_OPTIONAL_WHITESPACE(52);
        unsaved_str = ch;
        while (*ch != '\r' && *ch != ' ' && *ch != '\t') {
            if (ch >= unsaved_str + worker->conf->hostname_max_strlen) {
                RS_LOG(LOG_NOTICE, "Failing peer %s: Length of \"%.*s\" "
                    "exceeds the longest hostname's size %zu by %zu byte(s)",
                    get_addr_str(peer), (int) (ch - unsaved_str), unsaved_str,
                    worker->conf->hostname_max_strlen,
                    ch - unsaved_str - worker->conf->hostname_max_strlen);
                RS_H_ERR(RS_HTTP_BAD_REQUEST);
            }
            RS_H_GETCH(53);
        }
        if (match_hostname(worker->conf, peer, unsaved_str, ch - unsaved_str,
            true) != RS_OK) {
            RS_H_ERR(RS_HTTP_BAD_REQUEST);
        }
        unsaved_str = NULL;
        RS_H_SKIP_OPTIONAL_WHITESPACE(54);
        goto parse_carriage_return;
    case 'O': case 'o':
        RS_H_GETCH(55); if (!RS_H_ICH('R')) break;
        RS_H_GETCH(56); if (!RS_H_ICH('I')) break;
        RS_H_GETCH(57); if (!RS_H_ICH('G')) break;
        RS_H_GETCH(58); if (!RS_H_ICH('I')) break;
        RS_H_GETCH(59); if (!RS_H_ICH('N')) break;
        RS_H_GETCH(60); if (!RS_H_ICH(':')) break;
        RS_H_GETCH_AND_SKIP_OPTIONAL_WHITESPACE(61);
        unsaved_str = ch;
        while (*ch != '\r' && *ch != ' ' && *ch != '\t') {
            if (ch >= unsaved_str + worker->conf->allowed_origin_max_strlen) {
                RS_LOG(LOG_NOTICE, "Failing peer %s: length of \"%.*s\" "
                    "exceeds the longest allowed origin's size %zu by %zu "
                    "byte(s)", get_addr_str(peer), (int) (ch - unsaved_str),
                    unsaved_str, worker->conf->allowed_origin_max_strlen,
                    ch - unsaved_str - worker->conf->allowed_origin_max_strlen);
                RS_H_ERR(RS_HTTP_FORBIDDEN);
            }
            RS_H_GETCH(62);
        }
        if (match_origin(worker->conf, peer, unsaved_str, ch - unsaved_str) !=
            RS_OK) {
            RS_H_ERR(RS_HTTP_FORBIDDEN);
        }
        unsaved_str = NULL;
        RS_H_SKIP_OPTIONAL_WHITESPACE(63);
        goto parse_carriage_return;
    case 'S': case 's':
        RS_H_GETCH(64); if (!RS_H_ICH('E')) break;
        RS_H_GETCH(65); if (!RS_H_ICH('C')) break;
        RS_H_GETCH(66); if (!RS_H_CH('-')) break;
        RS_H_GETCH(67); if (!RS_H_ICH('W')) break;
        RS_H_GETCH(68); if (!RS_H_ICH('E')) break;
        RS_H_GETCH(69); if (!RS_H_ICH('B')) break;
        RS_H_GETCH(70); if (!RS_H_ICH('S')) break;
        RS_H_GETCH(71); if (!RS_H_ICH('O')) break;
        RS_H_GETCH(72); if (!RS_H_ICH('C')) break;
        RS_H_GETCH(73); if (!RS_H_ICH('K')) break;
        RS_H_GETCH(74); if (!RS_H_ICH('E')) break;
        RS_H_GETCH(75); if (!RS_H_ICH('T')) break;
        RS_H_GETCH(76); if (!RS_H_CH('-')) break;
        RS_H_GETCH(77); switch (*ch) {
        case 'K': case 'k':
            RS_H_GETCH(78); if (!RS_H_ICH('E')) break;
            RS_H_GETCH(79); if (!RS_H_ICH('Y')) break;
            RS_H_GETCH(80); if (!RS_H_CH(':')) break;
            RS_H_GETCH_AND_SKIP_OPTIONAL_WHITESPACE(81);
            unsaved_str = ch;
            do {
                // check if Base64
                if (!((*ch >= 'A' && *ch <= 'Z') ||
                    (*ch >= 'a' && *ch <= 'z') ||
                    (*ch >= '0' && *ch <= '9') || *ch == '+' || *ch == '/')) {
                    RS_H_ERR(RS_HTTP_BAD_REQUEST);
                }
                RS_H_GETCH(82);
            } while (ch < unsaved_str + 22);
            RS_H_IFNOT_CH_ERR('=', RS_HTTP_BAD_REQUEST);
            RS_H_GETCH(83); RS_H_IFNOT_CH_ERR('=', RS_HTTP_BAD_REQUEST);
            peer->http.wskey_was_parsed = true;
            *wskey = unsaved_str;
            unsaved_str = NULL;
            RS_H_GETCH_AND_SKIP_OPTIONAL_WHITESPACE(84);
            goto parse_carriage_return;
        case 'V': case 'v':
            RS_H_GETCH(85); if (!RS_H_ICH('E')) break;
            RS_H_GETCH(86); if (!RS_H_ICH('R')) break;
            RS_H_GETCH(87); if (!RS_H_ICH('S')) break;
            RS_H_GETCH(88); if (!RS_H_ICH('I')) break;
            RS_H_GETCH(89); if (!RS_H_ICH('O')) break;
            RS_H_GETCH(90); if (!RS_H_ICH('N')) break;
            RS_H_GETCH(91); if (!RS_H_CH(':')) break;
            RS_H_GETCH_AND_SKIP_OPTIONAL_WHITESPACE(92);
            RS_H_IFNOT_CH_ERR('1', RS_HTTP_BAD_REQUEST);
            RS_H_GETCH(93); RS_H_IFNOT_CH_ERR('3', RS_HTTP_BAD_REQUEST);
            RS_H_GETCH_AND_SKIP_OPTIONAL_WHITESPACE(94);
            peer->http.wsversion_was_parsed = true;
            goto parse_carriage_return;
        }
    default:
        break;
    }
    while (!RS_H_CH('\r')) {
        RS_H_GETCH(95);
    }
    goto parse_line_feed;
}

static rs_ret write_http_upgrade_response(
    struct rs_worker * worker,
    union rs_peer * peer,
    char * wskey
) {
    thread_local static char http101[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: upgrade\r\n"
        "Sec-WebSocket-Accept: 123456789012345678901234567=\r\n"
        "\r\n";
    char * const wskey_hash_dest = http101 + RS_CONST_STRLEN(http101) -
        RS_CONST_STRLEN("=\r\n\r\n") - 27;
    if (wskey) {
        RS_GUARD(get_websocket_key_hash(worker, wskey, wskey_hash_dest));
    } else {
        memcpy(wskey_hash_dest, peer->http.char_buf, 27);
    }
    rs_ret ret = peer->is_encrypted ?
        write_tls(worker, peer, http101, RS_CONST_STRLEN(http101)) :
                write_tcp(peer, http101, RS_CONST_STRLEN(http101));
    switch (ret) {
    case RS_OK:
        if (peer->http.char_buf) {
            RS_FREE(peer->http.char_buf);
        }
        return RS_OK;
    case RS_AGAIN:
        if (wskey) {
            if (peer->http.char_buf) {
                RS_REALLOC(peer->http.char_buf, 27);
            } else {
                RS_CALLOC(peer->http.char_buf, 27);
            }
            memcpy(peer->http.char_buf, wskey_hash_dest, 27);
        }
        return RS_AGAIN;
    default:
        return ret;
    }
}

static rs_ret write_http_error_response(
    struct rs_worker * worker,
    union rs_peer * peer
) {
    unsigned error_i = RS_MAX(peer->http.error_i, 3);
    RS_LOG(LOG_NOTICE, "Writing HTTP_%s) to peer %s",
        (char *[]){"BAD_REQUEST (400", "FORBIDDEN (403", "NOT_FOUND (404",
        "METHOD_NOT_ALLOWED (405"}[error_i],
        get_addr_str(peer));
    char const * msg = http_errors[error_i];
    return peer->is_encrypted ?
        write_tls(worker, peer, msg, RS_CONST_STRLEN(msg)) :
                write_tcp(peer, msg, RS_CONST_STRLEN(msg));
}

rs_ret handle_http_io(
    struct rs_worker * worker,
    union rs_peer * peer
) {
    char * wskey = NULL;
    switch (peer->mortality) {
    case RS_MORTALITY_LIVE:
        switch (peer->continuation) {
        case RS_CONT_NONE:
        case RS_CONT_PARSING:
            switch (parse_http_upgrade_request(worker, peer, &wskey)) {
            case RS_OK:
                goto write_http_upgrade;
            case RS_AGAIN:
                peer->continuation = RS_CONT_PARSING;
                return RS_OK;
            case RS_CLOSE_PEER:
                if (peer->http.char_buf) {
                    RS_FREE(peer->http.char_buf);
                }
                if (peer->mortality == RS_MORTALITY_SHUTDOWN_WRITE) {
                    goto write_http_error;
                }
                break;
            case RS_FATAL: default:
                return RS_FATAL;
            }
            break;
        case RS_CONT_SENDING: default:
            write_http_upgrade:
            switch (write_http_upgrade_response(worker, peer, wskey)) {
            case RS_OK:
                // Keep shared peer union members as-is, but reset all
                // http/ws-specific union members to 0.
                memset(peer->layer_specific_data, 0,
                    sizeof(peer->layer_specific_data));
                // todo: flush read buffer
                peer->continuation = RS_CONT_NONE;
                peer->layer = RS_LAYER_WEBSOCKET;
                return RS_OK;
            case RS_AGAIN:
                peer->continuation = RS_CONT_SENDING;
                return RS_OK;
            case RS_CLOSE_PEER:
                break;
            case RS_FATAL: default:
                return RS_FATAL;
            }
        }
        break;
    case RS_MORTALITY_SHUTDOWN_WRITE:
        write_http_error:
        switch (write_http_error_response(worker, peer)) {
        case RS_OK:
            // Keep peer->mortality at RS_MORTALITY_SHUTDOWN_WRITE because
            // the next thing will be write_bidirectional_(tls/tcp)_shutdown().
            peer->layer = peer->is_encrypted ? RS_LAYER_TLS : RS_LAYER_TCP;
            set_shutdown_deadline(peer, worker->conf->shutdown_wait_http);
            return RS_OK;
        case RS_AGAIN:
            peer->continuation = RS_CONT_SENDING;
            return RS_OK;
        case RS_CLOSE_PEER:
            break;
        case RS_FATAL: default:
            return RS_FATAL;
        }
        break;
    default:
        break;
    }
    if (peer->http.char_buf) {
        RS_FREE(peer->http.char_buf);
    }
    peer->mortality = RS_MORTALITY_DEAD;
    peer->layer = peer->is_encrypted ? RS_LAYER_TLS : RS_LAYER_TCP;
    return RS_OK;
}
