// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include <ringsocket.h>
#include <stdio.h> // sprintf

#define RST_MAX_CLIENT_C 1000
#define RST_MAX_SIMUL_MSG_PER_CLIENT_C 5
#define RST_MAX_MSG_CONTENT_SIZE 0x1000000 // 16 MB
#define RST_MAX_SIMUL_TOTAL_MSG_BYTE_C 0x10000000 // 256 MB

typedef enum {
    RST_FATAL = -1,
    RST_OK = 0,
    RST_TOO_MANY_CLIENTS = 4000
} rst_ret;

struct rst_client {
    uint64_t msg_ids[RST_MAX_SIMUL_MSG_PER_CLIENT_C];
    uint64_t id;
    int msg_c;
    int port;
};

struct rst_stress {
    struct rst_client clients[RST_MAX_CLIENT_C];
    uint64_t total_msg_byte_c;
    int client_c;
    int avail_client_c;
    unsigned max_msg_content_size;
};

static struct rst_client * get_client(
    rs_t * rs,
    struct rst_stress * s
) {
    uint64_t client_id = rs_get_client_id(rs);
    for (struct rst_client * c = s->clients; c < s->clients + s->client_c;
        c++) {
        if (c->id == client_id) {
            return c;
        }
    }
    RS_LOG(LOG_ERR, "Client with ID %" PRIu64 " not found.");
    return NULL;
}

static int randrange( // Crappy randomness is OK for the purpose of this app
    int range
) {
    return (intmax_t) range * rand() / ((intmax_t) RAND_MAX + 1);
}

// Perform a Fisher-Yates shuffle over an array of clients
static void shuffle_clients(
    struct rst_client * clients,
    int client_c
) {
    if (client_c < 2) {
        return;
    }
    for (int i = client_c - 1; i; i--) {
        int j = randrange(i + 1);
        struct rst_client c = clients[j];
        clients[j] = clients[i];
        clients[i] = c;
    }
}

static uint64_t generate_random_msg_id(
    void
) {
    uint64_t msg_id = 0;
    uint16_t * quarter = (uint16_t *) &msg_id;
    *quarter++ = randrange(0x10000);
    *quarter++ = randrange(0x10000);
    *quarter++ = randrange(0x10000);
    *quarter   = randrange(0x10000);
    return msg_id;
}

static void send_anything_anywhere(
    rs_t * rs,
    struct rst_stress * s,
    struct rst_client * cur_client
) {
    if (cur_client->msg_c > RST_MAX_SIMUL_MSG_PER_CLIENT_C / 2) {
        return;
    }

    // Any clients preceding avail_clients have reached their
    // RST_MAX_SIMUL_MSG_PER_CLIENT_C and therefore are currently not available.
    // (Design-wise, unavailable clients must be kept at the head rather than
    // the tail, because newly connected clients are added to the tail, and they
    // start out as being available.)
    struct rst_client * avail_clients =
        s->clients + s->client_c - s->avail_client_c;
    shuffle_clients(avail_clients, s->avail_client_c);

    bool include_cur = (s->total_msg_byte_c + 1) % 2;
    int recipient_c = randrange(s->avail_client_c) + include_cur;
    if (!recipient_c) {
        return;
    }

    uint64_t msg_id = generate_random_msg_id();
    rs_w_uint64_hton(rs, msg_id);

    thread_local static uint64_t ids[RST_MAX_CLIENT_C] = {0};
    thread_local static char ports_str[
        RST_MAX_CLIENT_C * RS_CONST_STRLEN("12345, ")] = {0};
    {
        uint64_t * id = ids;
        char * p_str = ports_str;
        for (struct rst_client * c = avail_clients,
            * const c_over = avail_clients + recipient_c; c < c_over; c++) {
            *id++ = c->id;
            p_str += sprintf(p_str, "%d, ", c->port);
            c->msg_ids[c->msg_c++] = msg_id;
            if (c->msg_c == RST_MAX_SIMUL_MSG_PER_CLIENT_C) {
                // From here on out this client will no longer be available
                // until its msg_c decreases, so ensure that it no longer will
                // be among the avail_clients by swapping its contents with
                // avail_clients[0] and then incrementing avail_clients.
                struct rst_client c_swap = *c;
                *c = *avail_clients;
                *avail_clients++ = c_swap;
                s->avail_client_c--;
            }
        }
        p_str[-2] = '\0';
    }

    int content_size = RS_MAX(
        RST_MAX_SIMUL_TOTAL_MSG_BYTE_C - s->total_msg_byte_c, 0);
    if (content_size) {
        content_size = randrange(
            RS_MIN(content_size / recipient_c, s->max_msg_content_size)
        );
    }
    rs_w_uint64_hton(rs, content_size);
    // Write a cheap predictable sequence of data that should nonetheless
    // function as an okay-ish signal. In other words, in the event that bytes
    // in this stream become corrupt due to a bug, they are fairly likely to
    // be distinguishable from the expected sequence.
    for (int i = 0; i < content_size; i++) {
        rs_w_uint8(rs, 255 - i % 256);
    }
    s->total_msg_byte_c += recipient_c * (16 + content_size);
    
    if (recipient_c > (s->client_c + 1) / 2) {
        if (recipient_c == s->client_c) {
            RS_LOG(LOG_DEBUG, "Sending 16+%zu bytes to_every[%s]",
                content_size, ports_str);
            rs_to_every(rs, RS_BIN);
        } else if (recipient_c == s->client_c - 1) {
            if (include_cur) {
                RS_LOG(LOG_DEBUG, "Sending 16+%zu bytes "
                    "to_every_except_single[%s]", content_size, ports_str);
                rs_to_every_except_single(rs, RS_BIN, ids[recipient_c]);
            } else {
                RS_LOG(LOG_DEBUG, "Sending 16+%zu bytes "
                    "to_every_except_cur[%s]", content_size, ports_str);
                rs_to_every_except_cur(rs, RS_BIN);
            }
        } else {
            RS_LOG(LOG_DEBUG, "Sending 16+%zu bytes to_every_except_multi[%s]",
                content_size, ports_str);
            rs_to_every_except_multi(rs, RS_BIN, ids + recipient_c,
                s->client_c - recipient_c);
        }
    } else {
        if (recipient_c == 1) {
            if (include_cur) {
                RS_LOG(LOG_DEBUG, "Sending 16+%zu bytes to_cur[%s]",
                    content_size, ports_str);
                rs_to_cur(rs, RS_BIN);
            } else {
                RS_LOG(LOG_DEBUG, "Sending 16+%zu bytes to_single[%s]",
                    content_size, ports_str);
                rs_to_single(rs, RS_BIN, ids[0]);
            }
        } else {
            RS_LOG(LOG_DEBUG, "Sending 16+%zu bytes to_multi[%s]",
                content_size, ports_str);
            rs_to_multi(rs, RS_BIN, ids, recipient_c);
        }
    }
}

rst_ret init_cb(
    rs_t * rs
) {
    struct rs_conf const * conf = rs_get_conf(rs);
    struct rst_stress * s = rs_get_app_data(rs);
    s->max_msg_content_size = RS_MIN(conf->max_ws_msg_size - sizeof(uint64_t),
        RST_MAX_MSG_CONTENT_SIZE);
    RS_LOG(LOG_DEBUG, "s->max_msg_content_size: %zu", s->max_msg_content_size);
    // Feed some quasi-crappy seed to quasi-crappy rand().
    srand((unsigned) time(NULL));
    return RST_OK;
}

rst_ret open_cb(
    rs_t * rs
) {
    struct rst_stress * s = rs_get_app_data(rs);
    if (s->client_c >= RST_MAX_CLIENT_C) {
        return RST_TOO_MANY_CLIENTS;
    }
    struct rst_client * client = s->clients + s->client_c++;
    client->id = rs_get_client_id(rs);
    struct sockaddr_storage addr = {0};
    if (rs_get_client_addr(rs, &addr) == -1) {
        RS_LOG_ERRNO(LOG_ERR, "Unsuccessful rs_get_client_addr()");
        return RST_FATAL;
    }
    client->port = RS_NTOH16(addr.ss_family == AF_INET6 ?
        ((struct sockaddr_in6 *) &addr)->sin6_port :
        ((struct sockaddr_in *) &addr)->sin_port
    );
    RS_LOG(LOG_DEBUG, "Connection established with new client on remote port "
        "%d: client_c is now %" PRIu32, client->port, s->client_c);
    s->avail_client_c++;
    send_anything_anywhere(rs, s, client);
    return RST_OK;
}

rst_ret read_cb(
    rs_t * rs,
    uint64_t msg_id,
    uint64_t declared_size,
    uint8_t * content,
    size_t content_size
) {
    struct rst_stress * s = rs_get_app_data(rs);
    struct rst_client * client = get_client(rs, s);
    if (!client) {
        RS_LOG(LOG_CRIT, "get_client() failed unexpectedly. Shutting down...");
        return RST_FATAL;
    }
    for (int i = 0; i < client->msg_c; i++) {
        if (client->msg_ids[i] == msg_id) {
            while (++i < client->msg_c) {
                client->msg_ids[i - 1] = client->msg_ids[i];
            }
            if (client->msg_c-- == RST_MAX_SIMUL_MSG_PER_CLIENT_C) {
                s->avail_client_c++;
            }
            client->msg_ids[client->msg_c] = 0;
            goto size_validation;
        }
    }
    RS_LOG(LOG_ERR, "Received a message from remote port %d with an ID of %"
        PRIu64 " not included in its array of size %d of pending verifications",
        client->port, msg_id, client->msg_c);
    return RST_FATAL;

    size_validation:
    if (declared_size != content_size) {
        RS_LOG(LOG_ERR, "Received a message from remote port %d with a "
            "declared content size of %zu despite its actual content size of "
            "%zu", client->port, declared_size, content_size);
        return RST_FATAL;
    }
    for (size_t i = 0; i < content_size; i++) {
        if (content[i] != 255 - i % 256) { // See send_anything_anywhere()
            RS_LOG(LOG_ERR, "Received from remote port %d a content byte at "
                "index %zu with a value of %" PRIu8 " instead of the expected "
                "value %" PRIu8, client->port, i, content[i], 255 - i % 256);
            return RST_FATAL;
        }
    }
    s->total_msg_byte_c -= 16 + content_size;
    RS_LOG(LOG_DEBUG, "Validated 16+%zu byte message with ID %" PRIu64 " from "
        "remote port %d. Total message byte count is now %" PRIu64,
        content_size, msg_id, client->port, s->total_msg_byte_c);
    send_anything_anywhere(rs, s, client);
    return RST_OK;
}

rst_ret close_cb(
    rs_t * rs
) {
    (void) rs;
    RS_LOG(LOG_CRIT, "The stress app expects to be the side doing any "
        "connection closing, not the other way around!");
    return RST_FATAL;
}

RS_APP(
    RS_INIT(init_cb, sizeof(struct rst_stress)),
    RS_OPEN(open_cb),
    RS_READ_BIN(read_cb, RS_NTOH(uint64_t), RS_NTOH(uint64_t),
        RS_NET_STA(uint8_t, 0, RST_MAX_MSG_CONTENT_SIZE)),
    RS_CLOSE(close_cb),
    RS_TIMER_NONE
);
