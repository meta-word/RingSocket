// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include <ringsocket.h>

#define RST_MAX_CLIENT_C 1000
#define RST_MAX_SIMUL_MSG_PER_CLIENT_C 5
#define RST_MAX_MSG_CONTENT_SIZE 0x1000000 // 16 MB
#define RST_MAX_SIMUL_TOTAL_MSG_BYTE_C 0x10000000 // 256 MB

typedef enum {
    RST_FATAL = -1,
    RST_OK = 0,
    RST_TOO_MANY_CLIENTS = 4000,
    RST_BAD_MSG = 4001
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

static void remove_client(
    struct rst_stress * s,
    struct rst_client * client
) {
    struct rst_client * last_client = s->clients + --s->client_c;
    if (client < last_client) {
        memmove(client, client + 1, sizeof(*client) * (last_client - client));
    }
    memset(last_client, 0, sizeof(*last_client));
}

static int randrange( // Crappy randomness is OK for the purpose of this app
    int range
) {
    return (intmax_t) range * rand() / ((intmax_t) RAND_MAX + 1);
}

static void shuffle_clients( // Perform a Fisher-Yates shuffle over all clients
    struct rst_stress * s
) {
    if (s->client_c < 2) {
        return;
    }
    for (int i = s->client_c - 1; i; i--) {
        int j = randrange(i + 1);
        struct rst_client c = s->clients[j];
        s->clients[j] = s->clients[i];
        s->clients[i] = c;
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
    shuffle_clients(s);
    static uint64_t ids[RST_MAX_CLIENT_C] = {0};
    static char ports_str[RST_MAX_CLIENT_C * RS_CONST_STRLEN("12345, ")] = {0};
    bool include_cur = s->total_msg_byte_c % 2;
    int recipient_c = 0;
    {
        int ready_c = 0;
        char * p = ports_str;
        for (struct rst_client * c = s->clients; c < s->clients + s->client_c;
            c++) {
            if (c->msg_c >= RST_MAX_SIMUL_MSG_PER_CLIENT_C ||
                (c == cur_client && !include_cur)) {
                continue;
            }
            ids[ready_c++] = c->id;
            int x = c->port;
            int y = x % 10000;
            *p = '0' + x / 10000; p += x != y; x = y; y = x % 1000;
            *p = '0' + x /  1000; p += x != y; x = y; y = x % 100;
            *p = '0' + x /   100; p += x != y; x = y; y = x % 10;
            *p = '0' + x /    10; p += x != y;
            *p++ = '0' + y; *p++ = ','; *p++ = ' ';
        }
        p[-2] = '\0';
        recipient_c = randrange(ready_c) + 1;
    }
    if (!recipient_c) {
        return;
    }

    uint64_t msg_id = generate_random_msg_id();
    rs_w_uint64_hton(rs, msg_id);
    {
        struct rst_client * c = s->clients;
        for (int i = 0; i < recipient_c; i++, c++) {
            while (c->msg_c >= RST_MAX_SIMUL_MSG_PER_CLIENT_C) {
                c++;
            }
            c->msg_ids[c->msg_c++] = msg_id;
        }
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
    
    if (recipient_c > s->client_c / 2) {
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
            client->msg_ids[--client->msg_c] = 0;
            goto size_validation;
        }
    }
    RS_LOG(LOG_ERR, "Received a message from remote port %d with an ID of %"
        PRIu64 " not included in its array of size %d of pending verifications",
        client->port, msg_id, client->msg_c);
        remove_client(s, client);
    return RST_BAD_MSG;

    size_validation:
    if (declared_size != content_size) {
        RS_LOG(LOG_ERR, "received a message from remote port %d with a "
            "declared content size of %zu despite its actual content size of "
            "%zu", client->port, declared_size, content_size);
        remove_client(s, client);
        return RST_BAD_MSG;
    }
    for (size_t i = 0; i < content_size; i++) {
        if (content[i] != 255 - i % 256) { // See send_anything_anywhere()
            RS_LOG(LOG_ERR, "Received from remote port %d a content byte at "
                "index %zu with a value of %" PRIu8 " instead of the expected "
                "value %" PRIu8, client->port, i, content[i], 255 - i % 256);
            remove_client(s, client);
            return RST_BAD_MSG;
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
    struct rst_stress * s = rs_get_app_data(rs);
    struct rst_client * client = get_client(rs, s);
    if (!client) {
        RS_LOG(LOG_CRIT, "get_client() failed unexpectedly. Shutting down...");
        return RST_FATAL;
    }
    if (client->msg_c) {
        RS_LOG(LOG_WARNING, "Close callback called for prematurely for remote "
            "port %d despite having %d pending message validations remaining. ",
            client->port, client->msg_c);
    }
    remove_client(s, client);
    return RST_OK;
}

RS_APP(
    RS_INIT(init_cb, sizeof(struct rst_stress)),
    RS_OPEN(open_cb),
    RS_READ_BIN(read_cb, RS_NTOH(uint64_t), RS_NTOH(uint64_t),
        RS_NET_STA(uint8_t, 0, RST_MAX_MSG_CONTENT_SIZE)),
    RS_CLOSE(close_cb),
    RS_TIMER_NONE
);
