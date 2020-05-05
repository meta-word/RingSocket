// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include <ringsocket.h>

#define RST_MAX_READ_MSG_BYTE_C 0x1000000 // 16 MB
#define RST_MAX_CLIENT_C 1000

typedef enum {
    RST_FATAL = -1,
    RST_OK = 0,
    RST_TOO_MANY_CLIENTS = 4000,
    RST_BAD_MSG = 4001
} rst_ret;

struct rst_client {
    uint64_t id;
    int port;
};

struct rst_stress {
    struct rst_client clients[RST_MAX_CLIENT_C];
    uint64_t max_content_size;
    uint64_t content_size;
    int client_c;
    int interval;
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
}

static size_t randrange( // Crappy randomness is OK for the purpose of this app
    int range
) {
    return rand() / (RAND_MAX + 1.) * range;
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

static void send_somewhere(
    rs_t * rs,
    struct rst_stress * s
) {
    shuffle_clients(s);
    static uint64_t ids[RST_MAX_CLIENT_C] = {0};
    static char ports_str[RST_MAX_CLIENT_C * RS_CONST_STRLEN("12345, ")] = {0};
    {
        char * p = ports_str;
        for (int i = 0; i < s->client_c; i++) {
            ids[i] = s->clients[i].id;
            int port = s->clients[i].port;
            int j = port % 10000;
            *p = '0' + port / 10000; p += port != j; port = j; j = port % 1000;
            *p = '0' + port /  1000; p += port != j; port = j; j = port % 100;
            *p = '0' + port /   100; p += port != j; port = j; j = port % 10;
            *p = '0' + port /    10; p += port != j;
            *p++ = '0' + j; *p++ = ','; *p++ = ' ';
        }
        p[-2] = '\0';
    }
    int recipient_c = randrange(s->client_c) + 1;
    if (recipient_c > s->client_c / 2) {
        if (recipient_c == s->client_c) {
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_every[%s]",
                s->content_size, ports_str);
            rs_to_every(rs, RS_BIN);
        } else if (recipient_c == s->client_c - 1) {
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_every_except_single[%s]",
                s->content_size, ports_str);
            rs_to_every_except_single(rs, RS_BIN, ids[recipient_c]);
        } else {
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_every_except_multi[%s]",
                s->content_size, ports_str);
            rs_to_every_except_multi(rs, RS_BIN, ids + recipient_c,
                s->client_c - recipient_c);
        }
    } else {
        if (recipient_c == 1) {
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_single[%s]",
                s->content_size, ports_str);
            rs_to_single(rs, RS_BIN, ids[0]);
        } else {
            RS_LOG(LOG_DEBUG, "Sending 8+%zu bytes to_multi[%s]",
                s->content_size, ports_str);
            rs_to_multi(rs, RS_BIN, ids, recipient_c);
        }
    }
}

static void send_something(
    rs_t * rs,
    struct rst_stress * s
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
    send_somewhere(rs, s);
}

rst_ret init_cb(
    rs_t * rs
) {
    struct rs_conf const * conf = rs_get_conf(rs);
    struct rst_stress * s = rs_get_app_data(rs);
    s->max_content_size = conf->max_ws_msg_size - sizeof(uint64_t);
    s->interval = 1000000; // 1 second
    RS_LOG(LOG_DEBUG, "[init_cb] s->interval: %d, s->max_content_size: %zu",
        s->interval, s->max_content_size);
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
    RS_LOG(LOG_DEBUG, "open_cb called for new client on remote port %d "
        "(client_c is now %" PRIu32 ")", client->port, s->client_c);
    return RST_OK;
}

rst_ret read_cb(
    rs_t * rs,
    uint64_t declared_size,
    uint8_t * content,
    size_t content_size
) {
    struct rst_stress * s = rs_get_app_data(rs);
    struct rst_client * client = get_client(rs, s);
    if (!client) {
        return RST_FATAL;
    }
    if (declared_size != content_size) {
        RS_LOG(LOG_ERR, "received a message from remote port %d with a "
            "declared content size of %zu despite its actual content size of "
            "%zu", client->port, declared_size, content_size);
        remove_client(s, client);
        return RST_BAD_MSG;
    }
    for (size_t i = 0; i < content_size; i++) {
        if (content[i] != 255 - i % 256) { // expected to match send_something()
            RS_LOG(LOG_ERR, "Received from remote port %d a content byte at "
                "index %zu with a value of %" PRIu8 " instead of the expected "
                "value %" PRIu8, client->port, i, content[i], 255 - i % 256);
            remove_client(s, client);
            return RST_BAD_MSG;
        }
    }
    RS_LOG(LOG_DEBUG, "Validated 8+%zu bytes from remote port %d.",
        content_size, client->port);
    return RST_OK;
}

rst_ret close_cb(
    rs_t * rs
) {
    struct rst_stress * s = rs_get_app_data(rs);
    struct rst_client * client = get_client(rs, s);
    if (!client) {
        return RST_FATAL;
    }
    remove_client(s, client);
    return RST_OK;
}

rst_ret timer_cb(
    rs_t * rs
) {
    struct rst_stress * s = rs_get_app_data(rs);
    if (s->client_c) {
        s->content_size = randrange(s->max_content_size / 10) + 1;
        send_something(rs, s);
    }
    return s->interval = RS_MAX(10000 /* 0.01 sec */, s->interval - 1000);
}

RS_APP(
    RS_INIT(init_cb, sizeof(struct rst_stress)),
    RS_OPEN(open_cb),
    RS_READ_BIN(read_cb, RS_NTOH(uint64_t),
        RS_NET_STA(uint8_t, 0, RST_MAX_READ_MSG_BYTE_C)),
    RS_CLOSE(close_cb),
    RS_TIMER_WAKE(timer_cb, 1000000 /* 1 sec */)
);
