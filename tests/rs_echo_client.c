// SPDX-License-Identifier: MIT
// Copyright © 2020 William Budd

// This program is a barebones WebSocket echo client intended for efficiently
// stress testing RingSocket in parallel. It is NOT a full-fledged client,
// NOT secure, extremely half-assed in many other ways too, and should NOT be
// used for anything other than the aforementioned purpose.

#define _POSIX_C_SOURCE 201112L // getaddrinfo()

#include <fcntl.h>
#include <jgrandson.h>
#include <netdb.h>
#include <ringsocket_wsframe.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

// Preserve space at the head of rwbuf when parsing WebSocket to allow replying
// in-place, which results in messages that are exactly 4 mask bytes longer.
#define RSC_PREBUF_SIZE 4 // Total of 4 WebSocket mask bytes

RS_LOG_VARS; // See the RS_LOG() section in ringsocket_api.h for explanation.

enum rsc_state {
    RSC_READ_HTTP_CRLFCRLF = 0,
    RSC_READ_HTTP_LFCRLF = 1,
    RSC_READ_HTTP_CRLF = 2,
    RSC_READ_HTTP_LF = 3,
    RSC_READ_WS = 4,
    RSC_WRITE_WS = 5
};

struct rsc_client {
    uint8_t * storage;
    uint8_t * next_read;
    size_t old_wsize;
    int fd;
    enum rsc_state state;
};

struct rsc_route {
    char * host;     // The "example.com" part of "wss://example.com:12345/foo"
    char * port_str; // The       "12345" part of "wss://example.com:12345/foo"
    char * url;      // The         "foo" part of "wss://example.com:12345/foo"
    struct rsc_client * clients;
    uint32_t client_c;
    bool is_encrypted;
};

static char const default_conf_path[] = "rs_client.json";

static rs_ret parse_url(
    char const * full_url,
    struct rsc_route * route
) {
    char const * host = full_url;
    if (*host++ == 'w') {
        if (*host++ == 's') {
            if (*host == 's') {
                route->is_encrypted = true;
                host++;
            }
            if (*host++ == ':') {
                if (*host++ == '/') {
                    if (*host++ == '/') {
                        goto parse_url_host;
                    }
                }
            }
        }
    }
    RS_LOG(LOG_ERR, "WebSocket URL \"%s\" does not start with the required "
        "scheme \"wss://\" or \"ws://\"", full_url);
    return RS_FATAL;
    parse_url_host:
    if (*host == '\0') {
        RS_LOG(LOG_ERR, "WebSocket URL \"%s\" seems to be missing a hostname",
            full_url);
        return RS_FATAL;
    }
    char * slash = strchr(host, '/');
    char * colon = strchr(host, ':');
    if (colon) {
        size_t _strlen = colon - host;
        RS_CALLOC(route->host, _strlen + 1);
        memcpy(route->host, host, _strlen);
        if (slash) {
            if (colon > slash) {
                RS_LOG(LOG_ERR, "WebSocket URL \"%s\" seems to contain a stray "
                    "colon in its path. A colon is only allowed in the "
                    "hostname section as a port number designator.", full_url);
                return RS_FATAL;
            }
            _strlen = slash - ++colon;
            if (*++slash != '\0') {
                RS_CALLOC(route->url, strlen(slash) + 1);
                strcpy(route->url, slash); 
            }
        } else {
            _strlen = strlen(++colon);
        }
        RS_CALLOC(route->port_str, _strlen + 1);
        memcpy(route->port_str, colon, _strlen);
    } else if (slash) {
        size_t _strlen = slash - host;
        RS_CALLOC(route->host, _strlen + 1);
        memcpy(route->host, host, _strlen);
        if (*++slash != '\0') {
            RS_CALLOC(route->url, strlen(slash) + 1);
            strcpy(route->url, slash); 
        }
    } else {
        RS_CALLOC(route->host, strlen(host) + 1);
        strcpy(route->host, host);
    }
    return RS_OK;
}

#define RS_GUARD_JG(_jg_ret) do { \
    if ((_jg_ret) != JG_OK) { \
        RS_LOG(LOG_ERR, "Error parsing configuration file: %s", \
            jg_get_err_str(jg, NULL, NULL)); \
        return RS_FATAL; \
    } \
} while (0)

static rs_ret get_conf(
    char const * conf_path,
    size_t * rwbuf_size,
    size_t * epoll_buf_elem_c, 
    struct rsc_route * * routes,
    size_t * route_c
) {
    jg_t * jg = jg_init();
    RS_GUARD_JG(jg_parse_file(jg, conf_path ? conf_path : default_conf_path));

    jg_obj_get_t * root_obj = NULL;
    RS_GUARD_JG(jg_root_get_obj(jg, NULL, &root_obj));

    {
        char log_level[] = "notice";
        RS_GUARD_JG(jg_obj_get_callerstr(jg, root_obj, "log_level",
            &(jg_obj_callerstr){
                .defa = "debug",
                .max_byte_c = RS_CONST_STRLEN("notice"),
            }, log_level));
        if (!strcmp(log_level, "error")) {
            _rs_log_max = LOG_ERR;
        } else if (!strcmp(log_level, "warning")) {
            _rs_log_max = LOG_WARNING;
        } else if (!strcmp(log_level, "info")) {
            _rs_log_max = LOG_INFO;
            RS_LOG(LOG_INFO, "Syslog log priority set to \"info\"");
        } else if (!strcmp(log_level, "debug")) {
            _rs_log_max = LOG_DEBUG;
            RS_LOG(LOG_INFO, "Syslog log priority set to \"debug\"");
        } else if (strcmp(log_level, "notice")) {
            RS_LOG(LOG_ERR, "Unrecognized configuration value for "
                "\"log_level\": \"%s\". The value must be one of: \"error\", "
                "\"warning\", \"notice\", \"info\", or \"debug\".", log_level);
            return RS_FATAL;
        }
    }

    RS_GUARD_JG(jg_obj_get_sizet(jg, root_obj, "rwbuf_size", NULL, rwbuf_size));
    RS_GUARD_JG(jg_obj_get_sizet(jg, root_obj, "epoll_buf_elem_c", NULL,
        epoll_buf_elem_c));

    jg_arr_get_t * arr = NULL;
    RS_GUARD_JG(jg_obj_get_arr(jg, root_obj, "routes", NULL, &arr, route_c));
    RS_CALLOC(*routes, *route_c);
    for (size_t i = 0; i < *route_c; i++) {
        jg_obj_get_t * obj = NULL;
        RS_GUARD_JG(jg_arr_get_obj(jg, arr, i, NULL, &obj));

        char * full_url = NULL;
        RS_GUARD_JG(jg_obj_get_str(jg, obj, "url", NULL, &full_url));
        RS_GUARD(parse_url(full_url, *routes + i));
        free(full_url);
        
        RS_GUARD_JG(jg_obj_get_uint32(jg, obj, "client_c", NULL,
            &(*routes)[i].client_c));
        RS_CALLOC((*routes)[i].clients, (*routes)[i].client_c);
    }

    jg_free(jg);
    return RS_OK;
}

static rs_ret write_http_upgrade_request(
    char * rwbuf,
    int epoll_fd,
    struct rsc_route const * route,
    struct rsc_client * client
) {
    // Send a dummy WebSocket key in flagrant disregard of RFC6455, because
    // that's not the aspect of the standard we're interested in testing here.
    int http_strlen = sprintf(rwbuf, // sizeof(rwbuf) > 1000 guaranteed
        "GET /%s HTTP/1.1\r\n"
        "Host: %s%s%s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: 1234567890123456789012==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        route->url,
        route->host,
        route->port_str ? ":" : "",
        route->port_str ? route->port_str : ""
    );
    if (write(client->fd, rwbuf, http_strlen) != http_strlen) {
        RS_LOG_ERRNO(LOG_ERR, "Unsuccessful write(%d, rwbuf, %d)",
            client->fd, http_strlen);
        return RS_FATAL;
    }
    // Time to switch the socket to non-blocking mode
    if (fcntl(client->fd, F_SETFL, O_NONBLOCK) == -1) {
        RS_LOG_ERRNO(LOG_ERR, "Unsuccessful fcntl(%d, F_SETFL, O_NONBLOCK)",
            client->fd);
        return RS_FATAL;
    }
    struct epoll_event event = {
        .data = {.ptr = client},
        .events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client->fd, &event) == -1) {
        RS_LOG_ERRNO(LOG_ERR, "Unsuccessful epoll_ctl(%d, EPOLL_CTL_ADD, "
            "%d, &event)", epoll_fd, client->fd);
        return RS_FATAL;
    }
    RS_LOG(LOG_DEBUG, "Upgrade request sent for socket fd %d:\n%.*s",
        client->fd, http_strlen, rwbuf);
    return RS_OK;
}

static rs_ret send_upgrade_request(
    char * rwbuf,
    int epoll_fd,
    struct rsc_route const * route,
    struct rsc_client * client
) {
    struct addrinfo * ai_first;
    {
        int ret = getaddrinfo(route->host, route->port_str ? route->port_str :
            (route->is_encrypted ? "443" : "80"), &(struct addrinfo){
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM
        }, &ai_first);
        if (ret) {
            RS_LOG(LOG_ERR, "Unsuccessful getaddrinfo(%s, %s, ...): %s",
                route->host, route->port_str, gai_strerror(ret));
        }
    }
    for (struct addrinfo * ai = ai_first; ai; ai = ai->ai_next) {
        // To keep things simple, don't set the new socket to non-blocking mode
        // until after the HTTP upgrade request is written.
        client->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (client->fd == -1) {
            RS_LOG_ERRNO(LOG_WARNING, "Unsuccessful socket(...)");
            continue;
        }
        if (!connect(client->fd, ai->ai_addr, ai->ai_addrlen)) {
            freeaddrinfo(ai_first);
            return write_http_upgrade_request(rwbuf, epoll_fd, route, client);
        }
        RS_LOG_ERRNO(LOG_WARNING, "Unsuccessful connect(%d, ...)", client->fd);
        if (close(client->fd) == -1) {
            RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful close(%d)", client->fd);
            freeaddrinfo(ai_first);
            return RS_FATAL;
        }
    }
    freeaddrinfo(ai_first);
    RS_LOG_ERRNO(LOG_ERR, "All getaddrinfo(%s, %s, ...) results failed",
        route->host, route->port_str);
    return RS_FATAL;
}

static rs_ret read_http(
    struct rsc_client * client,
    char * rwbuf,
    size_t rwbuf_size
) {
    for (;;) {
        ssize_t rsize = read(client->fd, rwbuf, rwbuf_size);
        switch (rsize) {
        case -1:
            if (errno == EAGAIN) {
                return RS_AGAIN;
            }
            RS_LOG_ERRNO(LOG_ERR, "Unsuccessful read(%d, ...)", client->fd);
            return RS_FATAL;
        case 0:
            RS_LOG_ERRNO(LOG_ERR, "read(%d, ...) 0 bytes", client->fd);
            return RS_FATAL;
        default:
            for (ssize_t i = 0; i < rsize;) {
                switch (rwbuf[i++]) {
                case '\r':
                    switch (client->state) {
                    case RSC_READ_HTTP_CRLFCRLF:
                        client->state = RSC_READ_HTTP_LFCRLF;
                        continue;
                    case RSC_READ_HTTP_CRLF:
                        client->state = RSC_READ_HTTP_LF;
                        continue;
                    default:
                        break;
                    }
                    break;
                case '\n':
                    switch (client->state) {
                    case RSC_READ_HTTP_LFCRLF:
                        client->state = RSC_READ_HTTP_CRLF;
                        continue;
                    case RSC_READ_HTTP_LF:
                        RS_LOG(LOG_DEBUG, "HTTP handshake completed for socket "
                            "fd: %d", client->fd);
                        client->state = RSC_READ_WS;
                        if (i < rsize) {
                            memmove(rwbuf, rwbuf + i, rsize - i);
                        }
                        return RS_OK;
                    default:
                        break;
                    }
                }
                client->state = RSC_READ_HTTP_CRLFCRLF;
            }
        }
    }
}

static rs_ret parse_websocket_frame_header(
    struct rsc_client * client,
    union rs_wsframe const * frame,
    unsigned * header_size,
    uint64_t * payload_size
) {
    switch (rs_get_wsframe_opcode(frame)) {
    case RS_WSFRAME_OPC_CONT:
    case RS_WSFRAME_OPC_TEXT:
    case RS_WSFRAME_OPC_BIN:
        break;
    case RS_WSFRAME_OPC_CLOSE:
        RS_LOG(LOG_WARNING, "Received WebSocket Close frame for fd %d: "
            "shutting down...", client->fd);
        return RS_FATAL; // Todo: return RS_CLOSE_PEER and handle that somehow?
    default:
        RS_LOG(LOG_WARNING, "Received unexpected opcode %d for fd %d: "
            "shutting down...", rs_get_wsframe_opcode(frame), client->fd);
        return RS_FATAL;
    }
    if (client->next_read < frame->sc_small.payload) {
        return RS_AGAIN;
    }
    switch (frame->payload_size_x7F) {
    default:
        *header_size = sizeof(frame->sc_small);
        *payload_size = frame->payload_size_x7F;
        return RS_OK;
    case 126:
        if (client->next_read < frame->sc_medium.payload) {
            return RS_AGAIN;
        }
        *header_size = sizeof(frame->sc_medium);
        *payload_size = RS_R_NTOH16(frame->sc_medium.payload_size);
        return RS_OK;
    case 127:
        if (client->next_read < frame->sc_large.payload) {
            return RS_AGAIN;
        }
        *header_size = sizeof(frame->sc_large);
        *payload_size = RS_R_NTOH64(frame->sc_large.payload_size);
        return RS_OK;
    }
}

static rs_ret parse_websocket_frame(
    struct rsc_client * client,
    uint8_t const * wsbuf,
    unsigned * header_size,
    uint64_t * payload_size
) {
    union rs_wsframe const * frame = (union rs_wsframe const *) wsbuf;
    RS_GUARD(parse_websocket_frame_header(client, frame, header_size,
        payload_size));
    return client->next_read < wsbuf + *header_size + *payload_size ?
        RS_AGAIN : RS_OK;
}

static rs_ret write_websocket(
    struct rsc_client * client,
    uint8_t const * wbuf,
    size_t wbuf_size
) {
    ssize_t ret = write(client->fd, wbuf, wbuf_size);
    if (ret > 0) {
        size_t wsize = ret;
        RS_LOG(LOG_DEBUG, "Echoed %zu byte chunk back to RingSocket for fd "
            "%d", wsize, client->fd);
        if (wsize == wbuf_size) {
            client->old_wsize = 0;
            client->state = RSC_READ_WS;
            return RS_OK;
        }
        client->old_wsize += wsize;
        return RS_AGAIN;
    }
    if (errno == EAGAIN) {
        return RS_AGAIN;
    }
    RS_LOG_ERRNO(LOG_ERR, "Unsuccessful write(%d, wbuf, %zu)",
        client->fd, wbuf_size);
    return RS_FATAL; // Todo: handle this more gracefully
}

static rs_ret mask_and_write_websocket(
    struct rsc_client * client,
    uint8_t * wsbuf,
    unsigned header_size,
    uint64_t payload_size
) {
    RS_LOG(LOG_DEBUG, "Masking %zu+4+%zu=%zu bytes received frame for fd %d",
        header_size, payload_size, header_size + 4 + payload_size, client->fd);
    client->state = RSC_WRITE_WS;
    uint8_t * mask = NULL;
    switch (header_size) {
    case sizeof(struct rs_wsframe_sc_small):
        *((uint16_t *) (wsbuf - 4)) = *((uint16_t *) wsbuf);
        mask = wsbuf - 2;
        break;
    case sizeof(struct rs_wsframe_sc_medium):
        *((uint32_t *) (wsbuf - 4)) = *((uint32_t *) wsbuf);
        mask = wsbuf;
        break;
    case sizeof(struct rs_wsframe_sc_large): default:
        *((uint32_t *) (wsbuf - 4)) = *((uint32_t *) wsbuf);
        *((uint32_t *) wsbuf) = *((uint32_t *) (wsbuf + 4));
        *((uint16_t *) (wsbuf + 4)) = *((uint16_t *) (wsbuf + 6));
        mask = wsbuf + 6;
    }
    wsbuf[-3] |= 0x80; // Set the mask bit
    *((uint16_t *) mask) = UINT16_MAX * (rand() / (RAND_MAX + 1.));
    *((uint16_t *) (mask + 2)) = UINT16_MAX * (rand() / (RAND_MAX + 1.));
    uint8_t * payload = mask + 4;
    for (size_t i = 0; i < payload_size; i++) {
        payload[i] ^= mask[i % 4];
    }
    return write_websocket(client, wsbuf - 4, header_size + 4 + payload_size);
}

static rs_ret read_websocket(
    struct rsc_client * client,
    uint8_t * wsbuf,
    size_t wsbuf_size
) {
    uint8_t * const wsbuf_over = wsbuf + wsbuf_size;
    bool parse_is_complete = true;
    if (client->storage) {
        parse_is_complete = false;
        memcpy(wsbuf, client->storage, client->next_read - wsbuf);
        RS_FREE(client->storage);
    } else {
        client->next_read = wsbuf;
    }
    for (;;) {
        ssize_t rsize = read(client->fd, client->next_read,
            wsbuf_over - client->next_read);
        switch (rsize) {
        case -1:
            if (errno != EAGAIN) {
                RS_LOG_ERRNO(LOG_ERR, "Unsuccessful read(%d, ...)", client->fd);
                return RS_FATAL;
            }
            if (parse_is_complete) {
                return RS_OK;
            }
            store_buf:
            {
                size_t size = client->next_read - wsbuf;
                client->storage = malloc(size);
                if (!client->storage) {
                    RS_LOG(LOG_ERR, "Unsuccessful malloc(%zu)",
                        client->storage);
                    return RS_FATAL;
                }
                memcpy(client->storage, wsbuf, size);
            }
            return RS_AGAIN;
        case 0:
            RS_LOG_ERRNO(LOG_ERR, "read(%d, ...) 0 bytes", client->fd);
            return RS_FATAL;
        default:
            RS_LOG(LOG_DEBUG, "Read %zu bytes from RingSocket for fd %d",
                (size_t) rsize, client->fd);
            client->next_read += rsize;
            for (;;) {
                unsigned header_size = 0;
                uint64_t payload_size = 0;
                switch (parse_websocket_frame(client, wsbuf, &header_size,
                    &payload_size)) {
                case RS_OK:
                    switch (mask_and_write_websocket(client, wsbuf,
                        header_size, payload_size)) {
                    case RS_OK:
                        break;
                    case RS_AGAIN:
                        wsbuf -= 4;
                        goto store_buf;
                    default:
                        return RS_FATAL;
                    }
                    uint8_t * next_frame = wsbuf + header_size + payload_size;
                    if (next_frame == client->next_read) {
                        parse_is_complete = true;
                        break;
                    }
                    size_t remaining_size = client->next_read - next_frame;
                    if (remaining_size > header_size + payload_size) {
                        memmove(wsbuf, next_frame, remaining_size);
                    } else {
                        memcpy(wsbuf, next_frame, remaining_size);
                    }
                    client->next_read = wsbuf + remaining_size;
                    continue;
                case RS_AGAIN:
                    parse_is_complete = false;
                    break;
                default:
                    return RS_FATAL;
                }
                break;
            }
        }
    }
}

static rs_ret _main(
    int arg_c,
    char * const * args
) {
    if (arg_c > 2) {
        RS_LOG(LOG_WARNING, "%s received %d command-line arguments, but can "
            "handle only one: the path to the configuration file -- which in "
            "this case is assumed to be: \"%s\". Ignoring all other arguments!",
            args[0], arg_c, args[1]);
    }

    size_t rwbuf_size = 0;
    size_t epoll_buf_elem_c = 0;
    struct rsc_route * routes = NULL;
    size_t route_c = 0;
    RS_GUARD(get_conf(arg_c > 1 ? args[1] : NULL, &rwbuf_size,
        &epoll_buf_elem_c, &routes, &route_c));

    char * rwbuf = NULL;
    RS_CALLOC(rwbuf, rwbuf_size);

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful epoll_create1(0)");
        return RS_FATAL;
    }
    srand((unsigned) time(NULL));

    for (size_t i = 0; i < route_c; i++) {
        struct rsc_route * route = routes + i;
        for (size_t j = 0; j < route->client_c; j++) {
            RS_GUARD(send_upgrade_request(rwbuf, epoll_fd, route,
                route->clients + j));
        }
    }

    struct epoll_event * epoll_buf = NULL;
    RS_CALLOC(epoll_buf, epoll_buf_elem_c);
    for (;;) {
        int event_c = epoll_wait(epoll_fd, epoll_buf, epoll_buf_elem_c, -1);
        if (event_c == -1) {
            RS_LOG_ERRNO(LOG_CRIT,
                "Unsuccessful epoll_wait(%d, epoll_buf, %zu, -1)",
                epoll_fd, epoll_buf_elem_c);
            return RS_FATAL;
        }
        for (struct epoll_event * e = epoll_buf; e < epoll_buf + event_c; e++) {
            struct rsc_client * client = e->data.ptr;
            if (e->events & EPOLLERR) {
                RS_LOG(LOG_ERR, "Received EPOLLERR for fd %d", client->fd);
                close_client:
                if (close(client->fd) == -1) {
                    RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful close(%d)",
                        client->fd);
                    return RS_FATAL;
                }
                continue;
            }
            if (e->events & EPOLLHUP) {
                RS_LOG(LOG_WARNING, "Received EPOLLHUP for fd %d", client->fd);
                goto close_client;
            }
            if (e->events & EPOLLRDHUP) {
                RS_LOG(LOG_INFO, "Received EPOLLRDHUP for fd %d", client->fd);
                goto close_client;
            }
            switch (client->state) {
            case RSC_READ_HTTP_CRLFCRLF:
            case RSC_READ_HTTP_LFCRLF:
            case RSC_READ_HTTP_CRLF:
            case RSC_READ_HTTP_LF:
                if (!(e->events & EPOLLIN)) {
                    continue;
                }
                switch (read_http(client, rwbuf, rwbuf_size)) {
                case RS_OK:
                    break;
                case RS_AGAIN:
                    continue;
                default:
                    return RS_FATAL;
                }
                break;
            case RSC_READ_WS:
                if (!(e->events & EPOLLIN)) {
                    continue;
                }
                break;
            case RSC_WRITE_WS: default:
                if (!(e->events & EPOLLOUT)) {
                    continue;
                }
                {
                    unsigned header_size = 0;
                    uint64_t payload_size = 0;
                    parse_websocket_frame_header(client,
                        (union rs_wsframe *) client->storage,
                        &header_size, &payload_size);
                    uint64_t frame_size = header_size + 4 + payload_size;
                    switch (write_websocket(client, client->storage +
                        client->old_wsize, frame_size - client->old_wsize)) {
                    case RS_OK:
                        break;
                    case RS_AGAIN:
                        continue;
                    default:
                        return RS_FATAL;
                    }
                    uint8_t * next_frame = (uint8_t *) rwbuf + frame_size;
                    if (client->next_read > next_frame) {
                        memcpy(rwbuf + 4, client->storage + frame_size,
                            client->next_read - next_frame);
                    }
                    RS_FREE(client->storage);
                }
            }
            switch (read_websocket(client, (uint8_t *) rwbuf +
                RSC_PREBUF_SIZE, rwbuf_size - RSC_PREBUF_SIZE)) {
            case RS_OK:
            case RS_AGAIN:
                continue;
            default:
                return RS_FATAL;
            }
        }
    }
}

int main(
    int arg_c, // 1 or 2 
    char * * args // "rs_test_client" and optionally the path to the conf file
) {
    openlog(args[0], LOG_PID, LOG_USER);
    return _main(arg_c, args) == RS_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
