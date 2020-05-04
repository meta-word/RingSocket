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
#include <time.h>
#include <unistd.h>

// Preserve space at the head of rwbuf when parsing WebSocket to allow replying
// in-place, which results in messages that are exactly 4 mask bytes longer.
#define RSC_PREBUF_SIZE 4 // Total of 4 WebSocket mask bytes

#define RSC_CONNECT_ATTEMPT_C 100
#define RSC_COOL_OFF_INIT_NS 10000000 // 0.01s
#define RSC_COOL_OFF_MULT 1.5

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
    uint16_t port;
    uint16_t state;
};

static char const default_conf_path[] = "rs_client.json";

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
    struct rs_conf_endpoint * * endpoints,
    size_t * endpoint_c,
    struct rsc_client * * clients,
    size_t * client_c
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
        RS_GUARD(rs_set_log_level(log_level));
    }

    RS_GUARD_JG(jg_obj_get_sizet(jg, root_obj, "rwbuf_size", NULL, rwbuf_size));
    RS_GUARD_JG(jg_obj_get_sizet(jg, root_obj, "epoll_buf_elem_c", NULL,
        epoll_buf_elem_c));

    jg_arr_get_t * arr = NULL;
    RS_GUARD_JG(jg_obj_get_arr(jg, root_obj, "urls", NULL, &arr,
        endpoint_c));
    RS_CALLOC(*endpoints, *endpoint_c);
    for (size_t i = 0; i < *endpoint_c; i++) {
        char * url = NULL;
        RS_GUARD_JG(jg_arr_get_str(jg, arr, i, NULL, &url));
        RS_GUARD(rs_parse_canon_ws_url(url, *endpoints + i));
        RS_FREE(url);
    }

    RS_GUARD_JG(jg_obj_get_sizet(jg, root_obj, "client_c", NULL, client_c));
    RS_CALLOC(*clients, *client_c);

    jg_free(jg);
    return RS_OK;
}

static rs_ret get_local_port(
    struct rsc_client * client,
    bool is_ipv6
) {
    if (is_ipv6) {
        struct sockaddr_in6 ipv6_addr;
        socklen_t addr_size = sizeof(ipv6_addr);
        if (getsockname(client->fd, (struct sockaddr *) &ipv6_addr,
            &addr_size) == -1) {
            RS_LOG_ERRNO(LOG_ERR,
                "Unsuccessful getsockname(%d, &ipv6_addr, ...)", client->fd);
            return RS_FATAL;
        }
        client->port = RS_NTOH16(ipv6_addr.sin6_port);
    } else {
        struct sockaddr_in ipv4_addr;
        socklen_t addr_size = sizeof(ipv4_addr);
        if (getsockname(client->fd, (struct sockaddr *) &ipv4_addr,
            &addr_size) == -1) {
            RS_LOG_ERRNO(LOG_ERR,
                "Unsuccessful getsockname(%d, &ipv4_addr, ...)", client->fd);
            return RS_FATAL;
        }
        client->port = RS_NTOH16(ipv4_addr.sin_port);
    }
    return RS_OK;
}

static rs_ret write_http_upgrade_request(
    char * rwbuf,
    int epoll_fd,
    struct rs_conf_endpoint const * endpoint,
    struct rsc_client * client
) {
    // Send a dummy WebSocket key in flagrant disregard of RFC6455, because
    // that's not the aspect of the standard we're interested in testing here.
    int http_strlen = sprintf(rwbuf, // sizeof(rwbuf) > 1000 guaranteed
        "GET /%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: 1234567890123456789012==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        endpoint->url,
        endpoint->hostname
    );
    if (write(client->fd, rwbuf, http_strlen) != http_strlen) {
        RS_LOG_ERRNO(LOG_ERR, "Unsuccessful write(%d, rwbuf, %d) on port %"
            PRIu16, client->fd, http_strlen, client->port);
        return RS_FATAL;
    }
    // Time to switch the socket to non-blocking mode
    if (fcntl(client->fd, F_SETFL, O_NONBLOCK) == -1) {
        RS_LOG_ERRNO(LOG_ERR, "Unsuccessful fcntl(%d, F_SETFL, O_NONBLOCK) "
            "on port %" PRIu16, client->fd, client->port);
        return RS_FATAL;
    }
    struct epoll_event event = {
        .data = {.ptr = client},
        .events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client->fd, &event) == -1) {
        RS_LOG_ERRNO(LOG_ERR, "Unsuccessful epoll_ctl(%d, EPOLL_CTL_ADD, "
            "%d, &event) on port %" PRIu16, epoll_fd, client->fd, client->port);
        return RS_FATAL;
    }
    RS_LOG(LOG_DEBUG, "Upgrade request sent for socket fd %d on port %" PRIu16
        ":\n%.*s", client->fd, client->port, http_strlen, rwbuf);
    return RS_OK;
}

static rs_ret send_upgrade_request(
    char * rwbuf,
    int epoll_fd,
    struct rs_conf_endpoint const * endpoint,
    struct rsc_client * client
) {
    struct addrinfo * ai_first;
    {
        int ret = -1;
        struct addrinfo ai_preset = {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM
        };
        char * colon = strchr(endpoint->hostname, ':');
        if (colon) {
            *colon = '\0';
            ret = getaddrinfo(endpoint->hostname,
                colon + 1, &ai_preset, &ai_first);
            *colon = ':';
        } else {
            ret = getaddrinfo(endpoint->hostname,
                endpoint->is_encrypted ? "443" : "80", &ai_preset, &ai_first);
        }
        if (ret) {
            RS_LOG(LOG_ERR, "Unsuccessful getaddrinfo() for %s",
                endpoint->hostname, gai_strerror(ret));
            return RS_FATAL;
        }
    }
    int connect_attempt_c = RSC_CONNECT_ATTEMPT_C;
    static struct timespec cool_off_time = {0, RSC_COOL_OFF_INIT_NS};
    struct addrinfo * ai = ai_first;
    for (;;) {
        // To keep things simple, don't set the new socket to non-blocking mode
        // until after the HTTP upgrade request is written.
        client->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (client->fd == -1) {
            RS_LOG_ERRNO(LOG_WARNING, "Unsuccessful socket(...)");
        } else {
            if (connect(client->fd, ai->ai_addr, ai->ai_addrlen) != -1) {
                RS_GUARD(get_local_port(client,
                    ai->ai_addr->sa_family == AF_INET6));
                freeaddrinfo(ai_first);
                return write_http_upgrade_request(rwbuf, epoll_fd, endpoint,
                    client);
            }
            if (errno == ECONNREFUSED) {
                uint64_t ns =
                    1000000000 * cool_off_time.tv_sec + cool_off_time.tv_nsec;
                RS_LOG(LOG_WARNING, "Unsuccessful connect(%d, ...): "
                    "connection refused: sleeping %fs before retrying...",
                    client->fd, ns / 1000000000.);
                nanosleep(&cool_off_time, NULL);
                // Next time, sleep RSC_COOL_OFF_MULT times as long
                ns *= RSC_COOL_OFF_MULT;
                cool_off_time.tv_sec = ns / 1000000000;
                cool_off_time.tv_nsec = ns % 1000000000;
            } else {
                RS_LOG_ERRNO(LOG_WARNING, "Unsuccessful connect(%d, ...)",
                    client->fd);
            }
            if (close(client->fd) == -1) {
                RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful close(%d)", client->fd);
                freeaddrinfo(ai_first);
                return RS_FATAL;
            }
        }
        ai = ai->ai_next;
        if (!ai) {
            if (!--connect_attempt_c) {
                freeaddrinfo(ai_first);
                RS_LOG_ERRNO(LOG_ERR,
                    "All getaddrinfo() results for %s were unsuccessful",
                    endpoint->hostname);
                return RS_FATAL;
            }
            ai = ai_first;
        }
    }
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
            RS_LOG_ERRNO(LOG_ERR, "Unsuccessful read(%d, ...) on port %" PRIu16,
                client->fd, client->port);
            return RS_FATAL;
        case 0:
            RS_LOG_ERRNO(LOG_ERR, "read(%d, ...) 0 bytes on port %" PRIu16,
                client->fd, client->port);
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
                            "fd %d on port %" PRIu16, client->fd, client->port);
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
        RS_LOG(LOG_WARNING, "Received WebSocket Close frame for fd %d on port %"
            PRIu16 ": shutting down...", client->fd, client->port);
        return RS_CLOSE_PEER;
    default:
        RS_LOG(LOG_WARNING, "Received unexpected opcode %d for fd %d on port %"
            PRIu16": shutting down...", rs_get_wsframe_opcode(frame),
            client->fd, client->port);
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
        RS_LOG(LOG_DEBUG, "Echoed %zu byte chunk back to RingSocket for fd %d "
            "on port %" PRIu16, wsize, client->fd, client->port);
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
    RS_LOG_ERRNO(LOG_ERR, "Unsuccessful write(%d, wbuf, %zu) on port %" PRIu16,
        client->fd, wbuf_size, client->port);
    return RS_FATAL; // Todo: handle this more gracefully
}

static rs_ret mask_and_write_websocket(
    struct rsc_client * client,
    uint8_t * wsbuf,
    unsigned header_size,
    uint64_t payload_size
) {
    RS_LOG(LOG_DEBUG, "Masking %zu+4+%zu=%zu bytes received frame for fd %d on "
        "port %" PRIu16, header_size, payload_size,
        header_size + 4 + payload_size, client->fd, client->port);
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
        *((uint32_t *) (wsbuf + 4)) = *((uint32_t *) (wsbuf + 8));
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
        size_t size = client->next_read - wsbuf;
        RS_LOG(LOG_DEBUG, "Retrieving %zu byte read from storage for fd %d on "
            "port %" PRIu16, size, client->fd, client->port);
        memcpy(wsbuf, client->storage, size);
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
                RS_LOG_ERRNO(LOG_ERR, "Unsuccessful read(%d, ...) on port %"
                    PRIu16, client->fd, client->port);
                return RS_FATAL;
            }
            if (parse_is_complete) {
                return RS_OK;
            }
            store_buf:
            {
                size_t size = client->next_read - wsbuf;
                RS_LOG(LOG_DEBUG, "Storing %zu byte read to storage for fd %d "
                    "on port %" PRIu16, size, client->fd, client->port);
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
            RS_LOG(LOG_ERR, "read(%d, ...) 0 bytes on port %" PRIu16,
                client->fd, client->port);
            return RS_FATAL;
        default:
            RS_LOG(LOG_DEBUG, "Read %zu bytes from RingSocket for fd %d on "
                "port %" PRIu16, (size_t) rsize, client->fd, client->port);
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
                        client->next_read = wsbuf;
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
                case RS_CLOSE_PEER:
                    return RS_CLOSE_PEER;
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
    struct rs_conf_endpoint * endpoints = NULL;
    size_t endpoint_c = 0;
    struct rsc_client * clients = NULL;
    size_t client_c = 0;
    RS_GUARD(get_conf(arg_c > 1 ? args[1] : NULL, &rwbuf_size,
        &epoll_buf_elem_c, &endpoints, &endpoint_c, &clients, &client_c));

    char * rwbuf = NULL;
    RS_CALLOC(rwbuf, rwbuf_size);

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful epoll_create1(0)");
        return RS_FATAL;
    }
    srand((unsigned) time(NULL));

    for (size_t i = 0, j = 0; i < client_c; i++, j++, j %= endpoint_c) {
        RS_GUARD(send_upgrade_request(rwbuf, epoll_fd, endpoints + j,
            clients + i));
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
                RS_LOG(LOG_ERR, "Received EPOLLERR for fd %d on port %" PRIu16,
                    client->fd, client->port);
                close_client:
                if (close(client->fd) == -1) {
                    RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful close(%d) on port %"
                        PRIu16, client->fd, client->port);
                    return RS_FATAL;
                }
                if (--client_c) {
                    continue;
                }
                RS_LOG(LOG_NOTICE,
                    "Shutting down because all clients have been closed.");
                return RS_OK;
            }
            if (e->events & EPOLLHUP) {
                RS_LOG(LOG_WARNING, "Received EPOLLHUP for fd %d on port %"
                    PRIu16, client->fd, client->port);
                goto close_client;
            }
            if (e->events & EPOLLRDHUP) {
                RS_LOG(LOG_INFO, "Received EPOLLRDHUP for fd %d on port %"
                    PRIu16, client->fd, client->port);
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
                    uint64_t frame_size = rs_get_wsframe_cs_size(
                        (union rs_wsframe *) client->storage);
                    RS_LOG(LOG_DEBUG, "Resuming %zu byte frame write from "
                        "storage for fd %d on port %" PRIu16, frame_size,
                        client->fd, client->port);
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
                        size_t tail_size = client->next_read - next_frame;
                        RS_LOG(LOG_DEBUG, "Retrieving %zu byte tail from "
                            "storage for fd %d on port %" PRIu16, tail_size,
                            client->fd, client->port);
                        memcpy(rwbuf + 4, client->storage + frame_size,
                            tail_size);
                    }
                    RS_FREE(client->storage);
                }
            }
            switch (read_websocket(client, (uint8_t *) rwbuf +
                RSC_PREBUF_SIZE, rwbuf_size - RSC_PREBUF_SIZE)) {
            case RS_OK:
            case RS_AGAIN:
                continue;
            case RS_CLOSE_PEER:
                goto close_client;
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
