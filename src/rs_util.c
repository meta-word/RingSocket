// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#define _GNU_SOURCE // NI_MAXHOST, NI_MAXSERV

#include "rs_util.h"

#include <netdb.h> // getnameinfo(), MI_MAXHOST, NI_MAXSERV
#include <sys/epoll.h> // EPOLL* event bitflag macros

static char * get_addr_str(
    int socket_fd,
    char * str
) {
    struct sockaddr_storage addr = {0};
    socklen_t addr_size = sizeof(addr);
    if (getpeername(socket_fd, (struct sockaddr *) &addr, &addr_size) == -1) {
        RS_LOG_ERRNO(LOG_ERR, "Unsuccessful getpeername(%d, ...)", socket_fd);
        strcpy(str, "<UNKNOWN>");
        return str + RS_CONST_STRLEN("<UNKNOWN>");
    }
    if (addr.ss_family == AF_INET6) {
        *str++ = '[';
    }
    char * port_str = str + NI_MAXHOST + RS_CONST_STRLEN("]:");
    int ret = getnameinfo((struct sockaddr *) &addr, addr_size, str,
        NI_MAXHOST, port_str, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
    if (ret) {
        RS_LOG(LOG_ERR, "Unsuccessful getnameinfo(): %s", gai_strerror(ret));
        if (addr.ss_family == AF_INET6) {
            str--;
        }
        strcpy(str, "<UNKNOWN>");
        return str + RS_CONST_STRLEN("<UNKNOWN>");
    }
    while (*str != '\0') {
        str++;
    }
    if (addr.ss_family == AF_INET6) {
        *str++ = ']';
    }
    *str++ = ':';
    size_t port_strlen = strlen(port_str);
    move_left(str, port_str - str, port_strlen + 1);
    return str + port_strlen;
}

char * get_peer_str(
    union rs_peer * peer
) {
    // Upside of using thread_local static like this: no worrying about free().
    // Downside of this approach: 40 lines of cruft to get an appropriate size,
    // instead of just calling asprintf().
    thread_local static char peer_str[
        RS_CONST_STRLEN("[") + NI_MAXHOST + RS_CONST_STRLEN("]:") + NI_MAXSERV +
        RS_CONST_STRLEN(" (") + RS_CONST_STRLEN(
            "is_encrypted: Y, "
            "is_writing: Y, "
            "layer: HTTP, "
            "mortality: SHUTDOWN_WRITE_WS, "
            "continuation: PARSING, "
            "app_i: 255, "
            "endpoint_i: 65535, "
            "socket_fd: 2147483647, "
            "heap_buf: used, "
            "shutdown_deadline: 65535, "
            "old_wsize: 18446744073709551615, "
        ) +
        RS_MAX(
            RS_CONST_STRLEN(
                "http.origin_i: 65535, "
                "http.partial_strlen: 4294967295, "
                "http.jump_distance: 65535, "
                "http.error_i: 255, "
                "http.hostname_was_parsed: Y, "
                "http.origin_was_parsed: Y, "
                "http.upgrade_was_parsed: Y, "
                "http.wskey_was_parsed: Y, "
                "http.wsversion_was_parsed: Y"
            ),
            RS_CONST_STRLEN(
                "ws.rmsg_utf8_state: 255, "
                "ws.heap_buf_contains_pong: Y, "
                "ws.rmsg_is_fragmented: Y, "
                "ws.rmsg_is_utf8: Y, "
                "ws.wref_c: 255, "
                "ws.wref_i: 4294967295, "
                "ws.msg_rsize: 4294967295, "
                "ws.unparsed_rsize: 4294967295 "
            )
        ) +
        RS_CONST_STRLEN(")") +
        1
    ] = {0};
    char * str = get_addr_str(peer->socket_fd, peer_str);
    str += sprintf(str, " ("
        "is_encrypted: %c, "
        "is_writing: %c, "
        "layer: %s, "
        "mortality: %s, "
        "continuation: %s, "
        "app_i: %" PRIu8 ", "
        "endpoint_i: %" PRIu16 ", "
        "socket_fd: %d, "
        "heap_buf: %s, "
        "shutdown_deadline: %" PRIu16,
        peer->is_encrypted ? 'Y' : 'N',
        peer->is_writing ? 'Y' : 'N',
        (char *[]){"TCP", "TLS", "HTTP", "WS"}[peer->layer],
        (char *[]){"LIVE", "SHUTDOWN_WRITE_WS", "SHUTDOWN_WRITE",
            "SHUTDOWN_READ", "DEAD"}[peer->mortality],
        (char *[]){"NONE", "PARSING", "SENDING"}[peer->continuation],
        peer->app_i,
        peer->endpoint_i,
        peer->socket_fd,
        peer->heap_buf ? "used" : "null",
        peer->shutdown_deadline
    );
    if (!peer->is_encrypted) {
        str += sprintf(str, ", old_wsize: %zu", peer->old_wsize);
    }
    if (peer->layer == RS_LAYER_HTTP) {
        str += sprintf(str, ", "
            "http.origin_i: %" PRIu16 ", "
            "http.partial_strlen: %" PRIu32 ", "
            "http.jump_distance: %" PRIu16 ", "
            "http.error_i: %" PRIu8 ", "
            "http.hostname_was_parsed: %c, "
            "http.origin_was_parsed: %c, "
            "http.upgrade_was_parsed: %c, "
            "http.wskey_was_parsed: %c, "
            "http.wsversion_was_parsed: %c",
            peer->http.origin_i,
            peer->http.partial_strlen,
            peer->http.jump_distance,
            peer->http.error_i,
            peer->http.hostname_was_parsed ? 'Y' : 'N',
            peer->http.origin_was_parsed ? 'Y' : 'N',
            peer->http.upgrade_was_parsed ? 'Y' : 'N',
            peer->http.wskey_was_parsed ? 'Y' : 'N',
            peer->http.wsversion_was_parsed ? 'Y' : 'N'
            );
    } else if (peer->layer == RS_LAYER_WEBSOCKET) {
        str += sprintf(str, ", "
            "ws.heap_buf_contains_pong: %c, "
            "ws.rmsg_is_fragmented: %c, "
            "ws.rmsg_is_utf8: %c, "
            "ws.rmsg_utf8_state: %" PRIu8 ", "
            "ws.wref_c: %" PRIu8 ", "
            "ws.wref_i: %" PRIu32 ", "
            "ws.msg_rsize: %" PRIu32 ", "
            "ws.%s: %" PRIu32,
            peer->ws.heap_buf_contains_pong ? 'Y' : 'N',
            peer->ws.rmsg_is_fragmented ? 'Y' : 'N',
            peer->ws.rmsg_is_utf8 ? 'Y' : 'N',
            peer->ws.rmsg_utf8_state,
            peer->ws.wref_c,
            peer->ws.wref_i,
            peer->ws.msg_rsize,
            peer->mortality == RS_MORTALITY_LIVE ?
                "unparsed_rsize" : "close_wmsg_i",
            peer->ws.unparsed_rsize // same as unionized peer->ws.close_wmsg_i
        );
    }
    * str = ')';
    return peer_str;
}

char * get_epoll_events_str(
    uint32_t epoll_events
) {
    thread_local static char str[] =
        "[EPOLLERR, EPOLLHUP, EPOLLRDHUP, EPOLLOUT, EPOLLIN, ";
    if (epoll_events) {
        int size = sprintf(str, "[%s%s%s%s%s",
            epoll_events & EPOLLERR   ?   "EPOLLERR, " : "",
            epoll_events & EPOLLHUP   ?   "EPOLLHUP, " : "",
            epoll_events & EPOLLRDHUP ? "EPOLLRDHUP, " : "",
            epoll_events & EPOLLOUT   ?   "EPOLLOUT, " : "",
            epoll_events & EPOLLIN    ?    "EPOLLIN, " : ""
        );
        str[--size] = '\0';
        str[--size] = ']';
    } else {
        strcpy(str, "(none)");
    }
    return str;
}

// Move <size> bytes from <dest + offset> to <dest>. Source memory range and
// destination memory range are allowed to overlap. Implemented through one or
// more memcpy() operations of max <offset> bytes from the source range leftward
// to the destination in left to right order, which has the cache-miss-reducing
// benefit of eliminating the need to copy to a temporary intermediate buffer
// outside of the <dest> array -- as might have been the case if a naive
// memmove() implementation was used instead.
void move_left(
    void * dest,
    size_t offset,
    size_t size
) {
    uint8_t * _dest = dest;
    uint8_t * _src = _dest + offset;
    size_t moved_size = 0;
    while (size > offset) {
        memcpy(_dest + moved_size, _src + moved_size, offset);
        size -= offset;
        moved_size += offset;
    }
    memcpy(_dest + moved_size, _src + moved_size, size);
}
