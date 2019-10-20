// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#define _GNU_SOURCE // NI_MAXHOST, NI_MAXSERV

#include "rs_util.h"

#include <netdb.h> // getnameinfo(), MI_MAXHOST, NI_MAXSERV
#include <sys/epoll.h> // EPOLL* event bitflag macros

// Move "size" bytes from "dst"+"offset" to "dst". Source memory range and
// destination memory range are allowed to overlap. Implemented through one or
// more memcpy() operations of max "offset" bytes from the source range leftward
// to the destination in left to right order, which has the cache-miss-reducing
// benefit of eliminating the need to copy to a temporary intermediate buffer
// outside of the "dst" array -- as might have been the case if a naive
// memmove() implementation was used instead.
void move_left(
    void * dst,
    size_t offset,
    size_t size
) {
    uint8_t * _dst = dst;
    uint8_t * _src = _dst + offset;
    size_t moved_size = 0;
    while (size > offset) {
        memcpy(_dst + moved_size, _src + moved_size, offset);
        size -= offset;
        moved_size += offset;
    }
    memcpy(_dst + moved_size, _src + moved_size, size);
}

// Helper for bin_to_log_buf() and pointer_context_to_log_buf() (see below).
static char * bin_to_hex(
    uint8_t const * bin,
    uint8_t const * const bin_max,
    char * hex,
    char * const hex_max
) {
    char const hex_table[] = "0123456789ABCDEF";
    if (bin <= bin_max && hex <= hex_max) {
        *hex++ = hex_table[*bin >> 4];
        *hex++ = hex_table[*bin++ & 0xF];
        while (bin <= bin_max && hex <= hex_max) {
            *hex++ = ' ';
            *hex++ = hex_table[*bin >> 4];
            *hex++ = hex_table[*bin++ & 0xF];
        }
    }
    return hex;
}

// For any buf/array "bin" of "size" bytes, store a hex representation string of
// its binary contents in worker->log_buf. Any tail end of the hex string that
// would overflow sizeof(worker->log_buf) is truncated. The resulting
// worker-log_buf string is guaranteed to be null-terminated. Finally,
// return the worker->log_buf pointer to allow calls to be inlined as arguments.
char * bin_to_log_buf(
    struct rs_worker * worker,
    void const * bin,
    size_t size
) {
    char * hex = worker->log_buf;
    char * const hex_max = hex + sizeof(worker->log_buf) - 1;
    static_assert(sizeof(worker->log_buf) >= sizeof("[01]"));
    
    *hex++ = '[';
    hex = bin_to_hex(bin, (uint8_t const *) bin + size - 1,
        hex, hex_max - sizeof(" EF]"));
    *hex++ = ']';
    *hex = '\0';
    return worker->log_buf;
}

// Same as bin_to_log_buf() above, except that the hex sequence shall start
// "max_left_byte_c" to the left of "pointer" and end "max_right_byte_c" to the
// right of it, with the byte at "pointer" enclosed in angular <> brackets.
// However, any such start or end part beyond the "lower_bound" or "upper_bound"
// pointer arguments respectively shall be truncated -- lest we crash and burn.
char * pointer_context_to_log_buf(
    struct rs_worker * worker,
    void const * pointer,
    void const * lower_bound,
    void const * upper_bound,
    size_t max_left_byte_c,
    size_t max_right_byte_c
) {
    uint8_t const * const ptr = pointer;
    uint8_t const * const lower = lower_bound;
    uint8_t const * const upper = upper_bound;

    char * hex = worker->log_buf;
    char * const hex_max = hex + sizeof(worker->log_buf) - 1;
    static_assert(sizeof(worker->log_buf) >= sizeof("[01 <23> 45]"));
    
    *hex++ = '[';
    if (ptr > lower) {
        hex = bin_to_hex(RS_MAX(ptr - max_left_byte_c, lower), ptr - 1,
            hex, hex_max - sizeof(" CD <EF> ]"));
        *hex++ = ' ';
    }
    *hex++ = '<';
    hex = bin_to_hex(ptr, ptr, hex, hex_max - sizeof("EF> ]"));
    *hex++ = '>';
    if (ptr < upper) {
        *hex++ = ' ';
        hex = bin_to_hex(ptr + 1, RS_MIN(upper, ptr + max_right_byte_c),
            hex, hex_max - sizeof(" EF]"));
    }
    *hex++ = ']';
    *hex = '\0';
    return worker->log_buf;
}

char * get_addr_str(
    union rs_peer const * peer
) {
    thread_local static char addr_str[
        RS_CONST_STRLEN("[") + NI_MAXHOST + RS_CONST_STRLEN("]:") +
        NI_MAXSERV + 1
    ] = {0};

    struct sockaddr_storage addr = {0};
    socklen_t addr_size = sizeof(addr);
    if (getpeername(peer->socket_fd, (struct sockaddr *) &addr, &addr_size) ==
        -1) {
        RS_LOG_ERRNO(LOG_NOTICE, "Unsuccessful getpeername(%d, ...)",
            peer->socket_fd);
        strcpy(addr_str, "<UNKNOWN>");
        return addr_str;
    }

    char * str = addr_str;
    if (addr.ss_family == AF_INET6) {
        *str++ = '[';
    }
    char * port_str = str + NI_MAXHOST + RS_CONST_STRLEN("]:");
    int ret = getnameinfo((struct sockaddr *) &addr, addr_size, str,
        NI_MAXHOST, port_str, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
    if (ret) {
        RS_LOG(LOG_NOTICE, "Unsuccessful getnameinfo(): %s", gai_strerror(ret));
        strcpy(addr_str, "<UNKNOWN>");
        return addr_str;
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
    return addr_str;
}

char * print_to_log_buf(
    struct rs_worker * worker,
    char * log_dst,
    char const * fmt,
    ...
) {
    if (log_dst < worker->log_buf) {
        RS_LOG(LOG_ERR, "The code monkey responsible for the calling function "
            "messed up: first worker->log_buf character byte position "
            "undershot by %zu bytes", worker->log_buf - log_dst);
        return NULL;
    }
    if (log_dst >= worker->log_buf + sizeof(worker->log_buf) - 1) {
        RS_LOG(LOG_ERR, "The code monkey responsible for the calling function "
            "messed up: last worker->log_buf character byte position overshot "
            "by %zu bytes",
            log_dst - (worker->log_buf + sizeof(worker->log_buf) - 1));
        return NULL;
    }
    // Don't subtract 1 from max_char_c because vsnprintf() expects the null
    // byte to be included when calculating its max size argument.
    size_t max_char_c = worker->log_buf + sizeof(worker->log_buf) - log_dst;

    va_list args;
    va_start(args, fmt);
    int char_c = vsnprintf(log_dst, max_char_c, fmt, args);
    va_end(args);

    if (char_c < 0) {
        RS_LOG(LOG_ERR, "Unsuccessful snprintf(%p, %zu, %s, ...)",
            log_dst, max_char_c, fmt);
        return NULL;
    }
    if ((size_t) char_c > max_char_c) {
        RS_LOG(LOG_WARNING, "Insufficient worker->log_buf size: "
            "log message truncated by %zu bytes", char_c - max_char_c);
        return NULL;
    }
    return log_dst + char_c;
}

char * get_peer_str(
    struct rs_worker * worker,
    union rs_peer const * peer
) {
    char * log_dst = worker->log_buf;
    if (!(log_dst = print_to_log_buf(worker, log_dst,
        "%s ("
        "is_encrypted: %c, "
        "is_writing: %c, "
        "layer: %s, "
        "mortality: %s, "
        "continuation: %s, "
        "app_i: %" PRIu8 ", "
        "endpoint_i: %" PRIu16 ", "
        "socket_fd: %d, "
        "shutdown_deadline: %" PRIu16 ", ",
        get_addr_str(peer),
        peer->is_encrypted ? 'Y' : 'N',
        peer->is_writing ? 'Y' : 'N',
        (char *[]){"TCP", "TLS", "HTTP", "WS"}[RS_BOUNDS(0, peer->layer, 3)],
        (char *[]){"LIVE", "SHUTDOWN_WRITE_WS", "SHUTDOWN_WRITE",
            "SHUTDOWN_READ", "DEAD"}[RS_BOUNDS(0, peer->mortality, 4)],
        (char *[]){"NONE", "PARSING", "SENDING"}
            [RS_BOUNDS(0, peer->continuation, 2)],
        peer->app_i,
        peer->endpoint_i,
        peer->socket_fd,
        peer->shutdown_deadline
    ))) {
        return NULL;
    }
    if (!peer->is_encrypted && !(log_dst = print_to_log_buf(worker, log_dst,
        "old_wsize: %zu, ", peer->old_wsize))) {
        return NULL;
    }
    if (peer->layer == RS_LAYER_HTTP) {
        if (!print_to_log_buf(worker, log_dst,
            "http.hostname_was_parsed: %c, "
            "http.origin_was_parsed: %c, "
            "http.upgrade_was_parsed: %c, "
            "http.wskey_was_parsed: %c, "
            "http.wsversion_was_parsed: %c, "
            "http.error_i: %" PRIu8 ", "
            "http.jump_distance: %" PRIu16 ", "
            "http.partial_strlen: %" PRIu32 ", "
            "http.origin_i: %" PRIu16 ", "
            "http.char_buf: %s)",
            peer->http.hostname_was_parsed ? 'Y' : 'N',
            peer->http.origin_was_parsed ? 'Y' : 'N',
            peer->http.upgrade_was_parsed ? 'Y' : 'N',
            peer->http.wskey_was_parsed ? 'Y' : 'N',
            peer->http.wsversion_was_parsed ? 'Y' : 'N',
            peer->http.error_i,
            peer->http.jump_distance,
            peer->http.partial_strlen,
            peer->http.origin_i,
            peer->http.char_buf ? "used" : "null"
        )) {
            return NULL;
        }
    } else if (peer->layer == RS_LAYER_WEBSOCKET) {
        if (!(log_dst = print_to_log_buf(worker, log_dst,
            "ws.owref_c: %" PRIu16 ", "
            "ws.owref_i: %" PRIu32 ", ",
            peer->ws.owref_c,
            peer->ws.owref_i
        ))) {
            return NULL;
        }
        if (peer->mortality == RS_MORTALITY_LIVE) {
            if (!print_to_log_buf(worker, log_dst,
                "ws.%s: %s)",
                peer->continuation == RS_CONT_SENDING ? "pong_response" :
                "storage", peer->ws.storage ? "used" : "null"
            )) {
                return NULL;
            }
        } else if (!print_to_log_buf(worker, log_dst,
            "ws.close_frame: %d)",
            peer->ws.close_frame
        )) {
            return NULL;
        }
    }
    return worker->log_buf;
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
