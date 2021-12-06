// SPDX-License-Identifier: MIT
// Copyright © 2021 MetaWord Inc
// Copyright © 2019-2021 William Budd

#pragma once

#include <ringsocket_api.h>
// <ringsocket_variadic.h>           # Arity-based macro expansion helper macros
//   |
//   \---> <ringsocket_api.h>                            # RingSocket's core API
//                        |
//   [YOU ARE HERE]       |
// <ringsocket_conf.h> <--/   # Definition of struct rs_conf and its descendents
//   |
//   \---> <ringsocket_ring.h> # Single producer single consumer ring buffer API
//                         |
// <ringsocket_queue.h> <--/      # Ring buffer update queuing and thread waking
//   |
//   \--> <ringsocket_wsframe.h>   # RFC 6455 WebSocket frame protocol interface
//                           |
// <ringsocket_app.h> <------/    # Definition of RS_APP() and descendent macros
//   |            |
//   |            |
//   |            \--------------> [ Worker translation units: see rs_worker.h ]
//   |
//   |
//   \--> <ringsocket_helper.h> # Definitions of app helper functions (internal)
//                          |
//  <ringsocket.h> <--------/        # Definitions of app helper functions (API)
//    |
//    |
//    \-------------------------------> [ Any RingSocket app translation units ]

#include <arpa/inet.h> // struct in_addr, struct in6_addr
#include <stdbool.h>

// A single struct rs_conf const pointer "conf" is shared between all worker and
// app threads. This same pointer is returned by the app helper rs_get_conf().
// It is therefore paramount that this struct instance and all its descendent
// structs are treated as read-only, as the "const" implies!

// Struct member naming mostly mirrors the key strings recognized by the JSON
// configuration file, as described in README.md's Configuration section;
// although minor differences exist.

struct rs_conf {
    struct rs_conf_port * ports;
    struct rs_conf_cert * certs;
    struct rs_conf_app * apps;
    size_t inbound_ring_buf_size;
    size_t outbound_ring_buf_size;
    size_t worker_rbuf_size;
    size_t max_ws_msg_size;
    size_t max_ws_frame_chain_size;
    double realloc_multiplier;
    uint32_t fd_alloc_c;
    uint32_t owrefs_elem_c;
    uint16_t epoll_buf_elem_c;
    uint16_t port_c;
    uint16_t cert_c;
    uint16_t app_c;
    uint16_t worker_c;
    uint8_t update_queue_size;
    uint8_t hostname_max_strlen;
    uint8_t url_max_strlen;
    uint8_t allowed_origin_max_strlen;
    uint8_t shutdown_wait_http; // in seconds
    uint8_t shutdown_wait_ws; // in seconds
};

struct rs_conf_port {
    int * * listen_fds;
    union {
        struct in_addr * ipv4_addrs;
        char * interface;
    };
    struct in6_addr * ipv6_addrs;
    uint16_t ipv4_addr_c;
    uint16_t ipv6_addr_c;
    uint16_t port_number;
    uint16_t listen_fd_c;
    uint8_t listen_ip_kind;
    uint8_t is_encrypted; // boolean
};

enum rs_listen_ip_kind {
    RS_LISTEN_IP_ANY = 0,
    RS_LISTEN_IP_ANY_V6_OR_EMBEDDED_V4 = 1,
    RS_LISTEN_IP_ANY_V4 = 2,
    RS_LISTEN_IP_ANY_V6 = 3,
    RS_LISTEN_IP_SPECIFIC = 4
};

struct rs_conf_cert {
    char * * hostnames;
    char * privkey_path;
    char * pubchain_path;
    size_t hostname_c;
};

struct rs_conf_app {
    char * name;
    char * app_path;
    struct rs_conf_endpoint * endpoints;
    uint32_t endpoint_c;
    uint32_t wbuf_size;
    uint16_t wants_open_notification; // boolean
    uint16_t wants_close_notification; // boolean
    uint8_t update_queue_size;
};

struct rs_conf_endpoint {
    char * hostname;
    char * url;
    char * * allowed_origins;
    uint16_t allowed_origin_c;
    uint16_t endpoint_id;
    uint16_t port_number;
    uint16_t is_encrypted; // boolean
};

// #############################################################################
// # The following functions are defined here instead of in rs_conf.c mainly to
// # allow their reuse outside of RingSocket itself (e.g., by rst_client_echo.c)

static inline rs_ret rs_set_log_level(
    char const * log_level_str
) {
    if (!strcmp(log_level_str, "error")) {
        _rs_log_max = LOG_ERR;
        return RS_OK;
    }
    if (!strcmp(log_level_str, "warning")) {
        _rs_log_max = LOG_WARNING;
        return RS_OK;
    }
    if (!strcmp(log_level_str, "notice")) {
        _rs_log_max = LOG_NOTICE;
        return RS_OK;
    }
    if (!strcmp(log_level_str, "info")) {
        _rs_log_max = LOG_INFO;
        RS_LOG(LOG_INFO, "Syslog log priority set to \"info\"");
        return RS_OK;
    }
    if (!strcmp(log_level_str, "debug")) {
        _rs_log_max = LOG_DEBUG;
        RS_LOG(LOG_INFO, "Syslog log priority set to \"debug\"");
        return RS_OK;
    }
    RS_LOG(LOG_ERR, "Unrecognized log_level configuration value \"%s\". "
        "Value must be one of: \"error\", \"warning\", \"notice\", \"info\", "
        "or \"debug\".", log_level_str);
    return RS_FATAL;
}

static inline rs_ret rs_parse_canon_ws_url(
    char const * url,
    struct rs_conf_endpoint * endpoint
) {
    char const * str = url;
    if (*str++ == 'w') {
        if (*str++ == 's') {
            if (*str == 's') {
                endpoint->is_encrypted = true;
                str++;
            }
            if (*str++ == ':') {
                if (*str++ == '/') {
                    if (*str++ == '/') {
                        goto parse_url_hostname;
                    }
                }
            }
        }
    }
    RS_LOG(LOG_ERR, "WebSocket URL \"%s\" does not start with the required "
        "scheme \"wss://\" or \"ws://\"", url);
    return RS_FATAL;
    parse_url_hostname:
    if (*str == '\0') {
        RS_LOG(LOG_ERR, "WebSocket URL \"%s\" seems to be missing a hostname",
            url);
        return RS_FATAL;
    }
    char * slash = strchr(str, '/');
    {
        char * colon = strchr(str, ':');
        if (colon) {
            if (slash && colon > slash) {
                RS_LOG(LOG_ERR, "WebSocket URL \"%s\" seems to contain a stray "
                    "colon in its path. A colon is only allowed in the "
                    "hostname section as a port number designator.", url);
                return RS_FATAL;
            }
            long i = strtol(++colon, NULL, 10);
            if (i < 0 || i > UINT16_MAX) {
                RS_LOG(LOG_ERR, "WebSocket URL \"%s\" contains an invalid port "
                    "number. Port numbers must be integers within the range "
                    "0 through 65535.", url);
                return RS_FATAL;
            }
            endpoint->port_number = i;
        } else if (endpoint->is_encrypted) {
            endpoint->port_number = 443;
        } else {
            endpoint->port_number = 80;
        }
    }
    if (slash) {
        RS_CALLOC(endpoint->hostname, slash - str + 1);
        memcpy(endpoint->hostname, str, slash - str);
        if (*++slash != '\0') {
            RS_CALLOC(endpoint->url, strlen(slash) + 1);
            strcpy(endpoint->url, slash);
        }
    } else {
        RS_CALLOC(endpoint->hostname, strlen(str) + 1);
        strcpy(endpoint->hostname, str);
    }
    return RS_OK;
}
