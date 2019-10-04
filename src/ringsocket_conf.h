// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket.h>
#include <arpa/inet.h> // struct in_addr, struct in6_addr

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
    double realloc_multiplier;
    uint32_t fd_alloc_c;
    uint32_t max_ws_msg_size;
    uint32_t worker_rbuf_size;
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
