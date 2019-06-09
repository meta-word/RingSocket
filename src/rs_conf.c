// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include "rs_conf.h"
#include "rs_tls.h" // derive_cert_index_from_hostname()

// Configuration file parsing is done with libckv: https://github/wbudd/libckv
#include <ckv.h> // ckv_*()
#include <ifaddrs.h> // getifaddrs()
#include <net/if.h> // IF_NAMESIZE

#define RS_GUARD_CKV(ckv_ret) do { \
    if ((ckv_ret) != CKV_OK) { \
        RS_LOG(LOG_ERR, "Error parsing configuration file: %s", \
            ckv_get_err_str(ckv)); \
        return RS_FATAL; \
    } \
} while (0)

// These numbers are merely an attempt at providing sensible defaults
#define RS_DEFAULT_FD_ALLOC_C 10000
#define RS_MIN_FD_ALLOC_C 0x1000 // 4096 == the Linux default these days
#define RS_DEFAULT_MAX_WS_MSG_SIZE 0x1000000 // 16 MB
#define RS_MIN_MAX_WS_MSG_SIZE 125
#define RS_MAX_MAX_WS_MSG_SIZE (UINT32_MAX - 0xFF)
#define RS_DEFAULT_WORKER_RBUF_SIZE (2 * RS_DEFAULT_MAX_WS_MSG_SIZE)
#define RS_MIN_WORKER_RBUF_SIZE (2 * RS_MIN_MAX_WS_MSG_SIZE)
#define RS_DEFAULT_INBOUND_RING_BUF_SIZE (4 * RS_DEFAULT_MAX_WS_MSG_SIZE)
#define RS_MIN_INBOUND_RING_BUF_SIZE (4 * RS_MIN_MAX_WS_MSG_SIZE)
#define RS_DEFAULT_OUTBOUND_RING_BUF_SIZE (8 * RS_DEFAULT_MAX_WS_MSG_SIZE)
#define RS_MIN_OUTBOUND_RING_BUF_SIZE (8 * RS_MIN_MAX_WS_MSG_SIZE)
#define RS_DEFAULT_REALLOC_MULTIPLIER 1.5
#define RS_MIN_REALLOC_MULTIPLIER 1.05
#define RS_MAX_REALLOC_MULTIPLIER 2.5
#define RS_DEFAULT_WREFS_ELEM_C 10000
#define RS_MIN_WREFS_ELEM_C 1000
#define RS_DEFAULT_EPOLL_BUF_ELEM_C 100
#define RS_MIN_EPOLL_BUF_ELEM_C 10
#define RS_DEFAULT_UPDATE_QUEUE_SIZE 5
#define RS_DEFAULT_APP_WBUF_SIZE 0x100000 // 1.6 MB
#define RS_MIN_APP_WBUF_SIZE 64
#define RS_MAX_CERT_C 0xFFFF // 65535
#define RS_IP_ADDR_MAX_STRLEN 0x3F // 63
#define RS_HOSTNAME_MAX_STRLEN 0x3FF // 1023
#define RS_PATH_MAX_STRLEN 0x1FFF // 8191
#define RS_URI_MAX_STRLEN 0x1FFF // 8191
#define RS_MAX_ALLOWED_ORIGIN_C 0x1FFF // 8191
#define RS_ALLOWED_ORIGIN_MAX_STRLEN 0x1FFF // 8191
#define RS_DEFAULT_SHUTDOWN_WAIT_HTTP 15 // in seconds
#define RS_DEFAULT_SHUTDOWN_WAIT_WS 30

static char const default_conf_path[] = "/etc/ringsocket.ckv";

// The only 2 vars with external linkage in RingSocket -- see ringsocket_util.h

// Configurable at run-time with the top-level "log_level" option -- see below
int _rs_log_mask = LOG_UPTO(LOG_WARNING);

// Worker threads set this to "Worker #%u: " with (worker_i + 1) as the %u arg.
// App threads set this to "App %s: " were %s is the app "name" string
// as defined in the configuration file -- see below. RS_APP_NAME_MAX_STRLEN
// and RS_THREAD_ID_MAX_STRLEN are defined in ringsocket_util.h.
thread_local char _rs_thread_id_str[RS_THREAD_ID_MAX_STRLEN + 1] = {0};

static bool ipv4_address_is_duplicate(
    struct in_addr const * new_addr,
    struct in_addr const * addrs,
    size_t addr_c
) {
    for (struct in_addr const * a = addrs; a < addrs + addr_c; a++) {
        if (!memcmp(a, new_addr, sizeof(struct in_addr))) {
            return true;
        }
    }
    return false;
}

static bool ipv6_address_is_duplicate(
    struct in6_addr const * new_addr,
    struct in6_addr const * addrs,
    size_t addr_c
) {
    for (struct in6_addr const * a = addrs; a < addrs + addr_c; a++) {
        if (!memcmp(a, new_addr, sizeof(struct in6_addr))) {
            return true;
        }
    }
    return false;
}

static rs_ret add_ip_addrs_from_strs(
    char * const * ip_strs,
    size_t ip_str_c,
    struct rs_conf_port * port
) {
    for (char * const * ip_str = ip_strs; ip_str < ip_strs + ip_str_c;
        ip_str++) {
        struct in_addr ipv4_addr = {0};
        if (inet_pton(AF_INET, *ip_str, &ipv4_addr)) {
            if (ipv4_address_is_duplicate(&ipv4_addr, port->ipv4_addrs,
                port->ipv4_addr_c)) {
                RS_LOG(LOG_ERR, "Duplicate IPv4 address \"%s\" for port %u",
                    *ip_str, port->port_number);
                return RS_FATAL;
            }
            RS_REALLOC(port->ipv4_addrs, port->ipv4_addr_c + 1);
            memcpy(port->ipv4_addrs + port->ipv4_addr_c++, &ipv4_addr,
                sizeof(struct in_addr));
        } else {
            struct in6_addr ipv6_addr = {0};
            if (!inet_pton(AF_INET6, *ip_str, &ipv6_addr)) {
                RS_LOG(LOG_ERR, "Port %u: \"%s\" is neither a valid IPv4 "
                    "address nor a valid IPv6 address", port->port_number,
                    *ip_str);
                return RS_FATAL;
            }
            if (ipv6_address_is_duplicate(&ipv6_addr, port->ipv6_addrs,
                port->ipv6_addr_c)) {
                RS_LOG(LOG_ERR, "Duplicate IPv6 address \"%s\" for port %u",
                    *ip_str, port->port_number);
                return RS_FATAL;
            }
            RS_REALLOC(port->ipv6_addrs, port->ipv6_addr_c + 1);
            memcpy(port->ipv6_addrs + port->ipv6_addr_c++, &ipv6_addr,
                sizeof(struct in6_addr));
        }
    }
    return RS_OK;
}

static rs_ret parse_uri(
    char const * uri,
    struct rs_conf_endpoint * endpoint
) {
    char const * str = uri;
    if (*str++ == 'w') {
        if (*str++ == 's') {
            if (*str == 's') {
                endpoint->is_encrypted = true;
                str++;
            }
            if (*str++ == ':') {
                if (*str++ == '/') {
                    if (*str++ == '/') {
                        goto parse_uri_hostname;
                    }
                }
            }
        }
    }
    RS_LOG(LOG_ERR, "WebSocket URI \"%s\" does not start with the required "
        "scheme \"wss://\" or \"ws://\"", uri);
    return RS_FATAL;
    parse_uri_hostname:
    if (*str == '\0') {
        RS_LOG(LOG_ERR, "WebSocket URI \"%s\" seems to be missing a hostname",
            uri);
        return RS_FATAL;
    }
    char * slash = strchr(str, '/');
    {
        char * colon = strchr(str, ':');
        if (colon) {
            if (slash && colon > slash) {
                RS_LOG(LOG_ERR, "WebSocket URI \"%s\" seems to contain a stray "
                    "colon in its path. A colon is only allowed in the "
                    "hostname section as a port number designator.", uri);
                return RS_FATAL;
            }
            long i = strtol(++colon, NULL, 10);
            if (i < 0 || i > UINT16_MAX) {
                RS_LOG(LOG_ERR, "WebSocket URI \"%s\" contains an invalid port "
                    "number. Port numbers must be integers within the range "
                    "1 through 65535.", uri);
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

static rs_ret check_if_endpoint_is_duplicate(
    struct rs_conf_endpoint const * old,
    struct rs_conf_endpoint const * new,
    char const * uri
) {
    if (strcmp(old->url, new->url) || strcmp(old->hostname, new->hostname)) {
        return RS_OK;
    }
    RS_LOG(LOG_ERR, "Duplicate endpoint WebSocket URI: %s", uri);
    return RS_FATAL;
}

static rs_ret parse_endpoint(
    ckv_t * ckv,
    struct ckv_map * map,
    struct rs_conf_endpoint * endpoint,
    struct rs_conf_app * app,
    struct rs_conf * conf
) {
    RS_GUARD_CKV(ckv_get_uint16(ckv, (ckv_arg_uint16){
        .map = map,
        .key = "endpoint_id",
        .is_required = true,
        .dst = &endpoint->endpoint_id
    }));
    {
        size_t allowed_origin_c = 0;
        RS_GUARD_CKV(ckv_get_strs(ckv, (ckv_arg_strs){
            .map = map,
            .key = "allowed_origins",
            .is_required = true,
            .min_c = 1,
            .max_c = RS_MAX_ALLOWED_ORIGIN_C,
            .max_strlen = RS_ALLOWED_ORIGIN_MAX_STRLEN,
            .elem_c = &allowed_origin_c,
            .dst = &endpoint->allowed_origins
        }));
        endpoint->allowed_origin_c = allowed_origin_c;
    }
    for (char * * ao = endpoint->allowed_origins;
         ao < endpoint->allowed_origins + endpoint->allowed_origin_c; ao++) {
        if (strlen(*ao) > conf->allowed_origin_max_strlen) {
            conf->allowed_origin_max_strlen = strlen(*ao);
        }
    }
    char * uri = NULL;
    RS_GUARD_CKV(ckv_get_str(ckv, (ckv_arg_str){
        .map = map,
        .key = "uri",
        .is_required = true,
        .max_strlen = RS_URI_MAX_STRLEN,
        .dst = &uri
    }));
    RS_GUARD(parse_uri(uri, endpoint));
    for (struct rs_conf_app *a = conf->apps; a < app; a++) {
        for (struct rs_conf_endpoint *e = a->endpoints;
             e < a->endpoints + a->endpoint_c; e++) {
            RS_GUARD(check_if_endpoint_is_duplicate(e, endpoint, uri));
        }
    }
    for (struct rs_conf_endpoint *e = app->endpoints; e < endpoint; e++) {
        RS_GUARD(check_if_endpoint_is_duplicate(e, endpoint, uri));
    }
    if (strlen(endpoint->hostname) > conf->hostname_max_strlen) {
        conf->hostname_max_strlen = strlen(endpoint->hostname);
    }
    if (strlen(endpoint->url) > conf->url_max_strlen) {
        conf->url_max_strlen = strlen(endpoint->url);
    }
    for (struct rs_conf_port *port = conf->ports;
         port < conf->ports + conf->port_c; port++) {
        if (port->port_number == endpoint->port_number) {
            if (port->is_encrypted != endpoint->is_encrypted) {
                RS_LOG(LOG_ERR, "The port number '%u' contained in WebSocket "
                    "URI \"%s\" is listed under \"ports\" with%s the "
                    "\"is_unencrypted\" flag, but this contradicts the scheme "
                    "with which the URI begins (\"ws%s://\"), which specifies "
                    "an %sencrypted connection.", endpoint->port_number, uri,
                    port->is_encrypted ? "out" : "", endpoint->is_encrypted ?
                    "s" : "", endpoint->is_encrypted ? "" : "un");
                return RS_FATAL;
            }
            if (endpoint->is_encrypted) {
                char * colon = strchr(endpoint->hostname, ':');
                size_t hostname_strlen = colon ?
                    (size_t) (colon - endpoint->hostname) :
                    strlen(endpoint->hostname);
                if (derive_cert_index_from_hostname(conf, endpoint->hostname,
                    hostname_strlen) < 0) {
                    // Overwrite colon (if any) prior to logging
                    endpoint->hostname[hostname_strlen] = '\0';
                    RS_LOG(LOG_ERR, "Could not find any TLS certificate "
                        "listed under the configuration file's \"certs\" that "
                        "matches the hostname portion \"%s\" of the secure "
                        "WebSocket URI \"%s\".", endpoint->hostname, uri);
                    return RS_FATAL;
                }
            }
            RS_FREE(uri);
            return RS_OK;
        }
    }
    switch (endpoint->port_number) {
    case 80:
        RS_LOG(LOG_ERR, "WebSocket URI \"%s\" implies endpoint port number "
            "80, but no \"ports\" entry in the configuration file listing "
            "such a \"port_number\" was found.", uri);
        return RS_FATAL;
    case 443:
        RS_LOG(LOG_ERR, "WebSocket URI \"%s\" implies endpoint port number "
            "443, but no \"ports\" entry in the configuration file listing "
            "such a \"port_number\" was found.", uri);
        return RS_FATAL;
    default:
        RS_LOG(LOG_ERR, "The port number '%u' contained in WebSocket URI "
            "\"%s\" is not listed under \"ports\" in the configuration file.",
            endpoint->port_number, uri);
        return RS_FATAL;
    }
}

static rs_ret parse_port(
    ckv_t * ckv,
    struct ckv_map * map,
    struct rs_conf_port * port,
    struct rs_conf_port * ports
) {
    RS_GUARD_CKV(ckv_get_uint16(ckv, (ckv_arg_uint16){
        .map = map,
        .key = "port_number",
        .is_required = true,
        .dst = &port->port_number
    }));
    for (struct rs_conf_port * p = ports; p < port; p++) {
        if (p->port_number == port->port_number) {
            RS_LOG(LOG_ERR, "Duplicate port number: %u" , port->port_number);
            return RS_FATAL;
        }
    }
    {
        bool is_unencrypted = false;
        RS_GUARD_CKV(ckv_get_bool(ckv, (ckv_arg_bool){
            .map = map,
            .key = "is_unencrypted",
            .dst = &is_unencrypted
        }));
        port->is_encrypted = !is_unencrypted;
    }
    {
        char * * ip_strs = NULL;
        size_t ip_str_c = 0;
        RS_GUARD_CKV(ckv_get_strs(ckv, (ckv_arg_strs){
            .map = map,
            .key = "ip_addrs",
            .min_c = 1,
            .max_c = UINT16_MAX,
            .max_strlen = RS_IP_ADDR_MAX_STRLEN,
            .elem_c = &ip_str_c,
            .dst = &ip_strs
        }));
        if (ip_str_c) {
            RS_GUARD(add_ip_addrs_from_strs(ip_strs, ip_str_c, port));
            port->listen_ip_kind = RS_LISTEN_IP_SPECIFIC;
        }
    }
    RS_GUARD_CKV(ckv_get_str(ckv, (ckv_arg_str){
        .map = map,
        .key = "interface",
        .max_strlen = IF_NAMESIZE,
        .dst = &port->interface
    }));
    if (port->interface && port->listen_ip_kind != RS_LISTEN_IP_ANY) {
        RS_LOG(LOG_ERR, "\"ipv4only\" cannot be set in combination with any "
            "of the following keys on the same port (%u): \"ipv4_addrs\", "
            "\"ipv6_addrs\"", port->port_number);
        return RS_FATAL;
    }
    {
        bool ipv4only = false;
        RS_GUARD_CKV(ckv_get_bool(ckv, (ckv_arg_bool){
            .map = map,
            .key = "ipv4only",
            .dst = &ipv4only
        }));
        if (ipv4only) {
            if (port->listen_ip_kind != RS_LISTEN_IP_ANY) {
                RS_LOG(LOG_ERR, "\"ipv4only\" cannot be set in combination "
                    "with any of the following keys on the same port (%u): "
                    "\"ipv4_addrs\", \"ipv6_addrs\", \"ipv6only\", "
                    "\"ipv4_is_embedded_in_ipv6\"", port->port_number);
                return RS_FATAL;
            }
            port->listen_ip_kind = RS_LISTEN_IP_ANY_V4;
        }
    } {
        bool ipv6only = false;
        RS_GUARD_CKV(ckv_get_bool(ckv, (ckv_arg_bool){
            .map = map,
            .key = "ipv6only",
            .dst = &ipv6only
        }));
        if (ipv6only) {
            if (port->listen_ip_kind != RS_LISTEN_IP_ANY) {
                RS_LOG(LOG_ERR, "\"ipv6only\" cannot be set in combination "
                    "with any of the following keys on the same port (%u): "
                    "\"ipv4_addrs\", \"ipv6_addrs\", \"ipv4only\", "
                    "\"ipv4_is_embedded_in_ipv6\"", port->port_number);
                return RS_FATAL;
            }
            port->listen_ip_kind = RS_LISTEN_IP_ANY_V6;
        }
    } {
        bool ipv4_is_embedded_in_ipv6 = false;
        RS_GUARD_CKV(ckv_get_bool(ckv, (ckv_arg_bool){
            .map = map,
            .key = "ipv4_is_embedded_in_ipv6",
            .dst = &ipv4_is_embedded_in_ipv6
        }));
        if (ipv4_is_embedded_in_ipv6) {
            if (port->listen_ip_kind != RS_LISTEN_IP_ANY) {
                RS_LOG(LOG_ERR, "\"ipv4_is_embedded_in_ipv6\" cannot be set in "
                    "combination with any of the following keys on the same "
                    "port (%u): \"ipv4_addrs\", \"ipv6_addrs\", "
                    "\"ipv4only\", \"ipv6only\"", port->port_number);
                return RS_FATAL;
            }
            port->listen_ip_kind = RS_LISTEN_IP_ANY_V6_OR_EMBEDDED_V4;
        }
    }
    return RS_OK;
}

static rs_ret parse_cert(
    ckv_t * ckv,
    struct ckv_map * map,
    struct rs_conf_cert * cert,
    struct rs_conf_cert * certs
) {
    RS_GUARD_CKV(ckv_get_strs(ckv, (ckv_arg_strs){
        .map = map,
        .key = "hostnames",
        .is_required = true,
        .min_c = 1,
        .max_c = UINT16_MAX,
        .max_strlen = RS_HOSTNAME_MAX_STRLEN,
        .elem_c = &cert->hostname_c,
        .dst = &cert->hostnames
    }));
    for (char * * hostname = cert->hostnames;
         hostname < cert->hostnames + cert->hostname_c; hostname++) {
        for (struct rs_conf_cert * c = certs; c < cert; c++) {
            for (char * * h = c->hostnames; h < c->hostnames + c->hostname_c;
                h++) {
                if (!strcmp(*h, *hostname)) {
                    RS_LOG(LOG_ERR, "Duplicate certificate hostname: \"%s\"",
                        *h);
                    return RS_FATAL;
                }
            }
        }
        for (char * * h = cert->hostnames; h < hostname; h++) {
            if (!strcmp(*h, *hostname)) {
                RS_LOG(LOG_ERR, "Duplicate certificate hostname: \"%s\"", *h);
                return RS_FATAL;
            }
        }
    }
    RS_GUARD_CKV(ckv_get_str(ckv, (ckv_arg_str){
        .map = map,
        .key = "privkey_path",
        .is_required = true,
        .max_strlen = RS_PATH_MAX_STRLEN,
        .dst = &cert->privkey_path
    }));
    RS_GUARD_CKV(ckv_get_str(ckv, (ckv_arg_str){
        .map = map,
        .key = "pubchain_path",
        .is_required = true,
        .max_strlen = RS_PATH_MAX_STRLEN,
        .dst = &cert->pubchain_path
    }));
    return RS_OK;
}

static rs_ret parse_app(
    ckv_t * ckv,
    struct ckv_map * map,
    struct rs_conf_app * app,
    struct rs_conf * conf
) {
    RS_GUARD_CKV(ckv_get_str(ckv, (ckv_arg_str){
        .map = map,
        .key = "name",
        .is_required = true,
        .max_strlen = RS_APP_NAME_MAX_STRLEN,
        .dst = &app->name
    }));
    RS_GUARD_CKV(ckv_get_str(ckv, (ckv_arg_str){
        .map = map,
        .key = "app_path",
        .is_required = true,
        .max_strlen = RS_PATH_MAX_STRLEN,
        .dst = &app->app_path
    }));
    RS_GUARD_CKV(ckv_get_uint8(ckv, (ckv_arg_uint8){
        .map = map,
        .key = "update_queue_size",
        .defaul = conf->update_queue_size,
        .dst = &app->update_queue_size
    }));
    if (!app->update_queue_size) {
        RS_LOG(LOG_ERR, "Update queue sizes must not be set to zero.");
        return RS_FATAL;
    }
    RS_GUARD_CKV(ckv_get_uint32(ckv, (ckv_arg_uint32){
        .map = map,
        .key = "wbuf_size",
        .defaul = RS_DEFAULT_APP_WBUF_SIZE,
        .dst = &app->wbuf_size
    }));
    if (app->wbuf_size < RS_MIN_APP_WBUF_SIZE) {
        RS_LOG(LOG_ERR, "Setting an app's wbuf_size to anything less than %d "
            "is a bad idea.", RS_MIN_APP_WBUF_SIZE);
        return RS_FATAL;
    }
    {
        bool no_open_cb = false;
        RS_GUARD_CKV(ckv_get_bool(ckv, (ckv_arg_bool){
            .map = map,
            .key = "no_open_cb",
            .dst = &no_open_cb
        }));
        app->wants_open_notification = !no_open_cb;
    }
    {
        bool no_close_cb = false;
        RS_GUARD_CKV(ckv_get_bool(ckv, (ckv_arg_bool){
            .map = map,
            .key = "no_close_cb",
            .dst = &no_close_cb
        }));
        app->wants_close_notification = !no_close_cb;
    }
    struct ckv_map * endpoint_maps = NULL;
    size_t endpoint_map_c = 0;
    RS_GUARD_CKV(ckv_get_maps(ckv, (ckv_arg_maps){
        .map = map,
        .key = "endpoints",
        .is_required = true,
        .min_c = 1,
        .max_c = UINT32_MAX,
        .elem_c = &endpoint_map_c,
        .dst = &endpoint_maps
    }));
    RS_CALLOC(app->endpoints, endpoint_map_c);
    app->endpoint_c = endpoint_map_c;
    for (size_t i = 0; i < endpoint_map_c; i++) {
        RS_GUARD(parse_endpoint(ckv, endpoint_maps + i, app->endpoints + i, app,
            conf));
    }
    return RS_OK;
}

static rs_ret parse_configuration(
    ckv_t * ckv,
    struct rs_conf * conf
) {
    {
        char * log_level = NULL;
        RS_GUARD_CKV(ckv_get_str(ckv, (ckv_arg_str){
            .key = "log_level",
            .max_strlen = RS_CONST_STRLEN("warning"),
            .dst = &log_level
        }));
        // default is "warning" -- see _rs_log_mask definition above
        if (log_level) {
            if (!strcmp(log_level, "error")) {
                _rs_log_mask = LOG_UPTO(LOG_ERR);
            } else if (!strcmp(log_level, "notice")) {
                _rs_log_mask = LOG_UPTO(LOG_NOTICE);
            } else if (!strcmp(log_level, "info")) {
                _rs_log_mask = LOG_UPTO(LOG_INFO);
            } else if (!strcmp(log_level, "debug")) {
                _rs_log_mask = LOG_UPTO(LOG_DEBUG);
            } else if (strcmp(log_level, "warning")) {
                RS_LOG(LOG_ERR, "Unrecognized configuration value for "
                    "\"log_level\": \"%s\". The value must be one of: "
                    "\"error\", \"warning\", \"notice\", \"info\", "
                    "or \"debug\".", log_level);
                return RS_FATAL;
            }
            RS_FREE(log_level);
        }
    }
    RS_GUARD_CKV(ckv_get_uint32(ckv, (ckv_arg_uint32){
        .key = "fd_alloc_c",
        .defaul = RS_DEFAULT_FD_ALLOC_C,
        .dst = &conf->fd_alloc_c
    }));
    if (conf->fd_alloc_c < RS_MIN_FD_ALLOC_C) {
        RS_LOG(LOG_ERR, "Setting the maximum number of open file descriptors "
            "to anything less than %d is a bad idea.", RS_MIN_FD_ALLOC_C);
        return RS_FATAL;
    }
    RS_GUARD_CKV(ckv_get_uint32(ckv, (ckv_arg_uint32){
        .key = "max_ws_msg_size",
        .defaul = RS_DEFAULT_MAX_WS_MSG_SIZE,
        .dst = &conf->max_ws_msg_size
    }));
    if (conf->max_ws_msg_size < RS_MIN_MAX_WS_MSG_SIZE) {
        RS_LOG(LOG_ERR, "Setting the maximum WebSocket message size to "
            "anything less than %d is a bad idea.", RS_MIN_MAX_WS_MSG_SIZE);
        return RS_FATAL;
    }
    if (conf->max_ws_msg_size > RS_MAX_MAX_WS_MSG_SIZE) {
        RS_LOG(LOG_ERR, "RS does not support WebSocket messages larger than "
            "%d bytes.", RS_MAX_MAX_WS_MSG_SIZE);
        return RS_FATAL;
    }
    RS_GUARD_CKV(ckv_get_uint32(ckv, (ckv_arg_uint32){
        .key = "worker_rbuf_size",
        .defaul = RS_DEFAULT_WORKER_RBUF_SIZE,
        .dst = &conf->worker_rbuf_size
    }));
    if (conf->worker_rbuf_size < RS_MIN_WORKER_RBUF_SIZE) {
        RS_LOG(LOG_ERR, "Setting worker_rbuf_size to anything less than %d is "
            "a bad idea.", RS_MIN_WORKER_RBUF_SIZE);
        return RS_FATAL;
    }
    RS_GUARD_CKV(ckv_get_sizet(ckv, (ckv_arg_sizet){
        .key = "inbound_ring_buf_size",
        .defaul = RS_DEFAULT_INBOUND_RING_BUF_SIZE,
        .dst = &conf->inbound_ring_buf_size
    }));
    if (conf->inbound_ring_buf_size < RS_MIN_INBOUND_RING_BUF_SIZE) {
        RS_LOG(LOG_ERR, "Setting inbound_ring_buf_size to anything less than "
            "%d is a bad idea.", RS_MIN_INBOUND_RING_BUF_SIZE);
        return RS_FATAL;
    }
    RS_GUARD_CKV(ckv_get_sizet(ckv, (ckv_arg_sizet){
        .key = "outbound_ring_buf_size",
        .defaul = RS_DEFAULT_OUTBOUND_RING_BUF_SIZE,
        .dst = &conf->outbound_ring_buf_size
    }));
    if (conf->outbound_ring_buf_size < RS_MIN_OUTBOUND_RING_BUF_SIZE) {
        RS_LOG(LOG_ERR, "Setting outbound_ring_buf_size to anything less than "
            "%d is a bad idea.", RS_MIN_OUTBOUND_RING_BUF_SIZE);
        return RS_FATAL;
    }
    RS_GUARD_CKV(ckv_get_double(ckv, (ckv_arg_double){
        .key = "realloc_multiplier",
        .defaul = RS_DEFAULT_REALLOC_MULTIPLIER,
        .dst = &conf->realloc_multiplier
    }));
    if (conf->realloc_multiplier < RS_MIN_REALLOC_MULTIPLIER) {
        RS_LOG(LOG_ERR, "Setting realloc_multiplier to anything less than %f "
            "is a bad idea.", RS_MIN_REALLOC_MULTIPLIER);
        return RS_FATAL;
    }
    if (conf->realloc_multiplier > RS_MAX_REALLOC_MULTIPLIER) {
        RS_LOG(LOG_ERR, "Setting realloc_multiplier to anything greater than "
            "%f is a bad idea.", RS_MAX_REALLOC_MULTIPLIER);
        return RS_FATAL;
    }
    RS_GUARD_CKV(ckv_get_uint32(ckv, (ckv_arg_uint32){
        .key = "wrefs_elem_c",
        .defaul = RS_DEFAULT_WREFS_ELEM_C,
        .dst = &conf->wrefs_elem_c
    }));
    if (conf->wrefs_elem_c < RS_MIN_WREFS_ELEM_C) {
        RS_LOG(LOG_ERR, "Setting the initial number of elements of the wrefs "
            "array to less than %d is a bad idea.", RS_MIN_WREFS_ELEM_C);
        return RS_FATAL;
    }
    RS_GUARD_CKV(ckv_get_uint16(ckv, (ckv_arg_uint16){
        .key = "epoll_buf_elem_c",
        .defaul = RS_DEFAULT_EPOLL_BUF_ELEM_C,
        .dst = &conf->epoll_buf_elem_c
    }));
    if (conf->epoll_buf_elem_c < RS_MIN_EPOLL_BUF_ELEM_C) {
        RS_LOG(LOG_ERR, "Setting the maximum number of events receivable per "
            "call to epoll_wait() to less than %d is a bad idea.",
            RS_MIN_EPOLL_BUF_ELEM_C);
        return RS_FATAL;
    }
    RS_GUARD_CKV(ckv_get_uint8(ckv, (ckv_arg_uint8){
        .key = "update_queue_size",
        .defaul = RS_DEFAULT_UPDATE_QUEUE_SIZE,
        .dst = &conf->update_queue_size
    }));
    if (!conf->update_queue_size) {
        RS_LOG(LOG_ERR, "Update queue sizes must not be set to zero.");
        return RS_FATAL;
    }
    RS_GUARD_CKV(ckv_get_uint8(ckv, (ckv_arg_uint8){
        .key = "shutdown_wait_http",
        .defaul = RS_DEFAULT_SHUTDOWN_WAIT_HTTP,
        .dst = &conf->shutdown_wait_http
    }));
    RS_GUARD_CKV(ckv_get_uint8(ckv, (ckv_arg_uint8){
        .key = "shutdown_wait_ws",
        .defaul = RS_DEFAULT_SHUTDOWN_WAIT_WS,
        .dst = &conf->shutdown_wait_http
    }));
    struct ckv_map * maps = NULL;
    size_t map_c = 0;
    RS_GUARD_CKV(ckv_get_maps(ckv, (ckv_arg_maps){
        .key = "ports",
        .is_required = true,
        .min_c = 1,
        .max_c = UINT16_MAX,
        .elem_c = &map_c,
        .dst = &maps
    }));
    RS_CALLOC(conf->ports, map_c);
    conf->port_c = map_c;
    for (size_t i = 0; i < map_c; i++) {
        RS_GUARD(parse_port(ckv, maps + i, conf->ports + i, conf->ports));
    }
    RS_GUARD_CKV(ckv_get_maps(ckv, (ckv_arg_maps){
        .key = "certs",
        .max_c = RS_MAX_CERT_C,
        .elem_c = &map_c,
        .dst = &maps
    }));
    if (map_c) {
        RS_CALLOC(conf->certs, map_c);
        conf->cert_c = map_c;
        for (size_t i = 0; i < map_c; i++) {
            RS_GUARD(parse_cert(ckv, maps + i, conf->certs + i, conf->certs));
        }
    }
    RS_GUARD_CKV(ckv_get_maps(ckv, (ckv_arg_maps){
        .key = "apps",
        .is_required = true,
        .min_c = 1,
        .max_c = UINT16_MAX,
        .elem_c = &map_c,
        .dst = &maps
    }));
    RS_CALLOC(conf->apps, map_c);
    conf->app_c = map_c;
    for (size_t i = 0; i < map_c; i++) {
        RS_GUARD(parse_app(ckv, maps + i, conf->apps + i, conf));
    }
    RS_GUARD_CKV(ckv_get_uint16(ckv, (ckv_arg_uint16){
        .key = "worker_c",
        .dst = &conf->worker_c
    }));
    if (!conf->worker_c) {
        long ret = sysconf(_SC_NPROCESSORS_ONLN);
        if (ret == -1) {
            RS_LOG_ERRNO(LOG_CRIT,
                "Unsuccessful sysconf(_SC_NPROCESSORS_ONLN)");
            return RS_FATAL;
        }
        conf->worker_c = RS_MIN(1, ret - conf->app_c);
    }
    return RS_OK;
}

rs_ret get_configuration(
    struct rs_conf * conf,
    char const * conf_path
) {
    if (!conf_path) {
        conf_path = default_conf_path;
    }
    FILE * f = fopen(conf_path, "r");
    if (!f) {
        RS_LOG_ERRNO(LOG_ERR, "Unsuccessful fopen(\"%s\", \"r\")", conf_path);
        return RS_FATAL;
    }
    ckv_t * ckv = ckv_init();
    RS_GUARD_CKV(ckv_parse_file(ckv, f, conf_path));
    if (fclose(f) == EOF) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful fclose(f) on opened file: %s",
            conf_path);
        return RS_FATAL;
    }
    RS_GUARD(parse_configuration(ckv, conf));
    ckv_free(ckv);
    return RS_OK;
}
