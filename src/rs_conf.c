// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include "rs_conf.h"
#include "rs_tls.h" // derive_cert_index_from_hostname()

#include <ifaddrs.h> // getifaddrs()
#include <jgrandson.h> // JSON conf file parsing: https://github/wbudd/jgrandson
#include <net/if.h> // IF_NAMESIZE

RS_LOG_VARS; // See the RS_LOG() section in ringsocket_api.h for explanation.

#define RS_GUARD_JG(_jg_ret) do { \
    if ((_jg_ret) != JG_OK) { \
        RS_LOG(LOG_ERR, "Error parsing configuration file: %s", \
            jg_get_err_str(jg, NULL, NULL)); \
        return RS_FATAL; \
    } \
} while (0)

// These numbers are merely an attempt at providing sensible defaults
#define RS_DEFAULT_FD_ALLOC_C 10000
#define RS_MIN_FD_ALLOC_C 0x1000 // 4096 == the Linux default these days
#define RS_DEFAULT_MAX_WS_MSG_SIZE 0x1000000 // 16 MB
#define RS_MIN_MAX_WS_MSG_SIZE 125
#define RS_MAX_MAX_WS_MSG_SIZE 0x1000000000 // 64 GB (Have a monstrous machine?)
#define RS_DEFAULT_MAX_WS_FRAME_CHAIN_SIZE (4 * RS_DEFAULT_MAX_WS_MSG_SIZE)
#define RS_MIN_MAX_WS_FRAME_CHAIN_SIZE (1.1 * RS_MIN_MAX_WS_MSG_SIZE)
#define RS_MAX_MAX_WS_FRAME_SIZE (1.01 * RS_MAX_MAX_WS_MSG_SIZE)
#define RS_DEFAULT_WORKER_RBUF_SIZE (2 * RS_DEFAULT_MAX_WS_MSG_SIZE)
#define RS_MIN_WORKER_RBUF_SIZE (2 * RS_MIN_MAX_WS_MSG_SIZE)
#define RS_DEFAULT_INBOUND_RING_BUF_SIZE (4 * RS_DEFAULT_MAX_WS_MSG_SIZE)
#define RS_MIN_INBOUND_RING_BUF_SIZE (4 * RS_MIN_MAX_WS_MSG_SIZE)
#define RS_DEFAULT_OUTBOUND_RING_BUF_SIZE (8 * RS_DEFAULT_MAX_WS_MSG_SIZE)
#define RS_MIN_OUTBOUND_RING_BUF_SIZE (8 * RS_MIN_MAX_WS_MSG_SIZE)
#define RS_DEFAULT_REALLOC_MULTIPLIER 1.5
#define RS_MIN_REALLOC_MULTIPLIER 1.05
#define RS_MAX_REALLOC_MULTIPLIER 2.5
#define RS_DEFAULT_OWREFS_ELEM_C 10000
#define RS_MIN_OWREFS_ELEM_C 1000
#define RS_DEFAULT_EPOLL_BUF_ELEM_C 100
#define RS_MIN_EPOLL_BUF_ELEM_C 10
#define RS_DEFAULT_UPDATE_QUEUE_SIZE 5
#define RS_DEFAULT_APP_WBUF_SIZE 0x100000 // 1 MB
#define RS_MIN_APP_WBUF_SIZE 64
#define RS_MAX_CERT_C 0xFFFF // 65535
#define RS_IP_ADDR_MAX_STRLEN 0x3F // 63
#define RS_HOSTNAME_MAX_STRLEN 0x3FF // 1023
#define RS_PATH_MAX_STRLEN 0x1FFF // 8191
#define RS_URL_MAX_STRLEN 0x1FFF // 8191
#define RS_MAX_ALLOWED_ORIGIN_C 0x1FFF // 8191
#define RS_ALLOWED_ORIGIN_MAX_STRLEN 0x1FFF // 8191
#define RS_DEFAULT_SHUTDOWN_WAIT_HTTP 15 // in seconds
#define RS_DEFAULT_SHUTDOWN_WAIT_WS 30

static char const default_conf_path[] = "/etc/ringsocket.json";

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
    char * * ip_strs,
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
        free(*ip_str);
    }
    free(ip_strs);
    return RS_OK;
}

static rs_ret parse_url(
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

static rs_ret check_if_endpoint_is_duplicate(
    struct rs_conf_endpoint const * old,
    struct rs_conf_endpoint const * new,
    char const * url
) {
    if (strcmp(old->url, new->url) || strcmp(old->hostname, new->hostname)) {
        return RS_OK;
    }
    RS_LOG(LOG_ERR, "Duplicate endpoint WebSocket URL: %s", url);
    return RS_FATAL;
}

static rs_ret parse_endpoint(
    jg_t * jg,
    jg_obj_get_t * obj,
    struct rs_conf_endpoint * endpoint,
    struct rs_conf_app * app,
    struct rs_conf * conf
) {
    RS_GUARD_JG(jg_obj_get_uint16(jg, obj, "endpoint_id", NULL,
        &endpoint->endpoint_id));
    {
        jg_arr_get_t * arr = NULL;
        size_t elem_c = 0;
        RS_GUARD_JG(jg_obj_get_arr(jg, obj, "allowed_origins",
            &(jg_obj_arr){
                .min_c = 1,
                .max_c = RS_MAX_ALLOWED_ORIGIN_C,
                .min_c_reason = "At least one origin must be allowed."
            }, &arr, &elem_c));
        RS_CALLOC(endpoint->allowed_origins, elem_c);
        endpoint->allowed_origin_c = elem_c;
        for (size_t i = 0; i < elem_c; i++) {
            size_t byte_c = 0;
            RS_GUARD_JG(jg_arr_get_str(jg, arr, i,
                &(jg_arr_str){
                    .byte_c = &byte_c,
                    .max_byte_c = RS_ALLOWED_ORIGIN_MAX_STRLEN
                }, endpoint->allowed_origins + i));
            if (byte_c > conf->allowed_origin_max_strlen) {
                conf->allowed_origin_max_strlen = byte_c;
            }
        }
    }

    char * url = NULL;
    RS_GUARD_JG(jg_obj_get_str(jg, obj, "url",
        &(jg_obj_str){
            .max_byte_c = RS_URL_MAX_STRLEN
        }, &url));
    RS_GUARD(parse_url(url, endpoint));
    for (struct rs_conf_app *a = conf->apps; a < app; a++) {
        for (struct rs_conf_endpoint *e = a->endpoints;
             e < a->endpoints + a->endpoint_c; e++) {
            RS_GUARD(check_if_endpoint_is_duplicate(e, endpoint, url));
        }
    }
    for (struct rs_conf_endpoint *e = app->endpoints; e < endpoint; e++) {
        RS_GUARD(check_if_endpoint_is_duplicate(e, endpoint, url));
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
                    "URL \"%s\" is listed under \"ports\" with%s the "
                    "\"is_unencrypted\" flag, but this contradicts the scheme "
                    "with which the URL begins (\"ws%s://\"), which specifies "
                    "an %sencrypted connection.", endpoint->port_number, url,
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
                        "WebSocket URL \"%s\".", endpoint->hostname, url);
                    return RS_FATAL;
                }
            }
            RS_FREE(url);
            return RS_OK;
        }
    }
    switch (endpoint->port_number) {
    case 80:
        RS_LOG(LOG_ERR, "WebSocket URL \"%s\" implies endpoint port number "
            "80, but no \"ports\" entry in the configuration file listing "
            "such a \"port_number\" was found.", url);
        return RS_FATAL;
    case 443:
        RS_LOG(LOG_ERR, "WebSocket URL \"%s\" implies endpoint port number "
            "443, but no \"ports\" entry in the configuration file listing "
            "such a \"port_number\" was found.", url);
        return RS_FATAL;
    default:
        RS_LOG(LOG_ERR, "The port number '%u' contained in WebSocket URL "
            "\"%s\" is not listed under \"ports\" in the configuration file.",
            endpoint->port_number, url);
        return RS_FATAL;
    }
}

static rs_ret parse_port(
    jg_t * jg,
    jg_obj_get_t * obj,
    struct rs_conf_port * port,
    struct rs_conf_port * ports
) {
    RS_GUARD_JG(jg_obj_get_uint16(jg, obj, "port_number", NULL,
        &port->port_number));
    for (struct rs_conf_port * p = ports; p < port; p++) {
        if (p->port_number == port->port_number) {
            RS_LOG(LOG_ERR, "Duplicate port number: %u" , port->port_number);
            return RS_FATAL;
        }
    }
    {
        bool is_unencrypted = false;
        RS_GUARD_JG(jg_obj_get_bool(jg, obj, "is_unencrypted", &(bool){false},
            &is_unencrypted));
        port->is_encrypted = !is_unencrypted;
    }
    {
        jg_arr_get_t * arr = NULL;
        size_t elem_c = 0;
        RS_GUARD_JG(jg_obj_get_arr_defa(jg, obj, "ip_addrs",
            &(jg_obj_arr_defa){
                .max_c = UINT16_MAX,
            }, &arr, &elem_c));
        if (elem_c) {
            char * * ip_strs = NULL;
            RS_CALLOC(ip_strs, elem_c);
            port->listen_ip_kind = RS_LISTEN_IP_SPECIFIC;
            for (size_t i = 0; i < elem_c; i++) {
                RS_GUARD_JG(jg_arr_get_str(jg, arr, i,
                    &(jg_arr_str){
                        .max_byte_c = RS_IP_ADDR_MAX_STRLEN
                    }, ip_strs + i));
            }
            RS_GUARD(add_ip_addrs_from_strs(ip_strs, elem_c, port));
        }
    }
    RS_GUARD_JG(jg_obj_get_str(jg, obj, "interface",
        &(jg_obj_str){
            .defa = "",
            .nullify_empty_str = true,
            .max_byte_c = IF_NAMESIZE
        }, &port->interface));
    if (port->interface && port->listen_ip_kind != RS_LISTEN_IP_ANY) {
        RS_LOG(LOG_ERR, "\"ipv4only\" cannot be set in combination with any "
            "of the following keys on the same port (%u): \"ipv4_addrs\", "
            "\"ipv6_addrs\"", port->port_number);
        return RS_FATAL;
    }
    {
        bool ipv4only = false;
        RS_GUARD_JG(jg_obj_get_bool(jg, obj, "ipv4only", &(bool){false},
            &ipv4only));
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
    }
    {
        bool ipv6only = false;
        RS_GUARD_JG(jg_obj_get_bool(jg, obj, "ipv6only", &(bool){false},
            &ipv6only));
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
    }
    {
        bool ipv4_is_embedded_in_ipv6 = false;
        RS_GUARD_JG(jg_obj_get_bool(jg, obj, "ipv4_is_embedded_in_ipv6",
            &(bool){false}, &ipv4_is_embedded_in_ipv6));
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
    jg_t * jg,
    jg_obj_get_t * obj,
    struct rs_conf_cert * cert,
    struct rs_conf_cert * certs
) {
    {
        jg_arr_get_t * arr = NULL;
        size_t elem_c = 0;
        RS_GUARD_JG(jg_obj_get_arr(jg, obj, "hostnames",
            &(jg_obj_arr){
                .min_c = 1,
                .max_c = UINT16_MAX,
                .min_c_reason = "Certificate should have at least one hostname."
            }, &arr, &elem_c));
        RS_CALLOC(cert->hostnames, elem_c);
        cert->hostname_c = elem_c;
        for (size_t i = 0; i < elem_c; i++) {
            char * * hostname = cert->hostnames + i;
            RS_GUARD_JG(jg_arr_get_str(jg, arr, i,
                &(jg_arr_str){
                    .max_byte_c = RS_HOSTNAME_MAX_STRLEN
                }, hostname));
            for (struct rs_conf_cert * c = certs; c < cert; c++) {
                for (char * * h = c->hostnames;
                    h < c->hostnames + c->hostname_c; h++) {
                    if (!strcmp(*h, *hostname)) {
                        RS_LOG(LOG_ERR,
                            "Duplicate certificate hostname: \"%s\"", *h);
                        return RS_FATAL;
                    }
                }
            }
            for (char * * h = cert->hostnames; h < hostname; h++) {
                if (!strcmp(*h, *hostname)) {
                    RS_LOG(LOG_ERR,
                        "Duplicate certificate hostname: \"%s\"", *h);
                    return RS_FATAL;
                }
            }
        }
    }
    RS_GUARD_JG(jg_obj_get_str(jg, obj, "privkey_path",
        &(jg_obj_str){
            .max_byte_c = RS_PATH_MAX_STRLEN
        }, &cert->privkey_path));

    RS_GUARD_JG(jg_obj_get_str(jg, obj, "pubchain_path",
        &(jg_obj_str){
            .max_byte_c = RS_PATH_MAX_STRLEN
        }, &cert->pubchain_path));
    return RS_OK;
}

static rs_ret parse_app(
    jg_t * jg,
    jg_obj_get_t * obj,
    struct rs_conf_app * app,
    struct rs_conf * conf
) {
    RS_GUARD_JG(jg_obj_get_str(jg, obj, "name",
        &(jg_obj_str){
            .max_byte_c = RS_APP_NAME_MAX_STRLEN
        }, &app->name));

    RS_GUARD_JG(jg_obj_get_str(jg, obj, "app_path",
        &(jg_obj_str){
            .max_byte_c = RS_PATH_MAX_STRLEN
        }, &app->app_path));

    RS_GUARD_JG(jg_obj_get_uint8(jg, obj, "update_queue_size",
        &(jg_obj_uint8){
            .defa = &(uint8_t){conf->update_queue_size},
            .min = &(uint8_t){1},
            .min_reason = "Update queue sizes must not be set to zero."
        }, &app->update_queue_size));

    RS_GUARD_JG(jg_obj_get_uint32(jg, obj, "wbuf_size",
        &(jg_obj_uint32){
            .defa = &(uint32_t){RS_DEFAULT_APP_WBUF_SIZE},
            .min = &(uint32_t){RS_MIN_APP_WBUF_SIZE},
            .min_reason = "Setting an app's wbuf_size any lower is a bad idea"
        }, &app->wbuf_size));

    {
        bool no_open_cb = false;
        RS_GUARD_JG(jg_obj_get_bool(jg, obj, "no_open_cb", &(bool){false},
            &no_open_cb));
        app->wants_open_notification = !no_open_cb;
    }
    {
        bool no_close_cb = false;
        RS_GUARD_JG(jg_obj_get_bool(jg, obj, "no_close_cb", &(bool){false},
            &no_close_cb));
        app->wants_close_notification = !no_close_cb;
    }
    jg_arr_get_t * arr = NULL;
    size_t elem_c = 0;
    RS_GUARD_JG(jg_obj_get_arr(jg, obj, "endpoints",
        &(jg_obj_arr){
            .min_c = 1,
            .max_c = UINT32_MAX,
            .min_c_reason = "At least one endpoint object must be defined."
        }, &arr, &elem_c));
    RS_CALLOC(app->endpoints, elem_c);
    app->endpoint_c = elem_c;
    for (size_t i = 0; i < elem_c; i++) {
        jg_obj_get_t * endp_obj = NULL;
        RS_GUARD_JG(jg_arr_get_obj(jg, arr, i, NULL, &endp_obj));
        RS_GUARD(parse_endpoint(jg, endp_obj, app->endpoints + i, app, conf));
    }
    return RS_OK;
}

static rs_ret parse_configuration(
    jg_t * jg,
    struct rs_conf * conf
) {
    jg_obj_get_t * root_obj = NULL;
    RS_GUARD_JG(jg_root_get_obj(jg, NULL, &root_obj));
    {
        char log_level[] = "notice";
        RS_GUARD_JG(jg_obj_get_callerstr(jg, root_obj, "log_level",
            &(jg_obj_callerstr){
                .defa = "notice",
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
    RS_GUARD_JG(jg_obj_get_uint32(jg, root_obj, "fd_alloc_c",
        &(jg_obj_uint32){
            .defa = &(uint32_t){RS_DEFAULT_FD_ALLOC_C},
            .min = &(uint32_t){RS_MIN_FD_ALLOC_C},
            .min_reason = "Setting the maximum number of open file descriptors "
                "any lower is a bad idea."
        }, &conf->fd_alloc_c));

    RS_GUARD_JG(jg_obj_get_sizet(jg, root_obj, "max_ws_msg_size",
        &(jg_obj_sizet){
            .defa = &(size_t){RS_DEFAULT_MAX_WS_MSG_SIZE},
            .min = &(size_t){RS_MIN_MAX_WS_MSG_SIZE},
            .max = &(size_t){RS_MAX_MAX_WS_MSG_SIZE},
            .min_reason = "Setting the maximum WebSocket message size any "
                "lower is a bad idea.",
            .max_reason = "RingSocket does not support WebSocket messages any "
                "larger."
        }, &conf->max_ws_msg_size));

    RS_GUARD_JG(jg_obj_get_sizet(jg, root_obj, "max_ws_frame_chain_size",
        &(jg_obj_sizet){
            .defa = &(size_t){RS_DEFAULT_MAX_WS_FRAME_CHAIN_SIZE},
            .min = &(size_t){RS_MIN_MAX_WS_FRAME_CHAIN_SIZE},
            .max = &(size_t){RS_MAX_MAX_WS_FRAME_SIZE},
            .min_reason = "Setting the maximum WebSocket frame chain size any "
                "lower is a bad idea.",
            .max_reason = "RingSocket does not support WebSocket frame chains "
                "any larger."
        }, &conf->max_ws_frame_chain_size));

    RS_GUARD_JG(jg_obj_get_sizet(jg, root_obj, "worker_rbuf_size",
        &(jg_obj_sizet){
            .defa = &(size_t){RS_DEFAULT_WORKER_RBUF_SIZE},
            .min = &(size_t){RS_MIN_WORKER_RBUF_SIZE},
            .min_reason = "Setting worker_rbuf_size any lower is a bad idea."
        }, &conf->worker_rbuf_size));

    RS_GUARD_JG(jg_obj_get_sizet(jg, root_obj, "inbound_ring_buf_size",
        &(jg_obj_sizet){
            .defa = &(size_t){RS_DEFAULT_INBOUND_RING_BUF_SIZE},
            .min = &(size_t){RS_MIN_INBOUND_RING_BUF_SIZE},
            .min_reason = "Setting inbound_ring_buf_size any lower is a bad "
                "idea."
        }, &conf->inbound_ring_buf_size));

    RS_GUARD_JG(jg_obj_get_sizet(jg, root_obj, "outbound_ring_buf_size",
        &(jg_obj_sizet){
            .defa = &(size_t){RS_DEFAULT_OUTBOUND_RING_BUF_SIZE},
            .min = &(size_t){RS_MIN_OUTBOUND_RING_BUF_SIZE},
            .min_reason = "Setting outbound_ring_buf_size any lower is a bad "
                "idea."
        }, &conf->outbound_ring_buf_size));

    RS_GUARD_JG(jg_obj_get_double(jg, root_obj, "realloc_multiplier",
        &(double){RS_DEFAULT_REALLOC_MULTIPLIER}, &conf->realloc_multiplier));
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

    RS_GUARD_JG(jg_obj_get_uint32(jg, root_obj, "owrefs_elem_c",
        &(jg_obj_uint32){
            .defa = &(uint32_t){RS_DEFAULT_OWREFS_ELEM_C},
            .min = &(uint32_t){RS_MIN_OWREFS_ELEM_C},
            .min_reason = "Setting the initial number of elements of the owrefs "
                "array any lower is a bad idea."
        }, &conf->owrefs_elem_c));

    RS_GUARD_JG(jg_obj_get_uint16(jg, root_obj, "epoll_buf_elem_c",
        &(jg_obj_uint16){
            .defa = &(uint16_t){RS_DEFAULT_EPOLL_BUF_ELEM_C},
            .min = &(uint16_t){RS_MIN_EPOLL_BUF_ELEM_C},
            .min_reason = "Setting the maximum number of events receivable per "
                "call to epoll_wait() any lower is a bad idea."
        }, &conf->epoll_buf_elem_c));

    RS_GUARD_JG(jg_obj_get_uint8(jg, root_obj, "update_queue_size",
        &(jg_obj_uint8){
            .defa = &(uint8_t){RS_DEFAULT_UPDATE_QUEUE_SIZE},
            .min = &(uint8_t){1},
            .min_reason = "Update queue sizes must not be set to zero."
    }, &conf->update_queue_size));

    RS_GUARD_JG(jg_obj_get_uint8(jg, root_obj, "shutdown_wait_http",
        &(jg_obj_uint8){
            .defa = &(uint8_t){RS_DEFAULT_SHUTDOWN_WAIT_HTTP}
        }, &conf->shutdown_wait_http));

    RS_GUARD_JG(jg_obj_get_uint8(jg, root_obj, "shutdown_wait_ws",
        &(jg_obj_uint8){
            .defa = &(uint8_t){RS_DEFAULT_SHUTDOWN_WAIT_WS}
        }, &conf->shutdown_wait_http));

    jg_arr_get_t * arr = NULL;
    size_t elem_c = 0;

    RS_GUARD_JG(jg_obj_get_arr(jg, root_obj, "ports",
        &(jg_obj_arr){
            .min_c = 1,
            .max_c = UINT16_MAX,
            .min_c_reason = "At least one port object must be defined."
        }, &arr, &elem_c));
    RS_CALLOC(conf->ports, elem_c);
    conf->port_c = elem_c;
    for (size_t i = 0; i < elem_c; i++) {
        jg_obj_get_t * port_obj = NULL;
        RS_GUARD_JG(jg_arr_get_obj(jg, arr, i, NULL, &port_obj));
        RS_GUARD(parse_port(jg, port_obj, conf->ports + i, conf->ports));
    }

    RS_GUARD_JG(jg_obj_get_arr_defa(jg, root_obj, "certs",
        &(jg_obj_arr_defa) { 
            .max_c = RS_MAX_CERT_C
        }, &arr, &elem_c));
    if (elem_c) {
        RS_CALLOC(conf->certs, elem_c);
        conf->cert_c = elem_c;
        for (size_t i = 0; i < elem_c; i++) {
            jg_obj_get_t * cert_obj = NULL;
            RS_GUARD_JG(jg_arr_get_obj(jg, arr, i, NULL, &cert_obj));
            RS_GUARD(parse_cert(jg, cert_obj, conf->certs + i, conf->certs));
        }
    }

    RS_GUARD_JG(jg_obj_get_arr(jg, root_obj, "apps",
        &(jg_obj_arr){
            .min_c = 1,
            .max_c = UINT16_MAX,
            .min_c_reason = "At least one app object must be defined."
        }, &arr, &elem_c));
    RS_CALLOC(conf->apps, elem_c);
    conf->app_c = elem_c;
    for (size_t i = 0; i < elem_c; i++) {
        jg_obj_get_t * app_obj = NULL;
        RS_GUARD_JG(jg_arr_get_obj(jg, arr, i, NULL, &app_obj));
        RS_GUARD(parse_app(jg, app_obj, conf->apps + i, conf));
    }

    RS_GUARD_JG(jg_obj_get_uint16(jg, root_obj, "worker_c",
        &(jg_obj_uint16){
            .defa = &(uint16_t){0}
        }, &conf->worker_c));
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
    jg_t * jg = jg_init();
    RS_GUARD_JG(jg_parse_file(jg, conf_path ? conf_path : default_conf_path));
    RS_GUARD(parse_configuration(jg, conf));
    jg_free(jg);
    return RS_OK;
}
