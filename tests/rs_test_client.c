#define _POSIX_C_SOURCE 201112L // getaddrinfo()

#include <fcntl.h>
#include <jgrandson.h>
#include <netdb.h>
#include <ringsocket_api.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

RS_LOG_VARS; // See the RS_LOG() section in ringsocket_api.h for explanation.

struct rsc_client {
    uint8_t * rbuf;
    uint8_t * wbuf;
    int fd;
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
    struct rsc_route * * routes,
    size_t * route_c
) {
    jg_t * jg = jg_init();
    RS_GUARD_JG(jg_parse_file(jg, conf_path ? conf_path : default_conf_path));

    jg_obj_get_t * root_obj = NULL;
    RS_GUARD_JG(jg_root_get_obj(jg, NULL, &root_obj));

    RS_GUARD_JG(jg_obj_get_sizet(jg, root_obj, "rwbuf_size", NULL, rwbuf_size));

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
    struct rsc_route const * route,
    int socket_fd
) {
    // Send a dummy WebSocket key in flagrant disregard of RFC6455, because
    // that's not the aspect of the standard we're interested in testing here.
    int http_strlen = sprintf(rwbuf, // sizeof(rwbuf) > 1000 guaranteed
        "RSC_HTTP_FMT"
        "GET /%s HTTP/1.1\r\n"
        "Host: %s%s%s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: ABCDEFGHIJKLMNOPQRSTUVWX\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        route->url,
        route->host,
        route->port_str ? ":" : "",
        route->port_str ? route->port_str : ""
    );
    if (write(socket_fd, rwbuf, http_strlen) == http_strlen) {
        return RS_OK;
    }
    RS_LOG_ERRNO(LOG_ERR, "Unsuccessful write(%d, rwbuf, %d)",
        socket_fd, http_strlen);
    return RS_FATAL;
}

static rs_ret send_upgrade_request(
    char * rwbuf,
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
        // until after the HTTP upgrade handshake is completed.
        client->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (client->fd == -1) {
            RS_LOG_ERRNO(LOG_WARNING, "Unsuccessful socket(...)");
            continue;
        }
        if (!connect(client->fd, ai->ai_addr, ai->ai_addrlen)) {
            freeaddrinfo(ai_first);
            return write_http_upgrade_request(rwbuf, route, client->fd);
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

static rs_ret receive_upgrade_responses(
    char * rwbuf,
    size_t rwbuf_size,
    int epoll_fd,
    struct rsc_client * client
) {
    for (;;) { // TODO........................
        read(client->fd, rwbuf, rwbuf_size);
    }
    // Switch the socket to non-blocking mode
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
    struct rsc_route * routes = NULL;
    size_t route_c = 0;
    RS_GUARD(get_conf(arg_c > 1 ? args[1] : NULL, &rwbuf_size, &routes,
        &route_c));

    char * rwbuf = NULL;
    RS_CALLOC(rwbuf, rwbuf_size);

    for (size_t i = 0; i < route_c; i++) {
        struct rsc_route * route = routes + i;
        for (size_t j = 0; j < route->client_c; j++) {
            RS_GUARD(send_upgrade_request(rwbuf, route, route->clients + j));
        }
    }
    
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful epoll_create1(0)");
        return RS_FATAL;
    }
   
    for (size_t i = 0; i < route_c; i++) {
        struct rsc_route * route = routes + i;
        for (size_t j = 0; j < route->client_c; j++) {
            RS_GUARD(receive_upgrade_responses(rwbuf, rwbuf_size,
                epoll_fd, route->clients + j));
        }
    }
    return RS_OK;
}

int main(
    int arg_c, // 1 or 2 
    char * * args // "rs_test_client" and optionally the path to the conf file
) {
    openlog(args[0], LOG_PID, LOG_USER);
    return _main(arg_c, args) == RS_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
