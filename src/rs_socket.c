// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#define _GNU_SOURCE // accept4()

#include "rs_event.h" // rs_event_kind
#include "rs_slot.h" // alloc_slot(), free_slot()
#include "rs_socket.h"
#include "rs_util.h" // get_addr_str()

#include <linux/filter.h> // struct sock_filter
#include <sys/epoll.h> // epoll_create1(), epoll_ctl()

static rs_ret bind_socket(
    struct rs_conf_port const * port,
    int fd,
    size_t worker_c,
    struct sockaddr const * addr,
    socklen_t addr_size
) {
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (int []){1}, sizeof(int)) ==
        -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful setsockopt(%d, SOL_SOCKET, "
            "SO_REUSEADDR, ...)", fd);
        return RS_FATAL;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (int[]){1}, sizeof(int)) ==
        -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful setsockopt(%d, SOL_SOCKET, "
            "SO_REUSEPORT, ...)", fd);
        return RS_FATAL;
    }
    // SO_ATTACH_REUSEPORT_CBPF only needs to be set once for each port, so
    // worker_c parameter is expected to be 0 whenever this function is called
    // again for the same port.
    if (worker_c) {
        // Todo: replace this with a CPU affinity-based
        // SO_ATTACH_REUSEPORT_EBPF program calling bpf_get_smp_processor_id()

        // Assign each incoming socket to a random worker thread, resulting in a
        // roughly equal load distribution vis a vis the Law of Large Numbers.
        // The values of the sock_filter struct below are equal to the output of
        // "echo 'ld rand mod #12345 ret a' | bpf_asm -c"
        // (except with 12345 replaced with worker_c).
        struct sock_filter filter[] = {
            { 0x20, 0, 0, 0xfffff038 },
            { 0x94, 0, 0, worker_c },
            { 0x16, 0, 0, 0 },
        };
        if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF,
            &(struct sock_fprog){
                .len = RS_ELEM_C(filter),
                .filter = filter,
            }, sizeof(struct sock_fprog)) == -1) {
            RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful setsockopt(%d, "
                "SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, ...)", fd);
            return RS_FATAL;
        }
    }
    if (port->listen_ip_kind != RS_LISTEN_IP_SPECIFIC && port->interface) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, port->interface,
            strlen(port->interface)) == -1) {
            RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful setsockopt(%d, SOL_SOCKET, "
                "SO_BIND_TODEVICE, \"%s\", %zu)", fd, port->interface,
                strlen(port->interface));
            return RS_FATAL;
        }
    } else if (bind(fd, addr, addr_size) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful bind(%d, addr, addr_size)", fd);
        return RS_FATAL;
    }
    return RS_OK;
}

static rs_ret bind_ipv4(
    struct rs_conf_port const * port,
    int * fd,
    size_t worker_c,
    struct in_addr addr
) {
    *fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (*fd == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful socket(AF_INET, SOCK_STREAM | "
            "SOCK_NONBLOCK, 0)");
        return RS_FATAL;
    }
    RS_LOG(LOG_DEBUG, "Bind()ing an IPv4 address on port %" PRIu16
        " to a socket_fd: fd=%d", port->port_number, *fd);
    return bind_socket(port, *fd, worker_c,
        (struct sockaddr *) &(struct sockaddr_in){
            .sin_family = AF_INET,
            .sin_port = RS_HTON16(port->port_number),
            .sin_addr = addr
        }, sizeof(struct sockaddr_in));
}

static rs_ret bind_ipv6(
    struct rs_conf_port const * port,
    int * fd,
    size_t worker_c,
    struct in6_addr addr,
    bool ipv6_is_v6only
) {
    *fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (*fd == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful socket(AF_INET6, SOCK_STREAM | "
            "SOCK_NONBLOCK, 0)");
        return RS_FATAL;
    }
    if (setsockopt(*fd, IPPROTO_IPV6, IPV6_V6ONLY, (int []){ipv6_is_v6only},
        sizeof(int)) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful setsockopt(%d, IPPROTO_IPV6, "
            "IPV6_V6ONLY, (int []){%d}, sizeof(int))", *fd, ipv6_is_v6only);
        return RS_FATAL;
    }
    RS_LOG(LOG_DEBUG, "Bind()ing an IPv6 address on port %" PRIu16
        " to a socket_fd: fd=%d", port->port_number, *fd);
    return bind_socket(port, *fd, worker_c,
        (struct sockaddr *) &(struct sockaddr_in6){
            .sin6_family = AF_INET6,
            .sin6_port = RS_HTON16(port->port_number),
            .sin6_addr = addr
        }, sizeof(struct sockaddr_in6));
}

rs_ret bind_to_ports(
    struct rs_conf * conf
) {
    for (struct rs_conf_port * port = conf->ports;
        port < conf->ports + conf->port_c; port++) {
        switch (port->listen_ip_kind) {
        case RS_LISTEN_IP_SPECIFIC:
            port->listen_fd_c = port->ipv4_addr_c + port->ipv6_addr_c;
            break;
        case RS_LISTEN_IP_ANY:
            port->listen_fd_c = 2;
            break;
        default:
            port->listen_fd_c = 1;
        }
        RS_CALLOC(port->listen_fds, conf->worker_c);
        for (size_t i = 0; i < conf->worker_c; i++) {
            RS_LOG(LOG_DEBUG, "Obtaining listen_fds for worker#%d...", i + 1);
            RS_CALLOC(port->listen_fds[i], port->listen_fd_c);
            int * fd = port->listen_fds[i];
            // See bind_socket() for the significance of a worker_c of 0
            size_t worker_c = i ? 0 : conf->worker_c;
            // It would arguably be cleaner to use INADDR_ANY and
            // IN6ADDR_ANY_INIT instead of just initializing the in(6)_addr
            // structs to zero, but they're de facto equivalent.
            switch (port->listen_ip_kind) {
            case RS_LISTEN_IP_ANY:
                RS_GUARD(bind_ipv4(port, fd++, worker_c,
                    (struct in_addr){0}));
                RS_GUARD(bind_ipv6(port, fd++, worker_c,
                    (struct in6_addr){0}, true));
                continue;
            case RS_LISTEN_IP_ANY_V6_OR_EMBEDDED_V4:
                RS_GUARD(bind_ipv6(port, fd++, worker_c,
                    (struct in6_addr){0}, false));
                continue;
            case RS_LISTEN_IP_ANY_V4:
                RS_GUARD(bind_ipv4(port, fd++, worker_c,
                    (struct in_addr){0}));
                continue;
            case RS_LISTEN_IP_ANY_V6:
                RS_GUARD(bind_ipv6(port, fd++, worker_c,
                    (struct in6_addr){0}, true));
                continue;
            case RS_LISTEN_IP_SPECIFIC:
                for (struct in_addr * addr = port->ipv4_addrs;
                    addr < port->ipv4_addrs + port->ipv4_addr_c; addr++) {
                    RS_GUARD(bind_ipv4(port, fd++, worker_c, *addr));
                }
                for (struct in6_addr * addr = port->ipv6_addrs;
                    addr < port->ipv6_addrs + port->ipv6_addr_c; addr++) {
                    RS_GUARD(bind_ipv6(port, fd++, worker_c, *addr, true));
                }
                continue;
            default:
                RS_LOG(LOG_CRIT, "Unexpected port->listen_ip_kind value: %u. "
                    "This shouldn't be possible.",
                    port->listen_ip_kind);
                return RS_FATAL;
            }
        }
    }
    return RS_OK;
}

rs_ret listen_to_sockets(
    struct rs_worker * worker,
    int epoll_fd
) {
    for (struct rs_conf_port * p = worker->conf->ports;
        p < worker->conf->ports + worker->conf->port_c; p++) {
        for (size_t i = 0; i < p->listen_fd_c; i++) {
            int listen_fd = p->listen_fds[worker->worker_i][i];
            // todo: for some bizarre reason listen() _sometimes_ returns
            // EADDRINUSE even though each listen_fd (as obtained through bind()
            // after setting both SO_REUSEADDR and SO_REUSEPORT) is never used
            // anywhere but here, and is unique (i.e., mutually exclusive)
            // between threads.
            //
            // A possible cause could be an unclean kernel state caused after a
            // previous execution of RingSocket segfaulted. Currently
            // investigating...
            if (listen(listen_fd, SOMAXCONN) == -1) {
                RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful listen(%d, SOMAXCONN)",
                    listen_fd);
                return RS_FATAL;
            }
            RS_LOG(LOG_DEBUG, "Successful listen(%d, SOMAXCONN)", listen_fd);
            struct epoll_event event = {
                .data = {.u64 = *((uint64_t *) (uint32_t []){
                    p->is_encrypted ? RS_EVENT_ENCRYPTED_LISTENFD :
                        RS_EVENT_UNENCRYPTED_LISTENFD,
                    listen_fd,
                })},
                .events = EPOLLIN | EPOLLET
            };
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &event) == -1) {
                RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful epoll_ctl(%d, "
                    "EPOLL_CTL_ADD, %d, &event)", epoll_fd, listen_fd);
                return RS_FATAL;
            }
        }
    }
    return RS_OK;
}

rs_ret accept_sockets(
    struct rs_worker * worker,
    int epoll_fd,
    int listen_fd,
    bool is_encrypted
) {
    static_assert(EAGAIN == EWOULDBLOCK, "EAGAIN != EWOULDBLOCK");
    for (;;) {
        // Use NULL as addr and addrlen args to save worker->peers array space.
        // When/if needed, peer info can be obtained with getpeername().
        int socket_fd = accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK);
        if (socket_fd == -1) {
            switch (errno) {
            case EAGAIN:
                return RS_OK;
            case ECONNABORTED: // Peer already hung up. Kinda rude.
                RS_LOG_ERRNO(LOG_DEBUG, "accept4(%d, NULL, NULL, "
                    "SOCK_NONBLOCK) returned ECONNABORTED", listen_fd);
                continue;
            case EMFILE:
                RS_LOG_ERRNO(LOG_WARNING, "accept4(%d, NULL, NULL, "
                    "SOCK_NONBLOCK) returned EMFILE", listen_fd);
                continue;
            case ENFILE:
                RS_LOG_ERRNO(LOG_WARNING, "accept4(%d, NULL, NULL, "
                    "SOCK_NONBLOCK) returned ENFILE", listen_fd);
                continue;
            case ENOBUFS:
                RS_LOG_ERRNO(LOG_WARNING, "accept4(%d, NULL, NULL, "
                    "SOCK_NONBLOCK) returned ENOBUFS", listen_fd);
                continue;
            case ENOMEM:
                RS_LOG_ERRNO(LOG_WARNING, "accept4(%d, NULL, NULL, "
                    "SOCK_NONBLOCK) returned ENOMEM", listen_fd);
                continue;
            default:
                RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful accept4(%d, NULL, NULL, "
                    "SOCK_NONBLOCK)", listen_fd);
                return RS_FATAL;
            }
        }
        size_t peer_i = 0;
        if (alloc_slot(&worker->peer_slots, &peer_i) != RS_OK) {
            RS_LOG(LOG_WARNING, "Accept()ed new peer %s, but all peer slots "
                "are currently full. Aborting peer.",
                get_addr_str(&(union rs_peer){.socket_fd = socket_fd}));
            if (close(socket_fd) == -1) {
                RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful close(%d)", socket_fd);
                return RS_FATAL;
            }
            continue;
        }
        RS_LOG(LOG_DEBUG, "Assigning accept()ed new peer with fd=%d to peer_i "
            "%zu", socket_fd, peer_i);
        if (peer_i > worker->highest_peer_i) {
            worker->highest_peer_i = peer_i;
        }
        worker->peers[peer_i].socket_fd = socket_fd;
        worker->peers[peer_i].is_encrypted = is_encrypted;
        struct epoll_event event = {
            .data = {.u64 = *((uint64_t *) (uint32_t []){
                RS_EVENT_PEER,
                peer_i
            })},
            .events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET
        };
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fd, &event) == -1) {
            RS_LOG_ERRNO(LOG_ERR, "Unsuccessful epoll_ctl(%d, EPOLL_CTL_ADD, "
                "%d, &event)", epoll_fd, socket_fd);
        }
    }
}
