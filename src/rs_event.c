// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include "rs_event.h"
#include "rs_hash.h" // init_hash_state()
#include "rs_http.h" // handle_http_io()
#include "rs_ring.h" // various functions
#include "rs_socket.h" // listen_to_sockets(), accept_sockets(), etc
#include "rs_tcp.h" // handle_tcp_io()
#include "rs_tls.h" // create_tls_contexts(), handle_tls_io()
#include "rs_util.h" // get_peer_str(), get_epoll_events_str()
#include "rs_websocket.h" // handle_ws_io()

#include <assert.h> // static_assert()
#include <sys/epoll.h>

rs_ret handle_peer_events(
    struct rs_conf const * conf,
    uint8_t * rbuf,
    union rs_peer * peer,
    uint32_t peer_i,
    uint32_t events
) {
    if (events & EPOLLERR) {
        RS_LOG(LOG_WARNING, "Received EPOLLERR (all events: %s) for %s",
            get_epoll_events_str(events), get_peer_str(peer));
        // Should not be a common occurence. Fail fast to free up resources.
        peer->mortality = RS_MORTALITY_DEAD;
        if (peer->layer == RS_LAYER_WEBSOCKET) {
            // handle_ws_io() assumes that send_close_to_app() and
            // remove_pending_write_references() have already been called before
            // peer->mortality == RS_MORTALITY_DEAD was set, so call them now
            // from here before proceeding.
            send_close_to_app(conf, peer, peer_i);
            remove_pending_write_references(peer, peer_i);
        }
    } else if (events & EPOLLHUP) {
        // Don't user get_peer_str() because the peer may already be gone.
        RS_LOG(LOG_DEBUG, "Received EPOLLHUP (all events: %s)",
            get_epoll_events_str(events));
        // HUP means that the peer has disappeared, or at least is not going to
        // read anything it is sent from here on out. However, there is a
        // possibility that data of value originating from this peer is still
        // in transit, provided that the peer is on the WebSocket layer -- so
        // only fail fast on other layers.
        if (peer->layer != RS_LAYER_WEBSOCKET) {
            peer->mortality = RS_MORTALITY_DEAD;
        }
    } else if (events & EPOLLRDHUP) {
        // Don't user get_peer_str() because the peer may already be gone.
        RS_LOG(LOG_DEBUG, "Received EPOLLRDHUP (all events: %s)",
            get_epoll_events_str(events));
        // Although RDHUP is supposed to mean that there will no longer be any
        // data left to read from the peer, this flag can not be interpreted as
        // a guarantee that the read buffer is empty. For example, the read
        // buffer may still contain lingering data that had to be temporarily
        // ignored because of a stalled write operation. Therefore, attempt to
        // continue processing as usual if on the WebSocket layer; but fail
        // fast on any other layer.
        if (peer->layer != RS_LAYER_WEBSOCKET) {
            peer->mortality = RS_MORTALITY_DEAD;
        }
    }
    if (peer->is_writing && !(events & EPOLLOUT) &&
        peer->mortality == RS_MORTALITY_LIVE) {
        RS_LOG(LOG_DEBUG, "Writing blocked for %s with events %s",
            get_peer_str(peer), get_epoll_events_str(events));
        return RS_OK;
    }
    enum rs_layer layer = RS_LAYER_TCP;
    do {
        layer = peer->layer;
        switch (layer) {
        case RS_LAYER_TCP:
            RS_GUARD(handle_tcp_io(peer, rbuf, conf->worker_rbuf_size, peer_i));
            break;
        case RS_LAYER_TLS:
            RS_GUARD(handle_tls_io(peer, rbuf, conf->worker_rbuf_size));
            break;
        case RS_LAYER_HTTP:
            RS_GUARD(handle_http_io(conf, peer, (char *) rbuf));
            if (peer->layer == RS_LAYER_WEBSOCKET) {
                RS_LOG(LOG_DEBUG, "Sending peer_i %zu open to app...", peer_i);
                RS_GUARD(send_open_to_app(conf, peer, peer_i));
                // The WebSocket Upgrade response was only just sent, so it is
                // not possible to have already received a WebSocket message:
                // don't try to read() until the next event occurs.
                return RS_OK;
            }
            break;
        case RS_LAYER_WEBSOCKET: default:
            RS_GUARD(handle_ws_io(conf, peer, peer_i, rbuf));
        }
    } while (peer->layer != layer);
    return RS_OK;
}

void set_shutdown_deadline(
    union rs_peer * peer,
    size_t wait_interval
) {
    // Convert the deadline time to an uint16_t greater than 0.
    peer->shutdown_deadline = (time(NULL) + wait_interval) % 0xFFFF + 1;
}

static rs_ret enforce_shutdown_deadlines(
    union rs_peer * peers,
    size_t peers_elem_c,
    time_t timestamp
) {
    uint16_t t = timestamp % 0xFFFF + 1;
    for (union rs_peer * p = peers; p < peers + peers_elem_c; p++) {
        if (p->shutdown_deadline &&
            (p->shutdown_deadline < t || p->shutdown_deadline > t + 0x7FFF)) {
            p->mortality = RS_MORTALITY_DEAD;
            // Calling handle_peer_events() with a MORTALITY_DEAD peer (but
            // without any actual events) allows cleanup to take place through
            // all relevant layers.
            RS_GUARD(handle_peer_events(NULL, NULL, p, 0, 0));
        }
    }
    return RS_OK;
}

static rs_ret loop_over_events(
    struct rs_conf const * conf,
    struct rs_thread_io_pairs * * all_io_pairs,
    struct rs_thread_sleep_state * app_sleep_states,
    struct rs_thread_sleep_state * worker_sleep_state,
    int worker_eventfd,
    size_t worker_i
) {
    // Thread ID used as prefix by RS_LOG -- see conf.c and ringsocket_util.h
    sprintf(_rs_thread_id_str, "Worker#%zu: ", worker_i + 1);
    RS_GUARD(init_rings(conf, all_io_pairs, app_sleep_states,
        worker_sleep_state, worker_i));
    RS_GUARD(init_hash_state());
    RS_GUARD(create_tls_contexts(conf));
    static_assert(sizeof(int) == 4, "sizeof(int) != 4. Some code might need to "
        "be written in a more portable manner after all. Please file a bug "
        "report mentioning your CPU model. ");
    static_assert(sizeof(union rs_peer) == 40, "sizeof(union rs_peer) is not "
        "the 40 bytes it was expected to be.");
    union rs_peer * peers = NULL;
    size_t const peers_elem_c = conf->fd_alloc_c / conf->worker_c;
    RS_CALLOC(peers, peers_elem_c);
    RS_GUARD(init_peer_slots(peers_elem_c));
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful epoll_create1(0)");
        return RS_FATAL;
    }
    RS_LOG(LOG_DEBUG, "Created an epoll_fd: fd=%d", epoll_fd);
    RS_GUARD(listen_to_sockets(conf, worker_i, epoll_fd));
    {
        struct epoll_event event = {
            .data = {.u64 = *((uint64_t *) (uint32_t []){
                RS_EVENT_EVENTFD,
                worker_eventfd,
            })},
            .events = EPOLLIN | EPOLLET
        };
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, worker_eventfd, &event) == -1) {
            RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful epoll_ctl(%d, "
                "EPOLL_CTL_ADD, %d (worker_eventfd), &event)", epoll_fd,
                worker_eventfd);
            return RS_FATAL;
        }
    }
    uint8_t * rbuf = NULL;
    RS_CALLOC(rbuf, conf->worker_rbuf_size);
    time_t timestamp = time(NULL);
    // Allocate the epoll buffer on the heap too, just in case it could be
    // large enough to gobble up too much stack space.
    struct epoll_event * epoll_buf = NULL;
    RS_CALLOC(epoll_buf, conf->epoll_buf_elem_c);
    RS_LOG(LOG_DEBUG, "Entering epoll event loop...");
    for (;;) {
        announce_worker_sleep();
        // There may be ring pointer updates pending, but because
        // memory_order_relaxed was used and because the corresponding inbound
        // write may have only been just completed, it is potentially still
        // prone to CPU memory reordering at this point. After an epoll_wait()
        // function call that should no longer be the case though, so call that
        // with a timeout argument of 0.
        int event_c = epoll_wait(epoll_fd, epoll_buf, conf->epoll_buf_elem_c,
            0);
        if (event_c == -1) {
            RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful epoll_wait(%d, epoll_buf, "
                "%u, 0)", epoll_fd, conf->epoll_buf_elem_c);
            return RS_FATAL;
        }
        flush_ring_updates(conf->app_c);
        if (!event_c) {
            // A timeout of 0 was needed above to guarantee an opportunity to
            // call flush_ring_updates(), but no events have ocurred yet; so
            // this time call epoll_wait without any timeout (-1) to obtain an
            // event_c > 0.
            event_c = epoll_wait(epoll_fd, epoll_buf, conf->epoll_buf_elem_c,
                -1);
            if (event_c == -1) {
                RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful epoll_wait(%d, "
                    "epoll_buf, %u, -1)", epoll_fd, conf->epoll_buf_elem_c);
                return RS_FATAL;
            }
        }
        for (struct epoll_event * e = epoll_buf; e < epoll_buf + event_c; e++) {
            uint32_t e_kind = 0;
            uint32_t e_data = 0;
            {
                uint32_t * p = (uint32_t *) &e->data.u64;
                e_kind = *p++;
                e_data = *p;
            }
            if (e_kind == RS_EVENT_PEER) {
                RS_GUARD(handle_peer_events(conf, rbuf, peers + e_data, e_data,
                    e->events));
                continue;
            }
            if (e->events & EPOLLERR) {
                RS_LOG(LOG_ERR, "Event EPOLLERR occurred on %s fd %d",
                    (char *[]){"???", "encrypted listen", "unencrypted listen",
                    "event"}[e_kind], (int) e_data);
                return RS_FATAL;
            }
            if (e->events & EPOLLHUP) {
                RS_LOG(LOG_ERR, "Event EPOLLHUP occurred on %s fd %d",
                    (char *[]){"???", "encrypted listen", "unencrypted listen",
                    "event"}[e_kind], (int) e_data);
                return RS_FATAL;
            }
            switch (e_kind) {
            case RS_EVENT_ENCRYPTED_LISTENFD:
                RS_GUARD(accept_sockets(peers, epoll_fd, e_data, true));
                continue;
            case RS_EVENT_UNENCRYPTED_LISTENFD:
                RS_GUARD(accept_sockets(peers, epoll_fd, e_data, false));
                continue;
            case RS_EVENT_EVENTFD: default:
                if (read((int) e_data, (uint64_t []){0}, 8) != 8) {
                    RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful read(eventfd, ...)");
                    return RS_FATAL;
                }
                // Do nothing for now, because after all events are processed,
                // receive_from_app() is called anyway.
            }
        }
        RS_GUARD(receive_from_app(conf, peers, peers_elem_c));
        time_t new_timestamp = time(NULL);
        if (new_timestamp > timestamp + 60) { // No more than 1 check per minute
            timestamp = new_timestamp;
            RS_GUARD(enforce_shutdown_deadlines(
                peers, peers_elem_c, timestamp));
        }
    }
}

int work(
    struct rs_worker_args *worker_args
) {
    if (loop_over_events(
        worker_args->conf,
        worker_args->all_io_pairs,
        worker_args->app_sleep_states,
        worker_args->worker_sleep_state,
        worker_args->worker_eventfd,
        worker_args->worker_i
        ) == RS_OK) {
        // todo: catch signal(s) such that this becomes actually possible?
        return thrd_success;
    }
    // exit() instead of return thrd_error to make sure any other threads go
    // down too.
    exit(EXIT_FAILURE);
}
