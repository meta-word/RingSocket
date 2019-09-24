#define _GNU_SOURCE // Because posix doesn't define RTLD_NEXT

#include "../src/rs_event.h" // RS_EVENT_PEER and <ringsocket.h>
#include <dlfcn.h> // dlsym()
#include <sys/epoll.h>

#define RS_SHAM_IO_REALLOC_FACTOR 1.5
#define RS_SHAM_IO_INIT_ELEM_C 1000

#define RS_MAPPED_PEER_NONE UINT32_MAX

thread_local static struct {
    union {
        void * sym;
        int (* func)(int);
    } close;
    union {
        void * sym;
        int (* func)(int, int, int, struct epoll_event *);
    } epoll_ctl;
    union {
        void * sym;
        int (* func)(int, struct epoll_event *, int, int);
    } epoll_wait;
    union {
        void * sym;
        ssize_t (* func)(int, void *, size_t);
    } read;
    union {
        void * sym;
        ssize_t (* func)(int, const void *, size_t);
    } write;
} actual = {0};

struct rs_fd_peer_map {
    int fd; // The socket file descriptor for which sham IO events are created
    uint32_t peer_i; // Worker thread's rs_event.c peer_i (needed as epoll data)
};

thread_local struct rs_fd_peer_map * map = NULL;
thread_local static size_t map_elem_c = 0;

thread_local struct epoll_event * sham_events = NULL;
thread_local static size_t sham_events_elem_c = 0;
thread_local static int sham_event_c = 0; // Use int to match epoll signatures

static rs_ret set_actual_function_symbol(
    const char * func_name,
    void * * sym
) {
    *sym = dlsym(RTLD_NEXT, func_name);
    if (*sym) {
        return RS_OK;
    }
    RS_LOG(LOG_CRIT, "Unsuccessful dlsym(RTLD_NEXT, %s)", func_name);
    return RS_FATAL;
}

static rs_ret init_sham(
    void
) {
    RS_GUARD(set_actual_function_symbol("close", &actual.close.sym));
    RS_GUARD(set_actual_function_symbol("epoll_ctl", &actual.epoll_ctl.sym));
    RS_GUARD(set_actual_function_symbol("epoll_wait", &actual.epoll_wait.sym));
    RS_GUARD(set_actual_function_symbol("read", &actual.read.sym));
    RS_GUARD(set_actual_function_symbol("write", &actual.write.sym));
    map_elem_c = sham_events_elem_c = RS_SHAM_IO_INIT_ELEM_C;
    RS_CALLOC(map, map_elem_c);
    RS_CALLOC(sham_events, sham_events_elem_c);
    return RS_OK;
}

static void remove_mapping_if_any(
    int fd
) {
    for (struct rs_fd_peer_map * m = map; m < map + map_elem_c; m++) {
        if (m->fd == fd) {
            memset(m, 0, sizeof(struct rs_fd_peer_map));
            return;
        }
    }
}

static rs_ret add_mapping(
    int fd,
    uint32_t peer_i
) {
    for (struct rs_fd_peer_map * m = map; m < map + map_elem_c; m++) {
        if (!m->fd) {
            // This element is vacant, so occupy it.
            m->fd = fd;
            m->peer_i = peer_i;
            return RS_OK;
        }
    }
    size_t map_i = map_elem_c;
    map_elem_c *= RS_SHAM_IO_REALLOC_FACTOR;
    RS_REALLOC(map, map_elem_c);
    map[map_i].fd = fd;
    map[map_i].peer_i = peer_i;
    while (++map_i < map_elem_c) {
        memset(map + map_i, 0, sizeof(struct rs_fd_peer_map));
    }
    return RS_OK;
}

static uint32_t get_mapped_peer_i(
    int fd
) {
    for (struct rs_fd_peer_map * m = map; m < map + map_elem_c; m++) {
        if (m->fd == fd) {
            return m->peer_i;
        }
    }
    return RS_MAPPED_PEER_NONE;
}

static struct epoll_event * get_sham_events(
    uint32_t peer_i
) {
    uint64_t u64 = RS_EVENT_PEER;
    u64 <<= 32;
    u64 |= peer_i;
    for (struct epoll_event * e = sham_events; e < sham_events + sham_event_c;
        e++) {
        if (e->data.u64 == u64) {
            return e;
        }
    }
    return NULL;
}

static rs_ret add_sham_event(
    uint32_t peer_i,
    uint32_t sham_event
) {
    if ((size_t) sham_event_c >= sham_events_elem_c) {
        sham_events_elem_c *= RS_SHAM_IO_REALLOC_FACTOR;
        RS_REALLOC(sham_events, sham_events_elem_c);
    }
    sham_events[sham_event_c].data.u64 =
        *((uint64_t *) (uint32_t []){RS_EVENT_PEER, peer_i});
    sham_events[sham_event_c++].events = sham_event;
    return RS_OK;
}

int epoll_ctl(
    int epoll_fd,
    int op,
    int fd,
    struct epoll_event * event
) {
    if (!map && init_sham() != RS_OK) {
        exit(1);
    }
    // Check if EPOLL_CTL_ADD, even though RingSocket doesn't use anything else.
    if (op == EPOLL_CTL_ADD) {
        // Same uint32_t assignment as that of loop_over_events() in rs_event.c
        uint32_t event_kind = 0;
        uint32_t event_peer_i = 0;
        {
            uint64_t u64 = event->data.u64;
            // If p were to be assigned directly from &e->data.u64,
            // GCC 9+ would complain about -Waddress-of-packed-member.
            uint32_t * p = (uint32_t *) &u64;
            event_kind = *p++;
            event_peer_i = *p;
        }
        if (event_kind == RS_EVENT_PEER &&
            add_mapping(fd, event_peer_i) != RS_OK) {
            exit(2);
        }
    }
    return actual.epoll_ctl.func(epoll_fd, op, fd, event);
}

int close(
    int fd
) {
    if (map) {
        remove_mapping_if_any(fd);
    } else if (init_sham() != RS_OK) {
        exit(3);
    }
    return actual.close.func(fd);
}

int epoll_wait(
    int epoll_fd,
    struct epoll_event * events,
    int max_event_c,
    int timeout
) {
    if (!map && init_sham() != RS_OK) {
        exit(4);
    }
    if (!sham_event_c) {
        return actual.epoll_wait.func(epoll_fd, events, max_event_c, timeout);
    }
    if (sham_event_c > max_event_c) {
        memcpy(events, sham_events, max_event_c);
        sham_event_c -= max_event_c;
        memcpy(sham_events, sham_events + max_event_c, sham_event_c);
        return max_event_c;
    }
    memcpy(events, sham_events, sham_event_c);
    int ret = sham_event_c;
    sham_event_c = 0;
    return ret;
}

static ssize_t generate_sham_io_byte_c(
    size_t req_byte_c
) {
    thread_local static size_t gen_i = 99;
    gen_i++;
    gen_i %= 100;
    if (gen_i % 2 == 1 || gen_i % 5 == 4) {
        return -1;
    }
    if (gen_i % 6) {
        return req_byte_c;
    }
    return gen_i % 3 ? RS_MAX(2, req_byte_c / (100 - gen_i)) : 1;
}

ssize_t read(
    int fd,
    void * buf,
    size_t byte_c
) {
    if (!map && init_sham() != RS_OK) {
        exit(5);
    }
    uint32_t mapped_peer_i = get_mapped_peer_i(fd);
    if (mapped_peer_i == RS_MAPPED_PEER_NONE) {
        return actual.read.func(fd, buf, byte_c);
    }
    struct epoll_event * e = get_sham_events(mapped_peer_i);
    ssize_t sham_byte_c = 0;
    if (e) {
        if (e->events & EPOLLIN) {
            errno = EAGAIN;
            return -1;
        }
        sham_byte_c = generate_sham_io_byte_c(byte_c);
        if (sham_byte_c == -1) {
            e->events |= EPOLLIN;
            errno = EAGAIN;
            return -1;
        }
    } else {
        sham_byte_c = generate_sham_io_byte_c(byte_c);
        if (sham_byte_c == -1) {
            if (add_sham_event(mapped_peer_i, EPOLLIN) != RS_OK) {
                exit(6);
            }
            errno = EAGAIN;
            return -1;
        }
    }
    return actual.read.func(fd, buf, sham_byte_c);
}

ssize_t write(
    int fd,
    const void * buf,
    size_t byte_c
) {
    if (!map && init_sham() != RS_OK) {
        exit(7);
    }
    uint32_t mapped_peer_i = get_mapped_peer_i(fd);
    if (mapped_peer_i == RS_MAPPED_PEER_NONE) {
        return actual.write.func(fd, buf, byte_c);
    }
    struct epoll_event * e = get_sham_events(mapped_peer_i);
    ssize_t sham_byte_c = 0;
    if (e) {
        if (e->events & EPOLLOUT) {
            errno = EAGAIN;
            return -1;
        }
        sham_byte_c = generate_sham_io_byte_c(byte_c);
        if (sham_byte_c == -1) {
            e->events |= EPOLLOUT;
            errno = EAGAIN;
            return -1;
        }
    } else {
        sham_byte_c = generate_sham_io_byte_c(byte_c);
        if (sham_byte_c == -1) {
            if (add_sham_event(mapped_peer_i, EPOLLOUT) != RS_OK) {
                exit(8);
            }
            errno = EAGAIN;
            return -1;
        }
    }
    return actual.write.func(fd, buf, sham_byte_c);
}
