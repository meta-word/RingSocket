// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

// This file is intended to be compiled as a shared object that should be
// preloaded by RingSocket by executing it with a command such as:
// "sudo LD_PRELOAD=$PWD/rs_sham_io.so ringsocket"
//
// The objective of this file is to simulate EAGAIN/partial IO events by
// wrapping the <unistd.h> read() and write() functions. This is accomplished
// at runtime by using LD_PRELOAD to replace those functions with our own
// versions that in turn call the dlsym()-loaded original read() and write()
// functions where necessary. (For more information, Google "LD_PRELOAD trick".)
//
// This is valuable for testing purposes, because it greatly increases code
// coverage of branches that are only evaluated under certain heavy loads.
// EAGAIN on write() in particular is hard to test deterministically without
// wrappers such as these.
//
// Due to the fact that RingSocket polls IO availability trough epoll in
// edge-triggered mode, any simulated EAGAIN must be followed by a simulated
// EPOLLIN/EPOLLOUT event to prevent indefinite stalls, which is why this file
// also wraps the epoll_wait() function. Furthermore, due to how RingSocket
// uses a peer index variable instead of the socket file descriptor as its epoll
// event data, the epoll_ctl() and close() functions are wrapped too, in order
// to keep track of any "fd" to "peer_i" mappings.
//
// Note that this file also works as intended for wss:// connections, owing to
// the fact that OpenSSL internally calls the same read() and write() functions
// (at least on Linux), as evidenced by the bottom part of:
// https://github.com/openssl/openssl/blob/master/include/internal/sockets.h

#define _GNU_SOURCE // Because posix doesn't define RTLD_NEXT

#include "../src/rs_event.h" // RS_EVENT_PEER and other RingSocket macros
#include <dlfcn.h> // dlsym()
#include <sys/epoll.h>

#define RS_SHAM_IO_REALLOC_FACTOR 1.5
#define RS_SHAM_IO_INIT_ELEM_C 1000

#define RS_MAPPED_PEER_NONE UINT32_MAX // Returned by get_mapped_peer_i() below

// A struct holding references to all wrapped original library functions.
thread_local static struct {
    // Using unions is a "relatively clean" way to avoid compiler complaints
    // regarding casting of object pointers to function pointers.
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
} orig = {0};

struct rs_fd_peer_map {
    int fd; // The socket file descriptor for which sham IO events are created
    uint32_t peer_i; // Worker thread's rs_event.c peer_i (needed as epoll data)
};

thread_local struct rs_fd_peer_map * map = NULL;
thread_local static size_t map_elem_c = 0;

thread_local struct epoll_event * sham_events = NULL;
thread_local static size_t sham_events_elem_c = 0;
thread_local static int sham_event_c = 0; // Use int to match epoll signatures

static rs_ret set_original_function_symbol(
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
    RS_GUARD(set_original_function_symbol("close", &orig.close.sym));
    RS_GUARD(set_original_function_symbol("epoll_ctl", &orig.epoll_ctl.sym));
    RS_GUARD(set_original_function_symbol("epoll_wait", &orig.epoll_wait.sym));
    RS_GUARD(set_original_function_symbol("read", &orig.read.sym));
    RS_GUARD(set_original_function_symbol("write", &orig.write.sym));
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
    return orig.epoll_ctl.func(epoll_fd, op, fd, event);
}

int close(
    int fd
) {
    if (map) {
        remove_mapping_if_any(fd);
    } else if (init_sham() != RS_OK) {
        exit(3);
    }
    return orig.close.func(fd);
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
        return orig.epoll_wait.func(epoll_fd, events, max_event_c, timeout);
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
        return orig.read.func(fd, buf, byte_c);
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
    return orig.read.func(fd, buf, sham_byte_c);
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
        return orig.write.func(fd, buf, byte_c);
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
    return orig.write.func(fd, buf, sham_byte_c);
}
