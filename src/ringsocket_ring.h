// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket.h>

#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h> // write()

// This header file implements ring-buffer-based lockless single-producer
// single-consumer inter-thread IO intended for use between worker threads and
// app threads. Each app <-> worker combination uses a single shared
// rs_thread_io_pairs struct, which in turn consists of an inbound and
// outbound rs_thread_pair reader and writer corresponding to an inbound
// ring buffer and outbound ring buffer respectively. The worker thread controls
// inbound.writer and outbound.reader, whereas the app thread controls
// inbound.reader and outbound.writer. 

// Atomic loads and stores with a memory_order other than memory_order_relaxed
// are known to be a bit expensive because of their de-pipelining effects.
//
// Instead of allowing the CPU to stall for such memory synchronization, rs
// instead stores ring buffer pointer updates in a rs_ring_update_queue struct
// of a constant (but configurable) size, and only performs the actual write to
// the corresponding shared atomic variable once a number of enqueue calls equal
// to its length causes it to be dequeued. To ensure that no update becomes
// stuck in a sleeping thread, calls to epoll_wait() and futex_wait() are
// doubled: 1st with a timeout of 0, then all pending updates are flushed (which
// is safe against memory reordering due to being done across the systemcalls
// involved in epol_wait() and futex_wait()), and then finally a 2nd time with
// the timeout actually intended (if any).
//
// The small delay in receiving notification of any progress made in other
// threads that occurs as a consequence of this approach does not pose any
// problem provided the ring buffers are of sufficient initial size.

#define RS_PREVENT_COMPILER_REORDERING __asm__ volatile("" ::: "memory")

// memory_order_relaxed for ring buffer updates should be safe enough provided
// that every update queue is long enough to defer updates long enough for ring
// buffer IO to have been completed even if worst case CPU memory reordering
// occurs. Appropriate sizes may differ significantly between CPU architectures;
// as well as between inbound writes, inbound reads, outbound writes, and
// outbound reads -- due to factors such as each code locations frequency of
// updates and expensive operations such as function calls. The same is true in
// reverse for app futexes: the app must set its sleep state well in advance of
// calling futex_wait().

#define RS_ATOMIC_STORE_RELAXED(store, val) \
do { \
    /* Don't let the compiler move atomic_store_explicit() to earlier code */ \
    RS_PREVENT_COMPILER_REORDERING; \
    atomic_store_explicit((store), (val), memory_order_relaxed); \
    /* Don't let the compiler move atomic_store_explicit() to later code */ \
    RS_PREVENT_COMPILER_REORDERING; \
} while (0)

#define RS_ATOMIC_LOAD_RELAXED(store, val) \
    RS_ATOMIC_LOAD_RELAXED_CASTED(store, val,)

#define RS_ATOMIC_LOAD_RELAXED_CASTED(store, val, cast) \
do { \
    /* Don't let the compiler move atomic_load_explicit() to earlier code */ \
    RS_PREVENT_COMPILER_REORDERING; \
    (val) = cast atomic_load_explicit((store), memory_order_relaxed); \
    /* Don't let the compiler move atomic_load_explicit() to later code */ \
    RS_PREVENT_COMPILER_REORDERING; \
} while (0)

struct rs_thread_pair { // C11 atomic types with C11 alignas
    alignas(RS_CACHELINE_SIZE) atomic_uintptr_t writer;
    alignas(RS_CACHELINE_SIZE) atomic_uintptr_t reader;
};

struct rs_thread_io_pairs {
    struct rs_thread_pair inbound;
    struct rs_thread_pair outbound;
};

struct rs_thread_sleep_state {
    // is_asleep is a boolean flag, but implemented as an atomic uint32_t for
    // compatibility with futex syscalls -- as used by app_sleepiness.is_asleep.
    alignas(RS_CACHELINE_SIZE) atomic_uint_least32_t is_asleep; // boolean
};

#define RS_RING_RESERVED_TAIL_SIZE ( \
    sizeof(uint32_t) + /* Reserved for msg_size 0 of an un-appendable msg */ \
    sizeof(uint8_t *) /* Reserved for a pointer to an un-appendable msg */ \
)

struct rs_ring {
    uint8_t * buf;
    uint8_t * old_buf;
    uint8_t * writer;
    size_t buf_size;
    double alloc_multiplier;
};

struct rs_ring_msg {
    uint32_t size;
    uint8_t const msg[];
};

struct rs_ring_update {
    uint8_t * ring_position;
    uint32_t thread_i;
    uint32_t is_write; // bool
};

struct rs_ring_update_queue {
    struct rs_ring_update * queue;
    size_t size;
    size_t oldest_i;
};

// Inline functions allowing apps to only include a single
// #include <ringsocket.h>, while avoiding function call overhead.

inline rs_ret rs_prepare_ring_write(
    struct rs_thread_pair * pair,
    struct rs_ring * ring,
    uint32_t msg_size
) {
    uint8_t * reader = NULL;
    RS_ATOMIC_LOAD_RELAXED(&pair->reader, reader);

    if (reader >= ring->buf && reader < ring->buf + ring->buf_size) {
        // Reader and writer are currently processing the same ring->buf.
        if (ring->old_buf) {
            // Which means any previously used ring buffer can be free()d now.
            RS_FREE(ring->old_buf);
        }
        if (ring->writer < reader) {
            // The writer is "one lap" ahead of the reader on this ring
            if (ring->writer + 4 + msg_size + RS_RING_RESERVED_TAIL_SIZE >
                reader) {
                goto allocate_new_ring_buf;
            }
        } else if (ring->writer + 4 + msg_size + RS_RING_RESERVED_TAIL_SIZE >
            ring->buf + ring->buf_size) {
            if (ring->buf + 4 + msg_size + RS_RING_RESERVED_TAIL_SIZE >
                reader) {
                allocate_new_ring_buf: // Allocate a bigger one.
                // Hold on to the existing buffer as old_buf, until the writer
                // has verified that the reader has reached the new buffer.
                ring->old_buf = ring->buf;
                ring->buf_size *= ring->alloc_multiplier;
                // Use RS_CACHE_ALIGNED_CALLOC() to eliminate possibility of
                // false sharing with preceding or trailing heap bytes.
                RS_CACHE_ALIGNED_CALLOC(ring->buf, ring->buf_size);
                RS_LOG(LOG_NOTICE, "Allocated a new ring buffer with size %zu",
                    ring->buf_size);
            }
            *((uint8_t * *) ring->writer) = ring->buf;
            ring->writer = ring->buf;
        }
    } else if (ring->writer + 4 + msg_size + RS_RING_RESERVED_TAIL_SIZE >
        ring->buf + ring->buf_size) {
        // The reader is still reading ring->old_buf and hasn't moved over to
        // ring->buf yet, even though ring->buf is already completely full.
        RS_LOG(LOG_CRIT, "FATAL CONDITION: Reader thread and writer thread "
            "are further out of sync than the entire ring buffer size %zu "
            "between them.", ring->buf_size);
            return RS_FATAL;
    }
    *((uint32_t *) ring->writer) = msg_size;
    ring->writer += 4;
    return RS_OK;
}

inline struct rs_ring_msg * rs_get_ring_msg(
    struct rs_thread_pair * pair,
    uint8_t const * reader // 1st msg ? ring->buf : prevref->msg + prevref->size
) {
    uint8_t * writer = NULL;
    RS_ATOMIC_LOAD_RELAXED(&pair->writer, writer);
    if (reader == writer) {
        // The reader has already caught up with the writer (i.e., the writer
        // hasn't published any new message yet).
        return NULL;
    }
    struct rs_ring_msg * ring_msg = (struct rs_ring_msg *) reader;
    if (!ring_msg->size) {
        // A size of 0 means the message was too large to be appended at the
        // current location. Instead, a pointer to its actual location should
        // be retrieved from the current location.
        ring_msg = *((struct rs_ring_msg * *) reader);
    }
    return ring_msg;
}


inline rs_ret rs_wake_up_app(
    struct rs_thread_sleep_state * app_sleep_state
) {
    bool app_is_asleep = false;
    RS_ATOMIC_LOAD_RELAXED(&app_sleep_state->is_asleep, app_is_asleep);
    if (app_is_asleep) {
        RS_ATOMIC_STORE_RELAXED(&app_sleep_state->is_asleep, false);
        if (syscall(SYS_futex, &app_sleep_state->is_asleep, FUTEX_WAKE_PRIVATE,
            1, NULL, NULL, 0) == -1) {
            RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful syscall(SYS_futex, %d, "
                "FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0)",
                app_sleep_state->is_asleep);
            return RS_FATAL;
        }
    }
    return RS_OK;
}

inline rs_ret rs_wake_up_worker(
    struct rs_thread_sleep_state * worker_sleep_state,
    int worker_eventfd
) {
    bool worker_is_asleep = false;
    RS_ATOMIC_LOAD_RELAXED(&worker_sleep_state->is_asleep, worker_is_asleep);
    if (worker_is_asleep) {
        RS_ATOMIC_STORE_RELAXED(&worker_sleep_state->is_asleep, false);
        if (write(worker_eventfd, (uint64_t []){1}, 8) != 8) {
            RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful write(worker_eventfd, ...)");
            return RS_FATAL;
        }
    }
    return RS_OK;
}

#define RS_TIME_INF UINT64_MAX

inline rs_ret rs_wait_for_worker(
    struct rs_thread_sleep_state * app_sleep_state,
    uint64_t timeout_microsec
) {
    struct timespec const * timeout = timeout_microsec == RS_TIME_INF ?
        NULL :
        &(struct timespec){
            .tv_sec = timeout_microsec / 1000000,
            .tv_nsec = 1000 * (timeout_microsec % 1000000)
        };
    if (syscall(SYS_futex, &app_sleep_state->is_asleep, FUTEX_WAIT_PRIVATE,
        true, timeout, NULL, 0) != -1 || errno == EAGAIN) {
        // May return immediately with errno == EAGAIN when a worker thread
        // already tried to wake this app thread up with rs_wake_up_app()
        // (which is possible because app_sleep_state->is_asleep was set to
        // true in advance of this function call). This is not a problem:
        // just try to do some more work.
        return RS_OK;
    }
    if (errno == ETIMEDOUT) {
        return RS_AGAIN; // Indicate that this function should be called again
        // to go back to sleep, because there was no worker thread activity.
    }
    RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful syscall(SYS_futex, &%d, "
        "FUTEX_WAIT_PRIVATE, 1, timeout, NULL, 0)", app_sleep_state->is_asleep);
    return RS_FATAL;
}

inline rs_ret rs_enqueue_ring_update(
    struct rs_ring_update_queue * updates,
    struct rs_thread_io_pairs * io_pairs,
    struct rs_thread_sleep_state * sleep_states,
    int const * eventfds,
    uint8_t const * new_ring_position,
    size_t thread_i,
    bool is_write
) {
    struct rs_ring_update * u = updates->queue + updates->oldest_i++;
    updates->oldest_i %= updates->size;
    // If an update exists at the oldest index, carry out dequeue procedures.
    if (u->ring_position) {
        if (eventfds) { // This function was called by an app thread.
            if (u->is_write) {
                RS_ATOMIC_STORE_RELAXED(
                    &io_pairs[u->thread_i].outbound.writer,
                    (atomic_uintptr_t) u->ring_position
                );
                RS_GUARD(rs_wake_up_worker(sleep_states + u->thread_i,
                    eventfds[u->thread_i]));
            } else {
                RS_ATOMIC_STORE_RELAXED(
                    &io_pairs[u->thread_i].inbound.reader,
                    (atomic_uintptr_t) u->ring_position
                );
            }
        } else { // This function was called by a worker thread.
            if (u->is_write) {
                RS_ATOMIC_STORE_RELAXED(
                    &io_pairs[u->thread_i].inbound.writer,
                    (atomic_uintptr_t) u->ring_position
                );
                RS_GUARD(rs_wake_up_app(sleep_states + u->thread_i));
            } else {
                RS_ATOMIC_STORE_RELAXED(
                    &io_pairs[u->thread_i].outbound.reader,
                    (atomic_uintptr_t) u->ring_position
                );
            }
        }
    }
    // Enqueue the new update at the oldest index, which is now the newest index
    u->ring_position = new_ring_position;
    u->thread_i = thread_i;
    u->is_write = is_write;
    return RS_OK;
}

inline rs_ret rs_flush_ring_updates(
    struct rs_ring_update_queue * updates,
    struct rs_thread_io_pairs * io_pairs,
    struct rs_thread_sleep_state * sleep_states,
    int const * eventfds,
    size_t dest_thread_c
) {
    for (size_t i = 0; i < dest_thread_c; i++) {
        bool updated_to_newer_r = false;
        bool updated_to_newer_w = false;
        size_t const newest_i = (updates->oldest_i + updates->size - 1)
            % updates->size;
        size_t j = newest_i;
        do {
            struct rs_ring_update * u = updates->queue + j;
            if (u->ring_position && u->thread_i == i) {
                if (eventfds) { // This function was called by an app thread.
                    if (u->is_write) {
                        if (!updated_to_newer_w) {
                            RS_ATOMIC_STORE_RELAXED(
                                &io_pairs[u->thread_i].outbound.writer,
                                (atomic_uintptr_t) u->ring_position
                            );
                            RS_GUARD(rs_wake_up_worker(sleep_states +
                                u->thread_i, eventfds[u->thread_i]));
                            updated_to_newer_w = true;
                        }
                    } else if (!updated_to_newer_r) {
                        RS_ATOMIC_STORE_RELAXED(
                            &io_pairs[u->thread_i].inbound.reader,
                            (atomic_uintptr_t) u->ring_position
                        );
                        updated_to_newer_r = true;
                    }
                } else { // This function was called by a worker thread.
                    if (u->is_write) {
                        if (!updated_to_newer_w) {
                            RS_ATOMIC_STORE_RELAXED(
                                &io_pairs[u->thread_i].inbound.writer,
                                (atomic_uintptr_t) u->ring_position
                            );
                            RS_GUARD(rs_wake_up_app(sleep_states +
                                u->thread_i));
                            updated_to_newer_w = true;
                        }
                    } else if (!updated_to_newer_r) {
                        RS_ATOMIC_STORE_RELAXED(
                            &io_pairs[u->thread_i].outbound.reader,
                            (atomic_uintptr_t) u->ring_position
                        );
                        updated_to_newer_r = true;
                    }
                }
                u->ring_position = NULL;
                u->thread_i = 0;
                u->is_write = false;
            }
            j += updates->size - 1;
            j %= updates->size;
        } while (j != newest_i);
    }
    return RS_OK;
}

// See the comment at the bottom of RS_APP() in ringsocket_app.h for explanation
#define RS_INLINE_PROTOTYPES_RING \
extern inline rs_ret rs_prepare_ring_write(struct rs_thread_pair * pair, \
    struct rs_ring * ring, uint32_t msg_size); \
extern inline struct rs_ring_msg * rs_get_ring_msg(struct rs_thread_pair *, \
    uint8_t const *); \
extern inline rs_ret rs_wake_up_app(struct rs_thread_sleep_state *); \
extern inline rs_ret rs_wake_up_worker(struct rs_thread_sleep_state *, int); \
extern inline rs_ret rs_wait_for_worker(struct rs_thread_sleep_state *, \
    uint64_t); \
extern inline rs_ret rs_enqueue_ring_update(struct rs_ring_update_queue *, \
    struct rs_thread_io_pairs *, struct rs_thread_sleep_state *, int const *, \
    uint8_t const *, size_t, bool); \
extern inline rs_ret rs_flush_ring_updates(struct rs_ring_update_queue *, \
    struct rs_thread_io_pairs *, struct rs_thread_sleep_state *, int const *, \
    size_t)
