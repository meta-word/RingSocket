// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket_ring.h>
// <ringsocket_variadic.h>           # Arity-based macro expansion helper macros
//   |
//   \---> <ringsocket_api.h>                            # RingSocket's core API
//                        |
// <ringsocket_conf.h> <--/   # Definition of struct rs_conf and its descendents
//   |
//   \---> <ringsocket_ring.h> # Single producer single consumer ring buffer API
//                         |
//    [YOU ARE HERE]       |
// <ringsocket_queue.h> <--/      # Ring buffer update queuing and thread waking
//   |
//   \-------> <ringsocket_app.h> # Definition of RS_APP() and descendent macros
//                          | |
//                          | |
//                          | \--> [ Worker translation units: see rs_worker.h ]
//                          |
//                          |
// <ringsocket_helper.h> <--/   # Definitions of app helper functions (internal)
//   |
//   \--> <ringsocket.h>             # Definitions of app helper functions (API)
//                   |
//                   |
//                   \----------------> [ Any RingSocket app translation units ]

#define _GNU_SOURCE // syscall()
#include <inttypes.h> // PRI print format of stdint.h types
#include <linux/futex.h> // FUTEX_WAKE_PRIVATE
#include <sys/syscall.h> // SYS_futex
#include <unistd.h> // syscall()

// If you're new to RingSocket, check ringsocket_ring.h before reading all this.
//
// Ring buffer producers and consumers communicate their write and read pointer
// updates respectively through C11 atomic loads and stores of C11
// atomic_uintptr_t types with memory_order_relaxed; which is the fastest way to
// use atomics, because it lacks any of the safeguards against memory reordering
// that other memory_order directives provide at the expense of a non-trivial
// number of clock cycles.
//
// Lacking these safeguards, RingSocket must take it upon itself to account for
// the two kinds of memory reordering that may occur in the wild:
// memory reordering by the compiler, and memory reordering by the CPU core.
// Compiler memory reordering on the one hand is trivially protected against by
// sandwiching atomic loads and stores between __asm__ memory directives:
// see RS_PREVENT_COMPILER_REORDERING in ringsocket_api.h. Dealing with CPU
// memory reordering on the other hand, is a little more involved.
//
// RingSocket implements a means of guarding against CPU memory reordering that
// minimizes the effect on each thread's overall processing processing speed:
// rather than immediately sharing ring buffer updates with the other thread by
// directly updating an rs_ring_atomic struct instance (see ringsocket_ring.h),
// it instead enqueues a reference to the update in a small fixed (but
// configurable) size per-thread FIFO: see struct rs_ring_queue below.
// E.g., if one such queue has a size of 5, any ring buffer update will be
// dequeued after 5 other ring buffer updates are enqueued to that same queue
// (including updates to different ring buffers that thread interacts with);
// with the dequeue operation being the procedure that actually propagates the
// ring buffer update to the corresponding atomic variable. In other words, each
// ring buffer update is delayed a length of time proportional to the length of
// the queue with the intent of making that interval larger than the maximum
// procedural incongruity that may arise from CPU memory reordering. The benefit
// of this approach is that while individual ring buffer updates are delayed,
// none of the threads themselves experience any slowdown at all.
//
// The minimum safe queue length depends on CPU architecture and the nature of
// CPU instructions performed in between each atomic load/store, and are best
// tested empirically (see rs_test_ring.c in the "tests" directory).
// RingSocket's default settings err on the side of caution in that regard.
// 
// Furthermore, to ensure that no ring buffer update remains unnoticed to a
// dormant thread, calls to epoll_wait() and futex_wait() are doubled: first
// they are called with a timeout of 0, then all pending updates are flushed
// (which is safe against CPU memory reordering due to these operations being
// performed on "the other side" of the systemcalls involved in epol_wait()
// and futex_wait()), and then finally they are called a 2nd time with the
// timeout actually intended (if any).

struct rs_sleep_state { // Indicates whether or not a certain thread is dormant.
    // is_asleep is a boolean flag, but implemented as an atomic uint32_t for
    // compatibility with futex syscalls -- as needed by app_sleep_state.
    alignas(RS_CACHE_LINE_SIZE) atomic_uint_least32_t is_asleep; // boolean
};

struct rs_ring_update {
    uint8_t * ring_position;
    uint32_t thread_i;
    bool is_write;
};

struct rs_ring_queue {
    struct rs_ring_update * updates;
    size_t size;
    size_t oldest_i;
};

#ifdef RS_INCLUDE_QUEUE_FUNCTIONS

static inline rs_ret rs_wake_up_app(
    struct rs_sleep_state * app_sleep_state,
    uint32_t app_i
) {
    bool app_is_asleep = false;
    RS_ATOMIC_LOAD_RELAXED(&app_sleep_state->is_asleep, app_is_asleep);
    if (app_is_asleep) {
        RS_ATOMIC_STORE_RELAXED(&app_sleep_state->is_asleep, false);
        if (syscall(SYS_futex, &app_sleep_state->is_asleep, FUTEX_WAKE_PRIVATE,
            1, NULL, NULL, 0) == -1) {
            RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful syscall(SYS_futex, %d, "
                "FUTEX_WAKE_PRIVATE, ...) for app_i %" PRIu32,
                app_sleep_state->is_asleep, app_i);
            return RS_FATAL;
        }
        RS_LOG(LOG_DEBUG, "Called syscall(SYS_futex, %d, FUTEX_WAKE_PRIVATE, "
            "...) for app_i %" PRIu32, app_sleep_state->is_asleep, app_i);
    } else {
        RS_LOG(LOG_DEBUG, "Not making a FUTEX_WAKE_PRIVATE syscall() for "
            "app_i %" PRIu32 ", because app_is_asleep seem to be false", app_i);
    }
    return RS_OK;
}

static inline rs_ret rs_wake_up_worker(
    struct rs_sleep_state * worker_sleep_state,
    int worker_eventfd,
    uint32_t worker_i
) {
    bool worker_is_asleep = false;
    RS_ATOMIC_LOAD_RELAXED(&worker_sleep_state->is_asleep, worker_is_asleep);
    if (worker_is_asleep) {
        RS_ATOMIC_STORE_RELAXED(&worker_sleep_state->is_asleep, false);
        if (write(worker_eventfd, (uint64_t []){1}, 8) != 8) {
            RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful write(worker_eventfd, ...) to "
                "worker #%" PRIu32, worker_i + 1);
            return RS_FATAL;
        }
        RS_LOG(LOG_DEBUG, "Successful write(worker_eventfd, ...) to worker #%"
            PRIu32, worker_i + 1);
    } else {
        RS_LOG(LOG_DEBUG, "Not calling write(worker_eventfd, ...) for worker #%"
            PRIu32 ", because worker_is_asleep seems to be false",
            worker_i + 1);
    }
    return RS_OK;
}

static inline rs_ret rs_enqueue_ring_update(
    struct rs_ring_queue * queue,
    struct rs_ring_pair * ring_pairs,
    struct rs_sleep_state * sleep_states,
    int const * eventfds,
    uint8_t * new_ring_position,
    size_t thread_i,
    bool is_write
) {
    struct rs_ring_update * update = queue->updates + queue->oldest_i++;
    queue->oldest_i %= queue->size;
    // If an update exists at the oldest index, carry out dequeue procedures.
    if (update->ring_position) {
        if (eventfds) { // This function was called by an app thread.
            if (update->is_write) {
                RS_ATOMIC_STORE_RELAXED(
                    &ring_pairs[update->thread_i].outbound_ring.w,
                    (atomic_uintptr_t) update->ring_position
                );
                RS_GUARD(rs_wake_up_worker(sleep_states + update->thread_i,
                    eventfds[update->thread_i], update->thread_i));
            } else {
                RS_ATOMIC_STORE_RELAXED(
                    &ring_pairs[update->thread_i].inbound_ring.r,
                    (atomic_uintptr_t) update->ring_position
                );
            }
        } else { // This function was called by a worker thread.
            if (update->is_write) {
                RS_ATOMIC_STORE_RELAXED(
                    &ring_pairs[update->thread_i].inbound_ring.w,
                    (atomic_uintptr_t) update->ring_position
                );
                RS_GUARD(rs_wake_up_app(sleep_states + update->thread_i,
                    update->thread_i));
            } else {
                RS_ATOMIC_STORE_RELAXED(
                    &ring_pairs[update->thread_i].outbound_ring.r,
                    (atomic_uintptr_t) update->ring_position
                );
            }
        }
    }
    // Enqueue the new update at the oldest index, which is now the newest index
    update->ring_position = new_ring_position;
    update->thread_i = thread_i;
    update->is_write = is_write;
    return RS_OK;
}

static inline rs_ret rs_flush_ring_updates(
    struct rs_ring_queue * queue,
    struct rs_ring_pair * ring_pairs,
    struct rs_sleep_state * sleep_states,
    int const * eventfds,
    size_t dest_thread_c
) {
    size_t const newest_i = (queue->oldest_i + queue->size - 1) % queue->size;
    //RS_LOG(LOG_DEBUG, "oldest_i: %zu", queue->oldest_i);
    //RS_LOG(LOG_DEBUG, "newest_i: %zu", newest_i);
    for (size_t i = 0; i < dest_thread_c; i++) {
        bool updated_to_newer_r = false;
        bool updated_to_newer_w = false;
        size_t j = newest_i; 
        do {
            struct rs_ring_update * update = queue->updates + j;
            //RS_LOG(LOG_DEBUG, "rq->queue[%zu]: .ring_position: %p, "
            //    ".thread_i: %" PRIu32 ", .is_write: %d "
            //    "(updated_to_newer_r: %d, updated_to_newer_w: %d)",
            //    j, update->ring_position, update->thread_i, update->is_write,
            //    updated_to_newer_r, updated_to_newer_w);
            if (update->ring_position && update->thread_i == i) {
                if (eventfds) { // This function was called by an app thread.
                    if (update->is_write) {
                        if (!updated_to_newer_w) {
                            RS_ATOMIC_STORE_RELAXED(
                                &ring_pairs[update->thread_i].outbound_ring.w,
                                (atomic_uintptr_t) update->ring_position
                            );
                            RS_GUARD(rs_wake_up_worker(sleep_states +
                                update->thread_i, eventfds[update->thread_i],
                                update->thread_i));
                            updated_to_newer_w = true;
                        }
                    } else if (!updated_to_newer_r) {
                        RS_ATOMIC_STORE_RELAXED(
                            &ring_pairs[update->thread_i].inbound_ring.r,
                            (atomic_uintptr_t) update->ring_position
                        );
                        updated_to_newer_r = true;
                    }
                } else { // This function was called by a worker thread.
                    if (update->is_write) {
                        if (!updated_to_newer_w) {
                            RS_ATOMIC_STORE_RELAXED(
                                &ring_pairs[update->thread_i].inbound_ring.w,
                                (atomic_uintptr_t) update->ring_position
                            );
                            RS_GUARD(rs_wake_up_app(sleep_states +
                                update->thread_i, update->thread_i));
                            updated_to_newer_w = true;
                        }
                    } else if (!updated_to_newer_r) {
                        RS_ATOMIC_STORE_RELAXED(
                            &ring_pairs[update->thread_i].outbound_ring.r,
                            (atomic_uintptr_t) update->ring_position
                        );
                        updated_to_newer_r = true;
                    }
                }
                update->ring_position = NULL;
                update->thread_i = 0;
                update->is_write = false;
            }
            j += queue->size - 1;
            j %= queue->size;
        } while (j != newest_i);
    }
    return RS_OK;
}

#endif
