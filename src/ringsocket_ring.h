// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <ringsocket_conf.h>
// <ringsocket_variadic.h>           # Arity-based macro expansion helper macros
//   |
//   \---> <ringsocket_api.h>                            # RingSocket's core API
//                        |
// <ringsocket_conf.h> <--/   # Definition of struct rs_conf and its descendents
//   |
//   |       [YOU ARE HERE]
//   \---> <ringsocket_ring.h> # Single producer single consumer ring buffer API
//                         |
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

#include <stdbool.h> // bool

// RingSocket's atomic interface to its single producer single consumer ring
// buffers, as shared between its threads.
struct rs_ring_atomic { // C11 atomic types with C11 alignas
    // Atomic pointer to where the producing thread will write new data next,
    // which is interpreted by the consuming thread to mean that it can safely
    // read all ring buffer bytes up to (but not through) w.
    alignas(RS_CACHE_LINE_SIZE) atomic_uintptr_t w;

    // Atomic pointer to where the consuming thread will read data next,
    // which is interpreted by the producing thread to mean that it can safely
    // write new data to the ring buffer up to (but not through) r.
    alignas(RS_CACHE_LINE_SIZE) atomic_uintptr_t r;
};

// Every worker thread <-> app thread pair shares a single unique instance of
// this rs_ring_pair struct through which all their communication takes place.
struct rs_ring_pair {
    struct rs_ring_atomic inbound_ring; // producing worker --> consuming app
    struct rs_ring_atomic outbound_ring; // producing app --> consuming worker
};

// RingSocket's producer-only interface to a RingSocket ring buffer: not shared
// with the thread at the consumer side.
struct rs_ring_producer {
    // The start of the current heap-allocated ring buffer, as produced by the
    // producer thread managing an instance of this struct.
    uint8_t * ring;

    // This pointer has the same semantics as the shared "w" of struct
    // rs_ring_atomic, except that this "w" contains the actual real-time
    // up-to-date write poiner, whereas the "w" of rs_ring_atomic will generally
    // be a slightly delayed version thereof.
    //
    // Why? Well, RingSocket loads and stores the atomic pointers in struct
    // rs_ring_atomic with memory_order_relaxed for max speed without any locks
    // or fences. To nonetheless guard itself against CPU memory reordering,
    // RingSocket briefly queues ring buffer read and write updates before
    // publicizing them in struct rs_ring_atomic: see ringsocket_queue.h.
    uint8_t * w;

    // In the event that the write pointer "w" speeds ahead of the consumer
    // thread's read pointer "r" by a "whole ring buffer lap", the ring buffer
    // is considered to be "full" (because carrying on obliviously would expose
    // the consumer thread to erroneous overwrites of yet to be read data).
    //
    // When that happens, the ring producer allocates a larger new ring buffer
    // to which it writes any excess new data. However, it can only free() the
    // old ring buffer once it knows that the consumer too has transitioned to
    // the new ring buffer (see rs_produce_ring_msg()). A reference to the old
    // buffer is kept as a "prev_ring" member until that time to free() arrives.
    uint8_t * prev_ring;

    // The size in bytes of the current heap-allocated ring buffer
    size_t ring_size;
};

// RingSocket's consumer-only interface to a RingSocket ring buffer: not shared
// with the thread at the producer side.
struct rs_ring_consumer {
    // From a utilitarian point of view, defining a struct with only one member
    // may seem dumb. Here it's done anyway to clarify the separation of
    // concerns between the ring buffer producer and ring buffer consumer: the
    // producer is responsible for all buffer management, while the consumer
    // just needs to "follow the trail" and update its "r" along the way.

    // This pointer has the same semantics as the shared "r" of struct
    // rs_ring_atomic, except that this "r" contains the actual real-time
    // up-to-date read poiner, whereas the "r" of rs_ring_atomic will generally
    // be a slightly delayed version thereof -- for the same reasons as
    // mentioned in struct rs_ring_producer.

    // Regarding const-ness: RingSocket consumers never directly alter any ring
    // buffer contents, as doing so would often lead to unneccessary false
    // sharing with the producer thread on the other end.
    uint8_t const * r;
};

// rs_consume_ring_msg() casts any ring buffer message pointer it returns to
// this struct to clarify the message format to the caller.
struct rs_consumer_msg {
    uint32_t const size; // The size of msg in bytes.
    uint8_t const msg[]; // const: see comment in struct rs_ring_consumer above
};

// Every ring message is preceded by an uint32_t holding its size in bytes
#define RS_RING_HEAD_SIZE sizeof(struct rs_consumer_msg) // AKA 4

// Every ring message must reserve the following size as a tail beyond the
// message itself; to allow a route instruction to be inserted upon the
// next ring write attempt, in the event that there is insufficient space inside
// the current ring buffer to append the next message contiguously.
//
// A route instruction is one uint32_t with a value of 0 (where the size
// uint32_t would be if the next message was appended contiguously), followed by
// a uint8_t pointer to the start of a new producer-allocated ring buffer.
#define RS_RING_ROUTE_SIZE (RS_RING_HEAD_SIZE + sizeof(uint8_t *))

#ifdef RS_INCLUDE_PRODUCE_RING_MSG
static inline bool rs_would_clobber(
    uint8_t const * unwritable,
    uint8_t const * w,
    uint32_t msg_size
) {
    return w + RS_RING_HEAD_SIZE + msg_size + RS_RING_ROUTE_SIZE > unwritable;
}

// Ensure that the calling producer thread can safely write msg_size message
// bytes to prod->w if RS_OK is returned. This will update the members of
// the prod instance where necessary in order to make said guarantee.
//
// This function will also take care of writing the uint32_t msg_size to the
// ring buffer (becoming the .size member of struct rs_consumer_msg),
// and incrementing prod->w by 4 bytes before returning. After returning, it's
// the caller's responsibility to increment prod->w by msg_size prior to calling
// rs_enqueue_ring_update() (see ringsocket_queue.h).
static inline rs_ret rs_produce_ring_msg(
    struct rs_ring_atomic const * atomic,
    struct rs_ring_producer * prod,
    double alloc_multiplier, // If allocated, how big should a new ring buf be?
    uint32_t msg_size
) {
    uint8_t const * r = NULL;
    RS_CASTED_ATOMIC_LOAD_RELAXED(&atomic->r, r, (uint8_t const *));
    if (r >= prod->ring && r < prod->ring + prod->ring_size) {
        // r and w are currently both within bounds of the same prod->ring.
        if (prod->prev_ring) {
            // This means any previously used ring buffer can be free()d now.
            RS_LOG(LOG_NOTICE, "Free()ing previous ring buffer at %p",
                prod->prev_ring);
            RS_FREE(prod->prev_ring);
        }
        if (prod->w < r) {
            // The w position has wrapped from the end of the ring back to the
            // front, while r has not reached the end of the same ring yet.
            if (rs_would_clobber(r, prod->w, msg_size)) {
                // prod->ring is "full": writing the msg as-is would clobber r.
                goto route_to_new_ring;
            }
        } else if (rs_would_clobber(prod->ring + prod->ring_size, prod->w,
            msg_size)) {
            // Writing the message as-is would mean overshooting the end of the
            // ring buffer: try to wrap the whole message around to the start
            // of the ring buffer instead.
            if (rs_would_clobber(r, prod->ring, msg_size)) {
                // Can't wrap the message to the start of the ring buffer
                // either: doing so would clobber r.
                route_to_new_ring: // Allocate a new larger ring buffer instead.
                // Hold on to the existing buffer as prev_ring, until the
                // producer thread has verified that the reader has reached the
                // new buffer.
                prod->prev_ring = prod->ring;
                prod->ring = NULL;
                prod->ring_size *= alloc_multiplier;
                // Use RS_CACHE_ALIGNED_CALLOC() to eliminate possibility of
                // false sharing with preceding or trailing heap bytes.
                RS_CACHE_ALIGNED_CALLOC(prod->ring, prod->ring_size);
                RS_LOG(LOG_NOTICE, "Allocated a new %zu byte ring buffer at %p",
                    prod->ring_size, prod->ring);
            } else {
                RS_LOG(LOG_DEBUG, "Insufficient ring buffer tail space: "
                    "wrapping message around to the start of the buffer at %p",
                    prod->ring);
            }
            // Write a "route instruction": a value of 0 instead of msg_size,
            // to tell the consumer thread that the bytes following it should be
            // interpreted as a pointer to the next ring buffer location.
            *((uint32_t *) prod->w) = 0;
            prod->w += sizeof(struct rs_consumer_msg); // += 4
            // Set either a pointer to the start of the same ring to indicate
            // wrapping, or a pointer to a new ring buffer (route_to_new_ring).
            *((uint8_t * *) prod->w) = prod->ring;
            prod->w = prod->ring;
        }
    } else if (rs_would_clobber(prod->ring + prod->ring_size, prod->w,
        msg_size)) {
        // Even though w has already filled up the entire prod->ring, r is still
        // on prod->prev_ring: consider this lagging by r excessive, and abort.
        RS_LOG(LOG_CRIT, "FATAL CONDITION: Producer and consumer are further "
            "out of sync than the entire ring buffer size %zu between them.",
            prod->ring_size);
        return RS_FATAL;
    }
    *((uint32_t *) prod->w) = msg_size;
    prod->w += sizeof(struct rs_consumer_msg); // += 4
    // Note that the message itself has not been writtin yet. Instead, this
    // function returns RS_OK to indicate that the calling producer thread can
    // now safely write msg_size message bytes starting from prod->w. 
    return RS_OK;
}
#endif

// Obtain a consumer_msg pointer from a ring consumer interface and increment
// cons->r by that message's size, or return NULL if no new message exists yet.
#ifdef RS_INCLUDE_CONSUME_RING_MSG
static inline struct rs_consumer_msg * rs_consume_ring_msg(
    struct rs_ring_atomic const * atomic,
    struct rs_ring_consumer * cons
) {
    uint8_t * w = NULL;
    RS_CASTED_ATOMIC_LOAD_RELAXED(&atomic->w, w, (uint8_t *));
    if (cons->r == w) {
        // The consumer has already caught up with the producer (i.e., the
        // producer hasn't publicized any new message yet).
        return NULL;
    }
    struct rs_consumer_msg * cmsg = (struct rs_consumer_msg *) cons->r;
    if (!cmsg->size) {
        // This is a "route instruction" (see rs_produce_ring_msg()): a value of
        // 0 means the message was too large to be appended at the current
        // location. Instead, a pointer to its actual location should be
        // retrieved from the current location.
        cons->r = *((uint8_t const * *) &cmsg->msg);
        RS_LOG(LOG_DEBUG, "Consuming ring message from non-contiguous ring "
            "buffer location %p", cons->r);
        cmsg = (struct rs_consumer_msg *) cons->r;
    }
    cons->r += sizeof(*cmsg) + cmsg->size;
    return cmsg;
}
#endif
