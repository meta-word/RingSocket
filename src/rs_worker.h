// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include <assert.h> // C11: static_assert()
#include <openssl/ssl.h>

// Including <ringsocket.h> here would include app helper functions contained in
// <ringsocket.h> and <ringsocket_helper.h> that are of no use to worker
// threads. Instead, commence the RingSocket "include chain" "2 steps up" at:
#include <ringsocket_app.h>

// #############################################################################
// # struct rs_worker & Co. ####################################################

// It may seem like the rs_worker_args and rs_worker structs could be replaced
// by a single struct, but their differentation is due to false sharing
// considerations.
//
// Mostly due to the constraints of C11 threading API, rs_worker_args references
// of all worker threads are held by the initial thread (i.e., the last worker
// thread). To prevent false sharing with that thread rs_worker_args only holds
// data that remains constant once workers are spawned; whereas rs_worker only
// exists on each worker thread's stack, and hence is free of such inhibitions.

struct rs_worker_args {
    struct rs_conf const * conf; // See ringsocket_conf.h
    
    // app_c length array of io_pair arrays allocated by each app respectively
    struct rs_ring_pair * * ring_pairs; // See ringsocket_ring.h
    
    // app_c length array of each app's sleep state
    struct rs_sleep_state * app_sleep_states; // See ringsocket_queue.h
    struct rs_sleep_state * sleep_state; // See ringsocket_queue.h
    int eventfd;
    
    size_t worker_i;
};

struct rs_worker {
    // These 6 members remain indentical to the ones in struct rs_worker_args.
    struct rs_conf const * const conf;
    struct rs_ring_pair * * const ring_pairs;
    struct rs_sleep_state * const sleep_state;
    struct rs_sleep_state * const app_sleep_states;
    int const eventfd;
    size_t worker_i;

    struct rs_ring_queue ring_queue; // See ringsocket_queue.h
    struct rs_ring_producer * inbound_producers; // See ringsocket_ring.h

    struct rs_slots { // For rs_slot.[c|h] usage only
        uint8_t * bytes; // Each bit signifies availability of 1 slot
        uint8_t * byte_over; // Pointer out of bounds if >= byte_over
        size_t i; // The lowest slot index that _could_ be empty
    } peer_slots;

    union rs_peer * peers; // See union definition below
    uint32_t peers_elem_c;
    // Prevents looping over the entire array when targeting all connected peers
    uint32_t highest_peer_i;

    uint8_t * rbuf; // Read buffer for read_tcp()/read_tls()

    // These 3 are used exclusively by rs_hash.c for HTTP Upgrade key hashing.
    EVP_MD_CTX * sha1_ctx;
    BIO * base64_bio;
    BUF_MEM * base64_buf;

    SSL_CTX * * tls_ctxs; // Used exclusively by rs_tls.c

    // The remaining members are used exclusively by rs_from_app.c
    struct rs_ring_consumer * outbound_consumers;
    struct rs_owref * owrefs; // See struct definition below
    size_t owrefs_elem_c;
    size_t newest_owref_i;
    size_t * oldest_owref_i_by_app;

    // Defined in ringsocket_wsframe.h. Used by rs_websocket.c to buffer pongs.
    struct rs_wsframe_sc_pong pong_response;

    // Used for OpenSSL's ERR_error_string_n(), and for passing on to RS_LOG().
    char log_buf[400]; // Enough to print a full control frame as hex, etc.
};

// #############################################################################
// # union rs_peer & Co. #######################################################

// The worker threads' array of connected peers may need to be quite long, so
// each peer element should be made as compact as possible to minimize cache
// misses, which is why rs_peer is implemented as follows:
//
// * Member types are as small as they can be proven to be safe (unless
//   alignment requirements allow them extra space that would otherwise lead to
//   padding below that member).
// * Small types are grouped in pairs such that their combined size matches the
//   alignment of their adjacent member recursively, up to 64-bit "blocks".
// * Union usage allows space sharing between variables that have mutually
//   exclusive lifetimes. E.g., HTTP parsing vs WebSocket parsing.
// * A union as member of a top level struct would have a size larger than the
//   maximum simple type size of 8 bytes, leading to unnecessary padding in that
//   top-level struct. Because of that, rs_peer is instead implemented as a
//   top-level union of equally sized structs.
// * Clean namespacing: full-lifetime shared member variables are placed in a
//   C11 anonymous struct to avoid confusion with layer-specific .http and .ws
//   struct members, and vice versa.
// * To prevent member overlap with the shared anonymous struct members, each
//   struct contains an anonymous "phony bit flag" placeholder of the right size
//   and position to achieve the desired alignment.
// * C11 static_assert(sizeof(X) == Y) assertions in rs_worker.c make sure
//   everything is packed by as intended in a standard-compliant way.

union rs_peer {
    // 4 64-bit "blocks" amounting to a total size of only 32 bytes
    // (static_assert(sizeof(union rs_peer) == 32) checked in rs_worker.c.)

    // Anonymous struct containing members that are valid regardless of .layer.
    struct {
        // 1st 64-bit block
        struct {
            uint8_t is_encrypted: 1; // Is this peer talking through TLS? 
            uint8_t is_writing: 1; // Will the next IO direction be a write()?
            uint8_t layer: 2; // See enum rs_layer below
            uint8_t mortality: 2; // See enum rs_mortality below
            uint8_t continuation: 2; // See enum rs_continuation below
        };
        uint8_t app_i;
        uint16_t endpoint_i;
        int socket_fd; // static_assert(sizeof(int) == 4) checked in rs_worker.c
        // 2nd (max-)64-bit block
        union {
            // Applicable if .is_encrypted is true: OpenSSL session pointer.
            SSL * tls;

            // Applicable if .is_encrypted is false: write() needs this offset
            // added to the original message pointer when resuming write()s in
            // order to match OpenSSL's SSL_write(_ex)() behavior which wants to
            // received the same message pointer on write resumptions (and
            // therefore tracks this offset internally in its session SSL data).
            size_t old_wsize;
        };
        // 3rd and 4th 64-bit blocks
        uint16_t shutdown_deadline;
        uint8_t layer_specific_data[14]; // Allow memset()ting layer data to 0.
    };

    // Applicable if .layer == RS_LAYER_HTTP
    struct {
        // 1st and 2nd 64-bit blocks
        uint64_t:64; uint64_t:64; // Pad past the anonymous shared struct above.
        
        // 3rd 64-bit block
        uint16_t:16; // Pad past .shutdown_deadline of the shared struct above;
        struct {
            uint8_t hostname_was_parsed: 1;
            uint8_t origin_was_parsed: 1;
            uint8_t upgrade_was_parsed: 1;
            uint8_t wskey_was_parsed: 1;
            uint8_t wsversion_was_parsed: 1;
            uint8_t error_i: 3;
        };
        uint8_t jump_distance; 
        uint16_t partial_strlen;
        uint16_t origin_i;

        // 4th (max-)64-bit block
        char * char_buf;
    } http;

    // Applicable if .layer == RS_LAYER_WEBSOCKET
    struct {
        // 1st and 2nd 64-bit blocks
        uint64_t:64; uint64_t:64; // Pad past the anonymous shared struct above.

        // 3rd  64-bit block
        uint16_t:16; // Pad past .shutdown_deadline of the shared struct above;
        // owref: "Outbound Write REFerence" (see struct rs_owref below)
        uint16_t owref_c; // Pending outbound write count (see rs_from_app.c)
        uint32_t owref_i; // This peer's lowest index among worker->owrefs

        // 4th (max-)64-bit block
        union {
            // Applicable if .mortality == RS_MORTALITY_LIVE &&
            //            .continuation == RS_CONT_PARSING
            struct rs_wsframe_parser_storage * storage; // See rs_websocket.c.

            // Applicable if .mortality == RS_MORTALITY_LIVE &&
            //            .continuation == RS_CONT_SENDING
            struct rs_wsframe_sc_small * pong_response; // See rs_websocket.c.
            
            // Applicable if .mortality == RS_MORTALITY_SHUTDOWN_WRITE &&
            //            .continuation == RS_CONT_SENDING
            // Control frame sent in response to a WebSocket parser condition
            int close_frame; // See rs_websocket.c
        };
    } ws;
};

// Marks the highest layer on which the peer is currently active
enum rs_layer {
    RS_LAYER_TCP = 0,
    RS_LAYER_TLS = 1,
    RS_LAYER_HTTP = 2,
    RS_LAYER_WEBSOCKET = 3
};

enum rs_mortality {
    // The connection is healthy and full-duplex
    RS_MORTALITY_LIVE = 0,

    // Sending bi-directional shutdown data to the peer
    RS_MORTALITY_SHUTDOWN_WRITE = 1,

    // Awaiting bi-directional shutdown response data from the peer
    RS_MORTALITY_SHUTDOWN_READ = 2,

    // Finalizing peer closure and freeing up all peer-specific data
    RS_MORTALITY_DEAD = 3
};

enum rs_continuation {
    RS_CONT_NONE = 0, // No unfinished parse or write operations remaining
    RS_CONT_PARSING = 1, // RS_AGAIN occurred during parsing
    RS_CONT_SENDING = 2 // RS_AGAIN occured during sending
};

// Each WebSocket message received on an outbound ring buffer from an app can be
// destined for any number of recipients. struct rs_owref ("Outbound Write
// Reference") keeps track of peer recipients for which said message has not
// been (fully) sent yet. (Only applicable when peer layer == LAYER_WEBSOCKET.)
struct rs_owref {
    struct rs_consumer_msg * cmsg;
    uint32_t remaining_recipient_c;
    uint16_t head_size;
    uint16_t app_i;
};

// rs_worker.c prototypes

int work(
    struct rs_worker_args const * worker_args
);

rs_ret enqueue_ring_update(
    struct rs_worker * worker,
    uint8_t * new_ring_position,
    size_t app_thread_i,
    bool is_write
);

rs_ret flush_ring_updates(
    struct rs_worker * worker
);
