// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

// The RS public API consists only of everything that is defined directly in
// this header file.

#define _POSIX_C_SOURCE 201112L // CLOCK_MONOTONIC_COARSE

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

// C11 language features
#include <stdalign.h> // alignas, aligned_alloc() 
#include <stdatomic.h> // atomic_uintptr_t, atomic_load/store_explicit()
#include <threads.h> // thread stuff

// The following headers are used internally -- not part of the RS public API
#include <ringsocket_variadic.h>
#include <ringsocket_util.h>

typedef struct rs rs_t;

// The following macros are included here instead of rs_util.h because they
// may be of use to apps -- hence part of the RS public API

#define RS_ELEM_C(arr) (sizeof(arr) / sizeof((arr)[0]))

#define RS_MIN(a, b) ((a) < (b) ? (a) : (b))
#define RS_MAX(a, b) ((a) > (b) ? (a) : (b))

#define RS_CONST_STRLEN(const_str) (sizeof(const_str) - 1)

#define RS_STRINGIFIED(str) #str
#define RS_STRINGIFY(str) RS_STRINGIFIED(str)

#define RS_IS_LITTLE_ENDIAN (*((uint8_t *) (uint32_t []){1}))
#define RS_NTOH16(h16) (RS_IS_LITTLE_ENDIAN ? \
    __builtin_bswap16(h16) : (h16))
#define RS_NTOH32(h32) (RS_IS_LITTLE_ENDIAN ? \
    __builtin_bswap32(h32) : (h32))
#define RS_NTOH64(h64) (RS_IS_LITTLE_ENDIAN ? \
    __builtin_bswap64(h64) : (h64))
#define RS_HTON16(n16) RS_NTOH16(n16)
#define RS_HTON32(n32) RS_NTOH32(n32)
#define RS_HTON64(n64) RS_NTOH64(n64)
#define RS_R_NTOH16(ptr) RS_NTOH16(*((uint16_t *) (ptr)))
#define RS_R_NTOH32(ptr) RS_NTOH32(*((uint32_t *) (ptr)))
#define RS_R_NTOH64(ptr) RS_NTOH64(*((uint64_t *) (ptr)))
#define RS_W_HTON16(ptr, uint16) *((uint16_t *) (ptr)) = RS_HTON16(uint16)
#define RS_W_HTON32(ptr, uint32) *((uint32_t *) (ptr)) = RS_HTON32(uint32)
#define RS_W_HTON64(ptr, uint64) *((uint64_t *) (ptr)) = RS_HTON64(uint64)

// Wrap syslog() in order to prepend source file name and line number.
// 1st arg: log level
// 2nd arg: format string
// 3rd arg etc: any parameters corresponding to the format string
#define RS_LOG(...) _RS_LOG(__VA_ARGS__) // Defined in rs_util.h

// Same as RS_LOG, except that it also appends strerror(errno)
#define RS_LOG_ERRNO(...) _RS_LOG_ERRNO(__VA_ARGS__) // See rs_util.h

// Same as RS_LOG, except that the 3rd arg is expected to be a non-
// 0-terminated (str) buffer, of which the size is expected to be the 4th arg.
#define RS_LOG_CHBUF(lvl, fmt, chbuf, ...) _RS_LOG_CHBUF(lvl, fmt, chbuf, \
    __VA_ARGS__) // See rs_util.h

// The following headers are used internally -- not part of the RingSocket API
#include <ringsocket_conf.h>
#include <ringsocket_peer.h>
#include <ringsocket_ring.h>
#include <ringsocket_app.h>

// Expanded in ringsocket_app.h
#define RS_APP(init_macro, open_macro, read_macro, close_macro, timer_macro) \
    _RS_APP(init_macro, open_macro, read_macro, close_macro, timer_macro)
