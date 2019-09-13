# RingSocket

RingSocket is a highly scalable WebSocket server for Linux written in C (C11)
featuring:

* A modular server app API facilitating fully self-contained runtime-pluggable
  backend apps
* A completely lockless multi-threaded design consisting of worker threads,
  app threads, and ring buffers
* A fully event-based architecture: epoll-based event loops for workers, and
  futex-based loops for apps
* 100% compliance with the
  [WebSocket standard](https://tools.ietf.org/html/rfc6455)
* Extensive configuration/customization from a single intuitive
  `ringsocket.json` file
* The ability to simultaneously listen on any number of ports/interfaces, each
  of which can be configured individually; e.g., to either accept only
  TLS-encrypted `wss://` traffic or only plaintext `ws://` traffic
* Adoption of fast new Linux kernel APIs for optimal throughput
* Principled coding practices designed to guard against the occurrence of
  security-related problems 

Planned features include app language ports: write server apps in languages
other than C such as Python, to be embedded directly into the server app's
shared object at compile time.

## Table of contents

* [Installation](#installation)
* [Creating RingSocket server apps](#creating-ringsocket-server-apps)
  * [RS_APP](#rs_appm1-m2-m3-m4-m5)
  * [App callback return values](#app-callback-return-values)
  * [App helper functions](#app-helper-functions)
* [Configuration](#configuration)
  * [Global configuration](#global-configuration)
  * [Port configuration](#port-configuration)
  * [TLS certificate configuration](#tls-certificate-configuration)
  * [App configuration](#app-configuration)
  * [Endpoint configuration](#endpoint-configuration)
* [Control flow overview](#control-flow-overview)
  * [Startup](#startup)
  * [Worker threads](#worker-threads)
  * [App threads](#app-threads)
* [Todo](#todo)
* [Contributing](#contributing)
* [Email me](#email-me)

## Installation

Aside from needing a fairly recent Linux kernel and C compiler, RingSocket has
only 2 external dependencies: OpenSSL and
[Jgrandson](https://github.com/wbudd/jgrandson/blob/master/src/jgrandson.h).
Make sure these are installed first, then proceed with something like this:

    git clone https://github.com/wbudd/ringsocket.git
    cd ringsocket
    make
    sudo make install

Note that if not already present, `make install` will attempt to create an
unprivileged system user named `ringsock` (if not already present), for
exclusive use by the RingSocket daemon.

## Creating RingSocket server apps

A RingSocket server app is a C library containing the variadic macro `RS_APP`.
Provided that it's compiled as a shared object (e.g.,
`gcc [other flags] -fpic -shared -o foo.so`—⁠see for example [this Makefile](https://github.com/wbudd/realitree/blob/master/realitree_ringsocket/Makefile))
and the path to this `.so` file is specified in `ringsocket.json`
(see [Configuration](#configuration)), the RingSocket executable will
dynamically load the app with `dlopen()` and run that app's event loop as
embedded by the `RS_APP` macro in its own dedicated thread. A lot of things are
taken care of under the hood, which means app authors get a lot of functionality
with very few lines of code, as the following silly self-contained example
demonstrates:
```C
#include <ringsocket.h> // The only header that RingSocket apps must include
#include <uchar.h> // Allow C11 unicode string literals (u8"笑笑?")

int silly_calc(rs_t * rs, int32_t i32, uint16_t * arr, size_t elem_c) {
    // Whenever a read callback is called, RingSocket has already checked that
    // the corresponding WebSocket message buffer correctly contains all sizes
    // and elements of all parameters. Furthermore, wherever RS_NTOH[_...]
    // macros are used in RS_APP, the corresponding integers are also
    // automatically converted from network byte order to host byte order.

    // Calculate the sum of all received integers as an int64_t
    int64_t i64 = i32;
    // The RS_NTOH_VLA(uint16_t, 1, 10) given below ensures that 0 < elem_c < 11
    for (size_t i = 0; i < elem_c; i++) {
        i64 += u16_arr[i];
    }

    // Send the result to every WebSocket client with a live connection to this
    // app, except for the client that made this silly_calc() request.
    rs_w_int64_hton(rs, i64); // ..._hton(): convert host to network byte order
    rs_to_every_except_cur(rs, RS_BIN); // RS_BIN: send a Binary Mode WS message

    // Reply to the client who made this request with "笑笑?" (don't ask me why)
    rs_w_str(rs, u8"笑笑");
    rs_w_uint8(rs, 0x3F); // '?' (just to show that these calls can be chained)
    rs_to_cur(rs, RS_UTF8); // RS_UTF8: send a Text Mode WebSocket message

    return 0; // Success: see "App callback return values" below
}

RS_APP( // See "RS_APP(m1, m2, m3, m4, m5)" reference below
    RS_INIT_NONE, // Omit callback during RingSocket startup
    RS_OPEN_NONE, // Omit callback for WebSocket client connection establishment
    RS_READ_BIN(silly_calc, RS_NTOH(int32_t), RS_NTOH_VLA(uint16_t, 1, 10)),
    RS_CLOSE_NONE, // Omit callback for WebSocket client disconnection events
    RS_TIMER_NONE // Omit timed interval callback
);

```
If that example is a bit much at once, keep on reading for brief references to
the [RS_APP](#rs_appm1-m2-m3-m4-m5) macro and its descendent macro arguments,
[App callback return values](#app-callback-return-values), and
[App helper functions](#app-helper-functions).

### RS_APP(*m1*, *m2*, *m3*, *m4*, *m5*)

Must be invoked exactly once at file scope with exactly 5 macro arguments, in the following order:
1. Either [`RS_INIT(init_cb)`](#rs_initinit_cb) or `RS_INIT_NONE`
1. Either [`RS_OPEN(open_cb)`](#rs_openopen_cb) or `RS_OPEN_NONE`
1. One of [`RS_READ_BIN(read_cb[, ...])`](#rs_read_binread_cb-read_m1-read_m2-), [`RS_READ_UTF8(read_cb[, ...])`](#rs_read_utf8read_cb-read_m1-read_m2-), or [`RS_READ_SWITCH(case_m1[, ...])`](#rs_read_switchcase_m1-case_m2-)
1. Either [`RS_CLOSE(close_cb)`](#rs_closeclose_cb) or `RS_CLOSE_NONE`
1. One of [`RS_TIMER_SLEEP(microseconds)`](#rs_timer_sleeptimer_cb-microsecondsrs_timer_waketimer_cb-microseconds), [`RS_TIMER_WAKE(microseconds)`](#rs_timer_sleeptimer_cb-microsecondsrs_timer_waketimer_cb-microseconds), or `RS_TIMER_NONE`

##### RS_INIT(*init_cb*)

Declaring `RS_INIT(foo_init)` will cause RingSocket to call an app-provided
`int foo_init(void)` callback function during RingSocket startup. Useful when
your app needs to do some initialization or resource allocation before engaging
in WebSocket IO. See [callback return values](#app-callback-return-values) for
valid return values.

##### RS_OPEN(*open_cb*)

Declaring `RS_OPEN(foo_open)` will cause RingSocket to call an app-provided
`int foo_open(rs_t * rs)` callback function whenever a WebSocket client
completes its HTTP Upgrade handshake with a RingSocket worker thread, thus
becoming available for WebSocket IO.

See [app helper functions](#app-helper-functions) for an overview of things that
can be done with use of the received opaque `rs_t` pointer. For example, if
WebSocket clients of this app always first need to receive some data from the
server in order to get started, such data can be sent immediately from this
callback function—without waiting for the client to make a request for it.

##### RS_READ_BIN(*read_cb*[, *read_m1*[, *read_m2*[, ...]]])

Declaring `RS_READ_BIN(foo_read, macro1, macro2)` will cause RingSocket to call
an app-provided `int foo_read(rs_t * rs, type1 var1, type2 var2)` callback
function whenever a WebSocket message with binary data originating from a
WebSocket client arrives at this app. All arguments other than the callback
argument must be one of the following macro arguments (up to a maximum of 15
macro arguments), which allow RingSocket to determine the type and number of
variables the read callback function expects to receive, as well as to validate
them in advance of calling said function:
* [`RS_NET(type)`](#rs_nettypers_nettype-elem_crs_nettype-min_elem_c-max_elem_c)
* [`RS_NET(type, elem_c)`](#rs_nettypers_nettype-elem_crs_nettype-min_elem_c-max_elem_c)
* [`RS_NET(type, min_elem_c, max_elem_c)`](#rs_nettypers_nettype-elem_crs_nettype-min_elem_c-max_elem_c)
* [`RS_NET_STA(type, min_elem_c, max_elem_c)`](#rs_net_statype-min_elem_c-max_elem_crs_net_vlatype-min_elem_c-max_elem_crs_net_heaptype-min_elem_c-max_elem_crs_ntoh_statype-min_elem_c-max_elem_crs_ntoh_vlatype-min_elem_c-max_elem_crs_ntoh_heaptype-min_elem_c-max_elem_c)
* [`RS_NET_VLA(type, min_elem_c, max_elem_c)`](#rs_net_statype-min_elem_c-max_elem_crs_net_vlatype-min_elem_c-max_elem_crs_net_heaptype-min_elem_c-max_elem_crs_ntoh_statype-min_elem_c-max_elem_crs_ntoh_vlatype-min_elem_c-max_elem_crs_ntoh_heaptype-min_elem_c-max_elem_c)
* [`RS_NET_HEAP(type, min_elem_c, max_elem_c)`](#rs_net_statype-min_elem_c-max_elem_crs_net_vlatype-min_elem_c-max_elem_crs_net_heaptype-min_elem_c-max_elem_crs_ntoh_statype-min_elem_c-max_elem_crs_ntoh_vlatype-min_elem_c-max_elem_crs_ntoh_heaptype-min_elem_c-max_elem_c)
* [`RS_NTOH(type)`](#rs_ntohtypers_ntohtype-elem_crs_ntohtype-min_elem_c-max_elem_c)
* [`RS_NTOH(type, elem_c)`](#rs_ntohtypers_ntohtype-elem_crs_ntohtype-min_elem_c-max_elem_c)
* [`RS_NTOH(type, min_elem_c, max_elem_c)`](#rs_ntohtypers_ntohtype-elem_crs_ntohtype-min_elem_c-max_elem_c)
* [`RS_NTOH_STA(type, min_elem_c, max_elem_c)`](#rs_net_statype-min_elem_c-max_elem_crs_net_vlatype-min_elem_c-max_elem_crs_net_heaptype-min_elem_c-max_elem_crs_ntoh_statype-min_elem_c-max_elem_crs_ntoh_vlatype-min_elem_c-max_elem_crs_ntoh_heaptype-min_elem_c-max_elem_c)
* [`RS_NTOH_VLA(type, min_elem_c, max_elem_c)`](#rs_net_statype-min_elem_c-max_elem_crs_net_vlatype-min_elem_c-max_elem_crs_net_heaptype-min_elem_c-max_elem_crs_ntoh_statype-min_elem_c-max_elem_crs_ntoh_vlatype-min_elem_c-max_elem_crs_ntoh_heaptype-min_elem_c-max_elem_c)
* [`RS_NTOH_HEAP(type, min_elem_c, max_elem_c)`](#rs_net_statype-min_elem_c-max_elem_crs_net_vlatype-min_elem_c-max_elem_crs_net_heaptype-min_elem_c-max_elem_crs_ntoh_statype-min_elem_c-max_elem_crs_ntoh_vlatype-min_elem_c-max_elem_crs_ntoh_heaptype-min_elem_c-max_elem_c)
* [`RS_STR(min_elem_c, max_elem_c)`](#rs_strmin_byte_c-max_byte_crs_str_stamin_byte_c-max_byte_crs_str_vlamin_byte_c-max_byte_crs_str_heapmin_byte_c-max_byte_c)
* [`RS_STR_STA(min_elem_c, max_elem_c)`](#rs_strmin_byte_c-max_byte_crs_str_stamin_byte_c-max_byte_crs_str_vlamin_byte_c-max_byte_crs_str_heapmin_byte_c-max_byte_c)
* [`RS_STR_VLA(min_elem_c, max_elem_c)`](#rs_strmin_byte_c-max_byte_crs_str_stamin_byte_c-max_byte_crs_str_vlamin_byte_c-max_byte_crs_str_heapmin_byte_c-max_byte_c)
* [`RS_STR_HEAP(min_elem_c, max_elem_c)`](#rs_strmin_byte_c-max_byte_crs_str_stamin_byte_c-max_byte_crs_str_vlamin_byte_c-max_byte_crs_str_heapmin_byte_c-max_byte_c)

##### RS_READ_UTF8(*read_cb*[, *read_m1*[, *read_m2*[, ...]]])

Same usage as
[`RS_READ_BIN(read_cb[, ...])`](#rs_read_binread_cb-read_m1-read_m2-),
except that it requires received WebSocket messages to have a payload of type
text (i.e., UTF-8) rather than a plain binary payload. RingSocket validates the
UTF-8 encoding of all WebSocket messages of type text in advance, in conformance
of [RFC 6455 Section 5.6](https://tools.ietf.org/html/rfc6455#section-5.6).

##### RS_READ_SWITCH(*case_m1*[, *case_m2*[, ...]])

By interpreting the 1st byte of any incoming WebSocket message payload as a
`uint8_t` request index (i.e., an index in the range [0...255]),
`RS_READ_SWITCH` will automatically call the read callback function listed for
whichever of its [RS_CASE_BIN](#rs_case_bincase_val-read_cb-read_m1-read_m2-rs_case_utf8case_val-read_cb-read_m1-read_m2-)
or [RS_CASE_UTF8](#rs_case_bincase_val-read_cb-read_m1-read_m2-rs_case_utf8case_val-read_cb-read_m1-read_m2-)
macro arguments provides a corresponding `uint8_t` *case_val* value, allowing
the app author to provide up to a maximum of 255 unique read callback functions,
accommodating the differentiation between any of the kinds of requests it may
wish to support.

##### RS_CASE_BIN(*case_val*, *read_cb*[, *read_m1*[, *read_m2*[, ...]]])<br>RS_CASE_UTF8(*case_val*, *read_cb*[, *read_m1*[, *read_m2*[, ...]]])

Apart from *case_val*, which fulfills the role described at
[`RS_READ_SWITCH(case_m1[, ...])`](#rs_read_switchcase_m1-case_m2-); these
macros accept the same arguments as
[`RS_READ_BIN(read_cb[, ...])`](#rs_read_binread_cb-read_m1-read_m2-) and
[`RS_READ_UTF8(read_cb[, ...])`](#rs_read_utf8read_cb-read_m1-read_m2-)
respectively.

##### RS_NET(*type*)<br>RS_NET(*type*, *elem_c*)<br>RS_NET(*type*, *min_elem_c*, *max_elem_c*)

The argument position of each `RS_NET(type)` decalaration corresponds to the
type expected of an argument to the read callback function in the same position.
E.g., `RS_READ_BIN(foo, RS_NET(uint64_t), RS_NET(int8_t))` would correspond to a
function signature of `int foo(rs_t * rs, uint64_t u64, int8_t i8);`.

When supplied with a 2nd argument, that argument is interpreted as a `size_t`
designating the number of elements of an array of the *type* given as the 1st
argument. E.g., `RS_READ_BIN(foo, RS_NET(uint8_t, 7))` would correspond to a
function signature of `int foo(rs_t * rs, uint8_t * u8_arr);`, with RingSocket
taking care of validating that `u8_arr` contains exactly 7 elements.

The form with arity 3 is only valid as the last argument passed to
`RS_READ_...()`: when supplied with a 2nd and 3rd argument, those arguments are
interpreted as *min_elem_c* and *max_elem_c*, setting a lower and upper bound on
the permissible number of elements of the given *type*. E.g.,
`RS_READ_BIN(foo, RS_NET(int32_t, 1, 10))` would correspond to
`int foo(char ch, int32_t * i32_arr, size_t elem_c)` where `elem_c` is an
additional `size_t` argument holding the number of elements actually received
and accessible by the preceding array pointer, which in this example must have a
minimum length of 1 element and a maximum length of 10 elements.

##### RS_NTOH(*type*)<br>RS_NTOH(*type*, *elem_c*)<br>RS_NTOH(*type*, *min_elem_c*, *max_elem_c*)

Identical to
[`RS_NET(type[, ...])`](#rs_nettypers_nettype-elem_crs_nettype-min_elem_c-max_elem_c),
except that these macros also take care of converting the endianness of
corresponding integers from network byte order to host byte order on any system
where these orders differ.

##### RS_NET_STA(*type*, *min_elem_c*, *max_elem_c*)<br>RS_NET_VLA(*type*, *min_elem_c*, *max_elem_c*)<br>RS_NET_HEAP(*type*, *min_elem_c*, *max_elem_c*)<br>RS_NTOH_STA(*type*, *min_elem_c*, *max_elem_c*)<br>RS_NTOH_VLA(*type*, *min_elem_c*, *max_elem_c*)<br>RS_NTOH_HEAP(*type*, *min_elem_c*, *max_elem_c*)

Same forms as the arity 3 form of
[`RS_NET(type[, ...])`](#rs_nettypers_nettype-elem_crs_nettype-min_elem_c-max_elem_c) and
[`RS_NTOH(type[, ...])`](#rs_ntohtypers_ntohtype-elem_crs_ntohtype-min_elem_c-max_elem_c)
respectively, except that instead of instantiating a stack array of fixed size
*max_elem_c*, these macros allocate their arrays as follows:
* ..._STA: A `thread_local static` array of fixed size *max_elem_c*
* ..._VLA: A C99 Variable Length Array with a variable size matching the actual
  instance's *elem_c*
* ..._HEAP: An array `malloc()`ed on the fly. RingSocket will not `free()` this
  array, as doing so is the prerogative of the app code. In other words, using
  this flavor eliminates the allocation of a temporary array in cases where the
  app intends to `malloc()` memory for the same contents anyway.

##### RS_STR(*min_byte_c*, *max_byte_c*)<br>RS_STR_STA(*min_byte_c*, *max_byte_c*)<br>RS_STR_VLA(*min_byte_c*, *max_byte_c*)<br>RS_STR_HEAP(*min_byte_c*, *max_byte_c*)

Same usage as the macros of arity 3 above, except that a type of `char` is
implied, and that the string arrays passed to the callback function are
NULL-terminated.

##### RS_CLOSE(*close_cb*)

Declaring `RS_CLOSE(foo_close)` will cause RingSocket to call an app-provided
`int foo_close(rs_t * rs)` callback function whenever a WebSocket connection
with a client has been closed by either side for any reason.

Note that although the same [helper functions](#app-helper-functions) are
exposed as in other callbacks, trying to send data at this time to the client
corresponding to the current close event will result in a fatal error, given
that the client will already have been marked as closed. Any other helper
functionality remains valid here though; including getting the client ID of the
closed client, or sending data to *other* clients.

##### RS_TIMER_SLEEP(*timer_cb*, *microseconds*)<br>RS_TIMER_WAKE(*timer_cb*, *microseconds*)

Declaring `RS_TIMER_WAKE(foo_timer, 12345)` will cause RingSocket to call an
app-provided `int foo_timer(rs_t * rs)` callback function every `12345`
microseconds.

The RingSocket app event loop is designed to stall on CPU-friendly FUTEX_WAIT
system calls during times when no traffic arrives from any WebSocket client,
only to be awoken once a worker thread notifies the app of new incoming data
with FUTEX_WAKE. Whereas using `RS_TIMER_WAKE` will set timeouts to the
FUTEX_WAIT calls such that the timer callback interval is honored even during
idle times; `RS_TIMER_SLEEP` will let the app sleep in peace, only periodically
calling the timer callback during periods that actually see WebSocket traffic.

An example use case for timer callbacks is the handling of the results of
time-consuming operations. The execution time of read callbacks—including the
sum of any child functions they call—should be kept fairly short in order to
keep overall app WebSocket IO throughput high. It can therefore be prudent to
offload time-consuming workloads (e.g., disk IO) from read callbacks to a child
thread, the result of which can then be queried and handled from a future
iteration of a timer callback.

### App callback return values

Every app callback function must return type `int`.
Recognized return values are:
* **0**: SUCCESS: all is well, and any WebSocket connection associated with the
callback is kept alive.
* **-1**: FATAL ERROR: this will cause the entire RingSocket daemon to `exit()`
(in the current implementation at least). Only return this value in the event of
critical and unrecoverable errors that leave your app in a wholly unusable
state.
* **[4000...4899]**: CLOSE CLIENT CONNECTION *(open and read callbacks only)*:
Tell RingSocket to close the connection with the WebSocket client associated
with the callback, applying a WebSocket Close Frame Status Code equal to the
value returned from the callback. As per [Section 7.4.2 of WebSocket RFC 6455](https://tools.ietf.org/html/rfc6455#section-7.4.2),
status codes in the range 4000 through 4999 are reserved for private use and
cannot be registered, making them available for custom use by applications.
Within that range though, RingSocket limits itself to using the range
[4900...4999] for [internally returned status codes](https://github.com/wbudd/ringsocket/blob/master/src/ringsocket_app.h),
leaving the range [4000...4899] for app authors to assign as they see fit.

RingSocket currently closes WebSocket client connections internally with one of
the following status codes when a received WebSocket payload doesn't meet the
app's requirements as specified by `RS_READ_...()`:
* **4900**: WRONG SIZE: The received message's payload size did not match the
  sum of all sizes of the read callback function's parameters.
* **4901**: WRONG DATA TYPE: An
  [`RS_READ_UTF8(read_cb[, ...])`](#rs_read_utf8read_cb-read_m1-read_m2-) read
  callback received a message with a binary data type, or vice versa.
* **4902**: UNKNOWN CASE: The 1st byte of the message received did not
  correspond to the *case_val* of any
  [RS_CASE_...](#rs_case_bincase_val-read_cb-read_m1-read_m2-rs_case_utf8case_val-read_cb-read_m1-read_m2-)
  within a [`RS_READ_SWITCH(case_m1[, ...])`](#rs_read_switchcase_m1-case_m2-).

### App helper functions

```C
uint64_t rs_get_client_id(rs_t * rs);
```

Obtains the client ID belonging to the WebSocket client connection that evoked
the current `RS_OPEN()`, `RS_READ()`, or `RS_CLOSE()` callback function.
I.e., every ID is mapped to one specific TCP socket file descriptor. Note that
calling this function from an `RS_TIMER_...()` callback will result in a fatal
error.

Also note that this ID is only valid while the corresponding connection is live.
Using an ID after the corresponding `RS_CLOSE()` callback function has returned
may result in errors and security vulnerabilities, given that RingSocket may
then assign the same ID to an unrelated future client connection.

```C
uint16_t rs_get_endpoint_id(rs_t * rs);
```

Obtains the endpoint ID of the WebSocket client connection that evoked
the current `RS_OPEN()`, `RS_READ()`, or `RS_CLOSE()` callback function.
For apps with multiple [configured endpoint urls](#endpoint-configuration),
this function allows the app to determine through which of those the WebSocket
client established its connection. Note that calling this function from an
`RS_TIMER_...()` callback will result in a fatal error.

```C
void rs_w_p(rs_t * rs, void const * src, size_t size);

void rs_w_str(rs_t * rs, char const * str);

void rs_w_uint8(rs_t * rs, uint8_t u8);
void rs_w_uint16(rs_t * rs, uint16_t u16);
void rs_w_uint32(rs_t * rs, uint32_t u32);
void rs_w_uint64(rs_t * rs, uint32_t u64);

void rs_w_uint16_hton(rs_t * rs, uint16_t u16);
void rs_w_uint32_hton(rs_t * rs, uint32_t u32);
void rs_w_uint64_hton(rs_t * rs, uint64_t u64);

void rs_w_int8(rs_t * rs, int8_t i8);
void rs_w_int16(rs_t * rs, int16_t i16);
void rs_w_int32(rs_t * rs, int32_t i32);
void rs_w_int64(rs_t * rs, int64_t i64);

void rs_w_int16_hton(rs_t * rs, int16_t i16);
void rs_w_int32_hton(rs_t * rs, int32_t i32);
void rs_w_int64_hton(rs_t * rs, int64_t i64);
```

These functions concatenate a buffer/string/integer onto a temporary internal
write buffer. The app thread will only flush the contents of this internal
buffer out to one or more outbound ring buffers once one of the `rs_to_...()`
functions listed below is called.

Note that each `rs_w_..._hton()` function above will take care of converting
integer endianness from host byte order to network byte order on any system
where these orders differ. Also note that the string passed to `rs_w_str()` must
be NULL-terminated—in case of unterminated strings just use `rs_w_p()` instead.

```C
// Write to a single WebSocket client, specified by client_id.
void rs_to_single(rs_t * rs, enum rs_data_kind kind, uint64_t cid);

// Write to multiple WebSocket clients, specified by a client_id array.
void rs_to_multi(rs_t * rs, enum rs_data_kind kind, uint64_t const * cids, size_t cid_c);

// Reply to the WebSocket client that evoked the current RS_OPEN() or RS_READ()
// callback. Calling this function from RS_CLOSE() or RS_TIMER_...() callbacks
// will result in a fatal error.
void rs_to_cur(rs_t * rs, enum rs_data_kind kind);

// Write to every WebSocket client currently connected to this app.
void rs_to_every(rs_t * rs, enum rs_data_kind kind);

// Write to every WebSocket client except one, as specified by its client_id.
void rs_to_every_except_single(rs_t * rs, enum rs_data_kind kind, uint64_t cid);

// Write to every WebSocket client except some, as specified by client_id array.
void rs_to_every_except_multi(rs_t * rs, enum rs_data_kind kind, uint64_t const * cids, size_t cid_c);

// Write to every WebSocket client except the one that evoked the current
// RS_OPEN() or RS_READ()callback. Calling this function from RS_CLOSE() or
// RS_TIMER_...() callbacks will result in a fatal error.
void rs_to_every_except_cur(rs_t * rs, enum rs_data_kind kind);
```

These functions write and flush any data buffered by the `rs_w_...()` functions
above to one or more outbound ring buffers, depending on the function variant
and any `client_id`s specified. From each outbound ring buffer, a corresponding
worker thread will take care of writing this data to any specified WebSocket
client recipients.

## Configuration

By default, all configuration options are specified in a JSON file at
`/etc/ringsocket.json`. To load the configuration from a different location,
specify its path as a command line option when executing the RingSocket binary
(e.g., `ringsocket /usr/local/etc/foo.json`).

### Global configuration

The configuration file's JSON root must be a JSON object containing at least the
keys `"ports"` and `"apps"`, whose values must be arrays consisting of at least
one JSON object element. Additionally, if any listed port is indended for use
with `wss` traffic (WebSocket encrypted with TLS), the JSON root must also
contain a key called "certs" with an array of at least one JSON object element:

```js
// The JSON standard does not officially support comments,
// but Jgrandson (the JSON parser used by RingSocket) does allow them anyway.
{
  "ports": [{
     // Port-specific configuration goes here
   }],
  "certs": [{ // required when using TLS encryption
     // Cert-specific configuration goes here
   }],
  "apps": [{
     // App-specific configuration goes here
   }],
   // Global configuration goes here
}
```
Other keys recognized in the root JSON object control global configuration values:
* `"log_level"`: The minimum level of importance at which log messages are
  printed to *syslog* (i.e., messages of less importance than the value of
  `"log_level"` are not recorded in the system log). Recognized values in order
  from high to low are: `"error"`, `"warning"`, `"notice"`, `"info"`, and
  `"debug"`. Default: `"warning"`
* `"worker_c"`: The number of worker threads RingSocket should use. If omitted,
  RingSocket will choose that number to be equal to the number of CPU cores
  available to the system minus the number of apps configured (or 1, if the
  number of apps is greater than or equal to the number of cores).

The remainder of the global options are mostly intended for performance
optimization. It's probably wise to just omit these unless "you know what you're
doing":
* `"shutdown_wait_http"`: The number of seconds to wait for a closing peer to
  fulfill its role in an orderly bi-directional shutdown handshake from the HTTP
  layer downward (i.e., in cases where the client did not yet complete a HTTP
  Upgrade handshake to the WebSocket layer), before unilaterally aborting the
  connection. Default: `15`
* `"shutdown_wait_ws"`: The number of seconds to wait for a closing peer to
  fulfill its role in an orderly bi-directional shutdown handshake from the
  WebSocket layer downward, before unilaterally aborting the connection.
  Default: `30`
* `"fd_alloc_c"`: The maximum number of open file descriptors (i.e., network
  connections) that RingSocket is allowed to handle simultaneously. Default:
  `4096`
* `"max_ws_msg_size"`: Sets the maximum number of bytes a single WebSocket
  message may contain. Default: `16777216` (i.e., 16 MB)
* `"realloc_multiplier"`: The factor with which RingSocket should multipy the
  size of any memory buffer that has run out of free space when attempting to
  reallocate a larger buffer on the heap. Default: `1.5`
* `"worker_rbuf_size"`: The initial size in bytes of each worker thread's read
  buffer for incoming WebSocket messages. Default: `33554432` (i.e., 32 MB)
* `"inbound_ring_buf_size"`: The initial size in bytes of each worker/app pair's
  ring buffer with which worker threads relay incoming WebSocket messages to app
  threads. Default: `67108864` (i.e., 64 MB)
* `"outbound_ring_buf_size"`: The initial size in bytes of each app/worker
  pair's ring buffer with which app threads relay outgoing WebSocket messages to
  worker threads. Default: `134217728` (i.e., 128 MB)
* `"wrefs_elem_c"`: The initial number of elements of each worker thread's array
  of write references, with which they keep track of the extent to which
  recipients have received their copies of outgoing WebSocket messages.
  Default: `10000`
* `"epoll_buf_elem_c"`: Determines the number of epoll events each worker thread
  can store during each call to `epoll_wait()`. Default: `100`
* `"update_queue_size"`: The number of ring buffer writes to deliberately
  queue in order to guard against CPU memory reordering (see
  [ringsocket_ring.h](https://github.com/wbudd/ringsocket/blob/master/src/ringsocket_ring.h)). Default: `5`

### Port configuration

Each element of the `"ports"` array must be a JSON object containing at least
the key:
* "`port_number`": a TCP port number on which to listen for incoming
connections.

The following optional keys are also recognized inside this JSON object:
* `"is_unencrypted"`: If `true`, this port will only accept plaintext `ws://`
  WebSocket connections. If `false`, (the default) this port will only accept
  TLS-encrypted `wss://` WebSocket connections. See the explanation of the
  `"url"` key-value of app [endpoints](#endpoint-configuration) for more
  information.
* `"ip_addrs"`: An array of IP address strings on which this port will listen
  for incoming connections. If omitted, RingSocket listens to `["0.0.0.0"]`,
  which means it will accept connections to any interface and IP address known
  on the RingSocket host system (provided that the port number matches).
* `"interface"`: The name of a destination network interface available on the
  RingSocket host system to which to accept incoming connections. If omitted,
  RingSocket will accept connections from any interface (provided that the port
  number matches).

  Note that RingSocket does not allow specifying both the "`ip_addrs`" and
  `"interface`" options for the same port.
* `"ipv4only"`: If `true`, this port will only accept IPv4 connections.
  If `false` (the default), RingSocket will allow both IPv4 and IPv6
  connections on this port.
* `"ipv6only"`: If `true`, this port will only accept IPv6 connections.
  If `false` (the default), RingSocket will allow both IPv4 and IPv6
  connections on this port.
* `"ipv4_is_embedded_in_ipv6"`: If `true`, Ringsocket will use a single IPv6
  stack on this port, in which IPv4 addresses are mapped to IPv6 addresses.
  For example, if an app were to log the address of an incoming connection
  from IPv4 address `192.0.2.128` it would show as the IPv6 address
  `::ffff:192.0.2.128`.
  If `false` (the default), RingSocket will use separate IP stacks for IPv4 and
  IPv6 on this port.

### TLS certificate configuration

Each element of the `"certs"` array must be a JSON object containing the
following keys:
* `"hostnames"`: An array of strings of the domains to which this TLS
  certificate has been issued.  
  E.g., `["example.com", "*.example.com"]`.
* `"privkey_path"`: The absolute path to the certificate's private key file.  
  E.g., `"/etc/letsencrypt/live/example.com/privkey.pem"`.
* `"pubchain_path"`: The absolute path to the certificate's full public key
  chain file.  
  E.g., `"/etc/letsencrypt/live/example.com/fullchain.pem"`.

### App configuration

Each element of the `"apps"` array must be a JSON object containing at least the
following keys:
* `"name"`: Log messages recorded from this app's thread will
  include this name string as a prefix.
* `"app_path"`: The absolute path to this app's shared object file (e.g.,
  `"/usr/local/lib/foo.so"`).
* `"endpoints"`: an array of JSON objects holding endpoint configurations. See
  [Endpoint configuration](#endpoint-configuration).

The following optional keys are also recognized inside this JSON object:
* `"no_open_cb"`: Setting this value to `"true"` reduces a bit of unnecessary
  overhead for apps that omit the client "open" callback by specifying
  `RS_OPEN_NONE`, by telling worker threads that they don't need to inform this
  app's thread of new connections being established.
* `"no_close_cb"`: Same mechanism as `"no_open_cb"`: tell worker threads they
  need not inform this app's thread of connections that are no longer available.
* `"wbuf_size"`: The initial size in bytes of this app's write buffer, which is
  used to accumulate data written with the `rs_w_...()` helper functions before
  their concatenated contents is written to the outbound ring buffers with any
  of the `rs_to_...()` helper functions. Default: `1048576` (i.e., 1 MB)
* `"update_queue_size"`: An app-specific value that takes preference over the
  global `"update_queue_size"` mentioned at
  [Global configuration](#global-configuration).

### Endpoint configuration

An endpoint is unique URL/ID pair with which an app can be accessed by WebSocket
clients. RingSocket supports configuring any number of endpoints per app within
the range [1...UINT16_MAX].

Each element of the `"endpoints"` array (see
[App configuration](#app-configuration)) must be a JSON object containing the
following keys:
* `"endpoint_id"`: An integer value in the range [0...UINT16_MAX] corresponding
  to this endpoint, which an app can obtain with the RingSocket helper function
  `rs_get_endpoint_id()` in order to determine to which endpoint a WebSocket
  client established its connection with the app. This way an app handling
  multiple endpoints can differentiate the content it serves, or assign
   different endpoint-based privileges to its WebSocket clients.
* `"url"`: The fully-qualified URL string belonging to this endpoint (e.g.,
  `"wss://example.com:12345/foo"`).

  Note that the port number contained in or
  implied by this URL must also be listed as a `"port_number"` of a
  [Port configuration](#port-configuration) JSON object. Furthermore, the scheme
  part of the URL must correspond to that port object's `"is_unencrypted"` flag:
  `"is_unencrypted: false"` (the default) for `wss://` URLs, and
  `"is_unencrypted: true"` for `ws://` URLs.

  Finally, note that every `wss://` endpoint URL must have a hostname component
  that is listed among the `"hostnames"` of any of the
  [configured TLS certificates](#tls-certificate-configuration).
* `"allowed_origins"`: An array of fully-qualified URL strings specifying from
  which origins WebSocket clients that include the *Origin* HTTP header
  (i.e., browser clients) are allowed to connect to this endpoint (e.g.,
  `["http://localhost:8080", "https://example.com/foo"]`).

## Control flow overview

### Startup

1. The RingSock binary is executed as a user with sufficient privileges/capabilities (e.g., root).
1. The process switches to running as user `ringsock` (see "Installation" above).
1. All capabilities are removed except those needed for configuration purposes.
1. The process daemonizes (double `fork()`, closing of std streams, etc).
1. The [configuration file](#configuration) is parsed.
1. Resource limits are set.
1. Network ports on which to listen for incoming WebSocket traffic are opened.
1. Each app DLL (`.so` file) specified in the configuration file is loaded with `dlopen()`.
1. All remaining capabilities are removed.
1. Worker threads and dedicated app threads are spawned.

### Worker threads

[todo: write documentation]

### App threads

[todo: write documentation]

## Todo

* Fill in the [todo: write documentation] parts of this README.md
* Move wref stuff out of `rs_ring.c` into a separate `rs_wref.c`
* Replace randomizing BPF with cpu affinity-based EBPF
* Reduce thread_local usage in favor of stack variables to optimize performance
* Add/improve comments for the lesser documented parts of the codebase

## Contributing

Pull requests and other contributions are always welcome! License:
[MIT](https://github.com/wbudd/jgrandson/blob/master/LICENSE).

## Email me

Feel free to send me email at the address below, *especially* if you might be
interested in offering me employment or contractual work. Based in Osaka, Japan;
but also happy to work remotely.

           _               _               _     _                   
          | |             | |             | |   | |                  
     _ _ _| |__      _ _ _| |__  _   _  __| | __| |  ____ ___  ____  
    | | | |  _ \    | | | |  _ \| | | |/ _  |/ _  | / ___) _ \|    \ 
    | | | | |_) ) @ | | | | |_) ) |_| ( (_| ( (_| |( (__| |_| | | | |
     \___/|____/     \___/|____/|____/ \____|\____(_)____)___/|_|_|_|
（2010年に日本語能力試験N1に合格／2017年に日本永住権を取得）
