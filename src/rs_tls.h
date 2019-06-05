// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#pragma once

#include "ringsocket.h"

int derive_cert_index_from_hostname(
    struct rs_conf const * conf,
    char const * hostname,
    size_t hostname_strlen
);

rs_ret create_tls_contexts(
    struct rs_conf const * conf
);

rs_ret init_tls_session(
    union rs_peer * peer
);

rs_ret handle_tls_io(
    union rs_peer * peer,
    uint8_t * rbuf,
    size_t rbuf_size
);

rs_ret read_tls(
    union rs_peer * peer,
    void * rbuf,
    size_t rbuf_size,
    size_t * rsize
);

rs_ret write_tls(
    union rs_peer * peer,
    void const * wbuf,
    size_t wbuf_size
);
