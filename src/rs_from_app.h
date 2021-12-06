// SPDX-License-Identifier: MIT
// Copyright © 2021 MetaWord Inc
// Copyright © 2019-2021 William Budd

#pragma once

#include "rs_worker.h"

rs_ret get_outbound_consumers_from_producers(
    struct rs_worker * worker
);

rs_ret init_owrefs(
    struct rs_worker * worker
);

rs_ret receive_from_app(
    struct rs_worker * worker
);

rs_ret send_pending_owrefs(
    struct rs_worker * worker,
    union rs_peer * peer,
    uint32_t peer_i
);

void remove_pending_owrefs(
    struct rs_worker * worker,
    union rs_peer * peer,
    uint32_t peer_i
);
