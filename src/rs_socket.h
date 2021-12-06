// SPDX-License-Identifier: MIT
// Copyright © 2021 MetaWord Inc
// Copyright © 2019-2021 William Budd

#pragma once

#include "rs_worker.h"

rs_ret bind_to_ports(
    struct rs_conf * conf
);

rs_ret listen_to_sockets(
    struct rs_worker * worker,
    int epoll_fd
);

rs_ret accept_sockets(
    struct rs_worker * worker,
    int epoll_fd,
    int listen_fd,
    bool is_encrypted
);
