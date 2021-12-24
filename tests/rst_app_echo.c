// SPDX-License-Identifier: MIT
// Copyright © 2021 MetaWord Inc
// Copyright © 2019-2021 William Budd

#include <ringsocket.h>

#define RST_MAX_ECHO_BYTE_C 0x1000000 // 16 MB (based on ...nothing really)

rs_cb_ret echo(
    rs_t * rs,
    uint8_t * msg,
    size_t msg_byte_c
) {
    rs_w_p(rs, msg, msg_byte_c);
    rs_to_cur(rs, rs_get_read_data_kind(rs));
    return RS_CB_OK;
}

RS_APP(
    RS_INIT_NONE,
    RS_OPEN_NONE,
    RS_READ_ANY(echo, RS_NET_STA(uint8_t, 0, RST_MAX_ECHO_BYTE_C)),
    RS_CLOSE_NONE,
    RS_TIMER_NONE
);
