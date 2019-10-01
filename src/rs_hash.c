// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include "rs_hash.h"

rs_ret init_hash_state(
    struct rs_worker * worker
) {
    worker->sha1_ctx = EVP_MD_CTX_new();
    if (!worker->sha1_ctx) {
        RS_LOG(LOG_CRIT, "Unsuccessful EVP_MD_CTX_new().");
        return RS_FATAL;
    }
    worker->base64_bio = BIO_new(BIO_f_base64());
    if (!worker->base64_bio) {
        RS_LOG(LOG_CRIT, "Unsuccessful BIO_new(BIO_f_base64())");
        return RS_FATAL;
    }
    BIO * mem_bio = BIO_new(BIO_s_mem());
    if (!mem_bio) {
        RS_LOG(LOG_CRIT, "Unsuccessful BIO_new(BIO_s_mem())");
        return RS_FATAL;
    }
    BIO_get_mem_ptr(mem_bio, &worker->base64_buf);
    BIO_push(worker->base64_bio, mem_bio);
    return RS_OK;
}

// This function performs no input or output bounds checking:
// * wskey_22str MUST be an array of exactly 22 bytes.
// * dst_27str MUST point to at least 27 overwritable destination bytes
rs_ret get_websocket_key_hash(
    struct rs_worker * worker,
    char const * wskey_22str,
    char * dst_27str
) {
    thread_local static char token_str[] = "1234567890123456789012=="
        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    memcpy(token_str, wskey_22str, 22);
    if (!EVP_DigestInit_ex(worker->sha1_ctx, EVP_sha1(), NULL)) {
        RS_LOG(LOG_CRIT, "Unsuccessful "
            "EVP_DigestInit_ex(worker->sha1_ctx, EVP_sha1(), NULL)");
        return RS_FATAL;
    }
    if (!EVP_DigestUpdate(worker->sha1_ctx, token_str,
        RS_CONST_STRLEN(token_str))) {
        RS_LOG(LOG_CRIT,
            "Unsuccessful EVP_DigestUpdate(worker->sha1_ctx, %s, %zu)",
            token_str, RS_CONST_STRLEN(token_str));
        return RS_FATAL;
    }
    uint8_t hash[20] = {0};
    if (!EVP_DigestFinal_ex(worker->sha1_ctx, hash, NULL)) {
        RS_LOG(LOG_CRIT,
            "Unsuccessful EVP_DigestFinal_ex(worker->sha1_ctx, hash, NULL)");
        return RS_FATAL;
    }
    BIO_write(worker->base64_bio, hash, 20);
    BIO_flush(worker->base64_bio);
    if (worker->base64_buf->length < 28 ||
        worker->base64_buf->data[27] != '=') {
        char data[worker->base64_buf->length + 1];
        memcpy(data, worker->base64_buf->data, worker->base64_buf->length);
        data[worker->base64_buf->length] = '\0';
        RS_LOG(LOG_CRIT, "Unexpected base64 websocket key encoding: \"%s\" "
            "(length: %zu)", data, worker->base64_buf->length);
        return RS_FATAL;
    }
    memcpy(dst_27str, worker->base64_buf->data, 27);
    BIO_reset(worker->base64_bio);
    return RS_OK;
}
