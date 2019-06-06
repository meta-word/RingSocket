// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#include "rs_hash.h"

thread_local static EVP_MD_CTX * sha1_ctx = NULL;
thread_local static BIO * base64_bio = NULL;
thread_local static BUF_MEM * base64_buf = NULL;

rs_ret init_hash_state(
    void
) {
    sha1_ctx = EVP_MD_CTX_new();
    if (!sha1_ctx) {
        RS_LOG(LOG_CRIT, "Unsuccessful EVP_MD_CTX_new().");
        return RS_FATAL;
    }
    base64_bio = BIO_new(BIO_f_base64());
    if (!base64_bio) {
        RS_LOG(LOG_CRIT, "Unsuccessful BIO_new(BIO_f_base64())");
        return RS_FATAL;
    }
    BIO * mem_bio = BIO_new(BIO_s_mem());
    if (!mem_bio) {
        RS_LOG(LOG_CRIT, "Unsuccessful BIO_new(BIO_s_mem())");
        return RS_FATAL;
    }
    BIO_get_mem_ptr(mem_bio, &base64_buf);
    BIO_push(base64_bio, mem_bio);
    return RS_OK;
}

// This function performs no input or output bounds checking:
// * wskey_22str MUST be an array of exactly 22 bytes.
// * dst_27str MUST point to at least 27 overwritable destination bytes
rs_ret get_websocket_key_hash(
    char const * wskey_22str,
    char * dst_27str
) {
    thread_local static char token_str[] = "1234567890123456789012=="
        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    memcpy(token_str, wskey_22str, 22);
    if (!EVP_DigestInit_ex(sha1_ctx, EVP_sha1(), NULL)) {
        RS_LOG(LOG_CRIT,
            "Unsuccessful EVP_DigestInit_ex(sha1_ctx, EVP_sha1(), NULL)");
        return RS_FATAL;
    }
    if (!EVP_DigestUpdate(sha1_ctx, token_str, RS_CONST_STRLEN(token_str))) {
        RS_LOG(LOG_CRIT, "Unsuccessful EVP_DigestUpdate(sha1_ctx, %s, %zu)",
            token_str, RS_CONST_STRLEN(token_str));
        return RS_FATAL;
    }
    uint8_t hash[20] = {0};
    if (!EVP_DigestFinal_ex(sha1_ctx, hash, NULL)) {
        RS_LOG(LOG_CRIT,
            "Unsuccessful EVP_DigestFinal_ex(sha1_ctx, hash, NULL)");
        return RS_FATAL;
    }
    BIO_write(base64_bio, hash, 20);
    BIO_flush(base64_bio);
    if (base64_buf->length < 28 || base64_buf->data[27] != '=') {
        char data[base64_buf->length + 1];
        memcpy(data, base64_buf->data, base64_buf->length);
        data[base64_buf->length] = '\0';
        RS_LOG(LOG_CRIT, "Unexpected base64 websocket key encoding: \"%s\" "
            "(length: %zu)", data, base64_buf->length);
        return RS_FATAL;
    }
    memcpy(dst_27str, base64_buf->data, 27);
    BIO_reset(base64_bio);
    return RS_OK;
}
