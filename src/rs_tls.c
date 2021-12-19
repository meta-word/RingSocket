// SPDX-License-Identifier: MIT
// Copyright © 2021 MetaWord Inc
// Copyright © 2019-2021 William Budd

#include "rs_tls.h"

#include "rs_tcp.h" // write_bidirectional_tcp_shutdown()
#include "rs_util.h" // get_addr_str()

#include <openssl/conf.h>
#include <openssl/err.h>

static size_t get_subdomain_depth(
    char const * str, // Can be un-0-terminated!
    size_t strlen
) {
    size_t subdomain_depth = 0;
    for (char const * str_over = str + strlen; str < str_over; str++) {
        if (* str == '.') {
            subdomain_depth++;
        }
    }
    return subdomain_depth;
}

static int tls_client_hello_cb(
    SSL * tls,
    int * alert,
    void * _worker
) {
    // Apparently SSL_CTX_set_tlsext_servername_callback() has been deprecated,
    // with this being its intended replacement. Based on the only available
    // (as of Feb 2019) example: client_hello_select_server_ctx() at
    // https://github.com/openssl/openssl/blob/master/test/handshake_helper.c
    uint8_t const *p = NULL;
    size_t size = 0;
    if (!SSL_client_hello_get0_ext(tls, TLSEXT_TYPE_server_name, &p, &size) ||
        size < 6) { // uint16_t size + type byte + uint16_t strlen + 1+ chars
        goto client_hello_failure;
    }
    {
        size_t reported_size = RS_R_NTOH16(p);
        p += 2;
        size -= 2;
        if (reported_size != size) {
            goto client_hello_failure;
        }
    }
    // From the link above: "The list in practice only has a single element,
    // so we only consider the first one.". For the time being, let's pretend
    // that doesn't sound sketchy at all.
    if (*p++ != TLSEXT_NAMETYPE_host_name) {
        goto client_hello_failure;
    }
    size--;
    {
        size_t reported_strlen = RS_R_NTOH16(p);
        p += 2;
        size -= 2;
        if (reported_strlen != size) {
            goto client_hello_failure;
        }
    }
    struct rs_worker * worker = _worker;
    int cert_i = derive_cert_index_from_hostname(worker->conf, (char const *) p,
        size);
    switch (cert_i) {
    case -1:
        break;
    case 0:
        return SSL_CLIENT_HELLO_SUCCESS;
    default:
        if (SSL_set_SSL_CTX(tls, worker->tls_ctxs[cert_i]) ==
            worker->tls_ctxs[cert_i]) {
            return SSL_CLIENT_HELLO_SUCCESS;
        }
    }
    client_hello_failure:
    *alert = SSL_AD_UNRECOGNIZED_NAME;
    return SSL_CLIENT_HELLO_ERROR;
}

int derive_cert_index_from_hostname(
    struct rs_conf const * conf,
    char const * hostname, // Can be un-0-terminated!
    size_t hostname_strlen
) {
    // returns -1 when no matching certificate was found
    if (!hostname || !hostname_strlen ||
        hostname_strlen > conf->hostname_max_strlen) {
        return -1;
    }
    size_t hostname_subdomain_depth = get_subdomain_depth(hostname,
        hostname_strlen);
    for (size_t i = 0; i < conf->cert_c; i++) {
        for (size_t j = 0; j < conf->certs[i].hostname_c; j++) {
            char * str = conf->certs[i].hostnames[j];
            if (*str != '*') {
                if (strncmp(str, hostname, hostname_strlen)) {
                    continue;
                }
                return i;
            }
            str += 2; // Skip "*."
            size_t strlen_without_asterisk = strlen(str);
            if (strlen_without_asterisk > hostname_strlen ||
                // Wildcard certs only apply to direct child subdomains,
                // so the total subdomain depth (number of dots) must be equal.
                get_subdomain_depth(str, strlen_without_asterisk) !=
                hostname_subdomain_depth) {
                continue;
            }
            for (char const * substr = hostname + hostname_strlen -
                strlen_without_asterisk; *str; str++, substr++) {
                if (*substr != *str) {
                    goto next_cert_hostname;
                }
            }
            return i;
            next_cert_hostname:;
        }
    }
    return -1;
}

rs_ret create_tls_contexts(
    struct rs_worker * worker
) {
    RS_CALLOC(worker->tls_ctxs, worker->conf->cert_c);
    for (size_t i = 0; i < worker->conf->cert_c; i++) {
        SSL_CTX *ctx = worker->tls_ctxs[i] = SSL_CTX_new(TLS_server_method());
        if (!ctx) {
            ERR_error_string_n(ERR_get_error(), worker->log_buf,
                sizeof(worker->log_buf));
            RS_LOG(LOG_CRIT,
                "Unsuccessful SSL_CTX_new(TLS_server_method()): %s",
                worker->log_buf);
            return RS_FATAL;
        }
        if (!SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION)) {
            RS_LOG(LOG_CRIT, "Unsuccessful SSL_CTX_set_min_proto_version("
                "ctx, TLS1_1_VERSION)");
            return RS_FATAL;
        }
        SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
        if (!SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!LOW:!MEDIUM")) {
            RS_LOG(LOG_CRIT, "Unsuccessful SSL_CTX_set_cipher_list(...)");
            return RS_FATAL;
        }

        // The following options should disable all session/ticket renegotiation
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
        // _Should_ be redundant, but is --as of Feb 2019-- necessary for TLS1.3
        if (!SSL_CTX_set_num_tickets(ctx, 0)) {
            RS_LOG(LOG_CRIT, "Unsuccessful SSL_CTX_set_num_tickets(ctx, 0)");
            return RS_FATAL;
        }
        // Probably redundant
        SSL_CTX_set_options(ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

        // Tell SSL_write_(ex)() to allow a different buffer location on
        // write resumption (but with the same size and contents). Only needed
        // for the current implementation of WebSocket Pong responses.
        SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

        // This has no effect function/API wise, but it supposedly significantly
        // reduces OpenSSL's memory footprint. Isn't that a no-brainer?!
        SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

        SSL_CTX_set_client_hello_cb(ctx, tls_client_hello_cb, (void *) worker);

        if (!SSL_CTX_use_PrivateKey_file(ctx,
            worker->conf->certs[i].privkey_path, SSL_FILETYPE_PEM)) {
            ERR_error_string_n(ERR_get_error(), worker->log_buf,
                sizeof(worker->log_buf));
            RS_LOG(LOG_ERR, "Unsuccessful SSL_CTX_use_PrivateKey_file(ctx, "
                "\"%s\", SSL_FILETYPE_PEM): %s",
                worker->conf->certs[i].privkey_path, worker->log_buf);
            return RS_FATAL;
        }
        if (!SSL_CTX_use_certificate_chain_file(ctx,
            worker->conf->certs[i].pubchain_path)) {
            ERR_error_string_n(ERR_get_error(), worker->log_buf,
                sizeof(worker->log_buf));
            RS_LOG(LOG_ERR, "Unsuccessful SSL_CTX_use_certificate_chain_file("
                "ctx, \"%s\"): %s", worker->conf->certs[i].pubchain_path,
                worker->log_buf);
            return RS_FATAL;
        }
    }
    return RS_OK;
}

rs_ret init_tls_session(
    struct rs_worker * worker,
    union rs_peer * peer
) {
    ERR_clear_error();
    peer->tls = SSL_new(worker->tls_ctxs[0]);
    if (!peer->tls) {
        ERR_error_string_n(ERR_get_error(), worker->log_buf,
            sizeof(worker->log_buf));
        RS_LOG(LOG_CRIT, "Unsuccessful SSL_new(worker->tls_ctxs[0]): %s",
            worker->log_buf);
        return RS_FATAL;
    }
    if (!SSL_set_fd(peer->tls, peer->socket_fd)) {
        ERR_error_string_n(ERR_get_error(), worker->log_buf,
            sizeof(worker->log_buf));
        RS_LOG(LOG_CRIT, "Unsuccessful SSL_set_fd(peer->tls, %d): %s",
            peer->socket_fd, worker->log_buf);
        return RS_FATAL;
    }
    return RS_OK;
}

static rs_ret check_tls_error(
    struct rs_worker * worker, // sizeof() wouldn't work for direct log_buf arg
    union rs_peer * peer,
    char const * func_str,
    size_t size,
    int ret,
    bool zero_return_is_expected
) {
    int err = SSL_get_error(peer->tls, 0);
    switch (err) {
    case SSL_ERROR_NONE:
        if (size) {
            RS_LOG(LOG_ERR, "%s: %s of size %zu returned %d and "
                "SSL_ERROR_NONE, even though those return values contradict "
                "each other", get_addr_str(peer), func_str, size, ret);
        } else {
            RS_LOG(LOG_ERR, "%s: %s returned %d and SSL_ERROR_NONE, even "
                "though those return values contradict each other",
                get_addr_str(peer), func_str, ret);
        }
        return RS_CLOSE_PEER;
    case SSL_ERROR_ZERO_RETURN:
        ERR_error_string_n(ERR_get_error(), worker->log_buf,
            sizeof(worker->log_buf));
        {
            int priority = zero_return_is_expected ? LOG_DEBUG : LOG_INFO;
            if (size) {
                RS_LOG(priority, "%s: %s of size %zu returned %d and "
                    "SSL_ERROR_ZERO_RETURN: %s", get_addr_str(peer), func_str,
                    size, ret, worker->log_buf);
            } else {
                RS_LOG(priority,
                    "%s: %s returned %d and SSL_ERROR_ZERO_RETURN: %s",
                    get_addr_str(peer), func_str, ret, worker->log_buf);
            }
        }
        return zero_return_is_expected ? RS_OK : RS_CLOSE_PEER;
    case SSL_ERROR_WANT_READ:
        peer->is_writing = false;
        return RS_AGAIN;
    case SSL_ERROR_WANT_WRITE:
        peer->is_writing = true;
        return RS_AGAIN;
    case SSL_ERROR_SYSCALL:
        ERR_error_string_n(ERR_get_error(), worker->log_buf,
            sizeof(worker->log_buf));
        if (size) {
            RS_LOG_ERRNO(LOG_ERR,
                "%s: %s of size %zu returned %d and SSL_ERROR_SYSCALL: %s",
                get_addr_str(peer), func_str, size, ret, worker->log_buf);
        } else {
            RS_LOG_ERRNO(LOG_ERR,
                "%s: %s returned %d and SSL_ERROR_SYSCALL: %s",
                get_addr_str(peer), func_str, ret, worker->log_buf);
        }
        return RS_CLOSE_PEER;
    case SSL_ERROR_SSL:
        ERR_error_string_n(ERR_get_error(), worker->log_buf,
            sizeof(worker->log_buf));
        if (size) {
            RS_LOG(LOG_ERR,
                "%s: %s of size %zu returned %d and SSL_ERROR_SSL: %s",
                get_addr_str(peer), func_str, size, ret, worker->log_buf);
        } else {
            RS_LOG(LOG_ERR, "%s: %s returned %d and SSL_ERROR_SSL: %s",
                get_addr_str(peer), func_str, ret, worker->log_buf);
        }
        return RS_CLOSE_PEER;
    default:
        ERR_error_string_n(ERR_get_error(), worker->log_buf,
            sizeof(worker->log_buf));
        if (size) {
            RS_LOG(LOG_ERR, "%s: %s of size %zu returned %d and wildly "
                "inappropriate error value %d: %s",
                get_addr_str(peer), func_str, size, ret, err, worker->log_buf);
        } else {
            RS_LOG(LOG_ERR, "%s: %s returned %d and wildly inappropriate "
                "error value %d: %s", get_addr_str(peer), func_str, ret, err,
                worker->log_buf);
        }
        return RS_CLOSE_PEER;
    }
}

static rs_ret shake_tls_hands(
    struct rs_worker * worker,
    union rs_peer * peer
) {
    ERR_clear_error();
    int ret = SSL_accept(peer->tls);
    return ret == 1 ? RS_OK :
        check_tls_error(worker, peer, "SSL_accept()", 0, ret, false);
}

static rs_ret write_bidirectional_tls_shutdown(
    struct rs_worker * worker,
    union rs_peer * peer,
    bool * received_tls_close_notify
) {
    ERR_clear_error();
    int ret = SSL_shutdown(peer->tls);
    switch (ret) {
    case 0:
        // man SSL_shutdown: "ret == 0: The shutdown is not yet finished: the
        // close_notify was sent but the peer did not send it back yet. Call
        // SSL_read() to do a bidirectional shutdown."
        *received_tls_close_notify = false;
        return RS_OK; // Proceed to read_bidirectional_tls_shutdown()
    case 1:
        // man SSL_shutdown: "ret == 1: The shutdown was successfully completed.
        // The close_notify alert was sent and the peer's close_notify alert was
        // received."
        *received_tls_close_notify = true;
        return RS_OK; // TLS layer stuff is all done
    default:
        // man SSL_shutdown: "ret <= 0: The shutdown was not successful. Call
        // SSL_get_error with the return value ret to find out the reason. It
        // can occur if an action is needed to continue the operation for
        // non-blocking BIOs. It can also occur when not all data was read
        // using SSL_read()."
        return check_tls_error(worker, peer, "SSL_shutdown()", 0, ret, false);
    }
}

static rs_ret read_bidirectional_tls_shutdown(
    struct rs_worker * worker,
    union rs_peer * peer
) {
    // Read peer data until SSL_ERROR_ZERO_RETURN is encountered, to conclude a
    // bidirectional TLS shutdown. No read data is actually processed though;
    // just stored, ignored, and overwritten.
    ERR_clear_error();
    size_t rsize = 0;
    while (SSL_read_ex(peer->tls, worker->rbuf, worker->conf->worker_rbuf_size,
        &rsize));
    return check_tls_error(worker, peer, "Zero-return-seeking SSL_read_ex()",
        rsize, 0, true);
}

rs_ret handle_tls_io(
    struct rs_worker * worker,
    union rs_peer * peer
) {
    switch (peer->mortality) {
    case RS_MORTALITY_LIVE:
        switch (shake_tls_hands(worker, peer)) {
        case RS_OK:
            peer->layer = RS_LAYER_HTTP;
            return RS_OK;
        case RS_AGAIN:
            return RS_OK;
        case RS_CLOSE_PEER:
            // If the TLS handshake fails, immediately abort the connection
            // instead of wasting resources attempting a bi-directional shutdown
            peer->mortality = RS_MORTALITY_DEAD;
            goto terminate_tls;
        case RS_FATAL: default:
            return RS_FATAL;
        }
    case RS_MORTALITY_SHUTDOWN_WRITE:
        {
            bool received_tls_close_notify;
            switch (write_bidirectional_tls_shutdown(worker, peer,
                &received_tls_close_notify)) {
            case RS_OK:
                if (received_tls_close_notify) {
                    goto terminate_tls;
                }
                break; // TLS close_notify alert sent, but still awaiting an ack
            case RS_AGAIN:
                return RS_OK;
            case RS_CLOSE_PEER:
                peer->mortality = RS_MORTALITY_DEAD;
                goto terminate_tls;
            case RS_FATAL: default:
                return RS_FATAL;
            }
        }
        // Now that there's nothing left to write to the peer on any layer,
        // the total shutdown process can potentially be sped up a little by
        // calling write_bidirectional_tcp_shutdown() before calling
        // read_bidirectional_tls_shutdown() to ensure that a bi-directional
        // shutdown at the TCP layer will already be underway once the
        // bi-directional shutdown on the TLS layer has been completed.
        switch (write_bidirectional_tcp_shutdown(peer)) {
        case RS_OK:
            peer->mortality = RS_MORTALITY_SHUTDOWN_READ;
            break;
        case RS_CLOSE_PEER:
            peer->mortality = RS_MORTALITY_DEAD;
            goto terminate_tls;
        default:
            return RS_FATAL;
        }
        // fall through
    case RS_MORTALITY_SHUTDOWN_READ:
        switch (read_bidirectional_tls_shutdown(worker, peer)) {
        case RS_OK:
            break;
        case RS_AGAIN:
            return RS_OK;
        case RS_CLOSE_PEER:
            peer->mortality = RS_MORTALITY_DEAD;
            break;
        case RS_FATAL: default:
            return RS_FATAL;
        }
        break;
    case RS_MORTALITY_DEAD: default:
        break;
    }
    terminate_tls:
    SSL_free(peer->tls);
    peer->tls = NULL;
    peer->layer = RS_LAYER_TCP;
    return RS_OK;
}

rs_ret read_tls(
    struct rs_worker * worker,
    union rs_peer * peer,
    void * rbuf,
    size_t rbuf_size,
    size_t * rsize
) {
    ERR_clear_error();
    return SSL_read_ex(peer->tls, rbuf, rbuf_size, rsize) ? RS_OK :
        check_tls_error(worker, peer, "SSL_read_ex()", *rsize, 0, false);
}

rs_ret write_tls(
    struct rs_worker * worker,
    union rs_peer * peer,
    void const * wbuf,
    size_t wbuf_size
) {
    // write_tcp() and write_tls() only return RS_OK when the entire message
    // has been written out.
    size_t wsize = 0;
    ERR_clear_error();
    return SSL_write_ex(peer->tls, wbuf, wbuf_size, &wsize) ? RS_OK :
        check_tls_error(worker, peer, "SSL_write_ex()", wsize, 0, false);
}
