/**
 *  Copyright 2025, LeNidViolet.
 *  Created by LeNidViolet on 2025/7/27.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <stdlib.h>
#include <stdarg.h>
#include <memory.h>
#include "mbedtls/platform.h"
#include "mbedtls/cipher.h"
#include "internal.h"

static unsigned int ssn_outstanding = 0;
static unsigned int dsn_outstanding = 0;


/* TCP流CONTEXT */
typedef struct {
    int index;
    int connected;                                                      /* 是否连接上 */

    int is_tls;                                                         /* 是否是TLS流 */
    void *tls_ctx;                                                      /* TLSFLAT使用的环境CTX */
    void *stream_id;                                                    /* 透明数据,回调时使用 */
} STREAM_SESSION_CRYP;


/* UDP流CONTEXT */
typedef struct {
    int index;
} DGRAM_SESSION_CRYP;


extern crypto_env socks5_env;



// ReSharper disable once CppParameterMayBeConst
void socks5_crypto_on_msg(int level, const char *format, ...) {
    va_list ap;
    char msg[1024];

    va_start(ap, format);
    vsnprintf(msg, sizeof(msg), format, ap);
    va_end(ap);

    if ( socks5_env.callbacks.on_msg ) {
        socks5_env.callbacks.on_msg(level, msg);
    }
}

// ReSharper disable once CppParameterMayBeConst
void socks5_crypto_on_bind(const char *host, unsigned short port) {
    if ( socks5_env.callbacks.on_bind ) {
        socks5_env.callbacks.on_bind(host, port);
    }
}

void socks5_crypto_on_new_stream(const ADDRESS *addr, void **ctx, void *stream_id) {
    static int stream_index = 0;
    STREAM_SESSION_CRYP *session;

    (void)addr;

    ENSURE((session = mbedtls_calloc(1, sizeof(*session))) != NULL);
    memset(session, 0, sizeof(*session));


    session->is_tls = 0;
    session->stream_id = stream_id;
    session->index = stream_index++;
    session->connected = 0;

    *ctx = session;

    ssn_outstanding++;
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
void socks5_crypto_on_stream_connection_made(ADDRESS_PAIR *addr, void *ctx) {
    STREAM_SESSION_CRYP *session;

    session = (STREAM_SESSION_CRYP *)ctx;
    CHECK(session);

    if ( 443 == addr->remote->port ) {              /* 如果是TLS流, 通知TLSFLAT */
        session->is_tls = 1;
        tlsflat_on_stream_connection_made(addr, session->stream_id, session, &session->tls_ctx);
    }

    if ( socks5_env.callbacks.on_stream_connection_made ) {
        socks5_env.callbacks.on_stream_connection_made(
            addr->local->domain,
            addr->local->ip,
            addr->local->port,
            addr->remote->domain,
            addr->remote->ip,
            addr->remote->port,
            session->index
            );
    }

    session->connected = 1;
}

void socks5_crypto_on_stream_teardown(void *ctx) {
    STREAM_SESSION_CRYP *session;
    session = (STREAM_SESSION_CRYP *)ctx;
    CHECK(session);

    if ( session->is_tls ) {
        tlsflat_on_stream_teardown(session->tls_ctx);
    }

    if ( socks5_env.callbacks.on_stream_teardown ) {
        /* 如果链接未链接上 不用继续向上调用 */
        if ( session->connected ) {
            socks5_env.callbacks.on_stream_teardown(session->index);
        }
    }


    if ( DEBUG_CHECKS )
        memset(session, -1, sizeof(*session));

    mbedtls_free(session);

    ssn_outstanding--;
}

void socks5_crypto_on_new_dgram(const ADDRESS_PAIR *addr, void **ctx) {
    static int dgram_index = 0;
    DGRAM_SESSION_CRYP *session;

    ENSURE((session = mbedtls_calloc(1, sizeof(*session))) != NULL);
    memset(session, 0, sizeof(*session));

    session->index = dgram_index++;

    *ctx = session;
    if ( socks5_env.callbacks.on_dgram_connection_made ) {
        socks5_env.callbacks.on_dgram_connection_made(
            addr->local->domain,
            addr->local->ip,
            addr->local->port,
            addr->remote->domain,
            addr->remote->ip,
            addr->remote->port,
            session->index
            );
    }

    dsn_outstanding++;
}

void socks5_crypto_on_dgram_teardown(void *ctx) {
    DGRAM_SESSION_CRYP *session;
    session = (DGRAM_SESSION_CRYP *)ctx;
    CHECK(session);

    if ( socks5_env.callbacks.on_dgram_teardown ) {
        socks5_env.callbacks.on_dgram_teardown(session->index);
    }

    if ( DEBUG_CHECKS )
        memset(session, -1, sizeof(*session));

    mbedtls_free(session);

    dsn_outstanding--;
}

// ReSharper disable once CppParameterMayBeConst
int socks5_crypto_on_plain_stream(const BUF_RANGE *buf, int direct, void *ctx) {
    STREAM_SESSION_CRYP *session;
    int action = PASS;

    session = (STREAM_SESSION_CRYP *)ctx;
    CHECK(session);

    /* 如果是 TLS 数据流, 等待 TLS 解密的回调中再向上通报数据 (socks5_crypto_tls_on_plain_stream) */
    if ( session->is_tls ) {
        action = tlsflat_on_plain_stream(buf, direct, session->tls_ctx);
        BREAK_NOW;
    }

    if ( socks5_env.callbacks.on_plain_stream ) {
        socks5_env.callbacks.on_plain_stream(
            buf->data_base,
            buf->data_len,
            STREAM_UP == direct,
            session->index
            );
    }

BREAK_LABEL:

    return action;
}

/* 由TLSFLAT解密数据之后调用至此 */
// ReSharper disable once CppParameterMayBeConst
void socks5_crypto_tls_on_plain_stream(const char *data, size_t data_len, int direct, void *ss_ctx) {
    STREAM_SESSION_CRYP *session;

    session = (STREAM_SESSION_CRYP *)ss_ctx;
    CHECK(session);

    if ( socks5_env.callbacks.on_plain_stream ) {
        socks5_env.callbacks.on_plain_stream(
            data,
            data_len,
            STREAM_UP == direct,
            session->index
            );
    }
}

// ReSharper disable once CppParameterMayBeConst
void socks5_crypto_on_plain_dgram(const BUF_RANGE *buf, int direct, void *ctx) {
    DGRAM_SESSION_CRYP *session;

    session = (DGRAM_SESSION_CRYP *)ctx;
    CHECK(session);

    if ( socks5_env.callbacks.on_plain_dgram ) {
        socks5_env.callbacks.on_plain_dgram(
            buf->data_base,
            buf->data_len,
            STREAM_UP == direct,
            session->index);
    }
}
