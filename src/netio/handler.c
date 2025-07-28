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
#include "internal.h"

// ==========
void socks5_crypto_on_msg(int level, const char *format, ...);
void socks5_crypto_on_bind(const char *host, unsigned short port);
void socks5_crypto_on_stream_connection_made(ADDRESS_PAIR *addr, void *ctx);
void socks5_crypto_on_new_stream(const ADDRESS *addr, void **ctx, void *stream_id);
void socks5_crypto_on_stream_teardown(void *ctx);
void socks5_crypto_on_new_dgram(const ADDRESS_PAIR *addr, void **ctx);
void socks5_crypto_on_dgram_teardown(void *ctx);
int  socks5_crypto_on_plain_stream(const BUF_RANGE *buf, int direct, void *ctx);
void socks5_crypto_on_plain_dgram(const BUF_RANGE *buf, int direct, void *ctx);


// ==========

typedef struct {
    BUF_RANGE   buf;
    uv_write_t  req;
    CONN  *conn;
} snd_ctx;

static void s5netio_write_stream_out_done(uv_write_t *req, int status);

// ReSharper disable once CppParameterMayBeConst
void s5netio_on_msg(int level, const char *format, ...) {
    va_list ap;
    char msg[1024];

    va_start(ap, format);
    vsnprintf(msg, sizeof(msg), format, ap);
    va_end(ap);

    socks5_crypto_on_msg(level, msg);
}

// ReSharper disable once CppParameterMayBeConst
void s5netio_on_bind(const char *host, unsigned short port) {
    socks5_crypto_on_bind(host, port);
}

void s5netio_on_connection_made(PROXY_NODE *pn) {
    ADDRESS_PAIR pair;

    pair.local = &pn->incoming.peer;
    pair.remote = &pn->outgoing.peer;

    socks5_crypto_on_stream_connection_made(&pair, pn->ctx);
}

void s5netio_on_new_stream(const CONN *conn) {
    void *ctx = NULL;

    socks5_crypto_on_new_stream(&conn->peer, &ctx, conn->pn);
    conn->pn->ctx = ctx;
}

void s5netio_on_stream_teardown(const PROXY_NODE *pn) {
    socks5_crypto_on_stream_teardown(pn->ctx);
}

void s5netio_on_new_dgram(ADDRESS *local, ADDRESS *remote, void **ctx) {
    ADDRESS_PAIR pair;

    pair.local = local;
    pair.remote = remote;

    socks5_crypto_on_new_dgram(&pair, ctx);
}

void s5netio_on_dgram_teardown(void *ctx) {
    socks5_crypto_on_dgram_teardown(ctx);
}

int s5netio_on_plain_stream(const CONN *conn) {
    int action;
    const int direct = conn == &conn->pn->incoming ? STREAM_UP : STREAM_DOWN;

    action = socks5_crypto_on_plain_stream(
        &conn->buf,
        direct,
        conn->pn->ctx);

    return action;
}

void s5netio_on_plain_dgram(const BUF_RANGE *buf, const int direct, void *ctx) {

    socks5_crypto_on_plain_dgram(buf, direct, ctx);
}

/* SERVER SIDE ONLY */
int s5netio_write_stream_out(
    // ReSharper disable once CppParameterMayBeConst
    const char *buf,  size_t len, int direct, void *stream_id) {
    int ret = -1;
    PROXY_NODE *pn;
    CONN *conn;
    uv_buf_t buf_t;
    snd_ctx *snd_ctx;

    BREAK_ON_NULL(buf);
    BREAK_ON_FALSE(STREAM_UP == direct || STREAM_DOWN == direct);
    BREAK_ON_NULL(stream_id);

    pn = (PROXY_NODE*)stream_id;
    conn = STREAM_UP == direct ? &pn->outgoing : &pn->incoming;


    snd_ctx = malloc(sizeof(*snd_ctx));
    ASSERT(snd_ctx);
    memset(snd_ctx, 0, sizeof(*snd_ctx));

    snd_ctx->buf.buf_base = malloc(len + 64);
    ASSERT(snd_ctx->buf.buf_base);
    snd_ctx->buf.data_base = snd_ctx->buf.buf_base;
    snd_ctx->buf.buf_len = len + 64;
    snd_ctx->buf.data_len = len;
    memmove(snd_ctx->buf.data_base, buf, len);


    buf_t = uv_buf_init(snd_ctx->buf.data_base, snd_ctx->buf.data_len);

    uv_req_set_data((uv_req_t*)&snd_ctx->req, snd_ctx);
    snd_ctx->conn = conn;

    if ( 0 != uv_write(&snd_ctx->req,
                       &conn->handle.stream,
                       &buf_t,
                       1,
                       s5netio_write_stream_out_done) ) {
        free(snd_ctx);
        do_kill(conn->pn);
        BREAK_NOW;
    }
    conn->pn->outstanding++;
    conn_timer_reset(conn);

    ret = 0;

BREAK_LABEL:

    return ret;
}

static void s5netio_write_stream_out_done(uv_write_t *req, int status) {
    CONN *conn;
    snd_ctx *snd_ctx;

    snd_ctx = uv_req_get_data((uv_req_t*)req);

    conn = snd_ctx->conn;
    conn->pn->outstanding--;

    if ( snd_ctx->buf.buf_base )
        free(snd_ctx->buf.buf_base);
    free(snd_ctx);
}

// ReSharper disable once CppParameterMayBeConst
void s5netio_stream_pause(void *stream_id, int direct, int pause) {
    PROXY_NODE *pn;
    CONN *conn;

    BREAK_ON_NULL(stream_id);
    BREAK_ON_FALSE(STREAM_UP == direct || STREAM_DOWN == direct);

    pn = (PROXY_NODE*)stream_id;
    conn = STREAM_UP == direct ? &pn->outgoing : &pn->incoming;
    if ( pause ) {
        if ( c_busy == conn->rdstate )
            uv_read_stop(&conn->handle.stream);
        if ( c_stop != conn->rdstate )
            conn->rdstate = c_stop;
    } else {
        if ( c_busy != conn->rdstate ) {
            if ( c_stop != conn->rdstate )
                conn->rdstate = c_stop;
            conn_read(conn);
        }
    }

BREAK_LABEL:

    return;
}
