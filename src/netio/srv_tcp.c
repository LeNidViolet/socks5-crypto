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
#include "socks5-crypto/socks5-crypto.h"
#include "dns_cache.h"


// ==========


static int pn_outstanding = 0;


static void on_connection(uv_stream_t *server, int status);


static void tcpsrv_handle_close_done(uv_handle_t* handle) {
    if ( handle ) {
        free(handle);
    }
}

static void tcpsrv_handle_close(uv_tcp_t *handle) {
    // ReSharper disable once CppDFAConstantConditions
    if ( handle ) {
        // TODO: tcp 句柄更多清理
        uv_close((uv_handle_t*)handle, tcpsrv_handle_close_done);
    }
}

/* 启动 TCP 服务 */
int server_tcp_launch(uv_loop_t *loop, const struct sockaddr *addr) {
    int ret = -1;
    uv_tcp_t *tcp_handle = NULL;
    ADDRESS address = {0};

    BREAK_ON_NULL(loop);
    BREAK_ON_NULL(addr);

    CHECK(0 == sockaddr_to_str(addr, &address, 1));

    ENSURE((tcp_handle = malloc(sizeof(*tcp_handle))) != NULL);
    CHECK(0 == uv_tcp_init(loop, tcp_handle));

    ret = uv_tcp_bind(tcp_handle, addr, 0);
    if ( 0 != ret ) {
        netio_on_msg(
            LOG_ERROR,
            "tcp bind to %s:%d failed: %s",
            address.ip,
            address.port,
            uv_strerror(ret));
        BREAK_NOW;
    }

    ret = uv_listen((uv_stream_t *)tcp_handle, SOMAXCONN, on_connection);
    if ( 0 != ret ) {
        netio_on_msg(
            LOG_ERROR,
            "tcp listen to %s:%d failed: %s",
            address.ip,
            address.port,
            uv_strerror(ret));
        BREAK_NOW;
    }

    tcp_handle = NULL;

BREAK_LABEL:

    if ( tcp_handle ) {
        tcpsrv_handle_close(tcp_handle);
    }

    return ret;
}




// ===========
// ===========
extern socks5_server_config srv_cfg;
extern SERVER_ADDRESSES srv_addrs;
static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void conn_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void conn_timer_expire(uv_timer_t *handle);
static void conn_write(CONN *conn, const void *data, unsigned int len);
static void conn_write_done(uv_write_t *req, int status);
static int  conn_connect(CONN *conn);
static void conn_connect_done(uv_connect_t *req, int status);
static void conn_close(CONN *conn);
static void conn_close_done(uv_handle_t *handle);
static int  conn_cycle(const char *who, CONN *recver, CONN *sender);
static void conn_timer_expire_server(uv_timer_t *handle);
static void conn_getaddrinfo_done(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);
static void conn_getaddrinfo(CONN *conn, const char *hostname);

static int  do_handshake_s5(PROXY_NODE *pn);
static int  do_handshake_ss(PROXY_NODE *pn);
static int  do_req_start(PROXY_NODE *pn);
static int  do_req_parse(PROXY_NODE *pn);
static int  do_req_connect(PROXY_NODE *pn);
static int  do_proxy_start(PROXY_NODE *pn);
static int  do_proxy(CONN *sender);
static int  do_dgram_start(PROXY_NODE *pn);
static int  do_dgram_stop(PROXY_NODE *pn);
static int  do_req_lookup(PROXY_NODE *pn);
static int  do_req_connect_start(PROXY_NODE *pn);
static int  do_dgram_response(PROXY_NODE *pn);

static void do_next(CONN *sender);
static int  do_almost_dead(const PROXY_NODE *pn);
static int  do_clear(PROXY_NODE *pn);
static void do_next_server(CONN *sender);






/* 入口点 代理链接到来 */
// ReSharper disable once CppParameterMayBeConst
static void on_connection(uv_stream_t *server, int status) {
    static unsigned int index = 0;
    uv_loop_t *loop;
    PROXY_NODE *pn;
    CONN *incoming;
    CONN *outgoing;

    BREAK_ON_FALSE(0 == status);

    loop = uv_handle_get_loop((uv_handle_t *)server);

    ENSURE((pn = malloc(sizeof(*pn))) != NULL);
    memset(pn, 0, sizeof(*pn));

    pn_outstanding++;

    pn->state = s_handshake;
    pn->outstanding = 0;
    pn->index = index++;
    pn->loop = loop;
    pn->ctx = NULL;
    s5_init(&pn->parser);

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    CHECK(0 == uv_tcp_init(loop, &incoming->handle.tcp));
    CHECK(0 == uv_accept(server, &incoming->handle.stream));
    uv_handle_set_data(&incoming->handle.handle, incoming);
    incoming->pn = pn;
    incoming->result = 0;
    incoming->rdstate = c_stop;
    incoming->wrstate = c_stop;
    incoming->idle_timeout = srv_cfg.config.idel_timeout;
    CHECK(0 == uv_timer_init(loop, &incoming->timer_handle));

    CHECK(0 == uv_tcp_init(loop, &outgoing->handle.tcp));
    uv_handle_set_data(&outgoing->handle.handle, outgoing);
    outgoing->pn = pn;
    outgoing->result = 0;
    outgoing->rdstate = c_stop;
    outgoing->wrstate = c_stop;
    outgoing->idle_timeout = srv_cfg.config.idel_timeout;
    CHECK(0 == uv_timer_init(loop, &outgoing->timer_handle));

    incoming->buf.buf_base = incoming->buf.data_base = incoming->slab;
    incoming->buf.buf_len = sizeof(incoming->slab);
    incoming->buf.data_len = 0;

    outgoing->buf.buf_base = outgoing->buf.data_base = outgoing->slab;
    outgoing->buf.buf_len = sizeof(outgoing->slab);
    outgoing->buf.data_len = 0;


    // 设置 incoming.peer.ip
    CHECK(0 == str_tcp_endpoint(&incoming->handle.tcp, peer, &incoming->peer));

    // incoming.peer.ip 是 ip 字符串, 拷贝到domain中
    strcpy(incoming->peer.domain, incoming->peer.ip);

    /* Emit notify */
    netio_on_new_stream(incoming);

    /* Wait for the initial packet. */
    conn_read(incoming);

BREAK_LABEL:

    return;
}

// ReSharper disable once CppParameterMayBeConst
// ReSharper disable once CppParameterMayBeConstPtrOrRef
static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    CONN *conn;

    (void)size;

    conn = uv_handle_get_data(handle);

    buf->base = conn->buf.buf_base;
    buf->len = conn->buf.buf_len;
}

void conn_read(CONN *conn) {
    ASSERT(c_stop == conn->rdstate);

    if( 0 != uv_read_start(
        &conn->handle.stream,
        conn_alloc,
        conn_read_done) ) {

        do_kill(conn->pn);
        BREAK_NOW;
    }
    conn->rdstate = c_busy;
    conn_timer_reset(conn);

BREAK_LABEL:

    return;
}

// ReSharper disable once CppParameterMayBeConst
static void conn_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    CONN *conn;

    conn = uv_handle_get_data((uv_handle_t*)handle);
    ASSERT(conn->buf.buf_base == buf->base);
    ASSERT(c_busy == conn->rdstate);
    conn->rdstate = c_done;
    conn->result = nread;

    conn->buf.data_base = buf->base;
    conn->buf.data_len = nread;
    uv_read_stop(&conn->handle.stream);
    do_next(conn);
}

// ReSharper disable once CppParameterMayBeConst
static void conn_write(CONN *conn, const void *data, unsigned int len) {
    uv_buf_t buf;

    ASSERT(c_stop == conn->wrstate || c_done == conn->wrstate);
    conn->wrstate = c_busy;

    buf = uv_buf_init((char*)data, len);

    if ( 0 != uv_write(&conn->write_req,
                       &conn->handle.stream,
                       &buf,
                       1,
                       conn_write_done) ) {
        do_kill(conn->pn);
        BREAK_NOW;
    }
    conn->pn->outstanding++;
    conn_timer_reset(conn);

BREAK_LABEL:

    return;
}

// ReSharper disable once CppParameterMayBeConst
static void conn_write_done(uv_write_t *req, int status) {
    CONN *conn;

    conn = CONTAINER_OF(req, CONN, write_req);
    conn->pn->outstanding--;
    ASSERT(c_busy == conn->wrstate);
    conn->wrstate = c_done;
    conn->result = status;

    do_next(conn);
}

// ReSharper disable once CppParameterMayBeConst
static void conn_connect_done(uv_connect_t *req, int status) {
    CONN *conn;

    conn = CONTAINER_OF(req, CONN, req.connect_req);
    conn->result = status;

    conn->pn->outstanding--;
    do_next(conn);
}

static void conn_close(CONN *conn) {
    ASSERT(c_dead != conn->rdstate);
    ASSERT(c_dead != conn->wrstate);
    conn->rdstate = c_dead;
    conn->wrstate = c_dead;
    uv_handle_set_data((uv_handle_t*)&conn->timer_handle, conn);
    uv_handle_set_data(&conn->handle.handle, conn);
    uv_close(&conn->handle.handle, conn_close_done);
    uv_close((uv_handle_t*)&conn->timer_handle, conn_close_done);
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
static void conn_close_done(uv_handle_t *handle) {
    CONN *conn;

    conn = uv_handle_get_data(handle);
    do_next(conn);
}

void conn_timer_reset(CONN *conn) {
    CHECK(0 == uv_timer_start(&conn->timer_handle,
                              conn_timer_expire,
                              conn->idle_timeout,
                              0));
}

static void conn_timer_expire(uv_timer_t *handle) {
    conn_timer_expire_server(handle);
}

static void conn_timer_expire_server(uv_timer_t *handle) {
    CONN *conn;
    CONN *incoming;
    CONN *outgoing;

    conn = CONTAINER_OF(handle, CONN, timer_handle);

    incoming = &conn->pn->incoming;
    outgoing = &conn->pn->outgoing;

    switch ( conn->pn->state ) {
    case s_handshake:
    case s_req_start:
    case s_req_parse:
    case s_dgram_start:
    case s_dgram_stop:
        ASSERT(conn == incoming);
        incoming->result = UV_ETIMEDOUT;
        break;
    case s_req_lookup:
    case s_req_connect:
    case s_proxy_start:
        outgoing->result = UV_ETIMEDOUT;
        break;
    default:
        conn->result = UV_ETIMEDOUT; /* s_proxy, .. */
        break;
    }

    do_next_server(conn);
}

static int conn_cycle(const char *who, CONN *recver, CONN *sender) {
    if ( recver->result < 0 ) {
        if ( UV_EOF != recver->result ) {
            netio_on_msg(
                LOG_WARN,
                "%4d %s error: %s [%s]",
                recver->pn->index,
                who,
                uv_strerror((int)recver->result),
                recver->pn->link_info);
        }

        return -1;
    }

    if ( sender->result < 0 ) {
        return -1;
    }

    if ( c_done == recver->wrstate ) {
        recver->wrstate = c_stop;
    }

    /* The logic is as follows: read when we don't write and write when we don't
     * read.  That gives us back-pressure handling for free because if the peer
     * sends data faster than we consume it, TCP congestion control kicks in.
     */
    if ( c_stop == recver->wrstate ) {
        if ( c_stop == sender->rdstate ) {
            conn_read(sender);
        }
        else if ( c_done == sender->rdstate ) {
            conn_write(recver, sender->buf.buf_base, (unsigned int)sender->result);
            sender->rdstate = c_stop;  /* Triggers the call to conn_read() above. */
        }
    }

    return 0;
}


// ==========
static int do_proxy_start(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int new_state;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( outgoing->result < 0 ) {
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    if (srv_cfg.config.asSocks5 == 0) {
        ASSERT(c_stop == incoming->rdstate);
        ASSERT(c_stop == incoming->wrstate);
        ASSERT(c_stop == outgoing->rdstate);
        ASSERT(c_done == outgoing->wrstate);
    } else {
        ASSERT(c_stop == incoming->rdstate);
        ASSERT(c_done == incoming->wrstate);
        ASSERT(c_stop == outgoing->rdstate);
        ASSERT(c_stop == outgoing->wrstate);
    }

    outgoing->wrstate = c_stop;

    conn_read(incoming);
    conn_read(outgoing);

    new_state = s_proxy;

BREAK_LABEL:

    return new_state;
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
static int do_proxy(CONN *sender) {
    int new_state = s_proxy, encrypt = 0, action;
    CONN *incoming;
    CONN *outgoing;

    incoming = &sender->pn->incoming;
    outgoing = &sender->pn->outgoing;

    if ( c_done == sender->rdstate && sender->result >= 0 ) {
        if (srv_cfg.config.asSocks5 == 0) {
            encrypt = sender == outgoing;

            if ( encrypt ) {
                sender->buf.data_len = (size_t)sender->result;
                action = netio_on_plain_stream(sender);
                switch (action) {
                    case PASS:
                        break;

                    case NEEDMORE:
                    case REJECT:
                        BREAK_NOW;

                    case TERMINATE:
                        new_state = do_kill(incoming->pn);
                        BREAK_NOW;
                    default:
                        UNREACHABLE();
                }

                if ( 0 != netio_on_stream_encrypt(sender, 0) ) {
                    new_state = do_kill(incoming->pn);
                    BREAK_NOW;
                }
            } else {
                if ( 0 != netio_on_stream_decrypt(sender, 0) ) {
                    new_state = do_kill(incoming->pn);
                    BREAK_NOW;
                }

                action = netio_on_plain_stream(sender);
                switch (action) {
                    case PASS:
                        break;

                    case NEEDMORE:
                    case REJECT:
                        BREAK_NOW;

                    case TERMINATE:
                        new_state = do_kill(incoming->pn);
                        BREAK_NOW;
                    default:
                        UNREACHABLE();
                }
            }
        } else {
            action = netio_on_plain_stream(sender);
            switch (action) {
                case PASS:
                    break;

                case NEEDMORE:
                case REJECT:
                    BREAK_NOW;

                case TERMINATE:
                    new_state = do_kill(incoming->pn);
                    BREAK_NOW;
                default:
                    UNREACHABLE();
            }
        }
    }

    if ( 0 != conn_cycle("client", incoming, outgoing) ) {
        new_state = do_kill(incoming->pn);
        BREAK_NOW;
    }

    if ( 0 != conn_cycle("upstream", outgoing, incoming) ) {
        new_state = do_kill(incoming->pn);
        BREAK_NOW;
    }

BREAK_LABEL:

    return new_state;
}

int do_kill(PROXY_NODE *pn) {
    int new_state;

    if ( 0 != pn->outstanding ) {
        /* Wait for uncomplete operations */
        netio_on_msg(
            LOG_INFO,
            "%4d waitting outstanding operation: %d [%s]",
            pn->index, pn->outstanding, pn->link_info);
        new_state = s_kill;
        BREAK_NOW;
    }

    if ( pn->state >= s_almost_dead_0 ) {
        new_state = pn->state;
        BREAK_NOW;
    }

    conn_close(&pn->incoming);
    conn_close(&pn->outgoing);

    new_state = s_almost_dead_1;

BREAK_LABEL:

    return new_state;
}

static int do_almost_dead(const PROXY_NODE *pn) {
    ASSERT(pn->state >= s_almost_dead_0);
    return pn->state + 1;  /* Another finalizer completed. */
}

static int do_clear(PROXY_NODE *pn) {
    netio_on_stream_teardown(pn);

    if ( DEBUG_CHECKS ) {
        memset(pn, -1, sizeof(*pn));
    }
    free(pn);
    pn_outstanding--;

    if ( 0 == pn_outstanding )
        netio_on_msg(LOG_INFO, "pn outstanding return to 0");

    return 0;
}

static void do_next(CONN *sender) {
    do_next_server(sender);
}


static void conn_getaddrinfo_done(
    // ReSharper disable once CppParameterMayBeConst
    uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    CONN *incoming;
    CONN *outgoing;
    struct addrinfo *ai;
    struct addrinfo *ai_ipv4 = NULL;
    struct addrinfo *ai_ipv6 = NULL;

    outgoing = CONTAINER_OF(req, CONN, req.addrinfo_req);
    ASSERT(outgoing == &outgoing->pn->outgoing);
    outgoing->result = status;

    incoming = &outgoing->pn->incoming;

    if ( 0 == status ) {
        for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
            dns_cache_add(outgoing->peer.domain, ai->ai_addr);

            if ( AF_INET == ai->ai_family && !ai_ipv4 ) {
                ai_ipv4 = ai;
            }
            if ( AF_INET6 == ai->ai_family && !ai_ipv6 ) {
                ai_ipv6 = ai;
            }
        }

        // 更新 remote.t.addr
        if (ai_ipv4) {
            sockaddr_cpy(ai_ipv4->ai_addr, &outgoing->addr.addr);
        } else if (ai_ipv6) {
            sockaddr_cpy(ai_ipv6->ai_addr, &outgoing->addr.addr);
        }
        sockaddr_set_port(&outgoing->addr.addr, outgoing->peer.port);

        /* 设置UPSTREAM远端 IP信息 */
        sockaddr_to_str(&outgoing->addr.addr, &outgoing->peer, 0);
    }

    uv_freeaddrinfo(addrs);

    incoming->pn->outstanding--;
    do_next_server(incoming);
}


static void do_next_server(CONN *sender) {
    int new_state;
    PROXY_NODE *pn = sender->pn;

    ASSERT(s_dead != pn->state);
    switch (pn->state) {
    case s_handshake:
        if (srv_cfg.config.asSocks5 == 0) {
            new_state = do_handshake_ss(pn);
        } else {
            new_state = do_handshake_s5(pn);
        }
        break;
    case s_req_start:
        new_state = do_req_start(pn);
        break;
    case s_req_parse:
        new_state = do_req_parse(pn);
        break;
    case s_req_lookup:
        new_state = do_req_lookup(pn);
        break;
    case s_req_connect:
        new_state = do_req_connect(pn);
        break;
    case s_dgram_start:
        new_state = do_dgram_start(pn);
        break;
    case s_dgram_stop:
        new_state = do_dgram_stop(pn);
        break;
    case s_proxy_start:
        new_state = do_proxy_start(pn);
        break;
    case s_proxy:
        new_state = do_proxy(sender);
        break;
    case s_kill:
        new_state = do_kill(pn);
        break;
    case s_almost_dead_0:
    case s_almost_dead_1:
    case s_almost_dead_2:
    case s_almost_dead_3:
    case s_almost_dead_4:
        new_state = do_almost_dead(pn);
        break;
    default:
        UNREACHABLE();
    }
    pn->state = new_state;

    if ( s_dead == pn->state )
        do_clear(pn);
}



static int do_handshake_ss(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int ret, new_state;
    struct addrinfo hints;
    const char *host;
    struct sockaddr* addr;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( incoming->result < 0 ) {
        netio_on_msg(LOG_WARN, "%4d handshake read error: %s",
                       pn->index, uv_strerror((int)incoming->result));
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_done == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    incoming->rdstate = c_stop;

    if ( 0 != netio_on_stream_decrypt(incoming, 0) ) {
        netio_on_msg(LOG_WARN, "%4d handshake data decrypt failed", pn->index);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    /* Parser to get dest address  解析之后填充 outgoing.peer.domain */
    ret = s5_parse_addr(&incoming->buf, &outgoing->peer);
    if ( 0 != ret ) {
        netio_on_msg(LOG_WARN, "%4d handshake parse addr error", pn->index);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    /* Maybe it's an ip address in string form */
    if ( 0 == uv_ip4_addr(outgoing->peer.domain, outgoing->peer.port, &outgoing->addr.addr4) ||
         0 == uv_ip6_addr(outgoing->peer.domain, outgoing->peer.port, &outgoing->addr.addr6)) {

        // 拷贝到 outgoing.peer.ip
        strcpy(outgoing->peer.ip, outgoing->peer.domain);

        host = dns_cache_find_host(&outgoing->addr.addr);
        if ( host ) {
            memset(outgoing->peer.domain, 0, sizeof(outgoing->peer.domain));
            strcpy(outgoing->peer.domain, host);
        }

        new_state = do_req_lookup(pn);
        BREAK_NOW;
    }

    addr = dns_cache_find_ip(outgoing->peer.domain, 1);
    if ( !addr ) {
        addr = dns_cache_find_ip(outgoing->peer.domain, 0);
    }
    if ( addr ) {
        // 拷贝到 outgoing.peer.ip
        sockaddr_to_str(addr, &outgoing->peer, 0);

        sockaddr_cpy(addr, &outgoing->addr.addr);
        sockaddr_set_port(&outgoing->addr.addr, outgoing->peer.port);
        new_state = do_req_lookup(pn);

    } else {
        // 进行DNS查询
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if ( 0 != uv_getaddrinfo(pn->loop,
                                 &outgoing->req.addrinfo_req,
                                 conn_getaddrinfo_done,
                                 outgoing->peer.domain,
                                 NULL,
                                 &hints) ) {
            new_state = do_kill(pn);
            BREAK_NOW;
        }

        pn->outstanding++;
        conn_timer_reset(outgoing);

        new_state = s_req_lookup;
    }

BREAK_LABEL:

    return new_state;
}



static int do_handshake_s5(PROXY_NODE *pn) {
    CONN *incoming;
    int new_state;
    int err;
    uint8_t *data_pos;
    size_t data_len;
    unsigned int methods;

    incoming = &pn->incoming;

    if ( incoming->result < 0 ) {
        netio_on_msg(LOG_WARN, "%4d handshake read error: %s",
                       pn->index, uv_strerror((int)incoming->result));
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_done == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    incoming->rdstate = c_stop;

    data_pos = (uint8_t *)incoming->buf.buf_base,
    data_len = (size_t)incoming->result;
    err = s5_parse(&pn->parser, &data_pos, &data_len);
    if ( s5_ok == err ) {
        conn_read(incoming);
        // 数据不足 继续读取数据
        new_state = s_req_parse;
        BREAK_NOW;
    }

    if ( 0 != data_len ) {
        netio_on_msg(LOG_ERROR, "%4d Junk in equest %u", pn->index, (unsigned)data_len);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    if ( s5_auth_select != err ) {
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    methods = s5_auth_methods(&pn->parser);
    if ( methods & (unsigned int)S5_AUTH_NONE ) {
        s5_select_auth(&pn->parser, S5_AUTH_NONE);
        conn_write(incoming, "\5\0", 2);  /* No auth required. */
        new_state = s_req_start;
    } else {
        conn_write(incoming, "\5\255", 2);  /* No acceptable auth. */
        new_state = s_kill;
    }

BREAK_LABEL:

    return new_state;
}

static int do_req_start(PROXY_NODE *pn) {
    CONN *incoming;
    int new_state;

    incoming = &pn->incoming;

    if ( incoming->result < 0 ) {
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_stop == incoming->rdstate);
    ASSERT(c_done == incoming->wrstate);
    incoming->wrstate = c_stop;

    conn_read(incoming);

    new_state = s_req_parse;

BREAK_LABEL:

    return new_state;
}


static int do_req_parse(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int new_state, err;
    s5_ctx *parser;
    uint8_t *data_pos;
    size_t data_len;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( incoming->result < 8 ) {  /* |VER|CMD|RSV|ATYP|DST.ADDR|DST.PORT|DATA */
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_done == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    ASSERT(c_stop == outgoing->rdstate);
    ASSERT(c_stop == outgoing->wrstate);
    incoming->rdstate = c_stop;

    parser = &pn->parser;
    data_pos = (uint8_t *)incoming->buf.buf_base;
    data_len = (size_t)incoming->result;
    err = s5_parse(parser, &data_pos, &data_len);
    if ( s5_ok == err ) {
        conn_read(incoming);
        new_state = s_req_parse;
        BREAK_NOW;
    }

    if ( 0 != data_len ) {
        netio_on_msg(LOG_ERROR, "%4d Junk in equest %u", pn->index, (unsigned)data_len);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    if ( s5_exec_cmd != err ) {
        netio_on_msg(LOG_ERROR, "%4d Request error: %s", pn->index, s5_strerror((s5_err)err));
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    if ( s5_cmd_tcp_bind == parser->cmd ) {
        /* Not supported */
        netio_on_msg(LOG_ERROR, "%4d Bind requests are not supported.", pn->index);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    if ( s5_cmd_udp_assoc == parser->cmd ) {
        new_state = do_dgram_response(pn);
        BREAK_NOW;
    }

    if ( s5_cmd_tcp_connect != parser->cmd ) {
        netio_on_msg(LOG_ERROR, "%4d Unknow s5 command %d.", pn->index, parser->cmd);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    // 这里有可能拿到的是域名, 这种情况下, t.addr 不会被赋值
    s5_addr_copy(parser, &outgoing->addr.addr, &outgoing->peer);

    if ( s5_atyp_host == parser->atyp ) {
        conn_getaddrinfo(outgoing, (const char*)parser->daddr);
        new_state = s_req_lookup;
        BREAK_NOW;
    }

    new_state = do_req_connect_start(pn);

BREAK_LABEL:

    return new_state;
}

static void conn_getaddrinfo(CONN *conn, const char *hostname) {
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    CHECK(0 == uv_getaddrinfo(conn->pn->loop,
                              &conn->req.addrinfo_req,
                              conn_getaddrinfo_done,
                              hostname,
                              NULL,
                              &hints));
    conn->pn->outstanding++;
    conn_timer_reset(conn);
}

static int conn_connect(CONN *conn) {
    int ret;

    ASSERT(AF_INET == conn->addr.addr.sa_family ||
           AF_INET6 == conn->addr.addr.sa_family);

    ret = uv_tcp_connect(&conn->req.connect_req,
                         &conn->handle.tcp,
                         &conn->addr.addr,
                         conn_connect_done);
    if ( 0 == ret ) {
        conn->pn->outstanding++;
        conn_timer_reset(conn);
    }

    return ret;
}


static int do_req_lookup(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int ret;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( outgoing->result < 0 ) {
        netio_on_msg(LOG_WARN, "%4d lookup error for %s : %s",
                       pn->index,
                       outgoing->peer.domain,
                       uv_strerror((int)outgoing->result));

        ret = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_stop == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    ASSERT(c_stop == outgoing->rdstate);
    ASSERT(c_stop == outgoing->wrstate);

    ASSERT(AF_INET == outgoing->addr.addr.sa_family ||
           AF_INET6 == outgoing->addr.addr.sa_family);

    if ( 0 != uv_tcp_connect(&outgoing->req.connect_req,
                             &outgoing->handle.tcp,
                             &outgoing->addr.addr,
                             conn_connect_done) ) {
        ret = do_kill(pn);
        BREAK_NOW;
    }

    pn->outstanding++;
    conn_timer_reset(outgoing);

    ret = s_req_connect;

BREAK_LABEL:

    return ret;
}


static int do_req_connect_start(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int err, new_state;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;
    ASSERT(c_stop == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    ASSERT(c_stop == outgoing->rdstate);
    ASSERT(c_stop == outgoing->wrstate);

    err = conn_connect(outgoing);
    if ( err != 0 ) {
        netio_on_msg(LOG_ERROR, "%4d Connect error: %s", pn->index, uv_strerror(err));
        new_state = do_kill(pn);
    } else {
        new_state = s_req_connect;
    }

    return new_state;
}


static int do_req_connect(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int addrlen;
    int new_state, action;
    char *host;
    char addr_storage[sizeof(struct sockaddr_in6)];
    static char ipv4_reply[] = { "\5\0\0\1\0\0\0\0\16\16" };
    static char ipv6_reply[] = { "\5\0\0\4"
                                 "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                 "\10\10" };

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( 0 != outgoing->result ) {
        netio_on_msg(
            LOG_WARN,
            "%4d connect to %s:%d failed: %s",
            pn->index,
            outgoing->peer.domain,
            outgoing->peer.port,
            uv_strerror((int)outgoing->result));
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_stop == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    ASSERT(c_stop == outgoing->rdstate);
    ASSERT(c_stop == outgoing->wrstate);


    if (srv_cfg.config.asSocks5 != 0) {
        /* 替换成可读性更高的域名 */
        host = (char*)dns_cache_find_host(&outgoing->addr.addr);
        if ( host ) {
            memset(outgoing->peer.domain, 0, sizeof(outgoing->peer.domain));
            strcpy(outgoing->peer.domain, host);
        }
    }

    netio_on_connection_made(pn);

    snprintf(pn->link_info, sizeof(pn->link_info), "%s:%d -> %s:%d",
             incoming->peer.domain,
             incoming->peer.port,
             outgoing->peer.domain,
             outgoing->peer.port);

    if (srv_cfg.config.asSocks5 == 0) {

        if ( 0 == incoming->buf.data_len ) {
            conn_read(incoming);
            conn_read(outgoing);
            new_state = s_proxy;
        } else {
            action = netio_on_plain_stream(incoming);
            switch (action) {
                case PASS:
                    break;

                case NEEDMORE:
                case REJECT:
                    new_state = s_proxy;
                    BREAK_NOW;

                case TERMINATE:
                    new_state = do_kill(pn);
                    BREAK_NOW;
                default:
                    UNREACHABLE();
            }

            conn_write(
                outgoing,
                incoming->buf.data_base,
                (unsigned int)incoming->buf.data_len);
            new_state = s_proxy_start;
        }

    } else {

        addrlen = sizeof(addr_storage);
        if ( 0 != uv_tcp_getsockname(&outgoing->handle.tcp,
                                     (struct sockaddr *) addr_storage,
                                     &addrlen) ) {
            new_state = do_kill(pn);
            BREAK_NOW;
                                     }

        if ( addrlen == sizeof(struct sockaddr_in) ) {
            conn_write(incoming, ipv4_reply, 10);
        } else if ( addrlen == sizeof(struct sockaddr_in6) ) {
            conn_write(incoming, ipv6_reply, 22);
        } else {
            UNREACHABLE();
        }

        new_state = s_proxy_start;
    }

BREAK_LABEL:

    return new_state;
}



// ReSharper disable once CppDFAConstantFunctionResult
// ReSharper disable once CppParameterMayBeConstPtrOrRef
static int do_dgram_response(PROXY_NODE *pn) {
    int ret;
    CONN *incoming;

    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } addr = {};
    int addr_len;
    void *p_addr;
    unsigned short port;
    char *p;

    // 返回固定端口
    if (pn->parser.atyp == s5_atyp_ipv4) {
        uv_ip4_addr(srv_addrs.addrv4_str, srv_cfg.config.bind_port, &addr.addr4);
    } else {
        uv_ip6_addr(srv_addrs.addrv6_str, srv_cfg.config.bind_port, &addr.addr6);
    }

    p_addr = addr.addr.sa_family ==
             AF_INET ? (void*)&addr.addr4.sin_addr : (void*)&addr.addr6.sin6_addr;
    addr_len = addr.addr.sa_family ==
               AF_INET ? sizeof(addr.addr4.sin_addr) : sizeof(addr.addr6.sin6_addr);
    port = addr.addr.sa_family ==
           AF_INET6 ? addr.addr4.sin_port : addr.addr6.sin6_port;

    /* Tell socks5 app udp adderss */
    /* struct s5 pkt */
    incoming = &pn->incoming;
    p = incoming->buf.buf_base;
    *p++ = (char)'\5';
    *p++ = (char)'\0';
    *p++ = (char)'\0';
    *p++ = addr.addr.sa_family == AF_INET ? (char)'\1' : (char)'\4';

    memcpy(p, p_addr, addr_len);
    p += addr_len;

    memcpy(p, &port, sizeof(port));
    p += sizeof(port);


    conn_write(incoming, incoming->buf.buf_base, (unsigned int)(p - incoming->buf.buf_base));

    ret = s_dgram_start;

BREAK_LABEL:

    return ret;
}


static int do_dgram_start(PROXY_NODE *pn) {
    CONN *incoming;
    int ret;

    incoming = &pn->incoming;

    if ( incoming->result < 0 ) {
        ret = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_stop == incoming->rdstate);
    ASSERT(c_done == incoming->wrstate);
    incoming->wrstate = c_stop;

    // 我们不把TCP与UDP关联, TCP就等待客户端断开连接, 所以不能让它主动超时
    pn->incoming.idle_timeout = 12 * 60 * 60 * 1000;
    pn->outgoing.idle_timeout = 12 * 60 * 60 * 1000;

    /* Wait EOF */
    conn_read(incoming);

    ret = s_dgram_stop;

BREAK_LABEL:

    return ret;
}

static int do_dgram_stop(PROXY_NODE *pn) {
    CONN *incoming;

    incoming = &pn->incoming;

    ASSERT(c_stop == incoming->wrstate);
    incoming->rdstate = c_stop;

    /* It should be EOF or read error or timer expire */
    ASSERT(incoming->result < 0);

    return do_kill(pn);
}
