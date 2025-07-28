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
#include "dns_cache.h"
#include "dgramsc.h"
#include "socks5-crypto/socks5-crypto.h"

// ==========

extern socks5_crypto_ctx srv_ctx;

static int dgram_read_local(uv_udp_t *handle);

static void dgramsrv_handle_close_done(uv_handle_t* handle) {
    if ( handle ) {
        free(handle);
    }
}

static void dgramsrv_handle_close(uv_udp_t *handle) {
    BUF_RANGE *buf;

    // ReSharper disable once CppDFAConstantConditions
    if ( handle ) {
        buf = uv_handle_get_data((uv_handle_t*)handle);
        if ( buf ) {
            if ( buf->buf_base )
                free(buf->buf_base);
            free(buf);
        }

        uv_udp_recv_stop(handle);
        uv_close((uv_handle_t*)handle, dgramsrv_handle_close_done);
    }
}


/* 启动 dgram 服务 */
int server_dgram_launch(uv_loop_t *loop, const struct sockaddr *addr) {
    uv_udp_t *udp_handle = NULL;
    int ret = -1;
    BUF_RANGE *buf;

    BREAK_ON_NULL(loop);
    BREAK_ON_NULL(addr);

    ENSURE((udp_handle = malloc(sizeof(*udp_handle))) != NULL);
    CHECK(0 == uv_udp_init(loop, udp_handle));

    /* associate buf to handle */
    ENSURE((buf = malloc(sizeof(*buf))) != NULL);
    ENSURE((buf->buf_base = malloc(MAX_UDP_PAYLOAD_LEN)) != NULL);
    buf->buf_len     = MAX_UDP_PAYLOAD_LEN;

    uv_handle_set_data((uv_handle_t*)udp_handle, buf);

    ret = uv_udp_bind(udp_handle, addr, 0);
    BREAK_ON_FAILURE(ret);

    CHECK(0 == dgram_read_local(udp_handle));

    udp_handle = NULL;

BREAK_LABEL:

    if ( udp_handle ) {
        dgramsrv_handle_close(udp_handle);
    }

    return ret;
}



// ==========
static void dgram_alloc_cb_local(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void dgram_read_done_local(
    uv_udp_t *handle, ssize_t nread,
    const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);
static void dgram_send_remote(DGRAMS *ds);
static void dgram_send_done_remote(uv_udp_send_t *req, int status);
static void dgram_read_remote(DGRAMS *ds);
static void dgram_alloc_cb_remote(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void dgram_read_done_remote(
    uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
    const struct sockaddr *addr, unsigned flags);
static void dgram_getaddrinfo_done(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);
static void dgram_lookup(DGRAMS *ds);
static void dgram_send_local(DGRAMS *ds, const uv_buf_t *buf);
static void dgram_send_done_local(uv_udp_send_t *req, int status);
static void dgram_timer_reset(DGRAMS *ds);
static void dgram_timer_expire(uv_timer_t *handle);
static void dgram_bind(DGRAMS *ds);


static int dgram_read_local(uv_udp_t *handle) {
    return uv_udp_recv_start(handle, dgram_alloc_cb_local, dgram_read_done_local);
}

static void dgram_alloc_cb_local(
    // ReSharper disable once CppParameterMayBeConstPtrOrRef
    uv_handle_t *handle,
    // ReSharper disable once CppParameterMayBeConst
    size_t suggested_size,
    uv_buf_t *buf) {
    BUF_RANGE *buf_r;

    (void)suggested_size;

    /* Each listening udp handle has an associated buf for recv data */
    buf_r       = uv_handle_get_data(handle);
    buf->base   = buf_r->buf_base;
    buf->len    = buf_r->buf_len;
}

/* 只通过一个UDP句柄进行监听. 所以通讯联系是一对多的关系
 * 每次有数据到来, 都暂停接收数据直到本次数据发送出去
 */
static void dgram_read_done_local(
    uv_udp_t *handle, const ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    const unsigned flags) {

    BUF_RANGE *buf_r;
    ADDRESS srv_addr = {0};
    ADDRESS clt_addr = {0};
    char key[128];
    DGRAMS *ds;
    uv_loop_t *loop;
    uint8_t *data_pos;
    size_t data_len;
    int err;
    s5_ctx parser;
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } remote_sockaddr = {};

    (void)flags;

    if ( nread <= 0 )
        BREAK_NOW;

    buf_r = uv_handle_get_data((uv_handle_t*)handle);
    ASSERT(buf_r->buf_base == buf->base);

    data_pos = (uint8_t*)buf->base;
    data_len = (size_t)nread;

    /* parse s5 packet */
    err = s5_parse_udp(&parser, &data_pos, &data_len);
    if ( s5_exec_cmd != err ) {
        s5netio_on_msg(LOG_ERROR, "S5 dgram parse error: %s", s5_strerror(err));
        BREAK_NOW;
    }
    if ( 0 == data_len ) {
        s5netio_on_msg(LOG_ERROR, "No dgram payload after parse", s5_strerror(err));
        BREAK_NOW;
    }

    // 拷贝出远程地址
    s5_addr_copy(&parser, &remote_sockaddr.addr, &srv_addr);


    /* Stop recv until all data sent out, or error occur */
    CHECK(0 == uv_udp_recv_stop(handle));

    // clt_addr.domain clt_addr.ip clt_addr.port
    CHECK(0 == sockaddr_to_str(addr, &clt_addr, 1));
    // ip->domain
    strcpy(clt_addr.domain, clt_addr.ip);

    /* unique key  这里的domain也可以是IP字符串 s5_addr_copy 已经做出处理*/
    snprintf(key, sizeof(key), "%s:%d-%s:%d",
             clt_addr.ip, clt_addr.port,
             srv_addr.domain, srv_addr.port);


    // 更新指针位置
    buf_r->data_base = (char*)data_pos;
    buf_r->data_len = data_len;

    ds = dgrams_find_by_key(key);
    if ( ds ) {
        /* Already in communication */
        dgram_send_remote(ds);
    } else {
        /* Create new one */
        loop = uv_handle_get_loop((uv_handle_t*)handle);

        ds = dgrams_add(key, loop);
        CHECK(NULL != ds);
        ds->udp_in = handle;

        sockaddr_cpy(addr, &ds->local.addr);

        // 初始化新节点
        ds->remote_peer     = srv_addr;
        ds->local_peer      = clt_addr;
        ds->buf.buf_base    = ds->slab;
        ds->buf.buf_len     = sizeof(ds->slab);

        dgram_lookup(ds);
    }

BREAK_LABEL:

    return;
}

static void dgram_lookup(DGRAMS *ds) {
    uv_loop_t *loop;
    const char* host;
    struct addrinfo hints;
    struct sockaddr *addr;

    /* Maybe it's an ip address in string form */
    if ( 0 == uv_ip4_addr(ds->remote_peer.domain, ds->remote_peer.port, &ds->remote.addr4) ||
         0 == uv_ip6_addr(ds->remote_peer.domain, ds->remote_peer.port, &ds->remote.addr6) ) {

        // remote_peer.ip
        strcpy(ds->remote_peer.ip, ds->remote_peer.domain);

        /* 替换成可读性更高的域名 */
        host = dns_cache_find_host(&ds->remote.addr);
        if ( host ) {
            memset(ds->remote_peer.domain, 0, sizeof(ds->remote_peer.domain));
            strcpy(ds->remote_peer.domain, host);
        }

        s5netio_on_new_dgram(&ds->local_peer, &ds->remote_peer, &ds->ctx);
        dgram_bind(ds);

        dgram_read_remote(ds);
        dgram_send_remote(ds);
    } else {
        /* Lookup dns cache */
        addr = dns_cache_find_ip(ds->remote_peer.domain, 1);
        if ( !addr )
            addr = dns_cache_find_ip(ds->remote_peer.domain, 0);

        if ( addr ) {
            sockaddr_cpy(addr, &ds->remote.addr);
            sockaddr_set_port(&ds->remote.addr, ds->remote_peer.port);

            // remote_peer.ip
            sockaddr_to_str(addr, &ds->remote_peer, 0);
            s5netio_on_new_dgram(&ds->local_peer, &ds->remote_peer, &ds->ctx);

            dgram_bind(ds);

            dgram_read_remote(ds);
            dgram_send_remote(ds);
        } else {
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            loop = uv_handle_get_loop((uv_handle_t*)ds->udp_in);

            if ( 0 != uv_getaddrinfo(loop,
                                     &ds->req_dns,
                                     dgram_getaddrinfo_done,
                                     ds->remote_peer.domain,
                                     NULL,
                                     &hints) ) {
                CHECK(0 == dgram_read_local(ds->udp_in));
                dgrams_remove(ds);
            }
        }
    }
}

static void dgram_getaddrinfo_done(
    uv_getaddrinfo_t *req, const int status, struct addrinfo *addrs) {
    DGRAMS *ds;
    struct addrinfo *ai;
    struct addrinfo *ai_ipv4 = NULL;
    struct addrinfo *ai_ipv6 = NULL;
    int valid = 0;

    ds = CONTAINER_OF(req, DGRAMS, req_dns);

    if ( 0 == status ) {
        for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
            dns_cache_add(ds->remote_peer.domain, ai->ai_addr);

            if ( AF_INET == ai->ai_family && !ai_ipv4 ) {
                ai_ipv4 = ai;
            }
            if ( AF_INET6 == ai->ai_family && !ai_ipv6 ) {
                ai_ipv6 = ai;
            }
        }

        if (ai_ipv4) {
            sockaddr_cpy(ai_ipv4->ai_addr, &ds->remote.addr);
            valid = 1;
        } else if (ai_ipv6) {
            sockaddr_cpy(ai_ipv6->ai_addr, &ds->remote.addr);
            valid = 1;
        }

        if (valid) {
            sockaddr_set_port(&ds->remote.addr, ds->remote_peer.port);

            sockaddr_to_str(&ds->remote.addr, &ds->remote_peer, 0);
            s5netio_on_new_dgram(&ds->local_peer, &ds->remote_peer, &ds->ctx);

            dgram_bind(ds);

            dgram_read_remote(ds);
            dgram_send_remote(ds);
        }
    }

    if (!valid) {
        s5netio_on_msg(
            LOG_WARN,
            "dgram getaddrinfo failed: %s, domain: %s",
            uv_strerror(status),
            ds->remote_peer.domain);

        CHECK(0 == dgram_read_local(ds->udp_in));
        dgrams_remove(ds);
    }

    uv_freeaddrinfo(addrs);
}

static void dgram_bind(DGRAMS *ds) {
    // 创建的新Socket在发包之前先bind一下 否则可能导致发包失败, 特别是IPV6情况下
    ds->is_ipv6 = ds->remote.addr.sa_family == AF_INET6;
    if (ds->is_ipv6) {
        struct sockaddr_in6 bind_addr = {};
        uv_ip6_addr("::", 0, &bind_addr);
        uv_udp_bind(&ds->udp_out, (struct sockaddr*)&bind_addr, 0);
    } else {
        struct sockaddr_in bind_addr = {};
        uv_ip4_addr("0.0.0.0", 0, &bind_addr);
        uv_udp_bind(&ds->udp_out, (struct sockaddr*)&bind_addr, 0);
    }
}

static void dgram_send_remote(DGRAMS *ds) {
    uv_buf_t buf_t;
    BUF_RANGE *buf;

    buf = uv_handle_get_data((uv_handle_t*)ds->udp_in);
    buf_t = uv_buf_init(buf->data_base, (unsigned int)buf->data_len);

    s5netio_on_plain_dgram(buf, STREAM_UP, ds->ctx);

    if ( 0 == uv_udp_send(
        &ds->req_c,
        &ds->udp_out,
        &buf_t,
        1,
        &ds->remote.addr,
        dgram_send_done_remote) ) {

        dgram_timer_reset(ds);
    } else {
        CHECK(0 == dgram_read_local(ds->udp_in));
        dgrams_remove(ds);
    }
}

static void dgram_send_done_remote(uv_udp_send_t *req, const int status) {
    DGRAMS *ds;

    (void)status;

    ds = CONTAINER_OF(req, DGRAMS, req_c);
    CHECK(0 == dgram_read_local(ds->udp_in));
}

static void dgram_send_local(DGRAMS *ds, const uv_buf_t *buf) {
    if ( 0 == uv_udp_send(
        &ds->req_s,
        ds->udp_in,
        buf,
        1,
        &ds->local.addr,
        dgram_send_done_local) ) {

        dgram_timer_reset(ds);
    } else {
        dgram_read_remote(ds);
    }
}

static void dgram_send_done_local(uv_udp_send_t *req, const int status) {
    DGRAMS *ds;

    (void)status;

    ds = CONTAINER_OF(req, DGRAMS, req_s);
    dgram_read_remote(ds);
}

static void dgram_read_remote(DGRAMS *ds) {
    CHECK(0 == uv_udp_recv_start(
        &ds->udp_out,
        dgram_alloc_cb_remote,
        dgram_read_done_remote));
    dgram_timer_reset(ds);
}

static void dgram_alloc_cb_remote(
    // ReSharper disable once CppParameterMayBeConstPtrOrRef
    uv_handle_t *handle,
    // ReSharper disable once CppParameterMayBeConst
    size_t suggested_size,
    uv_buf_t *buf) {
    DGRAMS *ds;

    (void)suggested_size;

    ds = uv_handle_get_data(handle);

    // 事先让出S5头位置 这里给IPV6的大值
    buf->base   = ds->buf.buf_base + S5_IPV6_UDP_SEND_HDR_LEN;
    buf->len    = ds->buf.buf_len - S5_IPV6_UDP_SEND_HDR_LEN;
}

static void dgram_read_done_remote(
    uv_udp_t *handle, const ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    const unsigned flags) {

    DGRAMS *ds;
    BUF_RANGE *buf_r;
    uv_buf_t buf_t;
    int hdr_len = 0;
    char *p;
    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;

    (void)flags;
    (void)addr;

    if ( nread <= 0 )
        BREAK_NOW;

    ds = CONTAINER_OF(handle, DGRAMS, udp_out);
    buf_r = &ds->buf;
    ASSERT(buf->base == buf_r->buf_base + S5_IPV6_UDP_SEND_HDR_LEN);

    /* Address check */
    ASSERT(addr->sa_family == ds->remote.addr.sa_family);
    if ( AF_INET == addr->sa_family ) {
        in = (struct sockaddr_in*)addr;
        ASSERT(in->sin_port == ds->remote.addr4.sin_port);
        ASSERT(0 == memcmp(&in->sin_addr, &ds->remote.addr4.sin_addr, sizeof(in->sin_addr)));
    }
    else if ( AF_INET6 == addr->sa_family ) {
        in6 = (struct sockaddr_in6*)addr;
        ASSERT(in6->sin6_port == ds->remote.addr6.sin6_port);
        ASSERT(0 == memcmp(&in6->sin6_addr, &ds->remote.addr6.sin6_addr, sizeof(in6->sin6_addr)));
    }


    buf_r->data_base    = buf_r->buf_base + S5_IPV6_UDP_SEND_HDR_LEN;
    buf_r->data_len     = (size_t)nread;

    s5netio_on_plain_dgram(buf_r, STREAM_DOWN, ds->ctx);

    /* shift to socks5 hdr */
    hdr_len = addr->sa_family == AF_INET ? S5_IPV4_UDP_SEND_HDR_LEN : S5_IPV6_UDP_SEND_HDR_LEN;
    p = buf_r->data_base - hdr_len;
    /* s5 hdr */
    *p++ = (char)'\0';
    *p++ = (char)'\0';
    *p++ = (char)'\0';
    *p++ = addr->sa_family == AF_INET ? (char)'\1' : (char)'\4';
    /* Write server ip && port to s5 hdr */
    if ( AF_INET == addr->sa_family ) {
        in = (struct sockaddr_in*)addr;
        memcpy(p, &in->sin_addr, sizeof(in->sin_addr));
        p += sizeof(in->sin_addr);
        memcpy(p, &in->sin_port, sizeof(in->sin_port));
    }
    else if ( AF_INET6 == addr->sa_family ) {
        in6 = (struct sockaddr_in6*)addr;
        memcpy(p, &in6->sin6_addr, sizeof(in6->sin6_addr));
        p += sizeof(in6->sin6_addr);
        memcpy(p, &in6->sin6_port, sizeof(in6->sin6_port));
    }


    /* 发送完成之前停止接收 */
    CHECK(0 == uv_udp_recv_stop(handle));

    buf_t = uv_buf_init(buf_r->data_base - hdr_len, buf_r->data_len + hdr_len);
    dgram_send_local(ds, &buf_t);

BREAK_LABEL:

    return ;
}

static void dgram_timer_reset(DGRAMS *ds) {
    CHECK(0 == uv_timer_start(
        &ds->timer,
        dgram_timer_expire,
        srv_ctx.config.idel_timeout,
        0));
}

static void dgram_timer_expire(uv_timer_t *handle) {
    DGRAMS *ds;

    ds = CONTAINER_OF(handle, DGRAMS, timer);
    s5netio_on_dgram_teardown(ds->ctx);
    dgrams_remove(ds);
}
