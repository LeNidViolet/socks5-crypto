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

#ifndef SOCKS5_NETIO_INTERNAL_H
#define SOCKS5_NETIO_INTERNAL_H

#include <uv.h>

#include "s5.h"
#include "../comm/comm.h"


/* Session states. */
enum SESS_STATE {
    s_handshake,        /* Wait for client handshake. */
    s_req_start,        /* Start waiting for request data. */
    s_req_parse,        /* Wait for request data. */
    s_req_lookup,       /* Wait for upstream hostname DNS lookup to complete. */
    s_req_connect,      /* Wait for uv_tcp_connect() to complete. */
    s_dgram_start,
    s_dgram_stop,
    s_proxy_start,      /* Connected. Start piping data. */
    s_proxy,            /* Connected. Pipe data back and forth. */
    s_kill,             /* Tear down session. */
    s_almost_dead_0,    /* Waiting for finalizers to complete. */
    s_almost_dead_1,    /* Waiting for finalizers to complete. */
    s_almost_dead_2,    /* Waiting for finalizers to complete. */
    s_almost_dead_3,    /* Waiting for finalizers to complete. */
    s_almost_dead_4,    /* Waiting for finalizers to complete. */
    s_dead,             /* Dead. Safe to free now. */

    s_max
};

enum CONN_STATE {
    c_busy,  /* Busy; waiting for incoming data or for a write to complete. */
    c_done,  /* Done; read incoming data or write finished. */
    c_stop,  /* Stopped. */
    c_dead
};

typedef enum {
    peer,
    sock
} ENDPOINT;


typedef struct {
    unsigned char rdstate;
    unsigned char wrstate;
    unsigned int idle_timeout;
    struct PROXY_NODE_ *pn;  /* Backlink */
    ssize_t result;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
        uv_udp_t udp;
    } handle;
    uv_timer_t timer_handle;  /* For detecting timeouts. */
    uv_write_t write_req;

    union {
        uv_getaddrinfo_t addrinfo_req;
        uv_connect_t connect_req;
        uv_req_t req;
    } req;

    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } addr;     // remote

    char slab[MAX_TCP_PAYLOAD_LEN];

    ADDRESS peer;
    BUF_RANGE buf;
} CONN;

typedef struct PROXY_NODE_{
    int state;
    unsigned int index;
    uv_loop_t *loop;

    CONN incoming;  /* Connection with the SOCKS client. */
    CONN outgoing;  /* Connection with upstream. */
    int outstanding;

    s5_ctx parser;

    char link_info[128];

    void *ctx;
} PROXY_NODE;


typedef struct SERVER_ADDRESSES_ {
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } addrv4;
    char addrv4_str[INET6_ADDRSTRLEN];

    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } addrv6;
    char addrv6_str[INET6_ADDRSTRLEN];
} SERVER_ADDRESSES;


/* URIL.C */
int  sockaddr_to_str(const struct sockaddr *addr, ADDRESS *addr_s, int set_port);
void sockaddr_cpy(const struct sockaddr *src, struct sockaddr *dst);
int  sockaddr_equal(const struct sockaddr *src, const struct sockaddr *dst, int cmp_port);
void sockaddr_set_port(struct sockaddr *addr, unsigned short port);
int  str_tcp_endpoint(const uv_tcp_t *tcp_handle, ENDPOINT ep, ADDRESS *addr_s);
int s5_addr_copy(s5_ctx *ctx, struct sockaddr *addr, ADDRESS *addr_s);

enum {
    s5_invalid_length = -1,
    s5_invalid_version = -2,
    s5_invalid_method = -3
};

/* Parse the host/ip and port from incoming data.
 * Set data_base AND data_len, to the actual data range.
 * return 0 if success.
 */
int s5_parse_addr(BUF_RANGE *buf, ADDRESS *addr);

/* HANDLER.C */
void s5netio_on_msg(int level, const char *format, ...);
void s5netio_on_bind(const char *host, unsigned short port);
void s5netio_on_connection_made(PROXY_NODE *pn);
void s5netio_on_new_stream(const CONN *conn);
void s5netio_on_stream_teardown(const PROXY_NODE *pn);
void s5netio_on_new_dgram(ADDRESS *local, ADDRESS *remote, void **ctx);
void s5netio_on_dgram_teardown(void *ctx);
int  s5netio_on_plain_stream(const CONN *conn);
void s5netio_on_plain_dgram(const BUF_RANGE *buf, int direct, void *ctx);

int  s5netio_write_stream_out(
    const char *buf, size_t len, int direct, void *stream_id);
void s5netio_stream_pause(void *stream_id, int direct, int pause);






int  server_tcp_launch(uv_loop_t *loop, const struct sockaddr *addr);
int  server_dgram_launch(uv_loop_t *loop, const struct sockaddr *addr);




int  do_kill(PROXY_NODE *pn);
void conn_timer_reset(CONN *conn);
void conn_read(CONN *conn);

#endif //SOCKS5_NETIO_INTERNAL_H
