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

#include <uv.h>
#include "socks5-crypto/socks5-crypto.h"
#include "internal.h"
#include "dgramsc.h"
#include "dns_cache.h"


// ==========
socks5_crypto_ctx srv_ctx;
SERVER_ADDRESSES srv_addrs;

static int server_run(socks5_crypto_ctx *ctx);
static void server_handle_walk_callback(uv_handle_t* Handle, void* arg);
static void server_exit_async_cb(uv_async_t* handle);

static void server_walk_addresses();
static int is_valid_address(const uv_interface_address_t* iface);

union {
    uv_handle_t             handle;
    uv_async_t              async;
} exit_async;         // 可以在任意线程调用, 但是必须在loop所在线程初始化


/* LAUNCHER */
int s5netio_server_launch(const socks5_crypto_ctx *ctx) {
    int ret = -1;

    BREAK_ON_NULL(ctx);
    BREAK_ON_NULL(ctx->config.bind_port);
    BREAK_ON_NULL(ctx->config.idel_timeout);

    dgrams_init();
    dns_cache_init();

    memcpy(&srv_ctx, ctx, sizeof(srv_ctx));
    srv_ctx.config.idel_timeout *= 1000;

    ret = server_run(&srv_ctx);

    dgrams_clear();
    dns_cache_clear();

BREAK_LABEL:

    return ret;
}

/* 取得NETIO底层操作接口 */
void s5netio_server_port(ioctl_port *port) {
    port->write_stream_out = s5netio_write_stream_out;
    port->stream_pause = s5netio_stream_pause;
}


// ReSharper disable once CppParameterMayBeConstPtrOrRef
static int server_run(socks5_crypto_ctx *ctx) {
    uv_loop_t                   *loop;
    int                         ret;

    union {
        uv_handle_t             handle;
        uv_tcp_t                tcp;
        uv_stream_t             stream;
    } tcpv4;                                            // TCPv4 listening socket

    union {
        uv_handle_t             handle;
        uv_tcp_t                tcp;
        uv_stream_t             stream;
    } tcpv6;                                            // TCPv6 listening socket

    union {
        uv_handle_t             handle;
        uv_udp_t                udp;
    } udpv4;                                            // UDPv4 listening socket

    union {
        uv_handle_t             handle;
        uv_udp_t                udp;
    } udpv6;                                            // UDPv6 listening socket

    // Union to hold sockaddr structures (supports both IPv4 and IPv6)
    union {
        struct sockaddr addr;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } addr = {};
    const char *addrs;
    const char *addrsv6;
    bool success = false;

    loop = uv_default_loop();

    ret = uv_tcp_init(loop, &tcpv4.tcp);
    CHECK(0 == ret);
    ret = uv_tcp_init(loop, &tcpv6.tcp);
    CHECK(0 == ret);
    ret = uv_udp_init(loop, &udpv4.udp);
    CHECK(0 == ret);
    ret = uv_udp_init(loop, &udpv6.udp);
    CHECK(0 == ret);

    // LISTEN ON TCPv4
    addrs = "0.0.0.0";
    ret = uv_ip4_addr(addrs, ctx->config.bind_port, &addr.addr4);
    CHECK(0 == ret);
    ret = server_tcp_launch(loop, &addr.addr);
    BREAK_ON_FALSE(0 == ret);

    // LISTEN ON UDPv4
    ret = server_dgram_launch(loop, &addr.addr);
    BREAK_ON_FALSE(0 == ret);


    // LISTEN ON TCPv6
    addrsv6 = "::";
    ret = uv_ip6_addr(addrsv6, ctx->config.bind_port, &addr.addr6);
    CHECK(0 == ret);
    ret = server_tcp_launch(loop, &addr.addr);
    BREAK_ON_FALSE(0 == ret);

    // LISTEN ON UDPv6
    ret = server_dgram_launch(loop, &addr.addr);
    BREAK_ON_FALSE(0 == ret);

    uv_async_init(loop, &exit_async.async, server_exit_async_cb);

    success = true;

    // 枚举一下 IPV4 IPV6 的非回环地址 主要是给UDP代理使用
    memset(&srv_addrs, 0, sizeof(srv_addrs));
    server_walk_addresses();

    s5netio_on_bind("0.0.0.0", ctx->config.bind_port);

    // uv_run returns 0 when all handles are closed;
    // a non-zero return indicates uv_stop was called, or live handles remain
    ret = uv_run(loop, UV_RUN_DEFAULT);
    if (ret != 0) {
        // There are still active handles; walk them for cleanup
        uv_walk(loop, server_handle_walk_callback, NULL);
        uv_run(loop, UV_RUN_DEFAULT);
    } else {
        // Normally should not reach here
    }


    uv_loop_close(loop);

    // MORE RESOURCE CLEAN
    memset(&srv_ctx, 0, sizeof(srv_ctx));
    memset(&srv_addrs, 0, sizeof(srv_addrs));

BREAK_LABEL:

    if (!success) {
        s5netio_on_msg(LOG_ERROR,"tcp/udp server launch failed");
    }

    return ret;
}

// Callback for uv_walk to close all handles in the loop
// ReSharper disable once CppParameterMayBeConstPtrOrRef
static void server_handle_walk_callback(uv_handle_t* Handle, void* arg) {
    // uv_handle_type type = uv_handle_get_type(Handle);
    // const uv_loop_t* loop = uv_handle_get_loop(Handle);

    // In this loop, we only have listener and async handles;
    // no extra cleanup is needed, just close them directly
    if (!uv_is_closing(Handle)) {
        uv_close(Handle, NULL);
    }
}



void s5netio_server_stop(void) {

    uv_async_send(&exit_async.async);
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
static void server_exit_async_cb(uv_async_t* handle) {
    (void)handle;

    uv_stop(uv_default_loop());
}


// 遍历有效的本地IP(非回环)
static void server_walk_addresses() {
    uv_interface_address_t* interfaces;
    int count, r;

    r = uv_interface_addresses(&interfaces, &count);
    if (r != 0) {
        return ;
    }

    for (int i = 0; i < count; ++i) {
        const uv_interface_address_t* iface = &interfaces[i];

        if (!is_valid_address(iface)) continue;

        char ip[INET6_ADDRSTRLEN] = {0};

        if (iface->address.address4.sin_family == AF_INET) {
            if (srv_addrs.addrv4.addr.sa_family == 0) {
                const int ret = uv_ip4_name(&iface->address.address4, ip, sizeof(ip));
                CHECK(0 == ret);
                snprintf(srv_addrs.addrv4_str, sizeof(srv_addrs.addrv4_str), "%s", ip);
                sockaddr_cpy((struct sockaddr*)&iface->address, &srv_addrs.addrv4.addr);
            }
        } else if (iface->address.address6.sin6_family == AF_INET6) {
            if (srv_addrs.addrv6.addr.sa_family == 0) {
                const int ret = uv_ip6_name(&iface->address.address6, ip, sizeof(ip));
                CHECK(0 == ret);
                snprintf(srv_addrs.addrv6_str, sizeof(srv_addrs.addrv6_str), "%s", ip);
                sockaddr_cpy((struct sockaddr*)&iface->address, &srv_addrs.addrv6.addr);
            }
        }
    }

    if (srv_addrs.addrv4.addr.sa_family == 0) {
        int ret = uv_ip4_addr("127.0.0.1", 0, &srv_addrs.addrv4.addr4);
        CHECK(0 == ret);
        ret = uv_ip4_name(&srv_addrs.addrv4.addr4, srv_addrs.addrv4_str, sizeof(srv_addrs.addrv4_str));
        CHECK(0 == ret);
    }
    if (srv_addrs.addrv6.addr.sa_family == 0) {
        int ret = uv_ip6_addr("::1", 0, &srv_addrs.addrv6.addr6);
        CHECK(0 == ret);
        ret = uv_ip6_name(&srv_addrs.addrv6.addr6, srv_addrs.addrv6_str, sizeof(srv_addrs.addrv6_str));
        CHECK(0 == ret);
    }

    s5netio_on_msg(LOG_KEY, "local ipv4 address: %s", srv_addrs.addrv4_str);
    s5netio_on_msg(LOG_KEY, "local ipv6 address: %s", srv_addrs.addrv6_str);

    uv_free_interface_addresses(interfaces, count);
}

static int is_valid_address(const uv_interface_address_t* iface) {
    if (iface->is_internal) return 0;
    const char* skip_ifaces[] = {"bridge", "vmnet", "vbox", "utun"};
    int skip = 0;
    for (int j = 0; j < sizeof(skip_ifaces) / sizeof(skip_ifaces[0]); ++j) {
        if (strncmp(iface->name, skip_ifaces[j], strlen(skip_ifaces[j])) == 0) {
            skip = 1;
            break;
        }
    }
    if (skip) return 0;

    if (iface->address.address4.sin_family == AF_INET) {
        // IPv4
        char ip[INET_ADDRSTRLEN];
        uv_ip4_name(&iface->address.address4, ip, sizeof(ip));

        // 排除 127.x.x.x 回环地址
        if (strncmp(ip, "127.", 4) == 0) return 0;

        return 1;
    } else if (iface->address.address6.sin6_family == AF_INET6) {
        // IPv6
        char ip[INET6_ADDRSTRLEN];
        uv_ip6_name(&iface->address.address6, ip, sizeof(ip));

        // 排除 ::1 回环地址
        if (strcmp(ip, "::1") == 0) return 0;

        // 排除 fe80::/10 链路本地地址
        if (strncmp(ip, "fe80", 4) == 0) return 0;

        return 1;
    }

    return 0;
}
