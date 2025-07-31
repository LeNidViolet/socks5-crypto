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

#include "internal.h"

socks5_server_config srv_cfg = { 0 };
crypto_env crypto = { 0 };
static int srv_running = 0;

int socks5_crypto_launch(const socks5_server_config *ctx) {
    int ret = -1;
    ioctl_port io_port;

    BREAK_ON_FALSE(0 == srv_running);

    BREAK_ON_NULL(ctx);
    BREAK_ON_NULL(ctx->config.root_cert);
    BREAK_ON_NULL(ctx->config.root_key);

    if (ctx->config.asSocks5 == 0) {
        BREAK_ON_NULL(ctx->config.method);
        BREAK_ON_NULL(ctx->config.password);

        crypto.method = get_method_by_name(ctx->config.method);
        BREAK_ON_NULL(crypto.method);


        /* 根据设置的密码生成加密用的KEY */
        CHECK(0 == gen_key(ctx->config.password, crypto.key, crypto.method->key_len));
    }

    srv_cfg = *ctx;
    srv_cfg.config.idel_timeout *= 1000;


    /* 获取NETIO底层发送数据等接口.需要在TLSFLAT中使用 */
    netio_server_port(&io_port);
    /* 初始化 TLS 部分 */
    ret = tlsflat_init(
        &io_port,
        ctx->config.root_cert,
        ctx->config.root_key);
    if ( 0 != ret ) {
        socks5_crypto_on_msg(LOG_ERROR, "tlsflat init failed");
        BREAK_NOW;
    }

    if (ctx->config.asSocks5 == 0) {
        /* 初始化加密解密单元 */
        init_crypt_unit();
    }


    srv_running = 1;

    /* 启动SS NETIO, 开始监听 */
    ret = netio_server_launch(ctx);

    srv_running = 0;

    if (ctx->config.asSocks5 == 0) {
        /* 释放加密解密单元资源 */
        free_crypt_unit();
    }

    /* 释放 TLS 资源 */
    tlsflat_clear();

BREAK_LABEL:

    return ret;
}

void socks5_crypto_stop() {
    if ( srv_running ) {
        netio_server_stop();
        srv_running = 0;
    }
}
