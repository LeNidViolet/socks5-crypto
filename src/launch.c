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

crypto_env env = { 0 };
static int ss_running = 0;

int socks5_crypto_launch(const socks5_crypto_ctx *ctx) {
    int ret = -1;
    ioctl_port io_port;

    BREAK_ON_FALSE(0 == ss_running);

    BREAK_ON_NULL(ctx);
    BREAK_ON_NULL(ctx->config.root_cert);
    BREAK_ON_NULL(ctx->config.root_key);


    /* 保存回调 */
    env.callbacks = ctx->callbacks;


    /* 获取NETIO底层发送数据等接口.需要在TLSFLAT中使用 */
    s5netio_server_port(&io_port);
    /* 初始化 TLS 部分 */
    ret = tlsflat_init(
        &io_port,
        ctx->config.root_cert,
        ctx->config.root_key);
    if ( 0 != ret ) {
        socks5_crypto_on_msg(LOG_ERROR, "tlsflat init failed");
        BREAK_NOW;
    }


    ss_running = 1;

    /* 启动SS NETIO, 开始监听 */
    ret = s5netio_server_launch(ctx);

    ss_running = 0;


    /* 释放 TLS 资源 */
    tlsflat_clear();

BREAK_LABEL:

    return ret;
}

void socks5_crypto_stop() {
    if ( ss_running ) {
        s5netio_server_stop();
        ss_running = 0;
    }
}
