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
#ifndef SOCKS5_CRYPTO_INTERNAL_H
#define SOCKS5_CRYPTO_INTERNAL_H

#include "socks5-crypto/socks5-crypto.h"
#include "comm/comm.h"
#include "mbedtls/cipher.h"


typedef struct {
    const mbedtls_cipher_type_t type;
    const char *mbedtls_name;
    const char *ss_name;
    const unsigned int key_len;
    const unsigned int iv_len;
} crypto_info;


#define MAX_CRYPTO_KEY_LEN          (32)
#define MAX_CRYPTO_SALT_LEN         MAX_SS_SALT_LEN

typedef struct {
    const crypto_info *method;
    unsigned char key[MAX_CRYPTO_KEY_LEN];
} crypto_env;

/* UTIL.C */
/* return 0 if success */
int gen_iv(const char *seed, unsigned char *iv, size_t iv_len);
/* return 0 if success */
int gen_key(const char *seed, unsigned char *key, size_t key_len);

const crypto_info *get_method_by_name(const char *name);


/* CALLBACK.C */
int  init_crypt_unit(void);
void free_crypt_unit(void);
void socks5_crypto_on_msg(int level, const char *format, ...);


/* EXTERNAL FUNCTION */
int  netio_server_launch(const socks5_server_config *ctx);
void netio_server_stop(void);
void netio_server_port(ioctl_port *port);
int  tlsflat_init(const ioctl_port *port, const char *root_crt, const char *root_key);
void tlsflat_clear(void);
void tlsflat_on_stream_connection_made(const ADDRESS_PAIR *addr, void *stream_id, void *caller_ctx, void **tls_ctx);
void tlsflat_on_stream_teardown(void *tls_ctx);
int  tlsflat_on_plain_stream(const BUF_RANGE *buf, int direct, void *ctx);

#endif //SOCKS5_CRYPTO_INTERNAL_H
