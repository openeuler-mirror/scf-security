/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef OPENSSL_DEF_H
#define OPENSSL_DEF_H

#include <cstdint>
#include <cstddef>

namespace scf {
#define SSL_VERSION_3_X 0x30000000UL

// 同步OpenSSL结构体定义
#define SSL void
#define SSL_CTX void
#define SSL_METHOD void
#define SSL_SESSION void
#define SSL_CIPHER void
#define BIO void
#define EVP_PKEY void
#define EVP_MD void
#define X509 void
#define X509_CRL void
#define X509_STORE void
#define X509_STORE_CTX void

#define SSL_EX_DATA_ID 1

// 同步OpenSSL宏定义
#define SSL_SUCCESS 1
#define SSL_ERROR   0

#define SSL_ERROR_WANT_READ  2
#define SSL_ERROR_WANT_WRITE 3

#define SSL_KEY_UPDATE_NONE          (-1)
#define SSL_KEY_UPDATE_NOT_REQUESTED   0
#define SSL_KEY_UPDATE_REQUESTED       1

#define X509_FILETYPE_PEM 1
#define SSL_FILETYPE_PEM X509_FILETYPE_PEM

#define X509_V_FLAG_CRL_CHECK 0x4

#define SSL_VERIFY_NONE                 0x00
#define SSL_VERIFY_PEER                 0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02

#define SSL_SESS_CACHE_OFF 0x0000

#define SSL_OP_NO_TLSv1_2 0x08000000U
#define SSL_OP_NO_TLSv1_3 0x20000000U

#define SSL_OP_NO_RENEGOTIATION 0x40000000U

#define SSL_CTRL_EXTRA_CHAIN_CERT      14
#define SSL_CTRL_SET_SESS_CACHE_MODE   44
#define SSL_CTRL_GET_SESS_CACHE_MODE   45
#define SSL_CTRL_SET_MIN_PROTO_VERSION 123
#define SSL_CTRL_SET_MAX_PROTO_VERSION 124
#define SSL_CTRL_GET_MIN_PROTO_VERSION 130
#define SSL_CTRL_GET_MAX_PROTO_VERSION 131

# define TLS1_2_VERSION  0x0303
# define TLS1_3_VERSION  0x0304

// 同步OpenSSL函数类宏定义
#define SSL_CTX_add_extra_chain_cert(ctx, x509) \
    LibSslApi::GetInstance().SSL_CTX_ctrl(ctx, SSL_CTRL_EXTRA_CHAIN_CERT, 0, (char *)(x509))
#define SSL_CTX_set_min_proto_version(ctx, version) \
    LibSslApi::GetInstance().SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, nullptr)
#define SSL_CTX_set_max_proto_version(ctx, version) \
    LibSslApi::GetInstance().SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, version, nullptr)
# define SSL_CTX_get_min_proto_version(ctx) \
    LibSslApi::GetInstance().SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, nullptr)
# define SSL_CTX_get_max_proto_version(ctx) \
    LibSslApi::GetInstance().SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, nullptr)
#define SSL_CTX_set_session_cache_mode(ctx, m) \
    LibSslApi::GetInstance().SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, m, nullptr)
#define SSL_CTX_get_session_cache_mode(ctx) \
    LibSslApi::GetInstance().SSL_CTX_ctrl(ctx, SSL_CTRL_GET_SESS_CACHE_MODE, 0, nullptr)

// 同步OpenSSL结构体定义
#define SSL void
#define SSL_CTX void
#define SSL_METHOD void
#define SSL_SESSION void
#define SSL_CIPHER void
#define BIO void
#define EVP_PKEY void
#define EVP_MD void
#define X509 void
#define X509_CRL void
#define X509_STORE void
#define X509_STORE_CTX void

struct ASN1String {
    int length;
    int type;
    unsigned char *data;
    int64_t flags;
};

using ASN1_INTEGER = ASN1String;
using ASN1_TIME = ASN1String;

enum SslSecureLevel {
    /* [0] Everything is permitted. This retains compatibility with previous versions of OpenSSL. */
    SSL_SECURITY_LEVEL_ZERO = 0,
    /* [1] The security level corresponds to a minimum of 80 bits of security.
       Any parameters offering below 80 bits of security are excluded.
       As a result RSA, DSA and DH keys shorter than 1024 bits and ECC keys shorter than 160 bits are prohibited.
       Any cipher suite using MD5 for the MAC is also prohibited.
       Any cipher suites using CCM with a 64 bit authentication tag are prohibited.
       Note that signatures using SHA1 and MD5 are also forbidden at this level as they have less than 80 security bits.
       Additionally, SSLv3, TLS 1.0, TLS 1.1 and DTLS 1.0 are all disabled at this level. */
    SSL_SECURITY_LEVEL_ONE,
    /* [2] Security level set to 112 bits of security.
       As a result RSA, DSA and DH keys shorter than 2048 bits and ECC keys shorter than 224 bits are prohibited.
       In addition to the level 1 exclusions any cipher suite using RC4 is also prohibited.
       Compression is disabled. */
    SSL_SECURITY_LEVEL_TWO,
    /* [3] Security level set to 128 bits of security.
       As a result RSA, DSA and DH keys shorter than 3072 bits and ECC keys shorter than 256 bits are prohibited.
       In addition to the level 2 exclusions cipher suites not offering forward secrecy are prohibited.
       Session tickets are disabled. */
    SSL_SECURITY_LEVEL_THREE,
    /* [4] Security level set to 192 bits of security.
       As a result RSA, DSA and DH keys shorter than 7680 bits and ECC keys shorter than 384 bits are prohibited.
       Cipher suites using SHA1 for the MAC are prohibited. */
    SSL_SECURITY_LEVEL_FOUR,
    /* [5] Security level set to 256 bits of security.
       As a result RSA, DSA and DH keys shorter than 15360 bits and ECC keys shorter than 512 bits are prohibited. */
    SSL_SECURITY_LEVEL_FIVE,
};

// 同步OpenSSL回调定义
using SSLVerifyCallback = int (*)(int, X509_STORE_CTX *);

using SSLPskFindSessionCallback = int (*)(SSL *, const unsigned char *, size_t, SSL_SESSION **);

using SSLPskUseSessionCallback = int (*)(SSL *, const EVP_MD *, const unsigned char **, size_t *, SSL_SESSION **);

using PemPasswordCallback = int(char *, int, int, void *);

using ERRPrintErrorsCallback = int (*)(const char *, size_t, void *);
}

#endif // OPENSSL_DEF_H