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

#ifndef LIB_SSL_API_H
#define LIB_SSL_API_H

#include "openssl_def.h"
#include "dlopen_lib_base.h"

namespace scf {
const std::string libSslName = "libssl.so";

class LibSslApi final : public DlOpenLibBase {
public:
    LibSslApi(const LibSslApi &) = delete;

    void operator=(const LibSslApi &) = delete;

    static LibSslApi &GetInstance();

    uint32_t Init(const std::string &libPath) override;

    void UnInit() override;

    DlFun<int, uint64_t, const void *> OPENSSL_init_ssl;
    DlFun<const char *, int> OpenSSL_version;
    DlFun<uint64_t> OpenSSL_version_num;
    DlFun<void *, SSL *> SSL_new;
    DlFun<void, SSL *> SSL_free;
    DlFun<int, void *> SSL_connect;
    DlFun<int, void *> SSL_accept;
    DlFun<int, void *, int> SSL_get_error;
    DlFun<int, void *, void *, size_t, size_t *> SSL_read_ex;
    DlFun<int, void *, const void *, size_t, size_t *> SSL_write_ex;
    DlFun<int, void *> SSL_shutdown;
    DlFun<int, void *, int, void *> SSL_set_ex_data;
    DlFun<void *, const void *, int> SSL_get_ex_data;
    DlFun<int, void *, int> SSL_set_fd;
    DlFun<int, const void *> SSL_is_init_finished;
    DlFun<int, void *, int> SSL_key_update;
    DlFun<char *, const void *> SSL_get_version;
    DlFun<void *, const void *> SSL_get_peer_certificate;
    DlFun<void *, const void *> SSL_get_certificate;
    DlFun<void, void *, int, SSLVerifyCallback> SSL_set_verify;
    /* 以下为算法套信息查询接口 */
    DlFun<void *, void *, const unsigned char *> SSL_CIPHER_find;
    DlFun<uint32_t, const void *> SSL_CIPHER_get_id;
    /* 以下为上下文CTX处理接口 */
    DlFun<void *, const void *> SSL_CTX_new;
    DlFun<void, void *> SSL_CTX_free;
    DlFun<int, void *, const char *, const char *> SSL_CTX_load_verify_locations;
    DlFun<void *, const void *> SSL_CTX_get_cert_store;
    DlFun<int, void *, const char *, int> SSL_CTX_use_certificate_file;
    DlFun<int, void *, void *> SSL_CTX_use_certificate;
    DlFun<int, void *, const char *> SSL_CTX_use_certificate_chain_file;
    DlFun<int, void *, const char *, int> SSL_CTX_use_PrivateKey_file;
    DlFun<int, void *, void *> SSL_CTX_use_PrivateKey;
    DlFun<void, void *, void *> SSL_CTX_set_default_passwd_cb_userdata;
    DlFun<int, void *, const char *> SSL_CTX_set_ciphersuites;
    DlFun<void *, void *> SSL_get_current_cipher;
    DlFun<uint64_t, void *, uint64_t> SSL_CTX_set_options;
    DlFun<uint64_t, void *> SSL_CTX_get_options;
    DlFun<void, void *, SCF_AppVerifyFunc, void *> SSL_CTX_set_cert_verify_callback;
    DlFun<int, const void *> SSL_CTX_check_private_key;
    DlFun<void, void *, int, SSLVerifyCallback> SSL_CTX_set_verify;
    DlFun<void, void *, int> SSL_CTX_set_security_level;
    DlFun<void, void *, SSLPskFindSessionCallback> SSL_CTX_set_psk_find_session_callback;
    DlFun<void, void *, SSLPskUseSessionCallback> SSL_CTX_set_psk_use_session_callback;
    DlFun<void *, const void *> SSL_CTX_get_ciphers;
    DlFun<int64_t, void *, int, int64_t, void *> SSL_CTX_ctrl;
    DlFun<void, void *, PemPasswordCallback *> SSL_CTX_set_default_passwd_cb;
    /* 以下为SSL对象处理接口 */
    DlFun<void *> SSL_SESSION_new;
    DlFun<void, void *> SSL_SESSION_free;
    DlFun<void *, const void *> SSL_SESSION_get0_cipher;
    DlFun<int, void *, const unsigned char *, size_t> SSL_SESSION_set1_master_key;
    DlFun<int, void *, const void *> SSL_SESSION_set_cipher;
    DlFun<int, void *, int> SSL_SESSION_set_protocol_version;
    DlFun<int, const void *> SSL_SESSION_get_protocol_version;
    /* 以下为方法设置接口 */
    DlFun<const void *> TLS_server_method;
    DlFun<const void *> TLS_client_method;
    /* 以下为bio处理接口 */
    DlFun<void *, void *, void **, PemPasswordCallback *, void *> PEM_read_bio_X509;
    DlFun<void *, void *, void **, PemPasswordCallback *, void *> PEM_read_bio_X509_CRL;
    DlFun<void *, void *, void **, PemPasswordCallback *, void *> PEM_read_bio_PrivateKey;
    DlFun<void *, void *, void **, PemPasswordCallback *, void *> PEM_read_X509_CRL;
    /* 以下为堆栈操作接口 */
    DlFun<int, const void *> OPENSSL_sk_num;
    DlFun<void *, const void *, int> OPENSSL_sk_value;

private:
    uint32_t LoadAll();

    void UnLoadAll();

    LibSslApi() = default;

    uint64_t versionNum_ = 0;

    uint32_t LoadCipherSuit();

    uint32_t LoadCtx();

    uint32_t LoadSSLObj();

    uint32_t LoadTLSMethod();

    uint32_t LoadBIO();

    uint32_t LoadStackOpt();

    void UnLoadCipherSuit();

    void UnLoadCtx();

    void UnLoadSSLObj();

    void UnLoadTLSMethod();

    void UnLoadBIO();

    void UnLoadStackOpt();
};
}

#endif // LIB_SSL_API_H