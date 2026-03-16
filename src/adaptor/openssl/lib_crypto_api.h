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

#ifndef LIB_CRYPTO_API_H
#define LIB_CRYPTO_API_H

#include "dlopen_lib_base.h"
#include "openssl_def.h"

namespace scf {
const std::string libCryptoName = "libcrypto.so";

class LibCryptoApi final : public DlOpenLibBase {
public:
    LibCryptoApi(const LibCryptoApi &) = delete;

    void operator=(const LibCryptoApi &) = delete;

    static LibCryptoApi &GetInstance();

    uint32_t Init(const std::string &libPath) override;

    void UnInit() override;

    char *ErrErrorString();

    DlFun<int, uint64_t, const void *> OPENSSL_init_crypto;
    DlFun<int, void *, void *> X509_STORE_add_cert;
    DlFun<int, void *, void *> X509_STORE_add_crl;
    DlFun<int, void *, uint64_t> X509_STORE_set_flags;
    DlFun<void, void *> X509_free;
    DlFun<void, void *> X509_CRL_free;
    DlFun<int64_t, const void *> X509_get_version;
    DlFun<void *, const void *> X509_getm_notBefore;
    DlFun<void *, const void *> X509_getm_notAfter;
    DlFun<void *, void *> X509_get_serialNumber;
    DlFun<int, const void *> X509_verify_cert;
    DlFun<int, void *> X509_STORE_CTX_get_error;
    DlFun<void *, void *, int> BIO_new_mem_buf;
    DlFun<int, void *> BIO_free;
    DlFun<void, void *> EVP_PKEY_free;
    DlFun<const void *> EVP_sha256;
    DlFun<const void *> EVP_sha384;
    DlFun<uint64_t> ERR_get_error;
    DlFun<char *, uint64_t, char *> ERR_error_string;
    DlFun<void, ERRPrintErrorsCallback, void *> ERR_print_errors_cb;

private:
    uint32_t LoadAll();

    void UnLoadAll();

    LibCryptoApi() = default;
};
}

#endif // LIB_CRYPTO_API_H