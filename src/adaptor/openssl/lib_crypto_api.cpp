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

#include "lib_crypto_api.h"

namespace scf {
LibCryptoApi &LibCryptoApi::GetInstance()
{
    static LibCryptoApi instance;
    return instance;
}

uint32_t LibCryptoApi::Init(const std::string &libPath)
{
    UnInit();
    std::ostringstream oos;
    oos << libPath << "/" << libCryptoName;
    std::string libName = oos.str();
    auto ret = SelfDlOpen(libName);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl Load lib:" << libCryptoName << " failed, ret:" << ret);
        return ret;
    }
    ret = LoadAll();
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl Load lib:" << libCryptoName << " Symbol failed, ret:" << ret);
        return ret;
    }
    auto sslRet = OPENSSL_init_crypto(0, nullptr);
    if (sslRet != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl OPENSSL_init_crypto failed, ret:" << ret);
        return SCF_ERRNO_INIT_OPENSSL_CRYPTO;
    }
    return SCF_SUCCESS;
}

void LibCryptoApi::UnInit()
{
    UnLoadAll();
    SelfDlClose();
}

char *LibCryptoApi::ErrErrorString()
{
    auto errorCode = ERR_get_error();
    return ERR_error_string(errorCode, nullptr);
}

uint32_t LibCryptoApi::LoadAll()
{
    uint32_t ret = SCF_SUCCESS;
    ret |= CONNECTOR_SELF_DLSYM(OPENSSL_init_crypto);
    ret |= CONNECTOR_SELF_DLSYM(X509_STORE_add_cert);
    ret |= CONNECTOR_SELF_DLSYM(X509_STORE_add_crl);
    ret |= CONNECTOR_SELF_DLSYM(X509_STORE_set_flags);
    ret |= CONNECTOR_SELF_DLSYM(X509_free);
    ret |= CONNECTOR_SELF_DLSYM(X509_CRL_free);
    ret |= CONNECTOR_SELF_DLSYM(X509_get_version);
    ret |= CONNECTOR_SELF_DLSYM(X509_getm_notBefore);
    ret |= CONNECTOR_SELF_DLSYM(X509_getm_notAfter);
    ret |= CONNECTOR_SELF_DLSYM(X509_get_serialNumber);
    ret |= CONNECTOR_SELF_DLSYM(X509_verify_cert);
    ret |= CONNECTOR_SELF_DLSYM(X509_STORE_CTX_get_error);
    ret |= CONNECTOR_SELF_DLSYM(BIO_new_mem_buf);
    ret |= CONNECTOR_SELF_DLSYM(BIO_free);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_free);
    ret |= CONNECTOR_SELF_DLSYM(EVP_sha256);
    ret |= CONNECTOR_SELF_DLSYM(EVP_sha384);
    ret |= CONNECTOR_SELF_DLSYM(ERR_get_error);
    ret |= CONNECTOR_SELF_DLSYM(ERR_error_string);
    ret |= CONNECTOR_SELF_DLSYM(ERR_print_errors_cb);
    if (ret != SCF_SUCCESS) {
        return SCF_ERRNO_LOAD_SYMBOL;
    }
    return SCF_SUCCESS;
}

void LibCryptoApi::UnLoadAll()
{
    OPENSSL_init_crypto.Reset();
    X509_STORE_add_cert.Reset();
    X509_STORE_add_crl.Reset();
    X509_STORE_set_flags.Reset();
    X509_free.Reset();
    X509_CRL_free.Reset();
    X509_get_version.Reset();
    X509_getm_notBefore.Reset();
    X509_getm_notAfter.Reset();
    X509_get_serialNumber.Reset();
    X509_verify_cert.Reset();
    X509_STORE_CTX_get_error.Reset();
    BIO_new_mem_buf.Reset();
    BIO_free.Reset();
    EVP_PKEY_free.Reset();
    EVP_sha256.Reset();
    EVP_sha384.Reset();
    ERR_get_error.Reset();
    ERR_error_string.Reset();
    ERR_print_errors_cb.Reset();
}
}