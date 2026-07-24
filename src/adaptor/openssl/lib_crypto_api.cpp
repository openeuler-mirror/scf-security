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
    uint32_t ret = LoadCoreSymbols();
    ret |= LoadPkeySymbols();
    if (ret != SCF_SUCCESS) {
        return SCF_ERRNO_LOAD_SYMBOL;
    }
    return SCF_SUCCESS;
}

uint32_t LibCryptoApi::LoadCoreSymbols()
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
    ret |= CONNECTOR_SELF_DLSYM(X509_get0_serialNumber);
    ret |= CONNECTOR_SELF_DLSYM(X509_verify_cert);
    ret |= CONNECTOR_SELF_DLSYM(X509_STORE_CTX_get_error);
    ret |= CONNECTOR_SELF_DLSYM(OBJ_txt2obj);
    ret |= CONNECTOR_SELF_DLSYM(ASN1_OBJECT_free);
    ret |= CONNECTOR_SELF_DLSYM(X509_get_ext_by_OBJ);
    ret |= CONNECTOR_SELF_DLSYM(X509_get_ext);
    ret |= CONNECTOR_SELF_DLSYM(X509_EXTENSION_get_data);
    ret |= CONNECTOR_SELF_DLSYM(ASN1_STRING_get0_data);
    ret |= CONNECTOR_SELF_DLSYM(ASN1_STRING_length);
    ret |= CONNECTOR_SELF_DLSYM(BIO_new_mem_buf);
    ret |= CONNECTOR_SELF_DLSYM(BIO_free);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_free);
    ret |= CONNECTOR_SELF_DLSYM(EVP_sha256);
    ret |= CONNECTOR_SELF_DLSYM(EVP_sha384);
    ret |= CONNECTOR_SELF_DLSYM(ERR_get_error);
    ret |= CONNECTOR_SELF_DLSYM(ERR_error_string);
    ret |= CONNECTOR_SELF_DLSYM(ERR_print_errors_cb);
    ret |= CONNECTOR_SELF_DLSYM(EVP_aes_128_gcm);
    ret |= CONNECTOR_SELF_DLSYM(EVP_aes_256_gcm);
    ret |= CONNECTOR_SELF_DLSYM(EVP_aes_128_ccm);
    ret |= CONNECTOR_SELF_DLSYM(EVP_chacha20_poly1305);
    ret |= CONNECTOR_SELF_DLSYM(EVP_CIPHER_CTX_new);
    ret |= CONNECTOR_SELF_DLSYM(EVP_CIPHER_CTX_free);
    ret |= CONNECTOR_SELF_DLSYM(EVP_CIPHER_CTX_ctrl);
    ret |= CONNECTOR_SELF_DLSYM(EVP_EncryptInit_ex);
    ret |= CONNECTOR_SELF_DLSYM(EVP_EncryptUpdate);
    ret |= CONNECTOR_SELF_DLSYM(EVP_EncryptFinal_ex);
    ret |= CONNECTOR_SELF_DLSYM(EVP_DecryptInit_ex);
    ret |= CONNECTOR_SELF_DLSYM(EVP_DecryptUpdate);
    ret |= CONNECTOR_SELF_DLSYM(EVP_DecryptFinal_ex);
    ret |= CONNECTOR_SELF_DLSYM(EVP_sha512);
    ret |= CONNECTOR_SELF_DLSYM(EVP_MD_CTX_new);
    ret |= CONNECTOR_SELF_DLSYM(EVP_MD_CTX_free);
    ret |= CONNECTOR_SELF_DLSYM(EVP_DigestInit_ex);
    ret |= CONNECTOR_SELF_DLSYM(EVP_DigestUpdate);
    ret |= CONNECTOR_SELF_DLSYM(EVP_DigestFinal_ex);
    ret |= CONNECTOR_SELF_DLSYM(EVP_MD_get_size);
    ret |= CONNECTOR_SELF_DLSYM(HMAC);
    ret |= CONNECTOR_SELF_DLSYM(OpenSSL_version);
    return ret;
}

uint32_t LibCryptoApi::LoadPkeySymbols()
{
    uint32_t ret = SCF_SUCCESS;
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_new);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_CTX_new_id);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_CTX_new);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_CTX_free);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_keygen_init);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_keygen);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_CTX_set_ec_paramgen_curve_nid);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_derive_init);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_derive_set_peer);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_derive);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_CTX_set_hkdf_md);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_CTX_set1_hkdf_salt);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_CTX_set1_hkdf_key);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_CTX_set_hkdf_mode);
    ret |= CONNECTOR_SELF_DLSYM(EVP_PKEY_CTX_add1_hkdf_info);
    ret |= CONNECTOR_SELF_DLSYM(d2i_PUBKEY);
    ret |= CONNECTOR_SELF_DLSYM(RAND_bytes);
    ret |= CONNECTOR_SELF_DLSYM(OpenSSL_version_num);
    if (ret == SCF_SUCCESS) {
        versionNum_ = OpenSSL_version_num();
    }
    if (versionNum_ >= SSL_VERSION_3_X) {
        ret |= CONNECTOR_SELF_DLSYM(OSSL_LIB_CTX_new);
        ret |= CONNECTOR_SELF_DLSYM(OSSL_LIB_CTX_free);
        ret |= CONNECTOR_SELF_DLSYM(OSSL_PROVIDER_load);
        ret |= CONNECTOR_SELF_DLSYM(OSSL_PROVIDER_unload);
        ret |= CONNECTOR_SELF_DLSYM(ERR_error_string_n);
    }
    return ret;
}

void LibCryptoApi::UnLoadAll()
{
    UnloadCoreSymbols();
    UnloadPkeySymbols();
}

void LibCryptoApi::UnloadCoreSymbols()
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
    X509_get0_serialNumber.Reset();
    X509_verify_cert.Reset();
    X509_STORE_CTX_get_error.Reset();
    OBJ_txt2obj.Reset();
    ASN1_OBJECT_free.Reset();
    X509_get_ext_by_OBJ.Reset();
    X509_get_ext.Reset();
    X509_EXTENSION_get_data.Reset();
    ASN1_STRING_get0_data.Reset();
    ASN1_STRING_length.Reset();
    BIO_new_mem_buf.Reset();
    BIO_free.Reset();
    EVP_PKEY_free.Reset();
    EVP_sha256.Reset();
    EVP_sha384.Reset();
    ERR_get_error.Reset();
    ERR_error_string.Reset();
    ERR_print_errors_cb.Reset();
    EVP_aes_128_gcm.Reset();
    EVP_aes_256_gcm.Reset();
    EVP_aes_128_ccm.Reset();
    EVP_chacha20_poly1305.Reset();
    EVP_CIPHER_CTX_new.Reset();
    EVP_CIPHER_CTX_free.Reset();
    EVP_CIPHER_CTX_ctrl.Reset();
    EVP_EncryptInit_ex.Reset();
    EVP_EncryptUpdate.Reset();
    EVP_EncryptFinal_ex.Reset();
    EVP_DecryptInit_ex.Reset();
    EVP_DecryptUpdate.Reset();
    EVP_DecryptFinal_ex.Reset();
    EVP_sha512.Reset();
    EVP_MD_CTX_new.Reset();
    EVP_MD_CTX_free.Reset();
    EVP_DigestInit_ex.Reset();
    EVP_DigestUpdate.Reset();
    EVP_DigestFinal_ex.Reset();
    EVP_MD_get_size.Reset();
    HMAC.Reset();
    OpenSSL_version.Reset();
}

void LibCryptoApi::UnloadPkeySymbols()
{
    EVP_PKEY_new.Reset();
    EVP_PKEY_CTX_new_id.Reset();
    EVP_PKEY_CTX_new.Reset();
    EVP_PKEY_CTX_free.Reset();
    EVP_PKEY_keygen_init.Reset();
    EVP_PKEY_keygen.Reset();
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid.Reset();
    EVP_PKEY_derive_init.Reset();
    EVP_PKEY_derive_set_peer.Reset();
    EVP_PKEY_derive.Reset();
    EVP_PKEY_CTX_set_hkdf_md.Reset();
    EVP_PKEY_CTX_set1_hkdf_salt.Reset();
    EVP_PKEY_CTX_set1_hkdf_key.Reset();
    EVP_PKEY_CTX_set_hkdf_mode.Reset();
    EVP_PKEY_CTX_add1_hkdf_info.Reset();
    d2i_PUBKEY.Reset();
    RAND_bytes.Reset();
    OpenSSL_version_num.Reset();
    OSSL_LIB_CTX_new.Reset();
    OSSL_LIB_CTX_free.Reset();
    OSSL_PROVIDER_load.Reset();
    OSSL_PROVIDER_unload.Reset();
    ERR_error_string_n.Reset();
    versionNum_ = 0;
}
}
