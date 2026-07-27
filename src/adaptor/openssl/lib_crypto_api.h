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

    int SetEcParamGenCurveNid(void *ctx, int nid);

    int SetHkdfMd(void *ctx, const void *md);

    int SetHkdfSalt(void *ctx, const void *salt, int saltLen);

    int SetHkdfKey(void *ctx, const void *key, int keyLen);

    int SetHkdfMode(void *ctx, int mode);

    int AddHkdfInfo(void *ctx, const void *info, int infoLen);

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
    DlFun<const void *, const void *> X509_get0_serialNumber;
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

    // EVP 对称加解密
    DlFun<const void *> EVP_aes_128_gcm;
    DlFun<const void *> EVP_aes_256_gcm;
    DlFun<const void *> EVP_aes_128_ccm;
    DlFun<const void *> EVP_chacha20_poly1305;
    DlFun<void *> EVP_CIPHER_CTX_new;
    DlFun<void, void *> EVP_CIPHER_CTX_free;
    DlFun<int, void *, int, int, void *> EVP_CIPHER_CTX_ctrl;
    DlFun<int, void *, const void *, void *, const void *, const void *> EVP_EncryptInit_ex;
    DlFun<int, void *, const void *, int *, const unsigned char *, int> EVP_EncryptUpdate;
    DlFun<int, void *, unsigned char *, int *> EVP_EncryptFinal_ex;
    DlFun<int, void *, const void *, void *, const void *, const void *> EVP_DecryptInit_ex;
    DlFun<int, void *, const void *, int *, const unsigned char *, int> EVP_DecryptUpdate;
    DlFun<int, void *, unsigned char *, int *> EVP_DecryptFinal_ex;

    // EVP 哈希
    DlFun<const void *> EVP_sha512;
    DlFun<void *> EVP_MD_CTX_new;
    DlFun<void, void *> EVP_MD_CTX_free;
    DlFun<int, void *, const void *, void *> EVP_DigestInit_ex;
    DlFun<int, void *, const void *, size_t> EVP_DigestUpdate;
    DlFun<int, void *, unsigned char *, unsigned int *> EVP_DigestFinal_ex;
    DlFun<int, const void *> EVP_MD_get_size;

    // HMAC
    DlFun<unsigned char *, const void *, const void *, int, const unsigned char *, size_t, unsigned char *,
        unsigned int *>
    HMAC;

    // EVP PKEY (非对称 + HKDF)
    DlFun<void *> EVP_PKEY_new;
    DlFun<void *, int, void *> EVP_PKEY_CTX_new_id;
    DlFun<void *, void *, void *> EVP_PKEY_CTX_new;
    DlFun<void, void *> EVP_PKEY_CTX_free;
    DlFun<int, void *> EVP_PKEY_keygen_init;
    DlFun<int, void *, void *> EVP_PKEY_keygen;
    DlFun<int, void *, int> EVP_PKEY_CTX_set_ec_paramgen_curve_nid;
    DlFun<int, void *> EVP_PKEY_derive_init;
    DlFun<int, void *, void *> EVP_PKEY_derive_set_peer;
    DlFun<int, void *, void *, size_t *> EVP_PKEY_derive;
    DlFun<int, void *, int, int, int, int, void *> EVP_PKEY_CTX_ctrl;
    DlFun<int, void *, const void *> EVP_PKEY_CTX_set_hkdf_md;
    DlFun<int, void *, const void *, int> EVP_PKEY_CTX_set1_hkdf_salt;
    DlFun<int, void *, const void *, int> EVP_PKEY_CTX_set1_hkdf_key;
    DlFun<int, void *, int> EVP_PKEY_CTX_set_hkdf_mode;
    DlFun<int, void *, const void *, int> EVP_PKEY_CTX_add1_hkdf_info;

    // 编码
    DlFun<void *, void *, const unsigned char **, long> d2i_PUBKEY;

    // 随机数
    DlFun<int, void *, int> RAND_bytes;

    // Provider API (OpenSSL 3.x+ only, via libcrypto.so)
    DlFun<uint64_t> OpenSSL_version_num;
    DlFun<const char *, int> OpenSSL_version;
    DlFun<void *> OSSL_LIB_CTX_new;
    DlFun<void, void *> OSSL_LIB_CTX_free;
    DlFun<void *, void *, const char *> OSSL_PROVIDER_load;
    DlFun<int, void *> OSSL_PROVIDER_unload;
    DlFun<void, uint64_t, char *, size_t> ERR_error_string_n;

private:
    uint32_t LoadAll();
    uint32_t LoadCoreSymbols();
    uint32_t LoadPkeySymbols();

    void UnLoadAll();
    void UnloadCoreSymbols();
    void UnloadPkeySymbols();

    uint64_t versionNum_ = 0;

    LibCryptoApi() = default;
};
}

#endif // LIB_CRYPTO_API_H