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

#include "lib_ssl_api.h"

#include "scf_inner.h"

namespace scf {

LibSslApi &LibSslApi::GetInstance()
{
    static LibSslApi instance;
    return instance;
}

uint32_t LibSslApi::Init(const std::string &libPath)
{
    UnInit();
    std::ostringstream oos;
    oos << libPath << "/" << libSslName;
    std::string libName = oos.str();
    auto ret = SelfDlOpen(libName);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl Load lib:" << libSslName << " failed, ret:" << ret);
        return ret;
    }
    ret = LoadAll();
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl Load lib:" << libSslName << " Symbol failed, ret:" << ret);
        return ret;
    }
    auto sslRet = OPENSSL_init_ssl(0, nullptr);
    if (sslRet != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl OPENSSL_init_ssl failed, ret:" << ret);
        return SCF_ERRNO_INIT_OPENSSL_CRYPTO;
    }
    return SCF_SUCCESS;
}

void LibSslApi::UnInit()
{
    UnLoadAll();
    SelfDlClose();
}


uint32_t LibSslApi::LoadAll()
{
    uint32_t ret = SCF_SUCCESS;
    if (CONNECTOR_SELF_DLSYM(OpenSSL_version_num) != SCF_SUCCESS) {
        return SCF_ERRNO_LOAD_SYMBOL;
    }
    versionNum_ = OpenSSL_version_num();

    ret |= CONNECTOR_SELF_DLSYM(OPENSSL_init_ssl);
    ret |= CONNECTOR_SELF_DLSYM(SSL_new);
    ret |= CONNECTOR_SELF_DLSYM(SSL_free);
    ret |= CONNECTOR_SELF_DLSYM(SSL_connect);
    ret |= CONNECTOR_SELF_DLSYM(SSL_accept);
    ret |= CONNECTOR_SELF_DLSYM(SSL_get_error);
    ret |= CONNECTOR_SELF_DLSYM(SSL_read_ex);
    ret |= CONNECTOR_SELF_DLSYM(SSL_write_ex);
    ret |= CONNECTOR_SELF_DLSYM(SSL_shutdown);
    ret |= CONNECTOR_SELF_DLSYM(SSL_set_ex_data);
    ret |= CONNECTOR_SELF_DLSYM(SSL_get_ex_data);
    ret |= CONNECTOR_SELF_DLSYM(SSL_set_fd);
    ret |= CONNECTOR_SELF_DLSYM(SSL_is_init_finished);
    ret |= CONNECTOR_SELF_DLSYM(SSL_key_update);
    ret |= CONNECTOR_SELF_DLSYM(SSL_get_version);
    if (versionNum_ >= SSL_VERSION_3_X) {
        ret |= SelfDlSym("SSL_get1_peer_certificate", SSL_get_peer_certificate);
    } else {
        ret |= SelfDlSym("SSL_get_peer_certificate", SSL_get_peer_certificate);
    }
    ret |= CONNECTOR_SELF_DLSYM(SSL_get_certificate);
    ret |= CONNECTOR_SELF_DLSYM(SSL_set_verify);
    ret |= LoadCipherSuit();
    ret |= LoadCtx();
    ret |= LoadSSLObj();
    ret |= LoadTLSMethod();
    ret |= LoadBIO();
    ret |= LoadStackOpt();
    if (ret != SCF_SUCCESS) {
        return SCF_ERRNO_LOAD_SYMBOL;
    }
    return SCF_SUCCESS;
}

uint32_t LibSslApi::LoadCipherSuit()
{
    uint32_t ret = SCF_SUCCESS;
    ret |= CONNECTOR_SELF_DLSYM(SSL_CIPHER_find);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CIPHER_get_id);
    return ret;
}

uint32_t LibSslApi::LoadCtx()
{
    uint32_t ret = SCF_SUCCESS;
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_new);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_free);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_load_verify_locations);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_get_cert_store);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_use_certificate_file);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_use_certificate);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_use_certificate_chain_file);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_use_PrivateKey_file);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_use_PrivateKey);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_set_default_passwd_cb_userdata);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_set_ciphersuites);
    ret |= CONNECTOR_SELF_DLSYM(SSL_get_current_cipher);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_set_options);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_get_options);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_set_cert_verify_callback);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_check_private_key);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_set_verify);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_set_security_level);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_set_psk_find_session_callback);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_set_psk_use_session_callback);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_get_ciphers);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_ctrl);
    ret |= CONNECTOR_SELF_DLSYM(SSL_CTX_set_default_passwd_cb);
    return ret;
}

uint32_t LibSslApi::LoadSSLObj()
{
    uint32_t ret = SCF_SUCCESS;
    ret |= CONNECTOR_SELF_DLSYM(SSL_SESSION_new);
    ret |= CONNECTOR_SELF_DLSYM(SSL_SESSION_free);
    ret |= CONNECTOR_SELF_DLSYM(SSL_SESSION_get0_cipher);
    ret |= CONNECTOR_SELF_DLSYM(SSL_SESSION_set1_master_key);
    ret |= CONNECTOR_SELF_DLSYM(SSL_SESSION_set_cipher);
    ret |= CONNECTOR_SELF_DLSYM(SSL_SESSION_set_protocol_version);
    ret |= CONNECTOR_SELF_DLSYM(SSL_SESSION_get_protocol_version);
    return ret;
}

uint32_t LibSslApi::LoadTLSMethod()
{
    uint32_t ret = SCF_SUCCESS;
    ret |= CONNECTOR_SELF_DLSYM(TLS_server_method);
    ret |= CONNECTOR_SELF_DLSYM(TLS_client_method);
    return ret;
}

uint32_t LibSslApi::LoadBIO()
{
    uint32_t ret = SCF_SUCCESS;
    ret |= CONNECTOR_SELF_DLSYM(PEM_read_bio_X509);
    ret |= CONNECTOR_SELF_DLSYM(PEM_read_bio_X509_CRL);
    ret |= CONNECTOR_SELF_DLSYM(PEM_read_bio_PrivateKey);
    ret |= CONNECTOR_SELF_DLSYM(PEM_read_X509_CRL);
    return ret;
}

uint32_t LibSslApi::LoadStackOpt()
{
    uint32_t ret = SCF_SUCCESS;
    ret |= CONNECTOR_SELF_DLSYM(OPENSSL_sk_num);
    ret |= CONNECTOR_SELF_DLSYM(OPENSSL_sk_value);
    return ret;
}

void LibSslApi::UnLoadAll()
{
    OPENSSL_init_ssl.Reset();
    SSL_new.Reset();
    SSL_free.Reset();
    SSL_connect.Reset();
    SSL_accept.Reset();
    SSL_get_error.Reset();
    SSL_read_ex.Reset();
    SSL_write_ex.Reset();
    SSL_shutdown.Reset();
    SSL_set_ex_data.Reset();
    SSL_get_ex_data.Reset();
    SSL_set_fd.Reset();
    SSL_is_init_finished.Reset();
    SSL_key_update.Reset();
    SSL_get_version.Reset();
    SSL_get_peer_certificate.Reset();
    SSL_get_certificate.Reset();
    SSL_set_verify.Reset();
    UnLoadCipherSuit();
    UnLoadCtx();
    UnLoadSSLObj();
    UnLoadTLSMethod();
    UnLoadBIO();
    UnLoadStackOpt();
    versionNum_ = 0;
}

void LibSslApi::UnLoadCipherSuit()
{
    SSL_CIPHER_find.Reset();
    SSL_CIPHER_get_id.Reset();
}

void LibSslApi::UnLoadCtx()
{
    SSL_CTX_new.Reset();
    SSL_CTX_free.Reset();
    SSL_CTX_load_verify_locations.Reset();
    SSL_CTX_get_cert_store.Reset();
    SSL_CTX_use_certificate_file.Reset();
    SSL_CTX_use_certificate.Reset();
    SSL_CTX_use_certificate_chain_file.Reset();
    SSL_CTX_use_PrivateKey_file.Reset();
    SSL_CTX_use_PrivateKey.Reset();
    SSL_CTX_set_default_passwd_cb_userdata.Reset();
    SSL_CTX_set_ciphersuites.Reset();
    SSL_get_current_cipher.Reset();
    SSL_CTX_set_options.Reset();
    SSL_CTX_get_options.Reset();
    SSL_CTX_set_cert_verify_callback.Reset();
    SSL_CTX_check_private_key.Reset();
    SSL_CTX_set_verify.Reset();
    SSL_CTX_set_security_level.Reset();
    SSL_CTX_set_psk_find_session_callback.Reset();
    SSL_CTX_set_psk_use_session_callback.Reset();
    SSL_CTX_get_ciphers.Reset();
    SSL_CTX_ctrl.Reset();
    SSL_CTX_set_default_passwd_cb.Reset();
}

void LibSslApi::UnLoadSSLObj()
{
    SSL_SESSION_new.Reset();
    SSL_SESSION_free.Reset();
    SSL_SESSION_get0_cipher.Reset();
    SSL_SESSION_set1_master_key.Reset();
    SSL_SESSION_set_cipher.Reset();
    SSL_SESSION_set_protocol_version.Reset();
    SSL_SESSION_get_protocol_version.Reset();
}

void LibSslApi::UnLoadTLSMethod()
{
    TLS_server_method.Reset();
    TLS_client_method.Reset();
}

void LibSslApi::UnLoadBIO()
{
    PEM_read_bio_X509.Reset();
    PEM_read_bio_X509_CRL.Reset();
    PEM_read_bio_PrivateKey.Reset();
    PEM_read_X509_CRL.Reset();
}

void LibSslApi::UnLoadStackOpt()
{
    OPENSSL_sk_num.Reset();
    OPENSSL_sk_value.Reset();
}
}