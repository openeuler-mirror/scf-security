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

#include "openssl_adaptor.h"

#include <custom_logger.h>

#include <memory>

#include "scf_errno.h"
#include "scf_def.h"
#include "scf_crypto_engine.h"
#include "lib_ssl_api.h"
#include "lib_crypto_api.h"
#include "openssl_def.h"
#include "scf_inner.h"
#include "securec.h"

// Undefine macros from openssl_def.h that conflict with real OpenSSL type declarations.
// openssl_def.h #define's SSL_CTX/SSL/BIO/etc. to void for dlopen-based abstraction,
// but including <openssl/ssl.h> with these macros active causes "multiple types in one declaration".
#undef SSL
#undef SSL_CTX
#undef SSL_METHOD
#undef SSL_SESSION
#undef SSL_CIPHER
#undef BIO
#undef EVP_PKEY
#undef EVP_MD
#undef X509
#undef X509_CRL
#undef X509_STORE
#undef X509_STORE_CTX

#include <openssl/ssl.h>
#include <openssl/provider.h>

// Save real OpenSSL types before re-defining macros, for use in static_cast<> when
// calling OpenSSL APIs directly (which require real types, not void*).
using RealSsl        = SSL;
using RealSslCtx     = SSL_CTX;
using RealSslMethod  = SSL_METHOD;
using RealSslSession = SSL_SESSION;
using RealSslCipher  = SSL_CIPHER;
using RealBio        = BIO;
using RealEvpPkey    = EVP_PKEY;
using RealEvpMd      = EVP_MD;
using RealX509       = X509;
using RealX509Crl    = X509_CRL;
using RealX509Store  = X509_STORE;
using RealX509StoreCtx = X509_STORE_CTX;

// Re-define macros so that function signatures match the header (which uses void* types).
// All direct OpenSSL API calls in this file must use static_cast to Real* types.
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

// OpenSSL 3.x headers rename SSL_get_peer_certificate → SSL_get1_peer_certificate via macro,
// but LibSslApi's member is named SSL_get_peer_certificate (dlsym loads both symbol names).
// Undef to prevent the rename from breaking member access.
#ifdef SSL_get_peer_certificate
#undef SSL_get_peer_certificate
#endif

namespace scf {

static int SslErrorsPrint(const char *errStr, size_t errStrLen, void *userdata)
{
    (void)userdata;
    /* Openssl确保调用该回调传入时有效参数，此处为防御性校验，针对空字符串默认返回成功 */
    if (errStr == nullptr || errStrLen == 0) {
        return SSL_SUCCESS;
    }

    CCSEC_LOG_ERROR("Openssl inner error log: " << errStr << ".");
    return SSL_SUCCESS;
}

bool OpenSSLAdapter::g_certlog_switch = false;

int32_t OpenSSLAdapter::Init(uint64_t flag, const void *settings)
{
    (void) flag; // 预留
    if (settings == nullptr) {
        return SCF_ERRNO_LOAD_LIB;
    }
    std::string libPath(static_cast<const char *>(settings));
    auto ret = LibCryptoApi::GetInstance().Init(libPath);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl Crypto Init Fail, ret:" << ret);
        DeInit();
        return ret;
    }
    ret = LibSslApi::GetInstance().Init(libPath);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl SSL Init Fail, ret:" << ret);
        DeInit();
        return ret;
    }
    return SCF_SUCCESS;
}

void OpenSSLAdapter::DeInit()
{
    m_cryptoEngine = nullptr;  // 引擎生命周期由调用方管理，此处仅清除引用
    LibCryptoApi::GetInstance().UnInit();
    LibSslApi::GetInstance().UnInit();
}

// ============================================================
// CryptoEngine 注入 (v2.0)
// ============================================================

void OpenSSLAdapter::SetCryptoEngine(ICryptoEngine *engine)
{
    m_cryptoEngine = engine;
    if (engine != nullptr) {
        CCSEC_LOG_INFO("OpenSSLAdapter: crypto engine set: "
            << (engine->IsHardwareAccelerated() ? "HARDWARE" : "SOFTWARE")
            << " (" << engine->GetAcceleratedAlgorithms() << ")");
    } else {
        CCSEC_LOG_INFO("OpenSSLAdapter: crypto engine cleared (using default)");
    }
}

ICryptoEngine *OpenSSLAdapter::GetCryptoEngine() const
{
    return m_cryptoEngine;
}

// ============================================================
// 密钥交换组配置 (v2.0, 抗量子支持)
// ============================================================
// 通过 SSL_CTX_set1_groups_list() 配置 TLS 1.3 密钥协商命名组。
// 支持经典 ECDH 组 (X25519/P-256/P-384/P-521) 和
// 后量子 Hybrid KEM 组 (p256_kyber512/x25519_kyber512/p521_kyber1024 等)。
// groups 格式: 冒号分隔的命名组列表，如 "X25519:P-256:p256_kyber512"
// 如果 PQ Provider 不可用，不支持的组会被自动跳过。

int32_t OpenSSLAdapter::SetKeyExchangeGroups(
    SCF_PolicyCtx *ctx, const std::vector<std::string> &groups)
{
    if (ctx == nullptr || ctx->sslConfig == nullptr) {
        CCSEC_LOG_WARN("OpenSSLAdapter: SetKeyExchangeGroups called with null ctx or sslConfig,"
            << " groups will be applied later.");
        return SCF_ERRNO_NULL_INPUT;
    }

    if (groups.empty()) {
        return SCF_SUCCESS;
    }

    // 构建冒号分隔的 groups 字符串: "X25519:P-256:p256_kyber512:..."
    std::string groupsStr;
    for (size_t i = 0; i < groups.size(); ++i) {
        if (i > 0) groupsStr += ":";
        groupsStr += groups[i];
    }

    auto *realSslCtx = static_cast<RealSslCtx *>(ctx->sslConfig);
    long ret = SSL_CTX_set1_groups_list(realSslCtx, groupsStr.c_str());
    if (ret != 1) {
        CCSEC_LOG_ERROR("OpenSSLAdapter: SSL_CTX_set1_groups_list failed for groups: "
            << groupsStr << ". Some groups may not be available (check PQ Provider).");
        // 不返回失败：某些组不可用是预期行为（如 PQ Provider 未加载时）
        // OpenSSL 会自动使用可用的组
    } else {
        CCSEC_LOG_INFO("OpenSSLAdapter: key exchange groups set: " << groupsStr);
    }

    return SCF_SUCCESS;
}

void OpenSSLAdapter::LogCertError(SCF_PolicyObj *obj)
{
    if (obj == nullptr) {
        return;
    }

    const X509 *cert = static_cast<const X509 *>(GetCurrentCert(obj));
    int32_t certVersion = GetCertVersion(cert);

    uint32_t snLen = 0;
    auto *certSN = reinterpret_cast<char *>(GetCertSerialNumber(cert, &snLen));

    char certHexSN[MAX_SERINALNUM_HEX_LEN];
    int32_t ret = Num2HexStr(certSN, snLen, certHexSN, MAX_SERINALNUM_HEX_LEN);
    CCSEC_LOG_ERROR("Cert Fail, CertVersion: " << certVersion);
    if (ret == SCF_SUCCESS) {
        CCSEC_LOG_ERROR("Cert SN: 0x" << certHexSN);
    }
    char *startTime = GetCertStartTime(cert);
    if (startTime != nullptr) {
        CCSEC_LOG_ERROR("Cert Start time: " << startTime);
        delete []startTime;
    }
    char *endTime = GetCertEndTime(cert);
    if (endTime != nullptr) {
        CCSEC_LOG_ERROR("Cert End time: " << endTime);
        delete []endTime;
    }
}

int32_t OpenSSLAdapter::HandleTransPortError(SCF_PolicyObj *obj, int32_t errorCode)
{
    // 针对故障模式进行处理
    // 目前只有一种故障模式，只有简易的证书详细信息开关
    if (errorCode == SSL_ERROR_WANT_READ) {
        return SCF_SSL_ERR_WANT_READ;
    }
    if (errorCode == SSL_ERROR_WANT_WRITE) {
        return SCF_SSL_ERR_WANT_WRITE;
    }
    CCSEC_LOG_ERROR("SSL_connect (Client) or SSL_accept (Server) failed! OPENSSL Error Code: "<< errorCode);
    LibCryptoApi::GetInstance().ERR_print_errors_cb(SslErrorsPrint, nullptr);
    if (g_certlog_switch) {
        LogCertError(obj);
    }
    return SCF_ERRNO_SECURE_TRANSPORT;
}

void OpenSSLAdapter::OpenCertErrorLog()
{
    g_certlog_switch = true;
}

void OpenSSLAdapter::CloseCertErrorLog()
{
    g_certlog_switch = false;
}

// SCF_cal_ssl_obj
void OpenSSLAdapter::FreeSslObj(SCF_PolicyObj *obj)
{
    if (obj != nullptr && obj->sslCtx != nullptr) {
        LibSslApi::GetInstance().SSL_free(obj->sslCtx);
        obj->sslCtx = nullptr;
    }
}

int32_t OpenSSLAdapter::Connect(SCF_PolicyObj *obj)
{
    if (obj == nullptr || obj->sslCtx == nullptr) {
        CCSEC_LOG_INFO("Openssl Connect obj or sslCtx is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (obj->role != SCF_ROLE_CLIENT) {
        return SCF_SSL_ERR_ROLE;
    }
    if (!obj->isSetRole) {
        obj->isSetRole = true;
    }
    int32_t ret = LibSslApi::GetInstance().SSL_connect(obj->sslCtx);
    if (ret != SSL_SUCCESS) {
        ret = LibSslApi::GetInstance().SSL_get_error(obj->sslCtx, ret);
        return HandleTransPortError(obj, ret);
    }
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::Accept(SCF_PolicyObj *obj)
{
    if (obj == nullptr || obj->sslCtx == nullptr) {
        CCSEC_LOG_INFO("Openssl Connect obj or sslCtx is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (obj->role != SCF_ROLE_SERVER) {
        return SCF_SSL_ERR_ROLE;
    }
    if (!obj->isSetRole) {
        obj->isSetRole = true;
    }
    int32_t ret = LibSslApi::GetInstance().SSL_accept(obj->sslCtx);
    if (ret != SSL_SUCCESS) {
        ret = LibSslApi::GetInstance().SSL_get_error(obj->sslCtx, ret);
        return HandleTransPortError(obj, ret);
    }
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::Read(SCF_PolicyObj *obj, uint8_t *data, uint32_t dataLen, uint32_t *readLen)
{
    if (obj == nullptr || obj->sslCtx == nullptr) {
        CCSEC_LOG_INFO("Openssl Read, obj or sslCtx is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    size_t readLenIn = 0;
    int32_t ret = LibSslApi::GetInstance().SSL_read_ex(obj->sslCtx, data, dataLen, &readLenIn);
    if (ret != SSL_SUCCESS) {
        int err = LibSslApi::GetInstance().SSL_get_error(obj->sslCtx, ret);
        if (err == SSL_ERROR_WANT_READ) {
            return SCF_SSL_ERR_WANT_READ;
        }
        CCSEC_LOG_ERROR("Openssl Read Fail, OPENSSL Error Code: " << err);
        LibCryptoApi::GetInstance().ERR_print_errors_cb(SslErrorsPrint, nullptr);
        return SCF_SSL_ERR_READ;
    }
    *readLen = static_cast<uint32_t>(readLenIn);
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::Write(SCF_PolicyObj *obj, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen)
{
    if (obj == nullptr || obj->sslCtx == nullptr) {
        CCSEC_LOG_INFO("Openssl Write, obj or sslCtx is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    size_t writeLenIn = 0;
    int32_t ret = LibSslApi::GetInstance().SSL_write_ex(obj->sslCtx, data, dataLen, &writeLenIn);
    if (ret != SSL_SUCCESS) {
        int err = LibSslApi::GetInstance().SSL_get_error(obj->sslCtx, ret);
        if (err == SSL_ERROR_WANT_WRITE) {
            return SCF_SSL_ERR_WANT_WRITE;
        }
        CCSEC_LOG_ERROR("Openssl Write Fail, OPENSSL Error Code: " << err);
        LibCryptoApi::GetInstance().ERR_print_errors_cb(SslErrorsPrint, nullptr);
        return SCF_SSL_ERR_WRITE;
    }
    *writeLen = static_cast<uint32_t>(writeLenIn);
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::Close(SCF_PolicyObj *obj)
{
    if (obj == nullptr || obj->sslCtx == nullptr) {
        CCSEC_LOG_INFO("Openssl Close, obj or sslCtx is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    int32_t ret = LibSslApi::GetInstance().SSL_shutdown(obj->sslCtx);
    if (ret < 0) {
        /**
        * 这个函数返回值特殊。=1 表示发送并接收到对端的 close notify。
        * =0 表示发送了 close notify 但还没有收到对端的，不是错误，不应该调用 SSL_get_error。
        * <0 才表示 shutdown 失败。
        */
        int32_t detailErr = LibSslApi::GetInstance().SSL_get_error(obj->sslCtx, ret);
        CCSEC_LOG_ERROR("Openssl Close not finished, OPENSSL Code: " << ret << ", detail error code: " << detailErr);
        return SCF_SSL_ERR_CLOSE;
    }
    return SCF_SUCCESS;
}

uint32_t OpenSSLAdapter::CheckVersion(SCF_PolicyObj *obj)
{
    if (obj == nullptr || obj->policyCtx == nullptr || obj->policyCtx->sslConfig == nullptr) {
        CCSEC_LOG_ERROR("Openssl Get Version Bit Fail, obj or polictCtx or sslConfig is nullptr.");
        return SSL_ERROR;
    }
    auto minVersion = SSL_CTX_get_min_proto_version(static_cast<RealSslCtx *>(obj->policyCtx->sslConfig));
    auto maxVersion = SSL_CTX_get_max_proto_version(static_cast<RealSslCtx *>(obj->policyCtx->sslConfig));
    if (minVersion == 0 && maxVersion == 0) {
        return SSL_SUCCESS;
    }

    auto options = LibSslApi::GetInstance().SSL_CTX_get_options(obj->policyCtx->sslConfig);
    for (auto version = minVersion; version <= maxVersion; version++) {
        uint32_t sslOp = 0;
        if (MapVersion2NoOpt(version, &sslOp) != SSL_SUCCESS) {
            CCSEC_LOG_ERROR("Openssl Get Version Bit Fail, Version: " << version << ".");
            return SSL_ERROR;
        }
        if ((sslOp & options) == 0) {
            // 存在未被禁止版本
            return SSL_SUCCESS;
        }
    }
    return SSL_ERROR;
}

int32_t OpenSSLAdapter::SetFd(SCF_PolicyObj *obj, int32_t fd)
{
    if (obj == nullptr) {
        return SCF_ERRNO_NULL_INPUT;
    }
    bool hasNewSSL = false;
    if (obj->sslCtx == nullptr) {
        /* 检查是否所有ssl版本都被禁用，若都禁用则创建失败 */
        if (CheckVersion(obj) != SSL_SUCCESS) {
            return SCF_SSL_ERR_POLICY_VERSION;
        }
        SSL *ssl = LibSslApi::GetInstance().SSL_new(obj->policyCtx->sslConfig);
        if (LibSslApi::GetInstance().SSL_set_ex_data(ssl, SSL_EX_DATA_ID, obj) != SSL_SUCCESS) {
            LibSslApi::GetInstance().SSL_free(ssl);
            return SCF_SSL_ERR_SET_EX_DATA;
        }
        obj->sslCtx = ssl;
        hasNewSSL = true;
    }
    if (LibSslApi::GetInstance().SSL_set_fd(obj->sslCtx, fd) != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl Set Fd Fail.");
        if (hasNewSSL) {
            LibSslApi::GetInstance().SSL_free(obj->sslCtx);
            obj->sslCtx = nullptr;
        }
        return SCF_SSL_ERR_SET_SOCKET_FD;
    }
    obj->fd = fd;
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::InnerGetOpensslUpdateType(KeyUpdateType updateType, int *opensslUpdateType)
{
    if (opensslUpdateType == nullptr) {
        return SCF_ERRNO_NULL_INPUT;
    }
    if (updateType == KeyUpdateType::KEY_UPDATE_NONE) {
        *opensslUpdateType = SSL_KEY_UPDATE_NONE;
    } else if (updateType == KeyUpdateType::KEY_UPDATE_NOT_REQUESTED) {
        *opensslUpdateType = SSL_KEY_UPDATE_NOT_REQUESTED;
    } else if (updateType == KeyUpdateType::KEY_UPDATE_REQUESTED) {
        *opensslUpdateType = SSL_KEY_UPDATE_REQUESTED;
    } else {
        return SCF_ERROR;
    }
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::KeyUpdate(SCF_PolicyObj *obj, KeyUpdateType updateType)
{
    if (obj == nullptr || obj->sslCtx == nullptr) {
        CCSEC_LOG_ERROR("Openssl KeyUpdate obj or sslCtx is null.");
        return SCF_SSL_ERR_KEY_UPDATE;
    }

    int32_t ret = LibSslApi::GetInstance().SSL_is_init_finished(obj->sslCtx);
    if (ret != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl Is Init Finished Fail, OPENSSL Error Code: " << ret);
        return SCF_SSL_ERR_IS_INIT_FINISHED;
    }

    int opensslUpdateType;
    ret = InnerGetOpensslUpdateType(updateType, &opensslUpdateType);
    if (ret != SCF_SUCCESS) {
        return SCF_SSL_ERR_KEY_UPDATE;
    }

    ret = LibSslApi::GetInstance().SSL_key_update(obj->sslCtx, opensslUpdateType);
    if (ret != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl Key Update Fail, OPENSSL Error Code: " << ret);
        LibCryptoApi::GetInstance().ERR_print_errors_cb(SslErrorsPrint, nullptr);
        return SCF_SSL_ERR_KEY_UPDATE;
    }
    obj->keyUpdateInfo.totalSizeOfWriteData = 0;
    obj->keyUpdateInfo.lastKeyUpdateTime = 0;
    obj->keyUpdateInfo.isLastUpdateSuccess = true;
    return SCF_SUCCESS;
}

const char *OpenSSLAdapter::GetVersion(SCF_PolicyObj *obj)
{
    if (obj == nullptr || obj->sslCtx == nullptr) {
        CCSEC_LOG_ERROR("Openssl GetVersion obj or sslCtx is null.");
        return nullptr;
    }
    return LibSslApi::GetInstance().SSL_get_version(obj->sslCtx);
}

void *OpenSSLAdapter::GetPeerCert(SCF_PolicyObj *obj)
{
    if (obj == nullptr || obj->sslCtx == nullptr) {
        CCSEC_LOG_ERROR("Openssl GetPeerCert obj or sslCtx is null.");
        return nullptr;
    }
    return LibSslApi::GetInstance().SSL_get_peer_certificate(obj->sslCtx);
}

void *OpenSSLAdapter::GetCurrentCert(SCF_PolicyObj *obj)
{
    if (obj == nullptr || obj->sslCtx == nullptr) {
        CCSEC_LOG_ERROR("Openssl GetCurrentCert obj or sslCtx is null.");
        return nullptr;
    }
    return LibSslApi::GetInstance().SSL_get_certificate(obj->sslCtx);
}

const void *OpenSSLAdapter::CipherFind(SCF_PolicyObj *obj, uint8_t *cipherId)
{
    if (obj == nullptr || obj->sslCtx == nullptr) {
        CCSEC_LOG_ERROR("Openssl CipherFind obj or sslCtx is null.");
        return nullptr;
    }
    return LibSslApi::GetInstance().SSL_CIPHER_find(obj->sslCtx, cipherId);
}

// SCF_cal_ssl
void OpenSSLAdapter::FreeSsl(SCF_PolicyCtx *ctx)
{
    if (ctx == nullptr || ctx->sslConfig == nullptr) {
        return;
    }
    LibSslApi::GetInstance().SSL_CTX_free(ctx->sslConfig);
    ctx->sslConfig = nullptr;
}

int32_t OpenSSLAdapter::AddCaCertByFile(SSL_CTX *sslCtx, const uint8_t *path, const size_t &len)
{
    // 外部保障路径合法
    if (path == nullptr || len == 0) {
        CCSEC_LOG_ERROR("invalid path or len is 0.");
        return SCF_ERRNO_INVALID_PARAM;
    }
    const char *filePath = reinterpret_cast<const char *>(path);
    int32_t ret = LibSslApi::GetInstance().SSL_CTX_load_verify_locations(sslCtx, filePath, nullptr);
    return ret == SSL_SUCCESS ? SCF_SUCCESS : SCF_SSL_ERR_ADD_CA_CERT_TO_STORE;
}

static X509 *CertBuffer2X509(void *cert, const size_t &len)
{
    if (len > INT32_MAX) {
        CCSEC_LOG_ERROR("Openssl CertBuffer2X509 len is too large:" << len << ".");
        return nullptr;
    }
    BIO *b = LibCryptoApi::GetInstance().BIO_new_mem_buf(cert, static_cast<int>(len));
    if (b == nullptr) {
        return nullptr;
    }

    X509 *x509 = LibSslApi::GetInstance().PEM_read_bio_X509(b, nullptr, nullptr, nullptr);
    LibCryptoApi::GetInstance().BIO_free(b);
    return x509;
}

int32_t OpenSSLAdapter::AddCaCertByBuffer(SSL_CTX *sslCtx, uint8_t *buf, const size_t &len)
{
    X509_STORE *certStore = LibSslApi::GetInstance().SSL_CTX_get_cert_store(sslCtx);
    if (certStore == nullptr) {
        return SCF_SSL_ERR_GET_CERT_STORE;
    }

    X509 *x509 = CertBuffer2X509(buf, len);
    if (x509 == nullptr) {
        return SCF_SSL_ERR_PARSE_CERT;
    }
    auto ret = LibCryptoApi::GetInstance().X509_STORE_add_cert(certStore, x509);
    LibCryptoApi::GetInstance().X509_free(x509);
    return ret == SSL_SUCCESS ? SCF_SUCCESS : SCF_SSL_ERR_ADD_CA_CERT_TO_STORE;
}

int32_t OpenSSLAdapter::AddCaCert(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx)
{
    if (certCtx->format != SCF_STORE_FORMAT_PEM) {
        CCSEC_LOG_ERROR("Openssl CertCtx format type Error.");
        return SCF_SSL_ERR_FORMAT_TYPE;
    }

    if (certCtx->storeType == SCF_STORE_FILE_PATH) {
        return AddCaCertByFile(ctx->sslConfig, certCtx->buf, certCtx->bufLen);
    }
    if (certCtx->storeType == SCF_STORE_BUFFER) {
        return AddCaCertByBuffer(ctx->sslConfig, certCtx->buf, certCtx->bufLen);
    }
    CCSEC_LOG_ERROR("Openssl CertCtx store type Error.");
    return SCF_SSL_ERR_STORE_TYPE;
}

int32_t OpenSSLAdapter::AddEeCertByFile(SSL_CTX *sslCtx, const uint8_t *path, const size_t &pathLen)
{
    // 外部保障路径合法
    if (path == nullptr || pathLen == 0) {
        CCSEC_LOG_ERROR("invalid path or len is 0.");
        return SCF_ERRNO_INVALID_PARAM;
    }
    const char *filePath = reinterpret_cast<const char *>(path);

    int32_t ret = LibSslApi::GetInstance().SSL_CTX_use_certificate_file(sslCtx, filePath, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        char *errBuf = LibCryptoApi::GetInstance().ErrErrorString();
        CCSEC_LOG_ERROR("Openssl Add Ee Fail " << errBuf << ".");
        return SCF_SSL_ERR_ADD_EE_CERT_TO_STORE;
    }
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::LoadEeCert(SSL_CTX *sslCtx, BIO *b)
{
    X509 *x509 = LibSslApi::GetInstance().PEM_read_bio_X509(b, nullptr, nullptr, nullptr);
    if (x509 == nullptr) {
        CCSEC_LOG_ERROR("Openssl LoadEeCert PEM read bio X509 Fail.");
        return SCF_SSL_ERR_PARSE_CERT;
    }
    auto ret = LibSslApi::GetInstance().SSL_CTX_use_certificate(sslCtx, x509);
    LibCryptoApi::GetInstance().X509_free(x509);
    if (ret != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl LoadEeCert Add Ee Fail.");
        return SCF_SSL_ERR_ADD_EE_CERT_TO_STORE;
    }
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::AddEeCertByBuffer(SSL_CTX *sslCtx, uint8_t *buf, const size_t &len)
{
    if (len > INT32_MAX) {
        CCSEC_LOG_ERROR("Openssl AddEeCertByBuffer len is too large:" << len << ".");
        return SCF_ERRNO_MEM_ALLOC;
    }
    BIO *b = LibCryptoApi::GetInstance().BIO_new_mem_buf(buf, static_cast<int>(len));
    if (b == nullptr) {
        CCSEC_LOG_ERROR("Openssl AddEeCertByBuffer BIO new mem buf Fail.");
        return SCF_ERRNO_MEM_ALLOC;
    }

    int32_t ret = LoadEeCert(sslCtx, b);
    LibCryptoApi::GetInstance().BIO_free(b);
    return ret;
}

int32_t OpenSSLAdapter::AddEeCert(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx)
{
    if (certCtx->format != SCF_STORE_FORMAT_PEM) {
        CCSEC_LOG_ERROR("Openssl AddEeCert CertCtx format type Error.");
        return SCF_SSL_ERR_FORMAT_TYPE;
    }

    if (certCtx->storeType == SCF_STORE_FILE_PATH) {
        return AddEeCertByFile(ctx->sslConfig, certCtx->buf, certCtx->bufLen);
    }
    if (certCtx->storeType == SCF_STORE_BUFFER) {
        return AddEeCertByBuffer(ctx->sslConfig, certCtx->buf, certCtx->bufLen);
    }
    CCSEC_LOG_ERROR("Openssl AddEeCert CertCtx store type Error.");
    return SCF_SSL_ERR_STORE_TYPE;
}

X509_CRL *OpenSSLAdapter::ReadCrlByFile(const uint8_t *path, const size_t &pathLen)
{
    if (path == nullptr || pathLen == 0) {
        CCSEC_LOG_ERROR("Openssl ReadCrlByFile path is nullptr or length is 0.");
        return nullptr;
    }
    const char *filePath = reinterpret_cast<const char *>(path);
    if (!SCF_CheckFilePathAndStat(filePath)) {
        CCSEC_LOG_ERROR("Openssl ReadCrlByFile invalid file path.");
        return nullptr;
    }
    FILE *fp = fopen(filePath, "r");
    if (fp == nullptr) {
        CCSEC_LOG_ERROR("Openssl ReadCrlByFile Open File Failed");
        return nullptr;
    }

    X509_CRL *crl = LibSslApi::GetInstance().PEM_read_X509_CRL(fp, nullptr, nullptr, nullptr);
    if (fclose(fp) != 0) {
        CCSEC_LOG_ERROR("Openssl ReadCrlByFile Close File Failed");
    }
    return crl;
}

X509_CRL *OpenSSLAdapter::ReadCrlByBuffer(void *buf, const size_t &len)
{
    if (buf == nullptr || len == 0 || len > INT32_MAX) {
        CCSEC_LOG_ERROR("Openssl ReadCrlByBuffer buf is nullptr or len is invalid.");
        return nullptr;
    }
    BIO *bio = LibCryptoApi::GetInstance().BIO_new_mem_buf(buf, static_cast<int>(len));
    if (bio == nullptr) {
        CCSEC_LOG_ERROR("Openssl ReadCrlByBuffer BIO new mem buf Fail.");
        return nullptr;
    }

    X509_CRL *crl = LibSslApi::GetInstance().PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr);
    LibCryptoApi::GetInstance().BIO_free(bio);
    return crl;
}

int32_t OpenSSLAdapter::AddCrl(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx)
{
    int32_t ret;
    X509_CRL *crl;

    if (certCtx->format != SCF_STORE_FORMAT_PEM) {
        CCSEC_LOG_ERROR("Openssl AddCrl CertCtx format type Error.");
        return SCF_SSL_ERR_FORMAT_TYPE;
    }

    const SSL_CTX *sslCtxConfig = ctx->sslConfig;
    X509_STORE *certStore = LibSslApi::GetInstance().SSL_CTX_get_cert_store(sslCtxConfig);
    if (certStore == nullptr) {
        return SCF_SSL_ERR_GET_CERT_STORE;
    }

    if (LibCryptoApi::GetInstance().X509_STORE_set_flags(certStore, X509_V_FLAG_CRL_CHECK) != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl AddCrl Set CrlCheck Fail.");
        return SCF_SSL_ERR_SET_CRL_CHECK_FLAGS;
    }

    if (certCtx->storeType == SCF_STORE_FILE_PATH) {
        crl = ReadCrlByFile(certCtx->buf, certCtx->bufLen);
    } else if (certCtx->storeType == SCF_STORE_BUFFER) {
        crl = ReadCrlByBuffer(certCtx->buf, certCtx->bufLen);
    } else {
        CCSEC_LOG_ERROR("Openssl AddCrl CertCtx store type Error.");
        return SCF_SSL_ERR_STORE_TYPE;
    }

    ret = LibCryptoApi::GetInstance().X509_STORE_add_crl(certStore, crl); // 函数内部有crl非空检查
    LibCryptoApi::GetInstance().X509_CRL_free(crl);
    if (ret != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl AddCrl Add Crl Fail.");
        return SCF_SSL_ERR_LOAD_CRL;
    }
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::AddEeChainByFile(SSL_CTX *sslCtx, uint8_t *path, size_t pathLen)
{
    if (path == nullptr || pathLen == 0) {
        CCSEC_LOG_ERROR("Openssl AddEeChainByFile path is nullptr or len is 0.");
        return SCF_ERRNO_INVALID_PARAM;
    }
    const char *filePath = reinterpret_cast<const char *>(path);

    int32_t ret = LibSslApi::GetInstance().SSL_CTX_use_certificate_chain_file(sslCtx, filePath);
    if (ret != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl AddEeChainByFile Add Ee Chain Fail.");
        return SCF_SSL_ERR_ADD_EE_CHAIN_TO_STORE;
    }
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::LoadCaChain(SSL_CTX *sslCtx, BIO *b)
{
    X509 *ca;
    while ((ca = LibSslApi::GetInstance().PEM_read_bio_X509(b, nullptr, nullptr, nullptr)) != nullptr) {
        auto addRet = SSL_CTX_add_extra_chain_cert(static_cast<RealSslCtx *>(sslCtx), static_cast<RealX509 *>(ca));
        LibCryptoApi::GetInstance().X509_free(ca);
        if (addRet != SSL_SUCCESS) {
            return SCF_SSL_ERR_LOAD_CA_CERT_CHAIN;
        }
    }
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::AddEeChainByBuffer(SSL_CTX *sslCtx, uint8_t *buf, size_t len)
{
    if (len > INT32_MAX) {
        CCSEC_LOG_ERROR("Openssl AddEeChainByBuffer len is too large:" << len << ".");
        return SCF_ERRNO_MEM_ALLOC;
    }
    BIO *b = LibCryptoApi::GetInstance().BIO_new_mem_buf(buf, static_cast<int>(len));
    if (b == nullptr) {
        CCSEC_LOG_ERROR("Openssl AddEeChainByBuffer BIO new mem buf Fail.");
        return SCF_ERRNO_MEM_ALLOC;
    }

    /*
     * 添加证书链里的第一本 EE 证书
     * ------------------------
     * 添加证书链里的其他 CA 证书到 ChainStore 中
     */
    int32_t ret = LoadEeCert(sslCtx, b);
    if (ret == SCF_SUCCESS) {
        ret = LoadCaChain(sslCtx, b);
    }
    LibCryptoApi::GetInstance().BIO_free(b);
    return ret;
}

int32_t OpenSSLAdapter::AddEeChain(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx)
{
    if (certCtx->format != SCF_STORE_FORMAT_PEM) {
        CCSEC_LOG_ERROR("Openssl AddEeChain CertCtx format type Error.");
        return SCF_SSL_ERR_FORMAT_TYPE;
    }

    if (certCtx->storeType == SCF_STORE_FILE_PATH) {
        return AddEeChainByFile(ctx->sslConfig, certCtx->buf, certCtx->bufLen);
    }
    if (certCtx->storeType == SCF_STORE_BUFFER) {
        return AddEeChainByBuffer(ctx->sslConfig, certCtx->buf, certCtx->bufLen);
    }
    CCSEC_LOG_ERROR("Openssl AddEeChain CertCtx store type Error.");
    return SCF_SSL_ERR_STORE_TYPE;
}

int32_t OpenSSLAdapter::AddCert(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx, SCF_CERT_TYPE type)
{
    if (type == SCF_CERT_TYPE_CA) {
        return AddCaCert(ctx, certCtx);
    }
    if (type == SCF_CERT_TYPE_EE) {
        return AddEeCert(ctx, certCtx);
    }
    if (type == SCF_CERT_TYPE_CRL) {
        return AddCrl(ctx, certCtx);
    }
    if (type == SCF_CERT_TYPE_EE_CHAIN) {
        return AddEeChain(ctx, certCtx);
    }
    CCSEC_LOG_ERROR("Openssl AddCert cert type Error, invalid cert type" << type << ".");
    LibCryptoApi::GetInstance().ERR_print_errors_cb(SslErrorsPrint, nullptr);
    return SCF_ERRNO_INVALID_PARAM;
}


int32_t OpenSSLAdapter::SetKeyByFile(SSL_CTX *sslCtx, const uint8_t *file, const size_t &len)
{
    if (file == nullptr || len == 0) {
        CCSEC_LOG_ERROR("Openssl SetKeyByFile path is nullptr or len is 0.");
        return SCF_ERRNO_INVALID_PARAM;
    }
    const char *filePath = reinterpret_cast<const char *>(file);

    int32_t ret = LibSslApi::GetInstance().SSL_CTX_use_PrivateKey_file(sslCtx, filePath, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl SetKeyByFile Set PrivateKey Fail.");
        return SCF_SSL_ERR_LOAD_KEY;
    }
    return SCF_SUCCESS;
}

EVP_PKEY *OpenSSLAdapter::KeyBuffer2Evp(uint8_t *key, const size_t &len)
{
    if (len > INT32_MAX) {
        CCSEC_LOG_ERROR("Openssl KeyBuffer2Evp len is too large:" << len << ".");
        return nullptr;
    }
    BIO *b = LibCryptoApi::GetInstance().BIO_new_mem_buf(key, static_cast<int>(len));
    if (b == nullptr) {
        CCSEC_LOG_ERROR("Openssl KeyBuffer2Evp BIO new mem buf Fail.");
        return nullptr;
    }

    EVP_PKEY *evpKey = LibSslApi::GetInstance().PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr);
    LibCryptoApi::GetInstance().BIO_free(b);
    return evpKey;
}

int32_t OpenSSLAdapter::SetKeyByBuffer(SSL_CTX *sslCtx, uint8_t *buf, const size_t &len)
{
    EVP_PKEY *evpKey = KeyBuffer2Evp(buf, len);
    if (evpKey == nullptr) {
        CCSEC_LOG_ERROR("Openssl SetKeyByBuffer Parse key buffer Error.");
        return SCF_SSL_ERR_LOAD_KEY;
    }

    int32_t ret = LibSslApi::GetInstance().SSL_CTX_use_PrivateKey(sslCtx, evpKey);
    LibCryptoApi::GetInstance().EVP_PKEY_free(evpKey);
    if (ret != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl SetKeyByBuffer PrivateKey Fail.");
        return SCF_SSL_ERR_LOAD_KEY;
    }
    return SCF_SUCCESS;
}

int DefaultPemPasswordCb(char *buf, int size, int rwflag, void *userdata)
{
    (void)rwflag;
    if (buf == nullptr || size == 0) {
        return 0;
    }

    if (userdata == nullptr) {
        (void)memset_s(buf, size, 0, size);
        return 0;
    }

    // 在 set pass 的接口中已经约束只能是字符串
    int i = static_cast<int>(strlen(static_cast<char *>(userdata)));
    i = (i > size) ? size : i;
    if (memcpy_s(buf, size, userdata, i) != EOK) {
        (void)memset_s(buf, size, 0, size);
        return 0;
    }
    return i;
}

int32_t OpenSSLAdapter::SetKey(SCF_PolicyCtx *ctx, SCF_FILE_CTX *keyCtx)
{
    if (ctx == nullptr || ctx->sslConfig == nullptr || keyCtx == nullptr) {
        CCSEC_LOG_ERROR("Openssl SetKey ctx or sslConfig or keyCtx is null.");
        return SCF_ERRNO_INVALID_PARAM;
    }
    if (keyCtx->format != SCF_STORE_FORMAT_PEM) {
        CCSEC_LOG_ERROR("Openssl SetKey KeyCtx format type Error.");
        return SCF_SSL_ERR_FORMAT_TYPE;
    }

    SSL_CTX *sslCtxConfig = ctx->sslConfig;
    LibSslApi::GetInstance().SSL_CTX_set_default_passwd_cb(sslCtxConfig, DefaultPemPasswordCb);
    LibSslApi::GetInstance().SSL_CTX_set_default_passwd_cb_userdata(sslCtxConfig, keyCtx->passwd); // 设置口令

    if (keyCtx->storeType == SCF_STORE_FILE_PATH) {
        return SetKeyByFile(sslCtxConfig, keyCtx->buf, keyCtx->bufLen);
    }
    if (keyCtx->storeType == SCF_STORE_BUFFER) {
        return SetKeyByBuffer(sslCtxConfig, keyCtx->buf, keyCtx->bufLen);
    }
    CCSEC_LOG_ERROR("Openssl SetKey CertCtx store type Error.");
    LibCryptoApi::GetInstance().ERR_print_errors_cb(SslErrorsPrint, nullptr);
    return SCF_SSL_ERR_STORE_TYPE;
}

static const char *CipherId2CipherStr(uint16_t cipherId)
{
    switch (cipherId) {
        /* TLS1.2 cipher suite */
        case SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:";
        case SCF_SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
            return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:";
        case SCF_SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:";
        case SCF_SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
            return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:";
        case SCF_SSL_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:";
        case SCF_SSL_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:";
        /* TLS1.3 cipher suite. 没有 TLS_AES_128_CCM_8_SHA256，因为不在公司规范白名单 */
        case SCF_SSL_AES_128_GCM_SHA256:
            return "TLS_AES_128_GCM_SHA256:";
        case SCF_SSL_AES_256_GCM_SHA384:
            return "TLS_AES_256_GCM_SHA384:";
        case SCF_SSL_CHACHA20_POLY1305_SHA256:
            return "TLS_CHACHA20_POLY1305_SHA256:";
        case SCF_SSL_AES_128_CCM_SHA256:
            return "TLS_AES_128_CCM_SHA256:";
        default:
            CCSEC_LOG_ERROR("CipherId2CipherStr CipherId Wrong.");
            break;
    }
    return nullptr;
}

static uint64_t GetCipherSuitesStrLen(const uint16_t *cipherSuites, uint32_t cipherSuitesSize)
{
    const char *pCipherSuite = nullptr;
    uint64_t len = 0;
    for (uint32_t i = 0; i < cipherSuitesSize; i++) {
        pCipherSuite = CipherId2CipherStr(cipherSuites[i]);
        if (pCipherSuite == nullptr) {
            continue;
        }
        // 单个算法套字符串<=50, 要达到 UINT64_MAX，数组需要 160 PB，不采用对该异常的处理
        len += strlen(pCipherSuite);
    }
    return len;
}

int32_t OpenSSLAdapter::SetCipherSuites(SCF_PolicyCtx *ctx, const uint16_t *cipherSuites,
    uint32_t cipherSuitesSize)
{
    uint64_t offset = 0;
    uint64_t strLen = 0;
    int ret;

    uint64_t totalLen = GetCipherSuitesStrLen(cipherSuites, cipherSuitesSize);
    if (totalLen == 0) {
        // 输入的算法套没有一个合理值
        CCSEC_LOG_ERROR("Openssl SetCipherSuites none of cipher id is ok.");
        return SCF_SSL_ERR_SET_CIPHER;
    }
    char *cipherSuitesStr = new(std::nothrow) char[totalLen];
    if (cipherSuitesStr == nullptr) {
        CCSEC_LOG_ERROR("Openssl SetCipherSuites new mem fail.");
        return SCF_ERRNO_MEM_ALLOC;
    }
    const char *pCipherSuite = nullptr;
    for (uint32_t i = 0; i < cipherSuitesSize; i++) {
        // 兼容 HiTLS，只要有一个匹配和转化为字符串成功，就返回成功
        pCipherSuite = CipherId2CipherStr(cipherSuites[i]);
        if (pCipherSuite == nullptr) {
            continue;
        }
        strLen = strlen(pCipherSuite);
        // 提前计算的 totalLen 一定 >= offset
        if (memcpy_s(cipherSuitesStr + offset, totalLen - offset, pCipherSuite, strLen) != EOK) {
            continue;
        }
        offset += strLen;
    }

    cipherSuitesStr[totalLen - 1] = '\0'; // 去掉最后一个":"
    ret = LibSslApi::GetInstance().SSL_CTX_set_ciphersuites(ctx->sslConfig, cipherSuitesStr);
    delete [] cipherSuitesStr;
    if (ret != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl set cipher suites fail.");
        return SCF_SSL_ERR_SET_CIPHER;
    }
    return SCF_SUCCESS;
}

uint32_t OpenSSLAdapter::MapVersion2NoOpt(int64_t version, uint32_t *sslOp)
{
    // support TLSv1.2 and TLSv1.3
    switch (version) {
        case TLS1_2_VERSION:
            *sslOp = SSL_OP_NO_TLSv1_2;
            break;
        case TLS1_3_VERSION:
            *sslOp = SSL_OP_NO_TLSv1_3;
            break;
        default:
            CCSEC_LOG_ERROR("Openssl MapVersion2NoOpt Fail.");
            return SSL_ERROR;
    }
    return SSL_SUCCESS;
}

int32_t OpenSSLAdapter::SetProtocolVersion(SCF_PolicyCtx *ctx, uint32_t minVersion, uint32_t maxVersion,
    uint32_t *forbidVersion, uint32_t forbidVersionLen)
{
    SSL_CTX *sslCtxConfig = ctx->sslConfig;
    auto *realCtx = static_cast<RealSslCtx *>(sslCtxConfig);
    if (SSL_CTX_set_min_proto_version(realCtx, minVersion) != SSL_SUCCESS ||
        SSL_CTX_set_max_proto_version(realCtx, maxVersion) != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl Set Protocol Ver Fail.");
        return SCF_SSL_ERR_SET_PROTOCOL_VER;
    }
    if (forbidVersion == nullptr || forbidVersionLen == 0) {
        return SCF_SUCCESS;
    }

    // forbid
    uint64_t forbidOpt = 0;
    uint32_t sslOp = 0;
    for (uint32_t i = 0; i < forbidVersionLen; i++) {
        if (MapVersion2NoOpt(forbidVersion[i], &sslOp) != SSL_SUCCESS) {
            CCSEC_LOG_ERROR("Openssl Set VerForbid Fail, Version: " << forbidVersion[i] << ".");
            return SCF_SSL_ERR_SET_VER_FORBID;
        }
        forbidOpt |= sslOp;
    }
    if (forbidOpt != 0) {
        (void)LibSslApi::GetInstance().SSL_CTX_set_options(sslCtxConfig, forbidOpt);
    }

    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::SetAppVerifyCallback(SCF_PolicyCtx *ctx, SCF_AppVerifyFunc cb, void *arg)
{
    LibSslApi::GetInstance().SSL_CTX_set_cert_verify_callback(ctx->sslConfig, cb, arg);
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::CheckPrivateKey(SCF_PolicyCtx *ctx)
{
    int32_t ret = LibSslApi::GetInstance().SSL_CTX_check_private_key(ctx->sslConfig);
    if (ret != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl Check PrivateKey Fail.");
        LibCryptoApi::GetInstance().ERR_print_errors_cb(SslErrorsPrint, nullptr);
        return SCF_SSL_ERR_CHECK_PKEY;
    }
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::SetVerifyMode(SCF_PolicyCtx *policyCtx, uint32_t verifyMode)
{
    if (policyCtx == nullptr || policyCtx->sslConfig == nullptr) {
        CCSEC_LOG_ERROR("Openssl SetVerifyMode ctx or sslConfig is null.");
        return SCF_ERRNO_INVALID_PARAM;
    }
    SSL_CTX *sslCtxConfig = policyCtx->sslConfig;

    if (verifyMode == static_cast<uint32_t>(SCF_VERIFY_MODE_NONE)) {
        // OpenSSL 默认设置为 SSL_VERIFY_NONE
        LibSslApi::GetInstance().SSL_CTX_set_verify(sslCtxConfig, SSL_VERIFY_NONE, nullptr);
        return SCF_SUCCESS;
    }

    uint16_t mode = 0; // OPENSSL是覆盖设置，需要引入中间变量设置进去
    if ((verifyMode & static_cast<uint32_t>(SCF_VERIFY_PEER)) == static_cast<uint32_t>(SCF_VERIFY_PEER)) {
        mode |= SSL_VERIFY_PEER;
    }
    if ((verifyMode & static_cast<uint32_t>(SCF_VERIFY_FAIL_IF_NO_PEER_CERT)) ==
        static_cast<uint32_t>(SCF_VERIFY_FAIL_IF_NO_PEER_CERT)) {
        mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
    LibSslApi::GetInstance().SSL_CTX_set_verify(sslCtxConfig, mode, nullptr);
    return SCF_SUCCESS;
}

const SSL_METHOD *OpenSSLAdapter::CalGetSslMethod(SCF_ROLE role)
{
    const SSL_METHOD *method = nullptr;
    if (role == SCF_ROLE_SERVER) {
        method = LibSslApi::GetInstance().TLS_server_method();
    } else if (role == SCF_ROLE_CLIENT) {
        method = LibSslApi::GetInstance().TLS_client_method();
    }
    return method;
}

int32_t OpenSSLAdapter::InitSsl(SCF_PolicyCtx *ctx, uint32_t minVersion, uint32_t maxVersion,
    uint32_t *forbidVersion, uint32_t forbidVersionLen)
{
    const SSL_METHOD *method = CalGetSslMethod(ctx->role);
    if (method == nullptr) {
        CCSEC_LOG_ERROR("Openssl CalInitSsl Get Ssl Method Fail.");
        return SCF_SSL_ERR_ROLE;
    }

    SSL_CTX *sslCtxConfig = nullptr;

    // === v2.0: 硬件密码加速引擎集成 ===
    // 如果配置了密码引擎且提供了 Provider Context，
    // 则使用 SSL_CTX_new_ex 将 KAE Provider 的 OSSL_LIB_CTX 绑定到 SSL_CTX。
    // 此后所有 SSL_read/SSL_write 内部的密码运算（AES-GCM, ECDH, HKDF 等）
    // 将由 OpenSSL 算法分发器自动路由到 KAE 硬件加速 Provider。
    if (m_cryptoEngine != nullptr) {
        void *providerCtx = m_cryptoEngine->GetProviderContext();
        if (providerCtx != nullptr) {
            // OpenSSL 3.0+ Provider 路径：使用硬件加速的 library context
            auto *libCtx = static_cast<OSSL_LIB_CTX *>(providerCtx);
            sslCtxConfig = SSL_CTX_new_ex(libCtx, nullptr,
                static_cast<const RealSslMethod *>(method));
            if (sslCtxConfig != nullptr) {
                CCSEC_LOG_INFO("OpenSSLAdapter: SSL_CTX created with hardware provider context."
                    << " Crypto engine: " << (m_cryptoEngine->IsHardwareAccelerated()
                        ? "HARDWARE" : "SOFTWARE")
                    << ". Algorithms: " << m_cryptoEngine->GetAcceleratedAlgorithms());
            } else {
                CCSEC_LOG_WARN("OpenSSLAdapter: SSL_CTX_new_ex with provider context failed,"
                    << " falling back to default SSL_CTX_new.");
            }
        }
    }

    // 回退路径：使用默认方式创建 SSL_CTX（无硬件加速）
    if (sslCtxConfig == nullptr) {
        sslCtxConfig = LibSslApi::GetInstance().SSL_CTX_new(method);
    }

    if (sslCtxConfig == nullptr) {
        return SCF_ERRNO_MEM_ALLOC;
    }

    // 根据安全功能规范2.3的F.D.CFD.CAA.1.1.2要求，密码算法强度需要 >= 112 bits，即对应 ssl 的 security level two
    LibSslApi::GetInstance().SSL_CTX_set_security_level(sslCtxConfig, SSL_SECURITY_LEVEL_TWO);

    // 防止会话恢复攻击
    auto *realSslCtxConfig = static_cast<RealSslCtx *>(sslCtxConfig);
    (void)SSL_CTX_set_session_cache_mode(realSslCtxConfig, SSL_SESS_CACHE_OFF);
    if (SSL_CTX_get_session_cache_mode(realSslCtxConfig) != SSL_SESS_CACHE_OFF) {
        LibSslApi::GetInstance().SSL_CTX_free(sslCtxConfig);
        return SCF_SSL_ERR_SET_SESS_TICKET;
    }

    // 如果 ctx->sslConfig非空，覆盖前需要释放资源
    FreeSsl(ctx);
    ctx->sslConfig = sslCtxConfig;
    auto ret = SetProtocolVersion(ctx, minVersion, maxVersion, forbidVersion, forbidVersionLen);
    if (ret != SCF_SUCCESS) {
        FreeSsl(ctx);
        return ret;
    }

    (void)LibSslApi::GetInstance().SSL_CTX_set_options(ctx->sslConfig, SSL_OP_NO_RENEGOTIATION);

    return ret;
}

int32_t OpenSSLAdapter::InitSslCustomer(SCF_PolicyCtx *ctx)
{
    const SSL_METHOD *method = CalGetSslMethod(ctx->role);
    if (method == nullptr) {
        return SCF_SSL_ERR_ROLE;
    }

    SSL_CTX *sslCtxConfig = nullptr;

    // v2.0: 硬件密码加速引擎集成（同 InitSsl 逻辑）
    if (m_cryptoEngine != nullptr) {
        void *providerCtx = m_cryptoEngine->GetProviderContext();
        if (providerCtx != nullptr) {
            auto *libCtx = static_cast<OSSL_LIB_CTX *>(providerCtx);
            sslCtxConfig = SSL_CTX_new_ex(libCtx, nullptr,
                static_cast<const RealSslMethod *>(method));
        }
    }

    if (sslCtxConfig == nullptr) {
        sslCtxConfig = LibSslApi::GetInstance().SSL_CTX_new(method);
    }

    if (sslCtxConfig == nullptr) {
        return SCF_ERRNO_MEM_ALLOC;
    }

    // 防止会话恢复攻击
    auto *realSslCtxConfig = static_cast<RealSslCtx *>(sslCtxConfig);
    (void)SSL_CTX_set_session_cache_mode(realSslCtxConfig, SSL_SESS_CACHE_OFF);
    if (SSL_CTX_get_session_cache_mode(realSslCtxConfig) != SSL_SESS_CACHE_OFF) {
        LibSslApi::GetInstance().SSL_CTX_free(sslCtxConfig);
        sslCtxConfig = nullptr;
        return SCF_SSL_ERR_SET_SESS_TICKET;
    }

    (void)LibSslApi::GetInstance().SSL_CTX_set_options(sslCtxConfig, SSL_OP_NO_RENEGOTIATION);

    // 如果 ctx->sslConfig非空，覆盖前需要释放资源
    FreeSsl(ctx);
    ctx->sslConfig = sslCtxConfig;
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::InitPolicyByMode(SCF_PolicyCtx *ctx)
{
    int ret;

    if (ctx->policyMode == SCF_POLICY_HIGH) {
        ret = InitSsl(ctx, SCF_SSL_VERSION_TLS13);
    } else if (ctx->policyMode == SCF_POLICY_MIDDLE) {
        ret = InitSsl(ctx, SCF_SSL_VERSION_TLS12);
    } else {
        ret = InitSslCustomer(ctx);
    }
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl InitPolicyByMode Init Policy Fail. mode:" << ctx->policyMode);
        LibCryptoApi::GetInstance().ERR_print_errors_cb(SslErrorsPrint, nullptr);
    }
    return ret;
}

static int32_t PskFindSessionCbWrapper(RealSsl *ssl, const unsigned char *id, size_t idLen, RealSslSession **sess)
{
    auto *obj = static_cast<SCF_PolicyObj *>(LibSslApi::GetInstance().SSL_get_ex_data(
        static_cast<void *>(ssl), SSL_EX_DATA_ID));
    if (obj == nullptr || obj->pskFindSessionCb == nullptr) {
        return SSL_ERROR;
    }
    int32_t ret = obj->pskFindSessionCb(obj, id, static_cast<uint32_t>(idLen),
        reinterpret_cast<SCF_Session **>(sess));
    if (ret != SCF_SUCCESS) {
        return SSL_ERROR;
    }
    if (sess != nullptr && *sess != nullptr) {
        if (LibSslApi::GetInstance().SSL_SESSION_get0_cipher(static_cast<void *>(*sess)) == nullptr) {
            // 用户实现异常，没配置 cipher 时，openssl server 会 core dump，此处避免 core dump
            LibSslApi::GetInstance().SSL_SESSION_free(static_cast<void *>(*sess));
            *sess = nullptr;
            return SSL_ERROR;
        }
    }

    LibSslApi::GetInstance().SSL_set_verify(static_cast<void *>(ssl), SSL_VERIFY_NONE, nullptr);
    return SSL_SUCCESS;
}

static uint32_t GetHashAlgo(const EVP_MD *md)
{
    if (md == LibCryptoApi::GetInstance().EVP_sha256()) {
        return SCF_CRYPT_MD_SHA256;
    }
    if (md == LibCryptoApi::GetInstance().EVP_sha384()) {
        return SCF_CRYPT_MD_SHA384;
    }
    return SCF_CRYPT_MD_UNKNOWN;
}

static int32_t PskUseSessionCbWrapper(RealSsl *ssl, const RealEvpMd *md, const unsigned char **id, size_t *idLen,
    RealSslSession **sess)
{
    auto *obj = static_cast<SCF_PolicyObj *>(LibSslApi::GetInstance().SSL_get_ex_data(
        static_cast<void *>(ssl), SSL_EX_DATA_ID));
    if (obj == nullptr || obj->pskUseSessionCb == nullptr) {
        return SSL_ERROR;
    }
    uint32_t idLenIn = 0; // 防止入参指针强转
    int32_t ret = obj->pskUseSessionCb(obj, GetHashAlgo(static_cast<const void *>(md)), id, &idLenIn,
        reinterpret_cast<SCF_Session **>(sess));
    if (ret != SCF_SUCCESS) {
        return SSL_ERROR;
    }
    *idLen = static_cast<size_t>(idLenIn);
    return SSL_SUCCESS;
}

int32_t OpenSSLAdapter::SetPskFindSessionCallback(SCF_PolicyCtx *ctx, SCF_PskFindSessionCb cb)
{
    if (ctx == nullptr || ctx->sslConfig == nullptr) {
        CCSEC_LOG_ERROR("Openssl SetPskFindSessionCallback ctx or sslConfig is nullptr.");
        return SCF_ERRNO_INVALID_PARAM;
    }
    ctx->pskFindSessionCb = cb;
    LibSslApi::GetInstance().SSL_CTX_set_psk_find_session_callback(ctx->sslConfig,
        cb == nullptr ? nullptr : reinterpret_cast<SSLPskFindSessionCallback>(PskFindSessionCbWrapper));
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::SetPskUseSessionCallback(SCF_PolicyCtx *ctx, SCF_PskUseSessionCb cb)
{
    if (ctx == nullptr || ctx->sslConfig == nullptr) {
        CCSEC_LOG_ERROR("Openssl SetPskUseSessionCallback ctx or sslConfig is nullptr.");
        return SCF_ERRNO_INVALID_PARAM;
    }
    ctx->pskUseSessionCb = cb;
    LibSslApi::GetInstance().SSL_CTX_set_psk_use_session_callback(ctx->sslConfig,
        cb == nullptr ? nullptr : reinterpret_cast<SSLPskUseSessionCallback>(PskUseSessionCbWrapper));
    return SCF_SUCCESS;
}

SCF_Session *OpenSSLAdapter::SessionNew()
{
    return LibSslApi::GetInstance().SSL_SESSION_new();
}

int32_t OpenSSLAdapter::SessionSetMasterKey(SCF_Session *sess, const uint8_t *masterKey, size_t masterKeySize)
{
    if (LibSslApi::GetInstance().SSL_SESSION_set1_master_key(sess, masterKey, masterKeySize) != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl SessionSetMasterKey Set Sess Master Key Fail.");
        return SCF_SSL_ERR_SESS_SET_KEY;
    }
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::SessionSetCipher(SCF_Session *sess, const void *cipherSuite, size_t cipherLen)
{
    (void)cipherLen; // 适应hitls
    if (LibSslApi::GetInstance().SSL_SESSION_set_cipher(sess, cipherSuite) != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl SessionSetCipher Set Sess Cipher Fail.");
        return SCF_SSL_ERR_SESS_SET_CIPHER;
    }
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::SessionGetCipher(SCF_Session *sess, void **cipherSuite, size_t &cipherLen)
{
    cipherLen = 0; // 初始化为0
    if (cipherSuite == nullptr) {
        CCSEC_LOG_ERROR("Openssl SessionGetCipher Fail. cipherSuite is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    *cipherSuite = LibSslApi::GetInstance().SSL_SESSION_get0_cipher(sess);
    if (*cipherSuite == nullptr) {
        CCSEC_LOG_ERROR("Openssl SessionGetCipher Fail.");
        return SCF_SSL_ERR_SESS_GET_CIPHER;
    }
    cipherLen = 1; // 固定返回1，让外部接口可以调用SessionFreeCipher
    return SCF_SUCCESS;
}

void OpenSSLAdapter::SessionFreeCipher(void **cipherSuite, size_t &cipherLen)
{
    cipherLen = 0;
    if (cipherSuite != nullptr) {
        *cipherSuite = nullptr;
    }
}

void OpenSSLAdapter::FreeBuffer(char **buffer, size_t &bufferLen)
{
    if (buffer == nullptr || *buffer == nullptr || bufferLen == 0) {
        return;
    }
    delete[] *buffer;
    *buffer = nullptr;
    bufferLen = 0;
}

int32_t OpenSSLAdapter::ProtocolStrToInt(const char *version, int32_t &intVer)
{
    std::unordered_map<std::string, int32_t> protocolMap{
        {"TLSv1.2", TLS1_2_VERSION},
        {"TLSv1.3", TLS1_3_VERSION}
    };
    auto ver = protocolMap.find(version);
    if (ver == protocolMap.end()) {
        return SCF_ERROR;
    }
    intVer = ver->second;
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::ProtocolIntToStr(const int32_t &version, std::string &strVer)
{
    std::unordered_map<int32_t, std::string> protocolMap{
        {TLS1_2_VERSION, "TLSv1.2"},
        {TLS1_3_VERSION, "TLSv1.3"}
    };
    auto ver = protocolMap.find(version);
    if (ver == protocolMap.end()) {
        return SCF_ERROR;
    }
    strVer = ver->second;
    return SCF_SUCCESS;
}


int32_t OpenSSLAdapter::SessionSetProtocolVersion(SCF_Session *sess, const char *version)
{
    int sslVersion = 0;
    if (ProtocolStrToInt(version, sslVersion) != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl SessionSetProtocolVersion Map Protocol Ver Fail.");
        return SCF_SSL_ERR_VERSION;
    }

    if (LibSslApi::GetInstance().SSL_SESSION_set_protocol_version(sess, sslVersion) != SSL_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl SessionSetProtocolVersion Set Sess Protocol Ver Fail.");
        return SCF_SSL_ERR_SESS_SET_PROTOCOL_VER;
    }
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::SessionGetProtocolVersion(SCF_Session *sess, char **version, size_t &versionLen)
{
    versionLen = 0;
    int intVer = LibSslApi::GetInstance().SSL_SESSION_get_protocol_version(sess);
    std::string versionStr;
    if (ProtocolIntToStr(intVer, versionStr) != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("Openssl SessionGetProtocolVersion unmapped ver:" << intVer);
        return SCF_SSL_ERR_SESS_GET_PROTOCOL_VER;
    }
    versionLen = versionStr.length();
    auto *vers = new(std::nothrow) char[versionLen + 1];
    if (vers == nullptr ||
        memcpy_s(vers, versionLen + 1, versionStr.c_str(), versionStr.length()) != EOK) {
        CCSEC_LOG_ERROR("Openssl SessionGetProtocolVersion memcpy_s Fail");
        delete[] vers;
        vers = nullptr;
        versionLen = 0;
        return SCF_SSL_ERR_SESS_GET_PROTOCOL_VER;
    }
    vers[versionStr.length()] = '\0';
    *version = vers;
    return SCF_SUCCESS;
}

void OpenSSLAdapter::SessionFree(SCF_Session *sess)
{
    LibSslApi::GetInstance().SSL_SESSION_free(sess);
}

int32_t OpenSSLAdapter::GetCertVersion(const void *cert)
{
    if (cert == nullptr) {
        return -1;
    }
    auto version = LibCryptoApi::GetInstance().X509_get_version(cert);
    // 检查版本号是否在 int32_t 范围内
    if (version < INT32_MIN || version > INT32_MAX) {
        CCSEC_LOG_ERROR("Openssl GetCertVersion fail, Version number out of int32_t range.");
        return -1;
    }
    return static_cast<int32_t>(version);
}

char *OpenSSLAdapter::GetCertStartTime(const void *cert)
{
    if (cert == nullptr) {
        return nullptr;
    }
    auto *timeString = static_cast<ASN1_TIME *>(LibCryptoApi::GetInstance().X509_getm_notBefore(cert));
    if (timeString == nullptr) {
        return nullptr;
    }
    auto *time = new(std::nothrow) char [MAX_DATETIME_LEN];
    if (time == nullptr || memcpy_s(time, MAX_DATETIME_LEN - 1, timeString->data, timeString->length) != EOK) {
        delete[] time;
        time = nullptr;
    }
    if (time != nullptr) {
        time[MAX_DATETIME_LEN - 1] = '\0';
    }
    return time;
}

char *OpenSSLAdapter::GetCertEndTime(const void *cert)
{
    if (cert == nullptr) {
        return nullptr;
    }
    auto *timeString = static_cast<ASN1_TIME *>(LibCryptoApi::GetInstance().X509_getm_notAfter(cert));
    if (timeString == nullptr) {
        return nullptr;
    }
    auto *time = new(std::nothrow) char [MAX_DATETIME_LEN];
    if (time == nullptr || memcpy_s(time, MAX_DATETIME_LEN - 1, timeString->data, timeString->length) != EOK) {
        delete[] time;
        time = nullptr;
    }
    if (time != nullptr) {
        time[MAX_DATETIME_LEN - 1] = '\0';
    }
    return time;
}

uint8_t *OpenSSLAdapter::GetCertSerialNumber(const void *cert, uint32_t *dataLen)
{
    *dataLen = 0;
    if (cert == nullptr) {
        return nullptr;
    }
    auto *result = LibCryptoApi::GetInstance().X509_get0_serialNumber(static_cast<const X509 *>(cert));
    if (result == nullptr) {
        return nullptr;
    }
    auto *snString = static_cast<const ASN1_INTEGER *>(result);
    *dataLen = snString->length;
    return snString->data;
}


int32_t OpenSSLAdapter::GetCipherSuites(SCF_PolicyCtx *ctx, uint16_t *data, uint32_t dataLen,
    uint32_t *cipherSuitesSize)
{
    SSL_CTX *sslCtxConfig = ctx->sslConfig;
    void *ciphersStack = LibSslApi::GetInstance().SSL_CTX_get_ciphers(sslCtxConfig);
    int cipherLen = ciphersStack == nullptr ? 0 : LibSslApi::GetInstance().OPENSSL_sk_num(ciphersStack);
    if (cipherLen <= 0 || static_cast<uint32_t>(cipherLen) > dataLen) {
        *cipherSuitesSize = 0;
        return SCF_SSL_ERR_GET_CIPHER;
    }

    for (int i = 0; i < cipherLen; i++) {
        auto *cipher = LibSslApi::GetInstance().OPENSSL_sk_value(ciphersStack, i);
        // 这个地方需要截断，取低16位
        data[i] = static_cast<uint16_t>(LibSslApi::GetInstance().SSL_CIPHER_get_id(cipher));
    }
    *cipherSuitesSize = cipherLen;
    return SCF_SUCCESS;
}

int32_t OpenSSLAdapter::NegotiateCipherSuite(SCF_PolicyObj *obj, uint16_t *data)
{
    if (obj == nullptr || obj->sslCtx == nullptr) {
        return SCF_ERRNO_NULL_INPUT;
    }

    SSL_CIPHER *cipher = LibSslApi::GetInstance().SSL_get_current_cipher(obj->sslCtx);
    if (cipher == nullptr) {
        return SCF_SSL_ERR_GET_CIPHER;
    }
    // 这个地方需要截断，取低16位
    *data = static_cast<uint16_t>(LibSslApi::GetInstance().SSL_CIPHER_get_id(cipher));
    return SCF_SUCCESS;
}

void OpenSSLAdapter::FreeCert(void *cert)
{
    LibCryptoApi::GetInstance().X509_free(cert);
}

int32_t OpenSSLAdapter::X509VerifyChain(void *storeCtx)
{
    if (storeCtx == nullptr) {
        return SCF_ERRNO_NULL_INPUT;
    }
    if (LibCryptoApi::GetInstance().X509_verify_cert(storeCtx) != SSL_SUCCESS) {
        int32_t ret = LibCryptoApi::GetInstance().X509_STORE_CTX_get_error(storeCtx);
        CCSEC_LOG_ERROR("Openssl X509 Verify Chain Fail. Openssl Error Code: " << ret);
        LibCryptoApi::GetInstance().ERR_print_errors_cb(SslErrorsPrint, nullptr);
        return SCF_SSL_ERR_X509_VERIFY_CHAIN;
    }
    return SCF_SUCCESS;
}
}