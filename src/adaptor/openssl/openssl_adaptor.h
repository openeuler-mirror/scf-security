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

#ifndef OPENSSL_ADAPTOR_H
#define OPENSSL_ADAPTOR_H

#include <string>
#include "abstract_tls_adaptor.h"
#include "scf_def.h"
#include "scf_errno.h"
#include "openssl_def.h"

namespace scf {

class OpenSSLAdapter : public AbstractTLSAdaptor {
public:
    OpenSSLAdapter() = default;

    ~OpenSSLAdapter() override = default;

    int32_t Init(uint64_t flag, const void *settings) override;

    void DeInit() override;

    // SCF_cal_log
    int32_t HandleTransPortError(SCF_PolicyObj *obj, int32_t errorCode) override;

    void OpenCertErrorLog() override;

    void CloseCertErrorLog() override;

    // SCF_cal_ssl_obj
    void FreeSslObj(SCF_PolicyObj *obj) override;

    int32_t Connect(SCF_PolicyObj *obj) override;

    int32_t Accept(SCF_PolicyObj *obj) override;

    int32_t Read(SCF_PolicyObj *obj, uint8_t *data, uint32_t dataLen, uint32_t *readLen) override;

    int32_t Write(SCF_PolicyObj *obj, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen) override;

    int32_t Close(SCF_PolicyObj *obj) override;

    int32_t SetFd(SCF_PolicyObj *obj, int32_t fd) override;

    int32_t KeyUpdate(SCF_PolicyObj *obj, KeyUpdateType updateType) override;

    const char *GetVersion(SCF_PolicyObj *obj) override;

    void *GetPeerCert(SCF_PolicyObj *obj) override;

    void *GetCurrentCert(SCF_PolicyObj *obj) override;

    const void *CipherFind(SCF_PolicyObj *obj, uint8_t *cipherId) override;

    // SCF_cal_ssl
    void FreeSsl(SCF_PolicyCtx *ctx) override;

    int32_t AddCert(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx, SCF_CERT_TYPE type) override;

    int32_t SetKey(SCF_PolicyCtx *ctx, SCF_FILE_CTX *keyCtx) override;

    int32_t SetCipherSuites(SCF_PolicyCtx *ctx, const uint16_t *cipherSuites, uint32_t cipherSuitesSize) override;

    int32_t SetProtocolVersion(SCF_PolicyCtx *ctx, uint32_t minVersion, uint32_t maxVersion,
        uint32_t *forbidVersion, uint32_t forbidVersionLen) override;

    int32_t SetAppVerifyCallback(SCF_PolicyCtx *ctx, SCF_AppVerifyFunc cb, void *arg) override;

    int32_t CheckPrivateKey(SCF_PolicyCtx *ctx) override;

    int32_t SetVerifyMode(SCF_PolicyCtx *policyCtx, uint32_t verifyMode) override;

    int32_t InitPolicyByMode(SCF_PolicyCtx *ctx) override;

    int32_t SetPskFindSessionCallback(SCF_PolicyCtx *ctx, SCF_PskFindSessionCb cb) override;

    int32_t SetPskUseSessionCallback(SCF_PolicyCtx *ctx, SCF_PskUseSessionCb cb) override;

    SCF_Session *SessionNew() override;

    int32_t SessionSetMasterKey(SCF_Session *sess, const uint8_t *masterKey, size_t masterKeySize) override;

    int32_t SessionSetCipher(SCF_Session *sess, const void *cipherSuite, size_t cipherLen) override;

    int32_t SessionGetCipher(SCF_Session *sess, void **cipherSuite, size_t &cipherLen) override;

    void SessionFreeCipher(void **cipherSuite, size_t &cipherLen) override;

    void FreeBuffer(char **buffer, size_t &bufferLen) override;

    int32_t SessionSetProtocolVersion(SCF_Session *sess, const char *version) override;

    int32_t SessionGetProtocolVersion(SCF_Session *sess, char **version, size_t &versionLen) override;

    void SessionFree(SCF_Session *sess) override;

    int32_t GetCertVersion(const void *cert) override;

    char *GetCertStartTime(const void *cert) override;

    char *GetCertEndTime(const void *cert) override;

    uint8_t *GetCertSerialNumber(const void *cert, uint32_t *dataLen) override;

    int32_t GetCipherSuites(SCF_PolicyCtx *ctx, uint16_t *data, uint32_t dataLen,
        uint32_t *cipherSuitesSize) override;

    int32_t NegotiateCipherSuite(SCF_PolicyObj *obj, uint16_t *data) override;

    void FreeCert(void *cert) override;

    int32_t X509VerifyChain(void *storeCtx) override;

protected:
    int32_t ProtocolStrToInt(const char *version, int32_t &intVer);

    int32_t ProtocolIntToStr(const int32_t &version, std::string &strVer);

    void LogCertError(SCF_PolicyObj *obj);

    int32_t InnerGetOpensslUpdateType(KeyUpdateType updateType, int *opensslUpdateType);

    int32_t SetKeyByFile(SSL_CTX *sslCtx, const uint8_t *file, const size_t &len);

    int32_t AddCaCertByFile(SSL_CTX *sslCtx, const uint8_t *path, const size_t &len);

    int32_t AddCaCertByBuffer(SSL_CTX *sslCtx, uint8_t *buf, const size_t &len);

    int32_t AddCaCert(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx);

    int32_t AddEeCertByFile(SSL_CTX *sslCtx, const uint8_t *path, const size_t &pathLen);

    int32_t LoadEeCert(SSL_CTX *sslCtx, BIO *b);

    int32_t AddEeCertByBuffer(SSL_CTX *sslCtx, uint8_t *buf, const size_t &len);

    int32_t AddEeCert(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx);

    X509_CRL *ReadCrlByFile(const uint8_t *path, const size_t &pathLen);

    X509_CRL *ReadCrlByBuffer(void *buf, const size_t &len);

    int32_t AddCrl(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx);

    int32_t AddEeChainByFile(SSL_CTX *sslCtx, uint8_t *path, size_t pathLen);

    int32_t LoadCaChain(SSL_CTX *sslCtx, BIO *b);

    int32_t AddEeChainByBuffer(SSL_CTX *sslCtx, uint8_t *buf, size_t len);

    int32_t AddEeChain(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx);

    EVP_PKEY *KeyBuffer2Evp(uint8_t *key, const size_t &len);

    int32_t SetKeyByBuffer(SSL_CTX *sslCtx, uint8_t *buf, const size_t &len);

    uint32_t MapVersion2NoOpt(int64_t version, uint32_t *sslOp);

    const SSL_METHOD *CalGetSslMethod(SCF_ROLE role);

    int32_t InitSsl(SCF_PolicyCtx *ctx, uint32_t minVersion, uint32_t maxVersion = SCF_SSL_VERSION_TLS13,
        uint32_t *forbidVersion = nullptr, uint32_t forbidVersionLen = 0);

    int32_t InitSslCustomer(SCF_PolicyCtx *ctx);

    uint32_t CheckVersion(SCF_PolicyObj *obj);
private:
    static bool g_certlog_switch;
};
}

#endif