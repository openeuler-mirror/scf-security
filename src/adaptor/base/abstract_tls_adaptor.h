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

#ifndef ABSTRACT_TLS_ADAPTOR_H
#define ABSTRACT_TLS_ADAPTOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "scf_def.h"
#include "scf_errno.h"
#include "constant_def.h"
#include "scf_crypto_engine.h"

namespace scf {
enum class KeyUpdateType:int16_t {
    KEY_UPDATE_NONE = -1,
    KEY_UPDATE_NOT_REQUESTED = 0,
    KEY_UPDATE_REQUESTED = 1,
    KEY_UPDATE_END = 255
};

class AbstractTLSAdaptor {
public:
    AbstractTLSAdaptor() = default;

    virtual ~AbstractTLSAdaptor() = default;

    virtual int32_t Init(uint64_t flag, const void *settings) = 0;

    virtual void DeInit() = 0;

    virtual int32_t HandleTransPortError(SCF_PolicyObj *obj, int32_t errorCode) = 0;

    virtual void OpenCertErrorLog() = 0;

    virtual void CloseCertErrorLog() = 0;

    virtual void FreeSslObj(SCF_PolicyObj *obj) = 0;

    virtual int32_t Connect(SCF_PolicyObj *obj) = 0;

    virtual int32_t Accept(SCF_PolicyObj *obj) = 0;

    virtual int32_t Read(SCF_PolicyObj *obj, uint8_t *data, uint32_t dataLen, uint32_t *readLen) = 0;

    virtual int32_t Write(SCF_PolicyObj *obj, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen) = 0;

    virtual int32_t Close(SCF_PolicyObj *obj) = 0;

    virtual int32_t SetFd(SCF_PolicyObj *obj, int32_t fd) = 0;

    virtual int32_t KeyUpdate(SCF_PolicyObj *obj, KeyUpdateType updateType) = 0;

    virtual const char *GetVersion(SCF_PolicyObj *obj) = 0;

    virtual void *GetPeerCert(SCF_PolicyObj *obj) = 0;

    virtual void *GetCurrentCert(SCF_PolicyObj *obj) = 0;

    virtual const void *CipherFind(SCF_PolicyObj *obj, uint8_t *cipherId) = 0;

    virtual void FreeSsl(SCF_PolicyCtx *ctx) = 0;

    virtual int32_t AddCert(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx, SCF_CERT_TYPE type) = 0;

    virtual int32_t SetKey(SCF_PolicyCtx *ctx, SCF_FILE_CTX *keyCtx) = 0;

    virtual int32_t SetCipherSuites(SCF_PolicyCtx *ctx, const uint16_t *cipherSuites,
        uint32_t cipherSuitesSize) = 0;

    virtual int32_t SetProtocolVersion(SCF_PolicyCtx *ctx, uint32_t minVersion, uint32_t maxVersion,
        uint32_t *forbidVersion, uint32_t forbidVersionLen) = 0;

    virtual int32_t SetAppVerifyCallback(SCF_PolicyCtx *ctx, SCF_AppVerifyFunc cb, void *arg) = 0;

    virtual int32_t CheckPrivateKey(SCF_PolicyCtx *ctx) = 0;

    virtual int32_t SetVerifyMode(SCF_PolicyCtx *policyCtx, uint32_t verifyMode) = 0;

    virtual int32_t InitPolicyByMode(SCF_PolicyCtx *ctx) = 0;

    virtual int32_t SetPskFindSessionCallback(SCF_PolicyCtx *ctx, SCF_PskFindSessionCb cb) = 0;

    virtual int32_t SetPskUseSessionCallback(SCF_PolicyCtx *ctx, SCF_PskUseSessionCb cb) = 0;

    virtual SCF_Session *SessionNew() = 0;

    virtual int32_t SessionSetMasterKey(SCF_Session *sess, const uint8_t *masterKey, size_t masterKeySize) = 0;

    virtual int32_t SessionSetCipher(SCF_Session *sess, const void *cipherSuite, size_t cipherLen) = 0;

    // get 后需要调用 SessionFreeCipher
    virtual int32_t SessionGetCipher(SCF_Session *sess, void **cipherSuite, size_t &cipherLen) = 0;

    virtual void SessionFreeCipher(void **cipherSuite, size_t &cipherLen) = 0;

    virtual void FreeBuffer(char **buffer, size_t &bufferLen) = 0;

    virtual int32_t SessionSetProtocolVersion(SCF_Session *sess, const char *version) = 0;

    // get 后需要调用 FreeBuffer
    virtual int32_t SessionGetProtocolVersion(SCF_Session *sess, char **version, size_t &versionLen) = 0;

    virtual void SessionFree(SCF_Session *sess) = 0;

    virtual int32_t GetCertVersion(const void *cert) = 0;

    // get 后需要调用 FreeBuffer
    virtual char *GetCertStartTime(const void *cert) = 0;

    // get 后需要调用 FreeBuffer
    virtual char *GetCertEndTime(const void *cert) = 0;

    virtual uint8_t *GetCertSerialNumber(const void *cert, uint32_t *dataLen) = 0;

    virtual int32_t GetCipherSuites(SCF_PolicyCtx *ctx, uint16_t *data, uint32_t dataLen,
        uint32_t *cipherSuitesSize) = 0;

    virtual int32_t NegotiateCipherSuite(SCF_PolicyObj *obj, uint16_t *data) = 0;

    virtual void FreeCert(void *cert) = 0;

    virtual int32_t X509VerifyChain(void *storeCtx) = 0;

    // --- 密码引擎注入 (v2.0) ---

    /**
     * @brief 设置外部密码引擎
     *
     * 在 SSL_CTX 创建之前调用此方法，将硬件密码加速度引擎
     * （如 KAEProviderEngine）注入到 TLS 适配器。
     * 适配器将使用引擎提供的 OSSL_LIB_CTX 创建 SSL_CTX，
     * 从而使 TLS 内部密码运算自动路由到硬件加速。
     *
     * @param engine 密码引擎实例（生命周期由调用方管理）
     */
    virtual void SetCryptoEngine(ICryptoEngine *engine) = 0;

    /**
     * @brief 获取当前密码引擎
     */
    virtual ICryptoEngine *GetCryptoEngine() const = 0;

    /**
     * @brief 设置密钥交换命名组 (TLS 1.3 groups)
     *
     * 配置 TLS 密钥协商使用的命名组，支持经典 ECDH 和后量子 Hybrid KEM。
     * 调用时机: SSL_CTX 创建之后、连接建立之前。
     *
     * @param ctx 安全策略上下文 (包含 SSL_CTX)
     * @param groups 命名组列表 (如 "X25519", "p256_kyber512", "P-521")
     * @return SCF_SUCCESS 或错误码
     */
    virtual int32_t SetKeyExchangeGroups(
        SCF_PolicyCtx *ctx, const std::vector<std::string> &groups) = 0;
};
}

#endif
