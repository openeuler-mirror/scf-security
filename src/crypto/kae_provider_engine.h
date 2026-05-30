/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 *
 * 基于 OpenSSL 3.0+ Provider 机制的鲲鹏 KAE 硬件加速引擎。
 *
 * KAE (Kunpeng Accelerator Engine) 通过 UADK (User Space Accelerator
 * Development Kit) 访问鲲鹏芯片的硬件密码加速模块。
 *
 * === 部分接口替换机制 ===
 * OpenSSL 3.0+ Provider 天然支持"部分接口替换"：
 *   - KAE Provider 注册了 AES-GCM、SM3、SM4、DH、RSA、ECDH 等算法
 *   - 所有 SSL_read/SSL_write 内部的密码运算，OpenSSL 算法分发器
 *     自动将 KAE 支持的算法路由到硬件加速，不支持的算法回退到
 *     default Provider（软件实现）
 *   - 用户无感知，TLS API 调用方式完全不变
 *
 * 使用方式:
 * @code
 *   // 方式1：通过注册工厂
 *   SCF_RegisterCryptoEngineFactory(new KAEProviderEngineFactory());
 *   SCFConnectionConfig cfg;
 *   cfg.cryptoEngineFactory = kaeFactory;
 *
 *   // 方式2：直接创建
 *   KAEProviderEngine engine;
 *   engine.Initialize(CryptoEngineConfig{});
 *   // engine.GetProviderContext() 返回 OSSL_LIB_CTX*
 *   // 传给 AbstractTLSAdaptor 创建 SSL_CTX
 * @endcode
 */

#ifndef SCF_KAE_PROVIDER_ENGINE_H
#define SCF_KAE_PROVIDER_ENGINE_H

#include <string>
#include "scf_crypto_engine.h"

using OSSL_LIB_CTX = struct ossl_lib_ctx_st;
using OSSL_PROVIDER = struct ossl_provider_st;

namespace scf {

/**
 * @brief KAE Provider 引擎配置
 */
struct KAEProviderConfig {
    static constexpr uint32_t kDefaultAsyncPollTimeoutMs = 100;

    std::string kaeProviderName;    ///< KAE Provider 名称 (默认 "kae")
    std::string kaeConfigFile;      ///< KAE 配置文件路径 (空则默认)
    bool enableAsyncPolling;        ///< 是否启用异步轮询模式
    uint32_t asyncPollTimeoutMs;    ///< 异步轮询超时(ms)

    KAEProviderConfig()
        : kaeProviderName("kae"),
          enableAsyncPolling(false),
        asyncPollTimeoutMs(kDefaultAsyncPollTimeoutMs)
    {}
};

/**
 * @brief KAE Provider 引擎 —— 鲲鹏硬件加速
 *
 * 实现 ICryptoEngine 接口，底层通过 OpenSSL 3.0+ Provider 机制
 * 加载鲲鹏 KAE Provider，使 TLS 内部的密码运算自动使用硬件加速。
 *
 * 直接密码运算方法（EncryptAEAD/DecryptAEAD 等）本地调用兜底：
 * 因为 OpenSSL Provider 机制下 SSL_read/SSL_write 已自动走硬件，
 * 这些方法的直接调用场景较少，实现上委托给软件兜底以保证正确性。
 */
class KAEProviderEngine : public ICryptoEngine {
public:
    KAEProviderEngine();
    explicit KAEProviderEngine(const KAEProviderConfig &kaeConfig);
    ~KAEProviderEngine() override;

    // --- 生命周期 ---
    bool Initialize(const CryptoEngineConfig &config) override;
    void Finalize() override;
    CryptoEngineCapability GetCapability() const override;
    bool IsInitialized() const override;

    // --- 对称加密 (兜底实现，TLS 数据路径上由 Provider 自动加速) ---
    bool EncryptAEAD(SymmetricAlgorithm algo, const uint8_t *key, size_t keyLen,
                     const uint8_t *iv, size_t ivLen,
                     const uint8_t *plaintext, size_t plaintextLen,
                     const uint8_t *aad, size_t aadLen,
                     uint8_t *ciphertext, size_t *ciphertextLen,
                     uint8_t *tag, size_t tagLen) override;

    bool DecryptAEAD(SymmetricAlgorithm algo, const uint8_t *key, size_t keyLen,
                     const uint8_t *iv, size_t ivLen,
                     const uint8_t *ciphertext, size_t ciphertextLen,
                     const uint8_t *aad, size_t aadLen,
                     const uint8_t *tag, size_t tagLen,
                     uint8_t *plaintext, size_t *plaintextLen) override;

    // --- 非对称运算 ---
    bool ECDHKeyAgreement(AsymmetricAlgorithm algo,
                          const uint8_t *peerPublicKey, size_t peerPublicKeyLen,
                          uint8_t *sharedSecret, size_t *sharedSecretLen) override;
    bool Sign(AsymmetricAlgorithm algo, const CryptoKeyHandle &key,
              const uint8_t *digest, size_t digestLen,
              uint8_t *signature, size_t *sigLen) override;
    bool Verify(AsymmetricAlgorithm algo, const CryptoKeyHandle &key,
                const uint8_t *digest, size_t digestLen,
                const uint8_t *signature, size_t sigLen) override;

    // --- 哈希运算 ---
    bool Hash(HashAlgorithm algo, const uint8_t *data, size_t dataLen,
              uint8_t *digest, size_t *digestLen) override;
    bool HMAC(HashAlgorithm algo, const uint8_t *key, size_t keyLen,
              const uint8_t *data, size_t dataLen,
              uint8_t *mac, size_t *macLen) override;

    // --- HKDF (TLS 1.3 密钥派生) ---
    bool HKDFExtract(HashAlgorithm algo,
                     const uint8_t *salt, size_t saltLen,
                     const uint8_t *ikm, size_t ikmLen,
                     uint8_t *prk, size_t *prkLen) override;
    bool HKDFExpand(HashAlgorithm algo,
                    const uint8_t *prk, size_t prkLen,
                    const uint8_t *info, size_t infoLen,
                    uint8_t *okm, size_t okmLen) override;

    // --- 随机数生成 ---
    bool RandomBytes(uint8_t *buffer, size_t len) override;

    // --- 密钥管理 ---
    bool ImportKey(uint64_t keyId, const uint8_t *keyData, size_t keyDataLen,
                   CryptoKeyHandle &handle) override;
    bool DestroyKey(const CryptoKeyHandle &handle) override;

    // --- Provider 集成 ---
    /**
     * @brief 获取 OSSL_LIB_CTX* 指针
     *
     * 返回加载了 KAE Provider 的 library context。
     * AbstractTLSAdaptor 在创建 SSL_CTX 时使用此上下文，
     * 从而使 TLS 内部密码运算自动使用 KAE 硬件加速。
     */
    void *GetProviderContext() const override;

    bool IsHardwareAccelerated() const override;
    const char *GetAcceleratedAlgorithms() const override;

    // --- KAE 特有的诊断接口 ---

    /**
     * @brief 查询 KAE Provider 是否加载成功
     */
    bool IsKAEProviderLoaded() const;

    /**
     * @brief 获取 KAE Provider 版本信息
     */
    std::string GetKAEVersion() const;

private:
    // 加载 KAE Provider
    bool LoadKAEProvider();

    // 获取默认软件兜底引擎
    ICryptoEngine *GetFallbackEngine();
    void ReleaseFallbackEngine();

    KAEProviderConfig m_kaeConfig;
    bool m_initialized;
    bool m_kaeLoaded;

    // OpenSSL 3.0+ Provider 句柄
    OSSL_LIB_CTX *m_libCtx;        // OSSL_LIB_CTX*
    OSSL_PROVIDER *m_defaultProv;   // OSSL_PROVIDER* (default provider)
    OSSL_PROVIDER *m_kaeProv;       // OSSL_PROVIDER* (KAE provider)

    // 软件兜底引擎（用于直接 API 调用场景，TLS 数据路径不走这里）
    ICryptoEngine *m_fallbackEngine;
};

/**
 * @brief KAE Provider 引擎工厂
 */
class KAEProviderEngineFactory : public ICryptoEngineFactory {
public:
    KAEProviderEngineFactory();
    explicit KAEProviderEngineFactory(const KAEProviderConfig &config);

    ICryptoEngine *Create() override;
    const char *GetName() const override;

private:
    KAEProviderConfig m_config;
};

}  // namespace scf

#endif  // SCF_KAE_PROVIDER_ENGINE_H
