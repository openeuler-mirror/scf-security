/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 */

#ifndef SCF_CRYPTO_ENGINE_H
#define SCF_CRYPTO_ENGINE_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace scf {

// ============================================================
// 硬件密码加速引擎抽象层
// 支持：软件实现(OpenSSL默认)、硬件加密卡、国密加速卡等可替换方案
// ============================================================

/**
 * @brief 对称加密算法类型
 */
enum class SymmetricAlgorithm : int32_t {
    AES_128_GCM = 1,
    AES_256_GCM = 2,
    AES_128_CCM = 3,
    CHACHA20_POLY1305 = 4,
    SM4_GCM = 5,         // 国密 SM4
    CUSTOM = 99,
};

/**
 * @brief 非对称算法类型
 */
enum class AsymmetricAlgorithm : int32_t {
    RSA = 1,
    ECDSA_P256 = 2,
    ECDSA_P384 = 3,
    ECDSA_P521 = 4,
    EDDSA_25519 = 5,
    SM2 = 6,             // 国密 SM2
    CUSTOM = 99,
};

/**
 * @brief 哈希算法类型
 */
enum class HashAlgorithm : int32_t {
    SHA256 = 1,
    SHA384 = 2,
    SHA512 = 3,
    SM3 = 4,             // 国密 SM3
    CUSTOM = 99,
};

/**
 * @brief 密钥交换算法类型
 */
enum class KeyExchangeAlgorithm : int32_t {
    ECDHE = 1,
    DHE = 2,
    PSK = 3,
    SM2_KEY_EXCHANGE = 4, // 国密 SM2 密钥交换
    CUSTOM = 99,
};

/**
 * @brief 密码引擎能力描述
 */
struct CryptoEngineCapability {
    std::string engineName;        // 引擎名称
    std::string engineVersion;     // 引擎版本
    std::string hardwareVendor;    // 硬件厂商信息

    // 支持的算法列表
    std::vector<SymmetricAlgorithm> symmetricAlgos;
    std::vector<AsymmetricAlgorithm> asymmetricAlgos;
    std::vector<HashAlgorithm> hashAlgos;
    std::vector<KeyExchangeAlgorithm> keyExchangeAlgos;

    // 硬件特性
    bool hardwareAccelerated;      // 是否硬件加速
    bool supportsAsyncOperation;    // 是否支持异步操作
    bool supportsOffload;           // 是否支持计算卸载
    uint32_t maxConcurrentOps;     // 最大并发操作数 (0 = 无限制)

    CryptoEngineCapability()
        : hardwareAccelerated(false),
          supportsAsyncOperation(false),
          supportsOffload(false),
        maxConcurrentOps(0)
    {}
};

/**
 * @brief 密码引擎配置
 */
struct CryptoEngineConfig {
    static constexpr uint32_t kDefaultSessionPoolSize = 16;
    static constexpr uint32_t kDefaultAsyncQueueDepth = 64;

    std::string configFilePath;    // 引擎配置文件路径
    std::string devicePath;        // 硬件设备路径 (如 /dev/crypto)
    uint32_t sessionPoolSize;      // 会话池大小
    bool enableAsyncMode;          // 是否启用异步模式
    uint32_t asyncQueueDepth;      // 异步队列深度

    CryptoEngineConfig()
        : sessionPoolSize(kDefaultSessionPoolSize),
          enableAsyncMode(false),
        asyncQueueDepth(kDefaultAsyncQueueDepth)
    {}
};

/**
 * @brief 密钥句柄 (用于硬件中存储的密钥引用)
 */
struct CryptoKeyHandle {
    uint64_t keyId;                // 密钥 ID
    std::string keyLabel;          // 密钥标签
    void *engineContext;           // 引擎内部上下文

    CryptoKeyHandle()
        : keyId(0),
        engineContext(nullptr)
    {}
};

// ============================================================
// 密码引擎抽象接口
// ============================================================

/**
 * @brief 密码引擎抽象接口
 *
 * 所有密码加速实现（软件、硬件加密卡、国密加速卡等）都需实现此接口。
 * 用户可通过此接口替换 TLS 底层的密码运算引擎。
 */
class ICryptoEngine {
public:
    virtual ~ICryptoEngine() = default;

    // --- 生命周期 ---

    /**
     * @brief 初始化引擎
     * @param config 引擎配置
     * @return true 成功, false 失败
     */
    virtual bool Initialize(const CryptoEngineConfig &config) = 0;

    /**
     * @brief 反初始化引擎，释放资源
     */
    virtual void Finalize() = 0;

    /**
     * @brief 获取引擎能力描述
     */
    virtual CryptoEngineCapability GetCapability() const = 0;

    /**
     * @brief 引擎是否已初始化
     */
    virtual bool IsInitialized() const = 0;

    // --- 对称加密 ---

    /**
     * @brief 使用 AEAD 加密
     * @param algo 算法
     * @param key 密钥
     * @param keyLen 密钥长度
     * @param iv 初始化向量
     * @param ivLen IV长度
     * @param plaintext 明文
     * @param plaintextLen 明文长度
     * @param aad 附加认证数据 (可为 nullptr)
     * @param aadLen AAD长度
     * @param ciphertext [OUT] 密文 (包含认证标签)
     * @param ciphertextLen [OUT] 密文长度
     * @param tag [OUT] 认证标签
     * @param tagLen 标签长度
     * @return true 成功
     */
    virtual bool EncryptAEAD(
        SymmetricAlgorithm algo,
        const uint8_t *key, size_t keyLen,
        const uint8_t *iv, size_t ivLen,
        const uint8_t *plaintext, size_t plaintextLen,
        const uint8_t *aad, size_t aadLen,
        uint8_t *ciphertext, size_t *ciphertextLen,
        uint8_t *tag, size_t tagLen) = 0;

    /**
     * @brief 使用 AEAD 解密
     * @return true 认证通过且解密成功
     */
    virtual bool DecryptAEAD(
        SymmetricAlgorithm algo,
        const uint8_t *key, size_t keyLen,
        const uint8_t *iv, size_t ivLen,
        const uint8_t *ciphertext, size_t ciphertextLen,
        const uint8_t *aad, size_t aadLen,
        const uint8_t *tag, size_t tagLen,
        uint8_t *plaintext, size_t *plaintextLen) = 0;

    // --- 非对称运算 ---

    /**
     * @brief ECDH/ECDHE 密钥协商
     * @param algo 椭圆曲线算法
     * @param peerPublicKey 对端公钥
     * @param peerPublicKeyLen 对端公钥长度
     * @param sharedSecret [OUT] 协商的共享密钥
     * @param sharedSecretLen [OUT] 共享密钥长度
     * @return true 成功
     */
    virtual bool ECDHKeyAgreement(
        AsymmetricAlgorithm algo,
        const uint8_t *peerPublicKey, size_t peerPublicKeyLen,
        uint8_t *sharedSecret, size_t *sharedSecretLen) = 0;

    /**
     * @brief 数字签名
     */
    virtual bool Sign(
        AsymmetricAlgorithm algo,
        const CryptoKeyHandle &key,
        const uint8_t *digest, size_t digestLen,
        uint8_t *signature, size_t *sigLen) = 0;

    /**
     * @brief 数字签名验证
     */
    virtual bool Verify(
        AsymmetricAlgorithm algo,
        const CryptoKeyHandle &key,
        const uint8_t *digest, size_t digestLen,
        const uint8_t *signature, size_t sigLen) = 0;

    // --- 哈希运算 ---

    /**
     * @brief 计算哈希值
     */
    virtual bool Hash(
        HashAlgorithm algo,
        const uint8_t *data, size_t dataLen,
        uint8_t *digest, size_t *digestLen) = 0;

    /**
     * @brief HMAC 运算
     */
    virtual bool HMAC(
        HashAlgorithm algo,
        const uint8_t *key, size_t keyLen,
        const uint8_t *data, size_t dataLen,
        uint8_t *mac, size_t *macLen) = 0;

    // --- HKDF (TLS 1.3 密钥派生) ---

    /**
     * @brief HKDF-Extract
     */
    virtual bool HKDFExtract(
        HashAlgorithm algo,
        const uint8_t *salt, size_t saltLen,
        const uint8_t *ikm, size_t ikmLen,
        uint8_t *prk, size_t *prkLen) = 0;

    /**
     * @brief HKDF-Expand
     */
    virtual bool HKDFExpand(
        HashAlgorithm algo,
        const uint8_t *prk, size_t prkLen,
        const uint8_t *info, size_t infoLen,
        uint8_t *okm, size_t okmLen) = 0;

    // --- 随机数生成 ---

    /**
     * @brief 生成安全随机数 (优先使用硬件真随机数)
     */
    virtual bool RandomBytes(uint8_t *buffer, size_t len) = 0;

    // --- 密钥管理 ---

    /**
     * @brief 从硬件安全模块导入/生成密钥
     * @param keyId 密钥标识
     * @param keyData 密钥材料 (nullptr 表示硬件内部生成)
     * @param keyDataLen 密钥材料长度
     * @param handle [OUT] 密钥句柄
     */
    virtual bool ImportKey(
        uint64_t keyId,
        const uint8_t *keyData, size_t keyDataLen,
        CryptoKeyHandle &handle) = 0;

    /**
     * @brief 销毁密钥句柄
     */
    virtual bool DestroyKey(const CryptoKeyHandle &handle) = 0;

    // --- OpenSSL 3.0+ Provider 集成 ---

    /**
     * @brief 获取此引擎管理的 OpenSSL Library Context (OSSL_LIB_CTX*)
     *
     * 对于基于 OpenSSL 3.0+ Provider 的硬件加速引擎（如 KAE），
     * 此方法返回加载了硬件加速 Provider 的 OSSL_LIB_CTX* 指针。
     * AbstractTLSAdaptor 将使用此上下文创建 SSL_CTX，
     * 从而使 TLS 内部的密码运算自动路由到硬件加速 Provider。
     *
     * @return 成功返回 OSSL_LIB_CTX* 指针，不使用 Provider 则返回 nullptr
     */
    virtual void *GetProviderContext() const = 0;

    /**
     * @brief 引擎是否提供硬件加速（而非纯软件实现）
     */
    virtual bool IsHardwareAccelerated() const = 0;

    /**
     * @brief 获取硬件加速支持的算法列表描述
     * @return 格式化字符串，用于日志输出。例如 "AES-GCM, SM3, SM4, ECDH"
     */
    virtual const char *GetAcceleratedAlgorithms() const = 0;
};

// ============================================================
// 默认软件密码引擎 (基于 OpenSSL)
// ============================================================

/**
 * @brief 基于 OpenSSL 软件实现的默认密码引擎
 *
 * 当没有硬件加速模块时使用此实现。
 */
class DefaultSoftwareCryptoEngine : public ICryptoEngine {
public:
    DefaultSoftwareCryptoEngine();
    ~DefaultSoftwareCryptoEngine() override;

    bool Initialize(const CryptoEngineConfig &config) override;
    void Finalize() override;
    CryptoEngineCapability GetCapability() const override;
    bool IsInitialized() const override;

    bool EncryptAEAD(SymmetricAlgorithm algo, const uint8_t *key, size_t keyLen,
                     const uint8_t *iv, size_t ivLen, const uint8_t *plaintext, size_t plaintextLen,
                     const uint8_t *aad, size_t aadLen, uint8_t *ciphertext, size_t *ciphertextLen,
                     uint8_t *tag, size_t tagLen) override;

    bool DecryptAEAD(SymmetricAlgorithm algo, const uint8_t *key, size_t keyLen,
                     const uint8_t *iv, size_t ivLen, const uint8_t *ciphertext, size_t ciphertextLen,
                     const uint8_t *aad, size_t aadLen, const uint8_t *tag, size_t tagLen,
                     uint8_t *plaintext, size_t *plaintextLen) override;

    bool ECDHKeyAgreement(AsymmetricAlgorithm algo, const uint8_t *peerPublicKey, size_t peerPublicKeyLen,
                          uint8_t *sharedSecret, size_t *sharedSecretLen) override;

    bool Sign(AsymmetricAlgorithm algo, const CryptoKeyHandle &key,
              const uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *sigLen) override;

    bool Verify(AsymmetricAlgorithm algo, const CryptoKeyHandle &key,
                const uint8_t *digest, size_t digestLen, const uint8_t *signature, size_t sigLen) override;

    bool Hash(HashAlgorithm algo, const uint8_t *data, size_t dataLen,
              uint8_t *digest, size_t *digestLen) override;

    bool HMAC(HashAlgorithm algo, const uint8_t *key, size_t keyLen,
              const uint8_t *data, size_t dataLen, uint8_t *mac, size_t *macLen) override;

    bool HKDFExtract(HashAlgorithm algo, const uint8_t *salt, size_t saltLen,
                     const uint8_t *ikm, size_t ikmLen, uint8_t *prk, size_t *prkLen) override;

    bool HKDFExpand(HashAlgorithm algo, const uint8_t *prk, size_t prkLen,
                    const uint8_t *info, size_t infoLen, uint8_t *okm, size_t okmLen) override;

    bool RandomBytes(uint8_t *buffer, size_t len) override;

    bool ImportKey(uint64_t keyId, const uint8_t *keyData, size_t keyDataLen,
                   CryptoKeyHandle &handle) override;

    bool DestroyKey(const CryptoKeyHandle &handle) override;

    // --- Provider 集成 ---
    void *GetProviderContext() const override;
    bool IsHardwareAccelerated() const override;
    const char *GetAcceleratedAlgorithms() const override;

private:
    bool m_initialized;
};

// ============================================================
// 密码引擎工厂
// ============================================================

/**
 * @brief 密码引擎工厂接口
 */
class ICryptoEngineFactory {
public:
    virtual ~ICryptoEngineFactory() = default;
    virtual ICryptoEngine *Create() = 0;
    virtual const char *GetName() const = 0;
};

/**
 * @brief 默认软件密码引擎工厂
 */
class DefaultSoftwareCryptoEngineFactory : public ICryptoEngineFactory {
public:
    ICryptoEngine *Create() override;
    const char *GetName() const override;
};

}  // namespace scf

#endif  // SCF_CRYPTO_ENGINE_H
