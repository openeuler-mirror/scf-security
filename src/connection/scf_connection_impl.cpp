/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 *
 * SCFConnection 实现 —— 整合 ctx/obj/transport/crypto 为用户统一接口。
 */

#include "scf_connection.h"
#include "scf.h"
#include "scf_ssl.h"
#include "scf_inner.h"

#include "socket_transport.h"
#include "kae_provider_engine.h"
#include "custom_logger.h"

#include <map>
#include <mutex>

namespace scf {

// ============================================================
// 全局注册表
// ============================================================

static std::mutex g_registryMutex;
static std::map<TransportProtocol, ITransportFactory *> g_transportFactories;
static std::map<std::string, ICryptoEngineFactory *> g_cryptoEngineFactories;

bool SCF_RegisterTransportFactory(ITransportFactory *factory)
{
    if (factory == nullptr) {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_registryMutex);
    g_transportFactories[factory->GetProtocol()] = factory;
    return true;
}

void SCF_UnregisterTransportFactory(TransportProtocol protocol)
{
    std::lock_guard<std::mutex> lock(g_registryMutex);
    g_transportFactories.erase(protocol);
}

bool SCF_RegisterCryptoEngineFactory(ICryptoEngineFactory *factory)
{
    if (factory == nullptr) {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_registryMutex);
    g_cryptoEngineFactories[factory->GetName()] = factory;
    return true;
}

void SCF_UnregisterCryptoEngineFactory(const std::string &name)
{
    std::lock_guard<std::mutex> lock(g_registryMutex);
    g_cryptoEngineFactories.erase(name);
}

// ============================================================
// NIST SP 800-57 安全强度 → 策略映射
// ============================================================
//
// 参考: NIST SP 800-57 Part 1 Rev.5, Table 2
//       NIST SP 800-52 Rev.2 (TLS Implementation Guidance)
//
//   安全强度    对称算法         哈希      ECDHE曲线      PQ KEM (抗量子)
//   ─────────────────────────────────────────────────────────────────
//   112-bit     AES-128-GCM      SHA-256  P-256           —
//   128-bit     AES-128-GCM      SHA-256  P-256/X25519    Kyber-512
//   192-bit     AES-256-GCM      SHA-384  P-384           Kyber-768
//   256-bit     AES-256-GCM      SHA-384/512  P-521       Kyber-1024
//
//   抗量子级别使用混合密钥交换 (Hybrid KEM):
//     经典 ECDHE + 后量子 KEM 同时协商，任一被攻破不影响安全性。

struct SecurityLevelMapping {
    uint32_t securityStrengthBits;     // NIST SP 800-57 安全强度 (bits)
    bool postQuantumResistant;         // 是否要求抗量子安全
    const char *nistLevelLabel;        // 可读标签，如 "NIST-SP800-57-128bit"

    // TLS 协议版本
    uint32_t protocolVersionMin;
    uint32_t protocolVersionMax;

    // TLS 1.3 算法套 (按优先级排列)
    std::vector<uint16_t> tls13CipherSuites;

    // 密钥交换命名组 (OpenSSL groups，按优先级排列)
    // 对于抗量子级别，应包含 Hybrid KEM 组
    std::vector<std::string> keyExchangeGroups;

    SCF_POLICY_MODE policyMode;
};

static SecurityLevelMapping GetSecurityLevelMapping(SCF_SECURITY_LEVEL level)
{
    SecurityLevelMapping m;

    switch (level) {
        // ============================================================
        // 经典安全强度 (无抗量子保护)
        // ============================================================

        case SCF_SECURITY_112BIT:
            // NIST 最低可接受安全强度 (2030年前)
            // 对标: 3DES / RSA-2048 / SHA-1 → 已弃用
            // 实际使用 AES-128-GCM + ECDHE-P256 (高于112-bit保证)
            m.securityStrengthBits = 112;
            m.postQuantumResistant = false;
            m.nistLevelLabel = "NIST-SP800-57-112bit";
            m.protocolVersionMin = SCF_SSL_VERSION_TLS12;
            m.protocolVersionMax = SCF_SSL_VERSION_TLS13;
            m.tls13CipherSuites = {
                SCF_SSL_AES_128_GCM_SHA256,
                SCF_SSL_AES_256_GCM_SHA384,
            };
            m.keyExchangeGroups = {
                "X25519",
                "P-256",
            };
            m.policyMode = SCF_POLICY_MIDDLE;
            break;

        case SCF_SECURITY_128BIT:
        default:
            // NIST 推荐最低安全强度 (2030年后仍有效)
            // 对标: AES-128 / ECDSA-P256 / SHA-256
            // TLS 1.3 only, 128-bit 等效安全
            m.securityStrengthBits = 128;
            m.postQuantumResistant = false;
            m.nistLevelLabel = "NIST-SP800-57-128bit";
            m.protocolVersionMin = SCF_SSL_VERSION_TLS13;
            m.protocolVersionMax = SCF_SSL_VERSION_TLS13;
            m.tls13CipherSuites = {
                SCF_SSL_AES_128_GCM_SHA256,
                SCF_SSL_AES_256_GCM_SHA384,
                SCF_SSL_CHACHA20_POLY1305_SHA256,
            };
            m.keyExchangeGroups = {
                "X25519",              // ECDH Curve25519 (128-bit, NIST推荐)
                "P-256",               // ECDH secp256r1 (128-bit)
            };
            m.policyMode = SCF_POLICY_HIGH;
            break;

        case SCF_SECURITY_192BIT:
            // NIST 192-bit 安全强度
            // 对标: AES-192 / ECDSA-P384 / SHA-384
            m.securityStrengthBits = 192;
            m.postQuantumResistant = false;
            m.nistLevelLabel = "NIST-SP800-57-192bit";
            m.protocolVersionMin = SCF_SSL_VERSION_TLS13;
            m.protocolVersionMax = SCF_SSL_VERSION_TLS13;
            m.tls13CipherSuites = {
                SCF_SSL_AES_256_GCM_SHA384,      // AES-256 满足 192-bit
                SCF_SSL_AES_128_GCM_SHA256,
            };
            m.keyExchangeGroups = {
                "P-384",               // ECDH secp384r1 (192-bit)
                "X25519",
            };
            m.policyMode = SCF_POLICY_HIGH;
            break;

        case SCF_SECURITY_256BIT:
            // NIST 最高经典安全强度
            // 对标: AES-256 / ECDSA-P521 / SHA-512
            m.securityStrengthBits = 256;
            m.postQuantumResistant = false;
            m.nistLevelLabel = "NIST-SP800-57-256bit";
            m.protocolVersionMin = SCF_SSL_VERSION_TLS13;
            m.protocolVersionMax = SCF_SSL_VERSION_TLS13;
            m.tls13CipherSuites = {
                SCF_SSL_AES_256_GCM_SHA384,      // AES-256 满足 256-bit
                SCF_SSL_AES_128_GCM_SHA256,
            };
            m.keyExchangeGroups = {
                "P-521",               // ECDH secp521r1 (256-bit)
                "P-384",
                "X25519",
            };
            m.policyMode = SCF_POLICY_HIGH;
            break;

        // ============================================================
        // 抗量子安全强度 (Hybrid ECDH + PQ KEM)
        // ============================================================
        // 混合密钥交换: 同时使用经典 ECDH 和后量子 KEM 进行两次密钥协商，
        // 组合结果作为会话密钥材料。任何一个被攻破都不影响另一方的安全性。
        //
        // 依赖: OpenSSL 3.x + oqsprovider (liboqs)
        // 运行时自动检测: 如果 PQ Provider 不可用，自动降级到对应经典级别

        case SCF_SECURITY_128BIT_PQ:
            // 128-bit 抗量子安全强度
            // Hybrid: X25519 (128-bit 经典) + Kyber-512 (NIST PQC Level 1)
            // NIST Level 1 等效于 AES-128 安全性
            m.securityStrengthBits = 128;
            m.postQuantumResistant = true;
            m.nistLevelLabel = "NIST-SP800-57-128bit-PQ";
            m.protocolVersionMin = SCF_SSL_VERSION_TLS13;
            m.protocolVersionMax = SCF_SSL_VERSION_TLS13;
            m.tls13CipherSuites = {
                SCF_SSL_AES_128_GCM_SHA256,
                SCF_SSL_AES_256_GCM_SHA384,
            };
            m.keyExchangeGroups = {
                // 优先级: Hybrid PQ 组在前，经典组作为回退
                SCF_NAMED_GROUP_X25519_KYBER512,   // Hybrid X25519 + Kyber-512
                SCF_NAMED_GROUP_P256_KYBER512,     // Hybrid P-256 + Kyber-512
                "x25519_kyber768",                  // Hybrid X25519 + Kyber-768 (更强)
                "X25519",                           // 经典回退
                "P-256",                            // 经典回退
            };
            m.policyMode = SCF_POLICY_HIGH;
            break;

        case SCF_SECURITY_256BIT_PQ:
            // 256-bit 抗量子安全强度
            // Hybrid: ECDH-P521 (256-bit 经典) + Kyber-1024 (NIST PQC Level 5)
            // NIST Level 5 等效于 AES-256 安全性
            m.securityStrengthBits = 256;
            m.postQuantumResistant = true;
            m.nistLevelLabel = "NIST-SP800-57-256bit-PQ";
            m.protocolVersionMin = SCF_SSL_VERSION_TLS13;
            m.protocolVersionMax = SCF_SSL_VERSION_TLS13;
            m.tls13CipherSuites = {
                SCF_SSL_AES_256_GCM_SHA384,         // AES-256 满足 256-bit
            };
            m.keyExchangeGroups = {
                // 优先级: 最高安全 Hybrid PQ 组
                SCF_NAMED_GROUP_P521_KYBER1024,     // Hybrid P-521 + Kyber-1024
                SCF_NAMED_GROUP_P521_MLKEM1024,     // Hybrid P-521 + ML-KEM-1024 (FIPS)
                "p384_kyber768",                     // Hybrid P-384 + Kyber-768
                "P-521",                             // 经典回退
                "P-384",                             // 经典回退
            };
            m.policyMode = SCF_POLICY_HIGH;
            break;
    }
    return m;
}

// ============================================================
// CertVerifyPolicy → SCF VerifyMode 映射
// ============================================================

static uint32_t MapCertVerifyPolicy(SCF_CERT_VERIFY_POLICY policy)
{
    switch (policy) {
        case SCF_CERT_VERIFY_NONE:
            return SCF_VERIFY_MODE_NONE;
        case SCF_CERT_VERIFY_OPTIONAL:
            return SCF_VERIFY_DEFAULT;
        case SCF_CERT_VERIFY_REQUIRED:
            return SCF_VERIFY_DEFAULT | SCF_VERIFY_PEER | SCF_VERIFY_FAIL_IF_NO_PEER_CERT;
        case SCF_CERT_VERIFY_STRICT:
            return SCF_VERIFY_DEFAULT | SCF_VERIFY_PEER | SCF_VERIFY_FAIL_IF_NO_PEER_CERT;
        default:
            return SCF_VERIFY_DEFAULT;
    }
}

// ============================================================
// SCFConnectionImpl
// ============================================================

class SCFConnectionImpl : public SCFConnection {
public:
    explicit SCFConnectionImpl(const SCFConnectionConfig &config);
    ~SCFConnectionImpl() override;

    int32_t Connect(const std::string &host, uint16_t port) override;
    int32_t Listen(const std::string &host, uint16_t port) override;
    SCFConnection *Accept() override;
    int32_t HandshakeStep() override;
    int32_t Close() override;

    int32_t Read(uint8_t *data, uint32_t len, uint32_t *readLen) override;
    int32_t Write(const uint8_t *data, uint32_t len, uint32_t *writeLen) override;

    SCF_CONNECTION_STATE GetState() const override;
    bool IsConnected() const override;
    const char *GetTLSVersion() const override;
    uint16_t GetCipherSuite() const override;
    void *GetPeerCertificate() override;
    void FreePeerCertificate(void *cert) override;
    ITransport *GetTransport() const override;
    int32_t GetNativeHandle() const override;

    int32_t TriggerKeyUpdate() override;
    void SetUserData(void *userData) override;
    void *GetUserData() const override;

private:
    int32_t SetupPolicyContext();
    int32_t SetupTransportClient(const std::string &host, uint16_t port);
    int32_t SetupTransportServer(const std::string &host, uint16_t port);
    int32_t CreatePolicyObj();
    int32_t SetupCertificates();
    int32_t SetupPSK();
    int32_t SetupCipherSuites();
    void Cleanup();

    SCFConnectionConfig m_config;
    SCF_CONNECTION_STATE m_state;

    SCF_PolicyCtx *m_policyCtx;
    SCF_PolicyObj *m_policyObj;
    ITransport *m_transport;
    ICryptoEngine *m_cryptoEngine;
    bool m_ownsCryptoEngine;       ///< 是否拥有密码引擎的所有权

    // v2.0: 密钥交换组 (延迟到 SSL_CTX 创建后应用)
    std::vector<std::string> m_keyExchangeGroups;
    bool m_postQuantumResistant;   ///< 当前连接是否要求抗量子安全

    bool m_isServer;
    bool m_handshakeDone;
    void *m_userData;
    std::string m_negotiatedVersion;
    uint16_t m_negotiatedCipherSuite;
};

// ============================================================
// 静态工厂方法
// ============================================================

SCFConnection *SCFConnection::Create(const SCFConnectionConfig &config)
{
    return new SCFConnectionImpl(config);
}

// ============================================================
// SCFConnectionImpl 实现
// ============================================================

SCFConnectionImpl::SCFConnectionImpl(const SCFConnectionConfig &config)
    : m_config(config),
      m_state(SCF_CONN_INIT),
      m_policyCtx(nullptr),
      m_policyObj(nullptr),
      m_transport(nullptr),
      m_cryptoEngine(nullptr),
      m_ownsCryptoEngine(false),
      m_postQuantumResistant(false),
      m_isServer(config.role == SCF_ROLE_SERVER),
      m_handshakeDone(false),
      m_userData(nullptr),
      m_negotiatedCipherSuite(0)
{
    CCSEC_LOG_DEBUG("SCFConnectionImpl created, role="
        << (m_isServer ? "server" : "client")
        << " securityLevel=" << config.securityLevel);
}

SCFConnectionImpl::~SCFConnectionImpl()
{
    Cleanup();
}

void SCFConnectionImpl::Cleanup()
{
    if (m_state == SCF_CONN_CONNECTED || m_state == SCF_CONN_CONNECTING) {
        Close();
    }

    if (m_policyObj != nullptr) {
        SCF_FreePolicyObj(&m_policyObj);
        m_policyObj = nullptr;
    }

    if (m_policyCtx != nullptr) {
        SCF_FreePolicyCtx(&m_policyCtx);
        m_policyCtx = nullptr;
    }

    if (m_transport != nullptr) {
        m_transport->Close();
        delete m_transport;
        m_transport = nullptr;
    }

    if (m_cryptoEngine != nullptr && m_ownsCryptoEngine) {
        // 从 TLS 适配器中清除引擎引用（避免悬空指针）
        if (g_adaptor != nullptr) {
            g_adaptor->SetCryptoEngine(nullptr);
        }
        m_cryptoEngine->Finalize();
        delete m_cryptoEngine;
        m_cryptoEngine = nullptr;
        m_ownsCryptoEngine = false;
    }

    m_state = SCF_CONN_CLOSED;
}

// ============================================================
// 策略与传输初始化
// ============================================================

int32_t SCFConnectionImpl::SetupPolicyContext()
{
    // === v2.0: 0. 初始化密码引擎（必须在 SSL_CTX 创建之前） ===
    // 如果密码引擎已存在（例如 Accept() 从父连接复用），跳过创建
    if (m_cryptoEngine == nullptr) {
        if (m_config.cryptoEngineFactory != nullptr) {
            m_cryptoEngine = m_config.cryptoEngineFactory->Create();
        } else {
            // 默认：尝试加载 KAE 硬件加速引擎（如果环境支持）
            KAEProviderEngineFactory kaeFactory;
            m_cryptoEngine = kaeFactory.Create();
        }

        if (m_cryptoEngine != nullptr) {
            CryptoEngineConfig ecfg;
            if (!m_cryptoEngine->Initialize(ecfg)) {
                CCSEC_LOG_WARN("SCFConnectionImpl: crypto engine init failed,"
                    << " falling back to default software crypto");
                delete m_cryptoEngine;
                m_cryptoEngine = nullptr;
            } else {
                m_ownsCryptoEngine = true;  // 标记所有权
                // ★ 核心：将密码引擎注入 TLS 适配器
                // 此后 InitSsl() 会通过 SSL_CTX_new_ex 使用引擎的 Provider Context
                // SSL_read/SSL_write 内部密码运算自动路由到硬件加速
                CHECK_SCF_ADAPTOR_RET("SetupPolicyContext-SetCryptoEngine");
                g_adaptor->SetCryptoEngine(m_cryptoEngine);

                CCSEC_LOG_INFO("SCFConnectionImpl: crypto engine injected into TLS adaptor."
                    << " Engine=" << (m_cryptoEngine->IsHardwareAccelerated() ? "HARDWARE" : "SOFTWARE")
                    << " Algorithms=" << m_cryptoEngine->GetAcceleratedAlgorithms());
            }
        }
    } else {
        // 复用已有引擎，确保 g_adaptor 仍持有正确的引用
        if (g_adaptor != nullptr) {
            g_adaptor->SetCryptoEngine(m_cryptoEngine);
        }
        CCSEC_LOG_DEBUG("SCFConnectionImpl: reusing existing crypto engine");
    }

    // 1. 创建策略上下文
    m_policyCtx = SCF_CreatePolicyCtx();
    if (m_policyCtx == nullptr) {
        CCSEC_LOG_ERROR("SCF_CreatePolicyCtx failed");
        return SCF_ERRNO_MEM_ALLOC;
    }

    // 2. 根据安全级别自动设置策略
    //    内部调用链路: SCF_SetPolicy → InitPolicyByMode → InitSsl()
    //    InitSsl() 会检查 g_adaptor->GetCryptoEngine()->GetProviderContext()
    //    并根据是否可用选择 SSL_CTX_new_ex() 或 SSL_CTX_new()
    auto mapping = GetSecurityLevelMapping(m_config.securityLevel);
    uint32_t verifyMode = MapCertVerifyPolicy(m_config.certVerifyPolicy);

    // ★ v2.0: 保存安全映射信息用于后续配置
    m_postQuantumResistant = mapping.postQuantumResistant;
    m_keyExchangeGroups = mapping.keyExchangeGroups;

    int32_t ret = SCF_SetPolicy(m_policyCtx, m_config.role, verifyMode, mapping.policyMode);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("SCF_SetPolicy failed, ret=" << ret);
        return ret;
    }

    // ★ v2.0: SSL_CTX 已在 InitPolicyByMode → InitSsl() 中创建，
    // 现在立即应用密钥交换组配置（必须在 SSL_CTX 创建之后）
    if (!m_keyExchangeGroups.empty() && g_adaptor != nullptr) {
        ret = g_adaptor->SetKeyExchangeGroups(m_policyCtx, m_keyExchangeGroups);
        if (ret != SCF_SUCCESS) {
            CCSEC_LOG_WARN("SCFConnectionImpl: SetKeyExchangeGroups failed, ret=" << ret <<
                ". Continuing without custom groups.");
            // 不返回失败：groups 不可用时回退到默认组
        } else {
            CCSEC_LOG_INFO("SCFConnectionImpl: security level configured. "
                << mapping.nistLevelLabel
                << " (" << mapping.securityStrengthBits << "bit"
                << (mapping.postQuantumResistant ? ", PQ-resistant" : "")
                << "), groups=" << m_keyExchangeGroups.size());
        }
    }

    // 3. 设置协议版本
    ret = SCF_SetProtocolVersion(m_policyCtx, mapping.protocolVersionMin,
        mapping.protocolVersionMax, nullptr, 0);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("SCF_SetProtocolVersion failed, ret=" << ret);
        return ret;
    }

    // 4. 设置算法套 (根据安全级别自动选择)
    ret = SetupCipherSuites();
    if (ret != SCF_SUCCESS) {
        return ret;
    }

    // 5. 设置证书或 PSK
    if (m_config.usePSK) {
        ret = SetupPSK();
    } else {
        ret = SetupCertificates();
    }
    if (ret != SCF_SUCCESS) {
        return ret;
    }

    // 6. 设置自定义校验回调
    if (m_config.appVerifyCb != nullptr) {
        ret = SCF_SetAppVerifyCallback(m_policyCtx, m_config.appVerifyCb, m_config.appVerifyArg);
        if (ret != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("SCF_SetAppVerifyCallback failed, ret=" << ret);
            return ret;
        }
    }

    // 7. 设置密钥自动更新
    if (m_config.enableKeyAutoUpdate) {
        constexpr uint32_t kDefaultKeyUpdateIntervalSec = 300;
        constexpr uint64_t kDefaultKeyUpdateByteLimit = 1073741824ULL;  // 1 GiB
        ret = SCF_SetKeyAutoUpdateParam(m_policyCtx, true,
                                        kDefaultKeyUpdateIntervalSec,
                                        kDefaultKeyUpdateByteLimit);
        if (ret != SCF_SUCCESS) {
            CCSEC_LOG_WARN("SCF_SetKeyAutoUpdateParam failed, ret=" << ret);
        }
    }

    return SCF_SUCCESS;
}

int32_t SCFConnectionImpl::SetupCipherSuites()
{
    auto mapping = GetSecurityLevelMapping(m_config.securityLevel);
    // 设置 TLS 1.3 算法套
    if (!mapping.tls13CipherSuites.empty()) {
        int32_t ret = SCF_SetCipherSuites(m_policyCtx, mapping.tls13CipherSuites.data(),
            static_cast<uint32_t>(mapping.tls13CipherSuites.size()));
        if (ret != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("SCF_SetCipherSuites failed, ret=" << ret);
            return ret;
        }
    }

    // 密钥交换组已在 SetupPolicyContext() 中通过 g_adaptor->SetKeyExchangeGroups() 应用，
    // 此处仅做日志记录。
    if (m_postQuantumResistant) {
        CCSEC_LOG_INFO("SCFConnectionImpl: post-quantum key exchange enabled."
            << " Security strength: " << mapping.securityStrengthBits << "bit."
            << " (NIST " << mapping.nistLevelLabel << ")");
    }

    return SCF_SUCCESS;
}

int32_t SCFConnectionImpl::SetupCertificates()
{
    // 加载 CA 证书
    if (!m_config.caCertPath.empty()) {
        SCF_FILE_CTX *caCtx = SCF_FileCtxNew();
        if (caCtx == nullptr) return SCF_ERRNO_MEM_ALLOC;

        int32_t ret = SCF_FileCtxSetBuf(caCtx, SCF_STORE_FILE_PATH,
            reinterpret_cast<uint8_t *>(m_config.caCertPath.data()),
            m_config.caCertPath.size() + 1,
            SCF_STORE_FORMAT_PEM);
        if (ret == SCF_SUCCESS) {
            ret = SCF_AddCert(m_policyCtx, caCtx, SCF_CERT_TYPE_CA);
        }
        SCF_FileCtxFree(&caCtx);
        if (ret != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("Add CA cert failed, ret=" << ret);
            return ret;
        }
    }

    // 加载设备证书和私钥
    if (!m_config.certPath.empty() && !m_config.keyPath.empty()) {
        // 设备证书
        SCF_FILE_CTX *certCtx = SCF_FileCtxNew();
        if (certCtx == nullptr) return SCF_ERRNO_MEM_ALLOC;

        int32_t ret = SCF_FileCtxSetBuf(certCtx, SCF_STORE_FILE_PATH,
            reinterpret_cast<uint8_t *>(m_config.certPath.data()),
            m_config.certPath.size() + 1,
            SCF_STORE_FORMAT_PEM);
        if (ret == SCF_SUCCESS) {
            ret = SCF_AddCert(m_policyCtx, certCtx, SCF_CERT_TYPE_EE);
        }
        SCF_FileCtxFree(&certCtx);
        if (ret != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("Add EE cert failed, ret=" << ret);
            return ret;
        }

        // 私钥
        SCF_FILE_CTX *keyCtx = SCF_FileCtxNew();
        if (keyCtx == nullptr) return SCF_ERRNO_MEM_ALLOC;

        ret = SCF_FileCtxSetBuf(keyCtx, SCF_STORE_FILE_PATH,
            reinterpret_cast<uint8_t *>(m_config.keyPath.data()),
            m_config.keyPath.size() + 1,
            SCF_STORE_FORMAT_PEM);
        if (ret == SCF_SUCCESS && !m_config.keyPassword.empty()) {
            ret = SCF_FileCtxSetPwd(keyCtx,
            reinterpret_cast<uint8_t *>(m_config.keyPassword.data()),
            m_config.keyPassword.size());
        }
        if (ret == SCF_SUCCESS) {
            ret = SCF_SetKey(m_policyCtx, keyCtx);
        }
        SCF_FileCtxFree(&keyCtx);
        if (ret != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("Set key failed, ret=" << ret);
            return ret;
        }
    }

    // 加载 CRL
    if (!m_config.crlPath.empty()) {
        SCF_FILE_CTX *crlCtx = SCF_FileCtxNew();
        if (crlCtx == nullptr) return SCF_ERRNO_MEM_ALLOC;

        int32_t ret = SCF_FileCtxSetBuf(crlCtx, SCF_STORE_FILE_PATH,
            reinterpret_cast<uint8_t *>(m_config.crlPath.data()),
            m_config.crlPath.size() + 1,
            SCF_STORE_FORMAT_PEM);
        if (ret == SCF_SUCCESS) {
            ret = SCF_AddCert(m_policyCtx, crlCtx, SCF_CERT_TYPE_CRL);
        }
        SCF_FileCtxFree(&crlCtx);
        if (ret != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("Add CRL failed, ret=" << ret);
            return ret;
        }
    }

    return SCF_SUCCESS;
}

int32_t SCFConnectionImpl::SetupPSK()
{
    // 创建 PSK 会话
    SCF_Session *sess = SCF_SessionNew();
    if (sess == nullptr) return SCF_ERRNO_MEM_ALLOC;

    int32_t ret = SCF_SessionSetMasterKey(sess, m_config.pskKey.data(),
        m_config.pskKey.size());
    if (ret != SCF_SUCCESS) {
        SCF_SessionFree(&sess);
        return ret;
    }

    ret = SCF_SessionSetProtocolVersion(sess, SCF_SSL_VERSION_TLS13_STR);
    if (ret != SCF_SUCCESS) {
        SCF_SessionFree(&sess);
        return ret;
    }

    // 根据安全级别设置算法套
    auto mapping = GetSecurityLevelMapping(m_config.securityLevel);
    if (!mapping.tls13CipherSuites.empty()) {
        static constexpr int kCipherIdByteCount = 2;
        static constexpr int kBitsPerByte = 8;
        uint8_t cipherId[kCipherIdByteCount];
        cipherId[0] = static_cast<uint8_t>(mapping.tls13CipherSuites[0] >> kBitsPerByte);
        cipherId[1] = static_cast<uint8_t>(mapping.tls13CipherSuites[0] & 0xFF);
        const void *cipherSuite = SCF_CipherFind(
            SCF_CreatePolicyObj(m_policyCtx), cipherId);  // 临时创建用于查找
        if (cipherSuite != nullptr) {
            SCF_SessionSetCipher(sess, cipherSuite, kCipherIdByteCount);
        }
    }

    // 设置 PSK 回调 (使用内置回调)
    // 注意：这里简化处理，实际生产代码中 PSK 回调需要更复杂的实现
    CCSEC_LOG_INFO("PSK session created");

    SCF_SessionFree(&sess);
    return SCF_SUCCESS;
}

// ============================================================
// 传输初始化
// ============================================================

int32_t SCFConnectionImpl::SetupTransportClient(const std::string &host, uint16_t port)
{
    // 创建传输对象
    if (m_config.transportFactory != nullptr) {
        m_transport = m_config.transportFactory->Create();
    } else {
        // 默认使用 Socket 传输
        SocketTransportFactory defaultFactory;
        m_transport = defaultFactory.Create();
    }

    if (m_transport == nullptr) {
        CCSEC_LOG_ERROR("Failed to create transport");
        return SCF_ERRNO_MEM_ALLOC;
    }

    // 设置传输配置
    TransportConfig tCfg;
    tCfg.nonBlocking = true;
    tCfg.connectTimeoutMs = static_cast<int32_t>(m_config.connectTimeoutMs);
    m_transport->SetConfig(tCfg);

    // 发起连接
    TransportAddress addr = TransportAddress::IPv4(host, port);
    TransportResult tRet = m_transport->Connect(addr, tCfg);
    if (tRet != TransportResult::SUCCESS) {
        CCSEC_LOG_ERROR("Transport connect failed: " << host << ":" << port);
        return SCF_ERRNO_SECURE_TRANSPORT;
    }

    m_state = SCF_CONN_CONNECTING;
    return SCF_SUCCESS;
}

int32_t SCFConnectionImpl::SetupTransportServer(const std::string &host, uint16_t port)
{
    if (m_config.transportFactory != nullptr) {
        m_transport = m_config.transportFactory->Create();
    } else {
        SocketTransportFactory defaultFactory;
        m_transport = defaultFactory.Create();
    }

    if (m_transport == nullptr) {
        return SCF_ERRNO_MEM_ALLOC;
    }

    TransportConfig tCfg;
    tCfg.nonBlocking = true;
    m_transport->SetConfig(tCfg);

    std::string bindHost = host.empty() ? "0.0.0.0" : host;
    TransportAddress addr = TransportAddress::IPv4(bindHost, port);
    TransportResult tRet = m_transport->Bind(addr);
    if (tRet != TransportResult::SUCCESS) {
        CCSEC_LOG_ERROR("Transport bind failed: " << bindHost << ":" << port);
        return SCF_ERRNO_SECURE_TRANSPORT;
    }

    m_state = SCF_CONN_INIT;  // 服务端等待 Accept
    return SCF_SUCCESS;
}

int32_t SCFConnectionImpl::CreatePolicyObj()
{
    m_policyObj = SCF_CreatePolicyObj(m_policyCtx);
    if (m_policyObj == nullptr) {
        CCSEC_LOG_ERROR("SCF_CreatePolicyObj failed");
        return SCF_ERRNO_MEM_ALLOC;
    }

    // 绑定底层传输句柄
    int32_t fd = m_transport->GetNativeHandle();
    if (fd >= 0) {
        int32_t ret = SCF_SetFd(m_policyObj, fd);
        if (ret != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("SCF_SetFd failed, ret=" << ret << " fd=" << fd);
            return ret;
        }
    }

    return SCF_SUCCESS;
}

// ============================================================
// 公共 API
// ============================================================

int32_t SCFConnectionImpl::Connect(const std::string &host, uint16_t port)
{
    CCSEC_LOG_INFO("SCFConnection::Connect to " << host << ":" << port);

    // 1. 初始化策略上下文
    int32_t ret = SetupPolicyContext();
    if (ret != SCF_SUCCESS) {
        m_state = SCF_CONN_ERROR;
        return ret;
    }

    // 2. 建立传输层连接
    ret = SetupTransportClient(host, port);
    if (ret != SCF_SUCCESS) {
        m_state = SCF_CONN_ERROR;
        Cleanup();
        return ret;
    }

    // 3. 创建策略对象
    ret = CreatePolicyObj();
    if (ret != SCF_SUCCESS) {
        m_state = SCF_CONN_ERROR;
        Cleanup();
        return ret;
    }

    // 4. 执行 TLS 握手
    ret = HandshakeStep();
    return ret;
}

int32_t SCFConnectionImpl::Listen(const std::string &host, uint16_t port)
{
    CCSEC_LOG_INFO("SCFConnection::Listen on " << host << ":" << port);

    int32_t ret = SetupPolicyContext();
    if (ret != SCF_SUCCESS) {
        m_state = SCF_CONN_ERROR;
        return ret;
    }

    ret = SetupTransportServer(host, port);
    if (ret != SCF_SUCCESS) {
        m_state = SCF_CONN_ERROR;
        return ret;
    }

    return SCF_SUCCESS;
}

SCFConnection *SCFConnectionImpl::Accept()
{
    if (!m_isServer || m_transport == nullptr) {
        CCSEC_LOG_ERROR("Accept called on non-server connection");
        return nullptr;
    }

    // 从传输层接受新连接
    ITransport *clientTransport = m_transport->Accept();
    if (clientTransport == nullptr) {
        return nullptr;  // 无可用的新连接
    }

    // 创建新的连接实例
    auto *newConn = new SCFConnectionImpl(m_config);
    newConn->m_transport = clientTransport;
    newConn->m_isServer = true;

    // 复用父连接的密码引擎（避免重复创建导致 g_adaptor 上的引擎被覆盖）
    if (m_cryptoEngine != nullptr) {
        newConn->m_cryptoEngine = m_cryptoEngine;
        newConn->m_ownsCryptoEngine = false;  // 子连接不拥有引擎所有权
        // 确保 g_adaptor 仍指向此引擎
        if (g_adaptor != nullptr) {
            g_adaptor->SetCryptoEngine(m_cryptoEngine);
        }
    }

    // 初始化策略（如果已有密码引擎，SetupPolicyContext 会跳过引擎创建）
    int32_t ret = newConn->SetupPolicyContext();
    if (ret != SCF_SUCCESS) {
        delete newConn;
        return nullptr;
    }

    ret = newConn->CreatePolicyObj();
    if (ret != SCF_SUCCESS) {
        delete newConn;
        return nullptr;
    }

    // 启动握手
    ret = newConn->HandshakeStep();
    if (ret == SCF_SSL_ERR_WANT_READ || ret == SCF_SSL_ERR_WANT_WRITE) {
        newConn->m_state = SCF_CONN_CONNECTING;
        return newConn;
    }
    if (ret != SCF_SUCCESS) {
        delete newConn;
        return nullptr;
    }

    newConn->m_state = SCF_CONN_CONNECTED;
    newConn->m_handshakeDone = true;
    return newConn;
}

int32_t SCFConnectionImpl::HandshakeStep()
{
    if (m_policyObj == nullptr) {
        return SCF_ERRNO_NULL_INPUT;
    }

    int32_t ret;
    if (m_isServer) {
        ret = SCF_Accept(m_policyObj);
    } else {
        ret = SCF_Connect(m_policyObj);
    }

    if (ret == SCF_SUCCESS) {
        m_handshakeDone = true;
        m_state = SCF_CONN_CONNECTED;

        // 获取协商结果
        const char *ver = SCF_GetProtocolVersion(m_policyObj);
        if (ver != nullptr) {
            m_negotiatedVersion = ver;
        }
        CCSEC_LOG_INFO("TLS handshake done, version=" << m_negotiatedVersion);
    } else if (ret == SCF_SSL_ERR_WANT_READ || ret == SCF_SSL_ERR_WANT_WRITE) {
        m_state = SCF_CONN_CONNECTING;
    } else {
        m_state = SCF_CONN_ERROR;
        CCSEC_LOG_ERROR("TLS handshake failed, ret=" << ret);
    }

    return ret;
}

int32_t SCFConnectionImpl::Close()
{
    CCSEC_LOG_DEBUG("SCFConnection::Close");

    if (m_state == SCF_CONN_CLOSED || m_state == SCF_CONN_CLOSING) {
        return SCF_SUCCESS;
    }
    m_state = SCF_CONN_CLOSING;

    int32_t ret = SCF_SUCCESS;
    if (m_policyObj != nullptr) {
        ret = SCF_Close(m_policyObj);
    }

    if (m_transport != nullptr) {
        m_transport->Close();
    }

    m_state = SCF_CONN_CLOSED;
    m_handshakeDone = false;
    return ret;
}

int32_t SCFConnectionImpl::Read(uint8_t *data, uint32_t len, uint32_t *readLen)
{
    if (m_state != SCF_CONN_CONNECTED || m_policyObj == nullptr) {
        return SCF_ERRNO_INVALID_PARAM;
    }
    return SCF_Read(m_policyObj, data, len, readLen);
}

int32_t SCFConnectionImpl::Write(const uint8_t *data, uint32_t len, uint32_t *writeLen)
{
    if (m_state != SCF_CONN_CONNECTED || m_policyObj == nullptr) {
        return SCF_ERRNO_INVALID_PARAM;
    }
    return SCF_Write(m_policyObj, data, len, writeLen);
}

SCF_CONNECTION_STATE SCFConnectionImpl::GetState() const
{
    return m_state;
}

bool SCFConnectionImpl::IsConnected() const
{
    return m_state == SCF_CONN_CONNECTED && m_handshakeDone;
}

const char *SCFConnectionImpl::GetTLSVersion() const
{
    if (m_handshakeDone && !m_negotiatedVersion.empty()) {
        return m_negotiatedVersion.c_str();
    }
    if (m_policyObj != nullptr) {
        return SCF_GetProtocolVersion(m_policyObj);
    }
    return "";
}

uint16_t SCFConnectionImpl::GetCipherSuite() const
{
    return m_negotiatedCipherSuite;
}

void *SCFConnectionImpl::GetPeerCertificate()
{
    if (m_policyObj == nullptr) {
        return nullptr;
    }
    return SCF_GetPeerCert(m_policyObj);
}

void SCFConnectionImpl::FreePeerCertificate(void *cert)
{
    SCF_FreeCert(&cert);
}

ITransport *SCFConnectionImpl::GetTransport() const
{
    return m_transport;
}

int32_t SCFConnectionImpl::GetNativeHandle() const
{
    if (m_transport != nullptr) {
        return m_transport->GetNativeHandle();
    }
    return -1;
}

int32_t SCFConnectionImpl::TriggerKeyUpdate()
{
    if (m_policyObj == nullptr) return SCF_ERRNO_NULL_INPUT;
    return SCF_ObjKeyUpdate(m_policyObj);
}

void SCFConnectionImpl::SetUserData(void *userData)
{
    m_userData = userData;
    if (m_policyObj != nullptr) {
        SCF_SetUserData(m_policyObj, userData);
    }
}

void *SCFConnectionImpl::GetUserData() const
{
    return m_userData;
}

// ============================================================
// 便捷工厂函数
// ============================================================

SCFConnection *SCF_NewClientConnection(
    SCF_SECURITY_LEVEL securityLevel, const std::string &caCertPath)
{
    SCFConnectionConfig cfg;
    cfg.securityLevel = securityLevel;
    cfg.role = SCF_ROLE_CLIENT;

    if (!caCertPath.empty()) {
        cfg.caCertPath = caCertPath;
        cfg.certVerifyPolicy = SCF_CERT_VERIFY_REQUIRED;
    } else {
        cfg.certVerifyPolicy = SCF_CERT_VERIFY_NONE;
    }

    return SCFConnection::Create(cfg);
}

SCFConnection *SCF_NewServerConnection(
    SCF_SECURITY_LEVEL securityLevel,
    const std::string &certPath, const std::string &keyPath)
{
    SCFConnectionConfig cfg;
    cfg.securityLevel = securityLevel;
    cfg.role = SCF_ROLE_SERVER;
    cfg.certPath = certPath;
    cfg.keyPath = keyPath;
    cfg.certVerifyPolicy = SCF_CERT_VERIFY_REQUIRED;

    return SCFConnection::Create(cfg);
}

SCFConnection *SCF_NewPSKConnection(
    SCF_SECURITY_LEVEL securityLevel,
    SCF_ROLE role,
    const std::string &pskIdentity,
    const uint8_t *pskKey, size_t pskKeyLen)
{
    SCFConnectionConfig cfg;
    cfg.securityLevel = securityLevel;
    cfg.role = role;
    cfg.usePSK = true;
    cfg.pskIdentity = pskIdentity;
    cfg.pskKey.assign(pskKey, pskKey + pskKeyLen);
    cfg.certVerifyPolicy = SCF_CERT_VERIFY_NONE;

    return SCFConnection::Create(cfg);
}

}  // namespace scf
