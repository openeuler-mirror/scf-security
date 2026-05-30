/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 */

#ifndef SCF_CONNECTION_H
#define SCF_CONNECTION_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <memory>
#include <functional>

#include "scf_def.h"
#include "scf_errno.h"
#include "scf_transport.h"
#include "scf_crypto_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

namespace scf {


// ============================================================
// 安全强度级别 —— NIST SP 800-57 安全强度 + 抗量子标识
// ============================================================
//
// 依据: NIST SP 800-57 Part 1 Rev.5
//
//   安全强度    经典算法等价             抗量子等级 (NIST PQC)
//   ─────────────────────────────────────────────────────────
//   112-bit     3DES / RSA-2048          —
//   128-bit     AES-128 / ECDSA-P256     NIST Level 1 (Kyber-512)
//   192-bit     AES-192 / ECDSA-P384     NIST Level 3 (Kyber-768)
//   256-bit     AES-256 / ECDSA-P521     NIST Level 5 (Kyber-1024)
//
// 经典级别 (无抗量子):
//   SCF_SECURITY_112BIT  : TLS 1.2+, AES-128-GCM, ECDHE-P256  (NIST 最低可接受)
//   SCF_SECURITY_128BIT  : TLS 1.3, AES-128-GCM, ECDHE-P256/X25519 (推荐)
//   SCF_SECURITY_192BIT  : TLS 1.3, AES-256-GCM, ECDHE-P384
//   SCF_SECURITY_256BIT  : TLS 1.3, AES-256-GCM, ECDHE-P521 (最高经典)
//
// 抗量子级别 (Hybrid ECDH + PQ KEM):
//   SCF_SECURITY_128BIT_PQ : 128-bit PQ (TLS 1.3, AES-128-GCM, Hybrid X25519+Kyber-512)
//   SCF_SECURITY_256BIT_PQ : 256-bit PQ (TLS 1.3, AES-256-GCM, Hybrid ECDH-P521+Kyber-1024)

/**
 * @brief NIST SP 800-57 安全强度级别
 *
 * 用户只需指定安全强度(bits)，框架自动选择对应的:
 *   - TLS协议版本 (TLS 1.2 / TLS 1.3)
 *   - 算法套 (AES-128-GCM / AES-256-GCM)
 *   - 密钥协商组 (P-256 / X25519 / Kyber-512 / Hybrid)
 *   - 证书校验严格程度
 *   - 完美前向保密 (PFS)
 *
 * @note 带 _PQ 后缀的级别需要加载抗量子 Provider (oqsprovider/liboqs)
 */
typedef enum SCFSecurityLevel {
    // === NIST SP 800-57 经典安全强度 ===
    SCF_SECURITY_112BIT = 0,       ///< 112-bit 安全强度 (TLS 1.2+, AES-128-GCM, NIST最低可接受)
    SCF_SECURITY_128BIT = 1,       ///< 128-bit 安全强度 (TLS 1.3, AES-128-GCM, NIST推荐) [默认]
    SCF_SECURITY_192BIT = 2,       ///< 192-bit 安全强度 (TLS 1.3, AES-256-GCM, ECDHE-P384)
    SCF_SECURITY_256BIT = 3,       ///< 256-bit 安全强度 (TLS 1.3, AES-256-GCM, ECDHE-P521)

    // === NIST PQC 抗量子安全强度 (Hybrid ECDH + PQ KEM) ===
    SCF_SECURITY_128BIT_PQ = 4,    ///< 128-bit 抗量子 (Hybrid X25519+Kyber-512, AES-128-GCM)
    SCF_SECURITY_256BIT_PQ = 5,    ///< 256-bit 抗量子 (Hybrid ECDH-P521+Kyber-1024, AES-256-GCM)
} SCF_SECURITY_LEVEL;

/**
 * @brief 证书校验策略
 *
 * 用户只需指定校验策略，框架自动处理证书链、CRL、OCSP 等校验。
 */
typedef enum SCFCertVerifyPolicy {
    SCF_CERT_VERIFY_NONE = 0,        ///< 不校验对端证书 (仅 PSK 模式)
    SCF_CERT_VERIFY_OPTIONAL = 1,    ///< 可选校验：有证书就验，无证书也允许
    SCF_CERT_VERIFY_REQUIRED = 2,    ///< 必须校验：对端必须提供有效证书
    SCF_CERT_VERIFY_STRICT = 3,      ///< 严格校验：证书+CRL+OCSP 全链路校验
} SCF_CERT_VERIFY_POLICY;

/**
 * @brief 连接状态
 */
typedef enum SCFConnectionState {
    SCF_CONN_INIT = 0,           ///< 初始状态
    SCF_CONN_CONNECTING = 1,     ///< 正在连接 (TLS握手进行中)
    SCF_CONN_CONNECTED = 2,      ///< 已连接 (安全通道就绪)
    SCF_CONN_CLOSING = 3,        ///< 正在关闭
    SCF_CONN_CLOSED = 4,         ///< 已关闭
    SCF_CONN_ERROR = 5,          ///< 错误状态
} SCF_CONNECTION_STATE;

/**
 * @brief 连接配置
 *
 * 用户创建连接时的简约配置。只需设置安全级别和证书路径即可使用。
 */
struct SCFConnectionConfig {
    static constexpr uint32_t kDefaultConnectTimeoutMs = 5000;
    static constexpr uint32_t kDefaultHandshakeTimeoutMs = 10000;

    // --- 必填：安全策略 ---
    SCF_SECURITY_LEVEL securityLevel;     ///< NIST安全强度级别 + 抗量子标识
    SCF_ROLE role;                        ///< 通信角色 (Client/Server)

    // --- 证书配置 ---
    std::string caCertPath;               ///< CA 证书路径 (校验对端时必填)
    std::string certPath;                 ///< 本端设备证书路径
    std::string keyPath;                  ///< 本端私钥路径
    std::string keyPassword;              ///< 私钥口令 (为空表示无口令)
    std::string crlPath;                  ///< CRL 吊销列表路径 (可选)
    SCF_CERT_VERIFY_POLICY certVerifyPolicy; ///< 证书校验策略

    // --- PSK 配置 (可选，与证书互斥) ---
    std::string pskIdentity;              ///< PSK 身份标识
    std::vector<uint8_t> pskKey;          ///< PSK 密钥
    bool usePSK;                          ///< 是否使用 PSK 模式

    // --- 传输配置 ---
    ITransportFactory *transportFactory;  ///< 传输工厂 (nullptr = 默认Socket)

    // --- 密码引擎配置 ---
    ICryptoEngineFactory *cryptoEngineFactory; ///< 密码引擎工厂 (nullptr = 默认软件)

    // --- 回调 ---
    SCF_AppVerifyFunc appVerifyCb;        ///< 自定义证书校验回调 (可选)
    void *appVerifyArg;                   ///< 回调用户数据

    // --- 高级选项 ---
    uint32_t connectTimeoutMs;            ///< 连接超时 (ms)，0 表示不超时
    uint32_t handshakeTimeoutMs;          ///< TLS握手超时 (ms)
    bool enableSessionResumption;         ///< 是否启用会话恢复
    bool enableKeyAutoUpdate;             ///< 是否启用自动密钥更新

    SCFConnectionConfig()
        : securityLevel(SCF_SECURITY_128BIT),  ///< 默认: NIST 128-bit 安全强度
          role(SCF_ROLE_CLIENT),
          certVerifyPolicy(SCF_CERT_VERIFY_REQUIRED),
          usePSK(false),
          transportFactory(nullptr),
          cryptoEngineFactory(nullptr),
          appVerifyCb(nullptr),
          appVerifyArg(nullptr),
          connectTimeoutMs(kDefaultConnectTimeoutMs),
          handshakeTimeoutMs(kDefaultHandshakeTimeoutMs),
          enableSessionResumption(true),
          enableKeyAutoUpdate(true)
    {}
};

// ============================================================
// SCF Connection —— 面向用户的高层抽象
// ============================================================

/**
 * @brief SCF 安全连接 —— 用户面向的核心抽象
 *
 * SCFConnection 封装了完整的 TLS 安全通信生命周期：
 *   1. 用户只需配置 SCFConnectionConfig (安全级别+证书策略)
 *   2. 调用 Connect() / Accept() 建立安全通道
 *   3. 调用 Read() / Write() 进行安全数据传输
 *   4. 调用 Close() 安全关闭
 *
 * 内部自动处理：
 *   - PolicyCtx / PolicyObj 的创建与管理
 *   - TLS 协议版本的自动选择 (依据 NIST SP 800-57 安全强度)
 *   - 算法套的自动协商
 *   - 密钥交换组的自动配置 (经典 ECDH / 抗量子 Hybrid KEM)
 *   - 传输IO的多路复用
 *   - 密码引擎的调度 (硬件加速自动启用)
 *   - 密钥自动更新
 *   - 证书链验证
 *
 * 使用示例 (客户端, NIST 128-bit 经典安全):
 * @code
 *   SCFConnectionConfig cfg;
 *   cfg.securityLevel = SCF_SECURITY_128BIT;   // NIST SP 800-57 128-bit
 *   cfg.role = SCF_ROLE_CLIENT;
 *   cfg.caCertPath = "/etc/certs/ca.pem";
 *   cfg.certVerifyPolicy = SCF_CERT_VERIFY_REQUIRED;
 *
 *   auto conn = SCFConnection::Create(cfg);
 *   conn->Connect("server.example.com", 443);
 *   conn->Write(data, len, &written);
 *   conn->Read(buf, size, &read);
 *   conn->Close();
 * @endcode
 *
 * 使用示例 (客户端, NIST 256-bit 抗量子安全):
 * @code
 *   SCFConnectionConfig cfg;
 *   cfg.securityLevel = SCF_SECURITY_256BIT_PQ; // 256-bit PQ-resistant
 *   cfg.role = SCF_ROLE_CLIENT;
 *   // 抗量子密钥交换: Hybrid ECDH-P521 + Kyber-1024
 *   auto conn = SCFConnection::Create(cfg);
 *   conn->Connect("secure.example.com", 443);
 * @endcode
 */
class SCFConnection {
public:
    /**
     * @brief 创建安全连接
     * @param config 连接配置
     * @return 连接实例指针，失败返回 nullptr
     */
    static SCFConnection *Create(const SCFConnectionConfig &config);

    /**
     * @brief 析构，自动释放资源
     */
    virtual ~SCFConnection() = default;

    // --- 连接生命周期 ---

    /**
     * @brief 主动发起安全连接 (客户端)
     * @param host 目标主机地址
     * @param port 目标端口
     * @return SCF_SUCCESS 或错误码
     * @note 非阻塞模式：返回后可能需要继续调用 HandshakeStep()
     */
    virtual int32_t Connect(const std::string &host, uint16_t port) = 0;

    /**
     * @brief 监听并等待安全连接 (服务端)
     * @param host 监听地址 (空表示 0.0.0.0)
     * @param port 监听端口
     * @return SCF_SUCCESS 或错误码
     */
    virtual int32_t Listen(const std::string &host, uint16_t port) = 0;

    /**
     * @brief 接受新的安全连接 (服务端)
     * @return 新的 SCFConnection 实例 (调用方负责释放)
     * @note 非阻塞模式：无可用连接时返回 nullptr
     */
    virtual SCFConnection *Accept() = 0;

    /**
     * @brief 执行 TLS 握手的一个步骤 (非阻塞模式)
     * @return SCF_SUCCESS = 握手完成
     *         SCF_SSL_ERR_WANT_READ  = 等待可读事件
     *         SCF_SSL_ERR_WANT_WRITE = 等待可写事件
     *         其他 = 握手失败
     */
    virtual int32_t HandshakeStep() = 0;

    /**
     * @brief 主动关闭安全连接
     * @return SCF_SUCCESS 或错误码
     */
    virtual int32_t Close() = 0;

    // --- 数据传输 ---

    /**
     * @brief 安全读取数据
     * @param data 接收缓冲区
     * @param len 缓冲区大小
     * @param readLen [OUT] 实际读取长度
     * @return SCF_SUCCESS 或错误码
     */
    virtual int32_t Read(uint8_t *data, uint32_t len, uint32_t *readLen) = 0;

    /**
     * @brief 安全写入数据
     * @param data 发送数据
     * @param len 数据长度
     * @param writeLen [OUT] 实际写入长度
     * @return SCF_SUCCESS 或错误码
     */
    virtual int32_t Write(const uint8_t *data, uint32_t len, uint32_t *writeLen) = 0;

    // --- 状态查询 ---

    /**
     * @brief 获取连接状态
     */
    virtual SCF_CONNECTION_STATE GetState() const = 0;

    /**
     * @brief 连接是否已建立
     */
    virtual bool IsConnected() const = 0;

    /**
     * @brief 获取本次协商的 TLS 协议版本字符串
     */
    virtual const char *GetTLSVersion() const = 0;

    /**
     * @brief 获取本次协商使用的算法套
     */
    virtual uint16_t GetCipherSuite() const = 0;

    /**
     * @brief 获取对端证书 (需在连接建立后调用)
     * @return 对端证书指针 (OpenSSL X509*)，使用后调用 FreePeerCert
     */
    virtual void *GetPeerCertificate() = 0;

    /**
     * @brief 释放对端证书资源
     */
    virtual void FreePeerCertificate(void *cert) = 0;

    /**
     * @brief 获取底层传输对象
     */
    virtual ITransport *GetTransport() const = 0;

    /**
     * @brief 获取底层原生 fd (用于事件循环集成)
     * @return 平台相关的原生句柄
     */
    virtual int32_t GetNativeHandle() const = 0;

    // --- 高级操作 ---

    /**
     * @brief 主动触发密钥更新 (TLS 1.3 KeyUpdate)
     * @return SCF_SUCCESS 或错误码
     */
    virtual int32_t TriggerKeyUpdate() = 0;

    /**
     * @brief 设置用户自定义数据
     */
    virtual void SetUserData(void *userData) = 0;

    /**
     * @brief 获取用户自定义数据
     */
    virtual void *GetUserData() const = 0;

protected:
    SCFConnection() = default;
};

// ============================================================
// 便捷工厂函数
// ============================================================

/**
 * @brief 快速创建客户端安全连接
 * @param securityLevel 安全级别
 * @param caCertPath CA证书路径 (空字符串表示不校验)
 * @return 连接实例，失败返回 nullptr
 */
SCFConnection *SCF_NewClientConnection(
    SCF_SECURITY_LEVEL securityLevel,
    const std::string &caCertPath = "");

/**
 * @brief 快速创建服务端安全连接
 * @param securityLevel 安全级别
 * @param certPath 服务端证书路径
 * @param keyPath 服务端私钥路径
 * @return 连接实例，失败返回 nullptr
 */
SCFConnection *SCF_NewServerConnection(
    SCF_SECURITY_LEVEL securityLevel,
    const std::string &certPath,
    const std::string &keyPath);

/**
 * @brief 快速创建 PSK 安全连接
 * @param securityLevel 安全级别
 * @param role 通信角色
 * @param pskIdentity PSK 身份标识
 * @param pskKey PSK 密钥
 * @param pskKeyLen PSK 密钥长度
 * @return 连接实例，失败返回 nullptr
 */
SCFConnection *SCF_NewPSKConnection(
    SCF_SECURITY_LEVEL securityLevel,
    SCF_ROLE role,
    const std::string &pskIdentity,
    const uint8_t *pskKey, size_t pskKeyLen);

// ============================================================
// 传输IO与密码引擎的注册 API
// ============================================================

/**
 * @brief 注册自定义传输工厂
 * @param factory 传输工厂实例 (所有权转移给 SCF)
 * @return 注册是否成功
 */
bool SCF_RegisterTransportFactory(ITransportFactory *factory);

/**
 * @brief 注销传输工厂
 * @param protocol 协议类型
 */
void SCF_UnregisterTransportFactory(TransportProtocol protocol);

/**
 * @brief 注册自定义密码引擎工厂
 * @param factory 引擎工厂实例 (所有权转移给 SCF)
 * @return 注册是否成功
 */
bool SCF_RegisterCryptoEngineFactory(ICryptoEngineFactory *factory);

/**
 * @brief 注销密码引擎工厂
 * @param name 引擎名称
 */
void SCF_UnregisterCryptoEngineFactory(const std::string &name);

}  // namespace scf

#ifdef __cplusplus
}
#endif

#endif  // SCF_CONNECTION_H
