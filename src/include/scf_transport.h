/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 */

#ifndef SCF_TRANSPORT_H
#define SCF_TRANSPORT_H

#include <cstdint>
#include <cstddef>
#include <string>

namespace scf {

// ============================================================
// 传输IO抽象接口
// 支持 Socket、URMA 等不同传输IO实现的可替换机制
// ============================================================

/**
 * @brief 传输IO操作结果码
 */
enum class TransportResult : int32_t {
    SUCCESS = 0,
    ERROR = -1,
    WOULD_BLOCK = -2,      // 非阻塞操作，需要重试
    CONNECTION_CLOSED = -3, // 连接已关闭
    TIMEOUT = -4,           // 操作超时
};

/**
 * @brief 传输地址类型
 */
enum class TransportAddressType : int32_t {
    IPv4 = 0,
    IPv6 = 1,
    DOMAIN = 2,    // 域名
    URMA = 3,      // URMA 地址
    CUSTOM = 99,   // 自定义地址格式
};

/**
 * @brief 传输协议类型
 */
enum class TransportProtocol : int32_t {
    TCP = 0,
    UDP = 1,
    URMA = 2,
    CUSTOM = 99,
};

/**
 * @brief 传输端点地址
 */
struct TransportAddress {
    TransportAddressType type;
    std::string host;
    uint16_t port;

    TransportAddress() : type(TransportAddressType::IPv4), port(0) {}

    static TransportAddress IPv4(const std::string &host, uint16_t port)
    {
        TransportAddress addr;
        addr.type = TransportAddressType::IPv4;
        addr.host = host;
        addr.port = port;
        return addr;
    }

    static TransportAddress URMAAddr(const std::string &addr, uint16_t port = 0)
    {
        TransportAddress a;
        a.type = TransportAddressType::URMA;
        a.host = addr;
        a.port = port;
        return a;
    }
};

/**
 * @brief 传输配置选项
 */
struct TransportConfig {
    static constexpr int32_t kDefaultConnectTimeoutMs = 5000;

    bool nonBlocking;       // 是否非阻塞模式
    int32_t sendTimeoutMs;  // 发送超时 (0 表示不设置)
    int32_t recvTimeoutMs;  // 接收超时 (0 表示不设置)
    int32_t connectTimeoutMs; // 连接超时
    size_t sendBufferSize;  // 发送缓冲区大小 (0 表示使用默认)
    size_t recvBufferSize;  // 接收缓冲区大小 (0 表示使用默认)
    bool tcpNoDelay;        // TCP_NODELAY

    TransportConfig()
        : nonBlocking(true),
          sendTimeoutMs(0),
          recvTimeoutMs(0),
          connectTimeoutMs(kDefaultConnectTimeoutMs),
          sendBufferSize(0),
          recvBufferSize(0),
        tcpNoDelay(true)
    {}
};

// ============================================================
// 抽象传输接口
// ============================================================

/**
 * @brief 抽象传输连接接口
 *
 * 所有传输IO实现（Socket、URMA等）都需实现此接口。
 * 设计为纯虚接口，方便用户替换不同的传输后端。
 */
class ITransport {
public:
    virtual ~ITransport() = default;

    /**
     * @brief 获取传输协议类型
     */
    virtual TransportProtocol GetProtocol() const = 0;

    /**
     * @brief 客户端发起连接
     * @param addr 目标地址
     * @param config 传输配置
     * @return SUCCESS 或错误码
     */
    virtual TransportResult Connect(const TransportAddress &addr,
                                     const TransportConfig &config) = 0;

    /**
     * @brief 服务端绑定并监听
     * @param addr 监听地址
     * @param backlog 等待队列长度
     * @return SUCCESS 或错误码
     */
    virtual TransportResult Bind(const TransportAddress &addr, int32_t backlog = 128) = 0;

    /**
     * @brief 服务端接受新连接
     * @return 新的传输连接对象 (调用方负责释放)
     */
    virtual ITransport *Accept() = 0;

    /**
     * @brief 发送数据
     * @param data 数据缓冲区
     * @param len 数据长度
     * @param sentLen [OUT] 实际发送长度
     * @return SUCCESS 或错误码
     */
    virtual TransportResult Send(const uint8_t *data, size_t len, size_t *sentLen) = 0;

    /**
     * @brief 接收数据
     * @param data 接收缓冲区
     * @param len 缓冲区长度
     * @param recvLen [OUT] 实际接收长度
     * @return SUCCESS 或错误码
     */
    virtual TransportResult Recv(uint8_t *data, size_t len, size_t *recvLen) = 0;

    /**
     * @brief 关闭传输连接
     */
    virtual void Close() = 0;

    /**
     * @brief 获取底层原生句柄 (用于 poll/select 等)
     * @return 平台相关的原生句柄，不支持返回 -1
     */
    virtual int32_t GetNativeHandle() const = 0;

    /**
     * @brief 连接是否有效
     */
    virtual bool IsConnected() const = 0;

    /**
     * @brief 获取本地地址
     */
    virtual TransportAddress GetLocalAddress() const = 0;

    /**
     * @brief 获取对端地址
     */
    virtual TransportAddress GetRemoteAddress() const = 0;

    /**
     * @brief 设置传输配置
     */
    virtual TransportResult SetConfig(const TransportConfig &config) = 0;

    /**
     * @brief 克隆此传输对象 (用于 Accept 场景)
     */
    virtual ITransport *Clone() const = 0;
};

// ============================================================
// 传输IO工厂
// ============================================================

/**
 * @brief 传输IO工厂接口
 *
 * 用于创建不同类型的传输对象。用户可以实现此接口来注册自定义传输。
 */
class ITransportFactory {
public:
    virtual ~ITransportFactory() = default;

    /**
     * @brief 创建新的传输对象
     * @return 传输对象实例
     */
    virtual ITransport *Create() = 0;

    /**
     * @brief 获取此工厂支持的协议类型
     */
    virtual TransportProtocol GetProtocol() const = 0;

    /**
     * @brief 获取此工厂的名称标识
     */
    virtual const char *GetName() const = 0;
};

}  // namespace scf

#endif  // SCF_TRANSPORT_H
