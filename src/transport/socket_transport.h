/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 */

#ifndef SCF_TRANSPORT_SOCKET_H
#define SCF_TRANSPORT_SOCKET_H

#include <sys/socket.h>
#include "scf_transport.h"

namespace scf {

/**
 * @brief 基于 POSIX Socket 的传输实现
 *
 * 支持 IPv4/IPv6 TCP 协议。
 * 可直接集成到现有 poll/select/epoll 事件循环中。
 */
class SocketTransport : public ITransport {
public:
    SocketTransport();
    explicit SocketTransport(int32_t fd);
    ~SocketTransport() override;

    // --- ITransport 接口实现 ---
    TransportProtocol GetProtocol() const override;
    TransportResult Connect(const TransportAddress &addr,
                            const TransportConfig &config) override;
    TransportResult Bind(const TransportAddress &addr, int32_t backlog = 128) override;
    ITransport *Accept() override;
    TransportResult Send(const uint8_t *data, size_t len, size_t *sentLen) override;
    TransportResult Recv(uint8_t *data, size_t len, size_t *recvLen) override;
    void Close() override;
    int32_t GetNativeHandle() const override;
    bool IsConnected() const override;
    TransportAddress GetLocalAddress() const override;
    TransportAddress GetRemoteAddress() const override;
    TransportResult SetConfig(const TransportConfig &config) override;
    ITransport *Clone() const override;

private:
    TransportResult MapSocketError() const;
    TransportResult SetNonBlocking(int32_t fd);
    TransportResult SetSocketOptions(int32_t fd, const TransportConfig &config);
    TransportResult ResolveAddress(const TransportAddress &addr,
                                    struct sockaddr_storage &sockAddr, socklen_t &addrLen);

    int32_t m_fd;
    bool m_connected;
    bool m_bound;
    TransportAddress m_localAddr;
    TransportAddress m_remoteAddr;
    TransportConfig m_config;
    TransportProtocol m_protocol;
};

/**
 * @brief Socket 传输工厂
 */
class SocketTransportFactory : public ITransportFactory {
public:
    ITransport *Create() override;
    TransportProtocol GetProtocol() const override;
    const char *GetName() const override;
};

}  // namespace scf

#endif  // SCF_TRANSPORT_SOCKET_H
