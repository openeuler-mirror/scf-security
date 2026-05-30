/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 */

#include "socket_transport.h"

#include <cstring>
#include <cerrno>

#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "custom_logger.h"

namespace scf {

// ============================================================
// SocketTransport
// ============================================================

SocketTransport::SocketTransport()
    : m_fd(-1),
      m_connected(false),
      m_bound(false),
    m_protocol(TransportProtocol::TCP)
{
}

SocketTransport::SocketTransport(int32_t fd)
    : m_fd(fd),
      m_connected(fd >= 0),
      m_bound(false),
    m_protocol(TransportProtocol::TCP)
{
}

SocketTransport::~SocketTransport()
{
    Close();
}

TransportProtocol SocketTransport::GetProtocol() const
{
    return m_protocol;
}

TransportResult SocketTransport::Connect(const TransportAddress &addr,
    const TransportConfig &config)
{
    m_config = config;

    // 解析地址
    struct sockaddr_storage sockAddr {};
    socklen_t addrLen = 0;
    TransportResult ret = ResolveAddress(addr, sockAddr, addrLen);
    if (ret != TransportResult::SUCCESS) {
        return ret;
    }

    // 创建 socket
    int family = (addr.type == TransportAddressType::IPv6)
                     ? AF_INET6 : AF_INET;
    m_fd = ::socket(family, SOCK_STREAM, 0);
    if (m_fd < 0) {
        CCSEC_LOG_ERROR("socket create failed, errno:" << errno);
        return TransportResult::ERROR;
    }

    // 设置 socket 选项
    ret = SetSocketOptions(m_fd, config);
    if (ret != TransportResult::SUCCESS) {
        Close();
        return ret;
    }

    // 设置非阻塞
    ret = SetNonBlocking(m_fd);
    if (ret != TransportResult::SUCCESS) {
        Close();
        return ret;
    }

    // 发起连接
    int rc = ::connect(m_fd, static_cast<struct sockaddr *>(static_cast<void *>(&sockAddr)), addrLen);
    if (rc < 0 && errno != EINPROGRESS) {
        CCSEC_LOG_ERROR("connect failed, errno:" << errno << " target:" << addr.host << ":" << addr.port);
        Close();
        return MapSocketError();
    }

    // EINPROGRESS 在非阻塞模式下是正常的，表示连接正在进行中
    if (rc < 0 && errno == EINPROGRESS) {
        CCSEC_LOG_DEBUG("connect in progress for " << addr.host << ":" << addr.port);
    }

    m_connected = true;
    m_remoteAddr = addr;
    return TransportResult::SUCCESS;
}

TransportResult SocketTransport::Bind(const TransportAddress &addr, int32_t backlog)
{
    struct sockaddr_storage sockAddr {};
    socklen_t addrLen = 0;
    TransportResult ret = ResolveAddress(addr, sockAddr, addrLen);
    if (ret != TransportResult::SUCCESS) {
        return ret;
    }

    int family = (addr.type == TransportAddressType::IPv6)
                     ? AF_INET6 : AF_INET;
    m_fd = ::socket(family, SOCK_STREAM, 0);
    if (m_fd < 0) {
        CCSEC_LOG_ERROR("socket create failed, errno:" << errno);
        return TransportResult::ERROR;
    }

    // 设置 SO_REUSEADDR
    int opt = 1;
    ::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (::bind(m_fd, static_cast<struct sockaddr *>(static_cast<void *>(&sockAddr)), addrLen) < 0) {
        CCSEC_LOG_ERROR("bind failed, errno:" << errno);
        Close();
        return TransportResult::ERROR;
    }

    if (::listen(m_fd, backlog) < 0) {
        CCSEC_LOG_ERROR("listen failed, errno:" << errno);
        Close();
        return TransportResult::ERROR;
    }

    ret = SetNonBlocking(m_fd);
    if (ret != TransportResult::SUCCESS) {
        Close();
        return ret;
    }

    m_bound = true;
    m_localAddr = addr;
    return TransportResult::SUCCESS;
}

ITransport *SocketTransport::Accept()
{
    if (!m_bound || m_fd < 0) {
        CCSEC_LOG_ERROR("accept called on unbound socket");
        return nullptr;
    }

    struct sockaddr_storage clientAddr {};
    socklen_t clientLen = sizeof(clientAddr);
    int clientFd = ::accept(m_fd, static_cast<struct sockaddr *>(static_cast<void *>(&clientAddr)), &clientLen);
    if (clientFd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return nullptr;  // 非阻塞模式无连接可接受
        }
        CCSEC_LOG_ERROR("accept failed, errno:" << errno);
        return nullptr;
    }

    // 设置新连接的选项
    SetNonBlocking(clientFd);

    auto *transport = new SocketTransport(clientFd);
    transport->m_config = m_config;

    // 提取对端地址信息
    if (clientAddr.ss_family == AF_INET) {
        auto *sin = static_cast<struct sockaddr_in *>(static_cast<void *>(&clientAddr));
        char ip[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        transport->m_remoteAddr = TransportAddress::IPv4(ip, ntohs(sin->sin_port));
        transport->m_remoteAddr.type = TransportAddressType::IPv4;
    } else if (clientAddr.ss_family == AF_INET6) {
        auto *sin6 = static_cast<struct sockaddr_in6 *>(static_cast<void *>(&clientAddr));
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        transport->m_remoteAddr = TransportAddress::IPv4(ip, ntohs(sin6->sin6_port));
        transport->m_remoteAddr.type = TransportAddressType::IPv6;
    }

    return transport;
}

TransportResult SocketTransport::Send(const uint8_t *data, size_t len, size_t *sentLen)
{
    if (m_fd < 0 || !m_connected) {
        return TransportResult::ERROR;
    }

    ssize_t n = ::send(m_fd, data, len, MSG_NOSIGNAL);
    if (n > 0) {
        *sentLen = static_cast<size_t>(n);
        return TransportResult::SUCCESS;
    }
    if (n == 0) {
        *sentLen = 0;
        return TransportResult::CONNECTION_CLOSED;
    }
    // n < 0
    *sentLen = 0;
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return TransportResult::WOULD_BLOCK;
    }
    CCSEC_LOG_ERROR("send failed, errno:" << errno);
    return TransportResult::ERROR;
}

TransportResult SocketTransport::Recv(uint8_t *data, size_t len, size_t *recvLen)
{
    if (m_fd < 0 || !m_connected) {
        return TransportResult::ERROR;
    }

    ssize_t n = ::recv(m_fd, data, len, 0);
    if (n > 0) {
        *recvLen = static_cast<size_t>(n);
        return TransportResult::SUCCESS;
    }
    if (n == 0) {
        *recvLen = 0;
        return TransportResult::CONNECTION_CLOSED;
    }
    // n < 0
    *recvLen = 0;
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return TransportResult::WOULD_BLOCK;
    }
    CCSEC_LOG_ERROR("recv failed, errno:" << errno);
    return TransportResult::ERROR;
}

void SocketTransport::Close()
{
    if (m_fd >= 0) {
        ::close(m_fd);
        m_fd = -1;
    }
    m_connected = false;
    m_bound = false;
}

int32_t SocketTransport::GetNativeHandle() const
{
    return m_fd;
}

bool SocketTransport::IsConnected() const
{
    return m_connected && m_fd >= 0;
}

TransportAddress SocketTransport::GetLocalAddress() const
{
    return m_localAddr;
}

TransportAddress SocketTransport::GetRemoteAddress() const
{
    return m_remoteAddr;
}

TransportResult SocketTransport::SetConfig(const TransportConfig &config)
{
    m_config = config;
    if (m_fd >= 0) {
        return SetSocketOptions(m_fd, config);
    }
    return TransportResult::SUCCESS;
}

ITransport *SocketTransport::Clone() const
{
    auto *copy = new SocketTransport();
    copy->m_fd = m_fd;  // 注意: 不复制 fd，调用方自行管理生命周期
    copy->m_connected = m_connected;
    copy->m_bound = m_bound;
    copy->m_localAddr = m_localAddr;
    copy->m_remoteAddr = m_remoteAddr;
    copy->m_config = m_config;
    copy->m_protocol = m_protocol;
    return copy;
}

// ============================================================
// 内部辅助方法
// ============================================================

TransportResult SocketTransport::SetNonBlocking(int32_t fd)
{
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        CCSEC_LOG_ERROR("fcntl F_GETFL failed, errno:" << errno);
        return TransportResult::ERROR;
    }
    if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        CCSEC_LOG_ERROR("fcntl F_SETFL O_NONBLOCK failed, errno:" << errno);
        return TransportResult::ERROR;
    }
    return TransportResult::SUCCESS;
}

TransportResult SocketTransport::SetSocketOptions(int32_t fd, const TransportConfig &config)
{
    // TCP_NODELAY
    if (config.tcpNoDelay) {
        int flag = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    }

    // 发送超时
    if (config.sendTimeoutMs > 0) {
        static constexpr int32_t kMilliPerSec = 1000;
        struct timeval tv {};
        tv.tv_sec = config.sendTimeoutMs / kMilliPerSec;
        tv.tv_usec = (config.sendTimeoutMs % kMilliPerSec) * kMilliPerSec;
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    // 接收超时
    if (config.recvTimeoutMs > 0) {
        static constexpr int32_t kMilliPerSec = 1000;
        struct timeval tv {};
        tv.tv_sec = config.recvTimeoutMs / kMilliPerSec;
        tv.tv_usec = (config.recvTimeoutMs % kMilliPerSec) * kMilliPerSec;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    // 缓冲区大小
    if (config.sendBufferSize > 0) {
        int sz = static_cast<int>(config.sendBufferSize);
        ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    }
    if (config.recvBufferSize > 0) {
        int sz = static_cast<int>(config.recvBufferSize);
        ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    }

    return TransportResult::SUCCESS;
}

TransportResult SocketTransport::ResolveAddress(const TransportAddress &addr,
    struct sockaddr_storage &sockAddr,
    socklen_t &addrLen)
{
    std::memset(&sockAddr, 0, sizeof(sockAddr));

    if (addr.type == TransportAddressType::URMA ||
        addr.type == TransportAddressType::CUSTOM) {
        // 非标准地址类型，留给子类处理
        return TransportResult::ERROR;
    }

    if (addr.type == TransportAddressType::IPv4 || addr.type == TransportAddressType::DOMAIN) {
        auto *sin = static_cast<struct sockaddr_in *>(static_cast<void *>(&sockAddr));
        sin->sin_family = AF_INET;
        sin->sin_port = htons(addr.port);

        // 尝试解析为 IP 地址
        int rc = inet_pton(AF_INET, addr.host.c_str(), &sin->sin_addr);
        if (rc != 1) {
            // DNS 解析
            struct addrinfo hints {};
            struct addrinfo *result = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            std::string portStr = std::to_string(addr.port);
            int gai = getaddrinfo(addr.host.c_str(), portStr.c_str(), &hints, &result);
            if (gai != 0 || result == nullptr) {
                CCSEC_LOG_ERROR("getaddrinfo failed: " << gai << " for " << addr.host);
                return TransportResult::ERROR;
            }
            std::memcpy(sin, result->ai_addr, result->ai_addrlen);
            freeaddrinfo(result);
        }

        addrLen = sizeof(struct sockaddr_in);
        return TransportResult::SUCCESS;
    }

    if (addr.type == TransportAddressType::IPv6) {
        auto *sin6 = static_cast<struct sockaddr_in6 *>(static_cast<void *>(&sockAddr));
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(addr.port);

        int rc = inet_pton(AF_INET6, addr.host.c_str(), &sin6->sin6_addr);
        if (rc != 1) {
            CCSEC_LOG_ERROR("inet_pton ipv6 failed for " << addr.host);
            return TransportResult::ERROR;
        }
        addrLen = sizeof(struct sockaddr_in6);
        return TransportResult::SUCCESS;
    }

    return TransportResult::ERROR;
}

TransportResult SocketTransport::MapSocketError() const
{
    switch (errno) {
#if EAGAIN != EWOULDBLOCK
        case EAGAIN:
#endif
        case EWOULDBLOCK:
            return TransportResult::WOULD_BLOCK;
        case ECONNRESET:
        case EPIPE:
            return TransportResult::CONNECTION_CLOSED;
        case ETIMEDOUT:
            return TransportResult::TIMEOUT;
        default:
            return TransportResult::ERROR;
    }
}

// ============================================================
// SocketTransportFactory
// ============================================================

ITransport *SocketTransportFactory::Create()
{
    return new SocketTransport();
}

TransportProtocol SocketTransportFactory::GetProtocol() const
{
    return TransportProtocol::TCP;
}

const char *SocketTransportFactory::GetName() const
{
    return "socket";
}

}  // namespace scf
