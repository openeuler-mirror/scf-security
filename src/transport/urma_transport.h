/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 */

#ifndef SCF_TRANSPORT_URMA_H
#define SCF_TRANSPORT_URMA_H

#include "scf_transport.h"

namespace scf {

/**
 * @brief 基于 URMA (Unified Remote Memory Access) 的传输桩实现
 *
 * URMA 是一种高性能 RDMA 类传输协议，适用于数据中心内部低延迟通信。
 * 当前为桩实现，集成时替换为真实 URMA 库调用。
 */
class UrmaTransport : public ITransport {
public:
    UrmaTransport();
    ~UrmaTransport() override;

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
    bool m_connected;
    TransportAddress m_localAddr;
    TransportAddress m_remoteAddr;
    TransportConfig m_config;
};

/**
 * @brief URMA 传输工厂
 */
class UrmaTransportFactory : public ITransportFactory {
public:
    ITransport *Create() override;
    TransportProtocol GetProtocol() const override;
    const char *GetName() const override;
};

}  // namespace scf

#endif  // SCF_TRANSPORT_URMA_H
