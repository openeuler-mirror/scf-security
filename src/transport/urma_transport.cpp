/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 *
 * URMA 传输桩实现。
 * 当前为占位实现，集成真实 URMA 库时需要替换以下方法：
 *   - Connect:   调用 urma_connect()
 *   - Bind:      调用 urma_bind() + urma_listen()
 *   - Accept:    调用 urma_accept()
 *   - Send/Recv: 调用 urma_send() / urma_recv()
 *   - Close:     调用 urma_close()
 */

#include "urma_transport.h"
#include "custom_logger.h"

namespace scf {

UrmaTransport::UrmaTransport()
    : m_connected(false)
{
}

UrmaTransport::~UrmaTransport()
{
    Close();
}

TransportProtocol UrmaTransport::GetProtocol() const
{
    return TransportProtocol::URMA;
}

TransportResult UrmaTransport::Connect(const TransportAddress &addr,
    const TransportConfig &config)
{
    m_config = config;
    (void)addr;
    CCSEC_LOG_WARN("URMA transport not yet implemented (stub)");
    m_connected = false;
    return TransportResult::ERROR;
}

TransportResult UrmaTransport::Bind(const TransportAddress &addr, int32_t backlog)
{
    (void)addr;
    (void)backlog;
    CCSEC_LOG_WARN("URMA transport Bind not yet implemented (stub)");
    return TransportResult::ERROR;
}

ITransport *UrmaTransport::Accept()
{
    CCSEC_LOG_WARN("URMA transport Accept not yet implemented (stub)");
    return nullptr;
}

TransportResult UrmaTransport::Send(const uint8_t *data, size_t len, size_t *sentLen)
{
    (void)data;
    (void)len;
    *sentLen = 0;
    CCSEC_LOG_WARN("URMA transport Send not yet implemented (stub)");
    return TransportResult::ERROR;
}

TransportResult UrmaTransport::Recv(uint8_t *data, size_t len, size_t *recvLen)
{
    (void)data;
    (void)len;
    *recvLen = 0;
    CCSEC_LOG_WARN("URMA transport Recv not yet implemented (stub)");
    return TransportResult::ERROR;
}

void UrmaTransport::Close()
{
    m_connected = false;
}

int32_t UrmaTransport::GetNativeHandle() const
{
    return -1;  // URMA 无 POSIX fd
}

bool UrmaTransport::IsConnected() const
{
    return m_connected;
}

TransportAddress UrmaTransport::GetLocalAddress() const
{
    return m_localAddr;
}

TransportAddress UrmaTransport::GetRemoteAddress() const
{
    return m_remoteAddr;
}

TransportResult UrmaTransport::SetConfig(const TransportConfig &config)
{
    m_config = config;
    return TransportResult::SUCCESS;
}

ITransport *UrmaTransport::Clone() const
{
    auto *copy = new UrmaTransport();
    copy->m_connected = m_connected;
    copy->m_localAddr = m_localAddr;
    copy->m_remoteAddr = m_remoteAddr;
    copy->m_config = m_config;
    return copy;
}

// ============================================================
// UrmaTransportFactory
// ============================================================

ITransport *UrmaTransportFactory::Create()
{
    return new UrmaTransport();
}

TransportProtocol UrmaTransportFactory::GetProtocol() const
{
    return TransportProtocol::URMA;
}

const char *UrmaTransportFactory::GetName() const
{
    return "urma";
}

}  // namespace scf
