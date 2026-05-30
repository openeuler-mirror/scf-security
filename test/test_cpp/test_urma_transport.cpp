/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
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

#include <gtest/gtest.h>
#include <cstring>

#include "urma_transport.h"
#include "scf_transport.h"
#include "custom_logger.h"
#include "test_scf.h"

namespace test {

constexpr int PROTOCOL_URMA = 2;
constexpr size_t BUFFER_LEN_10 = 10;
constexpr uint16_t PORT_8080 = 8080;
constexpr uint32_t TIMEOUT_1000_MS = 1000;

class TestUrmaTransport : public ::testing::Test {
protected:
    void SetUp() override
    {
        SetExternalLogFunction(ExternalLogFunction);
        transport = new scf::UrmaTransport();
    }

    void TearDown() override
    {
        if (transport != nullptr) {
            transport->Close();
            delete transport;
            transport = nullptr;
        }
        SetExternalLogFunction(nullptr);
    }

    scf::UrmaTransport *transport = nullptr;
};

TEST_F(TestUrmaTransport, Constructor_Default)
{
    EXPECT_TRUE(transport != nullptr);
    EXPECT_FALSE(transport->IsConnected());
    EXPECT_EQ(transport->GetProtocol(), scf::TransportProtocol::URMA);
}

TEST_F(TestUrmaTransport, GetProtocol_URMA)
{
    EXPECT_EQ(transport->GetProtocol(), scf::TransportProtocol::URMA);
}

TEST_F(TestUrmaTransport, GetNativeHandle_Invalid)
{
    EXPECT_EQ(transport->GetNativeHandle(), -1);
}

TEST_F(TestUrmaTransport, IsConnected_NotConnected)
{
    EXPECT_FALSE(transport->IsConnected());
}

TEST_F(TestUrmaTransport, GetLocalAddress_NotBound)
{
    scf::TransportAddress addr = transport->GetLocalAddress();
    EXPECT_EQ(addr.type, scf::TransportAddressType::IPv4);
}

TEST_F(TestUrmaTransport, GetRemoteAddress_NotConnected)
{
    scf::TransportAddress addr = transport->GetRemoteAddress();
    EXPECT_EQ(addr.type, scf::TransportAddressType::IPv4);
}

TEST_F(TestUrmaTransport, Close_NotConnected)
{
    transport->Close();
    EXPECT_FALSE(transport->IsConnected());
}

TEST_F(TestUrmaTransport, Connect_StubReturnsError)
{
    scf::TransportAddress addr;
    addr.type = scf::TransportAddressType::IPv4;
    addr.host = "127.0.0.1";
    addr.port = PORT_8080;

    scf::TransportConfig config;
    config.connectTimeoutMs = TIMEOUT_1000_MS;

    scf::TransportResult result = transport->Connect(addr, config);
    EXPECT_EQ(result, scf::TransportResult::ERROR);
    EXPECT_FALSE(transport->IsConnected());
}

TEST_F(TestUrmaTransport, Bind_StubReturnsError)
{
    scf::TransportAddress addr;
    addr.type = scf::TransportAddressType::IPv4;
    addr.host = "127.0.0.1";
    addr.port = PORT_8080;

    scf::TransportResult result = transport->Bind(addr, 5);
    EXPECT_EQ(result, scf::TransportResult::ERROR);
}

TEST_F(TestUrmaTransport, Accept_StubReturnsNull)
{
    scf::ITransport *accepted = transport->Accept();
    EXPECT_TRUE(accepted == nullptr);
}

TEST_F(TestUrmaTransport, Send_StubReturnsError)
{
    uint8_t data[BUFFER_LEN_10] = {0};
    size_t sentLen = 0;

    scf::TransportResult result = transport->Send(data, BUFFER_LEN_10, &sentLen);
    EXPECT_EQ(result, scf::TransportResult::ERROR);
    EXPECT_EQ(sentLen, 0);
}

TEST_F(TestUrmaTransport, Send_NullData)
{
    size_t sentLen = 0;
    scf::TransportResult result = transport->Send(nullptr, BUFFER_LEN_10, &sentLen);
    EXPECT_EQ(result, scf::TransportResult::ERROR);
    EXPECT_EQ(sentLen, 0);
}

TEST_F(TestUrmaTransport, Recv_StubReturnsError)
{
    uint8_t buffer[BUFFER_LEN_10] = {0};
    size_t recvLen = 0;

    scf::TransportResult result = transport->Recv(buffer, BUFFER_LEN_10, &recvLen);
    EXPECT_EQ(result, scf::TransportResult::ERROR);
    EXPECT_EQ(recvLen, 0);
}

TEST_F(TestUrmaTransport, Recv_NullBuffer)
{
    size_t recvLen = 0;
    scf::TransportResult result = transport->Recv(nullptr, BUFFER_LEN_10, &recvLen);
    EXPECT_EQ(result, scf::TransportResult::ERROR);
    EXPECT_EQ(recvLen, 0);
}

TEST_F(TestUrmaTransport, SetConfig_Valid)
{
    scf::TransportConfig config;
    config.nonBlocking = true;
    config.connectTimeoutMs = TIMEOUT_1000_MS;

    scf::TransportResult result = transport->SetConfig(config);
    EXPECT_EQ(result, scf::TransportResult::SUCCESS);
}

TEST_F(TestUrmaTransport, Clone_NotConnected)
{
    scf::ITransport *cloned = transport->Clone();
    EXPECT_TRUE(cloned != nullptr);
    EXPECT_EQ(cloned->GetProtocol(), scf::TransportProtocol::URMA);
    EXPECT_FALSE(cloned->IsConnected());

    cloned->Close();
    delete cloned;
}

TEST_F(TestUrmaTransport, Clone_WithConfig)
{
    scf::TransportConfig config;
    config.nonBlocking = true;
    transport->SetConfig(config);

    scf::ITransport *cloned = transport->Clone();
    EXPECT_TRUE(cloned != nullptr);

    cloned->Close();
    delete cloned;
}

TEST_F(TestUrmaTransport, TransportProtocol_Value)
{
    EXPECT_EQ(static_cast<int>(scf::TransportProtocol::URMA), PROTOCOL_URMA);
}

TEST_F(TestUrmaTransport, Factory_Create)
{
    scf::UrmaTransportFactory factory;
    scf::ITransport *trans = factory.Create();

    EXPECT_TRUE(trans != nullptr);
    EXPECT_EQ(trans->GetProtocol(), scf::TransportProtocol::URMA);

    trans->Close();
    delete trans;
}

TEST_F(TestUrmaTransport, Factory_GetProtocol)
{
    scf::UrmaTransportFactory factory;
    EXPECT_EQ(factory.GetProtocol(), scf::TransportProtocol::URMA);
}

TEST_F(TestUrmaTransport, Factory_GetName)
{
    scf::UrmaTransportFactory factory;
    const char *name = factory.GetName();
    EXPECT_TRUE(name != nullptr);
    EXPECT_STREQ(name, "urma");
}

TEST_F(TestUrmaTransport, MultipleCloseCalls)
{
    transport->Close();
    transport->Close();
    transport->Close();
    EXPECT_FALSE(transport->IsConnected());
}

TEST_F(TestUrmaTransport, Connect_IPV6)
{
    scf::TransportAddress addr;
    addr.type = scf::TransportAddressType::IPv6;
    addr.host = "::1";
    addr.port = PORT_8080;

    scf::TransportConfig config;
    scf::TransportResult result = transport->Connect(addr, config);
    EXPECT_EQ(result, scf::TransportResult::ERROR);
}

TEST_F(TestUrmaTransport, Bind_IPV6)
{
    scf::TransportAddress addr;
    addr.type = scf::TransportAddressType::IPv6;
    addr.host = "::1";
    addr.port = PORT_8080;

    scf::TransportResult result = transport->Bind(addr, 5);
    EXPECT_EQ(result, scf::TransportResult::ERROR);
}

}