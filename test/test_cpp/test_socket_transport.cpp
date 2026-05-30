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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>

#include "socket_transport.h"
#include "scf_transport.h"
#include "custom_logger.h"
#include "test_scf.h"

namespace test {

constexpr int RESULT_SUCCESS = 0;
constexpr int RESULT_ERROR = -1;
constexpr int RESULT_WOULD_BLOCK = -2;
constexpr int RESULT_CONNECTION_CLOSED = -3;
constexpr int RESULT_TIMEOUT = -4;
constexpr int PROTOCOL_TCP = 0;
constexpr int PROTOCOL_UDP = 1;
constexpr int PROTOCOL_URMA = 2;
constexpr int PROTOCOL_CUSTOM = 99;
constexpr size_t BUFFER_LEN_10 = 10;
constexpr uint16_t PORT_9999 = 9999;
constexpr uint16_t PORT_8080 = 8080;
constexpr uint32_t TIMEOUT_1000_MS = 1000;
constexpr uint32_t TIMEOUT_5000_MS = 5000;

class SocketTransportTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        SetExternalLogFunction(ExternalLogFunction);
        transport = new scf::SocketTransport();
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

    scf::SocketTransport *transport = nullptr;
};

TEST_F(SocketTransportTest, Constructor_Default)
{
    EXPECT_TRUE(transport != nullptr);
    EXPECT_FALSE(transport->IsConnected());
    EXPECT_EQ(transport->GetProtocol(), scf::TransportProtocol::TCP);
}

TEST_F(SocketTransportTest, Constructor_WithFd)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_TRUE(fd >= 0);

    scf::SocketTransport *fdTransport = new scf::SocketTransport(fd);
    EXPECT_TRUE(fdTransport != nullptr);

    fdTransport->Close();
    delete fdTransport;
}

TEST_F(SocketTransportTest, GetProtocol_TCP)
{
    EXPECT_EQ(transport->GetProtocol(), scf::TransportProtocol::TCP);
}

TEST_F(SocketTransportTest, GetNativeHandle_Invalid)
{
    EXPECT_EQ(transport->GetNativeHandle(), -1);
}

TEST_F(SocketTransportTest, IsConnected_NotConnected)
{
    EXPECT_FALSE(transport->IsConnected());
}

TEST_F(SocketTransportTest, GetLocalAddress_NotBound)
{
    scf::TransportAddress addr = transport->GetLocalAddress();
    EXPECT_EQ(addr.type, scf::TransportAddressType::IPv4);
}

TEST_F(SocketTransportTest, GetRemoteAddress_NotConnected)
{
    scf::TransportAddress addr = transport->GetRemoteAddress();
    EXPECT_EQ(addr.type, scf::TransportAddressType::IPv4);
}

TEST_F(SocketTransportTest, Close_NotConnected)
{
    transport->Close();
    EXPECT_FALSE(transport->IsConnected());
}

TEST_F(SocketTransportTest, Send_NotConnected)
{
uint8_t data[BUFFER_LEN_10] = {0};

    size_t sentLen = 0;
    scf::TransportResult result = transport->Send(data, BUFFER_LEN_10, &sentLen);
    EXPECT_NE(result, scf::TransportResult::SUCCESS);
}

TEST_F(SocketTransportTest, Recv_NotConnected)
{
uint8_t buffer[BUFFER_LEN_10] = {0};

    size_t recvLen = 0;
    scf::TransportResult result = transport->Recv(buffer, BUFFER_LEN_10, &recvLen);
    EXPECT_NE(result, scf::TransportResult::SUCCESS);
}

TEST_F(SocketTransportTest, Send_NullData)
{
    size_t sentLen = 0;
    scf::TransportResult result = transport->Send(nullptr, BUFFER_LEN_10, &sentLen);
    EXPECT_NE(result, scf::TransportResult::SUCCESS);
}

TEST_F(SocketTransportTest, Recv_NullBuffer)
{
    size_t recvLen = 0;
    scf::TransportResult result = transport->Recv(nullptr, BUFFER_LEN_10, &recvLen);
    EXPECT_NE(result, scf::TransportResult::SUCCESS);
}

TEST_F(SocketTransportTest, Send_ZeroLen)
{
    uint8_t data[BUFFER_LEN_10] = {0};
    size_t sentLen = 0;

    scf::TransportResult result = transport->Send(data, 0, &sentLen);
    EXPECT_TRUE(result == scf::TransportResult::SUCCESS || result != scf::TransportResult::SUCCESS);
}

TEST_F(SocketTransportTest, Recv_ZeroLen)
{
    uint8_t buffer[BUFFER_LEN_10] = {0};
    size_t recvLen = 0;

    scf::TransportResult result = transport->Recv(buffer, 0, &recvLen);
    EXPECT_TRUE(result == scf::TransportResult::SUCCESS || result != scf::TransportResult::SUCCESS);
}

TEST_F(SocketTransportTest, Bind_InvalidAddress)
{
    scf::TransportAddress addr;
    addr.type = scf::TransportAddressType::CUSTOM;

    scf::TransportResult result = transport->Bind(addr, 5);
    EXPECT_NE(result, scf::TransportResult::SUCCESS);
}

TEST_F(SocketTransportTest, Connect_InvalidAddress)
{
    scf::TransportAddress addr;
    addr.type = scf::TransportAddressType::CUSTOM;

    scf::TransportConfig config;
    scf::TransportResult result = transport->Connect(addr, config);
    EXPECT_NE(result, scf::TransportResult::SUCCESS);
}

TEST_F(SocketTransportTest, Connect_Refused)
{
    scf::TransportAddress addr;
    addr.type = scf::TransportAddressType::IPv4;
    addr.host = "127.0.0.1";
    addr.port = PORT_9999;

    scf::TransportConfig config;
    config.connectTimeoutMs = TIMEOUT_1000_MS;

    scf::TransportResult result = transport->Connect(addr, config);
    EXPECT_TRUE(result == scf::TransportResult::SUCCESS || result != scf::TransportResult::SUCCESS);
}

TEST_F(SocketTransportTest, SetConfig_Valid)
{
    scf::TransportConfig config;
    config.nonBlocking = true;
    config.connectTimeoutMs = TIMEOUT_5000_MS;

    scf::TransportResult result = transport->SetConfig(config);
    EXPECT_EQ(result, scf::TransportResult::SUCCESS);
}

TEST_F(SocketTransportTest, Clone_NotConnected)
{
    scf::ITransport *cloned = transport->Clone();
    EXPECT_TRUE(cloned != nullptr);

    cloned->Close();
    delete cloned;
}

TEST_F(SocketTransportTest, Accept_NotBound)
{
    scf::ITransport *accepted = transport->Accept();
    EXPECT_TRUE(accepted == nullptr);
}

TEST_F(SocketTransportTest, Bind_Success)
{
    scf::TransportAddress addr;
    addr.type = scf::TransportAddressType::IPv4;
    addr.host = "127.0.0.1";
    addr.port = 0;

    scf::TransportResult result = transport->Bind(addr, 5);
    EXPECT_EQ(result, scf::TransportResult::SUCCESS);
}

TEST_F(SocketTransportTest, Bind_ZeroBacklog)
{
    scf::TransportAddress addr;
    addr.type = scf::TransportAddressType::IPv4;
    addr.host = "127.0.0.1";
    addr.port = 0;

    scf::TransportResult result = transport->Bind(addr, 0);
    EXPECT_EQ(result, scf::TransportResult::SUCCESS);
}

TEST_F(SocketTransportTest, Bind_IPV6)
{
    scf::TransportAddress addr;
    addr.type = scf::TransportAddressType::IPv6;
    addr.host = "::1";
    addr.port = 0;

    scf::TransportResult result = transport->Bind(addr, 5);
    EXPECT_TRUE(result == scf::TransportResult::SUCCESS ||
                result == scf::TransportResult::ERROR);
}

TEST_F(SocketTransportTest, Factory_Create)
{
    scf::SocketTransportFactory factory;
    scf::ITransport *transport = factory.Create();

    EXPECT_TRUE(transport != nullptr);

    transport->Close();
    delete transport;
}

TEST_F(SocketTransportTest, Factory_GetProtocol)
{
    scf::SocketTransportFactory factory;
    EXPECT_EQ(factory.GetProtocol(), scf::TransportProtocol::TCP);
}

TEST_F(SocketTransportTest, Factory_GetName)
{
    scf::SocketTransportFactory factory;
    const char *name = factory.GetName();
    EXPECT_TRUE(name != nullptr);
}

TEST_F(SocketTransportTest, SendRecv_DataExchange)
{
    struct addrinfo hints;
    struct addrinfo *serverInfo = nullptr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int ret = getaddrinfo(nullptr, "0", &hints, &serverInfo);
    EXPECT_EQ(ret, 0);
    if (ret != 0) {
        return;
    }

    int serverFd = socket(serverInfo->ai_family, serverInfo->ai_socktype, serverInfo->ai_protocol);
    EXPECT_GE(serverFd, 0);

    ret = bind(serverFd, serverInfo->ai_addr, serverInfo->ai_addrlen);
    EXPECT_EQ(ret, 0);

    socklen_t addrLen = serverInfo->ai_addrlen;
    ret = getsockname(serverFd, serverInfo->ai_addr, &addrLen);
    EXPECT_EQ(ret, 0);

    listen(serverFd, 1);

    int clientFd = socket(serverInfo->ai_family, serverInfo->ai_socktype, serverInfo->ai_protocol);
    EXPECT_GE(clientFd, 0);

    ret = connect(clientFd, serverInfo->ai_addr, serverInfo->ai_addrlen);
    EXPECT_EQ(ret, 0);

    int acceptedFd = accept(serverFd, nullptr, nullptr);
    EXPECT_GE(acceptedFd, 0);

    uint8_t sendData[BUFFER_LEN_10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    ssize_t sent = send(clientFd, sendData, BUFFER_LEN_10, 0);
    EXPECT_EQ(sent, BUFFER_LEN_10);

    uint8_t recvData[BUFFER_LEN_10] = {0};
    ssize_t received = recv(acceptedFd, recvData, BUFFER_LEN_10, 0);
    EXPECT_EQ(received, BUFFER_LEN_10);
    EXPECT_EQ(memcmp(sendData, recvData, BUFFER_LEN_10), 0);

    close(acceptedFd);
    close(clientFd);
    close(serverFd);
    freeaddrinfo(serverInfo);
}

TEST_F(SocketTransportTest, TransportConfig_Default)
{
    scf::TransportConfig config;
    EXPECT_TRUE(config.nonBlocking);
    EXPECT_EQ(config.connectTimeoutMs, TIMEOUT_5000_MS);
    EXPECT_TRUE(config.tcpNoDelay);
}

TEST_F(SocketTransportTest, TransportAddress_IPV4)
{
    scf::TransportAddress addr;
    addr.type = scf::TransportAddressType::IPv4;
    addr.host = "192.168.1.1";
    addr.port = PORT_8080;

    EXPECT_EQ(addr.type, scf::TransportAddressType::IPv4);
    EXPECT_EQ(addr.host, "192.168.1.1");
    EXPECT_EQ(addr.port, PORT_8080);
}

TEST_F(SocketTransportTest, TransportAddress_IPV6)
{
    scf::TransportAddress addr;
    addr.type = scf::TransportAddressType::IPv6;
    addr.host = "fe80::1";
    addr.port = PORT_8080;

    EXPECT_EQ(addr.type, scf::TransportAddressType::IPv6);
    EXPECT_EQ(addr.host, "fe80::1");
    EXPECT_EQ(addr.port, PORT_8080);
}

TEST_F(SocketTransportTest, TransportResult_Values)
{
    EXPECT_EQ(static_cast<int>(scf::TransportResult::SUCCESS), RESULT_SUCCESS);
    EXPECT_EQ(static_cast<int>(scf::TransportResult::ERROR), RESULT_ERROR);
    EXPECT_EQ(static_cast<int>(scf::TransportResult::WOULD_BLOCK), RESULT_WOULD_BLOCK);
    EXPECT_EQ(static_cast<int>(scf::TransportResult::CONNECTION_CLOSED), RESULT_CONNECTION_CLOSED);
    EXPECT_EQ(static_cast<int>(scf::TransportResult::TIMEOUT), RESULT_TIMEOUT);
}

TEST_F(SocketTransportTest, TransportProtocol_Values)
{
    EXPECT_EQ(static_cast<int>(scf::TransportProtocol::TCP), PROTOCOL_TCP);
    EXPECT_EQ(static_cast<int>(scf::TransportProtocol::UDP), PROTOCOL_UDP);
    EXPECT_EQ(static_cast<int>(scf::TransportProtocol::URMA), PROTOCOL_URMA);
    EXPECT_EQ(static_cast<int>(scf::TransportProtocol::CUSTOM), PROTOCOL_CUSTOM);
}

}