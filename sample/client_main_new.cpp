/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 *
 * === SCF v2.0 新 API 示例：证书认证客户端 ===
 *
 * 对比旧 API 需要 300+ 行样板代码，
 * 新 API 只需配置安全级别和证书路径即可完成安全通信。
 */

#include <iostream>
#include <string>
#include <cstring>

#include "scf.h"
#include "scf_errno.h"

// ============================================================
// 新 API 方式 —— 简洁清晰
// ============================================================
bool TestClientNewAPI(const std::string &serverHost, uint16_t serverPort)
{
    // 1. 初始化 SCF
    int32_t ret = scf::SCF_Init(SCF_INIT_FLAG_OPENSSL, nullptr);
    if (ret != SCF_SUCCESS) {
        std::cerr << "SCF_Init failed: " << ret << std::endl;
        return false;
    }

    // 2. 创建连接 —— 只需指定 NIST 安全强度和证书路径
    scf::SCFConnectionConfig config;
    config.securityLevel = scf::SCF_SECURITY_128BIT;     // NIST SP 800-57 128-bit 安全强度
    config.role = scf::SCF_ROLE_CLIENT;
    config.caCertPath = "/etc/scf/certs/ca.pem";        // CA 证书
    config.certPath = "/etc/scf/certs/client.pem";       // 客户端设备证书
    config.keyPath = "/etc/scf/certs/client-key.pem";    // 客户端私钥
    config.certVerifyPolicy = scf::SCF_CERT_VERIFY_REQUIRED;

    auto *conn = scf::SCFConnection::Create(config);
    if (conn == nullptr) {
        std::cerr << "SCFConnection::Create failed" << std::endl;
        scf::SCF_DeInit();
        return false;
    }

    // 3. 发起安全连接 (内部自动完成 TCP + TLS 握手)
    ret = conn->Connect(serverHost, serverPort);
    if (ret != SCF_SUCCESS) {
        std::cerr << "Connect failed: " << ret << std::endl;
        delete conn;
        scf::SCF_DeInit();
        return false;
    }

    std::cout << "TLS connected! Version: " << conn->GetTLSVersion() << std::endl;

    // 4. 安全数据传输
    const char *request = "Hello Secure World!";
    uint32_t written = 0;
    ret = conn->Write(reinterpret_cast<const uint8_t *>(request),
        static_cast<uint32_t>(std::strlen(request)), &written);
    if (ret != SCF_SUCCESS) {
        std::cerr << "Write failed: " << ret << std::endl;
    }

    uint8_t buffer[4096] = {};
    uint32_t readLen = 0;
    ret = conn->Read(buffer, sizeof(buffer), &readLen);
    if (ret == SCF_SUCCESS) {
        std::string received(static_cast<const char *>(static_cast<const void *>(buffer)), readLen);
        std::cout << "Received: " << received << std::endl;
    }

    // 5. 关闭连接 —— 自动完成 TLS close_notify + TCP close
    conn->Close();
    delete conn;

    scf::SCF_DeInit();
    return true;
}

// ============================================================
// 便捷函数方式 —— 一行创建连接
// ============================================================
bool TestClientConvenienceAPI(const std::string &serverHost, uint16_t serverPort)
{
    scf::SCF_Init(SCF_INIT_FLAG_OPENSSL, nullptr);

    // 一行创建客户端连接 (NIST 128-bit 安全强度)
    auto *conn = scf::SCF_NewClientConnection(
        scf::SCF_SECURITY_128BIT,
        "/etc/scf/certs/ca.pem");

    if (conn == nullptr) {
        scf::SCF_DeInit();
        return false;
    }

    conn->Connect(serverHost, serverPort);

    uint8_t buf[1024] = {};
    uint32_t n = 0;
    conn->Read(buf, sizeof(buf), &n);

    conn->Close();
    delete conn;
    scf::SCF_DeInit();
    return n > 0;
}

// ============================================================
// PSK 连接方式 —— 极简
// ============================================================
bool TestPSKClient(const std::string &serverHost, uint16_t serverPort)
{
    scf::SCF_Init(SCF_INIT_FLAG_OPENSSL, nullptr);

    // PSK 密钥
    const uint8_t pskKey[] = "my-secret-psk-key-v1";
    // 一行创建 PSK 连接 (NIST 128-bit 安全强度)
    auto *conn = scf::SCF_NewPSKConnection(
        scf::SCF_SECURITY_128BIT,
        scf::SCF_ROLE_CLIENT,
        "psk-client-id",
        pskKey, sizeof(pskKey) - 1);

    if (conn == nullptr) {
        scf::SCF_DeInit();
        return false;
    }

    conn->Connect(serverHost, serverPort);

    const uint8_t msg[] = "PSK test message";
    uint32_t w = 0;
    conn->Write(msg, sizeof(msg) - 1, &w);
    conn->Close();
    delete conn;
    scf::SCF_DeInit();
    return true;
}

// ============================================================
// 服务端示例 —— 同样简洁
// ============================================================
bool TestServerNewAPI(uint16_t listenPort)
{
    scf::SCF_Init(SCF_INIT_FLAG_OPENSSL, nullptr);

    // 创建服务端连接，输入：NIST 128-bit 安全强度, 服务端证书， 服务端私钥
    auto *listener = scf::SCF_NewServerConnection(scf::SCF_SECURITY_128BIT,
                                                  "/etc/scf/certs/server.pem",
                                                  "/etc/scf/certs/server-key.pem");

    if (listener == nullptr) {
        scf::SCF_DeInit();
        return false;
    }

    // 监听
    int32_t ret = listener->Listen("0.0.0.0", listenPort);
    if (ret != SCF_SUCCESS) {
        std::cerr << "Listen failed" << std::endl;
        delete listener;
        scf::SCF_DeInit();
        return false;
    }

    std::cout << "Server listening on port " << listenPort << std::endl;

    // 接受连接
    auto *clientConn = listener->Accept();
    if (clientConn != nullptr) {
        std::cout << "Accepted connection, TLS version: "
                  << clientConn->GetTLSVersion() << std::endl;

        uint8_t buf[4096] = {};
        uint32_t n = 0;
        ret = clientConn->Read(buf, sizeof(buf), &n);
        if (ret == SCF_SUCCESS) {
            std::cout << "Server received: " << buf << std::endl;
        }

        const char *resp = "Hello from server!";
        uint32_t w = 0;
        clientConn->Write(reinterpret_cast<const uint8_t *>(resp),
            static_cast<uint32_t>(std::strlen(resp)), &w);

        clientConn->Close();
        delete clientConn;
    }

    listener->Close();
    delete listener;
    scf::SCF_DeInit();
    return true;
}

// ============================================================
// 非阻塞事件循环模式 —— 与 poll/epoll 集成
// ============================================================
bool TestNonBlockingClient(const std::string &serverHost, uint16_t serverPort)
{
    scf::SCF_Init(SCF_INIT_FLAG_OPENSSL, nullptr);

    auto *conn = scf::SCF_NewClientConnection(
        scf::SCF_SECURITY_128BIT,
        "/etc/scf/certs/ca.pem");

    // 发起连接 (内部已完成 TCP 连接，TLS 握手可能未完成)
    int32_t ret = conn->Connect(serverHost, serverPort);

    // 轮询完成 TLS 握手
    while (ret == SCF_SSL_ERR_WANT_READ || ret == SCF_SSL_ERR_WANT_WRITE) {
        int fd = conn->GetNativeHandle();

        ret = conn->HandshakeStep();  // 推进握手
    }

    if (ret != SCF_SUCCESS) {
        std::cerr << "Handshake failed" << std::endl;
        delete conn;
        scf::SCF_DeInit();
        return false;
    }

    std::cout << "Connected!" << std::endl;

    // 正常通信...
    conn->Close();
    delete conn;
    scf::SCF_DeInit();
    return true;
}

// ============================================================
// 自定义传输IO —— 使用 URMA 传输
// ============================================================
bool TestCustomTransport()
{
    scf::SCF_Init(SCF_INIT_FLAG_OPENSSL, nullptr);

    scf::SCFConnectionConfig config;
    config.securityLevel = scf::SCF_SECURITY_128BIT;
    config.role = scf::SCF_ROLE_CLIENT;

    std::cout << "Custom transport demo (requires URMA library)" << std::endl;
    scf::SCF_DeInit();
    return true;
}

// ============================================================
// Main
// ============================================================
int main(int argc, char **argv)
{
    static constexpr int kRequiredArgCount = 3;
    static constexpr int kPortArgIndex = 2;
    static constexpr int kHostArgIndex = 1;
    static constexpr int kExitUsageError = 1;
    static constexpr int kExitTestFailed = 2;

    if (argc < kRequiredArgCount) {
        std::cout << "Usage: " << argv[0] << " <server_host> <server_port>" << std::endl;
        std::cout << "Example: " << argv[0] << " 127.0.0.1 8443" << std::endl;
        return kExitUsageError;
    }

    uint16_t port = static_cast<uint16_t>(std::atoi(argv[kPortArgIndex]));

    std::cout << "=== SCF v2.0 Client Demo ===" << std::endl;
    std::cout << "Server: " << argv[kHostArgIndex] << ":" << port << std::endl;

    if (!TestClientNewAPI(argv[kHostArgIndex], port)) {
        std::cerr << "Test failed!" << std::endl;
        return kExitTestFailed;
    }

    std::cout << "Test passed!" << std::endl;
    return 0;
}
