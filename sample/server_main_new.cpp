/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 *
 * === SCF v2.0 新 API 示例：证书认证服务端 ===
 */

#include <iostream>
#include <string>

#include "scf.h"
#include "scf_errno.h"

bool TestServerNewAPI(uint16_t listenPort)
{
    scf::SCF_Init(SCF_INIT_FLAG_OPENSSL, nullptr);

    // 创建服务端连接监听器
    auto *listener = scf::SCF_NewServerConnection(
        scf::SCF_SECURITY_128BIT,
        "/etc/scf/certs/server.pem",
        "/etc/scf/certs/server-key.pem");

    if (listener == nullptr) {
        std::cerr << "Failed to create server listener" << std::endl;
        scf::SCF_DeInit();
        return false;
    }

    // 监听端口
    int32_t ret = listener->Listen("0.0.0.0", listenPort);
    if (ret != SCF_SUCCESS) {
        std::cerr << "Listen failed: " << ret << std::endl;
        delete listener;
        scf::SCF_DeInit();
        return false;
    }

    std::cout << "Server listening on port " << listenPort << std::endl;

    // 循环接受连接
    static constexpr int kMaxAcceptIterations = 10;
    for (int i = 0; i < kMaxAcceptIterations; ++i) {
        scf::SCFConnection *client = listener->Accept();
        if (client == nullptr) {
            // 非阻塞模式无可用连接，稍后重试
            // 实际应用中在此 poll/epoll 等待
            continue;
        }

        std::cout << "Accepted connection #" << i
                  << ", TLS version: " << client->GetTLSVersion()
                  << std::endl;

        // 读取数据
        uint8_t buf[4096] = {};
        uint32_t n = 0;
        ret = client->Read(buf, sizeof(buf), &n);
        if (ret == SCF_SUCCESS) {
            std::cout << "Received: " << buf << std::endl;

            // 回复
            const char *resp = "Hello from SCF server!";
            uint32_t w = 0;
            client->Write(reinterpret_cast<const uint8_t *>(resp),
                static_cast<uint32_t>(std::strlen(resp)), &w);
        }

        client->Close();
        delete client;
    }

    listener->Close();
    delete listener;
    scf::SCF_DeInit();
    return true;
}

int main(int argc, char **argv)
{
    static constexpr int kRequiredArgCount = 2;
    static constexpr int kPortArgIndex = 1;
    static constexpr int kExitUsageError = 1;
    static constexpr int kExitTestFailed = 2;

    if (argc < kRequiredArgCount) {
        std::cout << "Usage: " << argv[0] << " <listen_port>" << std::endl;
        return kExitUsageError;
    }

    uint16_t port = static_cast<uint16_t>(std::atoi(argv[kPortArgIndex]));
    std::cout << "=== SCF v2.0 Server Demo ===" << std::endl;

    if (!TestServerNewAPI(port)) {
        std::cerr << "Server test failed!" << std::endl;
        return kExitTestFailed;
    }

    return 0;
}
