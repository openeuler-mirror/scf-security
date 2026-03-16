/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
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

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <vector>
#include "securec.h"
#include "test_tcp_client.h"
#include "test_tcp_common.h"
#include "scf_errno.h"

namespace scf {
    test::fw::TestTcpConnection *g_conn = nullptr;
    constexpr uint32_t RW_LEN = 1024; // 传输的数据大小
    constexpr uint32_t DATA_BUF_LEN = 4096;

    void ClientTcpReadWrite(test::fw::TestTcpClient &client, int32_t &fd, uint32_t rwLen)
    {
        static int cnt = 0;
        cnt++;

        uint8_t *dataCW = new uint8_t[DATA_BUF_LEN]{
            0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
        };
        uint8_t *dataCR = new uint8_t[DATA_BUF_LEN]();
        uint32_t dataCLen = std::min(DATA_BUF_LEN, rwLen);
        ssize_t writeCLen = 0;
        ssize_t readCLen = 0;

        auto ret = client.Recv(fd, dataCR, DATA_BUF_LEN, readCLen);
        if (ret != test::fw::NN_OK || rwLen != readCLen) {
            std::cout << "TCP_Read error" << ret << std::endl;
        }

        ret = client.Send(fd, dataCW, dataCLen, writeCLen);
        if (ret != test::fw::NN_OK || writeCLen <= 0) {
            std::cout << "TCP_Write error" << ret << std::endl;
        }

        delete[] dataCW;
        delete[] dataCR;
    }

    void FreeGlobalConnAndClientObj()
    {
        delete g_conn;
        g_conn = nullptr;
    }

    bool TestTcpClient(char *serverIp, uint16_t port)
    {
        test::fw::TestTcpClient testClient{}; // 客户端
        auto ret = testClient.Connect(serverIp, port, g_conn); // 服务端ip
        if (ret != test::fw::NN_OK) {
            std::cout << "testClient.Connect error:" << ret << std::endl;
            return false;
        }

        int fdClient = g_conn->GetFd();
        if (fdClient < 0) {
            std::cout << "GetFd error:" << fdClient << std::endl;
            return false;
        }
        // 先传输一次，降低首次数据传输影响
        ClientTcpReadWrite(testClient, fdClient, RW_LEN);
        int64_t beginTime = test::fw::SystemMicrosecondsGet();
        for (int32_t i = 0; i < TEST_MAXLOOPS; i++) {
            ClientTcpReadWrite(testClient, fdClient, RW_LEN);
        }
        int64_t endTime = test::fw::SystemMicrosecondsGet();
        int64_t gapTimeSsl = endTime - beginTime;
        std::cout << "client gapTimeSsl:" << gapTimeSsl << "\n";
        return true;
    }
}

/* 主函数 */
int main([[maybe_unused]] int argc, [[maybe_unused]] char **argv)
{
    uint16_t port = 0;
    if (argc != test::fw::TEST_TCP_PARAM_COUNT ||
        test::fw::ParsePort(argv[test::fw::TEST_TCP_PORT_INDEX], port) != SCF_SUCCESS) {
        std::cout << "Invalid Params, example: ./client_main_tpc serverIp port" << std::endl;
        return 1;
    }
    if (scf::TestTcpClient(argv[test::fw::TEST_TCP_IP_INDEX], port)) {
        std::cout << "TestClient success" << std::endl;
    } else {
        std::cout << "TestClient fail" << std::endl;
    }
    scf::FreeGlobalConnAndClientObj();
    return 0;
}
