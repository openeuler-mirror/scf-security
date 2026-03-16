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

#include <cstdio>
#include <cstring>
#include <iostream>

#include "securec.h"
#include "test_tcp_server.h"
#include "scf_errno.h"

namespace scf {
    test::fw::TestTcpConnection *g_conn = nullptr;
    constexpr uint32_t RW_LEN = 1024; // 传输的数据大小
    constexpr uint32_t DATA_BUF_LEN = 4096;

    void ServerTcpReadWrite(test::fw::TestTcpServer &server, int &fd, uint32_t rwLen)
    {
        uint8_t *dataSW = new uint8_t[DATA_BUF_LEN]{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        uint8_t *dataSR = new uint8_t[DATA_BUF_LEN](); // server read
        uint32_t dataSLen = std::min(DATA_BUF_LEN, rwLen);
        ssize_t writeSLen = 0;
        ssize_t readSLen = 0;

        auto ret = server.Send(fd, dataSW, dataSLen, writeSLen);
        if (ret != test::fw::NN_OK || writeSLen <= 0) {
            std::cout << "TCP_Write error" << ret << std::endl;
        }
        ret = server.Recv(fd, dataSR, DATA_BUF_LEN, readSLen);
        if (ret != test::fw::NN_OK || rwLen != readSLen) {
            std::cout << "TCP_Read error" << ret << std::endl;
        }

        delete[] dataSW;
        delete[] dataSR;
    }

    void FreeGlobalConnAndServerObj()
    {
        delete g_conn;
        g_conn = nullptr;
    }

    bool TestTcpServer(char *serverIp, uint16_t port)
    {
        test::fw::TestTcpServer testServer(serverIp, port); // 服务段IP
        auto ret = testServer.Start();
        if (ret != test::fw::NN_OK) {
            std::cout << "testServer.Connect error:" << ret << std::endl;
            return false;
        }

        int fdServer = testServer.GetAcceptFd();
        if (fdServer < 0) {
            std::cout << "GetAcceptFd error:" << fdServer << std::endl;
            return false;
        }
        // 先传输一次，降低首次数据传输影响
        ServerTcpReadWrite(testServer, fdServer, RW_LEN);
        int64_t beginTime = test::fw::SystemMicrosecondsGet();
        for (int32_t i = 0; i < TEST_MAXLOOPS; i++) {
            ServerTcpReadWrite(testServer, fdServer, RW_LEN);
        }
        int64_t endTime = test::fw::SystemMicrosecondsGet();
        int64_t gapTimeSsl = endTime - beginTime;
        std::cout << "server gapTimeSsl:" << gapTimeSsl << "\n";
        return true;
    }
}

/* 主函数 */
int main([[maybe_unused]] int argc, [[maybe_unused]] char **argv)
{
    uint16_t port = 0;
    if (argc != test::fw::TEST_TCP_PARAM_COUNT ||
        test::fw::ParsePort(argv[test::fw::TEST_TCP_PORT_INDEX], port) != SCF_SUCCESS) {
        std::cout << "Invalid Params, example: ./server_main_tpc serverIp port" << std::endl;
        return 1;
    }
    if (scf::TestTcpServer(argv[test::fw::TEST_TCP_IP_INDEX], port)) {
        std::cout << "TestServer success" << std::endl;
    } else {
        std::cout << "TestServer fail" << std::endl;
    }
    scf::FreeGlobalConnAndServerObj();
    return 0;
}
