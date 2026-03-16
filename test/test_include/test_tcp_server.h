/*
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

#ifndef TEST_TCP_SERVER_H
#define TEST_TCP_SERVER_H

#include <stdint.h>

#include <atomic>
#include <iostream>
#include <string>
#include <thread>
#include <stdint.h>

#include "securec.h"
#include "test_tcp_common.h"

namespace test {
namespace fw {

class TestTcpServer {
public:
    TestTcpServer(const std::string &ip, uint16_t port)
    {
        mAcceptFD = -1;
        mListenIP = ip;
        mListenPort = port;
    }

    ~TestTcpServer()
    {
        (void)Stop();
    }

    NResult Start();
    NResult Stop();
    int GetListenFd();
    int GetAcceptFd(); // 获取刚刚 accept 成功的 fd，当前只支持一个客户端
    NResult Send(int &fd, uint8_t *buf, size_t bufLen, ssize_t &writeLen);
    NResult Recv(int &fd, uint8_t *buf, size_t bufLen, ssize_t &readLen);

protected:
    virtual void RunInThread();

protected:
    std::string mListenIP;                          /* listen ip for tcp listener */
    int mListenFD = -1;
    std::atomic<int> mAcceptFD;
    uint16_t mListenPort = OOB_DEFAULT_LISTEN_PORT; /* listen port for tcp listener */
    std::atomic<bool> mThreadStarted { false };
    std::atomic<bool> mAccepted { false };
    std::thread mAcceptThread;

private:
    NResult CreateAndConfigSocket(int &socketFD);
    NResult CreateAndStartSocket();
    NResult BindAndListenCommon(int socketFD);
    void DealConnectInThread(int &fd, struct sockaddr_in addressIn);
    bool IsNeedStop();

    bool mNeedStop = false;
    bool mStarted = false;
};

} // namespace fw
} // namespace test

#endif // TEST_TCP_SERVER_H
