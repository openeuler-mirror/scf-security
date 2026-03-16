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

#ifndef TEST_TCP_CLIENT_H
#define TEST_TCP_CLIENT_H

#include <string>
#include <atomic>
#include <iostream>
#include <thread>

#include "test_tcp_common.h"

namespace test::fw { // framework

class TestTcpConnection {
public:
    TestTcpConnection(int fd)
    {
        mFD = fd;
    }

    virtual ~TestTcpConnection();

    inline void ListenPort(uint32_t port)
    {
        mListenPort = port;
    }

    int GetFd() const;

protected:
    int mFD = -1;
    uint32_t mListenPort = 0;
};

class TestTcpClient {
public:
    TestTcpClient(const std::string &ip, uint16_t port)
    {
        mListenIP = ip;
        mListenPort = port;
    }

    ~TestTcpClient() = default;

    static NResult Connect(const std::string &ip, uint32_t port, TestTcpConnection *&conn);
    static NResult ConnectWithFd(const std::string &ip, uint32_t port, int &fd);

    static NResult Send(int &fd, uint8_t *buf, size_t bufLen, ssize_t &writeLen);
    static NResult Recv(int &fd, uint8_t *buf, size_t bufLen, ssize_t &readLen);

protected:
    std::string mListenIP;                          /* listen ip for tcp listener */
    int mListenFD = -1;
    uint16_t mListenPort = OOB_DEFAULT_LISTEN_PORT; /* listen port for tcp listener */
    std::atomic<bool> mThreadStarted { false };
    std::thread mAcceptThread;

private:
    bool mNeedStop = false;
    bool mStarted = false;
};

} // namespace test::fw

#endif // TEST_TCP_CLIENT_H
