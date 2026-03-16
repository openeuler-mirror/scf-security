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
#ifndef TEST_TCP_COMMON_H
#define TEST_TCP_COMMON_H

#include <cstdint>
#include <string>

namespace test::fw { // framework

#define TEST_MAXLOOPS 1000
#define TEST_REPEAT_LOG_TIME 100
#define TEST_READ_RETRY_MAX_CNT 20000
#define TEST_USLEEP_TIME 10 // 100 微秒 = 0.1 毫秒
const uint32_t USEC_PER_SEC = 1000000; // 1000000 微秒 = 1000 毫秒 = 1 秒
const uint32_t TEST_TCP_PARAM_COUNT = 3;
const uint32_t TEST_TCP_IP_INDEX = 1;
const uint32_t TEST_TCP_PORT_INDEX = 2;
const uint32_t TEST_SSL_PARAM_COUNT = 5;
const uint32_t TEST_SSL_FLAG_INDEX = 1;
const uint32_t TEST_SSL_LIBPATH_INDEX = 2;
const uint32_t TEST_SSL_IP_INDEX = 3;
const uint32_t TEST_SSL_PORT_INDEX = 4;

using NResult = int32_t;
constexpr uint32_t OOB_DEFAULT_LISTEN_PORT = 9981;
constexpr uint32_t OOB_DEFAULT_LISTEN_BACKLOG = 65535;

enum NNCode {
    NN_OK = 0,
    NN_NEW_OBJECT_FAILED = 102,
    NN_OOB_LISTEN_SOCKET_ERROR = 124,
    NN_OOB_CLIENT_SOCKET_ERROR = 128,
};

enum ConnectResp : int16_t {
    OK_PROTOCOL_TCP = 2, /* tell client using tcp socket to connect real worker */
    OK_PROTOCOL_UDS = 1, /* tell client using uds to connect real worker */
    OK = 0,
    MAGIC_MISMATCH = -1,
    VERSION_MISMATCH = -2,
    WORKER_GRPNO_MISMATCH = -3,
    WORKER_NOT_STARTED = -4,
    PROTOCOL_MISMATCH = -5,
    SERVER_INTERNAL_ERROR = -6,
    CONN_ACCEPT_NEW_TASK_FAIL = -7,
    CONN_ACCEPT_QUEUE_FULL = -8,
    SEC_VALID_FAILED = -9,
    TLS_VERSION_MISMATCH = -10,
};

void SafeCloseFd(int &fd);

NResult SetNonBlock(int &fd);

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

    int GetFd();

protected:
    int mFD = -1;
    uint32_t mListenPort = 0;
};

std::string GetLocalPath();

void ExternalLogFunc(int level, const char *msg);

int64_t SystemMicrosecondsGet();

int32_t ParsePort(char *portStr, uint16_t &port);
} // namespace test::fw

#endif // TEST_TCP_COMMON_H
