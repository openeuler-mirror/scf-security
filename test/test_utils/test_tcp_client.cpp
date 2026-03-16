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

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "test_tcp_client.h"

namespace test {
namespace fw {

NResult TestTcpClient::Send(int &fd, uint8_t *buf, size_t bufLen, ssize_t &writeLen)
{
    writeLen = ::send(fd, buf, bufLen, 0);
    if (writeLen <= 0) {
        return NN_OOB_CLIENT_SOCKET_ERROR;
    }
    return NN_OK;
}

NResult TestTcpClient::Recv(int &fd, uint8_t *buf, size_t bufLen, ssize_t &readLen)
{
    NResult ret = NN_OOB_CLIENT_SOCKET_ERROR;
    uint32_t retryCnt = 0;
    readLen = 0;
    errno = 0;
    // 非阻塞的，当前没有用 poll 类的事件机制，因此读太快可能读不到，需要等待一下。
    while (readLen == 0 && retryCnt < TEST_READ_RETRY_MAX_CNT) {
        readLen = ::recv(fd, buf, bufLen, 0);
        if (readLen == 0) {
            retryCnt++;
            usleep(TEST_USLEEP_TIME);
            continue;
        } else if (readLen < 0) {
            std::cout << "TestTcpClient::Recv ret = " << readLen << ", errno = " << errno << std::endl;
            break;
        }
        ret = NN_OK;
    }
    return ret;
}

NResult TestTcpClient::ConnectWithFd(const std::string &ip, uint32_t port, int &fd)
{
    auto tmpFD = ::socket(AF_INET, SOCK_STREAM, 0);
    if (tmpFD < 0) {
        std::cout << "Failed to create listen socket, errno:" << errno <<
            ", please check if fd is out of limit" << std::endl;
        return NN_OOB_CLIENT_SOCKET_ERROR;
    }

    int flags = 1;
    setsockopt(tmpFD, SOL_TCP, TCP_NODELAY, reinterpret_cast<void *>(&flags), sizeof(flags));
    int synCnt = 1; /* Set connect() retry time for quick connect */
    setsockopt(tmpFD, IPPROTO_TCP, TCP_SYNCNT, &synCnt, sizeof(synCnt));

    struct sockaddr_in addr {};
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    addr.sin_port = htons(port);

    uint32_t timesRetried = 0;
    uint32_t maxConnRetryTimes = 1;
    auto maxConnRetryInterval = 20;
    auto maxRecvTimeout = 1000;
    timeval timeout = { maxRecvTimeout, 0 };
    setsockopt(tmpFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeval));

    while (timesRetried < maxConnRetryTimes) {
        std::cout << "Trying to connect to " << ip << ":" << port << std::endl;
        if (::connect(tmpFD, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == 0) {
            ConnectResp connectStatus = ConnectResp::OK;
            ssize_t result = ::recv(tmpFD, &connectStatus, sizeof(ConnectResp), 0);
            if (result <= 0 || connectStatus != ConnectResp::OK) {
                std::cout << "Failed to receive connection status from peer on oob, as result:" << result <<
                    " errno:" << errno << " connTaskStatus:" << connectStatus << std::endl;
            } else {
                if (SetNonBlock(tmpFD) != NN_OK) {
                    SafeCloseFd(tmpFD);
                    std::cout << "failed to set non block" << std::endl;
                    return NN_OOB_CLIENT_SOCKET_ERROR;
                }
                fd = tmpFD;
                std::cout << "Connect to " << ip << ":" << port << " successfully" << std::endl;
                return NN_OK;
            }
        }

        if (errno == EINTR) {
            continue;
        }

        // interval between each retry, 1 sec for the first time,
        // and will be doubled for each time after, while it will be maxConnRetryInterval at maximum.
        sleep(1 << timesRetried > maxConnRetryInterval ? maxConnRetryInterval : 1 << timesRetried);
        timesRetried++;

        std::cout << "Trying to connect to " << ip << ":" << port << " errno:" << errno << " error:" <<
            " retry times:" << timesRetried << std::endl;
    }

    SafeCloseFd(tmpFD);
    std::cout << "Failed to connect to " << ip << ":" << port << " after tried " << timesRetried <<
        " times" << std::endl;
    return NN_OOB_CLIENT_SOCKET_ERROR;
}

NResult TestTcpClient::Connect(const std::string &ip, uint32_t port, TestTcpConnection *&conn)
{
    int fd = -1;
    auto result = ConnectWithFd(ip, port, fd);
    if (result != NN_OK) {
        return result;
    }

    conn = new (std::nothrow) TestTcpConnection(fd);
    if ((conn == nullptr)) {
        std::cout << "Failed to new oob connection, probably out of memory" << std::endl;
        SafeCloseFd(fd);
        return NN_NEW_OBJECT_FAILED;
    }

    conn->ListenPort(port);
    return NN_OK;
}

} // namespace fw
} // namespace test
