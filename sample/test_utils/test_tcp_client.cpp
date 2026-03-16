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
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "test_tcp_client.h"

namespace test {
namespace fw {

NResult TestTcpClient::Send(int &fd, uint8_t *buf, size_t bufLen, ssize_t &writeLen)
{
    ssize_t totalSent = 0;
    while (totalSent < static_cast<ssize_t>(bufLen)) {
        writeLen = ::send(fd, buf + totalSent, bufLen - totalSent, 0);
        if (writeLen <= 0) {
            return NN_OOB_CLIENT_SOCKET_ERROR;
        }
        totalSent += writeLen;
    }
    return NN_OK;
}

NResult TestTcpClient::Recv(int &fd, uint8_t *buf, size_t bufLen, ssize_t &readLen)
{
    NResult ret = NN_OOB_CLIENT_SOCKET_ERROR;
    uint32_t retryCnt = 0;
    readLen = 0;
    errno = 0;

    while (readLen < static_cast<ssize_t>(bufLen) && retryCnt < TEST_READ_RETRY_MAX_CNT) {
        ssize_t currentRead = ::recv(fd, buf + readLen, bufLen - readLen, 0);
        if (currentRead == 0) {
            // 对端关闭连接
            return NN_OOB_CLIENT_SOCKET_ERROR;
        }
        if (currentRead < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 非阻塞套接字上没有数据可读，继续重试
                std::cout<<"非阻塞套接字上没有数据可读，继续重试"<< retryCnt <<"\n";
                usleep(TEST_USLEEP_TIME);
                retryCnt++;
            } else {
                // 其他错误
                std::cerr << "Recv error: " << errno << std::endl;
                return NN_OOB_CLIENT_SOCKET_ERROR;
            }
        } else {
            readLen += currentRead;
            ret = NN_OK;
        }
    }
    return ret;
}

NResult TestTcpClient::ConnectWithFd(const std::string &ip, uint32_t port, int &fd)
{
    auto tmpFD = ::socket(AF_INET, SOCK_STREAM, 0);
    if (tmpFD < 0) {
        std::cout << "Failed to create listen socket, errno:" << errno << std::endl;
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

    uint32_t times = 0; // timesRetried
    auto maxConnRetryInterval = 20;
    struct timeval timeout = { 1000, 0 };
    setsockopt(tmpFD, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char *>(&timeout), sizeof(timeval));

    while (times < 1) { // maxConnRetryTimes = 1
        std::cout << "Trying to connect to " << ip << ":" << port << std::endl;
        if (::connect(tmpFD, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == 0) {
            ConnectResp connectStatus = ConnectResp::OK;
            ssize_t result = ::recv(tmpFD, &connectStatus, sizeof(ConnectResp), 0);
            if (result > 0 && connectStatus == ConnectResp::OK) {
                if (SetNonBlock(tmpFD) != NN_OK) {
                    SafeCloseFd(tmpFD);
                    std::cout << "failed to set non block" << std::endl;
                    return NN_OOB_CLIENT_SOCKET_ERROR;
                }
                fd = tmpFD;
                std::cout << "Connect to " << ip << ":" << port << " successfully" << std::endl;
                return NN_OK;
            }
            std::cout << "Failed to receive connection status from peer on oob, as result:" << result <<
                " errno:" << errno << " connTaskStatus:" << connectStatus << std::endl;
        }

        if (errno == EINTR) {
            continue;
        }

        // interval between each retry, 1 sec for the first time,
        // and will be doubled for each time after, while it will be maxConnRetryInterval at maximum.
        sleep(1 << times > maxConnRetryInterval ? maxConnRetryInterval : 1 << times);
        times++;

        std::cout << "Trying to connect to " << ip << ":" << port << " errno:" << errno <<
            " retry times:" << times << std::endl;
    }

    SafeCloseFd(tmpFD);
    std::cout << "Failed to connect to " << ip << ":" << port << " after tried " << times << " times" << std::endl;
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
