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
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include "test_scf.h"
#include "test_tcp_server.h"

namespace test {
namespace fw {

NResult TestTcpServer::CreateAndConfigSocket(int &socketFD)
{
    auto tmpFD = ::socket(AF_INET, SOCK_STREAM, 0);
    if (tmpFD < 0) {
        return NN_OOB_LISTEN_SOCKET_ERROR;
    }
    /* set no-blocking */
    int value = 1;
    if ((value = fcntl(tmpFD, F_GETFL, 0)) == -1) {
        SafeCloseFd(tmpFD);
        return NN_OOB_LISTEN_SOCKET_ERROR;
    }

    if ((value = fcntl(tmpFD, F_SETFL, uint32_t(value) | O_NONBLOCK) == -1)) {
        SafeCloseFd(tmpFD);
        return NN_OOB_LISTEN_SOCKET_ERROR;
    }

    // set option
    int flags = 1;
    int ret = ::setsockopt(tmpFD, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void *>(&flags), sizeof(flags));
    if (ret < 0) {
        SafeCloseFd(tmpFD);
        return NN_OOB_LISTEN_SOCKET_ERROR;
    }
    socketFD = tmpFD;
    return NN_OK;
}

NResult TestTcpServer::BindAndListenCommon(int socketFD)
{
    struct sockaddr_in addr {};
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(mListenIP.c_str());
    addr.sin_port = htons(mListenPort);
    auto ret = ::bind(socketFD, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
    if ((ret < 0)) {
        SafeCloseFd(socketFD);
        return NN_OOB_LISTEN_SOCKET_ERROR;
    }

    // listen
    if ((::listen(socketFD, OOB_DEFAULT_LISTEN_BACKLOG) < 0)) {
        SafeCloseFd(socketFD);
        return NN_OOB_LISTEN_SOCKET_ERROR;
    }
    return NN_OK;
}

NResult TestTcpServer::CreateAndStartSocket()
{
    int socketFD = 0;
    int ret = NN_OK;

    ret = CreateAndConfigSocket(socketFD);
    if ((ret != NN_OK)) {
        return ret;
    }
    ret = BindAndListenCommon(socketFD);
    if ((ret == NN_OK)) {
        mListenFD = socketFD;
    }
    return ret;
}

NResult TestTcpServer::Send(int &fd, uint8_t *buf, size_t bufLen, ssize_t &writeLen)
{
    writeLen = ::send(fd, buf, bufLen, 0);
    if (writeLen <= 0) {
        return NN_OOB_CLIENT_SOCKET_ERROR;
    }
    return NN_OK;
}

NResult TestTcpServer::Recv(int &fd, uint8_t *buf, size_t bufLen, ssize_t &readLen)
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
            std::cout << "TestTcpServer::Recv" << readLen << errno << std::endl;
            usleep(TEST_USLEEP_TIME);
            break;
        }
        ret = NN_OK;
    }
    return ret;
}

void TestTcpServer::DealConnectInThread(int &fd, struct sockaddr_in addressIn)
{
    ConnectResp resp = ConnectResp::OK;
    std::cout << "DealConnectInThread" << std::endl;
    if (::send(fd, &resp, sizeof(ConnectResp), 0) <= 0) {
        std::cout << "Failed to send connect status to peer on oob @ " << inet_ntoa(addressIn.sin_addr) << ":" <<
            ntohs(addressIn.sin_port) << ", as " << strerror(errno) << std::endl;
    }
    if (SetNonBlock(fd) != NN_OK) {
        SafeCloseFd(fd);
        fd = -1;
        std::cout << "DealConnectInThread send success, but set non block failed" << std::endl;
        return;
    }
    mAcceptFD.store(fd);
    mAccepted.store(true);
    std::cout << "DealConnectInThread send success, fd = " << mAcceptFD << std::endl;
}

bool TestTcpServer::IsNeedStop()
{
    return mNeedStop;
}

void TestTcpServer::RunInThread()
{
    // 只支持 tcp
    mThreadStarted.store(true);

    struct sockaddr_in addressIn {};
    socklen_t len = sizeof(addressIn);

    int flags = 1;
    int fd = -1;

    while (true) {
        try {
            if ((IsNeedStop())) {
                std::cout << "Got stop signal, stop listening"<< std::endl;
                break;
            }

            struct pollfd pollEventFd = {};
            pollEventFd.fd = mListenFD;
            pollEventFd.events = POLLIN;
            pollEventFd.revents = 0;

            int rc = poll(&pollEventFd, 1, 500);
            if (rc < 0 && errno != EINTR) {
                std::cout << "Get poll event failed  , errno " << strerror(errno) << std::endl;
                break;
            }

            if (rc == 0) {
                continue;
            }

            (void)memset_s(&addressIn, sizeof(struct sockaddr_in), 0, sizeof(struct sockaddr_in));
            fd = ::accept(mListenFD, reinterpret_cast<struct sockaddr *>(&addressIn), &len);
            if (fd < 0) {
                std::cout << "Failed to accept on new socket with " << strerror(errno) << ", ignore and continue" <<
                    std::endl;
                continue;
            }

            // set no delay
            setsockopt(fd, SOL_TCP, TCP_NODELAY, reinterpret_cast<void *>(&flags), sizeof(flags));

            DealConnectInThread(fd, addressIn);
        } catch (std::exception &ex) {
            std::cout << "Got exception in TestTcpServer::RunInThread, exception " << ex.what() <<
                ", ignore and continue" << std::endl;
        } catch (...) {
            std::cout << "Got unknown error in TestTcpServer::RunInThread, ignore and continue" << std::endl;
        }
        if (fd >= 0) {
            (void) ::shutdown(fd, SHUT_RDWR);
        };
    }

    std::cout << "Working thread for TestTcpServer at " << mListenIP << ":" << mListenPort << " exiting" << std::endl;
}

NResult TestTcpServer::Start()
{
    if (mStarted) {
        return NN_OK;
    }

    auto ret = CreateAndStartSocket();
    if (ret != NN_OK) {
        return ret;
    }
    mThreadStarted.store(false);

    // start oob accept thread
    std::thread tmpThread(&TestTcpServer::RunInThread, this);
    mAcceptThread = std::move(tmpThread);

    while (!mThreadStarted.load()) {
        usleep(NN_N100);
    }

    mStarted = true;
    return NN_OK;
}

NResult TestTcpServer::Stop()
{
    if (!mStarted) {
        std::cout << "TestTcpServer::Stop"<< std::endl;
        return NN_OK;
    }
    mNeedStop = true;
    std::cout << "TestTcpServer::Stop mNeedStop, listen = " << mListenFD << std::endl;
    mAcceptThread.join();
    SafeCloseFd(mListenFD);
    std::cout << "TestTcpServer::Stop close"<< std::endl;

    mStarted = false;
    return NN_OK;
}

int TestTcpServer::GetListenFd()
{
    return mListenFD;
}

int TestTcpServer::GetAcceptFd()
{
    /* 主线程 connect 成功，准备获取 fd 时，accept 线程可能正好切换时间片，导致 accept 线程还没配置 fd 到 mAcceptFD 上。
     * 因此需要尝试等待一段时间，避免线程同步问题。如果等待过久，说明是 tcp 网络有问题，超时返回当前 fd，令用例失败。
     */
    for (int i = 0; i < TEST_READ_RETRY_MAX_CNT; i++) {
        if (mAccepted.load() == true) {
            break;
        }
        sleep(1);
    }
    return mAcceptFD.load();
}

} // namespace fw
} // namespace test