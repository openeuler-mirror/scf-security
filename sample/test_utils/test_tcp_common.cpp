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

#include "test_tcp_common.h"
#include <iostream>
#include <sstream>
#include <climits>
#include <sys/time.h>
#include <unistd.h>
#include "scf_errno.h"

namespace test::fw {

void SafeCloseFd(int &fd)
{
    if ((fd < 0)) {
        return;
    }

    auto tmpFd = fd;
    if (__sync_bool_compare_and_swap(&fd, tmpFd, -1)) {
        close(tmpFd);
    }
}


NResult SetNonBlock(int &fd)
{
    (void)fd;
    return NN_OK;
}

TestTcpConnection::~TestTcpConnection()
{
    std::cout << "TestTcpConnection close " << mFD << std::endl;
}

int TestTcpConnection::GetFd()
{
    return mFD;
}

std::string GetLocalPath()
{
    if (char cwd[PATH_MAX] = {0}; getcwd(cwd, sizeof(cwd)) != nullptr) {
        auto fullPath = std::string(cwd);
        const std::string target = "SCF";
        if (const size_t pos = fullPath.find(target); pos != std::string::npos) {
            return fullPath.substr(0, pos + target.length());
        }
        return fullPath;
    }
    std::cout << "Failed to get current working directory.";
    return "";
}

void ExternalLogFunc(int level, const char *msg)
{
    std::cout << "|level:" << level << " msg:" << msg << '\n';
}

int64_t SystemMicrosecondsGet()
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return static_cast<int64_t>(tv.tv_sec * USEC_PER_SEC) + tv.tv_usec;
}

int32_t ParsePort(char *portStr, uint16_t &port)
{
    std::string str(portStr);
    std::stringstream ss(str);
    if (ss >> port) {
        if (ss.fail() || !ss.eof()) {
            std::cerr << "Invalid input or extra characters" << std::endl;
        } else {
            std::cout << "Converted number: " << port << std::endl;
            return SCF_SUCCESS;
        }
    } else {
        std::cerr << "Conversion failed" << std::endl;
    }
    return SCF_ERROR;
}
} // namespace test::fw
