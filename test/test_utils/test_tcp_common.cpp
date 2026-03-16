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

#include "test_tcp_common.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

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
    int tmpFD = fd;
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
    return NN_OK;
}

} // namespace test::fw