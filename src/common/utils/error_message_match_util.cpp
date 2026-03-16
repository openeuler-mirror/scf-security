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

#include <mutex>
#include "custom_logger.h"
#include "securec.h"
#include "scf.h"
#include "scf_def.h"
#include "scf_inner.h"
#include "constant_def.h"

namespace scf {

const char *GetErrorMessage(int32_t errorCode)
{
    static char buffer[ERROR_MSG_SIZE];
    const std::string &errorMessageCpp = GetErrorMessageInternal(errorCode);
    auto ret = strncpy_s(buffer, sizeof(buffer), errorMessageCpp.c_str(), sizeof(buffer) - 1);
    if (ret != EOK) {
        CCSEC_LOG_ERROR("|GetErrorMessage|END|returnF||strncpy_s failed.");
        return nullptr;
    }
    buffer[sizeof(buffer) - 1] = '\0';
    return buffer;
}
}