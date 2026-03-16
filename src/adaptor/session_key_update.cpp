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

#include "scf_inner.h"
#include "scf_def.h"
#include "scf_errno.h"

namespace scf {
static int32_t CheckTimeInterval(SCF_PolicyObj *obj, bool *isTimeToKeyUpdate)
{
    timeval sysTime{};
    *isTimeToKeyUpdate = false;

    (void) gettimeofday(&sysTime, nullptr);
    uint64_t curTime = static_cast<uint64_t>(sysTime.tv_sec);

    if (curTime < obj->keyUpdateInfo.lastKeyUpdateTime) {
        CCSEC_LOG_ERROR("|CheckTimeInterval|END|returnF||System time error");
        return SCF_ERRNO_SYSTEM_TIME_ERROR;
    }
    uint64_t relativeSec = curTime - obj->keyUpdateInfo.lastKeyUpdateTime;
    if (relativeSec >= static_cast<uint64_t>(obj->policyCtx->keyUpdateTime)) {
        *isTimeToKeyUpdate = true;
    }

    return SCF_SUCCESS;
}

int32_t CheckNeedKeyUpdate(SCF_PolicyObj *obj, uint32_t processDataLen, bool *isNeedKeyUpdate)
{
    if (obj == nullptr || isNeedKeyUpdate == nullptr) {
        CCSEC_LOG_ERROR("|CheckNeedKeyUpdate|END|returnF|| obj or isNeedKeyUpdate is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    *isNeedKeyUpdate = false;
    const char *tlsVersion = g_adaptor->GetVersion(obj);
    if (tlsVersion == nullptr || strcmp(tlsVersion, SCF_SSL_VERSION_TLS13_STR) != 0) {
        return SCF_SUCCESS;
    }
    // 避免obj->keyUpdateInfo.totalSizeOfWriteData + processDataLen整数溢出导致无法触发更新
    if (processDataLen >= obj->policyCtx->keyUpdateTraffic ||
        obj->keyUpdateInfo.totalSizeOfWriteData >= obj->policyCtx->keyUpdateTraffic - processDataLen) {
        *isNeedKeyUpdate = true;
        // 最大加到 UINT64_MAX
        obj->keyUpdateInfo.totalSizeOfWriteData += std::min(UINT64_MAX - obj->keyUpdateInfo.totalSizeOfWriteData,
                                                            static_cast<uint64_t>(processDataLen));
        return SCF_SUCCESS;
    }
    obj->keyUpdateInfo.totalSizeOfWriteData += processDataLen;
    if (obj->keyUpdateInfo.totalSizeOfWriteData >= obj->policyCtx->keyUpdateTraffic) {
        *isNeedKeyUpdate = true;
        return SCF_SUCCESS;
    }

    return CheckTimeInterval(obj, isNeedKeyUpdate);
}
}