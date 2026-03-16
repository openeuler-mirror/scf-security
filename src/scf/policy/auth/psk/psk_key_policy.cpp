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

#include "scf_ssl.h"
#include "scf.h"
#include "custom_logger.h"
#include "scf_inner.h"
#include "constant_def.h"

namespace scf {

int32_t SCF_SetKeyAutoUpdateParam(
    SCF_PolicyCtx *ctx, bool isNeedKeyUpdate, uint32_t keyUpdateTime, uint64_t keyUpdateTraffic)
{
    CCSEC_LOG_DEBUG("|SCF_SetKeyAutoUpdateParam|START|||SCF_SetKeyAutoUpdateParam start");
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SetKeyAutoUpdateParam|END|returnF||ctx is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_SetKeyAutoUpdateParam");
    ctx->isNeedKeyUpdate = isNeedKeyUpdate;

    // 当isNeedKeyUpdate为true时 才去SCF_SetKeyUpdateParam
    if (!isNeedKeyUpdate) {
        CCSEC_LOG_INFO("|SCF_SetKeyAutoUpdateParam|END|returnS|set key update param disable");
        return SCF_SUCCESS;
    }
    if (keyUpdateTime < MIN_KEY_UPDATE_TIME || keyUpdateTime > MAX_KEY_UPDATE_TIME ||
        keyUpdateTraffic < MIN_KEY_UPDATE_TRAFFIC || keyUpdateTraffic > MAX_KEY_UPDATE_TRAFFIC) {
        CCSEC_LOG_ERROR("|SCF_SetKeyAutoUpdateParam|END|returnF||key update time or traffic config error");
        return SCF_SSL_ERR_SET_UPDATE_PARAM;
    }
    ctx->keyUpdateTime = keyUpdateTime;
    ctx->keyUpdateTraffic = keyUpdateTraffic;
    return SCF_SUCCESS;
}

int32_t SCF_GetKeyAutoUpdateParam(
    SCF_PolicyCtx *ctx, bool &isNeedKeyUpdate, uint32_t &keyUpdateTime, uint64_t &keyUpdateTraffic)
{
    CCSEC_LOG_DEBUG("|SCF_GetKeyAutoUpdateParam|START|||SCF_GetKeyAutoUpdateParam start");
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetKeyAutoUpdateParam|END|returnF||ctx is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_GetKeyAutoUpdateParam");
    isNeedKeyUpdate = ctx->isNeedKeyUpdate;
    // 当isNeedKeyUpdate为true时 才返回time和traffic
    if (!isNeedKeyUpdate) {
        CCSEC_LOG_INFO("|SCF_SetKeyAutoUpdateParam|END|returnS|get key update param disable");
        return SCF_SUCCESS;
    }
    keyUpdateTime = ctx->keyUpdateTime;
    keyUpdateTraffic = ctx->keyUpdateTraffic;
    return SCF_SUCCESS;
}

int32_t SCF_GetKeyUpdateInfo(
    SCF_PolicyObj *obj, uint64_t *lastKeyUpdateTime, uint32_t *timeInterval, uint64_t *remainTraffic)
{
    CCSEC_LOG_DEBUG("|SCF_GetKeyUpdateInfo|START|||SCF_GetKeyUpdateInfo start.");
    if (obj == nullptr || obj->policyCtx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetKeyUpdateInfo|END|returnF||obj or policyCtx is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (lastKeyUpdateTime == nullptr || timeInterval == nullptr || remainTraffic == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetKeyUpdateInfo|END|returnF||invalid input param");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_GetKeyUpdateInfo");

    *lastKeyUpdateTime = obj->keyUpdateInfo.lastKeyUpdateTime;
    *timeInterval = obj->policyCtx->keyUpdateTime;
    *remainTraffic = obj->policyCtx->keyUpdateTraffic > obj->keyUpdateInfo.totalSizeOfWriteData
                         ? obj->policyCtx->keyUpdateTraffic - obj->keyUpdateInfo.totalSizeOfWriteData
                         : 0;
    return SCF_SUCCESS;
}

int32_t SCF_ObjKeyUpdate(SCF_PolicyObj *obj)
{
    CCSEC_LOG_DEBUG("|SCF_ObjKeyUpdate|START|||obj key update start");
    if (obj == nullptr) {
        CCSEC_LOG_ERROR("|SCF_ObjKeyUpdate|END|returnF||obj is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_SetKeyUpdateParam");
    CHECK_SCF_ADAPTOR_RET("SCF_SetKeyUpdateParam");
    timeval sysTime{};
    if (gettimeofday(&sysTime, nullptr) != 0) {
        CCSEC_LOG_ERROR("|SCF_ObjKeyUpdate|END|returnF||System time error");
        return SCF_ERRNO_SYSTEM_TIME_ERROR;
    }
    obj->keyUpdateInfo.totalSizeOfWriteData = 0;
    obj->keyUpdateInfo.lastKeyUpdateTime = static_cast<uint64_t>(sysTime.tv_sec);
    int32_t ret = g_adaptor->KeyUpdate(obj, KeyUpdateType::KEY_UPDATE_NOT_REQUESTED);
    obj->keyUpdateInfo.isLastUpdateSuccess = ret == SCF_SUCCESS;
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_ObjKeyUpdate|END|returnF||obj key update failed, ret:"
            << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }
    obj->keyUpdateInfo.totalKeyUpdateCnt += 1;
    return SCF_SUCCESS;
}
}