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

#include "scf.h"
#include "scf_ssl.h"

#include "custom_logger.h"
#include "scf_inner.h"
#include "scf_errno.h"
#include "securec.h"

namespace scf {
SCF_PolicyObj *SCF_CreatePolicyObj(SCF_PolicyCtx *ctx)
{
    CCSEC_LOG_DEBUG("|SCF_CreatePolicyObj|START|||SCF_CreatePolicyObj start.");
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_CreatePolicyObj|END|returnF||ctx is nullptr");
        return nullptr;
    }
    CHECK_SCF_INIT_POINTER("SCF_CreatePolicyObj");
    timeval sysTime{};

    if (gettimeofday(&sysTime, nullptr) != 0) {
        return nullptr;
    }
    auto *obj = new(std::nothrow) SCF_PolicyObj;
    if (obj == nullptr || memset_s(obj, sizeof(SCF_PolicyObj), 0, sizeof(SCF_PolicyObj)) != EOK) {
        CCSEC_LOG_ERROR("|SCF_CreatePolicyObj|END|returnF||init ctx fail, memset_s fail.");
        delete obj;
        return nullptr;
    }
    obj->policyCtx = ctx;
    ctx->refCnt++;

    obj->policyMode = ctx->policyMode;
    obj->verifyMode = static_cast<SCF_VERIFY_MODE>(ctx->verifyMode);
    obj->role = ctx->role;
    obj->isSetRole = ctx->isSetRole;
    obj->fd = -1; // -1 是无效值。0 是 stdin 是合法值。
    obj->pskFindSessionCb = ctx->pskFindSessionCb;
    obj->pskUseSessionCb = ctx->pskUseSessionCb;
    // updateInfo
    obj->keyUpdateInfo.timeInterval = ctx->keyUpdateTime;
    obj->keyUpdateInfo.trafficThreshold = ctx->keyUpdateTraffic;
    obj->keyUpdateInfo.totalSizeOfWriteData = 0;
    obj->keyUpdateInfo.lastKeyUpdateTime = static_cast<uint64_t>(sysTime.tv_sec);
    obj->keyUpdateInfo.totalKeyUpdateCnt = 0;
    obj->keyUpdateInfo.isLastUpdateSuccess = true;
    return obj;
}

int32_t SCF_SetFd(SCF_PolicyObj *obj, int32_t fd)
{
    CCSEC_LOG_DEBUG("|SCF_SetFd|START|||SCF_SetFd start.");
    CHECK_SCF_INIT_RET("SCF_SetFd");
    CHECK_SCF_ADAPTOR_RET("SCF_SetFd");
    if (obj == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SetFd|END|returnF||obj is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (obj->role == SCF_ROLE_NONE || fd < 0) {
        CCSEC_LOG_ERROR("|SCF_SetFd|END|returnF||fd or role is invalid, fd:" << fd << ", role" << obj->role);
        return SCF_ERRNO_INVALID_PARAM;
    }
    int32_t ret = g_adaptor->SetFd(obj, fd);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR(
            "|SCF_SetFd|END|returnF||SCF_SetFd failed, ret:" << ret << ". ret msg: " << GetErrorMessage(ret));
    }
    return ret;
}

void SCF_FreePolicyObj(SCF_PolicyObj **obj)
{
    CCSEC_LOG_DEBUG("|SCF_FreePolicyObj|START|||SCF_FreePolicyObj start.");
    if (obj == nullptr || *obj == nullptr) {
        CCSEC_LOG_WARN("|SCF_FreePolicyObj|END|returnF||obj is nullptr");
        return;
    }
    if (!g_scfInitialized || g_adaptor == nullptr) {
        return;
    }
    // 释放引用的 ctx 对象
    SCF_FreePolicyCtx(&(*obj)->policyCtx);
    // 释放ssl对象
    g_adaptor->FreeSslObj(*obj);
    // 释放obj
    delete *obj;
    *obj = nullptr;
}

void *SCF_GetCurrentCert(SCF_PolicyObj *obj)
{
    CCSEC_LOG_DEBUG("|SCF_GetCurrentCert|START|||SCF_GetCurrentCert start.");
    if (obj == nullptr) {
        CCSEC_LOG_WARN("|SCF_GetCurrentCert|END|||obj is nullptr.");
        return nullptr;
    }
    CHECK_SCF_INIT_POINTER("SCF_GetCurrentCert");
    CHECK_SCF_ADAPTOR_POINTER("SCF_GetCurrentCert");
    return g_adaptor->GetCurrentCert(obj);
}

void *SCF_GetPeerCert(SCF_PolicyObj *obj)
{
    if (obj == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetPeerCert|END|returnF||obj is nullptr");
        return nullptr;
    }
    CCSEC_LOG_DEBUG("|SCF_GetPeerCert|START|||SCF_GetPeerCert start.");
    CHECK_SCF_INIT_POINTER("SCF_GetPeerCert");
    CHECK_SCF_ADAPTOR_POINTER("SCF_GetPeerCert");
    return g_adaptor->GetPeerCert(obj);
}

void SCF_FreeCert(void **cert)
{
    CCSEC_LOG_DEBUG("|SCF_FreeCert|START|||SCF_FreeCert start.");
    if (cert == nullptr || *cert == nullptr) {
        CCSEC_LOG_WARN("|SCF_FreeCert|END|||cert is nullptr.");
        return;
    }
    if (!g_scfInitialized || g_adaptor == nullptr) {
        return;
    }
    g_adaptor->FreeCert(*cert);
    *cert = nullptr;
}

int32_t SCF_SetUserData(SCF_PolicyObj *obj, void *userData)
{
    CCSEC_LOG_DEBUG("|SCF_SetUserData|START|||SCF_SetUserData start");
    if (obj == nullptr || userData == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SetUserData|END|returnF||obj or userData is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_SetUserData");
    obj->userData = userData;
    return SCF_SUCCESS;
}

void *SCF_GetUserData(SCF_PolicyObj *obj)
{
    CCSEC_LOG_DEBUG("|SCF_GetUserData start|||SCF_GetUserData start");
    if (obj == nullptr) {
        CCSEC_LOG_WARN("|SCF_GetUserData|END|||obj is nullptr");
        return nullptr;
    }
    return obj->userData;
}
}