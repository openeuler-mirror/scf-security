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
#include "scf_errno.h"
#include "scf_inner.h"
#include "scf_ssl.h"
#include "custom_logger.h"
#include "parse_config.h"
#include "securec.h"
#include "constant_def.h"

namespace scf {

int32_t SCF_Init(uint64_t flag, void *settings)
{
    std::lock_guard<std::mutex> lock(g_scfMutex);
    CCSEC_LOG_DEBUG("|SCF_Init|START|||SCF_Init start.");
    if (g_scfInitialized) {
        return SCF_SUCCESS;
    }
    if (flag != SCF_INIT_FLAG_OPENSSL) {
        return SCF_ERRNO_INVALID_PARAM;
    }
    int32_t ret = SCFInitInner(flag, settings);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR(
            "|SCF_Init|END|returnF||SCF_Init failed, ret:" << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }
    g_scfInitialized = true;
    return ret;
}

void SCF_DeInit(void)
{
    std::lock_guard<std::mutex> lock(g_scfMutex);
    CCSEC_LOG_DEBUG("|SCF_DeInit|START|||SCF_DeInit start.");
    if (!g_scfInitialized) {
        return;
    }

    SCFDeInitInner();
    g_scfInitialized = false;
}

void SCF_FreeBuffer(char **buffer, size_t &bufferLen)
{
    CCSEC_LOG_DEBUG("|SCF_FreeBuffer|START|||SCF_FreeBuffer start.");
    if (buffer == nullptr || *buffer == nullptr || bufferLen == 0) {
        CCSEC_LOG_ERROR("|SCF_FreeBuffer|END|returnF||buffer is nullptr.");
        return;
    }
    if (!g_scfInitialized || g_adaptor == nullptr) {
        return;
    }
    g_adaptor->FreeBuffer(buffer, bufferLen);
    *buffer = nullptr;
    bufferLen = 0;
}

SCF_PolicyCtx *SCF_CreatePolicyCtx(void)
{
    CCSEC_LOG_DEBUG("|SCF_CreatePolicyCtx|START|||SCF_CreatePolicyCtx start.");
    CHECK_SCF_INIT_POINTER("SCF_CreatePolicyCtx");
    CHECK_SCF_ADAPTOR_POINTER("SCF_CreatePolicyCtx");
    auto *ctx = new(std::nothrow) SCF_PolicyCtx;
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_CreatePolicyCtx|END|retutnF||new mem fail.");
        return nullptr;
    }
    ctx->refCnt = 1;
    ctx->sslConfig = nullptr;
    ctx->policyMode = SCF_POLICY_HIGH;
    ctx->verifyMode = static_cast<uint32_t>(SCF_VERIFY_DEFAULT);
    ctx->role = SCF_ROLE_NONE;
    ctx->isSetRole = false;
    ctx->pskFindSessionCb = nullptr;
    ctx->pskUseSessionCb = nullptr;
    /* 默认不开，需要用户启用，因为产品存在同一个 fd，报文头用 socket send 发送，body 用 tls 发送的场景
     * 默认开 keyupdate 会导致业务发送一定流量后异常
     */
    ctx->isNeedKeyUpdate = false;
    ctx->keyUpdateTime = DEFAULT_KEY_UPDATE_TIME;
    ctx->keyUpdateTraffic = DEFAULT_KEY_UPDATE_TRAFFIC;
    ctx->isNullVersion = false;
    return ctx;
}

void SCF_FreePolicyCtx(SCF_PolicyCtx **ctx)
{
    CCSEC_LOG_DEBUG("|SCF_FreePolicyCtx|START|||SCF_FreePolicyCtx start.");
    if (ctx == nullptr || *ctx == nullptr) {
        CCSEC_LOG_WARN("|SCF_FreePolicyCtx|END|returnF||null input param");
        return;
    }
    if (!g_scfInitialized || g_adaptor == nullptr) {
        return;
    }
    if ((*ctx)->refCnt > 1) {
        (*ctx)->refCnt--;
        *ctx = nullptr;
        return;
    }

    g_adaptor->FreeSsl(*ctx);
    delete *ctx;
    *ctx = nullptr;
}

int32_t SCF_SetPolicy(SCF_PolicyCtx *ctx, SCF_ROLE role, uint32_t verifyMode, SCF_POLICY_MODE policyMode)
{
    CCSEC_LOG_DEBUG("|SCF_SetPolicy|START|||SCF_SetPolicy start.");
    if (ctx == nullptr || CheckRole(role) != SCF_SUCCESS || CheckVerifyMode(verifyMode) != SCF_SUCCESS ||
        CheckPolicyMode(policyMode) != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_SetPolicy|END|returnF||invalid input param.");
        return SCF_ERRNO_INVALID_PARAM;
    }
    CHECK_SCF_INIT_RET("SCF_SetPolicy");
    CHECK_SCF_ADAPTOR_RET("SCF_SetPolicy");
    ctx->role = role;
    ctx->verifyMode = verifyMode;
    ctx->policyMode = policyMode;
    auto ret = g_adaptor->InitPolicyByMode(ctx);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_SetPolicy|END|returnF||InitPolicyByMode failed, ret:" << ret << ". ret msg: "
            << GetErrorMessage(ret));
        return ret;
    }
    if (verifyMode == SCF_VERIFY_DEFAULT) {
        verifyMode = SCF_VERIFY_PEER | SCF_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
    ret = g_adaptor->SetVerifyMode(ctx, verifyMode);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_SetPolicy|END|returnF||SetVerifyMode failed, ret:" << ret << ". ret msg: "
            << GetErrorMessage(ret));
        return ret;
    }
    return SCF_SUCCESS;
}

int32_t SCF_GetPolicy(SCF_PolicyCtx *ctx, SCF_ROLE *role, uint32_t *verifyMode, SCF_POLICY_MODE *policyMode)
{
    CCSEC_LOG_DEBUG("|SCF_GetPolicy|START|||start to get policy.");
    if (ctx == nullptr || role == nullptr || verifyMode == nullptr || policyMode == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetPolicy|END|returnF||get policy failed, policy ctx is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    *verifyMode = ctx->verifyMode;
    *policyMode = ctx->policyMode;
    *role = ctx->role;
    CCSEC_LOG_DEBUG("|SCF_GetPolicy|END|returnS||get policy success .");
    return SCF_SUCCESS;
}

int32_t SCF_SetAppVerifyCallback(SCF_PolicyCtx *ctx, SCF_AppVerifyFunc cb, void *arg)
{
    CCSEC_LOG_DEBUG("|SCF_SetAppVerifyCallback|START|||SCF_SetAppVerifyCallback start.");
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SetAppVerifyCallback|END|returnF||ctx is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (ctx->role == SCF_ROLE_NONE) {
        CCSEC_LOG_ERROR("|SCF_SetAppVerifyCallback|END|returnF||role is wrong");
        return SCF_ERRNO_INVALID_PARAM;
    }
    CHECK_SCF_INIT_RET("SCF_SetAppVerifyCallback");
    if (ctx->policyMode != SCF_POLICY_CUSTOMER || (ctx->verifyMode & SCF_VERIFY_CUSTOMER) == 0) {
        CCSEC_LOG_ERROR("|SCF_SetAppVerifyCallback|END|returnF||SetAppVerifyCallback mode mismatch.");
        return SCF_SSL_ERR_SEC_LEVEL_MISMATCH;
    }
    CHECK_SCF_ADAPTOR_RET("SCF_SetAppVerifyCallback");
    int32_t ret = g_adaptor->SetAppVerifyCallback(ctx, cb, arg);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_SetAppVerifyCallback|END|returnF||SetAppVerifyCallback failed, ret:"
            << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }
    return SCF_SUCCESS;
}

int32_t SCF_SetCipherSuites(SCF_PolicyCtx *ctx, const uint16_t *cipherSuites, uint32_t cipherSuitesSize)
{
    CCSEC_LOG_DEBUG("|SCF_SetCipherSuites|START|||SCF_SetCipherSuites start.");
    if (ctx == nullptr || cipherSuites == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SetCipherSuites|END|returnF||ctx or cipherSuites is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (cipherSuitesSize == 0) {
        CCSEC_LOG_ERROR("|SCF_SetCipherSuites|END|returnF||cipherSuitesSize length is 0");
        return SCF_ERRNO_INVALID_PARAM;
    }
    if (ctx->role == SCF_ROLE_NONE) {
        // 未配置策略类型
        CCSEC_LOG_ERROR("|SCF_SetCipherSuites|END|returnF||role is none.");
        return SCF_ERRNO_INVALID_PARAM;
    }
    CHECK_SCF_INIT_RET("SCF_SetCipherSuites");
    CHECK_SCF_ADAPTOR_RET("SCF_SetCipherSuites");
    int32_t ret = g_adaptor->SetCipherSuites(ctx, cipherSuites, cipherSuitesSize);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_SetCipherSuites|END|returnF||SCF_SetCipherSuites failed, ret:"
            << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }
    return SCF_SUCCESS;
}

int32_t SCF_GetCipherSuites(SCF_PolicyCtx *ctx, uint16_t *data, uint32_t dataLen, uint32_t *cipherSuitesSize)
{
    CCSEC_LOG_DEBUG("|SCF_GetCipherSuites|START|||SCF_GetCipherSuites start.");
    if (ctx == nullptr || data == nullptr || dataLen == 0 || cipherSuitesSize == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetCipherSuites|END|returnF||get policy failed, invalid input param");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_GetCipherSuites");
    CHECK_SCF_ADAPTOR_RET("SCF_GetCipherSuites");
    int32_t ret = g_adaptor->GetCipherSuites(ctx, data, dataLen, cipherSuitesSize);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_GetCipherSuites|END|returnF||SCF_GetCipherSuites failed, ret:"
            << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }
    return ret;
}

int32_t SCF_SetProtocolVersion(
    SCF_PolicyCtx *ctx, uint32_t minVersion, uint32_t maxVersion, uint32_t *forbidVersion, uint32_t forbidVersionLen)
{
    CCSEC_LOG_DEBUG("|SCF_SetProtocolVersion|START|||SCF_SetProtocolVersion start.");
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SetProtocolVersion|END|returnF||ctx is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (ctx->role == SCF_ROLE_NONE) {
        // 未配置策略类型
        CCSEC_LOG_ERROR("|SCF_SetProtocolVersion|END|returnF||role is none.");
        return SCF_ERRNO_INVALID_PARAM;
    }
    if (ctx->policyMode == SCF_POLICY_HIGH) {
        if (minVersion != SCF_SSL_VERSION_TLS13 || maxVersion != SCF_SSL_VERSION_TLS13) {
            CCSEC_LOG_ERROR("|SCF_SetProtocolVersion|END|returnF||only tls13 supported when policy high.");
            return SCF_SSL_ERR_POLICY_VERSION;
        }
    }
    CHECK_SCF_INIT_RET("SCF_SetProtocolVersion");
    CHECK_SCF_ADAPTOR_RET("SCF_SetProtocolVersion");
    int32_t ret = g_adaptor->SetProtocolVersion(ctx, minVersion, maxVersion, forbidVersion, forbidVersionLen);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_SetProtocolVersion|END|returnF||SetProtocolVersion failed, ret:"
            << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }
    return SCF_SUCCESS;
}

const char *SCF_GetProtocolVersion(SCF_PolicyObj *obj)
{
    CCSEC_LOG_DEBUG("|SCF_GetProtocolVersion|START|||SCF_GetProtocolVersion start.");
    if (obj == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetProtocolVersion|END|returnF||obj is nullptr");
        return nullptr;
    }
    CHECK_SCF_INIT_POINTER("SCF_GetProtocolVersion");
    CHECK_SCF_ADAPTOR_POINTER("SCF_GetProtocolVersion");
    const char *ptr = g_adaptor->GetVersion(obj);
    if (ptr == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetProtocolVersion|END|returnF||GetVersion failed.");
    }
    return ptr;
}
}