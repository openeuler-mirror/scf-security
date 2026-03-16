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

#include "custom_logger.h"
#include "securec.h"
#include "scf.h"
#include "scf_def.h"
#include "scf_errno.h"
#include "scf_inner.h"

namespace scf {

int32_t SCF_AddCert(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx, SCF_CERT_TYPE type)
{
    CCSEC_LOG_DEBUG("|SCF_AddCert|START|||SCF_AddCert start.");
    // SCF_FileCtxSetBuf时会校验fileCtx，因此在使用的时候无需校验内容，判空即可
    if (ctx == nullptr || certCtx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_AddCert|END|returnF||ctx or certCtx is nullptr.");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (ctx->role == SCF_ROLE_NONE) { // 未配置策略类型
        CCSEC_LOG_ERROR("|SCF_AddCert|END|returnF||role is wrong.");
        return SCF_ERRNO_INVALID_PARAM;
    }
    CHECK_SCF_INIT_RET("SCF_AddCert");
    CHECK_SCF_ADAPTOR_RET("SCF_AddCert");
    int32_t ret = g_adaptor->AddCert(ctx, certCtx, type);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR(
            "|SCF_AddCert|END|returnF||AddCert failed, ret:" << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }
    return SCF_SUCCESS;
}

int32_t SCF_SetKey(SCF_PolicyCtx *ctx, SCF_FILE_CTX *keyCtx)
{
    CCSEC_LOG_DEBUG("|SCF_SetKey|START|||SCF_SetKey start.");
    // SCF_FileCtxSetBuf时会校验fileCtx，因此在使用的时候无需校验内容，判空即可
    if (ctx == nullptr || keyCtx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SetKey|END|returnF||ctx or keyCtx is nullptr.");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_SetKey");
    CHECK_SCF_ADAPTOR_RET("SCF_SetKey");
    int32_t ret = g_adaptor->SetKey(ctx, keyCtx);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR(
            "|SCF_SetKey|END|returnF||SetKey failed, ret:" << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }

    return SCF_SUCCESS;
}

int32_t SCF_CheckPrivateKey(SCF_PolicyCtx *ctx)
{
    CCSEC_LOG_DEBUG("|SCF_CheckPrivateKey|START|||SCF_CheckPrivateKey start.");
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_CheckPrivateKey|END|returnF||ctx is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_CheckPrivateKey");
    CHECK_SCF_ADAPTOR_RET("SCF_CheckPrivateKey");
    int32_t ret = g_adaptor->CheckPrivateKey(ctx);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_CheckPrivateKey|END|returnF||CheckPrivateKey failed, ret:"
            << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }

    return SCF_SUCCESS;
}

int32_t SCF_GetCertVersion(const void *cert)
{
    CCSEC_LOG_DEBUG("|SCF_GetCertVersion|START|||SCF_GetCertVersion start.");
    if (cert == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetCertVersion|END|returnF||cert is nullptr");
        return -1;
    }
    if (!g_scfInitialized || g_adaptor == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetCertVersion|END|returnF||not init or g_adaptor is nullptr");
        return -1;
    }
    return g_adaptor->GetCertVersion(cert);
}

int32_t SCF_GetCertStartTime(const void *cert, char *certStartTimeBuffer, size_t bufferLen)
{
    CCSEC_LOG_DEBUG("|SCF_GetCertStartTime|START|||SCF_GetCertStartTime start.");
    if (cert == nullptr || certStartTimeBuffer == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetCertStartTime|END|returnF||invalid input param");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (bufferLen == 0) {
        CCSEC_LOG_ERROR("|SCF_GetCertStartTime|END|returnF||bufferLen is 0");
        return SCF_ERROR;
    }
    CHECK_SCF_INIT_RET("SCF_GetCertStartTime");
    CHECK_SCF_ADAPTOR_RET("SCF_GetCertStartTime");
    char *datetime = g_adaptor->GetCertStartTime(cert);
    if (datetime == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetCertStartTime|END|returnF|get cert start time returned null ptr");
        return SCF_ERROR;
    }
    auto datetimeLen = strlen(datetime);
    if (datetimeLen >= bufferLen) {
        CCSEC_LOG_ERROR("|SCF_GetCertStartTime|END|returnF||certStartTimeBuffer length too short");
        delete []datetime;
        return SCF_ERROR;
    }

    auto ret = memcpy_s(certStartTimeBuffer, bufferLen, datetime, datetimeLen);
    delete []datetime;
    if (ret != EOK) {
        CCSEC_LOG_ERROR("|SCF_GetCertStartTime|END|returnF||memcpy_s failed, ret = " << ret);
        return SCF_ERROR;
    }
    certStartTimeBuffer[datetimeLen] = '\0';
    return SCF_SUCCESS;
}

int32_t SCF_GetCertEndTime(const void *cert, char *certEndTimeBuffer, size_t bufferLen)
{
    CCSEC_LOG_DEBUG("|SCF_GetCertEndTime|START|||SCF_GetCertEndTime start.");
    if (cert == nullptr || certEndTimeBuffer == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetCertEndTime|END|returnF||invalid input param");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (bufferLen == 0) {
        CCSEC_LOG_ERROR("|SCF_GetCertEndTime|END|returnF||bufferLen is 0");
        return SCF_ERROR;
    }
    CHECK_SCF_INIT_RET("SCF_GetCertEndTime");
    CHECK_SCF_ADAPTOR_RET("SCF_GetCertEndTime");
    char *datetime = g_adaptor->GetCertEndTime(cert);
    if (datetime == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetCertEndTime|END|returnF|get cert end time returned null ptr");
        return SCF_ERROR;
    }
    auto datetimeLen = strlen(datetime);
    if (datetimeLen >= bufferLen) {
        CCSEC_LOG_ERROR("|SCF_GetCertEndTime|END|returnF||certEndTimeBuffer length too short");
        delete []datetime;
        return SCF_ERROR;
    }

    auto ret = memcpy_s(certEndTimeBuffer, bufferLen, datetime, datetimeLen);
    delete []datetime;
    if (ret != EOK) {
        CCSEC_LOG_ERROR("|SCF_GetCertEndTime|END|returnF||memcpy_s failed, ret = " << ret);
        return SCF_ERROR;
    }
    certEndTimeBuffer[datetimeLen] = '\0';
    return SCF_SUCCESS;
}

uint8_t *SCF_GetCertSerialNumber(const void *cert, uint32_t *dataLen)
{
    CCSEC_LOG_DEBUG("|SCF_GetCertSerialNumber|START|||SCF_GetCertSerialNumber start.");
    if (cert == nullptr || dataLen == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetCertSerialNumber|END|returnF||invalid input param, cert or dataLen is nullptr");
        return nullptr;
    }
    CHECK_SCF_INIT_POINTER("SCF_GetCertSerialNumber");
    CHECK_SCF_ADAPTOR_POINTER("SCF_GetCertSerialNumber");
    return g_adaptor->GetCertSerialNumber(cert, dataLen);
}
}