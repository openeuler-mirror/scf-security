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
#include "scf_errno.h"
#include "scf_inner.h"
#include "custom_logger.h"

namespace scf {
    int32_t SCF_Connect(SCF_PolicyObj *obj)
    {
        CCSEC_LOG_DEBUG("|SCF_Connect|START|||SCF_Connect start.");
        if (obj == nullptr || obj->role == SCF_ROLE_NONE) {
            CCSEC_LOG_ERROR("|SCF_Connect|END|returnF||obj is nullptr or invalid role.");
            return SCF_ERRNO_NULL_INPUT;
        }
        CHECK_SCF_INIT_RET("SCF_Connect");
        CHECK_SCF_ADAPTOR_RET("SCF_Connect");
        int32_t ret = g_adaptor->Connect(obj);
        if (ret == SCF_SSL_ERR_WANT_WRITE || ret == SCF_SSL_ERR_WANT_READ) {
            // 此接口返回SCF_SSL_ERR_WANT_READ SCF_SSL_ERR_WANT_WRITE为合理错误场景，
            // 需要产品重试。读写接口本身为高频场景，经和下游产品讨论，不做日志打印，由错误码表达场景即可。
            return ret;
        }
        if (ret != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("|SCF_Connect|END|returnF||SCF_Connect failed, ret:" <<
                ret << ". ret msg: " << GetErrorMessage(ret));
        }
        return ret;
    }

    int32_t SCF_Accept(SCF_PolicyObj *obj)
    {
        CCSEC_LOG_DEBUG("|SCF_Accept|START|||SCF_Accept start.");
        if (obj == nullptr || obj->role == SCF_ROLE_NONE) {
            CCSEC_LOG_ERROR("|SCF_Accept|END|returnF||obj is nullptr or invalid role.");
            return SCF_ERRNO_NULL_INPUT;
        }
        CHECK_SCF_INIT_RET("SCF_Accept");
        CHECK_SCF_ADAPTOR_RET("SCF_Accept");
        int32_t ret = g_adaptor->Accept(obj);
        if (ret == SCF_SSL_ERR_WANT_WRITE || ret == SCF_SSL_ERR_WANT_READ) {
            // 此接口返回SCF_SSL_ERR_WANT_READ SCF_SSL_ERR_WANT_WRITE为合理错误场景，
            // 需要产品重试。读写接口本身为高频场景，经和下游产品讨论，不做日志打印，由错误码表达场景即可。
            return ret;
        }
        if (ret != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("|SCF_Accept|END|returnF||SCF_Accept failed, ret:" <<
                ret << ". ret msg: " << GetErrorMessage(ret));
        }
        return ret;
    }

    int32_t SCF_Close(SCF_PolicyObj *obj)
    {
        CCSEC_LOG_DEBUG("|SCF_Close|START|||SCF_Close start.");
        if (obj == nullptr || obj->sslCtx == nullptr) {
            return SCF_SUCCESS; // 视为已经关闭成功
        }
        CHECK_SCF_INIT_RET("SCF_Close");
        CHECK_SCF_ADAPTOR_RET("SCF_Close");
        int32_t ret = g_adaptor->Close(obj);
        if (ret != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("|SCF_Close|END|returnF||SCF_Close failed, ret:" <<
                ret << ". ret msg: " << GetErrorMessage(ret));
        }
        return ret;
    }

    int32_t SCF_Read(SCF_PolicyObj *obj, uint8_t *data, uint32_t dataLen, uint32_t *readLen)
    {
        if (obj == nullptr || data == nullptr || dataLen == 0 || readLen == nullptr) {
            CCSEC_LOG_ERROR("|SCF_Read|END|returnF||obj or data or readLen is nullptr or dataLen is 0.");
            return SCF_ERRNO_INVALID_PARAM;
        }
        if (obj->role == SCF_ROLE_NONE) {
            CCSEC_LOG_ERROR("|SCF_Read|END|returnF||invalid role.");
            return SCF_ERRNO_INVALID_PARAM;
        }
        CHECK_SCF_INIT_RET("SCF_Read");
        CHECK_SCF_ADAPTOR_RET("SCF_Read");
        int32_t ret = g_adaptor->Read(obj, data, dataLen, readLen);
        if (ret == SCF_SSL_ERR_WANT_READ) {
            // 此接口返回SCF_SSL_ERR_WANT_READ为合理错误场景，
            // 需要产品重试。读写接口本身为高频场景，经和下游产品讨论，不做日志打印，由错误码表达场景即可。
            return ret;
        }
        if (ret != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("|SCF_Read|END|returnF||SCF_Read failed, ret:" <<
                ret << ". ret msg: " << GetErrorMessage(ret));
        }
        return ret;
    }

    int32_t SCF_Write(SCF_PolicyObj *obj, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen)
    {
        if (obj == nullptr || data == nullptr || dataLen == 0 || writeLen == nullptr) {
            CCSEC_LOG_ERROR("|SCF_Write|END|returnF||obj or data or writeLen is nullptr or dataLen is 0.");
            return SCF_ERRNO_INVALID_PARAM;
        }
        if (obj->role == SCF_ROLE_NONE) {
            CCSEC_LOG_ERROR("|SCF_Write|END|returnF||invalid role.");
            return SCF_ERRNO_INVALID_PARAM;
        }
        CHECK_SCF_INIT_RET("SCF_Write");
        CHECK_SCF_ADAPTOR_RET("SCF_Write");
        int32_t ret = g_adaptor->Write(obj, data, dataLen, writeLen);
        if (ret == SCF_SSL_ERR_WANT_WRITE) {
            // 此接口返回SCF_SSL_ERR_WANT_WRITE为合理错误场景，
            // 需要产品重试。读写接口本身为高频场景，经和下游产品讨论，不做日志打印，由错误码表达场景即可。
            return ret;
        }
        if (ret != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("|SCF_Write|END|returnF||SCF_Write failed, ret:" << ret
                << ". ret msg: " << GetErrorMessage(ret));
            return ret;
        }
        if (obj->policyCtx != nullptr && obj->policyCtx->isNeedKeyUpdate) {
            bool isNeedKeyUpdate = false;
            ret = CheckNeedKeyUpdate(obj, *writeLen, &isNeedKeyUpdate);
            if (ret == SCF_SUCCESS && isNeedKeyUpdate) {
                CCSEC_LOG_INFO("|SCF_Write|END|returnF||start key update");
                ret = g_adaptor->KeyUpdate(obj, KeyUpdateType::KEY_UPDATE_NOT_REQUESTED);
            }
        }
        return ret;
    }
}
