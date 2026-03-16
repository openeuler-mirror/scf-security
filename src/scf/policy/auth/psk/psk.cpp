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
#include "scf_def.h"
#include "scf_errno.h"
#include "scf.h"
#include "scf_inner.h"
#include "custom_logger.h"

namespace scf {
int32_t SCF_SetPskFindSessionCallback(SCF_PolicyCtx *ctx, SCF_PskFindSessionCb cb)
{
    CCSEC_LOG_DEBUG("|SCF_SetPskFindSessionCallback|START|||SCF_SetPskFindSessionCallback start.");
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SetPskFindSessionCallback|END|returnF||ctx is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_SetPskFindSessionCallback");
    CHECK_SCF_ADAPTOR_RET("SCF_SetPskFindSessionCallback");
    int32_t ret = g_adaptor->SetPskFindSessionCallback(ctx, cb);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_SetPskFindSessionCallback|END|returnF||SCF_SetPskFindSessionCallback failed, ret:"
            << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }

    return SCF_SUCCESS;
}

int32_t SCF_SetPskUseSessionCallback(SCF_PolicyCtx *ctx, SCF_PskUseSessionCb cb)
{
    CCSEC_LOG_DEBUG("|SCF_SetPskUseSessionCallback|START|||SCF_SetPskUseSessionCallback start.");
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SetPskUseSessionCallback|END|returnF||ctx is nullptr");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_SetPskUseSessionCallback");
    CHECK_SCF_ADAPTOR_RET("SCF_SetPskUseSessionCallback");
    int32_t ret = g_adaptor->SetPskUseSessionCallback(ctx, cb);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_SetPskUseSessionCallback|END|returnF||SCF_SetPskUseSessionCallback failed, ret:"
            << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }

    return SCF_SUCCESS;
}
}