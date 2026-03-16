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
#include "openssl_adaptor.h"

namespace scf {

static bool g_isTlsInit = false;
AbstractTLSAdaptor *g_adaptor = nullptr;
static OpenSSLAdapter g_opensslAdaptor;

static int32_t RegisterTlsAdaptor(const uint64_t &flag, const void *settings)
{
    if (g_isTlsInit) {
        return SCF_ERRNO_TLS_ALREADY_INIT;
    }
    if (flag == SCF_INIT_FLAG_OPENSSL) {
        auto ret = g_opensslAdaptor.Init(flag, settings);
        if (ret != SCF_SUCCESS) {
            return ret;
        }
        g_isTlsInit = true;

        g_adaptor = &g_opensslAdaptor;
        return SCF_SUCCESS;
    }
    return SCF_ERRNO_INVALID_PARAM;
}

static void UnRegisterTlsAdaptor()
{
    if (!g_isTlsInit || g_adaptor == nullptr) {
        return;
    }
    g_adaptor->DeInit();
    g_adaptor = nullptr;
    g_isTlsInit = false;
}

int32_t SCFInitInner(const uint64_t &flag, const void *settings)
{
    if (g_scfInitialized) {
        return SCF_SUCCESS;
    }

    if (auto ret = RegisterTlsAdaptor(flag, settings); ret != SCF_SUCCESS) {
        return ret;
    }
    g_scfInitialized = true;
    return SCF_SUCCESS;
}

void SCFDeInitInner()
{
    if (!g_scfInitialized) {
        return;
    }

    UnRegisterTlsAdaptor();
    g_scfInitialized = false;
}
}