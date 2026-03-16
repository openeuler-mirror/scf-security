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

#include "dlopen_lib_base.h"
#include "scf_inner.h"
#include "securec.h"

namespace scf {
DlOpenLibBase::~DlOpenLibBase()
{
    SelfDlClose();
}

uint32_t DlOpenLibBase::Init([[maybe_unused]]const std::string &libPath)
{
    return SCF_SUCCESS;
}

void DlOpenLibBase::UnInit()
{
}

void DlOpenLibBase::SelfDlClose()
{
    if (!funCache_.empty()) {
        funCache_.clear();
    }
    if (libptr_ != nullptr) {
        dlclose(libptr_);
        libptr_ = nullptr;
    }
}

uint32_t DlOpenLibBase::SelfDlOpen(const std::string &libPath, int mode)
{
    if (!SCF_CheckFilePathAndStat(libPath)) {
        CCSEC_LOG_ERROR("dlopen failed, lib path check error.");
        return SCF_ERRNO_LOAD_LIB;
    }
    libptr_ = dlopen(libPath.c_str(), mode);
    if (libptr_ == nullptr) {
        CCSEC_LOG_ERROR("dlopen failed: " << dlerror());
        return SCF_ERRNO_LOAD_LIB;
    }
    return SCF_SUCCESS;
}

uint32_t DlOpenLibBase::CheckFunCache()
{
    for (auto *p : funCache_) {
        if (p == nullptr) {
            return SCF_ERRNO_LOAD_LIB;
        }
    }
    return SCF_SUCCESS;
}

size_t DlOpenLibBase::GetFunCacheSize()
{
    return funCache_.size();
}

} // namespace scf