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

#ifndef DLOPEN_LIB_BASE_H
#define DLOPEN_LIB_BASE_H

#include <dlfcn.h>
#include <iostream>
#include <cstdarg>
#include <functional>
#include <memory>
#include <numeric>
#include <stdexcept>
#include <string_view>
#include "custom_logger.h"
#include "scf_errno.h"

namespace scf {
template <typename... Args> std::string MakeString(Args... args)
{
    std::ostringstream oss;
    (oss << ... << args);
    return oss.str();
}

template <class R, class... Args> class DlFun {
public:
    using FunTy = R (*)(Args...);

    DlFun() = default;

    void Reset()
    {
        funptr_ = nullptr;
    }

    DlFun(std::string_view name, FunTy funptr)
        : funName_(name),
          funptr_(funptr)
    {
    }

    std::function<R(Args...)> Get() const
    {
        return funptr_;
    }

    std::string GetName() const
    {
        return funName_;
    }

    R operator()(Args... args)
    {
        if (funptr_ == nullptr) {
            throw std::runtime_error(MakeString("[", __FILE__ ":", __LINE__, "] Fatal Error: function ", funName_,
                " is nullptr, maybe previous dlsym failed."));
        }
        return funptr_(std::forward<Args>(args)...);
    }

private:
    std::string funName_ = "unknown";            // default to unknown
    std::function<R(Args...)> funptr_ = nullptr; // default to nullptr
};

// Dynamic-load Lib base class
class DlOpenLibBase {
public:
    virtual uint32_t Init(const std::string &libPath);

    virtual void UnInit();

protected:
    DlOpenLibBase() = default;

    virtual ~DlOpenLibBase();

    uint32_t SelfDlOpen(const std::string &libPath, int mode = RTLD_NOW | RTLD_GLOBAL);

    void SelfDlClose();

    template <class R, class... Args> uint32_t SelfDlSym(const std::string &funName, DlFun<R, Args...> &outFun)
    {
        if (libptr_ == nullptr || funName.empty()) {
            return SCF_ERRNO_LOAD_SYMBOL;
        }

        void *funPtr = dlsym(libptr_, funName.c_str());
        if (funPtr == nullptr) {
            std::cerr << "dlsym failed for " << funName << ": " << dlerror() << '\n';
            return SCF_ERRNO_LOAD_SYMBOL;
        }
        funCache_.push_back(funPtr); // the failed funPtr also get writed in funCache_, we check nullptr later
        outFun = DlFun<R, Args...>(funName, reinterpret_cast<R (*)(Args...)>(funPtr));
        return SCF_SUCCESS;
    }

    uint32_t CheckFunCache();

    size_t GetFunCacheSize();

private:
    void *libptr_ = nullptr;

    std::vector<void *> funCache_{};
};

// The second argument is the templateHelper which helps template deduction
#define CONNECTOR_SELF_DLSYM(NAME) SelfDlSym(#NAME, NAME)
} // namespace scf

#endif