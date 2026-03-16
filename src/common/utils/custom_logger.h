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

#ifndef CUSTOM_LOGGER_H
#define CUSTOM_LOGGER_H
#pragma once

#include <cstdio>
#include <cstring>
#include <functional>
#include <sstream>
#include "scf_def.h"

#ifndef CCSEC_LIKELY
#define CCSEC_LIKELY(x) (__builtin_expect(!!(x), 1) != 0)
#endif

#ifndef CCSEC_UNLIKELY
#define CCSEC_UNLIKELY(x) (__builtin_expect(!!(x), 0) != 0)
#endif

namespace scf {

const int STDOUT_TYPE = 0;
const int FILE_TYPE = 1;

class Logger {
public:
    using ExternalLogFunction = void (*)(int level, const char *msg);

    static Logger *Instance();

    inline void SetExternalLogFunction(ExternalLogFunction func)
    {
        if (func == nullptr) {
            log_function_ = nullptr;
            return;
        }

        log_function_ = *func;
    }

    void Log(int level, const std::ostringstream &oss) const;

    Logger(const Logger &) = delete;
    Logger(Logger &&) = delete;
    Logger &operator=(const Logger &) = delete;
    Logger &operator=(Logger &&) = delete;

    ~Logger()
    {
        log_function_ = nullptr;
    }

private:
    Logger() = default;

    std::function<void(int, const char *)> log_function_ = nullptr;
};

}  // namespace scf

// macro for log
#ifndef CCSEC_LOG_FILENAME
#define CCSEC_LOG_FILENAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

// define our logger
#define CCSEC_LOG(level, args)                                                     \
    do {                                                                           \
        std::ostringstream oss;                                                    \
        oss << "[CCSEC " << CCSEC_LOG_FILENAME << ":" << __LINE__ << "] " << args; \
        auto logger = ::scf::Logger::Instance();                  \
        if (logger != nullptr) {                                                   \
            logger->Log(level, oss);                                               \
        }                                                                          \
    } while (0)
#define CCSEC_LOG_TRACE(args) CCSEC_LOG(static_cast<int>(::scf::LOG_LEVEL::LOG_LEVEL_TRACE), args)
#define CCSEC_LOG_DEBUG(args) CCSEC_LOG(static_cast<int>(::scf::LOG_LEVEL::LOG_LEVEL_DEBUG), args)
#define CCSEC_LOG_INFO(args) CCSEC_LOG(static_cast<int>(::scf::LOG_LEVEL::LOG_LEVEL_INFO), args)
#define CCSEC_LOG_WARN(args) CCSEC_LOG(static_cast<int>(::scf::LOG_LEVEL::LOG_LEVEL_WARN), args)
#define CCSEC_LOG_ERROR(args) CCSEC_LOG(static_cast<int>(::scf::LOG_LEVEL::LOG_LEVEL_ERROR), args)

#define CCSEC_ASSERT_LOG_RETURN(args, ret)   \
    if (CCSEC_UNLIKELY(!(args))) {           \
        CCSEC_LOG_ERROR("Assert " << #args); \
        return (ret);                        \
    }

#define CCSEC_ASSERT_LOG_RETURN_VOID(args)   \
    if (CCSEC_UNLIKELY(!(args))) {           \
        CCSEC_LOG_ERROR("Assert " << #args); \
        return;                              \
    }

#endif