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

#include <iostream>
#include "scf.h"
#include "custom_logger.h"

namespace scf {
void SetExternalLogFunction(ExternalLogFunction func)
{
    CCSEC_LOG_INFO("|SetExternalLogFunction|START|||set external log function");
    auto *logger = scf::Logger::Instance();
    if (logger == nullptr) {
        std::cerr << "|SetExternalLogFunction|END|returnF||null logger ptr\n";
        return;
    }
    logger->SetExternalLogFunction(func);
}
}