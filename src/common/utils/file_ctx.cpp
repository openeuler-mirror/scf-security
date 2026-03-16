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

#include <fstream>
#include <filesystem>
#include "securec.h"
#include "scf_errno.h"
#include "scf_inner.h"

namespace scf {

int32_t ReadFileContent(const std::string &path, std::string &content)
{
    if (!SCF_CheckFilePathAndStat(path)) {
        return SCF_ERROR;
    }
    std::ifstream file(path);
    if (!file.is_open()) {
        return SCF_ERROR;
    }
    std::ostringstream fileContent;
    fileContent << file.rdbuf();
    content = fileContent.str();
    file.close();
    return SCF_SUCCESS;
}
} // namespace scf