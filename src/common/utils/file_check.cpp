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

#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include "scf_inner.h"

namespace scf {

bool Exist(const std::string &path, int type)
{
    return access(path.c_str(), type) != -1;
}

bool CanonicalPath(std::string &path)
{
    if (path.empty() || path.size() > PATH_MAX) {
        return false;
    }
    char pathBuf[PATH_MAX + 1] = {0};
    if (realpath(path.c_str(), pathBuf) == nullptr) {
        return false;
    }
    path = pathBuf;
    return true;
}

bool CheckFileStat(const std::string &filePath)
{
    struct stat st;
    if (stat(filePath.c_str(), &st) != 0) {
        CCSEC_LOG_ERROR("|CheckFileStat|END|returnF||check file stat error ");
        return false;
    }

    if ((st.st_mode & S_IFMT) != S_IFREG) {
        CCSEC_LOG_ERROR("|CheckFileStat|END|returnF||file is not reg");
        return false;
    }

    if (st.st_size > MAX_FILE_SIZE || st.st_size == 0) {
        CCSEC_LOG_ERROR("|CheckFileStat|END|returnF||file size out of range");
        return false;
    }

    return true;
}

bool GetFolderPath(const std::string &filePath, std::string &folderPath)
{
    const size_t pos = filePath.find_last_of("/");
    if (pos == std::string::npos) {
        return false;
    }
    folderPath = filePath.substr(0, pos);
    return true;
}

bool GetFileName(const std::string &filePath, std::string &fileName)
{
    const size_t pos = filePath.find_last_of("/");
    if (pos == std::string::npos) {
        return false;
    }
    fileName = filePath.substr(pos);
    return true;
}

bool IsAbsolutePath(const std::string &filePath)
{
    if (filePath.length() == 0) {
        return false;
    }

    if (filePath[0] != '/') {
        return false;
    }

    if (strstr(filePath.c_str(), "/../") != nullptr || strstr(filePath.c_str(), "/./") != nullptr) {
        return false;
    }

    return true;
}

bool CheckFilePath(const std::string &filePath)
{
    if (!IsAbsolutePath(filePath)) {
        CCSEC_LOG_ERROR("|SCF_CheckFilePathAndStat|END|returnF||relative path");
        return false;
    }
    std::string folderPath;
    if (!GetFolderPath(filePath, folderPath)) {
        CCSEC_LOG_ERROR("|SCF_CheckFilePathAndStat|END|returnF||get folder path");
        return false;
    }

    if (!CanonicalPath(folderPath)) {
        CCSEC_LOG_ERROR("|SCF_CheckFilePathAndStat|END|returnF||canonical path failed");
        return false;
    }
    return true;
}

bool SCF_CheckFilePathAndStat(const std::string &filePath)
{
    if (!CheckFilePath(filePath)) {
        return false;
    }
    if (!CheckFileStat(filePath)) {
        CCSEC_LOG_ERROR("|SCF_CheckFilePathAndStat|END|returnF||check path stat failed");
        return false;
    }
    if (!Exist(filePath, R_OK)) {
        CCSEC_LOG_ERROR("|SCF_CheckFilePathAndStat|END|returnF||file path is not exist");
        return false;
    }

    return true;
}
} // namespace scf