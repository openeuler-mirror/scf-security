/**
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

#ifndef SCF_INNER_H
#define SCF_INNER_H

#include <mutex>
#include <string>
#include <sys/time.h>
#include "custom_logger.h"
#include "scf_errno.h"
#include "scf_def.h"
#include "constant_def.h"
#include "abstract_tls_adaptor.h"

namespace scf {
    struct SCFFileCtx {
        SCF_STORE_TYPE storeType;
        uint8_t *buf; // 数据内容。根据 storeType 不同，应该分别是文件路径/buffer/标识符等
        size_t bufLen; // buf 的长度。文件路径时，最大路径长度为4096（有效长度4095 + '\0'结束符）
        uint8_t *passwd; // 密钥缓冲区
        size_t passwdLen; // passwd 长度
        SCF_STORE_FORMAT format; // 数据存储的格式
    };

    struct SCFPolicyCtx {
        uint32_t refCnt; // 引用计数。初始化为1，表示自身使用，每个obj+1
        void *sslConfig;
        SCF_POLICY_MODE policyMode;
        uint32_t verifyMode;
        SCF_ROLE role;
        bool isSetRole;
        SCF_PskFindSessionCb pskFindSessionCb;
        SCF_PskUseSessionCb pskUseSessionCb;
        bool isNeedKeyUpdate;
        uint32_t keyUpdateTime;
        uint64_t keyUpdateTraffic;
        bool isNullVersion;
    };

    struct SCF_KEY_UPDATE_INFO {
        uint32_t timeInterval; /* 更新间隔时间 */
        uint64_t trafficThreshold; /* 更新流量阈值 */
        uint64_t totalSizeOfWriteData; /* 当前密钥阶段发送数据总量 */
        uint64_t lastKeyUpdateTime; /* 上次主动更新会话密钥时间或obj创建时间 */
        uint32_t totalKeyUpdateCnt; /* 主动更新会话密钥次数 */
        bool isLastUpdateSuccess; /* 上次会话密钥是否更新成功 */
    };

    struct SCFPolicyObj {
        SCFPolicyCtx *policyCtx;
        void *sslCtx;
        SCF_POLICY_MODE policyMode;
        SCF_VERIFY_MODE verifyMode;
        SCF_ROLE role;
        bool isSetRole;
        int32_t fd;
        SCF_PskFindSessionCb pskFindSessionCb;
        SCF_PskUseSessionCb pskUseSessionCb;
        SCF_KEY_UPDATE_INFO keyUpdateInfo; /* 密钥更新相关信息 */
        void *userData; /* 用户自定义数据 */
    };
    /**
      * @brief  外部加密函数格式
      */
    using ExternalEncryptFunction = bool (*)(const uint8_t *content, size_t contentLen,
                                             std::vector<std::byte> &ciphertext);
    extern std::mutex g_scfMutex;
    extern bool g_scfInitialized;
    extern AbstractTLSAdaptor *g_adaptor;

    extern bool SCF_CheckFilePathAndStat(const std::string &filePath);

    bool CanonicalPath(std::string &path);

    bool CheckFileStat(const std::string &filePath);

    bool CheckFilePath(const std::string &filePath);

    bool IsAbsolutePath(const std::string &filePath);

    // policy_utils
    std::string GetErrorMessageInternal(int32_t errorCode);

    int32_t CheckRole(SCF_ROLE role);

    int32_t CheckVerifyMode(uint32_t verifyMode);

    int32_t CheckPolicyMode(SCF_POLICY_MODE policyMode);

    int32_t SCFInitInner(const uint64_t &flag, const void *settings);

    void SCFDeInitInner();

    int32_t CheckNeedKeyUpdate(SCF_PolicyObj *obj, uint32_t processDataLen, bool *isNeedKeyUpdate);

    int32_t Num2HexStr(const char *num, const uint32_t &numLen, char *hexStr, const uint32_t &hexStrLen);

    int32_t ReadFileContent(const std::string &path, std::string &content);

#define CHECK_SCF_ADAPTOR_RET(msg)                                                                       \
    do {                                                                                                   \
        if (g_adaptor == nullptr) {                                                                        \
            CCSEC_LOG_ERROR("|" << (msg) << "|END|returnF||g_adaptor is nullptr");                         \
            return SCF_ERRNO_INVALID_PARAM;                                                              \
        }                                                                                                  \
    } while (0)

#define CHECK_SCF_ADAPTOR_POINTER(msg)                                                                   \
    do {                                                                                                   \
        if (g_adaptor == nullptr) {                                                                        \
            CCSEC_LOG_ERROR("|" << (msg) << "|END|returnF||g_adaptor is nullptr");                         \
            return nullptr;                                                                                \
        }                                                                                                  \
    } while (0)

#define CHECK_SCF_INIT_RET(msg)                                                                          \
    do {                                                                                                   \
        if (!g_scfInitialized) {                                                                         \
            return SCF_ERRNO_NOT_INIT;                                                                   \
        }                                                                                                  \
    } while (0)

#define CHECK_SCF_INIT_POINTER(msg)                                                                      \
    do {                                                                                                   \
        if (!g_scfInitialized) {                                                                         \
            return nullptr;                                                                                \
        }                                                                                                  \
    } while (0)
}
#endif  // SCF_INNER_H
