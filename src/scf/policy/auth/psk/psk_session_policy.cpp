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

#include <crypto_util.h>

#include "scf_ssl.h"
#include "scf_def.h"
#include "scf_errno.h"
#include "scf.h"
#include "scf_inner.h"
#include "custom_logger.h"
#include <algorithm>

namespace scf {
SCF_Session *SCF_SessionNew(void)
{
    CCSEC_LOG_DEBUG("|SCF_SessionNew|START|||SCF_SessionNew start.");
    CHECK_SCF_INIT_POINTER("SCF_SessionNew");
    CHECK_SCF_ADAPTOR_POINTER("SCF_SessionNew");
    SCF_Session *ptr = g_adaptor->SessionNew();
    if (ptr == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SessionNew|END|returnF||SessionNew failed.");
    }
    return ptr;
}

void SCF_SessionFree(SCF_Session **sess)
{
    CCSEC_LOG_DEBUG("|SCF_SessionFree|START|||SCF_SessionFree start.");
    if (sess == nullptr || *sess == nullptr) {
        CCSEC_LOG_WARN("|SCF_SessionFree|END|||sess is nullptr.");
        return;
    }
    if (!g_scfInitialized || g_adaptor == nullptr) {
        return;
    }
    g_adaptor->SessionFree(*sess);
    *sess = nullptr;
}

int32_t SCF_SessionSetMasterKey(SCF_Session *sess, const uint8_t *masterKey, size_t masterKeyLen, bool isCipher)
{
    CCSEC_LOG_DEBUG("|SCF_SessionSetMasterKey|START|||SCF_SessionSetMasterKey start.");
    if (sess == nullptr || masterKey == nullptr || masterKeyLen == 0) {
        CCSEC_LOG_ERROR("|SCF_SessionSetMasterKey|END|returnF||sess or masterKey is nullptr or masterKeyLen is 0.");
        return SCF_ERRNO_INVALID_PARAM;
    }
    CHECK_SCF_INIT_RET("SCF_SessionSetMasterKey");
    CHECK_SCF_ADAPTOR_RET("SCF_SessionSetMasterKey");
    std::vector<uint8_t> finalKey{};
    if (isCipher) {
        std::vector<std::byte> plaintext{};
        if (!CryptoUtil::GetInstance().Decrypt(masterKey, masterKeyLen, plaintext)) {
            CCSEC_LOG_ERROR("|SCF_SessionSetMasterKey Decrypt|END|returnF||Decrypt masterKey failed");
            return SCF_ERROR;
        }
        finalKey.resize(plaintext.size());
        std::transform(plaintext.begin(), plaintext.end(), finalKey.begin(),
                       [](std::byte b) { return static_cast<uint8_t>(b); });
        std::fill(plaintext.begin(), plaintext.end(), std::byte{0});
    } else {
        // 如果不需要解密，直接使用原始密码
        finalKey.assign(masterKey, masterKey + masterKeyLen);
    }
    int32_t ret = g_adaptor->SessionSetMasterKey(sess, finalKey.data(), finalKey.size());
    std::fill(finalKey.begin(), finalKey.end(), 0);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_SessionSetMasterKey|END|returnF||SessionSetMasterKey failed, ret:"
            << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }
    return SCF_SUCCESS;
}

int32_t SCF_SessionSetCipher(SCF_Session *sess, const void *cipherSuite, size_t cipherLen)
{
    CCSEC_LOG_DEBUG("|SCF_SessionSetCipher|START|||SCF_SessionSetCipher start.");
    if (sess == nullptr || cipherSuite == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SessionSetCipher|END|returnF||sess or cipherSuite is nullptr.");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_SessionSetCipher");
    CHECK_SCF_ADAPTOR_RET("SCF_SessionSetCipher");
    int32_t ret = g_adaptor->SessionSetCipher(sess, cipherSuite, cipherLen);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_SessionSetCipher|END|returnF||SCF_SessionSetCipher failed, ret:"
            << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }

    return SCF_SUCCESS;
}

int32_t SCF_SessionGetCipher(SCF_Session *sess, void **cipherSuite, size_t &cipherLen)
{
    CCSEC_LOG_DEBUG("|SCF_SessionGetCipher|START|||SCF_SessionGetCipher start.");
    if (sess == nullptr || cipherSuite == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SessionGetCipher|END|returnF||sess or cipherSuite is nullptr.");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_SessionGetCipher");
    CHECK_SCF_ADAPTOR_RET("SCF_SessionGetCipher");
    int32_t ret = g_adaptor->SessionGetCipher(sess, cipherSuite, cipherLen);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_SessionGetCipher|END|returnF||SCF_SessionGetCipher failed, ret:"
            << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }
    return SCF_SUCCESS;
}

void SCF_SessionFreeCipher(void **cipherSuite, size_t &cipherLen)
{
    CCSEC_LOG_DEBUG("|SCF_SessionFreeCipher|START|||SCF_SessionFreeCipher start.");
    if (cipherSuite == nullptr || *cipherSuite == nullptr || cipherLen == 0) {
        CCSEC_LOG_ERROR("|SCF_SessionFreeCipher|END|returnF||cipherSuit is nullptr.");
        return;
    }
    if (!g_scfInitialized || g_adaptor == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SessionFreeCipher|END|returnF||not init.");
        return;
    }
    g_adaptor->SessionFreeCipher(cipherSuite, cipherLen);
}

int32_t SCF_SessionSetProtocolVersion(SCF_Session *sess, const char *version)
{
    CCSEC_LOG_DEBUG("|SCF_SessionSetProtocolVersion|START|||SCF_SessionSetProtocolVersion start.");
    if (sess == nullptr || version == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SessionSetProtocolVersion|END|returnF||sess or version is nullptr.");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_SessionSetProtocolVersion");
    CHECK_SCF_ADAPTOR_RET("SCF_SessionSetProtocolVersion");
    int32_t ret = g_adaptor->SessionSetProtocolVersion(sess, version);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_SessionSetProtocolVersion|END|returnF||SessionSetProtocolVersion failed, ret:"
            << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }

    return SCF_SUCCESS;
}

int32_t SCF_SessionGetProtocolVersion(SCF_Session *sess, char **version, size_t &versionLen)
{
    CCSEC_LOG_DEBUG("|SCF_SessionGetProtocolVersion|START|||SCF_SessionGetProtocolVersion start.");
    if (sess == nullptr || version == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SessionGetProtocolVersion|END|returnF||sess or version is nullptr.");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_SessionGetProtocolVersion");
    CHECK_SCF_ADAPTOR_RET("SCF_SessionGetProtocolVersion");
    int32_t ret = g_adaptor->SessionGetProtocolVersion(sess, version, versionLen);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_SessionGetProtocolVersion|END|returnF||SCF_SessionGetProtocolVersion failed, ret:"
            << ret << ". ret msg: " << GetErrorMessage(ret));
        return ret;
    }

    return SCF_SUCCESS;
}

const void *SCF_CipherFind(SCF_PolicyObj *obj, uint8_t *cipherId)
{
    CCSEC_LOG_DEBUG("|SCF_CipherFind|START|||SCF_CipherFind start.");
    if (obj == nullptr || cipherId == nullptr) {
        CCSEC_LOG_WARN("|SCF_CipherFind|END|||obj or cipherId is nullptr.");
        return nullptr;
    }
    CHECK_SCF_INIT_POINTER("SCF_CipherFind");
    CHECK_SCF_ADAPTOR_POINTER("SCF_CipherFind");
    return g_adaptor->CipherFind(obj, cipherId);
}
}