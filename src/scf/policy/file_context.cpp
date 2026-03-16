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

#include "scf.h"
#include "scf_errno.h"
#include "scf_inner.h"
#include "scf_ssl.h"
#include "custom_logger.h"
#include "parse_config.h"
#include "securec.h"
#include "constant_def.h"
#include "crypto_util.h"
#include <algorithm>

namespace scf {
SCF_FILE_CTX *SCF_FileCtxNew(void)
{
    CCSEC_LOG_DEBUG("|SCF_FileCtxNew|START|||SCF_FileCtxNew start.");
    CHECK_SCF_INIT_POINTER("SCF_FileCtxNew");
    auto *ctx = new(std::nothrow) SCF_FILE_CTX;
    if (ctx == nullptr || memset_s(ctx, sizeof(SCF_FILE_CTX), 0, sizeof(SCF_FILE_CTX)) != EOK) {
        CCSEC_LOG_ERROR("|SCF_FileCtxNew|START|||init ctx fail, memset_s fail.");
        delete ctx;
        return nullptr;
    }
    return ctx;
}

void SCF_FileCtxFree(SCF_FILE_CTX **ctx)
{
    CCSEC_LOG_DEBUG("|SCF_FileCtxFree|START|||SCF_FileCtxFree start.");
    if (ctx == nullptr || *ctx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_FileCtxFree|END|returnF||ctx is nullptr");
        return;
    }

    if ((*ctx)->buf != nullptr && (*ctx)->bufLen != 0) {
        (void) memset_s((*ctx)->buf, (*ctx)->bufLen, 0, (*ctx)->bufLen);
        delete[] (*ctx)->buf;
        (*ctx)->buf = nullptr;
        (*ctx)->bufLen = 0;
    }
    if ((*ctx)->passwd != nullptr && (*ctx)->passwdLen != 0) {
        (void) memset_s((*ctx)->passwd, (*ctx)->passwdLen, 0, (*ctx)->passwdLen);
        delete[] (*ctx)->passwd;
        (*ctx)->passwd = nullptr;
        (*ctx)->passwdLen = 0;
    }
    delete *ctx;
    *ctx = nullptr;
}

int32_t CheckFileCtxBufInput(const SCF_FILE_CTX *ctx, const SCF_STORE_TYPE &storeType, const uint8_t *buf,
    const size_t &bufLen, const SCF_STORE_FORMAT &format)
{
    if (ctx == nullptr || buf == nullptr || bufLen == 0) {
        return SCF_ERRNO_NULL_INPUT;
    }
    // 不支持的或预留的
    if (storeType >= SCF_STORE_ERROR || format > SCF_STORE_FORMAT_PEM) {
        return SCF_ERRNO_NOT_SUPPORT;
    }
    // path length 超出长度限制 （预留结束符）
    if (storeType == SCF_STORE_FILE_PATH) {
        if (bufLen > PATH_MAX - 1) {
            CCSEC_LOG_ERROR("fileCtx path is too long. PATH_MAX:" << PATH_MAX << ", actual:" << bufLen);
            return SCF_SSL_ERR_PATH_TOO_LONG;
        }
        // 校验路径合法
        if (!SCF_CheckFilePathAndStat(std::string(buf, buf + bufLen))) {
            CCSEC_LOG_ERROR("fileCtx path is invalid.");
            return SCF_ERRNO_FILE_PATH_ERROR;
        }
    }
    // buffer length 超出长度限制 （预留结束符）
    if (storeType == SCF_STORE_BUFFER && bufLen > BUF_MAX_LEN - 1) {
        CCSEC_LOG_ERROR("fileCtx buffer overflow (large file). BUF_MAX_LEN:" << BUF_MAX_LEN << ", actual:" << bufLen);
        return SCF_ERRNO_LARGE_FILE;
    }
    return SCF_SUCCESS;
}

int32_t SCF_FileCtxSetBuf(SCF_FILE_CTX *ctx, SCF_STORE_TYPE storeType, uint8_t *buf, size_t bufLen,
    SCF_STORE_FORMAT format)
{
    CCSEC_LOG_DEBUG("|SCF_FileCtxSetBuf|START|||SCF_FileCtxSetBuf start.");
    if (ctx == nullptr || buf == nullptr || bufLen == 0) {
        CCSEC_LOG_ERROR("|SCF_FileCtxSetBuf|END|returnF||ctx or buf is nullptr or bufLen is 0.");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (storeType > SCF_STORE_BUFFER || storeType < SCF_STORE_FILE_PATH || format != SCF_STORE_FORMAT_PEM) {
        return SCF_ERRNO_NOT_SUPPORT;
    }
    CHECK_SCF_INIT_RET("SCF_FileCtxSetBuf");
    int32_t ret = CheckFileCtxBufInput(ctx, storeType, buf, bufLen, format);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_FileCtxSetBuf|END|returnF||CheckFileCtxBufInput failed, ret:" << ret << ". ret msg: "
            << GetErrorMessage(ret));
        return ret;
    }

    auto *newBuf = new(std::nothrow) uint8_t[bufLen + 1];
    if (newBuf == nullptr || memcpy_s(newBuf, bufLen, buf, bufLen) != EOK) {
        delete[] newBuf;
        CCSEC_LOG_ERROR("|SCF_FileCtxSetBuf|END|returnF||memcpy_s error.");
        return SCF_ERRNO_MEM_ALLOC;
    }
    newBuf[bufLen] = '\0';

    // 如果 ctx->buf 非空，覆盖前需要释放，防止内存泄漏
    if (ctx->buf != nullptr && ctx->bufLen != 0) {
        (void)memset_s(ctx->buf, ctx->bufLen, 0, ctx->bufLen);
        delete[] ctx->buf;
    }

    ctx->storeType = storeType;
    ctx->buf = newBuf;
    ctx->bufLen = bufLen;
    ctx->format = format;
    return SCF_SUCCESS;
}

int32_t SCF_FileCtxSetPwd(SCF_FILE_CTX *ctx, uint8_t *passwd, const size_t passwdLen, bool isCipher)
{
    CCSEC_LOG_DEBUG("|SCF_FileCtxSetPwd|START|||SCF_FileCtxSetPwd start.");
    CHECK_SCF_INIT_RET("SCF_FileCtxSetPwd");
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_FileCtxSetPwd|END|returnF||ctx is nullptr.");
        return SCF_ERRNO_NULL_INPUT;
    }
    // pwd 可以没有
    if (passwd == nullptr || passwdLen == 0) {
        return SCF_SUCCESS;
    }
    std::vector<std::byte> plaintext{};
    if (isCipher) {
        if (!CryptoUtil::GetInstance().Decrypt(passwd, passwdLen, plaintext)) {
            CCSEC_LOG_ERROR("|SCF_FileCtxSetPwd Decrypt|END|returnF||Decrypt key password failed");
            return SCF_ERROR;
        }
    } else {
        // 明文，直接将passwd转成vector
        plaintext.resize(passwdLen);
        std::transform(passwd, passwd + passwdLen, plaintext.begin(),
                       [](uint8_t x) { return static_cast<std::byte>(x); });
    }
    // len+1 预留最后一个\0
    auto actPwdLen = plaintext.size();
    if (actPwdLen >= UINT32_MAX) {
        CCSEC_LOG_ERROR("|SCF_FileCtxSetPwd|END|returnF||new mem error.");
        // 清空plaintext
        std::fill(plaintext.begin(), plaintext.end(), std::byte{0});
        return SCF_ERRNO_MEM_ALLOC;
    }
    auto *newPassWd = new(std::nothrow) uint8_t[actPwdLen + 1];
    if (newPassWd == nullptr) {
        CCSEC_LOG_ERROR("|SCF_FileCtxSetPwd|END|returnF||new mem error.");
        // 清空plaintext
        std::fill(plaintext.begin(), plaintext.end(), std::byte{0});
        return SCF_ERRNO_MEM_ALLOC;
    }
    auto cpyRet = memcpy_s(newPassWd, actPwdLen, plaintext.data(), plaintext.size());
    // 清空plaintext
    std::fill(plaintext.begin(), plaintext.end(), std::byte{0});
    if (cpyRet != EOK) {
        (void)memset_s(newPassWd, actPwdLen + 1, 0, actPwdLen + 1);
        delete[] newPassWd;
        CCSEC_LOG_ERROR("|SCF_FileCtxSetPwd|END|returnF||memcpy_s error.");
        return SCF_ERRNO_MEM_ALLOC;
    }
    newPassWd[actPwdLen] = '\0';
    // 如果 ctx->passwd 非空，覆盖前需要释放，防止内存泄漏
    if (ctx->passwd != nullptr && ctx->passwdLen != 0) {
        (void)memset_s(ctx->passwd, ctx->passwdLen, 0, ctx->passwdLen);
        delete[] ctx->passwd;
    }
    ctx->passwd = newPassWd;
    ctx->passwdLen = actPwdLen;
    return SCF_SUCCESS;
}
}