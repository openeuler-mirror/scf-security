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
#include "scf_def.h"
#include "scf_errno.h"
#include "scf_inner.h"
#include "scf_ssl.h"
#include "custom_logger.h"
#include "parse_config.h"

namespace scf {
    int32_t SetTLS(SCF_PolicyCtx *ctx, const Config &cfg)
    {
        if (SetProtocolVersion4PolicyCtx(ctx, cfg.tlsVersion) != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("|SCF_SetConfigFile|END|returnF||set tls version failed");
            return SCF_ERROR;
        }
        if (SetCipherSuites4PolicyCtx(ctx, cfg.tlsCipherSuites) != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("|SCF_SetConfigFile|END|returnF||set tls ciphersuites failed");
            return SCF_ERROR;
        }
        return SCF_SUCCESS;
    }

    int32_t SetCertAndKey(SCF_PolicyCtx *ctx, Config &cfg)
    {
        if (AddCert2PolicyCtx(ctx, cfg.certs) != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("|SCF_SetConfigFile|END|returnF||add cert failed");
            return SCF_ERROR;
        }
        if (SetPrivKeyAndPwd4Ctx(ctx, cfg.privKey) != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("|SCF_SetConfigFile|END|returnF||set privKey and keyAuth error ");
            return SCF_ERROR;
        }
        return SCF_SUCCESS;
    }

    void CleanConfig(Config &cfg)
    {
        if (!cfg.privKey.keyAuth.storeBuf.empty()) {
            std::fill(cfg.privKey.keyAuth.storeBuf.begin(), cfg.privKey.keyAuth.storeBuf.end(), 0);
            cfg.privKey.keyAuth.storeBuf.clear();
        }
    }

    int32_t SCF_SetConfigFile(SCF_PolicyCtx *ctx, const char *config)
    {
        if (ctx == nullptr || config == nullptr) {
            CCSEC_LOG_ERROR("|SCF_SetConfigFile|END|returnF||policy ctx or config is null");
            return SCF_ERRNO_NULL_INPUT;
        }
        if (strlen(config) == 0) {
            CCSEC_LOG_ERROR("|SCF_SetConfigFile|END|returnF|config length is 0");
            return SCF_ERRNO_INVALID_PARAM;
        }
        std::string filepath(config);
        if (!SCF_CheckFilePathAndStat(filepath)) {
            CCSEC_LOG_ERROR("|SCF_SetConfigFile|END|returnF||invalid config file");
            return SCF_ERROR;
        }
        Config cfg;
        if (SCF_ParseConfig(filepath, cfg) != SCF_SUCCESS) {
            CCSEC_LOG_ERROR("|SCF_SetConfigFile|END|||parse config error");
            CleanConfig(cfg);
            return SCF_ERROR;
        }
        if (SetTLS(ctx, cfg) != SCF_SUCCESS) {
            CleanConfig(cfg);
            return SCF_ERROR;
        }
        if (SetCertAndKey(ctx, cfg) != SCF_SUCCESS) {
            CleanConfig(cfg);
            return SCF_ERROR;
        }

        CCSEC_LOG_DEBUG("|SCF_SetConfigFile|END|returnS||set config file success");
        return SCF_SUCCESS;
    }
}
