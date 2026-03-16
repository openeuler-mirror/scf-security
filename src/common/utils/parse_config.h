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

#ifndef PARSE_CONFIG_H
#define PARSE_CONFIG_H

#include <string>
#include <unordered_map>
#include <vector>

#include "scf_ssl.h"

namespace scf {

constexpr const char *TLS_VERSION = "tlsVersion";
constexpr const char *MIN_VERSION = "minVersion";
constexpr const char *MAX_VERSION = "maxVersion";
constexpr const char *FORBID_VERSION = "forbidVersion";
constexpr const int MAX_FORBIN_VERSION_LENGTH = 5;

constexpr const char *TLS_CIPHER_SUITES = "tlsCipherSuites";
constexpr const int MAX_TLS_CIPHER_SUITES_LENGTH = 20;

constexpr const char *CERT = "cert";
constexpr const char *CERTS = "certs";
constexpr const char *CERT_TYPE = "certType";
constexpr const char *STORE_BUF = "storeBuf";
constexpr const char *IS_CIPHER = "isCipher";

constexpr const char *PRIVATE_KEY = "privKey";

constexpr const char *KEY_AUTH = "keyAuth";

constexpr const char *KEY_STORE_BUF = "keyStoreBuf";
constexpr const char *KEY_STORE_BUF_BAK = "keyStoreBufBak";

// parse_certs
struct Cert {
    std::string certType;
    std::string storeBuf;
};

struct TlsVersion {
    uint32_t minVersion;
    uint32_t maxVersion;
    std::vector<uint32_t> forbidVersion;
};

struct KeyAuth {
    std::vector<char> storeBuf;
    bool isCipher;
};
// parse privKey
struct PrivKey {
    std::string storeBuf;
    KeyAuth keyAuth;
};


struct Config {
    TlsVersion tlsVersion;
    std::vector<uint16_t> tlsCipherSuites;
    std::vector<Cert> certs;
    PrivKey privKey;
    Config()
    {
        tlsVersion.maxVersion = 0;
        tlsVersion.minVersion = 0;
        privKey.keyAuth.isCipher = true;
    }
};

int SCF_ParseConfig(const std::string &filePath, Config &cfg);

int32_t SetProtocolVersion4PolicyCtx(SCF_PolicyCtx *ctx, const TlsVersion &tlsVersion);

int32_t SetCipherSuites4PolicyCtx(SCF_PolicyCtx *ctx, const std::vector<uint16_t> &tlsCipherSuites);

int32_t SetPrivKeyAndPwd4Ctx(SCF_PolicyCtx *ctx, PrivKey &privKey);

int32_t AddCert2PolicyCtx(SCF_PolicyCtx *ctx, const std::vector<Cert> &certsArray);
} // namespace scf
#endif // PARSE_CONFIG_H
