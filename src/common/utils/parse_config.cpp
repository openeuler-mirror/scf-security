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

#include "parse_config.h"

#include <filesystem>
#include <fstream>
#include <vector>

#include "securec.h"
#include "custom_logger.h"
#include "rapidjson/document.h"
#include "rapidjson/istreamwrapper.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "scf.h"
#include "scf_errno.h"
#include "scf_inner.h"
#include "scf_ssl.h"

namespace scf {

inline std::unordered_map<std::string, SCF_SSL_CipherSuite> cipherMap = {
    /* TLS1.2 cipher suite */
    {"SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
    {"SCF_SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", SCF_SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
    {"SCF_SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256", SCF_SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
    {"SCF_SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384", SCF_SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
    {"SCF_SSL_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", SCF_SSL_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
    {"SCF_SSL_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", SCF_SSL_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
    /* TLS1.3 cipher suite. 没有 SCF_SSL_AES_128_CCM_8_SHA256，因为不在公司规范白名单 */
    {"SCF_SSL_AES_128_GCM_SHA256", SCF_SSL_AES_128_GCM_SHA256},
    {"SCF_SSL_AES_256_GCM_SHA384", SCF_SSL_AES_256_GCM_SHA384},
    {"SCF_SSL_CHACHA20_POLY1305_SHA256", SCF_SSL_CHACHA20_POLY1305_SHA256},
    {"SCF_SSL_AES_128_CCM_SHA256", SCF_SSL_AES_128_CCM_SHA256},
};

std::unordered_map<std::string, uint32_t> tlsVersionMap = {
    {"SSL_VERSION_TLS12", SCF_SSL_VERSION_TLS12},
    {"SSL_VERSION_TLS13", SCF_SSL_VERSION_TLS13},
};

std::unordered_map<std::string, SCF_CERT_TYPE> tlsCertTypeMap = {
    {"CA", SCF_CERT_TYPE_CA},
    {"EE", SCF_CERT_TYPE_EE},
    {"CRL", SCF_CERT_TYPE_CRL},
    {"EE_CHAIN", SCF_CERT_TYPE_EE_CHAIN},
};

std::unordered_map<std::string, SCF_STORE_FORMAT> tlsStoreFormatMap = {
    {"pem", SCF_STORE_FORMAT_PEM},
    {"asn_der", SCF_STORE_FORMAT_PEM},
    {"pfx", SCF_STORE_FORMAT_PEM},
};

std::unordered_map<std::string, SCF_STORE_TYPE> tlsStoreTypeMap = {
    {"file", SCF_STORE_FILE_PATH}, {"buffer", SCF_STORE_BUFFER}};

// read config and parse it to doc
rapidjson::Document SCF_ReadConfig(const std::string &filePath)
{
    CCSEC_LOG_DEBUG("|SCF_ReadConfig|START|||start to read config file." << filePath.c_str());
    // std::ifstream is automatically released at the end of the function
    std::ifstream file(filePath);
    if (!file.is_open()) {
        CCSEC_LOG_ERROR("|SCF_ReadConfig|END|||failed to open config file");
        return {};
    }

    rapidjson::IStreamWrapper isw(file);
    rapidjson::Document doc;
    doc.ParseStream(isw);
    if (doc.HasParseError()) {
        CCSEC_LOG_ERROR("|SCF_ReadConfig|END|||parse config file failed");
        return {};
    }

    return doc;
}

int32_t FillTlsVersion(const rapidjson::Value &tlsVersion, TlsVersion &tlsVersionOut)
{
    std::string minVersionStr = tlsVersion[MIN_VERSION].GetString();
    std::string maxVersionStr = tlsVersion[MAX_VERSION].GetString();
    auto minVersion = tlsVersionMap.find(minVersionStr);
    if (minVersion != tlsVersionMap.end()) {
        tlsVersionOut.minVersion = minVersion->second;
    } else {
        CCSEC_LOG_ERROR("|SCF_ParseTLSVersion|END|||invalid min tls version");
        return SCF_ERROR;
    }
    auto maxVersion = tlsVersionMap.find(maxVersionStr);
    if (maxVersion != tlsVersionMap.end()) {
        tlsVersionOut.maxVersion = maxVersion->second;
    } else {
        CCSEC_LOG_ERROR("|SCF_ParseTLSVersion|END|||invalid max tls version");
        return SCF_ERROR;
    }
    return SCF_SUCCESS;
}

int32_t FillTlsForbidVersion(const rapidjson::Value &tlsVersion, TlsVersion &tlsVersionOut)
{
    for (const auto &v : tlsVersion[FORBID_VERSION].GetArray()) {
        if (!v.IsString()) {
            CCSEC_LOG_ERROR("|SCF_ParseTLSVersion|END|returnF||invalid tls version type");
            return SCF_ERROR;
        }
        std::string forbidVersionStr = v.GetString();
        auto forbidVersion = tlsVersionMap.find(forbidVersionStr);
        if (forbidVersion != tlsVersionMap.end()) {
            tlsVersionOut.forbidVersion.push_back(forbidVersion->second);
        } else {
            CCSEC_LOG_ERROR("|SCF_ParseTLSVersion|END|returnF||invalid tls version");
            return SCF_ERROR;
        }
    }
    return SCF_SUCCESS;
}

int32_t SCF_ParseTLSVersion(const rapidjson::Value &tlsVersion, TlsVersion &tlsVersionOut)
{
    CCSEC_LOG_DEBUG("|SCF_ParseTLSVersion||||start to parse tls version");
    bool hasMember =
        tlsVersion.HasMember(MIN_VERSION) && tlsVersion.HasMember(MAX_VERSION) && tlsVersion.HasMember(FORBID_VERSION);
    if (!hasMember) {
        CCSEC_LOG_ERROR("|SCF_ParseTLSVersion|END|||tlsVersion config item is invalid");
        return SCF_ERROR;
    }
    if (!(tlsVersion[MIN_VERSION].IsString() && tlsVersion[MAX_VERSION].IsString())) {
        CCSEC_LOG_ERROR("|SCF_ParseTLSVersion|END|||tlsVersion config item is invalid");
        return SCF_ERROR;
    }
    if (FillTlsVersion(tlsVersion, tlsVersionOut) != SCF_SUCCESS) {
        return SCF_ERROR;
    }
    bool forbidVersionInValid =
        !tlsVersion[FORBID_VERSION].IsArray() || tlsVersion[FORBID_VERSION].Size() > MAX_FORBIN_VERSION_LENGTH;
    if (forbidVersionInValid) {
        CCSEC_LOG_ERROR("|SCF_ParseTLSVersion|END|||invalid forbidVersion type or length");
        return SCF_ERROR;
    }
    if (FillTlsForbidVersion(tlsVersion, tlsVersionOut) != SCF_SUCCESS) {
        return SCF_ERROR;
    }

    CCSEC_LOG_DEBUG("|SCF_ParseTLSVersion||||parse tls version success");
    return SCF_SUCCESS;
}

int32_t FillTlsCipherSuites(const rapidjson::Value &tlsCiphersuites, std::vector<uint16_t> &tlsCiphersuitesOut)
{
    for (const auto &cipher : tlsCiphersuites.GetArray()) {
        if (!cipher.IsString()) {
            CCSEC_LOG_ERROR("|SCF_ParseTLSCiphersuites|END|||invalid data type");
            return SCF_ERROR;
        }
        std::string tlsCiphersuite = cipher.GetString();
        auto it = cipherMap.find(tlsCiphersuite);
        if (it != cipherMap.end()) {
            tlsCiphersuitesOut.push_back(it->second);
        } else {
            CCSEC_LOG_ERROR("|SCF_ParseTLSCiphersuites|END|||invalid tls ciphersuite is ");
            return SCF_ERROR;
        }
    }
    return SCF_SUCCESS;
}

int32_t SCF_ParseTLSCiphersuites(const rapidjson::Value &tlsCiphersuites, std::vector<uint16_t> &tlsCiphersuitesOut)
{
    CCSEC_LOG_DEBUG("|SCF_ParseTLSVersion||||start to parse tls cipher suites");
    bool tlsCiphersuitesInvalid = !tlsCiphersuites.IsArray() || tlsCiphersuites.Size() > MAX_TLS_CIPHER_SUITES_LENGTH;
    if (tlsCiphersuitesInvalid) {
        CCSEC_LOG_ERROR("|SCF_ParseTLSCiphersuites|END|||invalid tlsCipherSuites type or length");
        return SCF_ERROR;
    }
    if (FillTlsCipherSuites(tlsCiphersuites, tlsCiphersuitesOut) != SCF_SUCCESS) {
        return SCF_ERROR;
    }
    if (tlsCiphersuitesOut.empty()) {
        CCSEC_LOG_ERROR("|SCF_ParseTLSCiphersuites|END|returnF||tls ciphersuite is null");
        return SCF_ERROR;
    }
    CCSEC_LOG_DEBUG("|SCF_ParseTLSVersion||||parse tls cipher suites success");
    return SCF_SUCCESS;
}

int32_t CheckCertType(const std::string &certType)
{
    auto it = tlsCertTypeMap.find(certType);
    if (it != tlsCertTypeMap.end()) {
        return SCF_SUCCESS;
    }
    CCSEC_LOG_ERROR("|CheckCertType|END|||invalid cert type");
    return SCF_ERROR;
}

int32_t FillCerts(const rapidjson::Value &certs, std::vector<Cert> &certsOut)
{
    for (const auto &certObj : certs.GetArray()) {
        bool certObjInvalid = !certObj.IsObject() || !certObj.HasMember(CERT);
        if (certObjInvalid) {
            CCSEC_LOG_ERROR("SCF_ParseCerts|END|returnF||invalid certs item");
            return SCF_ERROR;
        }
        const rapidjson::Value &cert = certObj[CERT];
        if (!cert.IsObject()) {
            CCSEC_LOG_ERROR("|SCF_ParseCerts|END|returnF||cert is not an object");
            return SCF_ERROR;
        }
        bool certInvalid = !(cert.HasMember(CERT_TYPE) && cert.HasMember(STORE_BUF) && cert[CERT_TYPE].IsString() &&
                             cert[STORE_BUF].IsString());
        if (certInvalid) {
            CCSEC_LOG_ERROR("|SCF_ParseCerts|END|returnF||invalid cert item");
            return SCF_ERROR;
        }
        std::string certType = cert[CERT_TYPE].GetString();
        std::string certStoreBuf = cert[STORE_BUF].GetString();
        if (CheckCertType(certType) != SCF_SUCCESS || !SCF_CheckFilePathAndStat(certStoreBuf)) {
            CCSEC_LOG_ERROR("|SCF_ParseCerts|END|returnF||invalid cert item");
            return SCF_ERROR;
        }
        Cert certOut;
        certOut.certType = certType;
        certOut.storeBuf = certStoreBuf;

        certsOut.push_back(certOut);
    }
    return SCF_SUCCESS;
}

int32_t SCF_ParseCertsJson(const rapidjson::Value &certs, std::vector<Cert> &certsOut)
{
    CCSEC_LOG_DEBUG("|SCF_ParseTLSVersion||||start to parse cert");
    if (!certs.IsArray()) {
        CCSEC_LOG_WARN("|SCF_ParseCerts|END|||certs item is invalid");
        return SCF_ERROR;
    }
    if (FillCerts(certs, certsOut) != SCF_SUCCESS) {
        return SCF_ERROR;
    }
    CCSEC_LOG_DEBUG("|SCF_ParseTLSVersion||||parse cert success");
    return SCF_SUCCESS;
}

char *StringToCharPtr(const std::string &str)
{
    // 方法内部使用，传入参数为已校验过的合法路径，最大长度为4096，不会出现整数溢出
    char *charPtr = new (std::nothrow) char[str.length() + 1];
    if (charPtr == nullptr) {
        CCSEC_LOG_WARN("|StringToCharPtr||||new charPtr is nullptr");
        return nullptr;
    }
    if (memcpy_s(charPtr, str.length() + 1, str.c_str(), str.length()) != EOK) {
        CCSEC_LOG_WARN("|StringToCharPtr||||memcpy_s fail");
        delete[] charPtr;
        return nullptr;
    }
    charPtr[str.length()] = '\0';
    return charPtr;
}

int32_t SCF_ParseKeyAuthJson(const rapidjson::Value &keyAuth, KeyAuth &keyAuthOut)
{
    bool keyAuthInvalid = !keyAuth.IsObject() ||
                          !keyAuth.HasMember(STORE_BUF) || !keyAuth[STORE_BUF].IsString() ||
                          !keyAuth.HasMember(IS_CIPHER) || !keyAuth[IS_CIPHER].IsBool();
    if (keyAuthInvalid) {
        CCSEC_LOG_ERROR("SCF|ParseKeyAuth|END|||keyAuth storeBuf/isCipher item is invalid");
        return SCF_ERROR;
    }
    auto storeBuf = keyAuth[STORE_BUF].GetString();
    auto storeBufLen = std::strlen(storeBuf);
    keyAuthOut.storeBuf.insert(keyAuthOut.storeBuf.end(), storeBuf, storeBuf + storeBufLen);
    keyAuthOut.isCipher = keyAuth[IS_CIPHER].GetBool();
    return SCF_SUCCESS;
}

int32_t SCF_ParsePrivKeyJson(const rapidjson::Value &privKey, PrivKey &privKeyOut)
{
    if (!privKey.IsObject()) {
        CCSEC_LOG_ERROR("|SCF_ParsePrivKey|END|||privKey is not an object");
        return SCF_ERROR;
    }
    bool privKeyInvalid = !privKey.HasMember(STORE_BUF) || !privKey[STORE_BUF].IsString() ||
                          !privKey.HasMember(KEY_AUTH) || !privKey[KEY_AUTH].IsObject();
    if (privKeyInvalid) {
        CCSEC_LOG_ERROR("|SCF_ParsePrivKey|END|||privKey item is invalid");
        return SCF_ERROR;
    }

    std::string privKeyStoreBuf = privKey[STORE_BUF].GetString();
    if (!SCF_CheckFilePathAndStat(privKeyStoreBuf)) {
        CCSEC_LOG_ERROR("|SCF_ParsePrivKeyJson|END|||privKey storeBuf is invalid");
        return SCF_ERROR;
    }
    privKeyOut.storeBuf = privKey[STORE_BUF].GetString();
    if (SCF_ParseKeyAuthJson(privKey[KEY_AUTH], privKeyOut.keyAuth) != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_ParseConfig|END|returnF||keyAuth is invalid");
        return SCF_ERROR;
    }
    return SCF_SUCCESS;
}

int32_t AddCertInner(SCF_PolicyCtx *ctx, SCF_FILE_CTX *fileCtx, char *&storeBuf, const Cert &certObj)
{
    int32_t ret = SCF_FileCtxSetBuf(fileCtx, SCF_STORE_FILE_PATH, reinterpret_cast<uint8_t *>(storeBuf),
        strlen(storeBuf), SCF_STORE_FORMAT_PEM);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|AddCert2PolicyCtx|END|||SCF_FileCtxSetBuf failed");
        return SCF_ERROR;
    }
    auto certType = tlsCertTypeMap.find(certObj.certType);
    if (certType == tlsCertTypeMap.end()) {
        CCSEC_LOG_ERROR("|AddCert2PolicyCtx|END|||Unknown certType");
        return SCF_ERROR;
    }
    return SCF_AddCert(ctx, fileCtx, certType->second);
}

int32_t AddCert2PolicyCtx(SCF_PolicyCtx *ctx, const std::vector<Cert> &certsArray)
{
    if (certsArray.empty()) {
        CCSEC_LOG_DEBUG("|AddCert2PolicyCtx||||certs is null");
        return SCF_SUCCESS;
    }
    for (const auto &certObj : certsArray) {
        SCF_FILE_CTX *fileCtx = SCF_FileCtxNew();
        if (fileCtx == nullptr) {
            CCSEC_LOG_ERROR("|AddCert2PolicyCtx|END|||file context malloc mem error");
            return SCF_ERROR;
        }
        char *storeBuf = StringToCharPtr(certObj.storeBuf);
        if (storeBuf == nullptr) {
            SCF_FileCtxFree(&fileCtx);
            CCSEC_LOG_ERROR("|AddCert2PolicyCtx|END|||storeBuf is nullptr.");
            return SCF_ERROR;
        }
        auto ret = AddCertInner(ctx, fileCtx, storeBuf, certObj);
        delete[] storeBuf;
        SCF_FileCtxFree(&fileCtx);
        if (ret != SCF_SUCCESS) {
            return SCF_ERROR;
        }
    }
    return SCF_SUCCESS;
}

void CleanResource(SCF_FILE_CTX **fileCtx, char **storeBuf)
{
    SCF_FileCtxFree(fileCtx);
    if (storeBuf != nullptr && *storeBuf != nullptr) {
        delete[] *storeBuf;
        *storeBuf = nullptr;
    }
}

int32_t CreateAndInitializeFileCtx(const PrivKey &privKey, SCF_FILE_CTX *&fileCtx, char *&storeBuf)
{
    fileCtx = SCF_FileCtxNew();
    if (fileCtx == nullptr) {
        return SCF_ERRNO_MEM_ALLOC;
    }

    storeBuf = StringToCharPtr(privKey.storeBuf);
    if (storeBuf == nullptr) {
        SCF_FileCtxFree(&fileCtx);
        CCSEC_LOG_ERROR("|SetPrivKeyAndPwd4Ctx|END|||storeBuf is nullptr.");
        return SCF_ERROR;
    }

    return SCF_SUCCESS;
}

int32_t SetFileCtxPassword(SCF_FILE_CTX *fileCtx, KeyAuth &keyAuth)
{
    if (keyAuth.storeBuf.empty()) {
        CCSEC_LOG_ERROR("|SetFileCtxPassword|END|returnF||keyAuth is null");
        return SCF_ERROR;
    }
    if (!keyAuth.isCipher) {
        CCSEC_LOG_ERROR("|SetFileCtxPassword|END|returnF||keyAuth must be cipher");
        return SCF_ERROR;
    }
    // 配置文件中只能用密文
    int32_t ret = SCF_FileCtxSetPwd(fileCtx, reinterpret_cast<uint8_t *>(keyAuth.storeBuf.data()),
        keyAuth.storeBuf.size(), keyAuth.isCipher);
    if (ret != SCF_SUCCESS) {
        std::fill(keyAuth.storeBuf.begin(), keyAuth.storeBuf.end(), '\0');
        return ret;
    }
    return SCF_SUCCESS;
}

int32_t SetKeyAndPwd(SCF_PolicyCtx *ctx, SCF_FILE_CTX *fileCtx, char *&storeBuf, KeyAuth &keyAuth)
{
    auto ret = SCF_FileCtxSetBuf(fileCtx, SCF_STORE_FILE_PATH, reinterpret_cast<uint8_t *>(storeBuf),
        strlen(storeBuf), SCF_STORE_FORMAT_PEM);
    if (ret != SCF_SUCCESS) {
        return ret;
    }

    ret = SetFileCtxPassword(fileCtx, keyAuth);
    if (ret != SCF_SUCCESS) {
        return ret;
    }

    return SCF_SetKey(ctx, fileCtx);
}

int32_t SetPrivKeyAndPwd4Ctx(SCF_PolicyCtx *ctx, PrivKey &privKey)
{
    if (privKey.storeBuf.empty()) {
        if (privKey.keyAuth.storeBuf.empty()) {
            return SCF_SUCCESS;
        }
        CCSEC_LOG_ERROR("|SetPrivKeyAndPwd4Ctx||||no privKey for keyAuth");
        return SCF_ERROR;
    }
    SCF_FILE_CTX *fileCtx = nullptr;
    char *storeBuf = nullptr;

    int32_t ret = CreateAndInitializeFileCtx(privKey, fileCtx, storeBuf);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SetPrivKeyAndPwd4Ctx||||CreateAndInitializeFileCtx fail, ret:" << ret);
        CleanResource(&fileCtx, &storeBuf);
        return ret;
    }
    ret = SetKeyAndPwd(ctx, fileCtx, storeBuf, privKey.keyAuth);
    CleanResource(&fileCtx, &storeBuf);
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SetPrivKeyAndPwd4Ctx||||SetKeyAndPwd fail, ret:" << ret);
        return ret;
    }
    if (!privKey.keyAuth.storeBuf.empty()) {
        std::fill(privKey.keyAuth.storeBuf.begin(), privKey.keyAuth.storeBuf.end(), '\0');
    }
    CCSEC_LOG_DEBUG("|SetPrivKeyAndPwd4Ctx|END|returnS||set privKey and keyAuth success");
    return SCF_SUCCESS;
}

int32_t SetCipherSuites4PolicyCtx(SCF_PolicyCtx *ctx, const std::vector<uint16_t> &tlsCipherSuites)
{
    if (tlsCipherSuites.empty()) {
        CCSEC_LOG_DEBUG("|SetCipherSuites4PolicyCtx||||tls cipher suites is null");
        return SCF_SUCCESS;
    }
    if (SCF_SetCipherSuites(ctx, tlsCipherSuites.data(), static_cast<uint32_t>(tlsCipherSuites.size())) !=
        SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SetCipherSuites4PolicyCtx||||set cipher suites for policy context failed");
        return SCF_ERROR;
    }
    return SCF_SUCCESS;
}

int32_t SetProtocolVersion4PolicyCtx(SCF_PolicyCtx *ctx, const TlsVersion &tlsVersion)
{
    if (tlsVersion.maxVersion == 0 || tlsVersion.minVersion == 0) {
        CCSEC_LOG_DEBUG("|SetProtocolVersion4PolicyCtx||||tls version is null");
        return SCF_SUCCESS;
    }
    if (SCF_SetProtocolVersion(ctx, tlsVersion.minVersion, tlsVersion.maxVersion,
        const_cast<uint32_t *>(tlsVersion.forbidVersion.data()),
        static_cast<uint32_t>(tlsVersion.forbidVersion.size())) != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SetProtocolVersion4PolicyCtx||||set protocol version for policy context failed");
        return SCF_ERROR;
    }
    return SCF_SUCCESS;
}

int32_t ParseTLS(const rapidjson::Document &configDoc, Config &cfg)
{
    if (!configDoc.HasMember(TLS_VERSION)) {
        CCSEC_LOG_INFO("|SCF_ParseConfig||||config file tls version is null");
    } else if (SCF_ParseTLSVersion(configDoc[TLS_VERSION], cfg.tlsVersion) != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF|ParseTLSVersion|END|||tls version is invalid ");
        return SCF_ERROR;
    }

    if (!configDoc.HasMember(TLS_CIPHER_SUITES)) {
        CCSEC_LOG_INFO("|SCF_ParseConfig||||config file tls cipher suites if null");
    } else if (SCF_ParseTLSCiphersuites(configDoc[TLS_CIPHER_SUITES], cfg.tlsCipherSuites) != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_ParseConfig|END|returnF||tls cipher suites is invalid");
        return SCF_ERROR;
    }
    return SCF_SUCCESS;
}

int32_t ParseCertAndKey(const rapidjson::Document &configDoc, Config &cfg)
{
    if (!configDoc.HasMember(CERTS)) {
        CCSEC_LOG_INFO("|SCF_ParseConfig||||config file certs is null");
    } else if (SCF_ParseCertsJson(configDoc[CERTS], cfg.certs) != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_ParseConfig|END|returnF||certs is invalid");
        return SCF_ERROR;
    };

    if (!configDoc.HasMember(PRIVATE_KEY)) {
        CCSEC_LOG_INFO("|SCF_ParseConfig||||config file privkey is null");
    } else if (SCF_ParsePrivKeyJson(configDoc[PRIVATE_KEY], cfg.privKey) != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_ParseConfig|END|returnF||privKey is invalid");
        return SCF_ERROR;
    }
    return SCF_SUCCESS;
}

int SCF_ParseConfig(const std::string &filePath, Config &cfg)
{
    CCSEC_LOG_DEBUG("|SCF_ParseConfig|START|||start to parse config file." << filePath.c_str());
    // configDoc is automatically released at the end of the function
    rapidjson::Document configDoc = SCF_ReadConfig(filePath);
    if (configDoc.IsNull()) {
        CCSEC_LOG_WARN("|SCF_ParseConfig|END|||config doc is null");
        return SCF_ERROR;
    }

    if (ParseTLS(configDoc, cfg) != SCF_SUCCESS) {
        return SCF_ERROR;
    }

    if (ParseCertAndKey(configDoc, cfg) != SCF_SUCCESS) {
        return SCF_ERROR;
    }
    CCSEC_LOG_DEBUG("|SCF_ParseConfig|END|||parse config file success");
    return SCF_SUCCESS;
}
} // namespace scf