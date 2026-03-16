// Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
// Secure Communication Framework is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

#include <dlfcn.h>
#include <gtest/gtest.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <climits>
#include <cstring>
#include <filesystem>
#include <sstream>

#include "custom_logger.h"
#include "securec.h"

#include "scf.h"
#include "scf_def.h"
#include "scf_errno.h"
#include "scf_inner.h"
#include "scf_ssl.h"
#include "test_scf.h"

using namespace scf;

namespace test {

char g_cafilePath[PATH_MAX];
char g_configFilePath[PATH_MAX];

class TestTlsApiOpenssl : public ::testing::Test {
protected:
    void SetUp() override
    {
        SetExternalLogFunction(ExternalLogFunction);
        std::string filePath = GetLocalPath() + "/test/test_data/certificate/test_cert/ca.pem";
        if (realpath(filePath.c_str(), g_cafilePath) == nullptr) {
            CCSEC_LOG_ERROR("|get ca file path|||file path is:" << filePath << "|Get ca file path failed.");
        }
        std::string configfile = test::GetLocalPath() + "/test/test_data/configfile.json";
        if (realpath(configfile.c_str(), g_configFilePath) == nullptr) {
            CCSEC_LOG_ERROR("|get config file path|||file path is:" << filePath << "|Get config file path failed.");
        }
        std::string setting = "/usr/lib64";
        int32_t ret = SCF_Init(SCF_INIT_FLAG_OPENSSL, const_cast<char *>(setting.c_str()));
        ASSERT_EQ(ret, SCF_SUCCESS);
    }

    void TearDown() override
    {
        SCF_DeInit();
    }
};

[[maybe_unused]] static void LogLevelTest()
{
    CCSEC_LOG_TRACE("trace level");
    CCSEC_LOG_DEBUG("debug level");
    CCSEC_LOG_INFO("info level");
    CCSEC_LOG_WARN("warn level");
    CCSEC_LOG_ERROR("error level");
}

TEST_F(TestTlsApiOpenssl, SCF_ExternalLogFunction)
{
    SetExternalLogFunction(ExternalLogFunction);
    CCSEC_LOG_ERROR("aa");
    CCSEC_LOG_INFO("aa");
    CCSEC_LOG_WARN("aa");
    CCSEC_LOG_DEBUG("aa");
    CCSEC_LOG_TRACE("aa");
    SetExternalLogFunction(nullptr);
}

TEST_F(TestTlsApiOpenssl, Secure_Log_03)
{
    SCF_DeInit();
    char *settings = nullptr;

    ASSERT_EQ(SCF_Init(SCF_INIT_FLAG_OPENSSL + 1, settings), SCF_ERRNO_INVALID_PARAM);
    ASSERT_EQ(SCF_Init(SCF_INIT_FLAG_OPENSSL, settings), SCF_ERRNO_LOAD_LIB);
    SCF_DeInit();
    const char *settings2 = "nullptr";
    ASSERT_EQ(SCF_Init(SCF_INIT_FLAG_OPENSSL, const_cast<char *>(settings2)), SCF_ERRNO_LOAD_LIB);
}

TEST_F(TestTlsApiOpenssl, SCF_GetErroMsgTest)
{
    const char *msg = GetErrorMessage(SCF_SSL_ERR_ADD_EE_CHAIN_TO_STORE);
    ASSERT_TRUE(std::string(msg) == "SSL add EE chain to store error");
}

TEST_F(TestTlsApiOpenssl, SCF_FileCtxNew_FileCtxFree)
{
    SCF_FILE_CTX *tmpPtr = SCF_FileCtxNew();
    ASSERT_TRUE(tmpPtr != nullptr);
    SCF_FileCtxFree(&tmpPtr);
}

TEST_F(TestTlsApiOpenssl, SCF_FileCtxSetPwd)
{
    SCF_FILE_CTX *tmpPtr = SCF_FileCtxNew();
    ASSERT_TRUE(tmpPtr != nullptr);
    uint8_t passwd[] = "newpasswd";
    int32_t ret = SCF_FileCtxSetPwd(tmpPtr, passwd, strlen((const char *)passwd));
    ASSERT_EQ(ret, SCF_SUCCESS);
    (void)memset_s(passwd, sizeof(passwd), 0, sizeof(passwd));
    SCF_FileCtxFree(&tmpPtr);
}

TEST_F(TestTlsApiOpenssl, SCF_CheckFilePathAndStat)
{
    std::string testFilePath = "../filepath";
    auto ret = SCF_CheckFilePathAndStat(testFilePath);
    ASSERT_FALSE(ret);
    std::string testFilePath1 = "/tmp/";
    ret = SCF_CheckFilePathAndStat(testFilePath);
    ASSERT_FALSE(ret);
    std::string testFilePath2 = "/etc/os-release";
    ret = SCF_CheckFilePathAndStat(testFilePath);
    ASSERT_FALSE(ret);
    ret = CanonicalPath(testFilePath1);
    ASSERT_TRUE(ret);
    ret = CheckFileStat(testFilePath1);
    ASSERT_FALSE(ret);
}

TEST_F(TestTlsApiOpenssl, SCF_CreatePolicyCtx_SetPolicy_FreePolicyCtx)
{
    SCF_FILE_CTX *tmpPtr = SCF_FileCtxNew();
    ASSERT_TRUE(tmpPtr != nullptr);
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);

    int32_t ret = SCF_SetPolicy(policyctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_CUSTOMER);
    ASSERT_EQ(ret, SCF_SUCCESS);

    SCF_PolicyObj *policyobj = SCF_CreatePolicyObj(policyctx);
    ASSERT_TRUE(policyobj != nullptr);

    ret = SCF_FileCtxSetBuf(tmpPtr, SCF_STORE_FILE_PATH, reinterpret_cast<uint8_t *>(g_cafilePath),
        strlen(g_cafilePath),
        SCF_STORE_FORMAT_PEM);
    ASSERT_EQ(ret, SCF_SUCCESS);

    uint8_t passwd[] = "123456";
    ret = SCF_FileCtxSetPwd(tmpPtr, passwd, strlen(reinterpret_cast<const char *>(passwd)));
    (void)memset_s(passwd, sizeof(passwd), 0, sizeof(passwd));

    ret = SCF_SetKey(policyctx, tmpPtr);
    ASSERT_EQ(ret, SCF_SSL_ERR_LOAD_KEY); // 返回值报错

    ret = SCF_SetFd(policyobj, 0);
    ASSERT_EQ(ret, SCF_SUCCESS);

    uint16_t cipherSuites[] = {SCF_SSL_AES_256_GCM_SHA384};
    ret = SCF_SetCipherSuites(policyctx, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t));
    ASSERT_EQ(ret, SCF_SUCCESS);

    ret = SCF_SetProtocolVersion(policyctx, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS13, NULL, 0);
    ASSERT_EQ(ret, SCF_SUCCESS);

    SCF_ROLE role = SCF_ROLE_CLIENT;
    uint32_t verifyMode = SCF_VERIFY_PEER;
    SCF_POLICY_MODE policyMode = SCF_POLICY_MIDDLE;
    ret = SCF_GetPolicy(nullptr, &role, &verifyMode, &policyMode);
    ASSERT_NE(ret, SCF_SUCCESS);
    ret = SCF_GetPolicy(policyctx, &role, &verifyMode, &policyMode);

    ASSERT_EQ(ret, SCF_SUCCESS);

    ASSERT_EQ(role, SCF_ROLE_SERVER);

    ASSERT_EQ(verifyMode, SCF_VERIFY_DEFAULT);

    ASSERT_EQ(policyMode, SCF_POLICY_CUSTOMER);

    const char *version = SCF_GetProtocolVersion(policyobj);
    ASSERT_TRUE(version != nullptr);

    ret = SCF_CheckPrivateKey(policyctx);
    ASSERT_EQ(ret, SCF_SSL_ERR_CHECK_PKEY); // 返回值报错

    SCF_FreePolicyObj(&policyobj);
    SCF_FreePolicyCtx(&policyctx);
    SCF_FileCtxFree(&tmpPtr);
}

TEST_F(TestTlsApiOpenssl, SCF_SessionNew_SessionFree)
{
    SCF_Session *sessionnew = SCF_SessionNew();
    ASSERT_TRUE(sessionnew != nullptr);
    SCF_SessionFree(&sessionnew);
}

TEST_F(TestTlsApiOpenssl, SCF_SessionSetMasterKey)
{
    SCF_Session *sessionnew = SCF_SessionNew();
    ASSERT_TRUE(sessionnew != nullptr);
    const char *pskPlainShA256 = "pskPlainSha256";
    int32_t ret = SCF_SessionSetMasterKey(sessionnew, reinterpret_cast<const uint8_t *>(pskPlainShA256),
        strlen(pskPlainShA256));
    ASSERT_EQ(ret, SCF_SUCCESS);
    SCF_SessionFree(&sessionnew);
}

TEST_F(TestTlsApiOpenssl, SCF_SessionSetCipher)
{
    SCF_Session *sessionnew = SCF_SessionNew();
    ASSERT_TRUE(sessionnew != nullptr);
    uint16_t cipherSuites = SCF_SSL_AES_128_GCM_SHA256;
    int32_t ret = SCF_SessionSetCipher(sessionnew, &cipherSuites, 2);
    ASSERT_EQ(ret, SCF_SUCCESS);
    size_t cipherLen = 0;
    uint16_t *queryCipherSuits = nullptr;
    ret = SCF_SessionGetCipher(sessionnew, reinterpret_cast<void **>(&queryCipherSuits), cipherLen);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ASSERT_NE(queryCipherSuits, nullptr);
    ASSERT_EQ(*queryCipherSuits, cipherSuites);
    ASSERT_NO_THROW(SCF_SessionFreeCipher(reinterpret_cast<void **>(&queryCipherSuits), cipherLen));
    SCF_SessionFree(&sessionnew);
}

TEST_F(TestTlsApiOpenssl, SCF_SessionSetProtocolVersion)
{
    SCF_Session *sessionnew = SCF_SessionNew();
    ASSERT_TRUE(sessionnew != nullptr);
    int32_t ret = SCF_SessionSetProtocolVersion(sessionnew, SCF_SSL_VERSION_TLS13_STR);
    ASSERT_EQ(ret, SCF_SUCCESS);
    char *queryVersion = nullptr;
    size_t versionLen = 0;
    ASSERT_EQ(SCF_SessionGetProtocolVersion(sessionnew, &queryVersion, versionLen), SCF_SUCCESS);
    ASSERT_NE(queryVersion, nullptr);
    EXPECT_EQ(std::string(queryVersion), SCF_SSL_VERSION_TLS13_STR);
    ASSERT_NO_THROW(SCF_FreeBuffer(&queryVersion, versionLen));
    SCF_SessionFree(&sessionnew);
}

TEST_F(TestTlsApiOpenssl, SCF_GetCertVersion)
{
    void *cert = nullptr;
    int32_t ret = SCF_GetCertVersion(cert);
    ASSERT_EQ(ret, -1);
    SCF_FreeCert(&cert);
}

TEST_F(TestTlsApiOpenssl, SCF_GetCertStartTime)
{
    void *cert = nullptr;
    char certTimeBuffer[100]; // 100 buffer length
    int length = 100;         // 100 buffer length
    auto ret = SCF_GetCertStartTime(cert, certTimeBuffer, length);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    SCF_FreeCert(&cert);
}

TEST_F(TestTlsApiOpenssl, SCF_GetCertEndTime)
{
    void *cert = nullptr;
    char certTimeBuffer[100]; // 100 buffer length
    int length = 100;         // 100 buffer length
    auto ret = SCF_GetCertEndTime(cert, certTimeBuffer, length);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    SCF_FreeCert(&cert);
}

TEST_F(TestTlsApiOpenssl, SCF_GetCertSerialNumber)
{
    void *cert = nullptr;
    uint32_t *dataLen = nullptr;
    uint8_t *serialNum = SCF_GetCertSerialNumber(cert, dataLen);
    ASSERT_EQ(serialNum, nullptr);
    SCF_FreeCert(&cert);
}

TEST_F(TestTlsApiOpenssl, SCF_GetCipherSuites)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    uint16_t data[1024];
    uint32_t *cipherSuitesSize = nullptr;
    int32_t ret = SCF_GetCipherSuites(policyctx, data, 1024, cipherSuitesSize);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT); // 返回值报错
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, SCF_Close)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    SCF_PolicyObj *policyobj = SCF_CreatePolicyObj(policyctx);
    ASSERT_TRUE(policyobj != nullptr);
    int32_t ret = SCF_Close(policyobj);
    ASSERT_EQ(ret, SCF_SUCCESS);
    SCF_FreePolicyObj(&policyobj);
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, SCF_CipherFind)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    SCF_PolicyObj *policyobj = SCF_CreatePolicyObj(policyctx);
    ASSERT_TRUE(policyobj != nullptr);
    uint8_t *cipherId = nullptr;
    const void *buff = SCF_CipherFind(policyobj, cipherId);
    ASSERT_EQ(buff, nullptr);
    SCF_FreePolicyObj(&policyobj);
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, SCF_GetPeerCert)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    SCF_PolicyObj *policyobj = SCF_CreatePolicyObj(policyctx);
    ASSERT_TRUE(policyobj != nullptr);
    const void *buff = SCF_GetPeerCert(policyobj);
    ASSERT_EQ(buff, nullptr);
    SCF_FreePolicyObj(&policyobj);
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, SCF_GetCurrentCert)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    SCF_PolicyObj *policyobj = SCF_CreatePolicyObj(policyctx);
    ASSERT_TRUE(policyobj != nullptr);
    const void *buff = SCF_GetCurrentCert(policyobj);
    ASSERT_EQ(buff, nullptr);
    SCF_FreePolicyObj(&policyobj);
    SCF_FreePolicyCtx(&policyctx);
}

/* *
 * API 异常入参测试
 */
TEST_F(TestTlsApiOpenssl, UT_API_SCF_SetPolicy_TC001)
{
    int32_t ret = SCF_SetPolicy(nullptr, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    ret = SCF_SetPolicy(policyctx, SCF_ROLE_NONE, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    auto maxRole = static_cast<SCF_ROLE>(SCF_ROLE_SERVER + 1);
    ret = SCF_SetPolicy(policyctx, maxRole, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    auto errMode = static_cast<SCF_VERIFY_MODE>(SCF_VERIFY_FAIL_IF_NO_PEER_CERT + 1);
    ret = SCF_SetPolicy(policyctx, SCF_ROLE_SERVER, errMode, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    SCF_POLICY_MODE errPolicyMode = SCF_POLICY_MIDDLE;
    ret = SCF_SetPolicy(policyctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, errPolicyMode);
    SCF_FreePolicyCtx(&policyctx);
    ASSERT_EQ(ret, SCF_SUCCESS);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_AddCert_TC001)
{
    int32_t ret = SCF_ERROR;
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);

    SCF_FILE_CTX *fileCtx = SCF_FileCtxNew();
    ASSERT_TRUE(fileCtx != nullptr);
    ret = SCF_FileCtxSetBuf(fileCtx, SCF_STORE_FILE_PATH, reinterpret_cast<uint8_t *>(g_cafilePath),
        strlen(g_cafilePath),
        SCF_STORE_FORMAT_PEM);
    ASSERT_EQ(ret, SCF_SUCCESS);

    ret = SCF_AddCert(nullptr, fileCtx, SCF_CERT_TYPE_CA);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    ret = SCF_AddCert(policyctx, nullptr, SCF_CERT_TYPE_CA);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    auto errCertType = static_cast<SCF_CERT_TYPE>(SCF_CERT_TYPE_CRL + 1);
    ret = SCF_AddCert(policyctx, fileCtx, errCertType); // 超过最大值的类型
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    ret = SCF_AddCert(policyctx, fileCtx, SCF_CERT_TYPE_CA); // 正确的类型，但没有配置策略方式
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    SCF_FreePolicyCtx(&policyctx);
    SCF_FileCtxFree(&fileCtx);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_SetKey_TC001)
{
    int32_t ret = SCF_ERROR;
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);

    SCF_FILE_CTX *fileCtx = SCF_FileCtxNew();
    ASSERT_TRUE(fileCtx != nullptr);
    ret = SCF_FileCtxSetBuf(fileCtx, SCF_STORE_FILE_PATH, reinterpret_cast<uint8_t *>(g_cafilePath),
        strlen(g_cafilePath), SCF_STORE_FORMAT_PEM);
    ASSERT_EQ(ret, SCF_SUCCESS);

    ret = SCF_SetKey(nullptr, fileCtx);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    ret = SCF_SetKey(policyctx, nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    ret = SCF_SetKey(policyctx, fileCtx); // 正确的类型，但没有配置策略方式
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    SCF_FreePolicyCtx(&policyctx);
    SCF_FileCtxFree(&fileCtx);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_SetFd_TC001)
{
    int32_t ret = SCF_ERROR;
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    SCF_PolicyObj *policyobj = SCF_CreatePolicyObj(policyctx);
    ASSERT_TRUE(policyobj != nullptr);

    ret = SCF_SetFd(nullptr, 0);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    ret = SCF_SetFd(policyobj, -1);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    ret = SCF_SetFd(policyobj, 1); // 未配置策略类型
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    SCF_FreePolicyObj(&policyobj);
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_SetProtocolVersion_TC001)
{
    int32_t ret = SCF_ERROR;
    SCF_PolicyCtx *m_server = SCF_CreatePolicyCtx();
    SCF_PolicyCtx *m_client = SCF_CreatePolicyCtx();
    ASSERT_TRUE(m_server != nullptr);
    ret = SCF_SetProtocolVersion(nullptr, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS13, nullptr, 0);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    ret =
        SCF_SetProtocolVersion(m_client, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS13, nullptr, 0); // 未配置策略类型
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    ret = SCF_SetPolicy(m_server, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_SetProtocolVersion(m_server, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS13, nullptr, 0);
    ASSERT_EQ(ret, SCF_SSL_ERR_POLICY_VERSION);
    SCF_FreePolicyCtx(&m_server);
    SCF_FreePolicyCtx(&m_client);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_FileCtxSetPwd_TC001)
{
    SCF_FILE_CTX *tmpPtr = SCF_FileCtxNew();
    ASSERT_TRUE(tmpPtr != nullptr);
    uint8_t passwd[] = "newpasswd";
    int32_t ret = SCF_FileCtxSetPwd(nullptr, passwd, strlen(reinterpret_cast<const char *>(passwd)));
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    ret = SCF_FileCtxSetPwd(tmpPtr, nullptr, 0);
    ASSERT_EQ(ret, SCF_SUCCESS);

    (void)memset_s(passwd, sizeof(passwd), 0, sizeof(passwd));
    SCF_FileCtxFree(&tmpPtr);
}

bool MockDecrypt(const uint8_t *content, size_t contentLen, std::vector<std::byte> &plaintext)
{
    if (content == nullptr || contentLen == 0) {
        return false;
    }
    plaintext.resize(contentLen);
    std::transform(content, content + contentLen, plaintext.begin(),
                   [](uint8_t x) { return static_cast<std::byte>(x); });
    return true;
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_FileCtxSetPwdWithEncrypt)
{
    // 实际送的是明文，目前已经移除crypto依赖，如需使用加密，自行实现解密函数，并配置回调函数
    SetExternalDecryptFunction(MockDecrypt);
    std::string orPlaintext = "suidkgoekaaa";
    auto *passwd = reinterpret_cast<uint8_t *>(const_cast<char *>(orPlaintext.c_str()));
    size_t passwdLen = orPlaintext.size();

    SCF_FILE_CTX *tmpPtr = SCF_FileCtxNew();
    ASSERT_TRUE(tmpPtr != nullptr);
    // 传入密文
    int32_t ret = SCF_FileCtxSetPwd(tmpPtr, passwd, passwdLen, true);
    ASSERT_EQ(ret, SCF_SUCCESS);

    (void)memset_s(passwd, sizeof(passwd), 0, sizeof(passwd));
    SCF_FileCtxFree(&tmpPtr);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_FileCtxSetBuf_TC001)
{
    SCF_FILE_CTX *tmpPtr = SCF_FileCtxNew();
    ASSERT_TRUE(tmpPtr != nullptr);

    int32_t ret = SCF_FileCtxSetBuf(nullptr, SCF_STORE_FILE_PATH, reinterpret_cast<uint8_t *>(g_cafilePath),
        strlen(g_cafilePath), SCF_STORE_FORMAT_PEM);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    ret = SCF_FileCtxSetBuf(tmpPtr, SCF_STORE_FILE_PATH, nullptr, 0, SCF_STORE_FORMAT_PEM);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    SCF_FileCtxFree(&tmpPtr);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_SetCipherSuites_TC001)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    uint16_t cipherSuites[] = {SCF_SSL_AES_256_GCM_SHA384};
    int32_t ret = SCF_SetCipherSuites(nullptr, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t));
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    ret = SCF_SetCipherSuites(policyctx, nullptr, sizeof(cipherSuites) / sizeof(uint16_t));
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    ret = SCF_SetCipherSuites(policyctx, cipherSuites, 0);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    (void)memset_s(cipherSuites, sizeof(cipherSuites), 0, sizeof(cipherSuites));
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_SessionSetMasterKey_TC001)
{
    SCF_Session *sessionnew = SCF_SessionNew();
    ASSERT_TRUE(sessionnew != nullptr);
    const char *pskPlainShA256 = "pskPlainSha256";
    int32_t ret =
        SCF_SessionSetMasterKey(nullptr, reinterpret_cast<const uint8_t *>(pskPlainShA256), strlen(pskPlainShA256));
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    ret = SCF_SessionSetMasterKey(sessionnew, nullptr, strlen(pskPlainShA256));
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    ret = SCF_SessionSetMasterKey(sessionnew, reinterpret_cast<const uint8_t *>(pskPlainShA256), 0);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    SCF_SessionFree(&sessionnew);
}
TEST_F(TestTlsApiOpenssl, UT_API_SCF_SessionSetMasterKey_WithEncrypt)
{
    // 实际送的是明文，目前已经移除crypto依赖，如需使用加密，自行实现解密函数，并配置回调函数
    SetExternalDecryptFunction(MockDecrypt);
    std::string orPlaintext = "pskPlainSha256sgwegwsegweg";
    uint8_t *passwd = reinterpret_cast<uint8_t *>(const_cast<char *>(orPlaintext.c_str()));
    size_t passwdLen = orPlaintext.size();
    SCF_Session *sessionnew = SCF_SessionNew();
    ASSERT_TRUE(sessionnew != nullptr);
    int32_t ret = SCF_SessionSetMasterKey(sessionnew, passwd, passwdLen, true);
    ASSERT_EQ(ret, SCF_SUCCESS);
    SCF_SessionFree(&sessionnew);
    memset_s(passwd, passwdLen, 0, passwdLen);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_SessionSetCipher_TC001)
{
    SCF_Session *sessionnew = SCF_SessionNew();
    ASSERT_TRUE(sessionnew != nullptr);
    uint16_t cipherSuites = SCF_SSL_AES_128_GCM_SHA256;
    EXPECT_EQ(SCF_SessionSetCipher(nullptr, &cipherSuites, 2), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_SessionSetCipher(sessionnew, nullptr, 2), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_SessionSetCipher(sessionnew, &cipherSuites, 1), SCF_SUCCESS);
    EXPECT_EQ(SCF_SessionSetCipher(sessionnew, &cipherSuites, 2), SCF_SUCCESS);
    SCF_SessionFree(&sessionnew);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_SessionSetProtocolVersion_TC001)
{
    SCF_Session *sessionnew = SCF_SessionNew();
    ASSERT_TRUE(sessionnew != nullptr);
    int32_t ret = SCF_SessionSetProtocolVersion(nullptr, SCF_SSL_VERSION_TLS13_STR);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    ret = SCF_SessionSetProtocolVersion(sessionnew, nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    SCF_SessionFree(&sessionnew);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_GetCertVersion_TC001)
{
    int32_t ret = SCF_GetCertVersion(nullptr);
    ASSERT_EQ(ret, -1);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_GetCipherSuites_TC001)
{
    uint16_t data[1024];
    uint32_t *cipherSuitesSize = nullptr;
    int32_t ret = SCF_GetCipherSuites(nullptr, data, 1024, cipherSuitesSize);
    (void)memset_s(data, sizeof(data), 0, sizeof(data));
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_Connect_TC001)
{
    int32_t ret = SCF_Connect(nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_Accept_TC001)
{
    int32_t ret = SCF_Accept(nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_Read_TC001)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    SCF_PolicyObj *policyobj = SCF_CreatePolicyObj(policyctx);
    ASSERT_TRUE(policyobj != nullptr);
    uint8_t data[] = "123";
    uint32_t dataLen = sizeof(data);
    uint32_t readLen = 0;
    int32_t ret = SCF_Read(nullptr, data, dataLen, &readLen);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    ret = SCF_Read(policyobj, nullptr, dataLen, &readLen);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    ret = SCF_Read(policyobj, data, 0, &readLen);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    (void)memset_s(data, sizeof(data), 0, sizeof(data));
    SCF_FreePolicyObj(&policyobj);
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_Write_TC001)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    SCF_PolicyObj *policyobj = SCF_CreatePolicyObj(policyctx);
    ASSERT_TRUE(policyobj != nullptr);

    uint8_t data[] = "123";
    uint32_t dataLen = sizeof(data);
    uint32_t writeLen = 0;
    int32_t ret = SCF_Write(nullptr, data, dataLen, &writeLen);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    ret = SCF_Write(policyobj, nullptr, dataLen, &writeLen);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    ret = SCF_Write(policyobj, data, 0, &writeLen);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    (void)memset_s(data, sizeof(data), 0, sizeof(data));
    SCF_FreePolicyObj(&policyobj);
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_CheckPrivateKey_TC001)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    int32_t ret = SCF_CheckPrivateKey(policyctx);
    ASSERT_EQ(ret, SCF_SSL_ERR_CHECK_PKEY);
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_SetAppVerifyCallback_TC001)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    int32_t ret = SCF_SetAppVerifyCallback(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    ret = SCF_SetAppVerifyCallback(policyctx, nullptr, nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_SetPskFindSessionCallback_TC001)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    int32_t ret = SCF_SetPskFindSessionCallback(nullptr, nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    ret = SCF_SetPskFindSessionCallback(policyctx, nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, UT_API_SCF_SetPskUseSessionCallback_TC001)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    int32_t ret = SCF_SetPskUseSessionCallback(nullptr, nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    ret = SCF_SetPskUseSessionCallback(policyctx, nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, SCF_SetKeyAutoUpdateParam)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    uint32_t keyUpdateTime = 60;
    uint64_t keyUpdateTraffic = UINT64_MAX;
    int32_t ret = SCF_SetKeyAutoUpdateParam(nullptr, true, keyUpdateTime, keyUpdateTraffic);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    keyUpdateTime = 70;         // 测试模拟更新时间阈值70
    keyUpdateTraffic = 1000009; // 测试模拟更新流量阈值1000009
    ret = SCF_SetKeyAutoUpdateParam(policyctx, true, keyUpdateTime, keyUpdateTraffic);
    ASSERT_EQ(ret, SCF_SUCCESS);

    keyUpdateTime = 3600 * 24 * 365; // 测试模拟更新时间阈值3600 * 24 * 365
    keyUpdateTraffic = UINT64_MAX;
    ret = SCF_SetKeyAutoUpdateParam(policyctx, true, keyUpdateTime, keyUpdateTraffic);
    ASSERT_EQ(ret, SCF_SUCCESS);

    keyUpdateTime = 0;          // 测试模拟更新时间阈值0
    keyUpdateTraffic = 1000000; // 测试模拟更新流量阈值1000000
    ret = SCF_SetKeyAutoUpdateParam(policyctx, true, keyUpdateTime, keyUpdateTraffic);
    ASSERT_EQ(ret, SCF_SSL_ERR_SET_UPDATE_PARAM);

    keyUpdateTime = 60;     // 测试模拟更新时间阈值60
    keyUpdateTraffic = 999; // 测试模拟更新流量阈值999
    ret = SCF_SetKeyAutoUpdateParam(policyctx, true, keyUpdateTime, keyUpdateTraffic);
    ASSERT_EQ(ret, SCF_SSL_ERR_SET_UPDATE_PARAM);

    keyUpdateTime = 3600 * 24 * 365 + 1; // 测试模拟更新时间阈值3600 * 24 * 365 + 1
    keyUpdateTraffic = 1000000;          // 测试模拟更新流量阈值1000000
    ret = SCF_SetKeyAutoUpdateParam(policyctx, true, keyUpdateTime, keyUpdateTraffic);
    ASSERT_EQ(ret, SCF_SSL_ERR_SET_UPDATE_PARAM);
    SCF_FreePolicyCtx(&policyctx);
}
TEST_F(TestTlsApiOpenssl, UT_SCF_GetKeyAutoUpdateParam)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);

    uint32_t expectKeyUpdateTime = 70; // 测试模拟更新时间阈值70
    uint64_t expectKeyUpdateTraffic = 1000009; // 测试模拟更新流量阈值1000009
    int32_t ret = SCF_SetKeyAutoUpdateParam(policyctx, true, expectKeyUpdateTime, expectKeyUpdateTraffic);
    EXPECT_EQ(ret, SCF_SUCCESS);
    uint32_t actKeyUpdateTime = 0;
    uint64_t actKeyUpdateTraffic = 0;
    bool needKeyUpdate = false;
    EXPECT_EQ(SCF_GetKeyAutoUpdateParam(policyctx, needKeyUpdate, actKeyUpdateTime, actKeyUpdateTraffic),
              SCF_SUCCESS);
    EXPECT_EQ(ret, SCF_SUCCESS);
    EXPECT_TRUE(needKeyUpdate);
    EXPECT_EQ(actKeyUpdateTime, expectKeyUpdateTime);
    EXPECT_EQ(actKeyUpdateTraffic, expectKeyUpdateTraffic);
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, SCF_ObjKeyUpdate)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    SCF_PolicyObj *policyobj = SCF_CreatePolicyObj(policyctx);
    ASSERT_TRUE(policyobj != nullptr);

    int32_t ret = SCF_ObjKeyUpdate(nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    SCF_FreePolicyObj(&policyobj);
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, SCF_SetUserData)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    SCF_PolicyObj *policyobj = SCF_CreatePolicyObj(policyctx);
    ASSERT_TRUE(policyobj != nullptr);
    char userData[10];
    auto ret = SCF_SetUserData(nullptr, userData);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    ret = SCF_SetUserData(policyobj, nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    ret = SCF_SetUserData(policyobj, userData);
    ASSERT_EQ(ret, SCF_SUCCESS);
    SCF_FreePolicyObj(&policyobj);
    SCF_FreePolicyCtx(&policyctx);
}

TEST_F(TestTlsApiOpenssl, SCF_GetUserData)
{
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    SCF_PolicyObj *policyobj = SCF_CreatePolicyObj(policyctx);
    ASSERT_TRUE(policyobj != nullptr);
    void *ret = SCF_GetUserData(nullptr);
    ASSERT_TRUE(ret == nullptr);
    SCF_GetUserData(policyobj);
    SCF_FreePolicyObj(&policyobj);
    SCF_FreePolicyCtx(&policyctx);
}

} // namespace test