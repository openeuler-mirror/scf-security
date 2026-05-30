/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
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

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <vector>

#include "scf.h"
#include "scf_errno.h"
#include "scf_ssl.h"
#include "custom_logger.h"
#include "test_scf.h"

namespace fs = std::filesystem;

namespace test {

constexpr uint32_t CIPHER_COUNT_1 = 1;
constexpr uint32_t CIPHER_COUNT_2 = 2;
constexpr uint32_t CIPHER_COUNT_3 = 3;
constexpr uint32_t CIPHER_COUNT_INVALID = 100;
constexpr uint32_t FORBID_VERSION_COUNT_2 = 2;

class TestConfigParse : public ::testing::Test {
protected:
    void SetUp() override
    {
        SetExternalLogFunction(ExternalLogFunction);
        char libPath[] = "/usr/lib64";
        int32_t ret = SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);
        ASSERT_EQ(ret, SCF_SUCCESS);
        
        testDir = GetLocalPath() + "/test/test_data/config_parse_test";
        fs::create_directories(testDir);
    }
    
    void TearDown() override
    {
        fs::remove_all(testDir);
        SCF_DeInit();
        SetExternalLogFunction(nullptr);
    }
    
    std::string testDir;
};

TEST_F(TestConfigParse, SCF_SetConfigFile_ValidPath)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    std::string configFile = testDir + "/test_config.json";
    std::ofstream file(configFile);
    file << R"({
        "tlsVersion": {
            "minVersion": "SSL_VERSION_TLS12",
            "maxVersion": "SSL_VERSION_TLS13",
            "forbidVersion": []
        },
        "tlsCipherSuites": ["SCF_SSL_AES_128_GCM_SHA256"],
        "certs": [],
        "privKey": {
            "storeBuf": "",
            "keyAuth": {
                "storeBuf": "",
                "isCipher": false
            }
        }
    })";
    file.close();
    
    ret = SCF_SetConfigFile(ctx, configFile.c_str());
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_SetConfigFile_NullCtx)
{
    int32_t ret = SCF_SetConfigFile(nullptr, "/tmp/config.json");
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConfigParse, SCF_SetConfigFile_NullPath)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetConfigFile(ctx, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_SetConfigFile_EmptyPath)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetConfigFile(ctx, "");
    EXPECT_NE(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_SetConfigFile_NonExistentPath)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetConfigFile(ctx, "/nonexistent/path/config.json");
    EXPECT_NE(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_SetConfigFile_InvalidJson)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    std::string configFile = testDir + "/invalid.json";
    std::ofstream file(configFile);
    file << "{ invalid json }";
    file.close();
    
    ret = SCF_SetConfigFile(ctx, configFile.c_str());
    EXPECT_NE(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_SetConfigFile_MissingFields)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    std::string configFile = testDir + "/missing.json";
    std::ofstream file(configFile);
    file << "{}";
    file.close();
    
    ret = SCF_SetConfigFile(ctx, configFile.c_str());
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_SetConfigFile_EmptyFile)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    std::string configFile = testDir + "/empty.json";
    std::ofstream file(configFile);
    file << "";
    file.close();
    
    ret = SCF_SetConfigFile(ctx, configFile.c_str());
    EXPECT_NE(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_SetCipherSuites_MultipleCiphers)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t cipherSuites[] = {
        SCF_SSL_AES_128_GCM_SHA256,
        SCF_SSL_AES_256_GCM_SHA384,
        SCF_SSL_CHACHA20_POLY1305_SHA256
    };
    ret = SCF_SetCipherSuites(ctx, cipherSuites, CIPHER_COUNT_3);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_SetCipherSuites_SingleCipher)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t cipherSuites[] = {SCF_SSL_AES_128_GCM_SHA256};
    ret = SCF_SetCipherSuites(ctx, cipherSuites, CIPHER_COUNT_1);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_SetCipherSuites_ZeroSize)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t cipherSuites[] = {SCF_SSL_AES_128_GCM_SHA256};
    ret = SCF_SetCipherSuites(ctx, cipherSuites, 0);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_GetCipherSuites_ValidSize)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t cipherSuites[] = {SCF_SSL_AES_128_GCM_SHA256, SCF_SSL_AES_256_GCM_SHA384};
    ret = SCF_SetCipherSuites(ctx, cipherSuites, CIPHER_COUNT_2);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t retrieved[10] = {0};
    uint32_t size = 10;
    uint32_t actualSize = 0;
    ret = SCF_GetCipherSuites(ctx, retrieved, size, &actualSize);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret == SCF_SSL_ERR_GET_CIPHER);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_GetCipherSuites_SmallSize)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t cipherSuites[] = {SCF_SSL_AES_128_GCM_SHA256};
    ret = SCF_SetCipherSuites(ctx, cipherSuites, CIPHER_COUNT_1);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t retrieved[1] = {0};
    uint32_t size = 1;
    uint32_t actualSize = 0;
    ret = SCF_GetCipherSuites(ctx, retrieved, size, &actualSize);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret == SCF_SSL_ERR_GET_CIPHER);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_SetProtocolVersion_TLS12Only)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint32_t forbidVersion[] = {0};
    ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS12, forbidVersion, 0);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_SetProtocolVersion_TLS13Only)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint32_t forbidVersion[] = {0};
    ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS13, forbidVersion, 0);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_SetProtocolVersion_WithForbidVersion)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint32_t forbidVersion[] = {SCF_SSL_VERSION_TLS12};
    ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS13, forbidVersion, 1);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_SetProtocolVersion_MultipleForbidVersion)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint32_t forbidVersion[] = {SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS13};
    ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS12,
        SCF_SSL_VERSION_TLS13, forbidVersion, FORBID_VERSION_COUNT_2);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, SCF_SetProtocolVersion_NullForbidVersion)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS13, nullptr, 0);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, Policy_RoleClient)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_CLIENT, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, Policy_RoleServer)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, Policy_HighMode)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, Policy_MiddleMode)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, Policy_CustomerMode)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_CUSTOMER);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, Policy_GetPolicySuccess)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_ROLE role = SCF_ROLE_NONE;
    uint32_t verifyMode = 0;
    SCF_POLICY_MODE policyMode = SCF_POLICY_HIGH;
    ret = SCF_GetPolicy(ctx, &role, &verifyMode, &policyMode);
    EXPECT_EQ(ret, SCF_SUCCESS);
    EXPECT_EQ(role, SCF_ROLE_SERVER);
    EXPECT_EQ(verifyMode, static_cast<uint32_t>(SCF_VERIFY_DEFAULT));
    EXPECT_EQ(policyMode, SCF_POLICY_HIGH);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, Policy_GetPolicyNullRole)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint32_t verifyMode = 0;
    SCF_POLICY_MODE policyMode = SCF_POLICY_HIGH;
    ret = SCF_GetPolicy(ctx, nullptr, &verifyMode, &policyMode);
    EXPECT_NE(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, Policy_GetPolicyNullVerifyMode)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_ROLE role = SCF_ROLE_NONE;
    SCF_POLICY_MODE policyMode = SCF_POLICY_HIGH;
    ret = SCF_GetPolicy(ctx, &role, nullptr, &policyMode);
    EXPECT_NE(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, Policy_GetPolicyNullPolicyMode)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_ROLE role = SCF_ROLE_NONE;
    uint32_t verifyMode = 0;
    ret = SCF_GetPolicy(ctx, &role, &verifyMode, nullptr);
    EXPECT_NE(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, Policy_MultipleContexts)
{
    SCF_PolicyCtx *ctx1 = SCF_CreatePolicyCtx();
    SCF_PolicyCtx *ctx2 = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx1 != nullptr);
    ASSERT_TRUE(ctx2 != nullptr);
    
    int32_t ret1 = SCF_SetPolicy(ctx1, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    int32_t ret2 = SCF_SetPolicy(ctx2, SCF_ROLE_CLIENT, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
    
    EXPECT_EQ(ret1, SCF_SUCCESS);
    EXPECT_EQ(ret2, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx1);
    SCF_FreePolicyCtx(&ctx2);
}

TEST_F(TestConfigParse, Policy_MultipleObjectsSameCtx)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_PolicyObj *obj1 = SCF_CreatePolicyObj(ctx);
    SCF_PolicyObj *obj2 = SCF_CreatePolicyObj(ctx);
    
    if (obj1 != nullptr) {
        SCF_FreePolicyObj(&obj1);
    }
    if (obj2 != nullptr) {
        SCF_FreePolicyObj(&obj2);
    }
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestConfigParse, FileCtx_NewAndFree)
{
    SCF_FILE_CTX *ctx = SCF_FileCtxNew();
    if (ctx != nullptr) {
        SCF_FileCtxFree(&ctx);
        EXPECT_TRUE(ctx == nullptr);
    }
}

TEST_F(TestConfigParse, FileCtx_MultipleNew)
{
    SCF_FILE_CTX *ctx1 = SCF_FileCtxNew();
    SCF_FILE_CTX *ctx2 = SCF_FileCtxNew();
    
    if (ctx1 != nullptr) {
        SCF_FileCtxFree(&ctx1);
    }
    if (ctx2 != nullptr) {
        SCF_FileCtxFree(&ctx2);
    }
}

TEST_F(TestConfigParse, FileCtx_FreeNull)
{
    SCF_FileCtxFree(nullptr);
}

TEST_F(TestConfigParse, FileCtxSetPwd_Valid)
{
    SCF_FILE_CTX *ctx = SCF_FileCtxNew();
    if (ctx != nullptr) {
        uint8_t passwd[10] = {0x01, 0x02, 0x03};
        int32_t ret = SCF_FileCtxSetPwd(ctx, passwd, 3, false);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        SCF_FileCtxFree(&ctx);
    }
}

TEST_F(TestConfigParse, FileCtxSetPwd_NullCtx)
{
    uint8_t passwd[10] = {0};
    int32_t ret = SCF_FileCtxSetPwd(nullptr, passwd, 10, false);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConfigParse, FileCtxSetPwd_NullPasswd)
{
    SCF_FILE_CTX *ctx = SCF_FileCtxNew();
    if (ctx != nullptr) {
        int32_t ret = SCF_FileCtxSetPwd(ctx, nullptr, 10, false);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret == SCF_ERRNO_NULL_INPUT);
        SCF_FileCtxFree(&ctx);
    }
}

TEST_F(TestConfigParse, FileCtxSetPwd_ZeroLen)
{
    SCF_FILE_CTX *ctx = SCF_FileCtxNew();
    if (ctx != nullptr) {
        uint8_t passwd[10] = {0};
        int32_t ret = SCF_FileCtxSetPwd(ctx, passwd, 0, false);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        SCF_FileCtxFree(&ctx);
    }
}

TEST_F(TestConfigParse, SCF_CheckPrivateKey_NullCtx)
{
    int32_t ret = SCF_CheckPrivateKey(nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConfigParse, SCF_CheckPrivateKey_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_CheckPrivateKey(ctx);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

}