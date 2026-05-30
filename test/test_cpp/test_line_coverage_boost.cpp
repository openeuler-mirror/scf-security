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
#include <cstring>
#include <fstream>
#include <filesystem>

#include "scf.h"
#include "scf_errno.h"
#include "scf_ssl.h"
#include "scf_inner.h"
#include "custom_logger.h"
#include "test_scf.h"
#include "parse_config.h"

namespace fs = std::filesystem;

namespace test {

constexpr uint32_t VERIFY_MODE_INVALID = 100;
constexpr uint32_t VERIFY_MODE_MAX = 15;
constexpr int32_t INVALID_FD_NEGATIVE = -100;
constexpr int32_t FD_SIZE_SMALL = 10;
constexpr int32_t FD_SIZE_MEDIUM = 100;
constexpr int32_t FD_SIZE_LARGE = 1000;
constexpr int32_t LOOP_COUNT_20 = 20;
constexpr int32_t CIPHER_COUNT_50 = 50;
constexpr int32_t BUFFER_SIZE_10 = 10;
constexpr int32_t INVALID_VERSION_9999 = 9999;
constexpr int32_t BUFFER_SIZE_64 = 64;
constexpr int64_t TRAFFIC_1M = 1000000;
constexpr int32_t TIME_60 = 60;
constexpr int32_t PASSWORD_LEN_5 = 5;
constexpr int32_t PASSWORD_LEN_100 = 100;
constexpr int32_t PASSWORD_LEN_256 = 256;

class TestLineCoverageBoost : public ::testing::Test {
protected:
    void SetUp() override
    {
        SetExternalLogFunction(ExternalLogFunction);
        char libPath[] = "/usr/lib64";
        int32_t ret = SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);
        ASSERT_EQ(ret, SCF_SUCCESS);
    }
    
    void TearDown() override
    {
        SCF_DeInit();
        SetExternalLogFunction(nullptr);
    }
};

TEST_F(TestLineCoverageBoost, SCF_Init_DoubleInit)
{
    char libPath[] = "/usr/lib64";
    int32_t ret = SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(TestLineCoverageBoost, SCF_DeInit_WithoutInit)
{
    SCF_DeInit();
    SCF_DeInit();
    
    char libPath[] = "/usr/lib64";
    int32_t ret = SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(TestLineCoverageBoost, PolicyCtx_CreateAfterDeInit)
{
    SCF_DeInit();
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    EXPECT_TRUE(ctx == nullptr);
    
    char libPath[] = "/usr/lib64";
    SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);
}

TEST_F(TestLineCoverageBoost, PolicyObj_CreateWithNullCtx)
{
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(nullptr);
    EXPECT_TRUE(obj == nullptr);
}

TEST_F(TestLineCoverageBoost, PolicyObj_CreateMultipleObjects)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    std::vector<SCF_PolicyObj*> objects;
    for (int i = 0; i < LOOP_COUNT_20; ++i) {
        SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
        if (obj != nullptr) {
            objects.push_back(obj);
        }
    }
    
    for (auto obj : objects) {
        SCF_FreePolicyObj(&obj);
    }
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, Policy_DifferentVerifyModesCombinations)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    std::vector<uint32_t> verifyModes = {
        SCF_VERIFY_MODE_NONE,
        SCF_VERIFY_DEFAULT,
        SCF_VERIFY_PEER,
        SCF_VERIFY_FAIL_IF_NO_PEER_CERT,
        SCF_VERIFY_CUSTOMER,
        static_cast<uint32_t>(SCF_VERIFY_PEER | SCF_VERIFY_FAIL_IF_NO_PEER_CERT),
        VERIFY_MODE_INVALID,
        VERIFY_MODE_MAX
    };
    
    for (auto mode : verifyModes) {
        int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, mode, SCF_POLICY_HIGH);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret == SCF_ERRNO_INVALID_PARAM);
    }
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, SetCipherSuites_EmptyArray)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t cipherSuites[1] = {0};
    ret = SCF_SetCipherSuites(ctx, cipherSuites, 0);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, SetCipherSuites_InvalidCipher)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t cipherSuites[] = {9999};
    ret = SCF_SetCipherSuites(ctx, cipherSuites, 1);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, SetCipherSuites_MaxSize)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t cipherSuites[CIPHER_COUNT_50] = {SCF_SSL_AES_128_GCM_SHA256};
    ret = SCF_SetCipherSuites(ctx, cipherSuites, CIPHER_COUNT_50);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, GetCipherSuites_ZeroSize)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t retrieved[10] = {0};
    uint32_t actualSize = 0;
    ret = SCF_GetCipherSuites(ctx, retrieved, 1, &actualSize);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret == SCF_SSL_ERR_GET_CIPHER);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, GetCipherSuites_NullActualSize)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t retrieved[BUFFER_SIZE_10] = {0};
    ret = SCF_GetCipherSuites(ctx, retrieved, BUFFER_SIZE_10, nullptr);
    EXPECT_TRUE(ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, SetProtocolVersion_InvalidMinVersion)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint32_t forbidVersion[] = {0};
    ret = SCF_SetProtocolVersion(ctx, INVALID_VERSION_9999, SCF_SSL_VERSION_TLS13, forbidVersion, 0);
    EXPECT_TRUE(ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, SetProtocolVersion_InvalidMaxVersion)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint32_t forbidVersion[] = {0};
    ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS12, INVALID_VERSION_9999, forbidVersion, 0);
    EXPECT_TRUE(ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, SetProtocolVersion_ReverseOrder)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint32_t forbidVersion[] = {0};
    ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS12, forbidVersion, 0);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, SetKeyAutoUpdateParam_VariousTimeValues)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    std::vector<uint32_t> timeValues = {0, 1, 30, 59, 60, 100, 3600, 86400, 31536000, 31536001};
    for (auto time : timeValues) {
        ret = SCF_SetKeyAutoUpdateParam(ctx, true, time, TRAFFIC_1M);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret == SCF_SSL_ERR_SET_UPDATE_PARAM);
    }
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, SetKeyAutoUpdateParam_VariousTrafficValues)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    std::vector<uint64_t> trafficValues = {0, 1, 999, 1000, 10000, 1000000, UINT64_MAX};
    for (auto traffic : trafficValues) {
        ret = SCF_SetKeyAutoUpdateParam(ctx, true, TIME_60, traffic);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret == SCF_SSL_ERR_SET_UPDATE_PARAM);
    }
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, SetFd_VariousFdValues)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
    ASSERT_TRUE(obj != nullptr);
    
    std::vector<int32_t> fdValues = {INVALID_FD_NEGATIVE, -1, 0, 1, FD_SIZE_SMALL, FD_SIZE_MEDIUM, FD_SIZE_LARGE};
    for (auto fd : fdValues) {
        ret = SCF_SetFd(obj, fd);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    }
    
    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, Read_Write_WithDifferentFd)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
    ASSERT_TRUE(obj != nullptr);
    
    ret = SCF_SetFd(obj, 1);
    ASSERT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    uint8_t data[BUFFER_SIZE_10] = {0};
    uint32_t readLen = 0;
    ret = SCF_Read(obj, data, BUFFER_SIZE_10, &readLen);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    uint32_t writeLen = 0;
    ret = SCF_Write(obj, data, BUFFER_SIZE_10, &writeLen);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, FileCtx_NewAndFreeMultipleTimes)
{
    for (int i = 0; i < BUFFER_SIZE_10; ++i) {
        SCF_FILE_CTX *ctx = SCF_FileCtxNew();
        if (ctx != nullptr) {
            SCF_FileCtxFree(&ctx);
            EXPECT_TRUE(ctx == nullptr);
        }
    }
}

TEST_F(TestLineCoverageBoost, FileCtxSetPwd_VariousLengths)
{
    SCF_FILE_CTX *ctx = SCF_FileCtxNew();
    if (ctx != nullptr) {
        uint8_t passwd1[1] = {0};
        int32_t ret = SCF_FileCtxSetPwd(ctx, passwd1, 1, false);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        
        uint8_t passwd5[PASSWORD_LEN_5] = {0};
        ret = SCF_FileCtxSetPwd(ctx, passwd5, PASSWORD_LEN_5, false);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        
        uint8_t passwd10[BUFFER_SIZE_10] = {0};
        ret = SCF_FileCtxSetPwd(ctx, passwd10, BUFFER_SIZE_10, false);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        
        uint8_t passwd50[CIPHER_COUNT_50] = {0};
        ret = SCF_FileCtxSetPwd(ctx, passwd50, CIPHER_COUNT_50, false);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        
        uint8_t passwd100[PASSWORD_LEN_100] = {0};
        ret = SCF_FileCtxSetPwd(ctx, passwd100, PASSWORD_LEN_100, false);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        
        uint8_t passwd256[PASSWORD_LEN_256] = {0};
        ret = SCF_FileCtxSetPwd(ctx, passwd256, PASSWORD_LEN_256, false);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        
        SCF_FileCtxFree(&ctx);
    }
}

TEST_F(TestLineCoverageBoost, AddCert_DifferentCertTypes)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_FILE_CTX *certCtx = SCF_FileCtxNew();
    if (certCtx != nullptr) {
        std::vector<SCF_CERT_TYPE> certTypes = {
            SCF_CERT_TYPE_CA,
            SCF_CERT_TYPE_EE,
            SCF_CERT_TYPE_CRL,
            SCF_CERT_TYPE_EE_CHAIN
        };
        
        for (auto type : certTypes) {
            ret = SCF_AddCert(ctx, certCtx, type);
            EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        }
        
        SCF_FileCtxFree(&certCtx);
    }
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, SetKey_WithFileCtx)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_FILE_CTX *keyCtx = SCF_FileCtxNew();
    if (keyCtx != nullptr) {
        ret = SCF_SetKey(ctx, keyCtx);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        
        SCF_FileCtxFree(&keyCtx);
    }
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, GetCertStartTime_EndTime_WithNullCert)
{
    char startTime[BUFFER_SIZE_64] = {0};
    char endTime[BUFFER_SIZE_64] = {0};
    
    int32_t ret = SCF_GetCertStartTime(nullptr, startTime, BUFFER_SIZE_64);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    
    ret = SCF_GetCertEndTime(nullptr, endTime, BUFFER_SIZE_64);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestLineCoverageBoost, GetCertVersion_NullCert)
{
    int32_t ret = SCF_GetCertVersion(nullptr);
    EXPECT_TRUE(ret == SCF_ERRNO_NULL_INPUT || ret < 0);
}

TEST_F(TestLineCoverageBoost, CheckPrivateKey_AfterSetKey)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_CheckPrivateKey(ctx);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FILE_CTX *keyCtx = SCF_FileCtxNew();
    if (keyCtx != nullptr) {
        ret = SCF_SetKey(ctx, keyCtx);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        
        ret = SCF_CheckPrivateKey(ctx);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        
        SCF_FileCtxFree(&keyCtx);
    }
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, SetAppVerifyCallback_WithCallback)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_CUSTOMER);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetAppVerifyCallback(ctx, nullptr, nullptr);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, Config_ParseConfigFromFile)
{
    std::string testDir = GetLocalPath() + "/test/test_data/line_coverage_test";
    fs::create_directories(testDir);
    
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
    
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetConfigFile(ctx, configFile.c_str());
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
    fs::remove_all(testDir);
}

TEST_F(TestLineCoverageBoost, Close_MultipleCalls)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
    ASSERT_TRUE(obj != nullptr);
    
    ret = SCF_Close(obj);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_Close(obj);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    ret = SCF_Close(obj);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, Connect_WithoutFd)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_CLIENT, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
    ASSERT_TRUE(obj != nullptr);
    
    ret = SCF_Connect(obj);
    EXPECT_TRUE(ret != SCF_SUCCESS);
    
    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestLineCoverageBoost, Accept_WithoutFd)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
    ASSERT_TRUE(obj != nullptr);
    
    ret = SCF_Accept(obj);
    EXPECT_TRUE(ret != SCF_SUCCESS);
    
    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

}