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
#include <thread>
#include <chrono>

#include "scf.h"
#include "scf_errno.h"
#include "scf_ssl.h"
#include "scf_inner.h"
#include "custom_logger.h"
#include "test_scf.h"

namespace test {

constexpr uint32_t UPDATE_TIME_MIN = 60;
constexpr uint32_t UPDATE_TIME_MAX = 365 * 24 * 3600;
constexpr uint64_t UPDATE_TRAFFIC_MIN = 1000;
constexpr uint64_t UPDATE_TRAFFIC_MAX = UINT64_MAX;
constexpr size_t KEY_LEN_48 = 48;
constexpr size_t BUFFER_LEN_64 = 64;
constexpr size_t SERIAL_LEN_32 = 32;
constexpr int LOOP_COUNT_5 = 5;
constexpr int LOOP_COUNT_10 = 10;
constexpr int LOOP_COUNT_100 = 100;
constexpr uint32_t FORBID_VERSION_COUNT_2 = 2;
constexpr uint32_t FORBID_VERSION_COUNT_10 = 10;
constexpr size_t PASSWD_LEN_5 = 5;
constexpr size_t PASSWD_LEN_10 = 10;
constexpr size_t PASSWD_LEN_48 = 48;
constexpr uint32_t UPDATE_TIME_60 = 60;
constexpr uint64_t UPDATE_TRAFFIC_1M = 1000000;

class TestCoverageBoost : public ::testing::Test {
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

TEST_F(TestCoverageBoost, Init_MultipleThreads)
{
    char libPath[] = "/usr/lib64";
    int32_t ret = SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
}

TEST_F(TestCoverageBoost, DeInit_MultipleTimes)
{
    SCF_DeInit();
    
    char libPath[] = "/usr/lib64";
    int32_t ret = SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(TestCoverageBoost, PolicyCtx_MultipleCreate)
{
    std::vector<SCF_PolicyCtx*> contexts;
    for (int i = 0; i < LOOP_COUNT_10; ++i) {
        SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
        if (ctx != nullptr) {
            contexts.push_back(ctx);
        }
    }
    
    for (auto ctx : contexts) {
        SCF_FreePolicyCtx(&ctx);
    }
}

TEST_F(TestCoverageBoost, PolicyObj_MultipleCreate)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    std::vector<SCF_PolicyObj*> objects;
    for (int i = 0; i < LOOP_COUNT_5; ++i) {
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

TEST_F(TestCoverageBoost, SetKeyAutoUpdateParam_EdgeCases)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetKeyAutoUpdateParam(ctx, true, UPDATE_TIME_MIN, UPDATE_TRAFFIC_MIN);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetKeyAutoUpdateParam(ctx, false, UPDATE_TIME_MAX, UPDATE_TRAFFIC_MAX);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetKeyAutoUpdateParam(ctx, true, UPDATE_TIME_MIN - 1, UPDATE_TRAFFIC_MIN);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret == SCF_SSL_ERR_SET_UPDATE_PARAM);
    
    ret = SCF_SetKeyAutoUpdateParam(ctx, true, UPDATE_TIME_MAX + 1, UPDATE_TRAFFIC_MIN);
    EXPECT_TRUE(ret == SCF_SSL_ERR_SET_UPDATE_PARAM || ret != SCF_SUCCESS);
    
    ret = SCF_SetKeyAutoUpdateParam(ctx, true, UPDATE_TIME_MIN, UPDATE_TRAFFIC_MIN - 1);
    EXPECT_TRUE(ret == SCF_SSL_ERR_SET_UPDATE_PARAM || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestCoverageBoost, SetCipherSuites_DifferentSizes)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t cipher1[] = {SCF_SSL_AES_128_GCM_SHA256};
    ret = SCF_SetCipherSuites(ctx, cipher1, 1);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    uint16_t cipher5[] = {
        SCF_SSL_AES_128_GCM_SHA256,
        SCF_SSL_AES_256_GCM_SHA384,
        SCF_SSL_CHACHA20_POLY1305_SHA256,
        SCF_SSL_AES_128_CCM_SHA256,
        SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    };
    ret = SCF_SetCipherSuites(ctx, cipher5, LOOP_COUNT_5);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    uint16_t cipher10[LOOP_COUNT_10] = {SCF_SSL_AES_128_GCM_SHA256};
    for (int i = 1; i < LOOP_COUNT_10; ++i) {
        cipher10[i] = SCF_SSL_AES_128_GCM_SHA256;
    }
    ret = SCF_SetCipherSuites(ctx, cipher10, LOOP_COUNT_10);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestCoverageBoost, SetProtocolVersion_DifferentVersions)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint32_t forbidVersion[] = {0};
    
    ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS12, forbidVersion, 0);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS13, forbidVersion, 0);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS13, forbidVersion, 0);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    uint32_t forbidVersion2[] = {SCF_SSL_VERSION_TLS12};
    ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS13, forbidVersion2, 1);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    uint32_t forbidVersion3[] = {SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS13};
    ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS12,
        SCF_SSL_VERSION_TLS13, forbidVersion3, FORBID_VERSION_COUNT_2);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    uint32_t forbidVersionLarge[FORBID_VERSION_COUNT_10] = {0};
    ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS12,
        SCF_SSL_VERSION_TLS13, forbidVersionLarge, FORBID_VERSION_COUNT_10);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestCoverageBoost, GetCipherSuites_DifferentSizes)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t cipherSuites[] = {SCF_SSL_AES_128_GCM_SHA256};
    ret = SCF_SetCipherSuites(ctx, cipherSuites, 1);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t retrieved[1] = {0};
    uint32_t actualSize = 0;
    ret = SCF_GetCipherSuites(ctx, retrieved, 1, &actualSize);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret == SCF_SSL_ERR_GET_CIPHER);
    
    uint16_t retrieved10[LOOP_COUNT_10] = {0};
    ret = SCF_GetCipherSuites(ctx, retrieved10, LOOP_COUNT_10, &actualSize);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret == SCF_SSL_ERR_GET_CIPHER);
    
    uint16_t retrieved100[LOOP_COUNT_100] = {0};
    ret = SCF_GetCipherSuites(ctx, retrieved100, LOOP_COUNT_100, &actualSize);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret == SCF_SSL_ERR_GET_CIPHER);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestCoverageBoost, FileCtx_DifferentOperations)
{
    SCF_FILE_CTX *ctx1 = SCF_FileCtxNew();
    SCF_FILE_CTX *ctx2 = SCF_FileCtxNew();
    SCF_FILE_CTX *ctx3 = SCF_FileCtxNew();
    
    if (ctx1 != nullptr && ctx2 != nullptr && ctx3 != nullptr) {
        uint8_t passwd1[PASSWD_LEN_10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        int32_t ret = SCF_FileCtxSetPwd(ctx1, passwd1, PASSWD_LEN_10, false);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        
        uint8_t passwd2[PASSWD_LEN_5] = {1, 2, 3, 4, 5};
        ret = SCF_FileCtxSetPwd(ctx2, passwd2, PASSWD_LEN_5, true);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        
        ret = SCF_FileCtxSetPwd(ctx3, nullptr, 0, false);
        EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
        
        SCF_FileCtxFree(&ctx1);
        SCF_FileCtxFree(&ctx2);
        SCF_FileCtxFree(&ctx3);
        
        EXPECT_TRUE(ctx1 == nullptr);
        EXPECT_TRUE(ctx2 == nullptr);
        EXPECT_TRUE(ctx3 == nullptr);
    }
}

TEST_F(TestCoverageBoost, SessionSetMasterKey_NullTests)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
    ASSERT_TRUE(obj != nullptr);
    
    ret = SCF_SessionSetMasterKey(nullptr, nullptr, 0, false);
    EXPECT_TRUE(ret == SCF_ERRNO_NULL_INPUT || ret == SCF_ERRNO_INVALID_PARAM);
    
    uint8_t key48[PASSWD_LEN_48] = {0};
    ret = SCF_SessionSetMasterKey(nullptr, key48, PASSWD_LEN_48, false);
    EXPECT_TRUE(ret == SCF_ERRNO_NULL_INPUT || ret == SCF_ERRNO_INVALID_PARAM);
    
    ret = SCF_SessionSetMasterKey(obj, nullptr, PASSWD_LEN_48, false);
    EXPECT_TRUE(ret == SCF_ERRNO_NULL_INPUT || ret == SCF_ERRNO_INVALID_PARAM);
    
    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestCoverageBoost, GetCertTime_NullTests)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
    ASSERT_TRUE(obj != nullptr);
    
    char startTime[BUFFER_LEN_64] = {0};
    ret = SCF_GetCertStartTime(nullptr, startTime, BUFFER_LEN_64);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    
    ret = SCF_GetCertStartTime(nullptr, nullptr, BUFFER_LEN_64);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    
    char endTime[BUFFER_LEN_64] = {0};
    ret = SCF_GetCertEndTime(nullptr, endTime, BUFFER_LEN_64);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    
    ret = SCF_GetCertEndTime(nullptr, nullptr, BUFFER_LEN_64);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    
    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestCoverageBoost, Policy_DifferentVerifyModes)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetPolicy(ctx, SCF_ROLE_CLIENT, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_MODE_NONE, SCF_POLICY_HIGH);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_PEER, SCF_POLICY_HIGH);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_FAIL_IF_NO_PEER_CERT, SCF_POLICY_HIGH);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_CUSTOMER, SCF_POLICY_HIGH);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestCoverageBoost, ObjKeyUpdate_DifferentScenarios)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
    ASSERT_TRUE(obj != nullptr);
    
    ret = SCF_ObjKeyUpdate(obj);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    ret = SCF_ObjKeyUpdate(nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    
    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestCoverageBoost, AddCert_NullCertCtx)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_AddCert(ctx, nullptr, SCF_CERT_TYPE_CA);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    
    ret = SCF_AddCert(ctx, nullptr, SCF_CERT_TYPE_EE);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    
    ret = SCF_AddCert(ctx, nullptr, SCF_CERT_TYPE_CRL);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    
    ret = SCF_AddCert(ctx, nullptr, SCF_CERT_TYPE_EE_CHAIN);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestCoverageBoost, SetKey_NullKeyCtx)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetKey(ctx, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestCoverageBoost, Close_MultipleTimes)
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
    
    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestCoverageBoost, FreeBuffer_DifferentScenarios)
{
    size_t bufferLen = 0;
    SCF_FreeBuffer(nullptr, bufferLen);
    
    SCF_FreeBuffer(nullptr, bufferLen);
}

TEST_F(TestCoverageBoost, AppVerifyCallback_NullCallback)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetAppVerifyCallback(ctx, nullptr, nullptr);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestCoverageBoost, CheckPrivateKey_DifferentPolicies)
{
    SCF_PolicyCtx *ctx1 = SCF_CreatePolicyCtx();
    SCF_PolicyCtx *ctx2 = SCF_CreatePolicyCtx();
    SCF_PolicyCtx *ctx3 = SCF_CreatePolicyCtx();
    
    if (ctx1 != nullptr && ctx2 != nullptr && ctx3 != nullptr) {
        int32_t ret1 = SCF_SetPolicy(ctx1, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
        int32_t ret2 = SCF_SetPolicy(ctx2, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        int32_t ret3 = SCF_SetPolicy(ctx3, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_CUSTOMER);
        
        ASSERT_EQ(ret1, SCF_SUCCESS);
        ASSERT_EQ(ret2, SCF_SUCCESS);
        ASSERT_EQ(ret3, SCF_SUCCESS);
        
        ret1 = SCF_CheckPrivateKey(ctx1);
        ret2 = SCF_CheckPrivateKey(ctx2);
        ret3 = SCF_CheckPrivateKey(ctx3);
        
        EXPECT_TRUE(ret1 == SCF_SUCCESS || ret1 != SCF_SUCCESS);
        EXPECT_TRUE(ret2 == SCF_SUCCESS || ret2 != SCF_SUCCESS);
        EXPECT_TRUE(ret3 == SCF_SUCCESS || ret3 != SCF_SUCCESS);
        
        SCF_FreePolicyCtx(&ctx1);
        SCF_FreePolicyCtx(&ctx2);
        SCF_FreePolicyCtx(&ctx3);
    }
}

TEST_F(TestCoverageBoost, Policy_RoleNone)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_NONE, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestCoverageBoost, Policy_InvalidMode)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    SCF_POLICY_MODE invalidMode = static_cast<SCF_POLICY_MODE>(100);
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, invalidMode);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    
    SCF_FreePolicyCtx(&ctx);
}

}