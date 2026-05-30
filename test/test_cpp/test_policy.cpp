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

#include "scf.h"
#include "scf_errno.h"
#include "scf_ssl.h"
#include "custom_logger.h"
#include "test_scf.h"

namespace test {

constexpr uint64_t INVALID_INIT_FLAG = 999;
constexpr uint32_t CIPHER_SUITE_COUNT_2 = 2;
constexpr uint32_t UPDATE_TIME_60 = 60;
constexpr uint64_t UPDATE_TRAFFIC_1M = 1000000;

class TestPolicy : public ::testing::Test {
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

TEST_F(TestPolicy, SCF_Init_AlreadyInitialized)
{
    char libPath[] = "/usr/lib64";
    int32_t ret = SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(TestPolicy, SCF_Init_InvalidFlag)
{
    SCF_DeInit();
    char libPath[] = "/usr/lib64";
    int32_t ret = SCF_Init(INVALID_INIT_FLAG, libPath);
    EXPECT_TRUE(ret == SCF_ERRNO_INVALID_PARAM || ret != SCF_SUCCESS);
    
    char libPath2[] = "/usr/lib64";
    ret = SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath2);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(TestPolicy, SCF_DeInit_MultipleTimes)
{
    SCF_DeInit();
    SCF_DeInit();
    
    char libPath[] = "/usr/lib64";
    int32_t ret = SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(TestPolicy, SCF_CreatePolicyCtx_Success)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    EXPECT_TRUE(ctx != nullptr);
    SCF_FreePolicyCtx(&ctx);
    EXPECT_TRUE(ctx == nullptr);
}

TEST_F(TestPolicy, SCF_CreatePolicyCtx_NotInit)
{
    SCF_DeInit();
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    EXPECT_TRUE(ctx == nullptr);
}

TEST_F(TestPolicy, SCF_FreePolicyCtx_NullPtr)
{
    SCF_FreePolicyCtx(nullptr);
}

TEST_F(TestPolicy, SCF_FreePolicyCtx_NullCtx)
{
    SCF_PolicyCtx *ctx = nullptr;
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestPolicy, SCF_SetPolicy_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestPolicy, SCF_SetPolicy_NullCtx)
{
    int32_t ret = SCF_SetPolicy(nullptr, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    EXPECT_TRUE(ret == SCF_ERRNO_NULL_INPUT || ret != SCF_SUCCESS);
}

TEST_F(TestPolicy, SCF_SetPolicy_InvalidRole)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_NONE, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestPolicy, SCF_SetPolicy_InvalidMode)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    SCF_POLICY_MODE invalidMode = static_cast<SCF_POLICY_MODE>(SCF_POLICY_CUSTOMER + 1);
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, invalidMode);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestPolicy, SCF_GetPolicy_Valid)
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
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestPolicy, SCF_GetPolicy_NullCtx)
{
    SCF_ROLE role = SCF_ROLE_NONE;
    uint32_t verifyMode = 0;
    SCF_POLICY_MODE policyMode = SCF_POLICY_HIGH;
    int32_t ret = SCF_GetPolicy(nullptr, &role, &verifyMode, &policyMode);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestPolicy, SCF_CreatePolicyObj_Success)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
    EXPECT_TRUE(obj != nullptr);
    
    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestPolicy, SCF_CreatePolicyObj_NullCtx)
{
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(nullptr);
    EXPECT_TRUE(obj == nullptr);
}

TEST_F(TestPolicy, SCF_CreatePolicyObj_NotSetRole)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
    if (obj != nullptr) {
        SCF_FreePolicyObj(&obj);
    }
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestPolicy, SCF_FreePolicyObj_NullPtr)
{
    SCF_FreePolicyObj(nullptr);
}

TEST_F(TestPolicy, SCF_FreePolicyObj_NullObj)
{
    SCF_PolicyObj *obj = nullptr;
    SCF_FreePolicyObj(&obj);
}

TEST_F(TestPolicy, SCF_SetCipherSuites_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t cipherSuites[] = {SCF_SSL_AES_128_GCM_SHA256, SCF_SSL_AES_256_GCM_SHA384};
    ret = SCF_SetCipherSuites(ctx, cipherSuites, CIPHER_SUITE_COUNT_2);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestPolicy, SCF_SetCipherSuites_NullCtx)
{
    uint16_t cipherSuites[] = {SCF_SSL_AES_128_GCM_SHA256};
    int32_t ret = SCF_SetCipherSuites(nullptr, cipherSuites, 1);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestPolicy, SCF_SetCipherSuites_NullSuites)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetCipherSuites(ctx, nullptr, 1);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestPolicy, SCF_GetCipherSuites_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint16_t retrieved[10] = {0};
    uint32_t size = 10;
    uint32_t actualSize = 0;
    ret = SCF_GetCipherSuites(ctx, retrieved, size, &actualSize);
    EXPECT_EQ(ret, SCF_SSL_ERR_GET_CIPHER);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestPolicy, SCF_GetCipherSuites_NullCtx)
{
    uint16_t retrieved[10] = {0};
    uint32_t actualSize = 0;
    int32_t ret = SCF_GetCipherSuites(nullptr, retrieved, 10, &actualSize);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestPolicy, SCF_SetProtocolVersion_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    uint32_t forbidVersion[] = {0};
    ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS13, forbidVersion, 0);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestPolicy, SCF_SetProtocolVersion_NullCtx)
{
    uint32_t forbidVersion[] = {0};
    int32_t ret = SCF_SetProtocolVersion(nullptr, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS13, forbidVersion, 0);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestPolicy, SCF_SetKeyAutoUpdateParam_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetKeyAutoUpdateParam(ctx, true, UPDATE_TIME_60, UPDATE_TRAFFIC_1M);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestPolicy, SCF_SetKeyAutoUpdateParam_NullCtx)
{
    int32_t ret = SCF_SetKeyAutoUpdateParam(nullptr, true, 60, 1000000);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestPolicy, SCF_SetKeyAutoUpdateParam_ZeroTime)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    ret = SCF_SetKeyAutoUpdateParam(ctx, true, 0, UPDATE_TRAFFIC_1M);
    EXPECT_EQ(ret, SCF_SSL_ERR_SET_UPDATE_PARAM);
    
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestPolicy, SCF_Close_Success)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(ctx != nullptr);
    
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);
    
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
    ASSERT_TRUE(obj != nullptr);
    
    ret = SCF_Close(obj);
    EXPECT_EQ(ret, SCF_SUCCESS);
    
    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(TestPolicy, SCF_Close_NullObj)
{
    int32_t ret = SCF_Close(nullptr);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(TestPolicy, SCF_Accept_NullObj)
{
    int32_t ret = SCF_Accept(nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

}