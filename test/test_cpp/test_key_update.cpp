/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <gtest/gtest.h>
#include <sys/time.h>
#include <unistd.h>

#include "scf.h"
#include "scf_errno.h"
#include "scf_ssl.h"
#include "scf_inner.h"
#include "custom_logger.h"
#include "test_scf.h"

namespace test {

constexpr uint32_t UPDATE_TIME_60 = 60;
constexpr uint32_t UPDATE_TIME_59 = 59;
constexpr uint32_t UPDATE_TIME_100 = 100;
constexpr uint32_t UPDATE_TIME_3600 = 3600;
constexpr uint32_t UPDATE_TIME_1_YEAR = 365 * 24 * 3600;
constexpr uint64_t UPDATE_TRAFFIC_1M = 1000000;
constexpr uint64_t UPDATE_TRAFFIC_2M = 2000000;
constexpr uint64_t UPDATE_TRAFFIC_999 = 999;
constexpr size_t BUFFER_SIZE_1024 = 1024;

class KeyUpdateTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        SetExternalLogFunction(ExternalLogFunction);
        char libPath[] = "/usr/lib64";
        int32_t ret = SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);
        ASSERT_EQ(ret, SCF_SUCCESS);

        policyCtx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(policyCtx != nullptr);
        ret = SCF_SetPolicy(policyCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
        ASSERT_EQ(ret, SCF_SUCCESS);
    }

    void TearDown() override
    {
        SCF_FreePolicyCtx(&policyCtx);
        SCF_DeInit();
        SetExternalLogFunction(nullptr);
    }

    SCF_PolicyCtx *policyCtx = nullptr;
};

TEST_F(KeyUpdateTest, SetKeyAutoUpdateParam_ValidParams)
{
    uint32_t updateTime = UPDATE_TIME_60;
    uint64_t updateTraffic = UPDATE_TRAFFIC_1M;

    int32_t ret = SCF_SetKeyAutoUpdateParam(policyCtx, true, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(KeyUpdateTest, SetKeyAutoUpdateParam_NullCtx)
{
    uint32_t updateTime = UPDATE_TIME_60;
    uint64_t updateTraffic = UPDATE_TRAFFIC_1M;

    int32_t ret = SCF_SetKeyAutoUpdateParam(nullptr, true, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(KeyUpdateTest, SetKeyAutoUpdateParam_MinUpdateTime)
{
    uint32_t updateTime = UPDATE_TIME_60;
    uint64_t updateTraffic = UPDATE_TRAFFIC_1M;

    int32_t ret = SCF_SetKeyAutoUpdateParam(policyCtx, true, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(KeyUpdateTest, SetKeyAutoUpdateParam_BelowMinUpdateTime)
{
    uint32_t updateTime = UPDATE_TIME_59;
    uint64_t updateTraffic = UPDATE_TRAFFIC_1M;

    int32_t ret = SCF_SetKeyAutoUpdateParam(policyCtx, true, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(KeyUpdateTest, SetKeyAutoUpdateParam_ZeroUpdateTime)
{
    uint32_t updateTime = 0;
    uint64_t updateTraffic = UPDATE_TRAFFIC_1M;

    int32_t ret = SCF_SetKeyAutoUpdateParam(policyCtx, true, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SSL_ERR_SET_UPDATE_PARAM);
}

TEST_F(KeyUpdateTest, SetKeyAutoUpdateParam_MaxUpdateTime)
{
    uint32_t updateTime = UPDATE_TIME_1_YEAR;
    uint64_t updateTraffic = UPDATE_TRAFFIC_1M;

    int32_t ret = SCF_SetKeyAutoUpdateParam(policyCtx, true, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(KeyUpdateTest, SetKeyAutoUpdateParam_ExceedMaxUpdateTime)
{
    uint32_t updateTime = UPDATE_TIME_1_YEAR + 1;
    uint64_t updateTraffic = UPDATE_TRAFFIC_1M;

    int32_t ret = SCF_SetKeyAutoUpdateParam(policyCtx, true, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SSL_ERR_SET_UPDATE_PARAM);
}

TEST_F(KeyUpdateTest, SetKeyAutoUpdateParam_MinUpdateTraffic)
{
    uint32_t updateTime = UPDATE_TIME_60;
    uint64_t updateTraffic = UPDATE_TRAFFIC_1M;

    int32_t ret = SCF_SetKeyAutoUpdateParam(policyCtx, true, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(KeyUpdateTest, SetKeyAutoUpdateParam_BelowMinUpdateTraffic)
{
    uint32_t updateTime = UPDATE_TIME_60;
    uint64_t updateTraffic = UPDATE_TRAFFIC_999;

    int32_t ret = SCF_SetKeyAutoUpdateParam(policyCtx, true, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SSL_ERR_SET_UPDATE_PARAM);
}

TEST_F(KeyUpdateTest, SetKeyAutoUpdateParam_Disabled)
{
    uint32_t updateTime = UPDATE_TIME_60;
    uint64_t updateTraffic = UPDATE_TRAFFIC_1M;

    int32_t ret = SCF_SetKeyAutoUpdateParam(policyCtx, false, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(KeyUpdateTest, SetKeyAutoUpdateParam_MaxTraffic)
{
    uint32_t updateTime = UPDATE_TIME_60;
    uint64_t updateTraffic = UINT64_MAX;

    int32_t ret = SCF_SetKeyAutoUpdateParam(policyCtx, true, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(KeyUpdateTest, GetKeyAutoUpdateParam_Valid)
{
    uint32_t updateTime = UPDATE_TIME_100;
    uint64_t updateTraffic = UPDATE_TRAFFIC_2M;

    SCF_SetKeyAutoUpdateParam(policyCtx, true, updateTime, updateTraffic);

    bool enabled = false;
    uint32_t retrievedUpdateTime = 0;
    uint64_t retrievedUpdateTraffic = 0;

    int32_t ret = SCF_GetKeyAutoUpdateParam(policyCtx, enabled, retrievedUpdateTime, retrievedUpdateTraffic);
    EXPECT_EQ(ret, SCF_SUCCESS);
    EXPECT_TRUE(enabled);
    EXPECT_EQ(retrievedUpdateTime, updateTime);
    EXPECT_EQ(retrievedUpdateTraffic, updateTraffic);
}

TEST_F(KeyUpdateTest, GetKeyAutoUpdateParam_NullCtx)
{
    bool enabled = false;
    uint32_t updateTime = 0;
    uint64_t updateTraffic = 0;

    int32_t ret = SCF_GetKeyAutoUpdateParam(nullptr, enabled, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(KeyUpdateTest, GetKeyAutoUpdateParam_NullEnabled)
{
    uint32_t updateTime = 0;
    uint64_t updateTraffic = 0;

    SCF_PolicyCtx *tmpCtx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(tmpCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    bool enabled = false;
    int32_t ret = SCF_GetKeyAutoUpdateParam(tmpCtx, enabled, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SUCCESS);

    SCF_FreePolicyCtx(&tmpCtx);
}

TEST_F(KeyUpdateTest, GetKeyAutoUpdateParam_NullUpdateTime)
{
    bool enabled = false;
    uint64_t updateTraffic = 0;

    SCF_PolicyCtx *tmpCtx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(tmpCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    uint32_t updateTime = 0;
    int32_t ret = SCF_GetKeyAutoUpdateParam(tmpCtx, enabled, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SUCCESS);

    SCF_FreePolicyCtx(&tmpCtx);
}

TEST_F(KeyUpdateTest, GetKeyAutoUpdateParam_NullUpdateTraffic)
{
    bool enabled = false;
    uint32_t updateTime = 0;

    SCF_PolicyCtx *tmpCtx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(tmpCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    uint64_t updateTraffic = 0;
    int32_t ret = SCF_GetKeyAutoUpdateParam(tmpCtx, enabled, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SUCCESS);

    SCF_FreePolicyCtx(&tmpCtx);
}

TEST_F(KeyUpdateTest, GetKeyUpdateInfo_NullObj)
{
    uint64_t lastKeyUpdateTime = 0;
    uint32_t timeInterval = 0;
    uint64_t remainTraffic = 0;

    int32_t ret = SCF_GetKeyUpdateInfo(nullptr, &lastKeyUpdateTime, &timeInterval, &remainTraffic);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(KeyUpdateTest, GetKeyUpdateInfo_NullLastTime)
{
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(policyCtx);
    uint32_t timeInterval = 0;
    uint64_t remainTraffic = 0;

    int32_t ret = SCF_GetKeyUpdateInfo(obj, nullptr, &timeInterval, &remainTraffic);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    SCF_FreePolicyObj(&obj);
}

TEST_F(KeyUpdateTest, ObjKeyUpdate_NullObj)
{
    int32_t ret = SCF_ObjKeyUpdate(nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(KeyUpdateTest, CheckNeedKeyUpdate_NullObj)
{
    bool isNeedKeyUpdate = false;
    int32_t ret = scf::CheckNeedKeyUpdate(nullptr, BUFFER_SIZE_1024, &isNeedKeyUpdate);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(KeyUpdateTest, CheckNeedKeyUpdate_NullFlag)
{
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(policyCtx);

    int32_t ret = scf::CheckNeedKeyUpdate(obj, BUFFER_SIZE_1024, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    SCF_FreePolicyObj(&obj);
}

TEST_F(KeyUpdateTest, CheckTimeInterval_NotReached)
{
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(policyCtx);

    uint32_t updateTime = UPDATE_TIME_3600;
    uint64_t updateTraffic = UPDATE_TRAFFIC_1M;
    SCF_SetKeyAutoUpdateParam(policyCtx, true, updateTime, updateTraffic);

    bool isNeedUpdate = false;
    EXPECT_EQ(scf::CheckNeedKeyUpdate(obj, BUFFER_SIZE_1024, &isNeedUpdate), SCF_SUCCESS);

    SCF_FreePolicyObj(&obj);
}

TEST_F(KeyUpdateTest, SetKeyAutoUpdateParam_MiddlePolicy)
{
    SCF_FreePolicyCtx(&policyCtx);
    policyCtx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(policyCtx, SCF_ROLE_CLIENT, SCF_VERIFY_PEER, SCF_POLICY_MIDDLE);

    uint32_t updateTime = UPDATE_TIME_60;
    uint64_t updateTraffic = UPDATE_TRAFFIC_1M;

    int32_t ret = SCF_SetKeyAutoUpdateParam(policyCtx, true, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(KeyUpdateTest, SetKeyAutoUpdateParam_CustomerPolicy)
{
    SCF_FreePolicyCtx(&policyCtx);
    policyCtx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(policyCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_CUSTOMER);

    uint32_t updateTime = UPDATE_TIME_60;
    uint64_t updateTraffic = UPDATE_TRAFFIC_1M;

    int32_t ret = SCF_SetKeyAutoUpdateParam(policyCtx, true, updateTime, updateTraffic);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

}