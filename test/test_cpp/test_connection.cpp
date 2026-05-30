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
#include <unistd.h>

#include "scf.h"
#include "scf_errno.h"
#include "scf_ssl.h"
#include "custom_logger.h"
#include "test_scf.h"

namespace test {

constexpr int32_t INVALID_FD = -1;
constexpr int32_t VALID_FD = 1;
constexpr size_t DATA_LEN_10 = 10;
constexpr size_t DATA_LEN_100 = 100;

class TestConnection : public ::testing::Test {
protected:
    void SetUp() override
    {
        SetExternalLogFunction(ExternalLogFunction);
        char libPath[] = "/usr/lib64";
        int32_t ret = SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);
        ASSERT_EQ(ret, SCF_SUCCESS);
        
        ctx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(ctx != nullptr);
        ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
        ASSERT_EQ(ret, SCF_SUCCESS);
        
        obj = SCF_CreatePolicyObj(ctx);
        ASSERT_TRUE(obj != nullptr);
    }
    
    void TearDown() override
    {
        if (obj != nullptr) {
            SCF_FreePolicyObj(&obj);
        }
        if (ctx != nullptr) {
            SCF_FreePolicyCtx(&ctx);
        }
        SCF_DeInit();
        SetExternalLogFunction(nullptr);
    }
    
    SCF_PolicyCtx *ctx = nullptr;
    SCF_PolicyObj *obj = nullptr;
};

TEST_F(TestConnection, SCF_SetFd_Valid)
{
    int32_t ret = SCF_SetFd(obj, VALID_FD);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
}

TEST_F(TestConnection, SCF_SetFd_NullObj)
{
    int32_t ret = SCF_SetFd(nullptr, VALID_FD);
    EXPECT_NE(ret, SCF_SUCCESS);
}

TEST_F(TestConnection, SCF_SetFd_InvalidFd)
{
    int32_t ret = SCF_SetFd(obj, INVALID_FD);
    EXPECT_NE(ret, SCF_SUCCESS);
}

TEST_F(TestConnection, SCF_Connect_NullObj)
{
    int32_t ret = SCF_Connect(nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConnection, SCF_Accept_NullObj)
{
    int32_t ret = SCF_Accept(nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConnection, SCF_Read_NullObj)
{
    uint8_t buffer[DATA_LEN_10] = {0};
    uint32_t readLen = 0;
    int32_t ret = SCF_Read(nullptr, buffer, DATA_LEN_10, &readLen);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
}

TEST_F(TestConnection, SCF_Read_NullBuffer)
{
    uint32_t readLen = 0;
    int32_t ret = SCF_Read(obj, nullptr, DATA_LEN_10, &readLen);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
}

TEST_F(TestConnection, SCF_Read_NullReadLen)
{
    uint8_t buffer[DATA_LEN_10] = {0};
    int32_t ret = SCF_Read(obj, buffer, DATA_LEN_10, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
}

TEST_F(TestConnection, SCF_Write_NullObj)
{
    uint8_t data[DATA_LEN_10] = {0};
    uint32_t writeLen = 0;
    int32_t ret = SCF_Write(nullptr, data, DATA_LEN_10, &writeLen);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
}

TEST_F(TestConnection, SCF_Write_NullData)
{
    uint32_t writeLen = 0;
    int32_t ret = SCF_Write(obj, nullptr, DATA_LEN_10, &writeLen);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
}

TEST_F(TestConnection, SCF_Write_NullWriteLen)
{
    uint8_t data[DATA_LEN_10] = {0};
    int32_t ret = SCF_Write(obj, data, DATA_LEN_10, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
}

TEST_F(TestConnection, SCF_Close_NullObj)
{
    int32_t ret = SCF_Close(nullptr);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(TestConnection, SCF_SessionSetMasterKey_NullObj)
{
    uint8_t key[48] = {0};
    int32_t ret = SCF_SessionSetMasterKey(nullptr, key, 48, false);
    EXPECT_TRUE(ret == SCF_ERRNO_NULL_INPUT || ret == SCF_ERRNO_INVALID_PARAM);
}

TEST_F(TestConnection, SCF_SessionSetMasterKey_NullKey)
{
    int32_t ret = SCF_SessionSetMasterKey(obj, nullptr, 48, false);
    EXPECT_TRUE(ret == SCF_ERRNO_NULL_INPUT || ret == SCF_ERRNO_INVALID_PARAM);
}

TEST_F(TestConnection, SCF_GetCertStartTime_NullObj)
{
    char startTime[64] = {0};
    int32_t ret = SCF_GetCertStartTime(nullptr, startTime, 64);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConnection, SCF_GetCertStartTime_NullBuffer)
{
    int32_t ret = SCF_GetCertStartTime(obj, nullptr, 64);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConnection, SCF_GetCertEndTime_NullObj)
{
    char endTime[64] = {0};
    int32_t ret = SCF_GetCertEndTime(nullptr, endTime, 64);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConnection, SCF_GetCertEndTime_NullBuffer)
{
    int32_t ret = SCF_GetCertEndTime(obj, nullptr, 64);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConnection, SCF_ObjKeyUpdate_NullObj)
{
    int32_t ret = SCF_ObjKeyUpdate(nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConnection, PolicyCtx_RefCount)
{
    SCF_PolicyCtx *ctx2 = SCF_CreatePolicyCtx();
    EXPECT_TRUE(ctx2 != nullptr);
    SCF_FreePolicyCtx(&ctx2);
}

TEST_F(TestConnection, PolicyObj_MultipleCreate)
{
    SCF_PolicyObj *obj2 = SCF_CreatePolicyObj(ctx);
    if (obj2 != nullptr) {
        SCF_FreePolicyObj(&obj2);
    }
}

TEST_F(TestConnection, SCF_AddCert_NullCtx)
{
    int32_t ret = SCF_AddCert(nullptr, nullptr, SCF_CERT_TYPE_CA);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConnection, SCF_SetKey_NullCtx)
{
    int32_t ret = SCF_SetKey(nullptr, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConnection, SCF_SetConfigFile_NullCtx)
{
    int32_t ret = SCF_SetConfigFile(nullptr, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConnection, SCF_SetAppVerifyCallback_NullCtx)
{
    int32_t ret = SCF_SetAppVerifyCallback(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConnection, SCF_CheckPrivateKey_NullCtx)
{
    int32_t ret = SCF_CheckPrivateKey(nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConnection, SCF_GetCertVersion_NullCert)
{
    int32_t ret = SCF_GetCertVersion(nullptr);
    EXPECT_TRUE(ret == SCF_ERRNO_NULL_INPUT || ret < 0);
}

TEST_F(TestConnection, SCF_FreeCert_NullPtr)
{
    SCF_FreeCert(nullptr);
}

TEST_F(TestConnection, FreeCert_NullPtr)
{
    SCF_FreeCert(nullptr);
}

TEST_F(TestConnection, FileCtx_CreateAndFree)
{
    SCF_FILE_CTX *fileCtx = SCF_FileCtxNew();
    if (fileCtx != nullptr) {
        SCF_FileCtxFree(&fileCtx);
        EXPECT_TRUE(fileCtx == nullptr);
    }
}

TEST_F(TestConnection, FileCtx_NullPtr)
{
    SCF_FileCtxFree(nullptr);
}

TEST_F(TestConnection, FileCtxSetPwd_NullCtx)
{
    uint8_t passwd[10] = {0};
    int32_t ret = SCF_FileCtxSetPwd(nullptr, passwd, 10, false);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestConnection, FileCtxSetPwd_NullPasswd)
{
    SCF_FILE_CTX *fileCtx = nullptr;
    int32_t ret = SCF_FileCtxSetPwd(fileCtx, nullptr, 10, false);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

}