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

#include "scf_inner.h"
#include "scf_errno.h"
#include "scf.h"
#include "custom_logger.h"
#include "test_scf.h"

namespace test {

constexpr size_t HEX_STR_LEN_10 = 10;
constexpr size_t HEX_STR_LEN_5 = 5;
constexpr size_t NUM_LEN_2 = 2;
constexpr size_t NUM_LEN_3 = 3;
constexpr size_t NUM_LEN_1 = 1;
constexpr int32_t TEST_ERROR_CODE = -99999;

class PolicyUtilsTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        SetExternalLogFunction(ExternalLogFunction);
    }
    void TearDown() override
    {
        SetExternalLogFunction(nullptr);
    }
};

TEST_F(PolicyUtilsTest, CheckRole_Client)
{
    EXPECT_EQ(scf::CheckRole(SCF_ROLE_CLIENT), SCF_SUCCESS);
}

TEST_F(PolicyUtilsTest, CheckRole_Server)
{
    EXPECT_EQ(scf::CheckRole(SCF_ROLE_SERVER), SCF_SUCCESS);
}

TEST_F(PolicyUtilsTest, CheckRole_None)
{
    EXPECT_EQ(scf::CheckRole(SCF_ROLE_NONE), SCF_ERRNO_INVALID_PARAM);
}

TEST_F(PolicyUtilsTest, CheckRole_Invalid)
{
    SCF_ROLE invalidRole = static_cast<SCF_ROLE>(SCF_ROLE_SERVER + 1);
    EXPECT_EQ(scf::CheckRole(invalidRole), SCF_ERRNO_INVALID_PARAM);
}

TEST_F(PolicyUtilsTest, CheckVerifyMode_None)
{
    EXPECT_EQ(scf::CheckVerifyMode(SCF_VERIFY_MODE_NONE), SCF_SUCCESS);
}

TEST_F(PolicyUtilsTest, CheckVerifyMode_Default)
{
    EXPECT_EQ(scf::CheckVerifyMode(SCF_VERIFY_DEFAULT), SCF_SUCCESS);
}

TEST_F(PolicyUtilsTest, CheckVerifyMode_Peer)
{
    EXPECT_EQ(scf::CheckVerifyMode(SCF_VERIFY_PEER), SCF_SUCCESS);
}

TEST_F(PolicyUtilsTest, CheckVerifyMode_FailIfNoPeerCert)
{
    EXPECT_EQ(scf::CheckVerifyMode(SCF_VERIFY_FAIL_IF_NO_PEER_CERT), SCF_ERRNO_INVALID_PARAM);
}

TEST_F(PolicyUtilsTest, CheckVerifyMode_Invalid)
{
    uint32_t invalidMode = SCF_VERIFY_FAIL_IF_NO_PEER_CERT + 1;
    EXPECT_EQ(scf::CheckVerifyMode(invalidMode), SCF_ERRNO_INVALID_PARAM);
}

TEST_F(PolicyUtilsTest, CheckPolicyMode_High)
{
    EXPECT_EQ(scf::CheckPolicyMode(SCF_POLICY_HIGH), SCF_SUCCESS);
}

TEST_F(PolicyUtilsTest, CheckPolicyMode_Middle)
{
    EXPECT_EQ(scf::CheckPolicyMode(SCF_POLICY_MIDDLE), SCF_SUCCESS);
}

TEST_F(PolicyUtilsTest, CheckPolicyMode_Customer)
{
    EXPECT_EQ(scf::CheckPolicyMode(SCF_POLICY_CUSTOMER), SCF_SUCCESS);
}

TEST_F(PolicyUtilsTest, CheckPolicyMode_Invalid)
{
    SCF_POLICY_MODE invalidMode = static_cast<SCF_POLICY_MODE>(SCF_POLICY_CUSTOMER + 1);
    EXPECT_EQ(scf::CheckPolicyMode(invalidMode), SCF_ERRNO_INVALID_PARAM);
}

TEST_F(PolicyUtilsTest, Num2HexStr_ValidInput)
{
    char num[] = {0x12, static_cast<char>(0xAB)};
    char hexStr[HEX_STR_LEN_10] = {0};
    uint32_t hexStrLen = HEX_STR_LEN_10;

    EXPECT_EQ(scf::Num2HexStr(num, NUM_LEN_2, hexStr, hexStrLen), SCF_SUCCESS);
    EXPECT_STREQ(hexStr, "12ab");
}

TEST_F(PolicyUtilsTest, Num2HexStr_NullNum)
{
    char hexStr[HEX_STR_LEN_10] = {0};
    EXPECT_EQ(scf::Num2HexStr(nullptr, NUM_LEN_2, hexStr, HEX_STR_LEN_10), SCF_ERRNO_INVALID_PARAM);
}

TEST_F(PolicyUtilsTest, Num2HexStr_NullHexStr)
{
    char num[] = {0x12};
    EXPECT_EQ(scf::Num2HexStr(num, NUM_LEN_1, nullptr, HEX_STR_LEN_10), SCF_ERRNO_INVALID_PARAM);
}

TEST_F(PolicyUtilsTest, Num2HexStr_ZeroHexStrLen)
{
    char num[] = {0x12};
    char hexStr[HEX_STR_LEN_10] = {0};
    EXPECT_EQ(scf::Num2HexStr(num, NUM_LEN_1, hexStr, 0), SCF_ERRNO_INVALID_PARAM);
}

TEST_F(PolicyUtilsTest, Num2HexStr_ZeroNumLen)
{
    char num[] = {0x12};
    char hexStr[HEX_STR_LEN_10] = {0};
    EXPECT_EQ(scf::Num2HexStr(num, 0, hexStr, HEX_STR_LEN_10), SCF_SUCCESS);
    EXPECT_STREQ(hexStr, "");
}

TEST_F(PolicyUtilsTest, Num2HexStr_BufferOverflow)
{
    char num[] = {0x12, static_cast<char>(0xAB), static_cast<char>(0xCD)};
    char hexStr[HEX_STR_LEN_5] = {0};
    EXPECT_EQ(scf::Num2HexStr(num, NUM_LEN_3, hexStr, HEX_STR_LEN_5), SCF_SUCCESS);
    EXPECT_STREQ(hexStr, "");
}

TEST_F(PolicyUtilsTest, Num2HexStr_SingleByte)
{
    char num[] = {static_cast<char>(0xFF)};
    char hexStr[HEX_STR_LEN_10] = {0};
    EXPECT_EQ(scf::Num2HexStr(num, NUM_LEN_1, hexStr, HEX_STR_LEN_10), SCF_SUCCESS);
    EXPECT_STREQ(hexStr, "ff");
}

TEST_F(PolicyUtilsTest, GetErrorMessageInternal_KnownError)
{
    std::string msg = scf::GetErrorMessageInternal(SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(msg, "Null input");
}

TEST_F(PolicyUtilsTest, GetErrorMessageInternal_SSLError)
{
    std::string msg = scf::GetErrorMessageInternal(SCF_SSL_ERR_SSL);
    EXPECT_EQ(msg, "SSL error");
}

TEST_F(PolicyUtilsTest, GetErrorMessageInternal_UnknownError)
{
    std::string msg = scf::GetErrorMessageInternal(TEST_ERROR_CODE);
    EXPECT_EQ(msg, "Unknown error code.");
}

TEST_F(PolicyUtilsTest, GetErrorMessageInternal_ConfigError)
{
    std::string msg = scf::GetErrorMessageInternal(SCF_CFG_ERRNO_PARSE);
    EXPECT_EQ(msg, "CFG parse error");
}

}