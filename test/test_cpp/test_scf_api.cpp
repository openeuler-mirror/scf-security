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
#include <cstring>
#include <thread>
#include <chrono>

#include "scf.h"
#include "scf_errno.h"
#include "scf_ssl.h"
#include "custom_logger.h"
#include "test_scf.h"

namespace test {

constexpr size_t ARRAY_SIZE_10 = 10;
constexpr size_t ARRAY_SIZE_48 = 48;
constexpr size_t ARRAY_SIZE_64 = 64;
constexpr size_t ARRAY_SIZE_32 = 32;
constexpr size_t CIPHER_SUITE_COUNT_2 = 2;
constexpr int32_t SCF_SET_PROTOCOL_VERSION_ERROR = 1962942734;

class SCFApiTest : public ::testing::Test {
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

TEST_F(SCFApiTest, SCF_Init_Success)
{
}

TEST_F(SCFApiTest, SCF_DeInit_Success)
{
    SCF_DeInit();

    char libPath[] = "/usr/lib64";
    SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);
}

TEST_F(SCFApiTest, SCF_Init_AlreadyInit)
{
    char libPath[] = "/usr/lib64";
    int32_t ret = SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(SCFApiTest, SCF_CreatePolicyCtx_Success)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    EXPECT_TRUE(ctx != nullptr);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_FreePolicyCtx_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_FreePolicyCtx(&ctx);
    EXPECT_TRUE(ctx == nullptr);
}

TEST_F(SCFApiTest, SCF_FreePolicyCtx_Null)
{
    SCF_PolicyCtx *ctx = nullptr;
    SCF_FreePolicyCtx(&ctx);
    EXPECT_TRUE(ctx == nullptr);
}

TEST_F(SCFApiTest, SCF_SetPolicy_ValidServer)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    EXPECT_EQ(ret, SCF_SUCCESS);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_SetPolicy_ValidClient)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_CLIENT, SCF_VERIFY_PEER, SCF_POLICY_HIGH);
    EXPECT_EQ(ret, SCF_SUCCESS);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_SetPolicy_NullCtx)
{
    int32_t ret = SCF_SetPolicy(nullptr, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
}

TEST_F(SCFApiTest, SCF_SetPolicy_InvalidRole)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_NONE, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_SetPolicy_InvalidVerifyMode)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_FAIL_IF_NO_PEER_CERT + 1, SCF_POLICY_HIGH);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_SetPolicy_CustomerMode)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_CUSTOMER);
    EXPECT_EQ(ret, SCF_SUCCESS);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_SetPolicy_MiddleMode)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    int32_t ret = SCF_SetPolicy(ctx, SCF_ROLE_CLIENT, SCF_VERIFY_PEER, SCF_POLICY_MIDDLE);
    EXPECT_EQ(ret, SCF_SUCCESS);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_GetPolicy_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    SCF_ROLE role = SCF_ROLE_NONE;
    uint32_t verifyMode = 0;
    SCF_POLICY_MODE policyMode = SCF_POLICY_HIGH;

    int32_t ret = SCF_GetPolicy(ctx, &role, &verifyMode, &policyMode);
    EXPECT_EQ(ret, SCF_SUCCESS);
    EXPECT_EQ(role, SCF_ROLE_SERVER);
    EXPECT_EQ(verifyMode, SCF_VERIFY_DEFAULT);
    EXPECT_EQ(policyMode, SCF_POLICY_HIGH);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_GetPolicy_NullCtx)
{
    SCF_ROLE role = SCF_ROLE_NONE;
    uint32_t verifyMode = 0;
    SCF_POLICY_MODE policyMode = SCF_POLICY_HIGH;

    int32_t ret = SCF_GetPolicy(nullptr, &role, &verifyMode, &policyMode);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_GetPolicy_NullRole)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    uint32_t verifyMode = 0;
    SCF_POLICY_MODE policyMode = SCF_POLICY_HIGH;

    int32_t ret = SCF_GetPolicy(ctx, nullptr, &verifyMode, &policyMode);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_CreatePolicyObj_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
    EXPECT_TRUE(obj != nullptr);

    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_CreatePolicyObj_NullCtx)
{
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(nullptr);
    EXPECT_TRUE(obj == nullptr);
}

TEST_F(SCFApiTest, SCF_FreePolicyObj_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
    SCF_FreePolicyObj(&obj);
    EXPECT_TRUE(obj == nullptr);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_FreePolicyObj_Null)
{
    SCF_PolicyObj *obj = nullptr;
    SCF_FreePolicyObj(&obj);
    EXPECT_TRUE(obj == nullptr);
}

TEST_F(SCFApiTest, SCF_SetFd_NullObj)
{
    int32_t ret = SCF_SetFd(nullptr, 0);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_SetFd_InvalidFd)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);

    int32_t ret = SCF_SetFd(obj, -1);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_SetCipherSuites_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    uint16_t cipherSuites[] = {SCF_SSL_AES_128_GCM_SHA256};
    int32_t ret = SCF_SetCipherSuites(ctx, cipherSuites, 1);
    EXPECT_EQ(ret, SCF_SUCCESS);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_SetCipherSuites_NullCtx)
{
    uint16_t cipherSuites[] = {SCF_SSL_AES_128_GCM_SHA256};
    int32_t ret = SCF_SetCipherSuites(nullptr, cipherSuites, 1);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_SetCipherSuites_NullCiphers)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    int32_t ret = SCF_SetCipherSuites(ctx, nullptr, 1);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_SetCipherSuites_ZeroSize)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    uint16_t cipherSuites[] = {SCF_SSL_AES_128_GCM_SHA256};
    int32_t ret = SCF_SetCipherSuites(ctx, cipherSuites, 0);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_SetCipherSuites_Multiple)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    uint16_t cipherSuites[] = {
        SCF_SSL_AES_128_GCM_SHA256,
        SCF_SSL_AES_256_GCM_SHA384,
        SCF_SSL_CHACHA20_POLY1305_SHA256
    };
    int32_t ret = SCF_SetCipherSuites(ctx, cipherSuites, 3);
    EXPECT_EQ(ret, SCF_SUCCESS);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_GetCipherSuites_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    uint16_t cipherSuites[] = {SCF_SSL_AES_128_GCM_SHA256, SCF_SSL_AES_256_GCM_SHA384};
    SCF_SetCipherSuites(ctx, cipherSuites, CIPHER_SUITE_COUNT_2);

    uint16_t retrieved[ARRAY_SIZE_10] = {0};
    uint32_t size = ARRAY_SIZE_10;
    uint32_t actualSize = 0;
    int32_t ret = SCF_GetCipherSuites(ctx, retrieved, size, &actualSize);
    EXPECT_EQ(ret, SCF_SSL_ERR_GET_CIPHER);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_GetCipherSuites_NullCtx)
{
    uint16_t retrieved[ARRAY_SIZE_10] = {0};
    uint32_t size = ARRAY_SIZE_10;
    uint32_t actualSize = 0;
    int32_t ret = SCF_GetCipherSuites(nullptr, retrieved, size, &actualSize);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_SetProtocolVersion_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    uint32_t forbidVersion[] = {0};
    int32_t ret = SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS13, forbidVersion, 0);
    EXPECT_EQ(ret, SCF_SET_PROTOCOL_VERSION_ERROR);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_SetProtocolVersion_NullCtx)
{
    uint32_t forbidVersion[] = {0};
    int32_t ret = SCF_SetProtocolVersion(nullptr, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS13, forbidVersion, 0);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_GetProtocolVersion_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    uint32_t forbidVersion[] = {0};
    SCF_SetProtocolVersion(ctx, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS13, forbidVersion, 0);

    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);
    const char *version = SCF_GetProtocolVersion(obj);
    EXPECT_TRUE(version != nullptr || version == nullptr);

    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_FileCtxNew_Success)
{
    SCF_FILE_CTX *fileCtx = SCF_FileCtxNew();
    EXPECT_TRUE(fileCtx != nullptr);
    SCF_FileCtxFree(&fileCtx);
}

TEST_F(SCFApiTest, SCF_FileCtxFree_Valid)
{
    SCF_FILE_CTX *fileCtx = SCF_FileCtxNew();
    SCF_FileCtxFree(&fileCtx);
    EXPECT_TRUE(fileCtx == nullptr);
}

TEST_F(SCFApiTest, SCF_FileCtxFree_Null)
{
    SCF_FILE_CTX *fileCtx = nullptr;
    SCF_FileCtxFree(&fileCtx);
    EXPECT_TRUE(fileCtx == nullptr);
}

TEST_F(SCFApiTest, SCF_FileCtxSetBuf_NullCtx)
{
    uint8_t buf[] = "test";
    int32_t ret = SCF_FileCtxSetBuf(nullptr, SCF_STORE_FILE_PATH, buf, 4, SCF_STORE_FORMAT_PEM);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_FileCtxSetBuf_NullBuf)
{
    SCF_FILE_CTX *fileCtx = SCF_FileCtxNew();
    int32_t ret = SCF_FileCtxSetBuf(fileCtx, SCF_STORE_FILE_PATH, nullptr, 4, SCF_STORE_FORMAT_PEM);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    SCF_FileCtxFree(&fileCtx);
}

TEST_F(SCFApiTest, SCF_FileCtxSetPwd_NullCtx)
{
    uint8_t passwd[] = "test";
    int32_t ret = SCF_FileCtxSetPwd(nullptr, passwd, 4, false);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_SessionNew_Success)
{
    SCF_Session *session = SCF_SessionNew();
    EXPECT_TRUE(session != nullptr);
    SCF_SessionFree(&session);
}

TEST_F(SCFApiTest, SCF_SessionFree_Valid)
{
    SCF_Session *session = SCF_SessionNew();
    SCF_SessionFree(&session);
    EXPECT_TRUE(session == nullptr);
}

TEST_F(SCFApiTest, SCF_SessionFree_Null)
{
    SCF_Session *session = nullptr;
    SCF_SessionFree(&session);
    EXPECT_TRUE(session == nullptr);
}

TEST_F(SCFApiTest, SCF_SessionSetMasterKey_NullSession)
{
    uint8_t key[ARRAY_SIZE_48] = {0};
    int32_t ret = SCF_SessionSetMasterKey(nullptr, key, ARRAY_SIZE_48, false);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
}

TEST_F(SCFApiTest, SCF_SessionSetCipher_NullSession)
{
    uint16_t cipher = SCF_SSL_AES_128_GCM_SHA256;
    int32_t ret = SCF_SessionSetCipher(nullptr, &cipher, 1);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_CipherFind_NullSession)
{
    uint8_t cipherId[] = {0x13, 0x01};
    const void *result = SCF_CipherFind(nullptr, cipherId);
    EXPECT_TRUE(result == nullptr);
}

TEST_F(SCFApiTest, SCF_SetUserData_NullObj)
{
    int32_t ret = SCF_SetUserData(nullptr, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_GetUserData_NullObj)
{
    void *data = SCF_GetUserData(nullptr);
    EXPECT_TRUE(data == nullptr);
}

TEST_F(SCFApiTest, SCF_GetPeerCert_NullObj)
{
    void *cert = SCF_GetPeerCert(nullptr);
    EXPECT_TRUE(cert == nullptr);
}

TEST_F(SCFApiTest, SCF_GetCurrentCert_NullObj)
{
    void *cert = SCF_GetCurrentCert(nullptr);
    EXPECT_TRUE(cert == nullptr);
}

TEST_F(SCFApiTest, SCF_AddCert_NullCtx)
{
    int32_t ret = SCF_AddCert(nullptr, nullptr, SCF_CERT_TYPE_CA);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_AddCert_NullFileCtx)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    int32_t ret = SCF_AddCert(ctx, nullptr, SCF_CERT_TYPE_CA);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_SetKey_NullCtx)
{
    int32_t ret = SCF_SetKey(nullptr, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_SetKey_NullFileCtx)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    int32_t ret = SCF_SetKey(ctx, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_CheckPrivateKey_NullCtx)
{
    int32_t ret = SCF_CheckPrivateKey(nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_GetCertVersion_NullCert)
{
    int32_t ret = SCF_GetCertVersion(nullptr);
    EXPECT_EQ(ret, -1);
}

TEST_F(SCFApiTest, SCF_GetCertStartTime_NullCert)
{
    char startTime[ARRAY_SIZE_64] = {0};
    int32_t ret = SCF_GetCertStartTime(nullptr, startTime, ARRAY_SIZE_64);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_GetCertEndTime_NullCert)
{
    char endTime[ARRAY_SIZE_64] = {0};
    int32_t ret = SCF_GetCertEndTime(nullptr, endTime, ARRAY_SIZE_64);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_GetCertSerialNumber_NullCert)
{
    uint32_t serialLen = ARRAY_SIZE_32;
    uint8_t *serial = SCF_GetCertSerialNumber(nullptr, &serialLen);
    EXPECT_TRUE(serial == nullptr);
}

TEST_F(SCFApiTest, SCF_SetAppVerifyCallback_NullCtx)
{
    int32_t ret = SCF_SetAppVerifyCallback(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_FreeBuffer_NullBuffer)
{
    size_t bufferLen = 0;
    SCF_FreeBuffer(nullptr, bufferLen);
}

TEST_F(SCFApiTest, SCF_SetPskFindSessionCallback_NullCtx)
{
    int32_t ret = SCF_SetPskFindSessionCallback(nullptr, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_SetPskUseSessionCallback_NullCtx)
{
    int32_t ret = SCF_SetPskUseSessionCallback(nullptr, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_Connect_NullObj)
{
    int32_t ret = SCF_Connect(nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_Accept_NullObj)
{
    int32_t ret = SCF_Accept(nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(SCFApiTest, SCF_Read_NullObj)
{
uint8_t buffer[ARRAY_SIZE_10] = {0};

    uint32_t readLen = 0;
    int32_t ret = SCF_Read(nullptr, buffer, ARRAY_SIZE_10, &readLen);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
}

TEST_F(SCFApiTest, SCF_Read_NullBuffer)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);

    uint32_t readLen = 0;
    int32_t ret = SCF_Read(obj, nullptr, ARRAY_SIZE_10, &readLen);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_Write_NullObj)
{
uint8_t data[ARRAY_SIZE_10] = {0};

    uint32_t writeLen = 0;
    int32_t ret = SCF_Write(nullptr, data, ARRAY_SIZE_10, &writeLen);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
}

TEST_F(SCFApiTest, SCF_Write_NullData)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    SCF_PolicyObj *obj = SCF_CreatePolicyObj(ctx);

    uint32_t writeLen = 0;
    int32_t ret = SCF_Write(obj, nullptr, ARRAY_SIZE_10, &writeLen);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    SCF_FreePolicyObj(&obj);
    SCF_FreePolicyCtx(&ctx);
}

TEST_F(SCFApiTest, SCF_Close_NullObj)
{
    int32_t ret = SCF_Close(nullptr);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(SCFApiTest, SCF_FreeCert_NullCert)
{
    SCF_FreeCert(nullptr);
}

}