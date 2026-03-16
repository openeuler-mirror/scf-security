/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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

#include "gtest/gtest.h"
#include "iostream"
#include "stub.h"
#include "test_scf.h"

#include "scf.h"
#include "scf_errno.h"
#include "scf_inner.h"
#include "scf_ssl.h"
#include "crypto_util.h"

using namespace ::scf;

namespace test::scf {
    class SCFGetTestOpenssl : public SCFSmokeTest {
    };

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_54)
    {
        SCF_Session *sessionnew = SCF_SessionNew();
        ASSERT_TRUE(sessionnew != nullptr);
        uint16_t cipherSuites = SCF_SSL_AES_128_GCM_SHA256;
        ASSERT_EQ(SCF_SessionSetCipher(sessionnew, nullptr, NN_NO2), SCF_ERRNO_NULL_INPUT);
        ASSERT_EQ(SCF_SessionSetCipher(nullptr, &cipherSuites, NN_NO2), SCF_ERRNO_NULL_INPUT);
        SCF_SessionFree(&sessionnew);
    }

    TEST_F(SCFGetTestOpenssl, SCF_SetConfigFile_Succ)
    {
        Stub stub;
        stub.Set(&IsAbsolutePath, StubIsAbsolutePath);
        SetExternalDecryptFunction(StubKmcDecryptPassword);
        SetExternalLogFunction(ExternalLogFunction);
        m_client = SCF_CreatePolicyCtx();
        auto ret = SCF_SetPolicy(m_client, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_EQ(ret, SCF_SUCCESS);
        auto config = test::GetLocalPath() + "/test/test_data/test_config_succ.json";
        ret = SCF_SetConfigFile(m_client, config.c_str());
        ASSERT_EQ(ret, SCF_SUCCESS);
    }

    // 验证SCF_SetKeyAutoUpdateParam接口算法套在范围外的值失败
    TEST_F(SCFGetTestOpenssl, SCF_SetKeyAutoUpdateParam)
    {
        SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(policyctx != nullptr);
        uint32_t keyUpdateTime = 60;
        uint64_t keyUpdateTraffic = UINT64_MAX;
        int32_t ret = SCF_SetKeyAutoUpdateParam(nullptr, true, keyUpdateTime, keyUpdateTraffic);
        ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);

        keyUpdateTime = 70; // 测试模拟更新时间阈值
        keyUpdateTraffic = 1000009; // 测试模拟更新流量阈值
        ret = SCF_SetKeyAutoUpdateParam(policyctx, true, keyUpdateTime, keyUpdateTraffic);
        ASSERT_EQ(ret, SCF_SUCCESS);

        keyUpdateTime = 3600 * 24 * 365; // 测试模拟更新时间阈值
        keyUpdateTraffic = UINT64_MAX;
        ret = SCF_SetKeyAutoUpdateParam(policyctx, true, keyUpdateTime, keyUpdateTraffic);
        ASSERT_EQ(ret, SCF_SUCCESS);

        keyUpdateTime = 0; // 测试模拟更新时间阈值
        keyUpdateTraffic = 1000000; // 测试模拟更新流量阈值
        ret = SCF_SetKeyAutoUpdateParam(policyctx, true, keyUpdateTime, keyUpdateTraffic);
        ASSERT_EQ(ret, SCF_SSL_ERR_SET_UPDATE_PARAM);

        keyUpdateTime = 60; // 测试模拟更新时间阈值
        keyUpdateTraffic = 999; // 测试模拟更新流量阈值
        ret = SCF_SetKeyAutoUpdateParam(policyctx, true, keyUpdateTime, keyUpdateTraffic);
        ASSERT_EQ(ret, SCF_SSL_ERR_SET_UPDATE_PARAM);

        keyUpdateTime = 3600 * 24 * 365 + 1; // 测试模拟更新时间阈值
        keyUpdateTraffic = 1000000; // 测试模拟更新流量阈值
        ret = SCF_SetKeyAutoUpdateParam(policyctx, true, keyUpdateTime, keyUpdateTraffic);
        ASSERT_EQ(ret, SCF_SSL_ERR_SET_UPDATE_PARAM);
        SCF_FreePolicyCtx(&policyctx);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_53)
    {
        SCF_Session *sessionnew = SCF_SessionNew();
        ASSERT_TRUE(sessionnew != nullptr);
        int CipherSuite[] = {
            SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            SCF_SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            SCF_SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            SCF_SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            SCF_SSL_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            SCF_SSL_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            SCF_SSL_AES_128_GCM_SHA256,
            SCF_SSL_AES_256_GCM_SHA384,
            SCF_SSL_CHACHA20_POLY1305_SHA256,
            SCF_SSL_AES_128_CCM_SHA256
        };
        int size = sizeof(CipherSuite) / sizeof(CipherSuite[0]);
        for (int i = 0; i < size; i++) {
            auto ret = SCF_SessionSetCipher(sessionnew, &CipherSuite[i], 2);
            ASSERT_EQ(ret, SCF_SUCCESS);
        }
        SCF_SessionFree(&sessionnew);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_55)
    {
        SCF_Session *sessionnew = SCF_SessionNew();
        ASSERT_TRUE(sessionnew != nullptr);
        auto ret = SCF_SessionSetProtocolVersion(sessionnew, SCF_SSL_VERSION_TLS13_STR);
        ASSERT_EQ(ret, SCF_SUCCESS);
        ret = SCF_SessionSetProtocolVersion(sessionnew, SCF_SSL_VERSION_TLS12_STR);
        ASSERT_EQ(ret, SCF_SUCCESS);
        SCF_SessionFree(&sessionnew);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_56)
    {
        SCF_Session *sessionnew = SCF_SessionNew();
        ASSERT_TRUE(sessionnew != nullptr);
        auto ret = SCF_SessionSetProtocolVersion(nullptr, SCF_SSL_VERSION_TLS13_STR);
        ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
        ret = SCF_SessionSetProtocolVersion(sessionnew, nullptr);
        ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
        SCF_SessionFree(&sessionnew);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_35)
    {
        int32_t ret;
        // 服务端配置安全策略
        SCF_PolicyCtx *policyCtx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(policyCtx != nullptr);
        ret = SCF_SetPolicy(policyCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
        ASSERT_EQ(ret, SCF_SUCCESS);

        uint16_t cipherSuites[] = {SCF_SSL_AES_256_GCM_SHA384};
        uint16_t cipherSuites1[] = {0x1444};
        // 设置ctx为空
        ret = SCF_SetCipherSuites(nullptr, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t));
        ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
        // 设置cipherSuites为空
        ret = SCF_SetCipherSuites(policyCtx, nullptr, 0);
        ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
        ret = SCF_SetCipherSuites(policyCtx, cipherSuites1, sizeof(cipherSuites) / sizeof(uint16_t));
        ASSERT_EQ(ret, SCF_SSL_ERR_SET_CIPHER);

        SCF_FreePolicyCtx(&policyCtx);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_34)
    {
        int32_t ret;
        // 服务端配置安全策略
        SCF_PolicyCtx *policyCtx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(policyCtx != nullptr);
        ret = SCF_SetPolicy(policyCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
        ASSERT_EQ(ret, SCF_SUCCESS);

        uint16_t CipherSuite[] = {
            SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            SCF_SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            SCF_SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            SCF_SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            SCF_SSL_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            SCF_SSL_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            SCF_SSL_AES_128_GCM_SHA256,
            SCF_SSL_AES_256_GCM_SHA384,
            SCF_SSL_CHACHA20_POLY1305_SHA256,
            SCF_SSL_AES_128_CCM_SHA256
        };
        int size = sizeof(CipherSuite) / sizeof(CipherSuite[0]);
        uint16_t data[MAX_DATA_LEN];
        uint32_t cipherSuitesSize = 0;
        for (int i = 0; i < size; i++) {
            ret = SCF_SetCipherSuites(policyCtx, &CipherSuite[i], 1);
            ASSERT_EQ(ret, SCF_SUCCESS);
            ret = SCF_GetCipherSuites(policyCtx, data, MAX_DATA_LEN, &cipherSuitesSize);
            ASSERT_EQ(ret, SCF_SUCCESS);
        }
        SCF_FreePolicyCtx(&policyCtx);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_27)
    {
        int32_t ret;
        SCF_PolicyCtx *policyCtx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(policyCtx != nullptr);
        ret = SCF_SetPolicy(policyCtx, SCF_ROLE_SERVER, SCF_VERIFY_CUSTOMER | SCF_VERIFY_PEER,
                              SCF_POLICY_CUSTOMER);
        ASSERT_EQ(ret, SCF_SUCCESS);
        // 使用用户注册的校验逻辑，令校验通过
        ret = SCF_SetAppVerifyCallback(policyCtx, TEST_AppVerifyFuncImpl,
                                         (void *) (uintptr_t) SCF_CERT_RSA_CRL);
        ASSERT_EQ(ret, SCF_SUCCESS);
        SCF_FreePolicyCtx(&policyCtx);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_29)
    {
        int32_t ret;
        SCF_PolicyCtx *policyCtx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(policyCtx != nullptr);
        ret = SCF_SetPolicy(policyCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_CUSTOMER);
        ASSERT_EQ(ret, SCF_SUCCESS);
        // 使用用户注册的校验逻辑，令校验通过
        ret = SCF_SetAppVerifyCallback(nullptr, TEST_AppVerifyFuncImpl, (void *) (uintptr_t) SCF_CERT_RSA_CRL);
        ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
        SCF_FreePolicyCtx(&policyCtx);
    }

    // 验证SCF_GetCipherSuites接口入参范围外的值失败
    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_36)
    {
        SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
        SCF_SetPolicy(policyctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_TRUE(policyctx != nullptr);
        uint16_t data[MAX_DATA_LEN];
        uint32_t cipherSuitesSize = 0;
        ASSERT_EQ(SCF_GetCipherSuites(nullptr, data, MAX_DATA_LEN, &cipherSuitesSize), SCF_ERRNO_NULL_INPUT);
        ASSERT_EQ(SCF_GetCipherSuites(policyctx, nullptr, MAX_DATA_LEN, &cipherSuitesSize),
                  SCF_ERRNO_NULL_INPUT);
        ASSERT_EQ(SCF_GetCipherSuites(policyctx, data, MAX_DATA_LEN, nullptr), SCF_ERRNO_NULL_INPUT);
        ASSERT_EQ(SCF_GetCipherSuites(policyctx, data, MAX_DATA_LEN, nullptr), SCF_ERRNO_NULL_INPUT);
        SCF_FreePolicyCtx(&policyctx);
    }

    // 验证 SCF_GetKeyUpdateInfo接口算法套在范围外的值失败
    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_58)
    {
        m_server = SCF_CreatePolicyCtx();
        ASSERT_NE(m_server, nullptr);
        m_serverObj = SCF_CreatePolicyObj(m_server);
        ASSERT_NE(m_serverObj, nullptr);

        uint64_t lastKeyUpdateTime = 0;
        uint32_t timeInterval = 0;
        uint64_t remainTraffic = 0;

        ASSERT_EQ(SCF_GetKeyUpdateInfo(m_serverObj, nullptr, &timeInterval, &remainTraffic),
                  SCF_ERRNO_NULL_INPUT);
        ASSERT_EQ(SCF_GetKeyUpdateInfo(m_serverObj, &lastKeyUpdateTime, nullptr, &remainTraffic),
                  SCF_ERRNO_NULL_INPUT);
        ASSERT_EQ(SCF_GetKeyUpdateInfo(m_serverObj, &lastKeyUpdateTime, &timeInterval, nullptr),
                  SCF_ERRNO_NULL_INPUT);
    }


    // 验证SCF_Read接口入参范围外的值失败
    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_37)
    {
        auto *policyctx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(policyctx != nullptr);
        auto *policyobj = SCF_CreatePolicyObj(policyctx);
        ASSERT_TRUE(policyobj != nullptr);
        uint8_t data[] = "123";
        uint32_t dataLen = sizeof(data);
        uint32_t readLen = 0;
        ASSERT_EQ(SCF_Read(nullptr, data, dataLen, &readLen), SCF_ERRNO_INVALID_PARAM);
        ASSERT_EQ(SCF_Read(policyobj, nullptr, 0, &readLen), SCF_ERRNO_INVALID_PARAM);
        ASSERT_EQ(SCF_Read(policyobj, data, 0, &readLen), SCF_ERRNO_INVALID_PARAM);
        ASSERT_EQ(SCF_Read(policyobj, data, dataLen, nullptr), SCF_ERRNO_INVALID_PARAM);
        SCF_FreePolicyObj(&policyobj);
        SCF_FreePolicyCtx(&policyctx);
    }

    // 验证用户调用安全通信策略接口入参非法时失败
    TEST_F(SCFGetTestOpenssl, Secure_Communication_Component_08)
    {
        SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(policyctx != nullptr);
        auto ret = SCF_SetPolicy(policyctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_EQ(ret, SCF_SUCCESS);

        ret = SCF_SetConfigFile(policyctx, SCF_CONFIG_TLS_ECDSA_SERVER_NOT_EXIST);
        ASSERT_EQ(ret, SCF_ERROR);
        SCF_FreePolicyCtx(&policyctx);
    }

    // 验证用户设置TLS协议版本minVersion与maxVersion一致
    TEST_F(SCFGetTestOpenssl, Secure_Communication_Component_03)
    {
        int32_t ret;
        m_server = SCF_CreatePolicyCtx();
        ASSERT_TRUE(m_server != nullptr);
        ret = SCF_SetPolicy(m_server, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_EQ(ret, SCF_SUCCESS);

        ret = SCF_SetConfigFile(m_server, SCF_CONFIG_TLS_COMPONENT_03_1);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_server, SCF_CONFIG_TLS_COMPONENT_03_2);
        ASSERT_EQ(ret, SCF_ERROR);
    }


    // 验证用户设置TLS协议与协议对应的算法不一致后创建安全通信策略失败
    TEST_F(SCFGetTestOpenssl, Secure_Communication_Component_02)
    {
        int32_t ret;
        m_server = SCF_CreatePolicyCtx();
        ASSERT_TRUE(m_server != nullptr);
        ret = SCF_SetPolicy(m_server, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_EQ(ret, SCF_SUCCESS);

        ret = SCF_SetConfigFile(m_server, SCF_CONFIG_TLS_COMPONENT_02_1);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_server, SCF_CONFIG_TLS_COMPONENT_02_2);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_server, SCF_CONFIG_TLS_COMPONENT_02_3);
        ASSERT_EQ(ret, SCF_ERROR);
    }

    // 验证认证方式为证书认证用户创建安全通信策略成功
    TEST_F(SCFGetTestOpenssl, Secure_Communication_Component_04)
    {
        int32_t ret;
        m_server = SCF_CreatePolicyCtx();
        ASSERT_TRUE(m_server != nullptr);
        ret = SCF_SetPolicy(m_server, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_EQ(ret, SCF_SUCCESS);

        ret = SCF_SetConfigFile(m_server, SCF_CONFIG_TLS_COMPONENT_04_1);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_server, SCF_CONFIG_TLS_COMPONENT_04_2);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_server, SCF_CONFIG_TLS_COMPONENT_04_3);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_server, SCF_CONFIG_TLS_COMPONENT_04_4);
        ASSERT_EQ(ret, SCF_ERROR);
    }

    // 验证用户调用安全通信的证书认证接口与设置安全策略证书文件类型不一致失败
    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_17)
    {
        Stub stub;
        stub.Set(SCF_CheckFilePathAndStat, StubCheckFilePathAndStat);
        m_server = SCF_CreatePolicyCtx();
        int32_t ret = SCF_SetPolicy(m_server, SCF_ROLE_SERVER, SCF_VERIFY_PEER, SCF_POLICY_HIGH);
        ASSERT_EQ(ret, SCF_SUCCESS);

        auto *fileCtx = SCF_FileCtxNew();
        EXPECT_NE(fileCtx, nullptr);
        std::string filePath = SCF_CERT_ECDSA_SHA256_P12_SERVER;
        ret = SCF_FileCtxSetBuf(fileCtx, SCF_STORE_FILE_PATH,
                                  reinterpret_cast<uint8_t *>(const_cast<char *>(filePath.c_str())), filePath.size(),
                                  SCF_STORE_FORMAT_PEM);
        EXPECT_EQ(ret, SCF_SUCCESS);
        SCF_FileCtxFree(&fileCtx);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_22)
    {
        int32_t ret;
        SCF_PolicyCtx *policyCtx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(policyCtx != nullptr);
        ret = SCF_SetPolicy(policyCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_EQ(ret, SCF_SUCCESS);

        ret = SCF_SetConfigFile(nullptr, SCF_CONFIG_TLS_ECDSA_CLIENT);
        ASSERT_TRUE(ret == SCF_ERRNO_NULL_INPUT);

        ret = SCF_SetConfigFile(policyCtx, nullptr);
        ASSERT_TRUE(ret == SCF_ERRNO_NULL_INPUT);

        ret = SCF_SetConfigFile(policyCtx, "/tmp/API_Secure_Communication_Component_22"); // 配置文件不存在
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(policyCtx, SCF_CONFIG_TLS_ECDSA_CLIENT);
        ASSERT_TRUE(ret == SCF_ERROR);

        SCF_FreePolicyCtx(&policyCtx);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_39)
    {
        int32_t ret;
        SCF_PolicyCtx *policyCtx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(policyCtx != nullptr);
        ret = SCF_SetPolicy(policyCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
        ASSERT_EQ(ret, SCF_SUCCESS);
        SCF_PolicyObj *policyObj = SCF_CreatePolicyObj(policyCtx);
        ASSERT_NE(policyObj, nullptr);
        ret = SCF_SetFd(nullptr, 0);
        EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
        // 调用接口创建socket
        ret = SCF_SetFd(policyObj, NN_NO2);
        EXPECT_EQ(ret, SCF_SUCCESS);

        SCF_FreePolicyObj(&policyObj);
        SCF_FreePolicyCtx(&policyCtx);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_20)
    {
        int32_t ret;
        SCF_PolicyCtx *policyCtx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(policyCtx != nullptr);
        ret = SCF_SetPolicy(policyCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
        ASSERT_EQ(ret, SCF_SUCCESS);
        SCF_FILE_CTX *keyCtx = SCF_FileCtxNew();
        EXPECT_NE(keyCtx, nullptr);
        ret = SCF_SetKey(nullptr, keyCtx);
        EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
        ret = SCF_SetKey(policyCtx, nullptr);
        EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
        SCF_FileCtxFree(&keyCtx);
        SCF_FreePolicyCtx(&policyCtx);
    }

    // 验证用户调用安全通信的密钥接口成功
    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_19)
    {
        int32_t ret;
        // 安全策略
        SCF_PolicyCtx *policyCtx_server = SCF_CreatePolicyCtx();
        SCF_PolicyCtx *policyCtx_client = SCF_CreatePolicyCtx();
        ASSERT_TRUE(policyCtx_server != nullptr);
        ret = SCF_SetPolicy(policyCtx_server, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_EQ(ret, SCF_SUCCESS);
        ret = SCF_SetPolicy(policyCtx_client, SCF_ROLE_CLIENT, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_EQ(ret, SCF_SUCCESS);

        SCF_FreePolicyCtx(&policyCtx_server);
        SCF_FreePolicyCtx(&policyCtx_client);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_13)
    {
        int32_t ret;
        SCF_FILE_CTX *fileCtx = SCF_FileCtxNew();
        EXPECT_NE(fileCtx, nullptr);
        uint8_t pskPwd[] = SCF_PSK_PWD;
        // 配置passwd
        ret = SCF_FileCtxSetPwd(fileCtx, pskPwd, strlen(SCF_PSK_PWD));
        EXPECT_EQ(ret, SCF_SUCCESS);

        // 配置fileCtx为空
        ret = SCF_FileCtxSetPwd(nullptr, pskPwd, strlen(SCF_PSK_PWD));
        ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);

        SCF_FileCtxFree(&fileCtx);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_11)
    {
        int32_t ret;
        SCF_FILE_CTX *fileCtx = SCF_FileCtxNew();
        EXPECT_NE(fileCtx, nullptr);

        // 配置passwd
        uint8_t passwd[] = "newpasswd";
        ret = SCF_FileCtxSetPwd(fileCtx, passwd, strlen((const char *) passwd));
        EXPECT_EQ(ret, SCF_SUCCESS);

        SCF_FileCtxFree(&fileCtx);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_12)
    {
        int32_t ret;
        SCF_FILE_CTX *fileCtx = SCF_FileCtxNew();
        EXPECT_NE(fileCtx, nullptr);

        // 配置passwd
        ret = SCF_FileCtxSetPwd(fileCtx, nullptr, 0);
        EXPECT_EQ(ret, SCF_SUCCESS);

        SCF_FileCtxFree(&fileCtx);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_31)
    {
        int32_t ret;
        // 配置安全策略
        m_server = SCF_CreatePolicyCtx();
        ASSERT_TRUE(m_server != nullptr);
        ret = SCF_SetPolicy(m_server, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
        ASSERT_EQ(ret, SCF_SUCCESS);
        // 创建安全策略对象实例
        m_serverObj = SCF_CreatePolicyObj(m_server);
        ASSERT_EQ(ret, SCF_SUCCESS);
        ret = SCF_GetCertStartTime(nullptr, nullptr, 0);
        ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    }

    TEST_F(SCFGetTestOpenssl, Secure_Communication_Component_06)
    {
        int32_t ret;
        TestInitServer();

        ret = SCF_SetConfigFile(m_server, SCF_CONFIG_TLS_COMPONENT_06);
        ASSERT_EQ(ret, SCF_ERROR);
    }

    TEST_F(SCFGetTestOpenssl, Secure_Communication_Component_07)
    {
        int32_t ret;
        TestInitServer();

        ret = SCF_SetConfigFile(m_server, SCF_CONFIG_TLS_COMPONENT_07_01);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_server, SCF_CONFIG_TLS_COMPONENT_07_02);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_server, SCF_CONFIG_TLS_COMPONENT_07_03);
        ASSERT_EQ(ret, SCF_ERROR);
    }

    TEST_F(SCFGetTestOpenssl, Secure_Communication_Component_01)
    {
        int32_t ret;
        // 配置安全策略
        SCF_PolicyCtx *m_serverCtx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(m_serverCtx != nullptr);
        ret = SCF_SetPolicy(m_serverCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_EQ(ret, SCF_SUCCESS);

        SCF_PolicyCtx *m_clientCtx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(m_clientCtx != nullptr);
        ret = SCF_SetPolicy(m_clientCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_EQ(ret, SCF_SUCCESS);

        ret = SCF_SetConfigFile(m_clientCtx, SCF_CONFIG_TLS_COMPONENT_01_01);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_serverCtx, SCF_CONFIG_TLS_COMPONENT_01_02);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_serverCtx, SCF_CONFIG_TLS_COMPONENT_01_03);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_serverCtx, SCF_CONFIG_TLS_COMPONENT_01_04);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_serverCtx, SCF_CONFIG_TLS_COMPONENT_01_05);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_serverCtx, SCF_CONFIG_TLS_COMPONENT_01_06);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_serverCtx, SCF_CONFIG_TLS_COMPONENT_01_07);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_serverCtx, SCF_CONFIG_TLS_COMPONENT_01_08);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_serverCtx, SCF_CONFIG_TLS_COMPONENT_01_09);
        ASSERT_EQ(ret, SCF_ERROR);

        ret = SCF_SetConfigFile(m_serverCtx, SCF_CONFIG_TLS_COMPONENT_01_10);
        ASSERT_EQ(ret, SCF_ERROR);

        SCF_FreePolicyCtx(&m_clientCtx);
        SCF_FreePolicyCtx(&m_serverCtx);
    }

    TEST_F(SCFGetTestOpenssl, SCF_GetErroMsgTest)
    {
        const char *msg = GetErrorMessage(SCF_SSL_ERR_ADD_EE_CHAIN_TO_STORE);
        ASSERT_TRUE(std::string(msg) == "SSL add EE chain to store error");
    }

    // 验证 SCF_CreatePolicyObj接口，obj为空
    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_65)
    {
        m_server = SCF_CreatePolicyCtx();
        ASSERT_NE(m_server, nullptr);
        m_serverObj = SCF_CreatePolicyObj(nullptr);
        ASSERT_EQ(m_serverObj, nullptr);
    }

    // 未创建通信链接，获取通信链路对端的证书对象
    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_66)
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

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_67)
    {
        SCF_FILE_CTX *tmpPtr = SCF_FileCtxNew();
        ASSERT_TRUE(tmpPtr != nullptr);
        SCF_FileCtxFree(&tmpPtr);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_68)
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

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_69)
    {
        int32_t ret = SCF_Connect(nullptr);
        ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    }

    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_70)
    {
        SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
        ASSERT_TRUE(policyctx != nullptr);
        SCF_PolicyObj *policyobj = SCF_CreatePolicyObj(policyctx);
        ASSERT_TRUE(policyobj != nullptr);
        int32_t ret = SCF_Close(nullptr);
        ASSERT_EQ(ret, SCF_SUCCESS);
        ret = SCF_Close(policyobj);
        ASSERT_EQ(ret, SCF_SUCCESS);

        SCF_FreePolicyObj(&policyobj);
        SCF_FreePolicyCtx(&policyctx);
    }

    // 验证SCF_CipherFind查找算法套件-tls1.2
    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_60)
    {
        m_server = SCF_CreatePolicyCtx();
        ASSERT_TRUE(m_server != nullptr);
        auto ret = SCF_SetPolicy(m_server, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_EQ(ret, SCF_SUCCESS);
        ASSERT_EQ(ret, SCF_SUCCESS);
        // server设置通信协议为TLS1.2
        ret = SCF_SetProtocolVersion(m_server, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS12, nullptr, 0);
        ASSERT_EQ(ret, SCF_SUCCESS);
        m_serverObj = SCF_CreatePolicyObj(m_server);
        ASSERT_TRUE(m_serverObj != nullptr);
        const void *cipherSuite = nullptr;
        uint8_t tls12Id1[] = {0xC0, 0x2B};
        cipherSuite = SCF_CipherFind(m_serverObj, tls12Id1);
        // 没有调用SetFd，sslCtx为nullptr
        ASSERT_EQ(cipherSuite, nullptr);
    }

    // 验证SCF_CipherFind查找算法套件-tls1.3
    TEST_F(SCFGetTestOpenssl, API_Secure_Communication_Component_61)
    {
        int32_t ret;
        m_server = SCF_CreatePolicyCtx();
        ASSERT_TRUE(m_server != nullptr);
        ret = SCF_SetPolicy(m_server, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_EQ(ret, SCF_SUCCESS);
        // server设置通信协议为TLS1.2
        ret = SCF_SetProtocolVersion(m_server, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS13, nullptr, 0);
        ASSERT_EQ(ret, SCF_SUCCESS);
        m_serverObj = SCF_CreatePolicyObj(m_server);
        ASSERT_TRUE(m_serverObj != nullptr);
        const void *cipherSuite = nullptr;
        uint8_t tls13Id1[] = {0x13, 0x01};
        cipherSuite = SCF_CipherFind(m_serverObj, tls13Id1);
        // 没有调用SetFd，sslCtx为nullptr
        ASSERT_EQ(cipherSuite, nullptr);
    }
} // namespace test::scf
