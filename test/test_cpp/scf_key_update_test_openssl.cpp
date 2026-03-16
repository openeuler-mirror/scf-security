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

#include <cstdint>
#include <cstdio>
#include "gtest/gtest.h"

#include "scf_errno.h"
#include "scf_ssl.h"

#include "test_scf.h"
using namespace ::scf;

namespace test::scf {
#define TEST_DEFAULT_UPDATE_TIME 3600
#define TEST_DEFAULT_UPDATE_TRAFFIC (1024 * 1024 * 1024)
#define TEST_UPDATE_TIME 60 // 可自行设定，为方便测试选择的一个较小值
#define TEST_UPDATE_TRAFFIC (1024 * 1024) // 可自行设定

    class SCFKeyUpdateTestOpenssl : public SCFSmokeTest {
    protected:
        SCFKeyUpdateTestOpenssl() : SCFSmokeTest(SCF_INIT_FLAG_OPENSSL, "/usr/lib64")
        {
        }
        void InitConn();

        void InitConnTLS12();
    };


    void SCFKeyUpdateTestOpenssl::InitConn()
    {
        int32_t ret;
        TestInitServer();
        TestInitClient();
        SCF_SetKeyAutoUpdateParam(m_server, true, NN_N60, NN_N1000000);
        SCF_SetKeyAutoUpdateParam(m_client, true, NN_N60, NN_N1000000);
        // 使用默认的算法套
        // 使用默认的版本

        TestInitServerObj();
        TestInitClientObj();

        test::fw::TestTcpServer testServer(BASE_IP, NN_N9454);
        ret = testServer.Start();
        ASSERT_EQ(ret, test::fw::NN_OK);

        test::fw::TestTcpClient testClient(BASE_IP, NN_N9454);
        ret = testClient.Connect(BASE_IP, NN_N9454, conn);
        ASSERT_EQ(ret, test::fw::NN_OK);

        int fdServer = testServer.GetAcceptFd();
        ASSERT_TRUE(fdServer >= 0);
        int fdClient = conn->GetFd();
        ASSERT_TRUE(fdClient >= 0);

        // fd 转移给 SCF_PolicyCtx，跟随 SCF_PolicyCtx 的释放关闭，不需要单独关闭
        ret = SCF_SetFd(m_serverObj, fdServer);
        ASSERT_EQ(ret, SCF_SUCCESS);

        ret = SCF_SetFd(m_clientObj, fdClient);
        ASSERT_EQ(ret, SCF_SUCCESS);
    }

    void SCFKeyUpdateTestOpenssl::InitConnTLS12()
    {
        int32_t ret;
        m_server = SCF_CreatePolicyCtx();
        ASSERT_TRUE(m_server != nullptr);
        ret = SCF_SetPolicy(m_server, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_TRUE(ret == SCF_SUCCESS);

        m_client = SCF_CreatePolicyCtx();
        ASSERT_TRUE(m_client != nullptr);
        ret = SCF_SetPolicy(m_client, SCF_ROLE_CLIENT, SCF_VERIFY_DEFAULT, SCF_POLICY_MIDDLE);
        ASSERT_TRUE(ret == SCF_SUCCESS);

        SCF_SetKeyAutoUpdateParam(m_server, true, TEST_DEFAULT_UPDATE_TIME, TEST_UPDATE_TRAFFIC);
        ret = SCF_SetKeyAutoUpdateParam(m_client, true, TEST_DEFAULT_UPDATE_TIME, TEST_UPDATE_TRAFFIC);
        uint16_t cipherSuites1[] = {SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
        ret = SCF_SetCipherSuites(m_server, cipherSuites1, sizeof(cipherSuites1) / sizeof(uint16_t));

        ASSERT_EQ(ret, SCF_SUCCESS);
        ret = SCF_SetProtocolVersion(m_server, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS12, NULL, 0);
        ASSERT_EQ(ret, SCF_SUCCESS);

        ret = TestAddPemPrivKey(m_server, SCF_CERT_ECDSA_SHA256_KEY_SERVER);
        ASSERT_EQ(ret, SCF_SUCCESS);
        ret = SCF_CheckPrivateKey(m_server);
        ASSERT_EQ(ret, SCF_SUCCESS);

        uint16_t cipherSuites[] = {SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
        ret = SCF_SetCipherSuites(m_client, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t));
        ASSERT_EQ(ret, SCF_SUCCESS);
        ret = SCF_SetProtocolVersion(m_client, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS12, NULL, 0);
        ASSERT_EQ(ret, SCF_SUCCESS);

        ret = TestAddPemPrivKey(m_client, SCF_CERT_ECDSA_SHA256_KEY_CLIENT);
        ASSERT_EQ(ret, SCF_SUCCESS);
        ret = SCF_CheckPrivateKey(m_client);
        ASSERT_EQ(ret, SCF_SUCCESS);

        TestInitServerObj();
        TestInitClientObj();

        test::fw::TestTcpServer testServer(BASE_IP, NN_N9454);
        ret = testServer.Start();
        ASSERT_EQ(ret, test::fw::NN_OK);

        test::fw::TestTcpClient testClient(BASE_IP, NN_N9454);
        ret = testClient.Connect(BASE_IP, NN_N9454, conn);
        ASSERT_EQ(ret, test::fw::NN_OK);

        int fdServer = testServer.GetAcceptFd();
        ASSERT_TRUE(fdServer >= 0);
        int fdClient = conn->GetFd();
        ASSERT_TRUE(fdClient >= 0);

        // fd 转移给 SCF_PolicyCtx，跟随 SCF_PolicyCtx 的释放关闭，不需要单独关闭
        ret = SCF_SetFd(m_serverObj, fdServer);
        ASSERT_EQ(ret, SCF_SUCCESS);

        ret = SCF_SetFd(m_clientObj, fdClient);
        ASSERT_EQ(ret, SCF_SUCCESS);

        ret = Test_CreateBareSslConnection(m_serverObj, m_clientObj, SCF_SUCCESS);
        ASSERT_EQ(ret, 1);
    }

    // 验证SCF_SetKeyAutoUpdateParam接口算法套在范围外的值失败
    TEST_F(SCFKeyUpdateTestOpenssl, API_Secure_Communication_Component_57)
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

    static uint16_t g_sslCiphertSuite = 0;

    // 验证客户端、服务端的算法套无交集无法传输
    TEST_F(SCFKeyUpdateTestOpenssl, Secure_Communication_Session_Fuc_04)
    {
        int32_t ret = SCF_ERROR;
        TestInitServer();
        TestInitClient();

        // server指定TLS1.3协议的算法
        uint16_t cipherSuites[] = {SCF_SSL_AES_256_GCM_SHA384};
        g_sslCiphertSuite = SCF_SSL_AES_256_GCM_SHA384; // 用例回调里指定使用的算法套
        ret = SCF_SetCipherSuites(m_server, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t));
        ASSERT_EQ(ret, SCF_SUCCESS);
        ret = SCF_SetProtocolVersion(m_server, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS13, NULL, 0);
        ASSERT_EQ(ret, SCF_SUCCESS);
        ret = SCF_SetPskFindSessionCallback(m_server, nullptr);
        ASSERT_EQ(ret, SCF_SUCCESS);

        // client指定TLS1.2协议的算法
        uint16_t cipherSuites1[] = {SCF_SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384};
        ret = SCF_SetCipherSuites(m_client, cipherSuites1, sizeof(cipherSuites1) / sizeof(uint16_t));
        ASSERT_EQ(ret, SCF_SUCCESS);
        ret = SCF_SetProtocolVersion(m_client, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS13, NULL, 0);
        ASSERT_EQ(ret, SCF_SUCCESS);
        ret = SCF_SetPskUseSessionCallback(m_client, nullptr);
        ASSERT_EQ(ret, SCF_SUCCESS);

        TestInitServerObj();
        TestInitClientObj();

        const int serverPort = 9445;
        test::fw::TestTcpServer testServer(BASE_IP, serverPort);
        ret = testServer.Start();
        ASSERT_EQ(ret, test::fw::NN_OK);

        test::fw::TestTcpClient testClient(BASE_IP, serverPort);
        ret = testClient.Connect(BASE_IP, serverPort, conn);
        ASSERT_EQ(ret, test::fw::NN_OK);

        int fdServer = testServer.GetAcceptFd();
        ASSERT_TRUE(fdServer >= 0);
        int fdClient = conn->GetFd();
        ASSERT_TRUE(fdClient >= 0);

        // fd 转移给 SCF_PolicyCtx，跟随 SCF_PolicyCtx 的释放关闭，不需要单独关闭
        ret = SCF_SetFd(m_serverObj, fdServer);
        ASSERT_EQ(ret, SCF_SUCCESS);

        ret = SCF_SetFd(m_clientObj, fdClient);
        ASSERT_EQ(ret, SCF_SUCCESS);

        ret = SCF_Connect(m_clientObj);
        ASSERT_EQ(ret, SCF_ERRNO_SECURE_TRANSPORT);
    }

    // 验证安全通信建立后配置流量在范围外的值密钥更新失败
    TEST_F(SCFKeyUpdateTestOpenssl, Secure_Communication_Update_Key_04)
    {
        InitConn();

        int errorTraffic = 999;
        auto ret = SCF_SetKeyAutoUpdateParam(m_server, true, TEST_UPDATE_TIME, errorTraffic);
        ASSERT_EQ(ret, SCF_SSL_ERR_SET_UPDATE_PARAM);
    }

    // 验证安全通信建立后配置间隔时间在范围外的值密钥更新失败
    TEST_F(SCFKeyUpdateTestOpenssl, Secure_Communication_Update_Key_02)
    {
        InitConn();

        int maxTimeInterval = 31536001;
        auto ret = SCF_SetKeyAutoUpdateParam(m_server, true, maxTimeInterval, TEST_DEFAULT_UPDATE_TRAFFIC);
        ASSERT_EQ(ret, SCF_SSL_ERR_SET_UPDATE_PARAM);

        int minTimeInterval = 0;
        ret = SCF_SetKeyAutoUpdateParam(m_server, true, minTimeInterval, TEST_DEFAULT_UPDATE_TRAFFIC);
        ASSERT_EQ(ret, SCF_SSL_ERR_SET_UPDATE_PARAM);
    }
} // namespace test::scf
