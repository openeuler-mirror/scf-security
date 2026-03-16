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

#ifndef TEST_SCF_H
#define TEST_SCF_H

#include <gtest/gtest.h>
#include <stdint.h>

#include <atomic>
#include <iostream>
#include <string>
#include <thread>

#include "test_tcp_client.h"
#include "test_tcp_server.h"

#include "scf.h"

#ifdef __cplusplus
extern "C" {
#endif
#define MAX_DATA_LEN 1024
#define SCF_PSK_PWD "scf hello"
#define SCF_TEST_DATA_ROOT "./test_data" // need to config
#define SCF_CERT_ECDSA_SHA256_ROOT SCF_TEST_DATA_ROOT "/certificate/ecdsa_sha256"
#define SCF_CERT_ECDSA_SHA256_ROOT_AND_ICA SCF_CERT_ECDSA_SHA256_ROOT "/root_intca.pem"
#define SCF_CERT_ECDSA_SHA256_ROOT_CA SCF_CERT_ECDSA_SHA256_ROOT "/root.pem"
#define SCF_CERT_ECDSA_SHA256_ICA SCF_CERT_ECDSA_SHA256_ROOT "/intca.pem"
#define SCF_CERT_ECDSA_SHA256_EE_CLIENT SCF_CERT_ECDSA_SHA256_ROOT "/client.pem"
#define SCF_CERT_ECDSA_SHA256_EE_SERVER SCF_CERT_ECDSA_SHA256_ROOT "/server.pem"
#define SCF_CERT_ECDSA_SHA256_KEY_CLIENT SCF_CERT_ECDSA_SHA256_ROOT "/client.key.pem"
#define SCF_CERT_ECDSA_SHA256_KEY_SERVER SCF_CERT_ECDSA_SHA256_ROOT "/server.key.pem"
#define SCF_CERT_ECDSA_SHA256_P12_SERVER SCF_CERT_ECDSA_SHA256_ROOT "/server.p12"
#define SCF_CERT_ECDSA_SHA256_CRL_SERVER SCF_CERT_ECDSA_SHA256_ROOT "/client_crl.pem"
#define SCF_CERT_ECDSA_SHA256_CA_SERVER SCF_CERT_ECDSA_SHA256_ROOT "/ca.pem"
#define SCF_CERT_ECDSA_SHA256_KEY_private SCF_CERT_ECDSA_SHA256_ROOT "/private.pem"
#define SCF_CERT_ECDSA_SHA256_KEY_private1 SCF_CERT_ECDSA_SHA256_ROOT "/private1.pem"
#define SCF_CERT_ECDSA_SHA256_KEY_multiple SCF_CERT_ECDSA_SHA256_ROOT "/multiple_key.pem"
#define SCF_CERT_ECDSA_SHA256_KEY_single SCF_CERT_ECDSA_SHA256_ROOT "/single_key.pem"

#define SCF_CERT_ECDSA_SHA384_ROOT SCF_TEST_DATA_ROOT "/certificate/ecdsa_sha384"
#define SCF_CERT_ECDSA_SHA384_ROOT_CA SCF_CERT_ECDSA_SHA256_ROOT "/root.pem"
#define SCF_CERT_ECDSA_SHA384_ICA SCF_CERT_ECDSA_SHA256_ROOT "/intca.pem"
#define SCF_CERT_ECDSA_SHA384_EE_CLIENT SCF_CERT_ECDSA_SHA256_ROOT "/client.pem"
#define SCF_CERT_ECDSA_SHA384_EE_SERVER SCF_CERT_ECDSA_SHA256_ROOT "/server.pem"
#define SCF_CERT_ECDSA_SHA384_KEY_CLIENT SCF_CERT_ECDSA_SHA256_ROOT "/client.key.pem"
#define SCF_CERT_ECDSA_SHA384_KEY_SERVER SCF_CERT_ECDSA_SHA256_ROOT "/server.key.pem"

#define SCF_CERT_ECDSA_SHA1_ROOT SCF_TEST_DATA_ROOT "/certificate/ecdsa_sha1"
#define SCF_CERT_ECDSA_SHA1_ROOT_CA \
    SCF_CERT_ECDSA_SHA1_ROOT "/ec_root.pem" // sha1 证书的 root。root本身是 sha384 的
#define SCF_CERT_ECDSA_SHA1_ICA SCF_CERT_ECDSA_SHA1_ROOT "/ec_intca.pem" // sha1 证书的 ica。ica 本身是 sha384 的
#define SCF_CERT_ECDSA_SHA1_EE_CLIENT SCF_CERT_ECDSA_SHA1_ROOT "/ec_app384SHA1_c.pem"
#define SCF_CERT_ECDSA_SHA1_EE_SERVER SCF_CERT_ECDSA_SHA1_ROOT "/ec_app384SHA1.pem"
#define SCF_CERT_ECDSA_SHA1_KEY_CLIENT SCF_CERT_ECDSA_SHA1_ROOT "/ec_app384SHA1_c.key.pem"
#define SCF_CERT_ECDSA_SHA1_KEY_SERVER SCF_CERT_ECDSA_SHA1_ROOT "/ec_app384SHA1.key.pem"

#define SCF_CERT_RSA_SHA256_ROOT SCF_TEST_DATA_ROOT "/certificate/rsa_sha256"
#define SCF_CERT_RSA_SHA256_ERROR_PATH SCF_TEST_DATA_ROOT "/certificate/rsa_sha256/errorPath"
#define SCF_CERT_RSA_SHA256_NOCAP_PATH SCF_TEST_DATA_ROOT "/certificate/rsa_sha256/root_nocap.pem"
#define SCF_CERT_RSA_SHA256_RELATIVE_PATH SCF_TEST_DATA_ROOT "/certificate/../certificate/rsa_sha256/root_nocap.pem"
#define SCF_CERT_RSA_SHA256_INVALID_ZERO_PATH "/dev/zero"
#define SCF_CERT_RSA_SHA256_ROOT_CA SCF_CERT_RSA_SHA256_ROOT "/root.pem"
#define SCF_CERT_RSA_SHA256_ROOT_KEY_CA SCF_CERT_RSA_SHA256_ROOT "/root.key.pem"
#define SCF_CERT_RSA_SHA256_ICA SCF_CERT_RSA_SHA256_ROOT "/intca.pem"
#define SCF_CERT_RSA_SHA256_EE_CLIENT SCF_CERT_RSA_SHA256_ROOT "/client.pem"
#define SCF_CERT_RSA_SHA256_EE_SERVER SCF_CERT_RSA_SHA256_ROOT "/server.pem"
#define SCF_CERT_RSA_SHA256_KEY_CLIENT SCF_CERT_RSA_SHA256_ROOT "/client.key.pem"
#define SCF_CERT_RSA_SHA256_KEY_SERVER SCF_CERT_RSA_SHA256_ROOT "/server.key.pem"

#define SCF_CERT_RSA_CRL SCF_TEST_DATA_ROOT "/certificate/new_rsa_crl_chain/rootca.crl"

#define JSON_CONFIG_PATH SCF_TEST_DATA_ROOT "/scf_json_config/"
#define SCF_CONFIG_TLS_FOLDER SCF_TEST_DATA_ROOT "/scf_json_config"
#define SCF_CONFIG_TLS_PERF_PSK_CLIENT SCF_CONFIG_TLS_FOLDER "/test_scf_perf_tls_psk_client.json"
#define SCF_CONFIG_TLS_PERF_PSK_SERVER SCF_CONFIG_TLS_FOLDER "/test_scf_perf_tls_psk_server.json"
#define SCF_CONFIG_TLS_PSK_CLIENT SCF_CONFIG_TLS_FOLDER "/test_scf_smoke_tls_psk_client.json"
#define SCF_CONFIG_TLS_PSK_SERVER SCF_CONFIG_TLS_FOLDER "/test_scf_smoke_tls_psk_server.json"
#define SCF_CONFIG_TLS_ECDSA_CLIENT_ALL SCF_CONFIG_TLS_FOLDER "/test_scf_smoke_tls_ecdsa_client_all.json"
#define SCF_CONFIG_TLS_ECDSA_CLIENT SCF_CONFIG_TLS_FOLDER "/test_scf_smoke_tls_ecdsa_client.json"
#define SCF_CONFIG_TLS_ECDSA_SERVER SCF_CONFIG_TLS_FOLDER "/test_scf_smoke_tls_ecdsa_server.json"
#define SCF_CONFIG_TLS_ECDSA_SERVER_NOT_EXIST \
    SCF_CONFIG_TLS_FOLDER "/test_scf_smoke_tls_ecdsa_server_no_exist.json"
#define SCF_CONFIG_TLS_COMPONENT_03_1 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_03_1.json"
#define SCF_CONFIG_TLS_COMPONENT_03_2 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_03_2.json"
#define SCF_CONFIG_TLS_COMPONENT_02_1 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_02_1.json"
#define SCF_CONFIG_TLS_COMPONENT_02_2 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_02_2.json"
#define SCF_CONFIG_TLS_COMPONENT_02_3 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_02_3.json"
#define SCF_CONFIG_TLS_COMPONENT_04_1 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_04_1.json"
#define SCF_CONFIG_TLS_COMPONENT_04_2 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_04_2.json"
#define SCF_CONFIG_TLS_COMPONENT_04_3 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_04_3.json"
#define SCF_CONFIG_TLS_COMPONENT_04_4 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_04_4.json"
#define SCF_CONFIG_TLS_COMPONENT_04_5 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_04_5.json"
#define SCF_CONFIG_TLS_COMPONENT_06 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_06.json"
#define SCF_CONFIG_TLS_COMPONENT_07_01 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_07_01.json"
#define SCF_CONFIG_TLS_COMPONENT_07_02 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_07_02.json"
#define SCF_CONFIG_TLS_COMPONENT_07_03 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_07_03.json"
#define SCF_CONFIG_TLS_COMPONENT_01_01 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_01_01.json"
#define SCF_CONFIG_TLS_COMPONENT_01_02 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_01_02.json"
#define SCF_CONFIG_TLS_COMPONENT_01_03 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_01_03.json"
#define SCF_CONFIG_TLS_COMPONENT_01_04 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_01_04.json"
#define SCF_CONFIG_TLS_COMPONENT_01_05 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_01_05.json"
#define SCF_CONFIG_TLS_COMPONENT_01_06 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_01_06.json"
#define SCF_CONFIG_TLS_COMPONENT_01_07 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_01_07.json"
#define SCF_CONFIG_TLS_COMPONENT_01_08 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_01_08.json"
#define SCF_CONFIG_TLS_COMPONENT_01_09 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_01_09.json"
#define SCF_CONFIG_TLS_COMPONENT_01_10 SCF_CONFIG_TLS_FOLDER "/Secure_Communication_Component_01_10.json"

constexpr int32_t NN_NOF1 = -1;
constexpr uint32_t NN_NO0 = 0;
constexpr uint32_t NN_NO1 = 1;
constexpr uint32_t NN_NO2 = 2;
constexpr uint32_t NN_NO3 = 3;
constexpr uint32_t NN_NO4 = 4;
constexpr uint32_t NN_NO5 = 5;
constexpr uint32_t NN_NO6 = 6;
constexpr uint32_t NN_N60 = 60;
constexpr uint32_t NN_N100 = 100;
constexpr uint32_t NN_N1024 = 1024;
constexpr uint32_t NN_N9444 = 9444;
constexpr uint32_t NN_N9454 = 9454;
constexpr uint32_t NN_N1000000 = 1000000;
constexpr uint32_t NN_N4096 = 4096;

#ifdef __cplusplus
}
#endif
using namespace scf;
namespace test {

int Test_CreateBareSslConnection(SCF_PolicyObj *serverssl, SCF_PolicyObj *clientssl, int want);

int32_t TEST_PskCreateSession(const uint8_t *psk, size_t pskLen, const void *cipherSuite, SCF_Session **session);

int32_t TestAddPemCertWithExpected(SCF_PolicyCtx *ctx, const char *filePath, SCF_CERT_TYPE type, int32_t expected);
int32_t TestAddPemCert(SCF_PolicyCtx *ctx, const char *filePath, SCF_CERT_TYPE type);

int32_t TestAddPemPrivKey(SCF_PolicyCtx *ctx, const char *filePath);

int32_t TEST_AppVerifyFuncImpl(void *storeCtx, void *arg);

void ExternalLogFunction(int level, const char *msg);

bool StubCheckFilePathAndStat(const std::string &filePath);

bool StubIsAbsolutePath(const std::string &filePath);

int32_t StubSCFSuccess();

bool StubKmcDecryptPassword(const uint8_t *passwd, size_t passwdLen, std::vector<std::byte> &plaintext);

std::string GetLocalPath();

class SCFSmokeTest : public ::testing::Test {
protected:
    SCFSmokeTest()
    {
        initFlag = SCF_INIT_FLAG_OPENSSL;
        libPath = "/usr/lib64";
    }
    SCFSmokeTest(uint64_t initFlag, std::string libPath): initFlag(std::move(initFlag)), libPath(std::move(libPath)) {
    }
    virtual void SetUp();
    virtual void TearDown();
    virtual void TestInitServer();
    virtual void TestInitClient();
    void TestInitServerObj();
    void TestInitClientObj();
    void TestSslReadWrite();
    void TestSslReadWrite(uint32_t rwLen);

protected:
    SCF_PolicyCtx *m_client = nullptr;
    SCF_PolicyCtx *m_server = nullptr;
    SCF_PolicyObj *m_clientObj = nullptr;
    SCF_PolicyObj *m_serverObj = nullptr;
    fw::TestTcpConnection *conn = nullptr;
private:
    uint64_t initFlag;
    std::string libPath;
};

} // namespace test

#endif